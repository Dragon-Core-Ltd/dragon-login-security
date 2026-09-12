<?php
/**
 * TOTP (RFC 6238) authenticator-app provider. No third-party dependency —
 * TOTP is small and well-specified, and the RFC test vectors are the proof.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates and verifies 6-digit time-based one-time codes.
 */
class Provider_TOTP {

	/**
	 * Time step in seconds.
	 */
	const PERIOD = 30;

	/**
	 * Digits in a code.
	 */
	const DIGITS = 6;

	/**
	 * RFC 4648 base32 alphabet.
	 */
	const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * User-meta key holding the last accepted time step (replay guard).
	 */
	const LAST_STEP_META = 'dls_totp_last_step';

	/**
	 * How many times recording a step is retried when another request changed
	 * the counter in between. Each retry re-reads and re-compares.
	 */
	private const CONSUME_ATTEMPTS = 3;

	/**
	 * Generate a random base32 secret (160-bit).
	 *
	 * @return string
	 */
	public static function generate_secret(): string {
		$bytes  = random_bytes( 20 );
		$secret = '';
		$buffer = 0;
		$bits   = 0;
		for ( $i = 0, $len = strlen( $bytes ); $i < $len; $i++ ) {
			$buffer = ( $buffer << 8 ) | ord( $bytes[ $i ] );
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits   -= 5;
				$secret .= self::B32[ ( $buffer >> $bits ) & 31 ];
			}
		}
		if ( $bits > 0 ) {
			$secret .= self::B32[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}
		return $secret;
	}

	/**
	 * Decode a base32 secret to raw bytes.
	 *
	 * @param string $secret Base32 secret.
	 * @return string
	 */
	private static function base32_decode( string $secret ): string {
		$secret = strtoupper( str_replace( array( ' ', '=' ), '', $secret ) );
		$buffer = 0;
		$bits   = 0;
		$out    = '';
		for ( $i = 0, $len = strlen( $secret ); $i < $len; $i++ ) {
			$pos = strpos( self::B32, $secret[ $i ] );
			if ( false === $pos ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $pos;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $out;
	}

	/**
	 * The code for a secret at a given timestamp.
	 *
	 * @param string $secret    Base32 secret.
	 * @param int    $timestamp Unix time.
	 * @return string 6-digit, zero-padded.
	 */
	public static function code_at( string $secret, int $timestamp ): string {
		$key     = self::base32_decode( $secret );
		$counter = (int) floor( $timestamp / self::PERIOD );
		$binary  = pack( 'J', $counter ); // 64-bit big-endian.
		$hash    = hash_hmac( 'sha1', $binary, $key, true );
		$offset  = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$code    = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );
		$code    = $code % ( 10 ** self::DIGITS );
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a code against a secret, allowing +/- window steps of clock skew.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   Submitted code.
	 * @param int    $window Steps of tolerance either side.
	 * @param int    $now    Current time (injectable for tests).
	 * @return bool
	 */
	public static function verify( string $secret, string $code, int $window = 1, int $now = 0 ): bool {
		return self::verify_step( $secret, $code, $window, $now ) >= 0;
	}

	/**
	 * Verify a code and return the matching time-step counter, or -1. The step
	 * lets callers reject replay of a captured code within its validity window.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   Submitted code.
	 * @param int    $window Steps of tolerance either side.
	 * @param int    $now    Current time (injectable for tests).
	 * @return int Matching step counter, or -1 if no match.
	 */
	public static function verify_step( string $secret, string $code, int $window = 1, int $now = 0 ): int {
		$code = preg_replace( '/\D/', '', $code );
		if ( strlen( (string) $code ) !== self::DIGITS ) {
			return -1;
		}
		$now = $now > 0 ? $now : time();
		for ( $i = -$window; $i <= $window; $i++ ) {
			$ts = $now + ( $i * self::PERIOD );
			if ( hash_equals( self::code_at( $secret, $ts ), (string) $code ) ) {
				return (int) floor( $ts / self::PERIOD );
			}
		}
		return -1;
	}

	/**
	 * Record a verified time step as used, rejecting replays. A step that is
	 * not newer than the last recorded one, or that cannot be stored, fails:
	 * without the stored step the same code would be accepted again.
	 *
	 * @param int $user_id User id.
	 * @param int $step    Time-step counter returned by verify_step().
	 * @return bool Whether the step is fresh and now recorded.
	 */
	public static function consume_step( int $user_id, int $step ): bool {
		/*
		 * The counter must only ever move forward. Two requests verifying
		 * adjacent steps can both read the same old value, and an unconditional
		 * write would let the older step land last and put the counter back,
		 * making the newer code replayable. Checking the write's return value
		 * does not help: the write succeeds, it is simply the wrong value.
		 *
		 * So the comparison and the write are one step. $prev_value makes core
		 * update only a row that still holds the value that was read, and a
		 * unique add creates the first row only once; either way a request that
		 * loses the race re-reads and re-compares, and gives up if the stored
		 * step has caught up with its own.
		 */
		for ( $attempt = 0; $attempt < self::CONSUME_ATTEMPTS; $attempt++ ) {
			$raw  = get_user_meta( $user_id, self::LAST_STEP_META, true );
			$last = (int) $raw;

			if ( $step <= $last ) {
				return false;
			}

			if ( '' === $raw || null === $raw || false === $raw ) {
				if ( false !== add_user_meta( $user_id, self::LAST_STEP_META, $step, true ) ) {
					return true;
				}
				continue; // Another request recorded the first step; re-read it.
			}

			if ( false !== update_user_meta( $user_id, self::LAST_STEP_META, $step, $raw ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build the otpauth:// provisioning URI for a QR code.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $label  Account label (usually the username or email).
	 * @param string $issuer Issuer (site name).
	 * @return string
	 */
	public static function provisioning_uri( string $secret, string $label, string $issuer ): string {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			rawurlencode( $issuer ),
			rawurlencode( $label ),
			rawurlencode( $secret ),
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}
}
