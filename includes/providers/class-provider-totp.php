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
		$code = preg_replace( '/\D/', '', $code );
		if ( strlen( (string) $code ) !== self::DIGITS ) {
			return false;
		}
		$now = $now > 0 ? $now : time();
		for ( $i = -$window; $i <= $window; $i++ ) {
			if ( hash_equals( self::code_at( $secret, $now + ( $i * self::PERIOD ) ), (string) $code ) ) {
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
