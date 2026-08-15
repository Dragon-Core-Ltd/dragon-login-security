<?php
/**
 * The single-use, expiring, user-bound token that carries a login across the
 * 2FA interrupt. This is the anti-bypass boundary: no persistent auth cookie is
 * issued until a valid token AND a valid second factor are presented together.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issues and verifies 2FA login tokens.
 */
class Login_Token {

	/**
	 * Default lifetime in seconds.
	 */
	const TTL = 300;

	/**
	 * The transient key for a token (keyed by its hash, never the token itself).
	 *
	 * @param string $token Token.
	 * @return string
	 */
	private static function key( string $token ): string {
		return 'dragonloginsecurity_2fa_' . hash( 'sha256', $token );
	}

	/**
	 * Create a token bound to a user.
	 *
	 * @param int $user_id User id.
	 * @param int $ttl     Lifetime seconds.
	 * @return string The token (delivered to the browser).
	 */
	public static function create( int $user_id, int $ttl = self::TTL ): string {
		$token = bin2hex( random_bytes( 32 ) );
		set_transient(
			self::key( $token ),
			array(
				'user' => $user_id,
				'exp'  => time() + $ttl,
			),
			$ttl
		);
		return $token;
	}

	/**
	 * Verify a token against an expected user. Constant work; single-use
	 * (consumed on success or expiry); rejects unknown/expired/wrong-user.
	 *
	 * @param string $token   Token.
	 * @param int    $user_id Expected user id.
	 * @param int    $now     Injectable clock (0 = time()).
	 * @return bool
	 */
	public static function verify( string $token, int $user_id, int $now = 0 ): bool {
		$data = get_transient( self::key( $token ) );
		if ( ! is_array( $data ) || ! isset( $data['user'], $data['exp'] ) ) {
			return false;
		}

		$now     = $now > 0 ? $now : time();
		$expired = $now >= (int) $data['exp'];
		$valid   = ! $expired && (int) $data['user'] === $user_id;

		// Consume on success (single-use) or expiry (cleanup); leave a live token
		// untouched on a mere user mismatch so the legitimate holder can retry.
		if ( $valid || $expired ) {
			delete_transient( self::key( $token ) );
		}

		return $valid;
	}

	/**
	 * The user id a token is bound to (without consuming), or 0.
	 *
	 * @param string $token Token.
	 * @return int
	 */
	public static function user_for( string $token ): int {
		$data = get_transient( self::key( $token ) );
		return is_array( $data ) && isset( $data['user'] ) ? (int) $data['user'] : 0;
	}
}
