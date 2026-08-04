<?php
/**
 * Single-use recovery codes. Plaintext is shown to the user exactly once at
 * generation; only password_hash() digests are stored, and each code is
 * consumed (removed) on use.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates, stores, and consumes backup codes.
 */
class Provider_Backup_Codes {

	/**
	 * User-meta key holding the array of hashes.
	 */
	const META_KEY = 'dls_backup_codes';

	/**
	 * Generate N random, human-typeable plaintext codes (returned once).
	 *
	 * @param int $count How many.
	 * @return string[] Plaintext codes.
	 */
	public static function generate( int $count = 10 ): array {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			// 10 hex chars, grouped as xxxxx-xxxxx for readability.
			$raw     = bin2hex( random_bytes( 5 ) );
			$codes[] = substr( $raw, 0, 5 ) . '-' . substr( $raw, 5, 5 );
		}
		return $codes;
	}

	/**
	 * Find which stored hash matches a submitted code, in constant time over
	 * the whole set. Returns the hash's array key, or false.
	 *
	 * @param array  $hashes Stored password_hash digests.
	 * @param string $code   Submitted code.
	 * @return int|string|false Matching key or false.
	 */
	public static function match( array $hashes, string $code ) {
		$code  = strtolower( trim( $code ) );
		$found = false;
		foreach ( $hashes as $key => $hash ) {
			if ( is_string( $hash ) && password_verify( $code, $hash ) ) {
				$found = $key; // Do not break — keep timing uniform across the set.
			}
		}
		return $found;
	}

	/**
	 * Store hashes for the plaintext set (replaces any existing).
	 *
	 * @param int      $user_id User id.
	 * @param string[] $plain   Plaintext codes.
	 */
	public static function store( int $user_id, array $plain ): void {
		$hashes = array();
		foreach ( $plain as $code ) {
			$hashes[] = password_hash( strtolower( $code ), PASSWORD_DEFAULT );
		}
		update_user_meta( $user_id, self::META_KEY, $hashes );
	}

	/**
	 * Verify a code and, on success, consume it (single use).
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	public static function verify_and_consume( int $user_id, string $code ): bool {
		$hashes = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $hashes ) || empty( $hashes ) ) {
			return false;
		}
		$key = self::match( $hashes, $code );
		if ( false === $key ) {
			return false;
		}
		unset( $hashes[ $key ] );
		update_user_meta( $user_id, self::META_KEY, array_values( $hashes ) );
		return true;
	}

	/**
	 * How many unused codes remain.
	 *
	 * @param int $user_id User id.
	 * @return int
	 */
	public static function remaining( int $user_id ): int {
		$hashes = get_user_meta( $user_id, self::META_KEY, true );
		return is_array( $hashes ) ? count( $hashes ) : 0;
	}
}
