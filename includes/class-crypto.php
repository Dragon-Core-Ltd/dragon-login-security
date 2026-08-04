<?php
/**
 * AES-256-CBC helper for encrypting secrets at rest (e.g. TOTP secrets).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AES-256-CBC keyed from wp_salt('auth'), the fleet convention.
 */
class Crypto {

	/**
	 * Encrypt a string.
	 *
	 * @param string $data Plaintext.
	 * @return string Base64-encoded IV + ciphertext.
	 */
	public static function encrypt( string $data ): string {
		$key       = hash( 'sha256', wp_salt( 'auth' ), true );
		$iv        = openssl_random_pseudo_bytes( 16 );
		$encrypted = openssl_encrypt( $data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding encrypted binary payload, not obfuscating code.
		return base64_encode( $iv . $encrypted );
	}

	/**
	 * Decrypt a string.
	 *
	 * @param string $data Base64-encoded IV + ciphertext.
	 * @return string|null Plaintext or null on failure.
	 */
	public static function decrypt( string $data ): ?string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding encrypted binary payload, not obfuscating code.
		$data = base64_decode( $data, true );
		if ( false === $data || strlen( $data ) < 17 ) {
			return null;
		}
		$key       = hash( 'sha256', wp_salt( 'auth' ), true );
		$decrypted = openssl_decrypt( substr( $data, 16 ), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr( $data, 0, 16 ) );
		return false !== $decrypted ? $decrypted : null;
	}
}
