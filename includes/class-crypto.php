<?php
/**
 * Authenticated encryption helper for secrets at rest.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypt-then-MAC over AES-256-CBC, keyed from wp_salt('auth') (the fleet
 * convention). New values are authenticated: decrypt() verifies an HMAC before
 * decrypting, so ciphertext cannot be silently tampered with. Values written by
 * the previous unauthenticated helper (base64 of IV + ciphertext) are still
 * read, so existing stored secrets keep working.
 */
class Crypto {

	/**
	 * Marker prefixing the authenticated (v1) format.
	 */
	private const V1_PREFIX = 'DRGNc1:';

	/**
	 * Encryption key.
	 *
	 * @return string
	 */
	private static function enc_key(): string {
		return hash( 'sha256', wp_salt( 'auth' ), true );
	}

	/**
	 * MAC key (domain-separated from the encryption key).
	 *
	 * @return string
	 */
	private static function mac_key(): string {
		return hash( 'sha256', 'dragon-crypto-mac|' . wp_salt( 'auth' ), true );
	}

	/**
	 * Encrypt a string (authenticated).
	 *
	 * @param string $data Plaintext.
	 * @return string Prefixed base64 of IV + HMAC + ciphertext ('' on failure).
	 */
	public static function encrypt( string $data ): string {
		$iv = openssl_random_pseudo_bytes( 16 );
		$ct = openssl_encrypt( $data, 'AES-256-CBC', self::enc_key(), OPENSSL_RAW_DATA, $iv );
		if ( false === $ct ) {
			return '';
		}
		$mac = hash_hmac( 'sha256', $iv . $ct, self::mac_key(), true );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding encrypted binary payload, not obfuscating code.
		return self::V1_PREFIX . base64_encode( $iv . $mac . $ct );
	}

	/**
	 * Decrypt a string produced by encrypt(), or by the legacy CBC helper.
	 *
	 * @param string $data Ciphertext.
	 * @return string|null Plaintext, or null on failure or authentication failure.
	 */
	public static function decrypt( string $data ): ?string {
		if ( '' === $data ) {
			return null;
		}

		if ( 0 === strncmp( $data, self::V1_PREFIX, strlen( self::V1_PREFIX ) ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding encrypted binary payload, not obfuscating code.
			$raw = base64_decode( substr( $data, strlen( self::V1_PREFIX ) ), true );
			if ( false === $raw || strlen( $raw ) < 64 ) {
				return null;
			}
			$iv       = substr( $raw, 0, 16 );
			$mac      = substr( $raw, 16, 32 );
			$ct       = substr( $raw, 48 );
			$expected = hash_hmac( 'sha256', $iv . $ct, self::mac_key(), true );
			if ( ! hash_equals( $expected, $mac ) ) {
				return null;
			}
			$pt = openssl_decrypt( $ct, 'AES-256-CBC', self::enc_key(), OPENSSL_RAW_DATA, $iv );
			return false !== $pt ? $pt : null;
		}

		// Legacy unauthenticated format: base64( IV + ciphertext ).
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding encrypted binary payload, not obfuscating code.
		$raw = base64_decode( $data, true );
		if ( false === $raw || strlen( $raw ) < 17 ) {
			return null;
		}
		$pt = openssl_decrypt( substr( $raw, 16 ), 'AES-256-CBC', self::enc_key(), OPENSSL_RAW_DATA, substr( $raw, 0, 16 ) );
		return false !== $pt ? $pt : null;
	}
}
