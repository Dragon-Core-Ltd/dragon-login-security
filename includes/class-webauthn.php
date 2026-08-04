<?php
/**
 * Thin wrapper over the vendored lbuchs/WebAuthn library: builds the
 * registration/authentication ceremonies, persists challenges in short-TTL
 * transients, and enforces signature-counter monotonicity (cloned-key signal).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WebAuthn ceremony helper.
 */
class WebAuthn {

	/**
	 * Relying-party display name.
	 */
	const RP_NAME = 'Dragon Login Security';

	/**
	 * Challenge transient TTL (seconds).
	 */
	const CHALLENGE_TTL = 300;

	/**
	 * The relying-party id (registrable host) for a site URL.
	 *
	 * @param string $url Site URL.
	 * @return string
	 */
	public static function rp_id_from_url( string $url ): string {
		$host = wp_parse_url( $url, PHP_URL_HOST );
		return is_string( $host ) ? strtolower( $host ) : '';
	}

	/**
	 * Whether an asserted signature counter is acceptable vs the stored one.
	 * A regression signals a cloned authenticator. Both-zero means the
	 * authenticator does not implement a counter, which is permitted.
	 *
	 * @param int $stored   Stored counter.
	 * @param int $asserted Asserted counter.
	 * @return bool
	 */
	public static function sign_count_ok( int $stored, int $asserted ): bool {
		if ( 0 === $stored && 0 === $asserted ) {
			return true;
		}
		return $asserted > $stored;
	}

	/**
	 * URL-safe base64 encode.
	 *
	 * @param string $binary Binary.
	 * @return string
	 */
	public static function b64url_encode( string $binary ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding a binary credential id, not obfuscating code.
		return rtrim( strtr( base64_encode( $binary ), '+/', '-_' ), '=' );
	}

	/**
	 * URL-safe base64 decode.
	 *
	 * @param string $data Encoded.
	 * @return string
	 */
	public static function b64url_decode( string $data ): string {
		$pad = strlen( $data ) % 4;
		if ( $pad ) {
			$data .= str_repeat( '=', 4 - $pad );
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a binary credential id, not obfuscating code.
		$out = base64_decode( strtr( $data, '-_', '+/' ), true );
		return false === $out ? '' : $out;
	}

	/**
	 * Build a fresh lbuchs WebAuthn instance for this site.
	 *
	 * @return \lbuchs\WebAuthn\WebAuthn
	 */
	private static function lib(): \lbuchs\WebAuthn\WebAuthn {
		$rp_id = self::rp_id_from_url( home_url() );
		return new \lbuchs\WebAuthn\WebAuthn( self::RP_NAME, $rp_id, array( 'none' ) );
	}

	/**
	 * A stable binary user handle (does not leak the raw user id).
	 *
	 * @param int $user_id User id.
	 * @return string
	 */
	private static function user_handle( int $user_id ): string {
		return hash( 'sha256', 'dls|' . $user_id, true );
	}

	/**
	 * Registration ceremony arguments; stores the challenge for verification.
	 *
	 * @param int    $user_id    User id.
	 * @param string $user_login Username (relying-party user name).
	 * @return array JSON-serializable PublicKeyCredentialCreationOptions.
	 */
	public static function registration_args( int $user_id, string $user_login ): array {
		$lib     = self::lib();
		$exclude = array_map( array( self::class, 'b64url_decode' ), Credentials::credential_ids_for_user( $user_id ) );
		$args    = $lib->getCreateArgs(
			self::user_handle( $user_id ),
			$user_login,
			$user_login,
			60,
			false,
			true, // require user verification (PIN/biometric).
			null,
			$exclude
		);
		self::store_challenge( 'dls_wa_reg_' . $user_id, $lib->getChallenge()->getBinaryString() );
		return json_decode( wp_json_encode( $args ), true );
	}

	/**
	 * Verify a registration response; returns the credential to persist.
	 *
	 * @param int    $user_id             User id.
	 * @param string $client_data_b64     Base64 clientDataJSON.
	 * @param string $attestation_b64     Base64 attestationObject.
	 * @return array{credential_id:string,public_key:string,sign_count:int}
	 * @throws \Exception On verification failure.
	 */
	public static function verify_registration( int $user_id, string $client_data_b64, string $attestation_b64 ): array {
		$challenge = self::take_challenge( 'dls_wa_reg_' . $user_id );
		$lib       = self::lib();
		$data      = $lib->processCreate(
			self::raw_b64_decode( $client_data_b64 ),
			self::raw_b64_decode( $attestation_b64 ),
			new \lbuchs\WebAuthn\Binary\ByteBuffer( $challenge ),
			true,
			true
		);
		return array(
			'credential_id' => self::b64url_encode( self::to_binary( $data->credentialId ) ),
			'public_key'    => (string) $data->credentialPublicKey,
			'sign_count'    => (int) $data->signatureCounter,
		);
	}

	/**
	 * Authentication ceremony arguments; stores the challenge under a token.
	 *
	 * @param int $user_id User id (second-factor: user already known).
	 * @return array{args:array,token:string}
	 */
	public static function authentication_args( int $user_id ): array {
		$lib   = self::lib();
		$ids   = array_map( array( self::class, 'b64url_decode' ), Credentials::credential_ids_for_user( $user_id ) );
		$args  = $lib->getGetArgs( $ids, 60, true, true, true, true, true, true );
		$token = bin2hex( random_bytes( 16 ) );
		self::store_challenge( 'dls_wa_auth_' . $token, $lib->getChallenge()->getBinaryString() );
		return array(
			'args'  => json_decode( wp_json_encode( $args ), true ),
			'token' => $token,
		);
	}

	/**
	 * Verify an authentication response for a user. Returns true and updates the
	 * signature counter on success.
	 *
	 * @param int    $user_id            User id.
	 * @param string $token              Challenge token from authentication_args.
	 * @param string $credential_id_b64u Base64url credential id.
	 * @param string $client_data_b64    Base64 clientDataJSON.
	 * @param string $auth_data_b64      Base64 authenticatorData.
	 * @param string $signature_b64      Base64 signature.
	 * @return bool
	 */
	public static function verify_authentication( int $user_id, string $token, string $credential_id_b64u, string $client_data_b64, string $auth_data_b64, string $signature_b64 ): bool {
		$challenge = self::take_challenge( 'dls_wa_auth_' . $token );
		if ( '' === $challenge ) {
			return false;
		}

		$cred = Credentials::by_credential_id( $credential_id_b64u );
		if ( ! $cred || (int) $cred['user_id'] !== $user_id ) {
			return false; // Not this user's credential.
		}

		try {
			$lib = self::lib();
			$lib->processGet(
				self::raw_b64_decode( $client_data_b64 ),
				self::raw_b64_decode( $auth_data_b64 ),
				self::raw_b64_decode( $signature_b64 ),
				(string) $cred['public_key'],
				new \lbuchs\WebAuthn\Binary\ByteBuffer( $challenge ),
				(int) $cred['sign_count'],
				true
			);
		} catch ( \Throwable $e ) {
			return false;
		}

		$new = (int) $lib->getSignatureCounter();
		if ( ! self::sign_count_ok( (int) $cred['sign_count'], $new ) ) {
			return false;
		}
		Credentials::update_sign_count( (int) $cred['id'], $new );
		return true;
	}

	/**
	 * Coerce a ByteBuffer|string to a binary string.
	 *
	 * @param mixed $value ByteBuffer or string.
	 * @return string
	 */
	private static function to_binary( $value ): string {
		if ( is_object( $value ) && method_exists( $value, 'getBinaryString' ) ) {
			return $value->getBinaryString();
		}
		return (string) $value;
	}

	/**
	 * Standard base64 decode of a browser-supplied field.
	 *
	 * @param string $data Base64.
	 * @return string
	 */
	private static function raw_b64_decode( string $data ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a browser-supplied binary ceremony field.
		$out = base64_decode( $data, true );
		return false === $out ? '' : $out;
	}

	/**
	 * Persist a challenge (base64 of binary) in a short-TTL transient.
	 *
	 * @param string $key    Transient key.
	 * @param string $binary Binary challenge.
	 */
	private static function store_challenge( string $key, string $binary ): void {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Storing a binary challenge in a text transient.
		set_transient( $key, base64_encode( $binary ), self::CHALLENGE_TTL );
	}

	/**
	 * Consume a stored challenge (single use).
	 *
	 * @param string $key Transient key.
	 * @return string Binary challenge, or '' if absent.
	 */
	private static function take_challenge( string $key ): string {
		$stored = get_transient( $key );
		delete_transient( $key );
		if ( ! is_string( $stored ) || '' === $stored ) {
			return '';
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a stored binary challenge.
		$out = base64_decode( $stored, true );
		return false === $out ? '' : $out;
	}
}
