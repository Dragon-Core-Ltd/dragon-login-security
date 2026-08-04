<?php
/**
 * Passkey (WebAuthn) second-factor provider. Delegates the ceremony to the
 * WebAuthn wrapper; a user is "enrolled" once they have at least one credential.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Passkey provider.
 */
class Provider_Passkey {

	/**
	 * Whether a user has at least one passkey.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_enrolled( int $user_id ): bool {
		return ! empty( Credentials::for_user( $user_id ) );
	}

	/**
	 * Validate a passkey authentication response during a 2FA challenge.
	 *
	 * @param int   $user_id  User id.
	 * @param array $response Fields: token, credential_id, client_data, auth_data, signature.
	 * @return bool
	 */
	public static function validate( int $user_id, array $response ): bool {
		return WebAuthn::verify_authentication(
			$user_id,
			(string) ( $response['token'] ?? '' ),
			(string) ( $response['credential_id'] ?? '' ),
			(string) ( $response['client_data'] ?? '' ),
			(string) ( $response['auth_data'] ?? '' ),
			(string) ( $response['signature'] ?? '' )
		);
	}
}
