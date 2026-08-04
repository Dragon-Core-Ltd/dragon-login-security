<?php
/**
 * AJAX enrolment endpoints (profile screen). All handlers require the dls_ajax
 * nonce and the edit_user capability on the target user.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles TOTP setup, passkey registration/removal, and backup codes.
 */
class Ajax {

	/**
	 * Register handlers.
	 */
	public function hook(): void {
		$actions = array(
			'dls_totp_setup',
			'dls_totp_confirm',
			'dls_totp_disable',
			'dls_passkey_options',
			'dls_passkey_register',
			'dls_passkey_remove',
			'dls_backup_generate',
			'dls_backup_confirm',
		);
		foreach ( $actions as $action ) {
			add_action( 'wp_ajax_' . $action, array( $this, str_replace( 'dls_', '', $action ) ) );
		}
	}

	/**
	 * Shared guard: nonce + edit_user on the target. Returns the target id.
	 *
	 * @return int
	 */
	private function guard(): int {
		check_ajax_referer( 'dls_ajax', 'nonce' );
		$target = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : get_current_user_id(); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified above.
		if ( ! current_user_can( 'edit_user', $target ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'dragon-login-security' ) ), 403 );
		}
		return $target;
	}

	/**
	 * Enrolment guard: nonce, and the target MUST be the current user. Setting up
	 * a factor for someone else would let an admin plant their own authenticator
	 * as another user's second factor, or read that user's backup codes.
	 *
	 * @return int
	 */
	private function guard_self(): int {
		check_ajax_referer( 'dls_ajax', 'nonce' );
		$me     = get_current_user_id();
		$target = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : $me; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified above.
		if ( 0 === $me || $target !== $me ) {
			wp_send_json_error( array( 'message' => __( 'You can only set up two-factor for your own account.', 'dragon-login-security' ) ), 403 );
		}
		return $me;
	}

	/**
	 * Emit a login-security event.
	 *
	 * @param string $code    Code.
	 * @param int    $user_id User id.
	 */
	private function emit( string $code, int $user_id ): void {
		$user = get_userdata( $user_id );
		do_action(
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
			'dls_login_event',
			$code,
			array(
				'object_id'   => $user_id,
				'object_name' => $user ? $user->user_login : (string) $user_id,
			)
		);
	}

	/**
	 * Begin TOTP setup: generate a pending secret, return provisioning data.
	 */
	public function totp_setup(): void {
		$user_id = $this->guard_self();
		$secret  = Provider_TOTP::generate_secret();
		set_transient( 'dls_totp_pending_' . $user_id, Crypto::encrypt( $secret ), 10 * MINUTE_IN_SECONDS );

		$user = get_userdata( $user_id );
		wp_send_json_success(
			array(
				'secret' => $secret,
				'uri'    => Provider_TOTP::provisioning_uri( $secret, $user ? $user->user_login : (string) $user_id, get_bloginfo( 'name' ) ),
			)
		);
	}

	/**
	 * Confirm TOTP: verify a code against the pending secret, then enable it.
	 */
	public function totp_confirm(): void {
		$user_id = $this->guard_self();
		$pending = get_transient( 'dls_totp_pending_' . $user_id );
		$secret  = is_string( $pending ) ? Crypto::decrypt( $pending ) : null;
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().

		if ( null === $secret || ! Provider_TOTP::verify( $secret, $code ) ) {
			wp_send_json_error( array( 'message' => __( 'That code was not correct.', 'dragon-login-security' ) ) );
		}

		update_user_meta( $user_id, Two_Factor::TOTP_META, Crypto::encrypt( $secret ) );
		delete_transient( 'dls_totp_pending_' . $user_id );
		$this->emit( '2fa.enrolled', $user_id );
		wp_send_json_success( array( 'message' => __( 'Authenticator app enabled.', 'dragon-login-security' ) ) );
	}

	/**
	 * Disable TOTP.
	 */
	public function totp_disable(): void {
		$user_id = $this->guard();
		delete_user_meta( $user_id, Two_Factor::TOTP_META );
		$this->emit( '2fa.disabled', $user_id );
		wp_send_json_success();
	}

	/**
	 * Return passkey registration options.
	 */
	public function passkey_options(): void {
		$user_id = $this->guard_self();
		$user    = get_userdata( $user_id );
		wp_send_json_success( WebAuthn::registration_args( $user_id, $user ? $user->user_login : (string) $user_id ) );
	}

	/**
	 * Verify + store a passkey registration.
	 */
	public function passkey_register(): void {
		$user_id = $this->guard_self();
		$client  = isset( $_POST['client_data'] ) ? sanitize_text_field( wp_unslash( $_POST['client_data'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().
		$attest  = isset( $_POST['attestation'] ) ? sanitize_text_field( wp_unslash( $_POST['attestation'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().
		$label   = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().

		try {
			$cred = WebAuthn::verify_registration( $user_id, $client, $attest );
		} catch ( \Throwable $e ) {
			wp_send_json_error( array( 'message' => __( 'Passkey registration failed.', 'dragon-login-security' ) ) );
		}

		$transports = isset( $_POST['transports'] ) ? sanitize_text_field( wp_unslash( $_POST['transports'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().
		Credentials::add( $user_id, $cred['credential_id'], $cred['public_key'], $cred['sign_count'], $transports, '' === $label ? __( 'Passkey', 'dragon-login-security' ) : $label );
		$this->emit( 'passkey.added', $user_id );
		wp_send_json_success( array( 'message' => __( 'Passkey added.', 'dragon-login-security' ) ) );
	}

	/**
	 * Remove a passkey (owner-scoped).
	 */
	public function passkey_remove(): void {
		$user_id = $this->guard();
		$id      = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in guard().
		if ( $id && Credentials::delete( $id, $user_id ) ) {
			$this->emit( 'passkey.removed', $user_id );
			wp_send_json_success();
		}
		wp_send_json_error( array( 'message' => __( 'Could not remove passkey.', 'dragon-login-security' ) ) );
	}

	/**
	 * Generate + store backup codes; return the plaintext once.
	 */
	public function backup_generate(): void {
		$user_id = $this->guard_self();
		$codes   = Provider_Backup_Codes::generate( 10 );
		Provider_Backup_Codes::store( $user_id, $codes );
		delete_user_meta( $user_id, 'dls_backup_codes_confirmed' );
		wp_send_json_success( array( 'codes' => $codes ) );
	}

	/**
	 * Mark backup codes as downloaded/confirmed (satisfies enforcement policy).
	 */
	public function backup_confirm(): void {
		$user_id = $this->guard_self();
		update_user_meta( $user_id, 'dls_backup_codes_confirmed', 1 );
		wp_send_json_success();
	}
}
