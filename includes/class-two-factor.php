<?php
/**
 * The 2FA login interrupt. After a correct password, no persistent auth cookie
 * survives until a valid single-use login token AND a valid second factor are
 * presented together. Follows the official Two-Factor plugin's proven flow:
 * clear the cookie wp_signon just set, render an interim challenge carrying the
 * token, and only set the cookie once the factor verifies.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates the second-factor challenge.
 */
class Two_Factor {

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		add_action( 'wp_login', array( $this, 'maybe_challenge' ), 10, 2 );
		add_action( 'login_form_dls_2fa', array( $this, 'handle_submit' ) );
	}

	/**
	 * TOTP user-meta key.
	 */
	const TOTP_META = 'dls_totp_secret';

	/**
	 * Whether a user has a primary second factor (TOTP or passkey). Backup codes
	 * are recovery only, never a standalone factor.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function user_has_2fa( int $user_id ): bool {
		if ( '' !== (string) get_user_meta( $user_id, self::TOTP_META, true ) ) {
			return true;
		}
		return Provider_Passkey::is_enrolled( $user_id );
	}

	/**
	 * Which challenge methods are available for a user.
	 *
	 * @param int $user_id User id.
	 * @return string[]
	 */
	public function available_methods( int $user_id ): array {
		$methods = array();
		if ( Provider_Passkey::is_enrolled( $user_id ) ) {
			$methods[] = 'passkey';
		}
		if ( '' !== (string) get_user_meta( $user_id, self::TOTP_META, true ) ) {
			$methods[] = 'totp';
		}
		if ( Provider_Backup_Codes::remaining( $user_id ) > 0 ) {
			$methods[] = 'backup';
		}
		return $methods;
	}

	/**
	 * On successful primary auth, interrupt for a 2FA user.
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       Authenticated user.
	 */
	public function maybe_challenge( string $user_login, $user = null ): void {
		if ( ! ( $user instanceof \WP_User ) || ! $this->user_has_2fa( $user->ID ) ) {
			return; // No second factor: normal login proceeds.
		}

		// Undo the auth cookie/session wp_signon just established.
		wp_clear_auth_cookie();
		wp_destroy_current_session();

		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The login token is the CSRF secret; this is a UX redirect target only, re-validated by wp_safe_redirect.
		$remember = ! empty( $_REQUEST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-sensitive remember flag; the factor is still required.

		$this->render_challenge( $user, Login_Token::create( $user->ID ), $redirect, $remember, '' );
		exit;
	}

	/**
	 * Handle the interim 2FA form submission.
	 */
	public function handle_submit(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The single-use login token IS the CSRF/anti-bypass secret; verified below before any state change.
		$token    = isset( $_POST['dls_token'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_token'] ) ) : '';
		$user_id  = isset( $_POST['dls_user'] ) ? absint( wp_unslash( $_POST['dls_user'] ) ) : 0;
		$method   = isset( $_POST['dls_method'] ) ? sanitize_key( wp_unslash( $_POST['dls_method'] ) ) : '';
		$redirect = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : admin_url();
		$remember = ! empty( $_POST['rememberme'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$user = get_userdata( $user_id );
		if ( ! $user || ! Login_Token::verify( $token, $user_id ) ) {
			// Bad/expired/replayed token: send back to a clean login.
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		if ( $this->validate_factor( $user_id, $method ) ) {
			wp_set_auth_cookie( $user_id, $remember );
			$this->emit( '2fa.passed', $user );
			wp_safe_redirect( $redirect );
			exit;
		}

		// Failure: feed the brute-force machinery and re-challenge with a fresh token.
		do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'dls_2fa_failed', 'Invalid code.' ) );
		$this->emit( '2fa.failed', $user );
		$this->render_challenge(
			$user,
			Login_Token::create( $user_id ),
			$redirect,
			$remember,
			__( 'That code was not correct. Please try again.', 'dragon-login-security' )
		);
		exit;
	}

	/**
	 * Validate the chosen second factor.
	 *
	 * @param int    $user_id User id.
	 * @param string $method  'totp' | 'backup' | 'passkey'.
	 * @return bool
	 */
	private function validate_factor( int $user_id, string $method ): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Guarded by the verified login token in handle_submit().
		switch ( $method ) {
			case 'totp':
				$secret = Crypto::decrypt( (string) get_user_meta( $user_id, self::TOTP_META, true ) );
				$code   = isset( $_POST['dls_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_code'] ) ) : '';
				return null !== $secret && Provider_TOTP::verify( $secret, $code );

			case 'backup':
				$code = isset( $_POST['dls_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_code'] ) ) : '';
				return Provider_Backup_Codes::verify_and_consume( $user_id, $code );

			case 'passkey':
				return Provider_Passkey::validate(
					$user_id,
					array(
						'token'         => isset( $_POST['dls_wa_token'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_wa_token'] ) ) : '',
						'credential_id' => isset( $_POST['dls_wa_id'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_wa_id'] ) ) : '',
						'client_data'   => isset( $_POST['dls_wa_client'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_wa_client'] ) ) : '',
						'auth_data'     => isset( $_POST['dls_wa_auth'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_wa_auth'] ) ) : '',
						'signature'     => isset( $_POST['dls_wa_sig'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_wa_sig'] ) ) : '',
					)
				);
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		return false;
	}

	/**
	 * Render the interim challenge screen.
	 *
	 * @param \WP_User $user     User.
	 * @param string   $token    Fresh login token.
	 * @param string   $redirect Redirect target.
	 * @param bool     $remember Remember flag.
	 * @param string   $error    Error message (or '').
	 */
	private function render_challenge( \WP_User $user, string $token, string $redirect, bool $remember, string $error ): void {
		$methods = $this->available_methods( $user->ID );
		$wa_args = in_array( 'passkey', $methods, true ) ? WebAuthn::authentication_args( $user->ID ) : array(
			'args'  => null,
			'token' => '',
		);

		$dragonloginsecurity_ctx = array(
			'user'     => $user,
			'token'    => $token,
			'redirect' => $redirect,
			'remember' => $remember,
			'error'    => $error,
			'methods'  => $methods,
			'wa_args'  => $wa_args,
		);

		// login_header()/login_footer() are defined by wp-login.php, which is the
		// active script in both the wp_login and login_form_dls_2fa contexts.
		require DLS_PLUGIN_DIR . 'admin/views/2fa-challenge.php';
	}

	/**
	 * Emit a suite event.
	 *
	 * @param string   $code Event code.
	 * @param \WP_User $user User.
	 */
	private function emit( string $code, \WP_User $user ): void {
		do_action( // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
			'dls_login_event',
			$code,
			array(
				'object_id'   => $user->ID,
				'object_name' => $user->user_login,
				'message'     => '2fa.passed' === $code
					/* translators: %s: username. */
					? sprintf( __( 'Two-factor passed: %s', 'dragon-login-security' ), $user->user_login )
					/* translators: %s: username. */
					: sprintf( __( 'Two-factor failed: %s', 'dragon-login-security' ), $user->user_login ),
			)
		);
	}
}
