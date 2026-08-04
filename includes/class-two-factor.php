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
	 * TOTP user-meta key.
	 */
	const TOTP_META = 'dls_totp_secret';

	/**
	 * Whether the current request authenticated via an application password
	 * (a distinct, 2FA-exempt credential).
	 *
	 * @var bool
	 */
	private bool $app_password = false;

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		// Interactive form login: challenge at priority 5 so it runs before
		// Limit_Login::on_success (priority 10) clears the failure counter.
		add_action( 'wp_login', array( $this, 'maybe_challenge' ), 5, 2 );
		add_action( 'login_form_dls_2fa', array( $this, 'handle_submit' ) );

		// Enforce 2FA at the authenticate stage too, so non-interactive credential
		// paths (XML-RPC, REST with a real password) cannot skip the second factor
		// the way the wp_login-only hook would let them.
		add_filter( 'authenticate', array( $this, 'enforce_non_interactive' ), 40, 1 );
		add_action( 'application_password_did_authenticate', array( $this, 'mark_app_password' ) );
	}

	/**
	 * Flag that this request used an application password.
	 */
	public function mark_app_password(): void {
		$this->app_password = true;
	}

	/**
	 * Reject non-interactive credential authentication for 2FA users. Regular
	 * passwords over XML-RPC/REST must not bypass the second factor; application
	 * passwords (a separate, user-created credential) are allowed through.
	 *
	 * @param null|\WP_User|\WP_Error $user Auth result so far.
	 * @return null|\WP_User|\WP_Error
	 */
	public function enforce_non_interactive( $user ) {
		if ( ! ( $user instanceof \WP_User ) || ! $this->user_has_2fa( $user->ID ) ) {
			return $user;
		}
		$non_interactive = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		if ( $non_interactive && ! $this->app_password ) {
			return new \WP_Error(
				'dls_2fa_required',
				__( 'Two-factor authentication is required for this account. Create an application password for programmatic access.', 'dragon-login-security' )
			);
		}
		return $user;
	}

	/**
	 * The decrypted TOTP secret for a user, or null. Fails safe: if a stored
	 * secret cannot be decrypted (e.g. after a wp_salt rotation) it is cleared
	 * and the factor disabled, rather than leaving the user permanently unable
	 * to pass a factor they are still offered.
	 *
	 * @param int $user_id User id.
	 * @return string|null
	 */
	private function totp_secret( int $user_id ): ?string {
		$stored = (string) get_user_meta( $user_id, self::TOTP_META, true );
		if ( '' === $stored ) {
			return null;
		}
		$secret = Crypto::decrypt( $stored );
		if ( null === $secret ) {
			delete_user_meta( $user_id, self::TOTP_META );
			$user = get_userdata( $user_id );
			do_action(
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
				'dls_login_event',
				'2fa.disabled',
				array(
					'object_id'   => $user_id,
					'object_name' => $user ? $user->user_login : (string) $user_id,
					'message'     => __( 'Authenticator secret could not be decrypted and was cleared.', 'dragon-login-security' ),
				)
			);
			return null;
		}
		return $secret;
	}

	/**
	 * Whether a user has a primary second factor (TOTP or passkey). Backup codes
	 * are recovery only, never a standalone factor.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function user_has_2fa( int $user_id ): bool {
		if ( null !== $this->totp_secret( $user_id ) ) {
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
		if ( null !== $this->totp_secret( $user_id ) ) {
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

		/**
		 * Whether to challenge this interactive login for a second factor. Add-ons
		 * (e.g. Login Security Pro's trusted devices) may return false to skip the
		 * challenge for a device already verified. This filter is consulted ONLY on
		 * the interactive form-login path; non-interactive credential auth
		 * (XML-RPC/REST) is rejected for 2FA users regardless, so a trusted-device
		 * skip can never become a non-interactive bypass.
		 *
		 * @param bool     $should Whether to challenge (default true).
		 * @param \WP_User $user   The user who passed primary auth.
		 */
		$should = (bool) apply_filters( 'dls_should_challenge', true, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
		if ( ! $should ) {
			// A trusted device: let the login wp_signon already established stand.
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
			do_action( 'dls_login_event', '2fa.skipped', array( 'object_id' => $user->ID, 'object_name' => $user->user_login ) );
			return;
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
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) {
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

		// The second-factor step shares the brute-force lockout, so a password
		// holder cannot make unlimited code guesses here.
		$limit = new Limit_Login();
		if ( $limit->is_locked( IP::current() ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		if ( $this->validate_factor( $user_id, $method ) ) {
			$limit->clear( IP::current() );
			wp_set_auth_cookie( $user_id, $remember );
			/**
			 * Fires after a second factor is verified and the auth cookie is set.
			 * Add-ons (e.g. Login Security Pro) use this to remember a trusted
			 * device based on their own opt-in field on the challenge form.
			 *
			 * @param int $user_id The now fully-authenticated user.
			 */
			do_action( 'dls_2fa_passed', $user_id ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
			$this->emit( '2fa.passed', $user );
			wp_safe_redirect( $redirect );
			exit;
		}

		// Failure: feed the brute-force machinery (WordPress core's own hook) and
		// re-challenge with a fresh token.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Intentionally firing WordPress core's wp_login_failed.
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
				$secret = $this->totp_secret( $user_id );
				$code   = isset( $_POST['dls_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dls_code'] ) ) : '';
				if ( null === $secret ) {
					return false;
				}
				$step = Provider_TOTP::verify_step( $secret, $code );
				if ( $step < 0 ) {
					return false;
				}
				// Reject replay of a captured code within its validity window.
				$last = (int) get_user_meta( $user_id, 'dls_totp_last_step', true );
				if ( $step <= $last ) {
					return false;
				}
				update_user_meta( $user_id, 'dls_totp_last_step', $step );
				return true;

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
		do_action(
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
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
