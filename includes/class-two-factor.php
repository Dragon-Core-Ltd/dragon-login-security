<?php
/**
 * The 2FA login interrupt. After a correct password, no auth cookie is sent and
 * no session survives until a valid single-use login token AND a valid second
 * factor are presented together. Follows the official Two-Factor plugin's flow:
 * decide at the authenticate stage that the sign-in will be challenged, hold
 * back the cookies wp_signon would send, destroy the session it created, render
 * an interim challenge carrying the token, and only set the cookie once the
 * factor verifies.
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
	 * The user an application password (a distinct, 2FA-exempt credential)
	 * authenticated during the current authenticate run, or 0.
	 *
	 * @var int
	 */
	private int $app_password_user = 0;

	/**
	 * Whether wp_signon() has started, so the next authenticate result belongs
	 * to an interactive sign-in that will set cookies.
	 *
	 * @var bool
	 */
	private bool $in_signon = false;

	/**
	 * The user whose sign-in cookies are being held back pending the second
	 * factor, or 0.
	 *
	 * @var int
	 */
	private int $held_user = 0;

	/**
	 * The challenge decision made for $held_user at the authenticate stage, so
	 * the should-challenge filter is consulted once per sign-in.
	 *
	 * @var array<int,bool>
	 */
	private array $decisions = array();

	/**
	 * Session tokens issued during this request, by user id.
	 *
	 * @var array<int,string[]>
	 */
	private array $issued_tokens = array();

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		// Interactive form login: challenge at priority 5 so it runs before
		// Limit_Login::on_success (priority 10) clears the failure counter.
		add_action( 'wp_login', array( $this, 'maybe_challenge' ), 5, 2 );
		add_action( 'login_form_dragonloginsecurity_2fa', array( $this, 'handle_submit' ) );

		// Enforce 2FA at the authenticate stage too, so non-interactive credential
		// paths (XML-RPC, REST with a real password) cannot skip the second factor
		// the way the wp_login-only hook would let them.
		// One request can run several authenticate passes (XML-RPC multicall), so
		// the application-password marker is reset at the start of each pass and
		// only ever exempts the user it was recorded for.
		add_filter( 'authenticate', array( $this, 'reset_app_password' ), PHP_INT_MIN, 1 );
		add_filter( 'authenticate', array( $this, 'enforce_non_interactive' ), 40, 1 );
		add_action( 'application_password_did_authenticate', array( $this, 'mark_app_password' ), 10, 1 );

		// Hold back the sign-in cookies of a login that will be challenged, and
		// record the session tokens issued so the challenge can destroy them.
		add_action( 'wp_authenticate', array( $this, 'note_signon' ), 10, 0 );
		add_filter( 'authenticate', array( $this, 'hold_cookies_for_challenge' ), PHP_INT_MAX, 1 );
		add_filter( 'send_auth_cookies', array( $this, 'filter_send_auth_cookies' ), PHP_INT_MAX, 4 );
		add_action( 'set_auth_cookie', array( $this, 'record_session_token' ), 10, 6 );
		add_action( 'set_logged_in_cookie', array( $this, 'record_session_token' ), 10, 6 );
		add_action( 'shutdown', array( $this, 'destroy_unchallenged_sessions' ) );
	}

	/**
	 * Note that wp_signon() is running (it fires wp_authenticate just before it
	 * authenticates, then sets the cookies and fires wp_login).
	 */
	public function note_signon(): void {
		$this->in_signon = true;
	}

	/**
	 * At the end of a wp_signon() authenticate pass, decide whether this sign-in
	 * will be challenged and, if so, hold back its cookies.
	 *
	 * @param null|\WP_User|\WP_Error $user Auth result so far (passed through).
	 * @return null|\WP_User|\WP_Error
	 */
	public function hold_cookies_for_challenge( $user ) {
		$in_signon       = $this->in_signon;
		$this->in_signon = false;
		if ( ! $in_signon || ! ( $user instanceof \WP_User ) ) {
			return $user;
		}
		if ( $this->will_challenge( $user ) ) {
			$this->held_user = (int) $user->ID;
		}
		return $user;
	}

	/**
	 * Refuse to send the auth cookies of a sign-in awaiting its second factor.
	 * Clearing cookies (user 0) and every other user's cookies are unaffected.
	 *
	 * @param bool $send       Whether to send the cookies.
	 * @param int  $expire     Cookie expiry (unused).
	 * @param int  $expiration Auth expiry (unused).
	 * @param int  $user_id    User the cookies are for.
	 * @return bool
	 */
	public function filter_send_auth_cookies( $send, $expire = 0, $expiration = 0, $user_id = 0 ) {
		unset( $expire, $expiration );
		if ( $this->held_user > 0 && (int) $user_id === $this->held_user ) {
			return false;
		}
		return $send;
	}

	/**
	 * Record the session token behind an auth cookie issued in this request.
	 *
	 * @param string $cookie     Cookie value.
	 * @param int    $expire     Cookie expiry (unused).
	 * @param int    $expiration Auth expiry (unused).
	 * @param int    $user_id    User id.
	 * @param string $scheme     Cookie scheme (unused).
	 * @param string $token      Session token.
	 */
	public function record_session_token( $cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void {
		unset( $expire, $expiration, $scheme );
		unset( $cookie );
		$user_id = (int) $user_id;
		$token   = (string) $token;
		if ( $user_id <= 0 || '' === $token ) {
			return;
		}
		if ( ! in_array( $token, $this->issued_tokens[ $user_id ] ?? array(), true ) ) {
			$this->issued_tokens[ $user_id ][] = $token;
		}
	}

	/**
	 * Destroy every session issued to a user during this request.
	 *
	 * @param int $user_id User id.
	 */
	private function destroy_issued_sessions( int $user_id ): void {
		$tokens = $this->issued_tokens[ $user_id ] ?? array();
		unset( $this->issued_tokens[ $user_id ] );
		if ( empty( $tokens ) || ! class_exists( '\WP_Session_Tokens' ) ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		foreach ( $tokens as $token ) {
			$manager->destroy( $token );
		}
	}

	/**
	 * Safety net: if a sign-in was held for a challenge but the request ended
	 * without one (a form that never fired wp_login), its sessions go too.
	 */
	public function destroy_unchallenged_sessions(): void {
		if ( $this->held_user > 0 ) {
			$this->destroy_issued_sessions( $this->held_user );
			$this->held_user = 0;
		}
	}

	/**
	 * Whether an interactive sign-in by this user will be challenged. Consults
	 * the should-challenge filter once per user per request.
	 *
	 * @param \WP_User $user User who passed primary auth.
	 * @return bool
	 */
	private function will_challenge( \WP_User $user ): bool {
		$id = (int) $user->ID;
		if ( isset( $this->decisions[ $id ] ) ) {
			return $this->decisions[ $id ];
		}
		if ( ! $this->user_has_2fa( $id ) ) {
			$this->decisions[ $id ] = false;
			return false;
		}

		/**
		 * Whether to challenge this interactive login for a second factor. Add-ons
		 * implementing trusted devices may return false to skip the challenge for
		 * a device already verified. This filter is consulted ONLY on
		 * the interactive form-login path; non-interactive credential auth
		 * (XML-RPC/REST) is rejected for 2FA users regardless, so a trusted-device
		 * skip can never become a non-interactive bypass.
		 *
		 * @param bool     $should Whether to challenge (default true).
		 * @param \WP_User $user   The user who passed primary auth.
		 */
		$this->decisions[ $id ] = (bool) apply_filters( 'dragonloginsecurity_should_challenge', true, $user );
		return $this->decisions[ $id ];
	}

	/**
	 * Remove any auth-bearing Set-Cookie header already queued for this response.
	 * Cookies set outside wp_signon() are not held back at the authenticate
	 * stage; this keeps them off the wire when the challenge follows.
	 */
	private static function withdraw_queued_auth_cookies(): void {
		if ( headers_sent() ) {
			return;
		}
		$queued = headers_list();
		$keep   = self::without_auth_cookies( $queued, self::auth_cookie_names() );
		if ( count( $keep ) === count( $queued ) ) {
			return;
		}
		header_remove( 'Set-Cookie' );
		foreach ( $keep as $line ) {
			if ( 0 === stripos( $line, 'set-cookie:' ) ) {
				header( $line, false );
			}
		}
	}

	/**
	 * Core's auth cookie names.
	 *
	 * @return string[]
	 */
	private static function auth_cookie_names(): array {
		$names = array();
		foreach ( array( 'AUTH_COOKIE', 'SECURE_AUTH_COOKIE', 'LOGGED_IN_COOKIE' ) as $constant ) {
			if ( defined( $constant ) ) {
				$names[] = (string) constant( $constant );
			}
		}
		return $names;
	}

	/**
	 * The header lines minus Set-Cookie lines that carry one of the named
	 * cookies with a value (the expiring, blank ones that clear it are kept).
	 *
	 * @param string[] $headers Header lines as headers_list() returns them.
	 * @param string[] $names   Cookie names to withdraw.
	 * @return string[]
	 */
	public static function without_auth_cookies( array $headers, array $names ): array {
		$out = array();
		foreach ( $headers as $line ) {
			$line = (string) $line;
			if ( 1 === preg_match( '/^set-cookie:\s*([^=;\s]+)=([^;]*)/i', $line, $m )
				&& in_array( $m[1], $names, true )
				&& '' !== trim( rawurldecode( $m[2] ) ) ) {
				continue;
			}
			$out[] = $line;
		}
		return $out;
	}

	/**
	 * Forget any application-password marker at the start of an authenticate pass.
	 *
	 * @param null|\WP_User|\WP_Error $user Auth result so far (passed through).
	 * @return null|\WP_User|\WP_Error
	 */
	public function reset_app_password( $user ) {
		$this->app_password_user = 0;
		return $user;
	}

	/**
	 * Record which user an application password just authenticated.
	 *
	 * @param \WP_User|null $user The user core authenticated.
	 */
	public function mark_app_password( $user = null ): void {
		$this->app_password_user = $user instanceof \WP_User ? (int) $user->ID : 0;
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
		// The marker covers this authenticate pass only.
		$app_password_user       = $this->app_password_user;
		$this->app_password_user = 0;

		if ( ! ( $user instanceof \WP_User ) || ! $this->user_has_2fa( $user->ID ) ) {
			return $user;
		}
		$non_interactive = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		if ( $non_interactive && (int) $user->ID !== $app_password_user ) {
			return new \WP_Error(
				'dragonloginsecurity_2fa_required',
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
				'dragonloginsecurity_login_event',
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
		return Provider_Passkey::is_enrolled_on_network( $user_id );
	}

	/**
	 * Which challenge methods are available for a user.
	 *
	 * @param int $user_id User id.
	 * @return string[]
	 */
	public function available_methods( int $user_id ): array {
		$methods = array();
		if ( WebAuthn::available() && Provider_Passkey::is_enrolled( $user_id ) ) {
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
		if ( ! $this->will_challenge( $user ) ) {
			// A trusted device: let the login wp_signon already established stand.
			do_action(
				'dragonloginsecurity_login_event',
				'2fa.skipped',
				array(
					'object_id'   => $user->ID,
					'object_name' => $user->user_login,
				)
			);
			return;
		}

		// Nothing from the password step may outlive it: its cookies stay off the
		// wire and the sessions it created are destroyed by their exact tokens
		// (the request's own cookie does not name them).
		$this->held_user = 0;
		self::withdraw_queued_auth_cookies();
		$this->destroy_issued_sessions( (int) $user->ID );
		wp_clear_auth_cookie();

		$on_login_screen = function_exists( 'login_header' );
		$redirect        = self::requested_redirect( $on_login_screen );
		$remember        = ! empty( $_REQUEST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-sensitive remember flag; the factor is still required.
		$interim         = $on_login_screen && ! empty( $_REQUEST['interim-login'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display mode only (the session-expiry popup).
		$token           = Login_Token::create( $user->ID );

		if ( ! $on_login_screen ) {
			// Signed in from a form outside wp-login.php (such as a WooCommerce
			// account page): continue the challenge on the login screen, then
			// return to where the sign-in started. wp_redirect, not
			// wp_safe_redirect: the address is built here from site_url(),
			// whose host differs from home_url()'s on a site with WordPress in
			// its own domain, and wp_safe_redirect would swap it for admin_url()
			// with no challenge to show. The redirect_to it carries is re-checked
			// by wp_safe_redirect once the factor passes.
			wp_redirect( self::challenge_url( $token, $redirect, $remember ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Plugin-built login-screen address; see above.
			exit;
		}

		$this->render_challenge( $user, $token, $redirect, $remember, '', $interim );
		exit;
	}

	/**
	 * Where to send the user once the second factor passes.
	 *
	 * On the login screen this is its redirect_to (default: the dashboard).
	 * Elsewhere it is the form's own redirect field (redirect_to, or the
	 * "redirect" field WooCommerce uses), then the page the form was on, then
	 * the home page. Always re-validated by wp_safe_redirect when used.
	 *
	 * @param bool $on_login_screen Whether the sign-in came from wp-login.php.
	 * @return string
	 */
	public static function requested_redirect( bool $on_login_screen ): string {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- The login token is the CSRF secret; this is a UX redirect target only, re-validated by wp_safe_redirect.
		foreach ( $on_login_screen ? array( 'redirect_to' ) : array( 'redirect_to', 'redirect' ) as $field ) {
			if ( isset( $_REQUEST[ $field ] ) && is_string( $_REQUEST[ $field ] ) && '' !== $_REQUEST[ $field ] ) {
				return esc_url_raw( wp_unslash( $_REQUEST[ $field ] ) );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( $on_login_screen ) {
			return admin_url();
		}
		// The raw referer: account forms usually post back to their own page,
		// which wp_get_referer() would discard.
		$referer = wp_validate_redirect( (string) wp_get_raw_referer(), '' );
		return '' !== $referer ? $referer : home_url( '/' );
	}

	/**
	 * The login-screen address that resumes a pending challenge.
	 *
	 * @param string $token    Pending login token (single use).
	 * @param string $redirect Where to go after the factor passes.
	 * @param bool   $remember Remember-me flag.
	 * @return string
	 */
	public static function challenge_url( string $token, string $redirect, bool $remember ): string {
		$url  = site_url( 'wp-login.php?action=dragonloginsecurity_2fa', 'login' );
		$url .= '&dragonloginsecurity_token=' . rawurlencode( $token );
		$url .= '&redirect_to=' . rawurlencode( $redirect );
		if ( $remember ) {
			$url .= '&rememberme=forever';
		}
		return $url;
	}

	/**
	 * Show the challenge for a login handed over from another sign-in form.
	 * The token in the address is spent here and a fresh one goes into the form.
	 *
	 * @return bool Whether the challenge was shown (the caller ends the request).
	 */
	public function resume_challenge(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- The single-use login token IS the anti-bypass secret; verified before anything is shown.
		$token = isset( $_GET['dragonloginsecurity_token'] ) ? sanitize_text_field( wp_unslash( $_GET['dragonloginsecurity_token'] ) ) : '';
		if ( '' === $token ) {
			return false; // Nothing pending: wp-login.php shows its normal form.
		}
		$redirect = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : admin_url();
		$remember = ! empty( $_GET['rememberme'] );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$user_id = Login_Token::user_for( $token );
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user || ! Login_Token::verify( $token, $user_id ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		nocache_headers();
		$this->render_challenge( $user, Login_Token::create( $user_id ), $redirect, $remember, '', false );
		return true;
	}

	/**
	 * Handle the interim 2FA form submission.
	 */
	public function handle_submit(): void {
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) {
			if ( $this->resume_challenge() ) {
				exit;
			}
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The single-use login token IS the CSRF/anti-bypass secret; verified below before any state change.
		$token    = isset( $_POST['dragonloginsecurity_token'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_token'] ) ) : '';
		$user_id  = isset( $_POST['dragonloginsecurity_user'] ) ? absint( wp_unslash( $_POST['dragonloginsecurity_user'] ) ) : 0;
		$method   = isset( $_POST['dragonloginsecurity_method'] ) ? sanitize_key( wp_unslash( $_POST['dragonloginsecurity_method'] ) ) : '';
		$redirect = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : admin_url();
		$remember = ! empty( $_POST['rememberme'] );
		$interim  = ! empty( $_POST['interim-login'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// wp-login.php sets this global only after login_form_* actions run; the
		// login screen chrome reads it.
		$GLOBALS['interim_login'] = $interim; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own display flag for the session-expiry popup.

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
			$limit->clear_user( IP::current(), $user );
			wp_set_auth_cookie( $user_id, $remember );
			/**
			 * Fires after a second factor is verified and the auth cookie is set.
			 * Add-ons use this to remember a trusted device based on their own
			 * opt-in field on the challenge form.
			 *
			 * @param int $user_id The now fully-authenticated user.
			 */
			do_action( 'dragonloginsecurity_2fa_passed', $user_id );
			$this->emit( '2fa.passed', $user );
			if ( $interim ) {
				// The session-expiry popup closes itself on this success screen.
				$GLOBALS['interim_login'] = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own display flag for the session-expiry popup.
				login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'dragon-login-security' ) . '</p>' );
				login_footer();
				exit;
			}
			wp_safe_redirect( $redirect );
			exit;
		}

		// Failure: feed the brute-force machinery (WordPress core's own hook) and
		// re-challenge with a fresh token.

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Intentionally firing WordPress core's own wp_login_failed action so brute-force protection (core and other plugins) counts the failed 2FA step.
		do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'dragonloginsecurity_2fa_failed', __( 'Invalid code.', 'dragon-login-security' ) ) );
		$this->emit( '2fa.failed', $user );
		$this->render_challenge(
			$user,
			Login_Token::create( $user_id ),
			$redirect,
			$remember,
			__( 'That code was not correct. Please try again.', 'dragon-login-security' ),
			$interim
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
				$code   = isset( $_POST['dragonloginsecurity_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_code'] ) ) : '';
				if ( null === $secret ) {
					return false;
				}
				$step = Provider_TOTP::verify_step( $secret, $code );
				if ( $step < 0 ) {
					return false;
				}
				// Reject replay of a captured code within its validity window; the
				// step must be recorded for the code to count as used.
				return Provider_TOTP::consume_step( $user_id, $step );

			case 'backup':
				$code = isset( $_POST['dragonloginsecurity_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_code'] ) ) : '';
				return Provider_Backup_Codes::verify_and_consume( $user_id, $code );

			case 'passkey':
				return Provider_Passkey::validate(
					$user_id,
					array(
						'token'         => isset( $_POST['dragonloginsecurity_wa_token'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_wa_token'] ) ) : '',
						'credential_id' => isset( $_POST['dragonloginsecurity_wa_id'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_wa_id'] ) ) : '',
						'client_data'   => isset( $_POST['dragonloginsecurity_wa_client'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_wa_client'] ) ) : '',
						'auth_data'     => isset( $_POST['dragonloginsecurity_wa_auth'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_wa_auth'] ) ) : '',
						'signature'     => isset( $_POST['dragonloginsecurity_wa_sig'] ) ? sanitize_text_field( wp_unslash( $_POST['dragonloginsecurity_wa_sig'] ) ) : '',
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
	 * @param bool     $interim  Whether this is the session-expiry popup.
	 */
	private function render_challenge( \WP_User $user, string $token, string $redirect, bool $remember, string $error, bool $interim = false ): void {
		$methods = $this->available_methods( $user->ID );
		$wa_args = in_array( 'passkey', $methods, true ) ? WebAuthn::authentication_args( $user->ID ) : array(
			'args'  => null,
			'token' => '',
		);

		$dragonloginsecurity_ctx = array(
			'user'          => $user,
			'token'         => $token,
			'redirect'      => $redirect,
			'remember'      => $remember,
			'error'         => $error,
			'methods'       => $methods,
			'wa_args'       => $wa_args,
			'interim'       => $interim,
			// Guidance only, for a user whose passkeys all live on other sites of
			// the network. It adds no way through this challenge.
			'network_sites' => empty( $methods ) ? Provider_Passkey::other_network_sites( $user->ID, $redirect ) : array(),
		);

		// login_header()/login_footer() are defined by wp-login.php. Sign-ins from
		// any other form are handed over to wp-login.php before reaching here.
		require DRAGONLOGINSECURITY_PLUGIN_DIR . 'admin/views/2fa-challenge.php';
	}

	/**
	 * Emit a suite event.
	 *
	 * @param string   $code Event code.
	 * @param \WP_User $user User.
	 */
	private function emit( string $code, \WP_User $user ): void {
		do_action(
			'dragonloginsecurity_login_event',
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
