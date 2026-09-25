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
	 * Users whose sign-in cookies may be sent in this request: the second factor
	 * passed here, or the challenge was skipped by the should-challenge filter.
	 *
	 * @var array<int,bool>
	 */
	private array $cleared = array();

	/**
	 * Users whose password was reset in this request.
	 *
	 * @var array<int,bool>
	 */
	private array $reset_users = array();

	/**
	 * Whether handle_submit() is firing wp_login for a sign-in whose second
	 * factor has just passed.
	 *
	 * @var bool
	 */
	private bool $completing = false;

	/**
	 * When this request started, as a Unix timestamp. Sessions created at or
	 * after it were created by this request.
	 *
	 * @var int
	 */
	private int $request_start;

	/**
	 * The logged-in cookie this request arrived with, kept in case another
	 * plugin removes it from $_COOKIE when the auth cookies are cleared.
	 *
	 * @var string
	 */
	private string $request_cookie = '';

	/**
	 * Per-user record of incorrect second-factor codes.
	 */
	const CODE_FAILURES_META = 'dls_2fa_failures';

	/**
	 * Incorrect codes a user may enter within the window before the second-factor
	 * step is closed to them.
	 */
	const CODE_FAILURE_LIMIT = 5;

	/**
	 * How long the incorrect-code count lasts, in seconds.
	 */
	const CODE_FAILURE_WINDOW = 900;

	/**
	 * Per-user time of the last "second step failed" email, used to send at most
	 * one per CODE_LOCK_MAIL_INTERVAL.
	 */
	const CODE_LOCK_MAILED_META = 'dragonloginsecurity_2fa_lock_mailed';

	/**
	 * Minimum seconds between two "second step failed" emails to one user.
	 */
	const CODE_LOCK_MAIL_INTERVAL = 86400;

	/**
	 * Attempts to store an incorrect-code count before giving up and treating
	 * the account as locked.
	 */
	const CODE_RESERVE_TRIES = 5;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->request_start = time();
	}

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		// Interactive form login: challenge at priority 5 so it runs before
		// Limit_Login::on_success (priority 10) clears the failure counter.
		add_action( 'wp_login', array( $this, 'maybe_challenge' ), 5, 2 );
		add_action( 'login_form_dragonloginsecurity_2fa', array( $this, 'handle_submit' ) );
		add_filter( 'wp_login_errors', array( $this, 'code_lock_message' ), 10, 1 );

		// Enforce 2FA at the authenticate stage too, so non-interactive credential
		// paths (XML-RPC, REST with a real password) cannot skip the second factor
		// the way the wp_login-only hook would let them.
		// One request can run several authenticate passes (XML-RPC multicall), so
		// the application-password marker is reset at the start of each pass and
		// only ever exempts the user it was recorded for.
		add_filter( 'authenticate', array( $this, 'reset_app_password' ), PHP_INT_MIN, 1 );
		add_filter( 'authenticate', array( $this, 'enforce_non_interactive' ), 40, 1 );
		add_action( 'application_password_did_authenticate', array( $this, 'mark_app_password' ), 10, 1 );
		add_filter( 'xmlrpc_login_error', array( $this, 'xmlrpc_login_error' ), 10, 2 );

		// Hold back the sign-in cookies of a login that will be challenged, and
		// record the session tokens issued so the challenge can destroy them.
		add_action( 'wp_authenticate', array( $this, 'note_signon' ), 10, 0 );
		add_filter( 'authenticate', array( $this, 'hold_cookies_for_challenge' ), PHP_INT_MAX, 1 );
		add_filter( 'send_auth_cookies', array( $this, 'filter_send_auth_cookies' ), PHP_INT_MAX, 6 );
		add_action( 'password_reset', array( $this, 'on_password_reset' ), 10, 1 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 1 );
		add_action( 'clear_auth_cookie', array( $this, 'remember_request_cookie' ), PHP_INT_MIN, 0 );
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
		} else {
			$this->cleared[ (int) $user->ID ] = true;
		}
		return $user;
	}

	/**
	 * A password reset proves control of the mailbox, not the second factor, so
	 * no auth cookie may follow it in the same request. It also replaces the
	 * password behind any incorrect codes, so the account's incorrect-code
	 * lock is lifted.
	 *
	 * @param \WP_User|mixed $user User whose password was reset.
	 */
	public function on_password_reset( $user = null ): void {
		if ( $user instanceof \WP_User ) {
			$this->reset_users[ (int) $user->ID ] = true;
			unset( $this->cleared[ (int) $user->ID ] );
			delete_user_meta( (int) $user->ID, self::CODE_FAILURES_META );
		}
	}

	/**
	 * Decide whether auth cookies may be sent. For a user with a second factor
	 * they are sent only when this request passed that factor, the
	 * should-challenge filter skipped it at sign-in, or the cookie renews the
	 * session this request already carries (a password change on the profile
	 * screen). Any other issuer (for example a password-reset form that signs
	 * the user in) is refused and the session it created is destroyed.
	 * Clearing cookies (user 0) and users without a second factor are
	 * unaffected.
	 *
	 * @param bool   $send       Whether to send the cookies.
	 * @param int    $expire     Cookie expiry (unused).
	 * @param int    $expiration Auth expiry (unused).
	 * @param int    $user_id    User the cookies are for.
	 * @param string $scheme     Cookie scheme (unused).
	 * @param string $token      Session token behind the cookies.
	 * @return bool
	 */
	public function filter_send_auth_cookies( $send, $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ) {
		unset( $expire, $expiration, $scheme );
		$user_id = (int) $user_id;
		if ( ! $send || $user_id <= 0 ) {
			return $send;
		}
		if ( $this->held_user > 0 && $user_id === $this->held_user ) {
			return false;
		}
		if ( ! $this->user_has_2fa( $user_id ) ) {
			return $send;
		}
		$token = (string) $token;
		if ( empty( $this->reset_users[ $user_id ] ) ) {
			if ( ! empty( $this->cleared[ $user_id ] ) || $this->renews_request_session( $user_id, $token ) || self::user_switching_allows( $user_id, $this->request_cookie() ) ) {
				return $send;
			}
			/**
			 * Whether to send auth cookies issued for a user with a second factor
			 * outside this plugin's sign-in flow (for example by a user-switching
			 * tool). Default false: such cookies are refused.
			 *
			 * @param bool $allow   Whether to send the cookies.
			 * @param int  $user_id User the cookies are for.
			 */
			if ( true === apply_filters( 'dragonloginsecurity_allow_auth_cookie', false, $user_id ) ) {
				return $send;
			}
		}
		$this->destroy_new_session( $user_id, $token );
		return false;
	}

	/**
	 * Whether a cookie for this token renews the session the request already
	 * carries: the request's own logged-in cookie names the token and that
	 * session is still stored for the user. The browser sent the token, so the
	 * session existed before this request.
	 *
	 * @param int    $user_id User id.
	 * @param string $token   Session token.
	 * @return bool
	 */
	private function renews_request_session( int $user_id, string $token ): bool {
		if ( '' === $token || ! function_exists( 'wp_parse_auth_cookie' ) || ! class_exists( '\WP_Session_Tokens' ) ) {
			return false;
		}
		$raw = $this->request_cookie();
		if ( '' === $raw ) {
			return false;
		}
		$cookie = wp_parse_auth_cookie( $raw, 'logged_in' );
		if ( ! is_array( $cookie ) || ! isset( $cookie['token'] ) || ! hash_equals( (string) $cookie['token'], $token ) ) {
			return false;
		}
		return is_array( \WP_Session_Tokens::get_instance( $user_id )->get( $token ) );
	}

	/**
	 * Keep the request's logged-in cookie before the auth cookies are cleared.
	 */
	public function remember_request_cookie(): void {
		if ( '' === $this->request_cookie ) {
			$this->request_cookie = self::live_request_cookie();
		}
	}

	/**
	 * The logged-in cookie this request arrived with, or ''.
	 *
	 * @return string
	 */
	private function request_cookie(): string {
		$live = self::live_request_cookie();
		return '' !== $live ? $live : $this->request_cookie;
	}

	/**
	 * The logged-in cookie currently in $_COOKIE, or ''.
	 *
	 * @return string
	 */
	private static function live_request_cookie(): string {
		if ( ! defined( 'LOGGED_IN_COOKIE' ) || ! isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) || ! is_string( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
			return '';
		}
		return sanitize_text_field( wp_unslash( $_COOKIE[ LOGGED_IN_COOKIE ] ) );
	}

	/**
	 * Whether the User Switching plugin is switching to this user on behalf of
	 * someone already signed in: either a signed-in user who may switch to the
	 * target, or a switch back to the user whose own sign-in cookie User
	 * Switching kept.
	 *
	 * @param int    $user_id User the cookies are for.
	 * @param string $cookie  The logged-in cookie the request arrived with.
	 * @return bool
	 */
	public static function user_switching_allows( int $user_id, string $cookie ): bool {
		if ( ! class_exists( '\\user_switching' ) || ! function_exists( 'switch_to_user' ) ) {
			return false;
		}

		// Switching back: User Switching validates the original user's kept
		// cookie, which is backed by a session from an earlier sign-in.
		$old = function_exists( 'current_user_switched' ) ? current_user_switched() : false;
		if ( ! ( $old instanceof \WP_User ) && is_callable( array( '\\user_switching', 'get_old_user' ) ) ) {
			$old = \user_switching::get_old_user();
		}
		if ( $old instanceof \WP_User && (int) $old->ID === $user_id ) {
			return true;
		}

		// Switching to: the request's own sign-in cookie names a live session
		// of a user allowed to switch to the target.
		if ( '' === $cookie || ! function_exists( 'wp_validate_auth_cookie' ) || ! function_exists( 'user_can' ) ) {
			return false;
		}
		$switcher = (int) wp_validate_auth_cookie( $cookie, 'logged_in' );
		return $switcher > 0 && $switcher !== $user_id && user_can( $switcher, 'switch_to_user', $user_id ); // phpcs:ignore WordPress.WP.Capabilities.Unknown -- User Switching's own meta capability.
	}

	/**
	 * Destroy a session if this request created it. A session that existed
	 * before the request is left alone.
	 *
	 * @param int    $user_id User id.
	 * @param string $token   Session token.
	 */
	private function destroy_new_session( int $user_id, string $token ): void {
		if ( '' === $token || ! class_exists( '\WP_Session_Tokens' ) ) {
			return;
		}
		$cookie = wp_parse_auth_cookie( $this->request_cookie(), 'logged_in' );
		if ( is_array( $cookie ) && isset( $cookie['token'] ) && hash_equals( (string) $cookie['token'], $token ) ) {
			return; // The session the request arrived with.
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( is_array( $session ) && ( ! isset( $session['login'] ) || (int) $session['login'] >= $this->request_start ) ) {
			$manager->destroy( $token );
		}
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
	 * Replace XML-RPC's generic "Incorrect username or password" reply when the
	 * refusal came from enforce_non_interactive(). That error is only produced
	 * after the account password was accepted, so the reply tells nothing to a
	 * caller who does not know the password.
	 *
	 * @param mixed $error XML-RPC fault core is about to send.
	 * @param mixed $user  The WP_Error returned by wp_authenticate().
	 * @return mixed
	 */
	public function xmlrpc_login_error( $error, $user = null ) {
		if ( ! ( $user instanceof \WP_Error ) || 'dragonloginsecurity_2fa_required' !== $user->get_error_code() || ! class_exists( 'IXR_Error' ) ) {
			return $error;
		}
		return new \IXR_Error( 403, __( 'Accounts with two-factor sign-in must use an application password for XML-RPC, not the account password.', 'dragon-login-security' ) );
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
		if ( $this->completing ) {
			return; // wp_login fired again by handle_submit() once the factor passed.
		}
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

		if ( $this->code_locked( (int) $user->ID ) ) {
			wp_safe_redirect( self::code_locked_url() );
			exit;
		}

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

		// The second-factor step shares the address lockout, and each account
		// also has its own cap on incorrect codes, so neither a new address nor a
		// new password sign-in buys more guesses.
		$limit = new Limit_Login();
		if ( $limit->is_locked( IP::current() ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		// Each code is counted before it is checked, so parallel submissions can
		// never test more codes than the cap allows.
		$attempt = $this->reserve_code_attempt( $user_id );
		if ( $attempt > self::CODE_FAILURE_LIMIT ) {
			wp_safe_redirect( self::code_locked_url() );
			exit;
		}

		if ( $this->validate_factor( $user_id, $method ) ) {
			$limit->clear_user( IP::current(), $user );
			delete_user_meta( $user_id, self::CODE_FAILURES_META );
			$this->cleared[ $user_id ] = true;
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
			$this->fire_login( $user );
			if ( $interim ) {
				// The session-expiry popup closes itself on this success screen.
				$GLOBALS['interim_login'] = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own display flag for the session-expiry popup.
				login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'dragon-login-security' ) . '</p>' );
				login_footer();
				exit;
			}
			/** This filter is documented in wp-login.php */
			$redirect = (string) apply_filters( 'login_redirect', $redirect, $redirect, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core's own login_redirect filter, applied as wp-login.php does after a sign-in.
			wp_safe_redirect( '' !== $redirect ? $redirect : admin_url() );
			exit;
		}

		// Failure: feed the brute-force machinery (WordPress core's own hook) and
		// re-challenge with a fresh token.

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Intentionally firing WordPress core's own wp_login_failed action so brute-force protection (core and other plugins) counts the failed 2FA step.
		do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'dragonloginsecurity_2fa_failed', __( 'Invalid code.', 'dragon-login-security' ) ) );
		$this->emit( '2fa.failed', $user );
		if ( $attempt >= self::CODE_FAILURE_LIMIT ) {
			// Too many incorrect codes: the pending sign-in ends here.
			$this->notify_code_lock( $user );
			wp_safe_redirect( self::code_locked_url() );
			exit;
		}
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
	 * Fire core's wp_login for a sign-in whose second factor has just passed,
	 * so listeners after the challenge (audit logs, alerts, WooCommerce) see
	 * it. The challenge does not run again for it.
	 *
	 * @param \WP_User $user The now fully-authenticated user.
	 */
	private function fire_login( \WP_User $user ): void {
		$this->completing = true;
		try {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core's own wp_login action, fired once the sign-in is complete.
			do_action( 'wp_login', $user->user_login, $user );
		} finally {
			$this->completing = false;
		}
	}

	/**
	 * Whether a user has used up their incorrect second-factor codes. Fails
	 * closed on an unreadable record.
	 *
	 * @param int $user_id User id.
	 * @param int $now     Current time (0 for now).
	 * @return bool
	 */
	public function code_locked( int $user_id, int $now = 0 ): bool {
		$now    = $now > 0 ? $now : time();
		$record = get_user_meta( $user_id, self::CODE_FAILURES_META, true );
		if ( '' === $record || false === $record ) {
			return false;
		}
		if ( ! is_array( $record ) || ! isset( $record['count'], $record['since'] ) ) {
			return true;
		}
		if ( (int) $record['since'] + self::CODE_FAILURE_WINDOW <= $now ) {
			return false;
		}
		return (int) $record['count'] >= self::CODE_FAILURE_LIMIT;
	}

	/**
	 * Count an incorrect code against a user.
	 *
	 * @param int $user_id User id.
	 * @param int $now     Current time (0 for now).
	 * @return bool Whether the count was stored (false means treat as locked).
	 */
	public function record_code_failure( int $user_id, int $now = 0 ): bool {
		return $this->reserve_code_attempt( $user_id, $now ) <= self::CODE_FAILURE_LIMIT;
	}

	/**
	 * Count a code attempt against a user before the code is checked, and
	 * return its number within the current window. The count is written as a
	 * compare-and-swap on the stored record (core's update_user_meta() with a
	 * previous value), retried when another request changed it first, so
	 * parallel requests each get their own number and none is lost. A passed
	 * code deletes the record.
	 *
	 * @param int $user_id User id.
	 * @param int $now     Current time (0 for now).
	 * @return int The attempt number, or CODE_FAILURE_LIMIT + 1 when the
	 *             account is locked or the count could not be stored.
	 */
	public function reserve_code_attempt( int $user_id, int $now = 0 ): int {
		$now    = $now > 0 ? $now : time();
		$closed = self::CODE_FAILURE_LIMIT + 1;

		for ( $try = 0; $try < self::CODE_RESERVE_TRIES; $try++ ) {
			if ( $try > 0 ) {
				// A lost compare-and-swap leaves this request's meta cache holding
				// the stale record, so the retry must read the stored one.
				wp_cache_delete( $user_id, 'user_meta' );
			}
			$record = get_user_meta( $user_id, self::CODE_FAILURES_META, true );

			if ( '' === $record || false === $record ) {
				$first = array(
					'count' => 1,
					'since' => $now,
				);
				if ( add_user_meta( $user_id, self::CODE_FAILURES_META, $first, true ) ) {
					return 1;
				}
				continue;
			}

			if ( ! is_array( $record ) || ! isset( $record['count'], $record['since'] ) ) {
				return $closed;
			}

			if ( (int) $record['since'] + self::CODE_FAILURE_WINDOW <= $now ) {
				$next = array(
					'count' => 1,
					'since' => $now,
				);
			} elseif ( (int) $record['count'] >= self::CODE_FAILURE_LIMIT ) {
				return $closed;
			} else {
				$next = array(
					'count' => (int) $record['count'] + 1,
					'since' => (int) $record['since'],
				);
			}

			if ( update_user_meta( $user_id, self::CODE_FAILURES_META, $next, $record ) ) {
				return $next['count'];
			}
		}

		return $closed;
	}

	/**
	 * Tell a user that someone who knows their password failed the second
	 * step and the step is now paused. At most one email per
	 * CODE_LOCK_MAIL_INTERVAL; a failed send is retried on the next lock.
	 *
	 * @param \WP_User $user User whose second step was locked.
	 * @param int      $now  Current time (0 for now).
	 * @return bool Whether an email was sent.
	 */
	public function notify_code_lock( \WP_User $user, int $now = 0 ): bool {
		$now = $now > 0 ? $now : time();
		if ( '' === (string) $user->user_email ) {
			return false;
		}
		$last = (int) get_user_meta( (int) $user->ID, self::CODE_LOCK_MAILED_META, true );
		if ( $last > 0 && $last + self::CODE_LOCK_MAIL_INTERVAL > $now ) {
			return false;
		}

		$site    = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$minutes = (int) ( self::CODE_FAILURE_WINDOW / 60 );
		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] Unsuccessful two-factor sign-in on your account', 'dragon-login-security' ),
			$site
		);
		$lines = array(
			sprintf(
				/* translators: %s: username. */
				__( 'Hello %s,', 'dragon-login-security' ),
				$user->user_login
			),
			sprintf(
				/* translators: %s: site name. */
				__( 'Someone signed in to %s with your password, then entered incorrect two-factor codes too many times.', 'dragon-login-security' ),
				$site
			),
			sprintf(
				/* translators: %s: number of minutes. */
				_n(
					'To protect your account, the two-factor step is paused for up to %s minute.',
					'To protect your account, the two-factor step is paused for up to %s minutes.',
					$minutes,
					'dragon-login-security'
				),
				number_format_i18n( $minutes )
			),
			sprintf(
				/* translators: %s: password reset address. */
				__( 'If this was not you, someone else knows your password. Change it now: %s', 'dragon-login-security' ),
				wp_lostpassword_url()
			),
			__( 'Resetting your password also ends the pause.', 'dragon-login-security' ),
		);

		$sent = wp_mail( $user->user_email, $subject, implode( "\n\n", $lines ) );
		if ( $sent ) {
			update_user_meta( (int) $user->ID, self::CODE_LOCK_MAILED_META, $now );
		}
		return (bool) $sent;
	}

	/**
	 * The login-screen address shown after too many incorrect codes.
	 *
	 * @return string
	 */
	private static function code_locked_url(): string {
		return add_query_arg( 'dragonloginsecurity_2fa_locked', '1', wp_login_url() );
	}

	/**
	 * Explain the incorrect-code lock on the login screen.
	 *
	 * @param \WP_Error|mixed $errors Login screen messages.
	 * @return \WP_Error|mixed
	 */
	public function code_lock_message( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display flag only.
		if ( $errors instanceof \WP_Error && ! empty( $_GET['dragonloginsecurity_2fa_locked'] ) ) {
			$errors->add( 'dragonloginsecurity_2fa_locked', __( 'Too many incorrect codes. Please try again later.', 'dragon-login-security' ) );
		}
		return $errors;
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
