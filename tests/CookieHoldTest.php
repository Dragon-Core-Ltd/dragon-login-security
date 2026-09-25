<?php
/**
 * A sign-in awaiting its second factor gets no auth cookie and keeps no session.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class CookieHoldTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                     = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']       = array();
		$GLOBALS['dls_test_filters']         = array();
		$GLOBALS['dls_test_sessions']        = array();
		$GLOBALS['dls_test_filter_override'] = array();
		$GLOBALS['dls_test_users']           = array(
			1 => new \WP_User( 1, 'owner' ),
			2 => new \WP_User( 2, 'editor' ),
		);
		$_REQUEST                            = array();
		// User 1 has an authenticator app; user 2 has no second factor.
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_filter_override'] = array();
		$_REQUEST                            = array();
	}

	/**
	 * Walk the steps core's wp_signon() takes: wp_authenticate, the authenticate
	 * filter (its last callback), then wp_set_auth_cookie(), which creates a
	 * session and fires set_auth_cookie/set_logged_in_cookie before asking
	 * send_auth_cookies whether to send them.
	 *
	 * @param Two_Factor $tf        Gate.
	 * @param int        $user_id   User signing in.
	 * @param bool       $in_signon Whether wp_signon() started this pass.
	 * @return array{token:string,send:bool}
	 */
	private function sign_in( Two_Factor $tf, int $user_id, bool $in_signon = true ): array {
		if ( $in_signon ) {
			$tf->note_signon();
		}
		$user  = $tf->hold_cookies_for_challenge( get_userdata( $user_id ) );
		$token = \WP_Session_Tokens::get_instance( $user->ID )->create( time() + 3600 );
		$tf->record_session_token( 'cookie', 0, time() + 3600, $user->ID, 'auth', $token );
		$tf->record_session_token( 'cookie', 0, time() + 3600, $user->ID, 'logged_in', $token );
		return array(
			'token' => $token,
			'send'  => (bool) $tf->filter_send_auth_cookies( true, 0, time() + 3600, $user->ID, 'auth', $token ),
		);
	}

	public function test_hooks_wrap_the_whole_signon(): void {
		( new Two_Factor() )->hook();
		$seen = array();
		foreach ( $GLOBALS['dls_test_filters'] as $filter ) {
			if ( is_array( $filter[1] ) ) {
				$seen[ $filter[0] . ':' . $filter[1][1] ] = $filter[2] ?? 10;
			}
		}
		$this->assertSame( PHP_INT_MAX, $seen['authenticate:hold_cookies_for_challenge'] );
		$this->assertSame( PHP_INT_MAX, $seen['send_auth_cookies:filter_send_auth_cookies'] );
	}

	public function test_challenged_signin_sends_no_auth_cookie(): void {
		$tf = new Two_Factor();
		$this->assertFalse( $this->sign_in( $tf, 1 )['send'] );
		// Clearing cookies (user 0) and other users' cookies are unaffected.
		$this->assertTrue( $tf->filter_send_auth_cookies( true, 0, 0, 0 ) );
		$this->assertTrue( $tf->filter_send_auth_cookies( true, 0, 0, 2 ) );
	}

	public function test_signin_without_a_second_factor_is_untouched(): void {
		$this->assertTrue( $this->sign_in( new Two_Factor(), 2 )['send'] );
	}

	public function test_cookie_issued_outside_signon_is_refused_for_a_2fa_user(): void {
		// A form that calls wp_set_auth_cookie() directly (a password reset that
		// signs the user in) never passed the second factor.
		$tf     = new Two_Factor();
		$signed = $this->sign_in( $tf, 1, false );
		$this->assertFalse( $signed['send'] );
		$this->assertFalse( \WP_Session_Tokens::get_instance( 1 )->verify( $signed['token'] ), 'the session it created survived' );
		// A user without a second factor is unaffected.
		$this->assertTrue( $this->sign_in( $tf, 2, false )['send'] );
	}

	public function test_password_reset_then_cookie_is_refused(): void {
		$tf = new Two_Factor();
		$tf->on_password_reset( get_userdata( 1 ) );
		$token = \WP_Session_Tokens::get_instance( 1 )->create( time() + 3600 );
		$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, time() + 3600, 1, 'auth', $token ) );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 1 )->get_all() );
		// Even a cleared sign-in in the same request does not survive a reset.
		$tf2 = new Two_Factor();
		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_should_challenge'] = static function () {
			return false;
		};
		$this->assertTrue( $this->sign_in( $tf2, 1 )['send'] );
		$tf2->on_password_reset( get_userdata( 1 ) );
		$this->assertFalse( $tf2->filter_send_auth_cookies( true, 0, 0, 1, 'auth', 'x' ) );
	}

	public function test_renewing_the_requests_own_session_is_allowed(): void {
		// The profile screen re-issues the cookie for the session the request
		// already carries when the user changes their password.
		$token = \WP_Session_Tokens::get_instance( 1 )->create( time() + 3600 );
		foreach ( $GLOBALS['dls_test_sessions'][1] as &$session ) {
			$session['login'] = time() - 60;
		}
		unset( $session );
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'owner|' . ( time() + 3600 ) . '|' . $token . '|hmac';
		try {
			$tf = new Two_Factor();
			$this->assertTrue( $tf->filter_send_auth_cookies( true, 0, 0, 1, 'auth', $token ) );
			// A new session for the same user is not a renewal, and is removed.
			$fresh = \WP_Session_Tokens::get_instance( 1 )->create( time() + 3600 );
			$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, 0, 1, 'auth', $fresh ) );
			$this->assertFalse( \WP_Session_Tokens::get_instance( 1 )->verify( $fresh ) );
			// A token the request's cookie does not name is not a renewal.
			$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, 0, 1, 'auth', 'gone' ) );
			// A refusal never destroys a session from an earlier request.
			$this->assertTrue( \WP_Session_Tokens::get_instance( 1 )->verify( $token ) );
			// A plugin that removes the cookie from $_COOKIE when the auth
			// cookies are cleared does not break the renewal.
			$_COOKIE[ LOGGED_IN_COOKIE ] = 'owner|' . ( time() + 3600 ) . '|' . $token . '|hmac';
			$tf2                         = new Two_Factor();
			$tf2->remember_request_cookie();
			unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
			$this->assertTrue( $tf2->filter_send_auth_cookies( true, 0, 0, 1, 'auth', $token ) );
		} finally {
			unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		}
	}

	public function test_allow_filter_opens_the_gate(): void {
		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_allow_auth_cookie'] = static function ( $allow, $user_id ) {
			return 1 === $user_id;
		};
		$this->assertTrue( ( new Two_Factor() )->filter_send_auth_cookies( true, 0, 0, 1, 'auth', 'x' ) );
	}

	public function test_hook_reads_the_token(): void {
		( new Two_Factor() )->hook();
		$args = array();
		foreach ( $GLOBALS['dls_test_filters'] as $filter ) {
			if ( is_array( $filter[1] ) ) {
				$args[ $filter[0] . ':' . $filter[1][1] ] = $filter[3] ?? 1;
			}
		}
		$this->assertSame( 6, $args['send_auth_cookies:filter_send_auth_cookies'] );
	}

	public function test_trusted_device_skip_keeps_cookies_and_asks_once(): void {
		$asked = 0;

		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_should_challenge'] = static function () use ( &$asked ) {
			++$asked;
			return false;
		};
		$tf     = new Two_Factor();
		$signed = $this->sign_in( $tf, 1 );
		$this->assertTrue( $signed['send'] );
		$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
		$this->assertTrue( \WP_Session_Tokens::get_instance( 1 )->verify( $signed['token'] ) );
		$this->assertSame( 1, $asked );
	}

	public function test_unchallenged_held_session_is_destroyed_at_shutdown(): void {
		$tf     = new Two_Factor();
		$signed = $this->sign_in( $tf, 1 );
		$tf->destroy_unchallenged_sessions();
		$this->assertFalse( \WP_Session_Tokens::get_instance( 1 )->verify( $signed['token'] ) );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 1 )->get_all() );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_challenge_destroys_exactly_the_new_sessions(): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'class DLS_Test_Redirect extends \Exception {} function wp_safe_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_clear_auth_cookie() { $GLOBALS["dls_cleared"] = true; }' );

		$existing = \WP_Session_Tokens::get_instance( 1 )->create( time() + 3600 );
		foreach ( array( '', 'forever' ) as $remember ) {
			$_REQUEST = array( 'rememberme' => $remember );
			$tf       = new Two_Factor();
			$signed   = $this->sign_in( $tf, 1 );
			$this->assertFalse( $signed['send'] );
			try {
				$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
				$this->fail( 'no challenge' );
			} catch ( \DLS_Test_Redirect $r ) {
				$this->assertStringContainsString( 'action=dragonloginsecurity_2fa', $r->getMessage() );
			}
			$sessions = \WP_Session_Tokens::get_instance( 1 );
			$this->assertFalse( $sessions->verify( $signed['token'] ), 'the password-step session survived' );
			// A session the user already had elsewhere is not theirs to lose.
			$this->assertTrue( $sessions->verify( $existing ) );
			$this->assertCount( 1, $sessions->get_all() );
			$this->assertTrue( $GLOBALS['dls_cleared'] );
			// Nothing is left for the shutdown safety net.
			$tf->destroy_unchallenged_sessions();
			$this->assertCount( 1, $sessions->get_all() );
		}
	}

	public function test_queued_auth_cookies_are_withdrawn_but_clearing_ones_kept(): void {
		$names   = array( 'wordpress_abc', 'wordpress_sec_abc', 'wordpress_logged_in_abc' );
		$headers = array(
			'X-Frame-Options: SAMEORIGIN',
			'Set-Cookie: wordpress_abc=owner%7C1%7Ctok%7Chmac; path=/wp-admin; HttpOnly',
			'Set-Cookie: wordpress_logged_in_abc=owner%7C1%7Ctok%7Chmac; path=/; HttpOnly',
			'set-cookie: wordpress_sec_abc=owner%7C1%7Ctok%7Chmac; path=/; secure',
			'Set-Cookie: wordpress_logged_in_abc=%20; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/',
			'Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/',
			'Set-Cookie: wordpress_abcdef=keep; path=/',
		);
		$this->assertSame(
			array(
				'X-Frame-Options: SAMEORIGIN',
				'Set-Cookie: wordpress_logged_in_abc=%20; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/',
				'Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/',
				'Set-Cookie: wordpress_abcdef=keep; path=/',
			),
			Two_Factor::without_auth_cookies( $headers, $names )
		);
	}
}
