<?php
/**
 * Scenario hunt: every path that can produce a session or an auth cookie for a
 * two-factor user, modelled the way core drives the hooks.
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
class ScenarioSessionGateTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                     = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']       = array();
		$GLOBALS['dls_test_sessions']        = array();
		$GLOBALS['dls_test_filter_override'] = array();
		$GLOBALS['dls_test_actions_fired']   = array();
		$GLOBALS['dls_test_mail']            = array();
		$GLOBALS['dls_test_mail_result']     = true;
		$GLOBALS['dls_test_multisite']       = false;
		$GLOBALS['dls_test_blog_stack']      = array();
		$GLOBALS['dls_test_current_blog']    = 1;
		$owner                               = new \WP_User( 1, 'owner' );
		$owner->user_email                   = 'owner@example.test';
		$editor                              = new \WP_User( 2, 'editor' );
		$editor->user_email                  = 'editor@example.test';
		$GLOBALS['dls_test_users']           = array(
			1 => $owner,
			2 => $editor,
			3 => new \WP_User( 3, 'plain' ),
		);
		// Users 1 and 2 have an authenticator app; user 3 has no second factor.
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		update_user_meta( 2, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		$_REQUEST = array();
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_filter_override'] = array();
		$GLOBALS['dls_test_multisite']       = false;
		$GLOBALS['dls_test_blog_stack']      = array();
		$GLOBALS['dls_test_current_blog']    = 1;
		$_REQUEST                            = array();
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	}

	/**
	 * Core's wp_set_auth_cookie() for a user: create the session, fire the
	 * set_*_cookie actions, then ask send_auth_cookies.
	 *
	 * @param Two_Factor $tf      Gate.
	 * @param int        $user_id User.
	 * @return array{token:string,send:bool}
	 */
	private function issue( Two_Factor $tf, int $user_id ): array {
		$token = \WP_Session_Tokens::get_instance( $user_id )->create( time() + 3600 );
		$tf->record_session_token( 'c', 0, 0, $user_id, 'auth', $token );
		$tf->record_session_token( 'c', 0, 0, $user_id, 'logged_in', $token );
		return array(
			'token' => $token,
			'send'  => (bool) $tf->filter_send_auth_cookies( true, 0, time() + 3600, $user_id, 'auth', $token ),
		);
	}

	/**
	 * An existing session from an earlier request, named by the request cookie.
	 *
	 * @param int    $user_id User.
	 * @param string $login   Username in the cookie.
	 * @return string Its token.
	 */
	private function existing_session( int $user_id, string $login ): string {
		$token = \WP_Session_Tokens::get_instance( $user_id )->create( time() + 3600 );
		$GLOBALS['dls_test_sessions'][ $user_id ][ hash( 'sha256', $token ) ]['login'] = time() - 600;
		$_COOKIE[ LOGGED_IN_COOKIE ] = $login . '|' . ( time() + 3600 ) . '|' . $token . '|hmac';
		return $token;
	}

	/**
	 * wp-login.php calls wp_signon() with no credentials on every load, and
	 * core's wp_authenticate_cookie (authenticate, priority 30) answers that
	 * pass with the user the request's own valid cookie names. On a
	 * subdirectory multisite (core sets ADMIN_COOKIE_PATH = SITECOOKIEPATH) or
	 * any site with ADMIN_COOKIE_PATH '/', the auth cookie reaches wp-login.php
	 * and that is exactly what happens when a signed-in user opens it. Core
	 * re-issues the cookie and sends them to the dashboard; it is not a new
	 * sign-in, so the second factor (already passed for that session) must not
	 * be asked again and the valid cookies must not be cleared.
	 */
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_cookie_reauthentication_inside_wp_signon_is_not_a_fresh_sign_in(): void {
		$old = $this->existing_session( 1, 'owner' );
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'function wp_validate_auth_cookie( $cookie = "", $scheme = "" ) { $c = "" !== $cookie ? $cookie : ( $_COOKIE[ LOGGED_IN_COOKIE ] ?? "" ); return $c === $GLOBALS["scn_valid_cookie"] ? 1 : false; } class DLS_Test_Redirect extends \Exception {} function wp_safe_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_clear_auth_cookie() { $GLOBALS["scn_cleared"] = true; }' );
		$GLOBALS['scn_valid_cookie'] = $_COOKIE[ LOGGED_IN_COOKIE ];
		$GLOBALS['scn_cleared']      = false;

		$tf = new Two_Factor();
		$tf->note_signon();
		// wp_signon() with empty credentials: the filter runs with '' and ''.
		$tf->hold_cookies_for_challenge( get_userdata( 1 ), '', '' );
		$issued = $this->issue( $tf, 1 );

		$this->assertTrue( $issued['send'], 'a cookie re-authentication of the request\'s own valid session was held back as if it were a password sign-in' );
		try {
			$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
		} catch ( \DLS_Test_Redirect $r ) {
			$this->fail( 'the signed-in user was challenged again: ' . $r->getMessage() );
		}
		$this->assertFalse( $GLOBALS['scn_cleared'], 'the valid cookies the request arrived with were cleared' );
		$this->assertTrue( \WP_Session_Tokens::get_instance( 1 )->verify( $old ) );
	}

	/**
	 * The trusted-device seam must fail closed: only an explicit false may
	 * skip the challenge. A callback that forgets to return (null) is a broken
	 * add-on, not a decision to skip the second factor. The sibling
	 * dragonloginsecurity_allow_auth_cookie filter already requires `true ===`.
	 */
	public function test_should_challenge_returning_null_still_challenges(): void {
		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_should_challenge'] = static function () {
			return null;
		};
		$tf = new Two_Factor();
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$this->assertFalse( $this->issue( $tf, 1 )['send'], 'a null from the should-challenge filter skipped the second factor' );
	}

	public function test_challenge_decided_for_a_while_cookies_are_issued_for_b(): void {
		$tf = new Two_Factor();
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$this->assertFalse( $this->issue( $tf, 1 )['send'] );

		// A plugin now issues cookies for another two-factor user in the same
		// request, outside wp_signon(): refused, and its session removed.
		$b = $this->issue( $tf, 2 );
		$this->assertFalse( $b['send'] );
		$this->assertFalse( \WP_Session_Tokens::get_instance( 2 )->verify( $b['token'] ) );
		// A user without a second factor is unaffected.
		$this->assertTrue( $this->issue( $tf, 3 )['send'] );
	}

	public function test_two_sign_ins_in_one_request_keep_their_own_decisions(): void {
		$tf = new Two_Factor();
		// First wp_signon(): a user without a second factor is cleared.
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 3 ) );
		$this->assertTrue( $this->issue( $tf, 3 )['send'] );
		// Second wp_signon(): a two-factor user is held; the first is still clear.
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$held = $this->issue( $tf, 1 );
		$this->assertFalse( $held['send'] );
		$this->assertTrue( $this->issue( $tf, 3 )['send'] );
		// The same user signing in again in this request is held again, and the
		// should-challenge filter is not asked a second time.
		$asked = 0;
		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_should_challenge'] = static function () use ( &$asked ) {
			++$asked;
			return true;
		};
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$this->assertFalse( $this->issue( $tf, 1 )['send'] );
		$this->assertSame( 0, $asked );
		// At shutdown every held session goes.
		$tf->destroy_unchallenged_sessions();
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 1 )->get_all() );
		$this->assertCount( 2, \WP_Session_Tokens::get_instance( 3 )->get_all() );
	}

	public function test_a_token_the_request_cookie_names_for_another_user_is_not_a_renewal(): void {
		// The request's cookie names user 2's session; a plugin issues a cookie
		// for user 1 with that same token (wp_set_auth_cookie accepts a token).
		$token = $this->existing_session( 2, 'editor' );
		$tf    = new Two_Factor();
		$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, 0, 1, 'auth', $token ) );
		// User 2's session is not theirs to lose, and user 1 has none.
		$this->assertTrue( \WP_Session_Tokens::get_instance( 2 )->verify( $token ) );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 1 )->get_all() );
	}

	public function test_malformed_or_non_string_request_cookie_still_refuses_and_destroys(): void {
		// (An array-valued cookie is not modelled: core's own wp_parse_auth_cookie
		// explode()s it and fatals on every request before this plugin runs.)
		foreach ( array( 'owner|only-three|parts', '', 'owner|1|tok|hmac|extra' ) as $cookie ) {
			$_COOKIE[ LOGGED_IN_COOKIE ] = $cookie;
			$tf                          = new Two_Factor();
			$tf->remember_request_cookie();
			$issued = $this->issue( $tf, 1 );
			$this->assertFalse( $issued['send'] );
			$this->assertFalse( \WP_Session_Tokens::get_instance( 1 )->verify( $issued['token'] ), 'the new session survived' );
		}
	}

	public function test_password_reset_for_something_that_is_not_a_user_is_ignored(): void {
		$tf = new Two_Factor();
		foreach ( array( 1, '1', null, (object) array( 'ID' => 1 ), array( 'ID' => 1 ) ) as $not_a_user ) {
			$tf->on_password_reset( $not_a_user );
		}
		// Nothing was marked reset: a cleared sign-in in this request still sends.
		$GLOBALS['dls_test_filter_override']['dragonloginsecurity_should_challenge'] = static function () {
			return false;
		};
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$this->assertTrue( $this->issue( $tf, 1 )['send'] );
		// And a real reset still wins afterwards.
		$tf->on_password_reset( get_userdata( 1 ) );
		$this->assertFalse( $this->issue( $tf, 1 )['send'] );
	}

	public function test_int_and_junk_totp_meta_fail_closed(): void {
		foreach ( array( 123, 'O:8:"stdClass":0:{}', 'a:1:{i:0;s:1:"x";}' ) as $junk ) {
			$GLOBALS['dls_test_user_meta'][1][ Two_Factor::TOTP_META ] = $junk;
			$GLOBALS['dls_test_user_meta'][1][ Two_Factor::TOTP_UNREADABLE_MAILED_META ] = '';
			$GLOBALS['dls_test_mail']                                  = array();
			$tf                                                        = new Two_Factor();
			$this->assertTrue( $tf->user_has_2fa( 1 ), 'a stored but unreadable secret must keep the factor required' );
			$this->assertSame( 'unreadable', $tf->totp_state( 1 ) );
			$this->assertNotContains( 'totp', $tf->available_methods( 1 ) );
			$this->assertCount( 1, $GLOBALS['dls_test_mail'], 'told once' );
		}
	}

	/**
	 * A serialized array in the TOTP row (a botched import or a plugin writing
	 * the wrong shape) is unserialized by get_user_meta(). (string) of an array
	 * is a PHP warning on the sign-in path, and with display_errors on that
	 * output lands before the cookie headers.
	 */
	public function test_array_totp_meta_is_unreadable_without_a_php_warning(): void {
		$GLOBALS['dls_test_user_meta'][1][ Two_Factor::TOTP_META ] = array( 'secret' => 'ABC' );
		$tf                                                        = new Two_Factor();
		set_error_handler(
			static function ( $no, $str ) {
				throw new \ErrorException( $str );
			}
		);
		try {
			$this->assertTrue( $tf->user_has_2fa( 1 ) );
			$this->assertSame( 'unreadable', $tf->totp_state( 1 ) );
		} catch ( \ErrorException $e ) {
			$this->fail( 'PHP warning while reading an array-shaped TOTP secret: ' . $e->getMessage() );
		} finally {
			restore_error_handler();
		}
	}

	public function test_totp_replay_counter_and_code_lock_are_network_wide(): void {
		$GLOBALS['dls_test_multisite'] = true;
		$tf                            = new Two_Factor();
		$step = (int) floor( time() / Provider_TOTP::PERIOD );
		$this->assertTrue( Provider_TOTP::consume_step( 1, $step ) );
		for ( $i = 0; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$tf->record_code_failure( 2 );
		}

		switch_to_blog( 2 );
		try {
			// The secret, the used step and the lock live in usermeta, which is
			// one table for the whole network.
			$this->assertTrue( $tf->user_has_2fa( 1 ) );
			$this->assertFalse( Provider_TOTP::consume_step( 1, $step ), 'a code used on site 1 was accepted again on site 2' );
			$this->assertTrue( $tf->code_locked( 2 ), 'the incorrect-code lock did not follow the account to site 2' );
		} finally {
			restore_current_blog();
		}
	}

	public function test_unusual_set_cookie_lines_are_classified_correctly(): void {
		$names   = array( 'wordpress_abc', 'wordpress_sec_abc', 'wordpress_logged_in_abc' );
		$headers = array(
			'Set-Cookie:wordpress_logged_in_abc=owner%7C1%7Ctok%7Chmac',           // no space, no attributes: withdrawn
			'SET-COOKIE: wordpress_abc=owner%7C1%7Ctok%7Chmac; path=/wp-admin',    // header name case: withdrawn
			'Set-Cookie: wordpress_logged_in_abc=; expires=Thu, 01 Jan 1970 00:00:01 GMT', // empty value: clearing, kept
			'Set-Cookie: wordpress_logged_in_abc=%20%20; path=/',                   // whitespace only: clearing, kept
			'Set-Cookie: =orphan; path=/',                                          // no name: kept
			'Set-Cookie: wordpress_logged_in_abc',                                  // no value at all: kept
			'X-Set-Cookie: wordpress_logged_in_abc=x',                              // not a Set-Cookie header: kept
			'Set-Cookie: wordpress_logged_in_abcd=x; path=/',                       // longer name: kept
		);
		$this->assertSame(
			array_slice( $headers, 2 ),
			Two_Factor::without_auth_cookies( $headers, $names )
		);
	}
}
