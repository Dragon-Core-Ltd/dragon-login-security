<?php
/**
 * The User Switching plugin keeps working for users with a second factor.
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
class UserSwitchingTest extends TestCase {

	/**
	 * Admin 1 (may switch to 2), user 2 with a factor, user 3 who may not switch.
	 * $GLOBALS['us_cookie_user'] is the user the request's cookie validates as;
	 * $GLOBALS['us_old_user'] is the user User Switching kept a cookie for.
	 *
	 * @param bool $plugin_active Whether User Switching is loaded.
	 */
	private static function world( bool $plugin_active ): void {
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_users']     = array(
			1 => new \WP_User( 1, 'admin' ),
			2 => new \WP_User( 2, 'editor' ),
			3 => new \WP_User( 3, 'author' ),
		);
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		update_user_meta( 2, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'function wp_validate_auth_cookie( $c = "", $s = "" ) { return $GLOBALS["us_cookie_user"] ?? false; } function user_can( $u, $cap, ...$a ) { return 1 === (int) $u && "switch_to_user" === $cap && 2 === (int) ( $a[0] ?? 0 ); }' );
		if ( $plugin_active ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'class user_switching { public static function get_old_user() { $id = $GLOBALS["us_old_user"] ?? 0; return $id ? get_userdata( $id ) : false; } } function switch_to_user( $id, $r = false, $o = true ) {} function current_user_switched() { return ! empty( $GLOBALS["us_logged_in"] ) ? user_switching::get_old_user() : false; }' );
		}
	}

	/**
	 * Whether cookies for a user are sent.
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	private static function sends( int $user_id ): bool {
		$token = \WP_Session_Tokens::get_instance( $user_id )->create( time() + 3600 );
		$tf    = new Two_Factor();
		// User Switching clears the auth cookies (and removes the logged-in
		// cookie from $_COOKIE) before it sets the new ones.
		$tf->remember_request_cookie();
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		return (bool) $tf->filter_send_auth_cookies( true, 0, 0, $user_id, 'auth', $token );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_switching_to_a_user_is_allowed_for_a_signed_in_switcher(): void {
		self::world( true );
		$GLOBALS['us_cookie_user']   = 1;
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'admin|1|tok|hmac';
		$this->assertTrue( self::sends( 2 ) );
		// A signed-in user who may not switch to the target, or no signed-in user.
		$GLOBALS['us_cookie_user']   = 3;
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'author|1|tok|hmac';
		$this->assertFalse( self::sends( 2 ) );
		$GLOBALS['us_cookie_user'] = 1;
		$this->assertFalse( self::sends( 2 ), 'no cookie on the request' );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_switching_back_is_allowed_to_the_original_user(): void {
		self::world( true );
		// Switched from admin 1 to user 2, now switching back to 1.
		$GLOBALS['us_logged_in'] = true;
		$GLOBALS['us_old_user']  = 1;
		$this->assertTrue( self::sends( 1 ) );
		// After "switch off" the user is signed out but the kept cookie remains.
		$GLOBALS['us_logged_in'] = false;
		$this->assertTrue( self::sends( 1 ) );
		// The kept cookie names someone else.
		$GLOBALS['us_old_user'] = 3;
		$this->assertFalse( self::sends( 1 ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_refused_when_user_switching_is_not_active(): void {
		self::world( false );
		$GLOBALS['us_cookie_user']   = 1;
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'admin|1|tok|hmac';
		$this->assertFalse( Two_Factor::user_switching_allows( 2, 'admin|1|tok|hmac' ) );
		$this->assertFalse( self::sends( 2 ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_password_reset_is_never_excused_by_switching(): void {
		self::world( true );
		$GLOBALS['us_cookie_user']   = 1;
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'admin|1|tok|hmac';
		$tf                          = new Two_Factor();
		$tf->on_password_reset( get_userdata( 2 ) );
		$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, 0, 2, 'auth', 'x' ) );
	}
}
