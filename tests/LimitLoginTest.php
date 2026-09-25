<?php
/**
 * Tests for the brute-force lockout ladder (pure logic).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Limit_Login::class )]
class LimitLoginTest extends TestCase {

	public function test_escalating_lockout_ladder(): void {
		$l = new Limit_Login();
		$this->assertSame( 0, $l->lockout_seconds( 4 ) );      // below threshold = no lock
		$this->assertSame( 900, $l->lockout_seconds( 5 ) );    // 15 min
		$this->assertSame( 900, $l->lockout_seconds( 9 ) );
		$this->assertSame( 3600, $l->lockout_seconds( 10 ) );  // 1 hr
		$this->assertSame( 3600, $l->lockout_seconds( 19 ) );
		$this->assertSame( 86400, $l->lockout_seconds( 20 ) ); // 24 hr cap
		$this->assertSame( 86400, $l->lockout_seconds( 500 ) );
	}

	public function test_tier_boundary_detection(): void {
		$l = new Limit_Login();
		$this->assertTrue( $l->is_tier_boundary( 5 ) );
		$this->assertTrue( $l->is_tier_boundary( 10 ) );
		$this->assertTrue( $l->is_tier_boundary( 20 ) );
		$this->assertFalse( $l->is_tier_boundary( 6 ) );
		$this->assertFalse( $l->is_tier_boundary( 4 ) );
	}

	/**
	 * Fresh stores and a fixed client address.
	 */
	private function reset_state(): void {
		$GLOBALS['dls_test_transients'] = array();
		$GLOBALS['dls_test_options']    = array();
		$GLOBALS['wpdb']                = new \DLS_Test_Wpdb();
		$_SERVER['REMOTE_ADDR']         = '203.0.113.9';

		$own             = new \WP_User( 7, 'member' );
		$own->user_email = 'member@example.com';
		$target             = new \WP_User( 1, 'owner' );
		$target->user_email = 'owner@example.com';
		$GLOBALS['dls_test_users'] = array(
			1 => $target,
			7 => $own,
		);
	}

	public function test_other_accounts_sign_in_does_not_forgive_failures(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $round = 0; $round < 5; $round++ ) {
			for ( $i = 0; $i < 4; $i++ ) {
				$l->on_failure( 'owner' );
				if ( $l->is_locked( '203.0.113.9' ) ) {
					break 2;
				}
			}
			$l->on_success( 'member', get_userdata( 7 ) );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_sign_in_forgives_that_accounts_own_failures(): void {
		$this->reset_state();
		$l = new Limit_Login();
		$l->on_failure( 'owner' );
		$l->on_failure( 'Member' );
		$l->on_failure( 'MEMBER@example.com' );
		$l->on_failure( 'member' );
		$l->on_success( 'member', get_userdata( 7 ) );

		// Only the one failure against "owner" is left on the address.
		$this->assertSame( 1, (int) get_transient( 'dragonloginsecurity_fail_' . md5( '203.0.113.9' ) ) );
		for ( $i = 0; $i < 3; $i++ ) {
			$l->on_failure( 'member' );
		}
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		$l->on_failure( 'member' );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_second_factor_pass_forgives_only_that_account(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$l->clear_user( '203.0.113.9', get_userdata( 7 ) );
		$l->on_failure( 'owner' );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_identifier_shared_with_another_account_is_not_forgiven(): void {
		$this->reset_state();
		// A username equal to another account's email address.
		$GLOBALS['dls_test_users'][9]             = new \WP_User( 9, 'owner@example.com' );
		$GLOBALS['dls_test_users'][9]->user_email = 'nine@example.com';
		$l = new Limit_Login();
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'owner@example.com' );
		}
		$l->on_success( 'owner@example.com', get_userdata( 9 ) );
		$l->on_failure( 'owner' );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_admin_clear_still_unlocks_the_address(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
		$l->clear( '203.0.113.9' );
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_attempts_on_no_account_keep_no_per_username_state(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 50; $i++ ) {
			$code = $i < 10 ? 'invalid_username' : ( $i < 20 ? 'invalid_email' : 'dragonloginsecurity_locked' );
			$l->on_failure( 'nobody' . $i, new \WP_Error( $code ) );
		}
		$shares = array_filter(
			array_keys( $GLOBALS['dls_test_transients'] ),
			static function ( $key ) {
				return 0 === strpos( $key, 'dragonloginsecurity_failu_' );
			}
		);
		$this->assertSame( array(), array_values( $shares ) );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}
}
