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
		$GLOBALS['dls_test_transients']    = array();
		$GLOBALS['dls_test_options']       = array();
		$GLOBALS['dls_test_actions_fired'] = array();
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

	/**
	 * Let the current lock run out, as its transient expiring would.
	 */
	private function expire_lock(): void {
		delete_transient( 'dragonloginsecurity_lock_' . md5( '203.0.113.9' ) );
	}

	/**
	 * Seconds the current lock was set for.
	 *
	 * @return int
	 */
	private function lock_ttl(): int {
		return (int) ( $GLOBALS['dls_test_transient_ttls'][ 'dragonloginsecurity_lock_' . md5( '203.0.113.9' ) ] ?? 0 );
	}

	public function test_one_failure_after_a_lockout_ends_does_not_lock_again(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
		$this->expire_lock();

		$l->on_failure( 'owner' );
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		for ( $i = 0; $i < 3; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		$l->on_failure( 'owner' );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_repeated_lockouts_still_escalate(): void {
		$this->reset_state();
		$l         = new Limit_Login();
		$durations = array();
		for ( $round = 0; $round < 4; $round++ ) {
			for ( $i = 0; $i < 5; $i++ ) {
				$l->on_failure( 'owner' );
			}
			$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
			$durations[] = $this->lock_ttl();
			$this->expire_lock();
		}
		$this->assertSame( array( 900, 3600, 3600, 86400 ), $durations );

		$lockouts = array_filter(
			$GLOBALS['dls_test_actions_fired'],
			static function ( $fired ) {
				return 'dragonloginsecurity_lockout' === $fired[0];
			}
		);
		$this->assertCount( 4, $lockouts );
	}

	public function test_failures_during_a_lockout_escalate_it(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 10; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( $i < 5 ? 'incorrect_password' : 'dragonloginsecurity_locked' ) );
		}
		$this->assertSame( 3600, $this->lock_ttl() );
		for ( $i = 0; $i < 10; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'dragonloginsecurity_locked' ) );
		}
		$this->assertSame( 86400, $this->lock_ttl() );
	}

	public function test_admin_clear_also_forgets_earlier_lockouts(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$this->expire_lock();
		$l->clear( '203.0.113.9' );
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner' );
		}
		$this->assertSame( 900, $this->lock_ttl() );
	}

	public function test_refused_password_only_sign_in_is_not_a_failure(): void {
		$this->reset_state();
		$l = new Limit_Login();
		for ( $i = 0; $i < 10; $i++ ) {
			$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'dragonloginsecurity_2fa_required' ) ) );
		}
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_fail_' . md5( '203.0.113.9' ) ) );
	}

	public function test_deny_list_ranges_block_matching_addresses(): void {
		$this->reset_state();
		update_option(
			'dragonloginsecurity_settings',
			array(
				'allow_ips' => array( '2001:db8:1::/48' ),
				'deny_ips'  => array( '10.9.9.0/24', '2001:db8::/32' ),
			)
		);
		$l = new Limit_Login();
		$this->assertTrue( $l->is_locked( '10.9.9.77' ) );
		$this->assertTrue( $l->is_locked( '::ffff:10.9.9.77' ) );
		$this->assertFalse( $l->is_locked( '10.9.8.77' ) );
		$this->assertTrue( $l->is_locked( '2001:DB8:ffff::1' ) );
		$this->assertFalse( $l->is_locked( '2001:db8:1::5' ) );
		$this->assertFalse( $l->is_locked( '2001:db9::1' ) );
	}

	public function test_single_addresses_match_in_any_notation(): void {
		$this->reset_state();
		update_option(
			'dragonloginsecurity_settings',
			array(
				'allow_ips' => array(),
				'deny_ips'  => array( '2001:db8:0:0::7', '::ffff:198.51.100.7' ),
			)
		);
		$l = new Limit_Login();
		$this->assertTrue( $l->is_locked( '2001:db8::7' ) );
		$this->assertTrue( $l->is_locked( '198.51.100.7' ) );
		$this->assertFalse( $l->is_locked( '198.51.100.8' ) );
	}
}
