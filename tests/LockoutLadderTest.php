<?php
/**
 * Lockouts hold their length against login-page loads, keep escalating once
 * a lock and its counter have both run out, and cover a whole IPv6 /64.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Limit_Login::class )]
class LockoutLadderTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_transients']     = array();
		$GLOBALS['dls_test_transient_ttls'] = array();
		$GLOBALS['dls_test_options']        = array();
		$GLOBALS['dls_test_actions_fired']  = array();
		$GLOBALS['wpdb']                    = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_users']          = array( 1 => new \WP_User( 1, 'owner' ) );
		$_SERVER['REMOTE_ADDR']             = '203.0.113.9';
	}

	protected function tearDown(): void {
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Let time pass: every transient whose TTL has run out expires.
	 *
	 * @param int $seconds Seconds to advance.
	 */
	private function advance( int $seconds ): void {
		foreach ( $GLOBALS['dls_test_transient_ttls'] as $key => $ttl ) {
			if ( $ttl <= 0 ) {
				continue;
			}
			if ( $ttl - $seconds <= 0 ) {
				unset( $GLOBALS['dls_test_transients'][ $key ], $GLOBALS['dls_test_transient_ttls'][ $key ] );
			} else {
				$GLOBALS['dls_test_transient_ttls'][ $key ] = $ttl - $seconds;
			}
		}
	}

	private function lock_ttl( string $ip = '203.0.113.9' ): int {
		return (int) ( $GLOBALS['dls_test_transient_ttls'][ 'dragonloginsecurity_lock_' . md5( $ip ) ] ?? 0 );
	}

	/**
	 * What core does for one wp_signon() call: the credential check at
	 * priority 20 answers empty credentials itself, the lock filter runs at 30,
	 * and any error outside core's two ignored codes fires wp_login_failed.
	 *
	 * @param Limit_Login $l        Lockout.
	 * @param string      $username Username or ''.
	 * @param string      $password Password or ''.
	 * @return mixed What reached the end of the authenticate chain.
	 */
	private function core_signon( Limit_Login $l, string $username, string $password ) {
		$result = null;
		if ( '' === $username ) {
			$result = new \WP_Error( 'empty_username' );
		} elseif ( '' === $password ) {
			$result = new \WP_Error( 'empty_password' );
		}
		$result = $l->block_locked( $result, $username, $password );
		if ( $result instanceof \WP_Error && ! in_array( $result->get_error_code(), array( 'empty_username', 'empty_password' ), true ) ) {
			$l->on_failure( $username, $result );
		}
		return $result;
	}

	public function test_loading_the_login_page_while_locked_does_not_extend_the_lock(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $this->lock_ttl() );

		// wp-login.php calls wp_signon( array() ) on every GET of the login
		// screen, including the one a locked-out user refreshes while waiting.
		for ( $i = 0; $i < 20; $i++ ) {
			$this->core_signon( $l, '', '' );
		}
		$this->assertSame( 900, $this->lock_ttl(), 'a page load is not a failed sign-in' );
		$this->assertSame( 5, (int) get_transient( 'dragonloginsecurity_fail_' . md5( '203.0.113.9' ) ) );
		$this->assertSame( array(), $GLOBALS['wpdb']->inserted ?? array(), 'no lockout rows for empty usernames' );

		// Credentials are still refused while the lock stands, and still count.
		$this->assertInstanceOf( \WP_Error::class, $this->core_signon( $l, 'owner', 'pw' ) );
		$this->assertSame( 6, (int) get_transient( 'dragonloginsecurity_fail_' . md5( '203.0.113.9' ) ) );
	}

	public function test_a_locked_failure_without_a_username_is_not_counted(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 5, $l->on_failure( '', new \WP_Error( 'dragonloginsecurity_locked' ) ) );
		$this->assertSame( 5, (int) get_transient( 'dragonloginsecurity_fail_' . md5( '203.0.113.9' ) ) );
	}

	public function test_escalation_survives_a_lock_expiring_together_with_its_counter(): void {
		$l         = new Limit_Login();
		$durations = array();
		for ( $round = 0; $round < 4; $round++ ) {
			for ( $i = 0; $i < 5; $i++ ) {
				$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
			}
			$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
			$durations[] = $this->lock_ttl();
			// Wait the lock out for real: the hour-long counter window expires
			// with an hour-long lock.
			$this->advance( $this->lock_ttl() + 1 );
			$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		}
		$this->assertSame( array( 900, 3600, 3600, 86400 ), $durations );
	}

	public function test_a_quiet_hour_after_a_lock_ends_forgets_the_count_but_not_the_ladder(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 10; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 3600, $this->lock_ttl() );
		$this->advance( 3600 + 3600 + 1 );

		// One slip does not lock again; five more do, for longer than before.
		$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		$this->assertFalse( $l->is_locked( '203.0.113.9' ) );
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 3600, $this->lock_ttl() );
	}

	public function test_ipv6_addresses_in_one_64_block_share_a_lockout(): void {
		$l = new Limit_Login();
		for ( $i = 1; $i <= 5; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::' . $i;
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertTrue( $l->is_locked( '2001:db8:1:2:ffff::1' ) );
		$this->assertTrue( $l->is_locked( '2001:0DB8:0001:0002:0:0:0:9' ) );
		$this->assertFalse( $l->is_locked( '2001:db8:1:3::1' ) );

		// Unlocking any address in the block unlocks the block.
		$l->clear( '2001:db8:1:2::77' );
		$this->assertFalse( $l->is_locked( '2001:db8:1:2::1' ) );
	}

	public function test_ipv4_and_mapped_ipv6_keep_their_own_single_address(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
		$this->assertTrue( $l->is_locked( '::ffff:203.0.113.9' ) );
		$this->assertFalse( $l->is_locked( '203.0.113.10' ) );
	}
}
