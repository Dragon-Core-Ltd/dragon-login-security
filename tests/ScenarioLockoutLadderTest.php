<?php
/**
 * Scenario hunt: the lockout ladder across every tier, lock expiry with and
 * without failures during the lock, sign-ins by the attacked account, another
 * account and the attacker's own account, identifier edge cases, and the
 * lockout row / Activity Log message / action payload for one lockout.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Records lockout-row inserts so a test can read them back.
 */
class Scenario_Ladder_Wpdb extends \DLS_Test_Wpdb {
	public $inserted = array();
	public function insert( $table, $data, $format = null ) {
		unset( $format );
		$this->inserted[] = array( $table, $data );
		return $this->insert_result;
	}
}

#[CoversClass( Limit_Login::class )]
class ScenarioLockoutLadderTest extends TestCase {

	private const IP = '203.0.113.9';

	protected function setUp(): void {
		$GLOBALS['dls_test_transients']     = array();
		$GLOBALS['dls_test_transient_ttls'] = array();
		$GLOBALS['dls_test_options']        = array();
		$GLOBALS['dls_test_actions_fired']  = array();
		$GLOBALS['wpdb']                    = new Scenario_Ladder_Wpdb();
		$_SERVER['REMOTE_ADDR']             = self::IP;

		$owner             = new \WP_User( 1, 'owner' );
		$owner->user_email = 'owner@example.com';
		$member            = new \WP_User( 7, 'member' );
		$member->user_email = 'member@example.com';
		$GLOBALS['dls_test_users'] = array(
			1 => $owner,
			7 => $member,
		);
	}

	protected function tearDown(): void {
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		$GLOBALS['wpdb']        = new \DLS_Test_Wpdb();
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

	private function lock_ttl( string $bucket = self::IP ): int {
		return (int) ( $GLOBALS['dls_test_transient_ttls'][ 'dragonloginsecurity_lock_' . md5( $bucket ) ] ?? 0 );
	}

	private function fail_count( string $bucket = self::IP ): int {
		return (int) get_transient( 'dragonloginsecurity_fail_' . md5( $bucket ) );
	}

	/**
	 * Fired events of one hook.
	 *
	 * @param string $hook Hook name.
	 * @return array<int,array>
	 */
	private function fired( string $hook ): array {
		return array_values(
			array_map(
				static fn( $f ) => $f[1],
				array_filter( $GLOBALS['dls_test_actions_fired'], static fn( $f ) => $hook === $f[0] )
			)
		);
	}

	/**
	 * Login events of one code.
	 *
	 * @param string $code Event code.
	 * @return array<int,array>
	 */
	private function events( string $code ): array {
		return array_values(
			array_map(
				static fn( $args ) => $args[1],
				array_filter( $this->fired( 'dragonloginsecurity_login_event' ), static fn( $args ) => $code === $args[0] )
			)
		);
	}

	/**
	 * What core does for one wp_signon() with real credentials: the lock filter
	 * decides, and any error fires wp_login_failed with that error.
	 */
	private function signon( Limit_Login $l, string $username, string $password, ?\WP_Error $core_result = null ) {
		$result = $l->block_locked( $core_result, $username, $password );
		if ( $result instanceof \WP_Error && ! in_array( $result->get_error_code(), array( 'empty_username', 'empty_password' ), true ) ) {
			$l->on_failure( $username, $result );
		}
		return $result;
	}

	public function test_every_tier_boundary_records_one_row_one_event_and_one_action_with_matching_counts(): void {
		$l = new Limit_Login();
		for ( $i = 1; $i <= 25; $i++ ) {
			$this->signon( $l, 'owner', 'wrong', new \WP_Error( 'incorrect_password' ) );
			$expected_ttl = $i < 5 ? 0 : ( $i < 10 ? 900 : ( $i < 20 ? 3600 : 86400 ) );
			$this->assertSame( $expected_ttl, $this->lock_ttl(), "lock length after failure $i" );
		}

		$rows = $GLOBALS['wpdb']->inserted;
		$this->assertSame( array( 5, 10, 20 ), array_map( static fn( $r ) => $r[1]['attempts'], $rows ), 'rows only at tier boundaries' );
		$this->assertSame( array( self::IP, self::IP, self::IP ), array_map( static fn( $r ) => $r[1]['ip'], $rows ) );
		$this->assertSame( 'wp_dls_lockouts', $rows[0][0] );

		$actions = $this->fired( 'dragonloginsecurity_lockout' );
		$this->assertSame( array( array( self::IP, 5 ), array( self::IP, 10 ), array( self::IP, 20 ) ), $actions );

		$lockout_events = $this->events( 'user.lockout' );
		$this->assertCount( 3, $lockout_events );
		$this->assertSame( 'IP 203.0.113.9 locked out after 5 failed attempts', $lockout_events[0]['message'] );
		$this->assertSame( 'IP 203.0.113.9 locked out after 20 failed attempts', $lockout_events[2]['message'] );
		$this->assertSame( 'owner', $lockout_events[0]['object_name'] );
		$this->assertSame( self::IP, $lockout_events[0]['source_ip'] );

		$failed = $this->events( 'user.login_failed' );
		$this->assertCount( 25, $failed, 'every attempt, including those refused while locked, is a failed-login event' );
		$this->assertSame( 'Failed login for "owner"', $failed[0]['message'] );
	}

	public function test_failures_during_a_lock_refresh_it_and_the_first_failure_after_expiry_starts_a_fresh_count(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$this->signon( $l, 'owner', 'wrong', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $this->lock_ttl() );
		$this->advance( 600 );
		$this->assertSame( 300, $this->lock_ttl() );

		// A refused attempt while locked resets the lock to its full length.
		$this->signon( $l, 'owner', 'right-password-but-locked' );
		$this->assertSame( 900, $this->lock_ttl() );
		$this->assertSame( 6, $this->fail_count() );

		// The lock runs out but the hour-long counter (refreshed by the last
		// failure) is still alive with 6 on it: one slip must not re-lock.
		$this->advance( 901 );
		$this->assertFalse( $l->is_locked( self::IP ) );
		$this->assertSame( 6, $this->fail_count(), 'counter outlives the lock' );
		$this->signon( $l, 'owner', 'typo', new \WP_Error( 'incorrect_password' ) );
		$this->assertFalse( $l->is_locked( self::IP ), 'a single mistake after a lock does not lock again' );
		$this->assertSame( 1, $this->fail_count() );

		// Four more do lock, and for longer (6 banked + 5 = 11 -> hour tier).
		for ( $i = 0; $i < 4; $i++ ) {
			$this->signon( $l, 'owner', 'typo', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 3600, $this->lock_ttl() );
		$this->assertSame( array( 5, 11 ), array_map( static fn( $r ) => $r[1]['attempts'], $GLOBALS['wpdb']->inserted ) );
	}

	public function test_the_ladder_is_forgotten_once_a_day_long_lock_has_run_out(): void {
		$l = new Limit_Login();
		for ( $round = 0; $round < 4; $round++ ) {
			for ( $i = 0; $i < 5; $i++ ) {
				$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
			}
			$this->advance( $this->lock_ttl() + 1 );
		}
		// The day-long lock and the day-long escalation memory expire together:
		// the next five failures start the ladder at the bottom again.
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $this->lock_ttl() );
	}

	public function test_the_attacked_account_cannot_sign_in_during_the_lock_but_forgives_everything_after_it(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$this->signon( $l, 'owner', 'wrong', new \WP_Error( 'incorrect_password' ) );
		}
		// Correct password during the lock: refused, and it counts.
		$result = $this->signon( $l, 'owner', 'correct' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'dragonloginsecurity_locked', $result->get_error_code() );
		$this->assertSame( 6, $this->fail_count() );

		$this->advance( 901 );
		$this->assertFalse( $l->is_locked( self::IP ) );
		$this->assertNull( $this->signon( $l, 'owner', 'correct' ) );
		$l->on_success( 'owner', get_userdata( 1 ) );

		// The five password failures are forgiven; the refused attempt while
		// locked never reached the account, so it stays on the address, in both
		// the live counter and the remembered lock total.
		$this->assertSame( 1, $this->fail_count() );
		$this->assertSame( 1, (int) get_transient( 'dragonloginsecurity_banked_' . md5( self::IP ) ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_prior_' . md5( self::IP ) ) );

		// The next failure moves that leftover into history and starts a fresh
		// count, so four more do not lock and the fifth gives the bottom tier.
		for ( $i = 0; $i < 4; $i++ ) {
			$this->signon( $l, 'owner', 'wrong', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertFalse( $l->is_locked( self::IP ) );
		$this->assertSame( 1, (int) get_transient( 'dragonloginsecurity_prior_' . md5( self::IP ) ) );
		$this->signon( $l, 'owner', 'wrong', new \WP_Error( 'incorrect_password' ) );
		$this->assertSame( 900, $this->lock_ttl(), 'ladder starts over after the owner signed in' );
		$this->assertSame( 6, $this->fired( 'dragonloginsecurity_lockout' )[1][1] );
	}

	public function test_the_attackers_own_account_signing_in_does_not_shorten_the_victims_lock(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$l->on_failure( 'member', new \WP_Error( 'incorrect_password' ) );
		$this->assertSame( 900, $this->lock_ttl() );
		$this->advance( 901 );

		// The attacker signs into their own account: only their one failure goes.
		$l->on_success( 'member', get_userdata( 7 ) );
		$this->assertSame( 4, $this->fail_count() );
		$this->assertSame( 4, (int) get_transient( 'dragonloginsecurity_banked_' . md5( self::IP ) ) );

		// One more against the owner: 4 banked + 1 fresh = 5, no lock (count is 1);
		// then four more lock for the hour tier because 4 + 5 = 9 < 10... a 15 minute lock.
		$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		$this->assertFalse( $l->is_locked( self::IP ) );
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $this->lock_ttl() );
		$this->assertSame( 9, $this->fired( 'dragonloginsecurity_lockout' )[1][1] );
	}

	public function test_forgiveness_larger_than_the_current_count_also_drains_the_banked_and_prior_totals(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$l->on_failure( 'member', new \WP_Error( 'incorrect_password' ) );
		$this->advance( 901 );
		// Two more against the owner start a fresh count (prior = 6 banked).
		$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		$this->assertSame( 2, $this->fail_count() );
		$this->assertSame( 6, (int) get_transient( 'dragonloginsecurity_prior_' . md5( self::IP ) ) );

		$l->on_success( 'owner', get_userdata( 1 ) );
		$this->assertSame( 0, $this->fail_count() );
		$this->assertSame( 1, (int) get_transient( 'dragonloginsecurity_prior_' . md5( self::IP ) ), 'only the member failure remains in history' );
		$this->assertFalse( get_transient( 'dragonloginsecurity_banked_' . md5( self::IP ) ) );

		// The remaining history is one failure: four more must not lock, five do.
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'member', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertFalse( $l->is_locked( self::IP ) );
		$l->on_failure( 'member', new \WP_Error( 'incorrect_password' ) );
		$this->assertTrue( $l->is_locked( self::IP ) );
		$this->assertSame( 900, $this->lock_ttl(), '1 + 5 = 6 failures is the 15 minute tier' );
	}

	public function test_email_and_login_of_the_same_account_in_any_case_and_padding_are_one_identifier(): void {
		$l = new Limit_Login();
		$l->on_failure( 'OWNER', new \WP_Error( 'incorrect_password' ) );
		$l->on_failure( ' owner ', new \WP_Error( 'incorrect_password' ) );
		$l->on_failure( 'Owner@Example.com', new \WP_Error( 'incorrect_password' ) );
		$l->on_failure( 'owner@example.com', new \WP_Error( 'incorrect_password' ) );
		$this->assertSame( 4, $this->fail_count() );
		$l->on_success( 'owner', get_userdata( 1 ) );
		$this->assertSame( 0, $this->fail_count() );
	}

	public function test_usernames_are_forgiven_case_insensitively_beyond_ascii(): void {
		// Logins and emails compare case-insensitively in MySQL for every
		// letter, not only a-z (utf8mb4 _ci collations), so an attempt typed as
		// "ÖLÇEK" is the same identifier as the account "ölçek".
		$user             = new \WP_User( 12, 'ölçek' );
		$user->user_email = 'ölçek@example.com';
		$GLOBALS['dls_test_users'][12] = $user;

		$l = new Limit_Login();
		for ( $i = 0; $i < 4; $i++ ) {
			$l->on_failure( 'ÖLÇEK', new \WP_Error( 'incorrect_password' ) );
		}
		$l->on_success( 'ölçek', $user );
		$this->assertSame( 0, $this->fail_count(), 'the account that signed in should forgive its own failures whatever the case they were typed in' );
	}

	public function test_a_second_factor_failure_counts_and_a_second_factor_pass_forgives(): void {
		$l = new Limit_Login();
		// Two_Factor fires wp_login_failed with its own code after a wrong code.
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'dragonloginsecurity_2fa_failed', 'Invalid code.' ) );
		}
		$this->assertTrue( $l->is_locked( self::IP ) );
		$this->assertSame( 5, (int) get_transient( 'dragonloginsecurity_failu_' . md5( self::IP . '|owner' ) ), 'wrong codes are the account\'s own share' );

		$this->advance( 901 );
		$l->clear_user( self::IP, get_userdata( 1 ) );
		$this->assertSame( 0, $this->fail_count() );
	}

	public function test_a_refused_password_only_sign_in_never_counts_but_a_real_failure_after_it_does(): void {
		$l = new Limit_Login();
		// XML-RPC and REST refuse 2FA accounts with this code: the password was right.
		$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'dragonloginsecurity_2fa_required' ) ) );
		$this->assertSame( array(), $GLOBALS['dls_test_transients'] );
		$this->assertSame( array(), $this->fired( 'dragonloginsecurity_login_event' ), 'no failed-login event for a correct password' );
		$this->assertSame( 1, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ) );
	}

	public function test_no_error_object_is_treated_as_a_plain_failure(): void {
		$l = new Limit_Login();
		$this->assertSame( 1, $l->on_failure( 'owner' ) );
		$this->assertSame( 2, $l->on_failure( 'owner', 'a string, not a WP_Error' ) );
		$this->assertSame( 3, $l->on_failure( 'owner', array( 'code' => 'x' ) ) );
		$this->assertSame( 3, (int) get_transient( 'dragonloginsecurity_failu_' . md5( self::IP . '|owner' ) ) );
	}

	public function test_empty_or_whitespace_credentials_are_never_a_failure_even_while_locked(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $this->lock_ttl() );
		$this->advance( 100 );

		$this->assertNull( $l->block_locked( null, '', '' ) );
		$this->assertNull( $l->block_locked( null, 'owner', '' ) );
		$this->assertNull( $l->block_locked( null, '', 'pw' ) );
		$this->assertNull( $l->block_locked( null, null, null ) );
		$this->assertSame( 800, $this->lock_ttl(), 'none of those touched the lock' );
		$this->assertSame( 5, $this->fail_count() );

		// A whitespace username with a password IS a credential check to core
		// (sanitize_user has already trimmed it before the filter), and "0" is a
		// real username and password.
		$this->assertInstanceOf( \WP_Error::class, $l->block_locked( null, '0', '0' ) );
	}

	public function test_a_lockout_whose_username_is_longer_than_the_column_is_truncated_not_lost(): void {
		$l    = new Limit_Login();
		$long = str_repeat( 'ü', 300 );
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( $long, new \WP_Error( 'invalid_username' ) );
		}
		$this->assertCount( 1, $GLOBALS['wpdb']->inserted );
		$this->assertSame( 191, mb_strlen( $GLOBALS['wpdb']->inserted[0][1]['username'] ) );
		$this->assertSame( $long, $this->events( 'user.lockout' )[0]['object_name'], 'the event keeps the full identifier' );
	}

	public function test_ipv6_lockout_row_event_and_action_name_the_address_while_the_lock_covers_its_64_block(): void {
		$l = new Limit_Login();
		for ( $i = 1; $i <= 5; $i++ ) {
			$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::' . $i;
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$row = $GLOBALS['wpdb']->inserted[0][1];
		$this->assertSame( '2001:db8:1:2::5', $row['ip'], 'the row names the address that crossed the threshold' );
		$this->assertSame( array( '2001:db8:1:2::5', 5 ), $this->fired( 'dragonloginsecurity_lockout' )[0] );
		$this->assertSame( 'IP 2001:db8:1:2::5 locked out after 5 failed attempts', $this->events( 'user.lockout' )[0]['message'] );

		// Every notation of any address in the block is locked, and the
		// address the row names unlocks the block from the CLI.
		$this->assertTrue( $l->is_locked( '2001:0DB8:0001:0002:0000:0000:0000:0001' ) );
		$this->assertTrue( $l->is_locked( '2001:db8:1:2:ffff:ffff:ffff:ffff' ) );
		$this->assertTrue( $l->is_locked( ' 2001:db8:1:2::9 ' ) );
		$this->assertFalse( $l->is_locked( '2001:db8:1:3::1' ) );

		// The owner signing in from any address in the block forgives the share.
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:abcd::1';
		$l->on_success( 'owner', get_userdata( 1 ) );
		$this->assertSame( 0, $this->fail_count( '2001:db8:1:2::/64' ) );
	}

	public function test_an_ipv4_mapped_address_in_hex_form_counts_as_its_ipv4_address(): void {
		// inet_ntop( inet_pton( '::ffff:cb00:7109' ) ) is '::ffff:203.0.113.9': the
		// same address. The allow/deny matcher already treats them alike
		// (IP::pack), so the lockout bucket must too, or the address falls into
		// the ::/64 block that loopback (::1) lives in.
		$this->assertSame( '203.0.113.9', Limit_Login::bucket( '::ffff:203.0.113.9' ) );
		$this->assertSame( '203.0.113.9', Limit_Login::bucket( '::FFFF:203.0.113.9' ) );
		$this->assertSame( '203.0.113.9', Limit_Login::bucket( '::ffff:cb00:7109' ) );
		$this->assertNotSame( Limit_Login::bucket( '::1' ), Limit_Login::bucket( '::ffff:cb00:7109' ) );
	}

	public function test_bucket_and_lists_agree_for_ipv4_mapped_dotted_form(): void {
		update_option( 'dragonloginsecurity_settings', array( 'deny_ips' => array( '203.0.113.9' ) ) );
		$l = new Limit_Login();
		$this->assertTrue( $l->is_locked( '::ffff:203.0.113.9' ) );
		$this->assertTrue( $l->is_locked( '::FFFF:203.0.113.9' ) );
		$this->assertTrue( $l->is_locked( '::ffff:cb00:7109' ) );

		update_option( 'dragonloginsecurity_settings', array( 'allow_ips' => array( '::ffff:203.0.113.9' ) ) );
		$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ), 'allow list entry in mapped form covers the plain IPv4 visitor' );
	}

	public function test_a_link_local_or_zoned_remote_address_yields_no_address_and_no_counting_without_notices(): void {
		$l = new Limit_Login();
		foreach ( array( 'fe80::1%eth0', '[2001:db8::1]', '203.0.113.9:443', '', 'unknown', '0' ) as $remote ) {
			$_SERVER['REMOTE_ADDR'] = $remote;
			$this->assertSame( '', \DragonLoginSecurity\IP::current(), $remote );
			$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ), $remote );
			$this->assertNull( $l->block_locked( null, 'owner', 'pw' ), $remote );
		}
		unset( $_SERVER['REMOTE_ADDR'] );
		$this->assertSame( '', \DragonLoginSecurity\IP::current() );
		$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ) );
		$this->assertSame( array(), $GLOBALS['dls_test_transients'] );
	}

	public function test_leading_and_trailing_whitespace_on_remote_addr_is_ignored(): void {
		$_SERVER['REMOTE_ADDR'] = " \t203.0.113.9 ";
		$this->assertSame( '203.0.113.9', \DragonLoginSecurity\IP::current() );
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.9' ) );
	}

	public function test_an_allow_listed_address_is_never_counted_and_never_locked_even_when_also_denied(): void {
		update_option(
			'dragonloginsecurity_settings',
			array(
				'allow_ips' => array( '203.0.113.0/24' ),
				'deny_ips'  => array( '203.0.113.9' ),
			)
		);
		$l = new Limit_Login();
		for ( $i = 0; $i < 30; $i++ ) {
			$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ) );
		}
		$this->assertFalse( $l->is_locked( self::IP ) );
		$this->assertSame( array(), $GLOBALS['dls_test_transients'] );
		$this->assertSame( array(), $this->fired( 'dragonloginsecurity_login_event' ), 'no failed-login events for an allow-listed address' );
	}

	public function test_a_denied_address_is_refused_with_the_locked_code_from_the_first_attempt(): void {
		update_option( 'dragonloginsecurity_settings', array( 'deny_ips' => array( '203.0.113.0/24' ) ) );
		$l      = new Limit_Login();
		$result = $this->signon( $l, 'owner', 'correct' );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'dragonloginsecurity_locked', $result->get_error_code() );
	}

	public function test_lists_stored_in_odd_shapes_neither_match_nor_throw(): void {
		$l = new Limit_Login();
		foreach ( array( 'a string', 42, null, true, array( 'allow_ips' => '203.0.113.9' ), array( 'allow_ips' => array( null, 7, '' ) ), array( 'deny_ips' => 'garbage' ) ) as $settings ) {
			$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = $settings;
			$locked = $l->is_locked( self::IP );
			$this->assertFalse( $locked, wp_json_encode( $settings ) );
		}
		// A bare string entry is still honoured as a one-item list.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array( 'allow_ips' => '203.0.113.9' );
		$this->assertSame( 0, $l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) ) );
	}
}
