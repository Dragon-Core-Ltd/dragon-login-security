<?php
/**
 * Scenario hunt: the lockouts table rows, their pruning in batches, and the
 * WP-CLI unlock command with every address notation.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\CLI;
use DragonLoginSecurity\Limit_Login;
use DragonLoginSecurity\Plugin;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/class-cli.php';

/**
 * A lockouts table that honours DELETE ... WHERE created_at < X ... LIMIT N.
 */
class Scenario_Prune_Wpdb extends \DLS_Test_Wpdb {
	public $lockout_rows = array();
	public $queries      = array();
	public $query_result = null;
	public function query( $query ) {
		$this->queries[] = $query;
		if ( null !== $this->query_result ) {
			return $this->query_result;
		}
		// The stub's prepare() substitutes values unquoted.
		if ( ! preg_match( '/^DELETE FROM (\S+) WHERE created_at < (\S+ \S+) ORDER BY id ASC LIMIT (\d+)$/', $query, $m ) ) {
			return false;
		}
		$deleted = 0;
		foreach ( $this->lockout_rows as $id => $row ) {
			if ( $deleted >= (int) $m[3] ) {
				break;
			}
			if ( $row['created_at'] < $m[2] ) {
				unset( $this->lockout_rows[ $id ] );
				++$deleted;
			}
		}
		return $deleted;
	}
}

#[CoversClass( Plugin::class )]
#[CoversClass( CLI::class )]
#[CoversClass( Limit_Login::class )]
class ScenarioLockoutsTableTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_transients']     = array();
		$GLOBALS['dls_test_transient_ttls'] = array();
		$GLOBALS['dls_test_options']        = array();
		$GLOBALS['dls_test_actions_fired']  = array();
		$GLOBALS['wpdb']                    = new Scenario_Prune_Wpdb();
		\WP_CLI::$messages                  = array();
		$_SERVER['REMOTE_ADDR']             = '203.0.113.9';
	}

	protected function tearDown(): void {
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		$GLOBALS['wpdb']        = new \DLS_Test_Wpdb();
	}

	private function plugin(): Plugin {
		$ref = new \ReflectionClass( Plugin::class );
		return $ref->newInstanceWithoutConstructor();
	}

	public function test_prune_deletes_in_batches_of_a_thousand_until_a_short_batch(): void {
		$old = gmdate( 'Y-m-d H:i:s', time() - 31 * DAY_IN_SECONDS );
		$new = gmdate( 'Y-m-d H:i:s', time() - 29 * DAY_IN_SECONDS );
		for ( $i = 0; $i < 2500; $i++ ) {
			$GLOBALS['wpdb']->lockout_rows[] = array( 'created_at' => $old );
		}
		for ( $i = 0; $i < 3; $i++ ) {
			$GLOBALS['wpdb']->lockout_rows[] = array( 'created_at' => $new );
		}
		$this->plugin()->prune_lockouts();
		$this->assertCount( 3, $GLOBALS['wpdb']->queries, '1000 + 1000 + 500' );
		$this->assertCount( 3, $GLOBALS['wpdb']->lockout_rows, 'rows inside the 30 day window stay' );
		$this->assertStringContainsString( 'DELETE FROM wp_dls_lockouts WHERE created_at < ', $GLOBALS['wpdb']->queries[0] );
	}

	public function test_prune_of_exactly_one_full_batch_runs_one_more_empty_query_and_stops(): void {
		$old = gmdate( 'Y-m-d H:i:s', time() - 40 * DAY_IN_SECONDS );
		for ( $i = 0; $i < 1000; $i++ ) {
			$GLOBALS['wpdb']->lockout_rows[] = array( 'created_at' => $old );
		}
		$this->plugin()->prune_lockouts();
		$this->assertCount( 2, $GLOBALS['wpdb']->queries );
		$this->assertSame( array(), $GLOBALS['wpdb']->lockout_rows );
	}

	public function test_prune_stops_on_a_query_error_instead_of_looping(): void {
		$GLOBALS['wpdb']->query_result = false;
		$this->plugin()->prune_lockouts();
		$this->assertCount( 1, $GLOBALS['wpdb']->queries );
	}

	public function test_prune_cutoff_and_row_timestamps_are_both_utc(): void {
		$l = new Limit_Login();
		$GLOBALS['wpdb'] = new class() extends Scenario_Prune_Wpdb {
			public $inserted = array();
			public function insert( $table, $data, $format = null ) {
				unset( $table, $format );
				$this->inserted[] = $data;
				return 1;
			}
		};
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$row = $GLOBALS['wpdb']->inserted[0];
		$this->assertEqualsWithDelta( time(), strtotime( $row['created_at'] . ' UTC' ), 5 );
		$this->plugin()->prune_lockouts();
		$this->assertSame( 1, preg_match( '/created_at < (\S+ \S+) ORDER/', $GLOBALS['wpdb']->queries[0], $m ) );
		$this->assertEqualsWithDelta( time() - 30 * DAY_IN_SECONDS, strtotime( $m[1] . ' UTC' ), 5 );
	}

	public function test_unlock_accepts_every_notation_and_clears_the_whole_ipv6_block(): void {
		$l = new Limit_Login();
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::5';
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertTrue( $l->is_locked( '2001:db8:1:2::9' ) );
		( new CLI() )->unlock( array( '2001:0DB8:0001:0002:FFFF:0000:0000:0001' ) );
		$this->assertFalse( $l->is_locked( '2001:db8:1:2::5' ) );
		$this->assertSame( array( array( 'success', 'Cleared lockout for 2001:0DB8:0001:0002:FFFF:0000:0000:0001.' ) ), \WP_CLI::$messages );

		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		( new CLI() )->unlock( array( '::ffff:203.0.113.9' ) );
		$this->assertFalse( $l->is_locked( '203.0.113.9' ), 'the mapped form unlocks the IPv4 address' );

		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		( new CLI() )->unlock( array( '::ffff:cb00:7109' ) );
		$this->assertFalse( $l->is_locked( '203.0.113.9' ), 'the hex mapped form is the same address' );
	}

	public function test_unlock_also_forgets_the_ladder_history(): void {
		$l = new Limit_Login();
		for ( $i = 0; $i < 10; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		( new CLI() )->unlock( array( '203.0.113.9' ) );
		$this->assertSame( array(), array_filter( array_keys( $GLOBALS['dls_test_transients'] ), static fn( $k ) => 0 === strpos( $k, 'dragonloginsecurity_' ) && 0 !== strpos( $k, 'dragonloginsecurity_failu_' ) ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertSame( 900, $GLOBALS['dls_test_transient_ttls'][ 'dragonloginsecurity_lock_' . md5( '203.0.113.9' ) ] );
	}

	public function test_unlock_refuses_what_is_not_one_address(): void {
		foreach ( array( '', '[2001:db8::1]', 'fe80::1%eth0', '203.0.113.9:443', '203.0.113.0/24', '203.0.113.9 ', 'all', null ) as $bad ) {
			try {
				( new CLI() )->unlock( null === $bad ? array() : array( $bad ) );
				$this->fail( 'accepted ' . wp_json_encode( $bad ) );
			} catch ( \RuntimeException $e ) {
				$this->assertSame( 'Invalid IP address.', $e->getMessage(), wp_json_encode( $bad ) );
			}
		}
		$this->assertSame( array(), \WP_CLI::$messages );
	}

	public function test_unlock_of_a_denied_address_does_not_claim_it_can_sign_in(): void {
		update_option( 'dragonloginsecurity_settings', array( 'deny_ips' => array( '203.0.113.9' ) ) );
		$l = new Limit_Login();
		( new CLI() )->unlock( array( '203.0.113.9' ) );
		$this->assertTrue( $l->is_locked( '203.0.113.9' ), 'the deny list is not a lockout' );
		$this->assertSame( 'Cleared lockout for 203.0.113.9.', \WP_CLI::$messages[0][1] ?? '' );
	}
}
