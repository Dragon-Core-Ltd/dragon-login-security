<?php
/**
 * Tests for the table-creation retry throttle and its admin notice.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use DragonLoginSecurity\Plugin;
use PHPUnit\Framework\TestCase;

class SchemaRetryTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['dls_test_dbdelta_calls']      = array();
		$GLOBALS['dls_test_is_admin']           = true;
		$GLOBALS['wpdb']                        = new \DLS_Test_Wpdb();
	}

	private function plugin(): Plugin {
		return ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
	}

	private function create_tables(): void {
		$method = new \ReflectionMethod( Plugin::class, 'create_tables' );
		$method->setAccessible( true );
		$method->invoke( $this->plugin() );
	}

	public function test_failed_creation_records_the_failure_and_throttles_retries(): void {
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials' );

		$this->create_tables();

		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertSame( 1, get_transient( 'dragonloginsecurity_schema_retry' ) );
		$failure = get_option( 'dragonloginsecurity_schema_failure' );
		$this->assertSame( array( 'wp_dls_lockouts' ), $failure['tables'] );
		$this->assertEqualsWithDelta( time(), $failure['time'], 5 );

		// While the throttle stands, no further attempt is made.
		$this->create_tables();
		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertFalse( get_option( 'dragonloginsecurity_db_version' ) );
	}

	public function test_creation_is_retried_after_the_throttle_expires_and_cleared_on_success(): void {
		$this->create_tables();
		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );

		delete_transient( 'dragonloginsecurity_schema_retry' ); // Expiry.
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials', 'wp_dls_lockouts' );

		$this->create_tables();

		$this->assertCount( 4, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertSame( Plugin::DB_VERSION, get_option( 'dragonloginsecurity_db_version' ) );
		$this->assertFalse( get_option( 'dragonloginsecurity_schema_failure' ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_schema_retry' ) );
	}

	public function test_a_stamp_left_by_a_release_that_never_created_the_tables_is_not_trusted(): void {
		// 1.0.9 stamped the schema version even when dbDelta failed, and the
		// version did not change in 1.0.10, so an unconditional early return
		// would skip recovery forever on exactly the sites that need it.
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials' );

		$this->create_tables();

		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'], 'The missing table is created.' );
		$failure = get_option( 'dragonloginsecurity_schema_failure' );
		$this->assertSame( array( 'wp_dls_lockouts' ), $failure['tables'] );
	}

	public function test_a_stamp_backed_by_real_tables_costs_one_check_then_none(): void {
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials', 'wp_dls_lockouts' );

		$this->create_tables();
		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'], 'Nothing to create.' );

		$checks = $GLOBALS['wpdb']->table_checks;
		$this->assertGreaterThan( 0, $checks, 'The tables are confirmed once.' );

		// The confirmation is remembered, so the next call does not re-query.
		$this->create_tables();
		$this->assertSame( $checks, $GLOBALS['wpdb']->table_checks, 'Verified once, then cached.' );
	}

	public function test_activation_always_retries_even_while_throttled(): void {
		set_transient( 'dragonloginsecurity_schema_retry', 1, 600 );
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials', 'wp_dls_lockouts' );

		$this->plugin()->activate();

		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertSame( Plugin::DB_VERSION, get_option( 'dragonloginsecurity_db_version' ) );
	}

	private function render_notice(): string {
		ob_start();
		( new Admin() )->schema_notice();
		return (string) ob_get_clean();
	}

	public function test_notice_renders_only_after_a_failure_and_only_for_admins(): void {
		$this->assertSame( '', $this->render_notice() );

		$this->create_tables(); // Both tables missing.

		$GLOBALS['dls_test_is_admin'] = false;
		$this->assertSame( '', $this->render_notice() );

		$GLOBALS['dls_test_is_admin'] = true;
		$html                         = $this->render_notice();
		$this->assertStringContainsString( 'notice-error', $html );
		$this->assertStringContainsString( 'wp_dls_credentials, wp_dls_lockouts', $html );
		$this->assertStringContainsString( gmdate( 'Y-m-d H:i', get_option( 'dragonloginsecurity_schema_failure' )['time'] ), $html );
	}

	public function test_an_admin_request_repairs_a_table_that_went_missing(): void {
		// create_tables() used to run only on activation, so a table dropped or
		// lost after install stayed missing until someone deactivated and
		// reactivated the plugin. For a brute-force plugin that means lockouts
		// silently stop being recorded, so wp-admin checks and repairs too.
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials' );

		$this->plugin()->maybe_repair_schema();

		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'], 'The missing table is created.' );
		$failure = get_option( 'dragonloginsecurity_schema_failure' );
		$this->assertSame( array( 'wp_dls_lockouts' ), $failure['tables'] );
	}

	public function test_the_admin_repair_is_silent_when_both_tables_are_there(): void {
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials', 'wp_dls_lockouts' );

		$this->plugin()->maybe_repair_schema();

		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'], 'Nothing to create.' );
		$checks = $GLOBALS['wpdb']->table_checks;

		$this->plugin()->maybe_repair_schema();

		$this->assertSame( $checks, $GLOBALS['wpdb']->table_checks, 'Confirmed once, then cached.' );
	}
}
