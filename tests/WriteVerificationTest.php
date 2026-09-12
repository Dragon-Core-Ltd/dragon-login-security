<?php
/**
 * Tests that persistence failures are reported instead of being treated as
 * success: settings/import writes, the WebAuthn signature counter, TOTP
 * replay steps, backup-code consumption, schema stamping and the legacy
 * option migration.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use DragonLoginSecurity\Credentials;
use DragonLoginSecurity\Importer;
use DragonLoginSecurity\Plugin;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Provider_TOTP;
use PHPUnit\Framework\TestCase;

class WriteVerificationTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_user_meta']          = array();
		$GLOBALS['dls_test_meta_write_fails']   = false;
		$GLOBALS['dls_test_dbdelta_calls']      = array();
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['wpdb']                        = new \DLS_Test_Wpdb();
	}

	// Importer.

	public function test_merge_lists_reports_saved_when_the_option_holds_the_lists(): void {
		$result = Importer::merge_lists( array( '203.0.113.9' ), array( '198.51.100.7' ) );

		$this->assertTrue( $result['saved'] );
		$this->assertSame( 1, $result['allow'] );
		$this->assertSame( 1, $result['deny'] );
		$this->assertSame( array( '203.0.113.9' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		$this->assertSame( array( '198.51.100.7' ), get_option( 'dragonloginsecurity_settings' )['deny_ips'] );
	}

	public function test_merge_lists_reports_unsaved_when_the_write_is_dropped(): void {
		$GLOBALS['dls_test_option_write_fails'] = true;

		$result = Importer::merge_lists( array(), array( '198.51.100.7' ) );

		$this->assertFalse( $result['saved'] );
		$this->assertFalse( get_option( 'dragonloginsecurity_settings' ) );
	}

	public function test_merge_lists_with_nothing_new_is_still_saved(): void {
		update_option( 'dragonloginsecurity_settings', array( 'allow_ips' => array( '203.0.113.9' ), 'deny_ips' => array() ) );

		$result = Importer::merge_lists( array( '203.0.113.9' ), array() );

		$this->assertTrue( $result['saved'] );
		$this->assertSame( 0, $result['allow'] );
	}

	// Admin settings.

	public function test_record_save_result_stores_a_success_notice(): void {
		Admin::record_save_result( true );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'success', $notice['type'] );
		$this->assertSame( 'Settings saved.', $notice['message'] );
	}

	public function test_record_save_result_stores_an_error_notice(): void {
		Admin::record_save_result( false );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'could not be saved', $notice['message'] );
	}

	public function test_persist_settings_verifies_the_stored_value(): void {
		$settings = array( 'trust_proxy' => false, 'trusted_proxies' => array(), 'allow_ips' => array(), 'deny_ips' => array( '198.51.100.7' ) );

		$this->assertTrue( Admin::persist_settings( $settings ) );
		$this->assertSame( $settings, get_option( 'dragonloginsecurity_settings' ) );

		// Re-saving an identical value is a no-op write but still a success.
		$this->assertTrue( Admin::persist_settings( $settings ) );

		$GLOBALS['dls_test_option_write_fails'] = true;
		$this->assertFalse( Admin::persist_settings( array( 'deny_ips' => array() ) ) );
	}

	// WebAuthn signature counter.

	public function test_update_sign_count_reports_a_failed_write(): void {
		$GLOBALS['wpdb']->update_result = false;
		$this->assertFalse( Credentials::update_sign_count( 5, 42 ) );

		// Zero affected rows is not an error (identical values), one row is success.
		$GLOBALS['wpdb']->update_result = 0;
		$this->assertTrue( Credentials::update_sign_count( 5, 42 ) );
		$GLOBALS['wpdb']->update_result = 1;
		$this->assertTrue( Credentials::update_sign_count( 5, 42 ) );
		$this->assertSame( 42, $GLOBALS['wpdb']->last_update['data']['sign_count'] );
		$this->assertSame( array( 'id' => 5 ), $GLOBALS['wpdb']->last_update['where'] );
	}

	// TOTP replay step.

	public function test_consume_step_rejects_replay_and_records_the_new_step(): void {
		$this->assertTrue( Provider_TOTP::consume_step( 7, 100 ) );
		$this->assertSame( 100, get_user_meta( 7, 'dls_totp_last_step', true ) );

		$this->assertFalse( Provider_TOTP::consume_step( 7, 100 ) );
		$this->assertFalse( Provider_TOTP::consume_step( 7, 99 ) );
		$this->assertTrue( Provider_TOTP::consume_step( 7, 101 ) );
	}

	public function test_consume_step_fails_when_the_step_cannot_be_stored(): void {
		$GLOBALS['dls_test_meta_write_fails'] = true;

		$this->assertFalse( Provider_TOTP::consume_step( 7, 100 ) );
		$this->assertSame( '', get_user_meta( 7, 'dls_totp_last_step', true ) );
	}

	// Backup codes.

	public function test_store_reports_a_failed_write(): void {
		$this->assertTrue( Provider_Backup_Codes::store( 7, array( 'aaaaa-bbbbb' ) ) );

		$GLOBALS['dls_test_meta_write_fails'] = true;
		$this->assertFalse( Provider_Backup_Codes::store( 7, array( 'ccccc-ddddd' ) ) );
	}

	public function test_verify_and_consume_fails_when_the_code_cannot_be_consumed(): void {
		$plain = Provider_Backup_Codes::generate( 2 );
		Provider_Backup_Codes::store( 7, $plain );

		$GLOBALS['dls_test_meta_write_fails'] = true;
		$this->assertFalse( Provider_Backup_Codes::verify_and_consume( 7, $plain[0] ) );

		$GLOBALS['dls_test_meta_write_fails'] = false;
		$this->assertTrue( Provider_Backup_Codes::verify_and_consume( 7, $plain[0] ) );
		$this->assertFalse( Provider_Backup_Codes::verify_and_consume( 7, $plain[0] ) );
		$this->assertSame( 1, Provider_Backup_Codes::remaining( 7 ) );
	}

	// Schema stamping.

	private function create_tables(): void {
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$method = new \ReflectionMethod( Plugin::class, 'create_tables' );
		$method->setAccessible( true );
		$method->invoke( $plugin );
	}

	public function test_schema_version_is_not_stamped_until_both_tables_exist(): void {
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials' );

		$this->create_tables();

		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertFalse( get_option( 'dragonloginsecurity_db_version' ) );
	}

	public function test_schema_version_is_stamped_once_both_tables_exist(): void {
		$GLOBALS['wpdb']->existing_tables = array( 'wp_dls_credentials', 'wp_dls_lockouts' );

		$this->create_tables();

		$this->assertSame( Plugin::DB_VERSION, get_option( 'dragonloginsecurity_db_version' ) );
	}

	// Legacy option migration.

	private function migrate(): void {
		$method = new \ReflectionMethod( Plugin::class, 'migrate_legacy_prefix' );
		$method->setAccessible( true );
		$method->invoke( null );
	}

	public function test_legacy_option_is_removed_only_after_the_copy_is_confirmed(): void {
		$settings = array( 'allow_ips' => array( '203.0.113.9' ) );
		update_option( 'dls_settings', $settings );
		update_option( 'dls_db_version', '1' );

		$GLOBALS['dls_test_option_write_fails'] = true;
		$this->migrate();

		$this->assertSame( $settings, get_option( 'dls_settings' ), 'legacy copy must survive a failed carry-over' );
		$this->assertFalse( get_option( 'dragonloginsecurity_settings' ) );

		$GLOBALS['dls_test_option_write_fails'] = false;
		$this->migrate();

		$this->assertSame( $settings, get_option( 'dragonloginsecurity_settings' ) );
		$this->assertSame( '1', get_option( 'dragonloginsecurity_db_version' ) );
		$this->assertFalse( get_option( 'dls_settings' ) );
		$this->assertFalse( get_option( 'dls_db_version' ) );
	}

	public function test_a_failed_uninstall_preference_is_not_hidden_behind_settings_saved(): void {
		// Only the checkbox changed, so the settings array compares equal and the
		// settings write counts as a success. The preference write failing must
		// still be reported rather than covered by "Settings saved."
		Admin::record_save_result( true, false );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );

		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringNotContainsString( 'Settings saved.', $notice['message'] );
		$this->assertStringContainsString( 'uninstall', strtolower( $notice['message'] ) );
	}

	public function test_both_writes_landing_still_reports_a_plain_success(): void {
		Admin::record_save_result( true, true );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );

		$this->assertSame( 'success', $notice['type'] );
		$this->assertSame( 'Settings saved.', $notice['message'] );
	}

	public function test_a_failed_settings_write_is_reported_even_if_the_preference_landed(): void {
		Admin::record_save_result( false, true );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );

		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'previous settings', $notice['message'] );
	}
}
