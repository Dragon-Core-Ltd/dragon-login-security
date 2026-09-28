<?php
/**
 * Scenario hunt: install/uninstall lifecycle, WP-CLI recovery, the Activity
 * Log bridge under version skew, and the encryption helper on odd input.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\CLI;
use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Events;
use DragonLoginSecurity\Integration;
use DragonLoginSecurity\Plugin;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/class-cli.php';

class ScenarioLifecycleTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                        = new class() extends \DLS_Test_Wpdb {
			public $queries      = array();
			public $query_result = 0;
			public $usermeta     = 'wp_usermeta';
			public function query( $sql ) {
				$this->queries[] = $sql;
				return $this->query_result;
			}
		};
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_user_meta']          = array();
		$GLOBALS['dls_test_meta_write_fails']   = false;
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['dls_test_dbdelta_calls']      = array();
		$GLOBALS['dls_test_multisite']          = false;
		$GLOBALS['dls_test_current_blog']       = 1;
		$GLOBALS['dls_test_blog_stack']         = array();
		$GLOBALS['dls_test_blog_options']       = array();
		$GLOBALS['dls_test_blog_transients']    = array();
		$GLOBALS['dls_test_network_active']     = array();
		$GLOBALS['dls_test_actions_done']       = array( 'init' => 1 );
		\WP_CLI::$messages                      = array();
		WebAuthn::$available_override           = true;
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_multisite']       = false;
		$GLOBALS['dls_test_current_blog']    = 1;
		$GLOBALS['dls_test_blog_stack']      = array();
		$GLOBALS['dls_test_blog_options']    = array();
		$GLOBALS['dls_test_blog_transients'] = array();
		$GLOBALS['dls_test_network_active']  = array();
		$GLOBALS['dls_test_actions_done']    = array( 'init' => 1 );
		WebAuthn::$available_override        = null;
	}

	private function plugin(): Plugin {
		return ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
	}

	// --- uninstall ---

	/**
	 * Load uninstall.php with its core helpers stubbed (separate process: it
	 * defines a constant and a function).
	 */
	private function run_uninstall(): void {
		defined( 'WP_UNINSTALL_PLUGIN' ) || define( 'WP_UNINSTALL_PLUGIN', 'dragon-login-security/dragon-login-security.php' );
		if ( ! function_exists( 'delete_metadata' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only stubs of core helpers, static strings.
			eval(
				'function wp_clear_scheduled_hook( $h ) { $GLOBALS["dls_test_cleared_hooks"][] = $h; return 0; }
				function delete_metadata( $type, $id, $key, $value = "", $all = false ) { $GLOBALS["dls_test_meta_deleted"][] = $key; return true; }
				function get_sites( $args = array() ) { return array_keys( $GLOBALS["dls_test_sites"] ); }'
			);
		}
		$GLOBALS['dls_test_meta_deleted']  = array();
		$GLOBALS['dls_test_cleared_hooks'] = array();
		require __DIR__ . '/../uninstall.php';
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_without_the_opt_in_nothing_is_removed(): void {
		$GLOBALS['dls_test_options'] = array(
			'dragonloginsecurity_db_version'      => '1',
			'dragonloginsecurity_prefix_migrated' => '1',
		);
		$this->run_uninstall();
		$this->assertSame( array(), $GLOBALS['wpdb']->queries, 'No table dropped.' );
		$this->assertSame( array(), $GLOBALS['dls_test_meta_deleted'] );
		$this->assertCount( 2, $GLOBALS['dls_test_options'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_opted_in_uninstall_removes_the_migration_stamp_too(): void {
		// The 1.0.17 one-time prefix migration stamps an option that the
		// uninstall list does not know about.
		$GLOBALS['dls_test_options'] = array(
			'dragonloginsecurity_delete_data_on_uninstall' => 1,
			'dragonloginsecurity_db_version'               => '1',
			Plugin::PREFIX_MIGRATED_OPTION                 => '1',
			'blogname'                                     => 'Kept',
		);
		$this->run_uninstall();
		$this->assertSame( array( 'blogname' ), array_keys( $GLOBALS['dls_test_options'] ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_opted_in_uninstall_removes_every_user_meta_the_plugin_writes(): void {
		$GLOBALS['dls_test_options'] = array( 'dragonloginsecurity_delete_data_on_uninstall' => 1 );
		$this->run_uninstall();
		$expected = array(
			Two_Factor::TOTP_META,
			Two_Factor::TOTP_UNREADABLE_MAILED_META,
			Two_Factor::CODE_FAILURES_META,
			Two_Factor::CODE_LOCK_MAILED_META,
			Provider_Backup_Codes::META_KEY,
			'dls_backup_codes_confirmed',
			'dls_totp_last_step',
		);
		$missing = array_diff( $expected, $GLOBALS['dls_test_meta_deleted'] );
		$this->assertSame( array(), array_values( $missing ), 'User meta not removed on uninstall: ' . implode( ', ', $missing ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_network_uninstall_honours_each_sites_own_opt_in(): void {
		// Site 3 opted in, the main site did not. The setting lives per site (it
		// is a per-site settings screen), and the uninstall visits every site,
		// so site 3's tables should go and the main site's should stay.
		$GLOBALS['dls_test_multisite']    = true;
		$GLOBALS['dls_test_sites']        = array( 1 => (object) array( 'blog_id' => '1' ), 3 => (object) array( 'blog_id' => '3' ) );
		$GLOBALS['dls_test_options']      = array( 'dragonloginsecurity_db_version' => '1' );
		$GLOBALS['dls_test_blog_options'] = array(
			3 => array(
				'dragonloginsecurity_delete_data_on_uninstall' => 1,
				'dragonloginsecurity_db_version'               => '1',
			),
		);

		$this->run_uninstall();

		$dropped = implode( "\n", $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( 'wp_3_dls_credentials', $dropped, 'Site 3 opted in; its tables are dropped.' );
		$this->assertStringNotContainsString( 'DROP TABLE IF EXISTS wp_dls_', $dropped, 'The main site did not opt in.' );
		$this->assertSame( '1', $GLOBALS['dls_test_options']['dragonloginsecurity_db_version'] ?? null );
	}

	// --- install ---

	public function test_new_network_site_with_a_failing_dbdelta_records_the_failure_on_that_site_only(): void {
		$GLOBALS['dls_test_multisite']      = true;
		$GLOBALS['dls_test_network_active'] = array( DRAGONLOGINSECURITY_PLUGIN_BASENAME );
		$GLOBALS['dls_test_sites']          = array( 2 => (object) array( 'blog_id' => '2' ) );

		$this->plugin()->install_new_site( new \WP_Site( (object) array( 'blog_id' => '2' ) ) );

		$this->assertSame( 1, get_current_blog_id() );
		$this->assertSame( 'wp_', $GLOBALS['wpdb']->prefix );
		$this->assertArrayNotHasKey( 'dragonloginsecurity_db_version', $GLOBALS['dls_test_blog_options'][2] );
		$this->assertSame( array( 'wp_2_dls_credentials', 'wp_2_dls_lockouts' ), $GLOBALS['dls_test_blog_options'][2][ Plugin::SCHEMA_FAILURE_OPTION ]['tables'] );
		$this->assertSame( 1, $GLOBALS['dls_test_blog_transients'][2][ Plugin::SCHEMA_RETRY_TRANSIENT ] ?? null, 'The retry throttle belongs to the new site.' );
		$this->assertSame( array(), $GLOBALS['dls_test_options'], 'The main site records nothing.' );
	}

	public function test_prune_lockouts_stops_when_the_table_is_missing(): void {
		$GLOBALS['wpdb']->query_result = false; // DELETE on a missing table.
		$this->plugin()->prune_lockouts();
		$this->assertCount( 1, $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( 'DELETE FROM wp_dls_lockouts', $GLOBALS['wpdb']->queries[0] );
	}

	public function test_front_end_request_on_a_stamped_site_does_not_query_the_schema(): void {
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );
		$GLOBALS['wpdb']->existing_tables = array(); // Table gone; only wp-admin repairs.
		$this->plugin()->maybe_install_site();
		$this->assertSame( 0, $GLOBALS['wpdb']->table_checks );
		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'] );
	}

	// --- WP-CLI ---

	public function test_disable_2fa_resolves_id_login_and_email_and_clears_passkeys_network_wide(): void {
		$GLOBALS['dls_test_multisite'] = true;
		$owner                         = new \WP_User( 1, 'owner' );
		$owner->user_email             = 'Owner@Example.test';
		$GLOBALS['dls_test_users']     = array( 1 => $owner );
		$GLOBALS['wpdb']->rows         = array(
			'wp_dls_credentials'   => array( array( 'id' => 1, 'user_id' => 1, 'credential_id' => 'a', 'public_key' => 'k', 'sign_count' => 0 ) ),
			'wp_3_dls_credentials' => array( array( 'id' => 2, 'user_id' => 1, 'credential_id' => 'b', 'public_key' => 'k', 'sign_count' => 0 ) ),
		);
		foreach ( array( '1', 'OWNER', 'owner@example.test' ) as $ref ) {
			update_user_meta( 1, Two_Factor::TOTP_META, 'x' );
			( new CLI() )->disable_2fa( array( $ref ) );
			$this->assertSame( '', get_user_meta( 1, Two_Factor::TOTP_META, true ), $ref );
		}
		$this->assertFalse( ( new Two_Factor() )->user_has_2fa( 1 ) );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_3_dls_credentials'] );
		$this->assertCount( 3, \WP_CLI::$messages );
	}

	public function test_disable_2fa_for_an_unknown_user_changes_nothing(): void {
		$GLOBALS['dls_test_users'] = array( 1 => new \WP_User( 1, 'owner' ) );
		update_user_meta( 1, Two_Factor::TOTP_META, 'x' );
		foreach ( array( '', 'ghost', 'ghost@example.test', '999' ) as $ref ) {
			try {
				( new CLI() )->disable_2fa( array( $ref ) );
				$this->fail( "No error for '$ref'." );
			} catch ( \RuntimeException $e ) {
				$this->assertSame( 'User not found.', $e->getMessage() );
			}
		}
		$this->assertSame( 'x', get_user_meta( 1, Two_Factor::TOTP_META, true ) );
	}

	public function test_status_with_missing_tables_reports_zero_instead_of_failing(): void {
		if ( ! function_exists( 'WP_CLI\Utils\format_items' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only stub, static string.
			eval( 'namespace WP_CLI\Utils; function format_items( $format, $items, $fields ) { $GLOBALS["dls_test_cli_items"] = $items; }' );
		}
		$GLOBALS['wpdb']->get_var_result = null;
		( new CLI() )->status( array(), array() );
		$this->assertSame( array( 0, 0, 0 ), array_column( $GLOBALS['dls_test_cli_items'], 'value' ) );
	}

	// --- Activity Log bridge ---

	public function test_every_emitted_event_code_is_registered_with_activity_log(): void {
		// An unregistered code is stored by Activity Log at "info" severity with
		// no object type and no human label, and never appears in its filters.
		$emitted = array();
		foreach ( glob( __DIR__ . '/../includes/{,providers/}*.php', GLOB_BRACE ) as $file ) {
			$src = (string) file_get_contents( $file );
			if ( preg_match_all( "/emit\\(\\s*'([a-z0-9_]+\\.[a-z0-9_]+)'/", $src, $m ) ) {
				$emitted = array_merge( $emitted, $m[1] );
			}
			if ( preg_match_all( "/'dragonloginsecurity_login_event',\\s*'([a-z0-9_]+\\.[a-z0-9_]+)'/", $src, $m ) ) {
				$emitted = array_merge( $emitted, $m[1] );
			}
		}
		$emitted = array_values( array_unique( $emitted ) );
		$this->assertContains( '2fa.totp_unreadable', $emitted, 'The scan sees the unreadable-secret event.' );
		$this->assertContains( 'passkey.added', $emitted );

		$unregistered = array_values( array_diff( $emitted, array_keys( Events::codes() ) ) );
		$this->assertSame( array(), $unregistered, 'Emitted but not in Events::codes(): ' . implode( ', ', $unregistered ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_an_older_activity_log_without_logger_does_not_fatal(): void {
		// The bridge promises that "a missing or version-skewed Activity Log
		// must never fatal". A Plugin with get_instance() but no logger().
		// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only stand-in, static string.
		eval( 'namespace DragonActivityLog; class Plugin { public static function get_instance() { return new self(); } }' );
		$this->assertTrue( class_exists( '\\DragonActivityLog\\Plugin' ) );
		try {
			( new Integration() )->forward( 'user.lockout', array( 'object_name' => 'admin' ) );
		} catch ( \Throwable $e ) {
			$this->fail( 'forward() fataled on a version-skewed Activity Log: ' . get_class( $e ) . ': ' . $e->getMessage() );
		}
		$this->assertTrue( true );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_throwing_logger_does_not_break_the_login_flow(): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only stand-in, static string.
		eval( 'namespace DragonActivityLog; class Logger { public function record( $e ) { throw new \RuntimeException( "table gone" ); } } class Plugin { public static function get_instance() { return new self(); } public function logger() { return new Logger(); } }' );
		try {
			( new Integration() )->forward( 'user.lockout', array( 'object_name' => 'admin' ) );
		} catch ( \Throwable $e ) {
			$this->fail( 'A logger exception escaped into the login flow: ' . $e->getMessage() );
		}
		$this->assertTrue( true );
	}

	// --- Crypto ---

	public function test_decrypt_fails_closed_on_every_malformed_input(): void {
		$v1 = Crypto::encrypt( 'secret' );
		$this->assertStringStartsWith( 'DRGNc1:', $v1 );
		$raw = base64_decode( substr( $v1, 7 ), true );

		$cases = array(
			'empty'                 => '',
			'prefix only'           => 'DRGNc1:',
			'prefix + junk'         => 'DRGNc1:%%%not-base64',
			'prefix + short'        => 'DRGNc1:' . base64_encode( random_bytes( 63 ) ),
			'tampered mac'          => 'DRGNc1:' . base64_encode( substr( $raw, 0, 16 ) . ( substr( $raw, 16, 1 ) ^ "\x01" ) . substr( $raw, 17 ) ),
			'tampered ciphertext'   => 'DRGNc1:' . base64_encode( substr( $raw, 0, 48 ) . ( substr( $raw, 48, 1 ) ^ "\x01" ) . substr( $raw, 49 ) ),
			'truncated'             => substr( $v1, 0, -8 ),
			'legacy too short'      => base64_encode( random_bytes( 16 ) ),
			'legacy not base64'     => "\xff\xfe binary junk \x00",
			'legacy invalid base64' => 'abc$def',
			'wrong prefix case'     => 'drgnc1:' . substr( $v1, 7 ),
		);
		foreach ( $cases as $name => $input ) {
			$this->assertNull( Crypto::decrypt( $input ), $name );
		}
	}

	public function test_round_trips_and_legacy_format(): void {
		foreach ( array( '', 'JBSWY3DPEHPK3PXP', random_bytes( 100 ), 'ünïcödé 🐉' ) as $plain ) {
			$this->assertSame( $plain, Crypto::decrypt( Crypto::encrypt( $plain ) ) );
		}
		$this->assertNotSame( Crypto::encrypt( 'a' ), Crypto::encrypt( 'a' ), 'A fresh IV each time.' );

		// What the 1.0.7 helper wrote: base64( IV + AES-256-CBC ciphertext ), no MAC.
		$key    = hash( 'sha256', wp_salt( 'auth' ), true );
		$iv     = random_bytes( 16 );
		$legacy = base64_encode( $iv . openssl_encrypt( 'JBSWY3DPEHPK3PXP', 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv ) );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', Crypto::decrypt( $legacy ) );
	}
}
