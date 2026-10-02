<?php
/**
 * Opted-in uninstall removes every option the plugin writes.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
class UninstallTest extends TestCase {

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_opted_in_uninstall_leaves_no_options_behind(): void {
		define( 'WP_UNINSTALL_PLUGIN', 'dragon-login-security/dragon-login-security.php' );
		eval( 'function wp_clear_scheduled_hook( $h ) { return 0; } function delete_metadata( ...$a ) { return true; }' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged
		$GLOBALS['wpdb'] = new class() extends \DLS_Test_Wpdb {
			public function query( $q ) {
				unset( $q );
				return true;
			}
		};

		$GLOBALS['dls_test_options'] = array(
			'dragonloginsecurity_delete_data_on_uninstall' => 1,
			'dragonloginsecurity_settings'                 => array( 'trust_proxy' => 0 ),
			'dragonloginsecurity_db_version'               => '1',
			'dragonloginsecurity_schema_failure'           => array( 'tables' => array( 'wp_dls_lockouts' ) ),
			'dragonloginsecurity_pro_pointer'              => array(),
			'dragonloginsecurity_pro_pointer_events'       => 2,
			'dragonloginsecurity_proxy_mismatch'           => array( 'ip' => '6.6.6.6', 'time' => 1 ),
			'blogname'                                     => 'Kept',
		);

		require __DIR__ . '/../uninstall.php';

		$this->assertSame( array( 'blogname' ), array_keys( $GLOBALS['dls_test_options'] ) );
	}

	/**
	 * Stored opt-in values and whether they mean "delete my data".
	 *
	 * @return array<string,array{0:mixed,1:bool}>
	 */
	public static function opt_in_values(): array {
		return array(
			'bool true'      => array( true, true ),
			'int 1'          => array( 1, true ),
			'string 1'       => array( '1', true ),
			'string true'    => array( 'true', true ),
			'string TRUE'    => array( 'TRUE', true ),
			'padded yes'     => array( ' yes ', true ),
			'string on'      => array( 'on', true ),
			'bool false'     => array( false, false ),
			'int 0'          => array( 0, false ),
			'empty string'   => array( '', false ),
			'string 0'       => array( '0', false ),
			'string false'   => array( 'false', false ),
			'string no'      => array( 'no', false ),
			'string off'     => array( 'off', false ),
			'string No'      => array( 'No', false ),
			'another string' => array( 'random', false ),
			'missing'        => array( null, false ),
			'empty array'    => array( array(), false ),
		);
	}

	/**
	 * @param mixed $stored  Stored opt-in value; null leaves the option unset.
	 * @param bool  $deletes Whether the data is removed.
	 */
	#[DataProvider( 'opt_in_values' )]
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_only_a_clear_opt_in_removes_the_data( $stored, bool $deletes ): void {
		define( 'WP_UNINSTALL_PLUGIN', 'dragon-login-security/dragon-login-security.php' );
		eval( 'function wp_clear_scheduled_hook( $h ) { return 0; } function delete_metadata( ...$a ) { $GLOBALS["dls_test_meta_deleted"][] = $a[2]; return true; }' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged
		$GLOBALS['dls_test_meta_deleted'] = array();
		$GLOBALS['wpdb']                  = new class() extends \DLS_Test_Wpdb {
			public $queries = array();
			public function query( $q ) {
				$this->queries[] = $q;
				return true;
			}
		};

		$data = array(
			'dragonloginsecurity_settings'   => array( 'trust_proxy' => 0 ),
			'dragonloginsecurity_db_version' => '1',
			'blogname'                       => 'Kept',
		);
		if ( null !== $stored ) {
			$data['dragonloginsecurity_delete_data_on_uninstall'] = $stored;
		}
		$GLOBALS['dls_test_options'] = $data;

		require __DIR__ . '/../uninstall.php';

		if ( $deletes ) {
			$this->assertSame( array( 'blogname' ), array_keys( $GLOBALS['dls_test_options'] ) );
			$this->assertStringContainsString( 'dls_lockouts', implode( "\n", $GLOBALS['wpdb']->queries ) );
			$this->assertContains( 'dls_totp_secret', $GLOBALS['dls_test_meta_deleted'] );
			return;
		}

		$this->assertSame( $data, $GLOBALS['dls_test_options'], 'options are untouched' );
		$this->assertSame( array(), $GLOBALS['wpdb']->queries, 'no table is dropped' );
		$this->assertSame( array(), $GLOBALS['dls_test_meta_deleted'], 'user meta is untouched' );
	}
}
