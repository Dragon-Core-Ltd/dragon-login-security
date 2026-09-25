<?php
/**
 * Opted-in uninstall removes every option the plugin writes.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
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
			'blogname'                                     => 'Kept',
		);

		require __DIR__ . '/../uninstall.php';

		$this->assertSame( array( 'blogname' ), array_keys( $GLOBALS['dls_test_options'] ) );
	}
}
