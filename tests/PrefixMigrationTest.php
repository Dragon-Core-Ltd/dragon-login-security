<?php
/**
 * The one-time move off the pre-1.0.2 option prefix runs once, not on every
 * request.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Plugin;
use PHPUnit\Framework\TestCase;

class PrefixMigrationTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_option_write_fails'] = false;
	}

	private function migrate(): void {
		$method = new \ReflectionMethod( Plugin::class, 'migrate_legacy_prefix' );
		$method->setAccessible( true );
		$method->invoke( null );
	}

	public function test_legacy_options_are_carried_over_once(): void {
		update_option( 'dls_settings', array( 'trust_proxy' => true ) );
		$this->migrate();
		$this->assertSame( array( 'trust_proxy' => true ), get_option( 'dragonloginsecurity_settings' ) );
		$this->assertFalse( get_option( 'dls_settings' ) );
		$this->assertSame( '1', (string) get_option( Plugin::PREFIX_MIGRATED_OPTION ) );

		// Done: a legacy option appearing later is left alone.
		update_option( 'dls_settings', array( 'trust_proxy' => false ) );
		$this->migrate();
		$this->assertSame( array( 'trust_proxy' => true ), get_option( 'dragonloginsecurity_settings' ) );
		$this->assertSame( array( 'trust_proxy' => false ), get_option( 'dls_settings' ) );
	}

	public function test_a_fresh_install_is_marked_done_without_legacy_options(): void {
		$this->migrate();
		$this->assertSame( '1', (string) get_option( Plugin::PREFIX_MIGRATED_OPTION ) );
	}

	public function test_an_unconfirmed_copy_is_not_marked_done(): void {
		update_option( 'dls_settings', array( 'a' => 1 ) );
		$GLOBALS['dls_test_option_write_fails'] = true;
		$this->migrate();
		$this->assertFalse( get_option( Plugin::PREFIX_MIGRATED_OPTION ) );
		$this->assertSame( array( 'a' => 1 ), get_option( 'dls_settings' ) );
	}
}
