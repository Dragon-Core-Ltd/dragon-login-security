<?php
/**
 * The integration must never fatal when Dragon Activity Log is absent.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Integration;
use DragonLoginSecurity\Events;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Integration::class )]
#[CoversClass( Events::class )]
class IntegrationGuardTest extends TestCase {

	public function test_forward_is_noop_without_activity_log(): void {
		// \DragonActivityLog\Plugin is not loaded in this suite.
		$i = new Integration();
		$i->forward( 'user.login_failed', array( 'object_name' => 'admin' ) );
		$this->assertFalse( class_exists( '\\DragonActivityLog\\Plugin' ) );
	}

	public function test_register_merges_codes(): void {
		$i   = new Integration();
		$out = $i->register( array( 'existing' => array( 'x', 1, 'y' ) ) );
		$this->assertArrayHasKey( 'existing', $out );
		$this->assertArrayHasKey( 'user.lockout', $out );
		$this->assertArrayHasKey( '2fa.passed', $out );
	}

	public function test_registers_on_current_and_legacy_activity_log_hooks(): void {
		$GLOBALS['dls_test_filters'] = array();
		$i                           = new Integration();
		$hooks                       = array();
		foreach ( $GLOBALS['dls_test_filters'] as $args ) {
			if ( is_array( $args[1] ) && $args[1][0] === $i && 'register' === $args[1][1] ) {
				$hooks[] = $args[0];
			}
		}
		$this->assertContains( 'dragonactivitylog_register_event', $hooks );
		$this->assertContains( 'dal_register_event', $hooks );
		$this->assertCount( 2, $hooks );

		$once  = $i->register( array() );
		$twice = $i->register( $once );
		$this->assertSame( $once, $twice );
	}

	public function test_register_keeps_activity_log_definitions(): void {
		$native = array( 'user.login_failed' => array( 'Native label', 3, 'user' ) );
		$out    = ( new Integration() )->register( $native );
		$this->assertSame( $native['user.login_failed'], $out['user.login_failed'] );
		$this->assertArrayHasKey( 'user.lockout', $out );
	}

	public function test_register_is_a_noop_before_init(): void {
		$GLOBALS['dls_test_actions_done'] = array();
		try {
			$out = ( new Integration() )->register( array( 'existing' => array( 'x', 1, 'y' ) ) );
		} finally {
			$GLOBALS['dls_test_actions_done'] = array( 'init' => 1 );
		}
		$this->assertSame( array( 'existing' => array( 'x', 1, 'y' ) ), $out );
	}

	public function test_codes_have_valid_shape(): void {
		foreach ( Events::codes() as $code => $def ) {
			$this->assertIsString( $code );
			$this->assertCount( 3, $def );
			$this->assertIsInt( $def[1] );
		}
	}
}
