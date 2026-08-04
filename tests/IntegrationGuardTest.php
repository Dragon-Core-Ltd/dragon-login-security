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

	public function test_codes_have_valid_shape(): void {
		foreach ( Events::codes() as $code => $def ) {
			$this->assertIsString( $code );
			$this->assertCount( 3, $def );
			$this->assertIsInt( $def[1] );
		}
	}
}
