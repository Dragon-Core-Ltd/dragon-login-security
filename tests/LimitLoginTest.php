<?php
/**
 * Tests for the brute-force lockout ladder (pure logic).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Limit_Login::class )]
class LimitLoginTest extends TestCase {

	public function test_escalating_lockout_ladder(): void {
		$l = new Limit_Login();
		$this->assertSame( 0, $l->lockout_seconds( 4 ) );      // below threshold = no lock
		$this->assertSame( 900, $l->lockout_seconds( 5 ) );    // 15 min
		$this->assertSame( 900, $l->lockout_seconds( 9 ) );
		$this->assertSame( 3600, $l->lockout_seconds( 10 ) );  // 1 hr
		$this->assertSame( 3600, $l->lockout_seconds( 19 ) );
		$this->assertSame( 86400, $l->lockout_seconds( 20 ) ); // 24 hr cap
		$this->assertSame( 86400, $l->lockout_seconds( 500 ) );
	}

	public function test_tier_boundary_detection(): void {
		$l = new Limit_Login();
		$this->assertTrue( $l->is_tier_boundary( 5 ) );
		$this->assertTrue( $l->is_tier_boundary( 10 ) );
		$this->assertTrue( $l->is_tier_boundary( 20 ) );
		$this->assertFalse( $l->is_tier_boundary( 6 ) );
		$this->assertFalse( $l->is_tier_boundary( 4 ) );
	}
}
