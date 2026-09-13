<?php
/**
 * Tests for the Pro pointer's timing rule.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Pro_Pointer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Pro_Pointer::class )]
class ProPointerTest extends TestCase {

	private const NOW = 1_800_000_000;
	private const DAY = 86400;

	public function test_nothing_shows_before_any_value(): void {
		$this->assertFalse( Pro_Pointer::is_due( array( 'first_use' => self::NOW - 10 * self::DAY, 'events' => 0 ), self::NOW ) );
		$this->assertFalse( Pro_Pointer::is_due( array( 'first_use' => 0, 'events' => 5 ), self::NOW ) );
	}

	public function test_one_event_waits_for_the_minimum_age(): void {
		$fresh = array( 'first_use' => self::NOW - self::DAY, 'events' => 1 );
		$aged  = array( 'first_use' => self::NOW - ( Pro_Pointer::MIN_AGE_DAYS + 1 ) * self::DAY, 'events' => 1 );
		$this->assertFalse( Pro_Pointer::is_due( $fresh, self::NOW ) );
		$this->assertTrue( Pro_Pointer::is_due( $aged, self::NOW ) );
	}

	public function test_enough_events_show_early(): void {
		$this->assertTrue( Pro_Pointer::is_due( array( 'first_use' => self::NOW - 60, 'events' => Pro_Pointer::EARLY_EVENTS ), self::NOW ) );
	}

	public function test_dismissed_and_snoozed_stay_quiet(): void {
		$base = array( 'first_use' => self::NOW - 30 * self::DAY, 'events' => 9 );
		$this->assertFalse( Pro_Pointer::is_due( $base + array( 'dismissed' => true ), self::NOW ) );
		$this->assertFalse( Pro_Pointer::is_due( $base + array( 'snoozed_until' => self::NOW + self::DAY ), self::NOW ) );
		$this->assertTrue( Pro_Pointer::is_due( $base + array( 'snoozed_until' => self::NOW - 1 ), self::NOW ) );
	}
}
