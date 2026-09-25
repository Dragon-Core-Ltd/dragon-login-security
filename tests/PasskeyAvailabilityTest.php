<?php
/**
 * A stored passkey only counts as a second factor while WebAuthn is available.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Provider_Passkey;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Provider_Passkey::class )]
class PasskeyAvailabilityTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_multisite'] = false;
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		$GLOBALS['wpdb']->rows         = array(
			'wp_dls_credentials' => array(
				array( 'id' => 1, 'user_id' => 7, 'credential_id' => 'a', 'public_key' => 'k', 'sign_count' => 0 ),
			),
		);
		WebAuthn::$available_override = null;
	}

	protected function tearDown(): void {
		WebAuthn::$available_override = null;
	}

	public function test_passkey_counts_when_available(): void {
		WebAuthn::$available_override = true;
		$this->assertTrue( Provider_Passkey::is_enrolled( 7 ) );
		$this->assertTrue( Provider_Passkey::is_enrolled_on_network( 7 ) );
		$this->assertTrue( ( new Two_Factor() )->user_has_2fa( 7 ) );
	}

	public function test_unusable_passkey_is_not_a_factor(): void {
		// The library is gone: the stored passkey cannot be completed, so it must
		// not put the user in front of a dead-end challenge, and Pro enforcement
		// must not treat the account as already having a second factor.
		WebAuthn::$available_override = false;
		$this->assertFalse( Provider_Passkey::is_enrolled( 7 ) );
		$this->assertFalse( Provider_Passkey::is_enrolled_on_network( 7 ) );
		$this->assertFalse( ( new Two_Factor() )->user_has_2fa( 7 ) );
	}

	public function test_stored_credentials_are_still_detectable_for_the_warning(): void {
		WebAuthn::$available_override = false;
		$this->assertTrue( Provider_Passkey::has_stored_credentials( 7 ) );
		$this->assertFalse( Provider_Passkey::has_stored_credentials( 99 ) );
	}
}
