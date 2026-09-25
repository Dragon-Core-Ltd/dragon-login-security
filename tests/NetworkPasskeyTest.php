<?php
/**
 * On a multisite network a passkey on any site counts as two-factor enrolment.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Credentials;
use DragonLoginSecurity\Plugin;
use DragonLoginSecurity\Provider_Passkey;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Provider_Passkey::class )]
#[CoversClass( Credentials::class )]
#[CoversClass( Plugin::class )]
class NetworkPasskeyTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_multisite'] = true;
		WebAuthn::$available_override  = true;
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		// This request runs on site 2; user 8 registered a passkey on site 3.
		$GLOBALS['wpdb']->prefix = 'wp_2_';
		$GLOBALS['wpdb']->rows   = array(
			'wp_2_dls_credentials'       => array(),
			'wp_3_dls_credentials'       => array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'x', 'public_key' => 'k', 'sign_count' => 0 ) ),
			// Not ours despite the similar name.
			'wp_3_old_dls_credentials'   => array( array( 'id' => 1, 'user_id' => 9, 'credential_id' => 'y', 'public_key' => 'k', 'sign_count' => 0 ) ),
		);
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_multisite'] = false;
		WebAuthn::$available_override  = null;
	}

	public function test_deleting_a_site_drops_this_plugins_tables_with_it(): void {
		// During wpmu_drop_tables $wpdb is switched to the site being removed.
		$GLOBALS['wpdb']->prefix = 'wp_3_';
		$plugin                  = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$dropped                 = $plugin->drop_site_tables( array( 'wp_3_posts' ) );
		$this->assertContains( 'wp_3_dls_credentials', $dropped );
		$this->assertContains( 'wp_3_dls_lockouts', $dropped );
		$this->assertContains( 'wp_3_posts', $dropped ); // Core's own tables are kept.
	}

	public function test_passkey_on_another_site_counts_as_enrolled(): void {
		$this->assertFalse( Provider_Passkey::is_enrolled( 8 ) );
		$this->assertTrue( Provider_Passkey::is_enrolled_on_network( 8 ) );
		$this->assertTrue( ( new Two_Factor() )->user_has_2fa( 8 ) );
	}

	public function test_challenge_offers_only_this_sites_passkeys(): void {
		$this->assertNotContains( 'passkey', ( new Two_Factor() )->available_methods( 8 ) );
	}

	public function test_unrelated_tables_and_users_do_not_count(): void {
		$this->assertFalse( Provider_Passkey::is_enrolled_on_network( 9 ) );
		$this->assertFalse( Provider_Passkey::is_enrolled_on_network( 10 ) );
	}

	public function test_single_site_looks_only_at_its_own_table(): void {
		$GLOBALS['dls_test_multisite'] = false;
		$this->assertFalse( Provider_Passkey::is_enrolled_on_network( 8 ) );
	}

	public function test_recovery_removes_passkeys_on_every_site(): void {
		$GLOBALS['wpdb']->rows['wp_2_dls_credentials'][] = array( 'id' => 2, 'user_id' => 8, 'credential_id' => 'z', 'public_key' => 'k', 'sign_count' => 0 );
		$GLOBALS['wpdb']->rows['wp_3_dls_credentials'][] = array( 'id' => 3, 'user_id' => 11, 'credential_id' => 'w', 'public_key' => 'k', 'sign_count' => 0 );

		Credentials::delete_for_user_on_network( 8 );

		$this->assertFalse( ( new Two_Factor() )->user_has_2fa( 8 ) );
		$this->assertTrue( Provider_Passkey::is_enrolled_on_network( 11 ) );
	}
}
