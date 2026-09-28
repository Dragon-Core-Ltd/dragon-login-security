<?php
/**
 * Scenario hunt: the personal-data exporter and eraser for users with data
 * on several network sites, no data, malformed meta, and after erasure.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Privacy;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\TestCase;

class ScenarioPrivacyTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                   = new class() extends \DLS_Test_Wpdb {
			public $queries      = array();
			public $query_result = 1;
			public function query( $sql ) {
				$this->queries[] = $sql;
				return $this->query_result;
			}
		};
		$GLOBALS['dls_test_user_meta']     = array();
		$GLOBALS['dls_test_multisite']     = false;
		$GLOBALS['dls_test_options']       = array(
			'date_format' => 'Y-m-d',
			'time_format' => 'H:i',
		);
		$GLOBALS['dls_test_actions_fired'] = array();
		$GLOBALS['dls_test_mail']          = array();
		$user                              = new \WP_User( 8, 'pat' );
		$user->user_email                  = 'pat@example.test';
		$GLOBALS['dls_test_users']         = array( 8 => $user );
		WebAuthn::$available_override      = true;
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_multisite'] = false;
		WebAuthn::$available_override  = null;
	}

	private function items( array $export ): array {
		$out = array();
		foreach ( $export['data'][0]['data'] ?? array() as $item ) {
			$out[ $item['name'] ][] = $item['value'];
		}
		return $out;
	}

	public function test_unknown_email_exports_and_erases_nothing(): void {
		$p = new Privacy();
		$this->assertSame( array( 'data' => array(), 'done' => true ), $p->export( 'nobody@example.test' ) );
		$erase = $p->erase( 'nobody@example.test' );
		$this->assertFalse( $erase['items_removed'] );
		$this->assertTrue( $erase['done'] );
		$this->assertSame( array(), $GLOBALS['wpdb']->queries, 'No table is touched for an unknown address.' );
	}

	public function test_export_never_leaks_secret_material(): void {
		update_user_meta( 8, Two_Factor::TOTP_META, \DragonLoginSecurity\Crypto::encrypt( 'JBSWY3DPEHPK3PXP' ) );
		Provider_Backup_Codes::store( 8, array( 'aaaaa-bbbbb', 'ccccc-ddddd' ) );
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'SECRETID', 'public_key' => 'PEMKEY', 'sign_count' => 3, 'label' => '<b>Phone</b>', 'created_at' => '2026-01-02 03:04:05', 'last_used_at' => null ),
		);

		$json = wp_json_encode( ( new Privacy() )->export( 'pat@example.test' ) );

		$this->assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', $json );
		$this->assertStringNotContainsString( 'SECRETID', $json );
		$this->assertStringNotContainsString( 'PEMKEY', $json );
		$this->assertStringNotContainsString( '$2y$', $json );
		$items = $this->items( json_decode( $json, true ) );
		$this->assertSame( array( '2' ), $items['Backup codes remaining'] );
		$this->assertStringContainsString( 'registered 2026-01-02 03:04, last used never', $items['Passkey'][0] );
	}

	public function test_export_counts_backup_codes_the_way_the_challenge_does(): void {
		// Malformed meta (a string where the hash list should be). The challenge
		// treats it as no codes; the export must not report a code the user
		// cannot use.
		update_user_meta( 8, Provider_Backup_Codes::META_KEY, 'not-a-list' );
		$this->assertSame( 0, Provider_Backup_Codes::remaining( 8 ) );

		$items = $this->items( ( new Privacy() )->export( 'pat@example.test' ) );

		$this->assertSame( array( '0' ), $items['Backup codes remaining'] );
	}

	public function test_export_on_a_network_includes_passkeys_registered_on_other_sites(): void {
		// Erasure removes passkeys from every site of the network (they count as
		// a factor everywhere), so the export must list them too, or the user is
		// shown less than what is held about them.
		$GLOBALS['dls_test_multisite'] = true;
		$GLOBALS['wpdb']->prefix       = 'wp_2_';
		$GLOBALS['wpdb']->rows         = array(
			'wp_2_dls_credentials' => array(),
			'wp_3_dls_credentials' => array(
				array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'x', 'public_key' => 'k', 'sign_count' => 0, 'label' => 'Work laptop', 'created_at' => '2026-01-02 03:04:05', 'last_used_at' => null ),
			),
		);

		$items = $this->items( ( new Privacy() )->export( 'pat@example.test' ) );

		$this->assertArrayHasKey( 'Passkey', $items, 'The passkey on site 3 is part of the personal data held.' );
		$this->assertStringContainsString( 'Work laptop', $items['Passkey'][0] );
	}

	public function test_erasure_removes_every_per_user_meta_the_plugin_writes(): void {
		$keys = array(
			Two_Factor::TOTP_META,
			Two_Factor::TOTP_UNREADABLE_MAILED_META,
			Two_Factor::CODE_FAILURES_META,
			Two_Factor::CODE_LOCK_MAILED_META,
			Provider_Backup_Codes::META_KEY,
			'dls_backup_codes_confirmed',
			'dls_totp_last_step',
		);
		foreach ( $keys as $key ) {
			update_user_meta( 8, $key, 'x' );
		}

		$erase = ( new Privacy() )->erase( 'pat@example.test' );

		$this->assertTrue( $erase['items_removed'] );
		$left = array_keys( $GLOBALS['dls_test_user_meta'][8] ?? array() );
		$this->assertSame( array(), $left, 'Meta left behind after erasure: ' . implode( ', ', $left ) );
	}

	public function test_erasure_leaves_the_account_able_to_sign_in_with_a_password(): void {
		$GLOBALS['dls_test_multisite'] = true;
		$GLOBALS['wpdb']->prefix       = 'wp_2_';
		$GLOBALS['wpdb']->rows         = array(
			'wp_2_dls_credentials' => array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'a', 'public_key' => 'k', 'sign_count' => 0 ) ),
			'wp_3_dls_credentials' => array( array( 'id' => 2, 'user_id' => 8, 'credential_id' => 'b', 'public_key' => 'k', 'sign_count' => 0 ) ),
			'wp_2_dls_lockouts'    => array(),
			'wp_3_dls_lockouts'    => array(),
		);
		update_user_meta( 8, Two_Factor::TOTP_META, 'not-a-ciphertext' ); // unreadable, still "enrolled"
		Provider_Backup_Codes::store( 8, Provider_Backup_Codes::generate( 3 ) );
		update_user_meta( 8, Two_Factor::CODE_FAILURES_META, array( 'count' => 5, 'since' => time() ) );
		$tf = new Two_Factor();
		$this->assertTrue( $tf->user_has_2fa( 8 ) );
		$this->assertTrue( $tf->code_locked( 8 ) );

		$erase = ( new Privacy() )->erase( 'pat@example.test' );

		$this->assertTrue( $erase['items_removed'] );
		$this->assertFalse( $tf->user_has_2fa( 8 ) );
		$this->assertSame( array(), $tf->available_methods( 8 ) );
		$this->assertFalse( $tf->code_locked( 8 ) );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_2_dls_credentials'] );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_3_dls_credentials'] );
		// Lockout history is cleared on every site's table.
		$this->assertCount( 2, $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( 'wp_3_dls_lockouts', implode( "\n", $GLOBALS['wpdb']->queries ) );
		$this->assertStringContainsString( "username = pat", implode( "\n", $GLOBALS['wpdb']->queries ) );
	}

	public function test_erasure_survives_a_missing_lockouts_table(): void {
		$GLOBALS['wpdb']->query_result = false; // DELETE on a table that is not there.
		update_user_meta( 8, Provider_Backup_Codes::META_KEY, array( 'h' ) );

		$erase = ( new Privacy() )->erase( 'pat@example.test' );

		$this->assertTrue( $erase['done'] );
		$this->assertTrue( $erase['items_removed'], 'The meta that was removed still counts.' );
		$this->assertFalse( $erase['items_retained'] );
	}
}
