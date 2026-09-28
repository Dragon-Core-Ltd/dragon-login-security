<?php
/**
 * Scenario hunt: importing allow/deny lists from Limit Login Attempts
 * (Reloaded) and Wordfence with the formats those plugins really store.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Importer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Importer::class )]
class ScenarioImporterTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['wpdb']                        = new \DLS_Test_Wpdb();
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_option_write_fails'] = false;
	}

	public function test_detection_needs_either_lla_option_or_the_wordfence_table(): void {
		$this->assertSame( array(), Importer::detect() );

		update_option( 'limit_login_blacklist_ip', array() );
		$this->assertSame( array( 'limit-login' ), array_keys( Importer::detect() ), 'an empty list still marks the plugin as present' );

		$GLOBALS['dls_test_options'] = array();
		update_option( 'limit_login_whitelist_ip', '' );
		$this->assertSame( array( 'limit-login' ), array_keys( Importer::detect() ) );

		$GLOBALS['dls_test_options']       = array();
		$GLOBALS['wpdb']->existing_tables  = array( 'wp_wfconfig' );
		$this->assertSame( array( 'wordfence' ), array_keys( Importer::detect() ) );
		// Another site's table on a shared database does not count.
		$GLOBALS['wpdb']->existing_tables = array( 'other_wfconfig' );
		$this->assertSame( array(), Importer::detect() );
	}

	public function test_lla_reloaded_lists_with_ranges_usernames_and_mixed_formats(): void {
		// LLA Reloaded stores IPs and "start-end" ranges in the _ip options and
		// usernames in the un-suffixed ones; a site may also have hand-edited
		// entries with spaces, CIDR (from a fork) or an IPv6 address.
		$allow = array( '203.0.113.9', '192.168.0.1-192.168.0.100', ' 10.0.0.0/24 ', '2001:db8::1', 'admin', '', null, 42, '203.0.113.9' );
		$deny  = array( '198.51.100.7', '198.51.100.*', '[2001:db8::1]', '198.51.100.7' );
		$result = Importer::merge_lists( $allow, $deny );
		$this->assertTrue( $result['saved'] );
		$this->assertSame( 3, $result['allow'] );
		$this->assertSame( 1, $result['deny'] );
		$this->assertSame( 5, $result['skipped'], 'range, username, integer, wildcard and bracketed address are skipped' );
		$settings = get_option( 'dragonloginsecurity_settings' );
		$this->assertSame( array( '203.0.113.9', '10.0.0.0/24', '2001:db8::1' ), $settings['allow_ips'] );
		$this->assertSame( array( '198.51.100.7' ), $settings['deny_ips'] );
	}

	public function test_import_merges_into_existing_lists_without_duplicates_and_keeps_other_settings(): void {
		update_option(
			'dragonloginsecurity_settings',
			array(
				'trust_proxy'     => true,
				'proxy_header'    => 'cf_connecting_ip',
				'trusted_proxies' => array( '173.245.48.0/20' ),
				'allow_ips'       => array( '203.0.113.9' ),
				'deny_ips'        => array(),
			)
		);
		$result = Importer::merge_lists( array( '203.0.113.9', '203.0.113.10' ), array( '203.0.113.9' ) );
		$this->assertSame( 1, $result['allow'] );
		$this->assertSame( 1, $result['deny'], 'the same address may sit on both lists; the allow list wins at match time' );
		$this->assertSame( 0, $result['skipped'] );
		$settings = get_option( 'dragonloginsecurity_settings' );
		$this->assertTrue( $settings['trust_proxy'] );
		$this->assertSame( 'cf_connecting_ip', $settings['proxy_header'] );
		$this->assertSame( array( '173.245.48.0/20' ), $settings['trusted_proxies'] );
		$this->assertSame( array( '203.0.113.9', '203.0.113.10' ), $settings['allow_ips'] );
	}

	public function test_a_whole_internet_range_from_another_plugin_is_skipped(): void {
		$result = Importer::merge_lists( array( '0.0.0.0/0', '::/0', '::ffff:0:0/96', '1.0.0.0/7' ), array() );
		$this->assertSame( 0, $result['allow'] );
		$this->assertSame( 4, $result['skipped'] );
		$this->assertSame( array(), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
	}

	public function test_wordfence_whitelist_string_shapes(): void {
		foreach ( array( '', null, false, '  ', ',,', "\n" ) as $raw ) {
			$GLOBALS['dls_test_options'] = array();
			$allow = preg_split( '/[\s,]+/', (string) $raw );
			$result = Importer::merge_lists( false === $allow ? array() : $allow, array() );
			$this->assertSame( 0, $result['allow'], wp_json_encode( $raw ) );
			$this->assertSame( 0, $result['skipped'], wp_json_encode( $raw ) );
			$this->assertTrue( $result['saved'] );
		}
		// Wordfence's own formats: plain, CIDR, bracket ranges, dash ranges, IPv6.
		$raw    = "203.0.113.9,203.0.113.0/24, 192.168.[1-10].[1-255]\n10.0.0.1-10.0.0.9 2001:db8::/32";
		$result = Importer::merge_lists( preg_split( '/[\s,]+/', $raw ), array() );
		$this->assertSame( 3, $result['allow'] );
		$this->assertSame( 2, $result['skipped'] );
	}

	public function test_a_list_already_at_the_cap_accepts_nothing_and_counts_every_candidate_as_skipped(): void {
		$full = array();
		for ( $i = 0; $i < 1200; $i++ ) {
			$full[] = '10.' . intdiv( $i, 256 ) . '.' . ( $i % 256 ) . '.1';
		}
		update_option( 'dragonloginsecurity_settings', array( 'allow_ips' => $full ) );
		$result = Importer::merge_lists( array( '203.0.113.9', '10.0.0.1' ), array( '198.51.100.7' ) );
		$this->assertSame( 0, $result['allow'] );
		$this->assertSame( 1, $result['skipped'], 'a duplicate is neither added nor skipped' );
		$this->assertSame( 1, $result['deny'], 'the deny list has its own cap' );
		$this->assertCount( 1200, get_option( 'dragonloginsecurity_settings' )['allow_ips'], 'an over-cap list saved by hand is kept as is' );
	}

	public function test_a_failed_save_reports_nothing_added_and_leaves_the_lists_alone(): void {
		update_option( 'dragonloginsecurity_settings', array( 'allow_ips' => array( '203.0.113.9' ) ) );
		$GLOBALS['dls_test_option_write_fails'] = true;
		$result = Importer::merge_lists( array( '203.0.113.10' ), array() );
		$this->assertFalse( $result['saved'] );
		$this->assertSame( array( '203.0.113.9' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		// Nothing new once the database is back: the unchanged option is a
		// confirmed save.
		$GLOBALS['dls_test_option_write_fails'] = false;
		$result = Importer::merge_lists( array( '203.0.113.9' ), array() );
		$this->assertTrue( $result['saved'] );
		$this->assertSame( 0, $result['allow'] );
	}

	public function test_settings_stored_in_a_wrong_shape_do_not_break_the_import(): void {
		foreach ( array( 'a string', 42, null, array( 'allow_ips' => 'single' ) ) as $stored ) {
			$GLOBALS['dls_test_options'] = array( 'dragonloginsecurity_settings' => $stored );
			$result = Importer::merge_lists( array( '203.0.113.9' ), array() );
			$this->assertSame( 1, $result['allow'], wp_json_encode( $stored ) );
			$this->assertContains( '203.0.113.9', get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		}
	}
}
