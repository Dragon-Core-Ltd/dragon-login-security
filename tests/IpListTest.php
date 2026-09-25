<?php
/**
 * Allow/deny list entries: single addresses and CIDR ranges.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use DragonLoginSecurity\Importer;
use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( IP::class )]
#[CoversClass( Admin::class )]
#[CoversClass( Importer::class )]
class IpListTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_transients']         = array();
	}

	public function test_list_entry_validation(): void {
		$this->assertSame( '10.9.9.0/24', IP::normalise_list_entry( '10.9.9.0/24' ) );
		$this->assertSame( '2001:db8::/32', IP::normalise_list_entry( '2001:db8::/32' ) );
		$this->assertSame( '203.0.113.9', IP::normalise_list_entry( ' 203.0.113.9 ' ) );
		$this->assertSame( '::ffff:10.0.0.0/104', IP::normalise_list_entry( '::ffff:10.0.0.0/104' ) );
		$this->assertNull( IP::normalise_list_entry( '10.0.0.0/33' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::/129' ) );
		$this->assertNull( IP::normalise_list_entry( '10.0.0.0/' ) );
		$this->assertNull( IP::normalise_list_entry( '10.0.0.0/-1' ) );
		$this->assertNull( IP::normalise_list_entry( '10.0.0.0/8/8' ) );
		$this->assertNull( IP::normalise_list_entry( '10.0.0.1-10.0.0.9' ) );
		$this->assertNull( IP::normalise_list_entry( 'office' ) );
	}

	public function test_range_matching(): void {
		$this->assertTrue( IP::in_ranges( '10.9.9.255', array( '10.9.9.0/24' ) ) );
		$this->assertFalse( IP::in_ranges( '10.9.10.0', array( '10.9.9.0/24' ) ) );
		$this->assertTrue( IP::in_ranges( '172.31.0.1', array( '172.16.0.0/12' ) ) );
		$this->assertFalse( IP::in_ranges( '172.32.0.1', array( '172.16.0.0/12' ) ) );
		$this->assertTrue( IP::in_ranges( '8.8.8.8', array( '0.0.0.0/0' ) ) );
		$this->assertFalse( IP::in_ranges( '2001:db8::1', array( '0.0.0.0/0' ) ) );
		$this->assertTrue( IP::in_ranges( '::ffff:10.9.9.1', array( '10.9.9.0/24' ) ) );
		$this->assertTrue( IP::in_ranges( '10.9.9.1', array( '::ffff:10.9.9.0/120' ) ) );
		$this->assertFalse( IP::in_ranges( '10.9.8.1', array( '::ffff:10.9.9.0/120' ) ) );
		$this->assertTrue( IP::in_ranges( '10.1.2.3', array( '::ffff:0:0/96' ) ) );
		$this->assertTrue( IP::in_ranges( '2001:db8:abcd:12::1', array( '2001:db8:abcd:0010::/60' ) ) );
		$this->assertFalse( IP::in_ranges( '2001:db8:abcd:20::1', array( '2001:db8:abcd:0010::/60' ) ) );
		$this->assertTrue( IP::in_ranges( '2001:db8::7', array( '2001:DB8:0:0::7' ) ) );
		$this->assertFalse( IP::in_ranges( 'garbage', array( '0.0.0.0/0' ) ) );
	}

	public function test_settings_parse_keeps_ranges_and_names_invalid_entries(): void {
		$parsed = Admin::parse_ip_list( "203.0.113.9\n10.9.9.0/24\r\n2001:db8::/32\n\nnot-an-ip\n10.0.0.0/40\n203.0.113.9" );
		$this->assertSame( array( '203.0.113.9', '10.9.9.0/24', '2001:db8::/32' ), $parsed['valid'] );
		$this->assertSame( array( 'not-an-ip', '10.0.0.0/40' ), $parsed['invalid'] );
	}

	public function test_save_notice_names_refused_entries(): void {
		Admin::record_save_result( true, true, array( 'not-an-ip', '10.0.0.0/40' ) );
		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'not-an-ip', $notice['message'] );
		$this->assertStringContainsString( '10.0.0.0/40', $notice['message'] );
		$this->assertStringNotContainsString( 'Settings saved.', $notice['message'] );
	}

	public function test_save_notice_without_refused_entries_is_unchanged(): void {
		Admin::record_save_result( true, true, array() );
		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'success', $notice['type'] );
		$this->assertSame( 'Settings saved.', $notice['message'] );
	}

	public function test_import_keeps_ranges(): void {
		$result = Importer::merge_lists( array( '10.9.9.0/24', '2001:db8::/32', '1.2.3.4-1.2.3.9' ), array( '198.51.100.0/24' ) );
		$this->assertTrue( $result['saved'] );
		$this->assertSame( 2, $result['allow'] );
		$this->assertSame( 1, $result['deny'] );
		$this->assertSame( 1, $result['skipped'] );
		$this->assertSame( array( '10.9.9.0/24', '2001:db8::/32' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		$this->assertSame( array( '198.51.100.0/24' ), get_option( 'dragonloginsecurity_settings' )['deny_ips'] );
	}
}
