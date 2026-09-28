<?php
/**
 * Scenario hunt: allow/deny/trusted-proxy list validation at the range
 * boundaries, the settings save path with malformed input, the save notice,
 * and the dashboard notice / Site Health text.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use DragonLoginSecurity\IP;
use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( IP::class )]
#[CoversClass( Admin::class )]
class ScenarioIpListSettingsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['dls_test_is_admin']           = true;
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		if ( ! function_exists( 'sanitize_key' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function sanitize_key( $k ) { return preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $k ) ); }' );
		}
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_is_admin']           = true;
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	public function test_an_ipv4_mapped_range_cannot_cover_more_than_a_slash_8_of_ipv4(): void {
		// ::ffff:0:0/96 is every IPv4 address (the matcher already treats a
		// mapped range at /96 or wider as its IPv4 equivalent), so on an allow
		// list it switches brute-force protection off for every IPv4 visitor:
		// exactly what the "shorter than /8" refusal exists to prevent.
		$this->assertTrue( IP::in_ranges( '8.8.8.8', array( '::ffff:0:0/96' ) ) );
		$this->assertTrue( IP::in_ranges( '203.0.113.9', array( '::ffff:0:0/96' ) ) );
		$this->assertNull( IP::normalise_list_entry( '::ffff:0:0/96' ), 'all of IPv4' );
		$this->assertNull( IP::normalise_list_entry( '::ffff:0:0/100' ), 'half of IPv4 (/4)' );
		$this->assertNull( IP::normalise_list_entry( '::ffff:0:0/103' ), '/7' );
		$this->assertSame( '::ffff:a00:0/104', IP::normalise_list_entry( '::ffff:a00:0/104' ), '/8 is the floor' );
		$this->assertSame( '::ffff:10.0.0.0/104', IP::normalise_list_entry( '::ffff:10.0.0.0/104' ) );
	}

	public function test_a_mapped_range_wider_than_96_matches_every_plain_ipv4_address_too_so_it_needs_the_same_floor(): void {
		// Below /96 the matcher pads a plain IPv4 visitor into mapped form and
		// compares as IPv6, so ::ffff:0:0/95 (and any mapped-form prefix down
		// to the /16 floor) still covers all of IPv4.
		$this->assertTrue( IP::in_ranges( '8.8.8.8', array( '::ffff:0:0/95' ) ) );
		$this->assertTrue( IP::in_ranges( '8.8.8.8', array( '::ffff:0:0/16' ) ) );
		$this->assertTrue( IP::in_ranges( '::ffff:8.8.8.8', array( '::ffff:0:0/95' ) ) );
		$this->assertNull( IP::normalise_list_entry( '::ffff:0:0/95' ), 'all of IPv4 again' );
		$this->assertNull( IP::normalise_list_entry( '::ffff:0:0/16' ), 'all of IPv4 again' );
		// Whereas a non-mapped IPv6 prefix never matches a plain IPv4 visitor.
		$this->assertFalse( IP::in_ranges( '8.8.8.8', array( '::/16' ) ) );
		$this->assertFalse( IP::in_ranges( '8.8.8.8', array( '::fff0:0:0/76' ) ) );
	}

	public function test_range_boundaries_for_both_families(): void {
		$this->assertSame( '1.0.0.0/8', IP::normalise_list_entry( '1.0.0.0/8' ) );
		$this->assertSame( '1.0.0.0/8', IP::normalise_list_entry( '1.0.0.0/08' ) );
		$this->assertSame( '1.0.0.0/8', IP::normalise_list_entry( '1.0.0.0/008' ) );
		$this->assertNull( IP::normalise_list_entry( '1.0.0.0/0008' ) );
		$this->assertNull( IP::normalise_list_entry( '1.0.0.0/7' ) );
		$this->assertNull( IP::normalise_list_entry( '1.0.0.0/0' ) );
		$this->assertSame( '1.2.3.4/32', IP::normalise_list_entry( '1.2.3.4/32' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3.4/33' ) );
		$this->assertSame( '2001:db8::/16', IP::normalise_list_entry( '2001:db8::/16' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::/15' ) );
		$this->assertSame( '2001:db8::1/128', IP::normalise_list_entry( '2001:db8::1/128' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::1/129' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::/+16' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::/1e1' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8::/ 16' ) );
		$this->assertNull( IP::normalise_list_entry( '2001:db8:: /16' ) );
		$this->assertNull( IP::normalise_list_entry( '[2001:db8::1]' ) );
		$this->assertNull( IP::normalise_list_entry( 'fe80::1%eth0' ) );
		$this->assertNull( IP::normalise_list_entry( '010.0.0.1' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3.4.5' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3.4:443' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3.4-1.2.3.9' ) );
		$this->assertNull( IP::normalise_list_entry( '1.2.3.*' ) );
		$this->assertNull( IP::normalise_list_entry( "1.2.3.4\n" . '5.6.7.8' ) );
		$this->assertNull( IP::normalise_list_entry( '::ffff:999.1.1.1' ) );
	}

	public function test_a_matched_ipv4_range_at_the_slash_8_boundary_covers_exactly_that_block(): void {
		$this->assertTrue( IP::in_ranges( '10.255.255.255', array( '10.0.0.0/8' ) ) );
		$this->assertFalse( IP::in_ranges( '11.0.0.0', array( '10.0.0.0/8' ) ) );
		$this->assertFalse( IP::in_ranges( '9.255.255.255', array( '10.0.0.0/8' ) ) );
		$this->assertTrue( IP::in_ranges( '2001:ffff::1', array( '2001::/16' ) ) );
		$this->assertFalse( IP::in_ranges( '2002::1', array( '2001::/16' ) ) );
	}

	public function test_settings_parse_with_every_line_ending_tabs_comments_and_case_duplicates(): void {
		$raw    = "203.0.113.9\r\n10.9.9.0/24\r2001:DB8::/32\n\t2001:db8::/32\n10.9.9.0/024\n 203.0.113.9 \n10.0.0.0/24 # office\n1.2.3.4, 5.6.7.8\n<b>1.2.3.4</b>\n";
		$parsed = Admin::parse_ip_list( $raw );
		$this->assertSame( array( '203.0.113.9', '10.9.9.0/24', '2001:DB8::/32', '2001:db8::/32', '1.2.3.4' ), $parsed['valid'] );
		$this->assertSame( array( '10.0.0.0/24 # office', '1.2.3.4, 5.6.7.8' ), $parsed['invalid'] );
		// The two spellings of one IPv6 range match the same addresses; storing
		// both is harmless.
		$this->assertTrue( IP::in_ranges( '2001:db8:1::1', array( '2001:DB8::/32' ) ) );
	}

	public function test_a_huge_pasted_list_is_saved_whole_and_still_matches(): void {
		$lines = array();
		for ( $a = 0; $a < 20; $a++ ) {
			for ( $b = 0; $b < 250; $b++ ) {
				$lines[] = '10.' . $a . '.' . $b . '.0/24';
			}
		}
		$rejected = array();
		$settings = Admin::settings_from_input( array( 'deny_ips' => implode( "\n", $lines ) ), $rejected );
		$this->assertCount( 5000, $settings['deny_ips'] );
		$this->assertSame( array(), $rejected );
		$this->assertTrue( Admin::persist_settings( $settings ) );
		$l = new Limit_Login();
		$this->assertTrue( $l->is_locked( '10.19.249.77' ) );
		$this->assertFalse( $l->is_locked( '10.20.0.1' ) );
	}

	public function test_settings_from_input_rejects_lists_given_as_arrays_or_numbers_without_notices(): void {
		$rejected = array();
		$settings = Admin::settings_from_input(
			array(
				'allow_ips'       => array( '1.2.3.4' ),
				'deny_ips'        => 42,
				'trusted_proxies' => null,
				'proxy_header'    => array( 'x_real_ip' ),
				'trust_proxy'     => array(),
			),
			$rejected
		);
		$this->assertSame( array(), $settings['allow_ips'] );
		$this->assertSame( array(), $settings['deny_ips'] );
		$this->assertSame( array(), $settings['trusted_proxies'] );
		$this->assertSame( 'x_forwarded_for', $settings['proxy_header'] );
		$this->assertTrue( $settings['trust_proxy'], 'the checkbox is present, whatever its value' );
		$this->assertSame( array(), $rejected );
	}

	public function test_rejected_entries_are_pooled_across_lists_and_deduplicated(): void {
		$rejected = array();
		$settings = Admin::settings_from_input(
			array(
				'allow_ips'       => "office\n1.2.3.4",
				'deny_ips'        => "office\n1.2.3.4/33",
				'trusted_proxies' => "1.2.3.4/33\n2001:db8::/8",
			),
			$rejected
		);
		$this->assertSame( array( 'office', '1.2.3.4/33', '2001:db8::/8' ), $rejected );
		$this->assertSame( array( '1.2.3.4' ), $settings['allow_ips'] );
		Admin::record_save_result( true, true, $rejected );
		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'office, 1.2.3.4/33, and 2001:db8::/8', $notice['message'] );
		$this->assertStringStartsWith( 'Settings saved, except these entries', $notice['message'] );
	}

	public function test_save_notice_for_every_combination_of_outcomes(): void {
		Admin::record_save_result( false, true, array( 'office' ) );
		$this->assertSame( 'Settings could not be saved. Your previous settings are still in effect; try again.', get_transient( 'dragonloginsecurity_settings_notice' )['message'] );
		Admin::record_save_result( true, false, array() );
		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'delete data on uninstall', $notice['message'] );
		Admin::record_save_result( true, false, array( 'office' ) );
		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertStringContainsString( 'except this entry', $notice['message'] );
		$this->assertStringContainsString( 'could not be stored and is unchanged', $notice['message'] );
		$this->assertSame( 60, $GLOBALS['dls_test_transient_ttls']['dragonloginsecurity_settings_notice'] );
	}

	public function test_persist_settings_reports_success_when_nothing_changed_and_failure_when_the_write_is_lost(): void {
		$settings = Admin::settings_from_input( array( 'allow_ips' => '1.2.3.4' ) );
		$this->assertTrue( Admin::persist_settings( $settings ) );
		$this->assertTrue( Admin::persist_settings( $settings ), 'an unchanged save is still a confirmed save' );

		$GLOBALS['dls_test_option_write_fails'] = true;
		$this->assertTrue( Admin::persist_settings( $settings ), 'a failed write of an identical value still leaves the option correct' );
		$changed = Admin::settings_from_input( array( 'allow_ips' => '1.2.3.5' ) );
		$this->assertFalse( Admin::persist_settings( $changed ) );
		$this->assertSame( array( '1.2.3.4' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'], 'previous settings still in effect' );
	}

	public function test_a_stored_string_list_is_replaced_by_the_saved_array_and_matched_correctly(): void {
		// A list stored as a string by a manual `wp option update` matches as
		// one entry; the settings form always stores arrays.
		update_option( 'dragonloginsecurity_settings', array( 'deny_ips' => "1.2.3.4\n5.6.7.8" ) );
		$l = new Limit_Login();
		$this->assertFalse( $l->is_locked( '1.2.3.4' ), 'a multi-line string is not a list' );
		update_option( 'dragonloginsecurity_settings', array( 'deny_ips' => '1.2.3.4' ) );
		$this->assertTrue( $l->is_locked( '1.2.3.4' ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_dashboard_notice_and_site_health_name_the_proxy_and_the_time(): void {
		if ( ! function_exists( 'esc_url' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function esc_url( $u ) { return (string) $u; }' );
		}
		if ( ! function_exists( 'get_current_screen' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function get_current_screen() { return (object) array( "id" => $GLOBALS["dls_test_screen"] ); }' );
		}

		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';
		IP::current();
		$seen_at = time() - 100;
		$GLOBALS['dls_test_options'][ IP::UNCONFIGURED_OPTION ]['time'] = $seen_at;
		$stamp = gmdate( 'Y-m-d H:i', $seen_at );

		$admin = new Admin();
		foreach ( array( 'dashboard', 'settings_page_dragon-login-security' ) as $screen ) {
			$GLOBALS['dls_test_screen'] = $screen;
			ob_start();
			$admin->proxy_notice();
			$html = ob_get_clean();
			$this->assertStringContainsString( 'notice-warning', $html, $screen );
			$this->assertStringContainsString( 'Dragon Login Security: Sign-in requests arrive from 10.0.0.1 (last seen ' . $stamp . ' UTC)', $html, $screen );
			$this->assertStringContainsString( 'turn on proxy-header trust', $html );
		}
		$GLOBALS['dls_test_screen'] = 'plugins';
		ob_start();
		$admin->proxy_notice();
		$this->assertSame( '', ob_get_clean(), 'other screens stay quiet' );
		$GLOBALS['dls_test_screen'] = 'dashboard';
		$GLOBALS['dls_test_is_admin'] = false;
		ob_start();
		$admin->proxy_notice();
		$this->assertSame( '', ob_get_clean(), 'non-administrators see nothing' );
		$GLOBALS['dls_test_is_admin'] = true;

		$health = Admin::proxy_site_health();
		$this->assertSame( 'recommended', $health['status'] );
		$this->assertSame( 'orange', $health['badge']['color'] );
		$this->assertStringContainsString( '10.0.0.1 (last seen ' . $stamp . ' UTC)', $health['description'] );
		$this->assertStringContainsString( 'options-general.php?page=dragon-login-security', $health['actions'] );

		// The mismatch text wins when both records exist and trust is on.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array(
			'trust_proxy'     => true,
			'trusted_proxies' => array( '173.245.48.0/20' ),
		);
		$_SERVER['REMOTE_ADDR'] = '6.6.6.6';
		IP::current();
		$health = Admin::proxy_site_health();
		$this->assertStringContainsString( 'Requests from 6.6.6.6', $health['description'] );
		$this->assertStringContainsString( 'no action is needed', $health['description'] );
		$this->assertStringNotContainsString( '10.0.0.1', $health['description'] );

		// Reviewing the settings clears both records.
		Admin::forget_proxy_records();
		$this->assertSame( 'good', Admin::proxy_site_health()['status'] );
		ob_start();
		$admin->proxy_notice();
		$this->assertSame( '', ob_get_clean() );

		// Site Health registration keeps other tests and survives a non-array.
		$tests = $admin->site_status_tests( 'not an array' );
		$this->assertSame( array( Admin::class, 'proxy_site_health' ), $tests['direct']['dragonloginsecurity_proxy']['test'] );
		$tests = $admin->site_status_tests( array( 'direct' => array( 'other' => array() ) ) );
		$this->assertArrayHasKey( 'other', $tests['direct'] );
	}

	public function test_notice_text_escapes_a_hostile_recorded_address(): void {
		// The record is written from a validated REMOTE_ADDR, but the option is
		// still an option: a poisoned value must come out escaped.
		$text = Admin::proxy_unconfigured_text( array( 'ip' => '<script>x</script>', 'time' => 0 ) );
		$this->assertStringContainsString( '<script>', $text, 'the text itself is raw; the callers escape it' );
		$this->assertStringContainsString( '&lt;script&gt;', esc_html( $text ) );
		$health_description = '<p>' . esc_html( $text ) . '</p>';
		$this->assertStringNotContainsString( '<script>', $health_description );
	}
}
