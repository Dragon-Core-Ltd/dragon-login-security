<?php
/**
 * The proxy header choice is saved and validated, and a site behind a proxy
 * without proxy trust is warned on the dashboard and in Site Health.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Admin::class )]
class ProxySettingsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options'] = array();
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	protected function tearDown(): void {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	public function test_the_header_choice_is_saved_and_unknown_values_fall_back(): void {
		if ( ! function_exists( 'sanitize_key' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function sanitize_key( $k ) { return preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $k ) ); }' );
		}
		$settings = Admin::settings_from_input(
			array(
				'trust_proxy'  => 'on',
				'proxy_header' => 'cf_connecting_ip',
			)
		);
		$this->assertTrue( $settings['trust_proxy'] );
		$this->assertSame( 'cf_connecting_ip', $settings['proxy_header'] );

		$settings = Admin::settings_from_input( array( 'proxy_header' => '<script>' ) );
		$this->assertFalse( $settings['trust_proxy'] );
		$this->assertSame( 'x_forwarded_for', $settings['proxy_header'] );

		$settings = Admin::settings_from_input( array() );
		$this->assertSame( 'x_forwarded_for', $settings['proxy_header'] );
		$this->assertSame( array(), $settings['allow_ips'] );
	}

	public function test_site_health_warns_about_an_unconfigured_proxy(): void {
		if ( ! function_exists( 'esc_url' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function esc_url( $u ) { return (string) $u; }' );
		}
		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';
		IP::current();

		$result = Admin::proxy_site_health();
		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( '10.0.0.1', $result['description'] );
		$this->assertStringContainsString( 'share', $result['description'] );

		// Turning trust on resolves it.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array( 'trust_proxy' => 1 );
		$this->assertSame( 'good', Admin::proxy_site_health()['status'] );
	}

	public function test_saving_settings_clears_both_records(): void {
		update_option( IP::UNCONFIGURED_OPTION, array( 'ip' => '10.0.0.1', 'time' => time() ) );
		update_option( IP::MISMATCH_OPTION, array( 'ip' => '6.6.6.6', 'time' => time() ) );
		$this->assertTrue( Admin::persist_settings( Admin::settings_from_input( array() ) ) );
		Admin::forget_proxy_records();
		$this->assertFalse( get_option( IP::UNCONFIGURED_OPTION ) );
		$this->assertFalse( get_option( IP::MISMATCH_OPTION ) );
	}
}
