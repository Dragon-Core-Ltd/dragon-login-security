<?php
/**
 * Forwarded headers are read only from configured proxies.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( IP::class )]
class ProxyIpTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options'] = array();
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );
	}

	protected function tearDown(): void {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Resolve with the given settings and request.
	 *
	 * @param array       $settings Plugin settings.
	 * @param string      $remote   REMOTE_ADDR.
	 * @param string|null $xff      X-Forwarded-For.
	 * @param string|null $real     X-Real-IP.
	 * @return string
	 */
	private function resolve( array $settings, string $remote, ?string $xff = null, ?string $real = null ): string {
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = $settings;
		$_SERVER['REMOTE_ADDR']                                      = $remote;
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );
		if ( null !== $xff ) {
			$_SERVER['HTTP_X_FORWARDED_FOR'] = $xff;
		}
		if ( null !== $real ) {
			$_SERVER['HTTP_X_REAL_IP'] = $real;
		}
		return IP::current();
	}

	public function test_direct_client_cannot_choose_its_address(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => "173.245.48.0/20\n2400:cb00::/32",
		);
		$this->assertSame( '198.51.100.23', $this->resolve( $cf, '198.51.100.23', '9.9.9.9' ) );
		$this->assertSame( '198.51.100.23', $this->resolve( $cf, '198.51.100.23', null, '9.9.9.9' ) );
		$this->assertSame( '198.51.100.23', $this->resolve( $cf, '198.51.100.23', '1.1.1.1, 173.245.48.5' ) );
	}

	public function test_request_through_a_trusted_proxy_uses_the_forwarded_client(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20 10.0.0.0/8',
		);
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '173.245.48.9', '203.0.113.7' ) );
		// A forged prefix loses to the hop the proxy observed.
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '10.1.2.3', '9.9.9.9, 203.0.113.7, 173.245.48.1' ) );
		$this->assertSame( '203.0.113.8', $this->resolve( $cf, '173.245.48.9', null, '203.0.113.8' ) );
		// A malformed hop stops the walk at the last trusted address.
		$this->assertSame( '173.245.48.1', $this->resolve( $cf, '10.1.2.3', '203.0.113.7, junk, 173.245.48.1' ) );
		// No headers: the proxy itself.
		$this->assertSame( '173.245.48.9', $this->resolve( $cf, '173.245.48.9' ) );
	}

	public function test_existing_modes_are_unchanged(): void {
		$this->assertSame( '198.51.100.23', $this->resolve( array(), '198.51.100.23', '9.9.9.9' ) );
		// Trust on with no ranges: one proxy assumed, rightmost hop.
		$one = array( 'trust_proxy' => 1 );
		$this->assertSame( '203.0.113.7', $this->resolve( $one, '10.0.0.2', '9.9.9.9, 203.0.113.7' ) );
		$this->assertSame( '203.0.113.8', $this->resolve( $one, '10.0.0.2', null, '203.0.113.8' ) );
		$this->assertSame( '10.0.0.2', $this->resolve( $one, '10.0.0.2' ) );
	}

	public function test_cdn_then_load_balancer_resolves_the_visitor(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20',
		);
		// Cloudflare -> ALB: REMOTE_ADDR is the balancer's private address.
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '10.0.0.5', '1.2.3.4, 173.245.48.1' ) );
		// A forged prefix still loses to the hop Cloudflare observed.
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '10.0.0.5', '9.9.9.9, 1.2.3.4, 173.245.48.1' ) );
		// Private hops inside the chain are skipped too.
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '100.64.1.1', '1.2.3.4, 173.245.48.1, 172.16.4.4' ) );
	}

	public function test_nginx_in_front_of_apache_on_loopback_resolves_the_visitor(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20',
		);
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '127.0.0.1', '1.2.3.4, 173.245.48.1' ) );
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '::1', '1.2.3.4, 173.245.48.1' ) );
		$this->assertSame( '1.2.3.4', $this->resolve( $cf, '::ffff:127.0.0.1', '1.2.3.4, 173.245.48.1' ) );
		$this->assertSame( '2001:db8::7', $this->resolve( $cf, 'fd00::2', '2001:db8::7' ) );
	}

	public function test_public_address_outside_the_ranges_still_ignores_headers_and_is_recorded(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20',
		);
		$this->assertSame( '6.6.6.6', $this->resolve( $cf, '6.6.6.6', '9.9.9.9' ) );
		$this->assertSame( '6.6.6.6', $this->resolve( $cf, '6.6.6.6', '10.0.0.1' ) );
		// Near-internal public neighbours are not internal.
		$this->assertSame( '172.32.0.1', $this->resolve( $cf, '172.32.0.1', '9.9.9.9' ) );
		$this->assertSame( '100.128.0.1', $this->resolve( $cf, '100.128.0.1', '9.9.9.9' ) );

		$mismatch = IP::proxy_mismatch();
		$this->assertNotNull( $mismatch );
		$this->assertSame( '100.128.0.1', $mismatch['ip'] );
	}

	public function test_mismatch_is_reported_only_while_it_applies(): void {
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20',
		);
		// No forwarded header: nothing to report.
		$this->resolve( $cf, '6.6.6.6' );
		$this->assertNull( IP::proxy_mismatch() );
		// Through a trusted or internal hop: nothing to report.
		$this->resolve( $cf, '10.0.0.5', '1.2.3.4' );
		$this->resolve( $cf, '173.245.48.1', '1.2.3.4' );
		$this->assertNull( IP::proxy_mismatch() );

		$this->resolve( $cf, '6.6.6.6', '9.9.9.9' );
		$seen = IP::proxy_mismatch();
		$this->assertSame( '6.6.6.6', $seen['ip'] );
		$this->assertNull( IP::proxy_mismatch( $seen['time'] + IP::MISMATCH_TTL ), 'an old sighting expires' );

		// Once the address is listed, the warning goes away.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings']['trusted_proxies'] = "173.245.48.0/20\n6.6.6.6";
		$this->assertNull( IP::proxy_mismatch() );
		// Proxy trust off: no warning.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array( 'trusted_proxies' => '173.245.48.0/20' );
		$this->assertNull( IP::proxy_mismatch() );
	}

	public function test_no_ranges_mode_records_nothing(): void {
		$this->resolve( array( 'trust_proxy' => 1 ), '6.6.6.6', '9.9.9.9' );
		$this->resolve( array(), '6.6.6.6', '9.9.9.9' );
		$this->assertArrayNotHasKey( IP::MISMATCH_OPTION, $GLOBALS['dls_test_options'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_site_health_reports_the_mismatch(): void {
		if ( ! function_exists( 'esc_url' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function esc_url( $u ) { return (string) $u; }' );
		}
		$cf = array(
			'trust_proxy'     => 1,
			'trusted_proxies' => '173.245.48.0/20',
		);
		$this->resolve( $cf, '6.6.6.6' );
		$this->assertSame( 'good', \DragonLoginSecurity\Admin::proxy_site_health()['status'] );
		$this->resolve( $cf, '6.6.6.6', '9.9.9.9' );
		$result = \DragonLoginSecurity\Admin::proxy_site_health();
		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( '6.6.6.6', $result['description'] );
		$this->assertStringContainsString( 'no action is needed', $result['description'] );
	}
}
