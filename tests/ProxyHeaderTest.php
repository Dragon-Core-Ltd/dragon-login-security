<?php
/**
 * The administrator names the header their proxy sets, and a site behind a
 * proxy that has not turned proxy trust on is told about it.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( IP::class )]
class ProxyHeaderTest extends TestCase {

	private const HEADERS = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP' );

	protected function setUp(): void {
		$GLOBALS['dls_test_options'] = array();
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
	}

	protected function tearDown(): void {
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Resolve with the given settings and request headers.
	 *
	 * @param array                $settings Plugin settings.
	 * @param string               $remote   REMOTE_ADDR.
	 * @param array<string,string> $headers  Header name => value.
	 * @return string
	 */
	private function resolve( array $settings, string $remote, array $headers = array() ): string {
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = $settings;
		$_SERVER['REMOTE_ADDR']                                      = $remote;
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
		foreach ( $headers as $name => $value ) {
			$_SERVER[ $name ] = $value;
		}
		return IP::current();
	}

	public function test_the_default_header_is_x_forwarded_for(): void {
		$single = array( 'trust_proxy' => 1 );
		$this->assertSame( '9.9.9.9', $this->resolve( $single, '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 9.9.9.9', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
	}

	public function test_single_proxy_mode_reads_only_the_configured_header(): void {
		$real = array( 'trust_proxy' => 1, 'proxy_header' => 'x_real_ip' );
		// A proxy that sets X-Real-IP and passes a visitor's own X-Forwarded-For through.
		$this->assertSame( '203.0.113.5', $this->resolve( $real, '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		// The configured header missing: the connection address, never another header.
		$this->assertSame( '10.0.0.1', $this->resolve( $real, '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) ) );

		$cf = array( 'trust_proxy' => 1, 'proxy_header' => 'cf_connecting_ip' );
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '173.245.48.5', array( 'HTTP_CF_CONNECTING_IP' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) ) );
		$this->assertSame( '173.245.48.5', $this->resolve( $cf, '173.245.48.5', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9', 'HTTP_X_REAL_IP' => '9.9.9.9' ) ) );

		$tc = array( 'trust_proxy' => 1, 'proxy_header' => 'true_client_ip' );
		$this->assertSame( '203.0.113.8', $this->resolve( $tc, '10.0.0.1', array( 'HTTP_TRUE_CLIENT_IP' => '203.0.113.8' ) ) );
		$this->assertSame( '10.0.0.1', $this->resolve( $tc, '10.0.0.1', array( 'HTTP_TRUE_CLIENT_IP' => 'not-an-ip' ) ) );
	}

	public function test_a_single_value_header_with_ranges_is_read_only_from_a_trusted_hop(): void {
		$real = array( 'trust_proxy' => 1, 'proxy_header' => 'x_real_ip', 'trusted_proxies' => '173.245.48.0/20' );
		$this->assertSame( '203.0.113.5', $this->resolve( $real, '173.245.48.5', array( 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		$this->assertSame( '203.0.113.5', $this->resolve( $real, '10.0.0.4', array( 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		$this->assertSame( '198.51.100.23', $this->resolve( $real, '198.51.100.23', array( 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
	}

	public function test_an_unknown_header_choice_falls_back_to_x_forwarded_for(): void {
		$odd = array( 'trust_proxy' => 1, 'proxy_header' => 'something_else' );
		$this->assertSame( '9.9.9.9', $this->resolve( $odd, '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) ) );
	}

	public function test_forwarded_headers_with_proxy_trust_off_are_recorded(): void {
		$this->assertSame( '10.0.0.1', $this->resolve( array(), '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) ) );
		$seen = IP::proxy_unconfigured();
		$this->assertIsArray( $seen );
		$this->assertSame( '10.0.0.1', $seen['ip'] );
		$this->assertEqualsWithDelta( time(), $seen['time'], 5 );

		// Once proxy trust is on, the record no longer applies.
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array( 'trust_proxy' => 1 );
		$this->assertNull( IP::proxy_unconfigured() );
	}

	public function test_a_request_without_forwarded_headers_records_nothing(): void {
		$this->assertSame( '10.0.0.1', $this->resolve( array(), '10.0.0.1' ) );
		$this->assertNull( IP::proxy_unconfigured() );
		$this->assertSame( '198.51.100.23', $this->resolve( array(), '198.51.100.23' ) );
		$this->assertNull( IP::proxy_unconfigured() );
	}

	public function test_a_public_visitor_sending_headers_directly_is_also_recorded_once_an_hour(): void {
		$this->resolve( array(), '198.51.100.23', array( 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
		$first = IP::proxy_unconfigured();
		$this->assertSame( '198.51.100.23', $first['ip'] );
		$GLOBALS['dls_test_options'][ IP::UNCONFIGURED_OPTION ]['time'] = time() - 100;
		$this->resolve( array(), '198.51.100.23', array( 'HTTP_X_REAL_IP' => '203.0.113.9' ) );
		$this->assertSame( time() - 100, IP::proxy_unconfigured()['time'], 'throttled: not rewritten within the hour' );
	}

	public function test_an_old_record_is_not_reported(): void {
		$this->resolve( array(), '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$GLOBALS['dls_test_options'][ IP::UNCONFIGURED_OPTION ]['time'] = time() - IP::MISMATCH_TTL - 1;
		$this->assertNull( IP::proxy_unconfigured() );
	}
}
