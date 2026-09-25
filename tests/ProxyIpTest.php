<?php
/**
 * Forwarded headers are read only from configured proxies.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
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
}
