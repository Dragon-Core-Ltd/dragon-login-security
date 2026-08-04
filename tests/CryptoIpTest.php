<?php
/**
 * Tests for Crypto + IP helpers.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\IP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Crypto::class )]
#[CoversClass( IP::class )]
class CryptoIpTest extends TestCase {

	public function test_crypto_round_trip(): void {
		$c = Crypto::encrypt( 'JBSWY3DPEHPK3PXP' );
		$this->assertNotSame( 'JBSWY3DPEHPK3PXP', $c );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', Crypto::decrypt( $c ) );
	}

	public function test_crypto_decrypt_garbage_null(): void {
		$this->assertNull( Crypto::decrypt( 'not-valid!!' ) );
		$this->assertNull( Crypto::decrypt( '' ) );
	}

	public function test_ipv4_anonymize(): void {
		$this->assertSame( '203.0.113.0', IP::anonymize( '203.0.113.42' ) );
	}

	public function test_ipv6_anonymize_keeps_48_bits(): void {
		$anon = IP::anonymize( '2001:db8:abcd:1234:5678:9abc:def0:1234' );
		$this->assertSame( inet_ntop( inet_pton( '2001:db8:abcd::' ) ), inet_ntop( inet_pton( $anon ) ) );
	}

	public function test_non_ip_returned_unchanged(): void {
		$this->assertSame( 'nope', IP::anonymize( 'nope' ) );
	}
}
