<?php
/**
 * Tests for the TOTP provider, proven against the RFC 6238 test vectors.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Provider_TOTP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Provider_TOTP::class )]
class TotpTest extends TestCase {

	/**
	 * Base32 of the RFC 6238 ASCII seed "12345678901234567890".
	 */
	private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function test_rfc6238_vectors(): void {
		// SHA-1, 6 digits: the RFC's 8-digit values truncated to the low 6.
		$this->assertSame( '287082', Provider_TOTP::code_at( self::RFC_SECRET, 59 ) );
		$this->assertSame( '081804', Provider_TOTP::code_at( self::RFC_SECRET, 1111111109 ) );
		$this->assertSame( '050471', Provider_TOTP::code_at( self::RFC_SECRET, 1111111111 ) );
		$this->assertSame( '005924', Provider_TOTP::code_at( self::RFC_SECRET, 1234567890 ) );
	}

	public function test_verify_accepts_current_and_adjacent_window(): void {
		$secret = Provider_TOTP::generate_secret();
		$now    = 1_700_000_000;
		$this->assertTrue( Provider_TOTP::verify( $secret, Provider_TOTP::code_at( $secret, $now ), 1, $now ) );
		$this->assertTrue( Provider_TOTP::verify( $secret, Provider_TOTP::code_at( $secret, $now - 30 ), 1, $now ) );
		$this->assertTrue( Provider_TOTP::verify( $secret, Provider_TOTP::code_at( $secret, $now + 30 ), 1, $now ) );
	}

	public function test_verify_rejects_out_of_window_and_malformed(): void {
		$secret = Provider_TOTP::generate_secret();
		$now    = 1_700_000_000;
		$this->assertFalse( Provider_TOTP::verify( $secret, Provider_TOTP::code_at( $secret, $now - 120 ), 1, $now ) );
		$this->assertFalse( Provider_TOTP::verify( $secret, '12345', 1, $now ) );  // wrong length
		$this->assertFalse( Provider_TOTP::verify( $secret, 'abcdef', 1, $now ) ); // non-numeric
	}

	public function test_generate_secret_is_valid_base32_160bit(): void {
		$s = Provider_TOTP::generate_secret();
		$this->assertSame( 32, strlen( $s ) ); // 160 bits / 5 = 32 base32 chars
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $s );
	}

	public function test_provisioning_uri_shape(): void {
		$uri = Provider_TOTP::provisioning_uri( 'ABC', 'admin', 'My Site' );
		$this->assertStringStartsWith( 'otpauth://totp/My%20Site:admin?', $uri );
		$this->assertStringContainsString( 'secret=ABC', $uri );
		$this->assertStringContainsString( 'algorithm=SHA1', $uri );
	}
}
