<?php
/**
 * Tests for the WebAuthn wrapper's pure helpers.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( WebAuthn::class )]
class WebAuthnTest extends TestCase {

	public function test_rp_id_is_host_only(): void {
		$this->assertSame( 'shop.example.com', WebAuthn::rp_id_from_url( 'https://shop.example.com/wp' ) );
		$this->assertSame( 'localhost', WebAuthn::rp_id_from_url( 'http://localhost:8888' ) );
	}

	public function test_sign_count_regression_rejected(): void {
		$this->assertFalse( WebAuthn::sign_count_ok( 10, 9 ) );   // cloned-key signal
		$this->assertFalse( WebAuthn::sign_count_ok( 10, 10 ) );  // no increment
		$this->assertTrue( WebAuthn::sign_count_ok( 10, 11 ) );
		$this->assertTrue( WebAuthn::sign_count_ok( 0, 0 ) );      // counter-less authenticator
	}

	public function test_b64url_round_trip(): void {
		$binary = random_bytes( 37 ); // odd length exercises padding
		$enc    = WebAuthn::b64url_encode( $binary );
		$this->assertDoesNotMatchRegularExpression( '/[+\/=]/', $enc ); // url-safe, no padding
		$this->assertSame( $binary, WebAuthn::b64url_decode( $enc ) );
	}
}
