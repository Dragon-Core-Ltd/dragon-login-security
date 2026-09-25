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

	public function test_available_reflects_loaded_library(): void {
		$this->assertTrue( WebAuthn::available() );
		$this->assertSame( class_exists( \lbuchs\WebAuthn\WebAuthn::class ), WebAuthn::available() );
	}

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

	/**
	 * A passkey stored the way registration has always stored it: base64url
	 * credential id and the PEM public key.
	 *
	 * @return array{0:\OpenSSLAsymmetricKey,1:string}
	 */
	private function stored_passkey( int $user_id ): array {
		$key = openssl_pkey_new(
			array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			)
		);
		$pem = openssl_pkey_get_details( $key )['key'];
		$id  = WebAuthn::b64url_encode( random_bytes( 32 ) );

		$GLOBALS['wpdb']                    = new \DLS_Test_Wpdb();
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array(
				'id'            => 3,
				'user_id'       => $user_id,
				'credential_id' => $id,
				'public_key'    => $pem,
				'sign_count'    => 4,
			),
		);
		$GLOBALS['dls_test_transients'] = array();
		return array( $key, $id );
	}

	public function test_option_binaries_are_base64url_for_the_browser(): void {
		list( , $id ) = $this->stored_passkey( 5 );
		$reg          = WebAuthn::registration_args( 5, 'sam' );

		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]+$/', $reg['publicKey']['challenge'] );
		$this->assertSame( 32, strlen( WebAuthn::b64url_decode( $reg['publicKey']['challenge'] ) ) );
		$this->assertSame( hash( 'sha256', 'dls|5', true ), WebAuthn::b64url_decode( $reg['publicKey']['user']['id'] ) );
		$this->assertSame( $id, $reg['publicKey']['excludeCredentials'][0]['id'] );

		$auth = WebAuthn::authentication_args( 5 );
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]+$/', $auth['args']['publicKey']['challenge'] );
		$this->assertSame( $id, $auth['args']['publicKey']['allowCredentials'][0]['id'] );
	}

	public function test_existing_passkey_still_verifies(): void {
		list( $key, $id ) = $this->stored_passkey( 5 );
		$auth             = WebAuthn::authentication_args( 5 );

		// What a browser returns for the challenge it was given.
		$client = wp_json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => $auth['args']['publicKey']['challenge'],
				'origin'    => 'https://example.test',
			)
		);
		$auth_data = hash( 'sha256', 'example.test', true ) . chr( 0x05 ) . pack( 'N', 5 );
		openssl_sign( $auth_data . hash( 'sha256', $client, true ), $signature, $key, OPENSSL_ALGO_SHA256 );

		$this->assertTrue(
			WebAuthn::verify_authentication(
				5,
				$auth['token'],
				$id,
				base64_encode( $client ),
				base64_encode( $auth_data ),
				base64_encode( $signature )
			)
		);

		// Another user cannot use it, and the challenge is single use.
		$this->assertFalse( WebAuthn::verify_authentication( 6, $auth['token'], $id, base64_encode( $client ), base64_encode( $auth_data ), base64_encode( $signature ) ) );
	}
}
