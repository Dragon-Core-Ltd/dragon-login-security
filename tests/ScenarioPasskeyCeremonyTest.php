<?php
/**
 * Scenario hunt: full WebAuthn registration + assertion ceremonies driven
 * through the plugin wrapper with a synthetic "none"-format attestation, so
 * every malformed or replayed input reaches the real verifier.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Credentials;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\TestCase;

/**
 * Marks a value that the CBOR encoder must emit as a byte string.
 */
final class CborBytes {
	public string $bytes;
	public function __construct( string $bytes ) {
		$this->bytes = $bytes;
	}
}

class ScenarioPasskeyCeremonyTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_transients'] = array();
		$GLOBALS['dls_test_options']    = array();
		WebAuthn::$available_override   = null;
	}

	protected function tearDown(): void {
		WebAuthn::$available_override = null;
	}

	// --- tiny CBOR encoder (enough for an attestation object) ---

	private static function cbor_head( int $major, int $n ): string {
		if ( $n < 24 ) {
			return chr( ( $major << 5 ) | $n );
		}
		if ( $n < 256 ) {
			return chr( ( $major << 5 ) | 24 ) . chr( $n );
		}
		return chr( ( $major << 5 ) | 25 ) . pack( 'n', $n );
	}

	/**
	 * @param mixed $value int, string (text), CborBytes, or array (map).
	 */
	private static function cbor( $value ): string {
		if ( $value instanceof CborBytes ) {
			return self::cbor_head( 2, strlen( $value->bytes ) ) . $value->bytes;
		}
		if ( is_int( $value ) ) {
			return $value >= 0 ? self::cbor_head( 0, $value ) : self::cbor_head( 1, -1 - $value );
		}
		if ( is_string( $value ) ) {
			return self::cbor_head( 3, strlen( $value ) ) . $value;
		}
		$out = self::cbor_head( 5, count( $value ) );
		foreach ( $value as $k => $v ) {
			$out .= self::cbor( $k ) . self::cbor( $v );
		}
		return $out;
	}

	// --- synthetic authenticator ---

	/**
	 * @return array{0:\OpenSSLAsymmetricKey,1:string,2:string} key, x, y
	 */
	private static function ec_key(): array {
		$key = openssl_pkey_new(
			array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			)
		);
		$d   = openssl_pkey_get_details( $key );
		return array( $key, str_pad( $d['ec']['x'], 32, "\0", STR_PAD_LEFT ), str_pad( $d['ec']['y'], 32, "\0", STR_PAD_LEFT ) );
	}

	/**
	 * What a browser + authenticator would return for a create() call.
	 *
	 * @return array{client:string,attestation:string,key:\OpenSSLAsymmetricKey,cred_id:string} base64 client data, base64 attestation object.
	 */
	private static function registration_response( string $challenge_b64u, array $opts = array() ): array {
		$origin  = $opts['origin'] ?? 'https://example.test';
		$rp_host = $opts['rp_host'] ?? 'example.test';
		$flags   = $opts['flags'] ?? 0x45; // UP | UV | AT
		$type    = $opts['type'] ?? 'webauthn.create';
		$cred_id = $opts['cred_id'] ?? random_bytes( 32 );
		list( $key, $x, $y ) = self::ec_key();

		$client = json_encode(
			array(
				'type'      => $type,
				'challenge' => $challenge_b64u,
				'origin'    => $origin,
			)
		);
		$cose   = self::cbor(
			array(
				1  => 2,
				3  => -7,
				-1 => 1,
				-2 => new CborBytes( $x ),
				-3 => new CborBytes( $y ),
			)
		);
		$auth   = hash( 'sha256', $rp_host, true ) . chr( $flags ) . pack( 'N', $opts['sign_count'] ?? 0 ) . str_repeat( "\0", 16 ) . pack( 'n', strlen( $cred_id ) ) . $cred_id . $cose;
		$att    = self::cbor(
			array(
				'fmt'      => 'none',
				'attStmt'  => array(),
				'authData' => new CborBytes( $auth ),
			)
		);
		return array(
			'client'      => base64_encode( $client ),
			'attestation' => base64_encode( $att ),
			'key'         => $key,
			'cred_id'     => $cred_id,
		);
	}

	/**
	 * What a browser + authenticator would return for a get() call.
	 */
	private static function assertion_response( string $challenge_b64u, $key, int $sign_count, array $opts = array() ): array {
		$client    = json_encode(
			array(
				'type'      => $opts['type'] ?? 'webauthn.get',
				'challenge' => $challenge_b64u,
				'origin'    => $opts['origin'] ?? 'https://example.test',
			)
		);
		$auth_data = hash( 'sha256', $opts['rp_host'] ?? 'example.test', true ) . chr( $opts['flags'] ?? 0x05 ) . pack( 'N', $sign_count );
		openssl_sign( $auth_data . hash( 'sha256', $client, true ), $signature, $key, OPENSSL_ALGO_SHA256 );
		return array(
			'client'    => base64_encode( $client ),
			'auth_data' => base64_encode( $auth_data ),
			'signature' => base64_encode( $signature ),
		);
	}

	private function store_credential( int $user_id, array $cred, int $row_id = 1 ): void {
		$GLOBALS['wpdb']->rows['wp_dls_credentials'][] = array(
			'id'            => $row_id,
			'user_id'       => $user_id,
			'credential_id' => $cred['credential_id'],
			'public_key'    => $cred['public_key'],
			'sign_count'    => $cred['sign_count'],
		);
	}

	// --- registration ---

	public function test_registration_then_assertion_round_trip(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'] );

		$cred = WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );

		$this->assertSame( WebAuthn::b64url_encode( $resp['cred_id'] ), $cred['credential_id'] );
		$this->assertStringStartsWith( '-----BEGIN PUBLIC KEY-----', $cred['public_key'] );
		$this->assertSame( 0, $cred['sign_count'] );
		$this->assertFalse( get_transient( 'dragonloginsecurity_wa_reg_5' ), 'The registration challenge is single use.' );

		// The credential the registration produced verifies a later assertion.
		$this->store_credential( 5, $cred );
		$auth = WebAuthn::authentication_args( 5 );
		$this->assertSame( $cred['credential_id'], $auth['args']['publicKey']['allowCredentials'][0]['id'] );
		$a = self::assertion_response( $auth['args']['publicKey']['challenge'], $resp['key'], 1 );
		$this->assertTrue( WebAuthn::verify_authentication( 5, $auth['token'], $cred['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
		$this->assertSame( 1, $GLOBALS['wpdb']->last_update['data']['sign_count'] );
	}

	public function test_registration_rejects_a_get_ceremony_type(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'type' => 'webauthn.get' ) );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_rejects_non_base64_fields(): void {
		WebAuthn::registration_args( 5, 'sam' );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, 'not base64!!', '%%%' );
	}

	public function test_registration_rejects_another_users_challenge(): void {
		$five = WebAuthn::registration_args( 5, 'sam' );
		WebAuthn::registration_args( 6, 'kim' );
		$resp = self::registration_response( $five['publicKey']['challenge'] );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 6, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_cannot_be_replayed(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'] );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_without_a_stored_challenge_is_rejected(): void {
		// The challenge expired (or was never issued). A response whose client
		// data carries an EMPTY challenge must not be accepted: the wrapper hands
		// the library an empty expected challenge, and '' equals ''. The
		// authentication path refuses an absent challenge explicitly; the
		// registration path must too.
		$this->assertFalse( get_transient( 'dragonloginsecurity_wa_reg_5' ) );
		$resp = self::registration_response( '' );

		try {
			$cred = WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
		} catch ( \Throwable $e ) {
			$this->assertTrue( true );
			return;
		}
		$this->fail( 'A registration with no server-side challenge was accepted: ' . $cred['credential_id'] );
	}

	public function test_registration_requires_user_verification_flag(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'flags' => 0x41 ) ); // UP | AT, no UV
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_rejects_a_foreign_rp_id_hash(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'rp_host' => 'other.test' ) );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_rejects_a_sibling_looking_origin(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'origin' => 'https://evilexample.test' ) );
		$this->expectException( \Throwable::class );
		WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
	}

	public function test_registration_from_a_subdomain_origin_is_accepted(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'origin' => 'https://shop.example.test:8443' ) );
		$cred = WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
		$this->assertNotSame( '', $cred['credential_id'] );
	}

	public function test_registration_keeps_a_nonzero_initial_counter(): void {
		$args = WebAuthn::registration_args( 5, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'], array( 'sign_count' => 7 ) );
		$cred = WebAuthn::verify_registration( 5, $resp['client'], $resp['attestation'] );
		$this->assertSame( 7, $cred['sign_count'] );
	}

	// --- assertion ---

	/**
	 * @return array{cred:array,key:\OpenSSLAsymmetricKey}
	 */
	private function enrolled( int $user_id, int $stored_count ): array {
		$args = WebAuthn::registration_args( $user_id, 'sam' );
		$resp = self::registration_response( $args['publicKey']['challenge'] );
		$cred = WebAuthn::verify_registration( $user_id, $resp['client'], $resp['attestation'] );
		$cred['sign_count'] = $stored_count;
		$this->store_credential( $user_id, $cred );
		return array(
			'cred' => $cred,
			'key'  => $resp['key'],
		);
	}

	public function test_counter_regression_is_a_clone_signal(): void {
		$e    = $this->enrolled( 5, 10 );
		$auth = WebAuthn::authentication_args( 5 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 9 );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
		$this->assertNull( $GLOBALS['wpdb']->last_update, 'Nothing is written for a rejected assertion.' );
	}

	public function test_counter_dropping_to_zero_after_a_nonzero_history_is_rejected(): void {
		$e    = $this->enrolled( 5, 10 );
		$auth = WebAuthn::authentication_args( 5 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 0 );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
	}

	public function test_counter_less_authenticator_stays_at_zero(): void {
		$e    = $this->enrolled( 5, 0 );
		$auth = WebAuthn::authentication_args( 5 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 0 );
		$this->assertTrue( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
		$this->assertSame( 0, $GLOBALS['wpdb']->last_update['data']['sign_count'] );
	}

	public function test_assertion_is_rejected_when_the_counter_cannot_be_stored(): void {
		$e                              = $this->enrolled( 5, 3 );
		$GLOBALS['wpdb']->update_result = false;
		$auth                           = WebAuthn::authentication_args( 5 );
		$a                              = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 4 );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
	}

	public function test_assertion_requires_user_verification_flag(): void {
		$e    = $this->enrolled( 5, 3 );
		$auth = WebAuthn::authentication_args( 5 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 4, array( 'flags' => 0x01 ) );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
	}

	public function test_assertion_with_junk_or_wrongly_typed_fields_fails_closed(): void {
		$e    = $this->enrolled( 5, 3 );
		$auth = WebAuthn::authentication_args( 5 );
		$id   = $e['cred']['credential_id'];

		// Junk authenticator data (too short) and junk signature.
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $id, base64_encode( '{"type":"webauthn.get"}' ), base64_encode( 'xx' ), base64_encode( 'sig' ) ) );

		// challenge/origin of the wrong JSON type.
		$auth   = WebAuthn::authentication_args( 5 );
		$client = base64_encode( json_encode( array( 'type' => 'webauthn.get', 'challenge' => array( 1 ), 'origin' => 42 ) ) );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $id, $client, base64_encode( str_repeat( 'a', 37 ) ), base64_encode( 'sig' ) ) );

		// Unknown credential id, an expired (absent) token, and a replayed token.
		$auth = WebAuthn::authentication_args( 5 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $e['key'], 4 );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], 'AAAA', $a['client'], $a['auth_data'], $a['signature'] ) );
		$this->assertFalse( WebAuthn::verify_authentication( 5, 'deadbeef', $id, $a['client'], $a['auth_data'], $a['signature'] ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_wa_auth_' . $auth['token'] ), 'A token is consumed on first use, even a failed one.' );
	}

	public function test_a_second_users_key_cannot_answer_the_challenge(): void {
		$e     = $this->enrolled( 5, 3 );
		$other = self::ec_key();
		$auth  = WebAuthn::authentication_args( 5 );
		$a     = self::assertion_response( $auth['args']['publicKey']['challenge'], $other[0], 4 );
		$this->assertFalse( WebAuthn::verify_authentication( 5, $auth['token'], $e['cred']['credential_id'], $a['client'], $a['auth_data'], $a['signature'] ) );
	}

	// --- relying-party id ---

	public function test_rp_id_ignores_port_and_path(): void {
		$this->assertSame( 'example.test', WebAuthn::rp_id_from_url( 'https://example.test:8443/blog/' ) );
		$this->assertSame( 'example.test', WebAuthn::rp_id_from_url( 'https://EXAMPLE.test/wp' ) );
		$this->assertSame( '', WebAuthn::rp_id_from_url( 'not a url' ) );
	}

	public function test_rp_id_for_an_internationalised_host_is_its_ascii_form(): void {
		if ( ! function_exists( 'idn_to_ascii' ) ) {
			$this->markTestSkipped( 'intl not available' );
		}
		// A site whose address is stored in Unicode. The browser's origin, and
		// the rpId it will accept, are the ASCII (punycode) form; a Unicode rpId
		// is refused by the browser and never matches the origin check.
		$rp_id = WebAuthn::rp_id_from_url( 'https://bücher.example/' );

		$this->assertSame( 'xn--bcher-kva.example', $rp_id );
		$this->assertTrue( WebAuthn::origin_allowed( 'https://xn--bcher-kva.example', $rp_id ) );
	}

	public function test_origin_rules_for_loopback_and_case(): void {
		$this->assertTrue( WebAuthn::origin_allowed( 'http://localhost:8888', 'localhost' ) );
		$this->assertTrue( WebAuthn::origin_allowed( 'https://Example.TEST', 'example.test' ) );
		// Only localhost may be plain http; an IP literal is never a valid rpId.
		$this->assertFalse( WebAuthn::origin_allowed( 'http://127.0.0.1:8888', '127.0.0.1' ) );
		$this->assertFalse( WebAuthn::origin_allowed( 'https://example.test.', 'example.test' ) );
	}

	// --- storage edge ---

	public function test_credential_id_over_the_column_width_is_refused_by_wpdb(): void {
		// WebAuthn credential ids may be up to 1023 bytes (1364 base64url chars);
		// the column is varchar(255). Core's wpdb refuses an over-long value at
		// insert time (returns false), which add() must surface as 0.
		$GLOBALS['wpdb'] = new class() extends \DLS_Test_Wpdb {
			public $inserted = null;
			public function insert( $table, $data, $format = null ) {
				unset( $table, $format );
				$this->inserted = $data;
				return strlen( $data['credential_id'] ) > 255 ? false : 1;
			}
		};
		$long = WebAuthn::b64url_encode( random_bytes( 300 ) );
		$this->assertSame( 0, Credentials::add( 5, $long, 'pem', 0, '', 'x' ) );
		$this->assertSame( $long, $GLOBALS['wpdb']->inserted['credential_id'], 'The id is passed through untruncated, so a lookup could never silently miss.' );
	}
}
