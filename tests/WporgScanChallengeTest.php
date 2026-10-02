<?php
/**
 * The two-factor challenge form carries a nonce bound to the challenged user,
 * issued and checked under the same signed-out identity, and the sign-in
 * flags come from core's own sign-in values rather than the raw request.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Login_Token;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Marks a value the CBOR encoder emits as a byte string.
 */
final class WscBytes {
	public string $bytes;
	public function __construct( string $bytes ) {
		$this->bytes = $bytes;
	}
}

#[CoversClass( Two_Factor::class )]
class WporgScanChallengeTest extends TestCase {

	private const LOGIN = 'https://example.test/wp-login.php';
	private const ADMIN = 'https://example.test/wp-admin/';

	/**
	 * User 1's authenticator secret.
	 *
	 * @var string
	 */
	private string $secret = '';

	/**
	 * Per-process WordPress stand-ins. Only $screen loads wp-login.php's
	 * login_header()/login_footer().
	 *
	 * @param bool $screen Whether the request is on wp-login.php.
	 */
	private function boot( bool $screen ): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval(
			'class WSC_Redirect extends \Exception {}
			class WSC_Unsafe extends \Exception {}
			class WSC_Rendered extends \Exception {}
			function wp_safe_redirect( $l ) { throw new WSC_Redirect( wp_validate_redirect( $l, admin_url() ) ); }
			function wp_redirect( $l ) { throw new WSC_Unsafe( $l ); }
			function wp_login_url( $r = "" ) { return "https://example.test/wp-login.php"; }
			function wp_set_auth_cookie( $id, $remember = false, $secure = "", $token = "" ) {
				$t = \WP_Session_Tokens::get_instance( $id )->create( time() + 3600 );
				$GLOBALS["wsc_remember"][] = (bool) $remember;
				$GLOBALS["wsc_sent"][]     = $GLOBALS["wsc_tf"]->filter_send_auth_cookies( true, 0, time() + 3600, $id, "auth", $t );
			}
			function wp_clear_auth_cookie() { $GLOBALS["wsc_cleared"] = true; }
			function get_current_user_id() { return (int) ( $GLOBALS["dls_test_current_user"] ?? 0 ); }
			function absint( $v ) { return abs( (int) $v ); }
			function sanitize_key( $k ) { return is_scalar( $k ) ? preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $k ) ) : ""; }
			function nocache_headers() {}
			function esc_url( $u ) { return (string) $u; }
			function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); }
			function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }'
		);
		if ( $screen ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function login_header( $title = "", $message = "", $errors = null ) { $GLOBALS["wsc_header"] = array( $title, $message ); } function login_footer( ...$a ) { throw new WSC_Rendered( "shown" ); }' );
		}
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
		$GLOBALS['wpdb']                  = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']    = array();
		$GLOBALS['dls_test_transients']   = array();
		$GLOBALS['dls_test_options']      = array();
		$GLOBALS['dls_test_sessions']     = array();
		$GLOBALS['dls_test_current_user'] = 0;
		$GLOBALS['wsc_sent']              = array();
		$GLOBALS['wsc_remember']          = array();
		$GLOBALS['dls_test_users']        = array(
			1 => new \WP_User( 1, 'owner' ),
			2 => new \WP_User( 2, 'editor' ),
		);
		$this->secret = Provider_TOTP::generate_secret();
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( $this->secret ) );
		update_user_meta( 2, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$_POST                  = array();
		$_GET                   = array();
		$_REQUEST               = array();
		$_COOKIE                = array();
		$GLOBALS['wsc_tf']      = new Two_Factor();
	}

	/**
	 * Run a password sign-in through the plugin as wp_signon() does, then the
	 * wp_login challenge.
	 *
	 * @param bool $remember The credentials' remember flag.
	 * @return array{0:string,1:string} What happened ('RENDERED', 'UNSAFE', 'SAFE') and the output or target.
	 */
	private function sign_in( bool $remember ): array {
		$tf = $GLOBALS['wsc_tf'];
		$tf->note_signon();
		$this->assertTrue( $tf->note_remember( true, array( 'remember' => $remember ) ), 'the secure-cookie flag is passed through' );
		$level = ob_get_level();
		ob_start();
		try {
			$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
		} catch ( \WSC_Rendered $r ) {
			return array( 'RENDERED', (string) ob_get_clean() );
		} catch ( \WSC_Unsafe $r ) {
			return array( 'UNSAFE', $r->getMessage() );
		} catch ( \WSC_Redirect $r ) {
			return array( 'SAFE', $r->getMessage() );
		} finally {
			while ( ob_get_level() > $level ) {
				ob_end_clean();
			}
		}
		return array( 'RETURNED', '' );
	}

	/**
	 * POST the challenge form.
	 *
	 * @param array $fields Fields; a missing token is created for user 1 and a
	 *                      missing nonce is the one the form for that user carries.
	 * @return string The redirect target, 'RENDERED' or 'RETURNED'.
	 */
	private function submit( array $fields ): string {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$fields                   += array(
			'dragonloginsecurity_token'  => Login_Token::create( 1 ),
			'dragonloginsecurity_user'   => '1',
			'dragonloginsecurity_method' => 'totp',
			'redirect_to'                => self::ADMIN,
		);
		if ( ! array_key_exists( Two_Factor::NONCE_FIELD, $fields ) ) {
			$fields[ Two_Factor::NONCE_FIELD ] = wp_create_nonce( Two_Factor::nonce_action( absint( $fields['dragonloginsecurity_user'] ) ) );
		} elseif ( null === $fields[ Two_Factor::NONCE_FIELD ] ) {
			unset( $fields[ Two_Factor::NONCE_FIELD ] );
		}
		$_POST    = $fields;
		$_REQUEST = $fields;
		$level    = ob_get_level();
		ob_start();
		try {
			$GLOBALS['wsc_tf']->handle_submit();
		} catch ( \WSC_Redirect $r ) {
			return $r->getMessage();
		} catch ( \WSC_Rendered $r ) {
			return 'RENDERED';
		} finally {
			while ( ob_get_level() > $level ) {
				ob_end_clean();
			}
		}
		return 'RETURNED';
	}

	private function code( int $offset = 0 ): string {
		return Provider_TOTP::code_at( $this->secret, time() + $offset );
	}

	private static function field( string $html, string $name ): string {
		return preg_match( '/name="' . preg_quote( $name, '/' ) . '" value="([^"]*)"/', $html, $m ) ? html_entity_decode( $m[1], ENT_QUOTES ) : '';
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_challenge_form_carries_a_nonce_bound_to_the_challenged_user(): void {
		$this->boot( true );
		list( $what, $html ) = $this->sign_in( false );
		$this->assertSame( 'RENDERED', $what );
		$nonce = self::field( $html, Two_Factor::NONCE_FIELD );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{10}$/', $nonce );
		$this->assertSame( 1, wp_verify_nonce( $nonce, 'dragonloginsecurity_2fa_1' ) );
		$this->assertFalse( wp_verify_nonce( $nonce, 'dragonloginsecurity_2fa_2' ) );
		$this->assertStringNotContainsString( '_wp_http_referer', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_submit_without_a_valid_nonce_is_refused_before_the_token_or_an_attempt_is_used(): void {
		$this->boot( false );
		$token = Login_Token::create( 1 );
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'owner|1700000000|stale|hmac';
		$other_session               = wp_create_nonce( Two_Factor::nonce_action( 1 ) );
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		$cases = array(
			'missing'          => null,
			'empty'            => '',
			'wrong'            => 'abcdef0123',
			'array'            => array( wp_create_nonce( Two_Factor::nonce_action( 1 ) ) ),
			'other user'       => wp_create_nonce( Two_Factor::nonce_action( 2 ) ),
			'other action'     => wp_create_nonce( 'dls_ajax' ),
			'other session'    => $other_session,
		);
		foreach ( $cases as $label => $nonce ) {
			$to = $this->submit(
				array(
					'dragonloginsecurity_token' => $token,
					'dragonloginsecurity_code'  => $this->code(),
					Two_Factor::NONCE_FIELD     => $nonce,
				)
			);
			$this->assertSame( self::LOGIN, $to, $label );
		}
		$this->assertSame( array(), $GLOBALS['wsc_sent'], 'a cookie was issued' );
		$this->assertSame( '', get_user_meta( 1, Two_Factor::CODE_FAILURES_META, true ), 'an attempt was counted' );
		$this->assertSame( '', get_user_meta( 1, Provider_TOTP::LAST_STEP_META, true ), 'the code was spent' );

		// The token was not spent: the real form completes the sign-in.
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->code() ) ) );
		$this->assertSame( array( true ), $GLOBALS['wsc_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_nonce_for_one_user_cannot_carry_another_users_token(): void {
		$this->boot( false );
		$to = $this->submit(
			array(
				'dragonloginsecurity_token' => Login_Token::create( 2 ),
				'dragonloginsecurity_user'  => '2',
				'dragonloginsecurity_code'  => $this->code(),
				Two_Factor::NONCE_FIELD     => wp_create_nonce( Two_Factor::nonce_action( 1 ) ),
			)
		);
		$this->assertSame( self::LOGIN, $to );
		$this->assertSame( array(), $GLOBALS['wsc_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_posted_code_reaches_each_factor(): void {
		$this->boot( false );
		// TOTP, padded as a phone keyboard may send it.
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => ' ' . $this->code() . ' ' ) ) );

		// A backup code, with the method switch the form's link sets.
		$codes = Provider_Backup_Codes::generate( 2 );
		Provider_Backup_Codes::store( 1, $codes );
		$this->assertSame(
			self::ADMIN,
			$this->submit(
				array(
					'dragonloginsecurity_method' => 'backup',
					'dragonloginsecurity_code'   => $codes[0],
				)
			)
		);
		$this->assertSame( 1, Provider_Backup_Codes::remaining( 1 ) );

		// A wrong code re-renders the challenge and counts one attempt.
		$this->boot_screen_functions();
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_method' => 'backup', 'dragonloginsecurity_code' => array( $codes[1] ) ) ) );
		$this->assertSame( 1, Provider_Backup_Codes::remaining( 1 ) );
		$this->assertSame( 1, get_user_meta( 1, Two_Factor::CODE_FAILURES_META, true )['count'] );
	}

	/**
	 * Load the login-screen functions after boot( false ).
	 */
	private function boot_screen_functions(): void {
		if ( ! function_exists( 'login_header' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function login_header( $title = "", $message = "", $errors = null ) { $GLOBALS["wsc_header"] = array( $title, $message ); } function login_footer( ...$a ) { throw new WSC_Rendered( "shown" ); }' );
		}
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_passkey_assertion_posted_with_the_form_signs_in(): void {
		$this->boot( false );
		WebAuthn::$available_override = true;
		$reg  = WebAuthn::registration_args( 1, 'owner' );
		$resp = self::registration_response( $reg['publicKey']['challenge'] );
		$cred = WebAuthn::verify_registration( 1, $resp['client'], $resp['attestation'] );
		$GLOBALS['wpdb']->rows['wp_dls_credentials'][] = array(
			'id'            => 1,
			'user_id'       => 1,
			'credential_id' => $cred['credential_id'],
			'public_key'    => $cred['public_key'],
			'sign_count'    => 0,
		);
		$auth = WebAuthn::authentication_args( 1 );
		$a    = self::assertion_response( $auth['args']['publicKey']['challenge'], $resp['key'], 1 );

		$fields = array(
			'dragonloginsecurity_method'    => 'passkey',
			'dragonloginsecurity_wa_token'  => $auth['token'],
			'dragonloginsecurity_wa_id'     => $cred['credential_id'],
			'dragonloginsecurity_wa_client' => $a['client'],
			'dragonloginsecurity_wa_auth'   => $a['auth_data'],
			'dragonloginsecurity_wa_sig'    => $a['signature'],
		);
		// Without the nonce nothing is checked: the challenge stays unspent.
		$this->assertSame( self::LOGIN, $this->submit( $fields + array( Two_Factor::NONCE_FIELD => null ) ) );
		$this->assertNotFalse( get_transient( 'dragonloginsecurity_wa_auth_' . $auth['token'] ) );

		$this->assertSame( self::ADMIN, $this->submit( $fields ) );
		$this->assertSame( array( true ), $GLOBALS['wsc_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_remember_me_comes_from_the_sign_in_credentials(): void {
		$this->boot( false );
		$_REQUEST['redirect'] = 'https://example.test/my-account/';

		list( $what, $url ) = $this->sign_in( true );
		$this->assertSame( 'UNSAFE', $what );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertSame( 'forever', $q['rememberme'] );
		$this->assertArrayNotHasKey( 'interim-login', $q );

		// The raw request is not consulted: only wp_signon()'s credentials count.
		$_REQUEST['rememberme'] = 'forever';
		$_POST['rememberme']    = 'forever';
		list( , $url )          = $this->sign_in( false );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertArrayNotHasKey( 'rememberme', $q );

		// A sign-in that did not pass through wp_signon() is not remembered.
		$tf = new Two_Factor();
		$tf->note_remember( false, array( 'remember' => true ) );
		$tf->note_signon();
		try {
			$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
			$this->fail( 'no hand-over' );
		} catch ( \WSC_Unsafe $r ) {
			parse_str( (string) parse_url( $r->getMessage(), PHP_URL_QUERY ), $q );
		}
		$this->assertArrayNotHasKey( 'rememberme', $q );

		// Malformed credentials are not a remember request.
		$tf = new Two_Factor();
		$tf->note_signon();
		$this->assertSame( 'x', $tf->note_remember( 'x', 'not-an-array' ) );
		try {
			$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
			$this->fail( 'no hand-over' );
		} catch ( \WSC_Unsafe $r ) {
			parse_str( (string) parse_url( $r->getMessage(), PHP_URL_QUERY ), $q );
		}
		$this->assertArrayNotHasKey( 'rememberme', $q );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_login_screen_renders_inline_with_core_flags(): void {
		$this->boot( true );
		$GLOBALS['interim_login'] = true;
		$_REQUEST['redirect_to']  = 'https://example.test/wp-admin/profile.php';
		list( $what, $html )      = $this->sign_in( true );
		$this->assertSame( 'RENDERED', $what );
		$this->assertSame( '1', self::field( $html, 'interim-login' ) );
		$this->assertSame( 'forever', self::field( $html, 'rememberme' ) );
		$this->assertSame( 'https://example.test/wp-admin/profile.php', self::field( $html, 'redirect_to' ) );

		// wp-login.php's own flag decides popup mode; the raw request does not.
		$GLOBALS['interim_login']  = false;
		$_REQUEST['interim-login'] = '1';
		list( , $html )            = $this->sign_in( false );
		$this->assertStringNotContainsString( 'interim-login', $html );
		$this->assertSame( '', self::field( $html, 'rememberme' ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_sign_in_that_arrives_with_a_session_cookie_is_challenged_on_the_next_request(): void {
		$this->boot( true );
		$GLOBALS['interim_login']    = true;
		$_REQUEST['redirect_to']     = 'https://example.test/wp-admin/edit.php';
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'owner|1700000000|expiredsession|hmac';
		list( $what, $url )          = $this->sign_in( true );
		$this->assertSame( 'UNSAFE', $what, 'the challenge was rendered on the request whose cookie is being cleared' );
		$this->assertTrue( $GLOBALS['wsc_cleared'] );
		$this->assertStringStartsWith( 'https://example.test/wp-login.php?action=dragonloginsecurity_2fa&', $url );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertSame( '1', $q['interim-login'] );
		$this->assertSame( 'forever', $q['rememberme'] );
		$this->assertSame( 'https://example.test/wp-admin/edit.php', $q['redirect_to'] );

		// The browser comes back without the cleared cookie.
		$_COOKIE                  = array();
		$_REQUEST                 = array();
		$GLOBALS['interim_login'] = null;
		$_GET                     = $q;
		$_SERVER['REQUEST_METHOD'] = 'GET';
		ob_start();
		try {
			( new Two_Factor() )->handle_submit();
			$this->fail( 'challenge not shown' );
		} catch ( \WSC_Rendered $r ) {
			$html = (string) ob_get_clean();
		}
		$this->assertTrue( $GLOBALS['interim_login'] );
		$this->assertSame( '1', self::field( $html, 'interim-login' ) );
		$this->assertSame( 'forever', self::field( $html, 'rememberme' ) );

		$to = $this->submit(
			array(
				'dragonloginsecurity_token' => self::field( $html, 'dragonloginsecurity_token' ),
				'dragonloginsecurity_code'  => $this->code(),
				'rememberme'                => 'forever',
				'interim-login'             => '1',
				'redirect_to'               => self::field( $html, 'redirect_to' ),
				Two_Factor::NONCE_FIELD     => self::field( $html, Two_Factor::NONCE_FIELD ),
			)
		);
		$this->assertSame( 'RENDERED', $to );
		$this->assertSame( 'success', $GLOBALS['interim_login'] );
		$this->assertSame( array( true ), $GLOBALS['wsc_remember'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_signed_in_visitor_signing_in_again_is_handed_over_too(): void {
		$this->boot( true );
		$GLOBALS['dls_test_current_user'] = 2;
		list( $what, $url )               = $this->sign_in( false );
		$this->assertSame( 'UNSAFE', $what );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertArrayNotHasKey( 'interim-login', $q );
		$this->assertArrayNotHasKey( 'rememberme', $q );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_requested_redirect_reads_only_usable_addresses(): void {
		$this->boot( false );
		$_REQUEST = array(
			'redirect_to' => array( 'https://example.test/a/' ),
			'redirect'    => 'https://example.test/b/',
		);
		$this->assertSame( 'https://example.test/b/', Two_Factor::requested_redirect( false ) );
		$this->assertSame( self::ADMIN, Two_Factor::requested_redirect( true ) );

		$_REQUEST = array(
			'redirect_to' => 'javascript:alert(1)',
			'redirect'    => 'https://example.test/b/',
		);
		$this->assertSame( 'https://example.test/b/', Two_Factor::requested_redirect( false ) );
		$this->assertSame( self::ADMIN, Two_Factor::requested_redirect( true ) );

		$_REQUEST = array( 'redirect_to' => 'https://example.test/a b/?x=1&y=2' );
		$this->assertSame( 'https://example.test/a%20b/?x=1&y=2', Two_Factor::requested_redirect( true ) );

		$_REQUEST = array( 'redirect_to' => '' );
		$this->assertSame( self::ADMIN, Two_Factor::requested_redirect( true ) );
	}

	// --- synthetic authenticator (as in ScenarioPasskeyCeremonyTest) ---

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
	 * @param mixed $value int, string (text), WscBytes, or array (map).
	 */
	private static function cbor( $value ): string {
		if ( $value instanceof WscBytes ) {
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

	private static function registration_response( string $challenge_b64u ): array {
		$key     = openssl_pkey_new(
			array(
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			)
		);
		$d       = openssl_pkey_get_details( $key );
		$x       = str_pad( $d['ec']['x'], 32, "\0", STR_PAD_LEFT );
		$y       = str_pad( $d['ec']['y'], 32, "\0", STR_PAD_LEFT );
		$cred_id = random_bytes( 32 );
		$client  = json_encode(
			array(
				'type'      => 'webauthn.create',
				'challenge' => $challenge_b64u,
				'origin'    => 'https://example.test',
			)
		);
		$cose    = self::cbor(
			array(
				1  => 2,
				3  => -7,
				-1 => 1,
				-2 => new WscBytes( $x ),
				-3 => new WscBytes( $y ),
			)
		);
		$auth    = hash( 'sha256', 'example.test', true ) . chr( 0x45 ) . pack( 'N', 0 ) . str_repeat( "\0", 16 ) . pack( 'n', strlen( $cred_id ) ) . $cred_id . $cose;
		$att     = self::cbor(
			array(
				'fmt'      => 'none',
				'attStmt'  => array(),
				'authData' => new WscBytes( $auth ),
			)
		);
		return array(
			'client'      => base64_encode( $client ),
			'attestation' => base64_encode( $att ),
			'key'         => $key,
		);
	}

	private static function assertion_response( string $challenge_b64u, $key, int $sign_count ): array {
		$client    = json_encode(
			array(
				'type'      => 'webauthn.get',
				'challenge' => $challenge_b64u,
				'origin'    => 'https://example.test',
			)
		);
		$auth_data = hash( 'sha256', 'example.test', true ) . chr( 0x05 ) . pack( 'N', $sign_count );
		openssl_sign( $auth_data . hash( 'sha256', $client, true ), $signature, $key, OPENSSL_ALGO_SHA256 );
		return array(
			'client'    => base64_encode( $client ),
			'auth_data' => base64_encode( $auth_data ),
			'signature' => base64_encode( $signature ),
		);
	}
}
