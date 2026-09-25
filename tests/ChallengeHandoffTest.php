<?php
/**
 * Sign-ins from forms outside wp-login.php continue on the login screen.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Provider_TOTP;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class ChallengeHandoffTest extends TestCase {

	protected function setUp(): void {
		$_REQUEST = array();
		unset( $_SERVER['HTTP_REFERER'] );
	}

	protected function tearDown(): void {
		$_REQUEST = array();
		unset( $_SERVER['HTTP_REFERER'] );
	}

	public function test_challenge_url_resumes_on_the_login_screen(): void {
		$url = Two_Factor::challenge_url( str_repeat( 'ab', 32 ), 'https://example.test/my-account/?x=1&y=2', true );
		$this->assertStringStartsWith( 'https://example.test/wp-login.php?action=dragonloginsecurity_2fa&', $url );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertSame( str_repeat( 'ab', 32 ), $q['dragonloginsecurity_token'] );
		$this->assertSame( 'https://example.test/my-account/?x=1&y=2', $q['redirect_to'] );
		$this->assertSame( 'forever', $q['rememberme'] );
		$this->assertArrayNotHasKey( 'dragonloginsecurity_user', $q );

		parse_str( (string) parse_url( Two_Factor::challenge_url( 'cd', '/', false ), PHP_URL_QUERY ), $q );
		$this->assertArrayNotHasKey( 'rememberme', $q );
	}

	public function test_front_end_redirect_prefers_the_forms_own_field(): void {
		$_REQUEST['redirect'] = 'https://example.test/checkout/';
		$this->assertSame( 'https://example.test/checkout/', Two_Factor::requested_redirect( false ) );
		$_REQUEST['redirect_to'] = 'https://example.test/shop/';
		$this->assertSame( 'https://example.test/shop/', Two_Factor::requested_redirect( false ) );
	}

	public function test_front_end_redirect_falls_back_to_the_page_then_home(): void {
		$_SERVER['HTTP_REFERER'] = 'https://example.test/my-account/';
		$this->assertSame( 'https://example.test/my-account/', Two_Factor::requested_redirect( false ) );
		$_SERVER['HTTP_REFERER'] = 'https://elsewhere.example/phish';
		$this->assertSame( 'https://example.test/', Two_Factor::requested_redirect( false ) );
	}

	public function test_login_screen_redirect_ignores_the_front_end_field(): void {
		$_REQUEST['redirect'] = 'https://example.test/checkout/';
		$this->assertSame( 'https://example.test/wp-admin/', Two_Factor::requested_redirect( true ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_sign_in_outside_the_login_screen_continues_there(): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'class DLS_Test_Redirect extends \Exception {} function wp_safe_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_clear_auth_cookie() { $GLOBALS["dls_cleared"] = true; } function wp_destroy_current_session() {} function wp_login_url() { return "https://example.test/wp-login.php"; } function nocache_headers() {}' );
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
		$GLOBALS['wpdb']           = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_users'] = array( 4 => new \WP_User( 4, 'shopper' ) );
		update_user_meta( 4, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		$_REQUEST = array( 'redirect' => 'https://example.test/my-account/' );

		// wp-login.php is not loaded: no fatal, the cookie is withdrawn, and the
		// browser is sent to the login screen.
		$this->assertFalse( function_exists( 'login_header' ) );
		try {
			( new Two_Factor() )->maybe_challenge( 'shopper', get_userdata( 4 ) );
			$this->fail( 'no redirect' );
		} catch ( \DLS_Test_Redirect $r ) {
			$url = $r->getMessage();
		}
		$this->assertTrue( $GLOBALS['dls_cleared'] );
		$this->assertStringStartsWith( 'https://example.test/wp-login.php?action=dragonloginsecurity_2fa&', $url );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertSame( 'https://example.test/my-account/', $q['redirect_to'] );

		// The login screen shows the challenge with a fresh token.
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'function login_header( ...$a ) {} function login_footer( ...$a ) {} function esc_url( $u ) { return (string) $u; } function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); } function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }' );
		$_GET = $q;
		ob_start();
		$shown = ( new Two_Factor() )->resume_challenge();
		$html  = (string) ob_get_clean();
		$this->assertTrue( $shown );
		$this->assertMatchesRegularExpression( '/name="dragonloginsecurity_token" value="([0-9a-f]{64})"/', $html );
		preg_match( '/name="dragonloginsecurity_token" value="([0-9a-f]{64})"/', $html, $m );
		$this->assertNotSame( $q['dragonloginsecurity_token'], $m[1] );
		$this->assertStringContainsString( 'value="https://example.test/my-account/"', $html );

		// The address token is single use.
		foreach ( array( $q['dragonloginsecurity_token'], str_repeat( '0', 64 ), 'junk' ) as $token ) {
			$_GET['dragonloginsecurity_token'] = $token;
			ob_start();
			try {
				( new Two_Factor() )->resume_challenge();
				$this->fail( 'challenge shown for a spent or unknown token' );
			} catch ( \DLS_Test_Redirect $r ) {
				$this->assertSame( 'https://example.test/wp-login.php', $r->getMessage() );
			}
			$this->assertSame( '', (string) ob_get_clean() );
		}

		// Without a token, wp-login.php carries on as normal.
		$_GET = array();
		$this->assertFalse( ( new Two_Factor() )->resume_challenge() );
	}

	/**
	 * WordPress in its own directory on another host ("WordPress Address"
	 * differs from "Site Address"): the handoff must still reach wp-login.php
	 * on the WordPress host, and the password step must still leave no
	 * session behind.
	 */
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_handoff_reaches_the_login_screen_on_a_separate_wordpress_host(): void {
		// Core's wp_safe_redirect: anything wp_validate_redirect refuses
		// becomes admin_url().
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'class DLS_Test_Redirect extends \Exception {} function wp_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_safe_redirect( $l ) { return wp_redirect( wp_validate_redirect( $l, admin_url() ) ); } function wp_clear_auth_cookie() { $GLOBALS["dls_cleared"] = true; } function wp_destroy_current_session() {} function wp_login_url() { return site_url( "wp-login.php" ); } function nocache_headers() {}' );
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
		$GLOBALS['dls_test_site_url'] = 'https://wp.example.org';
		$GLOBALS['wpdb']              = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_users']    = array( 4 => new \WP_User( 4, 'shopper' ) );
		update_user_meta( 4, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
		$_REQUEST = array( 'redirect' => 'https://example.test/my-account/' );

		try {
			( new Two_Factor() )->maybe_challenge( 'shopper', get_userdata( 4 ) );
			$this->fail( 'no redirect' );
		} catch ( \DLS_Test_Redirect $r ) {
			$url = $r->getMessage();
		}
		$this->assertTrue( $GLOBALS['dls_cleared'], 'the password step leaves no cookie' );
		$this->assertStringStartsWith( 'https://wp.example.org/wp-login.php?action=dragonloginsecurity_2fa&', $url );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $q['dragonloginsecurity_token'] );
		$this->assertSame( 'https://example.test/my-account/', $q['redirect_to'] );
		$this->assertArrayNotHasKey( 'dragonloginsecurity_user', $q );

		// The token in the address still only shows the challenge once, and a
		// made-up one shows nothing.
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'function login_header( ...$a ) {} function login_footer( ...$a ) {} function esc_url( $u ) { return (string) $u; } function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); } function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }' );
		$_GET = $q;
		ob_start();
		$this->assertTrue( ( new Two_Factor() )->resume_challenge() );
		ob_end_clean();
		foreach ( array( $q['dragonloginsecurity_token'], str_repeat( '0', 64 ) ) as $token ) {
			$_GET['dragonloginsecurity_token'] = $token;
			ob_start();
			try {
				( new Two_Factor() )->resume_challenge();
				$this->fail( 'challenge shown for a spent or unknown token' );
			} catch ( \DLS_Test_Redirect $r ) {
				$this->assertStringNotContainsString( 'dragonloginsecurity_token', $r->getMessage() );
			}
			$this->assertSame( '', (string) ob_get_clean() );
		}
	}
}
