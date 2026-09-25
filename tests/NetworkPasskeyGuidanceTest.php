<?php
/**
 * A user whose only passkey lives on another network site is pointed there,
 * and is never let through this site's challenge without a verified factor.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Credentials;
use DragonLoginSecurity\Provider_Passkey;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Provider_Passkey::class )]
#[CoversClass( Credentials::class )]
#[CoversClass( Two_Factor::class )]
class NetworkPasskeyGuidanceTest extends TestCase {

	private const BASENAME = 'dragon-login-security/dragon-login-security.php';

	protected function setUp(): void {
		$GLOBALS['dls_test_user_meta']    = array();
		$GLOBALS['dls_test_multisite']    = true;
		$GLOBALS['dls_test_current_blog'] = 2;
		$GLOBALS['dls_test_blog_options'] = array(
			3 => array( 'blogname' => 'Site A' ),
		);
		$GLOBALS['dls_test_site_options'] = array( 'active_sitewide_plugins' => array( self::BASENAME => 1 ) );
		WebAuthn::$available_override     = true;
		$this->layout( 'example.test', '/b/', 'example.test', '/a/' );

		$GLOBALS['wpdb']         = new \DLS_Test_Wpdb();
		$GLOBALS['wpdb']->prefix = 'wp_2_';
		// This request runs on site 2 (B); user 8 registered a passkey on site 3 (A).
		$GLOBALS['wpdb']->rows = array(
			'wp_2_dls_credentials'     => array(),
			'wp_3_dls_credentials'     => array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'x', 'public_key' => 'k', 'sign_count' => 0 ) ),
			'wp_3_old_dls_credentials' => array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'y', 'public_key' => 'k', 'sign_count' => 0 ) ),
		);
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_multisite']    = false;
		$GLOBALS['dls_test_current_blog'] = 1;
		$GLOBALS['dls_test_sites']        = array();
		$GLOBALS['dls_test_blog_options'] = array();
		$GLOBALS['dls_test_site_options'] = array();
		WebAuthn::$available_override     = null;
	}

	/**
	 * Site 2 (this one) and site 3 (where the passkey is).
	 *
	 * @param string $b_host Host of site B.
	 * @param string $b_path Path of site B.
	 * @param string $a_host Host of site A.
	 * @param string $a_path Path of site A.
	 */
	private function layout( string $b_host, string $b_path, string $a_host, string $a_path ): void {
		$GLOBALS['dls_test_sites'] = array(
			1 => (object) array( 'blog_id' => '1', 'domain' => 'example.test', 'path' => '/', 'archived' => '0', 'deleted' => '0', 'spam' => '0' ),
			2 => (object) array( 'blog_id' => '2', 'domain' => $b_host, 'path' => $b_path, 'archived' => '0', 'deleted' => '0', 'spam' => '0' ),
			3 => (object) array( 'blog_id' => '3', 'domain' => $a_host, 'path' => $a_path, 'archived' => '0', 'deleted' => '0', 'spam' => '0' ),
		);
	}

	public function test_cookie_rule_matrix(): void {
		// Subdirectory network: host-only cookie, one host.
		$this->assertTrue( Provider_Passkey::cookie_reaches( '', '/', 'example.test', 'example.test', '/b/' ) );
		$this->assertTrue( Provider_Passkey::cookie_reaches( '', '/', 'Example.TEST', 'example.test', '/b/' ) );
		// Subdomain network with core's default '.network-domain'.
		$this->assertTrue( Provider_Passkey::cookie_reaches( '.example.test', '/', 'a.example.test', 'b.example.test', '/' ) );
		$this->assertTrue( Provider_Passkey::cookie_reaches( 'example.test', '/', 'a.example.test', 'example.test', '/' ) );
		// Subdomain network with COOKIE_DOMAIN switched off: host-only.
		$this->assertFalse( Provider_Passkey::cookie_reaches( '', '/', 'a.example.test', 'b.example.test', '/' ) );
		// Mapped domain outside the cookie domain, either way round.
		$this->assertFalse( Provider_Passkey::cookie_reaches( '.example.test', '/', 'a.example.test', 'shop.other.test', '/' ) );
		$this->assertFalse( Provider_Passkey::cookie_reaches( '.example.test', '/', 'shop.other.test', 'b.example.test', '/' ) );
		// A look-alike host is not inside the domain.
		$this->assertFalse( Provider_Passkey::cookie_reaches( '.example.test', '/', 'a.example.test', 'evilexample.test', '/' ) );
		// Cookie path: network under /net/ covers /net/b/ but not /other/.
		$this->assertTrue( Provider_Passkey::cookie_reaches( '', '/net/', 'example.test', 'example.test', '/net/b/' ) );
		$this->assertTrue( Provider_Passkey::cookie_reaches( '', '/net', 'example.test', 'example.test', '/net' ) );
		$this->assertFalse( Provider_Passkey::cookie_reaches( '', '/net/', 'example.test', 'example.test', '/network/' ) );
		$this->assertFalse( Provider_Passkey::cookie_reaches( '', '/', '', 'example.test', '/' ) );
	}

	public function test_subdirectory_network_lists_the_passkey_site_with_a_return_link(): void {
		$sites = Provider_Passkey::other_network_sites( 8, 'https://example.test/b/wp-admin/' );

		$this->assertCount( 1, $sites );
		$this->assertSame( 'Site A', $sites[0]['name'] );
		$this->assertSame(
			'https://example.test/a/wp-login.php?redirect_to=' . rawurlencode( 'https://example.test/b/wp-admin/' ),
			$sites[0]['login_url']
		);
		// COOKIE_DOMAIN is false on a subdirectory network: host-only, same host.
		$this->assertTrue( $sites[0]['shares_cookies'] );
	}

	public function test_off_site_return_target_is_replaced(): void {
		$sites = Provider_Passkey::other_network_sites( 8, 'https://evil.test/' );
		$this->assertStringNotContainsString( 'evil.test', $sites[0]['login_url'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_subdomain_network_with_shared_cookie_domain(): void {
		define( 'COOKIE_DOMAIN', '.example.test' );
		$this->layout( 'b.example.test', '/', 'a.example.test', '/' );
		$this->assertTrue( Provider_Passkey::other_network_sites( 8, '' )[0]['shares_cookies'] );

		// A site on a mapped domain does not get this network's cookie.
		$this->layout( 'b.example.test', '/', 'shop.other.test', '/' );
		$this->assertFalse( Provider_Passkey::other_network_sites( 8, '' )[0]['shares_cookies'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_subdomain_network_without_shared_cookies(): void {
		define( 'COOKIE_DOMAIN', false );
		$this->layout( 'b.example.test', '/', 'a.example.test', '/' );
		$sites = Provider_Passkey::other_network_sites( 8, '' );
		$this->assertCount( 1, $sites );
		$this->assertFalse( $sites[0]['shares_cookies'] );
	}

	public function test_main_site_table_maps_to_the_main_site(): void {
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'm', 'public_key' => 'k', 'sign_count' => 0 ) );
		$ids = Credentials::network_site_ids_for_user( 8 );
		sort( $ids );
		$this->assertSame( array( 1, 3 ), $ids );
	}

	public function test_unusable_sites_are_left_out(): void {
		$GLOBALS['wpdb']->rows['wp_2_dls_credentials'] = array( array( 'id' => 5, 'user_id' => 9, 'credential_id' => 'h', 'public_key' => 'k', 'sign_count' => 0 ) );
		$GLOBALS['wpdb']->rows['wp_dls_credentials']   = array( array( 'id' => 1, 'user_id' => 8, 'credential_id' => 'm', 'public_key' => 'k', 'sign_count' => 0 ) );
		$GLOBALS['dls_test_sites'][1]->archived        = '1';

		$this->assertSame( array( 'Site A' ), array_column( Provider_Passkey::other_network_sites( 8, '' ), 'name' ) );
		// This site itself is never listed.
		$this->assertSame( array(), Provider_Passkey::other_network_sites( 9, '' ) );

		// Plugin off on site A (neither network- nor site-activated).
		$GLOBALS['dls_test_site_options'] = array();
		$this->assertSame( array(), Provider_Passkey::other_network_sites( 8, '' ) );
		$GLOBALS['dls_test_blog_options'][3]['active_plugins'] = array( self::BASENAME );
		$this->assertCount( 1, Provider_Passkey::other_network_sites( 8, '' ) );

		// A deleted site.
		unset( $GLOBALS['dls_test_sites'][3] );
		$this->assertSame( array(), Provider_Passkey::other_network_sites( 8, '' ) );
	}

	public function test_single_site_lists_nothing(): void {
		$GLOBALS['dls_test_multisite'] = false;
		$this->assertSame( array(), Credentials::network_site_ids_for_user( 8 ) );
		$this->assertSame( array(), Provider_Passkey::other_network_sites( 8, '' ) );
	}

	public function test_dead_end_user_still_cannot_pass_without_a_factor(): void {
		$tf = new Two_Factor();
		// Still challenged here, with nothing this site can verify.
		$this->assertTrue( $tf->user_has_2fa( 8 ) );
		$this->assertSame( array(), $tf->available_methods( 8 ) );

		$validate = new \ReflectionMethod( Two_Factor::class, 'validate_factor' );
		$attempts = array(
			// Site A's own credential id, replayed at site B.
			'passkey' => array(
				'dragonloginsecurity_wa_token'  => 'anything',
				'dragonloginsecurity_wa_id'     => 'x',
				'dragonloginsecurity_wa_client' => base64_encode( '{"type":"webauthn.get"}' ),
				'dragonloginsecurity_wa_auth'   => base64_encode( str_repeat( "\0", 37 ) ),
				'dragonloginsecurity_wa_sig'    => base64_encode( 'sig' ),
			),
			'totp'    => array( 'dragonloginsecurity_code' => '123456' ),
			'backup'  => array( 'dragonloginsecurity_code' => 'aaaaa-bbbbb' ),
			''        => array(),
			'network' => array(),
		);
		foreach ( $attempts as $method => $post ) {
			// A live challenge, so the passkey attempt gets past the token check
			// and is refused at the credential lookup.
			set_transient( 'dragonloginsecurity_wa_auth_anything', base64_encode( 'challenge-bytes' ), 300 );
			$_POST = $post;
			$this->assertFalse( $validate->invoke( $tf, 8, (string) $method ), "method '$method' must not pass" );
			if ( 'passkey' === $method ) {
				$this->assertFalse( get_transient( 'dragonloginsecurity_wa_auth_anything' ), 'the challenge was consumed, so the token check passed' );
			}
		}
		$_POST = array();

		// Verification looks only in this site's table: site A's credential is
		// invisible here and found only on site A.
		$this->assertNull( Credentials::by_credential_id( 'x' ) );
		$GLOBALS['wpdb']->prefix = 'wp_3_';
		$this->assertSame( 8, (int) Credentials::by_credential_id( 'x' )['user_id'] );
	}
}
