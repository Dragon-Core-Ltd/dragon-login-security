<?php
/**
 * The challenge form keeps the session-expiry popup mode.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
class ChallengeViewTest extends TestCase {

	/**
	 * Render the view with login-screen helpers stubbed.
	 *
	 * @param bool $interim Popup mode.
	 * @return string
	 */
	private function render( bool $interim, array $methods = array( 'totp' ), array $wa_args = array( 'args' => null, 'token' => '' ), ?array $network_sites = null ): string {
		if ( ! function_exists( 'login_header' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged
			eval( 'function login_header( ...$a ) {} function login_footer( ...$a ) {} function esc_url( $u ) { return (string) $u; } function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); } function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }' );
		}
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
		$dragonloginsecurity_ctx = array(
			'user'     => new \WP_User( 4, 'sam' ),
			'token'    => 'abc',
			'redirect' => 'https://example.test/wp-admin/',
			'remember' => false,
			'error'    => '',
			'methods'  => $methods,
			'wa_args'  => $wa_args,
			'interim'  => $interim,
		);
		if ( null !== $network_sites ) {
			$dragonloginsecurity_ctx['network_sites'] = $network_sites;
		}
		ob_start();
		require dirname( __DIR__ ) . '/admin/views/2fa-challenge.php';
		return (string) ob_get_clean();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_popup_mode_is_carried_through_the_form(): void {
		$this->assertStringContainsString( 'name="interim-login" value="1"', $this->render( true ) );
		$this->assertStringNotContainsString( 'interim-login', $this->render( false ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_backup_switch_handler_is_present_without_a_passkey(): void {
		// A TOTP + backup-codes user (no passkey): the "use a backup code" link
		// AND its click handler must both be printed, or the switch does nothing
		// and a valid backup code is rejected.
		$html = $this->render( false, array( 'totp', 'backup' ) );
		$this->assertStringContainsString( 'id="dls-use-backup"', $html );
		$this->assertStringContainsString( "getElementById( 'dls-use-backup' )", $html );
		$this->assertStringContainsString( "value = 'backup'", $html );
		// The passkey script block, which used to be the only place the handler
		// lived, is not rendered here.
		$this->assertStringNotContainsString( 'dls-passkey-btn', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_no_backup_switch_when_only_one_code_method(): void {
		// TOTP only: nothing to switch to.
		$html = $this->render( false, array( 'totp' ) );
		$this->assertStringNotContainsString( 'id="dls-use-backup"', $html );
		$this->assertStringNotContainsString( "getElementById( 'dls-use-backup' )", $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_no_stray_separator_for_a_passkey_only_user(): void {
		// Passkey only: the "- or -" separator must not print with nothing after.
		$html = $this->render( false, array( 'passkey' ), array( 'args' => array( 'publicKey' => array() ), 'token' => 't' ) );
		$this->assertStringContainsString( 'dls-passkey-btn', $html );
		$this->assertStringNotContainsString( '- or -', $html );
		$this->assertStringNotContainsString( 'id="dragonloginsecurity_code"', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_separator_shows_when_a_method_follows_the_passkey(): void {
		$html = $this->render( false, array( 'passkey', 'totp' ), array( 'args' => array( 'publicKey' => array() ), 'token' => 't' ) );
		$this->assertStringContainsString( '- or -', $html );
		$this->assertStringContainsString( 'id="dragonloginsecurity_code"', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_dead_end_points_to_the_passkey_sites_without_a_way_through(): void {
		$sites = array(
			array(
				'name'           => 'Shop <script>x</script>',
				'login_url'      => 'https://example.test/a/wp-login.php?redirect_to=https%3A%2F%2Fexample.test%2Fb%2F',
				'shares_cookies' => true,
			),
			array(
				'name'           => 'Blog',
				'login_url'      => 'https://blog.other.test/wp-login.php',
				'shares_cookies' => false,
			),
		);
		$html = $this->render( false, array(), array( 'args' => null, 'token' => '' ), $sites );

		$this->assertStringContainsString( 'href="https://example.test/a/wp-login.php?redirect_to=https%3A%2F%2Fexample.test%2Fb%2F"', $html );
		$this->assertStringContainsString( 'Shop &lt;script&gt;', $html );
		$this->assertStringNotContainsString( '<script>x', $html );
		$this->assertStringContainsString( 'signing in there also signs you in here', $html );
		$this->assertStringContainsString( 'this site does not share its sign-in', $html );
		$this->assertStringContainsString( 'ask an administrator', $html );
		// Display only: no code field, no Verify button, no passkey prompt.
		$this->assertStringNotContainsString( 'id="dragonloginsecurity_code"', $html );
		$this->assertStringNotContainsString( 'type="submit"', $html );
		$this->assertStringNotContainsString( 'dls-passkey-btn', $html );
		$this->assertStringNotContainsString( 'No usable second factor', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_dead_end_without_network_sites_keeps_the_admin_message(): void {
		$html = $this->render( false, array(), array( 'args' => null, 'token' => '' ), array() );
		$this->assertStringContainsString( 'No usable second factor', $html );
		$this->assertStringNotContainsString( '<ul', $html );
	}
}
