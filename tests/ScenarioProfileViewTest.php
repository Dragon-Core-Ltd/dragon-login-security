<?php
/**
 * Scenario hunt: the profile enrolment section for self vs an administrator
 * viewing another user, an unreadable authenticator, and passkeys while
 * WebAuthn is unavailable.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\User_Profile;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/class-user-profile.php';

class ScenarioProfileViewTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                   = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']     = array();
		$GLOBALS['dls_test_options']       = array( 'date_format' => 'Y-m-d' );
		$GLOBALS['dls_test_is_admin']      = true;
		$GLOBALS['dls_test_mail']          = array();
		$GLOBALS['dls_test_actions_fired'] = array();
		$user                              = new \WP_User( 6, 'kim' );
		$user->user_email                  = 'kim@example.test';
		$GLOBALS['dls_test_users']         = array( 6 => $user );
		WebAuthn::$available_override      = null;
	}

	protected function tearDown(): void {
		WebAuthn::$available_override = null;
	}

	private function render( int $viewer, int $subject ): string {
		if ( ! function_exists( 'get_current_user_id' ) ) {
			// phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only stubs of core helpers, static strings.
			eval(
				'function get_current_user_id() { return (int) ( $GLOBALS["dls_test_current_user"] ?? 0 ); }
				function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); }
				function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }
				function esc_attr_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }'
			);
		}
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
		$GLOBALS['dls_test_current_user'] = $viewer;
		ob_start();
		( new User_Profile() )->render( $GLOBALS['dls_test_users'][ $subject ] );
		return (string) ob_get_clean();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_admin_viewing_another_user_gets_no_enrolment_controls_but_can_disable(): void {
		update_user_meta( 6, Two_Factor::TOTP_META, 'not-a-ciphertext' ); // unreadable
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array( 'id' => 1, 'user_id' => 6, 'credential_id' => 'a', 'public_key' => 'k', 'sign_count' => 0, 'label' => '<img src=x onerror=1>', 'created_at' => '2026-01-02 03:04:05' ),
		);

		$html = $this->render( 5, 6 );

		$this->assertStringContainsString( 'Needs setting up again', $html );
		$this->assertStringContainsString( 'dls-totp-disable', $html );
		$this->assertStringContainsString( 'you can disable it here', $html );
		$this->assertStringNotContainsString( 'id="dls-totp-setup"', $html );
		$this->assertStringNotContainsString( 'id="dls-add-passkey"', $html );
		$this->assertStringNotContainsString( 'id="dls-backup-generate"', $html );
		$this->assertStringContainsString( '&lt;img src=x onerror=1&gt;', $html, 'Labels are escaped.' );
		$this->assertStringNotContainsString( '<img src=x', $html );
		$this->assertStringContainsString( 'dls-remove-passkey', $html, 'An administrator can still remove a passkey.' );
		$this->assertCount( 1, $GLOBALS['dls_test_mail'], 'Viewing the unreadable state tells the user once.' );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_self_with_unreadable_totp_and_no_webauthn_sees_recovery_paths(): void {
		update_user_meta( 6, Two_Factor::TOTP_META, 'not-a-ciphertext' );
		update_user_meta( 6, Two_Factor::TOTP_UNREADABLE_MAILED_META, time() );
		WebAuthn::$available_override                = false;
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array( 'id' => 1, 'user_id' => 6, 'credential_id' => 'a', 'public_key' => 'k', 'sign_count' => 0, 'label' => 'Phone', 'created_at' => '2026-01-02 03:04:05' ),
		);

		$html = $this->render( 6, 6 );

		$this->assertStringContainsString( 'Set up authenticator app again', $html );
		$this->assertStringContainsString( 'id="dls-totp-panel"', $html );
		$this->assertStringContainsString( 'Passkeys are unavailable', $html );
		$this->assertStringNotContainsString( 'id="dls-add-passkey"', $html );
		$this->assertStringContainsString( 'Phone', $html );
		$this->assertStringContainsString( 'id="dls-backup-generate"', $html );
		$this->assertStringContainsString( '0 unused codes remaining', $html );
		$this->assertSame( array(), $GLOBALS['dls_test_mail'], 'Already told; not mailed again.' );

		ob_start();
		( new User_Profile() )->unusable_passkey_notice();
		$this->assertStringContainsString( 'notice-warning', (string) ob_get_clean() );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_viewer_without_edit_user_gets_nothing(): void {
		$GLOBALS['dls_test_is_admin'] = false;
		$this->assertSame( '', $this->render( 5, 6 ) );
	}
}
