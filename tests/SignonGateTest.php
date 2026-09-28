<?php
/**
 * A password alone authenticates a two-factor user only inside wp_signon(),
 * whose cookies the challenge holds back. Any other authenticate pass (an
 * HTTP Basic plugin on determine_current_user, a custom login route, XML-RPC
 * or REST) is refused unless an application password was used.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class SignonGateTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_sessions']  = array();
		$GLOBALS['dls_test_users']     = array(
			1 => new \WP_User( 1, 'owner' ),
			2 => new \WP_User( 2, 'editor' ),
		);
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
	}

	public function test_a_password_outside_wp_signon_is_refused_without_any_request_constant(): void {
		// Neither XMLRPC_REQUEST nor REST_REQUEST is defined here, as on a
		// determine_current_user pass that runs before parse_request.
		$tf = new Two_Factor();
		$tf->reset_app_password( null );
		$result = $tf->enforce_non_interactive( get_userdata( 1 ) );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'dragonloginsecurity_2fa_required', $result->get_error_code() );

		// A user without a second factor is unaffected.
		$this->assertInstanceOf( \WP_User::class, $tf->enforce_non_interactive( get_userdata( 2 ) ) );
	}

	public function test_inside_wp_signon_the_password_step_passes_to_the_challenge(): void {
		$tf = new Two_Factor();
		$tf->note_signon();
		$tf->reset_app_password( null );
		$this->assertInstanceOf( \WP_User::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );

		// wp_signon() ends its pass at PHP_INT_MAX; a later direct pass in the
		// same request is no longer interactive.
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$tf->reset_app_password( null );
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );
	}

	public function test_an_application_password_still_passes_outside_wp_signon(): void {
		$tf = new Two_Factor();
		$tf->reset_app_password( null );
		$tf->mark_app_password( get_userdata( 1 ) );
		$this->assertInstanceOf( \WP_User::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );
	}
}
