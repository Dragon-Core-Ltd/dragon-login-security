<?php
/**
 * The authenticate-stage second-factor gate for non-interactive credentials.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class TwoFactorGateTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_filters']   = array();
		$GLOBALS['dls_test_users']     = array(
			1 => new \WP_User( 1, 'owner' ),
			2 => new \WP_User( 2, 'editor' ),
		);
		// User 1 has an authenticator app; user 2 has no second factor.
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( Provider_TOTP::generate_secret() ) );
	}

	/**
	 * Run one authenticate pass the way core orders it: the reset at the start,
	 * an optional application-password match at 20, then the gate at 40.
	 *
	 * @param Two_Factor    $tf       Gate.
	 * @param \WP_User|null $app_user User an application password matched, if any.
	 * @param mixed         $result   Result reaching priority 40.
	 * @return mixed
	 */
	private function pass( Two_Factor $tf, ?\WP_User $app_user, $result ) {
		$tf->reset_app_password( null );
		if ( $app_user ) {
			$tf->mark_app_password( $app_user );
		}
		return $tf->enforce_non_interactive( $result );
	}

	public function test_gate_hooks_bracket_core_credential_checks(): void {
		( new Two_Factor() )->hook();
		$priorities = array();
		foreach ( $GLOBALS['dls_test_filters'] as $filter ) {
			if ( 'authenticate' === $filter[0] ) {
				$priorities[ $filter[1][1] ] = $filter[2];
			}
		}
		$this->assertLessThan( 20, $priorities['reset_app_password'] );
		$this->assertSame( 40, $priorities['enforce_non_interactive'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_password_without_app_password_is_refused(): void {
		define( 'XMLRPC_REQUEST', true );
		$tf = new Two_Factor();
		$this->assertInstanceOf( \WP_Error::class, $this->pass( $tf, null, get_userdata( 1 ) ) );
		// No second factor: nothing to enforce.
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, null, get_userdata( 2 ) ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_app_password_pass_is_bound_to_its_user(): void {
		define( 'XMLRPC_REQUEST', true );
		$tf = new Two_Factor();

		// Its own application password: allowed.
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, get_userdata( 1 ), get_userdata( 1 ) ) );

		// A pass exempts only the user its application password belongs to.
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, get_userdata( 2 ), get_userdata( 2 ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->pass( $tf, null, get_userdata( 1 ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->pass( $tf, null, get_userdata( 1 ) ) );
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, get_userdata( 2 ), get_userdata( 2 ) ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_marker_for_one_user_never_admits_another(): void {
		define( 'XMLRPC_REQUEST', true );
		$tf = new Two_Factor();

		// Recorded without a reset in between.
		$tf->mark_app_password( get_userdata( 2 ) );
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_marker_lasts_one_authenticate_pass(): void {
		define( 'XMLRPC_REQUEST', true );
		$tf = new Two_Factor();

		// Each pass starts clean.
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, get_userdata( 1 ), get_userdata( 1 ) ) );
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );

		// Also when a pass ends in an error before the gate sees a user.
		$tf->reset_app_password( null );
		$tf->mark_app_password( get_userdata( 1 ) );
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( new \WP_Error( 'dragonloginsecurity_locked' ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->pass( $tf, null, get_userdata( 1 ) ) );

		// And when the gate never ran for that pass.
		$tf->reset_app_password( null );
		$tf->mark_app_password( get_userdata( 1 ) );
		$this->assertInstanceOf( \WP_Error::class, $this->pass( $tf, null, get_userdata( 1 ) ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_marker_without_a_user_admits_nobody(): void {
		define( 'REST_REQUEST', true );
		$tf = new Two_Factor();
		$tf->reset_app_password( null );
		$tf->mark_app_password();
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );
		$tf->mark_app_password( 'owner' );
		$this->assertInstanceOf( \WP_Error::class, $tf->enforce_non_interactive( get_userdata( 1 ) ) );
	}

	public function test_interactive_login_is_left_to_the_challenge(): void {
		$tf = new Two_Factor();
		$this->assertInstanceOf( \WP_User::class, $this->pass( $tf, null, get_userdata( 1 ) ) );
	}
}
