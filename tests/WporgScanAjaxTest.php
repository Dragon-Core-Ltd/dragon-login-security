<?php
/**
 * Every enrolment AJAX handler checks the dls_ajax nonce and the capability
 * on its target user in its own body before it reads or writes anything.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Ajax;
use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Ajax::class )]
class WporgScanAjaxTest extends TestCase {

	private const SELF_HANDLERS = array( 'totp_setup', 'totp_confirm', 'passkey_options', 'passkey_register', 'backup_generate', 'backup_confirm' );

	private const ALL_HANDLERS = array( 'totp_setup', 'totp_confirm', 'totp_disable', 'passkey_options', 'passkey_register', 'passkey_remove', 'backup_generate', 'backup_confirm' );

	/**
	 * Core's check_ajax_referer() and JSON responders, per process.
	 */
	private static function load_stubs(): void {
		require_once __DIR__ . '/../includes/class-ajax.php';
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval(
			'class WSA_Exit extends \Exception {
				public $ok; public $payload; public $status;
				public function __construct( $ok, $payload, $status ) { parent::__construct( "exit" ); $this->ok = $ok; $this->payload = $payload; $this->status = $status; }
			}
			function check_ajax_referer( $action = -1, $query_arg = false, $stop = true ) {
				$nonce = "";
				if ( $query_arg && isset( $_REQUEST[ $query_arg ] ) ) { $nonce = $_REQUEST[ $query_arg ]; }
				elseif ( isset( $_REQUEST["_ajax_nonce"] ) ) { $nonce = $_REQUEST["_ajax_nonce"]; }
				elseif ( isset( $_REQUEST["_wpnonce"] ) ) { $nonce = $_REQUEST["_wpnonce"]; }
				$result = wp_verify_nonce( $nonce, $action );
				do_action( "check_ajax_referer", $action, $result );
				if ( $stop && false === $result ) { throw new WSA_Exit( null, -1, 403 ); }
				return $result;
			}
			function get_current_user_id() { return (int) ( $GLOBALS["dls_test_current_user"] ?? 0 ); }
			function absint( $v ) { return abs( (int) $v ); }
			function wp_send_json_success( $data = null, $status = null ) { throw new WSA_Exit( true, $data, $status ); }
			function wp_send_json_error( $data = null, $status = null ) { throw new WSA_Exit( false, $data, $status ); }'
		);
		$GLOBALS['wpdb']                  = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']    = array();
		$GLOBALS['dls_test_transients']   = array();
		$GLOBALS['dls_test_options']      = array( 'date_format' => 'Y-m-d' );
		$GLOBALS['dls_test_actions_fired'] = array();
		$GLOBALS['dls_test_is_admin']     = false;
		$GLOBALS['dls_test_current_user'] = 5;
		$GLOBALS['dls_test_users']        = array(
			5 => new \WP_User( 5, 'sam' ),
			6 => new \WP_User( 6, 'kim' ),
		);
		WebAuthn::$available_override     = true;
	}

	/**
	 * Call a handler with a request (admin-ajax.php POST: $_REQUEST mirrors it).
	 *
	 * @param string $method Handler.
	 * @param array  $post   Posted fields (unslashed).
	 * @return \WSA_Exit
	 */
	private function call( string $method, array $post ): \WSA_Exit {
		$_POST    = array_map( static fn( $v ) => is_string( $v ) ? addslashes( $v ) : $v, $post );
		$_REQUEST = $_POST;
		try {
			( new Ajax() )->$method();
		} catch ( \WSA_Exit $e ) {
			return $e;
		}
		$this->fail( "$method returned without a response." );
	}

	private function untouched(): void {
		$this->assertSame( array(), $GLOBALS['dls_test_user_meta'] );
		$this->assertSame( array(), $GLOBALS['dls_test_transients'] );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_dls_credentials'] ?? array() );
	}

	private function refused( \WSA_Exit $e, string $method ): void {
		$this->assertNull( $e->ok, "$method answered instead of dying" );
		$this->assertSame( -1, $e->payload, $method );
		$this->assertSame( 403, $e->status, $method );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_every_handler_refuses_a_request_without_a_nonce(): void {
		self::load_stubs();
		foreach ( self::ALL_HANDLERS as $method ) {
			$this->refused( $this->call( $method, array( 'user_id' => '5', 'code' => '123456', 'id' => '1' ) ), $method );
		}
		$this->untouched();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_every_handler_refuses_a_wrong_or_misplaced_nonce(): void {
		self::load_stubs();
		$GLOBALS['dls_test_current_user'] = 6;
		$kims                             = wp_create_nonce( 'dls_ajax' );
		$GLOBALS['dls_test_current_user'] = 5;
		$other_action                     = wp_create_nonce( 'dragonloginsecurity_settings' );
		$_COOKIE[ LOGGED_IN_COOKIE ]      = 'sam|1|othersession|h';
		$other_session                    = wp_create_nonce( 'dls_ajax' );
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		foreach ( self::ALL_HANDLERS as $method ) {
			foreach ( array( 'abcdef0123', $kims, $other_action, $other_session, '' ) as $nonce ) {
				$this->refused( $this->call( $method, array( 'nonce' => $nonce, 'user_id' => '5' ) ), $method );
			}
		}
		$this->untouched();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_nonce_also_counts_from_the_query_string(): void {
		self::load_stubs();
		$_GET     = array( 'nonce' => wp_create_nonce( 'dls_ajax' ) );
		$_POST    = array();
		$_REQUEST = $_GET;
		try {
			( new Ajax() )->backup_generate();
			$this->fail( 'no response' );
		} catch ( \WSA_Exit $e ) {
			$this->assertTrue( $e->ok );
		}
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_enrolment_handlers_refuse_another_users_account_even_for_an_admin(): void {
		self::load_stubs();
		$GLOBALS['dls_test_is_admin'] = true;
		$nonce                        = wp_create_nonce( 'dls_ajax' );
		foreach ( self::SELF_HANDLERS as $method ) {
			foreach ( array( '6', array( '5' ), '6abc' ) as $target ) {
				$e = $this->call( $method, array( 'nonce' => $nonce, 'user_id' => $target ) );
				$this->assertFalse( $e->ok, $method );
				$this->assertSame( 403, $e->status, $method );
				$this->assertSame( 'You can only set up two-factor for your own account.', $e->payload['message'], $method );
			}
		}
		$this->untouched();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_logged_out_request_is_refused(): void {
		self::load_stubs();
		$GLOBALS['dls_test_current_user'] = 0;
		$nonce                            = wp_create_nonce( 'dls_ajax' );
		foreach ( self::ALL_HANDLERS as $method ) {
			$e = $this->call( $method, array( 'nonce' => $nonce ) );
			$this->assertFalse( $e->ok, $method );
			$this->assertSame( 403, $e->status, $method );
		}
		$this->untouched();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_managing_another_users_factors_needs_edit_user_on_them(): void {
		self::load_stubs();
		update_user_meta( 6, Two_Factor::TOTP_META, 'kims-secret' );
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array( 'id' => 9, 'user_id' => 6, 'credential_id' => 'k', 'public_key' => 'p', 'sign_count' => 0 ),
		);
		$nonce = wp_create_nonce( 'dls_ajax' );
		foreach ( array( 'totp_disable', 'passkey_remove' ) as $method ) {
			$e = $this->call( $method, array( 'nonce' => $nonce, 'user_id' => '6', 'id' => '9' ) );
			$this->assertFalse( $e->ok, $method );
			$this->assertSame( 403, $e->status, $method );
			$this->assertSame( 'Permission denied.', $e->payload['message'], $method );
		}
		$this->assertSame( 'kims-secret', get_user_meta( 6, Two_Factor::TOTP_META, true ) );
		$this->assertCount( 1, $GLOBALS['wpdb']->rows['wp_dls_credentials'] );

		$GLOBALS['dls_test_is_admin'] = true;
		$this->assertTrue( $this->call( 'totp_disable', array( 'nonce' => $nonce, 'user_id' => '6' ) )->ok );
		$this->assertSame( '', get_user_meta( 6, Two_Factor::TOTP_META, true ) );
		$this->assertTrue( $this->call( 'passkey_remove', array( 'nonce' => $nonce, 'user_id' => '6', 'id' => '9' ) )->ok );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_dls_credentials'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_user_manages_their_own_factors_without_any_role_capability(): void {
		self::load_stubs();
		$nonce = wp_create_nonce( 'dls_ajax' );

		$setup = $this->call( 'totp_setup', array( 'nonce' => $nonce, 'user_id' => '5' ) );
		$this->assertTrue( $setup->ok );
		$secret = $setup->payload['secret'];

		$wrong = $this->call( 'totp_confirm', array( 'nonce' => $nonce, 'user_id' => '5', 'code' => '000000' === Provider_TOTP::code_at( $secret, time() ) ? '111111' : '000000' ) );
		$this->assertFalse( $wrong->ok );
		$this->assertSame( '', get_user_meta( 5, Two_Factor::TOTP_META, true ) );

		// A padded code and no user_id (the caller's own account) still confirm.
		$ok = $this->call( 'totp_confirm', array( 'nonce' => $nonce, 'code' => ' ' . Provider_TOTP::code_at( $secret, time() ) . ' ' ) );
		$this->assertTrue( $ok->ok );
		$this->assertSame( $secret, Crypto::decrypt( get_user_meta( 5, Two_Factor::TOTP_META, true ) ) );

		$codes = $this->call( 'backup_generate', array( 'nonce' => $nonce, 'user_id' => ' 5' ) );
		$this->assertTrue( $codes->ok );
		$this->assertCount( 10, $codes->payload['codes'] );
		$this->assertSame( 10, Provider_Backup_Codes::remaining( 5 ) );
		$this->assertTrue( $this->call( 'backup_confirm', array( 'nonce' => $nonce, 'user_id' => '5' ) )->ok );
		$this->assertSame( 1, (int) get_user_meta( 5, 'dls_backup_codes_confirmed', true ) );

		$this->assertTrue( $this->call( 'passkey_options', array( 'nonce' => $nonce, 'user_id' => '5' ) )->ok );
		$bad = $this->call(
			'passkey_register',
			array(
				'nonce'       => $nonce,
				'user_id'     => '5',
				'client_data' => "e30=\x01",
				'attestation' => array( 'x' ),
				'label'       => 'My "key" \\ 1',
			)
		);
		$this->assertFalse( $bad->ok );
		$this->assertSame( 'Passkey registration failed.', $bad->payload['message'] );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_dls_credentials'] ?? array() );

		$missing = $this->call( 'passkey_remove', array( 'nonce' => $nonce, 'user_id' => '5', 'id' => 'abc' ) );
		$this->assertFalse( $missing->ok );
		$this->assertSame( 'Could not remove passkey.', $missing->payload['message'] );

		$this->assertTrue( $this->call( 'totp_disable', array( 'nonce' => $nonce, 'user_id' => '5' ) )->ok );
		$this->assertSame( '', get_user_meta( 5, Two_Factor::TOTP_META, true ) );
	}
}
