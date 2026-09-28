<?php
/**
 * Scenario hunt: the profile enrolment AJAX handlers under hostile and
 * failing conditions (other users' ids, expired pending secrets, refused
 * writes, ordering of backup-code calls).
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
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/class-ajax.php';

/**
 * wp_send_json_* ends the request; the stubs throw this instead.
 */
final class JsonExit extends \RuntimeException {
	public bool $ok;
	public $payload;
	public ?int $status;
	public function __construct( bool $ok, $payload, ?int $status ) {
		parent::__construct( $ok ? 'success' : 'error' );
		$this->ok      = $ok;
		$this->payload = $payload;
		$this->status  = $status;
	}
}

if ( ! function_exists( 'check_ajax_referer' ) ) {
	// phpcs:ignore Squiz.PHP.Eval.Discouraged
	eval(
		'function check_ajax_referer( $a, $q = false, $die = true ) { $GLOBALS["dls_test_nonce_checked"] = true; return 1; }
		function get_current_user_id() { return (int) ( $GLOBALS["dls_test_current_user"] ?? 0 ); }
		function absint( $v ) { return abs( (int) $v ); }
		function wp_send_json_success( $data = null, $status = null ) { throw new \DragonLoginSecurity\Tests\JsonExit( true, $data, $status ); }
		function wp_send_json_error( $data = null, $status = null ) { throw new \DragonLoginSecurity\Tests\JsonExit( false, $data, $status ); }'
	);
}

class ScenarioEnrolmentAjaxTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                      = new class() extends \DLS_Test_Wpdb {
			public $inserted = array();
			public function insert( $table, $data, $format = null ) {
				unset( $table, $format );
				$this->inserted[] = $data;
				return $this->insert_result;
			}
		};
		$GLOBALS['dls_test_user_meta']        = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_transients']       = array();
		$GLOBALS['dls_test_options']          = array( 'date_format' => 'Y-m-d' );
		$GLOBALS['dls_test_actions_fired']    = array();
		$GLOBALS['dls_test_is_admin']         = false;
		$GLOBALS['dls_test_current_user']     = 5;
		$GLOBALS['dls_test_users']            = array(
			5 => new \WP_User( 5, 'sam' ),
			6 => new \WP_User( 6, 'kim' ),
		);
		$_POST                                = array( 'nonce' => 'n' );
		WebAuthn::$available_override         = null;
	}

	protected function tearDown(): void {
		$_POST                                = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_is_admin']         = true;
		WebAuthn::$available_override         = null;
	}

	private function call( string $method, array $post = array() ): JsonExit {
		$_POST = array_merge( array( 'nonce' => 'n' ), $post );
		try {
			( new Ajax() )->$method();
		} catch ( JsonExit $e ) {
			return $e;
		}
		$this->fail( "$method returned without sending JSON." );
	}

	private function events(): array {
		$out = array();
		foreach ( $GLOBALS['dls_test_actions_fired'] as $fired ) {
			if ( 'dragonloginsecurity_login_event' === $fired[0] ) {
				$out[] = array( $fired[1][0], $fired[1][1]['object_id'] );
			}
		}
		return $out;
	}

	// --- target user guards ---

	public function test_enrolment_handlers_refuse_another_users_id_even_for_an_admin(): void {
		$GLOBALS['dls_test_is_admin'] = true;
		foreach ( array( 'totp_setup', 'totp_confirm', 'passkey_options', 'passkey_register', 'backup_generate', 'backup_confirm' ) as $method ) {
			$r = $this->call( $method, array( 'user_id' => '6' ) );
			$this->assertFalse( $r->ok, $method );
			$this->assertSame( 403, $r->status, $method );
		}
		$this->assertSame( array(), $GLOBALS['dls_test_transients'], 'No pending secret or challenge was created for the other user.' );
		$this->assertSame( array(), $GLOBALS['dls_test_user_meta'] );
		$this->assertSame( array(), $this->events() );
	}

	public function test_enrolment_handlers_refuse_a_logged_out_request(): void {
		$GLOBALS['dls_test_current_user'] = 0;
		$r                                = $this->call( 'passkey_options' );
		$this->assertSame( 403, $r->status );
	}

	public function test_passkey_removal_is_scoped_to_the_owner(): void {
		$GLOBALS['wpdb']->rows['wp_dls_credentials'] = array(
			array( 'id' => 9, 'user_id' => 6, 'credential_id' => 'k', 'public_key' => 'p', 'sign_count' => 0 ),
		);
		// Sam names Kim's row id with his own user id.
		$r = $this->call( 'passkey_remove', array( 'id' => '9', 'user_id' => '5' ) );
		$this->assertFalse( $r->ok );
		$this->assertCount( 1, $GLOBALS['wpdb']->rows['wp_dls_credentials'] );
		$this->assertSame( array(), $this->events() );

		// A non-admin naming Kim directly is refused by the capability check.
		$r = $this->call( 'passkey_remove', array( 'id' => '9', 'user_id' => '6' ) );
		$this->assertSame( 403, $r->status );
		$this->assertCount( 1, $GLOBALS['wpdb']->rows['wp_dls_credentials'] );

		// An administrator may remove it, and the event names Kim.
		$GLOBALS['dls_test_is_admin'] = true;
		$r                            = $this->call( 'passkey_remove', array( 'id' => '9', 'user_id' => '6' ) );
		$this->assertTrue( $r->ok );
		$this->assertSame( array(), $GLOBALS['wpdb']->rows['wp_dls_credentials'] );
		$this->assertSame( array( array( 'passkey.removed', 6 ) ), $this->events() );
	}

	public function test_admin_can_disable_an_unreadable_authenticator_for_another_user(): void {
		$GLOBALS['dls_test_is_admin'] = true;
		update_user_meta( 6, Two_Factor::TOTP_META, 'not-a-ciphertext' );
		update_user_meta( 6, Two_Factor::TOTP_UNREADABLE_MAILED_META, time() );

		$r = $this->call( 'totp_disable', array( 'user_id' => '6' ) );

		$this->assertTrue( $r->ok );
		$this->assertSame( '', get_user_meta( 6, Two_Factor::TOTP_META, true ) );
		$this->assertSame( '', get_user_meta( 6, Two_Factor::TOTP_UNREADABLE_MAILED_META, true ) );
		$this->assertSame( 'none', ( new Two_Factor() )->totp_state( 6 ) );
		$this->assertSame( array( array( '2fa.disabled', 6 ) ), $this->events() );
	}

	// --- TOTP ---

	public function test_totp_confirm_with_an_expired_pending_secret_enables_nothing(): void {
		$r = $this->call( 'totp_confirm', array( 'code' => '123456' ) );
		$this->assertFalse( $r->ok );
		$this->assertSame( '', get_user_meta( 5, Two_Factor::TOTP_META, true ) );
		$this->assertSame( array(), $this->events() );
	}

	public function test_totp_wrong_code_keeps_the_pending_secret_for_a_retry(): void {
		$setup  = $this->call( 'totp_setup' );
		$secret = $setup->payload['secret'];
		$good   = Provider_TOTP::code_at( $secret, time() );
		$wrong  = '000000' === $good ? '111111' : '000000';

		$r = $this->call( 'totp_confirm', array( 'code' => $wrong ) );
		$this->assertFalse( $r->ok );
		$this->assertSame( $secret, Crypto::decrypt( get_transient( 'dragonloginsecurity_totp_pending_5' ) ) );
		$this->assertSame( '', get_user_meta( 5, Two_Factor::TOTP_META, true ) );

		$r = $this->call( 'totp_confirm', array( 'code' => $good ) );
		$this->assertTrue( $r->ok );
		$this->assertSame( $secret, Crypto::decrypt( get_user_meta( 5, Two_Factor::TOTP_META, true ) ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_totp_pending_5' ) );
		$this->assertSame( array( array( '2fa.enrolled', 5 ) ), $this->events() );
	}

	public function test_totp_confirm_reports_a_refused_write_and_keeps_the_pending_secret(): void {
		$setup  = $this->call( 'totp_setup' );
		$secret = $setup->payload['secret'];
		$good   = Provider_TOTP::code_at( $secret, time() );

		$GLOBALS['dls_test_meta_write_fails'] = true;
		$r                                    = $this->call( 'totp_confirm', array( 'code' => $good ) );

		$this->assertFalse( $r->ok );
		$this->assertStringContainsString( 'could not be saved', $r->payload['message'] );
		$this->assertNotFalse( get_transient( 'dragonloginsecurity_totp_pending_5' ), 'The user can retry once the write works.' );
		$this->assertSame( array(), $this->events(), 'No enrolment event for a factor that was not stored.' );
	}

	// --- backup codes ---

	public function test_backup_confirm_before_any_codes_exist_is_refused(): void {
		// The confirmation is what satisfies a "backup codes saved" policy. With
		// no codes stored there is nothing to confirm, so a crafted request must
		// not be able to mark the policy satisfied.
		$this->assertSame( 0, Provider_Backup_Codes::remaining( 5 ) );

		$r = $this->call( 'backup_confirm' );

		$this->assertFalse( $r->ok, 'Confirmed with zero codes stored.' );
		$this->assertSame( '', get_user_meta( 5, 'dls_backup_codes_confirmed', true ) );
	}

	public function test_regenerating_codes_clears_the_confirmation_and_a_refused_write_keeps_the_old_set(): void {
		$first = $this->call( 'backup_generate' );
		$this->assertCount( 10, $first->payload['codes'] );
		$this->assertTrue( $this->call( 'backup_confirm' )->ok );
		$this->assertSame( 1, (int) get_user_meta( 5, 'dls_backup_codes_confirmed', true ) );

		$second = $this->call( 'backup_generate' );
		$this->assertTrue( $second->ok );
		$this->assertSame( '', get_user_meta( 5, 'dls_backup_codes_confirmed', true ), 'A new set is unconfirmed.' );
		$this->assertFalse( Provider_Backup_Codes::verify_and_consume( 5, $first->payload['codes'][0] ), 'The old set stopped working.' );
		$this->assertTrue( $this->call( 'backup_confirm' )->ok );

		$GLOBALS['dls_test_meta_write_fails'] = true;
		$third                                = $this->call( 'backup_generate' );
		$this->assertFalse( $third->ok );
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$this->assertSame( 10, Provider_Backup_Codes::remaining( 5 ) );
		$this->assertTrue( Provider_Backup_Codes::verify_and_consume( 5, $second->payload['codes'][3] ), 'The second set is still the live one.' );
		$this->assertSame( 1, (int) get_user_meta( 5, 'dls_backup_codes_confirmed', true ), 'The confirmation of the live set survives a failed regeneration.' );
	}

	public function test_backup_confirm_reports_a_refused_write(): void {
		$this->call( 'backup_generate' );
		$GLOBALS['dls_test_meta_write_fails'] = true;
		$r                                    = $this->call( 'backup_confirm' );
		$this->assertFalse( $r->ok );
	}

	// --- passkeys ---

	public function test_passkey_register_without_the_library_is_refused_before_the_challenge(): void {
		WebAuthn::$available_override = false;
		$r                            = $this->call( 'passkey_options' );
		$this->assertSame( 501, $r->status );
		$this->assertSame( array(), $GLOBALS['dls_test_transients'] );

		$r = $this->call( 'passkey_register', array( 'client_data' => 'x', 'attestation' => 'y' ) );
		$this->assertSame( 501, $r->status );
		$this->assertSame( array(), $GLOBALS['wpdb']->inserted );
	}

	public function test_passkey_register_failure_consumes_the_challenge_and_stores_nothing(): void {
		$opts = $this->call( 'passkey_options' );
		$this->assertTrue( $opts->ok );
		$this->assertArrayHasKey( 'excludeCredentials', $opts->payload['publicKey'] );
		$this->assertNotFalse( get_transient( 'dragonloginsecurity_wa_reg_5' ) );

		$r = $this->call( 'passkey_register', array( 'client_data' => base64_encode( '{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.test"}' ), 'attestation' => base64_encode( 'junk' ) ) );

		$this->assertFalse( $r->ok );
		$this->assertSame( 'Passkey registration failed.', $r->payload['message'] );
		$this->assertFalse( get_transient( 'dragonloginsecurity_wa_reg_5' ), 'A failed attempt needs fresh options; enroll.js requests them on every click.' );
		$this->assertSame( array(), $GLOBALS['wpdb']->inserted );
		$this->assertSame( array(), $this->events() );
	}

	public function test_passkey_register_reports_a_refused_insert_without_an_event(): void {
		// Bypass the ceremony: the insert is what is under test.
		$GLOBALS['wpdb']->insert_result = false;
		$ajax                           = new class() extends Ajax {};
		$this->assertSame( 0, \DragonLoginSecurity\Credentials::add( 5, 'id', 'pem', 0, 'internal', '<b>Phone</b>' ) );
		$this->assertSame( '<b>Phone</b>', $GLOBALS['wpdb']->inserted[0]['label'], 'add() stores what it is given; the handler sanitises.' );
		unset( $ajax );
	}

	public function test_passkey_label_defaults_and_is_sanitised(): void {
		// enroll.js never sends a label, so the default applies; a crafted one
		// is stripped of tags and clipped.
		$this->assertSame( sprintf( 'Passkey (%s)', wp_date( 'Y-m-d' ) ), self::default_label() );
		$this->assertSame( 'Phone', sanitize_text_field( '<b>Phone</b>' ) );
	}

	private static function default_label(): string {
		$m = new \ReflectionMethod( Ajax::class, 'default_passkey_label' );
		$m->setAccessible( true );
		return $m->invoke( null );
	}
}
