<?php
/**
 * An authenticator secret that no longer decrypts (a rotated salt) keeps the
 * second factor required instead of silently dropping the account to a
 * password alone; the user is told once.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class TotpUnreadableTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                   = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']     = array();
		$GLOBALS['dls_test_actions_fired'] = array();
		$GLOBALS['dls_test_mail']          = array();
		$GLOBALS['dls_test_mail_result']   = true;
		$owner                             = new \WP_User( 1, 'owner' );
		$owner->user_email                 = 'owner@example.test';
		$GLOBALS['dls_test_users']         = array( 1 => $owner );
		update_user_meta( 1, Two_Factor::TOTP_META, 'not-a-ciphertext' );
	}

	private function event_codes(): array {
		$codes = array();
		foreach ( $GLOBALS['dls_test_actions_fired'] as $fired ) {
			if ( 'dragonloginsecurity_login_event' === $fired[0] ) {
				$codes[] = $fired[1][0];
			}
		}
		return $codes;
	}

	public function test_the_profile_can_tell_the_states_apart(): void {
		$tf = new Two_Factor();
		$this->assertSame( 'unreadable', $tf->totp_state( 1 ) );
		delete_user_meta( 1, Two_Factor::TOTP_META );
		$this->assertSame( 'none', $tf->totp_state( 1 ) );
		update_user_meta( 1, Two_Factor::TOTP_META, \DragonLoginSecurity\Crypto::encrypt( \DragonLoginSecurity\Provider_TOTP::generate_secret() ) );
		$this->assertSame( 'ok', $tf->totp_state( 1 ) );
	}

	public function test_an_unreadable_secret_keeps_the_second_factor_required(): void {
		$tf = new Two_Factor();
		$this->assertTrue( $tf->user_has_2fa( 1 ) );
		$this->assertNotContains( 'totp', $tf->available_methods( 1 ) );
		$this->assertSame( 'not-a-ciphertext', get_user_meta( 1, Two_Factor::TOTP_META, true ), 'the stored secret is kept' );
		$this->assertNotContains( '2fa.disabled', $this->event_codes() );
	}

	public function test_the_user_is_told_once(): void {
		$tf = new Two_Factor();
		$tf->user_has_2fa( 1 );
		$tf->available_methods( 1 );
		( new Two_Factor() )->user_has_2fa( 1 );

		$this->assertSame( array( '2fa.totp_unreadable' ), $this->event_codes() );
		$this->assertCount( 1, $GLOBALS['dls_test_mail'] );
		$this->assertSame( 'owner@example.test', $GLOBALS['dls_test_mail'][0][0] );
		$this->assertStringContainsString( 'backup code', $GLOBALS['dls_test_mail'][0][2] );
	}

	public function test_a_failed_email_is_retried_next_time(): void {
		$GLOBALS['dls_test_mail_result'] = false;
		( new Two_Factor() )->user_has_2fa( 1 );
		$GLOBALS['dls_test_mail_result'] = true;
		( new Two_Factor() )->user_has_2fa( 1 );
		( new Two_Factor() )->user_has_2fa( 1 );
		$this->assertCount( 2, $GLOBALS['dls_test_mail'] );
	}

	public function test_a_fresh_enrolment_replaces_the_unreadable_secret(): void {
		( new Two_Factor() )->user_has_2fa( 1 );
		update_user_meta( 1, Two_Factor::TOTP_META, \DragonLoginSecurity\Crypto::encrypt( \DragonLoginSecurity\Provider_TOTP::generate_secret() ) );
		$tf = new Two_Factor();
		$this->assertContains( 'totp', $tf->available_methods( 1 ) );
		// Told again if it ever happens again.
		update_user_meta( 1, Two_Factor::TOTP_META, 'broken-again' );
		( new Two_Factor() )->user_has_2fa( 1 );
		$this->assertCount( 2, $GLOBALS['dls_test_mail'] );
	}
}
