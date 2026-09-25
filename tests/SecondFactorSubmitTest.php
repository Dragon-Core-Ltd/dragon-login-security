<?php
/**
 * The second-factor step: completion issues the cookie, fires wp_login and
 * applies login_redirect; incorrect codes are capped per account.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Login_Token;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class SecondFactorSubmitTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']                     = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']       = array();
		$GLOBALS['dls_test_transients']      = array();
		$GLOBALS['dls_test_options']         = array();
		$GLOBALS['dls_test_actions_fired']   = array();
		$GLOBALS['dls_test_filter_override'] = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_after_read']       = null;
		$GLOBALS['dls_test_mail']             = array();
		$GLOBALS['dls_test_mail_result']      = true;
		$GLOBALS['dls_test_users']           = array( 1 => new \WP_User( 1, 'owner' ) );
		$GLOBALS['dls_test_users'][1]->user_email = 'owner@example.test';
		$_SERVER['REMOTE_ADDR']              = '203.0.113.9';
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_filter_override']  = array();
	}

	public function test_code_lock_after_the_limit_within_the_window(): void {
		$tf  = new Two_Factor();
		$now = 1000000;
		for ( $i = 1; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->assertTrue( $tf->record_code_failure( 1, $now + $i ) );
			$this->assertFalse( $tf->code_locked( 1, $now + $i ) );
		}
		$this->assertTrue( $tf->record_code_failure( 1, $now + 10 ) );
		$this->assertTrue( $tf->code_locked( 1, $now + 10 ) );
		// The window runs from the first miss.
		$this->assertFalse( $tf->code_locked( 1, $now + 1 + Two_Factor::CODE_FAILURE_WINDOW ) );
		$this->assertTrue( $tf->record_code_failure( 1, $now + Two_Factor::CODE_FAILURE_WINDOW + 1 ) );
		$this->assertFalse( $tf->code_locked( 1, $now + Two_Factor::CODE_FAILURE_WINDOW + 1 ) );
	}

	public function test_code_lock_fails_closed(): void {
		$tf                                   = new Two_Factor();
		$GLOBALS['dls_test_meta_write_fails'] = true;
		$this->assertFalse( $tf->record_code_failure( 1 ), 'an unstored miss must count as a lock' );
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = 'garbage';
		$this->assertTrue( $tf->code_locked( 1 ) );
		$this->assertFalse( $tf->code_locked( 2 ) );
	}

	public function test_a_parallel_failure_is_not_lost(): void {
		$tf  = new Two_Factor();
		$now = 1000000;
		$this->assertTrue( $tf->record_code_failure( 1, $now ) );
		// Another request stores its own failure between this request's read
		// and write.
		$GLOBALS['dls_test_after_read'] = static function () use ( $now ) {
			$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = array(
				'count' => 2,
				'since' => $now,
			);
		};
		$this->assertTrue( $tf->record_code_failure( 1, $now + 1 ) );
		$this->assertSame( 3, $GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ]['count'] );
		$this->assertContains( array( 1, 'user_meta' ), $GLOBALS['dls_test_cache_deletes'], 'the retry must bypass the stale meta cache' );
	}

	public function test_attempts_are_numbered_and_refused_past_the_limit(): void {
		$tf  = new Two_Factor();
		$now = 1000000;
		for ( $i = 1; $i <= Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->assertSame( $i, $tf->reserve_code_attempt( 1, $now ) );
		}
		$this->assertSame( Two_Factor::CODE_FAILURE_LIMIT + 1, $tf->reserve_code_attempt( 1, $now ) );
		$this->assertSame( Two_Factor::CODE_FAILURE_LIMIT, $GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ]['count'], 'a refused attempt is not stored' );
		$this->assertSame( 1, $tf->reserve_code_attempt( 1, $now + Two_Factor::CODE_FAILURE_WINDOW ) );
	}

	public function test_a_password_reset_lifts_the_code_lock(): void {
		$tf = new Two_Factor();
		for ( $i = 0; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$tf->record_code_failure( 1 );
		}
		$this->assertTrue( $tf->code_locked( 1 ) );
		$tf->on_password_reset( $GLOBALS['dls_test_users'][1] );
		$this->assertFalse( $tf->code_locked( 1 ) );
	}

	public function test_the_lock_email_is_sent_once_per_interval_and_retried_after_a_failed_send(): void {
		$tf   = new Two_Factor();
		$user = $GLOBALS['dls_test_users'][1];
		$now  = 1000000;

		$GLOBALS['dls_test_mail_result'] = false;
		$this->assertFalse( $tf->notify_code_lock( $user, $now ) );
		$this->assertArrayNotHasKey( Two_Factor::CODE_LOCK_MAILED_META, $GLOBALS['dls_test_user_meta'][1] ?? array() );

		$GLOBALS['dls_test_mail_result'] = true;
		$GLOBALS['dls_test_mail']        = array();
		$this->assertTrue( $tf->notify_code_lock( $user, $now + 1 ) );
		$this->assertCount( 1, $GLOBALS['dls_test_mail'] );
		$this->assertSame( 'owner@example.test', $GLOBALS['dls_test_mail'][0][0] );
		$this->assertStringContainsString( '[Example & Co]', $GLOBALS['dls_test_mail'][0][1] );
		$this->assertStringContainsString( 'action=lostpassword', $GLOBALS['dls_test_mail'][0][2] );

		$this->assertFalse( $tf->notify_code_lock( $user, $now + 60 ) );
		$this->assertTrue( $tf->notify_code_lock( $user, $now + 1 + Two_Factor::CODE_LOCK_MAIL_INTERVAL ) );
		$this->assertCount( 2, $GLOBALS['dls_test_mail'] );
	}

	/**
	 * Load the redirect/cookie stand-ins a submit needs.
	 */
	private static function load_submit_stubs(): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval( 'class DLS_Test_Redirect extends \Exception {} class DLS_Test_Rendered extends \Exception {} function wp_safe_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_redirect( $l ) { throw new DLS_Test_Redirect( $l ); } function wp_login_url() { return "https://example.test/wp-login.php"; } function wp_set_auth_cookie( $id, $remember = false ) { $t = \WP_Session_Tokens::get_instance( $id )->create( time() + 3600 ); $GLOBALS["dls_sent"][] = $GLOBALS["dls_tf"]->filter_send_auth_cookies( true, 0, time() + 3600, $id, "auth", $t ); } function absint( $v ) { return abs( (int) $v ); } function sanitize_key( $k ) { return preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $k ) ); } function login_header( ...$a ) {} function login_footer( ...$a ) { throw new DLS_Test_Rendered( "shown" ); } function esc_url( $u ) { return (string) $u; } function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); } function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }' );
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
	}

	/**
	 * Post a code for user 1.
	 *
	 * @param string $code Code.
	 * @return string Where the request was redirected ('' when the challenge was re-rendered).
	 */
	private function submit( string $code ): string {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_POST                     = array(
			'dragonloginsecurity_token'  => Login_Token::create( 1 ),
			'dragonloginsecurity_user'   => '1',
			'dragonloginsecurity_method' => 'totp',
			'dragonloginsecurity_code'   => $code,
			'redirect_to'                => 'https://example.test/wp-admin/',
		);
		$level = ob_get_level();
		ob_start();
		try {
			$GLOBALS['dls_tf']->handle_submit();
		} catch ( \DLS_Test_Redirect $r ) {
			return $r->getMessage();
		} catch ( \DLS_Test_Rendered $r ) {
			return '';
		} finally {
			while ( ob_get_level() > $level ) {
				ob_end_clean();
			}
		}
		return '';
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_completion_sends_the_cookie_fires_wp_login_and_applies_login_redirect(): void {
		self::load_submit_stubs();
		$secret = Provider_TOTP::generate_secret();
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( $secret ) );
		$GLOBALS['dls_test_filter_override']['login_redirect'] = static function ( $to, $requested, $user ) {
			return $user instanceof \WP_User ? 'https://example.test/welcome/' : $to;
		};
		$GLOBALS['dls_tf'] = new Two_Factor();
		$to                = $this->submit( Provider_TOTP::code_at( $secret, time() ) );

		$this->assertSame( 'https://example.test/welcome/', $to );
		$this->assertSame( array( true ), $GLOBALS['dls_sent'] );
		$logins = array_values(
			array_filter(
				$GLOBALS['dls_test_actions_fired'],
				static function ( $a ) {
					return 'wp_login' === $a[0];
				}
			)
		);
		$this->assertCount( 1, $logins );
		$this->assertSame( 'owner', $logins[0][1][0] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_incorrect_codes_end_the_sign_in_and_lock_even_a_correct_code(): void {
		self::load_submit_stubs();
		$secret = Provider_TOTP::generate_secret();
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( $secret ) );
		$GLOBALS['dls_tf'] = new Two_Factor();
		$locked            = 'https://example.test/wp-login.php?dragonloginsecurity_2fa_locked=1';

		for ( $i = 1; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->assertSame( '', $this->submit( '000000' === Provider_TOTP::code_at( $secret, time() ) ? '111111' : '000000' ) );
		}
		$this->assertSame( $locked, $this->submit( '000000' === Provider_TOTP::code_at( $secret, time() ) ? '111111' : '000000' ) );
		// From a new address, and with the right code, the step stays closed.
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		$this->assertSame( $locked, $this->submit( Provider_TOTP::code_at( $secret, time() ) ) );
		$this->assertArrayNotHasKey( 'dls_sent', $GLOBALS );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_parallel_request_cannot_test_a_code_past_the_limit(): void {
		self::load_submit_stubs();
		$secret = Provider_TOTP::generate_secret();
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( $secret ) );
		$GLOBALS['dls_tf'] = new Two_Factor();
		$since             = time();
		$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = array(
			'count' => Two_Factor::CODE_FAILURE_LIMIT - 1,
			'since' => $since,
		);
		// A parallel request takes the last attempt right after this one reads
		// the count.
		$GLOBALS['dls_test_after_read'] = static function () use ( $since ) {
			$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = array(
				'count' => Two_Factor::CODE_FAILURE_LIMIT,
				'since' => $since,
			);
		};

		$to = $this->submit( Provider_TOTP::code_at( $secret, time() ) );

		$this->assertSame( 'https://example.test/wp-login.php?dragonloginsecurity_2fa_locked=1', $to );
		$this->assertArrayNotHasKey( 'dls_sent', $GLOBALS );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_user_is_emailed_once_when_the_lock_trips(): void {
		self::load_submit_stubs();
		$secret = Provider_TOTP::generate_secret();
		update_user_meta( 1, Two_Factor::TOTP_META, Crypto::encrypt( $secret ) );
		$GLOBALS['dls_tf'] = new Two_Factor();
		$wrong             = '000000' === Provider_TOTP::code_at( $secret, time() ) ? '111111' : '000000';

		for ( $i = 1; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->submit( $wrong );
		}
		$this->assertSame( array(), $GLOBALS['dls_test_mail'] );
		$this->submit( $wrong );
		$this->assertCount( 1, $GLOBALS['dls_test_mail'] );
		// Further refused attempts while locked send nothing more.
		$this->submit( $wrong );
		$this->assertCount( 1, $GLOBALS['dls_test_mail'] );
	}
}
