<?php
/**
 * Scenario hunt: the challenge POST, the login token it depends on, the
 * providers behind it, the incorrect-code lock, and what the request does
 * with redirect_to, rememberme and interim-login.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Crypto;
use DragonLoginSecurity\Limit_Login;
use DragonLoginSecurity\Login_Token;
use DragonLoginSecurity\Provider_Backup_Codes;
use DragonLoginSecurity\Provider_TOTP;
use DragonLoginSecurity\Two_Factor;
use DragonLoginSecurity\WebAuthn;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Two_Factor::class )]
class ScenarioChallengeSubmitTest extends TestCase {

	private const LOGIN  = 'https://example.test/wp-login.php';
	private const LOCKED = 'https://example.test/wp-login.php?dragonloginsecurity_2fa_locked=1';
	private const ADMIN  = 'https://example.test/wp-admin/';

	/**
	 * Base32 secrets by user id.
	 *
	 * @var array<int,string>
	 */
	private array $secrets = array();

	protected function setUp(): void {
		$GLOBALS['wpdb']                      = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta']        = array();
		$GLOBALS['dls_test_transients']       = array();
		$GLOBALS['dls_test_options']          = array();
		$GLOBALS['dls_test_sessions']         = array();
		$GLOBALS['dls_test_actions_fired']    = array();
		$GLOBALS['dls_test_filter_override']  = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_after_read']       = null;
		$GLOBALS['dls_test_mail']             = array();
		$GLOBALS['dls_test_mail_result']      = true;
		$GLOBALS['dls_sent']                  = array();
		$GLOBALS['dls_remember']              = array();
		$owner                                = new \WP_User( 1, 'owner' );
		$owner->user_email                    = 'owner@example.test';
		$editor                               = new \WP_User( 2, 'editor' );
		$editor->user_email                   = 'editor@example.test';
		$GLOBALS['dls_test_users']            = array(
			1 => $owner,
			2 => $editor,
		);
		foreach ( array( 1, 2 ) as $id ) {
			$this->secrets[ $id ] = Provider_TOTP::generate_secret();
			update_user_meta( $id, Two_Factor::TOTP_META, Crypto::encrypt( $this->secrets[ $id ] ) );
		}
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$_POST                  = array();
		$_GET                   = array();
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_meta_write_fails'] = false;
		$GLOBALS['dls_test_filter_override']  = array();
		WebAuthn::$available_override         = null;
		$_POST                                = array();
		$_GET                                 = array();
	}

	/**
	 * The login-screen stand-ins a submit needs. wp_safe_redirect() validates
	 * as core's wp_validate_redirect() does (scheme, host-less URLs with a
	 * scheme, protocol-relative, foreign hosts all fall back to admin_url());
	 * wp_redirect() is the UNSAFE one and must never see a user-supplied
	 * target on this path.
	 */
	private static function load_stubs(): void {
		// Per-process WordPress stubs, the convention this suite uses for the login screen.
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval(
			'class DLS_Scn_Redirect extends \Exception {}
			class DLS_Scn_Unsafe extends \Exception {}
			class DLS_Scn_Rendered extends \Exception {}
			function dls_scn_validate( $location, $fallback ) {
				$location = trim( (string) $location );
				if ( "" === $location ) { return $fallback; }
				if ( "//" === substr( $location, 0, 2 ) ) { $location = "http:" . $location; }
				$cut  = strpos( $location, "?" );
				$test = $cut ? substr( $location, 0, $cut ) : $location;
				$lp   = parse_url( $test );
				if ( false === $lp ) { return $fallback; }
				if ( isset( $lp["scheme"] ) && ! in_array( $lp["scheme"], array( "http", "https" ), true ) ) { return $fallback; }
				if ( ! isset( $lp["host"] ) && ( isset( $lp["scheme"] ) || isset( $lp["user"] ) || isset( $lp["pass"] ) || isset( $lp["port"] ) ) ) { return $fallback; }
				if ( isset( $lp["host"] ) && "example.test" !== strtolower( $lp["host"] ) ) { return $fallback; }
				return $location;
			}
			function wp_safe_redirect( $l ) { throw new DLS_Scn_Redirect( dls_scn_validate( $l, admin_url() ) ); }
			function wp_redirect( $l ) { throw new DLS_Scn_Unsafe( $l ); }
			function wp_login_url( $r = "" ) { return "https://example.test/wp-login.php"; }
			function wp_set_auth_cookie( $id, $remember = false, $secure = "", $token = "" ) {
				$t = \WP_Session_Tokens::get_instance( $id )->create( time() + 3600 );
				$GLOBALS["dls_remember"][] = (bool) $remember;
				$GLOBALS["dls_sent"][]     = $GLOBALS["dls_tf"]->filter_send_auth_cookies( true, 0, time() + 3600, $id, "auth", $t );
			}
			function wp_clear_auth_cookie() { $GLOBALS["dls_cleared"] = true; }
			function absint( $v ) { return abs( (int) $v ); }
			function sanitize_key( $k ) { return is_scalar( $k ) ? preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $k ) ) : ""; }
			function nocache_headers() {}
			function login_header( $title = "", $message = "", $errors = null ) { $GLOBALS["dls_header"] = array( $title, $message ); }
			function login_footer( ...$a ) { throw new DLS_Scn_Rendered( "shown" ); }
			function esc_url( $u ) { return (string) $u; }
			function esc_attr( $t ) { return htmlspecialchars( (string) $t, ENT_QUOTES ); }
			function esc_html_e( $t, $d = "" ) { echo htmlspecialchars( (string) $t, ENT_QUOTES ); }'
		);
		defined( 'DRAGONLOGINSECURITY_PLUGIN_DIR' ) || define( 'DRAGONLOGINSECURITY_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
	}

	/**
	 * POST the challenge form.
	 *
	 * @param array $fields Form fields (a missing token gets a fresh one for user 1).
	 * @return string Where the request went: a redirect target, 'RENDERED' when the
	 *                challenge was shown again, or 'UNSAFE:<target>' for wp_redirect().
	 */
	private function submit( array $fields ): string {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_POST                     = $fields + array(
			'dragonloginsecurity_token'  => Login_Token::create( 1 ),
			'dragonloginsecurity_user'   => '1',
			'dragonloginsecurity_method' => 'totp',
			'redirect_to'                => self::ADMIN,
		);
		// The nonce the challenge form shown to that user carries.
		$_POST += array( Two_Factor::NONCE_FIELD => wp_create_nonce( Two_Factor::nonce_action( absint( $_POST['dragonloginsecurity_user'] ) ) ) );
		$level                     = ob_get_level();
		ob_start();
		try {
			$GLOBALS['dls_tf']->handle_submit();
		} catch ( \DLS_Scn_Redirect $r ) {
			return $r->getMessage();
		} catch ( \DLS_Scn_Unsafe $r ) {
			return 'UNSAFE:' . $r->getMessage();
		} catch ( \DLS_Scn_Rendered $r ) {
			return 'RENDERED';
		} finally {
			while ( ob_get_level() > $level ) {
				ob_end_clean();
			}
		}
		return 'RETURNED';
	}

	/**
	 * A code that is not the user's current one.
	 *
	 * @param int $user_id User.
	 * @return string
	 */
	private function wrong( int $user_id ): string {
		return '000000' === Provider_TOTP::code_at( $this->secrets[ $user_id ], time() ) ? '111111' : '000000';
	}

	/**
	 * The user's current code.
	 *
	 * @param int $user_id User.
	 * @param int $offset  Seconds from now.
	 * @return string
	 */
	private function right( int $user_id, int $offset = 0 ): string {
		return Provider_TOTP::code_at( $this->secrets[ $user_id ], time() + $offset );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_token_bound_to_one_user_cannot_complete_another_users_sign_in(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$token             = Login_Token::create( 1 );

		// User 1's token, user 2's id, and user 2's correct code.
		foreach ( array( '2', '2abc', ' 2' ) as $user_field ) {
			$to = $this->submit(
				array(
					'dragonloginsecurity_token' => $token,
					'dragonloginsecurity_user'  => $user_field,
					'dragonloginsecurity_code'  => $this->right( 2 ),
				)
			);
			$this->assertSame( self::LOGIN, $to );
		}
		$this->assertSame( array(), $GLOBALS['dls_sent'], 'a cookie was issued' );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 2 )->get_all() );
		// No attempt was counted against either account, and the token is left
		// for its real holder.
		$this->assertArrayNotHasKey( Two_Factor::CODE_FAILURES_META, $GLOBALS['dls_test_user_meta'][1] );
		$this->assertArrayNotHasKey( Two_Factor::CODE_FAILURES_META, $GLOBALS['dls_test_user_meta'][2] ?? array() );
		$this->assertTrue( Login_Token::verify( $token, 1 ) );

		// Nonexistent and zero users.
		foreach ( array( '0', '99', '', 'abc' ) as $user_field ) {
			$this->assertSame( self::LOGIN, $this->submit( array( 'dragonloginsecurity_user' => $user_field, 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		}
		$this->assertSame( array(), $GLOBALS['dls_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_token_is_spent_by_its_first_use_whatever_the_outcome(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();

		// Spent by a wrong code: the re-rendered form carries a new one.
		$token = Login_Token::create( 1 );
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->wrong( 1 ) ) ) );
		$this->assertSame( self::LOGIN, $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		$this->assertSame( array(), $GLOBALS['dls_sent'] );

		// Spent by a right code: replaying it with the next window's code fails.
		$token = Login_Token::create( 1 );
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		$this->assertSame( self::LOGIN, $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->right( 1, 30 ) ) ) );
		$this->assertSame( array( true ), $GLOBALS['dls_sent'] );

		// Expired, malformed and unknown tokens.
		$expired = Login_Token::create( 1, 1 );
		$GLOBALS['dls_test_transients'][ 'dragonloginsecurity_2fa_' . hash( 'sha256', $expired ) ]['exp'] = time() - 1;
		foreach ( array( $expired, '', 'junk', str_repeat( '0', 64 ), "\0" ) as $bad ) {
			$this->assertSame( self::LOGIN, $this->submit( array( 'dragonloginsecurity_token' => $bad, 'dragonloginsecurity_code' => $this->right( 1, 30 ) ) ) );
		}
		$this->assertSame( array( true ), $GLOBALS['dls_sent'] );
	}

	/**
	 * Core's esc_url() calls ltrim() on its argument, which throws a TypeError
	 * for an array on PHP 8, so `redirect_to[]=x` in the challenge POST (or in
	 * the handoff GET) is a fatal before the token is even checked.
	 * requested_redirect() already guards with is_string(); the two other
	 * readers do not.
	 */
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_an_array_redirect_to_is_ignored_not_fatal(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		// The stub esc_url_raw() casts to string, which is a PHP warning for an
		// array; core throws a TypeError. Either way the array must not reach it.
		set_error_handler(
			static function ( $no, $str ) {
				throw new \ErrorException( $str );
			}
		);
		try {
			$to = $this->submit(
				array(
					'redirect_to'              => array( 'https://example.test/' ),
					'dragonloginsecurity_code' => $this->right( 1 ),
				)
			);
			$this->assertSame( self::ADMIN, $to );
			$this->assertSame( array( true ), $GLOBALS['dls_sent'] );

			$_SERVER['REQUEST_METHOD'] = 'GET';
			$_GET                      = array(
				'dragonloginsecurity_token' => Login_Token::create( 1 ),
				'redirect_to'               => array( 'x' ),
			);
			ob_start();
			try {
				$GLOBALS['dls_tf']->resume_challenge();
				$this->fail( 'the challenge was not rendered' );
			} catch ( \DLS_Scn_Rendered $r ) {
				$this->assertStringContainsString( 'name="redirect_to" value="' . self::ADMIN . '"', (string) ob_get_clean() );
			}
		} catch ( \ErrorException $e ) {
			$this->fail( 'an array redirect_to reached esc_url_raw() (core: TypeError from ltrim()): ' . $e->getMessage() );
		} finally {
			restore_error_handler();
		}
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_redirect_to_only_ever_leaves_through_wp_safe_redirect(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$cases             = array(
			'//evil.test/'                        => self::ADMIN,
			'https:evil.test'                     => self::ADMIN,
			'javascript:alert(1)'                 => self::ADMIN,
			'https://evil.test/wp-admin/'         => self::ADMIN,
			'https://example.test.evil.test/'     => self::ADMIN,
			''                                    => self::ADMIN,
			'https://example.test/shop/?a=1&b=2'  => 'https://example.test/shop/?a=1&b=2',
			'/wp-admin/edit.php'                  => '/wp-admin/edit.php',
		);
		foreach ( $cases as $requested => $expected ) {
			// Each pass consumes the current step; forget it so the next pass can
			// reuse the current code (the window is only one step either side).
			delete_user_meta( 1, Provider_TOTP::LAST_STEP_META );
			$to = $this->submit(
				array(
					'redirect_to'              => $requested,
					'dragonloginsecurity_code' => $this->right( 1 ),
				)
			);
			$this->assertStringStartsNotWith( 'UNSAFE:', $to, $requested );
			$this->assertSame( $expected, $to, $requested );
		}
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_totp_code_shapes_and_replay_at_the_form(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$code              = $this->right( 1 );

		// Spaces and a dash between groups are typing, not the code.
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => substr( $code, 0, 3 ) . ' ' . substr( $code, 3 ) ) ) );
		// The same code again inside its window is a replay.
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $code ) ) );
		// The older adjacent window is not newer than the one just used.
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1, -30 ) ) ) );
		// The newer adjacent window is accepted once.
		$next = $this->right( 1, 30 );
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => $next . '-' ) ) );
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $next ) ) );
		// Seven digits, full-width digits, and a code padded to seven with a
		// leading zero are not the code.
		$far = $this->right( 1, 60 );
		foreach ( array( $far . '1', '0' . $far, str_replace( range( '0', '9' ), array( '０', '１', '２', '３', '４', '５', '６', '７', '８', '９' ), $far ) ) as $bad ) {
			$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $bad ) ), $bad );
		}
		$this->assertSame( array( true, true ), $GLOBALS['dls_sent'] );
		// Every miss was counted and every pass reset the count: 4 misses since
		// the last pass.
		$this->assertSame( 4, $GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ]['count'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_backup_codes_at_the_form(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$first             = Provider_Backup_Codes::generate( 2 );
		$this->assertTrue( Provider_Backup_Codes::store( 1, $first ) );

		$backup = static function ( string $code ): array {
			return array(
				'dragonloginsecurity_method' => 'backup',
				'dragonloginsecurity_code'   => $code,
			);
		};

		// A backup code entered on the authenticator field is not an authenticator code.
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $first[0] ) ) );
		// Upper case and surrounding spaces are accepted; the code is then gone.
		$this->assertSame( self::ADMIN, $this->submit( $backup( '  ' . strtoupper( $first[0] ) . ' ' ) ) );
		$this->assertSame( 'RENDERED', $this->submit( $backup( $first[0] ) ) );
		// A code from a previous set is void once a new set is generated.
		$second = Provider_Backup_Codes::generate( 1 );
		$this->assertTrue( Provider_Backup_Codes::store( 1, $second ) );
		$this->assertSame( 'RENDERED', $this->submit( $backup( $first[1] ) ) );
		// The last code works and leaves no backup method behind.
		$this->assertSame( self::ADMIN, $this->submit( $backup( $second[0] ) ) );
		$this->assertSame( 0, Provider_Backup_Codes::remaining( 1 ) );
		$this->assertNotContains( 'backup', $GLOBALS['dls_tf']->available_methods( 1 ) );
		$this->assertSame( 'RENDERED', $this->submit( $backup( $second[0] ) ) );
		$this->assertSame( array( true, true ), $GLOBALS['dls_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_correct_code_after_four_misses_resets_the_count_and_a_locked_account_gets_no_email_without_an_address(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();

		for ( $i = 1; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->wrong( 1 ) ) ) );
		}
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		$this->assertArrayNotHasKey( Two_Factor::CODE_FAILURES_META, $GLOBALS['dls_test_user_meta'][1] );

		// Now a user without an email address: the lock still trips and closes
		// the step, nothing is mailed, nothing warns.
		$GLOBALS['dls_test_users'][1]->user_email = '';
		for ( $i = 1; $i < Two_Factor::CODE_FAILURE_LIMIT; $i++ ) {
			$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->wrong( 1 ) ) ) );
		}
		$this->assertSame( self::LOCKED, $this->submit( array( 'dragonloginsecurity_code' => $this->wrong( 1 ) ) ) );
		$this->assertSame( self::LOCKED, $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1, 30 ) ) ) );
		$this->assertSame( array(), $GLOBALS['dls_test_mail'] );
		$this->assertSame( array( true ), $GLOBALS['dls_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_wrong_codes_across_the_window_boundary_start_a_new_count(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$tf                = $GLOBALS['dls_tf'];
		$since             = time() - Two_Factor::CODE_FAILURE_WINDOW - 1;
		// Four misses recorded just over a window ago.
		$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = array(
			'count' => Two_Factor::CODE_FAILURE_LIMIT - 1,
			'since' => $since,
		);
		$this->assertFalse( $tf->code_locked( 1 ) );
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->wrong( 1 ) ) ) );
		$record = $GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ];
		$this->assertSame( 1, $record['count'] );
		$this->assertGreaterThan( $since, $record['since'] );
		// The lock message needs the flag and a WP_Error that can carry it.
		$errors = new class() extends \WP_Error {
			public function add( $code, $message, $data = '' ) {
				unset( $data );
				$this->errors[ $code ][] = $message;
			}
		};
		$this->assertFalse( $tf->code_lock_message( $errors )->has_errors() );
		$_GET['dragonloginsecurity_2fa_locked'] = '1';
		$this->assertSame( 'dragonloginsecurity_2fa_locked', $tf->code_lock_message( $errors )->get_error_code() );
		$this->assertSame( 'plain', $tf->code_lock_message( 'plain' ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_remember_me_and_interim_login_are_carried_through(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();

		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1 ), 'rememberme' => 'forever' ) ) );
		$this->assertSame( self::ADMIN, $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1, 30 ), 'rememberme' => '' ) ) );
		$this->assertSame( array( true, false ), $GLOBALS['dls_remember'] );

		// The session-expiry popup: a wrong code re-renders in popup mode, a
		// right one shows the self-closing success screen instead of redirecting.
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->wrong( 1 ), 'interim-login' => '1' ) ) );
		$this->assertTrue( $GLOBALS['interim_login'] );
		delete_user_meta( 1, Provider_TOTP::LAST_STEP_META ); // Two steps were used above; the window is one step either side.
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_code' => $this->right( 1 ), 'interim-login' => '1' ) ) );
		$this->assertSame( 'success', $GLOBALS['interim_login'] );
		$this->assertStringContainsString( 'logged in successfully', $GLOBALS['dls_header'][1] );
		$this->assertSame( array( true, true, true ), $GLOBALS['dls_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_an_address_lockout_closes_the_second_step_without_spending_an_attempt(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		set_transient( 'dragonloginsecurity_lock_' . md5( Limit_Login::bucket( '203.0.113.9' ) ), 1, 600 );
		$token = Login_Token::create( 1 );
		$this->assertSame( self::LOGIN, $this->submit( array( 'dragonloginsecurity_token' => $token, 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		$this->assertSame( array(), $GLOBALS['dls_sent'] );
		$this->assertArrayNotHasKey( Two_Factor::CODE_FAILURES_META, $GLOBALS['dls_test_user_meta'][1] );
		// The token was consumed by the refused attempt.
		$this->assertFalse( Login_Token::verify( $token, 1 ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_passkey_method_without_the_library_or_a_passkey_fails_like_a_wrong_code(): void {
		self::load_stubs();
		WebAuthn::$available_override = false;
		$GLOBALS['dls_tf']            = new Two_Factor();
		$fields                       = array(
			'dragonloginsecurity_method'    => 'passkey',
			'dragonloginsecurity_wa_token'  => 'x',
			'dragonloginsecurity_wa_id'     => 'x',
			'dragonloginsecurity_wa_client' => 'x',
			'dragonloginsecurity_wa_auth'   => 'x',
			'dragonloginsecurity_wa_sig'    => 'x',
		);
		$this->assertSame( 'RENDERED', $this->submit( $fields ) );
		WebAuthn::$available_override = true;
		$this->assertSame( 'RENDERED', $this->submit( $fields ) );
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_method' => 'PASSKEY' ) ) );
		$this->assertSame( 'RENDERED', $this->submit( array( 'dragonloginsecurity_method' => array( 'totp' ), 'dragonloginsecurity_code' => $this->right( 1 ) ) ) );
		$this->assertSame( 4, $GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ]['count'] );
		$this->assertSame( array(), $GLOBALS['dls_sent'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_locked_account_is_turned_away_at_the_password_step_with_nothing_issued(): void {
		self::load_stubs();
		$GLOBALS['dls_tf'] = new Two_Factor();
		$tf                = $GLOBALS['dls_tf'];
		$GLOBALS['dls_test_user_meta'][1][ Two_Factor::CODE_FAILURES_META ] = array(
			'count' => Two_Factor::CODE_FAILURE_LIMIT,
			'since' => time(),
		);
		// The password step as wp_signon() runs it.
		$tf->note_signon();
		$tf->hold_cookies_for_challenge( get_userdata( 1 ) );
		$token = \WP_Session_Tokens::get_instance( 1 )->create( time() + 3600 );
		$tf->record_session_token( 'c', 0, 0, 1, 'auth', $token );
		$this->assertFalse( $tf->filter_send_auth_cookies( true, 0, 0, 1, 'auth', $token ) );
		try {
			$tf->maybe_challenge( 'owner', get_userdata( 1 ) );
			$this->fail( 'no redirect' );
		} catch ( \DLS_Scn_Redirect $r ) {
			$this->assertSame( self::LOCKED, $r->getMessage() );
		}
		$this->assertTrue( $GLOBALS['dls_cleared'] );
		$this->assertSame( array(), \WP_Session_Tokens::get_instance( 1 )->get_all() );
		$this->assertSame( array(), preg_grep( '/^dragonloginsecurity_2fa_/', array_keys( $GLOBALS['dls_test_transients'] ) ), 'a login token was issued to a locked account' );
		$this->assertSame( array(), $GLOBALS['dls_test_mail'], 'the lock email is sent when the lock trips, not on every turned-away sign-in' );
	}
}
