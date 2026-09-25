<?php
/**
 * Tests for the single-use, expiring, user-bound 2FA login token.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Login_Token;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Login_Token::class )]
class LoginTokenTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_transients']           = array();
		$GLOBALS['dls_test_after_transient_read'] = null;
	}

	public function test_token_valid_once_then_consumed(): void {
		$t = Login_Token::create( 42 );
		$this->assertTrue( Login_Token::verify( $t, 42 ) );
		$this->assertFalse( Login_Token::verify( $t, 42 ) ); // single use
	}

	public function test_token_rejects_wrong_user(): void {
		$t = Login_Token::create( 42 );
		$this->assertFalse( Login_Token::verify( $t, 99 ) );
	}

	public function test_token_rejects_unknown(): void {
		$this->assertFalse( Login_Token::verify( 'never-issued', 42 ) );
	}

	public function test_token_rejects_expired(): void {
		$t = Login_Token::create( 42, 1 );
		$this->assertFalse( Login_Token::verify( $t, 42, time() + 5 ) );
	}

	public function test_only_one_of_two_parallel_requests_consumes_the_token(): void {
		$t = Login_Token::create( 42 );
		// A second request carrying the same token reads it at the same moment
		// and consumes it first.
		$GLOBALS['dls_test_after_transient_read'] = static function () use ( $t ) {
			\delete_transient( 'dragonloginsecurity_2fa_' . hash( 'sha256', $t ) );
		};
		$this->assertFalse( Login_Token::verify( $t, 42 ), 'the request that lost the delete must be rejected' );
	}
}
