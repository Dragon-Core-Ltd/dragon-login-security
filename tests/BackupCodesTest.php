<?php
/**
 * Tests for backup codes (generation + single-use matching).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Provider_Backup_Codes;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( Provider_Backup_Codes::class )]
class BackupCodesTest extends TestCase {

	public function test_generate_count_and_shape(): void {
		$codes = Provider_Backup_Codes::generate( 8 );
		$this->assertCount( 8, $codes );
		foreach ( $codes as $c ) {
			$this->assertMatchesRegularExpression( '/^[0-9a-f]{5}-[0-9a-f]{5}$/', $c );
		}
		$this->assertCount( 8, array_unique( $codes ) );
	}

	public function test_match_finds_the_code_case_insensitively(): void {
		$plain  = Provider_Backup_Codes::generate( 3 );
		$hashes = array_map( fn( $c ) => password_hash( strtolower( $c ), PASSWORD_DEFAULT ), $plain );

		$key = Provider_Backup_Codes::match( $hashes, strtoupper( $plain[1] ) );
		$this->assertSame( 1, $key );
	}

	public function test_code_is_single_use(): void {
		$plain  = Provider_Backup_Codes::generate( 3 );
		$hashes = array_map( fn( $c ) => password_hash( strtolower( $c ), PASSWORD_DEFAULT ), $plain );

		$key = Provider_Backup_Codes::match( $hashes, $plain[0] );
		$this->assertNotFalse( $key );

		// Consume it, then the same code must no longer match.
		unset( $hashes[ $key ] );
		$this->assertFalse( Provider_Backup_Codes::match( $hashes, $plain[0] ) );
	}

	public function test_wrong_code_does_not_match(): void {
		$plain  = Provider_Backup_Codes::generate( 3 );
		$hashes = array_map( fn( $c ) => password_hash( strtolower( $c ), PASSWORD_DEFAULT ), $plain );
		$this->assertFalse( Provider_Backup_Codes::match( $hashes, 'ffff0-00000' ) );
	}

	/**
	 * Two requests that both read the same code list, as concurrent logins do.
	 */
	public function test_interleaved_consumption_cannot_bring_a_used_code_back(): void {
		$GLOBALS['dls_test_user_meta']      = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;

		$plain  = Provider_Backup_Codes::generate( 2 );
		$this->assertTrue( Provider_Backup_Codes::store( 5, $plain ) );

		// Request A and request B both start from the stored list of two codes.
		// A consumes the first, B consumes the second. Writing the whole list
		// back from a stale read would restore whichever code the other used.
		$this->assertTrue( Provider_Backup_Codes::verify_and_consume( 5, $plain[0] ) );
		$this->assertTrue( Provider_Backup_Codes::verify_and_consume( 5, $plain[1] ) );

		$this->assertSame( 0, Provider_Backup_Codes::remaining( 5 ) );
		$this->assertFalse(
			Provider_Backup_Codes::verify_and_consume( 5, $plain[0] ),
			'A consumed code must not become valid again.'
		);
		$this->assertFalse( Provider_Backup_Codes::verify_and_consume( 5, $plain[1] ) );
	}

	public function test_a_consumption_racing_another_does_not_resurrect_the_other_code(): void {
		$GLOBALS['dls_test_user_meta']        = array();
		$GLOBALS['dls_test_meta_write_fails'] = false;

		$plain = Provider_Backup_Codes::generate( 3 );
		$this->assertTrue( Provider_Backup_Codes::store( 5, $plain ) );

		// Request A reads the list of three. Before A writes, request B runs to
		// completion and consumes code 3. A then writes the list it read, which
		// still contains code 3.
		$GLOBALS['dls_test_after_read'] = static function () use ( $plain ): void {
			Provider_Backup_Codes::verify_and_consume( 5, $plain[2] );
		};

		Provider_Backup_Codes::verify_and_consume( 5, $plain[0] );

		$this->assertFalse(
			Provider_Backup_Codes::verify_and_consume( 5, $plain[2] ),
			'Code 3 was used by the other request and must stay used.'
		);
	}
}
