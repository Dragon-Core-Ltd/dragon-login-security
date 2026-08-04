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
}
