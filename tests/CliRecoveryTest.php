<?php
/**
 * The WP-CLI recovery command leaves the account able to sign in.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\CLI;
use DragonLoginSecurity\Two_Factor;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/class-cli.php';

class CliRecoveryTest extends TestCase {

	public function test_disable_2fa_also_lifts_the_incorrect_code_lock(): void {
		$GLOBALS['wpdb']               = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_user_meta'] = array();
		$GLOBALS['dls_test_users']     = array( 1 => new \WP_User( 1, 'owner' ) );
		update_user_meta( 1, Two_Factor::TOTP_META, 'x' );
		update_user_meta(
			1,
			Two_Factor::CODE_FAILURES_META,
			array(
				'count' => 5,
				'since' => time(),
			)
		);

		( new CLI() )->disable_2fa( array( 'owner' ) );

		$this->assertSame( '', get_user_meta( 1, Two_Factor::TOTP_META, true ) );
		$this->assertFalse( ( new Two_Factor() )->code_locked( 1 ) );
		$this->assertSame( '', get_user_meta( 1, Two_Factor::CODE_FAILURES_META, true ) );
	}
}
