<?php
/**
 * PHPUnit bootstrap. The classes under test are WP-light; the few core helpers
 * they touch are stubbed here.
 *
 * @package DragonLoginSecurity
 */

defined( 'ABSPATH' ) || define( 'ABSPATH', __DIR__ . '/' );
defined( 'MINUTE_IN_SECONDS' ) || define( 'MINUTE_IN_SECONDS', 60 );
defined( 'HOUR_IN_SECONDS' ) || define( 'HOUR_IN_SECONDS', 3600 );
defined( 'DAY_IN_SECONDS' ) || define( 'DAY_IN_SECONDS', 86400 );

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		unset( $domain );
		return $text;
	}
}

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		unset( $scheme );
		return 'unit-test-static-salt-value-0123456789';
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../includes/class-crypto.php';
require_once __DIR__ . '/../includes/class-ip.php';
require_once __DIR__ . '/../includes/providers/class-provider-totp.php';
require_once __DIR__ . '/../includes/providers/class-provider-backup-codes.php';
require_once __DIR__ . '/../includes/class-limit-login.php';
