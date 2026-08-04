<?php
/**
 * Event registry for the Activity Log bridge.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The login-security event codes exposed to Dragon Activity Log.
 */
class Events {

	/**
	 * code => [label, severity (1 info,2 notice,3 warning,4 critical), object_type].
	 *
	 * @return array<string,array>
	 */
	public static function codes(): array {
		return array(
			'user.login_failed' => array( __( 'Failed login attempt', 'dragon-login-security' ), 3, 'user' ),
			'user.lockout'      => array( __( 'IP locked out (brute force)', 'dragon-login-security' ), 3, 'user' ),
			'2fa.enrolled'      => array( __( 'Two-factor enrolled', 'dragon-login-security' ), 2, 'user' ),
			'2fa.disabled'      => array( __( 'Two-factor disabled', 'dragon-login-security' ), 3, 'user' ),
			'2fa.passed'        => array( __( 'Two-factor passed', 'dragon-login-security' ), 1, 'user' ),
			'2fa.failed'        => array( __( 'Two-factor failed', 'dragon-login-security' ), 3, 'user' ),
			'2fa.skipped'       => array( __( 'Two-factor skipped (trusted device)', 'dragon-login-security' ), 1, 'user' ),
			'passkey.added'     => array( __( 'Passkey added', 'dragon-login-security' ), 2, 'user' ),
			'passkey.removed'   => array( __( 'Passkey removed', 'dragon-login-security' ), 2, 'user' ),
		);
	}
}
