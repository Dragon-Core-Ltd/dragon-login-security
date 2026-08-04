<?php
/**
 * WP-CLI commands, including the recovery escape hatch.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage login security from the command line.
 */
class CLI {

	/**
	 * Disable all two-factor for a user (recovery when locked out of 2FA).
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User id, login, or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp dragon-login-security disable-2fa admin
	 *
	 * @subcommand disable-2fa
	 *
	 * @param array $args Positional args.
	 */
	public function disable_2fa( $args ): void {
		$user = $this->resolve_user( $args[0] ?? '' );
		if ( ! $user ) {
			\WP_CLI::error( 'User not found.' );
		}
		delete_user_meta( $user->ID, Two_Factor::TOTP_META );
		delete_user_meta( $user->ID, Provider_Backup_Codes::META_KEY );
		delete_user_meta( $user->ID, 'dls_backup_codes_confirmed' );
		Credentials::delete_for_user( $user->ID );
		\WP_CLI::success( sprintf( 'Two-factor disabled for %s. They can now sign in with a password alone.', $user->user_login ) );
	}

	/**
	 * Clear a brute-force lockout for an IP.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to unlock.
	 *
	 * @param array $args Positional args.
	 */
	public function unlock( $args ): void {
		$ip = $args[0] ?? '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\WP_CLI::error( 'Invalid IP address.' );
		}
		( new Limit_Login() )->clear( $ip );
		\WP_CLI::success( sprintf( 'Cleared lockout for %s.', $ip ) );
	}

	/**
	 * Show enrolment and lockout status.
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI status read.
		$totp = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE meta_key = %s', $wpdb->usermeta, Two_Factor::TOTP_META ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI status read.
		$passkeys = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(DISTINCT user_id) FROM %i', Plugin::credentials_table() ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI status read.
		$recent = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s', Plugin::lockouts_table(), gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) ) );

		\WP_CLI\Utils\format_items(
			'table',
			array(
				array(
					'metric' => 'Users with an authenticator app',
					'value'  => $totp,
				),
				array(
					'metric' => 'Users with a passkey',
					'value'  => $passkeys,
				),
				array(
					'metric' => 'Lockouts in the last 24h',
					'value'  => $recent,
				),
			),
			array( 'metric', 'value' )
		);
	}

	/**
	 * Resolve a user by id, login, or email.
	 *
	 * @param string $ref Reference.
	 * @return \WP_User|false
	 */
	private function resolve_user( string $ref ) {
		if ( is_numeric( $ref ) ) {
			return get_user_by( 'id', (int) $ref );
		}
		if ( is_email( $ref ) ) {
			return get_user_by( 'email', $ref );
		}
		return get_user_by( 'login', $ref );
	}
}

\WP_CLI::add_command( 'dragon-login-security', __NAMESPACE__ . '\CLI' );
