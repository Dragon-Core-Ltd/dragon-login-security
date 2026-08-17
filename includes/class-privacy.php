<?php
/**
 * WordPress privacy-tools integration: policy text, personal-data export
 * and erasure for the data this plugin stores about a user.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Registers suggested privacy-policy text plus a personal-data exporter and
 * eraser. Secrets are never exported — only the fact of enrolment. Erasure
 * removes the user's second-factor material and their lockout history.
 */
class Privacy {

	/**
	 * Register hooks.
	 */
	public function init_hooks(): void {
		add_action( 'admin_init', array( $this, 'add_policy_content' ) );
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_eraser' ) );
	}

	/**
	 * Suggested privacy-policy copy for Settings → Privacy.
	 */
	public function add_policy_content(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		wp_add_privacy_policy_content(
			__( 'Dragon Login Security', 'dragon-login-security' ),
			wp_kses_post(
				'<p>' . __( 'This site uses Dragon Login Security for brute-force protection and two-factor authentication. It stores, in this site&#8217;s own database: each enrolled user&#8217;s authenticator secret (encrypted), backup codes (hashed), and passkey public keys with device labels; and, for brute-force protection, the IP address and attempted username of failed logins. Lockout records are pruned automatically on a retention schedule. No data is sent to any third party.', 'dragon-login-security' ) . '</p>'
			)
		);
	}

	/**
	 * Register the exporter.
	 *
	 * @param array $exporters Registered exporters.
	 * @return array
	 */
	public function register_exporter( array $exporters ): array {
		$exporters['dragon-login-security'] = array(
			'exporter_friendly_name' => __( 'Dragon Login Security', 'dragon-login-security' ),
			'callback'               => array( $this, 'export' ),
		);
		return $exporters;
	}

	/**
	 * Register the eraser.
	 *
	 * @param array $erasers Registered erasers.
	 * @return array
	 */
	public function register_eraser( array $erasers ): array {
		$erasers['dragon-login-security'] = array(
			'eraser_friendly_name' => __( 'Dragon Login Security', 'dragon-login-security' ),
			'callback'             => array( $this, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Export what this plugin knows about a user — enrolment facts and passkey
	 * labels, never secret material.
	 *
	 * @param string $email Email address.
	 * @return array{data: array, done: bool}
	 */
	public function export( string $email ): array {
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		$items = array();

		$has_totp = '' !== (string) get_user_meta( $user->ID, 'dls_totp_secret', true );
		$codes    = (array) get_user_meta( $user->ID, 'dls_backup_codes', true );
		$items[]  = array(
			'name'  => __( 'Authenticator app (TOTP)', 'dragon-login-security' ),
			'value' => $has_totp ? __( 'Enrolled (secret stored encrypted; not exportable)', 'dragon-login-security' ) : __( 'Not enrolled', 'dragon-login-security' ),
		);
		$items[] = array(
			'name'  => __( 'Backup codes remaining', 'dragon-login-security' ),
			'value' => (string) count( array_filter( $codes ) ),
		);

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom credentials table; privacy export runs on demand.
		$passkeys = $wpdb->get_results(
			$wpdb->prepare( 'SELECT label, created_at, last_used_at FROM %i WHERE user_id = %d', Plugin::credentials_table(), $user->ID ),
			ARRAY_A
		);
		foreach ( (array) $passkeys as $row ) {
			$items[] = array(
				'name'  => __( 'Passkey', 'dragon-login-security' ),
				'value' => sprintf(
					/* translators: 1: passkey label, 2: created date, 3: last-used date */
					__( '%1$s (registered %2$s, last used %3$s)', 'dragon-login-security' ),
					'' !== (string) $row['label'] ? (string) $row['label'] : __( 'unnamed device', 'dragon-login-security' ),
					(string) $row['created_at'],
					(string) ( $row['last_used_at'] ?? __( 'never', 'dragon-login-security' ) )
				),
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom lockouts table; privacy export runs on demand.
		$lockouts = (int) $wpdb->get_var(
			$wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE username = %s', Plugin::lockouts_table(), $user->user_login )
		);
		$items[] = array(
			'name'  => __( 'Failed-login records referencing this username', 'dragon-login-security' ),
			'value' => (string) $lockouts,
		);

		return array(
			'data' => array(
				array(
					'group_id'    => 'dragon-login-security',
					'group_label' => __( 'Login security', 'dragon-login-security' ),
					'item_id'     => 'dragon-login-security-' . $user->ID,
					'data'        => $items,
				),
			),
			'done' => true,
		);
	}

	/**
	 * Erase the user's second-factor material and lockout history.
	 *
	 * @param string $email Email address.
	 * @return array{items_removed: bool, items_retained: bool, messages: array, done: bool}
	 */
	public function erase( string $email ): array {
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);
		}

		$removed = false;
		foreach ( array( 'dls_totp_secret', 'dls_totp_last_step', 'dls_backup_codes', 'dls_backup_codes_confirmed' ) as $key ) {
			if ( delete_user_meta( $user->ID, $key ) ) {
				$removed = true;
			}
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom tables; privacy erasure runs on demand.
		$removed = (bool) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE user_id = %d', Plugin::credentials_table(), $user->ID ) ) || $removed;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom tables; privacy erasure runs on demand.
		$removed = (bool) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE username = %s', Plugin::lockouts_table(), $user->user_login ) ) || $removed;

		return array(
			'items_removed'  => $removed,
			'items_retained' => false,
			'messages'       => $removed
				? array( __( 'Two-factor enrolment and lockout history removed. The user can log in with their password and re-enrol.', 'dragon-login-security' ) )
				: array(),
			'done'           => true,
		);
	}
}
