<?php
/**
 * One-click import of allow/deny IP lists from other login-protection plugins.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Detects Limit Login Attempts (and Reloaded) options and Wordfence's config
 * table, and merges their IP lists into this plugin's allow/deny settings.
 * Only syntactically valid single IPs are imported; ranges and usernames are
 * skipped and reported.
 */
class Importer {

	/**
	 * Register hooks.
	 */
	public function init_hooks(): void {
		add_action( 'admin_post_dragonloginsecurity_import', array( $this, 'handle' ) );
	}

	/**
	 * Sources present on this site.
	 *
	 * @return array<string,string> slug => label.
	 */
	public static function detect(): array {
		$sources = array();

		if ( false !== get_option( 'limit_login_whitelist_ip', false ) || false !== get_option( 'limit_login_blacklist_ip', false ) ) {
			$sources['limit-login'] = __( 'Limit Login Attempts (Reloaded)', 'dragon-login-security' );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time existence check on the import screen.
		$wf = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->prefix . 'wfconfig' ) );
		if ( $wf ) {
			$sources['wordfence'] = __( 'Wordfence', 'dragon-login-security' );
		}

		return $sources;
	}

	/**
	 * Handle the import (admin-post).
	 */
	public function handle(): void {
		check_admin_referer( 'dragonloginsecurity_import' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-login-security' ) );
		}

		$source = isset( $_POST['source'] ) ? sanitize_key( wp_unslash( $_POST['source'] ) ) : '';

		$allow = array();
		$deny  = array();

		if ( 'limit-login' === $source ) {
			$allow = (array) get_option( 'limit_login_whitelist_ip', array() );
			$deny  = (array) get_option( 'limit_login_blacklist_ip', array() );
		} elseif ( 'wordfence' === $source ) {
			global $wpdb;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time read of another plugin's config for import.
			$raw   = (string) $wpdb->get_var(
				$wpdb->prepare( 'SELECT val FROM %i WHERE name = %s', $wpdb->prefix . 'wfconfig', 'whitelisted' )
			);
			$allow = preg_split( '/[\s,]+/', $raw );
			$allow = false === $allow ? array() : $allow;
		} else {
			wp_die( esc_html__( 'Unknown import source.', 'dragon-login-security' ) );
		}

		$result = self::merge_lists( $allow, $deny );

		set_transient(
			'dragonloginsecurity_import_notice',
			sprintf(
				/* translators: 1: allow-list count, 2: deny-list count, 3: skipped count */
				__( 'Import finished: %1$d allow-list and %2$d deny-list addresses added; %3$d entries skipped (ranges or invalid).', 'dragon-login-security' ),
				$result['allow'],
				$result['deny'],
				$result['skipped']
			),
			60
		);

		wp_safe_redirect( admin_url( 'options-general.php?page=dragon-login-security' ) );
		exit;
	}

	/**
	 * Merge candidate lists into the stored settings. Pure apart from the
	 * option read/write — validation logic is separately testable.
	 *
	 * @param array $allow Candidate allow-list entries.
	 * @param array $deny  Candidate deny-list entries.
	 * @return array{allow:int, deny:int, skipped:int}
	 */
	public static function merge_lists( array $allow, array $deny ): array {
		$settings = (array) get_option( 'dragonloginsecurity_settings', array() );
		$current  = array(
			'allow_ips' => (array) ( $settings['allow_ips'] ?? array() ),
			'deny_ips'  => (array) ( $settings['deny_ips'] ?? array() ),
		);

		$skipped = 0;
		$added   = array(
			'allow' => 0,
			'deny'  => 0,
		);

		foreach ( array(
			'allow' => $allow,
			'deny'  => $deny,
		) as $list => $candidates ) {
			$key = 'allow' === $list ? 'allow_ips' : 'deny_ips';
			foreach ( $candidates as $candidate ) {
				$ip = trim( (string) $candidate );
				if ( '' === $ip ) {
					continue;
				}
				if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					++$skipped;
					continue;
				}
				if ( in_array( $ip, $current[ $key ], true ) ) {
					continue;
				}
				$current[ $key ][] = $ip;
				++$added[ $list ];
			}
		}

		$settings['allow_ips'] = $current['allow_ips'];
		$settings['deny_ips']  = $current['deny_ips'];
		update_option( 'dragonloginsecurity_settings', $settings, false );

		return array(
			'allow'   => $added['allow'],
			'deny'    => $added['deny'],
			'skipped' => $skipped,
		);
	}
}
