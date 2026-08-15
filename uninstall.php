<?php
/**
 * Uninstall: remove tables, options, per-user meta, and cron (all sites).
 *
 * @package DragonLoginSecurity
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Drop this site's tables and options.
 */
function dragonloginsecurity_uninstall_site(): void {
	global $wpdb;

	foreach ( array( 'dls_credentials', 'dls_lockouts' ) as $dragonloginsecurity_suffix ) {
		$dragonloginsecurity_table = $wpdb->prefix . $dragonloginsecurity_suffix;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table teardown on uninstall.
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $dragonloginsecurity_table ) );
	}

	// Current names plus the pre-1.0.2 dls_ names, in case a 1.0.1 install was
	// removed before its 1.0.2 migration ever ran.
	foreach ( array( 'dragonloginsecurity_db_version', 'dragonloginsecurity_settings', 'dls_db_version', 'dls_settings' ) as $dragonloginsecurity_option ) {
		delete_option( $dragonloginsecurity_option );
	}

	wp_clear_scheduled_hook( 'dragonloginsecurity_prune_lockouts' );
	wp_clear_scheduled_hook( 'dls_prune_lockouts' );
}

if ( is_multisite() ) {
	$dragonloginsecurity_sites = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	foreach ( $dragonloginsecurity_sites as $dragonloginsecurity_site_id ) {
		switch_to_blog( (int) $dragonloginsecurity_site_id );
		dragonloginsecurity_uninstall_site();
		restore_current_blog();
	}
} else {
	dragonloginsecurity_uninstall_site();
}

// Per-user 2FA meta is global (one row per user regardless of site).
foreach ( array( 'dls_totp_secret', 'dls_backup_codes', 'dls_2fa_methods', 'dls_backup_codes_confirmed', 'dls_totp_last_step' ) as $dragonloginsecurity_meta ) {
	delete_metadata( 'user', 0, $dragonloginsecurity_meta, '', true );
}
