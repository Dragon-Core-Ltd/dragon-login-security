<?php
/**
 * Uninstall: remove tables, options, per-user meta, and cron.
 *
 * @package DragonLoginSecurity
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

foreach ( array( 'dls_credentials', 'dls_lockouts' ) as $dragonloginsecurity_suffix ) {
	$dragonloginsecurity_table = $wpdb->prefix . $dragonloginsecurity_suffix;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table teardown on uninstall.
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $dragonloginsecurity_table ) );
}

foreach ( array( 'dls_db_version', 'dls_settings' ) as $dragonloginsecurity_option ) {
	delete_option( $dragonloginsecurity_option );
}

// Per-user 2FA meta (delete for every user in one query each).
foreach ( array( 'dls_totp_secret', 'dls_backup_codes', 'dls_2fa_methods', 'dls_backup_codes_confirmed' ) as $dragonloginsecurity_meta ) {
	delete_metadata( 'user', 0, $dragonloginsecurity_meta, '', true );
}

wp_clear_scheduled_hook( 'dls_prune_lockouts' );
