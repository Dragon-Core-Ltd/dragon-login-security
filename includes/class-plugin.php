<?php
/**
 * Main plugin bootstrap: singleton, activation, cron, and wiring.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the free plugin together.
 */
final class Plugin {

	/**
	 * Schema version; bump to trigger dbDelta.
	 */
	const DB_VERSION = '1';

	/**
	 * Singleton.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Get the singleton.
	 *
	 * @return Plugin
	 */
	public static function get_instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor: wire hooks. (Feature units are added as they are built.)
	 */
	private function __construct() {
		self::migrate_legacy_prefix();

		add_action( 'dragonloginsecurity_prune_lockouts', array( $this, 'prune_lockouts' ) );

		( new Limit_Login() )->hook();
		( new Two_Factor() )->hook();
		new Integration();
		( new Privacy() )->init_hooks();
		( new Importer() )->init_hooks();

		if ( is_admin() ) {
			( new Ajax() )->hook();
			( new User_Profile() )->hook();
			( new Admin() )->hook();
		}
	}

	/**
	 * Credentials table name.
	 *
	 * @return string
	 */
	public static function credentials_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dls_credentials';
	}

	/**
	 * Lockouts table name.
	 *
	 * @return string
	 */
	public static function lockouts_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dls_lockouts';
	}

	/**
	 * Activation.
	 */
	public function activate(): void {
		$this->create_tables();
		$this->register_cron();
	}

	/**
	 * Deactivation.
	 */
	public function deactivate(): void {
		wp_clear_scheduled_hook( 'dragonloginsecurity_prune_lockouts' );
	}

	/**
	 * Move options and the prune schedule off the pre-1.0.2 three-letter (dls_)
	 * prefix.
	 *
	 * The prefix was renamed to the namespace-derived `dragonloginsecurity_` to
	 * satisfy the WordPress.org uniqueness rule. Option values are carried across
	 * once and the lockout-prune cron is re-pointed at the renamed hook. The
	 * credentials and lockouts tables and the 2FA user-meta keys keep their
	 * original names (matched by exact name), so no enrolment data is touched.
	 */
	private static function migrate_legacy_prefix(): void {
		foreach ( array( 'db_version', 'settings' ) as $name ) {
			if ( false === get_option( 'dragonloginsecurity_' . $name, false ) ) {
				$legacy = get_option( 'dls_' . $name, null );
				if ( null !== $legacy ) {
					update_option( 'dragonloginsecurity_' . $name, $legacy );
				}
			}
			delete_option( 'dls_' . $name );
		}

		$legacy_cron = wp_next_scheduled( 'dls_prune_lockouts' );
		if ( $legacy_cron ) {
			wp_unschedule_event( $legacy_cron, 'dls_prune_lockouts' );
		}
		if ( ! wp_next_scheduled( 'dragonloginsecurity_prune_lockouts' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dragonloginsecurity_prune_lockouts' );
		}
	}

	/**
	 * Register the daily lockout-prune cron (idempotent).
	 */
	private function register_cron(): void {
		if ( ! wp_next_scheduled( 'dragonloginsecurity_prune_lockouts' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dragonloginsecurity_prune_lockouts' );
		}
	}

	/**
	 * Create or migrate the tables.
	 */
	private function create_tables(): void {
		if ( self::DB_VERSION === get_option( 'dragonloginsecurity_db_version' ) ) {
			return;
		}

		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		$credentials     = self::credentials_table();
		$lockouts        = self::lockouts_table();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$credentials} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				user_id bigint(20) unsigned NOT NULL,
				credential_id varchar(255) NOT NULL,
				public_key text NOT NULL,
				sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
				transports varchar(255) NOT NULL DEFAULT '',
				label varchar(191) NOT NULL DEFAULT '',
				created_at datetime NOT NULL,
				last_used_at datetime NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY credential_id (credential_id),
				KEY user_id (user_id)
			) {$charset_collate};"
		);

		dbDelta(
			"CREATE TABLE {$lockouts} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				ip varchar(45) NOT NULL DEFAULT '',
				username varchar(191) NOT NULL DEFAULT '',
				attempts int unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY ip (ip)
			) {$charset_collate};"
		);

		update_option( 'dragonloginsecurity_db_version', self::DB_VERSION );
	}

	/**
	 * Delete lockout rows past the retention cap, in bounded batches.
	 */
	public function prune_lockouts(): void {
		global $wpdb;

		$days   = 30;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched retention prune of plugin's custom table.
			$deleted = (int) $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE created_at < %s ORDER BY id ASC LIMIT %d',
					self::lockouts_table(),
					$cutoff,
					1000
				)
			);
		} while ( 1000 === $deleted );
	}
}
