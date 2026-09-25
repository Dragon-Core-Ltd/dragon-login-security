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
	 * Transient that throttles table-creation retries after a failure.
	 */
	const SCHEMA_RETRY_TRANSIENT = 'dragonloginsecurity_schema_retry';

	/**
	 * Marks the stamped schema as confirmed against the real tables, so the
	 * confirmation costs one query rather than one per request.
	 */
	const SCHEMA_VERIFIED_TRANSIENT = 'dragonloginsecurity_schema_verified';

	/**
	 * Option recording the last failed table creation (missing tables + time).
	 */
	const SCHEMA_FAILURE_OPTION = 'dragonloginsecurity_schema_failure';

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
		add_action( 'init', array( __CLASS__, 'ensure_scheduled' ) );

		add_action( 'dragonloginsecurity_prune_lockouts', array( $this, 'prune_lockouts' ) );

		// When a site is deleted on a network, drop its credential/lockout tables
		// with it. Otherwise the orphaned credentials table lingers and a passkey
		// on the removed site would keep counting as network enrolment forever.
		add_filter( 'wpmu_drop_tables', array( $this, 'drop_site_tables' ) );

		( new Limit_Login() )->hook();
		( new Two_Factor() )->hook();
		new Integration();
		( new Privacy() )->init_hooks();
		( new Importer() )->init_hooks();

		if ( is_admin() ) {
			// A table lost after install (a dropped table, a restore from a partial
			// backup, or an install stamped over a failed creation) used to stay
			// missing until the plugin was deactivated and reactivated, which for a
			// brute-force plugin means lockouts silently stop being recorded.
			add_action( 'admin_init', array( $this, 'maybe_repair_schema' ) );

			( new Ajax() )->hook();
			( new User_Profile() )->hook();
			( new Admin() )->hook();
		}
		( new Pro_Pointer() )->init_hooks();
	}

	/**
	 * Add this plugin's per-site tables to the list core drops when a network
	 * site is deleted. During this filter $wpdb is switched to the site being
	 * removed, so the table helpers name that site's tables.
	 *
	 * @param string[] $tables Tables core will drop for the site.
	 * @return string[]
	 */
	public function drop_site_tables( $tables ): array {
		$tables   = is_array( $tables ) ? $tables : array();
		$tables[] = self::credentials_table();
		$tables[] = self::lockouts_table();
		return $tables;
	}

	/**
	 * Recreate the tables in wp-admin if any has gone missing.
	 *
	 * Throttled by create_tables() itself, and a no-op once the schema has been
	 * confirmed, so a healthy site pays one cached lookup.
	 */
	public function maybe_repair_schema(): void {
		$this->create_tables();
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
		// Activation is an explicit request, so it always retries a failed creation
		// and re-checks the tables rather than trusting an earlier confirmation.
		delete_transient( self::SCHEMA_RETRY_TRANSIENT );
		delete_transient( self::SCHEMA_VERIFIED_TRANSIENT );
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
					// Keep the legacy copy until the new option is confirmed to hold it.
					if ( ! self::same_option_value( get_option( 'dragonloginsecurity_' . $name, null ), $legacy ) ) {
						continue;
					}
				}
			}
			delete_option( 'dls_' . $name );
		}

		$legacy_cron = wp_next_scheduled( 'dls_prune_lockouts' );
		if ( $legacy_cron ) {
			wp_unschedule_event( $legacy_cron, 'dls_prune_lockouts' );
		}
	}

	/**
	 * Schedule the daily dragonloginsecurity_prune_lockouts event if it is missing. Runs on init because
	 * scheduling reads every plugin's translated cron_schedules labels.
	 */
	public static function ensure_scheduled(): void {
		if ( ! wp_next_scheduled( 'dragonloginsecurity_prune_lockouts' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dragonloginsecurity_prune_lockouts' );
		}
	}

	/**
	 * Compare two option values, allowing for scalars being stored as strings.
	 *
	 * @param mixed $stored   Value read back from the option.
	 * @param mixed $expected Value that was written.
	 * @return bool
	 */
	private static function same_option_value( $stored, $expected ): bool {
		if ( is_scalar( $stored ) && is_scalar( $expected ) ) {
			return (string) $stored === (string) $expected;
		}
		return $stored === $expected;
	}

	/**
	 * Whether a table exists.
	 *
	 * @param string $table Fully-qualified table name.
	 * @return bool
	 */
	public static function table_exists( string $table ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema check during activation.
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
	}

	/**
	 * Whether the stamped schema version is backed by tables that really exist.
	 *
	 * A release that stamped the version despite a failed dbDelta leaves a stamp
	 * that matches the current one, so the stamp alone cannot be trusted: the
	 * installations needing repair are exactly the ones an unconditional early
	 * return would skip. The answer is cached for a day so the check is not a
	 * SHOW TABLES on every request.
	 *
	 * @return bool
	 */
	private static function schema_confirmed(): bool {
		if ( get_transient( self::SCHEMA_VERIFIED_TRANSIENT ) ) {
			return true;
		}

		foreach ( array( self::credentials_table(), self::lockouts_table() ) as $table ) {
			if ( ! self::table_exists( $table ) ) {
				return false;
			}
		}

		set_transient( self::SCHEMA_VERIFIED_TRANSIENT, 1, DAY_IN_SECONDS );

		return true;
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
		if ( self::DB_VERSION === get_option( 'dragonloginsecurity_db_version' ) && self::schema_confirmed() ) {
			return;
		}
		if ( get_transient( self::SCHEMA_RETRY_TRANSIENT ) ) {
			return; // A recent attempt failed; wait for the throttle to expire.
		}

		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		$credentials     = self::credentials_table();
		$lockouts        = self::lockouts_table();

		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}

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

		// dbDelta reports what it attempted, not whether it succeeded. Stamp the
		// schema version only once both tables exist. A failure is recorded for
		// the admin notice and throttled so it is not retried on every call.
		$missing = array_values( array_filter( array( $credentials, $lockouts ), fn( string $table ): bool => ! self::table_exists( $table ) ) );
		if ( ! empty( $missing ) ) {
			delete_transient( self::SCHEMA_VERIFIED_TRANSIENT );
			set_transient( self::SCHEMA_RETRY_TRANSIENT, 1, 10 * MINUTE_IN_SECONDS );
			update_option(
				self::SCHEMA_FAILURE_OPTION,
				array(
					'tables' => $missing,
					'time'   => time(),
				),
				false
			);
			return;
		}

		delete_transient( self::SCHEMA_RETRY_TRANSIENT );
		delete_option( self::SCHEMA_FAILURE_OPTION );
		update_option( 'dragonloginsecurity_db_version', self::DB_VERSION );
		set_transient( self::SCHEMA_VERIFIED_TRANSIENT, 1, DAY_IN_SECONDS );
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
