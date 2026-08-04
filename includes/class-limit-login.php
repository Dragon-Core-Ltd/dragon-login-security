<?php
/**
 * Brute-force protection. Live failed-attempt counters and lock state live in
 * transients (self-expiring, so the attacker-driven path never writes the DB per
 * attempt); the wp_dls_lockouts table records only actual lockout events, at
 * tier boundaries, for reporting.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tracks failures and enforces escalating lockouts.
 */
class Limit_Login {

	/**
	 * Failures needed before the first lockout.
	 */
	const THRESHOLD = 5;

	/**
	 * Seconds a failure counter persists (the accumulation window).
	 */
	const WINDOW = HOUR_IN_SECONDS;

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		add_filter( 'authenticate', array( $this, 'block_locked' ), 30, 1 );
		add_action( 'wp_login_failed', array( $this, 'on_failure' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 2 );
	}

	/**
	 * Lockout duration for a given failure count (escalating ladder).
	 *
	 * @param int $count Failure count.
	 * @return int Seconds locked (0 = not locked).
	 */
	public function lockout_seconds( int $count ): int {
		if ( $count < self::THRESHOLD ) {
			return 0;
		}
		if ( $count < 10 ) {
			return 15 * MINUTE_IN_SECONDS;
		}
		if ( $count < 20 ) {
			return HOUR_IN_SECONDS;
		}
		return DAY_IN_SECONDS;
	}

	/**
	 * Whether a count is a lockout tier boundary (where we record a row).
	 *
	 * @param int $count Failure count.
	 * @return bool
	 */
	public function is_tier_boundary( int $count ): bool {
		return in_array( $count, array( self::THRESHOLD, 10, 20 ), true );
	}

	/**
	 * Whether an IP is currently locked out (or on the deny list).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public function is_locked( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}
		if ( $this->in_list( $ip, 'allow' ) ) {
			return false;
		}
		if ( $this->in_list( $ip, 'deny' ) ) {
			return true;
		}
		return (bool) get_transient( 'dls_lock_' . md5( $ip ) );
	}

	/**
	 * Reject authentication while locked, regardless of credentials.
	 *
	 * @param null|\WP_User|\WP_Error $user Auth result so far.
	 * @return null|\WP_User|\WP_Error
	 */
	public function block_locked( $user ) {
		$ip = IP::current();
		if ( $this->is_locked( $ip ) ) {
			return new \WP_Error(
				'dls_locked',
				__( 'Too many failed attempts. Please try again later.', 'dragon-login-security' )
			);
		}
		return $user;
	}

	/**
	 * Record a failed login and, at a tier boundary, apply a lockout.
	 *
	 * @param string $username Attempted username.
	 * @param mixed  $error    WP error (unused).
	 * @return int Current failure count.
	 */
	public function on_failure( string $username, $error = null ): int {
		unset( $error );
		$ip = IP::current();
		if ( '' === $ip || $this->in_list( $ip, 'allow' ) ) {
			return 0;
		}

		$key   = 'dls_fail_' . md5( $ip );
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, self::WINDOW );

		$this->emit( 'user.login_failed', $ip, $username, $count );

		$seconds = $this->lockout_seconds( $count );
		if ( $seconds > 0 ) {
			set_transient( 'dls_lock_' . md5( $ip ), 1, $seconds );
			if ( $this->is_tier_boundary( $count ) ) {
				$this->record_lockout( $ip, $username, $count );
				$this->emit( 'user.lockout', $ip, $username, $count );
			}
		}

		return $count;
	}

	/**
	 * Clear counters on a successful login.
	 *
	 * @param string    $user_login Username.
	 * @param \WP_User  $user       User.
	 */
	public function on_success( string $user_login, $user = null ): void {
		unset( $user_login, $user );
		$this->clear( IP::current() );
	}

	/**
	 * Clear failure + lock state for an IP.
	 *
	 * @param string $ip IP.
	 */
	public function clear( string $ip ): void {
		if ( '' === $ip ) {
			return;
		}
		delete_transient( 'dls_fail_' . md5( $ip ) );
		delete_transient( 'dls_lock_' . md5( $ip ) );
	}

	/**
	 * Insert one lockout-event row (bounded: tier boundaries only).
	 *
	 * @param string $ip       IP.
	 * @param string $username Username.
	 * @param int    $count    Failure count.
	 */
	private function record_lockout( string $ip, string $username, int $count ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table (lockout event only).
		$wpdb->insert(
			Plugin::lockouts_table(),
			array(
				'ip'         => $ip,
				'username'   => mb_substr( $username, 0, 191 ),
				'attempts'   => $count,
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%d', '%s' )
		);
	}

	/**
	 * Whether an IP is in the allow or deny settings list.
	 *
	 * @param string $ip   IP.
	 * @param string $type 'allow' or 'deny'.
	 * @return bool
	 */
	private function in_list( string $ip, string $type ): bool {
		$settings = get_option( 'dls_settings', array() );
		$list     = is_array( $settings ) && ! empty( $settings[ $type . '_ips' ] ) ? (array) $settings[ $type . '_ips' ] : array();
		return in_array( $ip, $list, true );
	}

	/**
	 * Emit a suite event for the integration layer.
	 *
	 * @param string $code     Event code.
	 * @param string $ip       IP.
	 * @param string $username Username.
	 * @param int    $count    Failure count.
	 */
	private function emit( string $code, string $ip, string $username, int $count ): void {
		/**
		 * Fires on a login-security event (consumed by the Activity Log bridge).
		 *
		 * @param string $code  Event code.
		 * @param array  $event Event payload.
		 */
		do_action(
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- 3-letter plugin prefix.
			'dls_login_event',
			$code,
			array(
				'object_name' => $username,
				'source_ip'   => $ip,
				'message'     => 'user.lockout' === $code
					/* translators: 1: IP, 2: attempts. */
					? sprintf( __( 'IP %1$s locked out after %2$d failed attempts', 'dragon-login-security' ), $ip, $count )
					/* translators: %s: username. */
					: sprintf( __( 'Failed login for "%s"', 'dragon-login-security' ), $username ),
			)
		);
	}
}
