<?php
/**
 * Brute-force protection. Live failed-attempt counters and lock state live in
 * transients (self-expiring, so the attacker-driven path never writes the DB per
 * attempt); the wp_dragonloginsecurity_lockouts table records only actual lockout events, at
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
	 * Seconds an address's earlier lockouts are remembered for escalation.
	 */
	const ESCALATION_WINDOW = DAY_IN_SECONDS;

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		add_filter( 'authenticate', array( $this, 'block_locked' ), 30, 3 );
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
	 * The address an attempt is counted against. An IPv6 address counts as its
	 * /64 block, the allocation a single subscriber or device typically holds,
	 * so an attacker cannot take a fresh counter for every one of the 2^64
	 * addresses in it. IPv4 addresses, including IPv4-mapped IPv6 ones, count
	 * singly.
	 *
	 * @param string $ip IP address.
	 * @return string The address or block the counters are keyed on.
	 */
	public static function bucket( string $ip ): string {
		$ip = trim( $ip );
		if ( 1 === preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m ) ) {
			return $m[1];
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $ip;
		}
		$packed = inet_pton( $ip );
		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return $ip;
		}
		$block = inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) );
		return false === $block ? $ip : $block . '/64';
	}

	/**
	 * Transient key for one of an address's counters.
	 *
	 * @param string $what 'fail', 'prior', 'banked' or 'lock'.
	 * @param string $ip   IP address.
	 * @return string
	 */
	private function key( string $what, string $ip ): string {
		return 'dragonloginsecurity_' . $what . '_' . md5( self::bucket( $ip ) );
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
		return (bool) get_transient( $this->key( 'lock', $ip ) );
	}

	/**
	 * Reject a credential check while locked, whatever the credentials.
	 *
	 * An authenticate pass without both a username and a password is not a
	 * sign-in attempt: wp-login.php runs one on every load of the login screen
	 * (wp_signon with no credentials), and core's own check answers it with an
	 * "empty" error that never fires wp_login_failed. Replacing that answer
	 * with the lockout error would count every page load a locked-out visitor
	 * makes as another failure and extend their lock.
	 *
	 * @param null|\WP_User|\WP_Error $user     Auth result so far.
	 * @param string                  $username Username as submitted.
	 * @param string                  $password Password as submitted.
	 * @return null|\WP_User|\WP_Error
	 */
	public function block_locked( $user, $username = '', $password = '' ) {
		if ( '' === (string) $username || '' === (string) $password ) {
			return $user;
		}
		$ip = IP::current();
		if ( $this->is_locked( $ip ) ) {
			return new \WP_Error(
				'dragonloginsecurity_locked',
				__( 'Too many failed attempts. Please try again later.', 'dragon-login-security' )
			);
		}
		return $user;
	}

	/**
	 * Record a failed login and apply or extend a lockout.
	 *
	 * Failures are counted per address. THRESHOLD failures lock the address,
	 * and failures made while it is locked keep counting and extend the lock.
	 * Once a lock has run out, the next failure starts a new count, so a single
	 * mistake after a lockout does not lock the address again. The total behind
	 * each lock is recorded when the lock is set and remembered for
	 * ESCALATION_WINDOW, then added to the current count when choosing the
	 * next lock length, so repeated lockouts escalate along the same ladder
	 * (lockout_seconds()) even when the hour-long failure counter has expired
	 * with the lock.
	 *
	 * A password-only sign-in refused because the account uses two-factor
	 * sign-in is not counted: the password was correct.
	 *
	 * @param string $username Attempted username.
	 * @param mixed  $error    WP error from the failed attempt.
	 * @return int Failures counted toward the lock length (earlier lockouts included).
	 */
	public function on_failure( string $username, $error = null ): int {
		$ip = IP::current();
		if ( '' === $ip || $this->in_list( $ip, 'allow' ) ) {
			return 0;
		}

		$code = $error instanceof \WP_Error ? $error->get_error_code() : '';
		if ( 'dragonloginsecurity_2fa_required' === $code ) {
			return 0;
		}

		$key        = $this->key( 'fail', $ip );
		$prior_key  = $this->key( 'prior', $ip );
		$lock_key   = $this->key( 'lock', $ip );
		$banked_key = $this->key( 'banked', $ip );
		$count      = (int) get_transient( $key );
		$prior      = (int) get_transient( $prior_key );
		$locked     = (bool) get_transient( $lock_key );
		$banked     = (int) get_transient( $banked_key );

		if ( 'dragonloginsecurity_locked' === $code && '' === trim( $username ) ) {
			// A refusal that never carried credentials (see block_locked) is
			// not an attempt.
			return $prior + $count;
		}

		if ( ! $locked && $banked > 0 ) {
			// The previous lock has run out: its total, recorded when it was
			// set (the hour-long counter may have expired with it), becomes the
			// history behind a fresh count.
			$prior = $banked;
			$count = 0;
			set_transient( $prior_key, $prior, self::ESCALATION_WINDOW );
			delete_transient( $banked_key );
		}

		++$count;
		$total = $prior + $count;
		set_transient( $key, $count, self::WINDOW );

		// The address total decides lockouts; this per-username share of it is
		// what a later successful sign-in by that same account may forgive. No
		// share is kept for attempts that never reached an account.
		if ( ! in_array( $code, array( 'invalid_username', 'invalid_email', 'dragonloginsecurity_locked' ), true ) ) {
			$user_key = $this->user_key( $ip, $username );
			set_transient( $user_key, (int) get_transient( $user_key ) + 1, self::WINDOW );
		}

		$this->emit( 'user.login_failed', $ip, $username, $total );

		if ( $count >= self::THRESHOLD ) {
			set_transient( $lock_key, 1, $this->lockout_seconds( $total ) );
			set_transient( $banked_key, $total, self::ESCALATION_WINDOW );
			// A new lockout, or one escalated to a longer tier while in force.
			if ( ! $locked || $this->is_tier_boundary( $total ) ) {
				$this->record_lockout( $ip, $username, $total );
				$this->emit( 'user.lockout', $ip, $username, $total );

				/**
				 * Fires when an address has been locked out after repeated failures.
				 *
				 * @param string $ip    Address locked out.
				 * @param int    $count Failures counted so far.
				 */
				do_action( 'dragonloginsecurity_lockout', $ip, $total );
			}
		}

		return $total;
	}

	/**
	 * On a successful login, forget the failures this account made from this
	 * address. Failures against other usernames keep counting toward the
	 * address lockout.
	 *
	 * @param string    $user_login Username.
	 * @param \WP_User  $user       User.
	 */
	public function on_success( string $user_login, $user = null ): void {
		if ( $user instanceof \WP_User ) {
			$this->clear_user( IP::current(), $user );
		}
		unset( $user_login );
	}

	/**
	 * Forget the failures recorded from an address against one account (by its
	 * login or email), and take them off the address total. The lock itself is
	 * left to expire.
	 *
	 * An identifier that also names a different account (a username that is
	 * someone else's email address) is skipped, since its failures may have been
	 * against that other account.
	 *
	 * @param string   $ip   IP.
	 * @param \WP_User $user The account that signed in.
	 */
	public function clear_user( string $ip, \WP_User $user ): void {
		if ( '' === $ip ) {
			return;
		}

		$names = array();
		if ( '' !== (string) $user->user_login ) {
			$other = get_user_by( 'email', $user->user_login );
			if ( ! $other || (int) $other->ID === (int) $user->ID ) {
				$names[] = $user->user_login;
			}
		}
		if ( '' !== (string) $user->user_email ) {
			$other = get_user_by( 'login', $user->user_email );
			if ( ! $other || (int) $other->ID === (int) $user->ID ) {
				$names[] = $user->user_email;
			}
		}

		$forgiven = 0;
		foreach ( array_unique( array_map( array( $this, 'normalise_username' ), $names ) ) as $name ) {
			$user_key  = $this->user_key( $ip, $name );
			$forgiven += (int) get_transient( $user_key );
			delete_transient( $user_key );
		}
		if ( $forgiven <= 0 ) {
			return;
		}

		// A lock left to expire remembers its total; the forgiven failures
		// come off that too.
		$banked_key = $this->key( 'banked', $ip );
		$banked     = (int) get_transient( $banked_key );
		if ( $banked > 0 ) {
			if ( $banked - $forgiven > 0 ) {
				set_transient( $banked_key, $banked - $forgiven, self::ESCALATION_WINDOW );
			} else {
				delete_transient( $banked_key );
			}
		}

		$key       = $this->key( 'fail', $ip );
		$remaining = (int) get_transient( $key ) - $forgiven;
		if ( $remaining > 0 ) {
			set_transient( $key, $remaining, self::WINDOW );
			return;
		}
		delete_transient( $key );
		if ( 0 === $remaining ) {
			return;
		}

		// Forgiven failures older than the current count sit in the banked
		// total from earlier lockouts.
		$prior_key = $this->key( 'prior', $ip );
		$prior     = (int) get_transient( $prior_key ) + $remaining;
		if ( $prior > 0 ) {
			set_transient( $prior_key, $prior, self::ESCALATION_WINDOW );
		} else {
			delete_transient( $prior_key );
		}
	}

	/**
	 * Transient key for one address + username failure counter.
	 *
	 * @param string $ip       IP.
	 * @param string $username Username or email as typed.
	 * @return string
	 */
	private function user_key( string $ip, string $username ): string {
		return 'dragonloginsecurity_failu_' . md5( self::bucket( $ip ) . '|' . $this->normalise_username( $username ) );
	}

	/**
	 * Logins and emails match case-insensitively, so count them that way.
	 *
	 * @param string $username Username or email.
	 * @return string
	 */
	private function normalise_username( string $username ): string {
		return strtolower( trim( $username ) );
	}

	/**
	 * Clear all failure + lock state for an IP (administrator unlock).
	 *
	 * @param string $ip IP.
	 */
	public function clear( string $ip ): void {
		if ( '' === $ip ) {
			return;
		}
		delete_transient( $this->key( 'fail', $ip ) );
		delete_transient( $this->key( 'prior', $ip ) );
		delete_transient( $this->key( 'banked', $ip ) );
		delete_transient( $this->key( 'lock', $ip ) );
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
		$settings = get_option( 'dragonloginsecurity_settings', array() );
		$list     = is_array( $settings ) && ! empty( $settings[ $type . '_ips' ] ) ? (array) $settings[ $type . '_ips' ] : array();
		return array() !== $list && IP::in_ranges( $ip, $list );
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
			'dragonloginsecurity_login_event',
			$code,
			array(
				'object_name' => $username,
				'source_ip'   => $ip,
				'message'     => 'user.lockout' === $code
					/* translators: 1: IP address, 2: number of failed attempts. */
					? sprintf( _n( 'IP %1$s locked out after %2$s failed attempt', 'IP %1$s locked out after %2$s failed attempts', $count, 'dragon-login-security' ), $ip, number_format_i18n( $count ) )
					/* translators: %s: username. */
					: sprintf( __( 'Failed login for "%s"', 'dragon-login-security' ), $username ),
			)
		);
	}
}
