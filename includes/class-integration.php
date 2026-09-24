<?php
/**
 * Guarded bridge to Dragon Activity Log. Login Security works fully on its own;
 * when Activity Log is installed, events are forwarded to its tamper-evident
 * audit. The coupling is a public method on the free plugin, so every call is
 * guarded — a missing or version-skewed Activity Log must never fatal.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Forwards dragonloginsecurity_login_event to Activity Log and registers our event codes.
 */
class Integration {

	/**
	 * Register hooks.
	 */
	public function __construct() {
		add_action( 'dragonloginsecurity_login_event', array( $this, 'forward' ), 10, 2 );
		// Activity Log 1.0.x before the 2026-08 prefix rename fired dal_register_event;
		// current versions fire dragonactivitylog_register_event. Only one of them
		// ever runs, and register() is idempotent, so listening to both is safe.
		add_filter( 'dragonactivitylog_register_event', array( $this, 'register' ) );
		add_filter( 'dal_register_event', array( $this, 'register' ) );
	}

	/**
	 * Forward an event to Activity Log if it is reachable.
	 *
	 * @param string $code  Event code.
	 * @param array  $event Event payload.
	 */
	public function forward( string $code, array $event ): void {
		if ( ! class_exists( '\\DragonActivityLog\\Plugin' )
			|| ! method_exists( '\\DragonActivityLog\\Plugin', 'get_instance' ) ) {
			return; // Login Security works fully; there is just no audit row.
		}

		$logger = \DragonActivityLog\Plugin::get_instance()->logger();
		if ( ! is_object( $logger ) || ! method_exists( $logger, 'record' ) ) {
			return;
		}

		$event['event_code'] = $code;
		$logger->record( $event );
	}

	/**
	 * Register our event codes with Activity Log's registry (only ever called
	 * when Activity Log is present). Codes Activity Log already defines keep
	 * its own definition.
	 *
	 * @param array $events Existing registry.
	 * @return array
	 */
	public function register( array $events ): array {
		// Our labels are translated; Activity Log rebuilds its registry after init.
		if ( ! did_action( 'init' ) ) {
			return $events;
		}
		foreach ( Events::codes() as $code => $def ) {
			if ( ! isset( $events[ $code ] ) ) {
				$events[ $code ] = $def;
			}
		}
		return $events;
	}
}
