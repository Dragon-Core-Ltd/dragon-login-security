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
 * Forwards dls_login_event to Activity Log and registers our event codes.
 */
class Integration {

	/**
	 * Register hooks.
	 */
	public function __construct() {
		add_action( 'dls_login_event', array( $this, 'forward' ), 10, 2 );
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
	 * when Activity Log is present).
	 *
	 * @param array $events Existing registry.
	 * @return array
	 */
	public function register( array $events ): array {
		foreach ( Events::codes() as $code => $def ) {
			$events[ $code ] = $def;
		}
		return $events;
	}
}
