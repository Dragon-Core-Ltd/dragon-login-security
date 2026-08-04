<?php
/**
 * Client IP capture and privacy anonymization.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves the requesting client's IP. REMOTE_ADDR is trusted by default;
 * proxy headers are consulted only when explicitly enabled (they are
 * client-spoofable).
 */
class IP {

	/**
	 * Get the client IP for the current request.
	 *
	 * @return string Empty string when none resolvable.
	 */
	public static function current(): string {
		$settings    = get_option( 'dls_settings', array() );
		$trust_proxy = is_array( $settings ) && ! empty( $settings['trust_proxy'] );

		$candidates = array( 'REMOTE_ADDR' );
		if ( $trust_proxy ) {
			array_unshift( $candidates, 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP' );
		}

		foreach ( $candidates as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$value = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
			$value = trim( explode( ',', $value )[0] );
			if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
				return $value;
			}
		}

		return '';
	}

	/**
	 * Anonymize an IP: zero the last IPv4 octet or the last 80 bits of IPv6.
	 *
	 * @param string $ip IP address.
	 * @return string
	 */
	public static function anonymize( string $ip ): string {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts    = explode( '.', $ip );
			$parts[3] = '0';
			return implode( '.', $parts );
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = inet_pton( $ip );
			if ( false === $packed ) {
				return $ip;
			}
			$packed = substr( $packed, 0, 6 ) . str_repeat( "\0", 10 );
			$result = inet_ntop( $packed );
			return false === $result ? $ip : $result;
		}

		return $ip;
	}
}
