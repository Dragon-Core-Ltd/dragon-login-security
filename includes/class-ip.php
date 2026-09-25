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
	 * REMOTE_ADDR is the only value trusted by default. Proxy headers are
	 * client-spoofable, so they are consulted only when `trust_proxy` is enabled.
	 * With trusted-proxy ranges configured, the headers are read only when
	 * REMOTE_ADDR is one of those proxies (a direct connection keeps its own
	 * address), and the X-Forwarded-For chain, with REMOTE_ADDR as its last hop,
	 * is walked from the right past every trusted hop: the first untrusted hop
	 * is the client. The walk stops at a malformed hop and falls back to the
	 * last trusted one. X-Real-IP is used only when X-Forwarded-For is absent,
	 * under the same REMOTE_ADDR check. With no ranges configured, a single
	 * proxy is assumed and its rightmost forwarded address is used.
	 * HTTP_CLIENT_IP is never read.
	 *
	 * @return string Empty string when none resolvable.
	 */
	public static function current(): string {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$remote = filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';

		$settings    = get_option( 'dragonloginsecurity_settings', array() );
		$trust_proxy = is_array( $settings ) && ! empty( $settings['trust_proxy'] );

		if ( ! $trust_proxy ) {
			return $remote;
		}

		$trusted = self::trusted_proxies();
		if ( ! empty( $trusted ) && ( '' === $remote || ! self::ip_in_ranges( $remote, $trusted ) ) ) {
			return $remote;
		}

		$hops = array();
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			foreach ( explode( ',', $xff ) as $hop ) {
				$hops[] = trim( $hop, " \t[]" );
			}
		} elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
			$hops[] = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ), " \t[]" );
		}

		if ( empty( $trusted ) ) {
			// One proxy assumed: the address it observed is the rightmost hop.
			$last = end( $hops );
			return ( false !== $last && filter_var( $last, FILTER_VALIDATE_IP ) ) ? $last : $remote;
		}

		$client = $remote;
		for ( $i = count( $hops ) - 1; $i >= 0; $i-- ) {
			if ( ! filter_var( $hops[ $i ], FILTER_VALIDATE_IP ) ) {
				return $client;
			}
			$client = $hops[ $i ];
			if ( ! self::ip_in_ranges( $client, $trusted ) ) {
				return $client;
			}
		}
		return $client;
	}

	/**
	 * Configured trusted-proxy ranges (CIDR or bare IP), from settings.
	 *
	 * @return string[]
	 */
	private static function trusted_proxies(): array {
		$settings = get_option( 'dragonloginsecurity_settings', array() );
		$raw      = ( is_array( $settings ) && ! empty( $settings['trusted_proxies'] ) ) ? $settings['trusted_proxies'] : '';

		if ( is_string( $raw ) ) {
			$raw = preg_split( '/[\s,]+/', $raw );
		}
		if ( ! is_array( $raw ) ) {
			return array();
		}

		return array_values( array_filter( array_map( 'trim', $raw ) ) );
	}

	/**
	 * Whether an IP falls within any of the given CIDR/IP ranges.
	 *
	 * @param string   $ip     IP address.
	 * @param string[] $ranges CIDR ranges or bare IPs.
	 * @return bool
	 */
	private static function ip_in_ranges( string $ip, array $ranges ): bool {
		foreach ( $ranges as $range ) {
			if ( self::ip_in_cidr( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CIDR / bare-IP match for IPv4 and IPv6.
	 *
	 * @param string $ip    IP address.
	 * @param string $range CIDR range or bare IP.
	 * @return bool
	 */
	private static function ip_in_cidr( string $ip, string $range ): bool {
		$range = trim( $range );
		if ( '' === $range ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			return $ip === $range;
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$bits                  = (int) $bits;

		$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on malformed input; a false result is handled below.
		$subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on malformed input; a false result is handled below.

		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false; // Unparseable or IPv4/IPv6 family mismatch.
		}

		// Cap the prefix to the address width so a malformed range (e.g. an IPv4
		// address with /33+) can never read past the packed binary.
		$bits        = max( 0, min( $bits, strlen( $ip_bin ) * 8 ) );
		$whole_bytes = intdiv( $bits, 8 );
		$rem_bits    = $bits % 8;

		if ( $whole_bytes > 0 && substr( $ip_bin, 0, $whole_bytes ) !== substr( $subnet_bin, 0, $whole_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = chr( ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF );
			if ( ( ord( $ip_bin[ $whole_bytes ] ) & ord( $mask ) ) !== ( ord( $subnet_bin[ $whole_bytes ] ) & ord( $mask ) ) ) {
				return false;
			}
		}

		return true;
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
