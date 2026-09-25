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
	 * Addresses that are never a visitor's public address: loopback, private
	 * (RFC 1918, IPv6 unique-local) and carrier-grade NAT. A request from one
	 * of these came through the server's own network, such as a load balancer
	 * or a web server proxying to another on the same host.
	 */
	const INTERNAL_RANGES = array(
		'127.0.0.0/8',
		'10.0.0.0/8',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'100.64.0.0/10',
		'::1/128',
		'fc00::/7',
	);

	/**
	 * Option holding the last public address seen sending forwarded headers
	 * from outside the trusted-proxy ranges.
	 */
	const MISMATCH_OPTION = 'dragonloginsecurity_proxy_mismatch';

	/**
	 * Seconds before the same address is recorded again.
	 */
	const MISMATCH_THROTTLE = 3600;

	/**
	 * Seconds a recorded address stays reportable.
	 */
	const MISMATCH_TTL = 604800;

	/**
	 * Get the client IP for the current request.
	 *
	 * REMOTE_ADDR is the only value trusted by default. Proxy headers are
	 * client-spoofable, so they are consulted only when `trust_proxy` is enabled.
	 * With trusted-proxy ranges configured, the headers are read only when
	 * REMOTE_ADDR is one of those proxies or an internal address (loopback,
	 * private or carrier-grade NAT, see INTERNAL_RANGES), so a direct public
	 * connection keeps its own address. The X-Forwarded-For chain, with
	 * REMOTE_ADDR as its last hop, is walked from the right past every trusted
	 * or internal hop: the first other hop is the client. A public REMOTE_ADDR
	 * outside the ranges that sends forwarded headers is recorded for the
	 * misconfiguration notice. The walk stops at a malformed hop and falls back to the
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
		if ( ! empty( $trusted ) && ( '' === $remote || ! self::is_proxy_hop( $remote, $trusted ) ) ) {
			if ( '' !== $remote && ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) || ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) ) {
				self::record_mismatch( $remote );
			}
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
			if ( ! self::is_proxy_hop( $client, $trusted ) ) {
				return $client;
			}
		}
		return $client;
	}

	/**
	 * Whether an address is a hop that may forward a request: a configured
	 * trusted proxy or an internal address.
	 *
	 * @param string   $ip      IP address.
	 * @param string[] $trusted Trusted-proxy ranges.
	 * @return bool
	 */
	private static function is_proxy_hop( string $ip, array $trusted ): bool {
		return self::ip_in_ranges( $ip, $trusted ) || self::is_internal( $ip );
	}

	/**
	 * Whether an address is loopback, private or carrier-grade NAT. An
	 * IPv4-mapped IPv6 address is judged by its IPv4 part.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_internal( string $ip ): bool {
		if ( 1 === preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m ) ) {
			$ip = $m[1];
		}
		return self::ip_in_ranges( $ip, self::INTERNAL_RANGES );
	}

	/**
	 * Remember a public address that sent forwarded headers from outside the
	 * trusted-proxy ranges. Written at most once per MISMATCH_THROTTLE for the
	 * same address.
	 *
	 * @param string $remote REMOTE_ADDR.
	 */
	private static function record_mismatch( string $remote ): void {
		$now  = time();
		$last = get_option( self::MISMATCH_OPTION );
		if ( is_array( $last ) && ( $last['ip'] ?? '' ) === $remote && (int) ( $last['time'] ?? 0 ) + self::MISMATCH_THROTTLE > $now ) {
			return;
		}
		update_option(
			self::MISMATCH_OPTION,
			array(
				'ip'   => $remote,
				'time' => $now,
			),
			false
		);
	}

	/**
	 * The recorded proxy misconfiguration, while it still applies: proxy trust
	 * is on, ranges are set, the address is still outside them, and it was
	 * seen within MISMATCH_TTL.
	 *
	 * @param int $now Current time (0 for now).
	 * @return array{ip: string, time: int}|null
	 */
	public static function proxy_mismatch( int $now = 0 ): ?array {
		$now      = $now > 0 ? $now : time();
		$settings = get_option( 'dragonloginsecurity_settings', array() );
		if ( ! is_array( $settings ) || empty( $settings['trust_proxy'] ) ) {
			return null;
		}
		$trusted = self::trusted_proxies();
		$record  = get_option( self::MISMATCH_OPTION );
		if ( empty( $trusted ) || ! is_array( $record ) || empty( $record['ip'] ) || ! is_string( $record['ip'] ) ) {
			return null;
		}
		$time = (int) ( $record['time'] ?? 0 );
		if ( $time + self::MISMATCH_TTL <= $now || self::is_proxy_hop( $record['ip'], $trusted ) ) {
			return null;
		}
		return array(
			'ip'   => $record['ip'],
			'time' => $time,
		);
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
	 * Whether an IP falls within any of the given CIDR/IP ranges. IPv4-mapped
	 * IPv6 addresses (::ffff:a.b.c.d) match as their IPv4 address, and single
	 * addresses match in any notation.
	 *
	 * @param string   $ip     IP address.
	 * @param string[] $ranges CIDR ranges or bare IPs.
	 * @return bool
	 */
	public static function in_ranges( string $ip, array $ranges ): bool {
		return self::ip_in_ranges( $ip, $ranges );
	}

	/**
	 * Validate one allow/deny/proxy list entry: a single IPv4 or IPv6 address,
	 * or a CIDR range whose prefix fits the address family.
	 *
	 * @param string $entry Entry as typed.
	 * @return string|null The trimmed entry, or null when it is not valid.
	 */
	public static function normalise_list_entry( string $entry ): ?string {
		$entry = trim( $entry );
		if ( '' === $entry ) {
			return null;
		}

		if ( false === strpos( $entry, '/' ) ) {
			return filter_var( $entry, FILTER_VALIDATE_IP ) ? $entry : null;
		}

		list( $subnet, $bits ) = explode( '/', $entry, 2 );
		if ( '' === $bits || ! ctype_digit( $bits ) || strlen( $bits ) > 3 ) {
			return null;
		}
		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$max = 32;
		} elseif ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$max = 128;
		} else {
			return null;
		}

		return (int) $bits <= $max ? $subnet . '/' . (int) $bits : null;
	}

	/**
	 * Whether an IP falls within any of the given CIDR/IP ranges.
	 *
	 * @param string   $ip     IP address.
	 * @param string[] $ranges CIDR ranges or bare IPs.
	 * @return bool
	 */
	private static function ip_in_ranges( string $ip, array $ranges ): bool {
		$ip_bin = self::pack( $ip );
		if ( null === $ip_bin ) {
			return false;
		}
		foreach ( $ranges as $range ) {
			if ( self::ip_in_cidr( $ip_bin, (string) $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Packed binary form of an address, with an IPv4-mapped IPv6 address
	 * reduced to its four IPv4 bytes.
	 *
	 * @param string $ip IP address.
	 * @return string|null Null when the address cannot be parsed.
	 */
	private static function pack( string $ip ): ?string {
		$bin = @inet_pton( trim( $ip ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on malformed input; a false result is handled below.
		if ( false === $bin ) {
			return null;
		}
		if ( 16 === strlen( $bin ) && str_repeat( "\0", 10 ) . "\xff\xff" === substr( $bin, 0, 12 ) ) {
			return substr( $bin, 12 );
		}
		return $bin;
	}

	/**
	 * CIDR / bare-IP match for IPv4 and IPv6, by prefix comparison of the
	 * packed addresses. A range written in IPv4-mapped IPv6 form with a prefix
	 * of at least 96 bits is compared as the equivalent IPv4 range.
	 *
	 * @param string $ip_bin Packed IP address (see pack()).
	 * @param string $range  CIDR range or bare IP.
	 * @return bool
	 */
	private static function ip_in_cidr( string $ip_bin, string $range ): bool {
		$range = trim( $range );
		if ( '' === $range ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			return self::pack( $range ) === $ip_bin;
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		if ( '' === $bits || ! ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;

		$subnet_raw = @inet_pton( trim( $subnet ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on malformed input; a false result is handled below.
		if ( false === $subnet_raw ) {
			return false;
		}
		$subnet_bin = self::pack( $subnet );
		if ( strlen( $subnet_bin ) !== strlen( $subnet_raw ) ) {
			// An IPv4-mapped range: below /96 it also spans non-IPv4 addresses.
			if ( $bits < 96 ) {
				$subnet_bin = $subnet_raw;
				if ( 4 === strlen( $ip_bin ) ) {
					$ip_bin = str_repeat( "\0", 10 ) . "\xff\xff" . $ip_bin;
				}
			} else {
				$bits -= 96;
			}
		}

		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) || $bits > strlen( $ip_bin ) * 8 ) {
			return false; // IPv4/IPv6 family mismatch, or a prefix wider than the address.
		}

		$whole_bytes = intdiv( $bits, 8 );
		$rem_bits    = $bits % 8;

		if ( $whole_bytes > 0 && substr( $ip_bin, 0, $whole_bytes ) !== substr( $subnet_bin, 0, $whole_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
			if ( ( ord( $ip_bin[ $whole_bytes ] ) & $mask ) !== ( ord( $subnet_bin[ $whole_bytes ] ) & $mask ) ) {
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
