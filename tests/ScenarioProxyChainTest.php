<?php
/**
 * Scenario hunt: client address resolution for every proxy_header value
 * against every trusted_proxies shape, odd header values a real proxy or an
 * attacker sends, and the mismatch / unconfigured records.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\IP;
use DragonLoginSecurity\Limit_Login;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( IP::class )]
class ScenarioProxyChainTest extends TestCase {

	private const HEADERS = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_FORWARDED', 'HTTP_CLIENT_IP' );

	protected function setUp(): void {
		$GLOBALS['dls_test_options'] = array();
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
	}

	protected function tearDown(): void {
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	/**
	 * Resolve with the given settings and request headers.
	 *
	 * @param mixed                $settings Plugin settings (any shape).
	 * @param string|null          $remote   REMOTE_ADDR, null to unset.
	 * @param array<string,string> $headers  Header name => value.
	 * @return string
	 */
	private function resolve( $settings, ?string $remote, array $headers = array() ): string {
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = $settings;
		if ( null === $remote ) {
			unset( $_SERVER['REMOTE_ADDR'] );
		} else {
			$_SERVER['REMOTE_ADDR'] = $remote;
		}
		foreach ( self::HEADERS as $header ) {
			unset( $_SERVER[ $header ] );
		}
		foreach ( $headers as $name => $value ) {
			$_SERVER[ $name ] = $value;
		}
		return IP::current();
	}

	private function ranges( string $ranges, string $header = 'x_forwarded_for' ): array {
		return array(
			'trust_proxy'     => true,
			'proxy_header'    => $header,
			'trusted_proxies' => $ranges,
		);
	}

	public function test_a_port_suffixed_forwarded_hop_still_names_the_visitor(): void {
		// Azure Application Gateway / App Service and some HAProxy setups write
		// "address:port" into X-Forwarded-For. Treating the hop as malformed
		// gives every visitor the proxy's own address, so a few failed sign-ins
		// by anyone lock everyone out, and no misconfiguration record is written
		// because REMOTE_ADDR is a trusted hop.
		$cf = $this->ranges( '10.0.0.0/8' );
		$this->assertSame( '203.0.113.5', $this->resolve( $cf, '10.1.2.3', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.5:12345' ) ) );
		$this->assertSame( '2001:db8::1', $this->resolve( $cf, '10.1.2.3', array( 'HTTP_X_FORWARDED_FOR' => '[2001:db8::1]:443' ) ) );
		$this->assertSame( '203.0.113.5', $this->resolve( array( 'trust_proxy' => true ), '10.1.2.3', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.5:12345' ) ) );
	}

	public function test_a_port_suffixed_hop_is_at_least_not_an_attacker_controlled_address(): void {
		// Whatever is done with the port form, the forged prefix must not win.
		$cf = $this->ranges( '173.245.48.0/20' );
		$ip = $this->resolve( $cf, '10.1.2.3', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 203.0.113.5:12345, 173.245.48.1' ) );
		$this->assertNotSame( '9.9.9.9', $ip );
	}

	public function test_every_single_value_header_with_every_trusted_proxy_shape(): void {
		foreach ( array( 'x_real_ip' => 'HTTP_X_REAL_IP', 'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP', 'true_client_ip' => 'HTTP_TRUE_CLIENT_IP' ) as $choice => $server_key ) {
			$sent = array( $server_key => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' );

			// No ranges: read from anyone (single proxy assumed).
			$this->assertSame( '203.0.113.5', $this->resolve( array( 'trust_proxy' => 1, 'proxy_header' => $choice ), '198.51.100.23', $sent ), $choice );
			// Single address, CIDR, IPv6 range, list with blank lines and commas.
			foreach ( array( '173.245.48.5', '173.245.48.0/20', "2400:cb00::/32\n\n173.245.48.0/20", '173.245.48.0/20, 2400:cb00::/32', array( '173.245.48.0/20' ) ) as $ranges ) {
				$settings = $this->ranges( '', $choice );
				$settings['trusted_proxies'] = $ranges;
				$this->assertSame( '203.0.113.5', $this->resolve( $settings, '173.245.48.5', $sent ), $choice . ' via ' . wp_json_encode( $ranges ) );
				$this->assertSame( '198.51.100.23', $this->resolve( $settings, '198.51.100.23', $sent ), 'public non-proxy keeps its own address' );
				$this->assertSame( '203.0.113.5', $this->resolve( $settings, '127.0.0.1', $sent ), 'internal hop reads the header' );
			}
			// The IPv6 proxy itself as the connecting address.
			$this->assertSame( '203.0.113.5', $this->resolve( $this->ranges( '2400:cb00::/32', $choice ), '2400:cb00:1::7', $sent ) );
			// A bracketed IPv6 value and a mapped IPv4 value are accepted.
			$this->assertSame( '2001:db8::7', $this->resolve( $this->ranges( '10.0.0.0/8', $choice ), '10.0.0.1', array( $server_key => '[2001:db8::7]' ) ) );
			$this->assertSame( '::ffff:203.0.113.5', $this->resolve( $this->ranges( '10.0.0.0/8', $choice ), '10.0.0.1', array( $server_key => '::ffff:203.0.113.5' ) ) );
			$this->assertSame( '203.0.113.5', Limit_Login::bucket( $this->resolve( $this->ranges( '10.0.0.0/8', $choice ), '10.0.0.1', array( $server_key => '::ffff:203.0.113.5' ) ) ) );
			// Present but empty, whitespace, a list, junk: the proxy's address.
			foreach ( array( '', ' ', '203.0.113.5, 9.9.9.9', 'junk', '203.0.113.5:443', 'fe80::1%eth0' ) as $bad ) {
				$this->assertSame( '10.0.0.1', $this->resolve( $this->ranges( '10.0.0.0/8', $choice ), '10.0.0.1', array( $server_key => $bad ) ), $choice . ' value ' . wp_json_encode( $bad ) );
			}
		}
	}

	public function test_only_the_chosen_header_is_read_in_x_forwarded_for_mode_too(): void {
		// The settings screen says "Only this header is read". With
		// X-Forwarded-For chosen and absent, X-Real-IP must not be used instead:
		// a proxy that sets X-Forwarded-For passes a visitor's X-Real-IP through.
		$this->assertSame( '10.0.0.1', $this->resolve( array( 'trust_proxy' => 1 ), '10.0.0.1', array( 'HTTP_X_REAL_IP' => '9.9.9.9' ) ) );
		$this->assertSame( '10.0.0.1', $this->resolve( $this->ranges( '10.0.0.0/8' ), '10.0.0.1', array( 'HTTP_X_REAL_IP' => '9.9.9.9' ) ) );
	}

	public function test_x_forwarded_for_chains_a_real_proxy_produces(): void {
		$cf = $this->ranges( "173.245.48.0/20\n2400:cb00::/32" );
		// nginx $proxy_add_x_forwarded_for when the visitor sent an empty header.
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => ', 203.0.113.7, 173.245.48.1' ) ) );
		// Two proxies each appending, tabs and odd spacing, bracketed IPv6 client.
		$this->assertSame( '2001:db8::7', $this->resolve( $cf, '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => "[2001:db8::7]\t,173.245.48.1 ,  2400:cb00::9" ) ) );
		// Two headers merged by the web server (duplicate X-Forwarded-For lines).
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 203.0.113.7, 173.245.48.1' ) ) );
		// Every hop trusted: the leftmost is the best answer.
		$this->assertSame( '173.245.48.2', $this->resolve( $cf, '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '173.245.48.2, 173.245.48.1' ) ) );
		// A mapped IPv4 client through an IPv6 proxy.
		$this->assertSame( '::ffff:203.0.113.7', $this->resolve( $cf, '2400:cb00::9', array( 'HTTP_X_FORWARDED_FOR' => '::ffff:203.0.113.7' ) ) );
		// The visitor's own forged hops behind a trusted proxy lose.
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '173.245.48.1', array( 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 10.0.0.1, 173.245.48.9, 203.0.113.7' ) ) );
		// A forged trusted hop after the visitor: the visitor is still the
		// first non-trusted address from the right, which is now the forged
		// prefix's neighbour - the proxy-observed address wins because the
		// proxy appended it last.
		$this->assertSame( '203.0.113.7', $this->resolve( $cf, '173.245.48.1', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 173.245.48.9, 203.0.113.7' ) ) );
	}

	public function test_a_visitor_sending_an_obsolete_or_unread_header_gains_nothing(): void {
		$cf = $this->ranges( '173.245.48.0/20' );
		foreach ( array( 'HTTP_FORWARDED' => 'for=9.9.9.9;proto=https', 'HTTP_CLIENT_IP' => '9.9.9.9' ) as $name => $value ) {
			$this->assertSame( '173.245.48.1', $this->resolve( $cf, '173.245.48.1', array( $name => $value ) ), $name );
			$this->assertSame( '198.51.100.23', $this->resolve( array(), '198.51.100.23', array( $name => $value ) ), $name );
		}
		// Not one of the four read headers, so it is not "forwarded headers".
		$this->assertNull( IP::proxy_unconfigured() );
	}

	public function test_trust_proxy_stored_in_every_shape_a_checkbox_or_cli_edit_produces(): void {
		$sent = array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' );
		foreach ( array( true, 1, '1', 'on', 'yes' ) as $on ) {
			$this->assertSame( '203.0.113.7', $this->resolve( array( 'trust_proxy' => $on ), '10.0.0.1', $sent ), wp_json_encode( $on ) );
		}
		foreach ( array( false, 0, '0', '', null ) as $off ) {
			$this->assertSame( '10.0.0.1', $this->resolve( array( 'trust_proxy' => $off ), '10.0.0.1', $sent ), wp_json_encode( $off ) );
		}
	}

	public function test_settings_and_ranges_in_wrong_shapes_fall_back_safely(): void {
		$sent = array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' );
		foreach ( array( 'a string', 42, null, true, array( 0, 1 ) ) as $settings ) {
			$this->assertSame( '10.0.0.1', $this->resolve( $settings, '10.0.0.1', $sent ), wp_json_encode( $settings ) );
		}
		// Ranges that are garbage or of the wrong type: not a trusted hop, and the
		// public remote address is recorded as a mismatch, not resolved.
		foreach ( array( 'office', 'garbage, more', array( 'nope' ) ) as $ranges ) {
			$settings = $this->ranges( '' );
			$settings['trusted_proxies'] = $ranges;
			$this->assertSame( '198.51.100.23', $this->resolve( $settings, '198.51.100.23', $sent ), wp_json_encode( $ranges ) );
		}
	}

	public function test_a_trusted_proxy_range_with_host_bits_set_still_matches_its_block(): void {
		$this->assertSame( '203.0.113.7', $this->resolve( $this->ranges( '173.245.48.5/20' ), '173.245.63.254', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ) ) );
	}

	public function test_mismatch_records_the_latest_address_and_alternating_proxies_are_not_throttled(): void {
		$cf = $this->ranges( '173.245.48.0/20' );
		$this->resolve( $cf, '6.6.6.6', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) );
		$first_time = get_option( IP::MISMATCH_OPTION )['time'];
		$GLOBALS['dls_test_options'][ IP::MISMATCH_OPTION ]['time'] = $first_time - 10;

		// Same address within the hour: untouched.
		$this->resolve( $cf, '6.6.6.6', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) );
		$this->assertSame( $first_time - 10, get_option( IP::MISMATCH_OPTION )['time'] );
		// Another address: replaces it at once, so the notice names the latest.
		$this->resolve( $cf, '7.7.7.7', array( 'HTTP_CF_CONNECTING_IP' => '9.9.9.9' ) );
		$this->assertSame( '7.7.7.7', IP::proxy_mismatch()['ip'] );
		// Beyond the throttle the same address is refreshed.
		$GLOBALS['dls_test_options'][ IP::MISMATCH_OPTION ]['time'] = time() - IP::MISMATCH_THROTTLE - 1;
		$this->resolve( $cf, '7.7.7.7', array( 'HTTP_CF_CONNECTING_IP' => '9.9.9.9' ) );
		$this->assertEqualsWithDelta( time(), IP::proxy_mismatch()['time'], 5 );
	}

	public function test_a_corrupt_record_is_overwritten_and_never_reported(): void {
		foreach ( array( 'string', 42, array( 'ip' => array( '1.2.3.4' ) ), array( 'ip' => '' ), array( 'time' => time() ), array( 'ip' => '6.6.6.6', 'time' => 'soon' ) ) as $bad ) {
			$GLOBALS['dls_test_options'] = array(
				'dragonloginsecurity_settings' => $this->ranges( '173.245.48.0/20' ),
				IP::MISMATCH_OPTION            => $bad,
			);
			if ( is_array( $bad ) && '6.6.6.6' === ( $bad['ip'] ?? '' ) ) {
				// time 'soon' casts to 0: expired.
				$this->assertNull( IP::proxy_mismatch() );
			} else {
				$this->assertNull( IP::proxy_mismatch(), wp_json_encode( $bad ) );
			}
			$GLOBALS['dls_test_options'][ IP::UNCONFIGURED_OPTION ] = $bad;
			$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array();
			$this->assertNull( IP::proxy_unconfigured(), wp_json_encode( $bad ) );
		}
		$this->resolve( $this->ranges( '173.245.48.0/20' ), '6.6.6.6', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) );
		$this->assertSame( '6.6.6.6', IP::proxy_mismatch()['ip'] );
	}

	public function test_unconfigured_record_is_written_for_the_chosen_header_only_when_trust_is_off_and_ignores_internal_only_setups(): void {
		// Trust off: any of the four headers from any address records it.
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP' ) as $header ) {
			$GLOBALS['dls_test_options'] = array();
			$this->resolve( array(), '10.0.0.1', array( $header => '203.0.113.9' ) );
			$this->assertSame( '10.0.0.1', IP::proxy_unconfigured()['ip'], $header );
		}
		// Trust on with no ranges: nothing is ever recorded (single proxy mode).
		$GLOBALS['dls_test_options'] = array();
		$this->resolve( array( 'trust_proxy' => 1 ), '198.51.100.23', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$this->assertArrayNotHasKey( IP::MISMATCH_OPTION, $GLOBALS['dls_test_options'] );
		$this->assertArrayNotHasKey( IP::UNCONFIGURED_OPTION, $GLOBALS['dls_test_options'] );
		// An unconfigured record made earlier stops applying once trust is on,
		// and a mismatch made earlier stops applying once trust is off.
		$this->resolve( array(), '10.0.0.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$this->resolve( $this->ranges( '173.245.48.0/20' ), '6.6.6.6', array( 'HTTP_X_FORWARDED_FOR' => '9.9.9.9' ) );
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = $this->ranges( '173.245.48.0/20' );
		$this->assertNull( IP::proxy_unconfigured() );
		$this->assertNotNull( IP::proxy_mismatch() );
		$GLOBALS['dls_test_options']['dragonloginsecurity_settings'] = array();
		$this->assertNotNull( IP::proxy_unconfigured() );
		$this->assertNull( IP::proxy_mismatch() );
	}

	public function test_missing_or_invalid_remote_addr_with_headers_never_resolves_to_a_header(): void {
		$sent = array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7', 'HTTP_X_REAL_IP' => '203.0.113.8' );
		foreach ( array( null, '', 'unknown', '203.0.113.9:443', 'fe80::1%eth0' ) as $remote ) {
			$this->assertSame( '', $this->resolve( array(), $remote, $sent ), wp_json_encode( $remote ) );
			$this->assertSame( '', $this->resolve( $this->ranges( '10.0.0.0/8' ), $remote, $sent ), wp_json_encode( $remote ) );
			$this->assertSame( '', $this->resolve( $this->ranges( '10.0.0.0/8', 'x_real_ip' ), $remote, $sent ), wp_json_encode( $remote ) );
		}
		$this->assertArrayNotHasKey( IP::MISMATCH_OPTION, $GLOBALS['dls_test_options'], 'no record for an address that is not one' );
		$this->assertArrayNotHasKey( IP::UNCONFIGURED_OPTION, $GLOBALS['dls_test_options'] );
	}

	public function test_lockouts_follow_the_resolved_address_through_a_proxy(): void {
		$cf = $this->ranges( '173.245.48.0/20' );
		$GLOBALS['dls_test_transients']    = array();
		$GLOBALS['dls_test_actions_fired'] = array();
		$GLOBALS['wpdb']                   = new \DLS_Test_Wpdb();
		$GLOBALS['dls_test_users']         = array( 1 => new \WP_User( 1, 'owner' ) );
		$l = new Limit_Login();
		for ( $i = 0; $i < 5; $i++ ) {
			$this->resolve( $cf, '173.245.48.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ) );
			$l->on_failure( 'owner', new \WP_Error( 'incorrect_password' ) );
		}
		$this->assertTrue( $l->is_locked( '203.0.113.7' ) );
		$this->assertFalse( $l->is_locked( '173.245.48.1' ), 'the proxy is not locked' );
		// Another visitor through the same proxy is unaffected.
		$this->resolve( $cf, '173.245.48.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.8' ) );
		$this->assertNull( $l->block_locked( null, 'owner', 'pw' ) );
		$this->resolve( $cf, '173.245.48.1', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ) );
		$this->assertInstanceOf( \WP_Error::class, $l->block_locked( null, 'owner', 'pw' ) );
	}
}
