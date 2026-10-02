<?php
/**
 * The settings save reads each field it uses from the request after its own
 * nonce and capability checks, with a core sanitizer at the read, and stores
 * exactly what the form submitted before.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Admin;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[CoversClass( Admin::class )]
class WporgScanSettingsTest extends TestCase {

	private const SCREEN = 'https://example.test/wp-admin/options-general.php?page=dragon-login-security';

	/**
	 * Core's admin-referer check, redirect and sanitize_key, per process.
	 */
	private static function load_stubs(): void {
		// phpcs:ignore Squiz.PHP.Eval.Discouraged
		eval(
			'class WSS_Redirect extends \Exception {}
			class WSS_Die extends \Exception {}
			function check_admin_referer( $action = -1, $query_arg = "_wpnonce" ) {
				$result = isset( $_REQUEST[ $query_arg ] ) ? wp_verify_nonce( $_REQUEST[ $query_arg ], $action ) : false;
				do_action( "check_admin_referer", $action, $result );
				if ( ! $result ) { throw new WSS_Die( "403" ); }
				return $result;
			}
			function wp_safe_redirect( $l ) { throw new WSS_Redirect( $l ); }
			function sanitize_key( $key ) { $s = ""; if ( is_scalar( $key ) ) { $s = preg_replace( "/[^a-z0-9_\\-]/", "", strtolower( (string) $key ) ); } return $s; }'
		);
		$GLOBALS['dls_test_options']    = array();
		$GLOBALS['dls_test_transients'] = array();
		$GLOBALS['dls_test_is_admin']   = true;
		$GLOBALS['dls_test_current_user'] = 1;
	}

	/**
	 * Post the settings form as a browser would: core slashes the request.
	 *
	 * @param array $fields Unslashed form fields.
	 * @return string 'REDIRECT:<to>', 'DIE' or 'RETURNED'.
	 */
	private function save( array $fields ): string {
		$_POST    = self::slash( $fields );
		$_REQUEST = $_POST;
		try {
			( new Admin() )->maybe_save();
		} catch ( \WSS_Redirect $r ) {
			return 'REDIRECT:' . $r->getMessage();
		} catch ( \WSS_Die $d ) {
			return 'DIE';
		}
		return 'RETURNED';
	}

	/**
	 * Core's wp_slash() on a request array.
	 *
	 * @param mixed $value Value.
	 * @return mixed
	 */
	private static function slash( $value ) {
		return is_array( $value ) ? array_map( array( self::class, 'slash' ), $value ) : ( is_string( $value ) ? addslashes( $value ) : $value );
	}

	private function nothing_written(): void {
		$this->assertFalse( get_option( 'dragonloginsecurity_settings' ) );
		$this->assertFalse( get_option( 'dragonloginsecurity_delete_data_on_uninstall' ) );
		$this->assertFalse( get_transient( 'dragonloginsecurity_settings_notice' ) );
	}

	private static function form( array $fields = array() ): array {
		return $fields + array(
			'_wpnonce'                          => wp_create_nonce( 'dragonloginsecurity_settings' ),
			'dragonloginsecurity_save_settings' => '',
			'allow_ips'                         => "203.0.113.10\n198.51.100.0/24",
			'deny_ips'                          => '192.0.2.77',
			'trusted_proxies'                   => '10.9.8.0/24',
			'trust_proxy'                       => 'on',
			'proxy_header'                      => 'cf_connecting_ip',
		);
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_save_without_a_nonce_is_refused_and_writes_nothing(): void {
		self::load_stubs();
		$form = self::form();
		unset( $form['_wpnonce'] );
		$this->assertSame( 'DIE', $this->save( $form ) );
		$this->nothing_written();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_wrong_nonce_or_another_actions_nonce_is_refused(): void {
		self::load_stubs();
		foreach ( array( 'abcdef0123', wp_create_nonce( 'dragonloginsecurity_import' ), '' ) as $nonce ) {
			$this->assertSame( 'DIE', $this->save( self::form( array( '_wpnonce' => $nonce ) ) ) );
		}
		$this->nothing_written();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_nonce_from_another_user_is_refused(): void {
		self::load_stubs();
		$GLOBALS['dls_test_current_user'] = 2;
		$theirs                           = wp_create_nonce( 'dragonloginsecurity_settings' );
		$GLOBALS['dls_test_current_user'] = 1;
		$this->assertSame( 'DIE', $this->save( self::form( array( '_wpnonce' => $theirs ) ) ) );
		$this->nothing_written();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_user_without_manage_options_changes_nothing(): void {
		self::load_stubs();
		$GLOBALS['dls_test_is_admin'] = false;
		$this->assertSame( 'RETURNED', $this->save( self::form( array( 'dragonloginsecurity_delete_data' => '1' ) ) ) );
		$this->nothing_written();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_other_admin_posts_are_left_alone(): void {
		self::load_stubs();
		$form = self::form();
		unset( $form['dragonloginsecurity_save_settings'], $form['_wpnonce'] );
		$this->assertSame( 'RETURNED', $this->save( $form ) );
		$this->nothing_written();
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_valid_save_stores_the_form(): void {
		self::load_stubs();
		$this->assertSame( 'REDIRECT:' . self::SCREEN, $this->save( self::form( array( 'dragonloginsecurity_delete_data' => '1' ) ) ) );
		$this->assertSame(
			array(
				'trust_proxy'     => true,
				'proxy_header'    => 'cf_connecting_ip',
				'trusted_proxies' => array( '10.9.8.0/24' ),
				'allow_ips'       => array( '203.0.113.10', '198.51.100.0/24' ),
				'deny_ips'        => array( '192.0.2.77' ),
			),
			get_option( 'dragonloginsecurity_settings' )
		);
		$this->assertTrue( (bool) get_option( 'dragonloginsecurity_delete_data_on_uninstall' ) );
		$this->assertSame( 'success', get_transient( 'dragonloginsecurity_settings_notice' )['type'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_missing_fields_save_the_defaults(): void {
		self::load_stubs();
		$form = array(
			'_wpnonce'                          => wp_create_nonce( 'dragonloginsecurity_settings' ),
			'dragonloginsecurity_save_settings' => '',
		);
		$this->assertSame( 'REDIRECT:' . self::SCREEN, $this->save( $form ) );
		$this->assertSame(
			array(
				'trust_proxy'     => false,
				'proxy_header'    => 'x_forwarded_for',
				'trusted_proxies' => array(),
				'allow_ips'       => array(),
				'deny_ips'        => array(),
			),
			get_option( 'dragonloginsecurity_settings' )
		);
		$this->assertFalse( (bool) get_option( 'dragonloginsecurity_delete_data_on_uninstall' ) );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_arrays_where_text_is_expected_are_read_as_empty(): void {
		self::load_stubs();
		$form = self::form(
			array(
				'allow_ips'       => array( '203.0.113.5' ),
				'deny_ips'        => array( 'a' => array( '192.0.2.1' ) ),
				'trusted_proxies' => array(),
				'proxy_header'    => array( 'x_real_ip' ),
				'trust_proxy'     => array( 'on' ),
			)
		);
		$this->assertSame( 'REDIRECT:' . self::SCREEN, $this->save( $form ) );
		$this->assertSame(
			array(
				'trust_proxy'     => true,
				'proxy_header'    => 'x_forwarded_for',
				'trusted_proxies' => array(),
				'allow_ips'       => array(),
				'deny_ips'        => array(),
			),
			get_option( 'dragonloginsecurity_settings' )
		);
	}

	/**
	 * Submitted values whose stored result must be what the form stored before
	 * the fields were read one by one.
	 *
	 * @return array<string,array{0:array}>
	 */
	public static function edge_forms(): array {
		return array(
			'windows line endings and padding' => array( array( 'allow_ips' => " 203.0.113.11 \r\n\r\n198.51.100.7\t\r\n" ) ),
			'IPv6 and ranges'                  => array( array( 'deny_ips' => "2001:db8::1\n2001:db8::/32\n::ffff:192.0.2.1" ) ),
			'quotes and backslashes'           => array( array( 'allow_ips' => "it's\n\"203.0.113.13\"\nC:\\path\n203.0.113.14" ) ),
			'octets and control characters'    => array( array( 'deny_ips' => "203.0.113.%31\n192.0.2.9\x01\n192.0.2.10" ) ),
			'multibyte'                        => array( array( 'deny_ips' => "２０３.０.１１３.１\n192.0.2.11 é" ) ),
			'header in capitals'               => array( array( 'proxy_header' => 'X_REAL_IP' ) ),
			'header with a dash'               => array( array( 'proxy_header' => 'x-real-ip' ) ),
			'header with markup'               => array( array( 'proxy_header' => '<script>x_real_ip' ) ),
			'unchecked trust'                  => array( array( 'trust_proxy' => null ) ),
		);
	}

	#[DataProvider( 'edge_forms' )]
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_edge_values_store_what_they_stored_before( array $changes ): void {
		self::load_stubs();
		$form = self::form( $changes );
		if ( array_key_exists( 'trust_proxy', $changes ) && null === $changes['trust_proxy'] ) {
			unset( $form['trust_proxy'] );
		}
		$rejected = array();
		$before   = Admin::settings_from_input( $form, $rejected );

		$this->assertSame( 'REDIRECT:' . self::SCREEN, $this->save( $form ) );
		$this->assertSame( $before, get_option( 'dragonloginsecurity_settings' ) );
		$this->assertSame( array() === $rejected ? 'success' : 'error', get_transient( 'dragonloginsecurity_settings_notice' )['type'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_refused_entry_is_reported_unslashed(): void {
		self::load_stubs();
		$this->save( self::form( array( 'allow_ips' => "it's\n203.0.113.10" ) ) );
		$this->assertSame( array( '203.0.113.10' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		$this->assertStringContainsString( "it's", get_transient( 'dragonloginsecurity_settings_notice' )['message'] );
		$this->assertStringNotContainsString( "it\\'s", get_transient( 'dragonloginsecurity_settings_notice' )['message'] );
	}

	/**
	 * A list textarea containing '<' or '>' (which no address or range does),
	 * with the per-line text the notice must name.
	 *
	 * @return array<string,array{0:string,1:string,2:string[]}>
	 */
	public static function markup_lists(): array {
		return array(
			'unclosed tag across lines' => array( 'allow_ips', "10.0.0.1 <office\n10.0.0.2 lan>\n10.0.0.3", array( '10.0.0.1 &lt;office', '10.0.0.2 lan&gt;', '10.0.0.3' ) ),
			'unclosed tag at the end'   => array( 'allow_ips', "10.0.0.1 <old office\n10.0.0.2", array( '10.0.0.1 &lt;old office', '10.0.0.2' ) ),
			'closed tag'                => array( 'deny_ips', "203.0.113.10 <b>x</b>\r\n198.51.100.1", array( '203.0.113.10 &lt;b&gt;x&lt;/b&gt;', '198.51.100.1' ) ),
			'closing bracket alone'     => array( 'trusted_proxies', "10.9.8.0/24 >\n10.9.9.0/24", array( '10.9.8.0/24 &gt;', '10.9.9.0/24' ) ),
			'comment line'              => array( 'allow_ips', "<!-- office -->\n10.0.0.5", array( '&lt;!-- office --&gt;', '10.0.0.5' ) ),
			'only an empty tag'         => array( 'deny_ips', '<b></b>', array( '&lt;b&gt;&lt;/b&gt;' ) ),
		);
	}

	/**
	 * Stored lists the markup tests start from.
	 */
	private static function store_lists(): void {
		update_option(
			'dragonloginsecurity_settings',
			array(
				'trust_proxy'     => false,
				'proxy_header'    => 'x_forwarded_for',
				'trusted_proxies' => array( '10.1.0.0/16' ),
				'allow_ips'       => array( '192.0.2.50' ),
				'deny_ips'        => array( '192.0.2.60' ),
			)
		);
	}

	#[DataProvider( 'markup_lists' )]
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_list_containing_markup_is_refused_whole_and_reported( string $field, string $text, array $named ): void {
		self::load_stubs();
		self::store_lists();
		$stored = get_option( 'dragonloginsecurity_settings' );

		$this->assertSame( 'REDIRECT:' . self::SCREEN, $this->save( self::form( array( $field => $text ) ) ) );

		$saved = get_option( 'dragonloginsecurity_settings' );
		$this->assertSame( $stored[ $field ], $saved[ $field ], 'the refused list was rewritten' );
		$expected = array(
			'allow_ips'       => array( '203.0.113.10', '198.51.100.0/24' ),
			'deny_ips'        => array( '192.0.2.77' ),
			'trusted_proxies' => array( '10.9.8.0/24' ),
		);
		foreach ( $expected as $other => $list ) {
			if ( $other !== $field ) {
				$this->assertSame( $list, $saved[ $other ], "$other was not saved" );
			}
		}
		$this->assertTrue( $saved['trust_proxy'] );
		$this->assertSame( 'cf_connecting_ip', $saved['proxy_header'] );

		$notice = get_transient( 'dragonloginsecurity_settings_notice' );
		$this->assertSame( 'error', $notice['type'] );
		foreach ( $named as $line ) {
			$this->assertStringContainsString( $line, $notice['message'] );
		}
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_a_valid_list_with_ranges_and_ipv6_is_saved_as_before(): void {
		self::load_stubs();
		self::store_lists();
		$text = "203.0.113.10\n198.51.100.0/24\r\n2001:db8::1\n 2001:db8::/32 \n\n";
		$this->save( self::form( array( 'allow_ips' => $text ) ) );
		$this->assertSame( array( '203.0.113.10', '198.51.100.0/24', '2001:db8::1', '2001:db8::/32' ), get_option( 'dragonloginsecurity_settings' )['allow_ips'] );
		$this->assertSame( 'success', get_transient( 'dragonloginsecurity_settings_notice' )['type'] );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_an_empty_or_missing_list_clears_it_as_before(): void {
		self::load_stubs();
		self::store_lists();
		$form = self::form( array( 'allow_ips' => '' ) );
		unset( $form['trusted_proxies'] );
		$this->save( $form );
		$saved = get_option( 'dragonloginsecurity_settings' );
		$this->assertSame( array(), $saved['allow_ips'] );
		$this->assertSame( array(), $saved['trusted_proxies'] );
		$this->assertSame( array( '192.0.2.77' ), $saved['deny_ips'] );
		$this->assertSame( 'success', get_transient( 'dragonloginsecurity_settings_notice' )['type'] );
	}
}
