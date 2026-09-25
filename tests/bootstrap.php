<?php
/**
 * PHPUnit bootstrap. The classes under test are WP-light; the few core helpers
 * they touch are stubbed here.
 *
 * @package DragonLoginSecurity
 */

defined( 'ABSPATH' ) || define( 'ABSPATH', __DIR__ . '/' );
defined( 'MINUTE_IN_SECONDS' ) || define( 'MINUTE_IN_SECONDS', 60 );
defined( 'HOUR_IN_SECONDS' ) || define( 'HOUR_IN_SECONDS', 3600 );
defined( 'DAY_IN_SECONDS' ) || define( 'DAY_IN_SECONDS', 86400 );
defined( 'ARRAY_A' ) || define( 'ARRAY_A', 'ARRAY_A' );

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		unset( $domain );
		return $text;
	}
}

if ( ! function_exists( '_n' ) ) {
	function _n( $single, $plural, $number, $domain = 'default' ) {
		unset( $domain );
		return 1 === (int) $number ? $single : $plural;
	}
}

if ( ! function_exists( 'number_format_i18n' ) ) {
	function number_format_i18n( $number, $decimals = 0 ) {
		return number_format( (float) $number, (int) $decimals );
	}
}

if ( ! function_exists( 'wp_date' ) ) {
	function wp_date( $format, $timestamp = null, $timezone = null ) {
		$timestamp = null === $timestamp ? time() : (int) $timestamp;
		$timezone  = $timezone instanceof DateTimeZone ? $timezone : new DateTimeZone( 'UTC' );
		return ( new DateTimeImmutable( '@' . $timestamp ) )->setTimezone( $timezone )->format( $format );
	}
}

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		unset( $scheme );
		return 'unit-test-static-salt-value-0123456789';
	}
}


if ( ! function_exists( 'dragon_test_repair_utf8' ) ) {
	/**
	 * Mirrors wp_check_invalid_utf8( $text, true ) over a whole structure:
	 * invalid byte sequences are stripped rather than causing a failure.
	 *
	 * @param mixed $value Value to repair.
	 * @return mixed
	 */
	function dragon_test_repair_utf8( $value ) {
		if ( is_array( $value ) ) {
			$out = array();
			foreach ( $value as $key => $item ) {
				$out[ is_string( $key ) ? dragon_test_repair_utf8( $key ) : $key ] = dragon_test_repair_utf8( $item );
			}
			return $out;
		}

		if ( ! is_string( $value ) || '' === $value || 1 === preg_match( '//u', $value ) ) {
			return $value;
		}

		return (string) preg_replace( '/[\x80-\xFF]/', '', $value );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		/*
		 * Core runs every string through wp_check_invalid_utf8() first, which
		 * REPAIRS invalid UTF-8 rather than refusing to encode it. The result can
		 * therefore name different bytes than the input, and the function
		 * succeeds where plain json_encode() would return false. A stub that just
		 * calls json_encode() hides every bug where a repaired value is then used
		 * as if it were the original.
		 */
		return json_encode( dragon_test_repair_utf8( $data ), $options, $depth );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

$GLOBALS['dls_test_actions_done'] = array( 'init' => 1 );

if ( ! function_exists( 'did_action' ) ) {
	function did_action( $hook ) {
		return (int) ( $GLOBALS['dls_test_actions_done'][ $hook ] ?? 0 );
	}
}

if ( ! function_exists( 'wp_get_list_item_separator' ) ) {
	function wp_get_list_item_separator() {
		return __( ', ' );
	}
}


if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		return is_array( $value ) ? array_map( 'wp_unslash', $value ) : ( is_string( $value ) ? stripslashes( $value ) : $value );
	}
}
if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Close to core: tags stripped, line breaks/tabs and extra whitespace
	 * collapsed, ends trimmed; invalid UTF-8 gives ''.
	 */
	function sanitize_text_field( $str ) {
		$str = (string) $str;
		if ( '' !== $str && 1 !== preg_match( '//u', $str ) ) {
			return '';
		}
		$str = strip_tags( $str );
		$str = preg_replace( '/[\r\n\t ]+/', ' ', $str );
		return trim( (string) $str );
	}
}

if ( ! function_exists( 'site_url' ) ) {
	function site_url( $path = '', $scheme = null ) {
		unset( $scheme );
		// A test may put WordPress on its own host (core's "WordPress Address").
		$base = $GLOBALS['dls_test_site_url'] ?? 'https://example.test';
		return $base . '/' . ltrim( (string) $path, '/' );
	}
}
if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '', $scheme = null ) {
		unset( $scheme );
		return 'https://example.test/' . ltrim( (string) $path, '/' );
	}
}
if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '', $scheme = 'admin' ) {
		unset( $scheme );
		// Core builds this from site_url().
		return site_url( 'wp-admin/' . ltrim( (string) $path, '/' ) );
	}
}
if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * Core keeps http(s) and relative URLs and returns '' for other schemes.
	 */
	function esc_url_raw( $url, $protocols = null ) {
		unset( $protocols );
		$url = trim( (string) $url );
		if ( preg_match( '/^([a-z][a-z0-9+.\-]*):/i', $url, $m ) && ! in_array( strtolower( $m[1] ), array( 'http', 'https' ), true ) ) {
			return '';
		}
		return str_replace( array( ' ', '"', "'", '<', '>' ), array( '%20', '', '', '', '' ), $url );
	}
}
if ( ! function_exists( 'wp_validate_redirect' ) ) {
	/**
	 * Mirrors core: only the site's own host (or a relative path) is allowed,
	 * otherwise the fallback.
	 */
	function wp_validate_redirect( $location, $fallback_url = '' ) {
		$location = trim( (string) $location );
		if ( '' === $location ) {
			return $fallback_url;
		}
		if ( '//' === substr( $location, 0, 2 ) ) {
			return $fallback_url;
		}
		$host = parse_url( $location, PHP_URL_HOST );
		if ( null === $host || false === $host ) {
			return $location;
		}
		return 'example.test' === strtolower( $host ) ? $location : $fallback_url;
	}
}
if ( ! function_exists( 'wp_get_raw_referer' ) ) {
	function wp_get_raw_referer() {
		if ( ! empty( $_REQUEST['_wp_http_referer'] ) ) {
			return wp_unslash( $_REQUEST['_wp_http_referer'] );
		}
		return ! empty( $_SERVER['HTTP_REFERER'] ) ? wp_unslash( $_SERVER['HTTP_REFERER'] ) : false;
	}
}

$GLOBALS['dls_test_multisite'] = false;
if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite() {
		return (bool) $GLOBALS['dls_test_multisite'];
	}
}

// Multisite: sites keyed by blog id (objects shaped like WP_Site), per-site
// options, network options, and the current site.
$GLOBALS['dls_test_sites']         = array();
$GLOBALS['dls_test_blog_options']  = array();
$GLOBALS['dls_test_site_options']  = array();
$GLOBALS['dls_test_current_blog']  = 1;
if ( ! function_exists( 'get_current_blog_id' ) ) {
	function get_current_blog_id() {
		return (int) $GLOBALS['dls_test_current_blog'];
	}
}
if ( ! function_exists( 'get_main_site_id' ) ) {
	function get_main_site_id( $network_id = null ) {
		unset( $network_id );
		return 1;
	}
}
if ( ! function_exists( 'get_site' ) ) {
	/**
	 * Core returns a WP_Site (blog_id as a string) or null.
	 */
	function get_site( $site = null ) {
		$id = null === $site ? get_current_blog_id() : (int) $site;
		return $GLOBALS['dls_test_sites'][ $id ] ?? null;
	}
}
if ( ! function_exists( 'get_blog_option' ) ) {
	function get_blog_option( $id, $option, $default_value = false ) {
		return $GLOBALS['dls_test_blog_options'][ (int) $id ][ $option ] ?? $default_value;
	}
}
if ( ! function_exists( 'get_site_option' ) ) {
	function get_site_option( $option, $default_value = false, $deprecated = true ) {
		unset( $deprecated );
		return $GLOBALS['dls_test_site_options'][ $option ] ?? $default_value;
	}
}
if ( ! function_exists( 'get_site_url' ) ) {
	/**
	 * The given site's siteurl (scheme, domain and path) plus $path.
	 */
	function get_site_url( $blog_id = null, $path = '', $scheme = null ) {
		unset( $scheme );
		$site = get_site( $blog_id );
		if ( ! $site ) {
			return site_url( $path );
		}
		return 'https://' . $site->domain . rtrim( $site->path, '/' ) . '/' . ltrim( (string) $path, '/' );
	}
}
if ( ! function_exists( 'add_query_arg' ) ) {
	/**
	 * Mirrors core for the ( key, value, url ) form: replaces the key if it is
	 * already there, keeps the fragment, and does NOT encode the value.
	 */
	function add_query_arg( $key, $value, $url ) {
		$frag = '';
		if ( false !== strpos( $url, '#' ) ) {
			list( $url, $frag ) = explode( '#', $url, 2 );
			$frag               = '#' . $frag;
		}
		list( $base, $query ) = array_pad( explode( '?', $url, 2 ), 2, '' );
		$pairs                = array();
		foreach ( '' === $query ? array() : explode( '&', $query ) as $pair ) {
			if ( explode( '=', $pair, 2 )[0] !== $key ) {
				$pairs[] = $pair;
			}
		}
		$pairs[] = $key . '=' . $value;
		return $base . '?' . implode( '&', $pairs ) . $frag;
	}
}

// Hook recorders: actions fired, and per-hook filter overrides for tests.
$GLOBALS['dls_test_actions_fired']   = array();
$GLOBALS['dls_test_filter_override'] = array();
if ( ! function_exists( 'do_action' ) ) {
	function do_action( $hook, ...$args ) {
		$GLOBALS['dls_test_actions_fired'][] = array( $hook, $args );
	}
}
if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value, ...$args ) {
		if ( isset( $GLOBALS['dls_test_filter_override'][ $hook ] ) ) {
			return call_user_func( $GLOBALS['dls_test_filter_override'][ $hook ], $value, ...$args );
		}
		return $value;
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $errors = array();
		public function __construct( $code = '', $message = '', $data = '' ) {
			unset( $data );
			if ( '' !== $code ) {
				$this->errors[ $code ][] = $message;
			}
		}
		public function get_error_code() {
			$codes = array_keys( $this->errors );
			return $codes ? $codes[0] : '';
		}
		public function has_errors() {
			return ! empty( $this->errors );
		}
	}
}
if ( ! class_exists( 'WP_User' ) ) {
	class WP_User {
		public $ID         = 0;
		public $user_login = '';
		public $user_email = '';
		public $roles      = array();
		public function __construct( $id = 0, $name = '' ) {
			$this->ID         = (int) $id;
			$this->user_login = (string) $name;
		}
		public function exists() {
			return ! empty( $this->ID );
		}
	}
}

// In-memory user registry: id => WP_User.
$GLOBALS['dls_test_users'] = array();
if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( $user_id ) {
		return $GLOBALS['dls_test_users'][ (int) $user_id ] ?? false;
	}
}
if ( ! function_exists( 'get_user_by' ) ) {
	/**
	 * Mirrors core: logins and emails match case-insensitively (MySQL
	 * collation); false when nothing matches.
	 */
	function get_user_by( $field, $value ) {
		foreach ( $GLOBALS['dls_test_users'] as $user ) {
			$have = 'email' === $field ? $user->user_email : ( 'login' === $field ? $user->user_login : (string) $user->ID );
			if ( '' !== (string) $value && 0 === strcasecmp( (string) $have, (string) $value ) ) {
				return $user;
			}
		}
		return false;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( ...$args ) {
		unset( $args );
		return true;
	}
}
$GLOBALS['dls_test_filters'] = array();

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( ...$args ) {
		$GLOBALS['dls_test_filters'][] = $args;
		return true;
	}
}

$GLOBALS['dls_test_transients'] = array();

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		return array_key_exists( $key, $GLOBALS['dls_test_transients'] ) ? $GLOBALS['dls_test_transients'][ $key ] : false;
	}
}
if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $ttl = 0 ) {
		unset( $ttl );
		$GLOBALS['dls_test_transients'][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		unset( $GLOBALS['dls_test_transients'][ $key ] );
		return true;
	}
}

// In-memory option and user-meta stores. Setting the *_write_fails flag makes
// the write stubs drop the value and return false, mimicking a DB write error.
$GLOBALS['dls_test_options']            = array();
$GLOBALS['dls_test_option_write_fails'] = false;
$GLOBALS['dls_test_user_meta']          = array();
$GLOBALS['dls_test_meta_write_fails']   = false;

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $name, $default_value = false ) {
		return array_key_exists( $name, $GLOBALS['dls_test_options'] ) ? $GLOBALS['dls_test_options'][ $name ] : $default_value;
	}
}
if ( ! function_exists( 'update_option' ) ) {
	function update_option( $name, $value, $autoload = null ) {
		unset( $autoload );
		if ( $GLOBALS['dls_test_option_write_fails'] ) {
			return false;
		}
		if ( array_key_exists( $name, $GLOBALS['dls_test_options'] ) && $GLOBALS['dls_test_options'][ $name ] === $value ) {
			return false;
		}
		$GLOBALS['dls_test_options'][ $name ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $name ) {
		$existed = array_key_exists( $name, $GLOBALS['dls_test_options'] );
		unset( $GLOBALS['dls_test_options'][ $name ] );
		return $existed;
	}
}
if ( ! function_exists( 'get_user_meta' ) ) {
	/**
	 * $GLOBALS['dls_test_after_read'] is a callable run once immediately after a
	 * read returns, which is how a concurrent request is modelled: the caller
	 * holds the value it just read while another request completes its own
	 * read-modify-write against the same row.
	 */
	function get_user_meta( $user_id, $key, $single = false ) {
		unset( $single );
		$value = $GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] ?? '';

		if ( isset( $GLOBALS['dls_test_after_read'] ) && is_callable( $GLOBALS['dls_test_after_read'] ) ) {
			$callback                          = $GLOBALS['dls_test_after_read'];
			$GLOBALS['dls_test_after_read'] = null;
			$callback();
		}

		return $value;
	}
}
if ( ! function_exists( 'update_user_meta' ) ) {
	/**
	 * Mirrors core, including $prev_value: core updates only rows whose stored
	 * value still equals $prev_value, so passing it makes the write a
	 * compare-and-swap that fails when another request got there first.
	 */
	function update_user_meta( $user_id, $key, $value, $prev_value = '' ) {
		if ( $GLOBALS['dls_test_meta_write_fails'] ) {
			return false;
		}
		$stored = $GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] ?? null;
		if ( '' !== $prev_value && $stored !== $prev_value ) {
			return false;
		}
		if ( null !== $stored && $stored === $value ) {
			return false;
		}
		$GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'add_user_meta' ) ) {
	/**
	 * Mirrors core: with $unique the insert is refused when the key already
	 * exists, which makes first-time creation atomic between requests.
	 */
	function add_user_meta( $user_id, $key, $value, $unique = false ) {
		if ( $GLOBALS['dls_test_meta_write_fails'] ) {
			return false;
		}
		if ( $unique && isset( $GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] ) ) {
			return false;
		}
		$GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] = $value;
		return 1;
	}
}
if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( $user_id, $key ) {
		unset( $GLOBALS['dls_test_user_meta'][ $user_id ][ $key ] );
		return true;
	}
}
if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type, $gmt = 0 ) {
		unset( $type, $gmt );
		return gmdate( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	function wp_next_scheduled( $hook ) {
		unset( $hook );
		return false;
	}
}
if ( ! function_exists( 'wp_schedule_event' ) ) {
	function wp_schedule_event( ...$args ) {
		unset( $args );
		return true;
	}
}
if ( ! function_exists( 'wp_unschedule_event' ) ) {
	function wp_unschedule_event( ...$args ) {
		unset( $args );
		return true;
	}
}

// Capability stub driven by a global so notice tests can flip admin status.
$GLOBALS['dls_test_is_admin'] = true;
if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $cap ) {
		unset( $cap );
		return (bool) $GLOBALS['dls_test_is_admin'];
	}
}
if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES );
	}
}
if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) {
		unset( $domain );
		return htmlspecialchars( (string) $text, ENT_QUOTES );
	}
}

// In-memory session store shaped like core's WP_Session_Tokens: one manager per
// user, sessions keyed by a hash of the token, destroy() removes one session.
$GLOBALS['dls_test_sessions'] = array();
if ( ! class_exists( 'WP_Session_Tokens' ) ) {
	class WP_Session_Tokens {
		protected $user_id;
		protected function __construct( $user_id ) {
			$this->user_id = (int) $user_id;
		}
		public static function get_instance( $user_id ) {
			return new static( $user_id );
		}
		private function hash_token( $token ) {
			return hash( 'sha256', (string) $token );
		}
		public function create( $expiration ) {
			$token = bin2hex( random_bytes( 21 ) );
			$GLOBALS['dls_test_sessions'][ $this->user_id ][ $this->hash_token( $token ) ] = array( 'expiration' => (int) $expiration );
			return $token;
		}
		public function verify( $token ) {
			$session = $GLOBALS['dls_test_sessions'][ $this->user_id ][ $this->hash_token( $token ) ] ?? null;
			return is_array( $session ) && $session['expiration'] >= time();
		}
		public function destroy( $token ) {
			unset( $GLOBALS['dls_test_sessions'][ $this->user_id ][ $this->hash_token( $token ) ] );
		}
		public function destroy_all() {
			$GLOBALS['dls_test_sessions'][ $this->user_id ] = array();
		}
		public function get_all() {
			return array_values( $GLOBALS['dls_test_sessions'][ $this->user_id ] ?? array() );
		}
	}
}

// dbDelta stand-in: records the statements it was given and creates nothing.
$GLOBALS['dls_test_dbdelta_calls'] = array();
if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries ) {
		$GLOBALS['dls_test_dbdelta_calls'][] = $queries;
		return array();
	}
}

/**
 * Minimal $wpdb stand-in. Each query method returns whatever the test
 * assigned to the matching public property.
 */
class DLS_Test_Wpdb {
	public $prefix          = 'wp_';
	public $update_result   = 1;
	public $insert_result   = 1;
	public $insert_id       = 0;
	public $get_var_result  = null;
	public $existing_tables = array();
	public $table_checks    = 0;
	public $last_update     = null;
	public $last_query      = '';

	public $base_prefix = 'wp_';
	public function prepare( $query, ...$args ) {
		$this->last_query = $query;
		// Core accepts the values as one array argument too.
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}
		return vsprintf( str_replace( array( '%i', '%s', '%d' ), array( '%s', '%s', '%d' ), $query ), $args );
	}
	public function get_col( $query ) {
		// "(SELECT 'table' AS t FROM table WHERE user_id = N LIMIT 1)" groups.
		if ( preg_match_all( '/SELECT (\S+) AS t FROM (\S+) WHERE user_id = (\d+)/', $query, $m, PREG_SET_ORDER ) ) {
			$out = array();
			foreach ( $m as $part ) {
				foreach ( $this->rows[ $part[2] ] ?? array() as $row ) {
					if ( (int) $row['user_id'] === (int) $part[3] ) {
						$out[] = trim( $part[1], "'" );
						break;
					}
				}
			}
			return $out;
		}
		if ( 0 === strpos( $query, 'SHOW TABLES LIKE ' ) ) {
			$like  = substr( $query, strlen( 'SHOW TABLES LIKE ' ) );
			$regex = '/^' . str_replace( array( '%', '_' ), array( '.*', '.' ), preg_quote( $like, '/' ) ) . '$/';
			$names = array_unique( array_merge( $this->existing_tables, array_keys( $this->rows ) ) );
			return array_values( array_filter( $names, static function ( $t ) use ( $regex ) { return 1 === preg_match( $regex, $t ); } ) );
		}
		return array();
	}
	public function get_var( $query ) {
		if ( preg_match_all( '/SELECT 1 FROM (\S+) WHERE user_id = (\d+)/', $query, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $part ) {
				foreach ( $this->rows[ $part[1] ] ?? array() as $row ) {
					if ( (int) $row['user_id'] === (int) $part[2] ) {
						return '1';
					}
				}
			}
			return null;
		}
		if ( 0 === strpos( $query, 'SHOW TABLES LIKE ' ) ) {
			++$this->table_checks;
			$name = substr( $query, strlen( 'SHOW TABLES LIKE ' ) );
			return in_array( $name, $this->existing_tables, true ) ? $name : null;
		}
		return $this->get_var_result;
	}
	public function esc_like( $text ) {
		return $text;
	}
	public function get_charset_collate() {
		return '';
	}
	public function update( $table, $data, $where, $format = null, $where_format = null ) {
		$this->last_update = compact( 'table', 'data', 'where', 'format', 'where_format' );
		return $this->update_result;
	}
	public function insert( $table, $data, $format = null ) {
		unset( $table, $data, $format );
		return $this->insert_result;
	}
	/**
	 * Rows per table name, filtered on "user_id = N" when the query asks.
	 *
	 * @var array<string,array<int,array>>
	 */
	public $rows = array();
	public function delete( $table, $where, $format = null ) {
		unset( $format );
		$before               = count( $this->rows[ $table ] ?? array() );
		$this->rows[ $table ] = array_values(
			array_filter(
				$this->rows[ $table ] ?? array(),
				static function ( $row ) use ( $where ) {
					foreach ( $where as $col => $val ) {
						if ( (string) $row[ $col ] !== (string) $val ) {
							return true;
						}
					}
					return false;
				}
			)
		);
		return $before - count( $this->rows[ $table ] );
	}
	public function get_row( $query, $output = null ) {
		foreach ( $this->rows as $table => $rows ) {
			if ( false === strpos( $query, ' ' . $table . ' ' ) ) {
				continue;
			}
			foreach ( $rows as $row ) {
				if ( preg_match( "/credential_id = (\\S+)/", $query, $m ) && (string) $row['credential_id'] !== trim( $m[1], "'" ) ) {
					continue;
				}
				return $row;
			}
		}
		unset( $output );
		return null;
	}
	public function get_results( $query, $output = null ) {
		unset( $output );
		$out = array();
		foreach ( $this->rows as $table => $rows ) {
			if ( false === strpos( $query, ' ' . $table . ' ' ) ) {
				continue;
			}
			foreach ( $rows as $row ) {
				if ( preg_match( '/user_id = (\d+)/', $query, $m ) && (int) $row['user_id'] !== (int) $m[1] ) {
					continue;
				}
				$out[] = $row;
			}
		}
		return $out;
	}
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../includes/class-crypto.php';
require_once __DIR__ . '/../includes/class-ip.php';
require_once __DIR__ . '/../includes/providers/class-provider-totp.php';
require_once __DIR__ . '/../includes/providers/class-provider-backup-codes.php';
require_once __DIR__ . '/../includes/class-limit-login.php';
require_once __DIR__ . '/../includes/class-webauthn.php';
require_once __DIR__ . '/../includes/class-login-token.php';
require_once __DIR__ . '/../includes/class-events.php';
require_once __DIR__ . '/../includes/class-integration.php';
require_once __DIR__ . '/../includes/class-plugin.php';
require_once __DIR__ . '/../includes/class-credentials.php';
require_once __DIR__ . '/../includes/providers/class-provider-passkey.php';
require_once __DIR__ . '/../includes/class-two-factor.php';
require_once __DIR__ . '/../includes/class-admin.php';
require_once __DIR__ . '/../includes/class-importer.php';

require_once __DIR__ . '/../includes/class-pro-pointer.php';
