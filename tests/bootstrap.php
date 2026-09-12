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

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		unset( $domain );
		return $text;
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

if ( ! function_exists( 'add_action' ) ) {
	function add_action( ...$args ) {
		unset( $args );
		return true;
	}
}
if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( ...$args ) {
		unset( $args );
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

	public function prepare( $query, ...$args ) {
		$this->last_query = $query;
		return vsprintf( str_replace( array( '%i', '%s', '%d' ), array( '%s', '%s', '%d' ), $query ), $args );
	}
	public function get_var( $query ) {
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
require_once __DIR__ . '/../includes/class-admin.php';
require_once __DIR__ . '/../includes/class-importer.php';
