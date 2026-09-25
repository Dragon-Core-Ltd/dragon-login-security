<?php
/**
 * Tables are created on a site's first request when missing, and on a new
 * network site when the plugin is network-active.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity\Tests;

use DragonLoginSecurity\Plugin;
use PHPUnit\Framework\TestCase;

class SiteInstallTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['dls_test_options']            = array();
		$GLOBALS['dls_test_option_write_fails'] = false;
		$GLOBALS['dls_test_transients']         = array();
		$GLOBALS['dls_test_dbdelta_calls']      = array();
		$GLOBALS['dls_test_multisite']          = true;
		$GLOBALS['dls_test_current_blog']       = 1;
		$GLOBALS['dls_test_blog_stack']         = array();
		$GLOBALS['dls_test_blog_options']       = array();
		$GLOBALS['dls_test_blog_transients']    = array();
		$GLOBALS['dls_test_network_active']     = array( DRAGONLOGINSECURITY_PLUGIN_BASENAME );
		$GLOBALS['wpdb']                        = new \DLS_Test_Wpdb();
	}

	protected function tearDown(): void {
		$GLOBALS['dls_test_multisite']       = false;
		$GLOBALS['dls_test_network_active']  = array();
		$GLOBALS['dls_test_current_blog']    = 1;
		$GLOBALS['dls_test_blog_stack']      = array();
		$GLOBALS['dls_test_blog_options']    = array();
		$GLOBALS['dls_test_blog_transients'] = array();
	}

	private function plugin(): Plugin {
		return ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
	}

	private static function site( int $id ): \WP_Site {
		return new \WP_Site( (object) array( 'blog_id' => (string) $id ) );
	}

	public function test_first_request_on_a_site_without_tables_creates_them(): void {
		$GLOBALS['dls_test_current_blog'] = 2;
		$GLOBALS['wpdb']->prefix          = 'wp_2_';
		$GLOBALS['wpdb']->existing_tables = array( 'wp_2_dls_credentials', 'wp_2_dls_lockouts' );

		$this->plugin()->maybe_install_site();

		$created = implode( "\n", $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertStringContainsString( 'CREATE TABLE wp_2_dls_lockouts ', $created );
		$this->assertSame( Plugin::DB_VERSION, get_option( 'dragonloginsecurity_db_version' ) );
	}

	public function test_installed_site_pays_no_schema_query(): void {
		// Stamped, with the day-long confirmation expired: the per-request check
		// must still not look at the tables.
		update_option( 'dragonloginsecurity_db_version', Plugin::DB_VERSION );

		$this->plugin()->maybe_install_site();

		$this->assertSame( 0, $GLOBALS['wpdb']->table_checks );
		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'] );
	}

	public function test_failed_creation_is_not_retried_on_every_request(): void {
		$this->plugin()->maybe_install_site();
		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertFalse( get_option( 'dragonloginsecurity_db_version' ) );

		$this->plugin()->maybe_install_site();
		$this->assertCount( 2, $GLOBALS['dls_test_dbdelta_calls'], 'Throttled until the retry window passes.' );
	}

	public function test_new_site_gets_its_tables_when_network_active(): void {
		$GLOBALS['wpdb']->existing_tables = array( 'wp_2_dls_credentials', 'wp_2_dls_lockouts' );

		$this->plugin()->install_new_site( self::site( 2 ) );

		$created = implode( "\n", $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertStringContainsString( 'CREATE TABLE wp_2_dls_credentials ', $created );
		$this->assertStringContainsString( 'CREATE TABLE wp_2_dls_lockouts ', $created );
		$this->assertStringNotContainsString( 'CREATE TABLE wp_dls_', $created );

		$this->assertSame( 1, get_current_blog_id(), 'The current site is restored.' );
		$this->assertSame( 'wp_', $GLOBALS['wpdb']->prefix );
		$this->assertSame( Plugin::DB_VERSION, $GLOBALS['dls_test_blog_options'][2]['dragonloginsecurity_db_version'] ?? null, 'The new site is stamped.' );
		$this->assertFalse( get_option( 'dragonloginsecurity_db_version' ), 'The main site is untouched.' );
	}

	public function test_new_site_is_left_alone_when_not_network_active(): void {
		$GLOBALS['dls_test_network_active'] = array();

		$this->plugin()->install_new_site( self::site( 2 ) );

		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'] );
		$this->assertSame( array(), $GLOBALS['dls_test_blog_stack'] );
	}

	public function test_non_site_argument_is_ignored(): void {
		$this->plugin()->install_new_site( (object) array( 'blog_id' => '2' ) );

		$this->assertSame( array(), $GLOBALS['dls_test_dbdelta_calls'] );
	}
}
