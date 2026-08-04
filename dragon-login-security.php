<?php
/**
 * Plugin Name: Dragon Login Security
 * Plugin URI: https://dragoncore.ltd/plugins/dragon-login-security
 * Description: Brute-force protection and modern two-factor authentication (authenticator apps, backup codes, and passkeys) for WordPress. Feeds Dragon Activity Log when installed.
 * Version: 1.0.0
 * Requires at least: 6.2
 * Requires PHP: 8.0
 * Author: Dragon Core
 * Author URI: https://dragoncore.ltd
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: dragon-login-security
 * Domain Path: /languages
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Namespaced constants; 3-letter prefix is the plugin standard.
define( 'DLS_VERSION', '1.0.0' );
define( 'DLS_PLUGIN_FILE', __FILE__ );
define( 'DLS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'DLS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'DLS_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound

// Composer autoloader (vendored lbuchs/webauthn).
if ( file_exists( DLS_PLUGIN_DIR . 'vendor/autoload.php' ) ) {
	require_once DLS_PLUGIN_DIR . 'vendor/autoload.php';
}

require_once DLS_PLUGIN_DIR . 'includes/class-crypto.php';
require_once DLS_PLUGIN_DIR . 'includes/class-ip.php';
require_once DLS_PLUGIN_DIR . 'includes/providers/class-provider-totp.php';
require_once DLS_PLUGIN_DIR . 'includes/providers/class-provider-backup-codes.php';
require_once DLS_PLUGIN_DIR . 'includes/class-credentials.php';
require_once DLS_PLUGIN_DIR . 'includes/class-webauthn.php';
require_once DLS_PLUGIN_DIR . 'includes/providers/class-provider-passkey.php';
require_once DLS_PLUGIN_DIR . 'includes/class-limit-login.php';
require_once DLS_PLUGIN_DIR . 'includes/class-plugin.php';

/**
 * Activation: create tables, seed options, schedule cron.
 */
function dls_activate(): void {
	Plugin::get_instance()->activate();
}
register_activation_hook( __FILE__, __NAMESPACE__ . '\dls_activate' );

/**
 * Deactivation: clear scheduled cron.
 */
function dls_deactivate(): void {
	Plugin::get_instance()->deactivate();
}
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\dls_deactivate' );

/**
 * Boot the plugin.
 */
function dls_init(): void {
	Plugin::get_instance();
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\dls_init' );
