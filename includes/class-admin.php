<?php
/**
 * Settings page: Settings → Login Security.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders and saves the login-security settings.
 */
class Admin {

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_init', array( $this, 'maybe_save' ) );
		add_filter( 'plugin_action_links_' . DRAGONLOGINSECURITY_PLUGIN_BASENAME, array( $this, 'action_links' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	/**
	 * Enqueue the Dragon design system on the settings screen.
	 *
	 * @param string $hook_suffix Current admin page.
	 */
	public function enqueue( string $hook_suffix ): void {
		if ( 'settings_page_dragon-login-security' !== $hook_suffix ) {
			return;
		}
		wp_enqueue_style( 'dragon-login-security-dragon-ui', DRAGONLOGINSECURITY_PLUGIN_URL . 'admin/css/dragon-ui.css', array(), DRAGONLOGINSECURITY_VERSION );
	}

	/**
	 * Add the settings page.
	 */
	public function menu(): void {
		add_options_page(
			__( 'Dragon Login Security', 'dragon-login-security' ),
			__( 'Login Security', 'dragon-login-security' ),
			'manage_options',
			'dragon-login-security',
			array( $this, 'render' )
		);
	}

	/**
	 * Settings link on the plugin row.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function action_links( array $links ): array {
		$link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=dragon-login-security' ) ),
			esc_html__( 'Settings', 'dragon-login-security' )
		);
		array_unshift( $links, $link );
		return $links;
	}

	/**
	 * Save the settings form.
	 */
	public function maybe_save(): void {
		if ( ! isset( $_POST['dragonloginsecurity_save_settings'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'dragonloginsecurity_settings' );

		$settings = array(
			'trust_proxy' => isset( $_POST['trust_proxy'] ),
			'allow_ips'   => $this->parse_ips( isset( $_POST['allow_ips'] ) ? wp_unslash( $_POST['allow_ips'] ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed + validated line-by-line in parse_ips().
			'deny_ips'    => $this->parse_ips( isset( $_POST['deny_ips'] ) ? wp_unslash( $_POST['deny_ips'] ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed + validated line-by-line in parse_ips().
		);
		update_option( 'dragonloginsecurity_settings', $settings, false );
		update_option( 'dragonloginsecurity_delete_data_on_uninstall', isset( $_POST['dragonloginsecurity_delete_data'] ) );

		add_settings_error( 'dls', 'saved', __( 'Settings saved.', 'dragon-login-security' ), 'updated' );
		set_transient( 'settings_errors', get_settings_errors(), 30 );
		wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'options-general.php?page=dragon-login-security' ) ) );
		exit;
	}

	/**
	 * Parse a textarea of IPs into a validated list.
	 *
	 * @param string $raw Textarea contents.
	 * @return string[]
	 */
	private function parse_ips( $raw ): array {
		$out = array();
		foreach ( preg_split( '/[\r\n]+/', (string) $raw ) as $line ) {
			$ip = trim( sanitize_text_field( $line ) );
			if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$out[] = $ip;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Render the settings page.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$dragonloginsecurity_settings = get_option( 'dragonloginsecurity_settings', array() );
		$dragonloginsecurity_settings = is_array( $dragonloginsecurity_settings ) ? $dragonloginsecurity_settings : array();
		require DRAGONLOGINSECURITY_PLUGIN_DIR . 'admin/views/settings.php';
	}
}
