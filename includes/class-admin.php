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
		add_action( 'admin_notices', array( $this, 'library_notice' ) );
		add_action( 'admin_notices', array( $this, 'schema_notice' ) );
	}

	/**
	 * Tell administrators when the plugin's tables could not be created, so a
	 * missing CREATE privilege does not go unnoticed.
	 */
	public function schema_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$failure = get_option( Plugin::SCHEMA_FAILURE_OPTION );
		if ( ! is_array( $failure ) || empty( $failure['tables'] ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>';
		echo esc_html(
			sprintf(
				/* translators: 1: comma-separated table names, 2: UTC date and time of the last attempt */
				__( 'Dragon Login Security could not create its database tables (%1$s; last attempt %2$s UTC). Check that the database user has the CREATE privilege, then deactivate and reactivate the plugin to retry.', 'dragon-login-security' ),
				implode( ', ', array_map( 'strval', (array) $failure['tables'] ) ),
				gmdate( 'Y-m-d H:i', (int) ( $failure['time'] ?? 0 ) )
			)
		);
		echo '</p></div>';
	}

	/**
	 * Warn on the settings screen when the WebAuthn library is not loaded, so
	 * the administrator knows why passkeys are unavailable.
	 */
	public function library_notice(): void {
		if ( WebAuthn::available() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'settings_page_dragon-login-security' !== $screen->id ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		esc_html_e( 'Dragon Login Security: the bundled WebAuthn library (vendor/lbuchs/webauthn) is missing, so passkeys are unavailable. Authenticator apps and backup codes still work. Reinstall the plugin to restore passkeys.', 'dragon-login-security' );
		echo '</p></div>';
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
			'trust_proxy'     => isset( $_POST['trust_proxy'] ),
			'trusted_proxies' => $this->parse_proxies( isset( $_POST['trusted_proxies'] ) ? wp_unslash( $_POST['trusted_proxies'] ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed + validated line-by-line in parse_proxies().
			'allow_ips'       => $this->parse_ips( isset( $_POST['allow_ips'] ) ? wp_unslash( $_POST['allow_ips'] ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed + validated line-by-line in parse_ips().
			'deny_ips'        => $this->parse_ips( isset( $_POST['deny_ips'] ) ? wp_unslash( $_POST['deny_ips'] ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed + validated line-by-line in parse_ips().
		);
		$saved    = self::persist_settings( $settings );

		/*
		 * The uninstall preference is a separate option, so changing only the
		 * checkbox leaves the settings array comparing equal and its write
		 * counting as a success. update_option() also returns false for an
		 * unchanged value and stores a boolean as '1' or '', so the stored value
		 * is read back and compared as a boolean.
		 */
		$delete_data = isset( $_POST['dragonloginsecurity_delete_data'] );
		update_option( 'dragonloginsecurity_delete_data_on_uninstall', $delete_data );
		$delete_saved = (bool) get_option( 'dragonloginsecurity_delete_data_on_uninstall' ) === $delete_data;

		self::record_save_result( $saved, $delete_saved );
		wp_safe_redirect( admin_url( 'options-general.php?page=dragon-login-security' ) );
		exit;
	}

	/**
	 * Store the outcome of a settings save for the notice shown after redirect.
	 *
	 * The two writes are reported separately so a partial save is described as
	 * one, rather than the settings result standing in for both.
	 *
	 * @param bool $saved        Whether the settings were confirmed stored.
	 * @param bool $delete_saved Whether the uninstall preference was confirmed stored.
	 */
	public static function record_save_result( bool $saved, bool $delete_saved = true ): void {
		if ( ! $saved ) {
			$message = __( 'Settings could not be saved. Your previous settings are still in effect; try again.', 'dragon-login-security' );
		} elseif ( ! $delete_saved ) {
			$message = __( 'Settings saved, but the "delete data on uninstall" preference could not be stored and is unchanged. Try again.', 'dragon-login-security' );
		} else {
			$message = __( 'Settings saved.', 'dragon-login-security' );
		}

		set_transient(
			'dragonloginsecurity_settings_notice',
			array(
				'type'    => $saved && $delete_saved ? 'success' : 'error',
				'message' => $message,
			),
			60
		);
	}

	/**
	 * Write the settings option and confirm the stored value. update_option()
	 * returns false both on failure and when nothing changed, so the outcome
	 * is judged by reading the option back.
	 *
	 * @param array $settings Full settings array.
	 * @return bool Whether the option now holds exactly these settings.
	 */
	public static function persist_settings( array $settings ): bool {
		update_option( 'dragonloginsecurity_settings', $settings, false );
		return get_option( 'dragonloginsecurity_settings' ) === $settings;
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
	 * Parse a textarea of trusted proxy addresses (bare IP or CIDR) into a
	 * validated list.
	 *
	 * @param string $raw Textarea contents.
	 * @return string[]
	 */
	private function parse_proxies( $raw ): array {
		$out = array();
		foreach ( preg_split( '/[\r\n]+/', (string) $raw ) as $line ) {
			$entry = trim( sanitize_text_field( $line ) );
			if ( '' === $entry ) {
				continue;
			}

			if ( false !== strpos( $entry, '/' ) ) {
				list( $subnet, $bits ) = explode( '/', $entry, 2 );
				if ( ! ctype_digit( $bits ) ) {
					continue;
				}
				$bits = (int) $bits;
				if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					$max = 32;
				} elseif ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
					$max = 128;
				} else {
					continue;
				}
				if ( $bits >= 0 && $bits <= $max ) {
					$out[] = $subnet . '/' . $bits;
				}
			} elseif ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
				$out[] = $entry;
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
