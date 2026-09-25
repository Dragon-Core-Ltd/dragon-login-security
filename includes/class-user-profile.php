<?php
/**
 * Per-user two-factor enrolment on the profile screen.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the enrolment UI and enqueues its script.
 */
class User_Profile {

	/**
	 * Register hooks.
	 */
	public function hook(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_notices', array( $this, 'unusable_passkey_notice' ) );
	}

	/**
	 * Warn an admin whose account has passkeys that cannot be used because the
	 * WebAuthn library is not loaded, so a passkey is not silently treated as an
	 * active factor. Their passkey no longer counts as a second factor until the
	 * library returns; another factor should be set up.
	 */
	public function unusable_passkey_notice(): void {
		if ( WebAuthn::available() ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( $user_id <= 0 || ! Provider_Passkey::has_stored_credentials( $user_id ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'Your passkeys cannot be used to sign in on this site right now because passkey support is unavailable. Set up an authenticator app or backup codes so your account still has a second factor.', 'dragon-login-security' );
		echo '</p></div>';
	}

	/**
	 * Enqueue the enrolment script on profile pages.
	 *
	 * @param string $hook_suffix Current admin page.
	 */
	public function enqueue( string $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_style( 'dls-admin', DRAGONLOGINSECURITY_PLUGIN_URL . 'admin/css/admin.css', array(), DRAGONLOGINSECURITY_VERSION );
		wp_enqueue_script( 'dls-enroll', DRAGONLOGINSECURITY_PLUGIN_URL . 'admin/js/enroll.js', array( 'jquery' ), DRAGONLOGINSECURITY_VERSION, true );
		wp_localize_script(
			'dls-enroll',
			'dlsEnroll',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'dls_ajax' ),
				'i18n'    => array(
					'confirmRemove'  => __( 'Remove this passkey?', 'dragon-login-security' ),
					'confirmDisable' => __( 'Turn off your authenticator app? Your account will no longer ask for a code at sign-in.', 'dragon-login-security' ),
					'confirmRegen'   => __( 'Generate new backup codes? Your existing codes stop working immediately.', 'dragon-login-security' ),
					'passkeyError'   => __( 'Could not add passkey.', 'dragon-login-security' ),
					'saveCodes'      => __( 'Save these codes now - each works once and they will not be shown again.', 'dragon-login-security' ),
					'requestFailed'  => __( 'That did not work. Reload the page and try again.', 'dragon-login-security' ),
					'networkError'   => __( 'Could not reach the site. Check your connection, reload the page and try again.', 'dragon-login-security' ),
				),
			)
		);
	}

	/**
	 * Render the enrolment section.
	 *
	 * @param \WP_User $user The user being edited.
	 */
	public function render( $user ): void {
		if ( ! ( $user instanceof \WP_User ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$dragonloginsecurity_user     = $user;
		$dragonloginsecurity_is_self  = ( get_current_user_id() === $user->ID );
		$dragonloginsecurity_totp_on  = '' !== (string) get_user_meta( $user->ID, Two_Factor::TOTP_META, true );
		$dragonloginsecurity_passkeys = Credentials::for_user( $user->ID );
		$dragonloginsecurity_wa_ok    = WebAuthn::available();
		$dragonloginsecurity_backup_n = Provider_Backup_Codes::remaining( $user->ID );
		require DRAGONLOGINSECURITY_PLUGIN_DIR . 'admin/views/profile-2fa.php';
	}
}
