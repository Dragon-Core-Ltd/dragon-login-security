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
					'saveCodes'      => __( 'Save these codes now — each works once and they will not be shown again.', 'dragon-login-security' ),
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
		$dragonloginsecurity_backup_n = Provider_Backup_Codes::remaining( $user->ID );
		require DRAGONLOGINSECURITY_PLUGIN_DIR . 'admin/views/profile-2fa.php';
	}
}
