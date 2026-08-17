<?php
/**
 * Login Security settings view.
 *
 * @package DragonLoginSecurity
 * @var array $dragonloginsecurity_settings
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$dragonloginsecurity_s     = $dragonloginsecurity_settings;
$dragonloginsecurity_allow = ! empty( $dragonloginsecurity_s['allow_ips'] ) ? implode( "\n", (array) $dragonloginsecurity_s['allow_ips'] ) : '';
$dragonloginsecurity_deny  = ! empty( $dragonloginsecurity_s['deny_ips'] ) ? implode( "\n", (array) $dragonloginsecurity_s['deny_ips'] ) : '';
?>
<div class="wrap dragon-ui">
	<h1 class="dragon-title"><span class="dragon-mark" aria-hidden="true"></span><?php esc_html_e( 'Dragon Login Security', 'dragon-login-security' ); ?></h1>

	<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice flag. ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'dragon-login-security' ); ?></p></div>
	<?php endif; ?>

	<p class="description">
		<?php esc_html_e( 'Brute-force protection is always on (escalating lockout after repeated failed logins). Two-factor authentication is set up per user on each user\'s profile.', 'dragon-login-security' ); ?>
	</p>

	<form method="post">
		<?php wp_nonce_field( 'dragonloginsecurity_settings' ); ?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Never lock out these IPs', 'dragon-login-security' ); ?></th>
				<td>
					<textarea name="allow_ips" rows="4" class="large-text code" placeholder="203.0.113.10"><?php echo esc_textarea( $dragonloginsecurity_allow ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One IP per line. These IPs are never counted or locked out (e.g. your office).', 'dragon-login-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Always block these IPs', 'dragon-login-security' ); ?></th>
				<td>
					<textarea name="deny_ips" rows="4" class="large-text code" placeholder="198.51.100.23"><?php echo esc_textarea( $dragonloginsecurity_deny ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One IP per line. These IPs cannot log in at all.', 'dragon-login-security' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Proxy headers', 'dragon-login-security' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="trust_proxy" <?php checked( ! empty( $dragonloginsecurity_s['trust_proxy'] ) ); ?>>
						<?php esc_html_e( 'Trust X-Forwarded-For for the client IP', 'dragon-login-security' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Only enable this if your site is behind a trusted reverse proxy or load balancer. Otherwise attackers can spoof their IP.', 'dragon-login-security' ); ?></p>
				</td>
			</tr>
					<tr>
				<th scope="row"><?php esc_html_e( 'Delete all data on uninstall', 'dragon-login-security' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="dragonloginsecurity_delete_data" value="1" <?php checked( (bool) get_option( 'dragonloginsecurity_delete_data_on_uninstall' ) ); ?>>
						<?php esc_html_e( 'When the plugin is deleted, remove lockout history, passkeys, 2FA enrolments and settings. Leave off to keep them for a future reinstall.', 'dragon-login-security' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<p><button type="submit" name="dragonloginsecurity_save_settings" class="button button-primary"><?php esc_html_e( 'Save Settings', 'dragon-login-security' ); ?></button></p>
	</form>
	<?php $dragonloginsecurity_import_notice = get_transient( 'dragonloginsecurity_import_notice' ); ?>
	<?php if ( $dragonloginsecurity_import_notice ) : ?>
		<?php delete_transient( 'dragonloginsecurity_import_notice' ); ?>
		<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $dragonloginsecurity_import_notice ); ?></p></div>
	<?php endif; ?>
	<?php $dragonloginsecurity_sources = \DragonLoginSecurity\Importer::detect(); ?>
	<?php if ( ! empty( $dragonloginsecurity_sources ) ) : ?>
		<div class="dragon-card" style="margin-top:16px;max-width:640px;">
			<h2 style="margin-top:0;"><?php esc_html_e( 'Import from another plugin', 'dragon-login-security' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Carry your allow and deny IP lists over in one click. Nothing is removed from the other plugin.', 'dragon-login-security' ); ?></p>
			<?php foreach ( $dragonloginsecurity_sources as $dragonloginsecurity_src => $dragonloginsecurity_src_label ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px;">
					<?php wp_nonce_field( 'dragonloginsecurity_import' ); ?>
					<input type="hidden" name="action" value="dragonloginsecurity_import">
					<input type="hidden" name="source" value="<?php echo esc_attr( $dragonloginsecurity_src ); ?>">
					<button type="submit" class="button">
						<?php
						/* translators: %s: source plugin name */
						printf( esc_html__( 'Import from %s', 'dragon-login-security' ), esc_html( $dragonloginsecurity_src_label ) );
						?>
					</button>
				</form>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>
</div>
