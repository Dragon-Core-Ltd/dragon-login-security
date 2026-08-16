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
		</table>
		<p><button type="submit" name="dragonloginsecurity_save_settings" class="button button-primary"><?php esc_html_e( 'Save Settings', 'dragon-login-security' ); ?></button></p>
	</form>
</div>
