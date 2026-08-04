<?php
/**
 * Two-factor enrolment section on the user profile.
 *
 * @package DragonLoginSecurity
 * @var \WP_User $dragonloginsecurity_user
 * @var bool     $dragonloginsecurity_totp_on
 * @var array    $dragonloginsecurity_passkeys
 * @var int      $dragonloginsecurity_backup_n
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h2 id="dls-2fa"><?php esc_html_e( 'Login Security (Two-Factor)', 'dragon-login-security' ); ?></h2>
<table class="form-table dls-2fa" role="presentation" data-user="<?php echo esc_attr( (string) $dragonloginsecurity_user->ID ); ?>">
	<tr>
		<th scope="row"><?php esc_html_e( 'Passkeys', 'dragon-login-security' ); ?></th>
		<td>
			<ul id="dls-passkey-list">
				<?php foreach ( $dragonloginsecurity_passkeys as $dragonloginsecurity_pk ) : ?>
					<li data-id="<?php echo esc_attr( (string) $dragonloginsecurity_pk['id'] ); ?>">
						<?php echo esc_html( $dragonloginsecurity_pk['label'] ); ?>
						<span class="dls-muted"><?php echo esc_html( $dragonloginsecurity_pk['created_at'] ); ?></span>
						<button type="button" class="button-link dls-remove-passkey"><?php esc_html_e( 'Remove', 'dragon-login-security' ); ?></button>
					</li>
				<?php endforeach; ?>
			</ul>
			<button type="button" class="button" id="dls-add-passkey"><?php esc_html_e( 'Add a passkey', 'dragon-login-security' ); ?></button>
			<p class="description"><?php esc_html_e( 'A passkey lets you sign in with your device (Face ID, Touch ID, Windows Hello, or a security key) instead of a code.', 'dragon-login-security' ); ?></p>
		</td>
	</tr>
	<tr>
		<th scope="row"><?php esc_html_e( 'Authenticator app (TOTP)', 'dragon-login-security' ); ?></th>
		<td>
			<?php if ( $dragonloginsecurity_totp_on ) : ?>
				<p><span class="dls-on"><?php esc_html_e( 'Enabled', 'dragon-login-security' ); ?></span>
					<button type="button" class="button dls-totp-disable"><?php esc_html_e( 'Disable', 'dragon-login-security' ); ?></button>
				</p>
			<?php else : ?>
				<button type="button" class="button" id="dls-totp-setup"><?php esc_html_e( 'Set up authenticator app', 'dragon-login-security' ); ?></button>
				<div id="dls-totp-panel" style="display:none;margin-top:10px;">
					<p><?php esc_html_e( 'Add this key to your authenticator app (Google Authenticator, 1Password, Authy…):', 'dragon-login-security' ); ?></p>
					<p><code id="dls-totp-secret"></code></p>
					<p><a id="dls-totp-link" href="#"><?php esc_html_e( 'Open in your authenticator app', 'dragon-login-security' ); ?></a></p>
					<p>
						<label for="dls-totp-code"><?php esc_html_e( 'Enter the 6-digit code to confirm:', 'dragon-login-security' ); ?></label>
						<input type="text" id="dls-totp-code" inputmode="numeric" class="small-text">
						<button type="button" class="button button-primary" id="dls-totp-confirm"><?php esc_html_e( 'Confirm', 'dragon-login-security' ); ?></button>
						<span id="dls-totp-msg"></span>
					</p>
				</div>
			<?php endif; ?>
		</td>
	</tr>
	<tr>
		<th scope="row"><?php esc_html_e( 'Backup codes', 'dragon-login-security' ); ?></th>
		<td>
			<p class="dls-muted">
				<?php
				/* translators: %d: number of remaining codes. */
				echo esc_html( sprintf( _n( '%d unused code remaining.', '%d unused codes remaining.', $dragonloginsecurity_backup_n, 'dragon-login-security' ), $dragonloginsecurity_backup_n ) );
				?>
			</p>
			<button type="button" class="button" id="dls-backup-generate"><?php esc_html_e( 'Generate new backup codes', 'dragon-login-security' ); ?></button>
			<div id="dls-backup-panel" style="display:none;margin-top:10px;">
				<pre id="dls-backup-codes" style="background:#f6f7f7;padding:12px;border-radius:4px;"></pre>
				<button type="button" class="button button-primary" id="dls-backup-download"><?php esc_html_e( 'Download codes', 'dragon-login-security' ); ?></button>
			</div>
			<p class="description"><?php esc_html_e( 'Backup codes let you sign in if you lose your passkey or phone. Keep them somewhere safe.', 'dragon-login-security' ); ?></p>
		</td>
	</tr>
</table>
