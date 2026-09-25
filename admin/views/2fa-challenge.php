<?php
/**
 * Interim two-factor challenge screen (rendered inside the WordPress login flow).
 *
 * @package DragonLoginSecurity
 * @var array $dragonloginsecurity_ctx user, token, redirect, remember, error, methods, wa_args, interim, network_sites
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$dragonloginsecurity_ctx = isset( $dragonloginsecurity_ctx ) ? $dragonloginsecurity_ctx : array();
$dragonloginsecurity_c   = $dragonloginsecurity_ctx;
$dragonloginsecurity_has = static function ( $m ) use ( $dragonloginsecurity_c ) {
	return in_array( $m, $dragonloginsecurity_c['methods'], true );
};

login_header( __( 'Two-Factor Authentication', 'dragon-login-security' ) );
?>
<?php if ( ! empty( $dragonloginsecurity_c['error'] ) ) : ?>
	<div id="login_error"><?php echo esc_html( $dragonloginsecurity_c['error'] ); ?></div>
<?php endif; ?>

<form name="dragonloginsecurity_2fa_form" id="dragonloginsecurity_2fa_form" action="<?php echo esc_url( site_url( 'wp-login.php?action=dragonloginsecurity_2fa', 'login_post' ) ); ?>" method="post">
	<input type="hidden" name="dragonloginsecurity_token" value="<?php echo esc_attr( $dragonloginsecurity_c['token'] ); ?>">
	<input type="hidden" name="dragonloginsecurity_user" value="<?php echo esc_attr( (string) $dragonloginsecurity_c['user']->ID ); ?>">
	<input type="hidden" name="dragonloginsecurity_method" id="dragonloginsecurity_method" value="<?php echo esc_attr( $dragonloginsecurity_has( 'totp' ) ? 'totp' : 'backup' ); ?>">
	<input type="hidden" name="redirect_to" value="<?php echo esc_url( $dragonloginsecurity_c['redirect'] ); ?>">
	<input type="hidden" name="rememberme" value="<?php echo $dragonloginsecurity_c['remember'] ? 'forever' : ''; ?>">
	<?php if ( ! empty( $dragonloginsecurity_c['interim'] ) ) : ?>
		<input type="hidden" name="interim-login" value="1">
	<?php endif; ?>

	<?php if ( $dragonloginsecurity_has( 'passkey' ) ) : ?>
		<p style="margin-bottom:16px;">
			<button type="button" id="dls-passkey-btn" class="button button-primary button-large" style="width:100%;">
				<?php esc_html_e( 'Use a passkey', 'dragon-login-security' ); ?>
			</button>
		</p>
		<?php if ( $dragonloginsecurity_has( 'totp' ) || $dragonloginsecurity_has( 'backup' ) ) : ?>
			<p style="text-align:center;color:#646970;"><?php esc_html_e( '- or -', 'dragon-login-security' ); ?></p>
		<?php endif; ?>
		<!-- WebAuthn assertion fields, filled by JS -->
		<input type="hidden" name="dragonloginsecurity_wa_token" id="dragonloginsecurity_wa_token" value="<?php echo esc_attr( $dragonloginsecurity_c['wa_args']['token'] ); ?>">
		<input type="hidden" name="dragonloginsecurity_wa_id" id="dragonloginsecurity_wa_id" value="">
		<input type="hidden" name="dragonloginsecurity_wa_client" id="dragonloginsecurity_wa_client" value="">
		<input type="hidden" name="dragonloginsecurity_wa_auth" id="dragonloginsecurity_wa_auth" value="">
		<input type="hidden" name="dragonloginsecurity_wa_sig" id="dragonloginsecurity_wa_sig" value="">
	<?php endif; ?>

	<?php if ( empty( $dragonloginsecurity_c['methods'] ) && ! empty( $dragonloginsecurity_c['network_sites'] ) ) : ?>
		<p><?php esc_html_e( 'Your passkey is registered on another site in this network, and this site cannot check it. Sign in there with your passkey:', 'dragon-login-security' ); ?></p>
		<ul style="margin:0 0 16px 18px;list-style:disc;">
			<?php foreach ( $dragonloginsecurity_c['network_sites'] as $dragonloginsecurity_site ) : ?>
				<li>
					<a href="<?php echo esc_url( $dragonloginsecurity_site['login_url'] ); ?>"><?php echo esc_html( $dragonloginsecurity_site['name'] ); ?></a>
					- <?php echo $dragonloginsecurity_site['shares_cookies'] ? esc_html__( 'signing in there also signs you in here', 'dragon-login-security' ) : esc_html__( 'this site does not share its sign-in', 'dragon-login-security' ); ?>
				</li>
			<?php endforeach; ?>
		</ul>
		<p><?php esc_html_e( 'If this site still asks for a second factor, add an authenticator app or create backup codes from your profile on that site - they work on every site in this network. Otherwise, ask an administrator to reset your two-factor settings.', 'dragon-login-security' ); ?></p>
	<?php elseif ( empty( $dragonloginsecurity_c['methods'] ) ) : ?>
		<p><?php esc_html_e( 'No usable second factor is available for this account right now. Ask an administrator to reset your two-factor settings.', 'dragon-login-security' ); ?></p>
	<?php endif; ?>

	<?php if ( $dragonloginsecurity_has( 'totp' ) || $dragonloginsecurity_has( 'backup' ) ) : ?>
		<p>
			<label for="dragonloginsecurity_code"><?php esc_html_e( 'Authentication code', 'dragon-login-security' ); ?></label>
			<input type="text" name="dragonloginsecurity_code" id="dragonloginsecurity_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus>
		</p>
		<?php if ( $dragonloginsecurity_has( 'totp' ) && $dragonloginsecurity_has( 'backup' ) ) : ?>
			<p style="font-size:12px;">
				<a href="#" id="dls-use-backup"><?php esc_html_e( 'Use a backup code instead', 'dragon-login-security' ); ?></a>
			</p>
		<?php endif; ?>
		<p class="submit">
			<button type="submit" class="button button-primary button-large" style="width:100%;"><?php esc_html_e( 'Verify', 'dragon-login-security' ); ?></button>
		</p>
	<?php endif; ?>

	<?php
	/**
	 * Fires inside the 2FA challenge form. Add-ons use this to inject an opt-in
	 * field such as "remember this device".
	 *
	 * @param \WP_User $user The user being challenged.
	 */
	do_action( 'dragonloginsecurity_challenge_form', $dragonloginsecurity_c['user'] );
	?>
</form>

<?php if ( $dragonloginsecurity_has( 'passkey' ) && ! empty( $dragonloginsecurity_c['wa_args']['args'] ) ) : ?>
<script>
( function () {
	var opts = <?php echo wp_json_encode( $dragonloginsecurity_c['wa_args']['args'], JSON_HEX_TAG | JSON_HEX_AMP ); ?>;
	function b64urlToBuf( s ) {
		var m = /^=\?BINARY\?B\?(.*)\?=$/.exec( s );
		if ( m ) { s = m[ 1 ]; }
		s = s.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( s.length % 4 ) { s += '='; }
		var bin = atob( s ), buf = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) { buf[ i ] = bin.charCodeAt( i ); }
		return buf.buffer;
	}
	function bufToB64( b ) {
		var bytes = new Uint8Array( b ), s = '';
		for ( var i = 0; i < bytes.length; i++ ) { s += String.fromCharCode( bytes[ i ] ); }
		return btoa( s );
	}
	function bufToB64url( b ) {
		return bufToB64( b ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}
	var btn = document.getElementById( 'dls-passkey-btn' );
	if ( ! btn || ! window.PublicKeyCredential ) { return; }
	// Decode once, so a cancelled prompt can be retried.
	var pk = opts.publicKey;
	try {
		pk.challenge = b64urlToBuf( pk.challenge );
		( pk.allowCredentials || [] ).forEach( function ( c ) { c.id = b64urlToBuf( c.id ); } );
	} catch ( e ) {
		btn.disabled = true;
		return;
	}
	btn.addEventListener( 'click', function () {
		navigator.credentials.get( { publicKey: pk } ).then( function ( cred ) {
			document.getElementById( 'dragonloginsecurity_method' ).value = 'passkey';
			document.getElementById( 'dragonloginsecurity_wa_id' ).value = bufToB64url( cred.rawId );
			document.getElementById( 'dragonloginsecurity_wa_client' ).value = bufToB64( cred.response.clientDataJSON );
			document.getElementById( 'dragonloginsecurity_wa_auth' ).value = bufToB64( cred.response.authenticatorData );
			document.getElementById( 'dragonloginsecurity_wa_sig' ).value = bufToB64( cred.response.signature );
			document.getElementById( 'dragonloginsecurity_2fa_form' ).submit();
		} ).catch( function () {} );
	} );
} )();
</script>
<?php endif; ?>

<?php if ( $dragonloginsecurity_has( 'totp' ) && $dragonloginsecurity_has( 'backup' ) ) : ?>
<script>
// The "use a backup code instead" switch, printed whenever both an authenticator
// and backup codes are available - including when there is no passkey, so the
// script block above does not run.
( function () {
	var back = document.getElementById( 'dls-use-backup' );
	if ( ! back ) { return; }
	back.addEventListener( 'click', function ( e ) {
		e.preventDefault();
		document.getElementById( 'dragonloginsecurity_method' ).value = 'backup';
		document.getElementById( 'dragonloginsecurity_code' ).placeholder = 'xxxxx-xxxxx';
	} );
} )();
</script>
<?php endif; ?>

<?php
login_footer( 'dragonloginsecurity_code' );
