<?php
/**
 * Interim two-factor challenge screen (rendered inside the WordPress login flow).
 *
 * @package DragonLoginSecurity
 * @var array $dragonloginsecurity_ctx user, token, redirect, remember, error, methods, wa_args
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

<form name="dls_2fa_form" id="dls_2fa_form" action="<?php echo esc_url( site_url( 'wp-login.php?action=dls_2fa', 'login_post' ) ); ?>" method="post">
	<input type="hidden" name="dls_token" value="<?php echo esc_attr( $dragonloginsecurity_c['token'] ); ?>">
	<input type="hidden" name="dls_user" value="<?php echo esc_attr( (string) $dragonloginsecurity_c['user']->ID ); ?>">
	<input type="hidden" name="dls_method" id="dls_method" value="<?php echo esc_attr( $dragonloginsecurity_has( 'totp' ) ? 'totp' : 'backup' ); ?>">
	<input type="hidden" name="redirect_to" value="<?php echo esc_url( $dragonloginsecurity_c['redirect'] ); ?>">
	<input type="hidden" name="rememberme" value="<?php echo $dragonloginsecurity_c['remember'] ? 'forever' : ''; ?>">

	<?php if ( $dragonloginsecurity_has( 'passkey' ) ) : ?>
		<p style="margin-bottom:16px;">
			<button type="button" id="dls-passkey-btn" class="button button-primary button-large" style="width:100%;">
				<?php esc_html_e( 'Use a passkey', 'dragon-login-security' ); ?>
			</button>
		</p>
		<p style="text-align:center;color:#646970;"><?php esc_html_e( '— or —', 'dragon-login-security' ); ?></p>
		<!-- WebAuthn assertion fields, filled by JS -->
		<input type="hidden" name="dls_wa_token" id="dls_wa_token" value="<?php echo esc_attr( $dragonloginsecurity_c['wa_args']['token'] ); ?>">
		<input type="hidden" name="dls_wa_id" id="dls_wa_id" value="">
		<input type="hidden" name="dls_wa_client" id="dls_wa_client" value="">
		<input type="hidden" name="dls_wa_auth" id="dls_wa_auth" value="">
		<input type="hidden" name="dls_wa_sig" id="dls_wa_sig" value="">
	<?php endif; ?>

	<?php if ( $dragonloginsecurity_has( 'totp' ) || $dragonloginsecurity_has( 'backup' ) ) : ?>
		<p>
			<label for="dls_code"><?php esc_html_e( 'Authentication code', 'dragon-login-security' ); ?></label>
			<input type="text" name="dls_code" id="dls_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus>
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
</form>

<?php if ( $dragonloginsecurity_has( 'passkey' ) && ! empty( $dragonloginsecurity_c['wa_args']['args'] ) ) : ?>
<script>
( function () {
	var opts = <?php echo wp_json_encode( $dragonloginsecurity_c['wa_args']['args'] ); ?>;
	function b64urlToBuf( s ) {
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
	btn.addEventListener( 'click', function () {
		var pk = opts.publicKey;
		pk.challenge = b64urlToBuf( pk.challenge );
		( pk.allowCredentials || [] ).forEach( function ( c ) { c.id = b64urlToBuf( c.id ); } );
		navigator.credentials.get( { publicKey: pk } ).then( function ( cred ) {
			document.getElementById( 'dls_method' ).value = 'passkey';
			document.getElementById( 'dls_wa_id' ).value = bufToB64url( cred.rawId );
			document.getElementById( 'dls_wa_client' ).value = bufToB64( cred.response.clientDataJSON );
			document.getElementById( 'dls_wa_auth' ).value = bufToB64( cred.response.authenticatorData );
			document.getElementById( 'dls_wa_sig' ).value = bufToB64( cred.response.signature );
			document.getElementById( 'dls_2fa_form' ).submit();
		} ).catch( function () {} );
	} );
	var back = document.getElementById( 'dls-use-backup' );
	if ( back ) {
		back.addEventListener( 'click', function ( e ) {
			e.preventDefault();
			document.getElementById( 'dls_method' ).value = 'backup';
			document.getElementById( 'dls_code' ).placeholder = 'xxxxx-xxxxx';
		} );
	}
} )();
</script>
<?php endif; ?>

<?php
login_footer( 'dls_code' );
