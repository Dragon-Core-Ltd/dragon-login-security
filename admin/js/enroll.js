/* global jQuery, dlsEnroll */
( function ( $ ) {
	'use strict';

	var $root = $( '.dls-2fa' );
	var userId = $root.data( 'user' );

	function post( action, data ) {
		return $.post( dlsEnroll.ajaxUrl, $.extend( { action: action, nonce: dlsEnroll.nonce, user_id: userId }, data || {} ) );
	}

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

	// --- Passkey registration ---
	$( '#dls-add-passkey' ).on( 'click', function () {
		if ( ! window.PublicKeyCredential ) { window.alert( dlsEnroll.i18n.passkeyError ); return; }
		post( 'dls_passkey_options' ).done( function ( res ) {
			if ( ! res.success ) { return; }
			var pk = res.data.publicKey;
			pk.challenge = b64urlToBuf( pk.challenge );
			pk.user.id = b64urlToBuf( pk.user.id );
			( pk.excludeCredentials || [] ).forEach( function ( c ) { c.id = b64urlToBuf( c.id ); } );
			navigator.credentials.create( { publicKey: pk } ).then( function ( cred ) {
				var transports = ( cred.response.getTransports && cred.response.getTransports() || [] ).join( ',' );
				post( 'dls_passkey_register', {
					client_data: bufToB64( cred.response.clientDataJSON ),
					attestation: bufToB64( cred.response.attestationObject ),
					transports: transports,
					label: 'Passkey (' + new Date().toLocaleDateString() + ')'
				} ).done( function ( r ) {
					if ( r.success ) { window.location.reload(); } else { window.alert( r.data.message ); }
				} );
			} ).catch( function () { window.alert( dlsEnroll.i18n.passkeyError ); } );
		} );
	} );

	$root.on( 'click', '.dls-remove-passkey', function () {
		if ( ! window.confirm( dlsEnroll.i18n.confirmRemove ) ) { return; }
		var $li = $( this ).closest( 'li' );
		post( 'dls_passkey_remove', { id: $li.data( 'id' ) } ).done( function ( r ) {
			if ( r.success ) { $li.remove(); }
		} );
	} );

	// --- TOTP ---
	$( '#dls-totp-setup' ).on( 'click', function () {
		post( 'dls_totp_setup' ).done( function ( res ) {
			if ( ! res.success ) { return; }
			$( '#dls-totp-secret' ).text( res.data.secret );
			$( '#dls-totp-link' ).attr( 'href', res.data.uri );
			$( '#dls-totp-panel' ).show();
		} );
	} );
	$( '#dls-totp-confirm' ).on( 'click', function () {
		post( 'dls_totp_confirm', { code: $( '#dls-totp-code' ).val() } ).done( function ( res ) {
			$( '#dls-totp-msg' ).text( res.data.message );
			if ( res.success ) { window.setTimeout( function () { window.location.reload(); }, 800 ); }
		} );
	} );
	$root.on( 'click', '.dls-totp-disable', function () {
		post( 'dls_totp_disable' ).done( function () { window.location.reload(); } );
	} );

	// --- Backup codes ---
	var lastCodes = [];
	$( '#dls-backup-generate' ).on( 'click', function () {
		post( 'dls_backup_generate' ).done( function ( res ) {
			if ( ! res.success ) { return; }
			lastCodes = res.data.codes;
			$( '#dls-backup-codes' ).text( dlsEnroll.i18n.saveCodes + '\n\n' + lastCodes.join( '\n' ) );
			$( '#dls-backup-panel' ).show();
		} );
	} );
	$( '#dls-backup-download' ).on( 'click', function () {
		var blob = new Blob( [ lastCodes.join( '\n' ) + '\n' ], { type: 'text/plain' } );
		var a = document.createElement( 'a' );
		a.href = URL.createObjectURL( blob );
		a.download = 'backup-codes.txt';
		document.body.appendChild( a ); a.click(); document.body.removeChild( a );
		post( 'dls_backup_confirm' );
	} );
} )( jQuery );
