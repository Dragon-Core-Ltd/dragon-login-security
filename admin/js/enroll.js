/* global jQuery, dlsEnroll */
( function ( $ ) {
	'use strict';

	var $root = $( '.dls-2fa' );
	var userId = $root.data( 'user' );

	function post( action, data ) {
		return $.post( dlsEnroll.ajaxUrl, $.extend( { action: action, nonce: dlsEnroll.nonce, user_id: userId }, data || {} ) );
	}

	function text( key, fallback ) {
		return ( dlsEnroll.i18n && dlsEnroll.i18n[ key ] ) || fallback;
	}

	// Show the server's message for a failed response, or a generic one.
	function showError( res, $target ) {
		var msg = res && res.data && res.data.message ? res.data.message : text( 'requestFailed', dlsEnroll.i18n.passkeyError );
		if ( $target && $target.length ) {
			$target.text( msg );
		} else {
			window.alert( msg );
		}
	}

	// The request itself failed (network down, session expired, server error).
	function onFail( $target ) {
		return function ( xhr ) {
			var res = xhr && xhr.responseJSON;
			if ( res && res.data && res.data.message ) {
				showError( res, $target );
				return;
			}
			showError( { data: { message: text( 'networkError', dlsEnroll.i18n.passkeyError ) } }, $target );
		};
	}

	// Binary fields arrive base64url-encoded; the "=?BINARY?B?...?=" wrapper
	// (plain base64) is accepted too.
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

	// --- Passkey registration ---
	$( '#dls-add-passkey' ).on( 'click', function () {
		if ( ! window.PublicKeyCredential ) { window.alert( dlsEnroll.i18n.passkeyError ); return; }
		post( 'dragonloginsecurity_passkey_options' ).done( function ( res ) {
			if ( ! res || ! res.success ) { showError( res ); return; }
			var pk;
			try {
				pk = res.data.publicKey;
				pk.challenge = b64urlToBuf( pk.challenge );
				pk.user.id = b64urlToBuf( pk.user.id );
				( pk.excludeCredentials || [] ).forEach( function ( c ) { c.id = b64urlToBuf( c.id ); } );
			} catch ( e ) {
				window.alert( dlsEnroll.i18n.passkeyError );
				return;
			}
			navigator.credentials.create( { publicKey: pk } ).then( function ( cred ) {
				var transports = ( cred.response.getTransports && cred.response.getTransports() || [] ).join( ',' );
				post( 'dragonloginsecurity_passkey_register', {
					client_data: bufToB64( cred.response.clientDataJSON ),
					attestation: bufToB64( cred.response.attestationObject ),
					transports: transports
				} ).done( function ( r ) {
					if ( r && r.success ) { window.location.reload(); } else { window.alert( r && r.data && r.data.message ? r.data.message : dlsEnroll.i18n.passkeyError ); }
				} ).fail( onFail() );
			} ).catch( function () { window.alert( dlsEnroll.i18n.passkeyError ); } );
		} ).fail( onFail() );
	} );

	$root.on( 'click', '.dls-remove-passkey', function () {
		if ( ! window.confirm( dlsEnroll.i18n.confirmRemove ) ) { return; }
		var $li = $( this ).closest( 'li' );
		post( 'dragonloginsecurity_passkey_remove', { id: $li.data( 'id' ) } ).done( function ( r ) {
			if ( r && r.success ) { $li.remove(); } else { showError( r ); }
		} ).fail( onFail() );
	} );

	// --- TOTP ---
	$( '#dls-totp-setup' ).on( 'click', function () {
		post( 'dragonloginsecurity_totp_setup' ).done( function ( res ) {
			if ( ! res || ! res.success ) { showError( res ); return; }
			$( '#dls-totp-secret' ).text( res.data.secret );
			$( '#dls-totp-link' ).attr( 'href', res.data.uri );
			$( '#dls-totp-panel' ).show();
		} ).fail( onFail() );
	} );
	$( '#dls-totp-confirm' ).on( 'click', function () {
		var $msg = $( '#dls-totp-msg' );
		post( 'dragonloginsecurity_totp_confirm', { code: $( '#dls-totp-code' ).val() } ).done( function ( res ) {
			if ( ! res || ! res.success ) { showError( res, $msg ); return; }
			$msg.text( res.data && res.data.message ? res.data.message : '' );
			window.setTimeout( function () { window.location.reload(); }, 800 );
		} ).fail( onFail( $msg ) );
	} );
	$root.on( 'click', '.dls-totp-disable', function () {
		if ( ! window.confirm( dlsEnroll.i18n.confirmDisable ) ) { return; }
		post( 'dragonloginsecurity_totp_disable' ).done( function ( res ) {
			if ( res && res.success ) { window.location.reload(); } else { showError( res ); }
		} ).fail( onFail() );
	} );

	// --- Backup codes ---
	var lastCodes = [];
	$( '#dls-backup-generate' ).on( 'click', function () {
		if ( $( this ).attr( 'data-has-codes' ) && ! window.confirm( dlsEnroll.i18n.confirmRegen ) ) { return; }
		post( 'dragonloginsecurity_backup_generate' ).done( function ( res ) {
			if ( ! res || ! res.success ) { showError( res ); return; }
			lastCodes = res.data.codes;
			$( '#dls-backup-codes' ).text( dlsEnroll.i18n.saveCodes + '\n\n' + lastCodes.join( '\n' ) );
			$( '#dls-backup-panel' ).show();
		} ).fail( onFail() );
	} );
	$( '#dls-backup-download' ).on( 'click', function () {
		var blob = new Blob( [ lastCodes.join( '\n' ) + '\n' ], { type: 'text/plain' } );
		var a = document.createElement( 'a' );
		a.href = URL.createObjectURL( blob );
		a.download = 'backup-codes.txt';
		document.body.appendChild( a ); a.click(); document.body.removeChild( a );
		post( 'dragonloginsecurity_backup_confirm' ).done( function ( res ) {
			if ( ! res || ! res.success ) { showError( res ); }
		} ).fail( onFail() );
	} );
} )( jQuery );
