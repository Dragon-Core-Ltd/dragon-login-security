<?php
/**
 * Passkey (WebAuthn) second-factor provider. Delegates the ceremony to the
 * WebAuthn wrapper; a user is "enrolled" once they have at least one credential.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Passkey provider.
 */
class Provider_Passkey {

	/**
	 * Whether a user has at least one passkey this site can actually use as a
	 * second factor. A stored passkey is not a usable factor when the WebAuthn
	 * library is unavailable (e.g. a build shipped without vendor/): counting it
	 * would leave the user facing a challenge with no method they can complete.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_enrolled( int $user_id ): bool {
		if ( ! WebAuthn::available() ) {
			return false;
		}
		return ! empty( Credentials::for_user( $user_id ) );
	}

	/**
	 * Whether a user has passkey credentials stored on this site, regardless of
	 * whether the WebAuthn library is currently loaded. Used to warn when a
	 * passkey user's factor has become unusable, never to gate a challenge.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function has_stored_credentials( int $user_id ): bool {
		return ! empty( Credentials::for_user( $user_id ) );
	}

	/**
	 * Whether a user has a passkey on this site or, on a multisite network, on
	 * any site. Sign-in cookies can be valid across a network, so a passkey
	 * registered on one site means that account uses two-factor everywhere.
	 * The challenge itself still offers only this site's passkeys, which are the
	 * ones this site can verify.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_enrolled_on_network( int $user_id ): bool {
		if ( ! WebAuthn::available() ) {
			return false; // Not a usable factor here (see is_enrolled()).
		}
		if ( self::is_enrolled( $user_id ) ) {
			return true;
		}
		return is_multisite() && Credentials::user_has_any_on_network( $user_id );
	}

	/**
	 * Other sites on this network where the user has a passkey this plugin can
	 * verify, for the challenge screen's "no usable second factor" guidance.
	 * Display only: nothing here is a factor, and the challenge on this site
	 * still needs one of its own verified methods.
	 *
	 * @param int    $user_id   User id (already past the password step).
	 * @param string $return_to Where this site's sign-in was heading.
	 * @return array<int,array{name:string,login_url:string,shares_cookies:bool}>
	 */
	public static function other_network_sites( int $user_id, string $return_to ): array {
		if ( ! is_multisite() || ! WebAuthn::available() ) {
			return array();
		}
		$here = get_site( get_current_blog_id() );
		if ( ! $here ) {
			return array();
		}
		$return_to  = wp_validate_redirect( $return_to, admin_url() );
		$network_on = self::active_for_network();
		$sites      = array();
		foreach ( Credentials::network_site_ids_for_user( $user_id ) as $site_id ) {
			if ( (int) $here->blog_id === $site_id ) {
				continue;
			}
			$site = get_site( $site_id );
			if ( ! $site || ! empty( $site->archived ) || ! empty( $site->deleted ) || ! empty( $site->spam ) ) {
				continue;
			}
			if ( ! $network_on && ! in_array( self::basename(), (array) get_blog_option( $site_id, 'active_plugins', array() ), true ) ) {
				continue; // The plugin is off there, so the passkey would not be asked for.
			}
			$name    = trim( (string) get_blog_option( $site_id, 'blogname', '' ) );
			$sites[] = array(
				'name'           => '' !== $name ? $name : $site->domain . $site->path,
				'login_url'      => add_query_arg( 'redirect_to', rawurlencode( $return_to ), get_site_url( $site_id, 'wp-login.php', 'login' ) ),
				'shares_cookies' => self::cookie_reaches(
					self::cookie_domain(),
					defined( 'COOKIEPATH' ) ? (string) COOKIEPATH : '/',
					(string) $site->domain,
					(string) $here->domain,
					(string) $here->path
				),
			);
		}
		return $sites;
	}

	/**
	 * Whether a sign-in cookie set by the site on $from_host reaches this site.
	 * WordPress sets its cookies with COOKIE_DOMAIN (host-only when empty) and
	 * COOKIEPATH. A browser keeps a Domain cookie only when the setting host is
	 * inside that domain, and sends it only to hosts inside it.
	 *
	 * @param string $cookie_domain COOKIE_DOMAIN ('' when host-only).
	 * @param string $cookie_path   COOKIEPATH.
	 * @param string $from_host     Host of the site the user signs in on.
	 * @param string $to_host       Host of this site.
	 * @param string $to_path       Path of this site.
	 * @return bool
	 */
	public static function cookie_reaches( string $cookie_domain, string $cookie_path, string $from_host, string $to_host, string $to_path ): bool {
		$from_host = strtolower( rtrim( trim( $from_host ), '.' ) );
		$to_host   = strtolower( rtrim( trim( $to_host ), '.' ) );
		if ( '' === $from_host || '' === $to_host ) {
			return false;
		}
		$domain = strtolower( trim( trim( $cookie_domain ), '.' ) );
		if ( '' === $domain ) {
			$hosts_ok = $from_host === $to_host;
		} else {
			$inside   = static function ( string $host ) use ( $domain ): bool {
				return $host === $domain || str_ends_with( $host, '.' . $domain );
			};
			$hosts_ok = $inside( $from_host ) && $inside( $to_host );
		}
		$path = '/' . trim( $cookie_path, '/' );
		$path = '/' === $path ? '/' : $path . '/';
		$to   = '/' . ltrim( $to_path, '/' );
		$to   = str_ends_with( $to, '/' ) ? $to : $to . '/';
		return $hosts_ok && str_starts_with( $to, $path );
	}

	/**
	 * COOKIE_DOMAIN as a string ('' when host-only). Core defines it by the
	 * time a login screen renders: '.network-domain' on a subdomain network
	 * unless wp-config.php overrides it, false on a subdirectory network.
	 *
	 * @return string
	 */
	private static function cookie_domain(): string {
		return defined( 'COOKIE_DOMAIN' ) && is_string( COOKIE_DOMAIN ) ? COOKIE_DOMAIN : '';
	}

	/**
	 * This plugin's basename.
	 *
	 * @return string
	 */
	private static function basename(): string {
		return defined( 'DRAGONLOGINSECURITY_PLUGIN_BASENAME' ) ? (string) DRAGONLOGINSECURITY_PLUGIN_BASENAME : 'dragon-login-security/dragon-login-security.php';
	}

	/**
	 * Whether this plugin is network-activated.
	 *
	 * @return bool
	 */
	private static function active_for_network(): bool {
		return isset( ( (array) get_site_option( 'active_sitewide_plugins', array() ) )[ self::basename() ] );
	}

	/**
	 * Validate a passkey authentication response during a 2FA challenge.
	 *
	 * @param int   $user_id  User id.
	 * @param array $response Fields: token, credential_id, client_data, auth_data, signature.
	 * @return bool
	 */
	public static function validate( int $user_id, array $response ): bool {
		return WebAuthn::verify_authentication(
			$user_id,
			(string) ( $response['token'] ?? '' ),
			(string) ( $response['credential_id'] ?? '' ),
			(string) ( $response['client_data'] ?? '' ),
			(string) ( $response['auth_data'] ?? '' ),
			(string) ( $response['signature'] ?? '' )
		);
	}
}
