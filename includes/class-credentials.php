<?php
/**
 * Data access for registered passkeys (wp_dragonloginsecurity_credentials).
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CRUD over the passkey credential table.
 */
class Credentials {

	/**
	 * Add a credential.
	 *
	 * @param int    $user_id       User id.
	 * @param string $credential_id Base64url credential id.
	 * @param string $public_key    COSE/PEM public key.
	 * @param int    $sign_count    Initial signature counter.
	 * @param string $transports    Comma list of transports.
	 * @param string $label         Human label.
	 * @return int New row id (0 on failure).
	 */
	public static function add( int $user_id, string $credential_id, string $public_key, int $sign_count, string $transports, string $label ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table.
		$ok = $wpdb->insert(
			Plugin::credentials_table(),
			array(
				'user_id'       => $user_id,
				'credential_id' => $credential_id,
				'public_key'    => $public_key,
				'sign_count'    => $sign_count,
				'transports'    => mb_substr( $transports, 0, 255 ),
				'label'         => mb_substr( $label, 0, 191 ),
				'created_at'    => current_time( 'mysql', true ),
			),
			array( '%d', '%s', '%s', '%d', '%s', '%s', '%s' )
		);
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * All credentials for a user.
	 *
	 * @param int $user_id User id.
	 * @return array<int,array>
	 */
	public static function for_user( int $user_id ): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table read; results must be current.
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM %i WHERE user_id = %d ORDER BY id ASC', Plugin::credentials_table(), $user_id ),
			ARRAY_A
		);
		return $rows ? $rows : array();
	}

	/**
	 * Credential-id strings for a user (for allow/exclude lists).
	 *
	 * @param int $user_id User id.
	 * @return string[]
	 */
	public static function credential_ids_for_user( int $user_id ): array {
		return array_map(
			static function ( $row ) {
				return (string) $row['credential_id'];
			},
			self::for_user( $user_id )
		);
	}

	/**
	 * Look up a credential by its id.
	 *
	 * @param string $credential_id Base64url credential id.
	 * @return array|null
	 */
	public static function by_credential_id( string $credential_id ): ?array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table read; results must be current.
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE credential_id = %s', Plugin::credentials_table(), $credential_id ),
			ARRAY_A
		);
		return $row ? $row : null;
	}

	/**
	 * Update the signature counter and last-used time.
	 *
	 * @param int $id    Row id.
	 * @param int $count New sign count.
	 */
	public static function update_sign_count( int $id, int $count ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table.
		$wpdb->update(
			Plugin::credentials_table(),
			array(
				'sign_count'   => $count,
				'last_used_at' => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%d', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Delete a credential, scoped to its owner.
	 *
	 * @param int $id      Row id.
	 * @param int $user_id Owner (guards cross-user deletion).
	 * @return bool
	 */
	public static function delete( int $id, int $user_id ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table.
		return (bool) $wpdb->delete(
			Plugin::credentials_table(),
			array(
				'id'      => $id,
				'user_id' => $user_id,
			),
			array( '%d', '%d' )
		);
	}

	/**
	 * Delete all credentials for a user (recovery / disable-2fa).
	 *
	 * @param int $user_id User id.
	 */
	public static function delete_for_user( int $user_id ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table.
		$wpdb->delete( Plugin::credentials_table(), array( 'user_id' => $user_id ), array( '%d' ) );
	}
}
