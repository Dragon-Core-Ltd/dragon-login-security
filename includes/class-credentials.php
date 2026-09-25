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
	 * Whether a user has a passkey in any site's credentials table on this
	 * network. Sites where the plugin never ran have no table and are skipped.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function user_has_any_on_network( int $user_id ): bool {
		global $wpdb;
		$tables = self::network_tables();
		if ( empty( $tables ) ) {
			return false;
		}
		$sql  = implode( ' UNION ALL ', array_fill( 0, count( $tables ), '(SELECT 1 FROM %i WHERE user_id = %d LIMIT 1)' ) ) . ' LIMIT 1';
		$args = array();
		foreach ( $tables as $table ) {
			$args[] = $table;
			$args[] = $user_id;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Every table name and id is a placeholder; the SQL is only repeated placeholder groups. Results must be current.
		return null !== $wpdb->get_var( $wpdb->prepare( $sql, $args ) );
	}

	/**
	 * Ids of the network sites whose credentials table holds a passkey for a
	 * user. Empty on a single site. Used only to point a user at the site where
	 * their passkey can be verified; it never counts as a verified factor.
	 *
	 * @param int $user_id User id.
	 * @return int[]
	 */
	public static function network_site_ids_for_user( int $user_id ): array {
		global $wpdb;
		if ( ! is_multisite() ) {
			return array();
		}
		$tables = self::network_tables();
		if ( empty( $tables ) ) {
			return array();
		}
		$sql  = implode( ' UNION ALL ', array_fill( 0, count( $tables ), '(SELECT %s AS t FROM %i WHERE user_id = %d LIMIT 1)' ) );
		$args = array();
		foreach ( $tables as $table ) {
			$args[] = $table;
			$args[] = $table;
			$args[] = $user_id;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Every table name and id is a placeholder; the SQL is only repeated placeholder groups. Results must be current.
		$hits = (array) $wpdb->get_col( $wpdb->prepare( $sql, $args ) );

		$base = (string) $wpdb->base_prefix;
		$ids  = array();
		foreach ( $hits as $table ) {
			if ( ! is_string( $table ) || ! in_array( $table, $tables, true ) ) {
				continue;
			}
			$rest = substr( $table, strlen( $base ) );
			$id   = 1 === preg_match( '/^([0-9]+)_/', $rest, $m ) ? (int) $m[1] : (int) get_main_site_id();
			if ( $id > 0 ) {
				$ids[ $id ] = $id;
			}
		}
		return array_values( $ids );
	}

	/**
	 * Delete a user's passkeys from every site on the network (recovery), or
	 * from this site only on a single site.
	 *
	 * @param int $user_id User id.
	 */
	public static function delete_for_user_on_network( int $user_id ): void {
		global $wpdb;
		if ( ! is_multisite() ) {
			self::delete_for_user( $user_id );
			return;
		}
		foreach ( self::network_tables() as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to the plugin's custom tables.
			$wpdb->delete( $table, array( 'user_id' => $user_id ), array( '%d' ) );
		}
	}

	/**
	 * Every site's credentials table that exists on this network.
	 *
	 * @return string[]
	 */
	private static function network_tables(): array {
		global $wpdb;
		$base = (string) $wpdb->base_prefix;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema lookup; must be current so a newly enrolled site counts at once.
		$found   = (array) $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $base ) . '%' . $wpdb->esc_like( 'dls_credentials' ) ) );
		$pattern = '/^' . preg_quote( $base, '/' ) . '(?:[0-9]+_)?dls_credentials$/';
		return array_values(
			array_filter(
				$found,
				static function ( $table ) use ( $pattern ) {
					return is_string( $table ) && 1 === preg_match( $pattern, $table );
				}
			)
		);
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
	 * @return bool False when the write failed (zero affected rows is not a failure).
	 */
	public static function update_sign_count( int $id, int $count ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to plugin's custom table.
		$result = $wpdb->update(
			Plugin::credentials_table(),
			array(
				'sign_count'   => $count,
				'last_used_at' => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%d', '%s' ),
			array( '%d' )
		);
		return false !== $result;
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
