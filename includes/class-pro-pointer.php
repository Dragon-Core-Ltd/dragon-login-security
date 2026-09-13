<?php
/**
 * Points an administrator at Dragon Login Security Pro from the free plugin's own screens.
 *
 * @package DragonLoginSecurity
 */

namespace DragonLoginSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Pro_Pointer class.
 *
 * Three quiet surfaces, all withdrawn the moment the Pro add-on is active:
 * an "Upgrade to Pro" link on the plugins list, a one-line footer on the
 * plugin's own screens, and a single dismissible notice shown once the free
 * plugin has demonstrably done its job (a few completed events, or one plus a
 * few days). Nothing is locked or greyed out; the free plugin is complete.
 */
class Pro_Pointer {

	/**
	 * Option holding the administrator's choice and first use.
	 */
	public const OPTION = 'dragonloginsecurity_pro_pointer';

	/**
	 * Option holding the event count, kept apart from the choice so a
	 * background event write can never overwrite a dismissal made meanwhile.
	 */
	public const EVENTS_OPTION = 'dragonloginsecurity_pro_pointer_events';

	/**
	 * admin-post action handling the notice's choices.
	 */
	private const ACTION = 'dragonloginsecurity_pro_pointer';

	/**
	 * Screens the footer and notice may appear on. An entry starting with "*"
	 * matches by suffix: a submenu's screen id is prefixed with the translated
	 * parent menu title, which is not the plugin's to know in advance.
	 *
	 * @var array<string>
	 */
	private const SCREENS = array( 'settings_page_dragon-login-security' );

	/**
	 * Days of use before the notice may show with a single event.
	 */
	public const MIN_AGE_DAYS = 3;

	/**
	 * Events after which the notice may show regardless of age.
	 */
	public const EARLY_EVENTS = 3;

	/**
	 * Days a "Not now" keeps the notice away.
	 */
	public const SNOOZE_DAYS = 60;

	/**
	 * Hooks that mean the free plugin just did something worth having.
	 *
	 * @var array<string>
	 */
	private const VALUE_HOOKS = array( 'dragonloginsecurity_2fa_passed', 'dragonloginsecurity_lockout' );

	/**
	 * Store page for the add-on.
	 */
	private const STORE_URL = 'https://dragoncore.ltd/plugins/dragon-login-security-pro';

	/**
	 * Register hooks.
	 */
	public function init_hooks(): void {
		foreach ( self::VALUE_HOOKS as $hook ) {
			add_action( $hook, array( __CLASS__, 'record_value' ) );
		}
		add_filter( 'plugin_action_links_dragon-login-security/dragon-login-security.php', array( $this, 'action_links' ) );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'in_admin_footer', array( $this, 'render_footer' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * Whether the Pro add-on is installed and active.
	 *
	 * @return bool
	 */
	public static function pro_active(): bool {
		return class_exists( 'DragonLoginSecurityPro\\Plugin' );
	}

	/**
	 * Count a completed piece of work. Bounded: once the notice is dismissed
	 * or the early threshold is reached there is nothing left to learn.
	 */
	public static function record_value(): void {
		if ( self::pro_active() ) {
			return;
		}
		$state = self::state();
		if ( ! empty( $state['dismissed'] ) || $state['events'] >= self::EARLY_EVENTS ) {
			return;
		}
		update_option( self::EVENTS_OPTION, (int) $state['events'] + 1, false );
	}

	/**
	 * Whether the notice should show now. Pure, so it is testable.
	 *
	 * @param array $state Stored state.
	 * @param int   $now   Current Unix time.
	 * @return bool
	 */
	public static function is_due( array $state, int $now ): bool {
		if ( ! empty( $state['dismissed'] ) ) {
			return false;
		}
		if ( ! empty( $state['snoozed_until'] ) && (int) $state['snoozed_until'] > $now ) {
			return false;
		}
		$events    = (int) ( $state['events'] ?? 0 );
		$first_use = (int) ( $state['first_use'] ?? 0 );
		if ( $events < 1 || $first_use < 1 ) {
			return false;
		}

		return ( $first_use + self::MIN_AGE_DAYS * DAY_IN_SECONDS ) <= $now || $events >= self::EARLY_EVENTS;
	}

	/**
	 * Add an upgrade link on the plugins list.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( array $links ): array {
		if ( self::pro_active() || ! current_user_can( 'manage_options' ) ) {
			return $links;
		}
		$links[] = '<a href="' . esc_url( self::store_url( 'action-link' ) ) . '" target="_blank" rel="noopener" style="font-weight:600">' . esc_html__( 'Upgrade to Pro', 'dragon-login-security' ) . '</a>';

		return $links;
	}

	/**
	 * One line at the foot of the plugin's own screens.
	 */
	public function render_footer(): void {
		if ( ! $this->on_own_screen() || self::pro_active() ) {
			return;
		}
		printf(
			'<p class="description dragonloginsecurity_pro-line" style="margin:12px 0 0">%s <a href="%s" target="_blank" rel="noopener">%s</a></p>',
			esc_html__( 'Need 2FA enforced by role, trusted devices and alerts?', 'dragon-login-security' ),
			esc_url( self::store_url( 'footer' ) ),
			esc_html__( 'See Dragon Login Security Pro', 'dragon-login-security' )
		);
	}

	/**
	 * The one-time notice, on the plugin's own screens only.
	 */
	public function render_notice(): void {
		if ( ! $this->on_own_screen() || self::pro_active() || ! self::is_due( self::state(), time() ) ) {
			return;
		}
		?>
		<div class="notice notice-info dragonloginsecurity_pro-pointer">
			<p>
				<strong><?php esc_html_e( 'Dragon Login Security is doing its job.', 'dragon-login-security' ); ?></strong>
				<?php esc_html_e( 'Dragon Login Security Pro adds two-factor enforcement by role, trusted devices, risk-based re-challenge with alerts, compliance reports and WooCommerce customer 2FA.', 'dragon-login-security' ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $this->choice_url( 'view' ) ); ?>"><?php esc_html_e( 'See what Pro adds', 'dragon-login-security' ); ?></a>
				<a class="button" href="<?php echo esc_url( $this->choice_url( 'later' ) ); ?>"><?php esc_html_e( 'Not now', 'dragon-login-security' ); ?></a>
				<a href="<?php echo esc_url( $this->choice_url( 'never' ) ); ?>"><?php esc_html_e( 'No thanks', 'dragon-login-security' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Apply a choice made on the notice.
	 */
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'dragon-login-security' ), 403 );
		}
		check_admin_referer( self::ACTION );

		$choice = isset( $_GET['choice'] ) ? sanitize_key( wp_unslash( $_GET['choice'] ) ) : '';
		$prefs  = self::prefs();

		if ( 'later' === $choice ) {
			$prefs['snoozed_until'] = time() + self::SNOOZE_DAYS * DAY_IN_SECONDS;
		} else {
			$prefs['dismissed'] = true;
		}
		update_option( self::OPTION, $prefs, false );

		if ( 'view' === $choice ) {
			add_filter(
				'allowed_redirect_hosts',
				static function ( array $hosts ): array {
					$hosts[] = 'dragoncore.ltd';
					return $hosts;
				}
			);
			wp_safe_redirect( self::store_url( 'notice' ) );
			exit;
		}

		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url() );
		exit;
	}

	/**
	 * Whether the current screen belongs to this plugin.
	 *
	 * @return bool
	 */
	private function on_own_screen(): bool {
		if ( ! current_user_can( 'manage_options' ) || ! function_exists( 'get_current_screen' ) ) {
			return false;
		}
		$screen = get_current_screen();
		if ( ! $screen ) {
			return false;
		}
		foreach ( self::SCREENS as $wanted ) {
			if ( $wanted === $screen->id ) {
				return true;
			}
			if ( str_starts_with( $wanted, '*' ) && str_ends_with( $screen->id, substr( $wanted, 1 ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Store URL tagged with where the click came from.
	 *
	 * @param string $surface Which surface produced the link.
	 * @return string
	 */
	private static function store_url( string $surface ): string {
		return add_query_arg(
			array(
				'utm_source'   => 'plugin',
				'utm_medium'   => $surface,
				'utm_campaign' => 'dragon-login-security',
			),
			self::STORE_URL
		);
	}

	/**
	 * Nonce-protected admin-post URL for a choice.
	 *
	 * @param string $choice view|later|never.
	 * @return string
	 */
	private function choice_url( string $choice ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::ACTION,
					'choice' => $choice,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);
	}

	/**
	 * The administrator's preferences, stamping first use on first read.
	 *
	 * @return array{first_use:int,dismissed:bool,snoozed_until:int}
	 */
	private static function prefs(): array {
		$stored = get_option( self::OPTION, array() );
		$prefs  = wp_parse_args(
			is_array( $stored ) ? $stored : array(),
			array(
				'first_use'     => 0,
				'dismissed'     => false,
				'snoozed_until' => 0,
			)
		);
		unset( $prefs['events'] );
		if ( (int) $prefs['first_use'] < 1 ) {
			$prefs['first_use'] = time();
			update_option( self::OPTION, $prefs, false );
		}

		return $prefs;
	}

	/**
	 * Preferences plus the event count, the shape is_due() reasons about.
	 *
	 * @return array{first_use:int,events:int,dismissed:bool,snoozed_until:int}
	 */
	private static function state(): array {
		$state           = self::prefs();
		$state['events'] = (int) get_option( self::EVENTS_OPTION, 0 );

		return $state;
	}
}
