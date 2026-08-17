=== Dragon Login Security ===
Contributors: dragoncore
Tags: two factor, 2fa, passkeys, login security, brute force
Requires at least: 6.2
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.0.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Brute-force protection and modern two-factor authentication — authenticator apps, backup codes, and passkeys — for WordPress.

== Description ==

Dragon Login Security locks down the front door of your WordPress site: it stops brute-force attacks and adds real two-factor authentication, including **passkeys** (Face ID, Touch ID, Windows Hello, or a security key) — the passwordless standard most 2FA plugins still don't do well.

It works on its own, and when the free **Dragon Activity Log** plugin is installed, every login, lockout, and two-factor event flows into its tamper-evident audit trail.

* **Passkeys (WebAuthn)** - Sign in with your device instead of a code; the modern, phishing-resistant standard
* **Authenticator App (TOTP)** - Works with Google Authenticator, 1Password, Authy, and any RFC 6238 app
* **Single-Use Backup Codes** - Downloadable recovery codes for when you lose your device
* **Brute-Force Protection** - Escalating lockouts after repeated failed logins, with IP allow/deny lists
* **Secure by Design** - No auth cookie is issued until the second factor passes; secrets encrypted at rest, backup codes hashed
* **Activity Log Ready** - Feeds Dragon Activity Log's tamper-evident audit when installed
* **WP-CLI Recovery** - `wp dragon-login-security disable-2fa <user>` if you ever lock yourself out

Two-factor is set up per user on each user's own profile screen. Backup codes let you recover if a passkey or phone is lost, and the WP-CLI command is a last-resort escape hatch.

== Installation ==

1. Upload the `dragon-login-security` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Each user enables two-factor from their own profile (Users → Profile → Login Security).
4. Brute-force protection is on automatically; tune IP lists under Settings → Login Security.

== Frequently Asked Questions ==

= What if I lose my passkey or phone? =

Use one of your single-use backup codes on the two-factor screen. If you have no codes either, an administrator can run `wp dragon-login-security disable-2fa <your-username>` on the server to reset your two-factor.

= Do passkeys need any special hardware? =

No. Any modern device with a screen lock (Face ID, Touch ID, Windows Hello, Android) can create a passkey, as can a hardware security key.

= Does this hide or rename my login page? =

No. Renaming wp-login.php breaks REST and other login paths and offers little real protection, so it is intentionally not included.

= Does it work with the Dragon Activity Log plugin? =

Yes — when Activity Log is active, login and two-factor events are recorded in its tamper-evident audit. Dragon Login Security works fully without it.

== Changelog ==

= 1.0.5 =
* Data safety: uninstalling the plugin no longer deletes its data unless you explicitly opt in first — a reinstall now picks up exactly where you left off. (New setting.)
* New: one-click import of allow/deny IP lists from Limit Login Attempts (Reloaded) and Wordfence.
* Privacy: integrates WordPress's privacy tools — personal-data export shows a user's enrolment facts (never secrets) and erasure removes their second-factor material and lockout history; suggested privacy-policy text included.

= 1.0.4 =
* New look: the Dragon design system arrives — a consistent Dragon Core header, cleaner tables, and unified status colours. Purely visual; no behaviour changes.

= 1.0.3 =
* Maintenance: uninstall now also clears any pre-1.0.2 leftover options and scheduled task.

= 1.0.2 =
* Renamed all option, hook, function and constant prefixes to the unique `dragonloginsecurity_` / `DRAGONLOGINSECURITY_` prefix. Existing settings are migrated automatically on update; 2FA enrolment data (user meta) and the credentials/lockout tables are unaffected.

= 1.0.1 =
* Add filters (dls_should_challenge, dls_2fa_passed, dls_challenge_form) so Dragon Login Security Pro can offer trusted devices. No change to default behavior.

= 1.0.0 =
* Initial release.

== Privacy Policy ==

Dragon Login Security stores, in your own database: each user's authenticator secret (encrypted), backup codes (hashed), and passkey public keys and metadata. It records the IP addresses of failed logins and lockouts for brute-force protection. No data is sent to any third party. IP capture for lockouts is inherent to brute-force protection; proxy-header trust is off by default.
