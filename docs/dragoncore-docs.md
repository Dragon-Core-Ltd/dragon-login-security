# Dragon Login Security

Brute-force protection and modern two-factor authentication - passkeys, authenticator apps, and backup codes - in one lightweight plugin.

## Requirements
WordPress 6.2+, PHP 8.0+. Passkeys require HTTPS (any modern device with a screen lock can create one). Passkey verification uses the bundled lbuchs/WebAuthn library (MIT), shipped in the plugin's `vendor/` folder; if that folder is ever missing from an install, passkeys are switched off cleanly (a notice appears on the settings screen) while authenticator apps and backup codes keep working. Every screen, email and notice is translatable; translation files in the plugin's `languages/` folder load automatically.

## Brute-force protection
On automatically. Failed logins trigger escalating lockouts per IP; allow/deny lists live under **Settings → Login Security**. A successful sign-in clears only that account's own failed attempts from the address, so failures against other usernames keep counting toward the lockout.

**Getting the client IP right behind a proxy or CDN.** Proxy-header trust is **off by default** - the plugin uses the direct connection address (`REMOTE_ADDR`), which a visitor can't forge. Only enable **Trust X-Forwarded-For for the client IP** if your site genuinely sits behind a reverse proxy, load balancer or CDN (Cloudflare, a managed host's edge, and the like); otherwise an attacker can spoof the header to dodge a lockout or lock out someone else. When you turn it on, also fill in **Trusted proxy IPs / ranges** - your proxy/CDN addresses, one IP or CIDR per line. Forwarded headers (`X-Forwarded-For`, `X-Real-IP`) are then read only when the request itself comes from one of those addresses, so a visitor who reaches your server directly keeps their own address whatever headers they send. The real client is the first `X-Forwarded-For` entry that is *not* one of yours, walking the chain from the right so a forged prefix can't win. Leave the list empty only if a single proxy sits in front of the site and your server accepts connections from that proxy alone: the right-most forwarded address is then used without checking where the request came from.

## Two-factor authentication
Each user enrols from **Users → Profile → Login Security**:
- **Passkeys (WebAuthn)** - sign in with Face ID, Touch ID, Windows Hello or a security key. Phishing-resistant; no codes to type.
- **Authenticator app (TOTP)** - works with Google Authenticator, 1Password, Authy, any RFC 6238 app.
- **Backup codes** - single-use recovery codes; download them when enrolling.

Security property worth knowing: **no auth cookie is issued until the second factor passes** - the gate sits at WordPress's `authenticate` step and covers XML-RPC too (including multicall requests), a path some 2FA plugins have historically missed. It also covers sign-in cookies issued outside the login form (see below). After five incorrect codes the account's second-factor step closes for up to 15 minutes, counted from the first incorrect code. Application passwords remain the way to give scripts and apps access to a two-factor account.

Sign-in forms outside wp-login.php, such as the WooCommerce **My Account** page, hand over to the two-factor screen and return to the page the sign-in started from. The session-expiry popup in wp-admin asks for the second factor too and closes itself when it passes.

**Multisite:** when Login Security is network-activated, a passkey registered on any site in the network counts as two-factor for that account everywhere on the network. If it is activated on individual sites instead, only those sites ask for a second factor - a site where the plugin is not active signs the account in with the password alone - so network-activate it to protect every site. The sign-in screen on another site offers that site's own passkeys, the authenticator app and backup codes, so users who move between sites should also set up an authenticator app. If an account's only passkeys are on other sites, the sign-in screen lists those sites with a link to sign in there: on a network that shares sign-in cookies (subdirectory, or subdomains under a shared cookie domain) that also signs the user in here; otherwise the user can add an authenticator app or backup codes on that site, which work network-wide, or ask an administrator. The listing is guidance only - the site still refuses sign-in without one of its own verified factors.

## Other plugins that sign users in

For an account with two-factor enabled, a sign-in cookie is only issued when the second factor has been passed in the same request, or when the request renews the account's own existing session (for example after changing the password on the profile screen). Any other plugin that signs a user in directly - single sign-on, social login, magic links, or a password-reset form that logs the user in afterwards - is refused for these accounts: no cookie is sent, the session it created is removed, and the user signs in through the normal login form with their second factor. Accounts without two-factor are not affected.

The [User Switching](https://wordpress.org/plugins/user-switching/) plugin is supported: switching to a user is allowed when the signed-in administrator is permitted to switch to that account, and switching back is allowed to the original account.

If you rely on another sign-in integration that already verifies the user by its own strong means, you can allow it with the `dragonloginsecurity_allow_auth_cookie` filter. It receives two arguments:

- `$allow` (bool) - `false` by default;
- `$user_id` (int) - the account the cookie would sign in.

Return `true` only for requests your integration has verified. A password reset in the same request is never allowed, whatever the filter returns.

```php
add_filter( 'dragonloginsecurity_allow_auth_cookie', function ( $allow, $user_id ) {
	// my_sso_verified_user_id() stands for your integration's own check of
	// the current request, returning the verified user ID or 0.
	if ( function_exists( 'my_sso_verified_user_id' ) && my_sso_verified_user_id() === $user_id ) {
		return true;
	}
	return $allow;
}, 10, 2 );
```

## Locked out?
Use a backup code on the two-factor screen. If none remain, an administrator can run the escape hatch on the server:
```bash
wp dragon-login-security disable-2fa <username>
```

## Importing from another plugin
If Limit Login Attempts (Reloaded) or Wordfence is (or was) installed, **Settings → Login Security (import cards at the bottom of the settings tab)** carries your allow/deny IP lists across in one click. Only valid single IP addresses are imported; ranges are skipped and reported. The import confirms the lists were saved before reporting success; if they could not be stored, it shows an error and your existing lists are unchanged.

## Data & privacy
Stored in your own database: authenticator secrets (encrypted), backup codes (hashed), passkey public keys with device labels, and the IP + username of failed logins (pruned on a retention schedule). The plugin makes no external requests: all checks run on your own server, and nothing is sent to Dragon Core or any third party. The plugin integrates WordPress's privacy tools: personal-data **export** shows a user's enrolment facts (never secrets) and **erasure** removes their second-factor material and lockout history. **Uninstalling keeps your data by default**; opt into deletion in Settings.

## Why is there no "hide wp-login" option?
Renaming wp-login.php breaks REST and app passwords while adding little real protection, so it's deliberately not included.

## Dragon Login Security Pro
Adds role-based 2FA enforcement (grace periods, block-until-enrolled), trusted devices, risk-based re-challenge with alerts, a compliance report with CSV export, and WooCommerce customer 2FA.

## Uninstall
Deleting the plugin keeps all its data by default, so a reinstall picks up where you left off. To remove everything on uninstall, tick **Delete all data on uninstall** in the plugin's settings first (this sets the `dragonloginsecurity_delete_data_on_uninstall` option).
