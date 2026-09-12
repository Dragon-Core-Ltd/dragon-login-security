# Dragon Login Security

Brute-force protection and modern two-factor authentication - passkeys, authenticator apps, and backup codes - in one lightweight plugin.

## Requirements
WordPress 6.2+, PHP 8.0+. Passkeys require HTTPS (any modern device with a screen lock can create one). Passkey verification uses the bundled lbuchs/WebAuthn library (MIT), shipped in the plugin's `vendor/` folder; if that folder is ever missing from an install, passkeys are switched off cleanly (a notice appears on the settings screen) while authenticator apps and backup codes keep working.

## Brute-force protection
On automatically. Failed logins trigger escalating lockouts per IP; allow/deny lists live under **Settings → Login Security**.

**Getting the client IP right behind a proxy or CDN.** Proxy-header trust is **off by default** - the plugin uses the direct connection address (`REMOTE_ADDR`), which a visitor can't forge. Only enable **Trust X-Forwarded-For for the client IP** if your site genuinely sits behind a reverse proxy, load balancer or CDN (Cloudflare, a managed host's edge, and the like); otherwise an attacker can spoof the header to dodge a lockout or lock out someone else. When you turn it on, also fill in **Trusted proxy IPs / ranges** - your proxy/CDN addresses, one IP or CIDR per line. The real client is then taken as the first `X-Forwarded-For` entry that is *not* one of yours, walking the chain from the right so a forged prefix can't win. Leave it empty only if a single proxy sits in front of the site, in which case the right-most forwarded address is used.

## Two-factor authentication
Each user enrols from **Users → Profile → Login Security**:
- **Passkeys (WebAuthn)** - sign in with Face ID, Touch ID, Windows Hello or a security key. Phishing-resistant; no codes to type.
- **Authenticator app (TOTP)** - works with Google Authenticator, 1Password, Authy, any RFC 6238 app.
- **Backup codes** - single-use recovery codes; download them when enrolling.

Security property worth knowing: **no auth cookie is issued until the second factor passes** - the gate sits at WordPress's `authenticate` step and covers XML-RPC too, a path some 2FA plugins have historically missed.

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
