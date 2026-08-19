# Dragon Login Security

Brute-force protection and modern two-factor authentication — passkeys, authenticator apps, and backup codes — in one lightweight plugin.

## Requirements
WordPress 6.2+, PHP 8.0+. Passkeys require HTTPS (any modern device with a screen lock can create one).

## Brute-force protection
On automatically. Failed logins trigger escalating lockouts per IP; allow/deny lists live under **Settings → Login Security**. Proxy-header trust is **off by default** — only enable *Trust proxy headers* if your host genuinely terminates connections at a proxy, otherwise attackers could spoof their IP.

## Two-factor authentication
Each user enrols from **Users → Profile → Login Security**:
- **Passkeys (WebAuthn)** — sign in with Face ID, Touch ID, Windows Hello or a security key. Phishing-resistant; no codes to type.
- **Authenticator app (TOTP)** — works with Google Authenticator, 1Password, Authy, any RFC 6238 app.
- **Backup codes** — single-use recovery codes; download them when enrolling.

Security property worth knowing: **no auth cookie is issued until the second factor passes** — the gate sits at WordPress's `authenticate` step and covers XML-RPC too, a path some 2FA plugins have historically missed.

## Locked out?
Use a backup code on the two-factor screen. If none remain, an administrator can run the escape hatch on the server:
```bash
wp dragon-login-security disable-2fa <username>
```

## Importing from another plugin
If Limit Login Attempts (Reloaded) or Wordfence is (or was) installed, **Settings → Login Security (import cards at the bottom of the settings tab)** carries your allow/deny IP lists across in one click. Only valid single IP addresses are imported; ranges are skipped and reported.

## Data & privacy
Stored in your own database: authenticator secrets (encrypted), backup codes (hashed), passkey public keys with device labels, and the IP + username of failed logins (pruned on a retention schedule). The plugin integrates WordPress's privacy tools: personal-data **export** shows a user's enrolment facts (never secrets) and **erasure** removes their second-factor material and lockout history. **Uninstalling keeps your data by default**; opt into deletion in Settings.

## Why is there no "hide wp-login" option?
Renaming wp-login.php breaks REST and app passwords while adding little real protection, so it's deliberately not included.

## Dragon Login Security Pro
Adds role-based 2FA enforcement (grace periods, block-until-enrolled), trusted devices, risk-based re-challenge with alerts, a compliance report with CSV export, and WooCommerce customer 2FA.

## Uninstall
Deleting the plugin keeps all its data by default, so a reinstall picks up where you left off. To remove everything on uninstall, tick **Delete all data on uninstall** in the plugin's settings first (this sets the `dragonloginsecurity_delete_data_on_uninstall` option).
