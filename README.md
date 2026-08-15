# Dragon Login Security

**Brute-force protection and modern two-factor authentication — authenticator apps, backup codes, and passkeys — for WordPress.**

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
&nbsp;·&nbsp; Requires WordPress 6.2+ &nbsp;·&nbsp; Requires PHP 8.0+

Dragon Login Security locks down the front door of your WordPress site: it stops brute-force attacks and adds real two-factor authentication, including **passkeys** (Face ID, Touch ID, Windows Hello, or a security key) — the passwordless standard most 2FA plugins still don't do well.

It works on its own, and when the free [Dragon Activity Log](https://dragoncore.ltd/plugins/dragon-activity-log) plugin is installed, every login, lockout, and two-factor event flows into its tamper-evident audit trail.

---

> ### ℹ️ This is a read-only source mirror
> This repository is published so you can **read and audit** the code that runs on your site — security software should be inspectable. It is a mirror of the released plugin; **Issues and Pull Requests are not monitored here.**
>
> For support, bug reports, or feature requests, please use **[dragoncore.ltd](https://dragoncore.ltd/plugins/dragon-login-security)**.

---

## Features

- **Passkeys (WebAuthn)** — Sign in with your device instead of a code; the modern, phishing-resistant standard.
- **Authenticator App (TOTP)** — Works with Google Authenticator, 1Password, Authy, and any RFC 6238 app.
- **Single-Use Backup Codes** — Downloadable recovery codes for when you lose your device.
- **Brute-Force Protection** — Escalating lockouts after repeated failed logins, with IP allow/deny lists.
- **Secure by Design** — No auth cookie is issued until the second factor passes; secrets are encrypted at rest and backup codes are hashed.
- **Activity Log Ready** — Feeds [Dragon Activity Log](https://dragoncore.ltd/plugins/dragon-activity-log)'s tamper-evident audit when installed.
- **WP-CLI Recovery** — `wp dragon-login-security disable-2fa <user>` if you ever lock yourself out.

## Installation

1. Upload the `dragon-login-security` folder to `/wp-content/plugins/`.
2. Activate the plugin through the **Plugins** screen in WordPress.
3. Each user enables two-factor from their own profile (**Users → Profile → Login Security**).
4. Brute-force protection is on automatically; tune IP lists under **Settings → Login Security**.

## Two-factor & recovery

Two-factor is set up per user on each user's own profile screen. Backup codes let you recover if a passkey or phone is lost.

**Locked out?** Use a single-use backup code on the two-factor screen. If you have none either, an administrator can run the last-resort escape hatch on the server:

```bash
wp dragon-login-security disable-2fa <your-username>
```

## FAQ

**Do passkeys need special hardware?**
No. Any modern device with a screen lock (Face ID, Touch ID, Windows Hello, Android) can create a passkey, as can a hardware security key.

**Does this hide or rename my login page?**
No. Renaming `wp-login.php` breaks REST and other login paths and offers little real protection, so it is intentionally not included.

**Where is my data sent?**
Nowhere. Authenticator secrets (encrypted), backup codes (hashed), and passkey public keys are stored only in your own database. Failed-login IPs are recorded locally for brute-force protection; proxy-header trust is off by default.

## Dragon Login Security Pro

The free plugin is complete on its own. [**Dragon Login Security Pro**](https://dragoncore.ltd/plugins/dragon-login-security-pro) adds role-based 2FA enforcement (grace periods, block-until-enrolled), trusted devices, risk-based re-challenge with alerts, a compliance report/CSV, and WooCommerce customer 2FA.

## License

Dragon Login Security is free software, released under the [GNU General Public License v2.0 or later](https://www.gnu.org/licenses/gpl-2.0.html). See [`LICENSE`](LICENSE).

Built by [Dragon Core](https://dragoncore.ltd).
