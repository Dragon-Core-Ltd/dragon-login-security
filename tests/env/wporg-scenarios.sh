#!/usr/bin/env bash
# Real-HTTP scenarios for the request handlers that read submitted input:
# the settings save, the profile enrolment AJAX endpoints and the two-factor
# challenge (wp-login.php, interim re-authentication, a stale sign-in cookie,
# and the WooCommerce My Account sign-in).
#
# Usage: tests/env/wporg-scenarios.sh <wp-env dir>
# The env must have WooCommerce, this plugin and its Pro active. Every user,
# product and setting the run creates is removed or restored at the end.

set -u

ENV_DIR="${1:?usage: wporg-scenarios.sh <wp-env dir>}"
ENV_NAME="$(basename "$ENV_DIR")"
CLI="$(docker ps --format '{{.Names}}' | grep -E "^wp-env-${ENV_NAME}-[0-9a-f]+-cli-1$" | head -1)"
WEB="$(docker ps --format '{{.Names}}' | grep -E "^wp-env-${ENV_NAME}-[0-9a-f]+-wordpress-1$" | head -1)"
if [ -z "$CLI" ]; then
	echo "No running wp-env cli container for $ENV_NAME" >&2
	exit 2
fi
PORT="$(php -r '$c = json_decode( (string) file_get_contents( $argv[1] ), true ); echo (int) ( $c["port"] ?? 8888 );' "$ENV_DIR/.wp-env.json")"
BASE="http://localhost:$PORT"
TMP="$(mktemp -d)"
PW='Dlsx-Scenario-Pass-9'
SLUG='dragon-login-security'
NS='DragonLoginSecurity'

PASS=0
FAIL=0

# WP-CLI in the env's own cli container (what `wp-env run cli` execs into).
wpc() {
	docker exec -i "$CLI" wp "$@" 2>/dev/null
}

pass() {
	PASS=$((PASS + 1))
	echo "PASS $1"
}

fail() {
	FAIL=$((FAIL + 1))
	echo "FAIL $1${2:+ ($2)}"
}

# check <description> <command...>: PASS when the command succeeds.
check() {
	local desc="$1"
	shift
	if "$@"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# The value of a form field in a saved page, HTML entities decoded.
field() {
	php -r '$h = (string) file_get_contents( $argv[1] );
		if ( preg_match( "/name=\"" . preg_quote( $argv[2], "/" ) . "\"[^>]*value=\"([^\"]*)\"/", $h, $m ) ) { echo html_entity_decode( $m[1], ENT_QUOTES ); }' "$1" "$2"
}

# The Location header of a saved response, or ''.
location() {
	tr -d '\r' <"$1" | sed -n 's/^[Ll]ocation: //p' | tail -1
}

status() {
	tr -d '\r' <"$1" | sed -n 's/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -1
}

# Whether a cookie jar holds a live logged-in cookie.
logged_in() {
	grep -q "wordpress_logged_in_" "$1"
}

# The expiry column of the jar's logged-in cookie (0 = browser-session cookie).
login_cookie_expiry() {
	grep "wordpress_logged_in_" "$1" | awk -F'\t' '{print $5}' | head -1
}

not_logged_in() {
	! logged_in "$1"
}

in_file() {
	grep -q -- "$2" "$1"
}

not_in_file() {
	! grep -q -- "$2" "$1"
}

equals() {
	[ "$1" = "$2" ]
}

# Sign in through wp-login.php. Extra curl args are appended to the POST.
login_post() {
	local jar="$1" user="$2"
	shift 2
	curl -s -c "$jar" -b "$jar" -o /dev/null "$BASE/wp-login.php"
	curl -s -c "$jar" -b "$jar" -D "$TMP/h" -o "$TMP/b" \
		--data-urlencode "log=$user" --data-urlencode "pwd=$PW" \
		-d 'wp-submit=Log+In' -d 'testcookie=1' "$@" "$BASE/wp-login.php"
}

# A signed-in admin session (no second factor on these accounts).
admin_session() {
	local jar="$1" user="$2"
	: >"$jar"
	login_post "$jar" "$user"
}

# Submit the challenge form saved in $TMP/b. Args: jar, then field overrides
# as name=value pairs; a pair "nonce=-" drops the nonce field.
submit_challenge() {
	local jar="$1"
	shift
	local token user method redirect remember interim nonce
	token="$(field "$TMP/b" dragonloginsecurity_token)"
	user="$(field "$TMP/b" dragonloginsecurity_user)"
	method="$(field "$TMP/b" dragonloginsecurity_method)"
	redirect="$(field "$TMP/b" redirect_to)"
	remember="$(field "$TMP/b" rememberme)"
	interim="$(field "$TMP/b" interim-login)"
	nonce="$(field "$TMP/b" dragonloginsecurity_2fa_nonce)"
	local args=()
	local kv
	for kv in "$@"; do
		case "$kv" in
			nonce=*) nonce="${kv#nonce=}" ;;
			token=*) token="${kv#token=}" ;;
			user=*) user="${kv#user=}" ;;
			method=*) method="${kv#method=}" ;;
			*) args+=(--data-urlencode "$kv") ;;
		esac
	done
	[ "$nonce" != "-" ] && args+=(--data-urlencode "dragonloginsecurity_2fa_nonce=$nonce")
	[ -n "$interim" ] && args+=(--data-urlencode "interim-login=$interim")
	curl -s -c "$jar" -b "$jar" -D "$TMP/h" -o "$TMP/b" \
		--data-urlencode "dragonloginsecurity_token=$token" \
		--data-urlencode "dragonloginsecurity_user=$user" \
		--data-urlencode "dragonloginsecurity_method=$method" \
		--data-urlencode "redirect_to=$redirect" \
		--data-urlencode "rememberme=$remember" \
		"${args[@]}" \
		"$BASE/wp-login.php?action=dragonloginsecurity_2fa"
}

# Follow a challenge hand-over (302 to the resume address) when there is one.
follow_handover() {
	local jar="$1" loc
	loc="$(location "$TMP/h")"
	case "$loc" in
		*action=dragonloginsecurity_2fa*)
			curl -s -c "$jar" -b "$jar" -D "$TMP/h" -o "$TMP/b" "$loc"
			;;
	esac
}

user_id() {
	wpc user get "$1" --field=ID
}

totp_now() {
	wpc eval "echo $NS\\Provider_TOTP::code_at( (string) $NS\\Crypto::decrypt( (string) get_user_meta( $1, $NS\\Two_Factor::TOTP_META, true ) ), time() );"
}

# Wait until the next 30-second TOTP step so a user's code is not a replay.
next_step() {
	local s
	s=$(( 31 - $(date +%s) % 30 ))
	sleep "$s"
}

arm_totp() {
	wpc eval "update_user_meta( $1, $NS\\Two_Factor::TOTP_META, $NS\\Crypto::encrypt( $NS\\Provider_TOTP::generate_secret() ) ); delete_user_meta( $1, $NS\\Two_Factor::CODE_FAILURES_META );" >/dev/null
}

backup_codes() {
	wpc eval "\$c = $NS\\Provider_Backup_Codes::generate( 10 ); $NS\\Provider_Backup_Codes::store( $1, \$c ); echo implode( ' ', \$c );"
}

failures_meta() {
	wpc eval "echo wp_json_encode( get_user_meta( $1, $NS\\Two_Factor::CODE_FAILURES_META, true ) );"
}

# The address the site sees for this host's requests, read from the access log.
client_ip() {
	local probe ip
	probe="dlsx_ip_probe_$$_$RANDOM"
	curl -s -o /dev/null "$BASE/?$probe=1"
	ip="$(docker logs --tail 200 "$WEB" 2>&1 | grep "$probe" | tail -1 | awk '{print $1}')"
	printf '%s' "${ip:-127.0.0.1}"
}

unlock_all() {
	wpc eval "( new $NS\\Limit_Login() )->clear( '$CLIENT_IP' ); ( new $NS\\Limit_Login() )->clear( '127.0.0.1' );
		foreach ( get_users( array( 'search' => 'dlsx_*', 'search_columns' => array( 'user_login' ), 'fields' => 'ID' ) ) as \$id ) { delete_user_meta( (int) \$id, $NS\\Two_Factor::CODE_FAILURES_META ); }" >/dev/null
}

settings_json() {
	wpc eval 'echo wp_json_encode( get_option( "dragonloginsecurity_settings", null ) );'
}

ajax() {
	local jar="$1"
	shift
	curl -s -c "$jar" -b "$jar" -D "$TMP/ah" -o "$TMP/ab" "$@" "$BASE/wp-admin/admin-ajax.php"
}

enroll_nonce() {
	local jar="$1"
	curl -s -c "$jar" -b "$jar" -o "$TMP/profile" "$BASE/wp-admin/profile.php"
	php -r 'if ( preg_match( "/dlsEnroll = \\{[^}]*?\"nonce\":\"([a-f0-9]+)\"/", (string) file_get_contents( $argv[1] ), $m ) ) { echo $m[1]; }' "$TMP/profile"
}

# Mint the nonce a signed-in browser session would get for an action. Used
# for users WooCommerce keeps out of wp-admin (no profile screen to scrape).
session_nonce() {
	local jar="$1" uid="$2" action="$3" value
	value="$(grep "wordpress_logged_in_" "$jar" | awk -F'\t' '{print $7}' | head -1)"
	wpc eval "wp_set_current_user( $uid ); \$_COOKIE[ LOGGED_IN_COOKIE ] = urldecode( '$value' ); echo wp_create_nonce( '$action' );"
}

json_ok() {
	php -r '$j = json_decode( (string) file_get_contents( $argv[1] ), true ); exit( is_array( $j ) && true === ( $j["success"] ?? null ) ? 0 : 1 );' "$TMP/ab"
}

json_error() {
	php -r '$j = json_decode( (string) file_get_contents( $argv[1] ), true ); exit( is_array( $j ) && false === ( $j["success"] ?? null ) ? 0 : 1 );' "$TMP/ab"
}

ajax_refused() {
	[ "$(status "$TMP/ah")" = "403" ] && [ "$(cat "$TMP/ab")" = "-1" ]
}

ajax_forbidden_json() {
	[ "$(status "$TMP/ah")" = "403" ] && json_error
}

# --------------------------------------------------------------------------
echo "== setup"
LOG_START="$(wpc eval 'echo (int) @filesize( WP_CONTENT_DIR . "/debug.log" );')"
LOG_START="${LOG_START:-0}"
SETTINGS_BEFORE="$(settings_json)"
DELETE_BEFORE="$(wpc eval 'echo wp_json_encode( get_option( "dragonloginsecurity_delete_data_on_uninstall", null ) );')"
CLIENT_IP="$(client_ip)"
PRODUCT_ID=""

# Put the env back as it was: runs at the end, and on any early exit.
restore_env() {
	unlock_all
	[ -n "$PRODUCT_ID" ] && wpc post delete "$PRODUCT_ID" --force >/dev/null
	if [ "$SETTINGS_BEFORE" = "null" ]; then
		wpc option delete dragonloginsecurity_settings >/dev/null
	else
		printf '%s' "$SETTINGS_BEFORE" | docker exec -i "$CLI" wp option update dragonloginsecurity_settings --format=json >/dev/null 2>&1
	fi
	if [ "$DELETE_BEFORE" = "null" ]; then
		wpc option delete dragonloginsecurity_delete_data_on_uninstall >/dev/null
	else
		printf '%s' "$DELETE_BEFORE" | docker exec -i "$CLI" wp option update dragonloginsecurity_delete_data_on_uninstall --format=json >/dev/null 2>&1
	fi
	local u id
	for u in dlsx_admin dlsx_enrol dlsx_target dlsx_sub dlsx_2fa_a dlsx_2fa_b dlsx_2fa_c dlsx_cust; do
		id="$(user_id "$u")"
		[ -n "$id" ] && wpc dragon-login-security disable-2fa "$u" >/dev/null && wpc user delete "$id" --yes >/dev/null
	done
}
trap 'restore_env; rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM

for spec in dlsx_admin:administrator dlsx_enrol:administrator dlsx_target:editor dlsx_sub:subscriber \
	dlsx_2fa_a:editor dlsx_2fa_b:editor dlsx_2fa_c:editor dlsx_cust:customer; do
	u="${spec%%:*}"
	r="${spec#*:}"
	if [ -z "$(user_id "$u")" ]; then
		wpc user create "$u" "$u@example.test" --role="$r" --user_pass="$PW" >/dev/null
	else
		wpc user update "$u" --user_pass="$PW" --role="$r" >/dev/null
		wpc dragon-login-security disable-2fa "$u" >/dev/null
	fi
done
unlock_all

ADMIN_ID="$(user_id dlsx_admin)"
ENROL_ID="$(user_id dlsx_enrol)"
TARGET_ID="$(user_id dlsx_target)"
SUB_ID="$(user_id dlsx_sub)"
A_ID="$(user_id dlsx_2fa_a)"
B_ID="$(user_id dlsx_2fa_b)"
C_ID="$(user_id dlsx_2fa_c)"
CUST_ID="$(user_id dlsx_cust)"
for id in "$A_ID" "$B_ID" "$C_ID" "$CUST_ID"; do
	arm_totp "$id"
done
read -r -a A_CODES <<<"$(backup_codes "$A_ID")"
read -r -a B_CODES <<<"$(backup_codes "$B_ID")"
read -r -a C_CODES <<<"$(backup_codes "$C_ID")"
read -r -a CUST_CODES <<<"$(backup_codes "$CUST_ID")"
LOGGED_IN_NAME="$(wpc eval 'echo LOGGED_IN_COOKIE;')"

# --------------------------------------------------------------------------
echo "== settings save (Settings > Login Security)"
J="$TMP/admin.jar"
admin_session "$J" dlsx_admin
curl -s -c "$J" -b "$J" -D "$TMP/h" -o "$TMP/b" "$BASE/wp-admin/options-general.php?page=$SLUG"
check "settings screen renders" equals "$(status "$TMP/h")" 200
check "settings screen has its form" in_file "$TMP/b" 'name="dragonloginsecurity_save_settings"'
SNONCE="$(field "$TMP/b" _wpnonce)"

save_settings() {
	curl -s -c "$J" -b "$J" -D "$TMP/h" -o "$TMP/b" "$@" "$BASE/wp-admin/options-general.php?page=$SLUG"
}

save_settings -d "_wpnonce=$SNONCE" -d 'dragonloginsecurity_save_settings=1' \
	--data-urlencode $'allow_ips=203.0.113.10\n198.51.100.0/24\nnot-an-ip' \
	--data-urlencode 'deny_ips=192.0.2.77' -d 'trust_proxy=on' -d 'proxy_header=cf_connecting_ip' \
	--data-urlencode 'trusted_proxies=10.9.8.0/24'
S="$(settings_json)"
check "valid save redirects back" equals "$(status "$TMP/h")" 302
check "valid save stores the lists, header and trust flag" equals "$S" '{"trust_proxy":true,"proxy_header":"cf_connecting_ip","trusted_proxies":["10.9.8.0\/24"],"allow_ips":["203.0.113.10","198.51.100.0\/24"],"deny_ips":["192.0.2.77"]}'
check "invalid entry is reported" equals "$(wpc eval 'echo get_transient( "dragonloginsecurity_settings_notice" )["type"] ?? "";')" error

save_settings -d "_wpnonce=$SNONCE" -d 'dragonloginsecurity_save_settings=1' \
	--data-urlencode $'allow_ips=10.0.0.1 <office\n10.0.0.2 lan>\n10.0.0.3' \
	--data-urlencode 'deny_ips=192.0.2.78' -d 'trust_proxy=on' -d 'proxy_header=cf_connecting_ip' \
	--data-urlencode 'trusted_proxies=10.9.8.0/24'
check "list with an unclosed '<' is refused, stored list unchanged" equals "$(settings_json)" '{"trust_proxy":true,"proxy_header":"cf_connecting_ip","trusted_proxies":["10.9.8.0\/24"],"allow_ips":["203.0.113.10","198.51.100.0\/24"],"deny_ips":["192.0.2.78"]}'
curl -s -c "$J" -b "$J" -o "$TMP/b" "$BASE/wp-admin/options-general.php?page=$SLUG"
check "refused list is named in the error notice" in_file "$TMP/b" '10.0.0.2 lan&gt;'
check "refused list notice names the line after the tag" in_file "$TMP/b" '10.0.0.3'

save_settings -d "_wpnonce=$SNONCE" -d 'dragonloginsecurity_save_settings=1' \
	--data-urlencode 'allow_ips[]=203.0.113.99' --data-urlencode 'deny_ips=192.0.2.77' -d 'proxy_header[]=x_real_ip'
check "array-shaped fields are read as empty, header falls back" equals "$(settings_json)" '{"trust_proxy":false,"proxy_header":"x_forwarded_for","trusted_proxies":[],"allow_ips":[],"deny_ips":["192.0.2.77"]}'

save_settings -d "_wpnonce=$SNONCE" -d 'dragonloginsecurity_save_settings=1' \
	--data-urlencode $'allow_ips= 203.0.113.11 \r\n\r\n2001:db8::/32\t' --data-urlencode 'deny_ips=' -d 'proxy_header=X_REAL_IP'
check "line endings, padding and IPv6 ranges survive; header key normalised" equals "$(settings_json)" '{"trust_proxy":false,"proxy_header":"x_real_ip","trusted_proxies":[],"allow_ips":["203.0.113.11","2001:db8::\/32"],"deny_ips":[]}'
BEFORE_NEG="$(settings_json)"

save_settings -d 'dragonloginsecurity_save_settings=1' --data-urlencode 'deny_ips=192.0.2.66'
check "missing nonce is refused (403)" equals "$(status "$TMP/h")" 403
check "missing nonce changes nothing" equals "$(settings_json)" "$BEFORE_NEG"
save_settings -d '_wpnonce=0123456789' -d 'dragonloginsecurity_save_settings=1' --data-urlencode 'deny_ips=192.0.2.66'
check "bad nonce is refused (403)" equals "$(status "$TMP/h")" 403
check "bad nonce changes nothing" equals "$(settings_json)" "$BEFORE_NEG"

JS="$TMP/sub.jar"
admin_session "$JS" dlsx_sub
SUBNONCE="$(session_nonce "$JS" "$SUB_ID" dragonloginsecurity_settings)"
curl -s -c "$JS" -b "$JS" -D "$TMP/h" -o "$TMP/b" -d "_wpnonce=$SUBNONCE" -d 'dragonloginsecurity_save_settings=1' \
	--data-urlencode 'deny_ips=192.0.2.66' "$BASE/wp-admin/options-general.php?page=$SLUG"
check "subscriber save with its own valid nonce changes nothing" equals "$(settings_json)" "$BEFORE_NEG"

# --------------------------------------------------------------------------
echo "== enrolment AJAX (profile screen)"
JE="$TMP/enrol.jar"
admin_session "$JE" dlsx_enrol
EN="$(enroll_nonce "$JE")"
check "profile screen localises the enrolment nonce" test -n "$EN"

ajax "$JE" -d action=dragonloginsecurity_totp_setup -d "nonce=$EN" -d "user_id=$ENROL_ID"
check "totp_setup returns a pending secret" json_ok
SECRET="$(php -r '$j = json_decode( (string) file_get_contents( $argv[1] ), true ); echo $j["data"]["secret"] ?? "";' "$TMP/ab")"

ajax "$JE" -d action=dragonloginsecurity_totp_confirm -d "nonce=$EN" -d "user_id=$ENROL_ID" -d 'code=000000'
check "totp_confirm with a wrong code is refused" json_error
check "wrong code enables nothing" equals "$(wpc user meta get "$ENROL_ID" dls_totp_secret)" ""
ajax "$JE" -d action=dragonloginsecurity_totp_confirm -d "user_id=$ENROL_ID" -d "code=$(wpc eval "echo $NS\\Provider_TOTP::code_at( '$SECRET', time() );")"
check "totp_confirm without a nonce is refused (-1/403)" ajax_refused
ajax "$JE" -d action=dragonloginsecurity_totp_confirm -d 'nonce=abc123' -d "user_id=$ENROL_ID" -d "code=$(wpc eval "echo $NS\\Provider_TOTP::code_at( '$SECRET', time() );")"
check "totp_confirm with a bad nonce is refused (-1/403)" ajax_refused
check "refused confirms enable nothing" equals "$(wpc user meta get "$ENROL_ID" dls_totp_secret)" ""
ajax "$JE" -d action=dragonloginsecurity_totp_confirm -d "nonce=$EN" -d "user_id=$ENROL_ID" --data-urlencode "code= $(wpc eval "echo $NS\\Provider_TOTP::code_at( '$SECRET', time() );") "
check "totp_confirm with the right code (padded) succeeds" json_ok
check "authenticator stored for the enrolling user" test -n "$(wpc user meta get "$ENROL_ID" dls_totp_secret)"

ajax "$JE" -d action=dragonloginsecurity_totp_setup -d "nonce=$EN" -d "user_id=$TARGET_ID"
check "totp_setup for another user is refused (403 JSON)" ajax_forbidden_json
ajax "$JE" -d action=dragonloginsecurity_backup_generate -d "nonce=$EN" -d "user_id[]=$ENROL_ID"
check "array user_id is not the caller's own id (403 JSON)" ajax_forbidden_json

ajax "$JE" -d action=dragonloginsecurity_passkey_options -d "nonce=$EN" -d "user_id=$ENROL_ID"
check "passkey_options returns registration options" json_ok
ajax "$JE" -d action=dragonloginsecurity_passkey_register -d "nonce=$EN" -d "user_id=$ENROL_ID" \
	--data-urlencode 'client_data=eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=' --data-urlencode 'attestation=AAAA' --data-urlencode 'label=My "key" \ 1'
check "passkey_register with a forged attestation fails cleanly" json_error
ajax "$JE" -d action=dragonloginsecurity_passkey_register -d "user_id=$ENROL_ID" -d 'client_data=x' -d 'attestation=y'
check "passkey_register without a nonce is refused (-1/403)" ajax_refused
check "no passkey stored" equals "$(wpc eval "echo count( $NS\\Credentials::for_user( $ENROL_ID ) );")" 0

ajax "$JE" -d action=dragonloginsecurity_passkey_remove -d "nonce=$EN" -d "user_id=$ENROL_ID" -d 'id=999999'
check "passkey_remove of an unknown id fails cleanly" json_error
ajax "$JE" -d action=dragonloginsecurity_passkey_remove -d 'nonce=zzz' -d "user_id=$ENROL_ID" -d 'id=1'
check "passkey_remove with a bad nonce is refused (-1/403)" ajax_refused

ajax "$JE" -d action=dragonloginsecurity_backup_generate -d "nonce=$EN" -d "user_id=$ENROL_ID"
check "backup_generate returns ten codes" equals "$(php -r '$j = json_decode( (string) file_get_contents( $argv[1] ), true ); echo count( $j["data"]["codes"] ?? array() );' "$TMP/ab")" 10
ajax "$JE" -d action=dragonloginsecurity_backup_confirm -d "user_id=$ENROL_ID"
check "backup_confirm without a nonce is refused (-1/403)" ajax_refused
check "refused confirm records nothing" equals "$(wpc user meta get "$ENROL_ID" dls_backup_codes_confirmed)" ""
ajax "$JE" -d action=dragonloginsecurity_backup_confirm -d "nonce=$EN" -d "user_id=$ENROL_ID"
check "backup_confirm succeeds" json_ok
check "confirmation recorded" equals "$(wpc user meta get "$ENROL_ID" dls_backup_codes_confirmed)" 1

arm_totp "$TARGET_ID"
SUBEN="$(session_nonce "$JS" "$SUB_ID" dls_ajax)"
check "subscriber session nonce minted" test -n "$SUBEN"
ajax "$JS" -d action=dragonloginsecurity_totp_disable -d "nonce=$SUBEN" -d "user_id=$TARGET_ID"
check "subscriber cannot turn off another user's authenticator (403 JSON)" ajax_forbidden_json
ajax "$JS" -d action=dragonloginsecurity_passkey_remove -d "nonce=$SUBEN" -d "user_id=$TARGET_ID" -d 'id=1'
check "subscriber cannot remove another user's passkey (403 JSON)" ajax_forbidden_json
ajax "$JE" -d action=dragonloginsecurity_totp_disable -d "user_id=$TARGET_ID"
check "totp_disable without a nonce is refused (-1/403)" ajax_refused
check "target authenticator still on after refused requests" test -n "$(wpc user meta get "$TARGET_ID" dls_totp_secret)"
ajax "$JE" -d action=dragonloginsecurity_totp_disable -d "nonce=$EN" -d "user_id=$TARGET_ID"
check "an administrator turns off another user's authenticator" json_ok
check "target authenticator removed" equals "$(wpc user meta get "$TARGET_ID" dls_totp_secret)" ""
ajax "$JS" -d action=dragonloginsecurity_backup_generate -d "nonce=$SUBEN" -d "user_id=$SUB_ID"
check "a subscriber may create their own backup codes" json_ok
ajax "$JE" -d action=dragonloginsecurity_totp_disable -d "nonce=$EN" -d "user_id=$ENROL_ID"
check "a user turns off their own authenticator" json_ok

# --------------------------------------------------------------------------
echo "== wp-login.php challenge"
unlock_all
JA="$TMP/a.jar"
: >"$JA"
login_post "$JA" dlsx_2fa_a -d 'rememberme=forever' --data-urlencode "redirect_to=$BASE/wp-admin/profile.php"
check "password step shows the challenge inline (200)" equals "$(status "$TMP/h")" 200
check "challenge form is shown" in_file "$TMP/b" 'name="dragonloginsecurity_token"'
check "challenge form carries a nonce" test -n "$(field "$TMP/b" dragonloginsecurity_2fa_nonce)"
check "remember-me carried into the form" equals "$(field "$TMP/b" rememberme)" forever
check "redirect_to carried into the form" equals "$(field "$TMP/b" redirect_to)" "$BASE/wp-admin/profile.php"
check "no sign-in cookie before the second factor" not_logged_in "$JA"

cp "$TMP/b" "$TMP/a_form"
submit_challenge "$JA" "dragonloginsecurity_code=$(totp_now "$A_ID")" nonce=-
check "submit without the nonce goes back to the login screen" equals "$(location "$TMP/h")" "$BASE/wp-login.php"
check "submit without the nonce signs nobody in" not_logged_in "$JA"
check "submit without the nonce counts no code attempt" equals "$(failures_meta "$A_ID")" '""'

cp "$TMP/a_form" "$TMP/b"
submit_challenge "$JA" "dragonloginsecurity_code=$(totp_now "$A_ID")" nonce=0123456789
check "submit with a bad nonce goes back to the login screen" equals "$(location "$TMP/h")" "$BASE/wp-login.php"
check "submit with a bad nonce signs nobody in" not_logged_in "$JA"

JB="$TMP/b.jar"
: >"$JB"
login_post "$JB" dlsx_2fa_b --data-urlencode "redirect_to=$BASE/wp-admin/"
cp "$TMP/b" "$TMP/b_form"
A_NONCE="$(field "$TMP/a_form" dragonloginsecurity_2fa_nonce)"
submit_challenge "$JB" "dragonloginsecurity_code=${B_CODES[0]}" method=backup "nonce=$A_NONCE"
check "another user's challenge nonce is refused" equals "$(location "$TMP/h")" "$BASE/wp-login.php"
check "cross-user nonce signs nobody in" not_logged_in "$JB"

# The refused requests did not spend the token: the original form still works.
cp "$TMP/a_form" "$TMP/b"
submit_challenge "$JA" "dragonloginsecurity_code=$(totp_now "$A_ID")"
check "valid TOTP submit redirects to redirect_to" equals "$(location "$TMP/h")" "$BASE/wp-admin/profile.php"
check "valid submit signs the user in" logged_in "$JA"
check "remember-me gives a persistent cookie" test "$(login_cookie_expiry "$JA")" -gt 0
curl -s -b "$JA" -D "$TMP/h" -o /dev/null "$BASE/wp-admin/profile.php"
check "signed-in session reaches the dashboard" equals "$(status "$TMP/h")" 200

: >"$JB"
login_post "$JB" dlsx_2fa_b --data-urlencode "redirect_to=$BASE/wp-admin/"
submit_challenge "$JB" 'dragonloginsecurity_code=11111-22222' method=backup
check "wrong code re-shows the challenge" in_file "$TMP/b" 'That code was not correct'
check "re-shown challenge carries a fresh nonce" test -n "$(field "$TMP/b" dragonloginsecurity_2fa_nonce)"
submit_challenge "$JB" "dragonloginsecurity_code=${B_CODES[1]}" method=backup
check "backup code after a wrong one signs in" equals "$(location "$TMP/h")" "$BASE/wp-admin/"
check "session login (no remember-me) gives a browser-session cookie" equals "$(login_cookie_expiry "$JB")" 0

: >"$JB"
login_post "$JB" dlsx_2fa_b
submit_challenge "$JB" method=passkey dragonloginsecurity_wa_token=x dragonloginsecurity_wa_id=AAAA \
	dragonloginsecurity_wa_client=e30= dragonloginsecurity_wa_auth=AAAA dragonloginsecurity_wa_sig=AAAA
check "forged passkey assertion is refused and re-challenged" in_file "$TMP/b" 'That code was not correct'
check "forged passkey signs nobody in" not_logged_in "$JB"

echo "== interim (session-expiry popup) and stale sign-in cookie"
unlock_all
JC="$TMP/c.jar"
: >"$JC"
login_post "$JC" dlsx_2fa_c -d 'interim-login=1'
check "interim challenge is shown inline (200)" equals "$(status "$TMP/h")" 200
follow_handover "$JC"
check "interim challenge keeps the popup flag" equals "$(field "$TMP/b" interim-login)" 1
submit_challenge "$JC" "dragonloginsecurity_code=${C_CODES[0]}" method=backup
check "interim submit shows the popup success screen" in_file "$TMP/b" 'interim-login-success'
check "interim submit signs the user in" logged_in "$JC"

plant_stale_cookie() {
	: >"$1"
	printf 'localhost\tFALSE\t/\tFALSE\t0\t%s\t%s\n' "$LOGGED_IN_NAME" 'dlsx_2fa_c|1700000000|staletokenstaletokenstaletokenstaletoken123|0000' >>"$1"
}
plant_stale_cookie "$JC"
login_post "$JC" dlsx_2fa_c --data-urlencode "redirect_to=$BASE/wp-admin/profile.php"
check "stale cookie: challenge continues on a fresh request (302)" in_file "$TMP/h" 'action=dragonloginsecurity_2fa'
follow_handover "$JC"
check "stale cookie: challenge form shown" in_file "$TMP/b" 'name="dragonloginsecurity_token"'
submit_challenge "$JC" "dragonloginsecurity_code=${C_CODES[1]}" method=backup
check "stale cookie: submit signs in" equals "$(location "$TMP/h")" "$BASE/wp-admin/profile.php"
check "stale cookie: session cookie set" logged_in "$JC"

plant_stale_cookie "$JC"
login_post "$JC" dlsx_2fa_c -d 'interim-login=1'
check "stale cookie + interim: challenge continues on a fresh request (302)" in_file "$TMP/h" 'action=dragonloginsecurity_2fa'
follow_handover "$JC"
check "stale cookie + interim: popup flag kept" equals "$(field "$TMP/b" interim-login)" 1
submit_challenge "$JC" "dragonloginsecurity_code=${C_CODES[2]}" method=backup
check "stale cookie + interim: popup success screen" in_file "$TMP/b" 'interim-login-success'

curl -s -D "$TMP/h" -o /dev/null "$BASE/wp-login.php?action=dragonloginsecurity_2fa&dragonloginsecurity_token=bogus"
check "resume with an unknown token goes to the login screen" equals "$(location "$TMP/h")" "$BASE/wp-login.php"
curl -s -o "$TMP/b" "$BASE/wp-login.php?dragonloginsecurity_2fa_locked=1"
check "locked message shows on the login screen" in_file "$TMP/b" 'Too many incorrect codes'

echo "== WooCommerce My Account sign-in"
unlock_all
PRODUCT_ID="$(wpc eval '$p = new WC_Product_Simple(); $p->set_name( "dlsx scenario product" ); $p->set_regular_price( "1" ); $p->set_status( "publish" ); echo $p->save();')"
MYACC="$(wpc eval 'echo wc_get_page_permalink( "myaccount" );')"
JW="$TMP/w.jar"
: >"$JW"
curl -s -c "$JW" -b "$JW" -o /dev/null "$BASE/?add-to-cart=$PRODUCT_ID"
check "WooCommerce session cookie present (cart)" in_file "$JW" 'wp_woocommerce_session_'
curl -s -c "$JW" -b "$JW" -o "$TMP/myacc" "$MYACC"
WNONCE="$(field "$TMP/myacc" woocommerce-login-nonce)"
check "My Account login form found" test -n "$WNONCE"
curl -s -c "$JW" -b "$JW" -D "$TMP/h" -o "$TMP/b" -e "$MYACC" \
	--data-urlencode 'username=dlsx_cust' --data-urlencode "password=$PW" -d 'rememberme=forever' \
	-d "woocommerce-login-nonce=$WNONCE" --data-urlencode "_wp_http_referer=$MYACC" -d 'login=Log+in' "$MYACC"
check "My Account sign-in hands over to the challenge" in_file "$TMP/h" 'action=dragonloginsecurity_2fa'
check "no sign-in cookie before the second factor (Woo)" not_logged_in "$JW"
follow_handover "$JW"
check "Woo challenge form carries a nonce" test -n "$(field "$TMP/b" dragonloginsecurity_2fa_nonce)"
check "Woo remember-me carried" equals "$(field "$TMP/b" rememberme)" forever
cp "$TMP/b" "$TMP/w_form"
submit_challenge "$JW" "dragonloginsecurity_code=$(totp_now "$CUST_ID")" nonce=badbadbad0
check "Woo submit with a bad nonce is refused" equals "$(location "$TMP/h")" "$BASE/wp-login.php"
cp "$TMP/w_form" "$TMP/b"
submit_challenge "$JW" "dragonloginsecurity_code=$(totp_now "$CUST_ID")"
check "Woo submit returns to My Account" equals "$(location "$TMP/h")" "$MYACC"
check "Woo submit signs the customer in" logged_in "$JW"
check "Woo remember-me gives a persistent cookie" test "$(login_cookie_expiry "$JW")" -gt 0
curl -s -c "$JW" -b "$JW" -o "$TMP/b" "$MYACC"
check "My Account shows the signed-in customer" in_file "$TMP/b" 'customer-logout'

# --------------------------------------------------------------------------
echo "== cleanup"
trap - EXIT INT TERM
restore_env
check "settings restored" equals "$(settings_json)" "$SETTINGS_BEFORE"
check "scenario users removed" equals "$(wpc user list --search='dlsx_*' --field=ID | wc -l | tr -d ' ')" 0
check "client address $CLIENT_IP not locked out" equals "$(wpc eval "echo ( new $NS\\Limit_Login() )->is_locked( '$CLIENT_IP' ) ? 'locked' : 'open';")" open

NEW_LOG="$(docker exec -i "$CLI" sh -c "tail -c +$((LOG_START + 1)) /var/www/html/wp-content/debug.log 2>/dev/null" | grep -E "/plugins/$SLUG(/|-pro/)" || true)"
if [ -z "$NEW_LOG" ]; then
	pass "no new PHP notices from $SLUG in debug.log"
else
	fail "no new PHP notices from $SLUG in debug.log"
	printf '%s\n' "$NEW_LOG" | head -20
fi

rm -rf "$TMP"
echo "$PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
