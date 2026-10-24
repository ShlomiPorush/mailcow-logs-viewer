#!/bin/sh
# mailcow-logs for agents on Linux and macOS without Node: plain POSIX sh, curl and awk, nothing else.
#
# One of three versions with one contract (see mailcow-logs.mjs): same commands, same JSON output and error codes,
# same files and the same lock, so they can run side by side. Tokens never appear in the output, and never on a
# command line (other users can read those): curl reads them from its standard input.
# R_* fields are read and written through eval (record_read, record_write).
# shellcheck disable=SC2034
set -u
set -f
umask 077

# Filled in with the mailcow Logs Viewer address when the file is downloaded from it.
DEFAULT_URL="__MAILCOW_LOGS_URL__"
CLIENT_ID="mailcow-logs-cli"
SCOPE="status:read status:write messages:read outbound:read outbound:write quarantine:read quarantine:write security:read security:write rspamd:read rspamd:write dmarc:read dmarc:write domains:read domains:write mailboxes:read mailboxes:write logs:read settings:read"
WAIT_SECONDS="${MAILCOW_LOGS_WAIT_SECONDS:-90}"
# A pending code is dropped locally only this long after its expiry: until then the server decides
STALE_CODE_SECONDS=600
POLL_SECONDS="${MAILCOW_LOGS_TEST_POLL_SECONDS:-5}"
# A refresh is retried only once it cannot be in flight any more: twice the request timeout (tests shorten it).
REFRESH_GRACE="${MAILCOW_LOGS_TEST_REFRESH_GRACE:-30}"
LOCK_WAIT_MS="${MAILCOW_LOGS_LOCK_WAIT_MS:-20000}"
# The server answers an API call within 60 s (or says the outcome is unknown).
API_TIMEOUT="${MAILCOW_LOGS_TEST_API_TIMEOUT:-75}"
# Wait before the one retry of a call the server refused as busy (tests shorten it).
BUSY_WAIT="${MAILCOW_LOGS_TEST_BUSY_WAIT:-2}"
KINDS_MAX_AGE=3600
UNKNOWN_OUTCOME="The action may have run. Read its state before trying again."
FIELDS="v:n issuer:s label:s generation:s refreshToken:s accessToken:s accessExpiresAt:n scope:s refreshStartedAt:n refreshRetried:n deviceCode:s userCode:s link:s deviceExpiresAt:n interval:n nextPollAt:n toRevoke:s"

LOCKTOKEN=""
TMPD=""
SECURED=0
FAIL_STATUS=""

now() { date +%s; }
rand() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
host() { uname -n; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
nap() { sleep "$1" 2>/dev/null || sleep 1; }
# A message or path inside a JSON string.
esc() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

cleanup() {
  [ -n "$LOCKTOKEN" ] && release
  [ -n "$TMPD" ] && rm -rf -- "$TMPD"
  return 0
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# fail CODE MESSAGE [BODYFILE]: prints the error and stops; a body is included when it is JSON.
fail() {
  body=""
  st=""
  [ -n "$FAIL_STATUS" ] && st=",\"status\":$FAIL_STATUS"
  if [ $# -ge 3 ] && [ -s "$3" ]; then
    first=$(tr -d ' \t\r\n' <"$3" | cut -c1)
    case "$first" in "{" | "[") body=",\"body\":$(tr -d '\r\n' <"$3")" ;; esac
  fi
  printf '{"error":"%s","message":"%s"%s%s}\n' "$1" "$(esc "$2")" "$st" "$body"
  exit 1
}

# Reading flat JSON: one string or number field; values with escapes do not match and read as empty.
jstr() { tr -d '\r\n' <"$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*/\1/p'; }
jnum() {
  v=$(tr -d '\r\n' <"$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
  printf '%s' "${v:-0}"
}
secret_ok() { case "$1" in "" | *[!A-Za-z0-9._~+/=-]*) return 1 ;; esac }
plain_ok() { case "$1" in *[\"\\]*) return 1 ;; esac }

# json_scan MODE FILE: a small JSON reader. "failed" prints 1 when the top object says "success": false or
# "status": "error", else 0; "kinds" prints "METHOD PATH KIND" for each object of the top object's "endpoints" list.
json_scan() {
  tr -d '\000-\010\013\014\016-\037' <"$2" | awk -v mode="$1" '
function value(k, kind, v) {
  if (mode == "failed") {
    if (depth == 1 && typ[1] == "{" && ((k == "success" && kind == "l" && v == "false") || (k == "status" && kind == "s" && v == "error"))) found = 1
  } else if (depth == 3 && typ[1] == "{" && typ[2] == "[" && typ[3] == "{" && ckey[2] == "endpoints" && kind == "s") {
    if (k == "method") em = v
    else if (k == "path") ep = v
    else if (k == "kind") ek = v
  }
}
function flush() { if (lit != "") { value(cur[depth], "l", lit); lit = "" } }
{ text = text $0 "\n" }
END {
  n = length(text); depth = 0; instr = 0; esc = 0; lit = ""; found = 0
  for (i = 1; i <= n; i++) {
    c = substr(text, i, 1)
    if (instr) {
      if (esc) { esc = 0; buf = buf c }
      else if (c == "\\") { esc = 1; buf = buf c }
      else if (c == "\"") {
        instr = 0
        if (typ[depth] == "{" && want[depth]) cur[depth] = buf
        else value(cur[depth], "s", buf)
      } else buf = buf c
      continue
    }
    if (c == "\"") { flush(); instr = 1; buf = ""; continue }
    if (c == "{" || c == "[") {
      flush(); depth++; typ[depth] = c; want[depth] = (c == "{"); cur[depth] = ""
      ckey[depth] = ""
      if (depth > 1 && typ[depth - 1] == "{") ckey[depth] = cur[depth - 1]
      if (depth == 3) { em = ""; ep = ""; ek = "" }
      continue
    }
    if (c == "}" || c == "]") {
      flush()
      if (mode == "kinds" && depth == 3 && typ[3] == "{" && typ[2] == "[" && ckey[2] == "endpoints" && em != "" && ep != "") {
        if (ek == "read") print em " " ep " read"
        else print em " " ep " act"
      }
      depth--
      continue
    }
    if (c == ":") { flush(); want[depth] = 0; continue }
    if (c == ",") { flush(); if (typ[depth] == "{") want[depth] = 1; continue }
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { flush(); continue }
    lit = lit c
  }
  if (mode == "failed") print found
}'
}

# json_string FILE: the file as one JSON string.
json_string() {
  nl=0
  [ -s "$1" ] && [ "$(tail -c1 "$1" | od -An -c | tr -d ' ')" = '\n' ] && nl=1
  tr -d '\000-\010\013\014\016-\037' <"$1" | awk -v nl="$nl" '
BEGIN { printf "%s", "\"" }
{
  if (NR > 1) printf "%s", "\\n"
  n = length($0); out = ""
  for (i = 1; i <= n; i++) {
    c = substr($0, i, 1)
    if (c == "\\") out = out "\\\\"
    else if (c == "\"") out = out "\\\""
    else if (c == "\t") out = out "\\t"
    else if (c == "\r") out = out "\\r"
    else out = out c
  }
  printf "%s", out
}
END { if (nl == 1) printf "%s", "\\n"; printf "%s", "\"" }'
}

HELP="mailcow-logs: use mailcow Logs Viewer after a person approves it.

  connect [--replace]   Ask to connect; prints a link and a code to show the person.
  connect --wait        Wait up to $WAIT_SECONDS s for the approval; run again while it answers still_waiting.
  access                What this connection may view or act on, and until when.
  endpoints [area]      The API calls this connection may make, with their kind (read or act).
  get <path>            GET /api/<path>, for example: get 'messages?limit=20'
  post|put|patch|delete <path> [--json <body> | --json-file <file>]
  status                Whether this agent is connected (no secrets).
  disconnect            End this agent's connection.

  --url <address>       The mailcow Logs Viewer address (or MAILCOW_LOGS_URL)."

sha() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256
  else openssl dgst -sha256 -r; fi
}

# The app's address, this agent's identity (the folder it is installed in) and where its connection is kept.
setup() {
  command -v curl >/dev/null 2>&1 || fail missing_curl "curl is needed. Install curl, or Node 20 or later."
  raw="${URL_OPTION:-${MAILCOW_LOGS_URL:-}}"
  if [ -z "$raw" ]; then case "$DEFAULT_URL" in __*) ;; *) raw="$DEFAULT_URL" ;; esac fi
  [ -n "$raw" ] || fail no_url "No mailcow Logs Viewer address. Pass --url https://<its address> or set MAILCOW_LOGS_URL."
  raw=${raw%/}
  case "$raw" in
    https://*) rest=${raw#https://} PROTO=https ;;
    http://*) rest=${raw#http://} PROTO=http ;;
    *) fail insecure_url "The address must start with https:// (http only for this computer)." ;;
  esac
  hostpart=$(lower "$rest")
  case "$hostpart" in
    "[::1]" | "[::1]:"*) name="[::1]" port=${hostpart#"[::1]"} ;;
    "" | *[!a-z0-9.:-]* | :* | *:*:*) fail insecure_url "Use the address alone, for example https://logs.example.com." ;;
    *) name=${hostpart%%:*} port=${hostpart#"$name"} ;;
  esac
  case "$port" in "" | :[0-9]*) ;; *) fail insecure_url "Use the address alone, for example https://logs.example.com." ;; esac
  if [ "$PROTO" = http ]; then
    case "$name" in 127.0.0.1 | localhost | "[::1]") ;; *) fail insecure_url "The address must start with https:// (http only for this computer)." ;; esac
  fi
  # As a browser writes the origin: lower case, no default port.
  case "$hostpart" in *:443) [ "$PROTO" = https ] && hostpart=${hostpart%:443} ;; *:80) [ "$PROTO" = http ] && hostpart=${hostpart%:80} ;; esac
  ISSUER="$PROTO://$hostpart"
  INSTALL=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P) || fail failed "Cannot find the skill's folder."
  base="${XDG_CONFIG_HOME:-$HOME/.config}"
  DIR="${MAILCOW_LOGS_CREDENTIALS:-$base/mailcow-logs}"
  case "$DIR" in /*) ;; *) DIR="$(pwd -P)/$DIR" ;; esac
  plain_ok "$DIR" || fail insecure_credentials "The mailcow-logs folder's path cannot contain quotes or backslashes."
  install_id
  key=$(printf '%s\n%s' "$ISSUER" "$ID" | sha | cut -c1-32)
  FILE="$DIR/$key.json"
  LOCK="$DIR/$key.lock"
  KINDS="$DIR/$key.kinds"
  if [ -n "${MAILCOW_LOGS_AGENT_NAME:-}" ]; then
    LABEL=$(printf '%s' "$MAILCOW_LOGS_AGENT_NAME" | cut -c1-60)
  else
    agent="Agent"
    oldifs=$IFS
    IFS=/
    for part in $INSTALL; do
      p=$(lower "$part")
      case "$p" in
        .claude) agent="Claude Code" && break ;;
        .claude*) agent="Claude Code ($p)" && break ;;
        .codex) agent="Codex" && break ;;
        .codex*) agent="Codex ($p)" && break ;;
        .cursor*) agent="Cursor" && break ;;
      esac
    done
    IFS=$oldifs
    LABEL=$(printf '%s on %s' "$agent" "$(host)" | cut -c1-60)
  fi
}

# This install's id, kept in the skill's folder (.install-id), so every version agrees on it however each one spells
# the folder's path. Published in one step: written aside, then linked into place, which fails if one is there.
install_id() {
  f="$INSTALL/.install-id"
  id=$(head -n1 "$f" 2>/dev/null | tr -d '\r')
  case "$id" in "" | *[!0-9a-f]*) id="" ;; esac
  if [ ${#id} -ne 32 ]; then
    t="$f.$(rand 6)"
    if (
      set -C
      printf '%s\n' "$(rand 16)" >"$t"
    ) 2>/dev/null; then ln "$t" "$f" 2>/dev/null || :; fi
    rm -f "$t"
    id=$(head -n1 "$f" 2>/dev/null | tr -d '\r')
    case "$id" in "" | *[!0-9a-f]*) id="" ;; esac
  fi
  [ ${#id} -eq 32 ] || fail cannot_save "Cannot write in $INSTALL. The agent's id is kept there; allow writing it."
  ID=$id
}

# Only this user may open the folder and its files; never loosened or fixed silently.
check_private() {
  [ -L "$1" ] && fail insecure_credentials "$1 must be plain, not a link."
  [ -O "$1" ] || fail insecure_credentials "$1 belongs to another user. Use a folder of your own."
  # The mode string itself is what is checked; the path is ours.
  # shellcheck disable=SC2012
  mode=$(ls -ld "$1" | cut -c5-11)
  case "$mode" in
    ------ | "------ " | ------@ | ------.) ;;
    *) if [ -d "$1" ]; then fail insecure_credentials "Others can open $1. Run: chmod 700 '$1'"; else fail insecure_credentials "Others can read $1. Run: chmod 600 '$1'"; fi ;;
  esac
}

secure_dir() {
  [ "$SECURED" = 1 ] && return 0
  mkdir -p "$DIR" 2>/dev/null || fail cannot_save "Cannot create $DIR. Allow this agent to write there."
  [ -d "$DIR" ] || fail insecure_credentials "$DIR must be a plain folder."
  check_private "$DIR"
  SECURED=1
  # Temp files of commands that were killed (their own cleanup never ran).
  set +f
  for d in "$DIR"/.tmp.*; do
    [ -d "$d" ] || continue
    pid=${d##*/.tmp.}
    pid=${pid%%.*}
    alive "$pid" || rm -rf -- "$d"
  done
  set -f
}

# A private folder for this command's temp files, inside the credentials folder (so a rename stays atomic).
tmpdir() {
  [ -n "$TMPD" ] && return 0
  secure_dir
  TMPD="$DIR/.tmp.$$.$(rand 4)"
  mkdir "$TMPD" 2>/dev/null || fail cannot_save "Cannot write in $DIR. Allow this agent to write there."
}

# The connection: one shell variable per field, R_<name>.
record_clear() {
  for f in $FIELDS; do
    k=${f%%:*}
    case "$f" in *:n) eval "R_$k=0" ;; *) eval "R_$k=''" ;; esac
  done
  R_v=1 R_issuer="$ISSUER" R_label="$LABEL"
}

# record_read: 0 when there is a record, 1 when there is none.
record_read() {
  record_clear
  [ -e "$FILE" ] || return 1
  [ -f "$FILE" ] || fail insecure_credentials "$FILE must be a plain file."
  check_private "$FILE"
  grep -q '^{' "$FILE" || fail insecure_credentials "$FILE is damaged. Delete it and connect again."
  for f in $FIELDS; do
    k=${f%%:*}
    case "$f" in
      *:n) v=$(jnum "$k" "$FILE") ;;
      *) v=$(jstr "$k" "$FILE") ;;
    esac
    eval "R_$k=\$v"
  done
  return 0
}

# write_private TARGET TEXTFILE: moves a file written in the temp folder over TARGET, in one step.
write_private() {
  sync -- "$2" 2>/dev/null || :
  mv -f "$2" "$1" 2>/dev/null || fail cannot_save "Cannot replace $1."
}

record_write() {
  secure_dir
  out="{"
  sep=""
  for f in $FIELDS; do
    k=${f%%:*}
    eval "v=\${R_$k}"
    case "$f" in
      *:n)
        case "$v" in "" | *[!0-9]*) v=0 ;; esac
        out="$out$sep\"$k\":$v"
        ;;
      *)
        plain_ok "$v" || fail unexpected_answer "mailcow Logs Viewer sent a value that cannot be stored ($k)."
        out="$out$sep\"$k\":\"$v\""
        ;;
    esac
    sep=","
  done
  tmpdir
  tmp="$TMPD/record.$(rand 6)"
  # noclobber: created new, private by the umask.
  if ! (
    set -C
    printf '%s}\n' "$out" >"$tmp"
  ) 2>/dev/null; then
    fail cannot_save "Cannot write in $DIR. Allow this agent to write there."
  fi
  write_private "$FILE" "$tmp"
}

record_remove() { rm -f "$FILE" "$KINDS"; }

# The lock: a file created exclusively, naming its holder. Never taken from a live holder, however old.

lock_field() { printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}\([^",}]*\)"\{0,1\}.*/\1/p'; }

hook() {
  name=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  eval "at=\${MAILCOW_LOGS_TEST_HOLD_$name:-}"
  [ -n "$at" ] || return 0
  printf '%s' "$$" >"$at.reached"
  i=0
  while [ $i -lt 1200 ] && [ ! -e "$at.go" ]; do
    nap 0.05
    i=$((i + 1))
  done
}

alive() { kill -0 "$1" 2>/dev/null; }

# acquire [OWN]: takes the lock; OWN is a lock this process held before, which counts as taken if it is back in place.
acquire() {
  own=${1:-}
  secure_dir
  token=$(rand 16)
  line=$(printf '{"pid":%s,"host":"%s","token":"%s","startedAt":%s}' "$$" "$(host)" "$token" "$(now)")
  waited=0
  while :; do
    if (
      set -C
      printf '%s' "$line" >"$LOCK"
    ) 2>/dev/null; then
      LOCKTOKEN=$token
      hook locked
      return 0
    fi
    [ -e "$LOCK" ] || [ -w "$DIR" ] || fail cannot_save "Cannot create a lock in $DIR."
    held=$(cat "$LOCK" 2>/dev/null) || held=""
    dead=0
    if [ -e "$LOCK" ]; then
      htoken=$(lock_field "$held" token)
      # Another process moved this one's lock away by mistake and has put it back.
      if [ -n "$own" ] && [ "$htoken" = "$own" ]; then
        LOCKTOKEN=$own
        return 0
      fi
      if [ -z "$htoken" ]; then
        # A holder that died between creating the lock and writing its name leaves it empty; that takes a moment.
        [ -n "$(find "$LOCK" -mmin +1 2>/dev/null)" ] && dead=1
      elif [ "$(lower "$(lock_field "$held" host)")" = "$(lower "$(host)")" ] && ! alive "$(lock_field "$held" pid)"; then
        dead=1
      fi
    fi
    if [ $dead = 1 ]; then
      hook break-observed
      if break_lock "$htoken"; then continue; fi
    fi
    if [ "$waited" -gt "$LOCK_WAIT_MS" ]; then
      started=$(lock_field "$held" startedAt)
      if [ -n "$htoken" ] && [ -n "$started" ] && [ $(($(now) - started)) -gt 600 ]; then
        fail busy "Another mailcow-logs command has held $LOCK for over 10 minutes. If none is running, delete that file."
      fi
      fail busy "Another mailcow-logs command is using this connection. Nothing was sent; run it again."
    fi
    nap 0.2
    waited=$((waited + 200))
  done
}

# Moving the dead lock away is atomic, so of two that try only one moves it; if what was moved is not the dead lock
# (another process had just taken a fresh one), it goes back unless a newer one is there (ln never overwrites).
break_lock() {
  moved="$LOCK.$(rand 6).dead"
  mv "$LOCK" "$moved" 2>/dev/null || return 0
  hook break-moved
  got=$(lock_field "$(cat "$moved" 2>/dev/null)" token)
  if [ "$got" = "$1" ]; then
    rm -f "$moved"
    return 0
  fi
  ln "$moved" "$LOCK" 2>/dev/null || :
  rm -f "$moved"
  return 1
}

mine() { [ -n "$LOCKTOKEN" ] && [ "$(lock_field "$(cat "$LOCK" 2>/dev/null)" token)" = "$LOCKTOKEN" ]; }

release() {
  mine && rm -f "$LOCK"
  LOCKTOKEN=""
}

assert_mine() { mine || fail busy "Another mailcow-logs command took over this connection. Run it again."; }

# Requests. http METHOD URL [SETTINGS [TIMEOUT]]: SETTINGS are more curl settings, with the secrets; curl reads them
# from its standard input (printf is built in, so they are on no command line). Sets STATUS, CTYPE, RESP and SENT (no
# when the name, the connection or TLS failed first, so nothing reached the app).
http() {
  tmpdir
  RESP="$TMPD/resp.$(rand 6)"
  errf="$TMPD/err.$(rand 6)"
  out=$(printf 'url = "%s"\nrequest = "%s"\nheader = "Accept: application/json"\n%s\n' "$2" "$1" "${3:-}" |
    curl -q -sS -K - --proto "=$PROTO" --max-time "${4:-15}" --connect-timeout 10 -o "$RESP" -w '%{http_code} %{content_type}' 2>"$errf")
  rc=$?
  STATUS=${out%% *}
  CTYPE=$(lower "${out#* }")
  SENT=yes
  if [ $rc -ne 0 ]; then
    case $rc in 5 | 6 | 7 | 35 | 51 | 53 | 54 | 58 | 59 | 60 | 66 | 77 | 80 | 83 | 90 | 91) SENT=no ;; esac
    UNREACHABLE="Cannot reach $ISSUER ($(tr -d '\r\n' <"$errf" | cut -c1-120))."
    return 1
  fi
  return 0
}

# oauth PATH NAME=VALUE...: a form post to the authorization server.
oauth() {
  p=$1
  shift
  settings=$(printf 'data-urlencode = "client_id=%s"' "$CLIENT_ID")
  for kv in "$@"; do settings=$(printf '%s\ndata-urlencode = "%s"' "$settings" "$kv"); done
  http POST "$ISSUER$p" "$settings"
}

http_fail() {
  detail=$(jstr error_description "$RESP")
  [ -n "$detail" ] || detail=$(jstr message "$RESP")
  [ -n "$detail" ] || detail=$(jstr detail "$RESP")
  [ -n "$detail" ] || detail=$(jstr error "$RESP")
  if [ -n "$detail" ]; then fail "http_$STATUS" "$1 failed ($STATUS: $detail)." "$RESP"; fi
  fail "http_$STATUS" "$1 failed ($STATUS)." "$RESP"
}

# Reads the tokens of a 200 answer into the record variables.
take_tokens() {
  at=$(jstr access_token "$RESP")
  rt=$(jstr refresh_token "$RESP")
  sc=$(jstr scope "$RESP")
  ex=$(jnum expires_in "$RESP")
  if ! secret_ok "$at" || ! secret_ok "$rt" || ! plain_ok "$sc"; then
    fail unexpected_answer "mailcow Logs Viewer answered without usable tokens."
  fi
  R_refreshToken=$rt R_accessToken=$at R_scope=$sc R_accessExpiresAt=$(($(now) + ex))
}

revoke_pending() {
  [ -n "$R_toRevoke" ] || return 0
  left=""
  for t in $R_toRevoke; do
    if oauth /oauth/revoke "token=$t" "token_type_hint=refresh_token" && [ "$STATUS" = 200 ]; then :; else left="$left $t"; fi
  done
  left=$(printf '%s' "$left" | sed 's/^ *//')
  if [ "$left" != "$R_toRevoke" ]; then
    R_toRevoke=$left
    record_write
  fi
}

clear_pending() { R_deviceCode='' R_userCode='' R_link='' R_deviceExpiresAt=0 R_interval=0 R_nextPollAt=0; }

print_pending() {
  left=$((R_deviceExpiresAt - $(now)))
  [ $left -lt 0 ] && left=0
  printf '{"status":"pending","link":"%s","code":"%s","expiresIn":%s,"next":"End your turn with a reply that shows the person the link and the code and asks them to reply once they approve. When they reply, run: mailcow-logs connect --wait"}\n' \
    "$(esc "$R_link")" "$(esc "$R_userCode")" "$left"
}

# Commands

cmd_status() {
  if record_read && [ -n "$R_refreshToken" ]; then
    left=$((R_accessExpiresAt - $(now)))
    [ $left -lt 0 ] && left=0
    printf '{"status":"connected","url":"%s","label":"%s","scope":"%s","accessExpiresIn":%s}\n' \
      "$ISSUER" "$(esc "$R_label")" "$(esc "$R_scope")" "$left"
  elif [ -n "$R_deviceCode" ]; then
    printf '{"status":"pending","url":"%s","label":"%s"}\n' "$ISSUER" "$(esc "$R_label")"
  else
    printf '{"status":"not_connected","url":"%s","label":"%s"}\n' "$ISSUER" "$(esc "$LABEL")"
  fi
}

cmd_connect() {
  # Before any code exists: can it keep a connection here, and is the app there?
  secure_dir
  probe="$DIR/.probe-$(rand 4)"
  if ! (
    set -C
    : >"$probe"
  ) 2>/dev/null; then fail cannot_save "Cannot write in $DIR. Allow this agent to write there."; fi
  rm -f "$probe"
  http GET "$ISSUER/.well-known/oauth-authorization-server" || fail unreachable "$UNREACHABLE"
  if [ "$STATUS" != 200 ] || [ "$(jstr issuer "$RESP")" != "$ISSUER" ]; then
    fail unreachable "$ISSUER does not answer as mailcow Logs Viewer with agent access on ($STATUS). Check the address, and that agent access is on in Settings > Agents."
  fi
  acquire
  record_read || :
  revoke_pending
  if [ -n "$R_refreshToken" ] && [ "$REPLACE" != 1 ]; then
    printf '{"status":"already_connected","label":"%s","scope":"%s"}\n' "$(esc "$R_label")" "$(esc "$R_scope")"
    return 0
  fi
  # The open code again, unless asked for a new one (--replace: the link did not work for the person).
  if [ -n "$R_deviceCode" ] && [ $((R_deviceExpiresAt - $(now))) -gt 30 ] && [ "$REPLACE" != 1 ]; then
    print_pending
    return 0
  fi
  assert_mine
  oauth /oauth/device "scope=$SCOPE" "resource=$ISSUER/api" "client_label=$LABEL" || fail unreachable "$UNREACHABLE"
  [ "$STATUS" = 200 ] || http_fail "Asking to connect"
  dc=$(jstr device_code "$RESP")
  uc=$(jstr user_code "$RESP")
  link=$(jstr verification_uri_complete "$RESP")
  secret_ok "$dc" || fail unexpected_answer "mailcow Logs Viewer answered without a code."
  case "$uc" in "" | *[!A-Z0-9-]*) fail unexpected_answer "mailcow Logs Viewer answered without a code." ;; esac
  case "$link" in "$ISSUER"/*) ;; *) fail unexpected_answer "The approval link is not on mailcow Logs Viewer." ;; esac
  plain_ok "$link" || fail unexpected_answer "mailcow Logs Viewer answered without a code."
  interval=$(jnum interval "$RESP")
  [ "$interval" -le 0 ] && interval=$POLL_SECONDS
  [ "$interval" -lt "$POLL_SECONDS" ] && interval=$POLL_SECONDS
  expires=$(jnum expires_in "$RESP")
  [ "$expires" -le 0 ] && expires=600
  [ "$expires" -lt 60 ] && expires=60
  R_label=$LABEL R_deviceCode=$dc R_userCode=$uc R_link=$link
  R_deviceExpiresAt=$(($(now) + expires)) R_interval=$interval R_nextPollAt=$(($(now) + interval))
  record_write
  print_pending
}

cmd_wait() {
  until=$(($(now) + WAIT_SECONDS))
  while :; do
    acquire
    if ! record_read || [ -z "$R_deviceCode" ]; then
      if [ -n "$R_refreshToken" ]; then
        printf '{"status":"connected","label":"%s","scope":"%s"}\n' "$(esc "$R_label")" "$(esc "$R_scope")"
        return 0
      fi
      fail not_connected "No connection is being made. Run: mailcow-logs connect"
    fi
    t=$(now)
    if [ $((R_deviceExpiresAt + STALE_CODE_SECONDS)) -le "$t" ]; then
      clear_pending
      record_write
      fail expired "The code expired before it was approved. Run: mailcow-logs connect"
    fi
    wait=0
    if [ "$R_nextPollAt" -gt "$t" ]; then
      wait=$((R_nextPollAt - t))
    else
      assert_mine
      if ! oauth /oauth/token "grant_type=urn:ietf:params:oauth:grant-type:device_code" "device_code=$R_deviceCode"; then
        R_nextPollAt=$((t + R_interval))
        record_write
        fail unreachable "$UNREACHABLE"
      fi
      err=$(jstr error "$RESP")
      if [ "$STATUS" = 200 ]; then
        old=$R_refreshToken
        take_tokens
        # Connecting again (--replace): the old connection is ended once the new one is stored.
        if [ -n "$old" ] && [ "$old" != "$R_refreshToken" ]; then R_toRevoke=$(printf '%s %s' "$R_toRevoke" "$old" | sed 's/^ *//'); fi
        clear_pending
        R_generation=$(rand 8) R_refreshStartedAt=0 R_refreshRetried=0
        record_write
        rm -f "$KINDS"
        revoke_pending
        printf '{"status":"connected","label":"%s","scope":"%s"}\n' "$(esc "$R_label")" "$(esc "$R_scope")"
        return 0
      fi
      case "$err" in
        authorization_pending | slow_down)
          [ "$err" = slow_down ] && R_interval=$((R_interval + 5))
          R_nextPollAt=$((t + R_interval))
          record_write
          wait=$R_interval
          ;;
        access_denied)
          clear_pending
          record_write
          fail denied "The person did not approve the connection."
          ;;
        expired_token | invalid_grant)
          clear_pending
          record_write
          fail expired "The code is no longer valid. Run: mailcow-logs connect"
          ;;
        *) http_fail "Waiting for the approval" ;;
      esac
    fi
    release
    if [ $(($(now) + wait)) -gt "$until" ]; then
      printf '{"status":"still_waiting","next":"Not approved yet. Run again: mailcow-logs connect --wait"}\n'
      return 0
    fi
    sleep "$wait"
  done
}

usable() { [ -n "$R_accessToken" ] && [ $((R_accessExpiresAt - $(now))) -gt 60 ] && [ "$R_refreshStartedAt" = 0 ]; }

# access_token [STALE]: sets TOKEN to a live access token: the stored one while it lasts, else one refresh.
access_token() {
  stale=${1:-}
  record_read || fail not_connected "Not connected. Run: mailcow-logs connect"
  [ -n "$R_refreshToken" ] || fail not_connected "Not connected. Run: mailcow-logs connect"
  if [ -z "$stale" ] && usable; then
    TOKEN=$R_accessToken
    return 0
  fi
  acquire
  record_read || fail not_connected "Not connected. Run: mailcow-logs connect"
  [ -n "$R_refreshToken" ] || fail not_connected "Not connected. Run: mailcow-logs connect"
  revoke_pending
  # Another command refreshed while this one waited for the lock.
  if usable && [ "$R_accessToken" != "$stale" ]; then
    TOKEN=$R_accessToken
    release
    return 0
  fi
  b_started=$R_refreshStartedAt
  b_retried=$R_refreshRetried
  # A refresh that started moments ago may still be on its way (its holder lost the lock): never send it twice.
  if [ "$R_refreshStartedAt" != 0 ] && [ $(($(now) - R_refreshStartedAt)) -lt "$REFRESH_GRACE" ]; then
    fail busy "Another mailcow-logs command is refreshing this connection. Nothing was sent; run it again."
  fi
  if [ "$R_refreshStartedAt" != 0 ]; then
    # The last refresh got no answer; trying once more either continues the connection or ends it there.
    [ "$R_refreshRetried" != 0 ] && fail connection_ended "Two refreshes got no answer, so this connection cannot be trusted. Run: mailcow-logs connect --replace"
    R_refreshRetried=1
  fi
  R_refreshStartedAt=$(now)
  record_write
  assert_mine
  hook before-refresh
  if ! oauth /oauth/token "grant_type=refresh_token" "refresh_token=$R_refreshToken" "resource=$ISSUER/api"; then
    # Nothing left the computer: the token is as good as before.
    if [ "$SENT" = no ]; then
      R_refreshStartedAt=$b_started R_refreshRetried=$b_retried
      record_write
    fi
    fail unreachable "$UNREACHABLE"
  fi
  if [ "$STATUS" = 200 ]; then
    take_tokens
    R_refreshStartedAt=0 R_refreshRetried=0
    hook before-write
    if ! mine; then
      # The lock was taken while this one waited for the app: keep the new tokens anyway, under a fresh lock.
      held_before=$LOCKTOKEN
      LOCKTOKEN=""
      acquire "$held_before"
    fi
    record_write
    TOKEN=$R_accessToken
    release
    return 0
  fi
  if [ "$(jstr error "$RESP")" = invalid_grant ]; then
    # An old connection still to be ended (after --replace) keeps its place until the app confirms it.
    if [ -n "$R_toRevoke" ]; then
      keep=$R_toRevoke
      name=$R_label
      record_clear
      R_toRevoke=$keep R_label=$name
      record_write
    else
      record_remove
    fi
    fail connection_ended "This connection has ended (disconnected in Settings, its time ran out, sign-in settings changed, or its token was used twice). Run: mailcow-logs connect"
  fi
  # The app answered with an error before spending the token (a 4xx); a 5xx may have come after.
  if [ "$STATUS" -lt 500 ]; then
    R_refreshStartedAt=$b_started R_refreshRetried=$b_retried
    record_write
  fi
  http_fail "Refreshing the connection"
}

# api_url PATH: sets URL (to send to), APATH (the path alone) and HASQ (1 when there is a query).
api_url() {
  bad="Give a path of the API, for example: messages?limit=20 (percent-encode anything else)"
  p=$1
  case "$p" in /api/*) p=${p#/api} ;; esac
  case "$p" in "" | *://* | //* | *[!A-Za-z0-9._~!\$\&\'\(\)*+,\;=:@/?%-]*) fail bad_path "$bad" ;; esac
  # Encoded dots too: a server or proxy that decodes them would take the token out of the API.
  case "$(lower "$p")" in *%2e*) fail bad_path "$bad" ;; esac
  case "$p" in /*) ;; *) p="/$p" ;; esac
  pathonly=${p%%\?*}
  case "$pathonly/" in */../* | */./*) fail bad_path "$bad" ;; esac
  [ "$pathonly" = "/" ] && fail bad_path "$bad"
  URL="$ISSUER/api$p"
  APATH="/api$pathonly"
  HASQ=0
  case "$p" in *\?*) HASQ=1 ;; esac
}

# api_call METHOD URL TOKEN [BODYFILE]
api_call() {
  settings=$(printf 'header = "Authorization: Bearer %s"' "$3")
  if [ -n "${4:-}" ]; then settings=$(printf '%s\nheader = "Content-Type: application/json"\ndata-binary = "@%s"' "$settings" "$4"); fi
  http "$1" "$2" "$settings" "$API_TIMEOUT"
}

# api_send METHOD URL BODYFILE KIND: one API call with its retries. A refresh and one retry after a 401 (the server
# checks the token before the route runs), one retry after a 429 busy (nothing started), and for a read one retry
# after a network failure. An action is never sent again once it may have reached the app.
api_send() {
  access_token
  refreshed=0 busied=0 netted=0
  while :; do
    if ! api_call "$1" "$2" "$TOKEN" "$3"; then
      if [ "$4" = act ]; then
        [ "$SENT" = no ] && fail unreachable "$UNREACHABLE"
        fail outcome_unknown "$UNKNOWN_OUTCOME"
      fi
      [ $netted = 1 ] && fail unreachable "$UNREACHABLE"
      netted=1
      continue
    fi
    if [ "$STATUS" = 401 ] && [ $refreshed = 0 ]; then
      refreshed=1
      access_token "$TOKEN"
      continue
    fi
    if [ "$STATUS" = 429 ] && [ "$(jstr error "$RESP")" = busy ] && [ $busied = 0 ]; then
      busied=1
      nap "$BUSY_WAIT"
      continue
    fi
    if [ "$4" = act ] && [ "$STATUS" -ge 500 ]; then
      FAIL_STATUS=$STATUS
      fail outcome_unknown "$UNKNOWN_OUTCOME"
    fi
    return 0
  done
}

# Kinds: whether a call is a read or an action, from the server's own list of this connection's calls.

# kinds_lookup METHOD PATH: prints read, act, or stale (no usable list).
kinds_lookup() {
  [ -f "$KINDS" ] || {
    printf 'stale'
    return 0
  }
  awk -v m="$1" -v p="$2" -v gen="$R_generation" -v t="$(now)" -v maxage="$KINDS_MAX_AGE" '
function match_t(tpl, pth,   tn, sn, ta, sa, i, j, rest) {
  tn = split(tpl, ta, "/"); sn = split(pth, sa, "/")
  for (i = 1; i <= tn; i++) {
    if (ta[i] ~ /^[{][^}]*:path[}]$/) {
      if (i != tn || sn < i) return 0
      rest = ""
      for (j = i; j <= sn; j++) rest = rest sa[j]
      return rest != ""
    }
    if (i > sn) return 0
    if (ta[i] ~ /^[{][^}]*[}]$/) { if (sa[i] == "") return 0 }
    else if (ta[i] != sa[i]) return 0
  }
  return tn == sn
}
NR == 1 { if ($1 != "mailcow-logs-kinds" || $2 != "1" || $3 != gen || t - $4 > maxage) { bad = 1; exit } ; next }
NF == 3 && $1 == m && $2 ~ /^\/api\/[A-Za-z0-9._~{}:\/-]*$/ && ($3 == "read" || $3 == "act") {
  if (match_t($2, p)) { hit = 1; if ($3 == "act") act = 1 }
}
END { if (bad || NR == 0) printf "stale"; else if (!hit) printf "act"; else if (act) printf "act"; else printf "read" }' "$KINDS"
}

# kinds_write ANSWERFILE: keeps the list of an agent/endpoints answer for this connection.
kinds_write() {
  [ -n "$R_generation" ] || return 0
  tmpdir
  tmp="$TMPD/kinds.$(rand 6)"
  {
    printf 'mailcow-logs-kinds 1 %s %s\n' "$R_generation" "$(now)"
    json_scan kinds "$1" | awk 'NF == 3 && $1 ~ /^[A-Z][A-Z][A-Z]+$/ && $2 ~ /^\/api\/[A-Za-z0-9._~{}:\/-]*$/'
  } >"$tmp" 2>/dev/null || return 0
  write_private "$KINDS" "$tmp"
}

# kind_of METHOD PATH: sets KIND. An endpoint the list does not hold, or no list, counts as an action.
kind_of() {
  KIND=act
  if [ "$1" = GET ]; then
    case "$2" in /api/agent/access | /api/agent/endpoints) KIND=read && return 0 ;; esac
  fi
  record_read || return 0
  [ -n "$R_refreshToken" ] || return 0
  k=$(kinds_lookup "$1" "$2")
  if [ "$k" = stale ]; then
    # Fetched in a subshell: a failure there leaves every call counting as an action, and stops nothing here.
    tmpdir
    got="$TMPD/endpoints.$(rand 6)"
    (
      trap 'release' EXIT
      api_send GET "$ISSUER/api/agent/endpoints" "" read >/dev/null
      case "$STATUS" in 200) cp "$RESP" "$got" ;; esac
    ) >/dev/null 2>&1
    if [ -s "$got" ]; then
      record_read || return 0
      kinds_write "$got"
    fi
    k=$(kinds_lookup "$1" "$2")
  fi
  case "$k" in read) KIND=read ;; esac
}

cmd_api() {
  method=$1
  api_url "${2:-}"
  bodyfile=""
  if [ "$method" != GET ] && { [ "$method" != DELETE ] || [ -n "$JSON_FILE" ] || [ -n "$JSON_BODY" ]; }; then
    secure_dir
    tmpdir
    bodyfile="$TMPD/body.$(rand 6)"
    if [ -n "$JSON_FILE" ]; then
      cat -- "$JSON_FILE" >"$bodyfile" 2>/dev/null || fail bad_body "Cannot read $JSON_FILE."
    else
      if [ -n "$JSON_BODY" ]; then printf '%s' "$JSON_BODY" >"$bodyfile"; else printf '{}' >"$bodyfile"; fi
    fi
    first=$(tr -d ' \t\r\n' <"$bodyfile" | cut -c1)
    case "$first" in "{" | "[") ;; *) fail bad_body "The body is not JSON." ;; esac
  fi
  kind_of "$method" "$APATH"
  api_send "$method" "$URL" "$bodyfile" "$KIND"
  case "$STATUS" in
    2??)
      isjson=0
      case "$CTYPE" in *json*)
        first=$(tr -d ' \t\r\n' <"$RESP" | cut -c1)
        case "$first" in "{" | "[") isjson=1 ;; esac
        ;;
      esac
      if [ "$method" = GET ] && [ "$APATH" = /api/agent/endpoints ] && [ "$HASQ" = 0 ] && [ $isjson = 1 ]; then
        record_read && kinds_write "$RESP"
      fi
      if [ $isjson = 1 ]; then data=$(tr -d '\r\n' <"$RESP"); else data=$(json_string "$RESP"); fi
      if [ $isjson = 1 ] && [ "$(json_scan failed "$RESP")" = 1 ]; then
        printf '{"error":"failed","message":"%s","status":%s,"data":%s}\n' "$(esc "$method ${2:-} answered that it failed.")" "$STATUS" "$data"
        exit 1
      fi
      printf '{"status":%s,"data":%s}\n' "$STATUS" "$data"
      return 0
      ;;
  esac
  # The app's own refusals for agents carry a code and a message: passed on as they are.
  code=$(jstr error "$RESP")
  message=$(jstr message "$RESP")
  case "$code" in "" | *[!a-z_]*) ;; *)
    if [ -n "$message" ] && [ ${#code} -le 40 ]; then
      FAIL_STATUS=$STATUS
      fail "$code" "$message"
    fi
    ;;
  esac
  http_fail "$method ${2:-}"
}

cmd_disconnect() {
  acquire
  if ! record_read; then
    printf '{"status":"not_connected"}\n'
    return 0
  fi
  assert_mine
  left=""
  for t in $R_refreshToken $R_toRevoke; do
    if oauth /oauth/revoke "token=$t" "token_type_hint=refresh_token" && [ "$STATUS" = 200 ]; then :; else left="$left $t"; fi
  done
  if [ -n "$left" ]; then
    R_refreshToken='' R_accessToken='' R_accessExpiresAt=0 R_toRevoke=$(printf '%s' "$left" | sed 's/^ *//')
    record_write
    fail disconnect_failed "mailcow Logs Viewer did not confirm the disconnect. Run it again, or disconnect this agent in Settings > Agents."
  fi
  record_remove
  printf '{"status":"disconnected"}\n'
}

COMMAND=${1:-help}
[ $# -gt 0 ] && shift
URL_OPTION="" REPLACE=0 WAIT=0 JSON_BODY="" JSON_FILE="" ARG="" HAVEARG=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL_OPTION=${2:-} && shift ;;
    --replace) REPLACE=1 ;;
    --wait) WAIT=1 ;;
    --json) JSON_BODY=${2:-} && shift ;;
    --json-file) JSON_FILE=${2:-} && shift ;;
    *) [ $HAVEARG = 0 ] && ARG=$1 && HAVEARG=1 ;;
  esac
  shift
done

case "$COMMAND" in
  help | --help | -h)
    printf '%s\n' "$HELP"
    exit 0
    ;;
esac
setup
case "$COMMAND" in
  status) cmd_status ;;
  connect) if [ "$WAIT" = 1 ]; then cmd_wait; else cmd_connect; fi ;;
  access) cmd_api GET agent/access ;;
  endpoints)
    if [ $HAVEARG = 0 ]; then
      cmd_api GET agent/endpoints
    else
      case "$ARG" in "" | *[!a-z_]*) fail bad_path "Give an area name, for example: security" ;; esac
      cmd_api GET "agent/endpoints?area=$ARG"
    fi
    ;;
  get) cmd_api GET "$ARG" ;;
  post) cmd_api POST "$ARG" ;;
  put) cmd_api PUT "$ARG" ;;
  patch) cmd_api PATCH "$ARG" ;;
  delete) cmd_api DELETE "$ARG" ;;
  disconnect) cmd_disconnect ;;
  *) fail unknown_command "Unknown command \"$COMMAND\". Run: mailcow-logs help" ;;
esac
