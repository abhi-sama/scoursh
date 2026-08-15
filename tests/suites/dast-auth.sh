#!/usr/bin/env bash
# tests/suites/dast-auth.sh - modules/dast/auth.sh and auth_engine.sh:
# authentication and session acquisition (docs/DESIGN.md §7.0,
# docs/STEP5-DAST-PLAN.md DAST-03).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout, per docs/DESIGN.md §12 ("DAST
# logic is testable with no live target"), so this suite runs on a host with no
# network and no Docker.  The companion tests/e2e/dast-auth-live.sh proves the
# same code against the real, authorized local target, and is opt-in for exactly
# the reason this file is not.
#
# The seven things this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. A world-readable credential file is REFUSED, not warned about (E073), and
#      that applies to a `secret-file` as well as to config/auth.conf itself.
#   2. E074 is a real gate: a record whose `mode` needs a key it does not have
#      fails config load, rather than failing at the first request against a
#      live target.
#   3. `api-key` sends the RAW value, `bearer` sends `Bearer <value>`.  One
#      implementation for both would send a credential the target never issued.
#   4. A 2xx login that returns neither a cookie nor a token is NOT a session.
#   5. A failed login marks the identity `failed` WITH A REASON and lets the run
#      continue; it never leaves the identity looking usable and never runs the
#      authenticated checks unauthenticated.
#   6. Re-auth on 401 happens ONCE.  A loop is a login storm against somebody's
#      identity provider.
#   7. Two identities get two genuinely distinct sessions - the case DAST-29
#      (`authz.sh`) is built on.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes config keys and JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/dast/auth_engine.sh
source "$ROOT/modules/dast/auth_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

# Deliberately NOT $SCOURSH_SCRATCH/dast-auth: that is the session store's own
# path, and `_reset` below erases it between cases.  A workspace sharing it
# would take the run directory - and every finding shard in it - with it.
W=$SCOURSH_SCRATCH/dast-auth-workspace
rm -rf "$W"
mkdir -p "$W"

run_init "$W/run"

# ---------------------------------------------------------------------------
# The fixture scope, and the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
# The scope file lives in the SCRATCH workspace rather than under
# tests/fixtures/, so DAST-35's "no bundled scan target" lint has nothing new to
# reason about and tests/lint-rules.sh needs no new fixture-schema row.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: auth-fixture
base-url: https://auth.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-auth.sh. Never dialled: both the
  resolver and the transport are stubbed.

id: other-fixture
base-url: https://other.fixture.example/
notes: A SECOND in-scope target, so the cross-origin credential-drop case can
  redirect from one authorised origin to another authorised origin - which is
  the case a scope-gate-only reading of the rule would happily leak across.
EOF

_auth_resolve() {
  case $1 in
    auth.fixture.example) printf '93.184.216.34' ;;
    other.fixture.example) printf '93.184.216.35' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_auth_resolve

# The scripted transport.  Responses are QUEUED ON DISK rather than in a shell
# array, and the queue cursor is a file: lib/http.sh calls the transport inside
# a command substitution, so a subshell's increment of a shell variable is
# discarded the moment it returns - the same property lib/core.sh's
# `worker_id_set` is written the way it is for.
RESP=$W/resp
REQ_LOG=$W/requests.log
REQ_DETAIL=$W/requests.detail

_resp_reset() {
  rm -rf "$RESP"
  mkdir -p "$RESP"
  printf '0' >"$RESP/.count"
  printf '0' >"$RESP/.cursor"
  : >"$REQ_LOG"
  : >"$REQ_DETAIL"
}

# `_resp_add STATUS SETCOOKIE BODY`
_resp_add() {
  local n
  IFS= read -r n <"$RESP/.count" || true
  n=$(( n + 1 ))
  printf '%s' "$n" >"$RESP/.count"
  printf '%s\n%s\n' "$1" "$2" >"$RESP/$n.meta"
  printf '%s' "$3" >"$RESP/$n.body"
}

_auth_transport() {
  local method=$1 path=$5
  local n status setcookie body h
  IFS= read -r n <"$RESP/.cursor" || true
  n=$(( n + 1 ))
  printf '%s' "$n" >"$RESP/.cursor"

  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  {
    printf -- '--- %s %s\n' "$method" "$path"
    for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
      printf 'H %s\n' "$h"
    done
    printf 'BODYFLAG %s\n' "${_HTTP_TX_HAS_BODY:-false}"
    printf 'B %s\n' "${_HTTP_TX_BODY:-}"
  } >>"$REQ_DETAIL"

  status=500 setcookie='' body=''
  if [[ -r $RESP/$n.meta ]]; then
    { IFS= read -r status; IFS= read -r setcookie; } <"$RESP/$n.meta" || true
    IFS= read -r -d '' body <"$RESP/$n.body" || true
  fi

  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    printf '%s' "$body" >"$_HTTP_TX_BODY_OUT"
  fi
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    {
      printf 'HTTP/1.1 %s Stub\n' "$status"
      [[ -n $setcookie ]] && printf 'Set-Cookie: %s\n' "$setcookie"
      printf '\n'
    } >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '%s\n\n' "$status"
}
SCOURSH_HTTP_TRANSPORT=_auth_transport

http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# `_write_auth_conf MODE-600-PATH <<record text` helper: writes and chmods.
_auth_conf() {
  local path=$1
  shift
  : >"$path"
  chmod 600 "$path"
  printf '%s' "$1" >"$path"
}

_secret_file() {
  local path=$1 value=$2
  : >"$path"
  chmod 600 "$path"
  printf '%s' "$value" >"$path"
}

# One clean slate per case: the session store is keyed on (target, label) and
# lives for the whole run, so a case that did not reset it would be asserting
# against the previous case's session.
_reset() {
  rm -rf "$SCOURSH_SCRATCH/dast-auth"
  DAST_AUTH_LOADED=0
  records_clear auth 2>/dev/null || true
  _resp_reset
}

# The header the LAST request carried, not the first.  A re-auth case logs four
# requests, and reading the first Authorization header would report the STALE
# token that provoked the 401 - which is the very thing the retry is supposed to
# have replaced, so a first-match reader would fail the correct implementation
# and pass one that never refreshed the header at all.
_header_of() {
  local name=$1 line out=''
  while IFS= read -r line; do
    case $line in
      "H $name: "*) out=${line#"H $name: "} ;;
    esac
  done <"$REQ_DETAIL"
  printf '%s' "$out"
  return 0
}

# Every finding shard this run has written, as text, with no pipeline that can
# fail on an unmatched glob under `pipefail`.
_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_shard_lines() {
  local line n=0
  while IFS= read -r line; do
    [[ -n $line ]] && n=$(( n + 1 ))
  done <<<"$(_shard_text)"
  printf '%s' "$n"
}

_request_count() {
  local n=0 line
  while IFS= read -r line; do
    [[ -n $line ]] && n=$(( n + 1 ))
  done <"$REQ_LOG"
  printf '%s' "$n"
}

_last_body() {
  local line out=''
  while IFS= read -r line; do
    case $line in
      'B '*) out=${line#B } ;;
    esac
  done <"$REQ_DETAIL"
  printf '%s' "$out"
}

# =============================================================================
printf -- '\n-- A. config/auth.conf is a credential file, and is treated as one --\n'
# =============================================================================

t_case 'a config/auth.conf that is not mode 600 is REFUSED, not warned about'
_reset
CONF=$W/auth-perm.conf
printf 'id: auth-fixture.a\nmode: bearer\ntoken: t0ken\n' >"$CONF"
chmod 644 "$CONF"
assert_status 4 'a mode-644 config/auth.conf exits 4 (E073) - fails under "tests/lint-rules.sh already checks E073", which has said nothing at all about the operator'"'"'s own file on the operator'"'"'s own host' \
  bash -c "source '$ROOT/modules/dast/auth_engine.sh'; dast_auth_load '$CONF'"
PERM_ERR=$(bash -c "source '$ROOT/modules/dast/auth_engine.sh'; dast_auth_load '$CONF'" 2>&1 || true)
assert_contains "$PERM_ERR" 'E073' 'the refusal names the frozen error code'
assert_contains "$PERM_ERR" 'chmod 600' 'and tells the operator exactly how to fix it'

t_case 'an ABSENT config/auth.conf is not an error at all'
_reset
DAST_AUTH_RC=0
dast_auth_load "$W/does-not-exist.conf" || DAST_AUTH_RC=$?
assert_eq 1 "$DAST_AUTH_RC" \
  'an absent file returns 1 rather than dying - fails under "auth.conf is a required input", which would make every unauthenticated dast run exit 4 (docs/FOUNDATION.md tension 14 classes an absent requires-config as a DECLARED reduction)'

t_case 'a well-formed mode-600 file loads'
_reset
CONF=$W/auth-ok.conf
_auth_conf "$CONF" 'id: auth-fixture.a
mode: bearer
token: t0ken
'
dast_auth_load "$CONF"
assert_eq 1 "$DAST_AUTH_LOADED" 'the record set is loaded'
dast_auth_labels_set auth-fixture
assert_eq 'a' "${_DAST_AUTH_LABELS[*]}" 'and the identity label is discoverable by target'

# =============================================================================
printf -- '\n-- B. E074: mode-dependent required keys (rules/RULE-FORMAT.md §9.6.2) --\n'
# =============================================================================

_e074_of() {
  local text=$1 out
  : >"$W/e074.conf"
  chmod 600 "$W/e074.conf"
  printf '%s' "$text" >"$W/e074.conf"
  out=$(bash -c "source '$ROOT/modules/dast/auth_engine.sh'; dast_auth_load '$W/e074.conf'" 2>&1 || true)
  printf '%s' "$out"
}

t_case 'mode form without login-path is E074'
OUT=$(_e074_of 'id: auth-fixture.a
mode: form
username: u
password: p
')
assert_contains "$OUT" 'E074' \
  'a form identity with no login-path fails config validation - fails under "the mode table is checked at login time", which turns a config typo into a failed scan against a live target'
assert_contains "$OUT" 'login-path' 'and names the key that is missing'

t_case 'mode bearer with neither token nor secret-file is E074'
OUT=$(_e074_of 'id: auth-fixture.a
mode: bearer
header-name: X-Token
')
assert_contains "$OUT" 'E074' \
  'a credential-less bearer identity is refused - fails under "only the plainly required keys are checked", which lets a record with no credential at all validate cleanly'
assert_contains "$OUT" 'secret-file' 'and names secret-file as the preferred form (§9.6.2)'

t_case 'mode srp with a username and a pool but no token is E074, and says why'
OUT=$(_e074_of 'id: auth-fixture.a
mode: srp
username: u
password: p
pool-id: some-pool
')
assert_contains "$OUT" 'E074' \
  'srp without a pre-obtained token is refused at load - fails under "srp validates like form and fails later", which is the reading that lets an operator believe scoursh computes the SRP handshake'
assert_contains "$OUT" 'does not compute the SRP handshake' \
  'and the message states which of docs/DESIGN.md §7.0'"'"'s two permitted implementations this build chose, rather than leaving it to be inferred'

t_case 'an unknown mode is E024 alone, not E024 AND E074'
OUT=$(_e074_of 'id: auth-fixture.a
mode: kerberos
token: t
')
assert_contains "$OUT" 'E024' 'an unrecognised mode is an enum violation'
assert_not_contains "$OUT" 'E074' \
  'and NOT also a missing-key violation - fails under a table with a permissive default arm, which reports one typo as two separate faults and sends the operator looking for a second bug'

t_case 'each valid mode with its required keys passes'
for spec in \
  'bearer|token: t' \
  'api-key|token: t' \
  'external|token: t' \
  'srp|token: t' \
  'form|username: u
login-path: /login
secret-file: /tmp/x
password: p' \
  'oauth2-password|token-url: https://auth.fixture.example/token
username: u
password: p' \
  'oauth2-client|token-url: https://auth.fixture.example/token
client-id: cid
client-secret: cs'; do
  MODE=${spec%%|*}
  KEYS=${spec#*|}
  OUT=$(_e074_of "id: auth-fixture.a
mode: $MODE
$KEYS
")
  assert_not_contains "$OUT" 'E074' "mode $MODE with its required keys validates cleanly"
done

# =============================================================================
printf -- '\n-- C. the static credential modes --\n'
# =============================================================================

t_case 'bearer attaches "Bearer <token>" and sends no request of its own'
_reset
_auth_conf "$W/c1.conf" 'id: auth-fixture.a
mode: bearer
token: t0ken-b
'
dast_auth_load "$W/c1.conf"
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'a static bearer identity is authenticated'
assert_eq 0 "$(_request_count)" \
  'and it sent NOTHING to do it - fails under "every mode logs in", which would put a request on the wire for a credential the operator already handed us'
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'Bearer t0ken-b' "$(_header_of Authorization)" \
  'the request carries Authorization: Bearer <token> - fails if the session is stored but never applied, which is a scan that reports every authenticated endpoint as 401'

t_case 'api-key sends the RAW value, under its own header'
_reset
_auth_conf "$W/c2.conf" 'id: auth-fixture.a
mode: api-key
token: raw-key-value
header-name: X-API-Key
'
dast_auth_load "$W/c2.conf"
dast_auth_acquire auth-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'raw-key-value' "$(_header_of X-API-Key)" \
  'an API key is sent verbatim under header-name - FAILS under one shared implementation that prefixes every credential with "Bearer ", which sends a credential shape the target never issued and reports a working key as rejected'
assert_eq '' "$(_header_of Authorization)" \
  'and nothing is sent under Authorization when header-name names another header'

t_case 'header-name defaults to Authorization (§9.6.2'"'"'s own default)'
_reset
_auth_conf "$W/c3.conf" 'id: auth-fixture.a
mode: api-key
token: k
'
dast_auth_load "$W/c3.conf"
dast_auth_acquire auth-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'k' "$(_header_of Authorization)" \
  'the schema default is honoured - fails if the default lives only in the documentation'

t_case 'srp authenticates from a pre-obtained token AND records that the handshake was not computed'
_reset
_auth_conf "$W/c4.conf" 'id: auth-fixture.a
mode: srp
username: u
pool-id: a-pool
token: srp-issued-jwt
'
dast_auth_load "$W/c4.conf"
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" \
  'srp with a pre-obtained token authenticates - fails under "srp is unimplemented, so refuse", which docs/DESIGN.md §7.0 explicitly does not require'
assert_contains "$(run_facts coverage_reduction)" 'srp_handshake_not_computed' \
  'and the RUN says the SRP exchange was not performed - fails under "it works, so say nothing", which lets mode: srp read as evidence that the provider'"'"'s SRP implementation was exercised'

t_case 'external authenticates and is recorded as a mode of its own'
_reset
_auth_conf "$W/c5.conf" 'id: auth-fixture.a
mode: external
token: out-of-band
'
dast_auth_load "$W/c5.conf"
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'an externally-obtained credential is a usable session'
dast_auth_state auth-fixture a
assert_eq external "$_DAST_AUTH_MODE" \
  'and the mode is persisted as external rather than collapsed into api-key - fails if the two are merged, which loses the fact that nothing here checked the session was still fresh'

# =============================================================================
printf -- '\n-- D. the credential itself (docs/FOUNDATION.md tension 9) --\n'
# =============================================================================

t_case 'a secret-file that is not mode 600 is refused'
_reset
SF=$W/secret-loose
printf 'hunter2' >"$SF"
chmod 644 "$SF"
_auth_conf "$W/d1.conf" "id: auth-fixture.a
mode: bearer
secret-file: $SF
"
assert_status 4 'a mode-644 secret-file exits 4 - FAILS if only config/auth.conf'"'"'s own permissions are checked, which leaves the file that actually holds the password world-readable' \
  bash -c "source '$ROOT/modules/dast/auth_engine.sh'; http_scope_load '$SCOPE'; config_scope_load '$SCOPE'; dast_auth_load '$W/d1.conf'; dast_auth_acquire auth-fixture a"

t_case 'a relative secret-file path is refused (§9.6.2 says absolute)'
_reset
_auth_conf "$W/d2.conf" 'id: auth-fixture.a
mode: bearer
secret-file: relative/path
'
assert_status 4 'a relative secret-file exits 4 - fails under "resolve it against the cwd", which makes which credential is read depend on where the operator stood' \
  bash -c "source '$ROOT/modules/dast/auth_engine.sh'; dast_auth_load '$W/d2.conf'; dast_auth_acquire auth-fixture a"

t_case 'secret-file WINS over an inline value'
_reset
SF=$W/secret-wins
_secret_file "$SF" 'from-the-file'
_auth_conf "$W/d3.conf" "id: auth-fixture.a
mode: bearer
token: from-the-record
secret-file: $SF
"
dast_auth_load "$W/d3.conf"
dast_auth_acquire auth-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'Bearer from-the-file' "$(_header_of Authorization)" \
  'the file is preferred, as §9.6.2 requires - FAILS under "read the inline value first and fall back to the file", which silently ignores the operator'"'"'s more careful configuration'

t_case 'an EMPTY secret-file is a stated failure, not an empty credential on the wire'
_reset
SF=$W/secret-empty
_secret_file "$SF" ''
_auth_conf "$W/d4.conf" "id: auth-fixture.a
mode: form
username: u
login-path: /login
secret-file: $SF
"
dast_auth_load "$W/d4.conf"
RC=0
dast_auth_acquire auth-fixture a || RC=$?
assert_eq 1 "$RC" 'acquisition fails'
assert_eq failed "$_DAST_AUTH_STATE" 'and the identity is marked failed'
assert_eq 0 "$(_request_count)" \
  'and NO login request was sent with an empty password - FAILS under "the file existed, so use what is in it", which sends a blank credential and then reports the rejection as the target'"'"'s behaviour'
assert_contains "$_DAST_AUTH_FAIL_REASON" 'no usable credential' 'the reason names the real cause'

t_case 'a trailing newline in a secret-file is not part of the credential'
_reset
SF=$W/secret-nl
: >"$SF"
chmod 600 "$SF"
printf 'tok-with-newline\n' >"$SF"
_auth_conf "$W/d5.conf" "id: auth-fixture.a
mode: api-key
secret-file: $SF
"
dast_auth_load "$W/d5.conf"
dast_auth_acquire auth-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'tok-with-newline' "$(_header_of Authorization)" \
  'the editor-added newline is stripped - FAILS if the whole file is read, in which case lib/http.sh refuses the header outright (a CR/LF in a header value is request splitting) and every authenticated check dies on a config file that looks correct'

# =============================================================================
printf -- '\n-- E. form login (docs/DESIGN.md §7.0) --\n'
# =============================================================================

_form_conf() {
  _auth_conf "$W/form.conf" "id: auth-fixture.a
mode: form
username: user@fixture.example
password: p4ss word&special
login-path: /rest/user/login
"
  dast_auth_load "$W/form.conf"
}

t_case 'the first body shape that yields a session wins, and nothing more is sent'
_reset
_form_conf
_resp_add 200 'sid=abc; Path=/; HttpOnly' '{}'
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'the login succeeded'
assert_eq 1 "$(_request_count)" \
  'exactly ONE login request was sent - FAILS under "try all three shapes and pick the best", which triples the login traffic against every target and walks straight into an account lockout policy'
assert_contains "$(_last_body)" 'username=user%40fixture.example' \
  'the first shape is application/x-www-form-urlencoded, and the value is percent-encoded - fails if the username is interpolated raw, which breaks on the @ every email address has'
assert_contains "$(_last_body)" 'password=p4ss%20word%26special' \
  'and so is the password, including its space and its ampersand - FAILS under a naive concatenation, where the & starts a third parameter and the password silently becomes "p4ss word"'

t_case 'a Set-Cookie IS a session, even with no token in the body'
_reset
_form_conf
_resp_add 200 'sid=abc123; Path=/; HttpOnly' '{}'
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" \
  'a cookie-only login is a session - FAILS under "a session is a token", which is the reading that cannot log in to any classic server-rendered application at all (docs/DESIGN.md §7.0: "POST creds, capture Set-Cookie")'
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'sid=abc123' "$(_header_of Cookie)" \
  'and the cookie is replayed on the next request, with its attributes stripped'

t_case 'the JSON fallback runs only when the urlencoded shape produced no session'
_reset
_form_conf
_resp_add 401 '' '{"error":"Invalid email or password."}'
_resp_add 200 '' '{"authentication":{"token":"jwt-abc","bid":7}}'
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'the second shape logged in'
assert_eq 2 "$(_request_count)" \
  'two requests: the urlencoded attempt and the JSON one - fails under "give up on the first non-2xx", which cannot authenticate against a JSON login API, and under "always send all three", which sends a third after already succeeding'
assert_contains "$(_last_body)" '"email":"user@fixture.example"' \
  'the JSON shape uses the email field name real login APIs use'
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'Bearer jwt-abc' "$(_header_of Authorization)" \
  'and the token is dug out of the NESTED authentication object - fails under a flat top-level-keys-only reader, which is the shape a real login API is least likely to use'

t_case 'a re-auth replays the shape that worked and never probes again'
_reset
_form_conf
_resp_add 401 '' '{}'
_resp_add 200 '' '{"token":"first"}'
dast_auth_acquire auth-fixture a
assert_eq 2 "$(_request_count)" 'the first acquisition probed two shapes'
_resp_add 200 '' '{"token":"second"}'
dast_auth_acquire auth-fixture a
assert_eq 3 "$(_request_count)" \
  'the SECOND acquisition sent exactly one more request - FAILS if the shape is not pinned, in which case every re-auth re-probes and a long run multiplies its login traffic by three'

t_case 'a 200 that returns neither a cookie nor a token is NOT a session'
_reset
_form_conf
_resp_add 200 '' '<html>Please log in</html>'
_resp_add 200 '' '<html>Please log in</html>'
_resp_add 200 '' '<html>Please log in</html>'
RC=0
dast_auth_acquire auth-fixture a || RC=$?
assert_eq 1 "$RC" 'acquisition reports failure'
assert_eq failed "$_DAST_AUTH_STATE" \
  'the identity is failed - FAILS under "2xx means logged in", which is how a login form that re-renders itself on failure gets recorded as a working session and every authenticated check then reports clean against anonymous content'
assert_contains "$_DAST_AUTH_FAIL_REASON" 'neither a Set-Cookie nor a token' \
  'and the reason states exactly what was missing'

t_case 'a target that answers nothing at all is a stated failure, not a crash'
_reset
_form_conf
_down_transport() {
  printf '%s %s\n' "$1" "$5" >>"$REQ_LOG"
  return 1
}
SCOURSH_HTTP_TRANSPORT=_down_transport
RC=0
dast_auth_acquire auth-fixture a || RC=$?
SCOURSH_HTTP_TRANSPORT=_auth_transport
assert_eq 1 "$RC" 'acquisition reports failure rather than dying'
assert_eq failed "$_DAST_AUTH_STATE" 'and the identity is marked failed'
assert_eq 1 "$(_request_count)" \
  'it gave up after the FIRST shape - FAILS if a transport failure is treated like a rejected shape, which would send the other two body shapes at a target that is not answering, on top of the breaker already counting the first as a failure'
assert_contains "$_DAST_AUTH_FAIL_REASON" 'no response at all' \
  'and the reason distinguishes "the target did not answer" from "the target said no" - fails under one shared message, which sends an operator looking at their credentials when the host is down'

t_case 'a login that is rejected outright leaves a stated reason and does not abort the run'
_reset
_form_conf
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
RC=0
dast_auth_acquire auth-fixture a || RC=$?
assert_eq 1 "$RC" 'acquisition returns non-zero'
assert_eq failed "$_DAST_AUTH_STATE" 'the identity is marked failed'
assert_contains "$(dast_auth_skip_reason auth-fixture a)" 'is not authenticated' \
  'and every later check has a sentence to state - FAILS if a failed login is silent, which is the "quietly loses its session and reports no findings" outcome docs/DESIGN.md §15 exists to forbid'
assert_contains "$(dast_auth_skip_reason auth-fixture a)" '401' \
  'and the sentence carries what the target actually answered'

t_case 'an authenticated identity has no skip reason at all'
_reset
_form_conf
_resp_add 200 'sid=x' '{}'
dast_auth_acquire auth-fixture a
assert_eq '' "$(dast_auth_skip_reason auth-fixture a)" \
  'a working identity produces the empty string - fails if the reason is a status line rather than a skip reason, which would make every check skip on a session it actually has'

# =============================================================================
printf -- '\n-- F. the OAuth2 grants (RFC 6749 §4.3 and §4.4) --\n'
# =============================================================================

t_case 'the password grant posts grant_type=password with the credential urlencoded'
_reset
_auth_conf "$W/f1.conf" 'id: auth-fixture.a
mode: oauth2-password
token-url: https://auth.fixture.example/oauth/token
username: u@fixture.example
password: pw+1
client-id: my-client
scope: read write
'
dast_auth_load "$W/f1.conf"
_resp_add 200 '' '{"access_token":"at-1","token_type":"Bearer","expires_in":3600}'
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'the grant succeeded'
BODY=$(_last_body)
assert_contains "$BODY" 'grant_type=password' 'the grant type is the RFC name'
assert_contains "$BODY" 'username=u%40fixture.example' 'the username is urlencoded'
assert_contains "$BODY" 'password=pw%2B1' \
  'and so is the password - FAILS under raw concatenation, where the + decodes to a space at the server and the correct password is rejected'
assert_contains "$BODY" 'client_id=my-client' 'the client id is sent'
assert_contains "$BODY" 'scope=read%20write' 'and the scope, encoded'
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'Bearer at-1' "$(_header_of Authorization)" 'the access token is applied as a bearer token'

t_case 'the client-credentials grant sends no username'
_reset
_auth_conf "$W/f2.conf" 'id: auth-fixture.a
mode: oauth2-client
token-url: https://auth.fixture.example/oauth/token
client-id: cid
client-secret: csecret
'
dast_auth_load "$W/f2.conf"
_resp_add 200 '' '{"access_token":"at-2"}'
dast_auth_acquire auth-fixture a
BODY=$(_last_body)
assert_contains "$BODY" 'grant_type=client_credentials' 'the grant type is client_credentials'
assert_contains "$BODY" 'client_secret=csecret' 'the client secret is sent as a body parameter'
assert_not_contains "$BODY" 'username=' \
  'and no username is sent - fails if the two grants share one body builder, which sends an empty username= the RFC does not define for this grant'

t_case 'token_type from the response decides the scheme'
_reset
_auth_conf "$W/f3.conf" 'id: auth-fixture.a
mode: oauth2-client
token-url: https://auth.fixture.example/oauth/token
client-id: cid
client-secret: cs
'
dast_auth_load "$W/f3.conf"
_resp_add 200 '' '{"access_token":"at-3","token_type":"DPoP"}'
dast_auth_acquire auth-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'DPoP at-3' "$(_header_of Authorization)" \
  'the server-declared token_type is used - fails under a hardcoded "Bearer", which sends the wrong scheme to any provider that issues another'

t_case 'a rejected grant states the error the endpoint reported'
_reset
_auth_conf "$W/f4.conf" 'id: auth-fixture.a
mode: oauth2-password
token-url: https://auth.fixture.example/oauth/token
username: u
password: p
'
dast_auth_load "$W/f4.conf"
_resp_add 400 '' '{"error":"invalid_grant","error_description":"Bad credentials"}'
RC=0
dast_auth_acquire auth-fixture a || RC=$?
assert_eq 1 "$RC" 'the grant fails'
assert_contains "$_DAST_AUTH_FAIL_REASON" 'invalid_grant' \
  'and the reason carries RFC 6749 §5.2'"'"'s own error code - fails under "HTTP 400" alone, which cannot distinguish a wrong password from a misconfigured client'

t_case 'a 200 with no access_token is a failure, not a session'
_reset
_auth_conf "$W/f5.conf" 'id: auth-fixture.a
mode: oauth2-client
token-url: https://auth.fixture.example/oauth/token
client-id: c
client-secret: s
'
dast_auth_load "$W/f5.conf"
_resp_add 200 '' '{"expires_in":3600}'
RC=0
dast_auth_acquire auth-fixture a || RC=$?
assert_eq 1 "$RC" \
  'a token endpoint that returns 200 and no token is a failed acquisition - fails under "2xx is success", which stores an empty credential and sends unauthenticated requests under an authenticated label'

# =============================================================================
printf -- '\n-- G. transparent re-auth on 401 (docs/DESIGN.md §7.0) --\n'
# =============================================================================

t_case 'a 401 is answered by re-authenticating once and retrying'
_reset
_form_conf
_resp_add 200 '' '{"token":"tok-1"}'   # 1: login
dast_auth_acquire auth-fixture a
_resp_add 401 '' '{}'                   # 2: the protected request, expired
_resp_add 200 '' '{"token":"tok-2"}'    # 3: the re-login
_resp_add 200 '' 'the real content'     # 4: the retry
RC=0
dast_auth_request auth-fixture a GET https://auth.fixture.example/me || RC=$?
assert_eq 0 "$RC" 'the request ultimately succeeds'
assert_eq 200 "$_DAST_AUTH_REQ_STATUS" 'and reports the RETRY'"'"'s status, not the 401'
assert_eq 4 "$(_request_count)" \
  'four requests: login, 401, re-login, retry - FAILS if the 401 is simply returned to the caller, which is how an expired session turns every authenticated check into a clean result'
assert_eq 'Bearer tok-2' "$(_header_of Authorization)" \
  'and the retry carried the FRESH token - fails if re-auth refreshes the store but the retry replays the stale header it had already composed'

t_case 're-auth happens ONCE; a second 401 is a stated failure, not a loop'
_reset
_form_conf
_resp_add 200 '' '{"token":"t1"}'   # login
dast_auth_acquire auth-fixture a
_resp_add 401 '' '{}'                # protected: 401
_resp_add 200 '' '{"token":"t2"}'    # re-login succeeds
_resp_add 401 '' '{}'                # retry: 401 again
RC=0
dast_auth_request auth-fixture a GET https://auth.fixture.example/me || RC=$?
assert_eq 1 "$RC" 'the caller is told the request could not be made authenticated'
assert_eq 4 "$(_request_count)" \
  'exactly four requests, and no fifth - FAILS under a retry LOOP, which turns an always-401 endpoint into an unbounded login storm against somebody else'"'"'s identity provider'
dast_auth_state auth-fixture a
assert_eq failed "$_DAST_AUTH_STATE" 'the identity is marked failed for the rest of the run'
assert_contains "$_DAST_AUTH_REASON" 'rejected with 401' 'with a reason a later check can state'

t_case 'a re-auth that cannot log in at all is recorded as a coverage reduction'
_reset
_form_conf
_resp_add 200 '' '{"token":"t1"}'
dast_auth_acquire auth-fixture a
_resp_add 401 '' '{}'     # protected
_resp_add 401 '' '{}'     # the re-login itself is rejected
RC=0
dast_auth_request auth-fixture a GET https://auth.fixture.example/me || RC=$?
assert_eq 1 "$RC" 'the request fails'
assert_contains "$(run_facts coverage_reduction)" 'reason=reauth_failed' \
  'and the RUN records why - FAILS if the failure is only a return value, which leaves run.json describing a complete authenticated scan'

t_case 'an unauthenticated identity is never silently sent unauthenticated'
_reset
_form_conf
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
dast_auth_acquire auth-fixture a || true
BEFORE=$(_request_count)
RC=0
dast_auth_request auth-fixture a GET https://auth.fixture.example/me || RC=$?
assert_eq 1 "$RC" 'the request is refused'
assert_eq "$BEFORE" "$(_request_count)" \
  'and NOTHING was sent - FAILS under "attach what we have and carry on", which issues an anonymous request and lets the caller record its 200 as an authenticated result'

# =============================================================================
printf -- '\n-- H. two identities, two distinct sessions (the DAST-29 case) --\n'
# =============================================================================

t_case 'two labelled identities get two genuinely distinct sessions'
_reset
_auth_conf "$W/h1.conf" 'id: auth-fixture.a
mode: form
username: a@fixture.example
password: pa
login-path: /rest/user/login

id: auth-fixture.b
mode: form
username: b@fixture.example
password: pb
login-path: /rest/user/login
'
dast_auth_load "$W/h1.conf"
dast_auth_labels_set auth-fixture
assert_eq 'a b' "${_DAST_AUTH_LABELS[*]}" \
  'both labels are discovered, in file order - fails under a sorted list, which silently swaps identity A and identity B when somebody renames one'

_resp_add 200 'sid=cookie-A' '{"token":"token-A"}'
dast_auth_acquire auth-fixture a
_resp_add 200 'sid=cookie-B' '{"token":"token-B"}'
dast_auth_acquire auth-fixture b

_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
TOKEN_A=$(_header_of Authorization)
COOKIE_A=$(_header_of Cookie)
: >"$REQ_DETAIL"
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture b GET https://auth.fixture.example/me
TOKEN_B=$(_header_of Authorization)
COOKIE_B=$(_header_of Cookie)

assert_eq 'Bearer token-A' "$TOKEN_A" 'identity A sends its own token'
assert_eq 'Bearer token-B' "$TOKEN_B" 'identity B sends its own token'
assert_ne "$TOKEN_A" "$TOKEN_B" \
  'the two tokens are different - FAILS under a single shared session store, where the second login overwrites the first and DAST-29 would compare an identity with itself and report no IDOR anywhere'
assert_eq 'sid=cookie-A' "$COOKIE_A" 'identity A sends its own cookie jar'
assert_ne "$COOKIE_A" "$COOKIE_B" 'and the two jars are distinct too'

t_case 'only the identities that actually logged in count as available'
_reset
_auth_conf "$W/h2.conf" 'id: auth-fixture.a
mode: bearer
token: fine

id: auth-fixture.b
mode: form
username: b
password: p
login-path: /login
'
dast_auth_load "$W/h2.conf"
dast_auth_acquire auth-fixture a
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
_resp_add 401 '' '{}'
dast_auth_acquire auth-fixture b || true
dast_auth_authenticated_labels_set auth-fixture
assert_eq 'a' "${_DAST_AUTH_AUTHED_LABELS[*]}" \
  'the failed identity is excluded - FAILS if the count comes from config/auth.conf, in which case a cross-user check sees "two identities configured", runs, and reports no IDOR because one of the two sessions does not exist'

t_case 'an identity for ANOTHER target is not visible to this one'
_reset
_auth_conf "$W/h3.conf" 'id: auth-fixture.a
mode: bearer
token: mine

id: other-fixture.a
mode: bearer
token: theirs
'
dast_auth_load "$W/h3.conf"
dast_auth_labels_set other-fixture
assert_eq 'a' "${_DAST_AUTH_LABELS[*]}" 'the other target has its own identity'
dast_auth_acquire auth-fixture a
dast_auth_acquire other-fixture a
_resp_add 200 '' 'ok'
dast_auth_request auth-fixture a GET https://auth.fixture.example/me
assert_eq 'Bearer mine' "$(_header_of Authorization)" \
  'each target uses its own identity - fails if the session store is keyed on the label alone, which sends one target'"'"'s credential to another'

# =============================================================================
printf -- '\n-- I. the session store is a credential store --\n'
# =============================================================================

t_case 'the session directory is 700 and every file in it is 600'
_reset
_form_conf
_resp_add 200 'sid=perm-check' '{"token":"perm-token"}'
dast_auth_acquire auth-fixture a
_dast_auth_dir_set auth-fixture a
assert_eq '700' "$(stat_mode "$_DAST_AUTH_DIR")" \
  'the per-identity directory is 700 - fails under the process umask alone, which is not a guarantee a caller of this library can rely on'
assert_eq '600' "$(stat_mode "$_DAST_AUTH_DIR/token")" 'the token file is 600'
assert_eq '600' "$(stat_mode "$_DAST_AUTH_DIR/cookies")" 'the cookie jar is 600'
assert_eq '600' "$(stat_mode "$_DAST_AUTH_DIR/state")" 'the state record is 600'

t_case 'the session store lives under the run SCRATCH directory, not the run directory'
assert_contains "$_DAST_AUTH_DIR" "$SCOURSH_SCRATCH" \
  'the token is in the scratch tree the EXIT trap erases (finding F12'"'"'s own description of what belongs there) - fails if a session token is written under reports/<run>/, which outlives the run by design and is the directory operators attach to tickets'

# =============================================================================
printf -- '\n-- J. the config-derived user-enumeration check (docs/DESIGN.md §7.4) --\n'
# =============================================================================

t_case 'a login response that distinguishes account state is reported'
_reset
_form_conf
_resp_add 401 '' '{"message":"No such user with that email address."}'
_resp_add 401 '' '{"message":"No such user with that email address."}'
_resp_add 401 '' '{"message":"No such user with that email address."}'
dast_auth_acquire auth-fixture a || true
BEFORE=$(_request_count)
dast_auth_enum_scan auth-fixture a /rest/user/login
assert_eq "$BEFORE" "$(_request_count)" \
  'the check sent NOTHING - FAILS under a live probe, which is the half docs/DESIGN.md §7.4 gates behind --allow-intrusive precisely because it creates accounts and sends messages'
FINDINGS=$(_shard_text)
assert_contains "$FINDINGS" 'DAST-AUTH-ENUM_RESPONSE-01' 'and a finding was emitted'
assert_contains "$FINDINGS" 'No such user' \
  'whose evidence is the matched phrase, so a reader can see what the target actually said'

t_case 'a generic failure is NOT reported as enumeration'
_reset
_form_conf
_resp_add 401 '' '{"message":"Invalid credentials."}'
_resp_add 401 '' '{"message":"Invalid credentials."}'
_resp_add 401 '' '{"message":"Invalid credentials."}'
dast_auth_acquire auth-fixture a || true
BEFORE_N=$(_shard_lines)
dast_auth_enum_scan auth-fixture a /rest/user/login
AFTER_N=$(_shard_lines)
assert_eq "$BEFORE_N" "$AFTER_N" \
  'no finding for a response that reveals nothing about the account - FAILS under a pattern set that matches "invalid" or "failed", which reports every login endpoint on earth and buries the real one'

t_case 'a REJECTED shape is scanned, not only the last or the successful one'
_reset
_form_conf
_resp_add 401 '' '{"message":"user not found"}'
_resp_add 200 '' '{"token":"t"}'
dast_auth_acquire auth-fixture a
assert_eq authenticated "$_DAST_AUTH_STATE" 'the login eventually succeeded'
dast_auth_enum_scan auth-fixture a /rest/user/login
FINDINGS=$(_shard_text)
assert_contains "$FINDINGS" 'user not found' \
  'the disclosure in the REJECTED attempt is found - FAILS if only the final response is scanned, which examines the successful login and misses the exact case this check exists for'

t_case 'the run always states which half of the enumeration check ran'
_reset
run_record_before=$(run_facts coverage_gap)
dast_auth_enum_gap auth-fixture 2
GAP=$(run_facts coverage_gap)
assert_ne "$run_record_before" "$GAP" 'a gap is recorded'
assert_contains "$GAP" 'config-derived half' \
  'the gap names which half ran - fails under silence, which lets a clean report read as "user enumeration was tested and is fine"'
assert_contains "$GAP" 'needs --allow-intrusive' \
  'and names the flag the missing half needs, so an operator can act on it'

t_case 'and says so differently when there was nothing to read at all'
dast_auth_enum_gap auth-fixture 0
assert_contains "$(run_facts coverage_gap)" 'NOT assessed at all' \
  'zero responses is its own statement - fails under one sentence for both, which claims an assessment happened on a run that obtained no login response'

t_summary 'dast-auth'
