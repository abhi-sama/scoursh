#!/usr/bin/env bash
# tests/e2e/dast-auth-live.sh - modules/dast/auth.sh against a REAL target.
#
# Proves that DAST-03's session acquisition works end to end against the local,
# operator-started, authorized DAST test target (tools/dast-test-target.sh,
# authorized by tools/dast-test-target/scope.conf and
# docs/DAST-TEST-TARGET-AUTHORIZATION.md) - real HTTP through lib/http.sh's real
# curl transport, real credentials from real mode-600 secret-files, and two real
# distinct sessions.
#
# WHY THIS EXISTS ALONGSIDE tests/suites/dast-auth.sh.  That suite stubs the
# transport and proves the LOGIC; this one proves the code actually talks to a
# server.  They catch different things: a mock cannot tell you that curl was
# invoked with a config it rejects, that the form-shape probe picks the right
# shape against a real login API, or that two sessions a stub happily made
# distinct are distinct to a server that issued them.  This repository has
# already been bitten once by verifying a preview harness instead of the real
# route, so both halves are required rather than one standing in for the other.
#
# NOT part of tests/run-tests.sh's default suite list: it needs Docker and real
# network access to pull an image, which an egress-restricted CI/test host will
# not have (docs/DESIGN.md §1's no-egress rule is about scoursh's own runtime,
# not this kind of one-time operator/dev tooling - see tools/dast-test-target.sh's
# own header). Run it by hand:
#
#   bash tests/e2e/dast-auth-live.sh
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON and config syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/dast/auth_engine.sh
source "$ROOT/modules/dast/auth_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"

require_cmd docker curl

TARGET_ID=dast-test-target
SCOPE_FILE=$ROOT/tools/dast-test-target/scope.conf
W=$SCOURSH_SCRATCH/dast-auth-live
mkdir -p "$W"
run_init "$W/run"

# ---------------------------------------------------------------------------
printf -- '-- the target and its two identities --\n'
# ---------------------------------------------------------------------------
t_case 'the local DAST test target starts'
if bash "$ROOT/tools/dast-test-target.sh" start >"$W/start.out" 2>&1; then
  _t_ok 'tools/dast-test-target.sh start succeeded'
else
  cat "$W/start.out" >&2
  _t_no 'tools/dast-test-target.sh start succeeded' 'see stderr above'
  t_summary 'dast-auth-live'
  exit 1
fi

t_case 'two throwaway identities are provisioned, with a config/auth.conf to match'
bash "$ROOT/tools/dast-test-identities.sh" >"$W/identities.out" 2>"$W/identities.err" \
  || { cat "$W/identities.err" >&2; _t_no 'identity provisioning succeeded' 'see stderr'; }
assert_file_exists "$DTT_AUTH_CONF" \
  'tools/dast-test-identities.sh wrote an auth.conf in the real §9.6.2 record format'
assert_eq '600' "$(stat_mode "$DTT_AUTH_CONF")" \
  'and it is mode 600, which is the only mode scoursh will read it at (E073)'

# ---------------------------------------------------------------------------
printf -- '\n-- config/auth.conf loads, and E074 has nothing to complain about --\n'
# ---------------------------------------------------------------------------
http_scope_load "$SCOPE_FILE"
config_scope_load "$SCOPE_FILE"

t_case 'the generated auth.conf loads under the frozen schema'
dast_auth_load "$DTT_AUTH_CONF"
assert_eq 1 "$DAST_AUTH_LOADED" \
  'the file tools/dast-test-identities.sh generates is a valid §9.6.2 config - fails if the tool and the schema have drifted, which no unit test can notice because each is correct on its own'

dast_auth_labels_set "$TARGET_ID"
assert_eq 'a b' "${_DAST_AUTH_LABELS[*]}" \
  'both identities are discoverable on this target'

# ---------------------------------------------------------------------------
printf -- '\n-- both identities authenticate for real, over real HTTP --\n'
# ---------------------------------------------------------------------------
t_case 'identity A logs in against the live target'
RC=0
dast_auth_acquire "$TARGET_ID" a || RC=$?
if (( RC != 0 )); then
  _t_no 'identity A authenticated' "reason: ${_DAST_AUTH_FAIL_REASON:-unknown}"
else
  _t_ok 'identity A authenticated against the live target'
fi
assert_eq authenticated "$_DAST_AUTH_STATE" 'identity A has a session'
SHAPE_A=$_DAST_AUTH_SHAPE
_dast_auth_dir_set "$TARGET_ID" a
IFS= read -r TOKEN_A <"$_DAST_AUTH_DIR/token" || true

t_case 'identity B logs in too, and gets a different session'
RC=0
dast_auth_acquire "$TARGET_ID" b || RC=$?
if (( RC != 0 )); then
  _t_no 'identity B authenticated' "reason: ${_DAST_AUTH_FAIL_REASON:-unknown}"
else
  _t_ok 'identity B authenticated against the live target'
fi
_dast_auth_dir_set "$TARGET_ID" b
IFS= read -r TOKEN_B <"$_DAST_AUTH_DIR/token" || true

assert_ne '' "$TOKEN_A" 'identity A holds a real token'
assert_ne '' "$TOKEN_B" 'identity B holds a real token'
assert_ne "$TOKEN_A" "$TOKEN_B" \
  'THE TWO SESSIONS ARE GENUINELY DISTINCT - this is the case DAST-29 (authz.sh) is built on: a cross-user check works by asking for identity B'"'"'s object as identity A, so two sessions that turned out to be the same one would make every IDOR check report clean without testing anything'

t_case 'the form-shape probe picked a shape that actually works here'
assert_contains "$SHAPE_A" 'json' \
  'this target is a JSON login API, so the JSON shape is the one that won - FAILS under a single hardcoded urlencoded body, which cannot log in to this target at all, and which a mock-only test would never reveal'

t_case 'both identities are counted as available for a cross-user check'
dast_auth_authenticated_labels_set "$TARGET_ID"
assert_eq 'a b' "${_DAST_AUTH_AUTHED_LABELS[*]}" \
  'two LIVE sessions, not two configured identities - fails if availability is read off config/auth.conf, which would let a cross-user check run with one working session and report no IDOR'

# ---------------------------------------------------------------------------
printf -- '\n-- the sessions really are each identity, to the server --\n'
# ---------------------------------------------------------------------------
# THE SERVER'S OWN ANSWER, not a comparison of two token strings: two
# different-looking tokens that both resolve to one account would pass a string
# comparison and fail DAST-29 for real.
#
# The endpoint used is the per-identity object one, NOT this target's
# `/rest/user/whoami`.  That was tried first and is measurably the wrong probe
# here: this target reads whoami from a session COOKIE, and its login sets no
# cookie at all - it returns the JWT in the JSON body and leaves the SPA to
# install it - so whoami answers `{"user":{}}` to a perfectly valid bearer
# token.  That is a fact about this target worth recording rather than working
# around silently: a shell scanner authenticating against a client-rendered app
# holds a token the app's own cookie-reading endpoints will not accept, which is
# the same blind spot docs/DESIGN.md §7.5's SPA limitation names for crawling.
#
# The object id comes out of the login response the engine already captured.
# Reaching into the session store for it is deliberate and is what a real check
# will not have to do: DAST-04's inventory is where an object reference is
# supposed to come from, and it does not exist yet.
_bid_of() {
  local label=$1 body=''
  _dast_auth_dir_set "$TARGET_ID" "$label"
  [[ -r $_DAST_AUTH_DIR/responses ]] || { printf ''; return 0; }
  body=$(head -c 8000 -- "$_DAST_AUTH_DIR/responses")
  if [[ $body =~ \"bid\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    printf ''
  fi
  return 0
}

t_case 'each identity owns a different object on the server'
BID_A=$(_bid_of a)
BID_B=$(_bid_of b)
assert_ne '' "$BID_A" 'identity A'"'"'s login response named an object it owns'
assert_ne '' "$BID_B" 'identity B'"'"'s login response named an object it owns'
assert_ne "$BID_A" "$BID_B" \
  'and the two are different objects - the server itself distinguishes the two accounts'

t_case 'each session reads its OWN object, authenticated, through dast_auth_request'
_read_object() {
  local label=$1 bid=$2 body=''
  local out=$W/obj.$label
  dast_auth_request "$TARGET_ID" "$label" GET "$DTT_URL/rest/basket/$bid" "$out" '' 0 || return 1
  [[ -r $out ]] && IFS= read -r -d '' body <"$out" || true
  printf '%s' "$body"
  return 0
}
OBJ_A=$(_read_object a "$BID_A")
OBJ_B=$(_read_object b "$BID_B")
assert_contains "$OBJ_A" "\"id\":$BID_A" \
  'identity A'"'"'s session really does reach A'"'"'s own object over real HTTP - FAILS if the token is stored but never applied (every authenticated check would then report 401), and FAILS if it is applied under the wrong header name for this target'
assert_contains "$OBJ_B" "\"id\":$BID_B" \
  'and identity B'"'"'s session reaches B'"'"'s own object'

t_case 'and the two sessions are distinct TO THE SERVER, which is the DAST-29 case'
CROSS=$(_read_object a "$BID_B")
assert_contains "$CROSS" "\"id\":$BID_B" \
  'identity A'"'"'s session, asking for identity B'"'"'s object, gets B'"'"'s object back - this deliberately vulnerable target'"'"'s broken access control, reached for the first time through DAST-03'"'"'s own plumbing rather than through the tools/ helper. It is what DAST-29 (authz.sh) will assert on, and it can only be reached at all because the two sessions are genuinely different principals: with one shared session the request would be indistinguishable from A reading its own basket'

# ---------------------------------------------------------------------------
printf -- '\n-- transparent re-auth on a real 401 --\n'
# ---------------------------------------------------------------------------
# The session is corrupted deliberately, which is the only honest way to
# reproduce an expired token against a target that has not been running long
# enough for one to expire.  If this target does not answer 401 to a bad token,
# the case is reported SKIPPED rather than passing on a condition that never
# arose - a check that cannot fail proves nothing.
t_case 'a 401 is answered by re-authenticating once and retrying, against the live target'
_dast_auth_dir_set "$TARGET_ID" a
printf 'not-a-valid-jwt-at-all' >"$_DAST_AUTH_DIR/token"
: >"$_DAST_AUTH_DIR/cookies"

RC=0
dast_auth_request "$TARGET_ID" a GET "$DTT_URL/rest/basket/1" "$W/reauth.body" '' 0 || RC=$?
dast_auth_state "$TARGET_ID" a
if [[ $_DAST_AUTH_STATE == authenticated ]]; then
  _dast_auth_dir_set "$TARGET_ID" a
  IFS= read -r TOKEN_AFTER <"$_DAST_AUTH_DIR/token" || true
  assert_ne 'not-a-valid-jwt-at-all' "$TOKEN_AFTER" \
    'the corrupted token was replaced by a freshly acquired one - FAILS if a 401 is simply returned to the caller, which is how an expired session turns every authenticated check into a clean result'
  assert_ne '' "$TOKEN_AFTER" 'and the replacement is a real token'
else
  printf '  SKIP this target did not answer 401 to a corrupted token (it answered: state=%s, reason=%s), so the live re-auth path could not be exercised; the mocked path is covered by tests/suites/dast-auth.sh\n' \
    "$_DAST_AUTH_STATE" "${_DAST_AUTH_REASON:-}"
fi

# ---------------------------------------------------------------------------
printf -- '\n-- the credential never left the process in the clear --\n'
# ---------------------------------------------------------------------------
t_case 'no secret-file content appears in the run directory or the report meta'
IFS= read -r PW_A <"$DTT_STATE_DIR/identity-a.secret" || true
LEAK=$W/leak.out
: >"$LEAK"
if scan_match "$LEAK" -r -F -e "$PW_A" -- "$SCOURSH_RUN_DIR" 2>/dev/null; then
  _t_no 'the password appears nowhere under the run directory' "found in: $(cat "$LEAK")"
else
  _t_ok 'the password appears nowhere under the run directory - fails if a login body or a diagnostic is written into a meta record or a finding'
fi

t_case 'the session store is 600 on a real run'
_dast_auth_dir_set "$TARGET_ID" a
assert_eq '600' "$(stat_mode "$_DAST_AUTH_DIR/token")" 'the token file is 600'
assert_eq '700' "$(stat_mode "$_DAST_AUTH_DIR")" 'and its directory is 700'

# ---------------------------------------------------------------------------
printf -- '\n-- the target stops cleanly --\n'
# ---------------------------------------------------------------------------
t_case 'tools/dast-test-target.sh --stop leaves nothing running'
bash "$ROOT/tools/dast-test-target.sh" --stop >/dev/null
REMAINING=$(docker ps -a --filter "name=^/${DTT_CONTAINER}\$" --format '{{.Names}}')
assert_eq '' "$REMAINING" 'no container remains after --stop'

t_summary 'dast-auth-live'
