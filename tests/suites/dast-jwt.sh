#!/usr/bin/env bash
# tests/suites/dast-jwt.sh - modules/dast/jwt.sh and jwt_engine.sh: JWT
# token-verification weaknesses (docs/DESIGN.md §7.4,
# docs/STEP5-DAST-PLAN.md DAST-26).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), so this suite runs on a host with no network
# and no Docker, exactly like tests/suites/dast-auth.sh.  The stub transport is
# not a canned-status queue: it is a REAL HS256 verifier, so a forged token is
# accepted only when it genuinely verifies against the server's configured key -
# which is the whole point of a check whose correctness IS whether a forgery
# verifies.  DAST-26's own "NEEDS FROM OPERATOR" (a sample token + a protected
# endpoint) is the LIVE proof; this file proves the mechanism, and the opt-in
# live proof against the authorized local target is a companion e2e for the same
# reason dast-auth-live.sh is.
#
# The decisions this suite pins, each with a plausible wrong reading that would
# ship green:
#
#   1. base64url has NO padding and round-trips; a token is a JWT only when its
#      header decodes to JSON with an `alg` (an opaque/reference token is not).
#   2. A forged header PRESERVES other claims (kid/typ) and changes only `alg`;
#      a check that rebuilt a minimal header would miss a kid-keyed verifier.
#   3. The ORACLE is required: a forgery "accepted" is only a finding once a
#      wrong-signature token is shown to be REJECTED.  A check that skipped the
#      oracle would call every endpoint that returns 200 vulnerable.
#   4. alg:none is caught in its CASE VARIANTS ("None"/"NONE"), not just "none".
#   5. empty-secret, weak-secret (from the BOUNDED vendored list, naming which
#      secret), and RS->HS confusion each emit their OWN check id.
#   6. A server that does not verify signatures at all is ONE finding
#      (SIG_NOT_VERIFIED), not a spray of five - the per-variant probes do not
#      run once that is established.
#   7. The weak-secret list is bounded and vendored; there is no flag path that
#      enlarges it.
#   8. The phase degrades gracefully - no --authed, no openssl, no protected
#      endpoint, a non-JWT session token - each as a RECORDED gap, never an error
#      and never a silent pass.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON, header and flag syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=modules/dast/jwt_engine.sh
source "$ROOT/modules/dast/jwt_engine.sh"
# shellcheck source=modules/dast/auth_engine.sh
source "$ROOT/modules/dast/auth_engine.sh"
# shellcheck source=modules/dast/crawl_engine.sh
source "$ROOT/modules/dast/crawl_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-jwt-workspace
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope + the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: jwt-fixture
base-url: https://jwt.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-jwt.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF

_jwt_resolve() {
  case $1 in
    jwt.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_jwt_resolve

# The scripted SERVER.  A real HS256 verifier rather than a status queue, driven
# by per-case policy variables reset by `_srv_reset`:
#   SRV_SECRET       the HS256 key the server verifies with ('' is legal)
#   SRV_ALLOW_NONE   accept a token whose alg is any case of "none"
#   SRV_NO_VERIFY    accept ANY token (models a server that does not verify)
#   SRV_REJECT_ALL   reject even the real token (the "wrong endpoint" case)
#   SRV_REAL_RS      the exact RS-signed token to accept on the RS* path (the
#                    mock does not RSA-verify; it accepts the known-good token)
#   SRV_HEADER       the header the token rides in (default Authorization)
#   SRV_SCHEME       the scheme prefix to strip (default Bearer)
_srv_reset() {
  SRV_SECRET='' SRV_ALLOW_NONE=0 SRV_NO_VERIFY=0 SRV_REJECT_ALL=0 SRV_REAL_RS=''
  SRV_HEADER=Authorization SRV_SCHEME=Bearer
  : >"$REQ_LOG"
}
REQ_LOG=$W/requests.log

_jwt_transport() {
  local method=$1 path=$5 h tok='' alg hdr sig si expected status
  # Pull the token out of the request's Authorization (or configured) header.
  for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    case $h in
      "$SRV_HEADER: "*)
        tok=${h#"$SRV_HEADER: "}
        [[ -n $SRV_SCHEME ]] && tok=${tok#"$SRV_SCHEME "}
        ;;
    esac
  done
  printf '%s %s tok=%s\n' "$method" "$path" "${tok:0:16}" >>"$REQ_LOG"

  if (( SRV_REJECT_ALL )); then
    status=401
  elif (( SRV_NO_VERIFY )); then
    status=200
  elif ! jwt_split "$tok"; then
    status=400
  else
    hdr=$(jwt_b64url_decode "$_JWT_HEADER_B64")
    alg=$(jwt_json_str_field "$hdr" alg)
    si=$_JWT_SIGNING_INPUT
    sig=$_JWT_SIG_B64
    case $alg in
      [Nn][Oo][Nn][Ee])
        if (( SRV_ALLOW_NONE )); then status=200; else status=401; fi
        ;;
      HS256)
        expected=$(jwt_hs256_sign "$si" "$SRV_SECRET")
        [[ $sig == "$expected" ]] && status=200 || status=401
        ;;
      RS* | PS* | ES*)
        [[ -n $SRV_REAL_RS && $tok == "$SRV_REAL_RS" ]] && status=200 || status=401
        ;;
      *)
        status=401
        ;;
    esac
  fi
  printf '%s\n\n' "$status"
}
SCOURSH_HTTP_TRANSPORT=_jwt_transport

http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

URL=https://jwt.fixture.example/api/me

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  SCOURSH_DAST_CELL=jwt-fixture
  export SCOURSH_DAST_CELL
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_request_count() {
  local n=0 line
  [[ -r $REQ_LOG ]] || { printf 0; return 0; }
  while IFS= read -r line; do [[ -n $line ]] && n=$(( n + 1 )); done <"$REQ_LOG"
  printf '%s' "$n"
}

# Build a real HS256 JWT: header (with a kid, so claim-preservation is testable),
# payload, signed with KEY.
_mk_hs_token() {
  local key=$1 h p si
  h=$(printf '%s' '{"alg":"HS256","kid":"key-1","typ":"JWT"}' | jwt_b64url_encode)
  p=$(printf '%s' '{"sub":"1","user":"alice"}' | jwt_b64url_encode)
  si=$h.$p
  printf '%s.%s' "$si" "$(jwt_hs256_sign "$si" "$key")"
}

# ===========================================================================
# A. Pure functions (no network)
# ===========================================================================
printf '\n== A. pure token functions ==\n'

t_case 'base64url round-trips with no padding'
enc=$(printf '%s' '{"alg":"HS256"}' | jwt_b64url_encode)
assert_not_contains "$enc" '=' 'base64url output carries no = padding - fails if the +/ alphabet and padding are not stripped'
assert_eq '{"alg":"HS256"}' "$(jwt_b64url_decode "$enc")" 'decode inverts encode'

t_case 'a JWT is recognised; an opaque or malformed token is not'
TOK=$(_mk_hs_token secret)
assert_status 0 'a well-formed HS256 token is a JWT' jwt_is_jwt "$TOK"
assert_status 1 'an opaque session token is not a JWT - fails if any 3-dot string is treated as one' jwt_is_jwt 'opaque-reference-token'
assert_status 1 'a.b.c is not a JWT (its header is not JSON with an alg)' jwt_is_jwt 'a.b.c'

t_case 'a forged header preserves other claims and changes only alg'
NEW=$(jwt_header_with_alg '{"alg":"RS256","kid":"key-1","typ":"JWT"}' HS256)
assert_contains "$NEW" '"kid":"key-1"' 'kid is preserved - fails if the forgery rebuilt a minimal header, which a kid-keyed verifier would reject'
assert_contains "$NEW" '"alg":"HS256"' 'alg is changed to the requested value'
assert_not_contains "$NEW" 'RS256' 'the old alg is gone'

t_case 'the oracle control is a well-formed but different signature'
TAMP=$(jwt_sig_tampered "$TOK")
assert_ne "$TOK" "$TAMP" 'the tampered token differs from the real one'
jwt_split "$TAMP"
assert_eq "$(jwt_alg_of "$TOK")" "$(jwt_json_str_field "$(jwt_b64url_decode "$_JWT_HEADER_B64")" alg)" \
  'the tampered token keeps the ORIGINAL alg - only the signature is wrong, so the server rejects it for the right reason'

t_case 'the weak-secret list is bounded, vendored, and non-empty'
assert_status 0 'the vendored list loads' jwt_weak_secrets_load
jwt_weak_secrets_load
assert_true "$([[ ${#_JWT_WEAK_SECRETS[@]} -gt 0 && ${#_JWT_WEAK_SECRETS[@]} -le 100 ]] && echo 0 || echo 1)" \
  "the list is bounded (0 < n <= 100), here ${#_JWT_WEAK_SECRETS[@]} - fails if it ever grew into a cracking wordlist"

# ===========================================================================
# B. The replay oracle and the findings (jwt_run over the mock verifier)
# ===========================================================================
printf '\n== B. oracle and findings ==\n'

t_case 'a secure server yields NO finding, and the oracle held'
_fresh_run; _srv_reset
SRV_SECRET='a-strong-random-secret-nobody-would-guess-0xДЕ'
TOK=$(_mk_hs_token "$SRV_SECRET")
jwt_run jwt-fixture GET "$URL" "$TOK"
assert_eq ran "$_JWT_RUN_STATUS" 'the oracle held (real accepted, bad signature rejected) and every variant ran'
assert_not_contains "$(_shard_text)" 'DAST-JWT-' 'a server that verifies correctly produces no JWT finding - fails if any 2xx counts as acceptance'
assert_contains "$(run_facts checks_run)" 'DAST-JWT-ALG_NONE-01' 'checks_run records the checks that were exercised, even with no hit'

t_case 'alg:none acceptance is caught, including a capitalised spelling'
_fresh_run; _srv_reset
SRV_SECRET='a-strong-random-secret'; SRV_ALLOW_NONE=1
TOK=$(_mk_hs_token "$SRV_SECRET")
jwt_run jwt-fixture GET "$URL" "$TOK"
FIND=$(_shard_text)
assert_contains "$FIND" 'DAST-JWT-ALG_NONE-01' 'alg:none acceptance is reported'
# The mock accepts ANY case of none; jwt_run tries none/None/NONE/nOnE, so a hit
# proves the case-variant spellings are exercised (a lowercase-only forger would
# still hit here, so also assert the run did not falsely flag the others).
assert_not_contains "$FIND" 'DAST-JWT-EMPTY_HMAC-01' 'the empty-secret check did not falsely fire against an alg:none-only server'
assert_not_contains "$FIND" 'DAST-JWT-WEAK_HMAC-01' 'the weak-secret check did not falsely fire'

t_case 'alg:none forger uses case variants, not just lowercase "none"'
# A server that accepts ONLY the exact spelling "None" (not "none") must still
# be caught.  This fails under a forger that only ever tries lowercase.
_fresh_run
_srv_reset
_jwt_transport_case() {
  local method=$1 path=$5 h tok='' alg hdr status
  for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    case $h in "Authorization: "*) tok=${h#Authorization: Bearer } ;; esac
  done
  if jwt_split "$tok"; then
    hdr=$(jwt_b64url_decode "$_JWT_HEADER_B64"); alg=$(jwt_json_str_field "$hdr" alg)
    if [[ $alg == None ]]; then status=200
    elif [[ $alg == HS256 ]]; then
      [[ $_JWT_SIG_B64 == "$(jwt_hs256_sign "$_JWT_SIGNING_INPUT" 'strongkey')" ]] && status=200 || status=401
    else status=401; fi
  else status=400; fi
  printf '%s\n\n' "$status"
}
SCOURSH_HTTP_TRANSPORT=_jwt_transport_case
TOK=$(_mk_hs_token strongkey)
jwt_run jwt-fixture GET "$URL" "$TOK"
assert_contains "$(_shard_text)" 'DAST-JWT-ALG_NONE-01' \
  'a server accepting only the "None" spelling is caught - FAILS if the forger only tries lowercase "none"'
SCOURSH_HTTP_TRANSPORT=_jwt_transport

t_case 'empty-secret HS256 acceptance is its own finding'
_fresh_run; _srv_reset
SRV_SECRET=''            # the server verifies HS256 with an EMPTY key
TOK=$(_mk_hs_token '')   # so the real token is one signed with the empty key
jwt_run jwt-fixture GET "$URL" "$TOK"
FIND=$(_shard_text)
assert_contains "$FIND" 'DAST-JWT-EMPTY_HMAC-01' 'empty-secret acceptance is reported under its own id'
assert_contains "$FIND" 'empty' 'the evidence names the empty secret'

t_case 'a weak vendored secret is caught and NAMED'
_fresh_run; _srv_reset
SRV_SECRET='secret'          # a value that is on the vendored list
TOK=$(_mk_hs_token secret)
jwt_run jwt-fixture GET "$URL" "$TOK"
FIND=$(_shard_text)
assert_contains "$FIND" 'DAST-JWT-WEAK_HMAC-01' 'weak-secret acceptance is reported'
assert_contains "$FIND" "'secret'" 'the evidence names WHICH weak secret signed the token - the actionable fact'

t_case 'a server that does not verify signatures is ONE finding, not five'
_fresh_run; _srv_reset
SRV_NO_VERIFY=1
TOK=$(_mk_hs_token whatever)
jwt_run jwt-fixture GET "$URL" "$TOK"
FIND=$(_shard_text)
assert_eq no_verify "$_JWT_RUN_STATUS" 'the run stopped at the signature-not-verified finding'
assert_contains "$FIND" 'DAST-JWT-SIG_NOT_VERIFIED-01' 'the root-cause finding is emitted'
assert_not_contains "$FIND" 'DAST-JWT-ALG_NONE-01' 'the per-variant probes did NOT run - fails if the check sprays five duplicates of one root cause'
assert_not_contains "$FIND" 'DAST-JWT-WEAK_HMAC-01' 'no weak-secret duplicate either'

t_case 'an endpoint the token is not authorised for establishes no oracle'
_fresh_run; _srv_reset
SRV_REJECT_ALL=1
TOK=$(_mk_hs_token secret)
jwt_run jwt-fixture GET "$URL" "$TOK"
assert_eq token_rejected "$_JWT_RUN_STATUS" 'the sample token was not accepted, so no oracle - and no forgery is tested'
assert_not_contains "$(_shard_text)" 'DAST-JWT-' 'nothing is reported when the token itself is rejected'

t_case 'a non-JWT token makes the check not apply'
_fresh_run; _srv_reset
jwt_run jwt-fixture GET "$URL" 'opaque-reference-token'
assert_eq not_jwt "$_JWT_RUN_STATUS" 'an opaque token is not a JWT and the check declines rather than pretending to run'
assert_not_contains "$(_shard_text)" 'DAST-JWT-' 'no finding is emitted for a non-JWT token'

t_case 'RS->HS algorithm confusion is caught when a public key is available'
_fresh_run; _srv_reset
PRIV=$W/rs-priv.pem PUB=$W/rs-pub.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV" 2>/dev/null
openssl rsa -in "$PRIV" -pubout -out "$PUB" 2>/dev/null
RSH=$(printf '%s' '{"alg":"RS256","kid":"key-1","typ":"JWT"}' | jwt_b64url_encode)
RSP=$(printf '%s' '{"sub":"1","user":"alice"}' | jwt_b64url_encode)
RSSI=$RSH.$RSP
RSSIG=$(printf '%s' "$RSSI" | openssl dgst -sha256 -sign "$PRIV" -binary | jwt_b64url_encode)
RSTOK=$RSSI.$RSSIG
# The confused server: RS* accepted only for the known-good token; HS256 verified
# with the PUBLIC key as the secret (the confusion bug).
SRV_REAL_RS=$RSTOK
SRV_SECRET=$(cat "$PUB")
jwt_run jwt-fixture GET "$URL" "$RSTOK" Authorization Bearer "$PUB"
assert_eq ran "$_JWT_RUN_STATUS" 'the oracle held for the RS token'
assert_contains "$(_shard_text)" 'DAST-JWT-ALG_CONFUSION-01' 'RS->HS confusion is reported when the public key is supplied'

t_case 'an asymmetric token with no public key records the gap, no false finding'
_fresh_run; _srv_reset
SRV_REAL_RS=$RSTOK
SRV_SECRET='irrelevant-server-secret'
jwt_run jwt-fixture GET "$URL" "$RSTOK"     # no pubkey argument
assert_eq 1 "${_JWT_RUN_RS_PUBKEY_MISSING}" 'the missing-public-key gap is flagged for the phase to record'
assert_not_contains "$(_shard_text)" 'DAST-JWT-ALG_CONFUSION-01' 'no confusion finding without a key - fails if an absent key read as clean OR as a hit'

# ===========================================================================
# C. The phase: graceful degradation and the end-to-end happy path
# ===========================================================================
printf '\n== C. phase orchestration and graceful degradation ==\n'

# Write an inventory endpoints.json with one GET endpoint for the target.
_write_inventory() {
  local file=$1
  mkdir -p "${file%/*}"
  cat >"$file" <<EOF
{
  "schema": "scoursh.inventory.endpoints/1",
  "endpoints": [
    { "id": "aaaaaaaaaaaa", "target": "jwt-fixture", "method": "GET",
      "url": "$URL", "host": "jwt.fixture.example", "path": "/api/me",
      "source": "crawl", "depth": 1, "status": "200", "content_type": "application/json" },
    { "id": "bbbbbbbbbbbb", "target": "jwt-fixture", "method": "POST",
      "url": "https://jwt.fixture.example/api/order", "host": "jwt.fixture.example",
      "path": "/api/order", "source": "crawl", "depth": 1, "status": "200", "content_type": "" }
  ]
}
EOF
}

# Seed an authenticated session in the store, as auth.sh would have.
_seed_session() {
  local target=$1 label=$2 token=$3
  _DAST_AUTH_MODE=bearer _DAST_AUTH_HEADER=Authorization _DAST_AUTH_SCHEME=Bearer _DAST_AUTH_SHAPE=''
  _dast_auth_state_write "$target" "$label" authenticated ''
  _dast_auth_dir_set "$target" "$label"
  _dast_auth_touch600 "$_DAST_AUTH_DIR/token"
  printf '%s' "$token" >"$_DAST_AUTH_DIR/token"
}

_phase_env() {
  SCOURSH_DAST_TARGET=jwt-fixture
  SCOURSH_DAST_CELL=jwt-fixture
  SCOURSH_DAST_INTENSITY=active
  SCOURSH_DAST_AUTHED=${1:-true}
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  SCOURSH_DAST_ENDPOINTS=${2:-}
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
    SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE SCOURSH_DAST_ENDPOINTS
}

t_case 'without --authed the phase records a gap and sends nothing'
_fresh_run; _srv_reset
rm -rf "$SCOURSH_SCRATCH/dast-auth"
_phase_env false ''
source "$ROOT/modules/dast/jwt.sh"
assert_contains "$(run_facts coverage_reduction)" 'reason=authed_not_requested' 'the no-session case is a declared reduction'
assert_contains "$(run_facts coverage_gap)" 'was not tested' 'and a human-readable gap - fails under silence, which reads as a clean JWT posture'
assert_eq 0 "$(_request_count)" 'no request was sent without --authed'

t_case 'authed but no protected endpoint records the operator-input gap'
_fresh_run; _srv_reset
rm -rf "$SCOURSH_SCRATCH/dast-auth"
DAST_AUTH_LOADED=0; records_clear auth 2>/dev/null || true
AUTHCONF=$W/auth.conf; : >"$AUTHCONF"; chmod 600 "$AUTHCONF"
printf 'id: jwt-fixture.a\nmode: bearer\ntoken: %s\n' "$(_mk_hs_token secret)" >"$AUTHCONF"
dast_auth_load "$AUTHCONF"
_seed_session jwt-fixture a "$(_mk_hs_token secret)"
_phase_env true ''          # no endpoints file
source "$ROOT/modules/dast/jwt.sh"
assert_contains "$(run_facts coverage_reduction)" 'reason=no_protected_endpoint' 'the missing-endpoint case is declared'
assert_contains "$(run_facts coverage_gap)" 'no idempotent protected endpoint' 'and named as the operator input DAST-26 needs'

t_case 'a non-JWT session token is recorded per identity, not run'
_fresh_run; _srv_reset
rm -rf "$SCOURSH_SCRATCH/dast-auth"
DAST_AUTH_LOADED=0; records_clear auth 2>/dev/null || true
: >"$AUTHCONF"; chmod 600 "$AUTHCONF"
printf 'id: jwt-fixture.a\nmode: bearer\ntoken: opaque\n' >"$AUTHCONF"
dast_auth_load "$AUTHCONF"
_seed_session jwt-fixture a 'opaque-reference-token'
INV=$W/inv/endpoints.json; _write_inventory "$INV"
_phase_env true "$INV"
source "$ROOT/modules/dast/jwt.sh"
assert_contains "$(run_facts coverage_reduction)" 'reason=session_token_not_jwt' 'an opaque session token is a declared reduction, not a silent skip'

t_case 'end-to-end: authed identity + GET inventory + vulnerable server => finding'
_fresh_run; _srv_reset
rm -rf "$SCOURSH_SCRATCH/dast-auth"
DAST_AUTH_LOADED=0; records_clear auth 2>/dev/null || true
: >"$AUTHCONF"; chmod 600 "$AUTHCONF"
JWTTOK=$(_mk_hs_token secret)
printf 'id: jwt-fixture.a\nmode: bearer\ntoken: %s\n' "$JWTTOK" >"$AUTHCONF"
dast_auth_load "$AUTHCONF"
_seed_session jwt-fixture a "$JWTTOK"
SRV_SECRET=secret            # server signs/verifies with the weak secret
INV=$W/inv2/endpoints.json; _write_inventory "$INV"
_phase_env true "$INV"
source "$ROOT/modules/dast/jwt.sh"
FIND=$(_shard_text)
assert_contains "$FIND" 'DAST-JWT-WEAK_HMAC-01' 'the phase drives the engine end to end and emits the weak-secret finding'
# The POST /api/order endpoint must NOT have been probed: replay is idempotent-only.
assert_not_contains "$(cat "$REQ_LOG")" '/api/order' 'a non-idempotent (POST) endpoint is never replayed against - the non-destructive guarantee'

# ===========================================================================
# D. registration and the tension-15 check-set gate
# ===========================================================================
printf '\n== D. registration and check-set selection ==\n'

# modules/dast/engine.sh is a pure library with a sourced-once guard and no
# side effect at source time (its own header), and it is what pulls in
# lib/checks.sh's `checks_registry_load`.  It is sourced HERE rather than at the
# top of the file so sections A-C keep running against exactly the surface they
# ran against before this section existed.
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"

t_case 'the phase table reaches this script, and only at active or above'
FOUND=0
for spec in "${_DAST_PHASES[@]}"; do
  [[ $spec == 'jwt.sh:active' ]] && FOUND=1
done
assert_eq 1 "$FOUND" \
  'modules/dast/engine.sh names jwt.sh at tier active, so scan_dispatch dast runs it only at --intensity active'

t_case 'every check id this phase emits is in the registry'
# THIS IS THE TICKET'S CORE ASSERTION AND IT FAILS ON THE UNFIXED TREE: before
# modules/dast/checks.rules existed, `grep -rln DAST-JWT --include=*.rules .`
# returned nothing, so tension 12 could compute NO coverage for any of these five
# and tension 15's filter chain could neither select nor drop them.  An emitted
# check with no registry record is indistinguishable, in state/, from a check
# that never ran.
SCOURSH_INSTALL_ROOT=$ROOT checks_registry_load dast DASTJWTCK
REG=''
for s in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
  n=$(records_count "$s")
  for (( ri = 0; ri < n; ri++ )); do
    REG+=$(records_id "$s" "$ri")
    REG+=' '
  done
done
for id in DAST-JWT-SIG_NOT_VERIFIED-01 DAST-JWT-ALG_NONE-01 \
          DAST-JWT-EMPTY_HMAC-01 DAST-JWT-WEAK_HMAC-01 \
          DAST-JWT-ALG_CONFUSION-01; do
  assert_contains "$REG" "$id" \
    "$id is registered in modules/dast/checks.rules - FAILS if a check is emitted with no registry record, which leaves tension 12 unable to compute coverage for it and tension 15 unable to filter it"
done

t_case 'the registry ids are exactly the ids jwt_engine.sh emits, with no drift'
# The reverse direction of the assertion above.  A record for an id the engine
# never emits is a check the registry promises and the run can never cover, which
# reads in state/ as a permanently-uncovered check rather than as a typo.
ENGINE_IDS=$(grep -oE "DAST-JWT-[A-Z_]+-[0-9]+" "$ROOT/modules/dast/jwt_engine.sh" | LC_ALL=C sort -u)
RULE_IDS=$(grep -oE "^id: (DAST-JWT-[A-Z_]+-[0-9]+)$" "$ROOT/modules/dast/checks.rules" \
  | sed 's/^id: //' | LC_ALL=C sort -u)
assert_eq "$ENGINE_IDS" "$RULE_IDS" \
  'the emitted id set and the registered id set are identical - FAILS on a typo in either direction, which no other assertion here would catch'

t_case 'with no dast_check_selected in scope, every variant still runs'
# The fallback the whole guard depends on: `dast_check_selected` does not exist
# on every path these files are reachable from (it exists nowhere in the tree
# today), and absent it everything the tier already permitted must run.  Without
# this case, a guard that returned false when the function is missing would make
# the entire phase inert and every "stays quiet" assertion above would still pass.
unset -f dast_check_selected 2>/dev/null || true
_fresh_run; _srv_reset
SRV_SECRET=secret
TOK=$(_mk_hs_token secret)
jwt_run jwt-fixture GET "$URL" "$TOK"
UNGATED_REQS=$(_request_count)
assert_contains "$(_shard_text)" 'DAST-JWT-WEAK_HMAC-01' \
  'the weak-secret finding is still emitted with no selection function present - FAILS under a guard that fails closed on an absent dast_check_selected, which would silently disable the whole phase'
assert_contains "$(run_facts checks_run)" 'DAST-JWT-EMPTY_HMAC-01' \
  'and every variant is still recorded as exercised'

t_case 'a deselected variant is NOT probed and NOT recorded'
# The gate binding for real.  `dast_check_selected` is defined here because it
# exists nowhere in the tree yet (modules/dast/passive/headers.sh says so in its
# own comment); this proves the guard consults it the moment it does exist, which
# is what makes modules/dast/checks.rules a control rather than documentation.
#
# Each variant is its own outbound request carrying a FORGED token, so the
# assertion is on the REQUEST COUNT as well as on the findings: suppressing only
# the emit would leave the target receiving forgery traffic for a check that is
# not in this run's set, and a findings-only assertion passes under exactly that
# bug.
dast_check_selected() { [[ $1 == 'DAST-JWT-ALG_NONE-01' || $1 == 'DAST-JWT-SIG_NOT_VERIFIED-01' ]]; }
_fresh_run; _srv_reset
SRV_SECRET=secret
TOK=$(_mk_hs_token secret)
jwt_run jwt-fixture GET "$URL" "$TOK"
GATED_REQS=$(_request_count)
FIND=$(_shard_text)
RUNCHECKS=$(run_facts checks_run)
assert_not_contains "$FIND" 'DAST-JWT-WEAK_HMAC-01' \
  'the deselected weak-secret check emits nothing against a server whose secret IS weak - FAILS on the ungated engine, which emits it regardless of the check set'
assert_not_contains "$RUNCHECKS" 'DAST-JWT-WEAK_HMAC-01' \
  'and it is not claimed in checks_run - FAILS under gating the emit alone, which would report coverage for a check that was filtered out'
assert_not_contains "$RUNCHECKS" 'DAST-JWT-EMPTY_HMAC-01' \
  'nor is the deselected empty-secret check'
assert_contains "$RUNCHECKS" 'DAST-JWT-ALG_NONE-01' \
  'the one selected variant did run - FAILS under a gate that refuses everything, which would pass every assertion above for the wrong reason'
[[ $GATED_REQS -lt $UNGATED_REQS ]] && LESS=yes || LESS=no
assert_eq yes "$LESS" \
  "a deselected variant sends FEWER requests ($GATED_REQS < $UNGATED_REQS) - FAILS under gating the emit alone, where the forged tokens are still sent to the target and only the report is trimmed"

t_case 'the phase skips entirely when no DAST-JWT-* check is selected'
# The whole-phase arm, mirroring passive/cookies.sh's cookies_no_check_selected.
# Without it a fully-filtered run still authenticates, walks the inventory and
# establishes an oracle - three real requests - before finding nothing to probe.
dast_check_selected() { return 1; }
_fresh_run; _srv_reset
rm -rf "$SCOURSH_SCRATCH/dast-auth"
DAST_AUTH_LOADED=0; records_clear auth 2>/dev/null || true
: >"$AUTHCONF"; chmod 600 "$AUTHCONF"
JWTTOK=$(_mk_hs_token secret)
printf 'id: jwt-fixture.a\nmode: bearer\ntoken: %s\n' "$JWTTOK" >"$AUTHCONF"
dast_auth_load "$AUTHCONF"
_seed_session jwt-fixture a "$JWTTOK"
SRV_SECRET=secret
INV=$W/inv3/endpoints.json; _write_inventory "$INV"
_phase_env true "$INV"
source "$ROOT/modules/dast/jwt.sh"
assert_eq 0 "$(_request_count)" \
  'not one request is sent when every DAST-JWT-* id is filtered out - FAILS on the ungated phase, which authenticates and probes the full variant set regardless of the check set'
assert_contains "$(run_facts coverage_reduction)" 'reason=jwt_no_check_selected' \
  'and the skip is a DECLARED reduction - FAILS under a silent return, which makes a filtered-out check indistinguishable from a clean JWT posture'
assert_contains "$(run_facts coverage_gap)" 'was not tested' \
  'with a human-readable gap naming what was not tested'
assert_not_contains "$(_shard_text)" 'DAST-JWT-' \
  'and no finding is emitted'
unset -f dast_check_selected

t_summary 'dast-jwt'
