#!/usr/bin/env bash
# tests/suites/dast-authz.sh - modules/dast/authz.sh and authz_engine.sh: the
# §7.4 object-level authorization (IDOR) and excessive-data-exposure checks
# (docs/DESIGN.md §7.4, docs/STEP5-DAST-PLAN.md DAST-29).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), so this suite runs on a host with no
# network and no Docker, exactly like tests/suites/dast-jwt.sh and
# tests/suites/dast-auth.sh.  The stub is not a canned-status queue: it is a
# scripted SERVER keyed on (path, identity), because the correctness of this
# check IS which identity is served which object, and a queue would let a probe
# pass by asking for the wrong thing in the right order.
#
# The decisions this suite pins, each with a plausible wrong reading that would
# ship green:
#
#   1. An object reference is exactly what lib/findings.sh's `path_template_of`
#      turns into `{id}`.  Asserted against that function rather than by
#      restating the four patterns, so the two cannot drift.
#   2. A shared object is only a finding once an UNAUTHENTICATED request has
#      been shown NOT to return it.  Without the control every public object is
#      reported as a cross-user read.
#   3. "Public" is DIGEST EQUALITY with an identity's own response, never a 2xx
#      from the anonymous request.  Under the naive reading, an application that
#      answers an unauthenticated request with a 200 login page suppresses every
#      real finding on itself - a failure that reads as a clean report.
#   4. DAST-AUTHZ-IDOR-01 and DAST-AUTHZ-CROSS_IDENTITY_READ-01 are separated by
#      whether a REFUSAL was observed elsewhere under the same path template,
#      and the whole group is probed before either is emitted.  Under "always
#      emit IDOR" case C2 goes red; under "always emit the weaker id" C1 does.
#   5. Two identities that each read their OWN object, and are each refused the
#      other's, produce NO finding.  That is the correct application.
#   6. Both identities reading DIFFERENT bytes produces no finding and a
#      recorded gap, never a finding and never silence.
#   7. Only GET/HEAD is ever sent.  Asserted over a REQUEST LOG - the only form
#      of the claim a test can falsify - not over a return value.
#   8. The exposure check reads FIELD NAMES and never field VALUES: the secret
#      value planted in the fixture response must appear nowhere in the shard.
#   9. Identity B's identifier is never copied into a finding, because it comes
#      out of a mode-600 credential file.
#  10. Every skip path - no --authed, one identity, no inventory, no field list -
#      returns cleanly AND records why.  Silence would read as a clean
#      access-control posture.
#  11. Every id the engine can emit is registered in modules/dast/checks.rules
#      with `requires-identities: 2` and a matching severity.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON and flag syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# THE `source=` DIRECTIVES BELOW ARE PRUNED DELIBERATELY, AND THE PRUNING IS NOT
# COSMETIC.  `shellcheck -x` follows a source edge STATICALLY and inlines the
# whole reachable tree at every edge, with no "already inlined" memo - the same
# property AGENTS.md records costing 43.6 GB and 236 seconds on
# modules/sca/run.sh.  Here `modules/dast/authz_engine.sh` reaches
# `crawl_engine.sh` and `auth_engine.sh`, and `auth_engine.sh` reaches
# `lib/http.sh`, so the direct `lib/http.sh` edge below is a SECOND copy of a
# tree that arrives anyway, and each `source .../authz.sh` further down is a
# THIRD and FOURTH.  Measured: with every edge followed, `shellcheck -x` on this
# file had not terminated after 10 minutes; with the redundant edges cut it
# finishes in seconds.  Cut edges that are already covered elsewhere - never the
# one edge that carries a file nothing else pulls in.
#
# shellcheck source=/dev/null
source "$ROOT/lib/http.sh"
# shellcheck source=modules/dast/authz_engine.sh
source "$ROOT/modules/dast/authz_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-authz-workspace
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope + the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: authz-fixture
base-url: https://authz.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-authz.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF

_authz_resolve() {
  case $1 in
    authz.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_authz_resolve

REQ_LOG=$W/requests.log

# The scripted SERVER.  `SRV[<path>|<who>]` holds `<status><TAB><body>`, where
# <who> is `a`, `b` or `anon`, resolved from the bearer token the request
# carries.  An unlisted (path, who) pair is 404 with no body - which is a
# REFUSAL, exactly as a real application hiding somebody else's object behind a
# 404 is, and is why `authz_status_refused` counts it.
declare -A SRV=()
_srv_reset() {
  SRV=()
  : >"$REQ_LOG"
}

_authz_transport() {
  local method=$1 path=$5 out=${7:-${_HTTP_TX_BODY_OUT:-}}
  local h who=anon v status body
  for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    case $h in
      'Authorization: Bearer TOK-A') who=a ;;
      'Authorization: Bearer TOK-B') who=b ;;
    esac
  done
  printf '%s %s %s\n' "$method" "$path" "$who" >>"$REQ_LOG"
  v=${SRV["$path|$who"]:-}
  if [[ -z $v ]]; then
    status=404 body=''
  else
    status=${v%%$'\t'*} body=${v#*$'\t'}
  fi
  [[ -n $out ]] && printf '%s' "$body" >"$out"
  printf '%s\n\n%s\n' "$status" 'application/json'
}
SCOURSH_HTTP_TRANSPORT=_authz_transport

http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  SCOURSH_DAST_CELL=authz-fixture
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

# The check ids the run actually EMITTED, one per line, decoded through
# lib/findings.sh's own `finding_decode` rather than read out of the raw bytes.
#
# NEVER ASSERT A CHECK ID AGAINST THE RAW SHARD TEXT.  A finding carries its own
# remediation prose, and DAST-AUTHZ-CROSS_IDENTITY_READ-01's remediation NAMES
# DAST-AUTHZ-IDOR-01 on purpose - "unlike DAST-AUTHZ-IDOR-01, it saw no
# evidence ..." is how a reader knows which of the two they are holding.  A
# substring test over the shard therefore finds the confirmed id on a run that
# emitted only the observation, so `assert_not_contains "$FIND" IDOR` fails on
# correct behaviour AND, worse, `assert_contains "$FIND" IDOR` would PASS on the
# rejected "always emit the observation" implementation.  That is a test which
# certifies the defect green, which is the one failure this repository's testing
# rule exists to prevent - measured here, not reasoned about: case C2 went red
# against a correct engine before this helper existed.
_shard_check_ids() {
  local f line
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      printf '%s\n' "${_DF[check_id]:-}"
    done <"$f"
  done
  return 0
}

# The decoded value of FIELD on the first emitted finding whose check_id is
# CHECK, or '' when the run emitted no such finding.  Used where an assertion is
# about the CONTENT of a finding rather than its presence.
_finding_field() {
  local check=$1 field=$2 f line
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      if [[ ${_DF[check_id]:-} == "$check" ]]; then
        printf '%s' "${_DF[$field]:-}"
        return 0
      fi
    done <"$f"
  done
  return 0
}

_request_count() {
  local n=0 line
  [[ -r $REQ_LOG ]] || { printf 0; return 0; }
  while IFS= read -r line; do [[ -n $line ]] && n=$(( n + 1 )); done <"$REQ_LOG"
  printf '%s' "$n"
}

# Build an endpoints.json from `METHOD URL CONTENT_TYPE` triples, one per
# argument.  Deliberately hand-written rather than produced by crawl.sh: this
# suite is a consumer test of the frozen format (docs/INVENTORY-FORMAT.md), and
# generating the fixture from the producer would make the two agree by
# construction whatever the format said.
_write_endpoints() {
  local file=$1; shift
  mkdir -p "${file%/*}"
  {
    printf '{\n  "schema": "scoursh.inventory.endpoints/1",\n'
    printf '  "run_id": "fixture", "generated_by": "tests/suites/dast-authz.sh",\n'
    printf '  "endpoints": [\n'
    local first=1 spec m u ct path rest
    for spec in "$@"; do
      read -r m u ct <<<"$spec"
      rest=${u#*://}
      path=/${rest#*/}
      (( first )) || printf ',\n'
      first=0
      printf '    { "id": "%s", "target": "authz-fixture", "method": "%s", "url": "%s",' \
        "$(printf '%s' "$m$u" | sha256_of | cut -c1-12)" "$m" "$u"
      printf ' "host": "authz.fixture.example", "path": "%s", "source": "crawl",' "$path"
      printf ' "depth": 1, "status": "200", "content_type": "%s" }' "${ct:-}"
    done
    printf '\n  ]\n}\n'
  } >"$file"
}

_write_parameters() {
  local file=$1; shift
  mkdir -p "${file%/*}"
  {
    printf '{\n  "schema": "scoursh.inventory.parameters/1",\n'
    printf '  "run_id": "fixture", "generated_by": "tests/suites/dast-authz.sh",\n'
    printf '  "parameters": [\n'
    local first=1 spec m u name loc ex
    for spec in "$@"; do
      read -r m u name loc ex <<<"$spec"
      (( first )) || printf ',\n'
      first=0
      printf '    { "id": "p%s", "endpoint_id": "e%s", "target": "authz-fixture",' "$first" "$first"
      printf ' "method": "%s", "url": "%s", "name": "%s", "location": "%s", "source": "crawl", "example": "%s" }' \
        "$m" "$u" "$name" "$loc" "$ex"
    done
    printf '\n  ]\n}\n'
  } >"$file"
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

AUTHCONF=$W/auth.conf

# `_identities <user-a> <user-b> [labels...]` - write config/auth.conf and seed
# a live session for each label named. With one label, only that identity is
# configured, which is how the requires-identities: 2 skip path is reached.
_identities() {
  local ua=$1 ub=$2; shift 2
  rm -rf "$SCOURSH_SCRATCH/dast-auth"
  DAST_AUTH_LOADED=0
  records_clear auth 2>/dev/null || true
  : >"$AUTHCONF"
  chmod 600 "$AUTHCONF"
  {
    printf 'id: authz-fixture.a\nmode: bearer\ntoken: TOK-A\nusername: %s\n' "$ua"
    if [[ $# -gt 1 || ${1:-} == b ]]; then
      printf '\nid: authz-fixture.b\nmode: bearer\ntoken: TOK-B\nusername: %s\n' "$ub"
    fi
  } >"$AUTHCONF"
  dast_auth_load "$AUTHCONF"
  local l
  for l in "$@"; do
    _seed_session authz-fixture "$l" "TOK-${l^^}"
  done
}

_phase_env() {
  SCOURSH_DAST_TARGET=authz-fixture
  SCOURSH_DAST_CELL=authz-fixture
  SCOURSH_DAST_INTENSITY=active
  SCOURSH_DAST_AUTHED=${1:-true}
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  SCOURSH_DAST_ENDPOINTS=${2:-}
  SCOURSH_DAST_PARAMETERS=${3:-}
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
    SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE \
    SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
}

# ===========================================================================
# A. Pure functions (no network, no run directory)
# ===========================================================================
printf '\n== A. object references and the field list ==\n'

t_case 'an object reference is exactly what path_template_of turns into {id}'
# Asserted AGAINST that function, never by restating its four patterns here: if
# the two ever disagree this check probes a segment the fingerprint treats as a
# literal, or skips one it collapses. Fails the moment either side is edited
# alone.
for seg in 1 42 0 550e8400-e29b-41d4-a716-446655440000 \
  01ARZ3NDEKTSV4RRFFQ69G5FAV deadbeefdeadbeef 0123456789abcdef0123; do
  tmpl=$(path_template_of "/api/x/$seg")
  if [[ $tmpl == '/api/x/{id}' ]]; then
    assert_status 0 "'$seg' is a reference here, as it is to path_template_of" \
      authz_is_object_ref "$seg"
  else
    assert_status 1 "'$seg' is not a reference here, as it is not to path_template_of" \
      authz_is_object_ref "$seg"
  fi
done
for seg in jane about pricing index.html v2 '' abc; do
  tmpl=$(path_template_of "/api/x/$seg")
  assert_ne '/api/x/{id}' "$tmpl" "path_template_of keeps '$seg' literal"
  assert_status 1 "'$seg' is not an object reference - a slug is deliberately excluded" \
    authz_is_object_ref "$seg"
done

t_case 'a reference is named after the collection it belongs to'
assert_eq basket "$(authz_ref_param_name /rest/basket/5 2)" 'the preceding segment names it'
assert_eq users "$(authz_ref_param_name /api/users/1/orders/2 2)" 'first reference in a nested path'
assert_eq orders "$(authz_ref_param_name /api/users/1/orders/2 4)" \
  'second reference gets a DIFFERENT name - fails under a constant, which would collide the two on one fingerprint'
assert_eq segment-0 "$(authz_ref_param_name /7 0)" 'a leading reference falls back to the positional form'

t_case 'field names normalise across casing and separators'
for n in password_hash passwordHash Password-Hash PASSWORD.HASH; do
  assert_eq passwordhash "$(authz_normalise_field "$n")" "'$n' normalises"
done

t_case 'the vendored list loads and matches substring vs exact'
LIST=$W/fields.txt
cat >"$LIST" <<'EOF'
# a comment, and a blank line follow
password
=salt
=isadmin
EOF
# Called DIRECTLY, never through assert_status: that helper runs its command in
# a subshell, so a function that SETS a variable would have its whole effect
# discarded and every assertion below it would read a stale value.
rc=0; authz_sensitive_load "$LIST" || rc=$?
assert_eq 0 "$rc" 'the list loads'
assert_eq 3 "${#_AUTHZ_SENSITIVE[@]}" 'comments and blank lines are not entries'
assert_status 0 'a bare entry is a substring match' authz_field_matches passwordhash
assert_status 0 'and matches a prefix too' authz_field_matches userpassword
assert_status 0 'an = entry matches exactly' authz_field_matches salt
assert_status 1 'an = entry does NOT match a superstring - fails under a substring reading, which makes "saltwater" a credential' \
  authz_field_matches saltwater
assert_status 1 'an unrelated name does not match' authz_field_matches displayname

t_case 'an absent or empty list is a failure to load, not an error'
rc=0; authz_sensitive_load "$W/nope.txt" || rc=$?
assert_eq 1 "$rc" 'absent list'
: >"$W/empty.txt"
rc=0; authz_sensitive_load "$W/empty.txt" || rc=$?
assert_eq 1 "$rc" 'empty list'

t_case 'the shipped list is loadable and non-empty'
rc=0; authz_sensitive_load "$ROOT/modules/dast/sensitive-fields.txt" || rc=$?
assert_eq 0 "$rc" 'modules/dast/sensitive-fields.txt loads'
assert_true "$(( ${#_AUTHZ_SENSITIVE[@]} >= 20 ? 0 : 1 ))" 'the shipped list has real entries'

t_case 'field names are read from JSON; array indices are not fields'
BODY=$W/body.json
printf '%s' '{"id":1,"tags":["x","y","z"],"user":{"passwordHash":"$2b$PLANTED","email":"e"}}' >"$BODY"
NAMES=$(authz_field_names "$BODY")
assert_contains "$NAMES" 'passwordHash' 'a nested field name is read'
assert_contains "$NAMES" 'tags' \
  'an ARRAY field is named after the array, not its indices - fails under "drop a numeric last segment", which loses the field called `tokens` in `"tokens": [..]` entirely'
assert_not_contains "$NAMES" $'\n0\n' \
  'an array INDEX is never a field name - fails under "the last path segment is always a field", which turns a list of ten strings into ten columns'

t_case 'the body scan reports NAMES and never touches values'
authz_sensitive_load "$ROOT/modules/dast/sensitive-fields.txt"
rc=0; authz_scan_body "$BODY" || rc=$?
assert_eq 0 "$rc" 'the planted credential field is found'
assert_contains "${_AUTHZ_HITS[*]}" 'passwordHash' 'reported as the target spelled it'
assert_not_contains "${_AUTHZ_HITS[*]}" 'PLANTED' 'the VALUE is not in the hit list'

t_case 'a body over the parse bound is refused rather than parsed'
BIG=$W/big.json
head -c $(( 524288 + 16 )) /dev/zero | tr '\0' 'a' >"$BIG"
assert_status 1 'over the bound' authz_body_within_bounds "$BIG"
assert_status 0 'under the bound' authz_body_within_bounds "$BODY"

t_case 'the identity-substring test is case-insensitive and bounded'
assert_status 0 'present' authz_body_contains "$BODY" 'PASSWORDHASH'
assert_status 1 'absent' authz_body_contains "$BODY" 'nobody-here'
assert_status 1 'an empty needle never matches' authz_body_contains "$BODY" ''

# ===========================================================================
# B. Candidate extraction from the frozen inventory
# ===========================================================================
printf '\n== B. candidates from endpoints.json / parameters.json ==\n'

SCOURSH_DAST_TARGET=authz-fixture
export SCOURSH_DAST_TARGET

t_case 'path references are extracted and mutating methods never become candidates'
EP=$W/b1/endpoints.json
_write_endpoints "$EP" \
  'GET https://authz.fixture.example/api/basket/1 application/json' \
  'GET https://authz.fixture.example/api/basket/2 application/json' \
  'POST https://authz.fixture.example/api/basket/9 application/json' \
  'DELETE https://authz.fixture.example/api/basket/8 application/json' \
  'GET https://authz.fixture.example/about text/html'
authz_candidates_set authz-fixture "$EP" ''
assert_eq 2 "${#_AUTHZ_CANDIDATES[@]}" \
  'only the two idempotent object references are candidates - fails under "filter the method at the call site", which lets a DELETE reach the probe'
assert_eq 2 "$_AUTHZ_SKIPPED_METHOD" 'the two mutating entries are counted, not silently dropped'
assert_contains "${_AUTHZ_CANDIDATES[*]}" '/api/basket/1' 'the first reference'
assert_not_contains "${_AUTHZ_CANDIDATES[*]}" '/about' 'a slug-free static path is not an object reference'
assert_not_contains "${_AUTHZ_CANDIDATES[*]}" 'basket/9' 'the POST reference never appears at all'

t_case 'candidates under one path template share a group key'
K1=$(authz_group_key "${_AUTHZ_CANDIDATES[0]}")
K2=$(authz_group_key "${_AUTHZ_CANDIDATES[1]}")
assert_eq "$K1" "$K2" 'two references to one handler are one group'
assert_contains "$K1" '/api/basket/{id}' 'the key is built on the path TEMPLATE, not the concrete path'

t_case 'an out-of-scope inventory entry is dropped, never fatal'
EP2=$W/b2/endpoints.json
_write_endpoints "$EP2" \
  'GET https://authz.fixture.example/api/basket/1 application/json'
# The generator only writes in-scope hosts, so the off-target entry is appended
# by hand - which is exactly how it arrives in real life, from a page the
# scanned target chose.
python3 - "$EP2" <<'PY'
import json,sys
p=sys.argv[1]
d=json.load(open(p))
d['endpoints'].append({"id":"ffffffffffff","target":"authz-fixture","method":"GET",
  "url":"https://elsewhere.example/api/basket/7","host":"elsewhere.example",
  "path":"/api/basket/7","source":"crawl","depth":1,"status":"200","content_type":"application/json"})
json.dump(d,open(p,'w'))
PY
rc=0; authz_candidates_set authz-fixture "$EP2" '' || rc=$?
assert_eq 0 "$rc" 'extraction survives an out-of-scope entry - fails under "hand every inventory URL to http_request", which exits 3 and aborts the operator run'
assert_eq 1 "${#_AUTHZ_CANDIDATES[@]}" 'only the in-scope reference is kept'
assert_eq 1 "$_AUTHZ_SKIPPED_SCOPE" 'and the drop is counted'

t_case 'a query parameter whose example is a reference becomes a candidate'
PR=$W/b3/parameters.json
_write_parameters "$PR" \
  'GET https://authz.fixture.example/api/doc order_id query 7' \
  'GET https://authz.fixture.example/api/doc limit query 20' \
  'GET https://authz.fixture.example/api/doc q query 4' \
  'POST https://authz.fixture.example/api/doc post_id query 3'
authz_candidates_set authz-fixture '' "$PR"
assert_eq 1 "${#_AUTHZ_CANDIDATES[@]}" \
  'only the reference-NAMED query parameter is a candidate - fails under "any parameter with an integer example", which makes ?limit=20 an object reference'
assert_contains "${_AUTHZ_CANDIDATES[*]}" '/api/doc?order_id=7' \
  'the URL is composed from the parameter, since endpoints.json carries no query string (docs/INVENTORY-FORMAT.md §4)'

t_case 'an absent or empty inventory yields no candidates and no error'
rc=0; authz_candidates_set authz-fixture '' '' || rc=$?
assert_eq 0 "$rc" 'no inventory is a normal state'
assert_eq 0 "${#_AUTHZ_CANDIDATES[@]}" 'and produces nothing to probe'

# ===========================================================================
# C. The oracle, driven through the phase end to end
# ===========================================================================
printf '\n== C. the IDOR oracle ==\n'

# `_drive <endpoints-file> [parameters-file]` - one whole phase run: a fresh run
# directory, the two seeded identities, the inventory, and `source authz.sh`,
# which is exactly how `dast_run_phase` reaches it.  The SERVER table is set by
# the caller between `_srv_reset` and this.
_drive() {
  _phase_env true "${1:-}" "${2:-}"
  # shellcheck source=/dev/null
  source "$ROOT/modules/dast/authz.sh"
}

BASKETS=$W/c/endpoints.json
_write_endpoints "$BASKETS" \
  'GET https://authz.fixture.example/api/basket/1 application/json' \
  'GET https://authz.fixture.example/api/basket/2 application/json' \
  'GET https://authz.fixture.example/api/basket/3 application/json' \
  'POST https://authz.fixture.example/api/basket/9 application/json'

t_case 'C1: a shared object PLUS a refusal elsewhere in the group is a confirmed IDOR'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|b']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|anon']=$'401\t'
SRV['/api/basket/2|a']=$'403\t'
SRV['/api/basket/2|b']=$'200\tBASKET-TWO-BODY'
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_contains "$IDS" 'DAST-AUTHZ-IDOR-01' \
  'the refusal on /api/basket/2 proves this endpoint enforces ownership, so the shared object is a confirmed IDOR'
assert_not_contains "$IDS" 'DAST-AUTHZ-CROSS_IDENTITY_READ-01' \
  'and NOT the weaker id - fails under "always emit the observation", which buries a confirmed break at medium confidence'
assert_eq basket "$(_finding_field DAST-AUTHZ-IDOR-01 loc_param_name)" \
  'the finding names the COLLECTION as its parameter, not a positional label'
assert_eq '/api/basket/{id}' "$(_finding_field DAST-AUTHZ-IDOR-01 loc_path_template)" \
  'and is located on the path template, so two concrete references under one handler are one finding'
assert_eq high "$(_finding_field DAST-AUTHZ-IDOR-01 confidence)" \
  'a confirmed break is high confidence'

t_case 'C2: a shared object with NO refusal anywhere is the weaker observation'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|b']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|anon']=$'401\t'
# /api/basket/2 and /3 are unlisted: 404 to BOTH identities, which is not a
# witness, because a witness needs one identity served and the other refused.
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_contains "$IDS" 'DAST-AUTHZ-CROSS_IDENTITY_READ-01' \
  'with no evidence the endpoint enforces ownership at all, this is an observation'
assert_not_contains "$IDS" 'DAST-AUTHZ-IDOR-01' \
  'and NOT a confirmed IDOR - fails under "any shared object is an IDOR", which reports every legitimately shared resource at high confidence'
assert_eq medium "$(_finding_field DAST-AUTHZ-CROSS_IDENTITY_READ-01 confidence)" \
  'and it says so in the confidence, not only in the prose'

t_case 'C3: a PUBLIC object is excluded by the unauthenticated control'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tPUBLIC-BODY'
SRV['/api/basket/1|b']=$'200\tPUBLIC-BODY'
SRV['/api/basket/1|anon']=$'200\tPUBLIC-BODY'
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_not_contains "$IDS" 'DAST-AUTHZ-IDOR-01' 'a public object is not an authorization defect'
assert_not_contains "$IDS" 'DAST-AUTHZ-CROSS_IDENTITY_READ-01' \
  'nor a cross-identity read - fails under "both identities read it, therefore report it", which flags every public page on the target'
assert_contains "$(run_facts coverage_reduction)" 'reason=object_reference_public' \
  'and the exclusion is recorded rather than silent'

t_case 'C4: an unauthenticated 200 LOGIN PAGE does not make the object public'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|b']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|anon']=$'200\t<html>please sign in</html>'
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_contains "$IDS" 'DAST-AUTHZ-CROSS_IDENTITY_READ-01' \
  'the finding survives - fails under "an anonymous 2xx means public", which silences every real finding on any app that answers a logged-out request with a login page'
assert_not_contains "$(run_facts coverage_reduction)" 'reason=object_reference_public' \
  'and the object is not recorded as public'

t_case 'C5: an application that enforces ownership produces NO finding'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tALPHA-OWN-BASKET'
SRV['/api/basket/1|b']=$'403\t'
SRV['/api/basket/2|a']=$'403\t'
SRV['/api/basket/2|b']=$'200\tBRAVO-OWN-BASKET'
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_not_contains "$IDS" 'DAST-AUTHZ-' \
  'each identity reads only its own object, so there is nothing to report'

t_case 'C6: per-identity content is not a finding, and is not silence either'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tALPHA-VIEW'
SRV['/api/basket/1|b']=$'200\tBRAVO-VIEW'
_drive "$BASKETS"
IDS=$(_shard_check_ids)
assert_not_contains "$IDS" 'DAST-AUTHZ-IDOR-01' 'different bytes to each identity is the CORRECT shape'
assert_not_contains "$IDS" 'DAST-AUTHZ-CROSS_IDENTITY_READ-01' 'so neither id is emitted'
assert_contains "$(run_facts coverage_gap)" 'returned different bytes to each' \
  'but the run says so, because the same shape is what a per-request nonce defeating the comparison looks like'

printf '\n== D. read-only ==\n'

t_case 'D: every request is a GET, and the POST reference is never touched'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/basket/1|a']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|b']=$'200\tSHARED-BASKET-BODY'
SRV['/api/basket/1|anon']=$'401\t'
SRV['/api/basket/2|a']=$'403\t'
SRV['/api/basket/2|b']=$'200\tBASKET-TWO-BODY'
_drive "$BASKETS"
LOG=$(cat "$REQ_LOG")
assert_true "$(( $(_request_count) > 0 ? 0 : 1 ))" 'the phase really did send requests'
assert_not_contains "$LOG" 'POST ' 'no POST was ever sent'
assert_not_contains "$LOG" 'PUT ' 'no PUT was ever sent'
assert_not_contains "$LOG" 'DELETE ' 'no DELETE was ever sent'
assert_not_contains "$LOG" '/api/basket/9' \
  'the POST object reference in the inventory was never requested at all - the read-only guarantee, asserted over the request log rather than over a return value'

# ===========================================================================
# E. Excessive data exposure
# ===========================================================================
printf '\n== E. excessive data exposure ==\n'

# A path with NO object-reference segment, so the IDOR pass has nothing to do
# and each case here isolates the exposure pass.  The phase records
# `reason=no_object_reference` for these runs, which is correct and is asserted
# in section F rather than repeated per case.
PROFILE=$W/e/endpoints.json
_write_endpoints "$PROFILE" \
  'GET https://authz.fixture.example/api/profile application/json'

t_case 'E1: a sensitive FIELD NAME is reported and its VALUE never leaves the target'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/profile|a']=$'200\t{"id":1,"email":"alpha-user@example.test","passwordHash":"PLANTEDSECRETVALUE0001"}'
_drive "$PROFILE"
IDS=$(_shard_check_ids)
assert_contains "$IDS" 'DAST-AUTHZ-EXCESSIVE_DATA-01' \
  'a credential-shaped field name in an authenticated response is over-exposure'
assert_contains "$(_finding_field DAST-AUTHZ-EXCESSIVE_DATA-01 evidence)" 'passwordHash' \
  'the evidence names the field as the target spelled it, so an operator can find it'
assert_not_contains "$(_shard_text)" 'PLANTEDSECRETVALUE0001' \
  "the VALUE appears NOWHERE in the shard - fails under 'digest the value into the evidence', which makes the report of an over-exposed credential the second place it is exposed. The shard encodes only backslash, tab, CR and LF, so a plain value really would be visible here if it were copied"
assert_eq 'response-body' "$(_finding_field DAST-AUTHZ-EXCESSIVE_DATA-01 loc_param_name)" \
  'the finding is located on the response body rather than on a request parameter'

t_case 'E2: another identity IDENTIFIER in this identity response is the cross-tenant arm'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/profile|a']=$'200\t{"id":1,"displayName":"Alpha","peer":"bravo-user@example.test"}'
_drive "$PROFILE"
IDS=$(_shard_check_ids)
assert_contains "$IDS" 'DAST-AUTHZ-OTHER_IDENTITY_DATA-01' \
  "identity A's response carries identity B's configured identifier"
assert_not_contains "$IDS" 'DAST-AUTHZ-EXCESSIVE_DATA-01' \
  'and NOT the field-name id - fails under one merged check, which would lose which of the two claims was actually observed'
assert_not_contains "$(_shard_text)" 'bravo-user' \
  "identity B's identifier is never copied into the finding - fails under 'quote the needle in the evidence', which copies a value out of a mode-600 credential file into a world-readable report"
assert_contains "$(_finding_field DAST-AUTHZ-OTHER_IDENTITY_DATA-01 evidence)" "identity 'b'" \
  'the finding names the identity LABEL instead, which is the operator-chosen half'

t_case 'E3: an ordinary authenticated response produces neither exposure finding'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/profile|a']=$'200\t{"id":1,"displayName":"Alpha","locale":"en"}'
_drive "$PROFILE"
IDS=$(_shard_check_ids)
assert_not_contains "$IDS" 'DAST-AUTHZ-EXCESSIVE_DATA-01' 'no field name matches the list'
assert_not_contains "$IDS" 'DAST-AUTHZ-OTHER_IDENTITY_DATA-01' "and identity B's identifier is absent"
assert_contains "$(run_facts coverage_gap)" 'It reads no field VALUES' \
  'but the run still states what the clean result does and does not mean'

t_case 'E4: an identifier that is a substring of the other one refuses the test'
_fresh_run; _srv_reset
# 'alpha-user' CONTAINS 'alpha-us', so finding the second inside identity A's
# own response proves nothing about B.  The naive reading emits a high-severity
# cross-tenant finding on every response A receives about itself.
_identities alpha-user alpha-us a b
SRV['/api/profile|a']=$'200\t{"id":1,"displayName":"alpha-user"}'
_drive "$PROFILE"
IDS=$(_shard_check_ids)
assert_not_contains "$IDS" 'DAST-AUTHZ-OTHER_IDENTITY_DATA-01' \
  "no finding - fails under a bare substring test, which reports identity A's own profile as carrying identity B's data"
assert_contains "$(run_facts coverage_reduction)" 'reason=identity_identifier_not_discriminating' \
  'and the run says the arm was skipped rather than passing silently'

t_case 'E5: an unreadable field list is a recorded reduction, not an error'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
SRV['/api/profile|a']=$'200\t{"passwordHash":"PLANTEDSECRETVALUE0002"}'
rc=0
SCOURSH_DAST_SENSITIVE_FIELDS_FILE=$W/no-such-list.txt _drive "$PROFILE" || rc=$?
assert_eq 0 "$rc" 'the phase still returns cleanly'
assert_contains "$(run_facts coverage_reduction)" 'reason=sensitive_field_list_unavailable' \
  'and names the missing input - fails under a silent skip, where an absent finding reads as a clean response'

# ===========================================================================
# F. Every skip path returns cleanly AND says why
# ===========================================================================
printf '\n== F. skip paths ==\n'
# Silence on any of these would read as "this application enforces object-level
# authorization", which is the single most expensive way for this check to be
# wrong. Each case therefore asserts the EXIT STATUS and the RECORDED REASON,
# never just the absence of a finding.

t_case 'F1: without --authed nothing is sent and the gap is recorded'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
_phase_env false "$PROFILE"
rc=0
# shellcheck source=/dev/null
source "$ROOT/modules/dast/authz.sh" || rc=$?
assert_eq 0 "$rc" 'the phase returns 0, per the ticket: skip cleanly, do not fail'
assert_eq '' "$(_shard_check_ids)" 'nothing is emitted'
assert_eq 0 "$(_request_count)" 'and NO request is sent at all'
assert_contains "$(run_facts coverage_reduction)" 'reason=authed_not_requested' 'the reason is recorded'
assert_contains "$(run_facts coverage_gap)" 'absence of a test' 'in words an operator reads in the report'

t_case 'F2: one authenticated identity is not two, and the run says so'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a
rc=0
_drive "$PROFILE" || rc=$?
assert_eq 0 "$rc" 'still a clean return'
assert_eq '' "$(_shard_check_ids)" 'no finding is invented from one session'
assert_eq 0 "$(_request_count)" 'and no probe is made - fails under "run it against one identity and see", which cannot distinguish "mine" from "anybody\x27s"'
assert_contains "$(run_facts coverage_reduction)" 'reason=requires_identities_unmet' 'the reason names the unmet requirement'
assert_contains "$(run_facts coverage_reduction)" 'required=2 authenticated=1' 'with the counts, so the operator knows which half to fix'

t_case 'F3: no inventory means no candidates, on both passes'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
rc=0
_drive '' || rc=$?
assert_eq 0 "$rc" 'a clean return'
assert_eq 0 "$(_request_count)" 'and nothing is guessed at - no path is invented to probe'
REDUCTIONS=$(run_facts coverage_reduction)
assert_contains "$REDUCTIONS" 'reason=no_object_reference' 'the IDOR pass says it had nothing to substitute'
assert_contains "$REDUCTIONS" 'reason=no_endpoint_inventory' 'and the exposure pass says it had nothing to call'

t_case 'F4: a third identity is not used, and that is stated rather than hidden'
_fresh_run; _srv_reset
_identities alpha-user@example.test bravo-user@example.test a b
_seed_session authz-fixture c TOK-C
printf '\nid: authz-fixture.c\nmode: bearer\ntoken: TOK-C\nusername: charlie-user@example.test\n' >>"$AUTHCONF"
DAST_AUTH_LOADED=0
records_clear auth 2>/dev/null || true
dast_auth_load "$AUTHCONF"
SRV['/api/profile|a']=$'200\t{"id":1}'
_drive "$PROFILE"
assert_contains "$(run_facts coverage_reduction)" 'reason=extra_identities_unused' \
  'the pairing is the first two in config order and the rest are declared unprobed'

# ===========================================================================
# G. The registry and the emitter agree
# ===========================================================================
printf '\n== G. registry agreement ==\n'
t_case 'every id the phase can emit is registered with the same facts'
# modules/dast/checks.rules is the catalog tension 12's coverage and tension
# 15's filter chain read; `_authz_catalog` is what a finding actually carries.
# They are two copies of one fact, so they are asserted equal rather than
# assumed so.  The file is SHARED with the other tier-5 phases, so the id set
# is taken over THIS script's own records - counting every `id:` in the file
# would turn a correct, append-only merge by a peer into a failure here.
declare -A REG_SEV=() REG_CWE=() REG_OWASP=() REG_TITLE=() REG_SCRIPT=() REG_TAG=() REG_IDENT=()
_cur_id=''
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *': '* ]] || continue
  _key=${line%%': '*}; _val=${line#*': '}
  case $_key in
    id) _cur_id=$_val ;;
    title) REG_TITLE[$_cur_id]=$_val ;;
    severity) REG_SEV[$_cur_id]=$_val ;;
    cwe) REG_CWE[$_cur_id]=$_val ;;
    owasp) REG_OWASP[$_cur_id]=$_val ;;
    script) REG_SCRIPT[$_cur_id]=$_val ;;
    requires-identities) REG_IDENT[$_cur_id]=$_val ;;
    tags) [[ -z ${REG_TAG[$_cur_id]:-} ]] && REG_TAG[$_cur_id]=$_val ;;
  esac
done <"$ROOT/modules/dast/checks.rules"

_reg_ids=''
for _id in "${!REG_SCRIPT[@]}"; do
  [[ ${REG_SCRIPT[$_id]} == 'authz.sh' ]] && _reg_ids+="$_id "
done
assert_eq "${#_AUTHZ_CHECK_IDS[@]}" "$(printf '%s' "$_reg_ids" | wc -w | tr -d ' ')" \
  'the registry declares exactly the ids this phase can emit - FAILS if either side grows without the other'
for c in "${_AUTHZ_CHECK_IDS[@]}"; do
  _authz_catalog "$c"
  assert_eq "${REG_TITLE[$c]:-<absent>}" "$_AUTHZC_TITLE" "$c: title agrees with the registry"
  assert_eq "${REG_SEV[$c]:-<absent>}" "$_AUTHZC_SEV" "$c: severity agrees with the registry"
  assert_eq "${REG_CWE[$c]:-<absent>}" "$_AUTHZC_CWE" "$c: CWE agrees with the registry"
  assert_eq "${REG_OWASP[$c]:-<absent>}" "$_AUTHZC_OWASP" "$c: OWASP mapping agrees with the registry"
  assert_eq 'authz.sh' "${REG_SCRIPT[$c]:-<absent>}" "$c: the registry names this phase script"
  assert_eq '2' "${REG_IDENT[$c]:-<absent>}" \
    "$c: requires-identities is 2 - the key rules/RULE-FORMAT.md §9.5 froze naming authz.sh, and the reason this check may not run on one session"
  assert_eq 'active' "${REG_TAG[$c]:-<absent>}" \
    "$c: the type tag matches modules/dast/engine.sh's own 'authz.sh:active' floor - FAILS if the registry gate and the phase gate disagree, which tension 15 forbids"
done

t_case "the phase table's floor for this script is the one the registry declares"
# Read out of modules/dast/engine.sh rather than by sourcing it: that file
# publishes `_DAST_PHASES` alongside `dast_run_phase`, and sourcing it here to
# read one array would put a second definition of the phase runner into a suite
# whose whole point is to drive the phase script directly.  No bare `grep`
# (docs/FOUNDATION.md tension 4): a while-read over the file is exact and has no
# no-match exit status to confuse with an engine failure.
_phase_row=''
while IFS= read -r line || [[ -n $line ]]; do
  line=${line#"${line%%[![:space:]]*}"}
  [[ ${line:0:1} == "'" ]] || continue
  [[ $line == "'authz.sh:"* ]] || continue
  _phase_row=${line#\'}
  _phase_row=${_phase_row%%\'*}
  break
done <"$ROOT/modules/dast/engine.sh"
assert_eq 'authz.sh:active' "$_phase_row" \
  "authz.sh is a row in modules/dast/engine.sh's _DAST_PHASES at the 'active' floor, so scan_dispatch dast reaches it - fails if the row is dropped (every case above would then be testing a file nothing runs) or if its tier drifts from the registry tag asserted just above"

# ===========================================================================
printf '\n== dast-authz: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
