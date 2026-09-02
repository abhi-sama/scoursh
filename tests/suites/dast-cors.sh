#!/usr/bin/env bash
# tests/suites/dast-cors.sh - modules/dast/passive/cors.sh and cors_engine.sh:
# CORS origin reflection (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-08).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), and the stub serves RECORDED response
# headers from tests/fixtures/dast/cors/ - real, CRLF-terminated header blocks in
# the exact shape lib/http.sh's capture sink writes - rather than strings
# composed inline to agree with the parser.  See that directory's README for the
# roster and for why the CRLF matters.
#
# THE DECISIONS THIS SUITE PINS, each with the plausible wrong reading that
# would otherwise ship green:
#
#   1. `*` IS NOT REFLECTION.  A check keying on "an ACAO header came back"
#      grades a public CSS file the same as a reflecting authenticated API.
#      Pinned in both directions: the wildcard case emits WILDCARD and never
#      ORIGIN_REFLECTED, and the reflection case emits ORIGIN_REFLECTED and
#      never WILDCARD.
#   2. REFLECTION + CREDENTIALS IS ONE FINDING, NOT TWO.  The credentialed id
#      SUBSUMES the plain one; a check that emitted both would report one root
#      cause twice.
#   3. A STATIC ALLOWLIST IS NOT A FINDING.  A server that answers its own
#      configured origin to our sentinel validated the Origin correctly.
#   4. REFLECTION IS EXACT EQUALITY.  A value that CONTAINS the sentinel
#      (`<sentinel>.attacker.invalid`) is not a reflection of it; a substring
#      test calls it one.
#   5. HEADER NAMES ARE MATCHED CASE-INSENSITIVELY.  HTTP/2 requires lowercase
#      field names, so a check matching the RFC 6454 spelling byte-for-byte
#      reports every HTTP/2 target clean.
#   6. THE TRAILING CR IS STRIPPED.  Every fixture is CRLF-terminated, because
#      that is what HTTP is; a reader that keeps the CR compares
#      "<origin>\r" against the sentinel and finds a reflecting server clean.
#   7. THE PASSIVE CONTRACT.  Only GET/HEAD endpoints are requested, exactly one
#      request per distinct route, no body sink is set, no redirect is followed,
#      and no request is ever addressed to the sentinel origin.  All five are
#      asserted against a REQUEST LOG, not against a return value.
#   8. A TRANSPORT FAILURE IS NOT A CLEAN RESULT.  It is counted as untested and
#      recorded, never as "this route sends no CORS header".
#   9. GRACEFUL DEGRADATION.  No inventory, or an inventory with no idempotent
#      endpoint, is a RECORDED gap - never an error and never a silent pass.
#  10. THE NULL-ORIGIN FOLLOW-UP (DAST-08 follow-up): a SECOND `Origin: null`
#      probe fires only when the sentinel probe's own verdict was neither
#      `reflected` nor `wildcard`, one route now costs up to TWO requests
#      instead of one, and a server that reflects `null` back gets its own
#      two check ids (plain / credentialed, the credentialed one subsuming the
#      plain one) - pinned in section C2 and folded into section D's
#      request-log counts.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes header and JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# lib/report.sh for section F's round trip: in a real run scan.sh sources it at
# top level before scan_dispatch, so the phase never needs it - it is
# modules/dast/run.sh that calls report_all - but this suite drives the phase
# directly and then writes the reports itself.
if [[ -z ${SCOURSH_REPORT_SOURCED:-} ]]; then
  # shellcheck source=lib/report.sh
  source "$ROOT/lib/report.sh"
fi
# shellcheck source=modules/dast/passive/cors_engine.sh
source "$ROOT/modules/dast/passive/cors_engine.sh"
# shellcheck source=modules/dast/crawl_engine.sh
source "$ROOT/modules/dast/crawl_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$ROOT/tests/fixtures/dast/cors
W=$SCOURSH_SCRATCH/dast-cors-workspace
rm -rf "$W"
mkdir -p "$W"

# The value tests/fixtures/dast/cors/*.headers were RECORDED against.  Asserted
# rather than derived, so changing the shipped sentinel fails here with a
# sentence saying what to do, instead of silently turning every reflection
# fixture into a non-finding that still passes an "emits nothing" assertion.
RECORDED_SENTINEL='https://scoursh-cors-probe.example'

printf '\n== 0. the fixtures and the shipped sentinel agree ==\n'
t_case 'the recorded fixtures match the shipped sentinel origin'
assert_eq "$RECORDED_SENTINEL" "$CORS_SENTINEL_ORIGIN" \
  'CORS_SENTINEL_ORIGIN equals the origin tests/fixtures/dast/cors/*.headers were recorded against - if this fails, re-record those fixtures rather than deleting this assertion, or every reflection case silently becomes a non-finding'
assert_contains "$CORS_SENTINEL_ORIGIN" '.example' \
  'the sentinel is an RFC 2606 reserved name, so it can never resolve and can never reach a third party'

# ---------------------------------------------------------------------------
# Scope + the two stubs that keep this suite off the network.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: cors-fixture
base-url: https://cors.fixture.example/
allow-subdomains: false
notes: Fixture target for tests/suites/dast-cors.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF

_cors_resolve() {
  case $1 in
    cors.fixture.example) printf '198.51.100.7' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_cors_resolve

# The scripted SERVER.  A path -> recorded-fixture table, so every response this
# suite sees is a file on disk rather than a string composed to agree with the
# parser.  `SRV_FAIL_PATH` makes one path a transport-level failure, which is
# how the "a failure is not a clean result" case is driven.  `SRV_REDIRECT_PATH`
# makes one path answer a 3xx with a cross-origin `Location:` instead of the
# ordinary 200 - section G's redirect-across-origin case (ticket
# aa50f056-9b18-4fc7-9416-bb455bc7b7b1's follow-up).
REQ_LOG=$W/requests.log
declare -A SRV_MAP=()
SRV_FAIL_PATH=''
SRV_FAIL_ALL=0
SRV_REDIRECT_PATH=''
SRV_REDIRECT_LOCATION=''

_srv_reset() {
  SRV_MAP=()
  SRV_FAIL_PATH=''
  SRV_FAIL_ALL=0
  SRV_REDIRECT_PATH=''
  SRV_REDIRECT_LOCATION=''
  : >"$REQ_LOG"
}

# METHOD SCHEME HOST PORT PATH ADDR [BODY_OUT] [HEADERS_OUT] - lib/http.sh's
# frozen transport contract.  Logs enough for the passive-contract assertions to
# be made against the LOG rather than against a return value: the method, the
# host it was addressed to, the path, whether a body sink was asked for, and
# every request header that rode along.
_cors_transport() {
  local method=$1 host=$3 path=$5 h origin='' body_sink=no fixture
  for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    case $h in
      Origin:*) origin=${h#Origin: } ;;
    esac
  done
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && body_sink=yes
  printf '%s\t%s\t%s\torigin=%s\tbody_sink=%s\thas_body=%s\n' \
    "$method" "$host" "$path" "$origin" "$body_sink" \
    "${_HTTP_TX_HAS_BODY:-false}" >>"$REQ_LOG"

  (( SRV_FAIL_ALL )) && return 1
  [[ -n $SRV_FAIL_PATH && $path == "$SRV_FAIL_PATH" ]] && return 1

  fixture=${SRV_MAP[$path]:-none.headers}
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    cat -- "$FIX/$fixture" >>"$_HTTP_TX_HEADERS_OUT"
  fi
  if [[ -n $SRV_REDIRECT_PATH && $path == "$SRV_REDIRECT_PATH" ]]; then
    printf '302\n%s\n\n' "$SRV_REDIRECT_LOCATION"
    return 0
  fi
  printf '200\n\n'
}
SCOURSH_HTTP_TRANSPORT=_cors_transport

http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

_req_count() {
  local n=0 line
  [[ -r $REQ_LOG ]] || { printf 0; return 0; }
  while IFS= read -r line; do [[ -n $line ]] && n=$(( n + 1 )); done <"$REQ_LOG"
  printf '%s' "$n"
}

_req_log_text() {
  [[ -r $REQ_LOG ]] && cat -- "$REQ_LOG" || printf ''
}

RUN_N=0
_new_run() {
  RUN_N=$(( RUN_N + 1 ))
  local dir=$W/run.$RUN_N
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target cors-fixture
  occurrence_reset_all
  SCOURSH_DAST_CELL=cors-fixture
  export SCOURSH_DAST_CELL
  _srv_reset
}

# The shard `.fields` format is one finding per line, fields TAB-delimited as
# `key=value` (lib/findings.sh's `_finding_fields`).
_count_check() {
  local check=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && { n=$(( n + 1 )); break; }
      done
    done <"$f"
  done
  printf '%s' "$n"
}

_count_check_path() {
  local check=$1 tmpl=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_path_template=$tmpl" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# The value of one field of the FIRST finding for a check id (mirrors
# tests/suites/dast-leakage.sh's own `_field_of`).
_field_of() {
  local check=$1 want=$2 f line fld hit='' v=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      hit='' v=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hit=1
        [[ $fld == "$want="* ]] && v=${fld#"$want="}
      done
      [[ -n $hit ]] && { printf '%s' "$v"; return 0; }
    done <"$f"
  done
  printf ''
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

_meta_text() {
  local out=''
  out+=$(run_facts coverage_gap 2>/dev/null || true)
  out+=$'\n'
  out+=$(run_facts coverage_reduction 2>/dev/null || true)
  printf '%s' "$out"
}

_checks_run_text() {
  run_facts checks_run 2>/dev/null || true
}

# ===========================================================================
printf '\n== A. the header reader, against recorded CRLF responses ==\n'
# ===========================================================================
t_case 'cors_header_last reads a CRLF-terminated header and strips the CR'
cors_header_last "$FIX/reflect-plain.headers" 'Access-Control-Allow-Origin' || true
assert_eq "$RECORDED_SENTINEL" "$_CORS_HDR_VALUE" \
  'the reflected origin comes back with no trailing CR - FAILS under a reader that keeps the CR, which then compares "<origin>\r" against the sentinel and calls a reflecting server clean'

t_case 'the field name match is case-insensitive (HTTP/2 lowercases every name)'
cors_header_last "$FIX/reflect-lowercase.headers" 'Access-Control-Allow-Origin' || true
assert_eq "$RECORDED_SENTINEL" "$_CORS_HDR_VALUE" \
  'an HTTP/2 response spelling the field `access-control-allow-origin` is read - FAILS under a case-sensitive match, which reports every HTTP/2 target clean'

t_case 'RFC 7230 optional whitespace around a value is trimmed'
cors_header_last "$FIX/padded.headers" 'Access-Control-Allow-Origin' || true
assert_eq "$RECORDED_SENTINEL" "$_CORS_HDR_VALUE" \
  'leading and trailing OWS is stripped - FAILS under a raw `${line#*: }`, which leaves the value unequal to the sentinel'

t_case 'an absent header returns 1 and leaves the value empty'
assert_status 1 'cors_header_last returns 1 when the header is not present - FAILS if a no-match is reported as an empty-valued header, which makes `absent` unreachable' \
  cors_header_last "$FIX/none.headers" 'Access-Control-Allow-Origin'

t_case 'a duplicated header resolves to the LAST occurrence'
cors_header_last "$FIX/duplicate.headers" 'Access-Control-Allow-Origin' || true
assert_eq "$RECORDED_SENTINEL" "$_CORS_HDR_VALUE" \
  'the last Access-Control-Allow-Origin wins - FAILS under first-wins, which lets a permissive proxy value hide behind a strict application one'

t_case 'the credentials predicate is case-insensitive and rejects everything else'
assert_status 0 '`true` is credentialed' cors_credentials_true 'true'
assert_status 0 '`TRUE` is credentialed - FAILS under a byte-exact match against the Fetch standard spelling' cors_credentials_true 'TRUE'
assert_status 1 '`false` is not' cors_credentials_true 'false'
assert_status 1 'an empty value is not' cors_credentials_true ''
assert_status 1 '`1` is not credentialed - FAILS under a truthiness test rather than a value test' cors_credentials_true '1'

# ===========================================================================
printf '\n== A2. the two scratch files are unpredictable (CWE-377 via CWE-59) ==\n'
# ===========================================================================
# BOTH scratch paths in cors_engine.sh fall back to a world-writable directory
# when SCOURSH_SCRATCH is unset - which is every standalone-engine caller,
# including this suite before lib/core.sh has built one - so a name derived from
# $BASHPID is a name a local user can predict and pre-create as a symlink.  The
# process then writes THROUGH it: `scan_match` truncates whatever it points at,
# and the response-header sink would deposit the target's own headers at a
# location someone else chose.  `mktemp` refuses to follow a symlink and picks a
# name nobody can guess, which is what lib/http.sh's own transport already does.
#
# Driven by PLANTING the exact name the pre-fix code computed and asserting the
# canary behind it survives - so this fails on the pid-derived spelling and
# passes on the mktemp one, rather than asserting the source text.
# SETS `VICTIM`; it does NOT print it.  A `VICTIM=$(_plant_symlink ...)` would
# run this in a command substitution, i.e. a SUBSHELL with its own $BASHPID, so
# the planted name would not be the one the code under test computes and the
# assertion would pass against the vulnerable spelling - decoration rather than
# a test.  That is lib/core.sh's `occurrence_next` lesson (AGENTS.md, "Things
# measured on this codebase"), and it was caught here by running this section
# against the pre-fix code and watching it stay green.
_plant_symlink() {
  # Two lines, not one: assignments in a single `local` do not see each other
  # (same section of AGENTS.md).
  local base=$1
  local dir=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}
  VICTIM=$W/canary.$base
  printf 'CANARY\n' >"$VICTIM"
  ln -sf "$VICTIM" "$dir/${base}.$BASHPID"
}

t_case 'the header reader does not write through a pre-planted, predictable name'
_plant_symlink cors-hdr
cors_header_last "$FIX/reflect-plain.headers" 'Access-Control-Allow-Origin' || true
assert_eq "$RECORDED_SENTINEL" "$_CORS_HDR_VALUE" \
  'the reader still works'
assert_eq 'CANARY' "$(cat -- "$VICTIM")" \
  'a file behind a symlink at the pid-derived scratch name is untouched - FAILS under `$dir/cors-hdr.$BASHPID`, where scan_match truncates the attacker-chosen target (CWE-377 via CWE-59)'

t_case 'the probe does not write the response headers through a predictable name'
_new_run
SRV_MAP=( [/tmpsafe]=reflect-plain.headers )
_plant_symlink cors-resp
cors_probe cors-fixture GET 'https://cors.fixture.example/tmpsafe' || true
assert_eq reflected "$( cors_classify "$_CORS_ACAO_PRESENT" "$_CORS_ACAO"; printf '%s' "$_CORS_POLICY" )" \
  'the probe still reads the policy'
assert_eq 'CANARY' "$(cat -- "$VICTIM")" \
  'the target response headers are not deposited at a location a local user chose - FAILS under `$dir/cors-resp.$BASHPID`, where `: >"$file"` truncates through the planted symlink and the capture sink then appends the response into it'

# ===========================================================================
printf '\n== B. the classifier: four verdicts, and the three it must not confuse ==\n'
# ===========================================================================
_classify_fixture() {
  local file=$1 present=0 value=''
  if cors_header_last "$file" 'Access-Control-Allow-Origin'; then
    present=1; value=$_CORS_HDR_VALUE
  fi
  cors_classify "$present" "$value" "$CORS_SENTINEL_ORIGIN"
}

t_case 'the reflected origin classifies as reflection, never as wildcard'
_classify_fixture "$FIX/reflect-plain.headers"
assert_eq reflected "$_CORS_POLICY" 'an echoed sentinel is `reflected`'

t_case 'a literal asterisk classifies as wildcard, never as reflection'
_classify_fixture "$FIX/wildcard.headers"
assert_eq wildcard "$_CORS_POLICY" \
  '`*` is `wildcard` - FAILS under a check keying on "an ACAO header came back", which grades a public asset the same as a reflecting authenticated API'

t_case 'a static allowlisted origin is not a finding at all'
_classify_fixture "$FIX/allowlist.headers"
assert_eq allowlisted "$_CORS_POLICY" \
  'a server answering its OWN configured origin to our sentinel validated the Origin correctly - FAILS under "ACAO present means vulnerable", which is a false positive on correct configuration'

t_case 'reflection is exact equality, not a substring test'
_classify_fixture "$FIX/suffix-trap.headers"
assert_eq allowlisted "$_CORS_POLICY" \
  'a value that CONTAINS the sentinel and is not equal to it is NOT a reflection - FAILS under a substring or suffix match'

t_case 'no header at all classifies as absent'
_classify_fixture "$FIX/none.headers"
assert_eq absent "$_CORS_POLICY" 'a response with no CORS header is `absent`'

t_case 'the classifier compares against the CONFIGURED sentinel, not a hardcoded literal'
cors_classify 1 'https://somewhere.else.example' 'https://somewhere.else.example'
assert_eq reflected "$_CORS_POLICY" \
  'a caller-supplied sentinel is honoured - FAILS if the sentinel is baked into the comparison'
cors_classify 1 "$RECORDED_SENTINEL" 'https://somewhere.else.example'
assert_eq allowlisted "$_CORS_POLICY" \
  'and the shipped default is NOT special-cased when another sentinel is in force'

# ===========================================================================
printf '\n== C. the phase end to end, against recorded responses ==\n'
# ===========================================================================
# One inventory covering every verdict plus the two the probe must refuse to
# send: a POST endpoint, and a second URL on a route already probed.
_write_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e1", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/api/reflect" },
  { "id": "e2", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/api/creds" },
  { "id": "e3", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/assets/site.css" },
  { "id": "e4", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/api/allowlisted" },
  { "id": "e5", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/plain" },
  { "id": "e6", "target": "cors-fixture", "method": "POST",   "url": "https://cors.fixture.example/api/orders" },
  { "id": "e7", "target": "cors-fixture", "method": "DELETE", "url": "https://cors.fixture.example/api/session" },
  { "id": "e8", "target": "cors-fixture", "method": "HEAD",   "url": "https://cors.fixture.example/api/head" },
  { "id": "e9", "target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/orders/1" },
  { "id": "e10","target": "cors-fixture", "method": "GET",    "url": "https://cors.fixture.example/orders/2" },
  { "id": "e11","target": "other-target",  "method": "GET",   "url": "https://cors.fixture.example/api/notmine" }
] }
EOF
}

SCOURSH_DAST_TARGET=cors-fixture
SCOURSH_DAST_CELL=cors-fixture
SCOURSH_DAST_INTENSITY=passive
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
  SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS

# A phase script has no sourced-once guard and runs its phase function at source
# time (that is how dast_run_phase invokes it), so it is sourced once here
# against a throwaway run with no inventory - which is itself the first case:
# absent inventory must be a recorded gap, not an error.
_new_run
# shellcheck source=modules/dast/passive/cors.sh
source "$ROOT/modules/dast/passive/cors.sh"

t_case 'no endpoint inventory is a recorded gap, not an error and not a silent pass'
assert_eq 0 "$(_req_count)" \
  'no request is sent when the inventory is absent - FAILS if the check invents a URL from the scope base-url'
assert_contains "$(_meta_text)" 'reason=no_endpoint_inventory' \
  'the machine-readable coverage_reduction names the reason'
assert_contains "$(_meta_text)" 'not tested' \
  'and the human-readable coverage_gap says a clean result is the absence of a test'
assert_eq '' "$(_checks_run_text)" \
  'nothing is recorded in checks_run - FAILS under a reading that reports coverage for a check that never sent a probe'

_write_inventory
_new_run
SRV_MAP['/api/reflect']='reflect-plain.headers'
SRV_MAP['/api/creds']='reflect-credentials.headers'
SRV_MAP['/assets/site.css']='wildcard.headers'
SRV_MAP['/api/allowlisted']='allowlist.headers'
SRV_MAP['/plain']='none.headers'
SRV_MAP['/api/head']='reflect-lowercase.headers'
SRV_MAP['/orders/1']='none.headers'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase

t_case 'each verdict emits its own check id, on its own route'
assert_eq 1 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /api/reflect)" \
  'plain reflection emits ORIGIN_REFLECTED on /api/reflect'
assert_eq 1 "$(_count_check_path DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 /api/creds)" \
  'reflection WITH credentials emits the credentialed id on /api/creds'
assert_eq 1 "$(_count_check_path DAST-CORS-WILDCARD-01 /assets/site.css)" \
  'the wildcard emits WILDCARD on the CSS asset'

t_case 'the credentialed finding SUBSUMES the plain one - exactly one finding on that route'
assert_eq 0 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /api/creds)" \
  'no plain-reflection finding is emitted alongside the credentialed one - FAILS under "emit reflection, then separately note credentials", which reports one root cause twice and makes the CORS finding count meaningless'

t_case 'a wildcard is never reported as reflection, and reflection is never reported as a wildcard'
assert_eq 0 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /assets/site.css)" \
  'the `*` route produces no reflection finding'
assert_eq 0 "$(_count_check_path DAST-CORS-WILDCARD-01 /api/reflect)" \
  'the reflecting route produces no wildcard finding - FAILS under a shared "permissive CORS" id, which the fingerprint would then dedupe into one'

t_case 'a correctly-configured allowlist and a CORS-free route produce nothing at all'
assert_eq 0 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /api/allowlisted)" \
  'a static allowlisted origin is not a finding'
assert_eq 0 "$(_count_check_path DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 /api/allowlisted)" \
  'not even with Access-Control-Allow-Credentials: true beside it, because our origin was refused'
assert_eq 0 "$(_count_check_path DAST-CORS-WILDCARD-01 /plain)" \
  'a response with no CORS header at all is not a finding'

t_case 'an HTTP/2 (lowercase-header) reflecting response is caught'
assert_eq 1 "$(_count_check_path DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 /api/head)" \
  'the HEAD route answering lowercase field names is reported - FAILS under a case-sensitive header match, the single most likely way for this check to go quietly blind in production'

t_case 'the evidence names the observed values and the remediation is present'
SHARD=$(_shard_text)
assert_contains "$SHARD" 'Access-Control-Allow-Credentials: true' \
  'the credentialed evidence quotes the header it observed'
assert_contains "$SHARD" 'NOT origin reflection' \
  'the wildcard evidence states explicitly that it is not reflection, so a reader is not left to infer the distinction'
assert_contains "$SHARD" 'allowlist of exact origins' \
  'the remediation tells the operator what to do instead of echoing the Origin'
assert_contains "$SHARD" 'cwe=CWE-346' 'reflection maps to CWE-346 (origin validation error)'
assert_contains "$SHARD" 'cwe=CWE-942' 'the wildcard maps to CWE-942 (permissive cross-domain policy)'
assert_contains "$SHARD" 'owasp=A05:2021' 'both map to OWASP A05:2021 Security Misconfiguration'
assert_contains "$SHARD" 'loc_param_location=header' 'the location profile names the request field this check varies'
assert_contains "$SHARD" 'loc_param_name=Origin' 'and names it as Origin'

t_case 'checks_run records all three sentinel-probe ids once the probe ran, including the ones that found nothing'
CR=$(_checks_run_text)
assert_contains "$CR" 'DAST-CORS-ORIGIN_REFLECTED-01' 'the reflection id is covered'
assert_contains "$CR" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' 'the credentialed id is covered'
assert_contains "$CR" 'DAST-CORS-WILDCARD-01' 'the wildcard id is covered'

# ===========================================================================
printf '\n== C2. the null-origin follow-up (DAST-08 follow-up) ==\n'
# ===========================================================================
# A DEDICATED run and a DEDICATED, four-route inventory - never the one
# section C/D/E share - so this section's assertions cannot perturb the
# request-log counts section D pins, and so its own SRV_FAIL_ALL-free routes
# (every response here is a real 200) cannot contribute to the circuit
# breaker's cross-section failure count section E's own failure cases rely on.
#
# /api/nulltrust and /api/nulltrust-creds both answer `Access-Control-Allow-
# Origin: null` REGARDLESS of which Origin was sent - the scripted server here
# keys purely on path, exactly like a real misconfigured server that always
# emits a fixed `null` value rather than validating the Origin at all - so the
# SECOND, `Origin: null` probe observes the identical response the sentinel
# probe did, and that is precisely the case this check exists to catch: the
# sentinel probe alone classifies it `allowlisted` (a `null` value is not the
# sentinel and not `*`) and produces no finding, so only the second probe can
# tell that this server trusts the null origin specifically.
# /api/already-reflects and /assets/already-wildcard exist so this section can
# also pin, on its own isolated request log, that a route already shown to
# reflect the sentinel or to be wildcard never receives the second probe.
cat >"$W/null-inventory.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "n1", "target": "cors-fixture", "method": "GET", "url": "https://cors.fixture.example/api/nulltrust" },
  { "id": "n2", "target": "cors-fixture", "method": "GET", "url": "https://cors.fixture.example/api/nulltrust-creds" },
  { "id": "n3", "target": "cors-fixture", "method": "GET", "url": "https://cors.fixture.example/api/already-reflects" },
  { "id": "n4", "target": "cors-fixture", "method": "GET", "url": "https://cors.fixture.example/assets/already-wildcard" }
] }
EOF

_new_run
SRV_MAP['/api/nulltrust']='null.headers'
SRV_MAP['/api/nulltrust-creds']='null-credentials.headers'
SRV_MAP['/api/already-reflects']='reflect-plain.headers'
SRV_MAP['/assets/already-wildcard']='wildcard.headers'
SCOURSH_DAST_ENDPOINTS=$W/null-inventory.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase

t_case 'a server that answers null classifies as allowlisted to the sentinel probe alone (the gap this ticket closes)'
assert_eq 0 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /api/nulltrust)" \
  'the sentinel-reflection id never fires on a null answer'
assert_eq 0 "$(_count_check_path DAST-CORS-WILDCARD-01 /api/nulltrust)" \
  'neither does the wildcard id'

t_case 'the second, Origin: null probe catches what the sentinel probe alone cannot'
assert_eq 1 "$(_count_check_path DAST-CORS-NULL_ORIGIN-01 /api/nulltrust)" \
  'null-origin trust is reported on /api/nulltrust - FAILS if the follow-up probe is never sent, which is the exact gap this ticket exists to close'
assert_eq 1 "$(_count_check_path DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01 /api/nulltrust-creds)" \
  'and the credentialed variant fires on /api/nulltrust-creds, whose response also carries Access-Control-Allow-Credentials: true'

t_case 'the credentialed null-origin finding SUBSUMES the plain one - exactly one finding on that route'
assert_eq 0 "$(_count_check_path DAST-CORS-NULL_ORIGIN-01 /api/nulltrust-creds)" \
  'no plain null-origin finding is emitted alongside the credentialed one - FAILS under "emit the plain finding, then separately note credentials", which reports one root cause twice, mirroring DAST-CORS-REFLECTED_WITH_CREDENTIALS-01s own discipline'
assert_eq 0 "$(_count_check_path DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01 /api/nulltrust)" \
  'and the credentialed id never fires on the route whose response carried no credentials header'

t_case 'a route already known to reflect or to be wildcard never receives the second probe'
LOG_C2=$(_req_log_text)
N_REFLECT=0
N_WILDCARD=0
N_NULL_HEADER=0
while IFS= read -r line; do
  [[ $line == *$'\t'/api/already-reflects$'\t'* ]] && N_REFLECT=$(( N_REFLECT + 1 ))
  [[ $line == *$'\t'/assets/already-wildcard$'\t'* ]] && N_WILDCARD=$(( N_WILDCARD + 1 ))
  [[ $line == *origin=null* ]] && N_NULL_HEADER=$(( N_NULL_HEADER + 1 ))
done <<<"$LOG_C2"
assert_eq 1 "$N_REFLECT" \
  'exactly one request reached /api/already-reflects - FAILS if a second, redundant Origin: null probe is sent to a route already shown to reflect an arbitrary sentinel, which is pure cost for no new information'
assert_eq 1 "$N_WILDCARD" \
  'exactly one request reached the wildcard route, for the identical reason'
assert_eq 2 "$N_NULL_HEADER" \
  'exactly two Origin: null probes were sent in this run - one for /api/nulltrust, one for /api/nulltrust-creds - never four routes worth, confirming the reflect/wildcard routes above really were skipped rather than merely under-counted'
assert_eq 6 "$(_req_count)" \
  'four routes, two of which (the reflecting one and the wildcard one) cost one request and two of which (the two null-trust routes) cost two - six requests total'

t_case 'the evidence for a null-origin finding names the attacker-controlled contexts and the remediation'
SHARD_NULL=$(_shard_text)
assert_contains "$SHARD_NULL" 'sandboxed iframe' \
  'the evidence names the sandboxed-iframe vector, so a reader is not left to guess where Origin: null comes from'
assert_contains "$SHARD_NULL" 'DAST-CORS-NULL_ORIGIN' 'the null-origin check id reached the shard'

t_case 'the null-origin checks_run ids are covered once the second probe actually ran'
CR2=$(_checks_run_text)
assert_contains "$CR2" 'DAST-CORS-NULL_ORIGIN-01' 'the plain null-origin id is covered'
assert_contains "$CR2" 'DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01' 'the credentialed null-origin id is covered too'

# ===========================================================================
printf '\n== D. the passive contract, asserted against the REQUEST LOG ==\n'
# ===========================================================================
# Section C2 above ran its OWN dedicated `_new_run`, which reset REQ_LOG - so
# re-run section C's inventory+probe one more time on a fresh run (SRV_MAP set
# AFTER `_new_run`, which clears it) so this section's counts are independent
# of whatever C2 just logged.
_new_run
SRV_MAP['/api/reflect']='reflect-plain.headers'
SRV_MAP['/api/creds']='reflect-credentials.headers'
SRV_MAP['/assets/site.css']='wildcard.headers'
SRV_MAP['/api/allowlisted']='allowlist.headers'
SRV_MAP['/plain']='none.headers'
SRV_MAP['/api/head']='reflect-lowercase.headers'
SRV_MAP['/orders/1']='none.headers'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
LOG=$(_req_log_text)

t_case 'no non-idempotent endpoint is requested, under any method'
assert_not_contains "$LOG" '/api/orders' \
  'the POST endpoint is never requested - FAILS under a check that downgrades a POST route to a GET to read its headers, which is content discovery at the safe-active tier, not a passive read'
assert_not_contains "$LOG" '/api/session' \
  'the DELETE endpoint is never requested'
assert_not_contains "$LOG" $'POST\t' 'no POST is ever sent'
assert_not_contains "$LOG" $'DELETE\t' 'no DELETE is ever sent'

t_case 'an endpoint belonging to a different scope target is not probed'
assert_not_contains "$LOG" '/api/notmine' \
  "an inventory row whose target is not this run's target is skipped - FAILS if the target field is ignored, which would probe another operator's target from this run's budget"

t_case 'the sentinel origin is a header VALUE and is never a request destination'
assert_contains "$LOG" "origin=$CORS_SENTINEL_ORIGIN" \
  'the Origin header really was attached - without this the whole check is inert and every other assertion here would still pass'
assert_not_contains "$LOG" $'\tscoursh-cors-probe.example\t' \
  'no request is addressed to the sentinel host - FAILS if a future change ever treats the sentinel as a URL rather than a header value'

t_case 'the second probe really carries the literal null origin, and nothing else'
assert_contains "$LOG" 'origin=null' \
  'a follow-up probe with Origin: null really was sent for at least one route - without this, section C2 above would be passing for the wrong reason (the second probe never firing at all)'

t_case 'no request body is sent and no response body is captured'
assert_not_contains "$LOG" 'has_body=true' \
  'no request carries a body - FAILS if a probe ever composes one'
assert_not_contains "$LOG" 'body_sink=yes' \
  'no response body sink is set, so target content never enters this process or an artifact - FAILS under a copy of a probe that captures the body it does not read'

t_case 'two URLs on one route are two probes (sentinel + null), never four'
ORDERS=0
while IFS= read -r line; do
  [[ $line == *$'\t'/orders/* ]] && ORDERS=$(( ORDERS + 1 ))
done <<<"$LOG"
assert_eq 2 "$ORDERS" \
  '/orders/1 and /orders/2 are one route, probed twice in total (the sentinel probe, plus the null-origin follow-up since the route answered no CORS header at all) - FAILS under per-URL dedup, which would pay for a second URL to learn an answer already held (and quadruple to four once the null follow-up is added), and FAILS under a reading that forgets a route can now cost two requests, which would expect one'
assert_not_contains "$LOG" '/orders/2' \
  'and neither of those two requests is ever addressed to the second URL on that route'

t_case 'exactly one or two requests per probed route, and the total reflects the null-probe follow-up'
assert_eq 10 "$(_req_count)" \
  'seven distinct idempotent routes yield ten requests: one sentinel probe each, plus a second Origin: null probe on every route whose sentinel verdict was neither reflected nor wildcard (allowlisted, plain/absent, and the merged orders route/absent - three of the seven) - FAILS at 7 if the null-origin follow-up never fires, and FAILS at 14 if it fires unconditionally on every route including the four that already reflect or are wildcard'

# ===========================================================================
printf '\n== E. bounds and failure paths ==\n'
# ===========================================================================
t_case 'the per-run route cap truncates and RECORDS the bound'
_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
SCOURSH_DAST_CORS_MAX_ENDPOINTS=2 _dast_cors_phase
assert_eq 4 "$(_req_count)" \
  'the cap bounds ROUTES, not requests: two capped routes, each answering no CORS header at all, so each also draws its null-origin follow-up - four requests total, never more - FAILS if the cap is only applied to the findings (which would send every request anyway), and FAILS at 2 if the cap were mistaken for a request cap that forgot a route can now cost two'
assert_contains "$(_meta_text)" 'coverage bound, not a clean result' \
  'the untested remainder is recorded as a bound - FAILS under a silent cap, which reports a partially-probed target with the same verdict as a fully-probed one'

t_case 'a transport failure is counted as untested, never as "no CORS header"'
_new_run
SRV_MAP['/api/reflect']='reflect-plain.headers'
SRV_FAIL_PATH=/api/creds
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_eq 0 "$(_count_check_path DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 /api/creds)" \
  'the failed route produces no finding'
assert_contains "$(_meta_text)" 'reason=cors_probe_transport_failed' \
  'and its absence is RECORDED - FAILS under a reading that treats a failed request as a response with no CORS header, which reports a breaker-opened run as a clean target'
assert_eq 1 "$(_count_check_path DAST-CORS-ORIGIN_REFLECTED-01 /api/reflect)" \
  'the routes that did answer are still reported, so one failure does not abandon the check'

t_case 'a target with NO CORS headers anywhere is still covered, and emits nothing'
_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_eq 0 "$(_count_check DAST-CORS-ORIGIN_REFLECTED-01)" 'no reflection finding'
assert_eq 0 "$(_count_check DAST-CORS-REFLECTED_WITH_CREDENTIALS-01)" 'no credentialed finding'
assert_eq 0 "$(_count_check DAST-CORS-WILDCARD-01)" 'no wildcard finding'
assert_eq 0 "$(_count_check DAST-CORS-NULL_ORIGIN-01)" \
  'no null-origin finding either - every route answered no CORS header at all, including to the null-origin follow-up'
assert_eq 0 "$(_count_check DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01)" 'and no credentialed null-origin finding'
CLEAN_CR=$(_checks_run_text)
assert_contains "$CLEAN_CR" 'DAST-CORS-ORIGIN_REFLECTED-01' \
  'all five ids are still recorded in checks_run - FAILS under a reading that records only the ids that FIRED, which makes coverage a function of the result and leaves a genuinely clean target indistinguishable from an unscanned one'
assert_contains "$CLEAN_CR" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' \
  'including the credentialed id, which one response answers at the same time as the plain one'
assert_contains "$CLEAN_CR" 'DAST-CORS-WILDCARD-01' 'and the wildcard id'
assert_contains "$CLEAN_CR" 'DAST-CORS-NULL_ORIGIN-01' \
  'and the null-origin id - the follow-up probe genuinely ran on every route, since none of them reflected or were wildcard, so it is covered even though it found nothing'
assert_contains "$CLEAN_CR" 'DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01' 'and its credentialed sibling too'

t_case 'a run whose every probe fails covers NOTHING'
_new_run
SRV_FAIL_ALL=1
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_eq '' "$(_checks_run_text)" \
  'no check id is recorded as covered when not one probe got a response - FAILS under a reading that counts an attempted request as a tested route, which would let a run that reached nothing report the same coverage as one that reached everything'
assert_contains "$(_meta_text)" 'Nothing was tested; this is not a finding of safety.' \
  'and the run says so in the report the operator reads'

t_case 'an inventory with no idempotent endpoint is a recorded gap'
cat >"$W/post-only.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "p1", "target": "cors-fixture", "method": "POST", "url": "https://cors.fixture.example/api/orders" }
] }
EOF
_new_run
SCOURSH_DAST_ENDPOINTS=$W/post-only.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_eq 0 "$(_req_count)" 'nothing is sent'
assert_contains "$(_meta_text)" 'reason=no_endpoint_inventory' \
  'a POST-only surface is reported as untestable by this check rather than as clean'
assert_eq '' "$(_checks_run_text)" \
  'and no check is recorded as covered'

t_case 'a wildcard beside credentials stays the wildcard finding, with the pairing explained'
_new_run
SRV_MAP['/assets/site.css']='wildcard-credentials.headers'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_eq 1 "$(_count_check_path DAST-CORS-WILDCARD-01 /assets/site.css)" \
  'it is still one wildcard finding'
assert_eq 0 "$(_count_check_path DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 /assets/site.css)" \
  'and NOT the credentialed reflection finding - FAILS under a check that keys the high-severity id on "credentials are allowed" alone, when a browser refuses to honour `*` with credentials at all'
assert_contains "$(_shard_text)" 'refuses to honour' \
  'the evidence explains why the pair is broken rather than exploitable, so the low severity is defensible to a reader'

t_case 'the unauthenticated-probe bound is recorded only when a session actually exists'
_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
assert_not_contains "$(_meta_text)" 'reason=cors_probe_is_unauthenticated' \
  'a run with no --authed does NOT record it - FAILS under an unconditional record, which puts a line about a session that was never asked for into every passive run and buries the records that are about a real reduction'

_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
# Stand in for auth.sh having run: the phase consults it through the same
# `declare -F` guard modules/dast/active/sqli.sh uses, so a stub is exactly what
# a real authenticated run presents to it.
#
# SC2329 says this function is never invoked, which is true of this FILE and is
# the whole point: the code under test discovers it with `declare -F` and calls
# it by name, which is a call site no static reader can see.  Silenced with a
# reason per AGENTS.md rather than left to the checker version.
# shellcheck disable=SC2329
dast_auth_authenticated_labels_set() { _DAST_AUTH_AUTHED_LABELS=(alice); }
SCOURSH_DAST_AUTHED=true _dast_cors_phase
unset -f dast_auth_authenticated_labels_set
assert_contains "$(_meta_text)" 'reason=cors_probe_is_unauthenticated' \
  'a run that HOLDS a session is told its CORS probe did not use it - FAILS if the bound is never recorded, which lets an --authed run report a target clean for an authenticated-only CORS policy it never asked for'
assert_contains "$(_meta_text)" 'is not evidence its authenticated responses are safe' \
  'and the sentence states the consequence, not just the fact'

t_case 'the phase is a no-op when every CORS check id is deselected'
_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
dast_check_selected() { return 1; }
_dast_cors_phase
unset -f dast_check_selected
assert_eq 0 "$(_req_count)" \
  'a deselected check sends no traffic - FAILS if selection is applied only at emission, which pays the full request cost for findings that are then thrown away'
assert_contains "$(_meta_text)" 'reason=all_cors_checks_deselected' \
  'and the reason is recorded'

# ===========================================================================
printf '\n== F. a full round trip through every report format ==\n'
# ===========================================================================
# A finding that never survives the merge, or that breaks an emitter, is a
# finding nobody reads.  This is the same round-trip proof tests/suites/sca.sh
# and tests/suites/sast-gitleaks.sh already make for their own modules, and it
# matters more than usual here because this check's evidence deliberately
# contains a literal asterisk and backticked header names - exactly the
# characters an HTML or Markdown emitter mishandles (docs/FOUNDATION.md tension
# 10: evidence is untrusted target output and is escaped per emitter).
t_case 'the findings survive findings_merge and reach every report surface'
_new_run
SRV_MAP['/api/creds']='reflect-credentials.headers'
SRV_MAP['/assets/site.css']='wildcard.headers'
SRV_MAP['/plain']='null.headers'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
findings_merge "$SCOURSH_RUN_DIR"
derive_findings "$SCOURSH_RUN_DIR"
SCOURSH_FORMATS='json,md,html' report_all "$SCOURSH_RUN_DIR"

RJ=$(cat "$SCOURSH_RUN_DIR/run.json")
assert_contains "$RJ" '"dast"' 'run.json attributes the findings to the dast module'
assert_contains "$RJ" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' \
  'run.json records the credentialed check as run - FAILS if checks_run never leaves the phase process'

FJ=$(cat "$SCOURSH_RUN_DIR/findings.json" 2>/dev/null || printf '')
assert_contains "$FJ" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' 'the JSON report carries the credentialed finding'
assert_contains "$FJ" 'DAST-CORS-WILDCARD-01' 'and the wildcard finding - FAILS if two findings on one target collide on the fingerprint and dedupe to one'
assert_contains "$FJ" 'DAST-CORS-NULL_ORIGIN-01' \
  'and the null-origin finding too - FAILS if it collides with one of the other three on the same location profile and dedupes away'

MD=$(cat "$SCOURSH_RUN_DIR/report.md")
assert_contains "$MD" 'CORS origin reflection with credentials allowed' 'the markdown report names the finding in prose a human reads'
assert_contains "$MD" 'allowlist of exact origins' 'and carries the remediation'

HT=$(cat "$SCOURSH_RUN_DIR/report.html")
assert_contains "$HT" 'DAST-CORS-WILDCARD-01' 'the HTML report carries the finding'
assert_not_contains "$HT" '<script' \
  'and contains no script element at all, with this check evidence in it - docs/FOUNDATION.md tension 10'

# ===========================================================================
printf '\n== G. redirect-across-origin (ticket aa50f056-9b18-4fc7-9416-bb455bc7b7b1 follow-up) ==\n'
# ===========================================================================
# `cors_probe` sends every probe with `max_redirects` 0 (passive property 5),
# so a 3xx response is ALWAYS returned as-is and never followed - unlike
# markup.sh and leakage.sh, this check structurally cannot land on a different
# origin.  This section proves both halves of that: the cross-origin
# `Location` is never dialed (the request log), AND the finding's own `url`
# field is the DELIVERED response's canonical form (cors_engine.sh's
# `_CORS_LAST_URL`) rather than the raw inventory literal - which for THIS
# check happens to be the requested url's own canonical form (default port
# filled in), since no redirect is ever followed to change it.
cat >"$W/redirect-endpoints.json" <<'EOF'
{ "endpoints": [
  { "id": "r1", "target": "cors-fixture", "method": "GET", "url": "https://cors.fixture.example/redirect-cross" }
] }
EOF

t_case 'a cross-origin Location is never followed and never dialed'
_new_run
SRV_REDIRECT_PATH='/redirect-cross'
SRV_REDIRECT_LOCATION='https://cors-redirect-landing.example/elsewhere'
SRV_MAP['/redirect-cross']='redirect-reflect.headers'
SCOURSH_DAST_ENDPOINTS=$W/redirect-endpoints.json
export SCOURSH_DAST_ENDPOINTS
_dast_cors_phase
LOG=$(_req_log_text)
assert_not_contains "$LOG" 'cors-redirect-landing.example' \
  'the Location host is never dialed - FAILS under a probe that follows redirects, which would send a second request this check must never send'
assert_contains "$LOG" $'GET\tcors.fixture.example\t/redirect-cross' \
  'only the originally-requested host and path were ever requested'

t_case "the finding's url field is the delivered (canonical) url, never the raw inventory literal, and never the Location's origin"
assert_eq 1 "$(_count_check DAST-CORS-ORIGIN_REFLECTED-01)" \
  'the 3xx response itself reflects the sentinel, so the check has a finding to locate'
URL=$(_field_of DAST-CORS-ORIGIN_REFLECTED-01 url)
assert_eq 'https://cors.fixture.example:443/redirect-cross' "$URL" \
  "the url field is cors_probe's own _CORS_LAST_URL (lib/http.sh's _HTTP_LAST_URL), the DELIVERED response's canonical form with the default port filled in - FAILS under the raw inventory literal 'https://cors.fixture.example/redirect-cross' (no port), the reading this ticket replaces"
assert_ne 'https://cors-redirect-landing.example/elsewhere' "$URL" \
  "and it is emphatically NOT the Location this check correctly never followed - FAILS under any implementation that treats a 3xx's Location as the delivered url instead of the url that was actually requested"

t_summary dast-cors
