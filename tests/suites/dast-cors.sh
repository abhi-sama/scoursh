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
# how the "a failure is not a clean result" case is driven.
REQ_LOG=$W/requests.log
declare -A SRV_MAP=()
SRV_FAIL_PATH=''
SRV_FAIL_ALL=0

_srv_reset() {
  SRV_MAP=()
  SRV_FAIL_PATH=''
  SRV_FAIL_ALL=0
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

t_case 'checks_run records all three ids once the probe ran, including the ones that found nothing'
CR=$(_checks_run_text)
assert_contains "$CR" 'DAST-CORS-ORIGIN_REFLECTED-01' 'the reflection id is covered'
assert_contains "$CR" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' 'the credentialed id is covered'
assert_contains "$CR" 'DAST-CORS-WILDCARD-01' 'the wildcard id is covered'

# ===========================================================================
printf '\n== D. the passive contract, asserted against the REQUEST LOG ==\n'
# ===========================================================================
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

t_case 'no request body is sent and no response body is captured'
assert_not_contains "$LOG" 'has_body=true' \
  'no request carries a body - FAILS if a probe ever composes one'
assert_not_contains "$LOG" 'body_sink=yes' \
  'no response body sink is set, so target content never enters this process or an artifact - FAILS under a copy of a probe that captures the body it does not read'

t_case 'two URLs on one route are one probe, not two'
ORDERS=0
while IFS= read -r line; do
  [[ $line == *$'\t'/orders/* ]] && ORDERS=$(( ORDERS + 1 ))
done <<<"$LOG"
assert_eq 1 "$ORDERS" \
  '/orders/1 and /orders/2 are one route and are probed once - FAILS under per-URL dedup, which pays for a second request to learn an answer already held and then dedupes the two findings anyway'

t_case 'exactly one request per probed route'
assert_eq 7 "$(_req_count)" \
  'seven distinct idempotent routes yield exactly seven requests - FAILS if a preflight OPTIONS is sent alongside each probe (14), or if anything is retried'

# ===========================================================================
printf '\n== E. bounds and failure paths ==\n'
# ===========================================================================
t_case 'the per-run route cap truncates and RECORDS the bound'
_new_run
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
export SCOURSH_DAST_ENDPOINTS
SCOURSH_DAST_CORS_MAX_ENDPOINTS=2 _dast_cors_phase
assert_eq 2 "$(_req_count)" \
  'the cap really bounds the traffic - FAILS if the cap is only applied to the findings, which would send every request anyway'
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
CLEAN_CR=$(_checks_run_text)
assert_contains "$CLEAN_CR" 'DAST-CORS-ORIGIN_REFLECTED-01' \
  'all three ids are still recorded in checks_run - FAILS under a reading that records only the ids that FIRED, which makes coverage a function of the result and leaves a genuinely clean target indistinguishable from an unscanned one'
assert_contains "$CLEAN_CR" 'DAST-CORS-REFLECTED_WITH_CREDENTIALS-01' \
  'including the credentialed id, which one response answers at the same time as the plain one'
assert_contains "$CLEAN_CR" 'DAST-CORS-WILDCARD-01' 'and the wildcard id'

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

MD=$(cat "$SCOURSH_RUN_DIR/report.md")
assert_contains "$MD" 'CORS origin reflection with credentials allowed' 'the markdown report names the finding in prose a human reads'
assert_contains "$MD" 'allowlist of exact origins' 'and carries the remediation'

HT=$(cat "$SCOURSH_RUN_DIR/report.html")
assert_contains "$HT" 'DAST-CORS-WILDCARD-01' 'the HTML report carries the finding'
assert_not_contains "$HT" '<script' \
  'and contains no script element at all, with this check evidence in it - docs/FOUNDATION.md tension 10'

t_summary dast-cors
