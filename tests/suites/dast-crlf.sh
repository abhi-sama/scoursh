#!/usr/bin/env bash
# tests/suites/dast-crlf.sh - modules/dast/active/crlf.sh: the §7.3 CRLF /
# header-injection probe (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md
# DAST-23, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and every response is a
# RECORDED one composed by the mock below (docs/DESIGN.md §12: "DAST logic is
# testable with no live target"). The mock reproduces, at the STRING level,
# how a real transport (curl) locates the header/body boundary - the first
# CRLFCRLF - so this suite proves crlf.sh's detection against a byte-accurate
# simulation of what a vulnerable server would really put on the wire, not
# against a canned verdict.
#
# Each case that pins a decision NAMES THE READING IT FAILS UNDER, per this
# repository's testing rule - a test that passes under both the correct and
# the rejected reading pins nothing and is worse than no test.
#
#   1. the signal is a per-run RANDOM marker actually parsed as a response
#      header (or found at the front of the body), never a body-text
#      substring match - a value merely reflected into an error page is not
#      a finding.
#   2. a `header`-location parameter is NEVER sent a CR/LF-carrying value -
#      FAILS by aborting the whole scan (http_request_header's own refusal)
#      under a probe that does not exclude it.
#   3. response splitting (a full second status line PLUS a body sentinel
#      landing at the true front of the body) is a stronger, separate check
#      id from bare header injection, and the two are mutually exclusive per
#      parameter - never both, never neither when one confirmed.
#   4. a normalising/escaping endpoint that merges the injected CRLF back
#      into one header line is NOT flagged.
#   5. a value reflected only into the BODY (never into a header) is NOT
#      flagged, however exactly it echoes the payload back.
#   6. missing payloads / no parameter inventory / graphql-only surface each
#      degrade to a recorded coverage gap, never a clean-looking result and
#      never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter and header syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut: modules/dast/active/inject_engine.sh is already inlined
# elsewhere in this file's own source graph, and shellcheck re-expands EVERY
# source edge it follows. Cutting this one loses no checking and is what keeps
# the linter's memory bounded - see the shellcheck stage in tests/run-tests.sh,
# and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/headers_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-crlf-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
HOSTNAME_FIXTURE=crlf.fixture.example
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: crlf-fixture
base-url: https://crlf.fixture.example/
notes: Fixture target for tests/suites/dast-crlf.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

# The resolver answers for the fixture host and NOTHING else.
_crlf_resolve() { case $1 in crlf.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_crlf_resolve

# ---------------------------------------------------------------------------
# Percent-decoding, so the mock decides on the value the "application" sees.
# ---------------------------------------------------------------------------
# inject_engine.sh percent-encodes the payload before sending it, exactly as a
# real client would; the mock therefore decodes it rather than matching
# encoded bytes, which would make every assertion below a statement about
# inject_urlencode instead of about the probe.
_pctdec() {
  local s=$1 out='' i c hx
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    if [[ $c == '%' && ${s:i+1:2} =~ ^[0-9A-Fa-f]{2}$ ]]; then
      hx=${s:i+1:2}
      printf -v c '\\x%s' "$hx"
      printf -v c '%b' "$c"
      out+=$c
      i=$(( i + 2 ))
    elif [[ $c == '+' ]]; then
      out+=' '
    else
      out+=$c
    fi
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# Every endpoint below models ONE server-side behaviour that really exists in
# the wild. The mock composes the FULL raw response text with the decoded
# value inserted exactly where a real vulnerable handler would put it, then
# locates the header/body boundary itself by finding the first CRLFCRLF - the
# same thing curl does - and splits the capture files there. This is what
# lets a response-splitting payload actually MOVE that boundary in the mock,
# exactly as it would against a real server.
#
#   /vuln         q  VULNERABLE: the decoded value is concatenated, raw, into
#                     a Set-Cookie header value with no escaping at all.
#   /vulnpartial  q  VULNERABLE but NORMALISES a literal blank line back to a
#                     single space (a WAF/normaliser that blocks a full CRLF
#                     CRLF but not a bare CRLF) - the bare extra header still
#                     survives, but a full second response does not.
#   /safe         q  SAFE: strips CR and LF from the value before use.
#   /reflect      q  SAFE: echoes the raw value into the BODY only, never
#                     into a header.
#   /form         q  Same as /vuln, but the parameter arrives in the body
#                     (formData location) rather than the query string.
#   /cookie       q  Same as /vuln, but the parameter arrives as a Cookie
#                     request header (cookie location) rather than the query
#                     string; the mock reads it back out of the OUTBOUND
#                     Cookie header this scanner itself sent.
#   /path/{q}     q  Same as /vuln, but the parameter is a path segment.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

_crlf_transport() {
  local method=$1 host=$3 path=$5
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local body=${_HTTP_TX_BODY:-}
  local p=${path%%\?*}
  local qs=${path#*\?}
  [[ $qs == "$path" ]] && qs=''
  local v=''

  if [[ $p == /cookie ]]; then
    local h pair
    for h in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
      [[ $h == Cookie:\ * ]] || continue
      local cookiestr=${h#Cookie: }
      local -a pairs=()
      IFS=';' read -ra pairs <<<"$cookiestr"
      for pair in "${pairs[@]}"; do
        pair=${pair# }
        [[ $pair == q=* ]] && v=$(_pctdec "${pair#q=}")
      done
    done
  elif [[ $p == /form ]]; then
    v=${body#*=}
    v=${v%%&*}
    v=$(_pctdec "$v")
  elif [[ $p == /path/* ]]; then
    v=$(_pctdec "${p#/path/}")
    p=/path
  else
    v=${qs#*=}
    v=${v%%&*}
    v=$(_pctdec "$v")
  fi

  printf '%s %s %s\n' "$method" "$host" "$p" >>"$REQ_LOG"

  local raw=''
  case $p in
    /vuln | /form | /cookie | /path)
      raw="HTTP/1.1 200 OK"$'\r\n'"Content-Type: text/html"$'\r\n'"Set-Cookie: session=$v"$'\r\n\r\n'"ok" ;;
    /vulnpartial)
      local vv=${v//$'\r\n\r\n'/ }
      raw="HTTP/1.1 200 OK"$'\r\n'"Content-Type: text/html"$'\r\n'"Set-Cookie: session=$vv"$'\r\n\r\n'"ok" ;;
    /safe)
      local vs=${v//$'\r'/}; vs=${vs//$'\n'/}
      raw="HTTP/1.1 200 OK"$'\r\n'"Content-Type: text/html"$'\r\n'"Set-Cookie: session=$vs"$'\r\n\r\n'"ok" ;;
    /reflect)
      raw="HTTP/1.1 200 OK"$'\r\n'"Content-Type: text/html"$'\r\n\r\n'"<html>you sent: $v</html>" ;;
    *)
      raw="HTTP/1.1 404 Not Found"$'\r\n'"Content-Type: text/html"$'\r\n\r\n'"nope" ;;
  esac

  # Locate the FIRST CRLFCRLF, exactly as curl locates the header/body
  # boundary - so an injected blank line really does move it here, the same
  # as it would against a real transport.
  local sep=$'\r\n\r\n' headers_part=$raw body_part=''
  if [[ $raw == *"$sep"* ]]; then
    headers_part=${raw%%"$sep"*}
    body_part=${raw#*"$sep"}
  fi

  [[ -n $hdrsout ]] && printf '%s' "$headers_part" >>"$hdrsout"
  [[ -n $bodyout ]] && printf '%s' "$body_part" >"$bodyout"

  printf '%s\n%s\n%s\n' 200 '' 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_crlf_transport

# ---------------------------------------------------------------------------
# Inventory (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_vuln",        "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/vuln",        "path": "/vuln" },
  { "id": "e_vulnpartial", "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/vulnpartial", "path": "/vulnpartial" },
  { "id": "e_safe",        "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/safe",        "path": "/safe" },
  { "id": "e_reflect",     "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/reflect",     "path": "/reflect" },
  { "id": "e_form",        "target": "crlf-fixture", "method": "POST", "url": "https://crlf.fixture.example/form",       "path": "/form" },
  { "id": "e_cookie",      "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/cookie",     "path": "/cookie" },
  { "id": "e_path",        "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/path/{q}",   "path": "/path/{q}" },
  { "id": "e_hdrloc",      "target": "crlf-fixture", "method": "GET",  "url": "https://crlf.fixture.example/hdrloc",     "path": "/hdrloc" },
  { "id": "e_gql",         "target": "crlf-fixture", "method": "POST", "url": "https://crlf.fixture.example/graphql",    "path": "/graphql" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "e_vuln",        "target": "crlf-fixture", "name": "q", "location": "query",    "example": "hello" },
  { "id": "p2", "endpoint_id": "e_vulnpartial", "target": "crlf-fixture", "name": "q", "location": "query",    "example": "hello" },
  { "id": "p3", "endpoint_id": "e_safe",        "target": "crlf-fixture", "name": "q", "location": "query",    "example": "hello" },
  { "id": "p4", "endpoint_id": "e_reflect",     "target": "crlf-fixture", "name": "q", "location": "query",    "example": "hello" },
  { "id": "p5", "endpoint_id": "e_form",        "target": "crlf-fixture", "name": "q", "location": "formData", "example": "hello" },
  { "id": "p6", "endpoint_id": "e_cookie",      "target": "crlf-fixture", "name": "q", "location": "cookie",   "example": "hello" },
  { "id": "p7", "endpoint_id": "e_path",        "target": "crlf-fixture", "name": "q", "location": "path",     "example": "hello" },
  { "id": "p8", "endpoint_id": "e_hdrloc",      "target": "crlf-fixture", "name": "q", "location": "header",   "example": "hello" },
  { "id": "p9", "endpoint_id": "e_gql",         "target": "crlf-fixture", "name": "q", "location": "graphql",  "example": "hello" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and shard readers (the shape tests/suites/
# dast-openredirect.sh established: one finding per line, fields
# TAB-delimited as `key=value`).
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target crlf-fixture
  occurrence_reset_all
  _req_reset
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

_count_finding() {
  local check=$1 param=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_param_name=$param" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

_count_endpoint_finding() {
  local check=$1 pathtmpl=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_path_template=$pathtmpl" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Load the phase's functions. A phase script has no sourced-once guard and
# runs its phase function at source time (that is how dast_run_phase invokes
# it), so it is sourced once here against a throwaway run with no inventory -
# a harmless no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=crlf-fixture
SCOURSH_DAST_CELL=crlf-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/crlf.sh
source "$ROOT/modules/dast/active/crlf.sh"

# ===========================================================================
printf '== dast crlf: the marker is fresh per run, and the detectors are pure ==\n'
# ===========================================================================
_crlf_marker_set; M1=$_CRLF_MARKER_NAME; B1=$_CRLF_MARKER_BODY
_crlf_marker_set; M2=$_CRLF_MARKER_NAME; B2=$_CRLF_MARKER_BODY
if [[ $M1 == "$M2" ]]; then
  _t_no 'marker randomness' 'two markers in one process must differ'
else
  _t_ok 'the marker header name is fresh per call - FAILS under a constant, which would let an unrelated header supply the proof this probe reads as its own'
fi
assert_ne "$B1" "$B2" 'the body sentinel is likewise fresh per call'
assert_ne "$M1" "$B1" 'the header-name marker and the body sentinel are two distinct strings, never the same one'

_crlf_marker_set
F=$SCOURSH_SCRATCH/crlf-unit-test.hdrs
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n%s: 1\r\n' "$_CRLF_MARKER_NAME" >"$F"
BLOB=$(cat "$F")
if _crlf_header_present_in "$BLOB"; then
  _t_ok 'a genuine extra header line parses as present - FAILS if the reader only ever matched a fixed name'
else
  _t_no 'header present' 'the marker header line must be recognised'
fi
if _crlf_header_present_in "<html>x-scoursh-crlf-anything: 1 mentioned in prose</html>"; then
  _t_no 'header present false positive' 'body TEXT mentioning a header-shaped string is not a response header'
else
  _t_ok 'text that merely LOOKS like a header line, with no status line before it, is not read as one - FAILS under a substring match that never parses the header block at all'
fi
rm -f "$F"

if _crlf_body_split "${_CRLF_MARKER_BODY}"$'\r\n'"more real content"; then
  _t_ok 'the sentinel at the exact front of the body is a split - the base case'
else
  _t_no 'body split base case' 'an exact-prefix sentinel must be detected'
fi
if _crlf_body_split $'\r\n'"${_CRLF_MARKER_BODY}"; then
  _t_ok 'the sentinel after ONE leading CRLF is still a split - transports differ by a byte or two of leading whitespace at the boundary'
else
  _t_no 'body split leading whitespace' 'a leading CRLF before the sentinel must not defeat the match'
fi
if _crlf_body_split "<html>the sentinel ${_CRLF_MARKER_BODY} appears mid-page</html>"; then
  _t_no 'body split false positive' 'a sentinel appearing MID-BODY (an ordinary reflection) is not a split'
else
  _t_ok 'the sentinel merely present somewhere in the body is NOT a split - FAILS under an anywhere-in-body substring test, which a plain reflected-error page would also satisfy'
fi

# ===========================================================================
printf '== dast crlf: the probe fires on a real header-splitting endpoint ==\n'
# ===========================================================================
SCOURSH_DAST_INTENSITY=active
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_INTENSITY SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
unset SCOURSH_SELECTED_CHECKS

_write_inventory
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
STDERR=$W/main.stderr
_dast_crlf_phase 2>"$STDERR"

assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /vuln)" \
  'an endpoint that echoes the value raw into a header, with NO normalisation, escalates all the way to a confirmed full response split'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /vuln)" \
  'the SAME parameter does NOT also report the weaker header-injection id - FAILS under two independent sinks reported together (the openredirect shape), which is wrong here: this is one root cause observed at two possible strengths, not two sinks'
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /vulnpartial)" \
  'an endpoint that blocks a full blank line but not a bare CRLF still shows the bare extra header - FAILS if escalating on a normalising endpoint were allowed to suppress the still-real bare finding'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /vulnpartial)" \
  'and it does NOT escalate to a full split there - FAILS if the body-prefix check were satisfied by anything less than the boundary actually moving'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /safe)" \
  'an endpoint that strips CR/LF before use is NOT flagged - FAILS under a substring test that ignores whether the bytes actually split a header'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /safe)" \
  'nor does the safe endpoint report a split'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /reflect)" \
  'an endpoint that reflects the raw value into the BODY ONLY is NOT flagged - the marker never reaches a real response header, however exactly the body echoes it back'
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /form)" \
  'a formData-location parameter is probed and confirmed - FAILS if only query strings were injected'
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /cookie)" \
  'a cookie-location parameter is probed via the outbound Cookie header and confirmed - FAILS if cookie-location parameters were skipped'
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 '/path/{q}')" \
  'a path-segment-location parameter (with a template slot) is probed and confirmed'

# ===========================================================================
printf '== dast crlf: a header-location parameter is NEVER sent a raw CR/LF ==\n'
# ===========================================================================
# This is the safety property this probe rests on: http_request_header dies
# the WHOLE PROCESS on an embedded CR/LF (request smuggling against this
# scanner's own outbound request), so the phase itself must never reach
# inject_send for a header-location candidate with this probe's payload.
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /hdrloc)" \
  'a header-location parameter reports no finding'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /hdrloc)" \
  'and no split finding either'
if grep -q ' /hdrloc$' "$REQ_LOG"; then
  _t_no 'header-location skipped' 'a header-location parameter must never reach the transport with this probe payload at all'
else
  _t_ok 'a header-location parameter is skipped before ever composing a request - FAILS by aborting this entire scan process (exit SCOURSH_EXIT_INPUT) under a probe that does not exclude it, since http_request_header refuses an embedded CR/LF as request smuggling'
fi
# `die` calls `exit` directly (lib/core.sh), which would have ended this
# whole test PROCESS at the point it fired - so reaching this line at all,
# with the phase's own closing log line on stderr, is itself the proof
# nothing crashed. A stderr-must-be-empty assertion would be the wrong test:
# the phase logs its own normal summary line every run.
assert_contains "$(cat "$STDERR")" 'tested' \
  'the phase logged its own normal completion summary - proof it ran to the end rather than being killed by a die() partway through'
assert_contains "$(run_facts coverage_reduction)" 'crlf_uninjectable_parameters' \
  'the header-location (and graphql) parameters are a RECORDED coverage reduction, not a silent skip'

# ===========================================================================
printf '== dast crlf: a graphql-location parameter is skipped as uninjectable ==\n'
# ===========================================================================
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /graphql)" \
  'graphql is a structured operation body, not a scalar this probe substitutes - no finding'

# ===========================================================================
printf '== dast crlf: findings carry the mandated metadata ==\n'
# ===========================================================================
TEXT=$(_shard_text)
assert_contains "$TEXT" 'cwe=CWE-113' 'findings carry CWE-113 (CRLF sequences in HTTP headers)'
assert_contains "$TEXT" 'owasp=A03:2021' 'findings carry the OWASP A03:2021 mapping'
assert_contains "$TEXT" 'module=dast' 'findings are attributed to the dast module'
assert_contains "$TEXT" 'cell=crlf-fixture' 'the DAST coverage cell is the scope target id'
assert_contains "$TEXT" 'remediation=' 'findings carry remediation text'

CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-CRLF_HEADER_INJECTION-01' \
  'checks_run records the header-injection check id, so modules/dast/run.sh honesty roll-up does not report covered-nothing'
assert_contains "$CR" 'DAST-INJ-CRLF_RESPONSE_SPLITTING-01' 'checks_run records the response-splitting check id too'

# ===========================================================================
printf '== dast crlf: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_crlf_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  'with no inventory the probe emits NO finding - a clean result with nothing tested is the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  'no parameter surface records a coverage_gap the report renders'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run is EMPTY when nothing was tested - recording it here would overstate coverage'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast crlf: a surface with only header/graphql parameters ==\n'
# ===========================================================================
cat >"$W/none-endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_n", "target": "crlf-fixture", "method": "GET", "url": "https://crlf.fixture.example/n", "path": "/n" }
] }
EOF
cat >"$W/none-parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "n1", "endpoint_id": "e_n", "target": "crlf-fixture", "name": "auth", "location": "header", "example": "token" }
] }
EOF
_new_run nocand
SCOURSH_DAST_ENDPOINTS=$W/none-endpoints.json
SCOURSH_DAST_PARAMETERS=$W/none-parameters.json
_dast_crlf_phase
assert_eq 0 "$(wc -l <"$REQ_LOG" | tr -d ' ')" \
  'a surface with only a header-location parameter sends NO request at all'
assert_contains "$(run_facts coverage_gap)" 'none were in a location this probe could inject' \
  'and it says so in a coverage_gap - FAILS if "we probed nothing" is allowed to render as "we found nothing"'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run stays empty when no candidate parameter existed'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast crlf: missing payloads degrade to a recorded gap ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_write_inventory
_new_run degrade
rc=0
SCOURSH_DAST_CRLF_PAYLOAD_DIR=$W/empty-payloads _dast_crlf_phase || rc=$?
assert_eq 0 "$rc" \
  'an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'no payloads means no finding is emitted'
assert_contains "$(run_facts coverage_reduction)" 'crlf_payloads_missing' \
  'the absent payload file is a recorded coverage_reduction, not a silent skip'
assert_contains "$(run_facts coverage_gap)" 'no CRLF/header-injection payload templates are available' \
  'with no payloads a coverage_gap says so - a clean result here is not a clean bill of health'

# A payload file present but with only ONE of the two templates: also treated
# as missing (this probe needs both to reason about escalation).
mkdir -p "$W/partial-payloads"
printf '%s\n' '%B%NL%H' >"$W/partial-payloads/crlf-payloads.txt"
_new_run onetemplate
rc=0
SCOURSH_DAST_CRLF_PAYLOAD_DIR=$W/partial-payloads _dast_crlf_phase || rc=$?
assert_eq 0 "$rc" 'a payload file with only one template also degrades cleanly rather than erroring'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'and emits nothing, rather than guessing at a second template'
assert_contains "$(run_facts coverage_reduction)" 'crlf_payloads_missing' \
  'a payload file short of two templates is recorded the same way as an absent one'

# ===========================================================================
printf '== dast crlf: per-check selection is honoured ==\n'
# ===========================================================================
# `dast_check_selected` does not exist on every path this file is reachable
# through, so the probe guards on `declare -F`. Define it here to prove the
# guarded call really is consulted.
dast_check_selected() {
  case $1 in
    DAST-INJ-CRLF_HEADER_INJECTION-01 | DAST-INJ-CRLF_RESPONSE_SPLITTING-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run deselected
_write_inventory
_dast_crlf_phase
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-CRLF_RESPONSE_SPLITTING-01 /vuln)" \
  'with both check ids deselected, the probe sends nothing - FAILS if the probe ignores SCOURSH_SELECTED_CHECKS'
assert_contains "$(run_facts coverage_gap)" 'every CRLF/header-injection check was filtered out' \
  'a fully-deselected check set is a recorded coverage_gap, not silence'
unset -f dast_check_selected

dast_check_selected() {
  case $1 in
    DAST-INJ-CRLF_RESPONSE_SPLITTING-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run oneselected
_write_inventory
_dast_crlf_phase
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-CRLF_HEADER_INJECTION-01 /vulnpartial)" \
  'with only the header-injection id selected, the probe still runs (the two ids share one pass) and still reports the bare signal it actually observed'
unset -f dast_check_selected

# ===========================================================================
printf '== dast crlf: the vendored payload templates carry no raw CR or LF ==\n'
# ===========================================================================
PF=$ROOT/modules/dast/payloads/crlf-payloads.txt
BADBYTE=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *$'\r'* || $line == *$'\n'* ]] && BADBYTE=1
done <"$PF"
assert_eq 0 "$BADBYTE" \
  'no template line contains a raw CR or LF byte - FAILS the moment one does, since a real CR/LF cannot survive a line-oriented read as anything but a line break'
NTEMPLATES=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  NTEMPLATES=$(( NTEMPLATES + 1 ))
done <"$PF"
assert_eq 2 "$NTEMPLATES" 'the shipped file carries exactly the two templates this probe requires'
if grep -Eq '^[^#]*(\.com|\.net|\.org|\.io|\.co\.uk)([/:]|$)' "$PF"; then
  _t_no 'payload target-agnostic' 'a vendored payload names a registrable domain'
else
  _t_ok 'no vendored payload names a registrable domain or any application-specific string (§1)'
fi

# ===========================================================================
printf '== inject_engine: the two opt-in knobs leave every other probe alone ==\n'
# ===========================================================================
if ( unset _INJ_WANT_HEADERS _INJ_MAX_REDIRECTS
     unset SCOURSH_DAST_INJECT_ENGINE_SOURCED
     # -x back-edge cut: modules/dast/active/inject_engine.sh is already
     # inlined elsewhere in this file's own source graph, and shellcheck
     # re-expands EVERY source edge it follows. Cutting this one loses no
     # checking and is what keeps the linter's memory bounded - see the
     # shellcheck stage in tests/run-tests.sh, and docs/CI-RUNBOOK.md.
     # shellcheck source=/dev/null
     source "$ROOT/modules/dast/active/inject_engine.sh"
     [[ ${_INJ_WANT_HEADERS} == 0 && -z ${_INJ_MAX_REDIRECTS} ]] ); then
  _t_ok 'inject_engine defaults are header-capture OFF and the redirect count unchanged - FAILS if this ticket changed what active/sqli.sh does'
else
  _t_no 'inject_engine defaults' 'the new knobs must default to the pre-existing behaviour'
fi

t_summary dast-crlf
