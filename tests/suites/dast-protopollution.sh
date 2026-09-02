#!/usr/bin/env bash
# tests/suites/dast-protopollution.sh - modules/dast/active/protopollution.sh
# and the shared modules/dast/active/inject_engine.sh: __proto__/
# constructor.prototype-shaped JSON parameter probing for a JavaScript
# backend (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-25, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"), driven from a mock that models
# real vulnerable/safe server behaviours rather than a canned verdict.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and
# the rejected reading pins nothing.
#
#   1. error-based fires only when the __proto__/constructor.prototype
#      SHAPE provokes a JS-runtime/merge error a SHAPE-MATCHED CONTROL
#      (same nesting depth, an ordinary key) does not - not on any 500, and
#      not when the endpoint is already noisy on its own benign baseline.
#   2. marker-reflection fires only when a value planted via one request
#      reappears in a SEPARATE, later, entirely benign request's own
#      response - never on a same-request echo, however exact.
#   3. marker-reflection is confirmed on a SECOND, independent marker before
#      being reported - a one-off coincidence does not fire it.
#   4. the technique is not part of the fingerprint, so two techniques on
#      one parameter are two distinct check ids, not one deduped finding.
#   5. the injected value goes where the parameter's `location` says (query
#      AND formData/body proven here).
#   6. graphql and a path parameter with no template slot are uninjectable,
#      recorded, never silently "clean".
#   7. non-destructive: no vendored payload writes a file, spawns a process,
#      or names a registrable domain.
#   8. missing payloads / no parameter inventory degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON/property syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/dast/active/inject_engine.sh is already inlined
# elsewhere in this file's own source graph, and shellcheck re-expands EVERY
# source edge it follows. Cutting this one loses no checking and is what
# keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-protopollution-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: pp-fixture
base-url: https://pp.fixture.example/
notes: Fixture target for tests/suites/dast-protopollution.sh. Never dialled:
  both the resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32
# ceiling does not clamp the rate to 4/s and the throttle never real-sleeps.
# A very high breaker threshold so the deliberate 500s the error technique
# provokes never open the circuit and abort the run.
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_pp_resolve() { case $1 in pp.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_pp_resolve

# ---------------------------------------------------------------------------
# Percent-decoding, so the mock decides on the value the "application" sees
# - the same helper (and the same reasoning) as tests/suites/dast-crlf.sh's
# own `_pctdec`: inject_engine.sh percent-encodes before sending, exactly as
# a real client would, so the mock decodes rather than matching encoded
# bytes.
# ---------------------------------------------------------------------------
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

# `_pp_is_pollute_shape VALUE` - 0 when the decoded value carries the
# `__proto__` own-property key or the `constructor`+`prototype` pair, the
# two routes to Object.prototype this probe's payloads use.
_pp_is_pollute_shape() {
  local v=$1
  [[ $v == *'"__proto__"'* ]] && return 0
  [[ $v == *'"constructor"'* && $v == *'"prototype"'* ]] && return 0
  return 1
}

# `_pp_extract_kv VALUE` - sets _PP_KV_KEY/_PP_KV_VALUE from the one
# "key":"value" leaf every template in this probe's payload files carries
# (the marker, or the static "polluted":"1" pair).
_pp_extract_kv() {
  local v=$1
  if [[ $v =~ \"([A-Za-z0-9_-]+)\":\"([^\"]*)\" ]]; then
    _PP_KV_KEY=${BASH_REMATCH[1]}
    _PP_KV_VALUE=${BASH_REMATCH[2]}
  else
    _PP_KV_KEY=''
    _PP_KV_VALUE=''
  fi
}

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
#   /err_vuln       q  (query)    ERROR-VULNERABLE: a __proto__/
#                                 constructor.prototype value 500s with a
#                                 merge-library error signature; an
#                                 identically-shaped control (ordinary key)
#                                 does not.
#   /err_vuln_form  q  (formData) Same as /err_vuln, but the parameter
#                                 arrives in the request BODY - proves
#                                 body-location injection.
#   /err_safe       q  (query)    ERROR-SAFE: never errors on any shape (a
#                                 merge that rejects/strips the special keys,
#                                 or validates the field's type).
#   /err_noisy      q  (query)    Always 500s, even on the plain benign
#                                 baseline - an endpoint that is noisy for
#                                 reasons unrelated to this probe.
#   /err_noisy2     q  (query)    Baseline-noisy in a way that would still
#                                 look like a REAL differential if the
#                                 baseline-noise check were skipped: the
#                                 benign baseline 500s with one signature,
#                                 the pollute value 500s with a DIFFERENT
#                                 signature, and the control is clean. Proves
#                                 the endpoint is judged unreliable from its
#                                 OWN baseline before any pollute/control
#                                 comparison is even attempted.
#   /reflect_vuln   q  (query)    REFLECTION-VULNERABLE: a poisoning value
#                                 sets process-wide state a LATER, unrelated
#                                 request to the same endpoint reads back -
#                                 the mock's model of a value that reached
#                                 Object.prototype (or an equally shared,
#                                 long-lived object).
#   /reflect_safe   q  (query)    REFLECTION-SAFE: never persists anything
#                                 from a __proto__/constructor.prototype
#                                 value.
#   /reflect_echo   q  (query)    Echoes the CURRENT request's own value
#                                 into the CURRENT response ONLY - never into
#                                 any OTHER request's response. Proves plain
#                                 same-request reflection is not mistaken for
#                                 cross-request contamination.
#   /graphql        q  (graphql)  Structured operation body - uninjectable.
#   /notmpl         q  (path)     A path-location parameter whose URL/path
#                                 carries no `{q}` template slot -
#                                 uninjectable.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }
_pp_state_reset() { rm -f "$W"/state.*; }
_pp_state_path() { printf '%s/state.%s' "$W" "$1"; }

_pp_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local p=${path%%\?*}
  local qs=${path#*\?}
  [[ $qs == "$path" ]] && qs=''
  local v=''
  if [[ $p == /err_vuln_form ]]; then
    v=${body#*=}; v=${v%%&*}; v=$(_pctdec "$v")
  else
    v=${qs#*=}; v=${v%%&*}; v=$(_pctdec "$v")
  fi
  printf '%s %s\n' "$method" "$p" >>"$REQ_LOG"

  local status=200 out=ok
  case $p in
    /err_vuln | /err_vuln_form)
      if _pp_is_pollute_shape "$v"; then
        status=500
        out='TypeError: Cannot set property polluted of #<Object>'
      fi
      ;;
    /err_safe)
      out=ok
      ;;
    /err_noisy)
      status=500
      out='Object.prototype is not the object you expected'
      ;;
    /err_noisy2)
      if [[ -z $v || $v == abc ]]; then
        status=500
        out='Object.prototype is not the object you expected'
      elif _pp_is_pollute_shape "$v"; then
        status=500
        out='RangeError: Maximum call stack size exceeded'
      fi
      ;;
    /reflect_vuln)
      local st; st=$(_pp_state_path reflect_vuln)
      if _pp_is_pollute_shape "$v"; then
        _pp_extract_kv "$v"
        printf '%s' "$_PP_KV_VALUE" >"$st"
      fi
      if [[ -s $st ]]; then out="ok leaked:$(cat "$st")"; else out=ok; fi
      ;;
    /reflect_safe)
      out=ok
      ;;
    /reflect_echo)
      out="ok you sent: $v"
      ;;
    *)
      status=404
      out=nope
      ;;
  esac
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_pp_transport

# ---------------------------------------------------------------------------
# Inventory (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e_err_vuln",      "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/err_vuln",      "path": "/err_vuln" },
  { "id": "e_err_vuln_form", "target": "pp-fixture", "method": "POST", "url": "https://pp.fixture.example/err_vuln_form", "path": "/err_vuln_form" },
  { "id": "e_err_safe",      "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/err_safe",      "path": "/err_safe" },
  { "id": "e_err_noisy",     "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/err_noisy",     "path": "/err_noisy" },
  { "id": "e_err_noisy2",    "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/err_noisy2",    "path": "/err_noisy2" },
  { "id": "e_reflect_vuln",  "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/reflect_vuln",  "path": "/reflect_vuln" },
  { "id": "e_reflect_safe",  "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/reflect_safe",  "path": "/reflect_safe" },
  { "id": "e_reflect_echo",  "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/reflect_echo",  "path": "/reflect_echo" },
  { "id": "e_graphql",       "target": "pp-fixture", "method": "POST", "url": "https://pp.fixture.example/graphql",       "path": "/graphql" },
  { "id": "e_notmpl",        "target": "pp-fixture", "method": "GET",  "url": "https://pp.fixture.example/notmpl",        "path": "/notmpl" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "e_err_vuln",      "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p2", "endpoint_id": "e_err_vuln_form", "target": "pp-fixture", "name": "q", "location": "formData", "example": "abc" },
  { "id": "p3", "endpoint_id": "e_err_safe",      "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p4", "endpoint_id": "e_err_noisy",     "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p4b", "endpoint_id": "e_err_noisy2",    "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p5", "endpoint_id": "e_reflect_vuln",  "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p6", "endpoint_id": "e_reflect_safe",  "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p7", "endpoint_id": "e_reflect_echo",  "target": "pp-fixture", "name": "q", "location": "query",    "example": "abc" },
  { "id": "p8", "endpoint_id": "e_graphql",       "target": "pp-fixture", "name": "q", "location": "graphql",  "example": "abc" },
  { "id": "p9", "endpoint_id": "e_notmpl",        "target": "pp-fixture", "name": "q", "location": "path",     "example": "abc" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and shard readers (the shape tests/suites/
# dast-crlf.sh established: one finding per line, fields TAB-delimited as
# `key=value`).
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target pp-fixture
  occurrence_reset_all
  _req_reset
  _pp_state_reset
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
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
# it), so it is sourced once here against a throwaway run with no inventory
# - a harmless no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=pp-fixture
SCOURSH_DAST_CELL=pp-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/protopollution.sh
source "$ROOT/modules/dast/active/protopollution.sh"

# ===========================================================================
printf '== dast protopollution: the marker is fresh per call ==\n'
# ===========================================================================
_pp_marker_set; K1=$_PP_MARKER_KEY; V1=$_PP_MARKER_VALUE
_pp_marker_set; K2=$_PP_MARKER_KEY; V2=$_PP_MARKER_VALUE
if [[ $K1 == "$K2" ]]; then
  _t_no 'marker key randomness' 'two markers in one process must differ'
else
  _t_ok 'the marker property NAME is fresh per call - FAILS under a constant, which would let an unrelated response supply the proof this probe reads as its own'
fi
assert_ne "$V1" "$V2" 'the marker property VALUE is likewise fresh per call'
assert_ne "$K1" "$V1" 'the property name and its value are two distinct strings'

# ===========================================================================
printf '== dast protopollution: the probes fire on real vulnerable endpoints ==\n'
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
_dast_protopollution_phase 2>"$STDERR"

assert_eq 1 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_vuln)" \
  'an endpoint that errors on the __proto__/constructor.prototype shape but NOT on the shape-matched control is flagged - the differential, not a bare 500, is the signal'
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_vuln_form)" \
  'a formData/body-location parameter is probed and confirmed - FAILS if only query strings were injected'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_safe)" \
  'an endpoint that never errors on any shape is NOT flagged'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_noisy)" \
  'an endpoint that already 500s on the plain benign baseline is skipped for the error technique - FAILS if a naturally noisy endpoint were flagged on every request'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_noisy2)" \
  'an endpoint whose OWN baseline already matches a signature is skipped even when the pollute/control pair alone would look like a real differential - FAILS if the baseline-noise check were removed, since the pollute value there 500s with a DIFFERENT signature than the control'

assert_eq 1 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_vuln)" \
  'a value planted through one request that reappears in a SEPARATE, later, entirely benign request is flagged, confirmed on a second independent marker'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_safe)" \
  'an endpoint that never persists anything from the poisoning value is NOT flagged'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_echo)" \
  'an endpoint that echoes the CURRENT request only (never a later, unrelated one) is NOT flagged - FAILS under a check that reads the poisoning request'"'"'s own response instead of a separate follow-up, since that response legitimately contains the marker text as a plain echo'

assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /graphql)" \
  'graphql is a structured operation body, not a scalar this probe substitutes - no finding'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /graphql)" \
  'and no reflection finding either'
if grep -q ' /graphql$' "$REQ_LOG"; then
  _t_no 'graphql skipped' 'a graphql-location parameter must never reach the transport'
else
  _t_ok 'a graphql-location parameter never reaches the transport at all'
fi
if grep -q ' /notmpl$' "$REQ_LOG"; then
  _t_no 'no-template path skipped' 'a path-location parameter with no {name} template slot must never reach the transport'
else
  _t_ok 'a path-location parameter with no template slot never reaches the transport at all - inject_send refuses it before composing a request'
fi

assert_contains "$(cat "$STDERR")" 'tested' \
  'the phase logged its own normal completion summary - proof it ran to the end'
assert_contains "$(run_facts coverage_reduction)" 'protopollution_uninjectable_parameters' \
  'the graphql and no-template-path parameters are a RECORDED coverage reduction, not a silent skip'

CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-PROTOPOLLUTION_ERROR-01' \
  'checks_run records the error-based check id, so modules/dast/run.sh honesty roll-up does not report covered-nothing'
assert_contains "$CR" 'DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01' \
  'checks_run records the marker-reflection check id too'

# ===========================================================================
printf '== dast protopollution: findings carry the mandated metadata ==\n'
# ===========================================================================
TEXT=$(_shard_text)
assert_contains "$TEXT" 'cwe=CWE-1321' 'findings carry CWE-1321 (Improper Filtering of Special Elements)'
assert_contains "$TEXT" 'owasp=A03:2021' 'findings carry the OWASP A03:2021 mapping'
assert_contains "$TEXT" 'module=dast' 'findings are attributed to the dast module'
assert_contains "$TEXT" 'cell=pp-fixture' 'the DAST coverage cell is the scope target id'
assert_contains "$TEXT" 'remediation=' 'findings carry remediation text'
assert_contains "$TEXT" 'base_severity=critical' \
  'the confirmed cross-request marker-reflection finding carries the stronger, critical severity'

# ===========================================================================
printf '== dast protopollution: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_protopollution_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  'with no inventory the probe emits NO finding - a clean result with nothing tested is the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  'no parameter surface records a coverage_gap the report renders'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run is EMPTY when nothing was tested - recording it here would overstate coverage'
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast protopollution: missing payloads degrade to a recorded gap ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade-all
rc=0
SCOURSH_DAST_PROTOPOLLUTION_PAYLOAD_DIR=$W/empty-payloads _dast_protopollution_phase || rc=$?
assert_eq 0 "$rc" \
  'an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'no payloads means no finding is emitted'
assert_contains "$(run_facts coverage_reduction)" 'technique=error' \
  'the absent error payloads are a recorded coverage_reduction, not a silent skip'
assert_contains "$(run_facts coverage_reduction)" 'technique=reflected' \
  'the absent marker-reflection payloads are a recorded coverage_reduction too'
assert_contains "$(run_facts coverage_gap)" 'no prototype-pollution payloads are available' \
  'with no payloads at all a coverage_gap says so - a clean result here is not a clean bill of health'

# A payload dir carrying only the marker-reflection templates: the error
# technique degrades alone, and the other keeps running.
mkdir -p "$W/reflect-only"
cp "$ROOT/modules/dast/payloads/protopollution-payloads.txt" "$W/reflect-only/"
_new_run degrade-error-only
SCOURSH_DAST_PROTOPOLLUTION_PAYLOAD_DIR=$W/reflect-only _dast_protopollution_phase
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_vuln)" \
  'marker-reflection still runs when only the error payloads are missing - a missing file degrades ONLY its own technique'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_vuln)" \
  'error-based does NOT run without its payload/signature files - FAILS if a technique reports on a param it never probed'
assert_contains "$(run_facts coverage_reduction)" 'technique=error' \
  'the missing error payloads are recorded as a technique=error coverage_reduction'
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-PROTOPOLLUTION_ERROR-01' \
  'checks_run does NOT claim the error check ran when its payloads were absent'

# ===========================================================================
printf '== dast protopollution: per-check selection is honoured ==\n'
# ===========================================================================
dast_check_selected() {
  case $1 in
    DAST-INJ-PROTOPOLLUTION_ERROR-01 | DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run deselected
_dast_protopollution_phase
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_vuln)" \
  'with both check ids deselected, error-based sends nothing - FAILS if the probe ignores SCOURSH_SELECTED_CHECKS'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_vuln)" \
  'nor does marker-reflection'
assert_contains "$(run_facts coverage_gap)" 'no technique ran' \
  'a fully-deselected check set is a recorded coverage_gap, not silence'
unset -f dast_check_selected

dast_check_selected() {
  case $1 in
    DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01) return 1 ;;
    *) return 0 ;;
  esac
}
_new_run oneselected
_dast_protopollution_phase
assert_eq 1 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_ERROR-01 /err_vuln)" \
  'with only the error-based id selected, error-based still runs and confirms the same real differential'
assert_eq 0 "$(_count_endpoint_finding DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01 /reflect_vuln)" \
  'and marker-reflection, deselected, sends nothing'
unset -f dast_check_selected

# ===========================================================================
printf '== dast protopollution: every vendored payload is non-destructive and target-agnostic ==\n'
# ===========================================================================
# No payload writes a file, spawns a process, drops/deletes/updates data, or
# exfiltrates beyond the minimal marker/leaf value this probe itself planted
# (modules/dast/payloads/README.md's non-destructive contract).
BADVERB=0
for pf in "$ROOT"/modules/dast/payloads/protopollution-*.txt; do
  if grep -Eiq '\b(drop|delete|remove|update|insert|exec|eval|require|process\.env|child_process|readFileSync|writeFileSync)\b' "$pf"; then
    BADVERB=1
  fi
done
assert_eq 0 "$BADVERB" \
  "no vendored prototype-pollution payload carries a write/exec/exfiltration verb - FAILS the moment one is added, which docs/DESIGN.md §7.3's non-destructive contract forbids"

if grep -Eq '(\.com|\.net|\.org|\.io|\.co\.uk)([/:"]|$)' "$ROOT"/modules/dast/payloads/protopollution-*.txt; then
  _t_no 'payload target-agnostic' 'a vendored payload names a registrable domain'
else
  _t_ok 'no vendored payload names a registrable domain or any application-specific string (§1)'
fi

NTEMPLATES=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  NTEMPLATES=$(( NTEMPLATES + 1 ))
done <"$ROOT/modules/dast/payloads/protopollution-payloads.txt"
assert_eq 2 "$NTEMPLATES" \
  'the marker-reflection file carries exactly the two __proto__/constructor.prototype templates this probe requires'

NPAIRS=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  NPAIRS=$(( NPAIRS + 1 ))
done <"$ROOT/modules/dast/payloads/protopollution-error-pairs.txt"
assert_eq 2 "$NPAIRS" \
  'the error-pair file carries exactly the two pollute/control pairs this probe requires'

# ===========================================================================
printf '== inject_engine: unit checks (JSON __proto__/constructor.prototype shapes) ==\n'
# ===========================================================================
inject_urlencode '{"__proto__":{"k":"v"}}'
assert_contains "$_INJ_ENC" '%7B' "inject_urlencode percent-encodes an opening brace"
assert_contains "$_INJ_ENC" '%22' "inject_urlencode percent-encodes a double quote"
assert_contains "$_INJ_ENC" '%7D' "inject_urlencode percent-encodes a closing brace"

_write_inventory
inject_inventory_load "$W/endpoints.json" "$W/parameters.json"
assert_eq 10 "$_INJ_N" \
  "inject_inventory_load reads all 10 parameters and joins each to its endpoint - FAILS if a parameter whose endpoint row exists is dropped"

t_summary dast-protopollution
