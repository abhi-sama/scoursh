#!/usr/bin/env bash
# tests/suites/dast-cmdi.sh - modules/dast/active/cmdi.sh and the shared
# modules/dast/active/inject_engine.sh: BOUNDED time-based blind OS command
# injection (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-16, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), and the time-based technique is driven by a
# FAKE CLOCK (SCOURSH_INJECT_NOW_NS) so it is deterministic and fast with NO real
# sleep - the same swappable-hook idiom lib/http.sh's own transport/resolver
# stubs use. The suite runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.
#
#   1. time-based flags on a latency DELTA over the baseline floor above
#      threshold, not on absolute time: a uniformly slow endpoint is NOT flagged,
#      and a sub-threshold delay is NOT flagged.
#   2. the injected value goes where the parameter's `location` says (query AND
#      body proven here), per docs/DESIGN.md §7.3.
#   3. BOUNDED is load-bearing: the sleep seconds are clamped into 1..10 before
#      substitution, whatever the operator sets, so a probe cannot become a DoS.
#   4. non-destructive: no vendored payload carries a mutating command or an
#      unbounded/amplifying construct.
#   5. no parameter surface / missing payloads degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter/shell/JSON syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/dast/active/inject_engine.sh
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-cmdi-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'CONF'
id: cmdi-fixture
base-url: https://cmdi.fixture.example/
notes: Fixture target for tests/suites/dast-cmdi.sh. Never dialled: both the
  resolver and the transport are stubbed.
CONF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32 ceiling
# does not clamp the rate and the throttle never real-sleeps - the timing this
# suite cares about is the FAKE clock's, not wall clock.
cat >"$W/scanner.conf" <<'CONF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
CONF
config_scanner_load "$W/scanner.conf"

_cmdi_resolve() { case $1 in cmdi.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_cmdi_resolve

# ---------------------------------------------------------------------------
# The fake clock (SCOURSH_INJECT_NOW_NS).
# ---------------------------------------------------------------------------
CLOCKF=$W/clock.ns
PENDF=$W/clock.pending
_clock_reset() { printf '0' >"$CLOCKF"; printf '0' >"$PENDF"; }
_cmdi_now() {
  # `cur_ns`/`pend_ns`, not the obvious `cur`/`pend` - see
  # tests/suites/dast-sqli.sh's own `_sqli_now` for why: `shellcheck -x`
  # inlines every sourced file into one namespace, several engines under
  # modules/dast/ declare `local -A cur=()` inside their own functions, and a
  # plain `local cur=0` here then trips SC2178 against a variable in a
  # different function in a different file. Distinct names are the fix; a
  # suppression would hide the same warning if it ever became real here.
  local cur_ns=0 pend_ns=0
  IFS= read -r cur_ns <"$CLOCKF" 2>/dev/null || true
  IFS= read -r pend_ns <"$PENDF" 2>/dev/null || true
  [[ $cur_ns =~ ^[0-9]+$ ]] || cur_ns=0
  [[ $pend_ns =~ ^[0-9]+$ ]] || pend_ns=0
  cur_ns=$(( cur_ns + pend_ns ))
  printf '0' >"$PENDF"
  printf '%s' "$cur_ns" >"$CLOCKF"
  printf '%s' "$cur_ns"
}
SCOURSH_INJECT_NOW_NS=_cmdi_now

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
#   /run    cmd  - VULNERABLE (query): a shell sleep marker delays 10s (fake).
#   /exec   arg  - VULNERABLE (body): proves body-location injection.
#   /clean  safe - control: never any delay, never a signal.
#   /jitter j    - control: a SUB-THRESHOLD 0.5s delay, must NOT flag.
#   /slow   s    - control: uniformly 2s slow on EVERY request (baseline too),
#                  so a DELTA check does not flag but an ABSOLUTE one wrongly would.
# The vulnerable delay (10s) exceeds the threshold for any clamped sleep in
# 1..10 (max threshold 5s), so the signal fires regardless of the clamped value;
# the clamp itself is pinned separately by inspecting _CMDI_SLEEP_N.
REQ_LOG=$W/requests.log
SURFACE_LOG=$W/surface.log
_req_reset() { : >"$REQ_LOG"; : >"$SURFACE_LOG"; }

PAGE='<html><body>ok</body></html>'

# A shell sleep marker in the injected surface (percent-encoded; the command
# words sleep/timeout/Start-Sleep survive urlencoding since they are unreserved).
_has_sleep_marker() {
  local u=${1^^}
  [[ $u == *SLEEP* || $u == *TIMEOUT* ]]
}

_cmdi_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  printf '%s\n' "$surface" >>"$SURFACE_LOG"
  case $path in
    /run*|/exec*)
      _has_sleep_marker "$surface" && printf '10000000000' >"$PENDF" ;;  # 10s
    /jitter*)
      _has_sleep_marker "$surface" && printf '500000000' >"$PENDF" ;;    # 0.5s, sub-threshold
    /slow*)
      printf '2000000000' >"$PENDF" ;;                                   # 2s every request
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$PAGE" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' 200 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_cmdi_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  cat >"$W/endpoints.json" <<'JSON'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_run",    "target": "cmdi-fixture", "method": "GET",  "url": "https://cmdi.fixture.example/run",    "path": "/run" },
  { "id": "ep_exec",   "target": "cmdi-fixture", "method": "POST", "url": "https://cmdi.fixture.example/exec",   "path": "/exec" },
  { "id": "ep_clean",  "target": "cmdi-fixture", "method": "GET",  "url": "https://cmdi.fixture.example/clean",  "path": "/clean" },
  { "id": "ep_jitter", "target": "cmdi-fixture", "method": "GET",  "url": "https://cmdi.fixture.example/jitter", "path": "/jitter" },
  { "id": "ep_slow",   "target": "cmdi-fixture", "method": "GET",  "url": "https://cmdi.fixture.example/slow",   "path": "/slow" }
] }
JSON
  cat >"$W/parameters.json" <<'JSON'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_run",    "target": "cmdi-fixture", "name": "cmd",  "location": "query", "example": "list" },
  { "id": "p2", "endpoint_id": "ep_exec",   "target": "cmdi-fixture", "name": "arg",  "location": "body",  "example": "x" },
  { "id": "p3", "endpoint_id": "ep_clean",  "target": "cmdi-fixture", "name": "safe", "location": "query", "example": "ok" },
  { "id": "p4", "endpoint_id": "ep_jitter", "target": "cmdi-fixture", "name": "j",    "location": "query", "example": "1" },
  { "id": "p5", "endpoint_id": "ep_slow",   "target": "cmdi-fixture", "name": "s",    "location": "query", "example": "1" }
] }
JSON
}

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target cmdi-fixture
  occurrence_reset_all
  _clock_reset
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

_count_param() {
  local param=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "loc_param_name=$param" ]] && { n=$(( n + 1 )); break; }
      done
    done <"$f"
  done
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Load the phase's functions (sourced once against a throwaway no-inventory run,
# then re-invoked per case, exactly as tests/suites/dast-sqli.sh does).
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=cmdi-fixture
SCOURSH_DAST_CELL=cmdi-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/cmdi.sh
source "$ROOT/modules/dast/active/cmdi.sh"

# ===========================================================================
printf '== dast cmdi: time-based fires on the right parameters ==\n'
# ===========================================================================
SCOURSH_DAST_TARGET=cmdi-fixture
SCOURSH_DAST_CELL=cmdi-fixture
SCOURSH_DAST_INTENSITY=active
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
  SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
unset SCOURSH_SELECTED_CHECKS

_write_full_inventory
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_dast_cmdi_phase

assert_eq 1 "$(_count_finding DAST-INJ-CMDI_TIME-01 cmd)" \
  "time-based fires on query param 'cmd' delayed past a benign baseline - FAILS if it never measures the delta or is fooled by the throttle"
assert_eq 1 "$(_count_finding DAST-INJ-CMDI_TIME-01 arg)" \
  "time-based fires on BODY param 'arg' - FAILS if the probe only injects query strings, not body/JSON fields (docs/DESIGN.md §7.3)"

assert_eq 0 "$(_count_param safe)" \
  "the control parameter 'safe' yields no finding - FAILS if the probe flags a non-vulnerable parameter"
assert_eq 0 "$(_count_param j)" \
  "a SUB-THRESHOLD 0.5s delay does NOT flag - FAILS under 'any latency delta flags', which docs/DESIGN.md §7.3's threshold forbids"
assert_eq 0 "$(_count_param s)" \
  "a uniformly 2s-slow endpoint (baseline slow too) does NOT flag - FAILS under an ABSOLUTE-time reading; only the DELTA over the baseline floor counts"

# ===========================================================================
printf '== dast cmdi: BOUNDED - the sleep seconds are clamped into 1..10 ==\n'
# ===========================================================================
# The bound is load-bearing (this ticket). Whatever the operator sets, the
# substituted sleep is clamped into 1..10 seconds, so a payload can never delay
# a target for longer and a probe can never become a denial-of-service.
_new_run clamp_hi
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_CMDI_SLEEP=999 _dast_cmdi_phase
assert_eq 10 "$_CMDI_SLEEP_N" \
  "an operator sleep of 999 is clamped to the 10s ceiling - FAILS under an unbounded reading that would let a probe sleep for 999s (a DoS)"
# The sent surface never carries the un-clamped value, only the clamped one.
assert_not_contains "$(cat "$SURFACE_LOG")" '999' \
  "no request ever carried the un-clamped 999 - FAILS if the ceiling is advisory rather than applied before substitution"

_new_run clamp_lo
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_CMDI_SLEEP=0 _dast_cmdi_phase
assert_eq 1 "$_CMDI_SLEEP_N" \
  "an operator sleep of 0 is raised to the 1s floor - FAILS if a zero (or garbage) value disables the delay silently"

_new_run clamp_junk
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_CMDI_SLEEP=abc _dast_cmdi_phase
assert_eq 3 "$_CMDI_SLEEP_N" \
  "a non-numeric sleep falls back to the 3s default - FAILS if garbage input is substituted into a payload"

# ===========================================================================
printf '== dast cmdi: non-destructive, bounded payloads (no write, no amplify) ==\n'
# ===========================================================================
PF=$ROOT/modules/dast/payloads/cmdi-time-payloads.txt
# The PAYLOAD lines only (comments legitimately discuss the very words these
# checks ban - "no fork bomb", "reads nothing" - so scanning the whole file
# would flag the prose, not a payload).
PAYLOAD_LINES=$W/cmdi-payload-lines.txt
: >"$PAYLOAD_LINES"
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  printf '%s\n' "$line" >>"$PAYLOAD_LINES"
done <"$PF"
# No destructive/write command anywhere in the vendored payloads.
BADVERB=0
if grep -Eiq '\b(rm|mv|cp|dd|mkfs|shutdown|reboot|curl|wget|nc|ncat|chmod|chown|kill|del|format|rmdir)\b' "$PAYLOAD_LINES"; then BADVERB=1; fi
assert_eq 0 "$BADVERB" \
  "no vendored command-injection payload carries a destructive/exfiltrating command - FAILS the moment an rm/curl/nc is added, which docs/DESIGN.md §7.3's non-destructive contract forbids"
# No unbounded or amplifying construct: a loop, a fork bomb, a 'yes', or a nested
# background storm would turn a 'bounded delay' into a DoS.
UNBOUNDED=0
if grep -Eiq '(\bwhile\b|\bfor\b|\byes\b|\bping\b|:\(\)|fork|/dev/zero|/dev/urandom)' "$PAYLOAD_LINES"; then UNBOUNDED=1; fi
assert_eq 0 "$UNBOUNDED" \
  "no payload is an unbounded/amplifying construct - only a single fixed sleep - FAILS the moment a loop or amplifier is added, which the BOUNDED contract forbids"
# Every delay payload substitutes %N (the clamped seconds); a payload with a
# hardcoded large sleep would bypass the clamp.
NOSUB=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  case ${line^^} in
    *SLEEP*|*TIMEOUT*) [[ $line == *'%N'* ]] || NOSUB=1 ;;
  esac
done <"$PF"
assert_eq 0 "$NOSUB" \
  "every sleep/timeout payload takes its duration from the clamped %N, never a hardcoded number - FAILS if a payload hardcodes a delay that the 1..10 clamp cannot bound"

# ===========================================================================
printf '== dast cmdi: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
_new_run coverage
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
_dast_cmdi_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-CMDI_TIME-01' \
  "checks_run records the check that executed over a parameter (AGENTS.md's definition), so modules/dast/run.sh's honesty roll-up does not report covered-nothing"

# ===========================================================================
printf '== dast cmdi: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_cmdi_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, cmdi emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  "no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast cmdi: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
rc=0
SCOURSH_DAST_CMDI_PAYLOAD_DIR=$W/empty-payloads _dast_cmdi_phase || rc=$?
assert_eq 0 "$rc" \
  "an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "no payloads means no finding is emitted"
assert_contains "$(run_facts coverage_reduction)" 'cmdi_payloads_missing' \
  "the absent payload file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no command-injection payloads are available' \
  "with the payloads gone, a coverage_gap says so - a clean result here is not a clean bill of health"

# ===========================================================================
printf '== dast cmdi: per-check deselection skips the probe honestly ==\n'
# ===========================================================================
# When tension-15's filter chain deselects the only check, the probe runs
# nothing and records a gap rather than reporting clean.
dast_check_selected() { return 1; }   # deselect everything
_new_run deselect
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
_dast_cmdi_phase
unset -f dast_check_selected
assert_eq 0 "$(_count_param cmd)" \
  "a deselected check emits no finding even on a vulnerable parameter - FAILS if selection is ignored"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is empty when the check was deselected - it never ran"

# ===========================================================================
printf '== inject_engine: the shipped payloads load and substitute ==\n'
# ===========================================================================
N=0
while IFS= read -r line; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  N=$(( N + 1 ))
done <"$PF"
if (( N >= 1 )); then _t_ok "the shipped cmdi payload file carries at least one payload ($N)"; else _t_no "cmdi payloads" "empty shipped payload file"; fi

t_summary dast-cmdi
