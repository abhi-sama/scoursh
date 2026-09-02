#!/usr/bin/env bash
# tests/suites/dast-sqli.sh - modules/dast/active/sqli.sh and the shared
# modules/dast/active/inject_engine.sh: error-based, boolean-based and
# time-based blind SQL injection (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-14, tier 4).
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
#   1. error-based fires only when a DB error surfaces for an injected value and
#      NOT for the benign baseline - not on any 500, and not on the baseline's
#      own errors.
#   2. boolean-based needs the tautology to behave like the baseline AND the
#      contradiction to differ from it - a page that changes for BOTH (or
#      NEITHER) is not a differential.
#   3. time-based flags on a latency DELTA over the baseline floor above
#      threshold, not on absolute time: a uniformly slow endpoint is NOT flagged,
#      and a sub-threshold delay is NOT flagged.
#   4. the technique is not part of the fingerprint, so three techniques on one
#      parameter are three distinct check ids, not one deduped finding.
#   5. the injected value goes where the parameter's `location` says (query AND
#      body proven here), per docs/DESIGN.md §7.3.
#   6. non-destructive: no request ever carries a mutating SQL keyword.
#   7. no parameter surface / missing payloads degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter/SQL/JSON syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut: modules/dast/active/inject_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-sqli-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: sqli-fixture
base-url: https://sqli.fixture.example/
notes: Fixture target for tests/suites/dast-sqli.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32 ceiling
# does not clamp the rate to 4/s and the throttle never real-sleeps - the timing
# this suite cares about is the FAKE clock's, not wall clock. A very high
# breaker threshold so the deliberate 500s the error technique provokes never
# open the circuit and abort the run.
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_sqli_resolve() { case $1 in sqli.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_sqli_resolve

# ---------------------------------------------------------------------------
# The fake clock (SCOURSH_INJECT_NOW_NS).
# ---------------------------------------------------------------------------
# Virtual nanoseconds live on disk (the clock hook runs in a $(...) subshell, so
# a shell variable would not survive). Each read adds any pending delay the
# transport queued for the request just sent, then clears it: a request the
# transport marked as sleeping shows exactly that delay as elapsed, everything
# else shows zero. Real throttle sleeps inside http_request never touch this
# clock, which is what makes the time-based technique deterministic.
CLOCKF=$W/clock.ns
PENDF=$W/clock.pending
_clock_reset() { printf '0' >"$CLOCKF"; printf '0' >"$PENDF"; }
_sqli_now() {
  # `|| true`, not `|| now_ns=0`: the state files carry no trailing newline, so
  # `read` returns non-zero at EOF HAVING read the value - `|| now_ns=0` would
  # then throw the value away (the same EOF-reader lesson lib/core.sh records).
  #
  # The locals are `now_ns`/`pending_ns`, not the obvious `cur`/`pend`, because
  # `shellcheck -x` inlines every sourced file into ONE namespace: several
  # engines under modules/dast/ declare `local -A cur=()` inside their own
  # functions, and a plain `local cur=0` here then trips SC2178 ("used as an
  # array but is now assigned a string") against a variable in a different
  # function in a different file.  Distinct names are the fix; a suppression
  # would hide the same warning if it ever became real here.
  local now_ns=0 pending_ns=0
  IFS= read -r now_ns <"$CLOCKF" 2>/dev/null || true
  IFS= read -r pending_ns <"$PENDF" 2>/dev/null || true
  [[ $now_ns =~ ^[0-9]+$ ]] || now_ns=0
  [[ $pending_ns =~ ^[0-9]+$ ]] || pending_ns=0
  now_ns=$(( now_ns + pending_ns ))
  printf '0' >"$PENDF"
  printf '%s' "$now_ns" >"$CLOCKF"
  printf '%s' "$now_ns"
}
SCOURSH_INJECT_NOW_NS=_sqli_now

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# One vulnerable parameter per technique, plus controls, decided from the actual
# injected bytes (percent-encoded in the path/body the transport receives):
#   /search  q     - ERROR: a quote (%27/%22) provokes a MySQL error (500).
#   /login   user  - ERROR via a BODY parameter (proves body-location injection).
#   /item    id    - BOOLEAN: an always-false condition returns a short page.
#   /lookup  name  - TIME: a SLEEP payload delays the response by 3s (fake clock).
#   /clean   safe  - control: never any signal.
#   /jitter  j     - control: a SUB-THRESHOLD 0.5s delay, must NOT flag.
#   /slow    s     - control: uniformly 2s slow on EVERY request (baseline too),
#                    so a DELTA check does not flag but an ABSOLUTE one wrongly would.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

LONG='<html><body><ul><li>alpha</li><li>bravo</li><li>charlie</li><li>delta</li><li>echo</li><li>foxtrot</li><li>golf</li><li>hotel</li></ul></body></html>'
SHORT='<html><body>No results.</body></html>'
DBERR='<html><body>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near "'"'"'"</body></html>'

_sqli_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 out=$LONG
  case $path in
    /search*)
      if [[ $surface == *%27* || $surface == *%22* ]]; then status=500; out=$DBERR; fi
      ;;
    /login*)
      if [[ $surface == *%27* || $surface == *%22* ]]; then status=500; out=$DBERR; fi
      ;;
    /item*)
      if [[ $surface == *AND%201%3D2* || $surface == *%271%27%3D%272* ]]; then out=$SHORT; fi
      ;;
    /lookup*)
      # Case-insensitive SLEEP/WAITFOR/RECEIVE marker => a real (fake-clock) delay.
      local u=${surface^^}
      if [[ $u == *SLEEP* || $u == *WAITFOR* || $u == *RECEIVE_MESSAGE* ]]; then
        printf '3000000000' >"$PENDF"
      fi
      ;;
    /jitter*)
      local u=${surface^^}
      if [[ $u == *SLEEP* || $u == *WAITFOR* || $u == *RECEIVE_MESSAGE* ]]; then
        printf '500000000' >"$PENDF"   # 0.5s, below the 1.5s threshold
      fi
      ;;
    /slow*)
      printf '2000000000' >"$PENDF"     # 2s on EVERY request, baseline included
      ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_sqli_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_search", "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/search", "path": "/search" },
  { "id": "ep_login",  "target": "sqli-fixture", "method": "POST", "url": "https://sqli.fixture.example/login",  "path": "/login" },
  { "id": "ep_item",   "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/item",   "path": "/item" },
  { "id": "ep_lookup", "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/lookup", "path": "/lookup" },
  { "id": "ep_clean",  "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/clean",  "path": "/clean" },
  { "id": "ep_jitter", "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/jitter", "path": "/jitter" },
  { "id": "ep_slow",   "target": "sqli-fixture", "method": "GET",  "url": "https://sqli.fixture.example/slow",   "path": "/slow" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_search", "target": "sqli-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "p2", "endpoint_id": "ep_login",  "target": "sqli-fixture", "name": "user", "location": "body",  "example": "root" },
  { "id": "p3", "endpoint_id": "ep_item",   "target": "sqli-fixture", "name": "id",   "location": "query", "example": "5" },
  { "id": "p4", "endpoint_id": "ep_lookup", "target": "sqli-fixture", "name": "name", "location": "query", "example": "amy" },
  { "id": "p5", "endpoint_id": "ep_clean",  "target": "sqli-fixture", "name": "safe", "location": "query", "example": "ok" },
  { "id": "p6", "endpoint_id": "ep_jitter", "target": "sqli-fixture", "name": "j",    "location": "query", "example": "1" },
  { "id": "p7", "endpoint_id": "ep_slow",   "target": "sqli-fixture", "name": "s",    "location": "query", "example": "1" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  # The authorization affirmation the rate/budget ceilings read (DAST-33).
  run_record authorization_affirmed true
  run_record authorization_target sqli-fixture
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

# The shard `.fields` format is one finding per line, fields TAB-delimited as
# `key=value` (lib/findings.sh's `_finding_fields`). `_count_finding CHECK PARAM`
# counts findings whose `check_id` AND `loc_param_name` fields both match
# exactly; `_count_param PARAM` counts findings on a parameter regardless of
# technique (for the control assertions - an exact field match, so `s` never
# matches `safe`).
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
# Load the phase's functions. A phase script has no sourced-once guard and runs
# _dast_sqli_phase at source time (that is how dast_run_phase invokes it), so it
# is sourced once here against a throwaway run with no inventory - a harmless
# no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=sqli-fixture
SCOURSH_DAST_CELL=sqli-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/sqli.sh
source "$ROOT/modules/dast/active/sqli.sh"

# ===========================================================================
printf '== dast sqli: the three techniques fire on the right parameters ==\n'
# ===========================================================================
SCOURSH_DAST_TARGET=sqli-fixture
SCOURSH_DAST_CELL=sqli-fixture
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
_dast_sqli_phase

assert_eq 1 "$(_count_finding DAST-INJ-SQLI_ERROR-01 q)" \
  "error-based fires on query param 'q' whose quote provokes a DB error - FAILS under a reading that needs the baseline to error too, or that ignores the injected-only signature"
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_ERROR-01 user)" \
  "error-based fires on BODY param 'user' - FAILS if the probe only injects query strings, not body/JSON fields (docs/DESIGN.md §7.3)"
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_BOOLEAN-01 id)" \
  "boolean-based fires on 'id' where the contradiction returns a short page - FAILS if it flags whenever any two responses differ"
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_TIME-01 name)" \
  "time-based fires on 'name' delayed 3s past a benign baseline - FAILS if it never measures the delta or is fooled by the throttle"

assert_eq 0 "$(_count_finding DAST-INJ-SQLI_BOOLEAN-01 q)" \
  "NO boolean finding on 'q': its true/false pair both return the same page, so there is no differential - FAILS if a quote-provoked 500 is read as a boolean change"
assert_eq 0 "$(_count_finding DAST-INJ-SQLI_ERROR-01 id)" \
  "NO error finding on 'id': a quote there returns a normal page, no DB error - FAILS if error-based flags a non-error response"
assert_eq 0 "$(_count_finding DAST-INJ-SQLI_TIME-01 id)" \
  "NO time finding on 'id': its SLEEP payload does not delay - FAILS if a time finding is emitted without a real latency delta"

assert_eq 0 "$(_count_param safe)" \
  "the control parameter 'safe' yields no finding of any technique - FAILS if any probe flags a non-vulnerable parameter"
assert_eq 0 "$(_count_param j)" \
  "a SUB-THRESHOLD 0.5s delay does NOT flag time-based - FAILS under 'any latency delta flags', which docs/DESIGN.md §7.3's threshold forbids"
assert_eq 0 "$(_count_param s)" \
  "a uniformly 2s-slow endpoint (baseline slow too) does NOT flag - FAILS under an ABSOLUTE-time reading; only the DELTA over the baseline floor counts"

# ===========================================================================
printf '== dast sqli: three techniques, three distinct check ids on one param ==\n'
# ===========================================================================
# A single parameter that is vulnerable to ALL THREE at once must produce THREE
# findings, because the technique is not part of the DAST fingerprint (target,
# method, path_template, param_location, param_name) - one check id would dedupe
# them to one.
cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_all", "target": "sqli-fixture", "method": "GET", "url": "https://sqli.fixture.example/all", "path": "/all" }
] }
EOF
cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "pa", "endpoint_id": "ep_all", "target": "sqli-fixture", "name": "x", "location": "query", "example": "1" }
] }
EOF
_all_transport() {
  local method=$1 path=$5 body=${_HTTP_TX_BODY:-}
  local surface="$path?$body" status=200 out=$LONG u
  u=${surface^^}
  if [[ $surface == *%27* || $surface == *%22* ]]; then status=500; out=$DBERR
  elif [[ $u == *SLEEP* ]]; then printf '3000000000' >"$PENDF"
  elif [[ $surface == *AND%201%3D2* ]]; then out=$SHORT
  fi
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
_new_run allthree
SCOURSH_HTTP_TRANSPORT=_all_transport
_dast_sqli_phase
SCOURSH_HTTP_TRANSPORT=_sqli_transport
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_ERROR-01 x)" \
  "one error finding on the all-vulnerable param - FAILS if a shared check id collapsed the three"
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_BOOLEAN-01 x)" \
  "one boolean finding on the same param - three techniques are three ids, not one deduped finding"
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_TIME-01 x)" \
  "one time finding on the same param - proves the technique is not part of the fingerprint"

# ===========================================================================
printf '== dast sqli: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
_new_run coverage
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
_dast_sqli_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-SQLI_ERROR-01' \
  "checks_run records the error check that executed over a parameter (AGENTS.md's definition), so modules/dast/run.sh's honesty roll-up does not report covered-nothing"
assert_contains "$CR" 'DAST-INJ-SQLI_BOOLEAN-01' 'checks_run records the boolean check'
assert_contains "$CR" 'DAST-INJ-SQLI_TIME-01' 'checks_run records the time check'

# ===========================================================================
printf '== dast sqli: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_sqli_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, sqli emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  "no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast sqli: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
# An empty payload directory (a broken or deliberately trimmed install): every
# technique loses its payloads, so nothing runs, the run records it, and the
# phase RETURNS CLEANLY rather than erroring (docs/DESIGN.md §15).
mkdir -p "$W/empty-payloads"
_new_run degrade
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
rc=0
STDERR=$W/degrade.stderr
SCOURSH_DAST_SQLI_PAYLOAD_DIR=$W/empty-payloads _dast_sqli_phase 2>"$STDERR" || rc=$?
assert_eq 0 "$rc" \
  "an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "no payloads means no finding is emitted"
assert_contains "$(run_facts coverage_reduction)" 'sqli_payloads_missing' \
  "each technique's absent payload file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no SQL-injection payloads are available' \
  "with every technique's payloads gone, a coverage_gap says so - a clean result here is not a clean bill of health"
assert_not_contains "$(cat "$STDERR")" 'error scoursh:' \
  "the missing-payload-file degradation path never fires lib/core.sh's ERR trap - FAILS under _sqli_read_payload_file's pre-fix bare \`return 1\`, which reaches the trap from inside an unguarded process substitution and prints 'error scoursh: command failed' even though every assertion above already reads as a clean, non-erroring degrade"

# A single missing technique degrades ONLY that technique. Give the override dir
# just the boolean payloads and the error signatures+payloads; drop the time file.
mkdir -p "$W/partial-payloads"
cp "$ROOT/modules/dast/payloads/sqli-error-signatures.txt" "$W/partial-payloads/"
cp "$ROOT/modules/dast/payloads/sqli-error-payloads.txt" "$W/partial-payloads/"
cp "$ROOT/modules/dast/payloads/sqli-boolean-pairs.txt" "$W/partial-payloads/"
_new_run partial
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_SQLI_PAYLOAD_DIR=$W/partial-payloads _dast_sqli_phase
assert_eq 1 "$(_count_finding DAST-INJ-SQLI_ERROR-01 q)" \
  "error-based still runs when only the time payloads are missing - a missing file degrades ONLY its own technique"
assert_eq 0 "$(_count_finding DAST-INJ-SQLI_TIME-01 name)" \
  "time-based does NOT run without its payload file - FAILS if a technique reports on a param it never probed"
assert_contains "$(run_facts coverage_reduction)" 'technique=time' \
  "the missing time payloads are recorded as a technique=time coverage_reduction"
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-SQLI_TIME-01' \
  "checks_run does NOT claim the time check ran when its payloads were absent"

# ===========================================================================
printf '== dast sqli: every request is non-destructive (read-only payloads) ==\n'
# ===========================================================================
_new_run readonly
_write_full_inventory
_dast_sqli_phase
# The request log records METHOD + PATH; the bodies/queries are what carry the
# payload, so assert against everything the transport ever saw by re-scanning
# the payload files directly: no shipped payload may carry a write verb.
#
# The log is still read first, for one reason: the payload-file scan below is
# VACUOUSLY true on a run that sent nothing at all, so "the phase actually
# issued requests" has to be asserted or a phase broken into silence would
# certify itself non-destructive.  (This replaces a `REQTEXT=$(cat ...)` that
# was assigned and never read - a dead variable shellcheck flagged as SC2034,
# and the missing assertion it was evidently meant to carry.)
REQTEXT=$(cat "$REQ_LOG" 2>/dev/null || true)
assert_ne '' "$REQTEXT" \
  'the read-only case really did send requests - FAILS if the phase goes silent, which would make the non-destructive assertion below vacuous'
BADVERB=0
for pf in "$ROOT"/modules/dast/payloads/sqli-*.txt; do
  if grep -Eiq '\b(DROP|DELETE|INSERT|UPDATE|TRUNCATE|ALTER|CREATE|GRANT|EXEC|xp_cmdshell)\b' "$pf"; then
    BADVERB=1
  fi
done
assert_eq 0 "$BADVERB" \
  "no vendored SQLi payload carries a destructive/write verb - FAILS the moment a DROP/DELETE/UPDATE/INSERT is added, which docs/DESIGN.md §7.3's non-destructive contract forbids"

# ===========================================================================
printf '== inject_engine: unit checks ==\n'
# ===========================================================================
inject_urlencode "1' AND SLEEP(3)-- -"
assert_contains "$_INJ_ENC" '%27' "inject_urlencode percent-encodes a single quote"
assert_contains "$_INJ_ENC" 'SLEEP' "inject_urlencode leaves an unreserved word (SLEEP) intact"
assert_not_contains "$_INJ_ENC" ' ' "inject_urlencode encodes spaces"

# `if/then/else`, not `A && _t_ok ... || _t_no ...` (SC2015): in the `&&`/`||`
# spelling `_t_no` also runs whenever `_t_ok` itself exits non-zero, so a
# passing case could record a failure as well as a pass.  The negative case on
# the next line already had this shape; both now match.
if inject_len_similar 500 501; then _t_ok "inject_len_similar: 500 vs 501 are the same size"; else _t_no "len_similar 500/501" "should be within tolerance"; fi
if inject_len_similar 500 60; then _t_no "len_similar 500/60" "500 vs 60 must NOT be similar"; else _t_ok "inject_len_similar: 500 vs 60 differ meaningfully"; fi

inject_body_sig 'aXXXbXXXc' 'XXX'
assert_eq 3 "$_INJ_SIG_LEN" \
  "inject_body_sig strips the injected value before measuring, so a reflected payload is not read as a differential"

_write_full_inventory
inject_inventory_load "$W/endpoints.json" "$W/parameters.json"
assert_eq 7 "$_INJ_N" \
  "inject_inventory_load reads all 7 parameters and joins each to its endpoint - FAILS if a parameter whose endpoint row exists is dropped"

t_summary dast-sqli
