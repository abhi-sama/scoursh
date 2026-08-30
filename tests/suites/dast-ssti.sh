#!/usr/bin/env bash
# tests/suites/dast-ssti.sh - modules/dast/active/ssti.sh and its shared
# modules/dast/active/inject_engine.sh: server-side template injection detected
# from an EVALUATED arithmetic result (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-18, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"). The suite runs on a host with no
# network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.
#
#   1. THE PAIR. Every one of the four engine families is pinned by TWO
#      recorded responses on two endpoints: one that EVALUATES the expression
#      (a finding, under that family's own check id) and one that REFLECTS the
#      expression back unevaluated (no finding). A probe that flagged mere
#      reflection - which is what almost every parameter on almost every real
#      application does - passes the first half of every pair and fails the
#      second.
#   2. The family that fired decides the check id: a `${...}`-evaluating
#      endpoint yields DAST-INJ-SSTI_DOLLAR-01 and never the BRACES id.
#   3. A naive sanitiser that merely deletes the template delimiters is still
#      not a finding, because the signature shares no digit with the payload.
#   4. A baseline that already carries the signature is skipped, not flagged.
#   5. First confirmed family wins per parameter - the remaining families are
#      not sent, asserted on the REQUEST LOG rather than on a return value.
#   6. READ-ONLY: every request is a GET, and every request carrying any
#      percent-encoded byte carries exactly one of the four shipped arithmetic
#      payloads - nothing else ever left this probe.
#   7. The inventory is read from $SCOURSH_RUN_DIR/inventory/*.json directly
#      when SCOURSH_DAST_ENDPOINTS/PARAMETERS are empty - the documented
#      first-run state - rather than reporting a clean run.
#   8. Every skip path records a NAMED reason, and checks_run carries only the
#      family ids that really executed.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes template/parameter syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# shellcheck source=modules/dast/active/inject_engine.sh
source "$ROOT/modules/dast/active/inject_engine.sh"
# The REAL dast_check_selected (modules/dast/engine.sh section 3a), rather than
# a stub of it. Its whole-line membership test and its permissive unset/empty
# fallback are the two halves this probe's per-family gate depends on, and a
# stub would re-implement exactly the thing under test. Sourcing this file has
# no side effect beyond declarations - it carries its own sourced-once guard
# and dast_run_phase is only ever called explicitly - so the phase table is
# loaded but no phase runs.
#
# -x back-edge cut: modules/dast/engine.sh sources modules/sast/engine.sh and
# lib/checks.sh, an entire second subtree on top of the lib/http.sh diamond
# this file already carries through inject_engine.sh. `shellcheck -x` does not
# memoise, so following it here re-expands that whole tree inside an entry
# point measured at 9.8 GB WITHOUT it (AGENTS.md, "a DIAMOND in a perfectly
# acyclic graph"), which is what put the stage over its per-process budget.
# Nothing is lost: modules/dast/engine.sh is its own entry point in the
# whole-tree stage and is checked there. The directive is static only - the
# real function is still sourced and still runs.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-ssti-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: ssti-fixture
base-url: https://ssti.fixture.example/
notes: Fixture target for tests/suites/dast-ssti.sh. Never dialled: both the
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

_ssti_resolve() { case $1 in ssti.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_ssti_resolve

# ---------------------------------------------------------------------------
# The four shipped payloads, as the transport actually receives them.
# ---------------------------------------------------------------------------
# inject_urlencode keeps only [A-Za-z0-9._~-], so each payload arrives
# percent-encoded. These constants are asserted against the shipped payload
# file at the bottom of this suite, so a payload edit that changes the wire
# form fails HERE rather than silently making every mock endpoint unreachable
# and turning the whole suite green on a probe that tests nothing.
ENC_BRACES='sstiqzx%7B%7B29%2A31%7D%7Dsstiqzx'
ENC_DOLLAR='sstiqzx%24%7B29%2A31%7Dsstiqzx'
ENC_ERB='sstiqzx%3C%25%3D%2029%2A31%20%25%3Esstiqzx'
ENC_SMARTY='sstiqzx%7B29%2A31%7Dsstiqzx'
SIG='sstiqzx899sstiqzx'

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# One PAIR per family plus three shared controls:
#   /<fam>-vuln  - EVALUATES that family's syntax only: the response carries
#                  the sentinel-wrapped PRODUCT.
#   /<fam>-echo  - REFLECTS the payload back DECODED and unevaluated (what a
#                  real search box does). Must never flag.
#   /strip       - a naive sanitiser: deletes the template delimiters and
#                  echoes the rest. Must never flag.
#   /noisy       - the signature is on EVERY response, baseline included, so
#                  nothing changed after injection. Must never flag.
#   /clean       - nothing at all.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

PLAIN_BODY='<html><body>Report generated.</body></html>'

# A pure-bash percent-decoder, so the ECHO controls reflect what a real
# application would - the DECODED expression - rather than the wire form. The
# fixture payloads carry no backslash, which is the one byte this shape cannot
# round-trip.
_ssti_urldecode() {
  local s=${1//+/ }
  printf '%b' "${s//%/\\x}"
}

_ssti_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 out=$PLAIN_BODY decoded
  case $path in
    /braces-vuln*)
      [[ $surface == *"$ENC_BRACES"* ]] && out="<html><body>Hello, $SIG.</body></html>"
      ;;
    /dollar-vuln*)
      [[ $surface == *"$ENC_DOLLAR"* ]] && out="<html><body>Hello, $SIG.</body></html>"
      ;;
    /erb-vuln*)
      [[ $surface == *"$ENC_ERB"* ]] && out="<html><body>Hello, $SIG.</body></html>"
      ;;
    /smarty-vuln*)
      # Anchored on the sentinel so the DOUBLE-brace payload cannot satisfy it:
      # `sstiqzx%7B%7B29...` does not contain `sstiqzx%7B29...`.
      [[ $surface == *"$ENC_SMARTY"* ]] && out="<html><body>Hello, $SIG.</body></html>"
      ;;
    /*-echo*)
      # Reflects the DECODED payload verbatim - the expression, never its
      # result. This is the control the whole check turns on.
      decoded=$(_ssti_urldecode "$surface")
      out="<html><body>You searched for: ${decoded//$'\n'/ }</body></html>"
      ;;
    /strip*)
      # A naive sanitiser: delete every template delimiter, echo the rest. The
      # product's digits are still nowhere in what comes back.
      decoded=$(_ssti_urldecode "$surface")
      decoded=${decoded//[\{\}\$\<\>\%\=]/}
      out="<html><body>You searched for: ${decoded//$'\n'/ }</body></html>"
      ;;
    /noisy*)
      out="<html><body>cached: $SIG</body></html>"
      ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_ssti_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
# Every `example` is plain alphanumeric on purpose: a baseline request then
# carries NO percent-encoded byte, which is what lets the read-only assertion
# below say "every request that carries any %-escape carries a shipped
# arithmetic payload and nothing else".
_write_full_inventory() {
  local dir=$1
  mkdir -p "$dir"
  cat >"$dir/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_bv", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/braces-vuln", "path": "/braces-vuln" },
  { "id": "ep_be", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/braces-echo", "path": "/braces-echo" },
  { "id": "ep_dv", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/dollar-vuln", "path": "/dollar-vuln" },
  { "id": "ep_de", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/dollar-echo", "path": "/dollar-echo" },
  { "id": "ep_ev", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/erb-vuln", "path": "/erb-vuln" },
  { "id": "ep_ee", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/erb-echo", "path": "/erb-echo" },
  { "id": "ep_sv", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/smarty-vuln", "path": "/smarty-vuln" },
  { "id": "ep_se", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/smarty-echo", "path": "/smarty-echo" },
  { "id": "ep_st", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/strip", "path": "/strip" },
  { "id": "ep_nz", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/noisy", "path": "/noisy" },
  { "id": "ep_ok", "target": "ssti-fixture", "method": "GET", "url": "https://ssti.fixture.example/clean", "path": "/clean" }
] }
EOF
  cat >"$dir/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "q1",  "endpoint_id": "ep_bv", "target": "ssti-fixture", "name": "bv", "location": "query", "example": "hello" },
  { "id": "q2",  "endpoint_id": "ep_be", "target": "ssti-fixture", "name": "be", "location": "query", "example": "hello" },
  { "id": "q3",  "endpoint_id": "ep_dv", "target": "ssti-fixture", "name": "dv", "location": "query", "example": "hello" },
  { "id": "q4",  "endpoint_id": "ep_de", "target": "ssti-fixture", "name": "de", "location": "query", "example": "hello" },
  { "id": "q5",  "endpoint_id": "ep_ev", "target": "ssti-fixture", "name": "ev", "location": "query", "example": "hello" },
  { "id": "q6",  "endpoint_id": "ep_ee", "target": "ssti-fixture", "name": "ee", "location": "query", "example": "hello" },
  { "id": "q7",  "endpoint_id": "ep_sv", "target": "ssti-fixture", "name": "sv", "location": "query", "example": "hello" },
  { "id": "q8",  "endpoint_id": "ep_se", "target": "ssti-fixture", "name": "se", "location": "query", "example": "hello" },
  { "id": "q9",  "endpoint_id": "ep_st", "target": "ssti-fixture", "name": "st", "location": "query", "example": "hello" },
  { "id": "q10", "endpoint_id": "ep_nz", "target": "ssti-fixture", "name": "nz", "location": "query", "example": "hello" },
  { "id": "q11", "endpoint_id": "ep_ok", "target": "ssti-fixture", "name": "ok", "location": "query", "example": "hello" }
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
  run_record authorization_affirmed true
  run_record authorization_target ssti-fixture
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

# `_count_finding CHECK PARAM` counts findings whose `check_id` AND
# `loc_param_name` fields both match EXACTLY. Field equality, never a substring
# of the shard text: a finding carries its own remediation and evidence prose,
# and this family's evidence quotes the payload, so a substring test over the
# shard would answer a different question than the one being asked (the lesson
# tests/suites/dast-authz.sh records for its own `_shard_check_ids`).
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

# Every finding on PARAM, whatever its check id.
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

# Requests logged against one endpoint path.
_req_count_path() {
  local p=$1 n=0 line
  while IFS= read -r line; do
    [[ $line == *" $p"* ]] && n=$(( n + 1 ))
  done <"$REQ_LOG"
  printf '%s' "$n"
}

_req_total() { local n=0; while IFS= read -r _; do n=$(( n + 1 )); done <"$REQ_LOG"; printf '%s' "$n"; }

# ---------------------------------------------------------------------------
# Load the phase's functions. A phase script has no sourced-once guard and runs
# _dast_ssti_phase at source time (that is how dast_run_phase invokes it), so it
# is sourced once here against a throwaway run with no inventory - a harmless
# no-op that records a gap - and re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=ssti-fixture
SCOURSH_DAST_CELL=ssti-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/ssti.sh
source "$ROOT/modules/dast/active/ssti.sh"

# ===========================================================================
printf '== dast ssti: the PAIR - every family fires when EVALUATED and stays silent when merely REFLECTED ==\n'
# ===========================================================================
_write_full_inventory "$W/inv-main"
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_dast_ssti_phase

assert_eq 1 "$(_count_finding DAST-INJ-SSTI_BRACES-01 bv)" \
  'the {{...}}-evaluating endpoint yields exactly one BRACES finding - FAILS if the probe never checks the evaluated result, or emits more than one finding per parameter'
assert_eq 0 "$(_count_param be)" \
  'the {{...}}-REFLECTING endpoint yields NO finding: it echoes the expression back unevaluated - FAILS under a probe that treats reflection of the payload as the signal, which is what almost every real parameter does'

assert_eq 1 "$(_count_finding DAST-INJ-SSTI_DOLLAR-01 dv)" \
  'the ${...}-evaluating endpoint yields exactly one DOLLAR finding - FAILS if only the FIRST vendored family is ever sent'
assert_eq 0 "$(_count_finding DAST-INJ-SSTI_BRACES-01 dv)" \
  'the ${...}-evaluating endpoint yields the DOLLAR id and NOT the BRACES id - FAILS under a single shared check id, which would collide the two engines on one fingerprint and let findings_merge drop whichever sorted second'
assert_eq 0 "$(_count_param de)" \
  'the ${...}-REFLECTING endpoint yields NO finding'

assert_eq 1 "$(_count_finding DAST-INJ-SSTI_ERB-01 ev)" \
  'the <%= ... %>-evaluating endpoint yields exactly one ERB finding'
assert_eq 0 "$(_count_param ee)" \
  'the <%= ... %>-REFLECTING endpoint yields NO finding'

assert_eq 1 "$(_count_finding DAST-INJ-SSTI_SMARTY-01 sv)" \
  'the single-brace {...}-evaluating endpoint yields exactly one SMARTY finding - FAILS if the double-brace payload is allowed to satisfy the single-brace match'
assert_eq 0 "$(_count_param se)" \
  'the single-brace {...}-REFLECTING endpoint yields NO finding'

assert_eq 0 "$(_count_param st)" \
  'a naive sanitiser that DELETES the template delimiters and echoes the rest yields NO finding - FAILS if the signature could be manufactured out of the payload bytes; it cannot, because the digit 8 is in every signature and in no payload'
assert_eq 0 "$(_count_param nz)" \
  'NO finding where the signature is already on the BASELINE (a noisy parameter, nothing changed after injection) - FAILS if the probe flags without comparing to a clean baseline first'
assert_eq 0 "$(_count_param ok)" \
  'the control parameter yields no finding - FAILS if any probe flags a non-vulnerable parameter'

# ===========================================================================
printf '== dast ssti: read-only request log, and nothing but arithmetic left the probe ==\n'
# ===========================================================================
# Asserted on the REQUEST LOG, never on a return value: "it sent only safe
# payloads" must not be satisfiable by a probe that sent something else and
# then reported that it had not.
NON_GET=$(grep -cvE '^GET ' "$REQ_LOG" || true)
assert_eq 0 "$NON_GET" \
  'every request this probe sent is a GET - FAILS if any payload were delivered by a method that could mutate target state'

ENC_LINES=$(grep -c '%' "$REQ_LOG" || true)
KNOWN_LINES=$(grep -cE "$ENC_BRACES|$ENC_DOLLAR|$ENC_ERB|$ENC_SMARTY" "$REQ_LOG" || true)
assert_ne 0 "$ENC_LINES" 'the probe did send percent-encoded payloads at all (a probe that sent none would satisfy the next assertion vacuously)'
assert_eq "$ENC_LINES" "$KNOWN_LINES" \
  'EVERY request carrying any percent-encoded byte carries exactly one of the four SHIPPED arithmetic payloads - FAILS the moment any non-arithmetic payload (a file read, a command, a gadget chain) is added to this probe'

for forbidden in 'etc%2Fpasswd' 'sleep' 'DROP' 'DELETE' 'UPDATE' 'INSERT' '__proto__' 'self.__init__' 'getRuntime' 'popen'; do
  assert_not_contains "$(cat "$REQ_LOG")" "$forbidden" \
    "no request carries '$forbidden' - the payload set is arithmetic-only, reads no file, runs no command and walks no object graph"
done

# ===========================================================================
printf '== dast ssti: first confirmed family wins - the rest are NOT sent to that parameter ==\n'
# ===========================================================================
# /braces-vuln confirms on the FIRST family, so it costs 1 baseline + 1 probe.
# /clean confirms on none, so it costs 1 baseline + all 4 probes. Comparing the
# two is what distinguishes "stopped early" from "sent everything and reported
# once", which an assertion on the finding count alone cannot do.
assert_eq 2 "$(_req_count_path /braces-vuln)" \
  'the {{...}} endpoint costs exactly 2 requests (baseline + the first family, which confirms) - FAILS under a probe that keeps sending the remaining three families after a confirmation, which is three requests of avoidable traffic against an authorised target per parameter'
assert_eq 5 "$(_req_count_path /clean)" \
  'a parameter that confirms nothing costs 1 baseline + all 4 families - FAILS if the probe stops early on a NON-confirmation, which would leave three engine families untested while still reading as a clean result'
assert_eq 1 "$(_req_count_path /noisy)" \
  'a noisy baseline costs exactly ONE request: the baseline itself, after which the parameter is abandoned - FAILS if a parameter whose signal can never be attributed is probed anyway'

# ===========================================================================
printf '== dast ssti: checks_run records what EXECUTED, and nothing else ==\n'
# ===========================================================================
CR=$(run_facts checks_run)
for id in DAST-INJ-SSTI_BRACES-01 DAST-INJ-SSTI_DOLLAR-01 DAST-INJ-SSTI_ERB-01 DAST-INJ-SSTI_SMARTY-01; do
  assert_contains "$CR" "$id" \
    "checks_run records $id, whose payload really went out over at least one parameter (lib/records.sh's own definition of the field)"
done

# ===========================================================================
printf '== dast ssti: a family that never executed is a NAMED reduction, not silence ==\n'
# ===========================================================================
# Only BRACES is selected, so the other three are never sent. Recording all
# four in checks_run here would claim three checks ran that did not - DAST-29's
# own H3 defect, which is the most expensive way for this module to be wrong.
_new_run selected
SCOURSH_SELECTED_CHECKS=$'DAST-INJ-SSTI_BRACES-01\n'
export SCOURSH_SELECTED_CHECKS
_dast_ssti_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-SSTI_BRACES-01' 'the selected family still runs'
assert_not_contains "$CR" 'DAST-INJ-SSTI_DOLLAR-01' \
  'checks_run does NOT name a family the filter chain excluded - FAILS under a reading that writes all four ids unconditionally, which reports coverage the run never had'
RED=$(run_facts coverage_reduction)
assert_contains "$RED" 'reason=check_not_selected check=DAST-INJ-SSTI_DOLLAR-01' \
  'a deselected family records a named coverage_reduction'
assert_contains "$RED" 'reason=ssti_family_not_applicable check=DAST-INJ-SSTI_ERB-01' \
  'a family that never executed records ssti_family_not_applicable naming it - FAILS if its absence from the findings is left to read as a clean result for that engine'
assert_eq 1 "$(_count_finding DAST-INJ-SSTI_BRACES-01 bv)" 'the selected family still finds its vulnerable parameter'
assert_eq 0 "$(_count_param dv)" 'a deselected family emits nothing even against a vulnerable parameter'
assert_eq 0 "$(grep -cE "$ENC_DOLLAR|$ENC_ERB|$ENC_SMARTY" "$REQ_LOG" || true)" \
  'a deselected family sends NO request at all - asserted on the request log, because a probe that dialled the target and then declined to report is exactly what per-check selection exists to prevent'

# Every family deselected: nothing is sent at all and the run says so.
_new_run noneselected
SCOURSH_SELECTED_CHECKS=$'DAST-DISC-BACKUP-01\n'
_dast_ssti_phase
assert_eq 0 "$(_req_total)" \
  'with every family excluded the probe sends ZERO requests - FAILS under a reading that enters the parameter loop and sends baselines for checks it will never run'
assert_contains "$(run_facts coverage_gap)" 'every template-engine family was excluded' \
  'an all-excluded run records a coverage_gap rather than looking like a clean scan'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" 'checks_run is empty when nothing executed'

# THE OTHER DIRECTION, and it is the one that fails invisibly. When
# dast_check_selected does not exist in the process at all - which is every
# direct-engine suite in this tree, and any path that reaches a phase script
# without modules/dast/engine.sh - the `declare -F` guard must fall through to
# PERMISSIVE. A fail-closed guard (or an unguarded call, which is exit 127 and
# therefore reads as "deselected") makes the whole phase inert while every
# "stays quiet" assertion in this file still passes green.
_new_run guardabsent
SCOURSH_SELECTED_CHECKS=$'DAST-DISC-BACKUP-01\n'
_ssti_saved_sel=$(declare -f dast_check_selected)
unset -f dast_check_selected
_dast_ssti_phase
assert_eq 1 "$(_count_finding DAST-INJ-SSTI_BRACES-01 bv)" \
  'with dast_check_selected ABSENT the phase still probes and still finds - FAILS under a fail-closed guard or an unguarded call, either of which silently makes every direct-engine run of this phase inert while looking exactly like a clean scan'
eval "$_ssti_saved_sel"
unset SCOURSH_SELECTED_CHECKS

# ===========================================================================
printf '== dast ssti: reads the run-directory inventory directly (the first-run state) ==\n'
# ===========================================================================
# modules/dast/run.sh exports SCOURSH_DAST_ENDPOINTS/PARAMETERS BEFORE crawl.sh
# writes them, so on an ordinary run the export is EMPTY at the moment this
# phase runs even though the inventory now exists on disk. A probe that trusted
# the export alone would see no surface here and report a clean, untested run -
# the exact overstated coverage docs/DESIGN.md §15 forbids.
_new_run rundirect
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_write_full_inventory "$SCOURSH_RUN_DIR/inventory"
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_ssti_phase
assert_eq 1 "$(_count_finding DAST-INJ-SSTI_BRACES-01 bv)" \
  'with SCOURSH_DAST_ENDPOINTS/PARAMETERS empty but reports/<run>/inventory/*.json present, the phase still finds and tests the parameters - FAILS under a reading that trusts the export alone and reports clean on the ordinary first run'
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS

# ===========================================================================
printf '== dast ssti: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_ssti_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  'with no inventory, ssti emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids'
assert_contains "$(run_facts coverage_reduction)" 'reason=no_parameter_inventory' \
  'an absent inventory is a NAMED coverage_reduction'
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  'no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run is EMPTY when nothing was tested - recording it here would overstate coverage'
assert_eq 0 "$(_req_total)" 'no inventory means no request was sent'
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json

# ===========================================================================
printf '== dast ssti: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade
rc=0
SCOURSH_DAST_SSTI_PAYLOAD_DIR=$W/empty-payloads _dast_ssti_phase || rc=$?
assert_eq 0 "$rc" \
  'an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'no payloads means no finding is emitted'
assert_eq 0 "$(_req_total)" 'no payloads means no request was sent'
assert_contains "$(run_facts coverage_reduction)" 'reason=ssti_payloads_missing' \
  'the absent expression file is a recorded coverage_reduction, not a silent skip'
assert_contains "$(run_facts coverage_gap)" 'no template-injection probe was sent' \
  'with no payloads a coverage_gap says so - a clean result here is not a clean bill of health'
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  'checks_run does NOT claim the check ran when its payloads were absent'

# ===========================================================================
printf '== dast ssti: a payload row for an unregistered family is refused and recorded ==\n'
# ===========================================================================
# A finding minted under a check id that exists in no *.rules file is invisible
# to tension 15's filter chain and uncountable by tension 12's coverage, so the
# row is REFUSED rather than sent. Silently sending it would put a payload on a
# live system under an id the operator can neither select nor exclude.
mkdir -p "$W/unknown-family"
printf 'braces\tsstiqzx{{29*31}}sstiqzx\tsstiqzx899sstiqzx\n' >"$W/unknown-family/ssti-expressions.txt"
printf 'velocity\tsstiqzx#set($x=29*31)${x}sstiqzx\tsstiqzx899sstiqzx\n' >>"$W/unknown-family/ssti-expressions.txt"
_new_run unknownfam
rc=0
SCOURSH_DAST_SSTI_PAYLOAD_DIR=$W/unknown-family _dast_ssti_phase || rc=$?
assert_eq 0 "$rc" 'an unregistered family in the payload file does not error'
assert_contains "$(run_facts coverage_reduction)" 'reason=ssti_unknown_payload_family family=velocity' \
  'a row naming a family this build ships no check id for is a NAMED reduction - FAILS if it is silently dropped, or silently sent under an id no rule file declares'
assert_eq 0 "$(grep -c 'set(' "$REQ_LOG" || true)" \
  'the unregistered payload was never sent - asserted on the request log'
assert_eq 1 "$(_count_finding DAST-INJ-SSTI_BRACES-01 bv)" \
  'the registered row in the same file still runs - FAILS if one bad row disables the whole probe'

# ===========================================================================
printf '== dast ssti: the shipped payload file and its check ids agree ==\n'
# ===========================================================================
PF=$ROOT/modules/dast/payloads/ssti-expressions.txt
assert_file_exists "$PF" 'the vendored expression set ships in modules/dast/payloads/'

ROWS=$(grep -Ecv '^[[:space:]]*(#|$)' "$PF")
assert_eq 4 "$ROWS" 'the shipped file carries exactly the four documented engine families'

# THE INVARIANT THE WHOLE CHECK RESTS ON, re-derived from the file rather than
# trusted from a comment: every signature contains the digit `8` and no payload
# does, so no delete/reorder/re-encode/partial-strip of what was SENT can
# manufacture the RESULT. A payload edit that broke it would make this probe a
# reflection detector - a false-positive generator - and every "stays quiet"
# assertion above would still pass.
while IFS=$'\t' read -r fam payload sig; do
  [[ -n $fam ]] || continue
  [[ ${fam:0:1} == '#' ]] && continue
  assert_not_contains "$payload" '8' \
    "payload for family '$fam' contains no digit 8, which the signature does - so no transformation of the sent bytes can produce the result"
  assert_contains "$sig" '899' "the signature for family '$fam' is the sentinel wrapped around the evaluated product 29*31"
  assert_not_contains "$payload" '899' "the evaluated product is not a substring of family '$fam''s own payload"
  assert_contains "$payload" 'sstiqzx' "family '$fam''s payload carries the sentinel on which the signature is anchored"
  # The product is deliberately below 1000: FreeMarker and every other
  # locale-formatting engine groups from four digits up, so `73,109,819` would
  # never match a plain-digit signature - a MISS, which reads as a clean result.
  assert_not_contains "$sig" ',' "family '$fam''s signature carries no grouping separator, which is why the product is kept under 1000"
  ID=$(_ssti_check_id_for_family "$fam")
  assert_contains "$(cat "$ROOT/modules/dast/active/checks.rules")" "id: $ID" \
    "family '$fam' maps to $ID, which is a real record in modules/dast/active/checks.rules - FAILS if a payload could be sent under a check id tension 15 cannot filter"
done < <(grep -Ev '^[[:space:]]*(#|$)' "$PF")

# The wire forms this suite's mock target matches on are derived from the
# shipped payloads rather than assumed, so a payload edit fails HERE instead of
# quietly making every mock endpoint unreachable and turning the suite green on
# a probe that tests nothing.
_ssti_read_payloads_file "$PF"
for k in 0 1 2 3; do
  inject_urlencode "${_SSTI_PAYLOAD[$k]}"
  case ${_SSTI_FAMILY[$k]} in
    braces) assert_eq "$ENC_BRACES" "$_INJ_ENC" 'the braces payload encodes to the wire form this suite drives the mock target with' ;;
    dollar) assert_eq "$ENC_DOLLAR" "$_INJ_ENC" 'the dollar payload encodes to the wire form this suite drives the mock target with' ;;
    erb)    assert_eq "$ENC_ERB"    "$_INJ_ENC" 'the erb payload encodes to the wire form this suite drives the mock target with' ;;
    smarty) assert_eq "$ENC_SMARTY" "$_INJ_ENC" 'the smarty payload encodes to the wire form this suite drives the mock target with' ;;
  esac
done

# ===========================================================================
printf '== dast ssti: the emitting script and the check registry agree on severity ==\n'
# ===========================================================================
# `severity` is a per-record property of the registry (rules/RULE-FORMAT.md
# §9.5), so a phase that set a different base_severity at runtime would put the
# two into disagreement - and a severity that varied with context would have to
# be a SECOND check id rather than a number the script raises, because check_id
# is a fingerprint component (DAST-11's own lesson, which every DAST suite
# pins). Read from the shipped .rules file rather than restated here, so a
# registry edit that forgets the script fails.
declare -A REG_SEV=()
_reg_id=''
while IFS= read -r line; do
  case $line in
    'id: '*)       _reg_id=${line#id: } ;;
    'severity: '*) [[ -n $_reg_id ]] && REG_SEV[$_reg_id]=${line#severity: } ;;
  esac
done <"$ROOT/modules/dast/active/checks.rules"

# `_field_of CHECK FIELD` - one field of the single finding carrying CHECK.
_field_of() {
  local check=$1 want=$2 f line fld hit=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ $line == *"check_id=$check"* ]] || continue
      local IFS=$'\t'
      local ok=0 val=''
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && ok=1
        [[ $fld == "$want="* ]] && val=${fld#"$want="}
      done
      (( ok )) && hit=$val
    done <"$f"
  done
  printf '%s' "$hit"
}

_new_run severity
_dast_ssti_phase
for id in DAST-INJ-SSTI_BRACES-01 DAST-INJ-SSTI_DOLLAR-01 DAST-INJ-SSTI_ERB-01 DAST-INJ-SSTI_SMARTY-01; do
  assert_eq "${REG_SEV[$id]:-<absent in registry>}" "$(_field_of "$id" base_severity)" \
    "$id: the severity the script emits equals the one modules/dast/active/checks.rules declares"
  assert_eq CWE-1336 "$(_field_of "$id" cwe)" \
    "$id: mapped to CWE-1336 (template-engine injection), with CWE-94 carried in the record's references"
  assert_eq A03:2021 "$(_field_of "$id" owasp)" "$id: mapped to OWASP A03:2021 Injection"
done
assert_contains "$(cat "$ROOT/modules/dast/active/checks.rules")" 'references: CWE-94' \
  'the records carry CWE-94 (code injection) as the parent CWE-1336 specialises'

# ===========================================================================
printf '== dast ssti: registered as a phase and as a suite ==\n'
# ===========================================================================
assert_contains "$(cat "$ROOT/modules/dast/engine.sh")" "'active/ssti.sh:active'" \
  "modules/dast/engine.sh's _DAST_PHASES carries the row at tier active, so a scan_dispatch dast run reaches this phase - a phase script with no row is dead code"
assert_contains "$(grep '^SUITES=' "$ROOT/tests/run-tests.sh")" 'dast-ssti' \
  'this suite is registered in tests/run-tests.sh SUITES, so a full run executes it'

t_summary dast-ssti
