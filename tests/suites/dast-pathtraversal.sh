#!/usr/bin/env bash
# tests/suites/dast-pathtraversal.sh - modules/dast/active/pathtraversal.sh and
# its shared modules/dast/active/inject_engine.sh: path traversal via a
# benign, read-only marker signature (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-17, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"). The suite runs on a host with no
# network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and
# the rejected reading pins nothing.
#
#   1. a traversal payload whose response matches a marker's own CONTENT
#      signature is a finding - not any response that merely differs from the
#      baseline, and not a response that only echoes the payload STRING back
#      with no marker content in it.
#   2. a baseline that already carries a marker's signature (a noisy
#      parameter) is skipped rather than flagged - the signal has to appear
#      ONLY after injection to mean anything.
#   3. one finding per (endpoint, parameter) pair: the first confirmed marker
#      wins and the probe stops trying the rest of that parameter's
#      combinations.
#   4. the inventory is read from $SCOURSH_RUN_DIR/inventory/*.json directly
#      when SCOURSH_DAST_ENDPOINTS/PARAMETERS are empty - the documented
#      first-run state (AGENTS.md, modules/dast/run.sh exports the two paths
#      BEFORE crawl.sh writes them) - rather than reporting a clean run.
#   5. no parameter surface / missing payloads degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter/path syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# shellcheck source=modules/dast/active/inject_engine.sh
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-pathtraversal-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: pt-fixture
base-url: https://pt.fixture.example/
notes: Fixture target for tests/suites/dast-pathtraversal.sh. Never dialled:
  both the resolver and the transport are stubbed.
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

_pt_resolve() { case $1 in pt.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_pt_resolve

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# One vulnerable parameter per marker, plus controls, decided from the actual
# injected bytes (percent-encoded in the path/query the transport receives -
# inject_urlencode leaves '.' unreserved and encodes '/' as %2F, so a
# traversal value arrives as "..%2F..%2Fetc%2Fpasswd" regardless of depth):
#   /download  file  - VULNERABLE: any depth of ../ reaching etc/passwd
#                       returns real passwd-shaped content.
#   /winreport f     - VULNERABLE: any depth reaching windows/win.ini returns
#                       real win.ini-shaped content.
#   /echo      q     - control: ECHOES the raw payload text back (a page that
#                       reflects the traversal string, not the file) - must
#                       NOT flag.
#   /noisy     n     - control: the BASELINE (and every response) already
#                       contains the /etc/passwd signature - a noisy
#                       parameter, must NOT flag (nothing changed after
#                       injection).
#   /clean     safe  - control: never any signature, never an echo.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

PASSWD_BODY=$'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
WININI_BODY=$'[fonts]\r\nMS Sans Serif (TrueType)=micross.ttf\r\n'
PLAIN_BODY='<html><body>Report generated.</body></html>'

_pt_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 out=$PLAIN_BODY
  case $path in
    /download*)
      [[ $surface == *etc%2Fpasswd* ]] && out=$PASSWD_BODY
      ;;
    /winreport*)
      [[ $surface == *windows%2Fwin.ini* ]] && out=$WININI_BODY
      ;;
    /echo*)
      # Reflects the raw query string (the payload STRING) back - never the
      # marker's real content, however deep the traversal or whichever
      # marker it names.
      out="<html><body>You searched for: $(printf '%s' "$surface" | tr -d '\n')</body></html>"
      ;;
    /noisy*)
      # The passwd signature is present on EVERY response, baseline included -
      # nothing changes after injection, so this must never flag.
      out=$PASSWD_BODY
      ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_pt_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  local dir=$1
  mkdir -p "$dir"
  cat >"$dir/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_download", "target": "pt-fixture", "method": "GET", "url": "https://pt.fixture.example/download", "path": "/download" },
  { "id": "ep_winreport", "target": "pt-fixture", "method": "GET", "url": "https://pt.fixture.example/winreport", "path": "/winreport" },
  { "id": "ep_echo",     "target": "pt-fixture", "method": "GET", "url": "https://pt.fixture.example/echo",     "path": "/echo" },
  { "id": "ep_noisy",    "target": "pt-fixture", "method": "GET", "url": "https://pt.fixture.example/noisy",    "path": "/noisy" },
  { "id": "ep_clean",    "target": "pt-fixture", "method": "GET", "url": "https://pt.fixture.example/clean",    "path": "/clean" }
] }
EOF
  cat >"$dir/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_download",  "target": "pt-fixture", "name": "file", "location": "query", "example": "report.pdf" },
  { "id": "p2", "endpoint_id": "ep_winreport", "target": "pt-fixture", "name": "f",    "location": "query", "example": "notes.txt" },
  { "id": "p3", "endpoint_id": "ep_echo",      "target": "pt-fixture", "name": "q",    "location": "query", "example": "hello" },
  { "id": "p4", "endpoint_id": "ep_noisy",     "target": "pt-fixture", "name": "n",    "location": "query", "example": "1" },
  { "id": "p5", "endpoint_id": "ep_clean",     "target": "pt-fixture", "name": "safe", "location": "query", "example": "ok" }
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
  run_record authorization_target pt-fixture
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
# `loc_param_name` fields both match exactly (the shard `.fields` format is
# one finding per line, TAB-delimited `key=value` fields,
# lib/findings.sh's `_finding_fields`).
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
# Load the phase's functions. A phase script has no sourced-once guard and
# runs _dast_pathtraversal_phase at source time (that is how dast_run_phase
# invokes it), so it is sourced once here against a throwaway run with no
# inventory - a harmless no-op that records a gap - and re-invoked per case
# below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=pt-fixture
SCOURSH_DAST_CELL=pt-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/pathtraversal.sh
source "$ROOT/modules/dast/active/pathtraversal.sh"

# ===========================================================================
printf '== dast pathtraversal: fires on both vulnerable markers, one finding each ==\n'
# ===========================================================================
_write_full_inventory "$W/inv-main"
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_dast_pathtraversal_phase

assert_eq 1 "$(_count_finding DAST-INJ-PATH_TRAVERSAL-01 file)" \
  "exactly one finding on 'file', whose traversal to etc/passwd returns real passwd content - FAILS if the probe never checks the marker signature at all, or if it emits more than one finding per parameter"
assert_eq 1 "$(_count_finding DAST-INJ-PATH_TRAVERSAL-01 f)" \
  "exactly one finding on 'f', whose traversal to windows/win.ini returns real win.ini content - FAILS if only the FIRST vendored marker is ever tried"

assert_eq 0 "$(_count_param q)" \
  "NO finding on 'q': /echo reflects the raw traversal STRING back, never the marker's real content - FAILS if reflection of the payload text alone is read as a signal (the whole point of matching a CONTENT signature rather than the injected bytes)"
assert_eq 0 "$(_count_param n)" \
  "NO finding on 'n': the passwd signature is present on the BASELINE too (a noisy parameter, nothing changed after injection) - FAILS if the probe flags without comparing to a clean baseline first"
assert_eq 0 "$(_count_param safe)" \
  "the control parameter 'safe' yields no finding - FAILS if any probe flags a non-vulnerable parameter"

# ===========================================================================
printf '== dast pathtraversal: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
_new_run coverage
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
_dast_pathtraversal_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-PATH_TRAVERSAL-01' \
  "checks_run records the check that executed over a parameter (AGENTS.md's own definition), so modules/dast/run.sh's honesty roll-up does not report covered-nothing"

# ===========================================================================
printf '== dast pathtraversal: reads the run-directory inventory directly (AC1) ==\n'
# ===========================================================================
# The documented first-run state: modules/dast/run.sh exports
# SCOURSH_DAST_ENDPOINTS/PARAMETERS BEFORE crawl.sh writes them, so on an
# ordinary run the export is EMPTY at the moment this phase runs even though
# the inventory now exists on disk. A probe that trusted the export alone
# would see no surface here and report a clean, untested run - the exact
# overstated coverage docs/DESIGN.md §15 forbids.
_new_run rundirect
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_write_full_inventory "$SCOURSH_RUN_DIR/inventory"
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_pathtraversal_phase
assert_eq 1 "$(_count_finding DAST-INJ-PATH_TRAVERSAL-01 file)" \
  "with SCOURSH_DAST_ENDPOINTS/PARAMETERS empty but reports/<run>/inventory/*.json present, the phase still finds and tests the parameters - FAILS under a reading that trusts the export alone and reports clean on the ordinary first run"
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS

# ===========================================================================
printf '== dast pathtraversal: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_pathtraversal_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, pathtraversal emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  "no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json

# ===========================================================================
printf '== dast pathtraversal: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
rc=0
SCOURSH_DAST_PATHTRAVERSAL_PAYLOAD_DIR=$W/empty-payloads _dast_pathtraversal_phase || rc=$?
assert_eq 0 "$rc" \
  "an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "no payloads means no finding is emitted"
assert_contains "$(run_facts coverage_reduction)" 'pathtraversal_payloads_missing' \
  "the absent template file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_reduction)" 'pathtraversal_markers_missing' \
  "the absent marker file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no path-traversal probe was sent' \
  "with no templates and no markers, a coverage_gap says so - a clean result here is not a clean bill of health"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run does NOT claim the check ran when its payloads were absent"

# A markers-only-missing dir: templates present, no markers - the check still
# degrades cleanly (nothing to detect a signal with) even though it has
# something to send.
mkdir -p "$W/templates-only"
cp "$ROOT/modules/dast/payloads/pathtraversal-sequences.txt" "$W/templates-only/"
_new_run templatesonly
SCOURSH_DAST_ENDPOINTS=$W/inv-main/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/inv-main/parameters.json
rc=0
SCOURSH_DAST_PATHTRAVERSAL_PAYLOAD_DIR=$W/templates-only _dast_pathtraversal_phase || rc=$?
assert_eq 0 "$rc" "templates with no markers does NOT error either"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" "no markers means no finding is emitted, even with templates present"
assert_contains "$(run_facts coverage_reduction)" 'pathtraversal_markers_missing' \
  "the markers-missing reduction fires independently of the templates file's own presence"

# ===========================================================================
printf '== inject_engine + shipped payloads: sanity ==\n'
# ===========================================================================
_write_full_inventory "$W/inv-main"
inject_inventory_load "$W/inv-main/endpoints.json" "$W/inv-main/parameters.json"
assert_eq 5 "$_INJ_N" \
  "inject_inventory_load reads all 5 parameters and joins each to its endpoint"

SEQ_LINES=$(grep -Ecv '^[[:space:]]*(#|$)' "$ROOT/modules/dast/payloads/pathtraversal-sequences.txt")
assert_ne 0 "$SEQ_LINES" "the shipped directory-climb template file is non-empty"
MARK_LINES=$(grep -Ecv '^[[:space:]]*(#|$)' "$ROOT/modules/dast/payloads/pathtraversal-markers.txt")
assert_eq 2 "$MARK_LINES" "the shipped marker file carries exactly the two documented markers (etc/passwd, windows/win.ini)"

t_summary dast-pathtraversal
