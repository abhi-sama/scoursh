#!/usr/bin/env bash
# tests/suites/dast-ldapi.sh - modules/dast/active/ldapi.sh and the shared
# modules/dast/active/inject_engine.sh: error-based and boolean-based (response
# differential) LDAP injection (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md
# DAST-22, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), driven from recorded responses. The suite
# runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.
#
#   1. error-based fires only when an LDAP error surfaces for an injected value
#      and NOT for the benign baseline - not on any 500, and not on the
#      baseline's own errors.
#   2. boolean-based needs the always-match clause to behave like the baseline
#      AND the never-match clause to differ from it - a page that changes for
#      BOTH (or NEITHER) is not a differential.
#   3. the technique is not part of the fingerprint, so two techniques on one
#      parameter are two distinct check ids, not one deduped finding.
#   4. the injected value goes where the parameter's `location` says (query AND
#      body proven here), per docs/DESIGN.md §7.3.
#   5. non-destructive: no vendored payload carries an LDAP write/modify verb.
#   6. no parameter surface / missing payloads degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#   7. there is deliberately NO time-based technique (LDAP has no sleep
#      primitive), so a run records exactly the two checks it can perform.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter/LDAP/JSON syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: modules/dast/active/inject_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-ldapi-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: ldapi-fixture
base-url: https://ldapi.fixture.example/
notes: Fixture target for tests/suites/dast-ldapi.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32 ceiling
# does not clamp the rate to 4/s and the throttle never real-sleeps. A very high
# breaker threshold so the deliberate 500s the error technique provokes never
# open the circuit and abort the run.
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_ldapi_resolve() { case $1 in ldapi.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_ldapi_resolve

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# One vulnerable parameter per technique, plus controls, decided from the actual
# injected bytes (percent-encoded in the path/body the transport receives):
#   /search  q     - ERROR: a filter-breaking paren/backslash provokes a JNDI
#                    NamingException (500).
#   /login   user  - ERROR via a BODY parameter (proves body-location injection).
#   /dir     cn    - BOOLEAN: the never-match sentinel clause returns a short page,
#                    the always-match wildcard clause returns the full listing.
#   /clean   safe  - control: never any signal (same page whatever is injected).
#   /echo    e     - control: reflects the injected value but drives no filter -
#                    the body differs only by the reflected bytes, which the
#                    probe strips before comparing, so it must NOT flag.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

LONG='<html><body><ul><li>alpha</li><li>bravo</li><li>charlie</li><li>delta</li><li>echo</li><li>foxtrot</li><li>golf</li><li>hotel</li></ul></body></html>'
SHORT='<html><body>No entries found.</body></html>'
LDAPERR='<html><body>javax.naming.directory.InvalidSearchFilterException: Bad search filter</body></html>'

# The never-match sentinel the boolean pairs carry (percent-encoded when it
# reaches the transport). Its PRESENCE marks the "false" (contradiction) request.
NOENT='scoursh-no-such-entry-zq'

_ldapi_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 out=$LONG
  case $path in
    /search*)
      # A filter-breaking metacharacter: an unbalanced paren (%28/%29) or an
      # escaping backslash (%5C) - but NOT the sentinel-bearing boolean clauses,
      # which are well-formed filters. Provoke a NamingException.
      if [[ $surface == *"$NOENT"* ]]; then
        out=$SHORT
      elif [[ $surface == *%28* || $surface == *%29* || $surface == *%5C* ]]; then
        status=500; out=$LDAPERR
      fi
      ;;
    /login*)
      if [[ $surface == *"$NOENT"* ]]; then
        out=$SHORT
      elif [[ $surface == *%28* || $surface == *%29* || $surface == *%5C* ]]; then
        status=500; out=$LDAPERR
      fi
      ;;
    /dir*)
      # Boolean: the never-match sentinel returns an empty listing; every other
      # value (baseline, and the always-match wildcard clause) returns the full
      # listing. A well-formed filter, so no error is provoked.
      if [[ $surface == *"$NOENT"* ]]; then out=$SHORT; fi
      ;;
    /echo*)
      # Reflects the raw injected value into the body but runs no LDAP filter, so
      # the ONLY difference between requests is the reflected payload text, which
      # the probe strips before measuring length.
      out="<html><body>you searched for: $body</body></html>"
      ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_ldapi_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_search", "target": "ldapi-fixture", "method": "GET",  "url": "https://ldapi.fixture.example/search", "path": "/search" },
  { "id": "ep_login",  "target": "ldapi-fixture", "method": "POST", "url": "https://ldapi.fixture.example/login",  "path": "/login" },
  { "id": "ep_dir",    "target": "ldapi-fixture", "method": "GET",  "url": "https://ldapi.fixture.example/dir",    "path": "/dir" },
  { "id": "ep_clean",  "target": "ldapi-fixture", "method": "GET",  "url": "https://ldapi.fixture.example/clean",  "path": "/clean" },
  { "id": "ep_echo",   "target": "ldapi-fixture", "method": "GET",  "url": "https://ldapi.fixture.example/echo",   "path": "/echo" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_search", "target": "ldapi-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "p2", "endpoint_id": "ep_login",  "target": "ldapi-fixture", "name": "user", "location": "body",  "example": "root" },
  { "id": "p3", "endpoint_id": "ep_dir",    "target": "ldapi-fixture", "name": "cn",   "location": "query", "example": "amy" },
  { "id": "p4", "endpoint_id": "ep_clean",  "target": "ldapi-fixture", "name": "safe", "location": "query", "example": "ok" },
  { "id": "p5", "endpoint_id": "ep_echo",   "target": "ldapi-fixture", "name": "e",    "location": "query", "example": "hi" }
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
  run_record authorization_target ldapi-fixture
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
# _dast_ldapi_phase at source time (that is how dast_run_phase invokes it), so it
# is sourced once here against a throwaway run with no inventory - a harmless
# no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=ldapi-fixture
SCOURSH_DAST_CELL=ldapi-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/ldapi.sh
source "$ROOT/modules/dast/active/ldapi.sh"

# ===========================================================================
printf '== dast ldapi: the two techniques fire on the right parameters ==\n'
# ===========================================================================
SCOURSH_DAST_TARGET=ldapi-fixture
SCOURSH_DAST_CELL=ldapi-fixture
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
_dast_ldapi_phase

assert_eq 1 "$(_count_finding DAST-INJ-LDAP_ERROR-01 q)" \
  "error-based fires on query param 'q' whose broken filter provokes an LDAP error - FAILS under a reading that needs the baseline to error too, or that ignores the injected-only signature"
assert_eq 1 "$(_count_finding DAST-INJ-LDAP_ERROR-01 user)" \
  "error-based fires on BODY param 'user' - FAILS if the probe only injects query strings, not body/JSON fields (docs/DESIGN.md §7.3)"
assert_eq 1 "$(_count_finding DAST-INJ-LDAP_BOOLEAN-01 cn)" \
  "boolean-based fires on 'cn' where the never-match clause returns a short page - FAILS if it flags whenever any two responses differ"

assert_eq 0 "$(_count_finding DAST-INJ-LDAP_BOOLEAN-01 q)" \
  "NO boolean finding on 'q': the error param's always/never clauses do not produce a clean 200/200 differential - FAILS if a filter-error 500 is read as a boolean change"
assert_eq 0 "$(_count_finding DAST-INJ-LDAP_ERROR-01 cn)" \
  "NO error finding on 'cn': its clauses are well-formed filters, no LDAP error - FAILS if error-based flags a non-error response"

assert_eq 0 "$(_count_param safe)" \
  "the control parameter 'safe' yields no finding of any technique - FAILS if any probe flags a non-vulnerable parameter"
assert_eq 0 "$(_count_param e)" \
  "a REFLECTING endpoint that echoes the payload but drives no filter does NOT flag boolean - the probe strips the injected value before comparing, so a reflection is not read as a differential; FAILS if the reflected bytes alone are counted as the change"

# ===========================================================================
printf '== dast ldapi: two techniques, two distinct check ids on one param ==\n'
# ===========================================================================
# A single parameter vulnerable to BOTH at once must produce TWO findings,
# because the technique is not part of the DAST fingerprint (target, method,
# path_template, param_location, param_name) - one check id would dedupe them.
cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_all", "target": "ldapi-fixture", "method": "GET", "url": "https://ldapi.fixture.example/all", "path": "/all" }
] }
EOF
cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "pa", "endpoint_id": "ep_all", "target": "ldapi-fixture", "name": "x", "location": "query", "example": "1" }
] }
EOF
_all_transport() {
  local method=$1 path=$5 body=${_HTTP_TX_BODY:-}
  local surface="$path?$body" status=200 out=$LONG
  # A genuinely injectable endpoint: the never-match sentinel AND-clause returns
  # an empty listing (boolean false); a well-formed injected OR-clause (carrying
  # %7C, the `|`) is interpreted and returns the listing (boolean true, like the
  # baseline); a dangling/unbalanced metacharacter with no logical operator
  # breaks the filter and errors (error-based). The %7C check precedes the paren
  # check so a balanced boolean clause is not mistaken for a filter break.
  if [[ $surface == *"$NOENT"* ]]; then out=$SHORT
  elif [[ $surface == *%7C* || $surface == *%26* ]]; then out=$LONG
  elif [[ $surface == *%28* || $surface == *%29* || $surface == *%5C* ]]; then status=500; out=$LDAPERR
  fi
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
_new_run bothtech
SCOURSH_HTTP_TRANSPORT=_all_transport
_dast_ldapi_phase
SCOURSH_HTTP_TRANSPORT=_ldapi_transport
assert_eq 1 "$(_count_finding DAST-INJ-LDAP_ERROR-01 x)" \
  "one error finding on the all-vulnerable param - FAILS if a shared check id collapsed the two"
assert_eq 1 "$(_count_finding DAST-INJ-LDAP_BOOLEAN-01 x)" \
  "one boolean finding on the same param - two techniques are two ids, not one deduped finding"

# ===========================================================================
printf '== dast ldapi: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
_new_run coverage
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
_dast_ldapi_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-LDAP_ERROR-01' \
  "checks_run records the error check that executed over a parameter (AGENTS.md's definition), so modules/dast/run.sh's honesty roll-up does not report covered-nothing"
assert_contains "$CR" 'DAST-INJ-LDAP_BOOLEAN-01' 'checks_run records the boolean check'
assert_not_contains "$CR" 'LDAP_TIME' \
  "checks_run names NO time-based LDAP check - LDAP has no sleep primitive, so claiming a third technique would overstate coverage (docs/DESIGN.md §15)"

# ===========================================================================
printf '== dast ldapi: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_ldapi_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, ldapi emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  "no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast ldapi: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
rc=0
SCOURSH_DAST_LDAPI_PAYLOAD_DIR=$W/empty-payloads _dast_ldapi_phase || rc=$?
assert_eq 0 "$rc" \
  "an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "no payloads means no finding is emitted"
assert_contains "$(run_facts coverage_reduction)" 'ldapi_payloads_missing' \
  "each technique's absent payload file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no LDAP-injection payloads are available' \
  "with every technique's payloads gone, a coverage_gap says so - a clean result here is not a clean bill of health"

# A single missing technique degrades ONLY that technique. Give the override dir
# just the boolean payloads; drop the error files.
mkdir -p "$W/partial-payloads"
cp "$ROOT/modules/dast/payloads/ldapi-boolean-pairs.txt" "$W/partial-payloads/"
_new_run partial
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_LDAPI_PAYLOAD_DIR=$W/partial-payloads _dast_ldapi_phase
assert_eq 1 "$(_count_finding DAST-INJ-LDAP_BOOLEAN-01 cn)" \
  "boolean-based still runs when only the error payloads are missing - a missing file degrades ONLY its own technique"
assert_eq 0 "$(_count_finding DAST-INJ-LDAP_ERROR-01 q)" \
  "error-based does NOT run without its payload/signature files - FAILS if a technique reports on a param it never probed"
assert_contains "$(run_facts coverage_reduction)" 'technique=error' \
  "the missing error payloads are recorded as a technique=error coverage_reduction"
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-LDAP_ERROR-01' \
  "checks_run does NOT claim the error check ran when its payloads were absent"

# ===========================================================================
printf '== dast ldapi: every vendored payload is non-destructive ==\n'
# ===========================================================================
# LDAP write operations are ADD/MODIFY/DELETE/MODRDN (and no search filter can
# carry them); every vendored payload is a SEARCH filter. Fail the moment a
# write verb or a mutating operation appears in any payload file.
BADVERB=0
for pf in "$ROOT"/modules/dast/payloads/ldapi-*.txt; do
  if grep -Eiq '\b(modrdn|moddn|add:|delete:|modify:|changetype)\b' "$pf"; then
    BADVERB=1
  fi
done
assert_eq 0 "$BADVERB" \
  "no vendored LDAP payload carries a mutating LDIF/modify verb - FAILS the moment a changetype/add/delete/modify is added, which docs/DESIGN.md §7.3's non-destructive contract forbids"

# ===========================================================================
printf '== inject_engine: unit checks (LDAP metacharacters) ==\n'
# ===========================================================================
inject_urlencode "abc)(cn=*)"
assert_contains "$_INJ_ENC" '%29' "inject_urlencode percent-encodes a closing paren"
assert_contains "$_INJ_ENC" '%28' "inject_urlencode percent-encodes an opening paren"
assert_contains "$_INJ_ENC" '%2A' "inject_urlencode percent-encodes the LDAP wildcard '*'"

_write_full_inventory
inject_inventory_load "$W/endpoints.json" "$W/parameters.json"
assert_eq 5 "$_INJ_N" \
  "inject_inventory_load reads all 5 parameters and joins each to its endpoint - FAILS if a parameter whose endpoint row exists is dropped"

t_summary dast-ldapi
