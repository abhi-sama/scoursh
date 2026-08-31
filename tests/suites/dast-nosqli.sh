#!/usr/bin/env bash
# tests/suites/dast-nosqli.sh - modules/dast/active/nosqli.sh and the shared
# modules/dast/active/inject_engine.sh: error-based and boolean-based
# (operator/object injection, response differential) NoSQL injection
# (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md DAST-21, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST
# logic is testable with no live target"), driven from recorded responses.
# The suite runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and
# the rejected reading pins nothing.
#
#   1. error-based fires only when a NoSQL driver/$where error surfaces for
#      an injected value and NOT for the benign baseline - not on any 500,
#      and not on the baseline's own errors.
#   2. boolean-based needs the always-match clause to behave like the
#      baseline AND the never-match clause to differ from it - a page that
#      changes for BOTH (or NEITHER) is not a differential.
#   3. boolean-based fires from BOTH payload shapes: a %B-anchored $where
#      tautology AND a standalone operator-object literal that replaces the
#      value outright - proving the probe is not $where-only.
#   4. the technique is not part of the fingerprint, so two techniques on
#      one parameter are two distinct check ids, not one deduped finding.
#   5. the injected value goes where the parameter's `location` says (query
#      AND body proven here), per docs/DESIGN.md §7.3.
#   6. non-destructive: no vendored payload carries a NoSQL write operator.
#   7. no parameter surface / missing payloads degrade to a recorded
#      coverage_gap, never a clean-looking result and never an error.
#   8. there is deliberately NO time-based technique, so a run records
#      exactly the two checks it can perform.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes parameter/JSON syntax literally.
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

W=$SCOURSH_SCRATCH/dast-nosqli-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: nosqli-fixture
base-url: https://nosqli.fixture.example/
notes: Fixture target for tests/suites/dast-nosqli.sh. Never dialled: both the
  resolver and the transport are stubbed.
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

_nosqli_resolve() { case $1 in nosqli.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_nosqli_resolve

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# One vulnerable parameter per technique, plus controls, decided from the
# actual injected bytes (percent-encoded in the path/body the transport
# receives):
#   /search  q     - ERROR: a quote/brace metacharacter provokes a MongoError.
#   /login   user  - ERROR via a BODY parameter (proves body-location
#                    injection).
#   /find    f     - BOOLEAN via the $where tautology pair: the always-true
#                    clause returns the full listing, the always-false clause
#                    (carrying the sentinel) returns nothing.
#   /filter  x     - BOOLEAN via the standalone operator-object literal pair:
#                    {"$gte":""} returns the full listing, {"$eq":sentinel}
#                    returns nothing - proves the non-%B, whole-value
#                    payload shape works too.
#   /clean   safe  - control: never any signal (same page whatever is
#                    injected).
#   /echo    e     - control: reflects the injected value but drives no
#                    query - the body differs only by the reflected bytes,
#                    which the probe strips before comparing, so it must NOT
#                    flag.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

LONG='<html><body><ul><li>alpha</li><li>bravo</li><li>charlie</li><li>delta</li><li>echo</li><li>foxtrot</li><li>golf</li><li>hotel</li></ul></body></html>'
SHORT='<html><body>No entries found.</body></html>'
NOSQLERR='<html><body>MongoError: unterminated string in expression</body></html>'

# The never-match sentinel the boolean pairs carry (percent-encoded when it
# reaches the transport). Its PRESENCE marks the "false" (contradiction)
# request, whichever of the two boolean payload shapes sent it.
NOENT='scoursh-no-such-value-zq'

_nosqli_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 out=$LONG
  case $path in
    /search*)
      # A syntax-breaking metacharacter: a quote (%27/%22) or an unbalanced
      # brace/backslash (%7B/%5C) - but NOT the sentinel-bearing boolean
      # clauses, which are well-formed. Provoke a MongoError.
      if [[ $surface == *"$NOENT"* ]]; then
        out=$SHORT
      elif [[ $surface == *%27* || $surface == *%22* || $surface == *%7B* || $surface == *%5C* ]]; then
        status=500; out=$NOSQLERR
      fi
      ;;
    /login*)
      if [[ $surface == *"$NOENT"* ]]; then
        out=$SHORT
      elif [[ $surface == *%27* || $surface == *%22* || $surface == *%7B* || $surface == *%5C* ]]; then
        status=500; out=$NOSQLERR
      fi
      ;;
    /find*)
      # $where boolean: the never-match sentinel returns an empty listing;
      # every other value (baseline, and the always-match tautology clause)
      # returns the full listing. A well-formed expression, so no error is
      # provoked.
      if [[ $surface == *"$NOENT"* ]]; then out=$SHORT; fi
      ;;
    /filter*)
      # Operator-object boolean: identical shape to /find, on a DIFFERENT
      # parameter/endpoint, reached only by the non-%B whole-value pair
      # ({"$gte":""} vs {"$eq":"scoursh-no-such-value-zq"}).
      if [[ $surface == *"$NOENT"* ]]; then out=$SHORT; fi
      ;;
    /echo*)
      # Reflects the raw injected value into the body but runs no query, so
      # the ONLY difference between requests is the reflected payload text,
      # which the probe strips before measuring length.
      out="<html><body>you searched for: $body</body></html>"
      ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
SCOURSH_HTTP_TRANSPORT=_nosqli_transport

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_search", "target": "nosqli-fixture", "method": "GET",  "url": "https://nosqli.fixture.example/search", "path": "/search" },
  { "id": "ep_login",  "target": "nosqli-fixture", "method": "POST", "url": "https://nosqli.fixture.example/login",  "path": "/login" },
  { "id": "ep_find",   "target": "nosqli-fixture", "method": "GET",  "url": "https://nosqli.fixture.example/find",   "path": "/find" },
  { "id": "ep_filter", "target": "nosqli-fixture", "method": "GET",  "url": "https://nosqli.fixture.example/filter", "path": "/filter" },
  { "id": "ep_clean",  "target": "nosqli-fixture", "method": "GET",  "url": "https://nosqli.fixture.example/clean",  "path": "/clean" },
  { "id": "ep_echo",   "target": "nosqli-fixture", "method": "GET",  "url": "https://nosqli.fixture.example/echo",   "path": "/echo" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "p1", "endpoint_id": "ep_search", "target": "nosqli-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "p2", "endpoint_id": "ep_login",  "target": "nosqli-fixture", "name": "user", "location": "body",  "example": "root" },
  { "id": "p3", "endpoint_id": "ep_find",   "target": "nosqli-fixture", "name": "f",    "location": "query", "example": "amy" },
  { "id": "p4", "endpoint_id": "ep_filter", "target": "nosqli-fixture", "name": "x",    "location": "query", "example": "42" },
  { "id": "p5", "endpoint_id": "ep_clean",  "target": "nosqli-fixture", "name": "safe", "location": "query", "example": "ok" },
  { "id": "p6", "endpoint_id": "ep_echo",   "target": "nosqli-fixture", "name": "e",    "location": "query", "example": "hi" }
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
  run_record authorization_target nosqli-fixture
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
# Load the phase's functions. A phase script has no sourced-once guard and
# runs _dast_nosqli_phase at source time (that is how dast_run_phase invokes
# it), so it is sourced once here against a throwaway run with no inventory -
# a harmless no-op that records a gap - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=nosqli-fixture
SCOURSH_DAST_CELL=nosqli-fixture
SCOURSH_DAST_AUTHED=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/active/nosqli.sh
source "$ROOT/modules/dast/active/nosqli.sh"

# ===========================================================================
printf '== dast nosqli: the two techniques fire on the right parameters ==\n'
# ===========================================================================
SCOURSH_DAST_TARGET=nosqli-fixture
SCOURSH_DAST_CELL=nosqli-fixture
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
_dast_nosqli_phase

assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_ERROR-01 q)" \
  "error-based fires on query param 'q' whose syntax-breaking value provokes a MongoError - FAILS under a reading that needs the baseline to error too, or that ignores the injected-only signature"
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_ERROR-01 user)" \
  "error-based fires on BODY param 'user' - FAILS if the probe only injects query strings, not body/JSON fields (docs/DESIGN.md §7.3)"
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_BOOLEAN-01 f)" \
  "boolean-based fires on 'f' via the \$where tautology pair, where the never-match clause returns a short page - FAILS if it flags whenever any two responses differ"
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_BOOLEAN-01 x)" \
  "boolean-based ALSO fires on 'x' via the standalone operator-object pair ({\"\$gte\":\"\"} vs {\"\$eq\":sentinel}) - FAILS if the probe only tries the %B-anchored \$where shape"

assert_eq 0 "$(_count_finding DAST-INJ-NOSQLI_BOOLEAN-01 q)" \
  "NO boolean finding on 'q': the error param's always/never clauses do not produce a clean 200/200 differential - FAILS if a syntax-error 500 is read as a boolean change"
assert_eq 0 "$(_count_finding DAST-INJ-NOSQLI_ERROR-01 f)" \
  "NO error finding on 'f': its clauses are well-formed expressions, no NoSQL error - FAILS if error-based flags a non-error response"

assert_eq 0 "$(_count_param safe)" \
  "the control parameter 'safe' yields no finding of any technique - FAILS if any probe flags a non-vulnerable parameter"
assert_eq 0 "$(_count_param e)" \
  "a REFLECTING endpoint that echoes the payload but drives no query does NOT flag boolean - the probe strips the injected value before comparing, so a reflection is not read as a differential; FAILS if the reflected bytes alone are counted as the change"

# ===========================================================================
printf '== dast nosqli: two techniques, two distinct check ids on one param ==\n'
# ===========================================================================
# A single parameter vulnerable to BOTH at once must produce TWO findings,
# because the technique is not part of the DAST fingerprint (target, method,
# path_template, param_location, param_name) - one check id would dedupe
# them.
cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_all", "target": "nosqli-fixture", "method": "GET", "url": "https://nosqli.fixture.example/all", "path": "/all" }
] }
EOF
cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "pa", "endpoint_id": "ep_all", "target": "nosqli-fixture", "name": "z", "location": "query", "example": "1" }
] }
EOF
_all_transport() {
  local method=$1 path=$5 body=${_HTTP_TX_BODY:-}
  local surface="$path?$body" status=200 out=$LONG
  # A genuinely injectable endpoint: the never-match sentinel returns an
  # empty listing (boolean false, whichever payload shape carried it); a
  # well-formed tautology (the literal `==` comparison, %3D%3D) is
  # interpreted and returns the listing (boolean true, like the baseline); a
  # dangling quote/brace with no closing partner breaks the expression and
  # errors (error-based). The %3D%3D check precedes the quote/brace check so
  # a balanced boolean clause is not mistaken for a syntax break.
  if [[ $surface == *"$NOENT"* ]]; then out=$SHORT
  elif [[ $surface == *%3D%3D* || $surface == *%24gte* ]]; then out=$LONG
  elif [[ $surface == *%27* || $surface == *%22* || $surface == *%7B* || $surface == *%5C* ]]; then status=500; out=$NOSQLERR
  fi
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}
_new_run bothtech
SCOURSH_HTTP_TRANSPORT=_all_transport
_dast_nosqli_phase
SCOURSH_HTTP_TRANSPORT=_nosqli_transport
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_ERROR-01 z)" \
  "one error finding on the all-vulnerable param - FAILS if a shared check id collapsed the two"
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_BOOLEAN-01 z)" \
  "one boolean finding on the same param - two techniques are two ids, not one deduped finding"

# ===========================================================================
printf '== dast nosqli: checks_run reflects what executed, honestly ==\n'
# ===========================================================================
_new_run coverage
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
_dast_nosqli_phase
CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-INJ-NOSQLI_ERROR-01' \
  "checks_run records the error check that executed over a parameter (AGENTS.md's definition), so modules/dast/run.sh's honesty roll-up does not report covered-nothing"
assert_contains "$CR" 'DAST-INJ-NOSQLI_BOOLEAN-01' 'checks_run records the boolean check'
assert_not_contains "$CR" 'NOSQLI_TIME' \
  "checks_run names NO time-based NoSQL check - this probe ships exactly the two techniques §7.3 names, so claiming a third would overstate coverage (docs/DESIGN.md §15)"

# ===========================================================================
printf '== dast nosqli: no parameter surface degrades to a coverage gap ==\n'
# ===========================================================================
_new_run empty
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
_dast_nosqli_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no inventory, nosqli emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  "no parameter surface records a coverage_gap the report renders - FAILS if the absence of a test reads as the absence of a problem"
assert_eq '' "$(run_facts checks_run | tr -d '[:space:]')" \
  "checks_run is EMPTY when nothing was tested - recording it here would overstate coverage"
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json

# ===========================================================================
printf '== dast nosqli: missing payloads degrade to a recorded gap, not an error ==\n'
# ===========================================================================
mkdir -p "$W/empty-payloads"
_new_run degrade
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
rc=0
SCOURSH_DAST_NOSQLI_PAYLOAD_DIR=$W/empty-payloads _dast_nosqli_phase || rc=$?
assert_eq 0 "$rc" \
  "an empty payload dir does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "no payloads means no finding is emitted"
assert_contains "$(run_facts coverage_reduction)" 'nosqli_payloads_missing' \
  "each technique's absent payload file is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no NoSQL-injection payloads are available' \
  "with every technique's payloads gone, a coverage_gap says so - a clean result here is not a clean bill of health"

# A single missing technique degrades ONLY that technique. Give the override
# dir just the boolean payloads; drop the error files.
mkdir -p "$W/partial-payloads"
cp "$ROOT/modules/dast/payloads/nosqli-boolean-pairs.txt" "$W/partial-payloads/"
_new_run partial
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
_write_full_inventory
SCOURSH_DAST_NOSQLI_PAYLOAD_DIR=$W/partial-payloads _dast_nosqli_phase
assert_eq 1 "$(_count_finding DAST-INJ-NOSQLI_BOOLEAN-01 f)" \
  "boolean-based still runs when only the error payloads are missing - a missing file degrades ONLY its own technique"
assert_eq 0 "$(_count_finding DAST-INJ-NOSQLI_ERROR-01 q)" \
  "error-based does NOT run without its payload/signature files - FAILS if a technique reports on a param it never probed"
assert_contains "$(run_facts coverage_reduction)" 'technique=error' \
  "the missing error payloads are recorded as a technique=error coverage_reduction"
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-NOSQLI_ERROR-01' \
  "checks_run does NOT claim the error check ran when its payloads were absent"

# ===========================================================================
printf '== dast nosqli: every vendored payload is non-destructive ==\n'
# ===========================================================================
# NoSQL WRITE operators are $set/$unset/$push/$pull/$pop/$inc/$rename/
# $addToSet/$currentDate, plus the update/remove/delete/drop VERBS; no
# comparison-operator object or $where predicate needs any of them. Fail the
# moment a write operator or a mutating verb appears in any payload file.
BADVERB=0
for pf in "$ROOT"/modules/dast/payloads/nosqli-*.txt; do
  if grep -Eiq '\$(set|unset|push|pull|pop|inc|rename|addToSet|currentDate)\b|\b(drop|remove|deleteOne|deleteMany|updateOne|updateMany|insertOne|insertMany)\(' "$pf"; then
    BADVERB=1
  fi
done
assert_eq 0 "$BADVERB" \
  "no vendored NoSQL payload carries a mutating operator or driver-write verb - FAILS the moment a \$set/\$unset/... or a drop/remove/delete/update call is added, which docs/DESIGN.md §7.3's non-destructive contract forbids"

# ===========================================================================
printf '== inject_engine: unit checks (NoSQL operator/object shapes) ==\n'
# ===========================================================================
inject_urlencode '{"$ne":null}'
assert_contains "$_INJ_ENC" '%7B' "inject_urlencode percent-encodes an opening brace"
assert_contains "$_INJ_ENC" '%24' "inject_urlencode percent-encodes the NoSQL operator sigil '\$'"
assert_contains "$_INJ_ENC" '%7D' "inject_urlencode percent-encodes a closing brace"

_write_full_inventory
inject_inventory_load "$W/endpoints.json" "$W/parameters.json"
assert_eq 6 "$_INJ_N" \
  "inject_inventory_load reads all 6 parameters and joins each to its endpoint - FAILS if a parameter whose endpoint row exists is dropped"

t_summary dast-nosqli
