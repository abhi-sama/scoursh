#!/usr/bin/env bash
# tests/suites/dast-discovery.sh - modules/dast/active/discovery.sh: §7.2
# safe-active content discovery (docs/DESIGN.md §7.2;
# docs/STEP5-DAST-PLAN.md DAST-12, tier 3).
#
# NOTHING HERE TOUCHES THE NETWORK. SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout (docs/DESIGN.md §12: "DAST logic
# is testable with no live target"), driven by RECORDED responses. The suite
# runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.
#
#   1. the soft-404 baseline + status/length heuristic: a candidate that returns
#      the not-found baseline (same status AND similar length) is NOT a hit, so
#      an app that returns 200 for every path yields no findings; a candidate
#      with a materially different response IS a hit.
#   2. the three candidate sources map to the three finding families: a
#      well-known sensitive path -> SENSITIVE, a backup variant of an inventory
#      endpoint -> BACKUP, a vendored wordlist entry -> CONTENT.
#   3. a 200 whose body is a directory index emits DIRLIST (in addition to its
#      source finding).
#   4. an absent vendored wordlist degrades ONLY technique C to a recorded
#      coverage_gap - the sensitive-path and backup techniques still run - and
#      never errors (docs/DESIGN.md §15).
#   5. an unreachable base-url degrades to a coverage_gap, never a clean-looking
#      result.
#   6. the wordlist reader rejects unsafe entries (`..`, scheme/absolute URLs,
#      control chars), so a malicious vendored list cannot escape the surface.
#   7. non-destructive: every request is a GET.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes path/URL syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: lib/http.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/lib/http.sh"
# -x back-edge cut: modules/dast/crawl_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/crawl_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-discovery-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: disc-fixture
base-url: https://disc.fixture.example/
notes: Fixture target for tests/suites/dast-discovery.sh. Never dialled: both
  the resolver and the transport are stubbed.
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

_disc_resolve() { case $1 in disc.fixture.example) printf '93.184.216.34' ;; *) return 1 ;; esac; }
SCOURSH_HTTP_RESOLVE=_disc_resolve

# ---------------------------------------------------------------------------
# The mock target (recorded responses).
# ---------------------------------------------------------------------------
# The transport receives $5=path. A candidate resolves to
# https://disc.fixture.example/<rel>, so the path is /<rel>. The random baseline
# path begins /scoursh-nonexistent-.
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

NOTFOUND='<html><body>404 - not found</body></html>'
PAGE='<html><body><h1>Admin console</h1><p>welcome</p></body></html>'
GITHEAD='ref: refs/heads/main'
SRC='<?php $db_password = "s3cr3t"; // leaked backup source ?>'
DIRLIST='<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="../">Parent Directory</a><a href="a.txt">a.txt</a></body></html>'
FORBIDDEN='<html><body>403 Forbidden</body></html>'

# Baseline transport: a real 404 for the not-found baseline; distinct hits for
# the crafted paths; 404 for everything else.
_disc_transport() {
  local method=$1 path=$5
  local status=404 out=$NOTFOUND
  case $path in
    /scoursh-nonexistent-*) status=404; out=$NOTFOUND ;;
    /admin)            status=200; out=$PAGE ;;
    /.git/HEAD)        status=200; out=$GITHEAD ;;
    /config.php.bak)   status=200; out=$SRC ;;
    /files/)           status=200; out=$DIRLIST ;;
    /secret-dir/)      status=403; out=$FORBIDDEN ;;
    /bigpage)          status=200; out=$PAGE ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}

# Soft-404 transport: the app returns 200 for EVERYTHING, most with a body of
# the SAME length as the baseline, so only a materially different response is a
# real hit. /bigpage returns a much longer body (a genuine hit).
SOFT_BASE='<html><body>page: aaaaaaaaaaaaaaaaaaaa</body></html>'
SOFT_BIG='<html><body>'"$(printf 'x%.0s' {1..4000})"'</body></html>'
_disc_soft404_transport() {
  local method=$1 path=$5
  local status=200 out=$SOFT_BASE
  case $path in
    /bigpage) out=$SOFT_BIG ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" 'text/html'
}

# Unreachable transport: every request fails (no response at all).
_disc_dead_transport() { return 1; }

# ---------------------------------------------------------------------------
# Inventory writer (docs/INVENTORY-FORMAT.md) - one endpoint whose backup
# variant (config.php.bak) is a hit above.
# ---------------------------------------------------------------------------
_write_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_cfg",   "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/config.php", "path": "/config.php" },
  { "id": "ep_index", "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/",           "path": "/" }
] }
EOF
  : >"$W/parameters.json"
}

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target disc-fixture
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

# `_count_check CHECK` - findings whose check_id matches exactly.
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

# `_count_check_path CHECK PATHTEMPLATE` - findings whose check_id AND
# loc_path_template both match exactly.
_count_check_path() {
  local check=$1 pt=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_path_template=$pt" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Context and load. A phase script has no sourced-once guard and runs its phase
# at source time (that is how dast_run_phase invokes it), so it is sourced once
# against a throwaway run and re-invoked per case.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=disc-fixture
SCOURSH_DAST_CELL=disc-fixture
SCOURSH_DAST_INTENSITY=safe
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
  SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
unset SCOURSH_SELECTED_CHECKS
WORDLIST=$ROOT/tests/fixtures/dast-discovery/wordlist.txt

SCOURSH_HTTP_TRANSPORT=_disc_transport
_new_run boot
# shellcheck source=modules/dast/active/discovery.sh
source "$ROOT/modules/dast/active/discovery.sh"

# ===========================================================================
printf '== dast discovery: the three sources map to the three finding families ==\n'
# ===========================================================================
_write_inventory
_new_run main
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase

assert_eq 1 "$(_count_check_path DAST-DISC-SENSITIVE-01 /.git/HEAD)" \
  "a reachable well-known sensitive path (.git/HEAD) is a SENSITIVE finding - FAILS if the fixed sensitive-path set is not probed, or if a 200 there is read as the not-found baseline"
assert_eq 1 "$(_count_check_path DAST-DISC-BACKUP-01 /config.php.bak)" \
  "a reachable backup variant of an inventory endpoint (config.php.bak) is a BACKUP finding - FAILS if backup variants are not derived from the crawl inventory (docs/DESIGN.md §7.2)"
assert_eq 1 "$(_count_check_path DAST-DISC-CONTENT-01 /admin)" \
  "a reachable vendored-wordlist entry (admin) is a CONTENT finding - FAILS if the wordlist sweep does not run or the hit heuristic rejects a 200 differing from baseline"
# Note: path_template_of drops a trailing slash, so /secret-dir/ and /files/
# carry the loc_path_template /secret-dir and /files respectively (the exact URL
# is preserved in the finding's `url` field).
assert_eq 1 "$(_count_check_path DAST-DISC-CONTENT-01 /secret-dir)" \
  "a 403 wordlist entry is still a CONTENT hit (the resource exists but is protected) - FAILS under a reading that only counts 200 as a discovery"

# ===========================================================================
printf '== dast discovery: a directory index emits DIRLIST ==\n'
# ===========================================================================
assert_eq 1 "$(_count_check_path DAST-DISC-DIRLIST-01 /files)" \
  "a 200 whose body is an autoindex page emits DIRLIST - FAILS if directory-listing detection is missing"
assert_eq 1 "$(_count_check_path DAST-DISC-CONTENT-01 /files)" \
  "the same /files/ hit is ALSO its source (CONTENT) finding - DIRLIST is emitted in addition, not instead"

# ===========================================================================
printf '== dast discovery: the not-found baseline is not a finding ==\n'
# ===========================================================================
assert_eq 0 "$(_count_check_path DAST-DISC-CONTENT-01 /nonexistent-thing)" \
  "a wordlist entry that returns the 404 baseline is NOT a hit - FAILS if any 404 is read as a discovered resource"
assert_eq 1 "$(_count_check DAST-DISC-SENSITIVE-01)" \
  "exactly ONE sensitive finding overall (.git/HEAD); every other fixed sensitive path (.env, .htaccess, ...) 404s and is correctly silent - FAILS if the heuristic flags a 404"

CR=$(run_facts checks_run)
assert_contains "$CR" 'DAST-DISC-SENSITIVE-01' 'checks_run records the sensitive check that probed at least one candidate'
assert_contains "$CR" 'DAST-DISC-BACKUP-01'    'checks_run records the backup check'
assert_contains "$CR" 'DAST-DISC-CONTENT-01'   'checks_run records the content check (a wordlist was present)'
assert_contains "$CR" 'DAST-DISC-DIRLIST-01'   'checks_run records the dirlist check'

# ===========================================================================
printf '== dast discovery: soft-404 (200-for-everything) yields no false hits ==\n'
# ===========================================================================
_new_run soft404
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
SCOURSH_HTTP_TRANSPORT=_disc_soft404_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase
SCOURSH_HTTP_TRANSPORT=_disc_transport
assert_eq 0 "$(_count_check_path DAST-DISC-CONTENT-01 /admin)" \
  "under a soft-404 app (200 + same length for every path), /admin is NOT flagged - FAILS under a reading that treats any non-404 status as a hit, which is exactly the false-positive the length baseline exists to prevent"
assert_eq 1 "$(_count_check_path DAST-DISC-CONTENT-01 /bigpage)" \
  "a candidate whose 200 body is MATERIALLY longer than the baseline IS a hit even under a soft-404 app - FAILS if the length heuristic is not applied at all"

# ===========================================================================
printf '== dast discovery: an absent wordlist degrades ONLY technique C ==\n'
# ===========================================================================
_new_run nowl
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
rc=0
SCOURSH_DAST_DISCOVERY_WORDLIST=$W/does-not-exist.txt _dast_discovery_phase || rc=$?
assert_eq 0 "$rc" \
  "an absent wordlist does NOT error - the phase degrades and returns 0 (docs/DESIGN.md §15)"
assert_eq 1 "$(_count_check_path DAST-DISC-SENSITIVE-01 /.git/HEAD)" \
  "the sensitive-path technique STILL runs with no wordlist - it needs no external list"
assert_eq 1 "$(_count_check_path DAST-DISC-BACKUP-01 /config.php.bak)" \
  "the backup technique STILL runs with no wordlist - it derives from the inventory"
assert_eq 0 "$(_count_check DAST-DISC-CONTENT-01)" \
  "the wordlist (CONTENT) technique produced no finding with no list - FAILS if the phase invents wordlist hits"
assert_contains "$(run_facts coverage_reduction)" 'discovery_wordlist_absent' \
  "an absent wordlist is a recorded coverage_reduction, not a silent skip"
assert_contains "$(run_facts coverage_gap)" 'no content-discovery wordlist was available' \
  "an absent wordlist is a coverage_gap the report renders - the absence of a test is not the absence of a problem"
assert_not_contains "$(run_facts checks_run)" 'DAST-DISC-CONTENT-01' \
  "checks_run does NOT claim the content check ran when no wordlist was present"

# ===========================================================================
printf '== dast discovery: an unreachable base-url is a coverage gap ==\n'
# ===========================================================================
_new_run dead
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
SCOURSH_HTTP_TRANSPORT=_disc_dead_transport
rc=0
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase || rc=$?
SCOURSH_HTTP_TRANSPORT=_disc_transport
assert_eq 0 "$rc" \
  "an unreachable base-url does NOT error - it degrades and returns 0"
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  "with no reachable baseline, discovery emits NO finding - a clean result with nothing tested would be the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_gap)" 'could not be reached to establish a not-found baseline' \
  "an unreachable base-url records a coverage_gap the report renders"

# ===========================================================================
printf '== dast discovery: every request is a read-only GET ==\n'
# ===========================================================================
_new_run readonly
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase
NONGET=$(awk '!/^GET /{n++} END{print n+0}' "$REQ_LOG")
assert_eq 0 "$NONGET" \
  "every discovery request is a GET - FAILS the moment a probe sends a mutating method, which docs/DESIGN.md §7.2's non-destructive posture forbids"

# ===========================================================================
printf '== dast discovery: the wordlist reader rejects unsafe entries ==\n'
# ===========================================================================
# The fixture wordlist carries `../../etc/passwd`, an http:// URL, a
# protocol-relative //host, and a control-character line. None may survive.
mapfile -t READ < <(_discovery_read_wordlist "$WORDLIST")
JOINED=$(printf '%s\n' "${READ[@]}")
assert_contains "$JOINED" 'admin' "a plain relative entry survives"
assert_not_contains "$JOINED" '..' \
  "a dot-dot traversal entry is rejected - FAILS if a vendored list can escape the authorised path prefix"
assert_not_contains "$JOINED" 'evil.example' \
  "an absolute or scheme-relative URL is rejected - a wordlist contributes PATHS, never a host"
assert_not_contains "$JOINED" 'bad	path' \
  "a control-character (tab) entry is rejected - FAILS if CR/LF/control bytes reach a request"

# ===========================================================================
printf '== dast discovery: an inventory-derived path is held to the SAME safe-path rule ==\n'
# ===========================================================================
# The endpoints inventory is UNTRUSTED TARGET OUTPUT (docs/FOUNDATION.md tension
# 10): its `path` values come from the scanned application's own markup or from
# an operator-supplied specification, so a path there is strictly LESS trusted
# than a vendored wordlist entry - which technique C already validates. These
# cases pin that technique B applies the identical rule, and each FAILS under
# the reading that a path already recorded in the inventory needs no validation.
cat >"$W/endpoints-hostile.json" <<EOF
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_ok",   "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/config.php", "path": "/config.php" },
  { "id": "ep_dots", "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/x",           "path": "/a/../../../../etc/passwd" },
  { "id": "ep_ctl",  "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/y",           "path": "/inject\r\nX-Injected: 1" },
  { "id": "ep_sch",  "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/z",           "path": "https://evil.example/pwn" }
] }
EOF
_new_run hostile_inventory
SCOURSH_DAST_ENDPOINTS=$W/endpoints-hostile.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase
REQS=$(cat "$REQ_LOG")

assert_not_contains "$REQS" 'etc/passwd' \
  "a '..' traversal in an inventory endpoint path is never probed - FAILS under the reading that only the WORDLIST needs the safe-relative-path rule, when target-derived inventory data is the less trusted of the two"
assert_not_contains "$REQS" 'X-Injected' \
  "a CR/LF-bearing inventory endpoint path is never probed - FAILS if control bytes from target output reach the request line, which is exactly the header/request-splitting shape the wordlist reader already refuses"
assert_not_contains "$REQS" 'evil.example' \
  "an inventory endpoint path that is itself an absolute URL contributes no candidate - FAILS if a scanned target can steer a probe by writing a scheme into its own inventory path"
assert_contains "$REQS" '/config.php.bak' \
  "the well-formed sibling endpoint in the SAME inventory still yields its backup candidates - FAILS if the guard is over-broad and makes technique B inert, which every 'stays quiet' assertion above would otherwise pass"

# The same rule, asserted directly on the reader, so the guard is pinned
# independently of what the transport happened to be asked for.
# A rejection is a plain non-zero return, so each call carries `|| true`: the
# suite runs under `set -Eeuo pipefail` with lib/core.sh's ERR trap installed,
# and an unhandled 1 here would be reported as a command failure rather than as
# the refusal it is.
mapfile -t SAFE < <(_discovery_safe_rel 'config.php' || true; _discovery_safe_rel 'a/../../etc/passwd' || true; \
  _discovery_safe_rel 'https://evil.example/pwn' || true; _discovery_safe_rel "$(printf 'inject\rX: 1')" || true)
assert_eq 'config.php' "$(printf '%s' "${SAFE[0]:-}")" \
  "_discovery_safe_rel passes a plain relative path through unchanged"
assert_eq 1 "${#SAFE[@]}" \
  "_discovery_safe_rel emits nothing for a traversal, a scheme URL, or a control character - FAILS if any of the three is merely normalised rather than dropped"

# ===========================================================================
printf '== dast discovery: technique B in the REAL-RUN inventory shape ==\n'
# ===========================================================================
# THIS IS THE SHAPE AN ORDINARY `scan.sh dast` RUN HAS: modules/dast/run.sh
# resolves SCOURSH_DAST_ENDPOINTS to the fixed
# `$SCOURSH_RUN_DIR/inventory/endpoints.json` path and exports it
# unconditionally, whether or not crawl.sh has written the file yet - so this
# phase is handed that exact path, which becomes readable once the file
# lands.  Every backup case above instead points SCOURSH_DAST_ENDPOINTS at a
# synthetic fixture under $W, which is not the shape a real run has.
_new_run realshape
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_write_inventory
cp "$W/endpoints.json" "$SCOURSH_RUN_DIR/inventory/endpoints.json"
SCOURSH_DAST_ENDPOINTS=$SCOURSH_RUN_DIR/inventory/endpoints.json
SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase
REQS=$(cat "$REQ_LOG")

assert_contains "$REQS" '/config.php.bak' \
  "with SCOURSH_DAST_ENDPOINTS at its real run-dir path, the backup technique probes - FAILS if the phase cannot read the inventory at the path modules/dast/run.sh actually publishes"
assert_eq 1 "$(_count_check_path DAST-DISC-BACKUP-01 /config.php.bak)" \
  "a served, source-leaking backup file IS reported on a real-shaped run"
assert_contains "$(run_facts checks_run)" 'DAST-DISC-BACKUP-01' \
  "the backup check is recorded as covered on a run where it genuinely probed"

# ===========================================================================
printf '== dast discovery: NO inventory anywhere is a declared gap, not silent coverage ==\n'
# ===========================================================================
# The other half of the same rule, and the naive fix for each is the other's
# bug: adding the fallback without this makes an inventory-less run keep
# claiming DAST-DISC-BACKUP-01 coverage. docs/DESIGN.md §15 - a check that
# probed nothing must never appear in checks_run, and its absence must be
# stated. At step 7 this feeds state/'s (check, cell) coverage pairs, where a
# falsely-covered check lets a prior run's real finding be inferred `fixed`
# (docs/FOUNDATION.md tension 12).
_new_run noinv
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase

assert_not_contains "$(run_facts checks_run)" 'DAST-DISC-BACKUP-01' \
  "with no endpoint inventory readable by EITHER path, the backup check is NOT recorded in checks_run - FAILS under the reading that a technique which contributed zero candidates is still 'covered' because the phase sent some other technique's requests"
assert_contains "$(run_facts coverage_gap)" 'no endpoint inventory' \
  "the missing inventory is a stated coverage_gap the report renders - FAILS if the gap is silent, which is the overstated coverage docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts coverage_reduction)" 'discovery_no_endpoint_inventory' \
  "and a machine-readable coverage_reduction names the reason, exactly as the absent-wordlist case already does"
assert_contains "$(run_facts checks_run)" 'DAST-DISC-SENSITIVE-01' \
  "the sensitive-path technique still ran and is still recorded - FAILS if the inventory gap is over-broad and takes the whole phase down with it"

# ===========================================================================
printf '== dast discovery: a READABLE inventory that yields no candidate is a gap too ==\n'
# ===========================================================================
# The narrower residual of the same overstatement. `_discovery_inventory_path`
# answers "is a file readable and non-empty", which is NOT the question
# DAST-DISC-BACKUP-01's coverage turns on - "did technique B derive and probe a
# candidate". Both shapes below are reachable on an ordinary run, not
# theoretical:
#
#   - modules/dast/crawl.sh calls crawl_inv_write_endpoints UNCONDITIONALLY and
#     crawl_engine.sh emits the full envelope with `"endpoints": []`, so a crawl
#     that found nothing still leaves a readable, non-empty endpoints.json;
#   - an inventory WITH endpoints, every one of which `_discovery_safe_rel`
#     rejects (traversal, scheme URL, control byte) or which carries no filename
#     component, derives nothing either.
#
# In both, technique B sends zero probes. Recording DAST-DISC-BACKUP-01 anyway
# mints the (check, cell) coverage pair that lets step 7's state/ infer a prior
# real finding `fixed` (docs/FOUNDATION.md tension 12) - the exact failure
# DAST-12 exists to close.
#
# Each assertion FAILS under the reading that a readable inventory FILE is
# itself coverage. The distinct reason string is asserted in BOTH directions so
# "no inventory" and "an inventory with nothing usable in it" cannot collapse
# into one message.

# (1) The envelope a zero-endpoint crawl writes, at the real run-dir path.
_new_run inv_empty
mkdir -p "$SCOURSH_RUN_DIR/inventory"
printf '%s\n' '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [] }' \
  >"$SCOURSH_RUN_DIR/inventory/endpoints.json"
SCOURSH_DAST_ENDPOINTS=$SCOURSH_RUN_DIR/inventory/endpoints.json
SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase

assert_not_contains "$(run_facts checks_run)" 'DAST-DISC-BACKUP-01' \
  "a readable inventory listing ZERO endpoints does NOT make the backup check covered - FAILS under the reading that the inventory FILE existing is coverage, which is the shape every crawl-found-nothing run has (crawl.sh writes the envelope unconditionally)"
assert_contains "$(run_facts coverage_reduction)" 'discovery_inventory_yielded_no_candidate' \
  "the readable-but-useless inventory has its OWN machine-readable reason - FAILS if it is silent, and FAILS if it reuses the absent-inventory reason, which would tell an operator to run a crawl that already ran"
assert_not_contains "$(run_facts coverage_reduction)" 'discovery_no_endpoint_inventory' \
  "and it is NOT reported as an absent inventory - FAILS if the two shapes collapse into one message"
assert_contains "$(run_facts coverage_gap)" 'yielded no usable endpoint path' \
  "the gap the report renders states what actually happened - FAILS if a zero-candidate technique passes silently, which docs/DESIGN.md §15 forbids"
assert_contains "$(run_facts checks_run)" 'DAST-DISC-SENSITIVE-01' \
  "the sensitive-path technique still ran - FAILS if the empty-inventory gap is over-broad and takes the whole phase down with it"

# (2) An inventory WITH endpoints, none of which survives validation.
cat >"$W/endpoints-all-rejected.json" <<EOF
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_dots", "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/x", "path": "/a/../../../../etc/passwd" },
  { "id": "ep_ctl",  "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/y", "path": "/inject\r\nX-Injected: 1" },
  { "id": "ep_sch",  "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/z", "path": "https://evil.example/pwn" },
  { "id": "ep_root", "target": "disc-fixture", "method": "GET", "url": "https://disc.fixture.example/",  "path": "/" }
] }
EOF
_new_run inv_all_rejected
SCOURSH_DAST_ENDPOINTS=$W/endpoints-all-rejected.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase

assert_not_contains "$(run_facts checks_run)" 'DAST-DISC-BACKUP-01' \
  "an inventory whose every endpoint is rejected by the safe-path rule (or is a bare directory) does NOT make the backup check covered - FAILS under the reading that a non-empty endpoints array is coverage regardless of what survives validation"
assert_contains "$(run_facts coverage_reduction)" 'discovery_inventory_yielded_no_candidate' \
  "and it records the same readable-but-useless reason as the zero-endpoint case, since technique B derived exactly as much from both: nothing"

# (3) The other direction, and the assertion that catches an INERT technique:
# the well-formed inventory must STILL derive, probe and claim its check. Every
# "stays quiet" assertion above passes against a technique B that was broken
# outright, so this case is what makes the two above mean anything.
_new_run inv_still_works
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_write_inventory
cp "$W/endpoints.json" "$SCOURSH_RUN_DIR/inventory/endpoints.json"
SCOURSH_DAST_ENDPOINTS=$SCOURSH_RUN_DIR/inventory/endpoints.json
SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
SCOURSH_HTTP_TRANSPORT=_disc_transport
SCOURSH_DAST_DISCOVERY_WORDLIST=$WORDLIST _dast_discovery_phase
REQS=$(cat "$REQ_LOG")

assert_contains "$REQS" '/config.php.bak' \
  "a well-formed inventory STILL derives and probes its backup candidates - FAILS if the candidate-count gate is over-broad and makes technique B inert"
assert_eq 1 "$(_count_check_path DAST-DISC-BACKUP-01 /config.php.bak)" \
  "and the served backup file is still reported - FAILS if the gate suppresses the finding as well as the coverage claim"
assert_contains "$(run_facts checks_run)" 'DAST-DISC-BACKUP-01' \
  "and the check IS recorded as covered on the run where it genuinely probed - FAILS if the gate never lets technique B be covered at all, which every assertion in (1) and (2) would still pass under"
assert_not_contains "$(run_facts coverage_reduction)" 'discovery_inventory_yielded_no_candidate' \
  "and no yielded-nothing reduction is recorded on a run that did yield candidates - FAILS if the reason is emitted unconditionally"

# The mechanism itself, asserted directly on the collector, so the gate is
# pinned independently of what the transport happened to be asked for.
# `cats`/`rels` are the caller-scoped arrays the collector appends to (bash
# dynamic scope); _DISC_BACKUP_ADDED is the count it reports.
_disc_added_for() {
  local -a cats=() rels=()
  local _DISC_BACKUP_ADDED=0
  _discovery_collect_backups "$1"
  printf '%s %s' "$_DISC_BACKUP_ADDED" "${#rels[@]}"
}
printf '%s\n' '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [] }' >"$W/inv-empty.json"
assert_eq '0 0' "$(_disc_added_for "$W/inv-empty.json")" \
  "_discovery_collect_backups reports ZERO candidates appended for a zero-endpoint inventory - FAILS if the collector reports presence of a file rather than the count it derived"
assert_eq '0 0' "$(_disc_added_for "$W/endpoints-all-rejected.json")" \
  "and zero for an inventory whose every path is rejected - FAILS if a rejected path is counted as a contribution"
ADDED=$(_disc_added_for "$W/endpoints.json")
assert_eq "${ADDED%% *}" "${ADDED##* }" \
  "the reported count equals the number of candidates actually appended - FAILS if the count and the array can drift apart"
assert_ne 0 "${ADDED%% *}" \
  "and a well-formed inventory reports a NON-ZERO count - FAILS if the collector reports zero for everything, under which both cases above pass vacuously"

# ===========================================================================
printf '== dast discovery: the body read is bounded AT READ TIME, never after a full slurp ==\n'
# ===========================================================================
# Regression for the ticket ("Bound the DAST discovery response-body read at
# the cap instead of truncating after a full slurp"): `_discovery_probe` used
# to `read -r -d ''` the WHOLE captured body into a bash variable and only
# THEN trim it to _DISCOVERY_MAX_BODY_BYTES, so a target serving a large
# response materialised it in full in this process before any cap applied -
# exactly the memory hazard the cap comment at the top of this file names.
# `read -r -N _DISCOVERY_MAX_BODY_BYTES` stops reading once the cap is
# reached, whatever else remains on disk.
#
# Proof shape: a 256 MiB body (1024x the default 256 KiB cap) is served, and
# BOTH the reported length and the actual variable content are asserted at
# exactly the cap - and the whole probe (including the fixture transport's own
# disk write of the body, so the timing floor is comparable under EITHER
# reading) is timed.  Measured directly on this repository's own dev host,
# through this exact harness: the fixed `-N` read finishes the whole probe in
# under 200ms; reverting to the unbounded `read -d ''` this ticket replaces
# takes 1.7+ seconds for the identical 256 MiB body - an order-of-magnitude
# difference, not hardware-noise-sized - so the 800ms ceiling below FAILS
# reliably under the un-bounded reading while leaving real headroom above the
# fixed reading's own measured cost.
HUGEFILE=$W/huge-body.raw
if [[ ! -f $HUGEFILE ]]; then
  # Built via in-process string doubling (2^28 = 268435456 bytes = 256 MiB)
  # rather than `head -c ... | tr '\0' a`, measured ~2x slower for the same
  # size - this is fixture SETUP, not the code under test, so speed here is
  # only about keeping the suite itself fast.
  hs='a'
  for _ in $(seq 1 28); do hs+=$hs; done
  printf '%s' "$hs" >"$HUGEFILE"
  unset hs
fi

_disc_huge_transport() {
  local method=$1 path=$5
  local status=404
  case $path in
    /hugefile) status=200 ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $path == /hugefile ]]; then
      cp -- "$HUGEFILE" "$_HTTP_TX_BODY_OUT"
    else
      printf '%s' "$NOTFOUND" >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '%s\n\n%s\n' "$status" 'text/html'
}

_new_run huge
SCOURSH_HTTP_TRANSPORT=_disc_huge_transport
t0=$(now_epoch_ns)
huge_rc=0
_discovery_probe "https://disc.fixture.example/hugefile" || huge_rc=$?
t1=$(now_epoch_ns)
huge_ms=$(( (t1 - t0) / 1000000 ))

assert_eq 0 "$huge_rc" 'the probe itself succeeds for a large-but-reachable body'
assert_eq "$_DISCOVERY_MAX_BODY_BYTES" "$_DISC_LEN" \
  "a 256 MiB body (1024x the cap) is reported at exactly the ${_DISCOVERY_MAX_BODY_BYTES}-byte cap - FAILS if the cap is applied to what is RETAINED after a full read rather than to what is READ"
assert_eq "$_DISCOVERY_MAX_BODY_BYTES" "${#_DISC_BODY}" \
  "and _DISC_BODY itself holds exactly the cap's worth of bytes, never the full 256 MiB response"
assert_true "$([[ $huge_ms -lt 800 ]] && echo 0 || echo 1)" \
  "the whole probe (fixture write plus read) completed in ${huge_ms}ms for a 256 MiB body - FAILS under the un-bounded \`read -d ''\` this replaces, which must slurp the whole body before trimming it (measured 1.7+ seconds on this host for the identical fixture through this exact harness - an order-of-magnitude difference this 800ms ceiling reliably catches)"

# ===========================================================================
printf '== dast discovery: an embedded NUL byte does not abort the probe ==\n'
# ===========================================================================
# bash variables cannot hold a NUL byte under EITHER reading, so a binary body
# is inherently lossy here - the shapes differ (old: everything after the
# first NUL is dropped, as its own delimiter; new: NUL bytes are skipped but
# reading continues, accumulating non-NUL bytes up to the cap) but neither is
# new with this change. What must hold under the fix: the read still
# completes cleanly (no abort under this suite's own `set -Eeuo pipefail`)
# and the reported length never exceeds the cap.
NULBODY_FILE=$W/nul-body.raw
printf 'abc\x00def\x00ghi' >"$NULBODY_FILE"
_disc_nul_transport() {
  local method=$1 path=$5
  local status=404
  case $path in
    /nulbody) status=200 ;;
  esac
  printf '%s %s\n' "$method" "$path" >>"$REQ_LOG"
  if [[ -n ${_HTTP_TX_BODY_OUT:-} ]]; then
    if [[ $path == /nulbody ]]; then
      cp -- "$NULBODY_FILE" "$_HTTP_TX_BODY_OUT"
    else
      printf '%s' "$NOTFOUND" >"$_HTTP_TX_BODY_OUT"
    fi
  fi
  printf '%s\n\n%s\n' "$status" 'text/html'
}
_new_run nulbody
SCOURSH_HTTP_TRANSPORT=_disc_nul_transport
nul_rc=0
_discovery_probe "https://disc.fixture.example/nulbody" || nul_rc=$?
assert_eq 0 "$nul_rc" \
  'a body carrying embedded NUL bytes does not abort the probe - FAILS if the bounded read chokes on a NUL rather than just losing it'
assert_true "$([[ $_DISC_LEN -le $_DISCOVERY_MAX_BODY_BYTES ]] && echo 0 || echo 1)" \
  "the reported length (${_DISC_LEN}) still never exceeds the cap for a body containing embedded NULs"

t_summary dast-discovery
