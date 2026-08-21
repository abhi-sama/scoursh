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
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=modules/dast/crawl_engine.sh
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

t_summary dast-discovery
