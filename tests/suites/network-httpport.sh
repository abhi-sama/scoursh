#!/usr/bin/env bash
# tests/suites/network-httpport.sh - modules/network/httpport.sh and
# httpport_engine.sh: NET-09, the `safe-active` HTTP-identification probe
# against a declared non-standard HTTP port
# (data/scoursh-network-scan-design/report.md §3.2 item 3, §7 Tier 2).
#
# Five things this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. `httpport_listeners_load` reads ONLY `role: extra-host` rows out of
#      NET-05's listeners.json - the target's own `base-url` (already
#      covered in full by modules/dast/) is never a candidate, and a
#      non-http/https scheme is never handed to `http_request`.
#   2. A known-vulnerable version disclosed on a non-standard port fires
#      NET-SVC-HTTP_OUTDATED_COMPONENT-01 (an exact data/versions.db `banner`
#      match); a current or unlisted version stays quiet on THAT check while
#      the disclosure checks still fire - report.md §3.4's "exact table
#      lookup, never a heuristic" is testable from both directions.
#   3. A target with no declared listener beyond its own base-url (or an
#      empty/unusable listeners.json) records a `coverage_reduction` +
#      `coverage_gap` and sends nothing - "this host has one listener" and
#      "scoursh did not look" are different facts (report.md §5.2 rule 3).
#   4. Every request goes through the SAME two-tier authorization
#      report.md §5.2 rule 1 describes: an artifact-tuple row
#      `net_endpoint_keep` drops is a counted `coverage_reduction`, never a
#      silent skip and never a fatal abort of the whole target.
#   5. Findings round-trip through every emitted report format - json, md,
#      html, sarif and the `--format agent` scaffold - via the SAME
#      `report_all` path a real run.sh takes, not a second, untested
#      rendering path this suite invents for itself.
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a fixture root can never leak into the
#   next case.
# shellcheck disable=SC2016,SC2030,SC2031
#
# WHY THE PHASE SCRIPT IS SOURCED THROUGH ONE WRAPPER FUNCTION RATHER THAN A
# LITERAL `source` LINE REPEATED PER CASE, AND WHY TWO OF THE FOUR SOURCE
# LINES BELOW ARE CUT TO `/dev/null`.  `shellcheck -x` follows every `source`
# STATICALLY and re-expands the whole target subtree at EVERY distinct
# `source` TEXT occurrence, with no "already inlined" memoisation
# (AGENTS.md's "Things measured on this codebase" section; measured directly
# on an earlier draft of this file: >21 GB resident and still climbing after
# 3.5 minutes with three real top-level sources into the lib/ hub, one of
# which duplicated content the other two already reached).
#   - `modules/network/engine.sh` is cut, mirroring tests/suites/network.sh's
#     own identical cut on the identical line: this suite calls its
#     functions (`net_inventory_read`/`net_check_selected`/`net_endpoint_keep`/
#     `net_scope_record_skips`) but needs shellcheck to see none of their
#     bodies to check THIS file - engine.sh is itself a real entry point
#     checked separately, on its own, elsewhere in the stage.
#   - `modules/network/httpport_engine.sh` is cut too, for the same reason:
#     `lib/http.sh` below is the one real edge this file needs into the lib/
#     hub, and `_hp_source_phase`'s own single occurrence of `source
#     modules/network/httpport.sh` (which itself reaches httpport_engine.sh
#     for real) is the one place httpport_engine.sh's own subtree
#     (banner_engine.sh, crawl_engine.sh) is actually walked for this file -
#     a second, top-level real edge to it here would re-walk that whole
#     subtree AGAIN on top of the one `_hp_source_phase` already needs.
# Wrapping the phase script's own real source line in `_hp_source_phase`
# keeps that one text occurrence to exactly one, however many times the
# WRAPPING FUNCTION is called at runtime - shellcheck counts source lines in
# the file's text, not function-call counts at run time.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=/dev/null
source "$ROOT/modules/network/engine.sh"
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# -x back-edge cut: httpport.sh (sourced for real, exactly once, inside
# _hp_source_phase below) reaches this file's own real subtree already; see
# this file's own top-of-file note for the full reasoning.
# shellcheck source=/dev/null
source "$ROOT/modules/network/httpport_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

# -x back-edge cut: modules/network/httpport.sh is its own entry point,
# statically checked in full, exactly once, elsewhere in the stage - the
# identical reasoning tests/suites/dast-banner.sh's own header gives for
# cutting every one of its own (there, five) occurrences of `source
# .../banner.sh`. Its real subtree (httpport_engine.sh, and through that
# banner_engine.sh/crawl_engine.sh, plus its own guarded-but-still-followed
# edge back to lib/http.sh) would otherwise be walked a second time on top
# of what this file's own two real edges above already cover. The RUNTIME
# `source` below is unaffected by this comment - only shellcheck -x's static
# walk is.
_hp_source_phase() {
  # shellcheck source=/dev/null
  source "$ROOT/modules/network/httpport.sh"
}

W=$SCOURSH_SCRATCH/network-httpport
rm -rf "$W"
mkdir -p "$W"
# Canonicalise - lib/records.sh strips $SCOURSH_INSTALL_ROOT as a literal
# prefix, so a fixture root reached through macOS's /var -> /private/var
# symlink would break that strip (tests/suites/network.sh's own comment).
W=$(cd -- "$W" && pwd -P)

FIXDB=$ROOT/tests/fixtures/dast/versions.db

# ---------------------------------------------------------------------------
# Fixture install roots - tests/suites/network.sh's own shape.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

# `_hp_listeners_json TARGET SCHEME HOST PORT [SCHEME HOST PORT ...]` - one
# `role: extra-host` row per triple, matching modules/network/inventory.sh's
# own written shape exactly (its own header comment gives the schema) so
# httpport_listeners_load is exercised against the real producer's format,
# not a shape this suite invented for itself.
_hp_listeners_json() {
  local target=$1; shift
  local scheme host port first=1
  printf '{\n  "schema": "scoursh.inventory.listeners/1",\n  "run_id": "fixture",\n  "generated_by": "modules/network/inventory.sh",\n  "target": "%s",\n  "listeners": [\n' "$target"
  printf '    {"target": "%s", "role": "base-url", "scheme": "https", "host": "base.fixture.invalid", "port": 443}' "$target"
  while (( $# >= 3 )); do
    scheme=$1; host=$2; port=$3; shift 3
    printf ',\n    {"target": "%s", "role": "extra-host", "scheme": "%s", "host": "%s", "port": %s}' \
      "$target" "$scheme" "$host" "$port"
  done
  printf '\n  ]\n}\n'
}

REQ_LOG=$W/requests.log
: >"$REQ_LOG"

# The scripted SERVER: replays a canned response by (host,port), the same
# "recorded response" idiom tests/suites/dast-banner.sh's own `_banner_transport`
# uses. SRV_CASE selects which behaviour a case wants; unhandled hosts return
# failure (a connection that never answers), so an unexpected request is a
# transport failure the suite can observe rather than a silent 200.
SRV_CASE=basic
_hp_transport() {
  local method=$1 scheme=$2 host=$3 port=$4 path=$5 bodyout=${7:-} hdrsout=${8:-}
  printf '%s %s://%s:%s%s\n' "$method" "$scheme" "$host" "$port" "$path" >>"$REQ_LOG"
  case $SRV_CASE:$host:$port in
    vuln:extra.fixture.invalid:8080)
      [[ -n $hdrsout ]] && printf 'HTTP/1.1 200 OK\r\nServer: fixtureserver/1.2.3\r\n\r\n' >>"$hdrsout"
      [[ -n $bodyout ]] && : >"$bodyout"
      printf '200\n\ntext/plain\n'
      ;;
    clean:extra.fixture.invalid:8080)
      [[ -n $hdrsout ]] && printf 'HTTP/1.1 200 OK\r\nServer: fixtureserver/9.9.9\r\n\r\n' >>"$hdrsout"
      [[ -n $bodyout ]] && : >"$bodyout"
      printf '200\n\ntext/plain\n'
      ;;
    nameonly:extra.fixture.invalid:8080)
      [[ -n $hdrsout ]] && printf 'HTTP/1.1 200 OK\r\nServer: unversionedwidget\r\n\r\n' >>"$hdrsout"
      [[ -n $bodyout ]] && : >"$bodyout"
      printf '200\n\ntext/plain\n'
      ;;
    twolisteners:extra1.fixture.invalid:8080)
      [[ -n $hdrsout ]] && printf 'HTTP/1.1 200 OK\r\nServer: fixtureserver/1.2.3\r\n\r\n' >>"$hdrsout"
      [[ -n $bodyout ]] && : >"$bodyout"
      printf '200\n\ntext/plain\n'
      ;;
    twolisteners:extra2.fixture.invalid:9443)
      [[ -n $hdrsout ]] && printf 'HTTP/1.1 200 OK\r\nServer: fixturelib/4.0.0\r\n\r\n' >>"$hdrsout"
      [[ -n $bodyout ]] && : >"$bodyout"
      printf '200\n\ntext/plain\n'
      ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_hp_transport

_hp_resolve() {
  case $1 in
    base.fixture.invalid) printf '203.0.113.1' ;;
    extra.fixture.invalid) printf '203.0.113.2' ;;
    extra1.fixture.invalid) printf '203.0.113.3' ;;
    extra2.fixture.invalid) printf '203.0.113.4' ;;
    outofscope.fixture.invalid) printf '203.0.113.5' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_hp_resolve

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  SCOURSH_NET_TARGET=hp-fixture
  SCOURSH_NET_CELL=hp-fixture
  export SCOURSH_NET_TARGET SCOURSH_NET_CELL
  : >"$REQ_LOG"
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_meta_text() {
  local key=$1
  local f=$SCOURSH_RUN_DIR/meta/$key
  [[ -r $f ]] && cat -- "$f" || printf ''
}

# Every host this suite's positive cases probe (extra.fixture.invalid,
# extra1/extra2.fixture.invalid) is declared here as an `extra-host` -
# http_request's own gate is FATAL for a tuple config/scope.conf does not
# authorise, exactly as report.md §5.2 rule 1 requires for an
# operator-configured tuple, so a listener this suite wants httpport.sh to
# actually GET must be declared, not merely resolvable.
# `outofscope.fixture.invalid` (used by the artifact-tuple-skip case below) is
# DELIBERATELY ABSENT from this list: it resolves (SCOURSH_HTTP_RESOLVE admits
# it) but is not declared, which is exactly the "a listeners.json row names a
# tuple config/scope.conf never authorised" shape that case exists to prove.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: hp-fixture
base-url: https://base.fixture.invalid/
extra-host: extra.fixture.invalid:8080
extra-host: extra1.fixture.invalid:8080
extra-host: extra2.fixture.invalid:9443
allow-subdomains: false
notes: Fixture target for tests/suites/network-httpport.sh. Never dialled
  for real - both the resolver and the transport are stubbed.
EOF

# =============================================================================
printf '\n-- httpport_listeners_load: extra-host only, base-url excluded --\n'
# =============================================================================

http_scope_load "$SCOPE"

LJ=$W/listeners-basic.json
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$LJ"

httpport_listeners_load "$LJ" hp-fixture
t_case 'exactly one extra-host candidate, the base-url row is never a candidate'
assert_eq 1 "$_HTTPPORT_L_N" \
  'httpport_listeners_load reports one candidate - FAILS if the base-url row were included as a second candidate, which would send an HTTP GET at the target'"'"'s own primary port that modules/dast/ already covers in full'
assert_eq extra.fixture.invalid "${_HTTPPORT_L_HOST[0]}" 'the surviving candidate is the extra-host row'
assert_eq 8080 "${_HTTPPORT_L_PORT[0]}" 'and its declared port'

LJ_NOSCHEME=$W/listeners-nonhttp.json
cat >"$LJ_NOSCHEME" <<'EOF'
{
  "schema": "scoursh.inventory.listeners/1",
  "run_id": "fixture",
  "generated_by": "modules/network/inventory.sh",
  "target": "hp-fixture",
  "listeners": [
    {"target": "hp-fixture", "role": "base-url", "scheme": "https", "host": "base.fixture.invalid", "port": 443},
    {"target": "hp-fixture", "role": "extra-host", "scheme": "ssh", "host": "extra.fixture.invalid", "port": 22}
  ]
}
EOF
httpport_listeners_load "$LJ_NOSCHEME" hp-fixture
t_case 'a declared extra-host listener with a non-http/https scheme is never a candidate'
assert_eq 0 "$_HTTPPORT_L_N" \
  'zero candidates - FAILS if an ssh-scheme row were handed to http_request as if it spoke HTTP'

# =============================================================================
printf '\n-- a known-vulnerable version disclosed on a non-standard port fires the outdated check --\n'
# =============================================================================

SCOURSH_DAST_VERSIONS_DB=$FIXDB
export SCOURSH_DAST_VERSIONS_DB

_fresh_run
SRV_CASE=vuln
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
SHARD=$(_shard_text)

t_case 'the version and outdated-component checks fire for the vulnerable listener'
assert_contains "$SHARD" 'check_id=NET-SVC-HTTP_VERSION_DISCLOSURE-01' \
  'the version disclosure fires - FAILS if a Server header with a version were reported only as a name-only disclosure'
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP_SERVER_DISCLOSURE-01' \
  'a Server header that DOES carry a version is never ALSO reported as a bare name-only disclosure - FAILS if _httpport_consider double-counted one header value into both buckets'
assert_contains "$SHARD" 'check_id=NET-SVC-HTTP_OUTDATED_COMPONENT-01' \
  'the outdated-component check fires on the exact fixtureserver/1.2.3 versions.db match - FAILS under any "close enough" heuristic reading, since this is an EXACT table lookup (report.md §3.4)'

t_case 'the finding carries the net location profile - host, port and transport, not a DAST-shaped identity'
assert_contains "$SHARD" 'loc_host=extra.fixture.invalid' 'loc_host names the probed listener'
assert_contains "$SHARD" 'loc_port=8080' 'loc_port names its declared port, not the base-url'"'"'s 443'
assert_contains "$SHARD" 'loc_transport=https' 'loc_transport names the scheme actually used for the GET'
assert_contains "$SHARD" 'confidence=medium' \
  'the outdated finding is confidence: medium, never high - report.md §3.4'"'"'s backport caveat: a banner-read version cannot see a distribution'"'"'s own backported fix'

t_case 'checks_run records all three ids for a successfully-probed listener'
CR=$(_meta_text checks_run)
assert_contains "$CR" 'NET-SVC-HTTP_SERVER_DISCLOSURE-01' 'server-disclosure id recorded as run'
assert_contains "$CR" 'NET-SVC-HTTP_VERSION_DISCLOSURE-01' 'version-disclosure id recorded as run'
assert_contains "$CR" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' 'outdated-component id recorded as run'

t_case 'exactly one GET was sent to the declared listener, and none to base-url'
assert_eq 1 "$(grep -c . "$REQ_LOG")" 'one request total'
assert_contains "$(cat "$REQ_LOG")" 'GET https://extra.fixture.invalid:8080/' \
  'the one request targets the declared extra-host listener'
assert_not_contains "$(cat "$REQ_LOG")" 'base.fixture.invalid' \
  'base.fixture.invalid was never requested by this check - FAILS if the base-url row were mistakenly treated as a candidate'

# =============================================================================
printf '\n-- a current/unlisted version stays quiet on the outdated check, but discloses --\n'
# =============================================================================

_fresh_run
SRV_CASE=clean
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
SHARD=$(_shard_text)

t_case 'fixtureserver 9.9.9 is not in the fixture versions.db, so the outdated check stays silent'
assert_contains "$SHARD" 'check_id=NET-SVC-HTTP_VERSION_DISCLOSURE-01' \
  'the version is still disclosed - a clean-version result is not the same as no response being read at all'
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP_OUTDATED_COMPONENT-01' \
  'no outdated-component finding - FAILS under a "close to a known-bad version" heuristic, which report.md §3.4 explicitly forbids: only an EXACT match is a finding'
CR=$(_meta_text checks_run)
assert_contains "$CR" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' \
  'the outdated check id is still recorded as RUN (it executed and found nothing) - FAILS if a clean result were indistinguishable from the check never having executed at all'

# =============================================================================
printf '\n-- a name with no version is a server-disclosure only, never a version disclosure --\n'
# =============================================================================

_fresh_run
SRV_CASE=nameonly
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
SHARD=$(_shard_text)

t_case 'a bare product name with no version is NET-SVC-HTTP_SERVER_DISCLOSURE-01 only'
assert_contains "$SHARD" 'check_id=NET-SVC-HTTP_SERVER_DISCLOSURE-01' 'the name-only disclosure fires'
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP_VERSION_DISCLOSURE-01' \
  'no version-disclosure finding - FAILS if a name with no version were reported as a version disclosure anyway'
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP_OUTDATED_COMPONENT-01' \
  'no outdated finding either - there is no version to look up'

# =============================================================================
printf '\n-- report.md §5.2 rule 3: no non-standard listener records a reduction and sends nothing --\n'
# =============================================================================

_fresh_run
# _NET_LISTENERS_STATE=absent: no inventory/listeners.json file at all.
_hp_source_phase
t_case 'an absent listeners.json records a coverage_reduction and a coverage_gap, and sends no request'
CR=$(_meta_text coverage_reduction)
assert_contains "$CR" 'reason=no_http_listener' \
  'the reduction names the reason - FAILS if a target with no declared listener silently produced zero findings, which reads identically to "scoursh looked and found nothing"'
GAP=$(_meta_text coverage_gap)
assert_contains "$GAP" 'no non-standard-port HTTP response was examined' 'the gap is stated in plain language too'
assert_eq 0 "$(grep -c . "$REQ_LOG")" 'no request was sent - FAILS if this phase invented a port to probe with no declared listener behind it'
SHARD=$(_shard_text)
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP' 'no finding of any kind was emitted'

_fresh_run
mkdir -p "$SCOURSH_RUN_DIR/inventory"
: >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
t_case 'an empty listeners.json (state=empty) is the identical honest outcome as absent'
CR=$(_meta_text coverage_reduction)
assert_contains "$CR" 'reason=no_http_listener' 'the same reason fires for an empty artifact'
assert_eq 0 "$(grep -c . "$REQ_LOG")" 'no request was sent'

# =============================================================================
printf '\n-- report.md §5.2 rule 1: an out-of-scope artifact-tuple row is a counted skip, not a fatal abort --\n'
# =============================================================================

_fresh_run
mkdir -p "$SCOURSH_RUN_DIR/inventory"
# outofscope.fixture.invalid resolves (the resolver stub above admits it) but
# is NOT declared in config/scope.conf at all - a listeners.json row this
# scanner did not author itself, matching report.md §5.2 rule 1's own
# "artifact this scanner did not author" shape exactly.
_hp_listeners_json hp-fixture https outofscope.fixture.invalid 9200 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
t_case 'an out-of-scope declared-listener row is dropped as ONE counted reduction, and the run does not abort'
CR=$(_meta_text coverage_reduction)
assert_contains "$CR" 'reason=artifact_tuple_out_of_scope' \
  'the artifact-tuple pre-check (net_endpoint_keep) dropped it - FAILS under "listeners.json rows are re-gated fatally, exactly like an operator-configured scope.conf tuple", which would die exit 3 over a row this phase did not author (modules/network/httpport.sh'"'"'s own header explains why that reading is wrong here)'
assert_eq 0 "$(grep -c . "$REQ_LOG")" \
  'no request was sent to the out-of-scope host - FAILS if the pre-check were skipped and http_request were called directly on it'
SHARD=$(_shard_text)
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP' 'no finding was emitted for a listener that was never probed'

# =============================================================================
printf '\n-- a transport failure is its own named, counted reduction --\n'
# =============================================================================

_fresh_run
SRV_CASE=doesnotexist
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
t_case 'a listener that fails at the transport records net_http_unavailable, not a silent clean result'
CR=$(_meta_text coverage_reduction)
assert_contains "$CR" 'reason=net_http_unavailable' \
  'FAILS if a connection failure were swallowed, which would let "the listener never answered" render identically to "it answered cleanly" - report.md §5.2 rule 4'"'"'s own filtered/not-open distinction, applied here'
GAP=$(_meta_text coverage_gap)
assert_contains "$GAP" 'failed at the transport' 'the human-readable gap says so too'
SHARD=$(_shard_text)
assert_not_contains "$SHARD" 'check_id=NET-SVC-HTTP' 'no finding from a listener that never answered'

# =============================================================================
printf '\n-- two distinct listeners produce two distinct, non-colliding findings --\n'
# =============================================================================

_fresh_run
SRV_CASE=twolisteners
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra1.fixture.invalid 8080 https extra2.fixture.invalid 9443 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase
SHARD=$(_shard_text)

t_case 'the net location profile (host, port, transport) keeps two listeners'"'"' disclosures apart'
assert_contains "$SHARD" 'loc_host=extra1.fixture.invalid' 'the first listener'"'"'s host is in a finding'
assert_contains "$SHARD" 'loc_host=extra2.fixture.invalid' 'the second listener'"'"'s host is in a finding too - FAILS if the coarse net fingerprint collapsed two different listeners onto one finding'
assert_contains "$SHARD" 'loc_port=8080' 'the first listener'"'"'s port'
assert_contains "$SHARD" 'loc_port=9443' 'the second listener'"'"'s port'
N_OUTDATED=$(grep -c 'check_id=NET-SVC-HTTP_OUTDATED_COMPONENT-01' <<<"$SHARD")
assert_eq 2 "$N_OUTDATED" \
  'two DISTINCT outdated-component findings, one per listener - both extra1'"'"'s fixtureserver/1.2.3 and extra2'"'"'s fixturelib/4.0.0 have an exact versions.db row (the latter'"'"'s carries an unusable "notaseverity" severity - matching still happens on (product,version) alone, never on whether the row'"'"'s own severity is well-formed) - FAILS if the coarse net fingerprint (no product/version component) collapsed the two onto one finding instead of keeping them apart by loc_host/loc_port'

t_case 'an unrecognised severity value in the vendored list falls back rather than silencing the row'
assert_contains "$SHARD" 'base_severity=high' \
  'fixturelib 4.0.0'"'"'s db row carries severity "notaseverity" - banner_db_match'"'"'s own severity_rank fallback defaults an unusable value to high (modules/dast/passive/banner_engine.sh'"'"'s own _banner_severity_max), reused unchanged here'

# =============================================================================
printf '\n-- findings round-trip through every report format via the real report_all path --\n'
# =============================================================================

_fresh_run
SRV_CASE=vuln
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
_hp_source_phase

# The identical five-call tail modules/network/run.sh's own _net_run_module
# ends every target's loop with - findings_merge, derive_findings,
# diff_classify_run (a no-op with no state/ this suite touches), then the
# renderers, so this is the SAME path a real `scan.sh network` run takes
# rather than a second, hand-rolled rendering call this suite invents.
findings_merge "$SCOURSH_RUN_DIR"
derive_findings "$SCOURSH_RUN_DIR"
SCOURSH_FORMATS='json,md,html,sarif,agent'
export SCOURSH_FORMATS
report_all "$SCOURSH_RUN_DIR"

t_case 'the finding round-trips into findings.jsonl and findings.json'
JSONL=$(cat -- "$SCOURSH_RUN_DIR/findings.jsonl")
assert_contains "$JSONL" '"check_id":"NET-SVC-HTTP_OUTDATED_COMPONENT-01"' \
  'findings.jsonl (mandatory per AGENTS.md) carries the finding'
JSON=$(cat -- "$SCOURSH_RUN_DIR/findings.json")
assert_contains "$JSON" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' 'findings.json (the --format json artifact) carries it too'

t_case 'report.md and report.html render the finding under a real "Network" category label'
MD=$(cat -- "$SCOURSH_RUN_DIR/report.md")
assert_contains "$MD" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' 'report.md names the check id'
HTML=$(cat -- "$SCOURSH_RUN_DIR/report.html")
assert_contains "$HTML" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' 'report.html names the check id'
assert_contains "$HTML" '>Network<' \
  'the finding'"'"'s category group is labelled "Network", not the bare module string "net" - FAILS if lib/report.sh'"'"'s _RPT_CAT_LABEL map, keyed by the finding'"'"'s own module field, carried no [net] entry'

t_case 'the SARIF rule registry and results both name the check'
SARIF=$(cat -- "$SCOURSH_RUN_DIR/report.sarif")
assert_contains "$SARIF" '"id":"NET-SVC-HTTP_OUTDATED_COMPONENT-01"' \
  'the rule is registered - FAILS if modules/network/checks-httpport.rules were not discovered by _sarif_build_registry (it globs every *.rules under modules/network/, the network module'"'"'s own registry directory)'

t_case 'the --format agent scaffold carries the finding and attributes it to the net module'
AGENT=$(cat -- "$SCOURSH_RUN_DIR/agent-fix.json")
assert_contains "$AGENT" 'NET-SVC-HTTP_OUTDATED_COMPONENT-01' 'the agent-format finding scaffold carries the check id'
assert_contains "$AGENT" '"mod":"net"' 'and the finding'"'"'s own module field, verbatim'

# =============================================================================
printf '\n-- no traffic tool is ever invoked directly, and no socket bypasses http_request --\n'
# =============================================================================

_fresh_run
SRV_CASE=vuln
mkdir -p "$SCOURSH_RUN_DIR/inventory"
_hp_listeners_json hp-fixture https extra.fixture.invalid 8080 >"$SCOURSH_RUN_DIR/inventory/listeners.json"
STUB=$W/stub-bin
mkdir -p "$STUB"
for c in curl wget nc ncat netcat openssl; do
  cat >"$STUB/$c" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "$c" "\$*" >>"$W/direct-tool-invocations"
exit 1
EOF
  chmod 0755 "$STUB/$c"
done
rm -f "$W/direct-tool-invocations"
PATH="$STUB:$PATH" _hp_source_phase
t_case 'httpport.sh never shells out to a transport tool directly - only through SCOURSH_HTTP_TRANSPORT'
assert_file_absent "$W/direct-tool-invocations" \
  'FAILS if this phase (or httpport_engine.sh) ever opened a socket or invoked curl/wget/nc/openssl itself instead of going through lib/http.sh'"'"'s http_request alone'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID='' SCOURSH_DAST_VERSIONS_DB='' SCOURSH_FORMATS=''

t_summary 'network-httpport'
