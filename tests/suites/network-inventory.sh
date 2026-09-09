#!/usr/bin/env bash
# tests/suites/network-inventory.sh - modules/network/inventory.sh: the
# authorised listener set (NET-05,
# data/scoursh-network-scan-design/report.md §7's Tier 1, serial ticket).
# Every Tier 2+ ticket (NET-06..09) reads the one artifact this file writes,
# so this suite pins its shape and its honesty contract directly, separately
# from tests/suites/network.sh's own dispatch/orchestration coverage.
#
# Five things this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. A target with real extra-host listeners produces EXACTLY that
#      authorised set - base-url plus every declared extra-host, no more, no
#      fewer - in reports/<run>/inventory/listeners.json.
#   2. A target whose declared set holds ONLY base-url writes NO artifact at
#      all and records ONE coverage_gap naming why, then exits 0 - report.md
#      §5.2 rule 3.  "This host has one listener" and "scoursh did not look"
#      are different facts.
#   3. An out-of-scope tuple (here: a declared extra-host that resolves to a
#      link-local address - 169.254.169.254, the cloud metadata endpoint
#      lib/http.sh's own deny-list comment names by example - with no
#      allow-private-addresses: true) is refused FATALLY through
#      http_authorize_raw_connection, exit 3 - report.md §5.2 rule 1: every
#      tuple this file reads is operator-configured, so a refusal is never a
#      soft skip.
#   4. A transient DNS failure on ONE declared listener degrades to a single
#      counted coverage_reduction and the run continues, producing the
#      authorised set MINUS the unresolvable listener - the one named
#      softening this file's own header borrows from
#      modules/dast/passive/tls.sh, so one bad lookup does not abort every
#      sibling listener.
#   5. No real network call and no socket is ever opened - every transport
#      tool stays untouched even when the declared set has real extra
#      listeners to authorise.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a fixture root can never leak into the
#   next case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh's own bottom-of-file `scratch_init` call is what SCOURSH_SCRATCH
# below depends on - sourced directly (rather than only transitively through
# modules/network/engine.sh, which this suite has no other reason to load at
# top level) for the identical reason tests/suites/network.sh's own header
# note gives for canonicalising $W right after: this suite wants its scratch
# root before anything else runs.
# shellcheck source=/dev/null
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/network-inventory
rm -rf "$W"
mkdir -p "$W"
# Canonicalise, the identical reason tests/suites/network.sh's own comment
# gives: lib/records.sh strips $SCOURSH_INSTALL_ROOT as a literal prefix, so a
# fixture root reached through macOS's /var -> /private/var symlink would
# break that strip.
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# Fixture install roots - tests/suites/network.sh's own shape, copied rather
# than symlinked for the identical reason: a symlinked modules/ resolves back
# to the real repo's realpath the moment a real file exists there.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

# Every hostname below is an RFC 2606-reserved *.invalid name, so none of
# them resolve for real; SCOURSH_HTTP_RESOLVE (lib/http.sh section 7) is
# stubbed to a script rather than a function so it survives crossing into the
# `bash scan.sh` subprocess _net_scan launches.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  multi.fixture.invalid) printf '203.0.113.10' ;;
  priv.fixture.invalid) printf '203.0.113.20' ;;
  internal.fixture.invalid) printf '169.254.169.254' ;;
  mixed.fixture.invalid) printf '203.0.113.30' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"
export SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB

# `_net_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh network`
# subprocess, mirroring tests/suites/network.sh's own helper exactly. Sets
# _RC and _LOG.
_net_scan() {
  local rundir=$1 root=$2
  shift 2
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$root SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
    bash "$ROOT/scan.sh" network --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- a target with extra declared listeners produces exactly that set --\n'
# =============================================================================

FIX_MULTI=$W/root-multi
_fixture_root "$FIX_MULTI"
cat >"$FIX_MULTI/config/scope.conf" <<'EOF'
id: net-multi
base-url: https://multi.fixture.invalid/
extra-host: multi.fixture.invalid:8443
extra-host: multi.fixture.invalid:9200
allow-subdomains: false
EOF

t_case 'a run over a target with two extra-host listeners exits 0 and writes listeners.json'
_net_scan "$W/run-multi" "$FIX_MULTI" --target net-multi
assert_eq 0 "$_RC" \
  'scan.sh network --target net-multi exits 0 - FAILS if authorising three already-declared, resolvable tuples were somehow treated as a refusal'
assert_file_exists "$W/run-multi/inventory/listeners.json" \
  'inventory/listeners.json exists - FAILS under report.md §5.2 rule 3'"'"'s "absent when only base-url" reading applied to a target that plainly declares two extra listeners'

LISTENERS_JSON=$(_slurp "$W/run-multi/inventory/listeners.json")
t_case 'the artifact names its own schema, run and producer'
assert_contains "$LISTENERS_JSON" '"schema": "scoursh.inventory.listeners/1"' \
  'the schema field is present and versioned - FAILS if the shape ships with no schema token, which is exactly what would make a NET-06+ reader unable to detect a future incompatible change'
assert_contains "$LISTENERS_JSON" '"generated_by": "modules/network/inventory.sh"' \
  'the producer is named'
assert_contains "$LISTENERS_JSON" '"target": "net-multi"' \
  'the target id is named at the top level'

t_case 'the authorised set contains exactly the base-url row and the two declared extra-host rows'
assert_contains "$LISTENERS_JSON" '"role": "base-url", "scheme": "https", "host": "multi.fixture.invalid", "port": 443' \
  'the base-url tuple is in the authorised set - FAILS if inventory.sh reports only the extra-host rows and silently drops its own base-url row, which report.md §5.2 rule 3'"'"'s own "only base-url" wording implies is itself part of "the declared set"'
assert_contains "$LISTENERS_JSON" '"role": "extra-host", "scheme": "https", "host": "multi.fixture.invalid", "port": 8443' \
  'the first declared extra-host listener is in the authorised set'
assert_contains "$LISTENERS_JSON" '"role": "extra-host", "scheme": "https", "host": "multi.fixture.invalid", "port": 9200' \
  'the second declared extra-host listener is in the authorised set'
LISTENER_COUNT=$(grep -c '"role":' <<<"$LISTENERS_JSON")
assert_eq 3 "$LISTENER_COUNT" \
  'exactly three listener rows, no more and no fewer - FAILS if a fourth, invented row appeared, or if one of the three declared tuples were silently coalesced with another'

t_case 'no coverage_reduction or coverage_gap was recorded for a fully-authorised, fully-resolvable declared set'
CR_MULTI=$(_slurp "$W/run-multi/meta/coverage_reduction")
assert_not_contains "$CR_MULTI" 'net_listener_unresolvable' \
  'nothing was dropped for a target where every declared tuple resolves - FAILS if the DNS-softening path spuriously fires on a target with no DNS problem at all'
GAP_MULTI=$(_slurp "$W/run-multi/meta/coverage_gap")
assert_not_contains "$GAP_MULTI" "declares only its base-url" \
  'the rule-3 "declares only base-url" gap text is absent - FAILS if it fires even though net-multi plainly declares two extra listeners'

# =============================================================================
printf '\n-- report.md §5.2 rule 3: a base-url-only target writes no artifact --\n'
# =============================================================================

FIX_SOLO=$W/root-solo
_fixture_root "$FIX_SOLO"
cat >"$FIX_SOLO/config/scope.conf" <<'EOF'
id: net-solo
base-url: https://solo.fixture.invalid/
allow-subdomains: false
EOF

t_case 'a base-url-only target exits 0 and writes no listeners.json'
_net_scan "$W/run-solo" "$FIX_SOLO" --target net-solo
assert_eq 0 "$_RC" \
  'a target with no extra-host listener still exits 0 - FAILS if the honest zero-listener case were made fatal instead of a declared coverage_gap'
assert_file_absent "$W/run-solo/inventory/listeners.json" \
  'no artifact is written - FAILS if a file naming only the base-url row were written anyway, which a future NET-06+ reader could mistake for "this target has one authorised extra listener: itself"'

t_case 'net_inventory_read reports the artifact absent for a base-url-only run'
(
  # shellcheck source=/dev/null
  source "$FIX_SOLO/modules/network/engine.sh"
  net_inventory_read "$W/run-solo"
  [[ $_NET_LISTENERS_STATE == absent ]] || exit 1
  [[ -z $_NET_LISTENERS_FILE ]] || exit 1
)
assert_eq 0 "$?" \
  'net_inventory_read (modules/network/engine.sh) reports state=absent and an empty file path - FAILS if a future NET-06+ reader had to special-case "file does not exist" itself rather than reading the same absent/empty/present vocabulary dast_inventory_read already established'

t_case 'run.json records the rule-3 coverage_gap naming the target and its base-url'
SOLO_JSON=$(_slurp "$W/run-solo/run.json")
assert_contains "$SOLO_JSON" "target 'net-solo' declares only its base-url (https://solo.fixture.invalid:443)" \
  'the coverage_gap names the target and its base-url tuple explicitly - FAILS if the gap were generic and a reader with several targets could not tell which one it is about'
assert_contains "$SOLO_JSON" "'This host has one listener' and 'scoursh did not look' are different facts" \
  'the gap states the docs/DESIGN.md §15 / report.md §5.2 rule 3 warning in the artifact itself, not only in prose a reader has to already know'

# =============================================================================
printf '\n-- report.md §5.2 rule 1: an out-of-scope declared tuple is refused fatally --\n'
# =============================================================================

FIX_PRIV=$W/root-priv
_fixture_root "$FIX_PRIV"
cat >"$FIX_PRIV/config/scope.conf" <<'EOF'
id: net-priv
base-url: https://priv.fixture.invalid/
extra-host: internal.fixture.invalid:5432
allow-subdomains: false
EOF

t_case 'a declared extra-host that resolves to a link-local address (169.254.169.254) with no allow-private-addresses is exit 3, not a soft skip'
_net_scan "$W/run-priv" "$FIX_PRIV" --target net-priv
assert_eq 3 "$_RC" \
  'the whole run dies exit 3 (SCOURSH_EXIT_SCOPE) through http_authorize_raw_connection - FAILS under "an operator-declared listener that happens to resolve to a deny-listed address is quietly dropped like a DNS failure", which report.md §5.2 rule 1 and this file'"'"'s own header both refuse: there is no non-fatal path for an operator-authored config/scope.conf mistake, only for a transient DNS failure. lib/http.sh'"'"'s deny list (_http_ipv4_denied) covers loopback, link-local/169.254.0.0/16 (which includes the cloud metadata address used here), CGN and 0.0.0.0/8 - NOT the full RFC1918 private ranges, so this fixture deliberately uses a link-local address rather than a 10.x/172.16.x/192.168.x one'
assert_file_absent "$W/run-priv/inventory/listeners.json" \
  'no partial artifact survives a fatal refusal - FAILS if the base-url row (which DOES resolve, publicly) were written before the fatal extra-host row aborted the process, leaving a listeners.json a reader could mistake for a complete authorised set'

# =============================================================================
printf '\n-- report.md §5.2 rule 1: a transient DNS failure degrades, one bad listener does not sink the rest --\n'
# =============================================================================

FIX_MIXED=$W/root-mixed
_fixture_root "$FIX_MIXED"
cat >"$FIX_MIXED/config/scope.conf" <<'EOF'
id: net-mixed
base-url: https://mixed.fixture.invalid/
extra-host: mixed.fixture.invalid:8443
extra-host: nowhere.fixture.invalid:9999
allow-subdomains: false
EOF

t_case 'a run with one resolvable and one unresolvable extra-host listener still exits 0'
_net_scan "$W/run-mixed" "$FIX_MIXED" --target net-mixed
assert_eq 0 "$_RC" \
  'the run exits 0 despite one declared listener failing to resolve - FAILS under "http_authorize_raw_connection is always called with its fatal default", which would die exit 3 on the very first unresolvable host and abort every sibling listener with it'

MIXED_JSON=$(_slurp "$W/run-mixed/inventory/listeners.json")
t_case 'the authorised set contains the two resolvable tuples and NOT the unresolvable one'
assert_contains "$MIXED_JSON" '"role": "base-url"' 'the base-url row survived (it resolves)'
assert_contains "$MIXED_JSON" '"host": "mixed.fixture.invalid", "port": 8443' \
  'the resolvable extra-host listener survived'
assert_not_contains "$MIXED_JSON" 'nowhere.fixture.invalid' \
  'the unresolvable extra-host listener is ABSENT from the authorised set - FAILS if a dropped tuple were written anyway, which would hand a future NET-06+ probe a listener nothing ever confirmed as authorised'
MIXED_COUNT=$(grep -c '"role":' <<<"$MIXED_JSON")
assert_eq 2 "$MIXED_COUNT" 'exactly two surviving rows, not three'

t_case 'the DNS failure is recorded as ONE counted coverage_reduction, never a fatal abort'
CR_MIXED=$(_slurp "$W/run-mixed/meta/coverage_reduction")
assert_contains "$CR_MIXED" 'module=network phase=inventory.sh reason=net_listener_unresolvable target=net-mixed count=1' \
  'one reduction naming the module, phase, reason, target and the real count of dropped tuples'
assert_eq 1 "$(grep -c 'reason=net_listener_unresolvable' <<<"$CR_MIXED")" \
  'written exactly once, not once per resolution attempt'

# =============================================================================
printf '\n-- no real network call and no socket is ever opened --\n'
# =============================================================================

t_case 'even with real extra listeners to authorise, no transport tool is ever invoked'
STUB=$W/stub-bin
mkdir -p "$STUB"
for c in curl wget nc ncat netcat openssl; do
  cat >"$STUB/$c" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "$c" "\$*" >>"$W/network-attempts"
exit 1
EOF
  chmod 0755 "$STUB/$c"
done
rm -f "$W/network-attempts"
_NT_RC=0
SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" network --target net-multi --out "$W/run-multi-notraffic" \
  >"$W/run-multi-notraffic.log" 2>&1 || _NT_RC=$?
assert_eq 0 "$_NT_RC" \
  'the run still exits 0 with a poisoned PATH - inventory.sh never reaches for curl/wget/nc/openssl, only lib/http.sh'"'"'s own authorization/DNS-resolution machinery, which this suite'"'"'s SCOURSH_HTTP_RESOLVE stub already replaces'
assert_file_absent "$W/network-attempts" \
  'no curl/wget/nc/ncat/netcat/openssl was invoked while authorising three real, declared listeners - FAILS if inventory.sh (or a future change to it) ever opened a socket or shelled out to a transport tool directly instead of going through http_authorize_raw_connection alone'
assert_file_exists "$W/run-multi-notraffic/inventory/listeners.json" \
  'sanity: the run still produced the authorised set despite the poisoned PATH, proving the no-traffic result above is not an accidental early failure'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-inventory'
