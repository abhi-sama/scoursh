#!/usr/bin/env bash
# tests/suites/network.sh - modules/network/: the `scan_dispatch network`
# entry point, the target/intensity orchestration, and the report.md §5.2
# honesty contract (NET-04, data/scoursh-network-scan-design/report.md).
#
# The four things this suite exists to pin, because each has a plausible
# wrong reading that would ship silently - mirroring tests/suites/dast.sh's
# own three, plus the honesty contract's own tuple-authorization split:
#
#   1. The scope gate is NOT the module's to soften.  An unauthorised
#      --target is still exit 3 and a wholly missing config/scope.conf is
#      still exit 4, and the module re-asserts the gate itself rather than
#      trusting scan.sh already did.
#   2. A run with NO phase script sends NOTHING and says so, on run.json and
#      on the report - the surfaces a consumer actually reads, never only an
#      internal record.  A target with only base-url (every target in this
#      ticket's world) records a coverage_gap and exits 0 (report.md §5.2
#      rule 3).
#   3. Intensity is a real gate, not a recorded string - the identical
#      alphabetical-order trap tests/suites/dast.sh's own case 3 pins
#      (`active` < `passive` < `safe` lexically, the exact reverse of the
#      tier order).
#   4. report.md §5.2 rule 1's TWO-TIER authorization split is real: an
#      operator-configured tuple (config/scope.conf) is refused FATALLY
#      (http_authorize_raw_connection, exit 3) and a tuple lifted out of an
#      ARTIFACT this scanner did not author degrades NON-FATALLY to one
#      counted coverage_reduction, never collapsing the two.
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
# shellcheck source=/dev/null
source "$ROOT/modules/network/engine.sh"
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/network
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh resolves every loaded file's
# path via realpath and strips $SCOURSH_INSTALL_ROOT as a literal prefix, so a
# fixture root reached through macOS's /var -> /private/var $TMPDIR symlink
# would make the strip fail (tests/suites/dast.sh documents the same fact).
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# Fixture install roots - tests/suites/dast.sh's own shape, copied rather
# than symlinked for the identical reason its own comment gives: a symlinked
# modules/ would resolve back to the real repo's realpath the moment a real
# *.rules file exists there, breaking lib/records.sh's literal-prefix strip.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

FIX_SCOPE=$W/root-with-scope
_fixture_root "$FIX_SCOPE"
cat >"$FIX_SCOPE/config/scope.conf" <<'EOF'
id: net-fixture
base-url: https://net.fixture.invalid/
allow-subdomains: false
notes: Fixture scope target for tests/suites/network.sh. Nothing is ever
  sent to it: this suite asserts that a network run with no phase script on
  disk makes no probe at all.
EOF

FIX_NO_SCOPE=$W/root-no-scope
_fixture_root "$FIX_NO_SCOPE"

# `net.fixture.invalid` deliberately does NOT resolve (RFC 2606 reserved) -
# tests/suites/dast.sh's own SCOURSH_HTTP_RESOLVE stub, applied here so an
# out-of-scope-tuple assertion never depends on whatever DNS this suite
# happens to run under.  `tuple.fixture.invalid` (the §5.2 rule 1 section,
# below) DOES resolve, to a TEST-NET-3 (RFC 5737) literal never dialled by
# this suite - it needs an "in-scope AND resolves" case to prove the
# fatal/non-fatal split is a real scope decision rather than every raw
# connection being refused regardless of scope.conf, the identical
# "resolving direction is pinned too" shape tests/suites/dast.sh's own
# `dast-resolves.fixture.invalid` case already establishes.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  tuple.fixture.invalid) printf '203.0.113.5' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"
export SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB

# `_net_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh network`
# subprocess, the way an operator hits it.  Sets _RC and _LOG; the run
# directory is the caller's to inspect.
_net_scan() {
  local rundir=$1 root=$2
  shift 2
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$root bash "$ROOT/scan.sh" network --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- the scope gate is not the module'"'"'s to soften --\n'
# =============================================================================

t_case 'an authorised target completes cleanly and exits 0'
_net_scan "$W/run-ok" "$FIX_SCOPE" --target net-fixture
assert_eq 0 "$_RC" \
  'scan.sh network --target net-fixture exits 0 - FAILS under "a module with no checks is an incomplete run (exit 5)" and under "a module with no run.sh is the only clean network path"'
assert_file_exists "$W/run-ok/run.json" 'the run wrote run.json'

t_case 'a --target with no entry in a PRESENT scope.conf is still exit 3'
_net_scan "$W/run-unauth" "$FIX_SCOPE" --target no-such-target
assert_eq 3 "$_RC" \
  'an unauthorised target dies exit 3 - FAILS under "the module resolves its own targets and an unknown one is simply an empty target list"'

t_case 'a WHOLLY MISSING scope.conf is still exit 4, never exit 3'
_net_scan "$W/run-noscope" "$FIX_NO_SCOPE" --target anything
assert_eq 4 "$_RC" \
  'a missing config/scope.conf dies exit 4 - FAILS under "no file also means no matching entry, so it is exit 3 too" (docs/FOUNDATION.md tension 14)'

t_case 'network with no --target at all is a usage error (exit 2), not a crash'
_net_scan "$W/run-notarget" "$FIX_SCOPE"
assert_eq 2 "$_RC" \
  "'network' requires --target - FAILS if the required-flag map (scan.sh _SCAN_REQUIRED_FLAG) omits network and the run instead falls through to config_scope_require with an empty target"

t_case 'the module re-asserts the gate itself, not only through scan.sh'
_MOD_GATE_RC=0
(
  SCOURSH_INSTALL_ROOT=$FIX_SCOPE
  export SCOURSH_INSTALL_ROOT
  declare -A SCAN_FLAGS=([target]=no-such-target)
  export SCOURSH_RUN_DIR=$W/run-modgate
  mkdir -p "$SCOURSH_RUN_DIR/meta"
  source "$ROOT/modules/network/run.sh"
) >/dev/null 2>&1 || _MOD_GATE_RC=$?
assert_eq 3 "$_MOD_GATE_RC" \
  'sourcing modules/network/run.sh directly with an unauthorised target still dies exit 3 - FAILS under "scan.sh already called config_scope_require, so the module may trust its caller" (report.md §5.2 rule 1)'

# =============================================================================
printf '\n-- this ticket ships no phase script and issues no traffic --\n'
# =============================================================================

t_case 'a network run makes no network call at all, even with every transport tool on PATH'
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
_NET2_RC=0
SCOURSH_INSTALL_ROOT=$FIX_SCOPE PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" network --target net-fixture --out "$W/run-notraffic" \
  >"$W/run-notraffic.log" 2>&1 || _NET2_RC=$?
assert_eq 0 "$_NET2_RC" 'the run still exits 0 with a poisoned PATH, because it never reaches for a transport - there is no phase script on disk to reach for one with'
assert_file_absent "$W/network-attempts" \
  'no curl/wget/nc/openssl was invoked - FAILS if any phase script existed and tried to probe before this ticket landed one'

t_case 'nothing is claimed as executed'
RUN_OK_JSON=$(_slurp "$W/run-ok/run.json")
assert_contains "$RUN_OK_JSON" '"checks_run": []' \
  'checks_run is empty - FAILS under "record the phases we would have run", the overclaim this ticket exists to avoid'

# =============================================================================
printf '\n-- run.json tells the truth about a run that covered nothing --\n'
# =============================================================================

t_case 'run.json records the phases_present declared reduction naming the real cause, now that NET-05, NET-06, NET-08 and NET-09 have all landed'
assert_contains "$RUN_OK_JSON" 'module=network reason=no_check_covered_by_any_phase' \
  'run.json carries the declared reduction with its owning module token - FAILS if the module logs it only to stderr, which leaves the artifact claiming a complete run, or if it is written under the finding-module short form "net" instead of the SCAN_COMMANDS/checks_module_dir token "network" lib/report.sh'"'"'s _RPT_MODULES actually greps for. Since NET-05 (inventory.sh) landed, net-fixture'"'"'s own single-listener (base-url only) run now RUNS that one phase rather than finding it absent, so the reduction reason moves from no_phase_scripts_on_disk_yet to no_check_covered_by_any_phase - FAILS under the pre-NET-05 reading, where nothing on disk would ever run'
assert_contains "$RUN_OK_JSON" 'phases_expected=6 phases_present=4 phases_ran=2' \
  'and states the phase count honestly (6 rows in _NET_PHASES; inventory.sh (NET-05, passive) and tlsport.sh (NET-08, passive) present and RAN; reachability.sh (NET-06, safe) and httpport.sh (NET-09, safe) also present on disk now but both gated by this run'"'"'s default --intensity passive - present counts a real -f test on every phase file, ran counts only the ones the intensity ceiling actually let through, and the two are different numbers here for exactly that reason; the other 2 rows, banner.sh and transport.sh, are still absent) - FAILS if the phase table is declared but never actually walked, or if a phase'"'"'s mere PRESENCE on disk were conflated with having RUN'
assert_contains "$RUN_OK_JSON" 'reason=phase_above_intensity_ceiling target=net-fixture intensity=passive phases=[reachability.sh(>=safe) httpport.sh(>=safe)]' \
  'BOTH present-but-too-high-tier phases are named in ONE reduction, in the phase table'"'"'s own declared order (reachability.sh'"'"'s row precedes httpport.sh'"'"'s in _NET_PHASES) - FAILS if a phase that exists on disk but requires a higher --intensity than this run used were counted as merely "absent" (which would read identically to a phase that has not been written yet), or if the two present-but-gated phases produced two separate reduction lines instead of one naming both'

t_case 'run.json records a coverage_gap a human reads, naming the target'
assert_contains "$RUN_OK_JSON" "network covered nothing on target 'net-fixture'" \
  'the coverage_gap names the target by id - FAILS if the gap sentence is generic and a reader with two targets in one run.json cannot tell which one it is about'
assert_contains "$RUN_OK_JSON" 'absence of a test, not the absence of a problem' \
  'and states the docs/DESIGN.md §15 warning in the artifact itself, not only in prose a reader has to already know'

t_case 'the target and cell are recorded, and the coverage-scope is target'
assert_contains "$RUN_OK_JSON" '"targets": [' \
  'run.json carries a targets array'
assert_contains "$RUN_OK_JSON" 'net-fixture' \
  'naming this run'"'"'s own target'
NOTES_FILE=$(_slurp "$W/run-ok/meta/notes")
assert_contains "$NOTES_FILE" 'module=network target=net-fixture coverage-scope=target cell=net-fixture' \
  'the per-target notes line records network'"'"'s own coverage-scope (rules/RULE-FORMAT.md §9.5.1, NET-02: target) - FAILS if a copy-paste from modules/dast/run.sh left the literal string "module=dast" behind'

t_case 'the coverage_reduction and coverage_gap are each written EXACTLY ONCE per reason for one target'
CR_FILE=$(_slurp "$W/run-ok/meta/coverage_reduction")
assert_eq 1 "$(grep -c 'reason=no_check_covered_by_any_phase' <<<"$CR_FILE")" \
  'exactly one no_check_covered_by_any_phase reduction - FAILS if the phase loop or the per-target loop double-counts'
GAP_FILE=$(_slurp "$W/run-ok/meta/coverage_gap")
assert_eq 3 "$(grep -c "target 'net-fixture'" <<<"$GAP_FILE")" \
  'exactly THREE coverage_gap lines name this target - inventory.sh'"'"'s own report.md §5.2 rule 3 gap (net-fixture declares only base-url), tlsport.sh'"'"'s (NET-08) own "no non-base-url listener" gap, and modules/network/run.sh'"'"'s own generic "covered nothing" gap - FAILS if any producer'"'"'s gap silently swallows another'"'"'s, which would leave a reader unable to tell "this module has no check registry yet" apart from "this target declared no additional listener"'

# =============================================================================
printf '\n-- intensity is a real gate, not a recorded string --\n'
# =============================================================================

t_case 'net_intensity_permits orders passive < safe < active, never the lexical order'
if net_intensity_permits passive active; then r1=0; else r1=1; fi
assert_eq 1 "$r1" \
  'a passive run may NOT run an active-tier phase - FAILS under a lexical string comparison, where "active" < "passive" is true and would let this through'
if net_intensity_permits active passive; then r2=0; else r2=1; fi
assert_eq 0 "$r2" \
  'an active run MAY run a passive-tier phase (the run is more permissive than the phase requires)'
if net_intensity_permits safe safe; then r3=0; else r3=1; fi
assert_eq 0 "$r3" 'a run at exactly a phase'"'"'s own tier permits it'
if net_intensity_permits bogus passive; then r4=0; else r4=1; fi
assert_eq 1 "$r4" \
  'an unrecognised run intensity fails CLOSED rather than resolving to a permissive default - FAILS if a typo silently ran something the operator did not ask for'

t_case 'net_run_phase reports absent for a row whose script does not exist on disk (banner.sh, still NET-07-not-landed)'
net_run_phase 'banner.sh:passive' passive net-fixture
assert_eq absent "$_NET_PHASE_OUTCOME" \
  'banner.sh:passive is absent under a passive run - FAILS if presence is inferred from the table alone rather than a real -f test on modules/network/banner.sh. inventory.sh itself is no longer a usable "absent" fixture here: NET-05 landed it on disk, so net_run_phase now correctly reports it ran (see the two-tier authorization section below for direct inventory.sh coverage)'
assert_eq 0 "$_NET_PHASE_PRESENT" 'and _NET_PHASE_PRESENT agrees'

net_run_phase 'reachability.sh:safe' passive net-fixture
assert_eq skipped_intensity "$_NET_PHASE_OUTCOME" \
  'a safe-tier phase under a passive run reports skipped_intensity, not absent - the intensity gate is evaluated FIRST, before the script is even looked for (byte-identical to modules/dast/engine.sh'"'"'s own dast_run_phase), so this is the outcome REGARDLESS of whether the file exists. FAILS if the file-existence test runs first and this phase (which happens to not exist either) reports absent instead'
assert_eq 1 "$_NET_PHASE_PRESENT" \
  'and _NET_PHASE_PRESENT now correctly reports 1, now that NET-06 landed reachability.sh on disk - modules/network/run.sh reads this to decide whether a skipped_intensity phase belongs in the "phases_above_intensity_ceiling" count (present, this case) or the plain absent count (not present) - FAILS under the pre-NET-06 reading, where the file did not exist either'

t_case 'net_intensity_rank fails on an unrecognised name and never leaves a stale rank'
net_intensity_rank passive >/dev/null
FIRST_RANK=$_NET_INTENSITY_RANK
if net_intensity_rank bogus; then r5=0; else r5=1; fi
assert_eq 1 "$r5" 'net_intensity_rank bogus fails'
assert_eq '' "$_NET_INTENSITY_RANK" \
  'and clears _NET_INTENSITY_RANK rather than leaving the PREVIOUS successful lookup'"'"'s value behind - FAILS if a caller reads a stale rank from an earlier, unrelated call and believes an unrecognised name resolved'
assert_ne '' "$FIRST_RANK" 'sanity: the earlier real lookup did set a rank'

# =============================================================================
printf '\n-- report.md §5.2 rule 1: the two-tier tuple authorization split --\n'
# =============================================================================
# `run_init` gives this section its own scratch run directory so run_record
# writes land somewhere real - lib/core.sh's own primitive, already sourced
# transitively through modules/network/engine.sh -> modules/sast/engine.sh
# -> lib/report.sh -> lib/findings.sh -> lib/records.sh -> lib/core.sh.

TUPLE_ROOT=$W/tuple-root
_fixture_root "$TUPLE_ROOT"
cat >"$TUPLE_ROOT/config/scope.conf" <<'EOF'
id: tuple-fixture
base-url: https://tuple.fixture.invalid/
extra-host: tuple.fixture.invalid:8443
allow-subdomains: false
EOF
SCOURSH_INSTALL_ROOT=$TUPLE_ROOT

rm -rf "$W/run-tuple"
run_init "$W/run-tuple"

t_case 'an OPERATOR-configured out-of-scope tuple is refused FATALLY, exit 3'
_TUPLE_RC=0
( http_authorize_raw_connection 'https://tuple.fixture.invalid:9999' tuple-fixture >/dev/null 2>&1 ) \
  || _TUPLE_RC=$?
assert_eq 3 "$_TUPLE_RC" \
  'a port config/scope.conf never declared dies exit 3 through http_authorize_raw_connection - the exact chokepoint report.md §2.5'"'"'s table says a future NET-05+ phase calls directly for an operator-configured tuple. FAILS if this were instead a soft skip: an operator-authored scope.conf mistake would then read as "this port is closed" rather than "this scanner refused to even ask"'

t_case 'the SAME operator-declared tuple, on an authorised port, is not refused'
_TUPLE_OK_RC=0
( http_authorize_raw_connection 'https://tuple.fixture.invalid:8443' tuple-fixture >/dev/null 2>&1 ) \
  || _TUPLE_OK_RC=$?
assert_eq 0 "$_TUPLE_OK_RC" \
  'the extra-host-declared port 8443 is authorised - FAILS if the gate refuses every raw connection regardless of scope.conf, which would make the exit-3 case above meaningless (a gate that always refuses is not gating on scope)'

t_case 'an ARTIFACT-sourced tuple degrades NON-FATALLY, and is counted rather than fatal'
net_scope_skips_reset
SCOURSH_NET_TARGET=tuple-fixture
_ARTIFACT_RC=0
net_endpoint_keep 'https://tuple.fixture.invalid:9999' tuple-fixture || _ARTIFACT_RC=$?
assert_eq 1 "$_ARTIFACT_RC" \
  'net_endpoint_keep returns 1 (drop, non-fatal) for the identical out-of-scope port the fatal path above dies on - FAILS if this were fatal too, collapsing report.md §5.2 rule 1'"'"'s two-tier split into one'
assert_eq 1 "$_NET_SCOPE_SKIPPED" 'and the skip is counted'
assert_contains "$_NET_SCOPE_REASONS" 'no entry in config/scope.conf' \
  'the captured reason names the real gate refusal, not a generic placeholder'

t_case 'the SAME artifact tuple, on an authorised port, is kept (not counted as a skip)'
net_scope_skips_reset
_ARTIFACT_OK_RC=0
net_endpoint_keep 'https://tuple.fixture.invalid:8443' tuple-fixture || _ARTIFACT_OK_RC=$?
assert_eq 0 "$_ARTIFACT_OK_RC" 'net_endpoint_keep returns 0 (keep) for an authorised tuple'
assert_eq 0 "$_NET_SCOPE_SKIPPED" 'and nothing was counted as a skip'

t_case 'net_scope_record_skips writes exactly one coverage_reduction naming the count and reason'
net_scope_skips_reset
net_endpoint_keep 'https://tuple.fixture.invalid:9999' tuple-fixture || true
net_endpoint_keep 'https://tuple.fixture.invalid:7777' tuple-fixture || true
net_scope_record_skips reachability.sh tuple-fixture
CR2=$(_slurp "$SCOURSH_RUN_DIR/meta/coverage_reduction")
assert_contains "$CR2" 'module=network phase=reachability.sh reason=artifact_tuple_out_of_scope target=tuple-fixture count=2' \
  'ONE reduction line names the module, phase, reason and the real count of dropped tuples - FAILS if a naive implementation writes one reduction PER dropped tuple, which floods run.json with one line per port on a real scan (the identical trap modules/dast/engine.sh'"'"'s own dast_scope_record_skips guards against)'
assert_eq 1 "$(grep -c 'reason=artifact_tuple_out_of_scope' <<<"$CR2")" \
  'and it is written exactly once, not once per net_endpoint_keep call'

t_case 'net_scope_record_skips writes NOTHING when nothing was skipped'
rm -rf "$W/run-tuple-clean"
run_init "$W/run-tuple-clean"
net_scope_skips_reset
net_endpoint_keep 'https://tuple.fixture.invalid:8443' tuple-fixture || true
net_scope_record_skips reachability.sh tuple-fixture
CR3=$(_slurp "$SCOURSH_RUN_DIR/meta/coverage_reduction")
assert_eq '' "$CR3" \
  'a phase that dropped nothing writes no reduction at all - FAILS if the function unconditionally writes a "0 dropped" line, which would clutter every clean run with a record that says nothing happened'

t_case 'net_scope_safe_text sanitizes control bytes and bounds length'
UNSAFE=$'line one\nline two\ttabbed\r'
SAFE=$(net_scope_safe_text "$UNSAFE")
assert_not_contains "$SAFE" $'\n' 'no raw newline survives - FAILS if this reached a run_record line, a raw newline would forge a second record (rules/RULE-FORMAT.md §3.1 forbids it in a location component)'
LONG=$(printf 'a%.0s' {1..300})
SAFE_LONG=$(net_scope_safe_text "$LONG")
assert_eq 163 "${#SAFE_LONG}" \
  'a text longer than the default 160-byte max is truncated to 160 chars plus a 3-char "..." marker - FAILS if the truncation marker is appended without bound, or the cap is not applied at all'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network'
