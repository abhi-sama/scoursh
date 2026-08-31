#!/usr/bin/env bash
# tests/suites/dast.sh - modules/dast/: the `scan_dispatch dast` entry point,
# target/intensity orchestration, and the honesty records a run that ships no
# phase script owes its reader (DAST-02, docs/STEP5-DAST-PLAN.md tier 0).
#
# The three things this suite exists to pin, because each has a plausible
# wrong reading that would ship silently:
#
#   1. The scope gate is NOT the module's to soften.  An unauthorised target
#      is still exit 3 and a wholly missing config/scope.conf is still exit 4,
#      exactly as tests/suites/scan.sh already pinned them BEFORE modules/dast/
#      existed - landing a real run.sh must not change either, and the module
#      re-asserts the gate itself rather than trusting the caller.
#   2. A run with no phase script sends NOTHING and says so.  This repository
#      has been bitten three times by code that skipped work and left a report
#      claiming a complete run, so the assertions are made on run.json and on
#      report.md - the surfaces a consumer actually reads - never only on an
#      internal record.
#   3. Intensity is a real gate, not a recorded string.  A phase declared
#      `active` must not run under a `passive` run, and the assertion below
#      fails under a lexical comparison of the two names (`active` < `passive`
#      < `safe` alphabetically, which is the exact reverse of the tier order).
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
# -x back-edge cut: modules/dast/engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh resolves every loaded file's
# path via realpath and strips $SCOURSH_INSTALL_ROOT as a literal prefix, so a
# fixture root reached through macOS's /var -> /private/var $TMPDIR symlink would
# make the strip fail and every check under it fire a spurious E081 (see
# tests/suites/scan.sh's ROOT_WITH_CHECKS, which documents the same fact).
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# Fixture install roots.
#
# A dast run needs modules/dast/ AND lib/ to be reachable from
# $SCOURSH_INSTALL_ROOT, while its config/ must be the fixture's own (the real
# repository ships config/scope.conf.example and no config/scope.conf, which is
# the shipped default and is deliberately left that way - docs/STEP5-DAST-PLAN.md
# "no shipped file names a third-party host as a scannable target").  So each
# fixture root holds a real COPY of the tree's code and owns its own config/.
#
# A copy, not a symlink: lib/records.sh resolves every loaded rule file's path
# through realpath, which follows a symlinked `modules/` back to the real repo -
# outside $SCOURSH_INSTALL_ROOT - so the moment a real `*.rules` file exists
# under `modules/dast/` (modules/dast/active/checks.rules) the literal-prefix
# strip in `_records_relpath` fails and every check fires a spurious E081,
# aborting the whole `scan.sh dast` run.  A real copy keeps each file's realpath
# genuinely inside the canonical root, so E081 is decided on where the file
# actually sits.  `cp -RL` dereferences into plain files; `$W` is canonical (see
# above) so the copies' realpaths are too.
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
id: dast-fixture
base-url: https://dast.fixture.invalid/
allow-subdomains: false
notes: Fixture scope target for tests/suites/dast.sh. Nothing is ever sent to
  it: this suite asserts that a dast run makes no request at all.
EOF

FIX_NO_SCOPE=$W/root-no-scope
_fixture_root "$FIX_NO_SCOPE"

# ---------------------------------------------------------------------------
# SCOURSH_HTTP_RESOLVE, stubbed for every scan this suite runs - never the
# host's real resolver.
#
# `dast.fixture.invalid` is RFC 2606 reserved and every existing case below
# depends on it NOT resolving (the scope gate refuses it before a transport is
# ever reached, which is what "makes no network call" and every
# `url_not_requestable`/`endpoint_inventory_absent` assertion below rests on).
# Relying on the host's real resolver to fail made that outcome a property of
# whatever network this suite happens to run on rather than of the code - and
# is what made this suite's result depend on lib/http.sh's DNS-failure path
# staying a hard failure, the exact path commit a4f9f5e had to change.  This
# stub makes the failure deterministic instead: it is a real executable, not a
# bash function, because `_dast_scan` and every ad hoc `bash "$ROOT/scan.sh"`
# call below spawn a genuine subprocess, and an exported bash function does
# not propagate into a `bash <script>` child on this host (measured - see this
# ticket).  `SCOURSH_HTTP_RESOLVE` accepts either a function name or a program
# on PATH (lib/http.sh: `"${SCOURSH_HTTP_RESOLVE:-_http_resolve_default}"`
# invoked as a plain command), so a script path works identically in-process
# (the "module re-asserts the gate itself" case below) and across a fork -
# tests/suites/dast-crawl.sh already establishes the same pattern.
#
# `dast-resolves.fixture.invalid` is the one host this stub DOES resolve, so
# the opposite direction - a resolver that answers - has real, pinned coverage
# too, in "the resolving direction is pinned too" below, rather than being
# genuinely untested as this ticket found it.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  dast-resolves.fixture.invalid) printf '198.51.100.7' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"
export SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB

# `_dast_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh dast`
# subprocess, the way an operator hits it.  Sets _RC and _LOG; the run
# directory is the caller's to inspect.  Never `assert_status`, because these
# cases assert on the run's ARTIFACTS as well as its exit code.
_dast_scan() {
  local rundir=$1 root=$2
  shift 2
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$root bash "$ROOT/scan.sh" dast --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf -- '\n-- the scope gate is not the module'"'"'s to soften (constraint 4) --\n'
# =============================================================================

t_case 'an authorised target completes cleanly and exits 0'
_dast_scan "$W/run-ok" "$FIX_SCOPE" --target dast-fixture
assert_eq 0 "$_RC" \
  'scan.sh dast --target dast-fixture exits 0 - fails under "a module with no checks is an incomplete run (exit 5)" and under "a module with no run.sh is the only clean dast path"'
assert_file_exists "$W/run-ok/run.json" 'the run wrote run.json'

t_case 'a --target with no entry in a PRESENT scope.conf is still exit 3'
_dast_scan "$W/run-unauth" "$FIX_SCOPE" --target no-such-target
assert_eq 3 "$_RC" \
  'an unauthorised target still dies exit 3 once modules/dast/run.sh exists - fails under "the module resolves its own targets and an unknown one is simply an empty target list"'

t_case 'a WHOLLY MISSING scope.conf is still exit 4, never exit 3'
_dast_scan "$W/run-noscope" "$FIX_NO_SCOPE" --target anything
assert_eq 4 "$_RC" \
  'a missing config/scope.conf still dies exit 4 - fails under "no file also means no matching entry, so it is exit 3 too" (docs/FOUNDATION.md tension 14)'

t_case 'the module re-asserts the gate itself, not only through scan.sh'
_MOD_GATE_RC=0
(
  SCOURSH_INSTALL_ROOT=$FIX_SCOPE
  export SCOURSH_INSTALL_ROOT
  declare -A SCAN_FLAGS=([target]=no-such-target)
  export SCOURSH_RUN_DIR=$W/run-modgate
  mkdir -p "$SCOURSH_RUN_DIR/meta"
  source "$ROOT/modules/dast/run.sh"
) >/dev/null 2>&1 || _MOD_GATE_RC=$?
assert_eq 3 "$_MOD_GATE_RC" \
  'sourcing modules/dast/run.sh directly with an unauthorised target still dies exit 3 - fails under "scan.sh already called config_scope_require, so the module may trust its caller"'

# =============================================================================
printf '\n-- this ticket ships no checks and issues no traffic (constraints 1, 2) --\n'
# =============================================================================

t_case 'a dast run makes no network call at all'
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
_NET_RC=0
SCOURSH_INSTALL_ROOT=$FIX_SCOPE PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" dast --target dast-fixture --out "$W/run-notraffic" \
  >"$W/run-notraffic.log" 2>&1 || _NET_RC=$?
assert_eq 0 "$_NET_RC" 'the run still exits 0 with a poisoned PATH, because it never reaches for a transport'
# DAST-04 landed `crawl.sh`, which DOES want to send requests, so this case no
# longer says "this module never makes a network call" - that would be false.
# What it says now is narrower and still load-bearing: this fixture's target
# does not RESOLVE, so lib/http.sh's gate refuses it before the transport is
# ever reached, and a refused URL costs no request.  It fails under "the
# crawler fetches first and checks the gate against the response", which is
# the ordering that would put a request on the wire for a host the gate was
# about to refuse.
assert_file_absent "$W/network-attempts" \
  'no curl/wget/nc/openssl was invoked for a target the scope gate refuses - fails if a URL is fetched before it is gated'

t_case 'nothing is claimed as executed'
RUN_OK_JSON=$(_slurp "$W/run-ok/run.json")
assert_contains "$RUN_OK_JSON" '"checks_run": []' \
  'checks_run is empty - fails under "record the phases we would have run", which is the overclaim this ticket exists to avoid'

# =============================================================================
printf '\n-- run.json tells the truth about a run that covered nothing (constraint 3) --\n'
# =============================================================================
# THIS BLOCK CHANGED SHAPE TWICE, AND BOTH CHANGES ARE THE POINT.
# It originally asserted `reason=no_phase_scripts_on_disk_yet` - "modules/dast/
# ships no phase script" - which was true of DAST-02 and is now false twice
# over: DAST-03 put `auth.sh` on disk and DAST-04 put `crawl.sh` there, and
# both run at `passive`.  The obligation being pinned never changed and is
# re-asserted below against the records this run actually produces: a run that
# tested nothing must SAY it tested nothing, on run.json and on report.md, in a
# sentence naming the target.  Weakening it to "some coverage record exists"
# would have let the honesty regress silently.
#
# BOTH PHASES' REASONS ARE ASSERTED, not either one.  Each phase states why it
# covered nothing in its own words, and a resolution that kept only one side's
# assertions would stop noticing if that phase went silent.

t_case 'run.json records a coverage_reduction naming the real cause'
assert_contains "$RUN_OK_JSON" 'reason=no_check_covered_by_any_phase' \
  'run.json carries the declared reduction - fails under "the module logs it to stderr", which leaves the artifact claiming a complete run'
assert_not_contains "$RUN_OK_JSON" 'no_phase_scripts_on_disk_yet' \
  'and it does NOT claim modules/dast/ ships no phase script, now that auth.sh and crawl.sh both do - fails if the roll-up keys on "did a phase run" rather than "was a check covered", which was one question while no phase existed and is two now'

t_case 'the auth phase states its own reason for covering nothing'
assert_contains "$RUN_OK_JSON" 'reason=authed_not_requested' \
  'auth.sh records why it acquired no session - fails under "the roll-up is enough", which leaves a reader unable to tell an unauthenticated run from a broken one'
assert_contains "$RUN_OK_JSON" 'No credential was sent' \
  'and states plainly that no credential left the process on a run that did not ask for one'

t_case 'the crawl phase states its own reason for discovering nothing'
assert_contains "$RUN_OK_JSON" 'reason=url_not_requestable' \
  'crawl.sh records what stopped it - fails if the no-phases branch is reached whenever a phase found nothing, which would make "not shipped" and "found nothing" the same sentence'

t_case 'run.json records a coverage_gap a human reads, naming the target'
assert_contains "$RUN_OK_JSON" '"coverage_gap": [' 'run.json has a coverage_gap array'
assert_contains "$RUN_OK_JSON" "target 'dast-fixture'" \
  'the gap sentence itself names the target it did not cover - fails under "the targets array already names it", which leaves the gap unattributed'
assert_contains "$RUN_OK_JSON" 'no property of the running endpoint was tested' \
  'the gap says plainly that nothing was tested - fails under "reason=not_yet_built is enough", which a reader cannot tell from a clean scan'
assert_contains "$RUN_OK_JSON" 'NOTHING was discovered' \
  'and the crawl says plainly that it found nothing - fails under "a machine-readable reason is enough", which a reader cannot tell from a clean scan'

t_case 'the report a human opens carries the same statement'
REPORT_MD=$(_slurp "$W/run-ok/report.md")
assert_contains "$REPORT_MD" 'Limitations and coverage' 'report.md has its limitations section'
assert_contains "$REPORT_MD" 'no_check_covered_by_any_phase' \
  'report.md states the reduction - fails under "run.json is the audit surface, the report is for findings"'
assert_contains "$REPORT_MD" 'url_not_requestable' \
  'and the crawl phase reaches the report too, not only run.json'

t_case 'the target-scoped coverage cell is recorded'
assert_contains "$RUN_OK_JSON" '"targets": ["dast-fixture"]' \
  'run.json names the config/scope.conf target id as the run cell (docs/FOUNDATION.md tension 12, coverage-scope: target) - fails under "the cell is only meaningful once a finding carries it"'

# =============================================================================
printf '\n-- intensity is resolved, recorded, and gates what may run (constraint 5) --\n'
# =============================================================================

t_case 'the default intensity is resolved and recorded'
assert_contains "$RUN_OK_JSON" 'intensity=passive' \
  'an unflagged run records intensity=passive (lib/checks.sh CHECKS_INTENSITY_DEFAULT) - fails under "intensity only matters to the check-registry filter, so the module need not resolve it"'

t_case 'an explicit intensity is resolved and recorded'
# `--intensity active` now needs the own-your-target affirmation to be reachable
# at all (docs/STEP5-DAST-PLAN.md DAST-32: `passive` is the ceiling for a host
# this tool cannot vouch for).  The affirmation is what this case supplies; the
# REFUSAL without it is pinned in tests/suites/scan.sh's own affirmation
# section rather than here, because it is a parser decision and never reaches
# the module.
_dast_scan "$W/run-active" "$FIX_SCOPE" --target dast-fixture --intensity active \
  --i-own-target dast-fixture
assert_eq 0 "$_RC" 'an affirmed --intensity active run still exits 0'
RUN_ACTIVE_JSON=$(_slurp "$W/run-active/run.json")
assert_contains "$RUN_ACTIVE_JSON" 'intensity=active' \
  'run.json records the intensity actually resolved for this run'

t_case 'the tier order is the ceiling order, not the alphabet'
_r=0; dast_intensity_permits active safe || _r=$?
assert_eq 0 "$_r" \
  'an active run may run a safe phase - fails under a lexical comparison of the names, where "active" < "safe" makes this refuse'
_r=0; dast_intensity_permits active passive || _r=$?
assert_eq 0 "$_r" 'an active run may run a passive phase'
_r=0; dast_intensity_permits safe safe || _r=$?
assert_eq 0 "$_r" 'a safe run may run a safe phase'
_r=0; dast_intensity_permits passive safe || _r=$?
assert_eq 1 "$_r" 'a passive run may NOT run a safe phase'
_r=0; dast_intensity_permits passive active || _r=$?
assert_eq 1 "$_r" 'a passive run may NOT run an active phase'
_r=0; dast_intensity_permits safe active || _r=$?
assert_eq 1 "$_r" 'a safe run may NOT run an active phase'

t_case 'an unknown intensity name keeps nothing'
_r=0; dast_intensity_permits bogus passive || _r=$?
assert_eq 1 "$_r" \
  'an unrecognised run intensity permits nothing - fails under "default to the shipped default when the name is not recognised", which turns a typo into a scan'
_r=0; dast_intensity_permits active bogus || _r=$?
assert_eq 1 "$_r" 'an unrecognised phase tier is never permitted'

t_case 'every phase in the table declares a legal tier and a path under modules/dast/'
_bad_tier=''
_bad_path=''
for _spec in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
  _script=${_spec%%:*}
  _tier=${_spec##*:}
  checks_valid_intensity "$_tier" || _bad_tier+="$_spec "
  case $_script in
    /* | *..*) _bad_path+="$_spec " ;;
  esac
done
assert_eq '' "$_bad_tier" \
  'every phase tier is one of lib/checks.sh CHECKS_INTENSITIES - fails under a hand-typed tier vocabulary that can drift from the filter chain'
assert_eq '' "$_bad_path" 'no phase escapes modules/dast/'

t_case 'the phase table covers every tier-1..tier-5 script the plan names'
_phase_scripts=" ${_DAST_PHASES[*]%%:*} "
for _want in auth.sh crawl.sh passive/headers.sh passive/cookies.sh passive/tls.sh \
  passive/cors.sh passive/banner.sh passive/leakage.sh passive/markup.sh \
  active/discovery.sh active/methods.sh active/sqli.sh active/xss.sh active/cmdi.sh \
  active/pathtraversal.sh active/ssti.sh active/openredirect.sh active/xxe_ssrf.sh \
  active/nosqli.sh active/ldapi.sh active/crlf.sh active/hosthdr.sh \
  active/protopollution.sh jwt.sh graphql.sh ratelimit.sh authz.sh \
  passive/transport.sh; do
  _found=0
  for _spec in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
    [[ ${_spec%%:*} == "$_want" ]] && _found=1
  done
  assert_eq 1 "$_found" "the phase table names $_want (docs/STEP5-DAST-PLAN.md tiers 1-5)"
done

t_case 'a phase above the run intensity is not sourced, even when its script exists'
FIX_PHASE=$W/root-with-phase
_fixture_root "$FIX_PHASE"
# This case needs a modules/ of the fixture's OWN - just a controlled dast
# run.sh/engine.sh, a fake active/sqli.sh, and a sast/engine.sh - so the copied
# modules/ (a real directory now, not the former symlink) is replaced wholesale
# with that minimal tree; hence `rm -rf`, not `rm -f`.
rm -rf "$FIX_PHASE/modules"
mkdir -p "$FIX_PHASE/modules/dast/active" "$FIX_PHASE/modules/sast"
cp "$ROOT/modules/dast/run.sh" "$ROOT/modules/dast/engine.sh" "$FIX_PHASE/modules/dast/"
ln -sfn "$ROOT/modules/sast/engine.sh" "$FIX_PHASE/modules/sast/engine.sh"
printf '#!/usr/bin/env bash\nprintf "sourced\\n" >>"%s"\n' "$W/phase-ran" \
  >"$FIX_PHASE/modules/dast/active/sqli.sh"
rm -f "$W/phase-ran"

SCOURSH_INSTALL_ROOT=$FIX_PHASE dast_run_phase active/sqli.sh:active passive dast-fixture
assert_eq skipped_intensity "$_DAST_PHASE_OUTCOME" \
  'an active phase under a passive run is refused by the runner - fails under "the check registry type-tag filter is the only intensity gate", which leaves a phase script with no registry entry unguarded'
assert_file_absent "$W/phase-ran" \
  'the active phase script was never sourced under a passive run'

t_case 'the same phase runs once the run intensity permits it'
SCOURSH_INSTALL_ROOT=$FIX_PHASE dast_run_phase active/sqli.sh:active active dast-fixture
assert_eq ran "$_DAST_PHASE_OUTCOME" 'the runner reports it ran'
assert_file_exists "$W/phase-ran" \
  'the active phase script was sourced under an active run - fails under "gate everything off and the boundary is trivially safe", which would make the whole table inert'

t_case 'an absent phase script is a clean no-op, never an error'
SCOURSH_INSTALL_ROOT=$FIX_PHASE dast_run_phase passive/headers.sh:passive passive dast-fixture
assert_eq absent "$_DAST_PHASE_OUTCOME" \
  'a phase whose script has not landed is reported absent - fails under "a missing phase script is a broken install"'

t_case 'a whole run whose only phase is above the ceiling says THAT, not "nothing is shipped"'
cp "$FIX_SCOPE/config/scope.conf" "$FIX_PHASE/config/scope.conf"
rm -f "$W/phase-ran"
_dast_scan "$W/run-ceilinged" "$FIX_PHASE" --target dast-fixture
assert_eq 0 "$_RC" 'a run whose every phase is above the ceiling is still a clean run'
assert_file_absent "$W/phase-ran" 'and it really did not run the active phase'
RUN_CEIL_JSON=$(_slurp "$W/run-ceilinged/run.json")
assert_contains "$RUN_CEIL_JSON" 'reason=phase_above_intensity_ceiling' \
  'run.json names the phase the intensity ceiling refused - fails under "a refused phase is the same as an absent one", which hides a check the operator could have had for a flag'
assert_contains "$RUN_CEIL_JSON" 'active/sqli.sh(>=active)' \
  'and names which phase, and the tier it needs'
assert_contains "$RUN_CEIL_JSON" 'reason=no_phase_permitted_by_intensity' \
  'the no-coverage reason distinguishes "refused" from "not shipped" - fails under one reason string for both causes'
assert_not_contains "$RUN_CEIL_JSON" 'no_phase_scripts_on_disk_yet' \
  'and does not claim modules/dast/ ships nothing when a phase script is sitting right there'

# =============================================================================
printf '\n-- an absent inventory is normal and is a recorded gap (constraint 6) --\n'
# =============================================================================

t_case 'both inventory files absent is a clean run with two recorded gaps'
assert_contains "$RUN_OK_JSON" 'inventory/endpoints.json' \
  'run.json names the absent endpoint inventory (docs/FOUNDATION.md tension 21) - fails under "absence is normal, so say nothing", which overstates the surface tested'
assert_contains "$RUN_OK_JSON" 'inventory/parameters.json' \
  'run.json names the absent parameter inventory'
assert_contains "$RUN_OK_JSON" 'endpoint_inventory_absent' \
  'the endpoint gap carries a machine-readable reason'
assert_contains "$RUN_OK_JSON" 'parameter_inventory_absent' \
  'the parameter gap carries a machine-readable reason'

t_case 'a present but EMPTY inventory is a distinct gap, not silence'
mkdir -p "$W/run-empty-inv/inventory"
: >"$W/run-empty-inv/inventory/endpoints.json"
_dast_scan "$W/run-empty-inv" "$FIX_SCOPE" --target dast-fixture
assert_eq 0 "$_RC" 'an empty inventory file is still a clean run'
RUN_EMPTY_JSON=$(_slurp "$W/run-empty-inv/run.json")
assert_contains "$RUN_EMPTY_JSON" 'endpoint_inventory_empty' \
  'an empty endpoints.json is reported as empty, not absent - fails under "-f is enough", which reports a file nobody wrote to as real coverage'
assert_not_contains "$RUN_EMPTY_JSON" 'endpoint_inventory_absent' \
  'and not also as absent'

t_case 'a populated inventory records no gap for that file'
mkdir -p "$W/run-full-inv/inventory"
printf '[{"url":"https://dast.fixture.invalid/","method":"GET"}]\n' \
  >"$W/run-full-inv/inventory/endpoints.json"
printf '[{"name":"q","in":"query"}]\n' >"$W/run-full-inv/inventory/parameters.json"
_dast_scan "$W/run-full-inv" "$FIX_SCOPE" --target dast-fixture
assert_eq 0 "$_RC" 'a populated inventory is still a clean run'
RUN_FULL_JSON=$(_slurp "$W/run-full-inv/run.json")
assert_not_contains "$RUN_FULL_JSON" 'endpoint_inventory_absent' \
  'no absent-gap is recorded for a file that is there - fails under "record the gap unconditionally", which would make the record decoration'
assert_not_contains "$RUN_FULL_JSON" 'parameter_inventory_absent' \
  'nor for the parameter inventory'
assert_contains "$RUN_FULL_JSON" 'no_check_covered_by_any_phase' \
  'and the no-coverage reduction is still recorded, because a full inventory that no CHECK consumes is not coverage'
assert_contains "$RUN_FULL_JSON" 'inventory_merged=' \
  'and the merge result is recorded, because "an inventory was present" and "this run could read it" are two different facts - fails under "the absent-gap not firing is proof enough", which reports an unreadable inventory as coverage'

t_case 'the inventory paths are published for the phase that will consume them'
assert_eq "$W/run-full-inv/inventory/endpoints.json" \
  "$(SCOURSH_RUN_DIR=$W/run-full-inv bash -c \
    'source "'"$ROOT"'/modules/dast/engine.sh"; dast_inventory_read; printf "%s" "$_DAST_ENDPOINTS_FILE"')" \
  'dast_inventory_read publishes the endpoints path when the file is real - fails under "the reader only counts, so a later phase re-derives the path itself"'

# =============================================================================
printf '\n-- SCOURSH_DAST_ENDPOINTS/PARAMETERS survive a mid-loop producer (regression) --\n'
# =============================================================================
# modules/dast/run.sh calls dast_inventory_read ONCE, before the phase loop,
# to answer "was an inventory available as INPUT when this module started"
# (the case above). On an ordinary run that answer is "no" - crawl.sh is
# itself one of the phases the loop is about to run, and writes both
# inventory artifacts partway through it. The defect this ticket fixes: the
# variables a phase reads to find that inventory (SCOURSH_DAST_ENDPOINTS /
# SCOURSH_DAST_PARAMETERS) used to be set ONCE from that pre-loop snapshot,
# so a phase reached LATER in the same loop - after a crawl-shaped producer
# already wrote the file - still saw the pre-loop, unusable value. This is
# asserted end to end, through a real `scan.sh dast` subprocess, with a fake
# `crawl.sh` standing in for DAST-04's real one (isolating the orchestration
# bug from crawl.sh's own real behaviour, which tests/suites/dast-crawl.sh
# already covers) and a fake later phase that records what it actually saw.
FIX_INV=$W/root-with-crawl-producer
_fixture_root "$FIX_INV"
rm -rf "$FIX_INV/modules"
mkdir -p "$FIX_INV/modules/dast/passive" "$FIX_INV/modules/sast"
cp "$ROOT/modules/dast/run.sh" "$ROOT/modules/dast/engine.sh" "$FIX_INV/modules/dast/"
ln -sfn "$ROOT/modules/sast/engine.sh" "$FIX_INV/modules/sast/engine.sh"
cp "$FIX_SCOPE/config/scope.conf" "$FIX_INV/config/scope.conf"

# Stands in for crawl.sh:passive, the first producer of either artifact
# (docs/INVENTORY-FORMAT.md).  It writes AFTER the loop has already started
# and AFTER modules/dast/run.sh has already exported SCOURSH_DAST_ENDPOINTS -
# exactly the ordering the real crawl.sh (DAST-04) uses.
cat >"$FIX_INV/modules/dast/crawl.sh" <<'EOF'
#!/usr/bin/env bash
mkdir -p "$SCOURSH_RUN_DIR/inventory"
printf '[{"id":"ep1","target":"dast-fixture","method":"GET","url":"https://dast.fixture.invalid/x","path":"/x"}]\n' \
  >"$SCOURSH_RUN_DIR/inventory/endpoints.json"
EOF

# Stands in for any real phase reached LATER in _DAST_PHASES (passive/headers.sh
# is a real row, tier passive, after crawl.sh's tier-1 row) - it never parses
# the inventory itself, only proves whether SCOURSH_DAST_ENDPOINTS resolves to
# something readable and non-empty AT THE TIME THIS PHASE RUNS.
cat >"$FIX_INV/modules/dast/passive/headers.sh" <<'EOF'
#!/usr/bin/env bash
if [[ -r ${SCOURSH_DAST_ENDPOINTS:-} && -s ${SCOURSH_DAST_ENDPOINTS:-} ]]; then
  printf 'nonempty\n' >>"$INV_CONSUMER_MARKER"
else
  printf 'empty\n' >>"$INV_CONSUMER_MARKER"
fi
EOF

INV_CONSUMER_MARKER=$W/inv-consumer-seen
rm -f "$INV_CONSUMER_MARKER"
export INV_CONSUMER_MARKER

t_case 'a phase reached later in the SAME loop sees an inventory a crawl-shaped phase wrote earlier in it'
_dast_scan "$W/run-inv-mid-loop" "$FIX_INV" --target dast-fixture
assert_eq 0 "$_RC" 'the run completes cleanly'
assert_file_exists "$INV_CONSUMER_MARKER" \
  'the later phase actually ran and recorded what it saw - if this is absent the case below is not testing anything'
assert_eq nonempty "$(_slurp "$INV_CONSUMER_MARKER")" \
  'the later phase read a populated endpoint inventory - FAILS on the pre-fix code, which resolves SCOURSH_DAST_ENDPOINTS to a snapshot taken BEFORE the phase loop (and therefore before crawl.sh has run), so every later phase saw the pre-loop empty value even though crawl.sh had by then written a real one'

unset INV_CONSUMER_MARKER

# =============================================================================
printf '\n-- what this ticket deliberately does not ship --\n'
# =============================================================================

t_case 'modules/dast/ now registers its active-injection checks, recorded honestly'
# DAST-14 ships the module's FIRST check registry, modules/dast/active/checks.rules
# (the DAST-INJ-SQLI_* checks), nested under active/ rather than at the module
# root.  Before it, modules/dast/ had none and a dast run recorded
# reason=no_check_registry_on_disk_yet; that reason must no longer fire now that
# the registry loads, and the registered checks must reach run.json.
assert_file_exists "$ROOT/modules/dast/active/checks.rules" \
  'the active-injection check registry is shipped (DAST-14)'
assert_not_contains "$RUN_OK_JSON" 'reason=no_check_registry_on_disk_yet' \
  'the empty-registry reason no longer fires once modules/dast/ ships a checks.rules - fails under "the reason is unconditional for dast", which would misreport a warm registry as absent'
assert_contains "$RUN_OK_JSON" 'DAST-INJ-SQLI_ERROR-01' \
  'the registered active-injection checks reach run.json - fails if checks_registry_load'"'"'s any-depth glob does not discover the nested modules/dast/active/checks.rules'

t_case 'modules/dast/passive/ ships FIVE per-owner registries and all five load'
# rules/RULE-FORMAT.md §9's `checks-<name>.rules` row replaced this directory's
# single co-owned `checks.rules` with one file per owning phase script, so that
# tier-2 peers built in parallel have no shared file to collide on.  The claim
# that needs proving is not "the glob has no allowlist" - that is readable in
# lib/checks.sh - but that a REAL RUN ends up with every one of the five files'
# records in its registry.  So this asserts on run.json from the `run-ok`
# subprocess above, one id per file, and on the TOTAL.
#
# The surface is `checks_selected`, deliberately, and NOT `checks_run`.  Those
# are different sets (lib/report.sh's own note says so): `checks_run` is what
# EXECUTED, and this fixture's target does not resolve, so no phase runs and
# `checks_run` is empty by design - which the "nothing is claimed as executed"
# case above already pins.  Asserting registry discovery on `checks_run` here
# would therefore fail for a reason that has nothing to do with the glob, and
# passing it by making the fixture reachable would put real traffic on the wire.
for _f in checks-cookies checks-headers checks-markup checks-leakage checks-transport; do
  assert_file_exists "$ROOT/modules/dast/passive/$_f.rules" \
    "modules/dast/passive/$_f.rules is shipped"
done
assert_file_absent "$ROOT/modules/dast/passive/checks.rules" \
  'the shared co-owned checks.rules is gone - fails if the split left a sixth file behind, which would silently double every id it still held'
# One id per file.  A single id would pass with four of the five undiscovered.
assert_contains "$RUN_OK_JSON" 'DAST-COOKIE-NO_SECURE-01'  'checks-cookies.rules loaded'
assert_contains "$RUN_OK_JSON" 'DAST-HDR-CSP_MISSING-01'   'checks-headers.rules loaded'
assert_contains "$RUN_OK_JSON" 'DAST-MARKUP-SRI_MISSING-01' 'checks-markup.rules loaded'
assert_contains "$RUN_OK_JSON" 'DAST-LEAK-STACK_TRACE-01'  'checks-leakage.rules loaded'
assert_contains "$RUN_OK_JSON" 'DAST-TRANSPORT-MIXED_ACTIVE-01' 'checks-transport.rules loaded'
# The total, which is what catches a record LOST in the split rather than a
# whole file lost: the shared checks.rules held 31 records (4 cookie + 11 header
# + 6 markup + 5 leakage + 5 transport) and the five files must still hold 31
# between them.  Counted off run.json rather than off the files, so it measures
# what the loader produced and not what the directory contains.
_PASSIVE_SELECTED=$(printf '%s' "$RUN_OK_JSON" \
  | tr ',' '\n' \
  | grep -cE '"DAST-(COOKIE|HDR|MARKUP|LEAK|TRANSPORT)-' || true)
assert_eq 31 "$_PASSIVE_SELECTED" \
  'all 31 records from the five per-owner files reach the registry - fails if the split dropped or duplicated a record, which a per-file existence check cannot see'

# =============================================================================
printf '\n-- DAST-32/33/34 end to end: the authorisation record a real run leaves --\n'
# =============================================================================
# Everything below runs `scan.sh dast` as a REAL SUBPROCESS and asserts on
# run.json and report.md - the surfaces a consumer actually reads.  Asserting
# on reports/<run>/meta/<key> instead is the exact gap DAST-33 exists to close:
# `run_record use_engines` had been writing its meta file since the semgrep
# adapter landed, nothing rendered it into run.json, and both suites covering
# it asserted against the meta file, so a fact that never reached a consumer
# read as fully covered.

t_case 'an unaffirmed run records a complete, honest authorization object'
_dast_scan "$W/run-authz-none" "$FIX_SCOPE" --target dast-fixture
assert_eq 0 "$_RC" 'an ordinary unaffirmed dast run still exits 0'
AZ_NONE=$(_slurp "$W/run-authz-none/run.json")
assert_contains "$AZ_NONE" '"authorization": {' \
  'run.json carries the authorization object on an UNAFFIRMED run too - fails under "record it only when something was affirmed", which leaves an absent key ambiguous between "nothing was affirmed" and "this version does not record it"'
assert_contains "$AZ_NONE" '"affirmed": false' 'and states plainly that nothing was affirmed'
assert_contains "$AZ_NONE" '"scope_target": "dast-fixture"' 'and names the host the decision was about'
assert_contains "$AZ_NONE" '"intensity": "passive"' 'and the intensity it actually ran at'
assert_contains "$AZ_NONE" 'request-budget:20000->5000 reason=no_owner_affirmation source=default' \
  'and the clamp that actually bit, as a delta with its resolution layer - fails if the clamp only warns on stderr, which is not an artifact a reader has a month later'
assert_contains "$AZ_NONE" 'scope-gate:config/scope.conf' \
  'and what stayed enforced, so the record is a complete statement rather than a partial one'
assert_contains "$AZ_NONE" '"use_engines": false' \
  'and run.json renders use_engines - fails in the state this ticket found the tool in, where scan.sh recorded the flag and report_run_json never rendered it'
assert_not_contains "$(_slurp "$W/run-authz-none/report.md")" 'This run was UNRESTRICTED' \
  'and an unaffirmed run gets no unrestricted banner, because nothing was lifted'

t_case 'a run with no operator contact says so, once, and names the key that fixes it'
NOCONTACT_LOG=$(_slurp "$_LOG")
assert_contains "$NOCONTACT_LOG" 'no operator contact is configured' \
  'a dast run with no contact set states it at run start - fails if the contact is simply omitted from the User-Agent, which leaves an operator with no idea that a target owner who notices their traffic has no way to reach them'
assert_contains "$NOCONTACT_LOG" 'config/scanner.conf' \
  'and names the config key that fixes it, rather than describing the problem only'
assert_not_contains "$NOCONTACT_LOG" 'warn  no operator contact' \
  'and it is INFO, not a warning - an unset contact is a legal configuration and the request is still identified as scoursh, so scolding every run for it teaches the operator to ignore the log'

t_case 'a configured contact removes that line entirely'
FIX_CONTACT=$W/root-with-contact
_fixture_root "$FIX_CONTACT"
cp "$FIX_SCOPE/config/scope.conf" "$FIX_CONTACT/config/scope.conf"
printf 'id: scanner\ncontact: security@operator.example\n' >"$FIX_CONTACT/config/scanner.conf"
_dast_scan "$W/run-contact" "$FIX_CONTACT" --target dast-fixture
assert_eq 0 "$_RC" 'a run with a configured contact still exits 0'
assert_not_contains "$(_slurp "$_LOG")" 'no operator contact is configured' \
  'and says nothing about a missing contact - fails if the notice is unconditional, which is noise rather than information'

t_case 'an explicit env value above a ceiling is exit 2 through the real CLI, before anything ran'
_RC=0
SCOURSH_INSTALL_ROOT=$FIX_SCOPE SCOURSH_CONFIG_REQUEST_BUDGET=100000 \
  bash "$ROOT/scan.sh" dast --target dast-fixture --out "$W/run-authz-refuse" \
  >"$W/refuse.log" 2>&1 || _RC=$?
assert_eq 2 "$_RC" \
  'an explicit over-ceiling request-budget exits 2 end to end - fails under a symmetric clamp, which would run the scan at a number the operator did not ask for'
assert_contains "$(_slurp "$W/refuse.log")" '--i-own-target' \
  'and the refusal names the flag that resolves it'
assert_file_absent "$W/run-authz-refuse/report.md" \
  'and it refuses BEFORE the module ran, so no report claims a scan happened - fails if the ceiling is only enforced at the first request, where a usage error fires after traffic has already left'

t_case 'an affirmed run records the deltas, banners them, and says so on stderr'
_RC=0
SCOURSH_INSTALL_ROOT=$FIX_SCOPE SCOURSH_OPERATOR='ops@operator.example' \
  SCOURSH_CONFIG_REQUEST_BUDGET=20000 \
  bash "$ROOT/scan.sh" dast --target dast-fixture --intensity active \
  --i-own-target dast-fixture --out "$W/run-authz-yes" \
  >"$W/affirmed.log" 2>&1 || _RC=$?
assert_eq 0 "$_RC" 'an affirmed run at a raised budget completes'
AZ_YES=$(_slurp "$W/run-authz-yes/run.json")
assert_contains "$AZ_YES" '"affirmed": true' 'run.json records the affirmation'
assert_contains "$AZ_YES" '"affirmation_source": "flag"' 'and that it came by flag rather than from a terminal'
assert_contains "$AZ_YES" '"affirmation_target": "dast-fixture"' 'and which host it named'
assert_contains "$AZ_YES" '"operator": "ops@operator.example"' \
  'and the operator, because SCOURSH_OPERATOR was set - fails if identity is harvested unconditionally, which attaches a username and machine name to an artifact frequently handed to a third party'
assert_contains "$AZ_YES" 'intensity-ceiling:passive->active' \
  'the intensity delta is recorded as a from->to pair, never as a boolean'
assert_contains "$AZ_YES" 'request-budget:5000->20000' \
  'and so is the budget the affirmation actually raised - fails if the affirmation is recorded without the numbers it changed, which is the "unrestricted: true" record that reconstructs no traffic profile'
BANNER_MD=$(_slurp "$W/run-authz-yes/report.md")
assert_contains "$BANNER_MD" 'This run was UNRESTRICTED' \
  'report.md banners it where a human reads - fails under "run.json is the audit surface", which leaves the report reader unable to tell a target that handles load from a scanner told to ignore its own limits'
assert_contains "$(_slurp "$W/run-authz-yes/report.html")" 'This run was UNRESTRICTED' 'and so does report.html'
assert_contains "$(_slurp "$W/affirmed.log")" 'UNRESTRICTED RUN' \
  'and one stderr line says so at run start, naming the target, the operator and the relaxations - fails if the only trace is in files the operator has to go and open'
assert_eq 1 "$(_slurp "$W/affirmed.log" | grep -c 'UNRESTRICTED RUN' || true)" \
  'exactly ONE such line, not one per relaxation: loud, once, not a wall'

t_case 'the affirmation must still name this run'"'"'s own target, end to end'
_dast_scan "$W/run-authz-mismatch" "$FIX_SCOPE" --target dast-fixture --i-own-target some-other-host
assert_eq 2 "$_RC" \
  'an affirmation naming a different host is exit 2 through the real CLI - fails under "the affirmation is a switch", which is how a copied CI file carries one to a target that changed hands'


# =============================================================================
printf -- '\n-- the auth phase, through the real scan.sh dispatch (DAST-03) --\n'
# =============================================================================
# tests/suites/dast-auth.sh exercises the engine directly.  These two cases
# exercise the WIRING: that `dast_run_phase` reaches modules/dast/auth.sh at all,
# that it sees `--authed`, and that what it records lands on the surfaces a
# consumer reads.  Neither sends a request.

t_case '--authed with no config/auth.conf is a recorded reduction, not an error'
_dast_scan "$W/run-authed-noconf" "$FIX_SCOPE" --target dast-fixture --authed
assert_eq 0 "$_RC" \
  'the run still exits 0 - FAILS under "auth.conf is a required input for --authed", which docs/FOUNDATION.md tension 14 classes as a DECLARED reduction ("a check skipped for an absent requires-config"), not a missing-input abort'
RUN_AUTH_JSON=$(_slurp "$W/run-authed-noconf/run.json")
assert_contains "$RUN_AUTH_JSON" 'reason=auth_config_absent' \
  'run.json says the session could not be acquired and why - fails if the phase returns quietly, which leaves an --authed run reporting the same coverage as an authenticated one'
assert_contains "$RUN_AUTH_JSON" 'every authenticated check is skipped' \
  'and the human-readable gap states the consequence, not just the cause'
assert_contains "$RUN_AUTH_JSON" 'NOT assessed at all' \
  'the user-enumeration gap says which half ran even when neither did (docs/DESIGN.md §7.4) - fails under "say nothing when nothing happened", which lets a clean report read as "user enumeration was tested"'

t_case 'a static identity authenticates through the real dispatch, sending nothing'
FIX_AUTH=$W/root-with-auth
_fixture_root "$FIX_AUTH"
cp "$FIX_SCOPE/config/scope.conf" "$FIX_AUTH/config/scope.conf"
cat >"$FIX_AUTH/config/auth.conf" <<'AUTHEOF'
id: dast-fixture.a
mode: bearer
token: a-static-token-no-login-needed
AUTHEOF
chmod 600 "$FIX_AUTH/config/auth.conf"
STUB2=$W/netstub2
mkdir -p "$STUB2"
for c in curl wget nc openssl; do
  printf '#!/bin/sh\nprintf "%%s\\n" "$0 $*" >>"%s"\nexit 0\n' "$W/authed-network-attempts" >"$STUB2/$c"
  chmod 755 "$STUB2/$c"
done
rm -f "$W/authed-network-attempts"
_AUTH_RC=0
SCOURSH_INSTALL_ROOT=$FIX_AUTH PATH="$STUB2:$PATH" \
  bash "$ROOT/scan.sh" dast --target dast-fixture --authed --out "$W/run-authed-ok" \
  >"$W/run-authed-ok.log" 2>&1 || _AUTH_RC=$?
assert_eq 0 "$_AUTH_RC" 'the authenticated run exits 0'
assert_file_absent "$W/authed-network-attempts" \
  'and a STATIC credential produced no network call at all - FAILS under "every mode logs in", which would put a request on the wire for a credential the operator already handed us'
RUN_AUTH_OK=$(_slurp "$W/run-authed-ok/run.json")
assert_contains "$RUN_AUTH_OK" 'state=authenticated' \
  'run.json records the identity as authenticated - fails if the phase is reached but its record never leaves the process'
assert_not_contains "$RUN_AUTH_OK" 'a-static-token-no-login-needed' \
  'and the CREDENTIAL ITSELF appears nowhere in run.json - FAILS if the phase records the identity by logging what it sent, which writes the operator'"'"'s token into the artifact people attach to tickets'
assert_not_contains "$(_slurp "$W/run-authed-ok/report.md")" 'a-static-token-no-login-needed' \
  'nor in the markdown report'
assert_contains "$RUN_AUTH_OK" 'need TWO' \
  'and the run states that one identity is not enough for a cross-user check - fails if the shortfall is discovered later by DAST-29 reporting a clean result it had no second identity to obtain'

# =============================================================================
printf '\n-- tension-15 per-check selection: dast_check_selected --\n'
# =============================================================================
# scan.sh's `_scan_apply_profile_filter` builds SCOURSH_SELECTED_CHECKS from
# --profile-scan / --intensity / --allow-intrusive.  `dast_check_selected` is
# the DAST side's reader, and every phase script that gates a check on the
# operator's check set calls it.  Until it existed the four call sites were all
# `declare -F`-guarded, so the filter chain narrowed the REGISTRY and narrowed
# nothing a run actually SENT - forged JWTs and SQLi payloads went to the target
# for checks the operator had filtered out.
#
# The permissive default is the load-bearing half.  Unset or empty MUST mean
# "all selected", exactly as lib/findings.sh's `_derived_record_selected`
# already reads it: every direct-engine suite (dast-cookies/headers/sqli/
# discovery) sources a phase with no filter chain anywhere, so a fail-closed
# default would make every DAST phase inert while every "stays quiet"
# assertion in those suites still passed green - the worst possible failure,
# because it is invisible from the test output.

_sel_rc() {
  local rc=0
  dast_check_selected "$1" || rc=$?
  printf '%s' "$rc"
}

t_case 'the function four phase scripts call actually exists'
_HAVE_SEL=1
declare -F dast_check_selected >/dev/null && _HAVE_SEL=0
assert_eq 0 "$_HAVE_SEL" \
  'modules/dast/engine.sh defines dast_check_selected - FAILS while every call site is a `declare -F` guard over a function nothing defines, which is a silent no-op rather than an error'

t_case 'unset means all selected, not none'
unset SCOURSH_SELECTED_CHECKS
assert_eq 0 "$(_sel_rc DAST-INJ-SQLI_ERROR-01)" \
  'an UNSET SCOURSH_SELECTED_CHECKS selects everything - FAILS under a fail-closed default, which would make every direct-engine DAST suite green while testing nothing'

t_case 'empty means all selected too'
SCOURSH_SELECTED_CHECKS=''
assert_eq 0 "$(_sel_rc DAST-COOKIE-NO_SECURE-01)" \
  'an EMPTY SCOURSH_SELECTED_CHECKS selects everything - fails if only the unset case is special-cased, which is the shape scan.sh actually exports (it exports the variable unconditionally, possibly empty)'

t_case 'a populated list is honoured in both directions'
SCOURSH_SELECTED_CHECKS=$'DAST-COOKIE-NO_SECURE-01\nDAST-HDR-CSP_MISSING-01\nDAST-INJ-SQLI_TIME-01'
assert_eq 0 "$(_sel_rc DAST-COOKIE-NO_SECURE-01)" \
  'the FIRST id in the list is selected - fails under a match that skips the first line (a leading-newline anchor bug)'
assert_eq 0 "$(_sel_rc DAST-HDR-CSP_MISSING-01)" \
  'a MIDDLE id is selected'
assert_eq 0 "$(_sel_rc DAST-INJ-SQLI_TIME-01)" \
  'the LAST id in the list is selected - fails under a match that skips the last line (a trailing-newline anchor bug)'
assert_eq 1 "$(_sel_rc DAST-INJ-SQLI_ERROR-01)" \
  'an id NOT in the list is refused - FAILS under "always 0", which is exactly what the missing definition produced through the `declare -F` guards, and is why an operator-filtered payload still reached the target'

t_case 'membership is whole-line, never substring'
SCOURSH_SELECTED_CHECKS=$'DAST-HDR-CSP_MISSING-01\nDAST-COOKIE-NO_HTTPONLY-01'
assert_eq 1 "$(_sel_rc DAST-HDR-CSP)" \
  'a PREFIX of a selected id is not itself selected - FAILS under a bare `*"$id"*` substring glob'
assert_eq 1 "$(_sel_rc HTTPONLY-01)" \
  'a SUFFIX of a selected id is not itself selected - fails under the same substring glob from the other end'
SCOURSH_SELECTED_CHECKS=$'PRE-DAST-INJ-SQLI_ERROR-01\nDAST-HDR-CSP_MISSING-01'
assert_eq 1 "$(_sel_rc DAST-INJ-SQLI_ERROR-01)" \
  'an id that is only a SUFFIX OF ANOTHER LINE is not selected - fails under a substring glob, which would deliver a SQLi payload the operator filtered out because an unrelated id happened to end with the same bytes'

t_case 'the reader does not mutate the list it reads'
SCOURSH_SELECTED_CHECKS=$'DAST-HDR-CSP_MISSING-01\nDAST-HDR-HSTS_MISSING-01'
_sel_rc DAST-HDR-CSP_MISSING-01 >/dev/null
_sel_rc DAST-NOT-A-CHECK-01 >/dev/null
assert_eq $'DAST-HDR-CSP_MISSING-01\nDAST-HDR-HSTS_MISSING-01' "$SCOURSH_SELECTED_CHECKS" \
  'SCOURSH_SELECTED_CHECKS is unchanged after two lookups - fails if the reader normalises the list in place, which would let one phase narrow the set every later phase sees'
unset SCOURSH_SELECTED_CHECKS

# =============================================================================
printf '\n-- and the filter chain reaches a phase end to end, through scan.sh --\n'
# =============================================================================
# Both directions on ONE fixture, because the naive fix for each is the other's
# bug: a fail-closed default makes the "filtered" assertion pass for the wrong
# reason, and an undefined (or unconsulted) reader makes the "not filtered" one
# pass for the wrong reason.
#
# The fixture drops `tags: quick` from the DAST-COOKIE-* records ONLY, so
# `--profile-scan quick` selects the three quick-tagged DAST-HDR-* ids and no
# cookie id at all.  A profile that selected NOTHING would prove nothing: the
# permissive default above (correctly) cannot distinguish "the filter chain ran
# and kept nothing" from "there is no filter chain", so the selected set has to
# stay non-empty for this to be a test of selection rather than of the fallback.
FIX_SEL=$W/root-selection
_fixture_root "$FIX_SEL"
cp "$FIX_SCOPE/config/scope.conf" "$FIX_SEL/config/scope.conf"
_SEL_RULES=$FIX_SEL/modules/dast/passive/checks-cookies.rules
awk '
  /^id: /       { id = $2 }
  /^tags: quick$/ && id ~ /^DAST-COOKIE-/ { next }
                { print }
' "$_SEL_RULES" >"$_SEL_RULES.new"
mv "$_SEL_RULES.new" "$_SEL_RULES"

t_case 'every DAST-COOKIE-* check filtered out means the phase inspects nothing and says so'
_dast_scan "$W/run-sel-quick" "$FIX_SEL" --target dast-fixture --profile-scan quick
assert_eq 0 "$_RC" 'the filtered run still exits 0'
RUN_SEL_QUICK=$(_slurp "$W/run-sel-quick/run.json")
assert_contains "$RUN_SEL_QUICK" 'DAST-HDR-CSP_MISSING-01' \
  'the selected set is genuinely non-empty - without this the case below would pass under the "empty means all" fallback instead of under real selection'
# On the ARTIFACT, not on run.json: `assert_not_contains` quotes its needle, so
# a `checks_selected*DAST-COOKIE-NO_SECURE-01` glob is a LITERAL asterisk that
# can never appear, so the earlier form of this assertion was vacuous: measured
# green against a fixture deliberately mutated to leave every DAST-COOKIE-* id
# IN the selected set, which is the precondition failure it exists to catch.
# run.json cannot be asserted on bare either: it
# also carries `skipped_checks`, where the cookie ids legitimately DO appear.
# meta/checks_selected is the selected set alone, which is the precondition this
# case actually needs; tests/suites/scan.sh:381 reads it the same way.
assert_not_contains "$(cat "$W/run-sel-quick/meta/checks_selected")" 'DAST-COOKIE-NO_SECURE-01' \
  'and the cookie ids are genuinely out of the selected set - FAILS if the fixture stops narrowing the registry, which would let the case below pass because the phase was never filtered rather than because it honoured the filter'
assert_contains "$RUN_SEL_QUICK" 'reason=cookies_no_check_selected' \
  'the cookies phase consulted the operator'"'"'s check set and inspected NO response - FAILS while dast_check_selected is undefined, which is the bug this ticket fixes: the registry was narrowed and the phase still ran every check'

t_case 'and with the same fixture unfiltered, the phase runs normally'
_dast_scan "$W/run-sel-full" "$FIX_SEL" --target dast-fixture --profile-scan full
assert_eq 0 "$_RC" 'the unfiltered run exits 0'
RUN_SEL_FULL=$(_slurp "$W/run-sel-full/run.json")
assert_not_contains "$RUN_SEL_FULL" 'reason=cookies_no_check_selected' \
  'no "nothing selected" record under --profile-scan full - FAILS under a fail-closed default or an inverted membership test, either of which would make every DAST phase inert on an ordinary run'
assert_contains "$RUN_SEL_FULL" 'inspected for cookie flags' \
  'and the phase reached its ordinary per-target coverage statement instead - fails if "filtered" and "ran" produce the same silence'

# =============================================================================
printf '\n-- the resolving direction is pinned too (this ticket) --\n'
# =============================================================================
# tests/suites/dast-crawl.sh already proves the crawl phase end to end against
# a resolving, stubbed target; this suite's own job is narrower and
# orchestration-level - proving that RESOLVE_STUB above really is consulted by
# a real `scan.sh dast` SUBPROCESS (every case above only proves the FAILING
# side of that, since dast.fixture.invalid never resolves), and that a host it
# resolves takes a genuinely different, request-issuing path than
# dast.fixture.invalid's refusal does.
#
# Both directions are asserted together because the naive fix for either is
# the other's bug: a resolve stub that always fails leaves this direction as
# untested as the host's real DNS did (this ticket's own finding), and a
# resolve stub that always succeeds would silently make dast.fixture.invalid
# resolve too and delete every `url_not_requestable`/`endpoint_inventory_absent`
# case earlier in this file - which the second case below, re-checking
# $RUN_OK_JSON, exists to catch.
FIX_RESOLVES=$W/root-resolves
_fixture_root "$FIX_RESOLVES"
cat >"$FIX_RESOLVES/config/scope.conf" <<'EOF'
id: dast-resolves
base-url: https://dast-resolves.fixture.invalid/
allow-subdomains: false
notes: The one host RESOLVE_STUB above actually resolves. The transport is
  ALSO stubbed (TRANSPORT_STUB below), so a real request still never reaches a
  real network even though resolution succeeds.
EOF

TRANSPORT_STUB=$W/transport-stub
cat >"$TRANSPORT_STUB" <<'STUBEOF'
#!/usr/bin/env bash
# METHOD SCHEME HOST PORT PATH ADDR [BODY_OUT] [HEADERS_OUT] - lib/http.sh's
# transport contract (the same shape tests/suites/dast-crawl.sh's own stub
# uses). Logs every request it is asked to make and serves a trivial,
# uninteresting page, so this suite - which pins ORCHESTRATION, not phase
# behaviour - stays quiet on every passive check.
set -Eeuo pipefail
method=$1; path=$5; bodyout=${7:-}
printf '%s %s\n' "$method" "$path" >>"$RESOLVES_REQLOG"
[[ -n $bodyout ]] && printf '<html></html>' >"$bodyout"
printf '200\n\ntext/html\n'
STUBEOF
chmod 0755 "$TRANSPORT_STUB"

t_case 'a host RESOLVE_STUB resolves is actually requested, end to end through a real subprocess'
RESOLVES_REQLOG=$W/resolves-requests.log
: >"$RESOLVES_REQLOG"
_RC=0
SCOURSH_INSTALL_ROOT=$FIX_RESOLVES SCOURSH_HTTP_TRANSPORT=$TRANSPORT_STUB \
  RESOLVES_REQLOG=$RESOLVES_REQLOG \
  bash "$ROOT/scan.sh" dast --target dast-resolves --out "$W/run-resolves" \
  >"$W/run-resolves.log" 2>&1 || _RC=$?
assert_eq 0 "$_RC" 'a run against a host this suite'"'"'s resolver stub resolves still exits 0'
# The log is pre-touched empty above, so `assert_file_exists` alone would pass
# whether or not a request was ever made - the content check below is the one
# that actually pins that SCOURSH_HTTP_RESOLVE was honoured in a real
# subprocess, which is the untested direction this ticket names.
assert_contains "$(_slurp "$RESOLVES_REQLOG")" 'GET /' \
  'a real request reached the stubbed transport, as the crawl'"'"'s own entry-point GET on the base URL - fails if SCOURSH_HTTP_RESOLVE is not actually honoured in a real scan.sh dast SUBPROCESS (as opposed to the in-process cases elsewhere in this file)'
RUN_RESOLVES_JSON=$(_slurp "$W/run-resolves/run.json")
assert_not_contains "$RUN_RESOLVES_JSON" 'reason=url_not_requestable' \
  'and no url_not_requestable reduction is recorded for a host that DID resolve - fails under the mirror bug, a resolve stub that answers every host regardless of name, which would silently make dast.fixture.invalid resolve too'

t_case 'dast.fixture.invalid still does not resolve - the stub is host-specific, not a blanket pass'
assert_contains "$RUN_OK_JSON" 'reason=url_not_requestable' \
  'the unresolvable fixture'"'"'s own earlier run still carries the refusal - fails if RESOLVE_STUB were a blanket success, which would delete this suite'"'"'s existing DNS-failure coverage while every case above still read green'

t_summary dast
