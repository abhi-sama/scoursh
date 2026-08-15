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
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Fixture install roots.
#
# A dast run needs modules/dast/ AND lib/ to be reachable from
# $SCOURSH_INSTALL_ROOT, while its config/ must be the fixture's own (the real
# repository ships config/scope.conf.example and no config/scope.conf, which is
# the shipped default and is deliberately left that way - docs/STEP5-DAST-PLAN.md
# "no shipped file names a third-party host as a scannable target").  So each
# fixture root symlinks the real tree's code and owns its own config/.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    ln -sfn "$ROOT/$e" "$dir/$e"
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
assert_file_absent "$W/network-attempts" \
  'no curl/wget/nc/openssl was invoked by a dast run - fails under "the dispatch skeleton may probe the target once to prove it is up"'

t_case 'nothing is claimed as executed'
RUN_OK_JSON=$(_slurp "$W/run-ok/run.json")
assert_contains "$RUN_OK_JSON" '"checks_run": []' \
  'checks_run is empty - fails under "record the phases we would have run", which is the overclaim this ticket exists to avoid'

# =============================================================================
printf '\n-- run.json tells the truth about a run with no phases (constraint 3) --\n'
# =============================================================================

t_case 'run.json records a coverage_reduction naming the missing phase scripts'
assert_contains "$RUN_OK_JSON" 'reason=no_phase_scripts_on_disk_yet' \
  'run.json carries the declared reduction - fails under "the module logs it to stderr", which leaves the artifact claiming a complete run'

t_case 'run.json records a coverage_gap a human reads, naming the target'
assert_contains "$RUN_OK_JSON" '"coverage_gap": [' 'run.json has a coverage_gap array'
assert_contains "$RUN_OK_JSON" "covered nothing on target 'dast-fixture'" \
  'the gap sentence itself names the target it did not cover - fails under "the targets array already names it", which leaves the gap unattributed'
assert_contains "$RUN_OK_JSON" 'no request was sent' \
  'the gap says plainly that nothing was sent - fails under "reason=not_yet_built is enough", which a reader cannot tell from a clean scan'

t_case 'the report a human opens carries the same statement'
REPORT_MD=$(_slurp "$W/run-ok/report.md")
assert_contains "$REPORT_MD" 'Limitations and coverage' 'report.md has its limitations section'
assert_contains "$REPORT_MD" 'no_phase_scripts_on_disk_yet' \
  'report.md states the reduction - fails under "run.json is the audit surface, the report is for findings"'

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
  active/protopollution.sh jwt.sh graphql.sh ratelimit.sh authz.sh transport.sh; do
  _found=0
  for _spec in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
    [[ ${_spec%%:*} == "$_want" ]] && _found=1
  done
  assert_eq 1 "$_found" "the phase table names $_want (docs/STEP5-DAST-PLAN.md tiers 1-5)"
done

t_case 'a phase above the run intensity is not sourced, even when its script exists'
FIX_PHASE=$W/root-with-phase
_fixture_root "$FIX_PHASE"
# The symlinked modules/ is the real tree, so a fixture phase script has to
# live in a modules/ of the fixture's own.  Copy the two dast files across and
# leave the rest symlinked.
rm -f "$FIX_PHASE/modules"
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
assert_contains "$RUN_FULL_JSON" 'no_phase_scripts_on_disk_yet' \
  'and the no-phases reduction is still recorded, because a full inventory that nothing consumes is not coverage'

t_case 'the inventory paths are published for the phase that will consume them'
assert_eq "$W/run-full-inv/inventory/endpoints.json" \
  "$(SCOURSH_RUN_DIR=$W/run-full-inv bash -c \
    'source "'"$ROOT"'/modules/dast/engine.sh"; dast_inventory_read; printf "%s" "$_DAST_ENDPOINTS_FILE"')" \
  'dast_inventory_read publishes the endpoints path when the file is real - fails under "the reader only counts, so a later phase re-derives the path itself"'

# =============================================================================
printf '\n-- what this ticket deliberately does not ship --\n'
# =============================================================================

t_case 'modules/dast/ registers no check, so nothing can be selected'
assert_file_absent "$ROOT/modules/dast/checks.rules" \
  'no checks.rules is shipped - fails under "register the phases now so the registry is warm", which would trip rules/RULE-FORMAT.md E072 (script must exist) on every one of them'
assert_contains "$RUN_OK_JSON" 'reason=no_check_registry_on_disk_yet' \
  'scan.sh still records the empty registry honestly, exactly as it did before this module landed'

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


t_summary dast
