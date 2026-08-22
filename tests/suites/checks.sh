#!/usr/bin/env bash
# tests/suites/checks.sh - lib/checks.sh: the docs/FOUNDATION.md tension 15
# filter chain (--profile-scan / --intensity / --allow-intrusive) and the
# registry loader, including the two closed findings this file settles (F3's
# `compliance` definition, F8's `derived`-exempt-from-intensity rule).
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/checks.sh
source "$ROOT/lib/checks.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIXTURE_ROOT=$ROOT/tests/fixtures/checks-registry

# =============================================================================
printf -- '\n-- profile/intensity name validation --\n'
# =============================================================================
t_case 'the three named profiles validate; anything else does not'
assert_status 0 'quick is a valid profile name' checks_valid_profile quick
assert_status 0 'full is a valid profile name' checks_valid_profile full
assert_status 0 'compliance is a valid profile name' checks_valid_profile compliance
assert_status 1 "'bogus' is not a valid profile name - this ticket's 2nd acceptance criterion" \
  checks_valid_profile bogus
assert_status 1 'an empty profile name is not valid' checks_valid_profile ''

t_case 'the three named intensities validate; anything else does not'
assert_status 0 'passive is a valid intensity' checks_valid_intensity passive
assert_status 0 'safe is a valid intensity' checks_valid_intensity safe
assert_status 0 'active is a valid intensity' checks_valid_intensity active
assert_status 1 "'bogus' is not a valid intensity" checks_valid_intensity bogus

t_case 'CHECKS_PROFILES/CHECKS_INTENSITIES are the single source of truth: checks_valid_profile/checks_valid_intensity accept exactly the array members and nothing else'
# Guards against the two arrays and the checks_valid_* membership loops
# silently disagreeing (they read the same array, so this mostly proves the
# arrays themselves have not grown a stray entry) - the case statements this
# pins are checks_profile_keeps/checks_intensity_keeps and
# scan.sh's scan_validate_flag_value, both exercised below.
assert_eq 'quick full compliance' "${CHECKS_PROFILES[*]}" \
  'CHECKS_PROFILES is exactly the three documented profile names, in the order the header comment documents them'
assert_eq 'passive safe active' "${CHECKS_INTENSITIES[*]}" \
  'CHECKS_INTENSITIES is exactly the three documented tiers, in ceiling order'
for _p in "${CHECKS_PROFILES[@]}"; do
  assert_status 0 "checks_valid_profile accepts '$_p' (a CHECKS_PROFILES member)" checks_valid_profile "$_p"
done
for _i in "${CHECKS_INTENSITIES[@]}"; do
  assert_status 0 "checks_valid_intensity accepts '$_i' (a CHECKS_INTENSITIES member)" checks_valid_intensity "$_i"
done
unset _p _i

# =============================================================================
printf -- '\n-- loading the fixture registry --\n'
# =============================================================================
# lib/records.sh's E018/E081 ownership checks resolve a loaded file's path
# relative to $SCOURSH_INSTALL_ROOT internally, so a fixture registry must be
# read through that same variable rather than through a root argument
# (lib/checks.sh's own comment on checks_registry_load explains why).
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT

checks_registry_load dast reg_dast
DAST_SET=${CHECKS_REGISTRY_SETS[0]:-}
t_case 'checks_registry_load finds the fixture checks.rules for dast'
assert_eq 1 "${#CHECKS_REGISTRY_SETS[@]}" 'exactly one file matched modules/dast/**/*.rules'
assert_eq 5 "$(records_count "$DAST_SET")" 'the fixture registry has 5 script checks'

checks_registry_load sast reg_sast
SAST_SET=${CHECKS_REGISTRY_SETS[0]:-}
t_case 'checks_registry_load finds the fixture pattern-rule pack for sast'
assert_eq 1 "${#CHECKS_REGISTRY_SETS[@]}" 'exactly one file matched modules/sast/rules/*.rules'
assert_eq 2 "$(records_count "$SAST_SET")" 'the fixture pack has 2 pattern rules'

t_case 'a module with no fixture directory at all finds nothing (silent no-op, not an error)'
checks_registry_load cloud reg_cloud
assert_eq 0 "${#CHECKS_REGISTRY_SETS[@]}" \
  'no modules/cloud/ under the fixture root - fails under "checks_registry_load errors on a missing module dir"'

t_case 'an unknown module name finds nothing rather than dying'
checks_registry_load bogus-module reg_bogus
assert_eq 0 "${#CHECKS_REGISTRY_SETS[@]}" 'checks_module_dir has no row for it'

unset SCOURSH_INSTALL_ROOT

# =============================================================================
printf -- '\n-- per-record tag/type inspection (fixture: dast checks.rules) --\n'
# =============================================================================
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT
checks_registry_load dast reg_dast2
DAST_SET=${CHECKS_REGISTRY_SETS[0]}
unset SCOURSH_INSTALL_ROOT

_idx_of() { records_index_of_id "$DAST_SET" "$1"; }

t_case 'checks_type_tag reads the single type tag off each fixture check'
assert_eq passive "$(checks_type_tag "$DAST_SET" "$(_idx_of DAST-HDR-CSP-01)")" 'DAST-HDR-CSP-01 is passive'
assert_eq safe-active "$(checks_type_tag "$DAST_SET" "$(_idx_of DAST-AUTHZ-OBJREF-01)")" 'DAST-AUTHZ-OBJREF-01 is safe-active'
assert_eq active "$(checks_type_tag "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)")" 'DAST-INJ-SQLI-01 is active'
assert_eq config-read "$(checks_type_tag "$DAST_SET" "$(_idx_of DAST-DISC-CRAWL-01)")" 'DAST-DISC-CRAWL-01 is config-read'

t_case 'checks_is_intrusive is true only for the one fixture check tagged intrusive'
assert_status 0 'DAST-INJ-SQLI-01 is intrusive' checks_is_intrusive "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)"
assert_status 1 "DAST-HDR-CSP-01 is NOT intrusive - fails under 'every active check is intrusive'" \
  checks_is_intrusive "$DAST_SET" "$(_idx_of DAST-HDR-CSP-01)"

t_case 'checks_has_tag finds an authored tag and correctly misses an absent one'
assert_status 0 'DAST-HDR-CSP-01 has the quick tag' checks_has_tag "$DAST_SET" "$(_idx_of DAST-HDR-CSP-01)" quick
assert_status 1 'DAST-HDR-HSTS-01 has NO quick tag (full-only by design)' \
  checks_has_tag "$DAST_SET" "$(_idx_of DAST-HDR-HSTS-01)" quick

# =============================================================================
printf -- "\n-- filter 1: --profile-scan (docs/FOUNDATION.md tension 15 step 2) --\n"
# =============================================================================
t_case "'full' keeps every check regardless of profile tag (rules/RULE-FORMAT.md §9.1.3's 'no profile tag runs only in full') - but --allow-intrusive is a SEPARATE filter, so the one intrusive check still needs it"
FULL_SEL=$(checks_select full '' false "$DAST_SET")
assert_eq 4 "$(printf '%s\n' "$FULL_SEL" | grep -c .)" \
  "4 of 5 selected under full with no --allow-intrusive - fails under 'full also implies --allow-intrusive' (it does not: they are independent filters, tension 15's own intersection rule)"
assert_not_contains "$FULL_SEL" 'DAST-INJ-SQLI-01' 'the intrusive check is excluded from full without --allow-intrusive'
FULL_INTRUSIVE_SEL=$(checks_select full '' true "$DAST_SET")
assert_eq 5 "$(printf '%s\n' "$FULL_INTRUSIVE_SEL" | grep -c .)" \
  'all 5 fixture checks selected under full + --allow-intrusive'

t_case "'quick' keeps only checks tagged quick"
QUICK_SEL=$(checks_select quick '' false "$DAST_SET")
assert_contains "$QUICK_SEL" 'DAST-HDR-CSP-01' 'DAST-HDR-CSP-01 (tags: passive, quick) is selected'
assert_contains "$QUICK_SEL" 'DAST-DISC-CRAWL-01' 'DAST-DISC-CRAWL-01 (tags: config-read, quick) is selected'
assert_not_contains "$QUICK_SEL" 'DAST-HDR-HSTS-01' \
  "DAST-HDR-HSTS-01 (tags: passive only) is NOT selected - fails under 'a rule with no profile tag runs under quick too'"
assert_not_contains "$QUICK_SEL" 'DAST-AUTHZ-OBJREF-01' 'the compliance-only check is not selected under quick'
assert_not_contains "$QUICK_SEL" 'DAST-INJ-SQLI-01' 'the active/intrusive check is not selected under quick'

t_case "'compliance' keeps only checks tagged compliance - finding F3, closed on the TAG reading"
COMPLIANCE_SEL=$(checks_select compliance '' false "$DAST_SET")
assert_contains "$COMPLIANCE_SEL" 'DAST-AUTHZ-OBJREF-01' \
  'DAST-AUTHZ-OBJREF-01 (tags: safe-active, compliance; owasp: A01:2021; cis: 6.1) is selected'
assert_not_contains "$COMPLIANCE_SEL" 'DAST-HDR-HSTS-01' \
  "DAST-HDR-HSTS-01 (owasp: A05:2021, a REAL non-none value, but NO compliance tag) is NOT selected - fails under the rejected 'non-empty cis-or-owasp field' reading from docs/FOUNDATION.md tension 15's original text, which this fixture is built to distinguish from the tag reading"
assert_not_contains "$COMPLIANCE_SEL" 'DAST-DISC-CRAWL-01' \
  'DAST-DISC-CRAWL-01 (owasp: none, cis: absent, no compliance tag) is correctly excluded either way'

t_case 'an unknown profile name selects nothing, rather than silently defaulting to full'
BOGUS_SEL=$(checks_select bogus '' false "$DAST_SET")
assert_eq '' "$BOGUS_SEL" \
  "checks_select with profile='bogus' selects zero checks - fails under 'an unrecognised profile falls back to full'"

t_case "checks_profile_keeps has a real, non-default-fallthrough arm for EVERY CHECKS_PROFILES member - fails if a profile is ever added to the array without a matching case arm (the drift QA flagged: a case statement with no matching pattern and no '*)' returns 0, i.e. silently KEEPS a check it should have filtered)"
for _p in "${CHECKS_PROFILES[@]}"; do
  if [[ $_p == full ]]; then
    assert_status 0 "'$_p' keeps DAST-HDR-HSTS-01 (no profile tags at all) - full's documented behaviour" \
      checks_profile_keeps "$DAST_SET" "$(_idx_of DAST-HDR-HSTS-01)" "$_p"
  else
    assert_status 1 "'$_p' drops DAST-HDR-HSTS-01 (carries neither a quick nor a compliance tag) - would wrongly pass (fallthrough bug) if this profile's case arm went missing" \
      checks_profile_keeps "$DAST_SET" "$(_idx_of DAST-HDR-HSTS-01)" "$_p"
  fi
done
unset _p

# =============================================================================
printf -- "\n-- filter 2: --intensity (the type-tag ceiling) --\n"
# =============================================================================
t_case "'passive' keeps passive/config-read/posture/static and drops safe-active/active"
PASSIVE_SEL=$(checks_select full passive false "$DAST_SET")
assert_contains "$PASSIVE_SEL" 'DAST-HDR-CSP-01' 'passive check kept under --intensity passive'
assert_contains "$PASSIVE_SEL" 'DAST-DISC-CRAWL-01' 'config-read check kept under --intensity passive'
assert_not_contains "$PASSIVE_SEL" 'DAST-AUTHZ-OBJREF-01' \
  "safe-active check dropped under --intensity passive - fails under 'intensity only ceils active, not safe-active'"
assert_not_contains "$PASSIVE_SEL" 'DAST-INJ-SQLI-01' 'active check dropped under --intensity passive'

t_case "'safe' additionally keeps safe-active, still drops active"
SAFE_SEL=$(checks_select full safe false "$DAST_SET")
assert_contains "$SAFE_SEL" 'DAST-AUTHZ-OBJREF-01' 'safe-active check kept under --intensity safe'
assert_not_contains "$SAFE_SEL" 'DAST-INJ-SQLI-01' 'active check still dropped under --intensity safe'

t_case "'active' keeps everything up to and including active"
ACTIVE_SEL=$(checks_select full active true "$DAST_SET")
assert_contains "$ACTIVE_SEL" 'DAST-INJ-SQLI-01' 'active check kept under --intensity active (with --allow-intrusive)'

t_case "the worked example from docs/FOUNDATION.md tension 15's own text: '--profile-scan quick --intensity active' runs passive checks only, i.e. selects zero active/safe-active checks"
QA_SEL=$(checks_select quick active true "$DAST_SET")
assert_not_contains "$QA_SEL" 'DAST-INJ-SQLI-01' \
  "--profile-scan quick --intensity active still drops the active check - fails under 'the more permissive control wins' (tension 15's rejected option 1)"
QUICK_ONLY_SEL=$(checks_select quick '' false "$DAST_SET")
assert_eq "$QUICK_ONLY_SEL" "$QA_SEL" \
  "raising --intensity to active adds NOTHING beyond what --profile-scan quick alone already selected in this fixture (every quick-tagged check is already passive/config-read, both inside the active ceiling) - fails under 'active re-enables something a narrower filter dropped'"

t_case "'' (no ceiling) keeps everything, independent of type tag"
NONE_SEL=$(checks_select full '' true "$DAST_SET")
assert_contains "$NONE_SEL" 'DAST-INJ-SQLI-01' 'active check kept when no intensity ceiling is applied at all'

t_case "checks_intensity_keeps has a real, non-default-fallthrough arm for EVERY CHECKS_INTENSITIES member - same drift guard as checks_profile_keeps above, using DAST-INJ-SQLI-01 (type: active), which only 'active' admits"
for _i in "${CHECKS_INTENSITIES[@]}"; do
  if [[ $_i == active ]]; then
    assert_status 0 "'$_i' keeps DAST-INJ-SQLI-01 (type: active) - the top tier's documented behaviour" \
      checks_intensity_keeps "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)" "$_i"
  else
    assert_status 1 "'$_i' drops DAST-INJ-SQLI-01 (type: active, above this tier's ceiling) - would wrongly pass (fallthrough bug) if this tier's case arm went missing" \
      checks_intensity_keeps "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)" "$_i"
  fi
  assert_status 0 "'$_i' keeps DAST-DISC-CRAWL-01 (type: config-read) - inside every tier's ceiling" \
    checks_intensity_keeps "$DAST_SET" "$(_idx_of DAST-DISC-CRAWL-01)" "$_i"
done
unset _i

# =============================================================================
printf -- "\n-- filter 3: --allow-intrusive --\n"
# =============================================================================
t_case '--allow-intrusive=false (the default) drops the intrusive check even under full+active'
NO_INTRUSIVE=$(checks_select full active false "$DAST_SET")
assert_not_contains "$NO_INTRUSIVE" 'DAST-INJ-SQLI-01' \
  "the intrusive check is dropped without --allow-intrusive - fails under 'intensity alone gates intrusive checks'"

t_case '--allow-intrusive=true keeps it (still subject to the other two filters)'
WITH_INTRUSIVE=$(checks_select full active true "$DAST_SET")
assert_contains "$WITH_INTRUSIVE" 'DAST-INJ-SQLI-01' '--allow-intrusive=true keeps the intrusive check'

t_case '--allow-intrusive never RE-ENABLES a check profile-scan already dropped (intersection, not override)'
QUICK_INTRUSIVE=$(checks_select quick active true "$DAST_SET")
assert_not_contains "$QUICK_INTRUSIVE" 'DAST-INJ-SQLI-01' \
  "quick + active + allow-intrusive still drops it (no quick tag) - fails under 'allow-intrusive outranks profile-scan'"

# =============================================================================
printf -- '\n-- checks_selection_reason names the FIRST filter that drops a check --\n'
# =============================================================================
t_case 'a check dropped by profile-scan reports profile-scan, even when intensity/allow-intrusive would also drop it'
REASON=$(checks_selection_reason "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)" quick passive false)
assert_eq 'profile-scan=quick' "$REASON" \
  "reports the profile filter (step 1), not intensity or allow-intrusive - fails under 'the LAST filter that would drop it wins'"

t_case 'a check that survives profile-scan but not intensity reports intensity'
REASON=$(checks_selection_reason "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)" full passive false)
assert_eq 'intensity=passive' "$REASON" 'reports intensity=passive, not allow-intrusive'

t_case 'a check that survives profile-scan and intensity but not allow-intrusive reports allow-intrusive'
REASON=$(checks_selection_reason "$DAST_SET" "$(_idx_of DAST-INJ-SQLI-01)" full active false)
assert_eq 'allow-intrusive=false' "$REASON" 'the third filter is the one that actually drops it here'

t_case 'a selected check has an empty reason'
REASON=$(checks_selection_reason "$DAST_SET" "$(_idx_of DAST-HDR-CSP-01)" full '' false)
assert_eq '' "$REASON" 'DAST-HDR-CSP-01 survives every filter under full/no-ceiling/no-intrusive'

# =============================================================================
printf -- "\n-- finding F8: derived checks are exempt from the --intensity ceiling --\n"
# =============================================================================
DERIVED_SET=derived_fixture
records_load "$ROOT/tests/fixtures/rules/derived.rules" derived "$DERIVED_SET" >/dev/null 2>&1
DERIVED_IDX=$(records_index_of_id "$DERIVED_SET" COMPOSITE-FIXTURE-CHAIN)

t_case "a derived (composite) check is kept under --intensity active even though 'derived' is not in the active ceiling's tag list"
assert_status 0 'checks_intensity_keeps returns true for a derived-type record under active' \
  checks_intensity_keeps "$DERIVED_SET" "$DERIVED_IDX" active

t_case "...and kept under --intensity passive too - fails under 'derived only survives the top tier'"
assert_status 0 'checks_intensity_keeps returns true for a derived-type record under passive' \
  checks_intensity_keeps "$DERIVED_SET" "$DERIVED_IDX" passive

t_case 'a derived check is STILL subject to --profile-scan (F8 exempts only the intensity ceiling, not every filter)'
assert_status 1 "COMPOSITE-FIXTURE-CHAIN (tags: derived, no quick tag) is dropped under --profile-scan quick - fails under 'derived is exempt from every filter'" \
  checks_profile_keeps "$DERIVED_SET" "$DERIVED_IDX" quick

# =============================================================================
printf -- '\n-- checks_record_run_selection: run.json wiring (meta/checks_selected, meta/skipped_checks) --\n'
# =============================================================================
W=$SCOURSH_SCRATCH/checks
rm -rf "$W"
mkdir -p "$W"
run_init "$W/run1"

# Captured via a `{ ...; } 2>file` GROUP, not `$(...)`: checks_record_run_selection's
# own comment requires it be called directly, never through a command
# substitution subshell (CHECKS_LAST_SELECTED_IDS below would silently stay
# empty otherwise).  A `{ }` group redirects this shell's stderr for the
# duration without forking one, so the discipline holds while still letting
# the test capture what log_warn wrote.
RUN1_WARN_LOG=$W/run1-warn.log
{ checks_record_run_selection quick passive false "$DAST_SET"; } 2>"$RUN1_WARN_LOG"

t_case "checks_record_run_selection logs a warning naming the flag that won and the count of checks it dropped - docs/FOUNDATION.md tension 15's own quoted requirement, previously implemented (checks_record_run_selection's log_warn call) but untested"
assert_contains "$(cat "$RUN1_WARN_LOG")" "profile filter 'profile-scan=quick' dropped 3 check(s)" \
  "names the flag ('profile-scan=quick') and the count (3: HSTS-01, IDOR-01, SQLI-01, all dropped by profile-scan per the skipped_checks assertions below) - fails under 'no warning is logged' or under a wrong flag/count"

t_case 'selected checks landed in meta/checks_selected'
assert_file_exists "$W/run1/meta/checks_selected" 'meta/checks_selected was written'
assert_contains "$(cat "$W/run1/meta/checks_selected")" 'DAST-HDR-CSP-01' 'the quick-tagged passive check is recorded as run'

t_case 'dropped checks landed in meta/skipped_checks with their reason'
assert_file_exists "$W/run1/meta/skipped_checks" 'meta/skipped_checks was written'
assert_contains "$(cat "$W/run1/meta/skipped_checks")" 'check=DAST-HDR-HSTS-01 skipped_by=profile-scan=quick' \
  'the full-only check is recorded with the profile-scan reason'
assert_contains "$(cat "$W/run1/meta/skipped_checks")" 'check=DAST-AUTHZ-OBJREF-01 skipped_by=profile-scan=quick' \
  'the compliance-only check is ALSO dropped by profile-scan (not by intensity), naming the FIRST filter'
assert_contains "$(cat "$W/run1/meta/skipped_checks")" 'check=DAST-INJ-SQLI-01 skipped_by=profile-scan=quick' \
  'the active/intrusive check is dropped by profile-scan first, even though intensity/allow-intrusive would also drop it'

t_case 'CHECKS_LAST_SELECTED_IDS reflects exactly the selected set'
assert_eq 2 "${#CHECKS_LAST_SELECTED_IDS[@]}" 'two checks selected under quick+passive (CSP and discovery)'

# Run AFTER every RUN1/CHECKS_LAST_SELECTED_IDS assertion above, deliberately:
# checks_record_run_selection overwrites CHECKS_LAST_SELECTED_IDS on every
# call, so a second call earlier would make the assertion above see this
# call's ids instead of RUN1's.
W2=$SCOURSH_SCRATCH/checks-nowarn
rm -rf "$W2"
mkdir -p "$W2"
run_init "$W2/run1"
RUN2_WARN_LOG=$W2/run1-warn.log
{ checks_record_run_selection full '' true "$DAST_SET"; } 2>"$RUN2_WARN_LOG"

t_case 'checks_record_run_selection logs NO warning when every check survives every filter'
assert_eq '' "$(cat "$RUN2_WARN_LOG")" \
  "full + no intensity ceiling + --allow-intrusive selects all 5 fixture checks, so dropped_by is empty - fails under 'a warning is logged unconditionally, even with nothing dropped'"

t_summary 'checks' || FAILED=1
exit "${FAILED:-0}"
