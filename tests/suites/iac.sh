#!/usr/bin/env bash
# tests/suites/iac.sh - modules/iac/{parse.sh,run.sh} and the terraform.rules
# seed pack (docs/DESIGN.md §13 step 4, this ticket).
#
# Modeled on tests/suites/sast.sh's go.rules section (§13 step 3c precedent):
# one true-positive fixture per rule id under tests/fixtures/vuln/, one
# true-negative (safe-equivalent) fixture per rule id under
# tests/fixtures/clean/, both directories scanned wholesale exactly like the
# real end-to-end shape - terraform.rules' own `files: *.tf` glob is what
# does the filtering out of the non-Terraform fixtures already living there.
#
# Covers this ticket's acceptance criteria:
#   - `scan_dispatch iac` no longer no-ops for a fixture .tf file matching
#     each seed rule (the exit-code-flip section, and the real `scan.sh iac`
#     subprocess calls below)
#   - each IAC-TF-* id fires on its vuln fixture and stays quiet on its
#     clean fixture
#   - findings emitted by the iac module carry module=iac, not module=sast
#     (lib/findings.sh's _fp_profile_for has a dedicated `iac` branch; this
#     is what proves modules/iac/parse.sh's own emission path, not a reused
#     sast one, actually ran)
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/iac/parse.sh
source "$ROOT/modules/iac/parse.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/iac-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- terraform.rules: true-positive AND true-negative, per rule id --\n'
# =============================================================================
_scan_one_pack() {
  local pack=$1 fixture=$2 rundir=$3
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=iac-suite
  SCOURSH_PATH_ROOT=$(path_root_cell "$fixture")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$fixture")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_IAC_MAX_MATCHES_PER_FILE=200
  CHECKS_REGISTRY_SETS=(pkset)
  records_load "$ROOT/modules/iac/$pack.rules" pattern-rule pkset >/dev/null
  sast_index_checks
  local -a ids=()
  local n i
  n=$(records_count pkset)
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id pkset "$i")"); done
  # `fixture` is always a DIRECTORY, mirroring tests/suites/sast.sh's own
  # _scan_one_pack - docs/DESIGN.md §5's grammar is `--path DIR`, never a
  # single file.
  iac_scan_tree "$fixture" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
}

_ids_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[check_id]}"
  done <"$rundir/findings.fields"
}

_modules_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[module]}"
  done <"$rundir/findings.fields"
}

TF_IDS='IAC-TF-OPEN_CIDR-01 IAC-TF-PUBLIC_ACL-01 IAC-TF-UNENCRYPTED-01 IAC-TF-KEY_ROTATION_DISABLED-01 IAC-TF-PUBLIC_IP-01 IAC-TF-HARDCODED_SECRET-01 IAC-TF-RDS_PUBLIC-01'

_scan_one_pack terraform "$ROOT/tests/fixtures/vuln" "$W/run-tf-vuln"
_tf_vuln_found=$(_ids_found "$W/run-tf-vuln")
for _want_id in $TF_IDS; do
  t_case "terraform: $_want_id true-positive detection"
  assert_contains "$_tf_vuln_found" "$_want_id" \
    "$_want_id fires on its tests/fixtures/vuln/*.tf fixture - fails if the pattern, files glob, or context directive silently drops the match"
done

_scan_one_pack terraform "$ROOT/tests/fixtures/clean" "$W/run-tf-clean"
_tf_clean_found=$(_ids_found "$W/run-tf-clean")
for _safe_id in $TF_IDS; do
  t_case "terraform: $_safe_id stays quiet on its safe equivalent"
  assert_not_contains "$_tf_clean_found" "$_safe_id" \
    "$_safe_id does NOT fire on its tests/fixtures/clean/*.tf fixture - fails if the safe rewrite still matches the pattern (a true-negative fixture that isn't actually negative)"
done

t_case 'every finding the iac module emits carries module=iac, not module=sast'
_tf_vuln_modules=$(_modules_found "$W/run-tf-vuln")
assert_not_contains "$_tf_vuln_modules" 'sast' \
  'no finding from this run reports module=sast - fails if iac_scan_tree fell through to sast_scan_file/_sast_emit_finding instead of its own emission path'
assert_contains "$_tf_vuln_modules" 'iac' \
  'at least one finding reports module=iac - sanity check that the assertion above is not vacuously true on an empty run'

unset TF_IDS _tf_vuln_found _tf_clean_found _want_id _safe_id _tf_vuln_modules

# =============================================================================
printf -- '\n-- check selection integration: scan_dispatch iac is no longer a no-op --\n'
# =============================================================================
t_case 'scan.sh iac tests/fixtures/vuln records every IAC-TF-* id as actually run'
rm -rf "$W/run-checks"
bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --out "$W/run-checks" >/dev/null 2>&1
_checks_run=$(cat "$W/run-checks/meta/checks_run" 2>/dev/null || true)
for _id in IAC-TF-OPEN_CIDR-01 IAC-TF-PUBLIC_ACL-01 IAC-TF-UNENCRYPTED-01 \
  IAC-TF-KEY_ROTATION_DISABLED-01 IAC-TF-PUBLIC_IP-01 IAC-TF-HARDCODED_SECRET-01 \
  IAC-TF-RDS_PUBLIC-01; do
  t_case "scan.sh iac: $_id is recorded in checks_run - fails if scan_dispatch iac still took the 'no run.sh yet' no-op path"
  assert_contains "$_checks_run" "$_id" "$_id present in $W/run-checks/meta/checks_run"
done
unset _checks_run _id

# =============================================================================
printf -- '\n-- exit-code flip (mirrors sast.sh''s own last section) --\n'
# =============================================================================
t_case 'scan.sh iac tests/fixtures/vuln --fail-on high --fail-on-new now exits non-zero'
assert_status "$SCOURSH_EXIT_GATE" \
  'a real subprocess against the vuln fixture, gated on high+, exits the GATE code - fails if scan_dispatch iac were still a no-op (every gate would stay 0)' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --fail-on high --fail-on-new --out "$W/run-gate"

t_case 'the SAME command against the clean fixture still exits 0 - the gate is not a blanket failure'
assert_status 0 \
  'no findings at/above high on the clean fixture, so the gate does not trip' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/clean" --fail-on high --fail-on-new --out "$W/run-gate-clean"

t_case 'without --fail-on, the vuln fixture still exits 0 - the gate is opt-in, never ambient'
assert_status 0 \
  'no --fail-on given means not-evaluated, never a silent gate - fails if the gate fired without being asked' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --out "$W/run-no-gate"

t_summary 'iac' || FAILED=1
exit "${FAILED:-0}"
