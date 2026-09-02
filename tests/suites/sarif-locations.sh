#!/usr/bin/env bash
# tests/suites/sarif-locations.sh - lib/report.sh's report_locations
# (docs/STEP10-SARIF-PLAN.md SARIF-02, docs/FOUNDATION.md tension 22's chosen
# option 3, the physical half).
#
# Covers this ticket's acceptance criteria:
#   - reports/<run>/locations/<module>.txt is written, one line per finding
#     whose profile carries no usable real file, keyed on the finding's own
#     logical_fqn (SARIF-01)
#   - the four-case location table: case 1 (a real working-tree file) and
#     case 2 (sca, whose own `path` field already names a real file) are left
#     alone; case 3 (SAST-HIST-*) is a filesystem test at write time - a
#     resolving loc_path is left alone, a non-resolving one falls back to the
#     artifact, carrying loc_blob_sha and commit so a reader can `git show`
#     it; case 4 (dast, cloud, posture, derived) always writes
#   - the assigned line number is recorded BACK onto the finding's own
#     loc_line, in place, so a later SARIF-04 needs no case-specific logic
#   - written unconditionally: a report_all run with SCOURSH_FORMATS=md (no
#     sarif) still gets the artifact
#   - deterministic: two runs over the same fixture produce byte-identical
#     location files
#   - the physical artifact is a real file that exists at the path a SARIF
#     would cite (tension 22's own validation requirement)
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose mentions `git show` and a shell path literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sarif-locations-suite
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Reads one field off the finding with the given check_id in rundir's merged
# findings.fields.  Empty if no such finding, or the field is unset.
_field_of() {                      # rundir check_id field
  local rundir=$1 check_id=$2 field=$3 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]:-} == "$check_id" ]] || continue
    printf '%s' "${_DF[$field]:-}"
    return 0
  done <"$rundir/findings.fields"
}

_new_rundir() {                    # name -> sets D, resets it
  D=$W/$1
  rm -rf "$D"
  run_init "$D"
  D=$SCOURSH_RUN_DIR
}

# ---------------------------------------------------------------------------
printf '\n-- case 4: dast, cloud, posture, derived always get the artifact --\n'
# ---------------------------------------------------------------------------
_new_rundir case4
occurrence_reset_all

finding_new
finding_set check_id DAST-XSS-REFLECT-01
finding_set module dast
finding_set title 'Unescaped reflection'
finding_set base_severity high
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /users/9/p
finding_set loc_param_location query
finding_set loc_param_name q
finding_emit

finding_new
finding_set check_id CLOUD-S3-PUBLIC-01
finding_set module cloud
finding_set title 'Public bucket'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set loc_account_id '111111111111'
finding_set loc_region us-east-1
finding_set loc_resource_key 'arn:aws:s3:::example-bucket'
finding_emit

finding_new
finding_set check_id POSTURE-MFA-MISSING-01
finding_set module posture
finding_set title 'MFA not enforced'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_control_id CIS-1.2
finding_set loc_scope_key '111111111111'
finding_emit

finding_new
finding_set check_id COMPOSITE-TOKEN-HIJACK
finding_set module derived
finding_set title 'Token hijack chain'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set logical_kind composite
finding_set logical_fqn 'COMPOSITE-TOKEN-HIJACK@corr1'
finding_set loc_correlation corr1
finding_emit

findings_merge "$D"
report_locations "$D"

t_case 'each module gets its own real artifact file'
for m in dast cloud posture derived; do
  assert_file_exists "$D/locations/$m.txt" "locations/$m.txt exists"
done

t_case 'the artifact line is the finding logical identity, and the finding is told which line'
FQN=$(_field_of "$D" DAST-XSS-REFLECT-01 logical_fqn)
LN=$(_field_of "$D" DAST-XSS-REFLECT-01 loc_line)
assert_eq '1' "$LN" 'dast finding is line 1 of locations/dast.txt (only dast finding written)'
assert_eq "$FQN" "$(sed -n "${LN}p" "$D/locations/dast.txt")" \
  'that line IS the finding own logical_fqn'

FQN=$(_field_of "$D" CLOUD-S3-PUBLIC-01 logical_fqn)
assert_eq 'arn:aws:s3:::example-bucket' "$FQN" 'cloud logical_fqn is the ARN (SARIF-01)'
LN=$(_field_of "$D" CLOUD-S3-PUBLIC-01 loc_line)
assert_eq "$FQN" "$(sed -n "${LN}p" "$D/locations/cloud.txt")" \
  'cloud finding loc_line points at its own line in locations/cloud.txt'

FQN=$(_field_of "$D" POSTURE-MFA-MISSING-01 logical_fqn)
assert_eq 'CIS-1.2' "$FQN" 'posture logical_fqn is the control id (SARIF-01)'
LN=$(_field_of "$D" POSTURE-MFA-MISSING-01 loc_line)
assert_eq "$FQN" "$(sed -n "${LN}p" "$D/locations/posture.txt")" \
  'posture finding loc_line points at its own line in locations/posture.txt'

LN=$(_field_of "$D" COMPOSITE-TOKEN-HIJACK loc_line)
assert_eq 'COMPOSITE-TOKEN-HIJACK@corr1' "$(sed -n "${LN}p" "$D/locations/derived.txt")" \
  'derived finding loc_line points at its own line in locations/derived.txt'

# ---------------------------------------------------------------------------
printf '\n-- case 1 and case 2: real files are left alone --\n'
# ---------------------------------------------------------------------------
_new_rundir case1and2
occurrence_reset_all

finding_new
finding_set check_id SAST-SEC-K-01
finding_set module sast
finding_set title 'Hardcoded key'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path app.py
finding_set loc_line 3
finding_set_match 'k'
finding_emit

finding_new
finding_set check_id IAC-TF-OPEN_CIDR-01
finding_set module iac
finding_set title 'Open CIDR'
finding_set base_severity high
finding_set cwe CWE-284
finding_set owasp A01:2021
finding_set loc_path main.tf
finding_set loc_line 12
finding_set_match '0.0.0.0/0'
finding_emit

finding_new
finding_set check_id SCA-NPM-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'Vulnerable dependency'
finding_set base_severity high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package left-pad
finding_set loc_advisory_id GHSA-TEST-0001
finding_set path package-lock.json
finding_set logical_kind dependency
finding_set logical_fqn 'npm:left-pad@1.0.0'
finding_emit

findings_merge "$D"
report_locations "$D"

t_case 'case 1 (sast/iac): no artifact, loc_line untouched'
assert_file_absent "$D/locations/sast.txt" 'no locations/sast.txt - the sast finding here is case 1, not case 3/4'
assert_file_absent "$D/locations/iac.txt" 'no locations/iac.txt at all - case 1 never gets one'
assert_eq '3' "$(_field_of "$D" SAST-SEC-K-01 loc_line)" 'sast loc_line is still the real file line'
assert_eq '12' "$(_field_of "$D" IAC-TF-OPEN_CIDR-01 loc_line)" 'iac loc_line is still the real file line'

t_case 'case 2 (sca): no artifact, path field and loc_line untouched'
assert_file_absent "$D/locations/sca.txt" 'no locations/sca.txt - sca already has a real file in `path`'
assert_eq '' "$(_field_of "$D" SCA-NPM-VULNERABLE_DEP-01 loc_line)" 'sca finding gets no loc_line at all'
assert_eq 'package-lock.json' "$(_field_of "$D" SCA-NPM-VULNERABLE_DEP-01 path)" \
  'sca finding keeps its own path field, untouched by the writer'

# ---------------------------------------------------------------------------
printf '\n-- case 3: SAST-HIST-*, a real filesystem test --\n'
# ---------------------------------------------------------------------------
REPO=$W/history-repo
rm -rf "$REPO"
mkdir -p "$REPO"
git -C "$REPO" init -q
git -C "$REPO" config user.email 'test@example.com'
git -C "$REPO" config user.name 'test'

printf 'password = "x"\n' >"$REPO/secret_gone.txt"
git -C "$REPO" add secret_gone.txt
git -C "$REPO" commit -q -m 'add secret_gone'
BLOB_GONE=$(git -C "$REPO" rev-parse HEAD:secret_gone.txt)
COMMIT_GONE=$(git -C "$REPO" rev-parse HEAD)
git -C "$REPO" rm -q secret_gone.txt
git -C "$REPO" commit -q -m 'remove secret_gone'

printf 'password = "y"\n' >"$REPO/secret_here.txt"
git -C "$REPO" add secret_here.txt
git -C "$REPO" commit -q -m 'add secret_here'
BLOB_HERE=$(git -C "$REPO" rev-parse HEAD:secret_here.txt)
COMMIT_HERE=$(git -C "$REPO" rev-parse HEAD)

_new_rundir case3
occurrence_reset_all
SCOURSH_SCAN_ROOT_PATH=$(scan_root_of "$REPO")
export SCOURSH_SCAN_ROOT_PATH

finding_new
finding_set check_id SAST-HIST-SECRET-01
finding_set module sast
finding_set title 'Hardcoded secret (history)'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_gone.txt
finding_set loc_line 7
finding_set loc_blob_sha "$BLOB_GONE"
finding_set commit "$COMMIT_GONE"
finding_set_match 'password = "x"'
finding_emit

finding_new
finding_set check_id SAST-HIST-SECRET-01
finding_set module sast
finding_set title 'Hardcoded secret (history)'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_here.txt
finding_set loc_line 42
finding_set loc_blob_sha "$BLOB_HERE"
finding_set commit "$COMMIT_HERE"
finding_set_match 'password = "y"'
finding_emit

findings_merge "$D"
report_locations "$D"

t_case 'a loc_path that no longer resolves in the working tree falls back to the artifact'
assert_file_exists "$D/locations/sast.txt" 'the fallback created locations/sast.txt'
LN=$(_field_of "$D" SAST-HIST-SECRET-01 loc_line)
# Both history findings share one check_id, so re-derive by matching on the
# recorded commit rather than the (now ambiguous) check_id alone.
_hist_field() {                    # commit field
  local commit=$1 field=$2 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[commit]:-} == "$commit" ]] || continue
    printf '%s' "${_DF[$field]:-}"
    return 0
  done <"$D/findings.fields"
}
GONE_LINE=$(_hist_field "$COMMIT_GONE" loc_line)
assert_ne '7' "$GONE_LINE" 'the non-resolving finding loc_line was overwritten - the fallback fired'
FALLBACK_TEXT=$(sed -n "${GONE_LINE}p" "$D/locations/sast.txt")
assert_contains "$FALLBACK_TEXT" 'secret_gone.txt:7' \
  'the fallback line still carries the logical identity (SARIF-01 fqn)'
assert_contains "$FALLBACK_TEXT" "$BLOB_GONE" 'the fallback line carries loc_blob_sha, so a reader can `git show` it'
assert_contains "$FALLBACK_TEXT" "$COMMIT_GONE" 'the fallback line carries commit too'

t_case 'a loc_path that still resolves in the working tree is left alone - case 3 is not case 4'
HERE_LINE=$(_hist_field "$COMMIT_HERE" loc_line)
assert_eq '42' "$HERE_LINE" 'the resolving finding loc_line is untouched'
assert_not_contains "$(cat "$D/locations/sast.txt")" 'secret_here.txt' \
  'the resolving finding never reaches the generated artifact at all'

# ---------------------------------------------------------------------------
printf '\n-- written unconditionally: no --format sarif in play --\n'
# ---------------------------------------------------------------------------
_new_rundir noformat
occurrence_reset_all
finding_new
finding_set check_id DAST-XSS-REFLECT-01
finding_set module dast
finding_set title 'Unescaped reflection'
finding_set base_severity high
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /users/9/p
finding_set loc_param_location query
finding_set loc_param_name q
finding_emit
findings_merge "$D"
SCOURSH_FORMATS=md
export SCOURSH_FORMATS
report_all "$D"
unset SCOURSH_FORMATS

t_case 'report_all with --format md (no sarif) still writes the location artifact'
assert_file_exists "$D/locations/dast.txt" 'locations/dast.txt exists even though sarif was never selected'
assert_eq '1' "$(_field_of "$D" DAST-XSS-REFLECT-01 loc_line)" \
  'and the finding was told its line, exactly as it would be under --format sarif'

# ---------------------------------------------------------------------------
printf '\n-- determinism: two runs over the same fixture, byte-identical output --\n'
# ---------------------------------------------------------------------------
_build_det_fixture() {             # rundir
  _new_rundir "$1"
  occurrence_reset_all
  finding_new
  finding_set check_id DAST-XSS-REFLECT-01
  finding_set module dast
  finding_set title 'Unescaped reflection'
  finding_set base_severity high
  finding_set cwe CWE-79
  finding_set owasp A03:2021
  finding_set loc_target t1
  finding_set loc_method GET
  finding_set path /users/9/p
  finding_set loc_param_location query
  finding_set loc_param_name q
  finding_emit

  finding_new
  finding_set check_id DAST-XSS-REFLECT-01
  finding_set module dast
  finding_set title 'Unescaped reflection'
  finding_set base_severity high
  finding_set cwe CWE-79
  finding_set owasp A03:2021
  # A different --target, not just a different path, so the fingerprint
  # (target/method/path_template/param_location/param_name) genuinely
  # differs: path_template_of collapses BOTH /users/9/p and /users/8/p to
  # /{id}/p, so varying only the numeric segment would silently dedup the
  # two findings into one.
  finding_set loc_target t2
  finding_set loc_method GET
  finding_set path /users/8/p
  finding_set loc_param_location query
  finding_set loc_param_name q
  finding_emit

  finding_new
  finding_set check_id CLOUD-S3-PUBLIC-01
  finding_set module cloud
  finding_set title 'Public bucket'
  finding_set base_severity critical
  finding_set cwe none
  finding_set owasp none
  finding_set loc_account_id '111111111111'
  finding_set loc_region us-east-1
  finding_set loc_resource_key 'arn:aws:s3:::example-bucket'
  finding_emit

  findings_merge "$D"
  report_locations "$D"
}

_build_det_fixture det1
D1=$D
_build_det_fixture det2
D2=$D

t_case 'two independent runs over an identical fixture produce byte-identical location files'
assert_eq '2' "$(wc -l <"$D1/locations/dast.txt" | tr -d ' ')" 'sanity: two dast findings landed in run 1'
if diff -q "$D1/locations/dast.txt" "$D2/locations/dast.txt" >/dev/null 2>&1; then
  _t_ok 'locations/dast.txt is byte-identical across two runs'
else
  _t_no 'locations/dast.txt is byte-identical across two runs' "diff: $(diff "$D1/locations/dast.txt" "$D2/locations/dast.txt" || true)"
fi
if diff -q "$D1/locations/cloud.txt" "$D2/locations/cloud.txt" >/dev/null 2>&1; then
  _t_ok 'locations/cloud.txt is byte-identical across two runs'
else
  _t_no 'locations/cloud.txt is byte-identical across two runs' "diff: $(diff "$D1/locations/cloud.txt" "$D2/locations/cloud.txt" || true)"
fi

# ---------------------------------------------------------------------------
printf '\n-- report_all runs more than once per run directory (scan.sh all dispatches sast, then sca, then iac, then dast, EACH calling report_all over the same growing findings.fields) --\n'
# ---------------------------------------------------------------------------
_new_rundir multimodule
occurrence_reset_all

# Pass 1: what modules/sast/run.sh's own report_all call would see, right
# after SAST is dispatched.
finding_new
finding_set check_id DAST-XSS-REFLECT-01
finding_set module dast
finding_set title 'Unescaped reflection'
finding_set base_severity high
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /users/9/p
finding_set loc_param_location query
finding_set loc_param_name q
finding_emit
findings_merge "$D"
report_locations "$D"

# Pass 2: modules/sca/run.sh's own report_all call, later in the SAME
# scan.sh all invocation - findings_merge rebuilds findings.fields from
# EVERY shard emitted so far, so this pass sees the pass-1 finding again
# PLUS a new one.
finding_new
finding_set check_id CLOUD-S3-PUBLIC-01
finding_set module cloud
finding_set title 'Public bucket'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set loc_account_id '111111111111'
finding_set loc_region us-east-1
finding_set loc_resource_key 'arn:aws:s3:::example-bucket'
finding_emit
findings_merge "$D"
report_locations "$D"

t_case 'a second report_locations call over the SAME growing findings.fields does not duplicate the first pass finding'
DAST_LINES=$(grep -c . "$D/locations/dast.txt" 2>/dev/null || printf 0)
assert_eq '1' "$DAST_LINES" \
  'locations/dast.txt has exactly one line, not two - FAILS under a writer that only ever appends across calls'
assert_eq '1' "$(_field_of "$D" DAST-XSS-REFLECT-01 loc_line)" \
  'the pass-1 finding loc_line still points at its real (only) line after a second pass ran'

t_case 'the second-pass finding lands correctly too'
assert_eq '1' "$(_field_of "$D" CLOUD-S3-PUBLIC-01 loc_line)" \
  'cloud finding is line 1 of its own freshly-regenerated locations/cloud.txt'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID='' SCOURSH_SCAN_ROOT_PATH=''

t_summary sarif-locations
