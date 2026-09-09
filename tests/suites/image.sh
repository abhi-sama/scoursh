#!/usr/bin/env bash
# tests/suites/image.sh - modules/image/: the `scan_dispatch image` entry
# point and the module-registration surface IMG-01 lands (IMG-01,
# data/scoursh-image-scan-design/report.md §3.2/§5.3).
#
# IMG-01 is the module-FOUNDATION ticket only: it registers `IMAGE` across
# every frozen table and shared list so IMG-02 onward add only their own
# files. There is no acquisition, no distro enumerator, and no comparator to
# test - what this suite pins instead is that:
#
#   1. `--image` is genuinely required (exit 2, not a crash) and the module
#      re-asserts that itself, not only through scan.sh - the same
#      "a gate only the caller applies is not a gate" shape
#      modules/dast/run.sh and modules/network/run.sh already establish for
#      their own required flags.
#   2. A run with no acquisition/enumerator/comparator on disk sends nothing
#      claims nothing, and says so honestly on run.json - the surface a
#      consumer actually reads, never only an internal record.
#   3. The `image-id` coverage cell (rules/RULE-FORMAT.md §9.5.1) is
#      recorded under the operator's own `--image` value, not the volatile
#      digest or tag report.md §3.4 explicitly excludes.
#   4. A synthetic `module: image` finding - proving the frozen-format
#      additions (lib/records.sh, lib/findings.sh, lib/report.sh) actually
#      work together - round-trips through findings.jsonl/findings.json,
#      report.md, report.html, report.sarif, report-audit.html and
#      report_agent's agent-fix.json.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/image
rm -rf "$W"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# `_image_scan RUNDIR [ARGS...]` - one real `scan.sh image` subprocess, the
# way an operator hits it. `image` needs no config/scope.conf and no live
# target, so the real repository is a safe install root - no fixture copy
# needed the way tests/suites/network.sh's own config/scope.conf-dependent
# cases require.
_image_scan() {
  local rundir=$1
  shift
  _LOG=$rundir.log
  _RC=0
  SCOURSH_INSTALL_ROOT=$ROOT bash "$ROOT/scan.sh" image --out "$rundir" "$@" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

# =============================================================================
printf -- '\n-- --image is genuinely required --\n'
# =============================================================================

t_case "'image' with no --image at all is a usage error (exit 2), not a crash"
_image_scan "$W/run-noimage"
assert_eq 2 "$_RC" \
  "'image' requires --image - FAILS if the required-flag map (scan.sh _SCAN_REQUIRED_FLAG) omits image and the run instead falls through to modules/image/run.sh with an empty id"

t_case 'the module re-asserts the requirement itself, not only through scan.sh'
_MOD_RC=0
(
  SCOURSH_INSTALL_ROOT=$ROOT
  export SCOURSH_INSTALL_ROOT
  declare -A SCAN_FLAGS=()
  export SCOURSH_RUN_DIR=$W/run-modgate
  mkdir -p "$SCOURSH_RUN_DIR"/{shards,units,meta,inventory,locations}
  source "$ROOT/modules/image/run.sh"
) >/dev/null 2>&1 || _MOD_RC=$?
assert_eq "$SCOURSH_EXIT_USAGE" "$_MOD_RC" \
  'sourcing modules/image/run.sh directly with no --image still dies exit 2 - FAILS under "scan.sh already required --image, so the module may trust its caller"'

# =============================================================================
printf '\n-- a run with no acquisition/enumerator/comparator sends nothing and says so --\n'
# =============================================================================

t_case 'an --image run completes cleanly and exits 0'
_image_scan "$W/run-ok" --image myapp --source /tmp/myapp.tar
assert_eq 0 "$_RC" \
  'scan.sh image --image myapp exits 0 - FAILS under "a module with no checks is an incomplete run (exit 5)" and under "a module with no run.sh is the only clean image path"'
assert_file_exists "$W/run-ok/run.json" 'the run wrote run.json'
RUN_OK_JSON=$(_slurp "$W/run-ok/run.json")

t_case 'nothing is claimed as executed'
assert_contains "$RUN_OK_JSON" '"checks_run": []' \
  'checks_run is empty - FAILS under "record the work we would have done", the overclaim this ticket exists to avoid'

t_case 'run.json records why nothing was examined, naming the image'
assert_contains "$RUN_OK_JSON" 'module=image reason=no_check_registry_on_disk_yet' \
  'the profile-filter reduction fires first - FAILS if modules/image/ shipped a checks-*.rules registry already, which this ticket explicitly does not'
assert_contains "$RUN_OK_JSON" "module=image reason=no_distro_enumerator_on_disk_yet image=myapp" \
  "the module's own reduction names the image id - FAILS if a copy-paste from modules/network/run.sh left the literal string \"module=network\" behind"
assert_contains "$RUN_OK_JSON" "image scanning examined nothing for image 'myapp'" \
  'the coverage_gap is a sentence a human reads, naming the image - FAILS if the gap is generic and a reader with two images in one run.json cannot tell which one it is about'
assert_contains "$RUN_OK_JSON" 'absence of a test, not the absence of a problem' \
  'and states the docs/DESIGN.md §15 warning in the artifact itself, not only in prose a reader has to already know'

t_case 'the image id and cell are recorded, and the coverage-scope is image-id'
NOTES_FILE=$(_slurp "$W/run-ok/meta/notes")
assert_contains "$NOTES_FILE" 'module=image image=myapp source=/tmp/myapp.tar coverage-scope=image-id cell=myapp' \
  "the notes line records image's own coverage-scope (rules/RULE-FORMAT.md §9.5.1: image-id) - FAILS if the cell were the volatile --source path or a digest rather than the operator's own stable --image id"

t_case 'the coverage_reduction and coverage_gap are each written exactly once'
CR_FILE=$(_slurp "$W/run-ok/meta/coverage_reduction")
assert_eq 1 "$(grep -c 'reason=no_distro_enumerator_on_disk_yet' <<<"$CR_FILE")" \
  'exactly one no_distro_enumerator_on_disk_yet reduction - FAILS if the run loop double-counts'
GAP_FILE=$(_slurp "$W/run-ok/meta/coverage_gap")
assert_eq 1 "$(grep -c "image 'myapp'" <<<"$GAP_FILE")" \
  'exactly one coverage_gap names this image'

t_case 'a run with no traffic tool on PATH still completes (image issues no network call at all)'
STUB=$W/stub-bin
mkdir -p "$STUB"
for c in curl wget nc ncat netcat openssl aws; do
  cat >"$STUB/$c" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "$c" "\$*" >>"$W/image-attempts"
exit 1
EOF
  chmod 0755 "$STUB/$c"
done
rm -f "$W/image-attempts"
_IMG2_RC=0
SCOURSH_INSTALL_ROOT=$ROOT PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" image --image myapp --out "$W/run-notraffic" \
  >"$W/run-notraffic.log" 2>&1 || _IMG2_RC=$?
assert_eq 0 "$_IMG2_RC" 'the run still exits 0 with a poisoned PATH - it never reaches for a transport'
assert_file_absent "$W/image-attempts" \
  'no curl/wget/nc/openssl/aws was invoked - image scanning is offline, per docs/DESIGN.md §1'

# =============================================================================
printf '\n-- scan.sh surface: SCAN_COMMANDS, --help, and the module-built probe --\n'
# =============================================================================

t_case "'image' is a real scan.sh subcommand"
HELP=$(SCOURSH_INSTALL_ROOT=$ROOT bash "$ROOT/scan.sh" --help 2>&1 || true)
assert_contains "$HELP" 'image' 'the top-level --help lists image - FAILS if SCAN_COMMANDS omits it'

t_case "'scan.sh image --help' states the required flag and the current build status"
IMG_HELP=$(SCOURSH_INSTALL_ROOT=$ROOT bash "$ROOT/scan.sh" image --help 2>&1 || true)
assert_contains "$IMG_HELP" 'Required: --image' \
  'the per-subcommand help states --image is required, from the same _SCAN_REQUIRED_FLAG map scan_main enforces'
assert_contains "$IMG_HELP" 'partially built' \
  'the status line reflects that modules/image/run.sh now exists on disk - FAILS if _scan_module_script has no generic fallback for a module scan.sh does not special-case'

t_case 'an unknown flag for image is still refused (exit 2), same as every other command'
_UNK_RC=0
SCOURSH_INSTALL_ROOT=$ROOT bash "$ROOT/scan.sh" image --image myapp --bogus-flag \
  >/dev/null 2>&1 || _UNK_RC=$?
assert_eq 2 "$_UNK_RC" 'an unrecognised flag dies with a usage error'

# =============================================================================
printf '\n-- a synthetic module: image finding round-trips through every format --\n'
# =============================================================================

export SCOURSH_INSTALL_ROOT=$ROOT
D=$W/finding-run
rm -rf "$D"
run_init "$D"
D=$SCOURSH_RUN_DIR
occurrence_reset_all

finding_new
finding_set check_id IMAGE-PKG-VULNERABLE_OS_PACKAGE-01
finding_set module image
finding_set title 'Installed apk package matches a known advisory'
finding_set base_severity high
finding_set cwe CWE-1104
finding_set owasp A06:2021
finding_set confidence high
finding_set cell myapp
finding_set loc_image_id myapp
finding_set loc_ecosystem 'Alpine:v3.18'
finding_set loc_package openssl
finding_set loc_advisory_id CVE-2099-00001
finding_set logical_fqn 'image myapp: Alpine:v3.18/openssl'
finding_set_evidence 'openssl 3.1.4-r1 (fixed: 3.1.4-r2)'
finding_set remediation 'Rebuild the image with an updated base layer.'
finding_emit

findings_merge "$D"
FIELDS=$(_slurp "$D/findings.fields")

t_case 'the finding fingerprints without dying - the image location profile exists'
assert_contains "$FIELDS" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'findings.fields carries the finding - FAILS if lib/findings.sh has no image case in _fp_profile_for, which dies finding_fingerprint at finding_emit time instead of producing this line at all'
assert_contains "$FIELDS" 'module=image' 'and records module=image'

export SCOURSH_FORMATS=json,sarif,html,md,audit
report_all "$D"
report_agent "$D"

t_case 'findings.jsonl and findings.json (both machine-generated records) carry the finding'
assert_contains "$(_slurp "$D/findings.jsonl")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'findings.jsonl - written by report_all, not by findings_merge - carries it'
assert_contains "$(_slurp "$D/findings.jsonl")" '"module":"image"' 'and records module:image'
assert_contains "$(_slurp "$D/findings.json")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'findings.json also carries it'

t_case 'report.md carries the finding'
assert_contains "$(_slurp "$D/report.md")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'the markdown report lists it - report_md/_md_findings is module-agnostic, so this is a fingerprint/emit-path check rather than a report_md-specific one'

t_case 'report.html carries the finding'
assert_contains "$(_slurp "$D/report.html")" 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01' \
  'the html report lists it, even with no [image] entry in _RPT_CAT_LABEL/_RPT_CAT_ORDER (report.html groups an unrecognised module value under its own "never drop it" fallback path, per lib/report.sh section 2136-2168s own header - a category LABEL for image is added only once a real finding ships, mirroring NET-09s own [net] addition)'

t_case 'report.sarif carries the finding at a generated-artifact location, not an empty URI'
SARIF=$(_slurp "$D/report.sarif")
assert_contains "$SARIF" '"ruleId":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-01"' \
  'the SARIF result names the check id as its ruleId'
assert_contains "$SARIF" 'locations/image.txt' \
  'the artifactLocation points at report_locations own generated artifact - FAILS if _sarif_result_location has no image arm, which falls through to the loc_path/loc_line default and would emit an empty URI, since an image finding carries no source file'
assert_file_exists "$D/locations/image.txt" 'report_locations wrote the generated artifact for the image category'

t_case 'report-audit.html renders the image category under its own real label'
AUDIT=$(_slurp "$D/report-audit.html")
assert_contains "$AUDIT" '>Image<' \
  'the [image] category renders under its real label - FAILS if lib/report.sh _RPTC_CAT_LABEL has no [image] entry, which _html_audit_nav/_html_audit_category read with no fallback (empty <a> text / an empty <h2>)'
assert_contains "$AUDIT" 'Built container image scanning' \
  'and its own description - FAILS if _RPTC_CAT_DESCR has no [image] entry'

t_case 'agent-fix.json (report_agent, --format agent) carries the finding'
AGENT_JSON=$(_slurp "$D/agent-fix.json")
assert_contains "$AGENT_JSON" '"check":"IMAGE-PKG-VULNERABLE_OS_PACKAGE-01"' \
  'the agent format names the check'
assert_contains "$AGENT_JSON" '"mod":"image"' \
  'and its module - FAILS if _agent_module_of_check has no IMAGE-* arm, which is a silent classification gap rather than a crash'

t_case 'no existing record shape changed: a plain SAST finding still round-trips unaffected'
D2=$W/sast-control
rm -rf "$D2"
run_init "$D2"
D2=$SCOURSH_RUN_DIR
occurrence_reset_all
finding_new
finding_set check_id SAST-SEC-K-01
finding_set module sast
finding_set title 'Hardcoded key'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set confidence high
finding_set loc_path app.py
finding_set loc_line 3
finding_set cell .
finding_set_match 'k'
finding_set_evidence 'k = "x"'
finding_set remediation 'Rotate it.'
finding_emit
findings_merge "$D2"
assert_contains "$(_slurp "$D2/findings.fields")" 'SAST-SEC-K-01' \
  'the additive IMAGE enum entry left an unrelated SAST finding parsing and fingerprinting exactly as before'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
unset SCOURSH_FORMATS

t_summary 'image'
