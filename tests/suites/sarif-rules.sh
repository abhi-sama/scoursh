#!/usr/bin/env bash
# tests/suites/sarif-rules.sh - lib/report.sh's report_sarif
# (docs/STEP10-SARIF-PLAN.md SARIF-03: the SARIF 2.1.0 skeleton - document,
# tool.driver, rules[], artifacts[], invocations[], with an empty results[]).
#
# Covers this ticket's acceptance criteria:
#   - report_all writes reports/<run>/report.sarif when `sarif` is a selected
#     format (the default), and skips it when it is not
#   - runs[0].tool.driver carries name/version/informationUri and rules[]
#   - rules[] is the FULL loaded check registry, keyed by check_id
#     (tension 22, verbatim) - every id checks_registry_load finds on disk,
#     whether or not a finding fired for it this run
#   - the three ungoverned id families (SCA, adapter, derived/composite) get
#     a SYNTHESISED descriptor built from a finding of that check_id, marked
#     properties.descriptorSource: "synthesised" - one case per family
#   - a registry-backed descriptor carries the check's own remediation,
#     references, cwe, owasp, cis and rule_digest, and is NEVER marked
#     descriptorSource - proven against a finding that DISAGREES with the
#     registry record, so the registry's own fields winning is observable
#   - artifacts[] lists the SARIF-02 generated location artifacts this run
#     actually wrote, and nothing else
#   - invocations[] carries startTimeUtc/endTimeUtc/executionSuccessful/
#     exitCode, and the latter two track a real incomplete-run signal
#   - results stays [] - SARIF-04's own territory
#   - the document is deterministic: two runs over the same fixture produce
#     byte-identical report.sarif
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.  report_sarif does not exist before this ticket,
# so every assertion below failed with "command not found" before the
# implementation existed - the coarse form of "observed failing, then
# passing" - and the finer-grained cases each say what wrong reading they
# additionally rule out.
#
# shellcheck shell=bash
#
# SC2016: assertion prose mentions JSON/shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sarif-rules-suite
rm -rf "$W"
mkdir -p "$W"

# The fixture registry tests/suites/checks.sh already uses: one sast pattern
# pack (2 checks) and one dast script-check registry (5 checks), 7 checks
# total, no sca/iac/cloud directory at all - which is exactly the shape a
# real checkout has for sca (modules/sca/ ships no *.rules by design), so it
# doubles as the "no registry record" fixture for that family with no need
# for a second fixture tree.
FIXTURE_ROOT=$ROOT/tests/fixtures/checks-registry

_new_rundir() {                    # name -> sets D, resets it
  D=$W/$1
  rm -rf "$D"
  run_init "$D"
  D=$SCOURSH_RUN_DIR
}

# Reads a top-level string field out of report.sarif via python3 when
# available; prints nothing and lets the caller degrade gracefully otherwise
# (mirrors tests/suites/report.sh's own python3-optional pattern).
_py() {                            # rundir python-expr
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -c "
import json
d = json.load(open('$1/report.sarif'))
print($2)
"
}

# ===========================================================================
printf '\n-- document shape and the mandatory-per-run wiring --\n'
# ===========================================================================
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT
_new_rundir shape
report_all "$D"

t_case 'report_all writes report.sarif when sarif is a selected format (the default)'
assert_file_exists "$D/report.sarif" 'report.sarif exists after a report_all call with SCOURSH_FORMATS unset'

RAW=$(cat "$D/report.sarif")
assert_contains "$RAW" '"version": "2.1.0"' 'the document declares SARIF 2.1.0'
assert_contains "$RAW" '"$schema"' 'a $schema key is present'
assert_contains "$RAW" '"name": "scoursh"' 'tool.driver.name is scoursh'
assert_contains "$RAW" '"informationUri": "https://github.com/abhi-sama/scoursh"' \
  'tool.driver.informationUri names this project'
assert_contains "$RAW" '"results": []' \
  'results stays empty - SARIF-03 ships the skeleton only, FAILS under an implementation that already maps findings into results (SARIF-04 scope creep)'

if command -v python3 >/dev/null 2>&1; then
  t_case 'the document is well-formed JSON'
  if python3 -c "import json,sys; json.load(open('$D/report.sarif'))" 2>/dev/null; then
    _t_ok 'report.sarif parses as JSON'
  else
    _t_no 'report.sarif parses as JSON' 'json.load raised'
  fi
else
  _t_ok 'python3 unavailable, JSON parse check skipped'
fi

t_case 'report_all skips report.sarif when sarif is not a selected format'
_new_rundir noformat
SCOURSH_FORMATS=md report_all "$D"
assert_file_absent "$D/report.sarif" \
  'no report.sarif when --format md alone was asked for - FAILS under an emitter that ignores SCOURSH_FORMATS and always writes'

unset SCOURSH_INSTALL_ROOT

# ===========================================================================
printf '\n-- rules[] is the FULL loaded check registry, not just what fired --\n'
# ===========================================================================
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT
_new_rundir full-registry
report_all "$D"

t_case 'a run with ZERO findings still lists every on-disk check as a rule - tension 22, "the full loaded check registry"'
N_RULES=$(_py "$D" "len(d['runs'][0]['tool']['driver']['rules'])")
assert_eq '7' "$N_RULES" \
  '7 = 2 sast + 5 dast fixture checks, none of which fired a finding this run - FAILS under an implementation that only emits rules for checks a finding actually referenced'

for cid in SAST-GEN-DEMO_QUICK-01 SAST-GEN-DEMO_FULL-01 DAST-HDR-CSP-01 DAST-HDR-HSTS-01 \
  DAST-AUTHZ-OBJREF-01 DAST-INJ-SQLI-01 DAST-DISC-CRAWL-01; do
  HAS=$(_py "$D" "'$cid' in {r['id'] for r in d['runs'][0]['tool']['driver']['rules']}")
  assert_eq 'True' "$HAS" "$cid is present in rules[]"
done

unset SCOURSH_INSTALL_ROOT

# ===========================================================================
printf '\n-- a registry-backed descriptor carries the CHECK RECORD, not the finding --\n'
# ===========================================================================
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT
_new_rundir registry-wins

# This finding deliberately DISAGREES with the fixture record on every field
# a registry-backed descriptor is supposed to source from the record: a
# different title, remediation, and base_severity that maps to a DIFFERENT
# SARIF level (info->note, where the record's own severity is high->error).
# If the descriptor is (wrongly) built from the finding instead of the
# record, every assertion below FAILS under that reading.
finding_new
finding_set check_id SAST-GEN-DEMO_QUICK-01
finding_set module sast
finding_set title 'WRONG - this must not appear in the descriptor'
finding_set base_severity info
finding_set cwe CWE-1
finding_set owasp none
finding_set loc_path app.py
finding_set loc_line 3
finding_set cell .
finding_set_match 'demo_eval'
finding_set_evidence 'demo_eval(x)'
finding_set remediation 'WRONG remediation - this must not appear either'
finding_emit
findings_merge "$D"
report_all "$D"

t_case 'name comes from the record title, not the finding title'
NAME=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['name']")
assert_eq 'Fixture quick+compliance rule' "$NAME" \
  "the record's own title wins - FAILS under a reading that sources name from the colliding finding's title"

t_case 'defaultConfiguration.level comes from the record severity (high->error), not the finding base_severity (info->note)'
LEVEL=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['defaultConfiguration']['level']")
assert_eq 'error' "$LEVEL" \
  "high (the record's base severity) maps to error - FAILS under a reading that used the finding's own info/note instead"

t_case 'help.text carries the record remediation, not the finding remediation'
HELP=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['help']['text']")
assert_contains "$HELP" 'exists only to prove registry' "the record's own remediation text is present"
assert_not_contains "$HELP" 'WRONG remediation' "the colliding finding's remediation never leaks in"

t_case 'the record cwe/owasp/cis reach properties.tags, not the finding cwe/owasp (which disagree)'
TAGS=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['properties']['tags']")
assert_eq "['external/cwe/CWE-95', 'external/owasp/A03:2021', 'external/cis/1.1']" "$TAGS" \
  "tags come from the record's CWE-95/A03:2021/1.1, not the finding's CWE-1/none - FAILS under a reading that reads cwe/owasp/cis off the finding for a registry-backed check"

t_case 'rule_digest is present and non-empty'
DIGEST=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['properties']['ruleDigest']")
assert_ne '' "$DIGEST" 'ruleDigest is a real, non-empty value'

t_case 'a registry-backed descriptor is NEVER marked descriptorSource - the property exists to mark the OPPOSITE case'
HAS_SRC=$(_py "$D" "'descriptorSource' in next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='SAST-GEN-DEMO_QUICK-01')['properties']")
assert_eq 'False' "$HAS_SRC" \
  'descriptorSource is absent on a registry-backed descriptor - FAILS under a reading that marks every descriptor the same way, hiding the distinction the ticket exists to make visible'

unset SCOURSH_INSTALL_ROOT

# ===========================================================================
printf '\n-- the three ungoverned id families: SCA, adapter, derived/composite --\n'
# ===========================================================================
# Real $SCOURSH_INSTALL_ROOT (no fixture override): these three ids genuinely
# have no on-disk *.rules record in the real tree either - modules/sca/ ships
# none by design, an adapter id is minted at runtime, and rules/derived.rules
# is deliberately unseeded - so this proves the synthesis path against the
# actual shipped registry, not only a fixture that happens to omit them.
_new_rundir synth

finding_new
finding_set check_id SCA-NPM-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'Vulnerable dependency: leftpad'
finding_set base_severity medium
finding_set cwe none
finding_set owasp none
finding_set path package-lock.json
finding_set cell .
finding_set remediation 'Upgrade leftpad to a patched version.'
finding_emit

finding_new
finding_set check_id 'semgrep:python.lang.security.audit.eval-detected'
finding_set module sast
finding_set title 'Use of eval() detected'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path app.py
finding_set loc_line 9
finding_set cell .
finding_set remediation 'Do not eval() untrusted input.'
finding_emit

finding_new
finding_set check_id COMPOSITE-TOKEN-HIJACK
finding_set module derived
finding_set title 'Token hijack chain'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set cell ''
finding_set remediation 'Rotate the token and close the leaking endpoint.'
finding_emit

findings_merge "$D"
report_all "$D"

for row in \
  'SCA-NPM-VULNERABLE_DEP-01|Vulnerable dependency: leftpad|Upgrade leftpad to a patched version.|warning|SCA' \
  'semgrep:python.lang.security.audit.eval-detected|Use of eval() detected|Do not eval() untrusted input.|error|adapter' \
  'COMPOSITE-TOKEN-HIJACK|Token hijack chain|Rotate the token and close the leaking endpoint.|error|derived/composite'
do
  IFS='|' read -r cid want_name want_help want_level family <<<"$row"

  t_case "$family id ($cid): synthesised descriptor exists and is marked"
  PRESENT=$(_py "$D" "'$cid' in {r['id'] for r in d['runs'][0]['tool']['driver']['rules']}")
  assert_eq 'True' "$PRESENT" \
    "$cid has a rules[] entry despite no *.rules record anywhere in the tree - FAILS under an implementation that only emits registry-backed descriptors, which is exactly the ticket's own trap (a result.ruleId with no matching reportingDescriptor)"

  SRC=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='$cid')['properties']['descriptorSource']")
  assert_eq 'synthesised' "$SRC" \
    "$cid is marked properties.descriptorSource: synthesised, so the difference from a registry-backed descriptor is visible rather than hidden"

  NAME=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='$cid')['name']")
  assert_eq "$want_name" "$NAME" "$cid: name comes from the finding's own title"

  HELP=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='$cid')['help']['text']")
  assert_eq "$want_help" "$HELP" "$cid: help.text comes from the finding's own remediation"

  LEVEL=$(_py "$D" "next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='$cid')['defaultConfiguration']['level']")
  assert_eq "$want_level" "$LEVEL" "$cid: defaultConfiguration.level is derived from the finding's own base_severity"

  HAS_DIGEST=$(_py "$D" "'ruleDigest' in next(r for r in d['runs'][0]['tool']['driver']['rules'] if r['id']=='$cid')['properties']")
  assert_eq 'False' "$HAS_DIGEST" \
    "$cid: no ruleDigest - there is no check record to take one from, and inventing one would be exactly the fabrication tension 22 forbids elsewhere in this file"
done

# ===========================================================================
printf '\n-- artifacts[]: the SARIF-02 generated location artifacts, and nothing else --\n'
# ===========================================================================
_new_rundir artifacts
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
finding_set remediation 'Escape it.'
finding_emit

# Case 1 (a real working-tree file): SAST native, no locations/sast.txt.
finding_new
finding_set check_id SAST-SEC-K-01
finding_set module sast
finding_set title 'Hardcoded key'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path app.py
finding_set loc_line 3
finding_set cell .
finding_set_match 'k'
finding_set_evidence 'k = "x"'
finding_set remediation 'Rotate it.'
finding_emit

findings_merge "$D"
report_all "$D"

t_case 'artifacts[] lists the dast location file this run actually wrote'
HAS_DAST=$(_py "$D" "'locations/dast.txt' in {a['location']['uri'] for a in d['runs'][0]['artifacts']}")
assert_eq 'True' "$HAS_DAST" 'locations/dast.txt is in artifacts[]'
assert_file_exists "$D/locations/dast.txt" 'and it is a real file at that relative path (tension 22: the physical location always points at a file that genuinely exists)'

t_case 'artifacts[] does NOT list a module that never got a location file - FAILS under an implementation that lists every module unconditionally'
HAS_SAST=$(_py "$D" "'locations/sast.txt' in {a['location']['uri'] for a in d['runs'][0]['artifacts']}")
assert_eq 'False' "$HAS_SAST" 'no locations/sast.txt entry: the SAST finding is a real working-tree file (case 1), so report_locations never created that file'
assert_file_absent "$D/locations/sast.txt" 'and the file itself was never created either'

N_ARTIFACTS=$(_py "$D" "len(d['runs'][0]['artifacts'])")
assert_eq '1' "$N_ARTIFACTS" 'exactly one artifact entry, matching the one location file this run wrote'

# ===========================================================================
printf '\n-- invocations[]: real facts, not a fabricated always-clean run --\n'
# ===========================================================================
_new_rundir invocations-clean
report_all "$D"

t_case 'a clean run reports executionSuccessful:true, exitCode:0'
SUCCESS=$(_py "$D" "d['runs'][0]['invocations'][0]['executionSuccessful']")
assert_eq 'True' "$SUCCESS" 'executionSuccessful is true'
CODE=$(_py "$D" "d['runs'][0]['invocations'][0]['exitCode']")
assert_eq '0' "$CODE" 'exitCode is 0'
STARTED=$(_py "$D" "d['runs'][0]['invocations'][0]['startTimeUtc']")
assert_ne '' "$STARTED" 'startTimeUtc is set'
ENDED=$(_py "$D" "d['runs'][0]['invocations'][0]['endTimeUtc']")
assert_ne '' "$ENDED" 'endTimeUtc is set'

_new_rundir invocations-incomplete
run_record incomplete_reason 'pattern engine unavailable mid-run'
report_all "$D"

t_case 'a run that recorded incomplete_reason reports executionSuccessful:false, exitCode:5 - FAILS under a reading that always reports a clean invocation'
SUCCESS=$(_py "$D" "d['runs'][0]['invocations'][0]['executionSuccessful']")
assert_eq 'False' "$SUCCESS" 'executionSuccessful is false'
CODE=$(_py "$D" "d['runs'][0]['invocations'][0]['exitCode']")
assert_eq '5' "$CODE" 'exitCode is 5 (SCOURSH_EXIT_INCOMPLETE), the same code scan_exit_code would produce for this case'

# ===========================================================================
printf '\n-- determinism: two runs over the same fixture are byte-identical --\n'
# ===========================================================================
export SCOURSH_INSTALL_ROOT=$FIXTURE_ROOT
_new_rundir det1
finding_new
finding_set check_id SAST-GEN-DEMO_QUICK-01
finding_set module sast
finding_set title 'Fixture finding'
finding_set base_severity high
finding_set cwe CWE-95
finding_set owasp A03:2021
finding_set loc_path app.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'demo_eval'
finding_set_evidence 'demo_eval(x)'
finding_set remediation 'Fix it.'
finding_emit
findings_merge "$D"
report_all "$D"
DET1=$(cat "$D/report.sarif")

_new_rundir det2
finding_new
finding_set check_id SAST-GEN-DEMO_QUICK-01
finding_set module sast
finding_set title 'Fixture finding'
finding_set base_severity high
finding_set cwe CWE-95
finding_set owasp A03:2021
finding_set loc_path app.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'demo_eval'
finding_set_evidence 'demo_eval(x)'
finding_set remediation 'Fix it.'
finding_emit
findings_merge "$D"
report_all "$D"
DET2=$(cat "$D/report.sarif")
unset SCOURSH_INSTALL_ROOT

# started_at/endTimeUtc are wall-clock and legitimately differ between two
# separate run_init calls, so strip the one line that carries them before
# comparing - everything else, including rules[] ordering, must be identical.
STRIP1=$(printf '%s' "$DET1" | grep -v '"startTimeUtc"')
STRIP2=$(printf '%s' "$DET2" | grep -v '"startTimeUtc"')
t_case 'two runs over the same fixture produce byte-identical report.sarif (modulo the wall-clock invocation timestamp)'
assert_eq "$STRIP1" "$STRIP2" \
  'identical - FAILS under a reading whose rules[] order depends on associative-array iteration order rather than the LC_ALL=C sort'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary sarif-rules
