#!/usr/bin/env bash
# tests/suites/agent-format.sh - `--format agent` (docs/AGENT-FORMAT.md),
# report_agent and its supporting pieces (rules/RULE-FORMAT.md §9.1.4's fix
# scaffold keys, lib/findings.sh's fix_* fields).
#
# Every test here pins the reading it fails under (AGENTS.md's own rule for
# this file), per docs/AGENT-FORMAT.md's own §4 test plan (A1-A16).
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes JSON keys and shell syntax literally.
# SC2015: `cmd && ok || no` is the intended reporting shape (tests/suites/report.sh's own header).
# shellcheck disable=SC2016,SC2015

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1
(( HAVE_PY )) || printf '  NOTICE python3 is not on PATH: every JSON-shape assertion below is a SKIP, not a pass.\n'

# Prints one JSON value (Python repr via json.dumps of whatever the dotted
# EXPR evaluates to on the loaded document) so bash can assert_eq/assert_contains
# against it as plain text. EXPR is a Python expression over `doc`.
jget() {
  local file=$1 expr=$2
  python3 -c "
import json,sys
doc=json.load(open(sys.argv[1]))
v=$expr
print(json.dumps(v))
" "$file" 2>&1
}

# ==============================================================================
printf '\n-- schema wiring: scan.sh / lib/config.sh accept "agent" (§3 changes 3/4) --\n'
# ==============================================================================
t_case 'format enum'
# shellcheck source=lib/config.sh
source "$ROOT/lib/config.sh"
assert_status 0 '_scanner_validate_list_item formats agent accepts it' \
  _scanner_validate_list_item formats agent
assert_status 1 '_scanner_validate_list_item formats bogus still refuses an unknown value' \
  _scanner_validate_list_item formats bogus

# ==============================================================================
printf '\n-- A4/A5/A6/A9: the fix scaffold, built via finding_set directly --\n'
# ==============================================================================
D=$SCOURSH_SCRATCH/agent-main
rm -rf "$D"
run_init "$D"
D=$SCOURSH_RUN_DIR

# A5: a SAST check with no fix-kind at all - manual, no fix_* key.
finding_new
finding_set check_id SAST-PY-EVAL-01
finding_set module sast
finding_set title 'Unsafe eval() call'
finding_set base_severity high
finding_set cwe CWE-95
finding_set owasp A03:2021
finding_set loc_path app.py
finding_set loc_line 10
finding_set cell .
finding_set remediation 'Do not eval() request-derived data.'
finding_set_evidence 'eval(user_input)'
finding_emit

# A5/A6: a secret-family check - manual, no fix_* at all, and specifically
# no fix_find derived from its (here unredacted, for test simplicity)
# evidence - because fixability=manual omits fix_* entirely, "derived from
# evidence" can never even be reached.
finding_new
finding_set check_id SAST-SEC-AWS_AKID-01
finding_set module sast
finding_set title 'Hardcoded AWS access key id'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path config.py
finding_set loc_line 4
finding_set cell .
finding_set remediation 'Rotate it.'
finding_set_evidence 'AKIAABCDEFGHIJKLMNOP'
finding_emit

# A9: SCA npm TRANSITIVE - assisted, never auto, even though a fix exists.
# (npm rather than the design report's own pypi worked example: semver_cmp_v
# is proven ONLY for npm - modules/sca/semver.sh's own header - so this
# suite exercises the real, verified comparator rather than reproducing the
# design report's pypi/semver mismatch.)
finding_new
finding_set check_id SCA-NPM-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'npm: leftish@1.11.0 is vulnerable (GHSA-TEST-0001)'
finding_set base_severity high
finding_set confidence high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package leftish
finding_set loc_version 1.11.0
finding_set loc_advisory_id GHSA-TEST-0001
finding_set dep_type transitive
finding_set fix_fixed_versions '2.1.10,2.2.3,1.11.22'
finding_set path package-lock.json
finding_set cell .
finding_set logical_kind dependency
finding_set logical_fqn 'npm:leftish@1.11.0'
finding_set remediation 'Upgrade leftish to one of: 2.1.10,2.2.3,1.11.22.'
finding_set_evidence 'dependency: leftish@1.11.0'
finding_emit

# A7: the SAME advisory shape, but a DIFFERENT package and DIRECT - auto,
# and fix_to must pick the smallest fixed version on the SAME branch
# (1.11.22), never 2.1.10. (A different package name, not just a different
# dep_type, deliberately: the SCA fingerprint profile is
# ecosystem/package/advisory_id ONLY - lib/findings.sh's
# _fp_components_for - so a same-package pair here would collide onto one
# fingerprint and findings_merge would silently drop one of them.)
finding_new
finding_set check_id SCA-NPM-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'npm: rightish@1.11.0 is vulnerable (GHSA-TEST-0001)'
finding_set base_severity high
finding_set confidence high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package rightish
finding_set loc_version 1.11.0
finding_set loc_advisory_id GHSA-TEST-0001
finding_set dep_type direct
finding_set fix_fixed_versions '2.1.10,2.2.3,1.11.22'
finding_set path other/package-lock.json
finding_set cell .
finding_set logical_kind dependency
finding_set logical_fqn 'npm:rightish@1.11.0'
finding_set remediation 'Upgrade rightish to one of: 2.1.10,2.2.3,1.11.22.'
finding_set_evidence 'dependency: rightish@1.11.0'
finding_emit

# A8: no published fix at all - blocked, no fix_*.
finding_new
finding_set check_id SCA-PY-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'pypi: nofix@0.9.0 is vulnerable (GHSA-TEST-0002)'
finding_set base_severity medium
finding_set confidence high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem pypi
finding_set loc_package nofix
finding_set loc_version 0.9.0
finding_set loc_advisory_id GHSA-TEST-0002
finding_set dep_type direct
finding_set path requirements.txt
finding_set cell .
finding_set logical_kind dependency
finding_set logical_fqn 'pypi:nofix@0.9.0'
finding_set remediation 'No fixed version is published upstream yet.'
finding_set_evidence 'dependency: nofix@0.9.0'
finding_emit

# A non-npm ecosystem WITH a fix, to prove the documented first-listed
# fallback (never an invented ordering scoursh cannot verify - tension 25).
finding_new
finding_set check_id SCA-PY-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'pypi: django@1.11 is vulnerable (GHSA-TEST-0003)'
finding_set base_severity high
finding_set confidence high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem pypi
finding_set loc_package django
finding_set loc_version 1.11
finding_set loc_advisory_id GHSA-TEST-0003
finding_set dep_type direct
finding_set fix_fixed_versions '2.1.10,2.2.3,1.11.22'
finding_set path django-requirements.txt
finding_set cell .
finding_set logical_kind dependency
finding_set logical_fqn 'pypi:django@1.11'
finding_set remediation 'Upgrade django to one of: 2.1.10,2.2.3,1.11.22.'
finding_set_evidence 'dependency: django@1.11'
finding_emit

# A4 (real end-to-end): the shipped IAC-K8S-PRIVILEGED-01 record, through
# the real finding_from_record path - exactly the check docs/AGENT-FORMAT.md
# §3 names as the worked "auto" example.
declare -A _AGT_K8S=()
records_load "$ROOT/modules/iac/kubernetes.rules" pattern-rule agtk8s
IDX_K8S=$(records_index_of_id agtk8s IAC-K8S-PRIVILEGED-01)
finding_new
finding_from_record agtk8s "$IDX_K8S"
finding_set module iac
finding_set loc_path deploy/pod.yaml
finding_set loc_line 12
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'deploy/pod.yaml:12'
finding_set_match 'privileged: true'
finding_set_evidence 'privileged: true'
finding_emit

# A real "insert-near" example - IAC-DOCKER-ROOT_USER-01, anchor FROM.
records_load "$ROOT/modules/iac/dockerfile.rules" pattern-rule agtdock
IDX_DOCK=$(records_index_of_id agtdock IAC-DOCKER-ROOT_USER-01)
finding_new
finding_from_record agtdock "$IDX_DOCK"
finding_set module iac
finding_set loc_path Dockerfile
finding_set loc_line 1
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'Dockerfile:1'
finding_set_match 'FROM node:18'
finding_set_evidence 'FROM node:18'
finding_emit

# A real "replace-tpl" example - IAC-TF-OPEN_CIDR-01, placeholder replacement.
records_load "$ROOT/modules/iac/terraform.rules" pattern-rule agttf
IDX_TF=$(records_index_of_id agttf IAC-TF-OPEN_CIDR-01)
finding_new
finding_from_record agttf "$IDX_TF"
finding_set module iac
finding_set loc_path main.tf
finding_set loc_line 20
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'main.tf:20'
finding_set_match 'cidr_blocks = ["0.0.0.0/0"]'
finding_set_evidence 'cidr_blocks = ["0.0.0.0/0"]'
finding_emit

# A real cloud fix-cli example (captain decision: cloud gets a labeled,
# suggested, never-executed CLI scaffold) - CLOUD-S3-NO_VERSIONING-01.
records_load "$ROOT/modules/cloud/aws/live/checks.rules" script-check agtcloud
IDX_S3=$(records_index_of_id agtcloud CLOUD-S3-NO_VERSIONING-01)
finding_new
finding_from_record agtcloud "$IDX_S3"
finding_set module cloud
finding_set loc_account_id 111122223333
finding_set loc_region us-east-1
finding_set loc_resource_key 'arn:aws:s3:::my-test-bucket'
finding_set cell 111122223333/us-east-1
finding_set logical_kind resource
finding_set logical_fqn 'arn:aws:s3:::my-test-bucket'
finding_set_evidence 'bucket versioning: not enabled'
finding_emit

findings_merge "$D"
report_agent "$D"

t_case 'agent-fix.json is valid JSON'
if (( HAVE_PY )); then
  python3 -c "import json; json.load(open('$D/agent-fix.json'))" 2>/dev/null \
    && _t_ok 'parses as JSON' || _t_no 'parses as JSON' 'invalid JSON'
fi

if (( HAVE_PY )); then
  t_case 'A1: every non-suppressed finding appears exactly once in findings[]'
  N_FIELDS=$(grep -c '^.' "$D/findings.fields" || true)
  N_JSON=$(jget "$D/agent-fix.json" 'len(doc["findings"])')
  assert_eq "$N_FIELDS" "$N_JSON" 'findings[] length matches findings.fields record count'

  t_case 'A15: every findings[].check resolves to a checks{} key'
  BAD=$(jget "$D/agent-fix.json" \
    '[f["check"] for f in doc["findings"] if f["check"] not in doc["checks"]]')
  assert_eq '[]' "$BAD" 'no dangling check reference'

  t_case 'A5: manual SAST finding carries fixability manual and no fix_ key at all'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SAST-PY-EVAL-01")')
  assert_contains "$ROW" '"fixability": "manual"' 'fixability is manual'
  for k in fix_kind fix_find fix_replace fix_snippet fix_to fix_all fix_cmd fix_cli fix_writes; do
    assert_not_contains "$ROW" "\"$k\"" "no $k key present on a manual finding"
  done

  t_case 'A5/A6: secret-family finding is manual, no fix_find derived from its evidence'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SAST-SEC-AWS_AKID-01")')
  assert_contains "$ROW" '"fixability": "manual"' 'fixability is manual'
  assert_not_contains "$ROW" '"fix_find"' 'no fix_find key at all on a secret-family finding'

  t_case 'A7: SCA direct dependency picks the smallest same-branch fixed version (1.11.22, not 2.1.10)'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SCA-NPM-VULNERABLE_DEP-01" and f.get("dep_type")=="direct")')
  assert_contains "$ROW" '"fixability": "auto"' 'direct npm dep is auto'
  assert_contains "$ROW" '"fix_to": "1.11.22"' 'fix_to is the same-branch minimal upgrade'
  assert_contains "$ROW" '"fix_cmd": "npm install rightish@1.11.22"' 'fix_cmd is the npm template'

  t_case 'A9: SCA transitive dependency is assisted, never auto'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SCA-NPM-VULNERABLE_DEP-01" and f.get("dep_type")=="transitive")')
  assert_contains "$ROW" '"fixability": "assisted"' 'transitive npm dep is assisted, not auto'

  t_case 'A8: SCA with no published fix is blocked, and carries no fix_* at all'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SCA-PY-VULNERABLE_DEP-01" and f["advisory"]=="GHSA-TEST-0002")')
  assert_contains "$ROW" '"fixability": "blocked"' 'fixability is blocked'
  assert_not_contains "$ROW" '"fix_kind"' 'no fix_kind on a blocked finding'
  assert_not_contains "$ROW" '"fix_to"' 'no fix_to on a blocked finding'

  t_case 'non-npm ecosystem with a real fix falls back to the first-listed fixed version, never an unverified ordering'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="SCA-PY-VULNERABLE_DEP-01" and f["advisory"]=="GHSA-TEST-0003")')
  assert_contains "$ROW" '"fix_to": "2.1.10"' 'fix_to is the advisory\047s own first-listed version for pypi'
  assert_contains "$ROW" '"fix_all"' 'fix_all still carries every published option'

  t_case 'A4 (real record): IAC-K8S-PRIVILEGED-01 through finding_from_record yields auto/replace with the literal booleans'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="IAC-K8S-PRIVILEGED-01")')
  assert_contains "$ROW" '"fixability": "auto"' 'fixability is auto'
  assert_contains "$ROW" '"fix_kind": "replace"' 'fix_kind is replace'
  assert_contains "$ROW" '"fix_find": "privileged: true"' 'fix_find is the literal from the rule record'
  assert_contains "$ROW" '"fix_replace": "privileged: false"' 'fix_replace is the literal from the rule record'

  t_case 'insert-near (real record): IAC-DOCKER-ROOT_USER-01 anchors on FROM and carries a snippet, never fix_replace'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="IAC-DOCKER-ROOT_USER-01")')
  assert_contains "$ROW" '"fixability": "assisted"' 'fixability is assisted'
  assert_contains "$ROW" '"fix_kind": "insert-near"' 'fix_kind is insert-near'
  assert_contains "$ROW" '"fix_find": "FROM"' 'fix_find is the anchor token'
  assert_contains "$ROW" 'USER app' 'fix_snippet carries the USER instruction'
  assert_not_contains "$ROW" '"fix_replace"' 'insert-near carries no fix_replace'

  t_case 'replace-tpl (real record): IAC-TF-OPEN_CIDR-01 is assisted with a placeholder replacement'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="IAC-TF-OPEN_CIDR-01")')
  assert_contains "$ROW" '"fixability": "assisted"' 'fixability is assisted'
  assert_contains "$ROW" '"fix_kind": "replace-tpl"' 'fix_kind is replace-tpl'
  # fix-find/fix-replace were authored WITH their literal Terraform quote
  # characters ("0.0.0.0/0" / "<TRUSTED_CIDR>"), matching the quoted string
  # the pattern actually matches - json_string escapes those embedded quotes
  # as \" in the document, so the plain substring (no wrapper quotes) is
  # what to look for here.
  assert_contains "$ROW" '<TRUSTED_CIDR>' 'fix_replace carries the human-fill placeholder'

  t_case 'cloud fix-cli (captain decision): assisted, %RESOURCE% filled in, and explicitly labeled never-auto-run'
  ROW=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="CLOUD-S3-NO_VERSIONING-01")')
  assert_contains "$ROW" '"fixability": "assisted"' 'a cloud write is always assisted, never auto'
  assert_contains "$ROW" '"fix_kind": "cloud-cli"' 'fix_kind is cloud-cli'
  FIXCLI=$(jget "$D/agent-fix.json" \
    'next(f for f in doc["findings"] if f["check"]=="CLOUD-S3-NO_VERSIONING-01")["fix_cli"]')
  assert_contains "$FIXCLI" 'aws s3api put-bucket-versioning --bucket my-test-bucket' \
    '%RESOURCE% was filled in from loc_resource_key, stripped to the bare bucket name'
  assert_not_contains "$FIXCLI" '%RESOURCE%' 'no unfilled placeholder left in fix_cli'
  assert_not_contains "$FIXCLI" 'arn:aws:s3' 'the raw ARN was not pasted into the command verbatim (only into loc, which is a separate field)'
  assert_contains "$ROW" '"fix_writes": true' 'fix_writes is set'
  assert_contains "$ROW" 'do NOT auto-run' 'the never-auto-run note is present'
fi

# ==============================================================================
printf '\n-- A3: catalogue promotion is computed, never assumed --\n'
# ==============================================================================
D3=$SCOURSH_SCRATCH/agent-vary
rm -rf "$D3"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D3"
D3=$SCOURSH_RUN_DIR

finding_new
finding_set check_id SAST-GEN-VARYTEST-01
finding_set module sast
finding_set title 'Vary-test check'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path a.py
finding_set loc_line 1
finding_set cell .
finding_set remediation 'Fix A.'
finding_set_evidence 'a'
finding_emit

finding_new
finding_set check_id SAST-GEN-VARYTEST-01
finding_set module sast
finding_set title 'Vary-test check'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path b.py
finding_set loc_line 1
finding_set cell .
finding_set remediation 'Fix A.'
finding_set_evidence 'b'
finding_emit

findings_merge "$D3"
report_agent "$D3"

if (( HAVE_PY )); then
  t_case 'A3: a field that varies across a check\047s own findings is never promoted, and both values survive per-finding'
  CATSEV=$(jget "$D3/agent-fix.json" 'doc["checks"]["SAST-GEN-VARYTEST-01"].get("sev","<absent>")')
  assert_eq '"<absent>"' "$CATSEV" 'checks{}.sev is absent because severity varies (high vs low)'
  SEVS=$(jget "$D3/agent-fix.json" \
    'sorted(f["sev"] for f in doc["findings"] if f["check"]=="SAST-GEN-VARYTEST-01")')
  assert_eq '["high", "low"]' "$SEVS" 'both per-finding sev values are present, unchanged'
  CATTITLE=$(jget "$D3/agent-fix.json" 'doc["checks"]["SAST-GEN-VARYTEST-01"]["title"]')
  assert_eq '"Vary-test check"' "$CATTITLE" 'title, which IS byte-identical across both findings, is promoted'
  t_case 'A2: round-trip - merging checks[check] under a finding reproduces finding_decode of the same shard line'
  OK=$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
merged = dict(doc["checks"]["SAST-GEN-VARYTEST-01"])
f = next(x for x in doc["findings"] if x["loc"].startswith("a.py"))
merged.update(f)
print(merged["title"] == "Vary-test check" and merged["sev"] == "high")
' "$D3/agent-fix.json" 2>&1)
  assert_eq 'True' "$OK" 'the merge (catalogue overridden by per-finding keys) reconstructs the original title and severity'
fi

# ==============================================================================
printf '\n-- A10/A11: the honesty header --\n'
# ==============================================================================
DH=$SCOURSH_SCRATCH/agent-header
rm -rf "$DH"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$DH"
DH=$SCOURSH_RUN_DIR
run_record checks_run IAC-K8S-PRIVILEGED-01
run_record checks_run SAST-PY-EVAL-01
run_record checks_run SCA-NPM-VULNERABLE_DEP-01
run_record coverage_reduction 'module=dast reason=no --target given (declared, all)'
run_record coverage_reduction 'module=cloud reason=no --live given (declared, all)'
run_record coverage_gap 'module=sca reason=unknown_version ecosystem=Go count=1'
run_record skipped_checks 'check=SAST-PY-DESERIALIZE-01 skipped_by=--profile-scan quick'
run_record incomplete_reason 'test-injected incompleteness'
findings_merge "$DH"
report_agent "$DH"

if (( HAVE_PY )); then
  t_case 'A10: modules_not_run contains dast, and coverage_reduction carries the literal "no --target given" line'
  MNR=$(jget "$DH/agent-fix.json" '"dast" in doc["run"]["modules_not_run"]')
  assert_eq 'true' "$MNR" 'dast is in modules_not_run'
  CR=$(jget "$DH/agent-fix.json" '[c for c in doc["run"]["coverage_reduction"] if "no --target given" in c]')
  assert_eq '["module=dast reason=no --target given (declared, all)"]' "$CR" \
    'the exact coverage_reduction line is carried verbatim'
  t_case 'modules_reported holds the modules whose checks actually ran'
  MR=$(jget "$DH/agent-fix.json" 'sorted(doc["run"]["modules_reported"])')
  assert_eq '["iac", "sast", "sca"]' "$MR" 'sast/sca/iac reported; dast/cloud/posture did not'
  t_case 'A11: checks_run, coverage_gap, skipped_checks, incomplete_reason are carried verbatim and non-lossily'
  CHR=$(jget "$DH/agent-fix.json" 'sorted(doc["run"]["checks_run"])')
  assert_eq '["IAC-K8S-PRIVILEGED-01", "SAST-PY-EVAL-01", "SCA-NPM-VULNERABLE_DEP-01"]' "$CHR" \
    'checks_run names every id, not a count'
  CG=$(jget "$DH/agent-fix.json" 'doc["run"]["coverage_gap"]')
  assert_eq '["module=sca reason=unknown_version ecosystem=Go count=1"]' "$CG" 'coverage_gap carried verbatim'
  SK=$(jget "$DH/agent-fix.json" 'doc["run"]["skipped_checks"]')
  assert_eq '["check=SAST-PY-DESERIALIZE-01 skipped_by=--profile-scan quick"]' "$SK" 'skipped_checks carried verbatim'
  IR=$(jget "$DH/agent-fix.json" 'doc["run"]["incomplete_reason"]')
  assert_eq '["test-injected incompleteness"]' "$IR" 'incomplete_reason carried verbatim'
  t_case 'status_counts, gate, diff_usable and redact_secrets are present'
  SCK=$(jget "$DH/agent-fix.json" 'sorted(doc["run"]["status_counts"].keys())')
  assert_eq '["fixed", "new", "recurring", "unknown"]' "$SCK" 'status_counts has all four keys'
  GATE=$(jget "$DH/agent-fix.json" '"gate" in doc["run"] and "diff_usable" in doc["run"] and "redact_secrets" in doc["run"]')
  assert_eq 'true' "$GATE" 'gate/diff_usable/redact_secrets are all present'
fi

# ==============================================================================
printf '\n-- A12/A13/A14: format wiring --\n'
# ==============================================================================
D12=$SCOURSH_SCRATCH/agent-formats
rm -rf "$D12"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D12"
D12=$SCOURSH_RUN_DIR
finding_new
finding_set check_id SAST-GEN-FMTTEST-01
finding_set module sast
finding_set title 'fmt test'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path f.py
finding_set loc_line 1
finding_set cell .
finding_set remediation 'r'
finding_set_evidence 'e'
finding_emit
findings_merge "$D12"

t_case 'A12: --format agent alone writes agent-fix.json plus the two mandatory records, and nothing else'
SCOURSH_FORMATS=agent
report_all "$D12"
unset SCOURSH_FORMATS
assert_file_exists "$D12/agent-fix.json" 'agent-fix.json is written'
assert_file_exists "$D12/findings.jsonl" 'findings.jsonl (mandatory) is still written'
assert_file_exists "$D12/run.json" 'run.json (mandatory) is still written'
assert_file_absent "$D12/report.html" 'report.html is NOT written'
assert_file_absent "$D12/report.md" 'report.md is NOT written'
assert_file_absent "$D12/report.sarif" 'report.sarif is NOT written'
assert_file_absent "$D12/findings.json" 'findings.json is NOT written'

t_case 'A13: --format json,agent writes both, and agent never replaces json'
rm -f "$D12/agent-fix.json" "$D12/findings.json"
SCOURSH_FORMATS=json,agent
report_all "$D12"
unset SCOURSH_FORMATS
assert_file_exists "$D12/agent-fix.json" 'agent-fix.json is written'
assert_file_exists "$D12/findings.json" 'findings.json is ALSO written'
assert_file_absent "$D12/report.md" 'report.md is still not written (md was not requested)'

t_case 'A14: report --from DIR regenerates a byte-identical agent-fix.json'
D14=$SCOURSH_SCRATCH/agent-regen
rm -rf "$D14"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
run_init "$D14"
D14=$SCOURSH_RUN_DIR
# Deliberately wrong, matching tests/suites/report.sh's own pattern for this
# exact call: report_regenerate_from must restore these from $D12's own
# run.json, never leave this invocation's own values in place.
SCOURSH_GATE_RESULT=fail
SCOURSH_DIFF_USABLE=true
SCOURSH_FORMATS=agent
report_regenerate_from "$D12" "$D14"
unset SCOURSH_FORMATS
if cmp -s "$D12/agent-fix.json" "$D14/agent-fix.json"; then
  _t_ok 'agent-fix.json is byte-identical after report --from DIR'
else
  DIFF_OUT=$(diff "$D12/agent-fix.json" "$D14/agent-fix.json" | head -10) || true
  _t_no 'agent-fix.json is byte-identical after report --from DIR' "$DIFF_OUT"
fi
SCOURSH_GATE_RESULT='' SCOURSH_DIFF_USABLE=''

# ==============================================================================
printf '\n-- A16: the fix_* fields never move a fingerprint or leak into findings.jsonl/report.sarif --\n'
# ==============================================================================
# Two SEPARATE run directories, each through the real finding_emit pipeline
# (never finding_fingerprint/_finding_json called directly on a half-built
# _F, which needs the rubric/cvss/occurrence fields finding_emit itself
# computes). `occurrence_reset_all` resets the shared, in-process `_OCC`
# ordinal table between them - AGENTS.md: "a test harness that simulates
# several runs in one process must call it, or a counter from the previous
# run leaks into the next one's identities" - so both findings, at the
# identical (check_id, loc_match_digest) pair, land on occurrence 1 rather
# than 1 and 2, which would otherwise move the fingerprint for a reason
# having nothing to do with fix_kind.
D16A=$SCOURSH_SCRATCH/agent-a16-without
rm -rf "$D16A"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
occurrence_reset_all
run_init "$D16A"
D16A=$SCOURSH_RUN_DIR
finding_new
finding_set check_id IAC-K8S-PRIVILEGED-01
finding_set module iac
finding_set title 't'
finding_set base_severity critical
finding_set confidence high
finding_set cwe CWE-269
finding_set owasp A02:2025
finding_set loc_path pod.yaml
finding_set loc_line 5
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'pod.yaml:5'
finding_set remediation 'r'
finding_set_match 'privileged: true'
finding_set_evidence 'privileged: true'
finding_emit
findings_merge "$D16A"
findings_write_jsonl "$D16A"
FP_WITHOUT=$(grep -o 'fingerprint=[^	]*' "$D16A/findings.fields")
JSON_WITHOUT=$(sed -E 's/"(first_seen|last_seen)":"[^"]*"/"\1":"NOW"/g' "$D16A/findings.jsonl")

D16B=$SCOURSH_SCRATCH/agent-a16-with
rm -rf "$D16B"
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''
occurrence_reset_all
run_init "$D16B"
D16B=$SCOURSH_RUN_DIR
finding_new
finding_set check_id IAC-K8S-PRIVILEGED-01
finding_set module iac
finding_set title 't'
finding_set base_severity critical
finding_set confidence high
finding_set cwe CWE-269
finding_set owasp A02:2025
finding_set loc_path pod.yaml
finding_set loc_line 5
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'pod.yaml:5'
finding_set remediation 'r'
finding_set_match 'privileged: true'
finding_set_evidence 'privileged: true'
finding_set fix_kind replace
finding_set fix_find 'privileged: true'
finding_set fix_replace 'privileged: false'
finding_emit
findings_merge "$D16B"
findings_write_jsonl "$D16B"
FP_WITH=$(grep -o 'fingerprint=[^	]*' "$D16B/findings.fields")
JSON_WITH=$(sed -E 's/"(first_seen|last_seen)":"[^"]*"/"\1":"NOW"/g' "$D16B/findings.jsonl")

t_case 'A16: adding fix_kind/fix_find/fix_replace changes neither the fingerprint nor findings.jsonl'
assert_eq "$FP_WITHOUT" "$FP_WITH" 'the fingerprint (findings.fields) is unchanged'
assert_eq "$JSON_WITHOUT" "$JSON_WITH" 'findings.jsonl (and therefore report.sarif'\''s own input) is byte-identical'
assert_not_contains "$JSON_WITH" 'fix_kind' 'fix_kind never appears in findings.jsonl at all'

# ==============================================================================
printf '\n-- runtime guard: a fix-* key on a secret-family check aborts finding_from_record --\n'
# ==============================================================================
GW=$SCOURSH_SCRATCH/agent-guard
mkdir -p "$GW"
cat >"$GW/secret.rules" <<'EOF'
id: SAST-SEC-BADFIX-01
title: t
severity: high
cwe: CWE-798
owasp: A07:2021
pattern: x
dialect: ere
tags: static
fix-kind: replace
fix-find: x
fix-replace: y
remediation: r
EOF
records_load "$GW/secret.rules" pattern-rule agtguard
IDX_GUARD=$(records_index_of_id agtguard SAST-SEC-BADFIX-01)
_guard_call() { finding_new; finding_from_record agtguard "$IDX_GUARD"; }
t_case 'a fix-* key on a secret-family check id dies rather than being silently accepted'
assert_status 5 'finding_from_record refuses (SCOURSH_EXIT_INCOMPLETE=5)' _guard_call

t_summary agent-format
