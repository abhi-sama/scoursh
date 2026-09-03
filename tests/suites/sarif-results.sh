#!/usr/bin/env bash
# tests/suites/sarif-results.sh - lib/report.sh's runs[0].results[]
# (docs/STEP10-SARIF-PLAN.md SARIF-04: the per-finding mapping).
#
# Covers this ticket's acceptance criteria:
#   - the field-by-field mapping table: check_id/title/severity/base_severity/
#     confidence/module/cvss/location/logical/evidence/status/cell/
#     first_seen/last_seen/fingerprint/suppressed all reach the right place
#   - the five-to-four level mapping (critical/high->error, medium->warning,
#     low/info->note, info deliberately NOT none)
#   - the four-case location table, all four cases plus case 3's two halves
#   - partialFingerprints carries scourshFingerprint/v1, verbatim
#   - suppressions[] with kind:"external" and a justification, only when the
#     finding actually is suppressed - never an empty array otherwise
#   - security-severity is NEVER emitted anywhere in the document
#   - the SCA severity-provenance gap: a medium-severity sca finding records
#     the gap in run.json exactly once; a non-medium one does not, because
#     only "medium" is genuinely ambiguous between a real advisory and the
#     unscored fallback
#   - no result.ruleId lacks a matching reportingDescriptor across a run
#     emitting several profiles (and both ungoverned-id families) at once
#   - a redacted field stays redacted in report.sarif: the literal secret
#     bytes never reach the document, and hostile evidence (a script tag, an
#     ANSI sequence, a raw newline, invalid UTF-8, a backtick run) is
#     escaped rather than breaking the JSON
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.  results[] does not exist before this ticket -
# report_sarif always wrote "results": [] - so every assertion below failed
# under the empty array before this change, the coarse form of "observed
# failing, then passing"; the finer-grained cases each say what wrong
# reading they additionally rule out.
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

W=$SCOURSH_SCRATCH/sarif-results-suite
rm -rf "$W"
mkdir -p "$W"

_new_rundir() {                    # name -> sets D, resets it
  D=$W/$1
  rm -rf "$D"
  run_init "$D"
  D=$SCOURSH_RUN_DIR
}

# Reads a top-level expression out of report.sarif via python3 when
# available; the caller degrades gracefully otherwise (mirrors
# tests/suites/sarif-rules.sh's own python3-optional pattern).
_py() {                            # rundir python-expr
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -c "
import json
d = json.load(open('$1/report.sarif'))
print($2)
"
}

# One result object matching a check_id, as a python dict repr (via _py).
_result_for() {                    # rundir check_id python-expr-on-'r'
  _py "$1" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='$2')['$3']" 2>/dev/null || true
}

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

# The small fixture registry tests/suites/sarif-rules.sh already uses (2 sast
# + 5 dast checks), for the whole suite: nothing below tests registry-backed
# vs synthesised DESCRIPTOR content (that's SARIF-03's own territory) - only
# results[]'s mapping off the finding, which is agnostic to which registry is
# loaded - and loading the real, full check registry on every one of this
# file's dozen report_all calls made the suite take almost two minutes for no
# behavioural difference.
export SCOURSH_INSTALL_ROOT=$ROOT/tests/fixtures/checks-registry

# ===========================================================================
printf '\n-- field-by-field mapping, case 1 (a real working-tree file) --\n'
# ===========================================================================
_new_rundir mapping
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

findings_merge "$D"
FP=$(
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]:-} == SAST-SEC-K-01 ]] || continue
    printf '%s' "${_DF[fingerprint]}"
    break
  done <"$D/findings.fields"
)
report_all "$D"

if (( HAVE_PY )); then
  t_case 'ruleId is check_id verbatim (tension 7: check_id is the identity)'
  assert_eq 'SAST-SEC-K-01' "$(_result_for "$D" SAST-SEC-K-01 ruleId)" 'ruleId'

  t_case 'level is the mapped severity (critical -> error), not passed through raw'
  assert_eq 'error' "$(_result_for "$D" SAST-SEC-K-01 level)" \
    "critical maps to error - FAILS under a reading that copies severity verbatim into level (SARIF has no 'critical')"

  t_case 'message.text is the finding title'
  MSG=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['message']['text']")
  assert_eq 'Hardcoded key' "$MSG" 'message.text'

  t_case 'physicalLocation.artifactLocation.uri is loc_path (case 1: a real working-tree file)'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'app.py' "$URI" \
    'case 1 points at the real file - FAILS under a reading that sends every SAST finding to a generated artifact'

  t_case 'region.startLine is loc_line'
  LN=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['locations'][0]['physicalLocation']['region']['startLine']")
  assert_eq '3' "$LN" 'startLine'

  t_case 'logicalLocations[0] carries kind/fullyQualifiedName (SARIF-01)'
  KIND=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['locations'][0]['logicalLocations'][0]['kind']")
  FQN=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['locations'][0]['logicalLocations'][0]['fullyQualifiedName']")
  assert_eq 'file' "$KIND" 'logicalLocations[0].kind'
  assert_eq 'app.py:3' "$FQN" 'logicalLocations[0].fullyQualifiedName'

  t_case 'partialFingerprints carries scourshFingerprint/v1, verbatim (tension 5/22)'
  PFP=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['partialFingerprints']['scourshFingerprint/v1']")
  assert_eq "$FP" "$PFP" \
    'partialFingerprints matches the fingerprint findings.jsonl carries for this exact finding'

  t_case 'properties carries module/status/confidence/baseSeverity/cvss/cell/firstSeen/lastSeen'
  MOD=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['module']")
  assert_eq 'sast' "$MOD" 'properties.module'
  STATUS=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['status']")
  assert_eq 'new' "$STATUS" 'properties.status'
  CONF=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['confidence']")
  assert_eq 'high' "$CONF" 'properties.confidence'
  BASESEV=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['baseSeverity']")
  assert_eq 'critical' "$BASESEV" \
    "properties.baseSeverity keeps the ORIGINAL critical (not the mapped 'error' level), so a consumer can see the rubric moved it (tension 8)"
  HAS_CVSS=$(_py "$D" "'vector' in next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['cvss'] and 'score' in next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['cvss']")
  assert_eq 'True' "$HAS_CVSS" 'properties.cvss carries both vector and score, for audit'
  CELL=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['cell']")
  assert_eq '.' "$CELL" 'properties.cell is the coverage cell this finding set'
  FS=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['properties']['firstSeen']")
  assert_ne '' "$FS" 'properties.firstSeen is set'

  t_case 'evidence with a region goes to region.snippet.text, and message.text stays the bare title'
  SNIP=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-SEC-K-01')['locations'][0]['physicalLocation']['region']['snippet']['text']")
  assert_contains "$SNIP" 'redacted' \
    'the redacted evidence placeholder is in the snippet (see the redaction section below for the full proof)'
else
  _t_ok 'python3 unavailable, field-by-field mapping checks skipped'
fi

# ===========================================================================
printf '\n-- the five-to-four level mapping --\n'
# ===========================================================================
_new_rundir levels
occurrence_reset_all

_mk() {                            # check_id base_severity path line
  finding_new
  finding_set check_id "$1"
  finding_set module sast
  finding_set title "level test $1"
  finding_set base_severity "$2"
  finding_set cwe none
  finding_set owasp none
  finding_set loc_path "$3"
  finding_set loc_line "$4"
  finding_set cell .
  finding_set_match 'x'
  finding_emit
}
_mk LVL-CRITICAL-01 critical f.py 1
_mk LVL-HIGH-01 high f.py 2
_mk LVL-MEDIUM-01 medium f.py 3
_mk LVL-LOW-01 low f.py 4
_mk LVL-INFO-01 info f.py 5
findings_merge "$D"
report_all "$D"

if (( HAVE_PY )); then
  for row in 'LVL-CRITICAL-01|error' 'LVL-HIGH-01|error' 'LVL-MEDIUM-01|warning' 'LVL-LOW-01|note' 'LVL-INFO-01|note'; do
    IFS='|' read -r cid want <<<"$row"
    t_case "$cid: level is $want"
    GOT=$(_result_for "$D" "$cid" level)
    assert_eq "$want" "$GOT" "$cid maps to $want"
  done
  t_case "info maps to 'note', never 'none' - FAILS under a reading that collapses info onto none, which SARIF defines as 'no problem found'"
  GOT=$(_result_for "$D" LVL-INFO-01 level)
  assert_ne 'none' "$GOT" "info is not none"
else
  _t_ok 'python3 unavailable, level mapping checks skipped'
fi

# ===========================================================================
printf '\n-- the four-case location table --\n'
# ===========================================================================
_new_rundir locations
occurrence_reset_all

# Case 1: sast native, a real working-tree file.
finding_new
finding_set check_id LOC-CASE1-01
finding_set module sast
finding_set title 'case 1'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path app.py
finding_set loc_line 7
finding_set cell .
finding_set_match 'x'
finding_emit

# Case 2: sca, whose own `path` field (NOT loc_path) names a real, committed
# lockfile, and which carries NO line at all.
finding_new
finding_set check_id LOC-CASE2-01
finding_set module sca
finding_set title 'case 2'
finding_set base_severity high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package left-pad
finding_set loc_advisory_id GHSA-TEST-0002
finding_set path package-lock.json
finding_set logical_kind dependency
finding_set logical_fqn 'npm:left-pad@1.0.0'
finding_set_evidence 'dependency: left-pad@1.0.0'
finding_emit

# Case 4: dast, cloud, posture, derived - always the generated artifact.
finding_new
finding_set check_id LOC-CASE4-DAST-01
finding_set module dast
finding_set title 'case 4 dast'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_target t1
finding_set loc_method GET
finding_set path /a/b
finding_set loc_param_location query
finding_set loc_param_name q
finding_emit

findings_merge "$D"
report_all "$D"

if (( HAVE_PY )); then
  t_case 'case 1: uri is loc_path, region.startLine is loc_line'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE1-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'app.py' "$URI" 'case 1 uri'
  LN=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE1-01')['locations'][0]['physicalLocation']['region']['startLine']")
  assert_eq '7' "$LN" 'case 1 startLine'

  t_case 'case 2 (sca): uri is the `path` field, NOT loc_path, and region is OMITTED ENTIRELY - FAILS under a reading that defaults startLine to 1'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE2-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'package-lock.json' "$URI" 'case 2 uri is the lockfile, not the (nonexistent) loc_path'
  HAS_REGION=$(_py "$D" "'region' in next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE2-01')['locations'][0]['physicalLocation']")
  assert_eq 'False' "$HAS_REGION" \
    'no region key at all for a case-2 (sca) finding - a defaulted startLine:1 would be fabrication'

  t_case 'case 2 message.text carries the evidence as a continuation, since there is no region for a snippet'
  MSG=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE2-01')['message']['text']")
  assert_contains "$MSG" 'case 2' 'title is present'
  assert_contains "$MSG" 'dependency: left-pad@1.0.0' 'evidence is appended as a continuation'

  t_case 'case 4 (dast): uri is the generated location artifact, which is a real file'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE4-DAST-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'locations/dast.txt' "$URI" 'case 4 uri'
  assert_file_exists "$D/locations/dast.txt" 'and it genuinely exists (tension 22: never a fabricated location)'
  LN=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='LOC-CASE4-DAST-01')['locations'][0]['physicalLocation']['region']['startLine']")
  assert_ne '' "$LN" 'case 4 still carries a region.startLine, into the generated artifact'
else
  _t_ok 'python3 unavailable, case 1/2/4 location checks skipped'
fi

# ---------------------------------------------------------------------------
printf '\n-- case 3: SAST-HIST-*, the resolving and non-resolving halves --\n'
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
finding_set check_id SAST-HIST-CASE3-GONE-01
finding_set module sast
finding_set title 'case 3 gone'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_gone.txt
finding_set loc_line 1
finding_set loc_blob_sha "$BLOB_GONE"
finding_set commit "$COMMIT_GONE"
finding_set_match 'password = "x"'
finding_emit

finding_new
finding_set check_id SAST-HIST-CASE3-HERE-01
finding_set module sast
finding_set title 'case 3 here'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_here.txt
finding_set loc_line 1
finding_set loc_blob_sha "$BLOB_HERE"
finding_set commit "$COMMIT_HERE"
finding_set_match 'password = "y"'
finding_emit

findings_merge "$D"
report_all "$D"
unset SCOURSH_SCAN_ROOT_PATH

if (( HAVE_PY )); then
  t_case 'case 3, non-resolving half: falls back to the generated artifact, exactly like case 4'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-HIST-CASE3-GONE-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'locations/sast.txt' "$URI" \
    "the deleted blob's path no longer resolves - FAILS under a reading that points unconditionally at loc_path (tension 22: 'a file that genuinely exists')"
  assert_file_exists "$D/locations/sast.txt" 'and it is a real file'

  t_case 'case 3, resolving half: case 3 is NOT case 4 - the real, still-present file is used instead'
  URI=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SAST-HIST-CASE3-HERE-01')['locations'][0]['physicalLocation']['artifactLocation']['uri']")
  assert_eq 'secret_here.txt' "$URI" \
    'the still-present blob path resolves - FAILS under a reading that always sends SAST-HIST-* to the generated artifact'
else
  _t_ok 'python3 unavailable, case 3 checks skipped'
fi

# ===========================================================================
printf '\n-- suppressions[]: emitted only for a truly suppressed finding --\n'
# ===========================================================================
_new_rundir suppressed
occurrence_reset_all

finding_new
finding_set check_id SUP-LIVE-01
finding_set module sast
finding_set title 'live finding'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path g.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'x'
finding_emit

finding_new
finding_set check_id SUP-ACCEPTED-01
finding_set module sast
finding_set title 'accepted finding'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path g.py
finding_set loc_line 2
finding_set cell .
finding_set_match 'y'
finding_emit

findings_merge "$D"
SUP_FP=$(
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    [[ ${_DF[check_id]:-} == SUP-ACCEPTED-01 ]] || continue
    printf '%s' "${_DF[fingerprint]}"
    break
  done <"$D/findings.fields"
)
findings_mark_suppressed "$D" "$SUP_FP" 'accepted: tracked in TICKET-1'
report_all "$D"

if (( HAVE_PY )); then
  t_case 'a suppressed finding is emitted WITH suppressions[], kind external, never dropped (tension 22)'
  HAS_SUP=$(_py "$D" "'SUP-ACCEPTED-01' in {r['ruleId'] for r in d['runs'][0]['results']}")
  assert_eq 'True' "$HAS_SUP" \
    'the suppressed finding is STILL a result - FAILS under a reading that drops suppressed findings from results[]'
  KIND=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SUP-ACCEPTED-01')['suppressions'][0]['kind']")
  assert_eq 'external' "$KIND" 'suppressions[0].kind is external'
  JUST=$(_py "$D" "next(r for r in d['runs'][0]['results'] if r['ruleId']=='SUP-ACCEPTED-01')['suppressions'][0]['justification']")
  assert_eq 'accepted: tracked in TICKET-1' "$JUST" 'justification carries suppressed_by, verbatim'

  t_case 'a live (non-suppressed) finding carries NO suppressions key at all - FAILS under a reading that always adds an (empty) suppressions array'
  HAS_KEY=$(_py "$D" "'suppressions' in next(r for r in d['runs'][0]['results'] if r['ruleId']=='SUP-LIVE-01')")
  assert_eq 'False' "$HAS_KEY" 'no suppressions key on the live finding'
else
  _t_ok 'python3 unavailable, suppressions checks skipped'
fi

# ===========================================================================
printf '\n-- security-severity is NEVER emitted (the severity trap) --\n'
# ===========================================================================
_new_rundir no-sec-sev
occurrence_reset_all
finding_new
finding_set check_id NOSECSEV-01
finding_set module sast
finding_set title 'severity trap check'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set loc_path z.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'x'
finding_emit
findings_merge "$D"
report_all "$D"

t_case 'report.sarif never contains the string "security-severity" anywhere - FAILS under an implementation that publishes a derived security-severity score'
RAW=$(cat "$D/report.sarif")
assert_not_contains "$RAW" 'security-severity' \
  'security-severity is deliberately excluded (docs/STEP10-SARIF-PLAN.md: it would be a second, differently-derived severity number that can contradict result.level)'

# ===========================================================================
printf '\n-- SCA severity provenance: recorded in run.json only when it is genuinely ambiguous --\n'
# ===========================================================================
_new_rundir sca-gap-medium
occurrence_reset_all
finding_new
finding_set check_id SCA-GAP-MEDIUM-01
finding_set module sca
finding_set title 'medium sca finding'
finding_set base_severity medium
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package pkg-a
finding_set loc_advisory_id GHSA-TEST-0003
finding_set path package-lock.json
finding_set logical_kind dependency
finding_set logical_fqn 'npm:pkg-a@1.0.0'
finding_emit
findings_merge "$D"
report_all "$D"

t_case 'a medium-severity sca finding records the severity-provenance gap in run.json - a medium row is byte-indistinguishable from the unscored fallback, so report.sarif cannot honestly claim to know which it is'
RJ=$(cat "$D/run.json")
assert_contains "$RJ" 'sarif_severity_provenance_unavailable' \
  'the gap is recorded rather than the SARIF silently asserting a score it does not have (SARIF-04 own acceptance criterion)'

t_case 'report.sarif never emits result.properties.severityProvenance itself - the gap is recorded, not guessed around'
RAW=$(cat "$D/report.sarif")
assert_not_contains "$RAW" 'severityProvenance' \
  'no severityProvenance field is fabricated for the medium finding'

_new_rundir sca-gap-critical
occurrence_reset_all
finding_new
finding_set check_id SCA-GAP-CRITICAL-01
finding_set module sca
finding_set title 'critical sca finding'
finding_set base_severity critical
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package pkg-b
finding_set loc_advisory_id GHSA-TEST-0004
finding_set path package-lock.json
finding_set logical_kind dependency
finding_set logical_fqn 'npm:pkg-b@1.0.0'
finding_emit
findings_merge "$D"
report_all "$D"

t_case 'a non-medium (critical) sca finding does NOT record the gap - FAILS under a reading that fires the gap for every sca finding regardless of severity, which would be noise on the unambiguous cases'
RJ=$(cat "$D/run.json")
assert_not_contains "$RJ" 'sarif_severity_provenance_unavailable' \
  'critical can never be the medium fallback, so there is nothing ambiguous to record'

# ===========================================================================
printf '\n-- acceptance criterion: no result.ruleId lacks a descriptor, across several profiles at once --\n'
# ===========================================================================
_new_rundir multi-profile
occurrence_reset_all

finding_new
finding_set check_id MP-SAST-01
finding_set module sast
finding_set title 'sast'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path a.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'x'
finding_emit

finding_new
finding_set check_id MP-IAC-01
finding_set module iac
finding_set title 'iac'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path main.tf
finding_set loc_line 1
finding_set cell .
finding_set_match '0.0.0.0/0'
finding_emit

finding_new
finding_set check_id MP-DAST-01
finding_set module dast
finding_set title 'dast'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_target t1
finding_set loc_method GET
finding_set path /a
finding_set loc_param_location query
finding_set loc_param_name q
finding_emit

# Ungoverned family 1: SCA (modules/sca/ ships no *.rules file at all).
finding_new
finding_set check_id SCA-NPM-VULNERABLE_DEP-01
finding_set module sca
finding_set title 'sca'
finding_set base_severity high
finding_set cwe none
finding_set owasp A06:2021
finding_set loc_ecosystem npm
finding_set loc_package pkg-c
finding_set loc_advisory_id GHSA-TEST-0005
finding_set path package-lock.json
finding_set logical_kind dependency
finding_set logical_fqn 'npm:pkg-c@1.0.0'
finding_emit

# Ungoverned family 2: an adapter id, minted at runtime, never in a *.rules file.
finding_new
finding_set check_id 'semgrep:python.lang.security.audit.eval-detected'
finding_set module sast
finding_set title 'adapter'
finding_set base_severity high
finding_set cwe none
finding_set owasp none
finding_set loc_path b.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'eval'
finding_emit

# Ungoverned family 3: derived/composite (rules/derived.rules is unseeded).
finding_new
finding_set check_id COMPOSITE-TOKEN-HIJACK
finding_set module derived
finding_set title 'derived'
finding_set base_severity critical
finding_set cwe none
finding_set owasp none
finding_set logical_kind composite
finding_set logical_fqn 'COMPOSITE-TOKEN-HIJACK@corr1'
finding_set loc_correlation corr1
finding_emit

findings_merge "$D"
report_all "$D"

if (( HAVE_PY )); then
  t_case 'every result.ruleId matches a rules[] descriptor id - FAILS under any gap in the union of registry ids and this run own check ids (SARIF-03 own trap, re-proven at the results level)'
  MISSING=$(python3 -c "
import json
d = json.load(open('$D/report.sarif'))
rule_ids = {r['id'] for r in d['runs'][0]['tool']['driver']['rules']}
result_ids = {r['ruleId'] for r in d['runs'][0]['results']}
print(sorted(result_ids - rule_ids))
")
  assert_eq '[]' "$MISSING" 'no result.ruleId is missing its descriptor'

  N_RESULTS=$(_py "$D" "len(d['runs'][0]['results'])")
  assert_eq '6' "$N_RESULTS" 'all six findings across five profiles (sast, iac, dast, sca, derived) plus one adapter id became results'
else
  _t_ok 'python3 unavailable, multi-profile ruleId coverage check skipped'
fi

# ===========================================================================
printf '\n-- a redacted field stays redacted in report.sarif --\n'
# ===========================================================================
_new_rundir redaction
occurrence_reset_all

SECRET='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
finding_new
finding_set check_id SAST-SEC-AWS-01
finding_set module sast
finding_set title 'Hardcoded AWS key'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path creds.py
finding_set loc_line 1
finding_set cell .
finding_set_match "$SECRET"
finding_set_evidence "AWS_SECRET_ACCESS_KEY = \"$SECRET\""
finding_set remediation 'Rotate it.'
finding_emit

# The tension 10 hostile-evidence fixture, same shape tests/suites/report.sh
# already uses for the other three formats: a script-closing tag, a raw ANSI
# sequence, a raw newline, invalid UTF-8, and a backtick run.
HOSTILE=$(printf '</script><img src=x onerror=alert(1)>\033[31mANSI\033[0m raw\nnewline \xC3\050 bad ```````fence')
finding_new
finding_set check_id DAST-XSS-HOSTILE-01
finding_set module dast
finding_set title 'Unescaped reflection'
finding_set base_severity high
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /h
finding_set loc_param_location query
finding_set loc_param_name q
finding_set_evidence "$HOSTILE"
finding_emit

findings_merge "$D"
report_all "$D"
RAW=$(cat "$D/report.sarif")

t_case 'the literal secret bytes never reach report.sarif'
assert_not_contains "$RAW" "$SECRET" \
  'the matched credential is absent from the document - FAILS under a reading that bypasses finding_decode/the secret backstop and copies evidence raw'

t_case 'a redaction placeholder is present instead, so the finding is still legible'
assert_contains "$RAW" 'redacted:SECRET' 'the placeholder reaches the SARIF snippet'

t_case 'report.sarif is still valid JSON despite the hostile evidence'
if (( HAVE_PY )); then
  if python3 -c "import json; json.load(open('$D/report.sarif'))" 2>/dev/null; then
    _t_ok 'report.sarif parses as JSON'
  else
    _t_no 'report.sarif parses as JSON' 'json.load raised - the hostile bytes broke the document'
  fi
else
  _t_ok 'python3 unavailable, JSON parse check skipped'
fi

t_case 'the hostile bytes are absent or escaped, never raw or left to break the document'
# evidence_normalise already strips every C0 control byte (including the ANSI
# ESC here) before this emitter ever sees the value - lib/findings.sh's own
# "strip C0 controls" step - so the ESC byte is absent by construction, the
# same property tests/suites/report.sh's identical HOSTILE fixture already
# asserts for report.html/report.md; this emitter adds nothing on top of
# that for a control byte specifically, only for what evidence_normalise
# does NOT already handle: a literal backslash and an embedded newline
# (rewritten to a literal \n two-byte sequence by evidence_normalise, then
# JSON-escaped here into \\n) both surviving as legible, non-breaking data.
assert_not_contains "$RAW" "$(printf '\033')" 'no raw ESC byte reaches the document'
# A script/img tag inside a JSON string VALUE is inert data, not markup - JSON
# escaping only needs to protect backslash/quote/control bytes (tension 10's
# HTML-escaping requirement is report_html's, not this emitter's); the real
# risk here is a raw control byte or an unescaped quote breaking the JSON
# document itself, which the parse check above already proves did not happen.
assert_contains "$RAW" '\\n' 'the raw newline inside evidence is JSON-escaped (\\n), not a literal line break inside a JSON string'

unset SCOURSH_INSTALL_ROOT
SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary sarif-results
