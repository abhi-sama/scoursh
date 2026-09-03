#!/usr/bin/env bash
# tests/suites/sarif-schema.sh - docs/STEP10-SARIF-PLAN.md SARIF-05: make the
# docs/DESIGN.md §12 "validates JSON/SARIF schema" promise real for SARIF.
#
# This is a separate suite from tests/suites/sarif-locations.sh,
# tests/suites/sarif-rules.sh and tests/suites/sarif-results.sh deliberately:
# SARIF-05 exists specifically because "a ticket that ships an emitter and
# its own validator tends to ship a validator that agrees with the emitter"
# (AGENTS.md's round-5 lesson), so this suite is adversarial toward
# report_sarif's output rather than a restatement of what SARIF-04 already
# asserts about individual fields.
#
# Covers this ticket's acceptance criteria:
#   - report.sarif validates against the vendored OASIS SARIF 2.1.0 schema
#     (tests/fixtures/sarif/sarif-schema-2.1.0.json), over a fixture run that
#     deliberately exercises every one of docs/FOUNDATION.md tension 22's
#     four location-table cases in ONE document, plus both a registry-backed
#     and a synthesised rule descriptor, a suppressed finding, and the
#     tension-10 hostile-evidence fixture - a trivial one-result document
#     would validate under any reading, including a validator that does
#     nothing, so the fixture is built rich enough that a real defect in any
#     of those shapes would have failed it.
#   - tension 22's own strengthened extra condition: every result's
#     locations[0].physicalLocation.artifactLocation.uri is non-empty and
#     resolves to a real file under the run directory or the scanned tree -
#     asserted filesystem-backed (test -e / os.path.exists), never by
#     re-trusting the emitter's own string, which is the "the assertion
#     tension 22 says the validation must make" it names explicitly.
#   - the validator REJECTS a deliberately malformed document (several: a
#     missing required key, a property additionalProperties:false forbids,
#     an invalid `level` enum value, and a location pointing at a path that
#     does not exist) - proving the validation is demonstrably non-vacuous,
#     and specifically that a well-formedness-only check (plain `json.load`)
#     would have passed every one of them.
#   - tests/suites/report.sh's skip-as-pass defect is fixed separately, in
#     that file - see its own header for the shape used there.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
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

SCHEMA=$ROOT/tests/fixtures/sarif/sarif-schema-2.1.0.json
VALIDATOR=$ROOT/tests/lib/sarif_validate.py

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

if (( ! HAVE_PY )); then
  printf '\n== SARIF schema validation (needs python3) ==\n'
  printf '  NOTICE python3 is not on PATH: this whole suite did NOT run - report.sarif was never checked against the vendored schema, and tension 22'"'"'s location-existence condition was never asserted.  This is a SKIP, not a pass.\n'
  t_summary sarif-schema
  exit $?
fi

assert_file_exists "$SCHEMA" 'the vendored OASIS SARIF 2.1.0 schema is present'
assert_file_exists "$VALIDATOR" 'the validator script is present'

W=$SCOURSH_SCRATCH/sarif-schema-suite
rm -rf "$W"
mkdir -p "$W"

# The small fixture registry tests/suites/sarif-results.sh already uses:
# fast (avoids loading the real, full check registry on every run in this
# file), and it happens to give this suite exactly the split it needs for
# free - two ids ARE in it (one sast, one dast), everything else is not, so
# building "one registry-backed and one synthesised descriptor" needs no
# special-casing beyond which check_id each finding uses.
export SCOURSH_INSTALL_ROOT=$ROOT/tests/fixtures/checks-registry

# The tension 10 hostile-evidence fixture (tests/suites/report.sh's own),
# reused here so the schema/well-formedness proof is made against genuinely
# adversarial bytes, not just plain ASCII a naive escaper would also survive.
HOSTILE=$(printf '</script><img src=x onerror=alert(1)>\033[31mANSI\033[0m raw\nnewline \xC3\050 bad ```````fence')

# ===========================================================================
printf '\n-- building a real scan root: every location-table case needs a real file to test against --\n'
# ===========================================================================
REPO=$W/repo
rm -rf "$REPO"
mkdir -p "$REPO"
git -C "$REPO" init -q
git -C "$REPO" config user.email 'test@example.com'
git -C "$REPO" config user.name 'test'

printf 'def f():\n    pass\n' >"$REPO/demo.py"
printf 'resource "x" {}\n' >"$REPO/main.tf"
printf '{"lockfileVersion": 1}\n' >"$REPO/package-lock.json"
git -C "$REPO" add demo.py main.tf package-lock.json
git -C "$REPO" commit -q -m 'seed files for case 1 and case 2'

# case 3's own real filesystem test (report_locations' _locations_history_resolves):
# a secret that once existed and was removed (falls back to the generated
# artifact), and one that still exists (resolves to the real file).
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

SCOURSH_SCAN_ROOT_PATH=$(scan_root_of "$REPO")
export SCOURSH_SCAN_ROOT_PATH

# ===========================================================================
printf '\n-- one run, every case, both descriptor kinds, a suppression, hostile evidence --\n'
# ===========================================================================
D=$W/full
rm -rf "$D"
run_init "$D"
D=$SCOURSH_RUN_DIR
occurrence_reset_all

# case 1 (real working-tree file), registry-backed descriptor.
finding_new
finding_set check_id SAST-GEN-DEMO_QUICK-01
finding_set module sast
finding_set title 'Fixture quick rule fired'
finding_set base_severity high
finding_set cwe CWE-95
finding_set owasp A03:2021
finding_set confidence high
finding_set loc_path demo.py
finding_set loc_line 1
finding_set cell .
finding_set_match 'def f'
finding_set_evidence 'def f():'
finding_set remediation 'Fixture remediation.'
finding_emit

# A second registry-backed finding, dedicated to being suppressed below, so
# the suppression assertion cannot be satisfied by accident by the finding
# every other assertion in this file also inspects.
finding_new
finding_set check_id SAST-GEN-DEMO_FULL-01
finding_set module sast
finding_set title 'Fixture full-only rule fired'
finding_set base_severity low
finding_set cwe none
finding_set owasp none
finding_set loc_path demo.py
finding_set loc_line 2
finding_set cell .
finding_set_match 'pass'
finding_set_evidence 'pass'
finding_set remediation 'Fixture remediation.'
finding_emit

# case 1 (real working-tree file), synthesised descriptor (IAC-TF-* is not in
# the small fixture registry).
finding_new
finding_set check_id IAC-TF-OPEN_CIDR-01
finding_set module iac
finding_set title 'Open CIDR'
finding_set base_severity high
finding_set cwe CWE-284
finding_set owasp A01:2021
finding_set loc_path main.tf
finding_set loc_line 1
finding_set cell .
finding_set_match 'resource'
finding_emit

# case 2 (sca: `path` already names a real file), synthesised descriptor -
# modules/sca/ ships no *.rules file at all, by design.
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

# case 3a: SAST-HIST-*, loc_path still resolves - left pointing at the real
# file, no generated artifact.
finding_new
finding_set check_id SAST-HIST-SECRET-01
finding_set module sast
finding_set title 'Hardcoded secret (history, still present)'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_here.txt
finding_set loc_line 1
finding_set loc_blob_sha "$BLOB_HERE"
finding_set commit "$COMMIT_HERE"
finding_set_match 'password = "y"'
finding_emit

# case 3b: SAST-HIST-*, loc_path no longer resolves - falls back to the
# generated locations/sast.txt artifact.
finding_new
finding_set check_id SAST-HIST-SECRET-01
finding_set module sast
finding_set title 'Hardcoded secret (history, since removed)'
finding_set base_severity critical
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path secret_gone.txt
finding_set loc_line 1
finding_set loc_blob_sha "$BLOB_GONE"
finding_set commit "$COMMIT_GONE"
finding_set_match 'password = "x"'
finding_emit

# case 4 (dast/cloud/posture/derived: the generated locations/<module>.txt
# artifact, always). dast is registry-backed (in the small fixture pack);
# cloud, posture and derived are all synthesised (none has a registry - sca's
# reason for cloud/posture too, and derived/rules is deliberately unseeded,
# findings F5/F20). The dast finding carries the hostile-evidence fixture, so
# escaping is proven under real schema validation rather than only a
# string-containment assertion.
finding_new
finding_set check_id DAST-HDR-CSP-01
finding_set module dast
finding_set title 'Missing Content-Security-Policy'
finding_set base_severity high
finding_set cwe CWE-693
finding_set owasp A05:2021
finding_set loc_target t1
finding_set loc_method GET
finding_set path /users/9/p
finding_set loc_param_location query
finding_set loc_param_name q
finding_set_evidence "$HOSTILE"
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

# Suppress SAST-GEN-DEMO_FULL-01, to put suppressions[] on the wire.
SUPPRESSED_FP=''
while IFS= read -r _line; do
  finding_decode "$_line"
  [[ ${_DF[check_id]:-} == SAST-GEN-DEMO_FULL-01 ]] && { SUPPRESSED_FP=${_DF[fingerprint]}; break; }
done <"$D/findings.fields"
assert_ne '' "$SUPPRESSED_FP" 'found the finding to suppress before suppressing it (fixture sanity)'
findings_mark_suppressed "$D" "$SUPPRESSED_FP" 'accepted: fixture'

report_all "$D"
assert_file_exists "$D/report.sarif" 'report.sarif is written'

# ===========================================================================
printf '\n-- the real, positive document: schema-valid AND every location resolves --\n'
# ===========================================================================
ERR=$W/errors-full.txt
t_case 'report.sarif validates against the vendored OASIS SARIF 2.1.0 schema, including tension 22'"'"'s location condition'
if python3 "$VALIDATOR" "$SCHEMA" "$D/report.sarif" --check-locations "$D" "$REPO" 2>"$ERR"; then
  _t_ok 'a fixture run covering all four location-table cases, both descriptor kinds, a suppression and hostile evidence validates cleanly'
else
  _t_no 'schema and location validation' "$(cat "$ERR")"
fi

t_case 'a schema-only pass (no --check-locations) is not what makes the above true'
if python3 "$VALIDATOR" "$SCHEMA" "$D/report.sarif" >/dev/null 2>&1; then
  _t_ok 'schema-only validation also passes on the real document (a sanity check on the fixture, not the property under test)'
else
  _t_no 'schema-only validation of the real document' 'expected pass'
fi

# ===========================================================================
printf '\n-- the validator REJECTS a deliberately malformed document (non-vacuous) --\n'
# ===========================================================================
# Every mutation below starts from the real, schema-valid report.sarif above
# and breaks exactly one thing. Each is still well-formed JSON - proven
# explicitly for the first one - which is the whole point: a validator that
# only parses JSON (this project's OWN pre-SARIF-05 defect, and every naive
# reading of "validates JSON/SARIF schema") passes every single one of these,
# and only real schema validation catches them.

_mutate() {                        # out.json python-expr-mutating-d
  python3 - "$D/report.sarif" "$1" "$2" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
exec(sys.argv[3])
json.dump(d, open(sys.argv[2], 'w'))
PYEOF
}

t_case 'a missing required top-level key (version) is rejected'
BAD1=$W/bad-missing-version.json
_mutate "$BAD1" "del d['version']"
if python3 -c "import json; json.load(open('$BAD1'))" >/dev/null 2>&1; then
  _t_ok 'the mutated document is still well-formed JSON - a well-formedness-only check would have passed it'
else
  _t_no 'well-formedness of the mutation fixture' 'expected the mutation to still be valid JSON, so the failure below is attributable to schema validation alone'
fi
if python3 "$VALIDATOR" "$SCHEMA" "$BAD1" >"$W/e1.txt" 2>&1; then
  _t_no 'validator rejects a document missing the required "version" key' 'validator exited 0'
else
  assert_contains "$(cat "$W/e1.txt")" "missing required property 'version'" \
    'and says specifically what is missing'
fi

t_case 'an additional top-level property (additionalProperties:false at the document root) is rejected'
BAD2=$W/bad-extra-prop.json
_mutate "$BAD2" "d['notPartOfSarif'] = True"
if python3 "$VALIDATOR" "$SCHEMA" "$BAD2" >"$W/e2.txt" 2>&1; then
  _t_no 'validator rejects an unexpected top-level property' 'validator exited 0'
else
  assert_contains "$(cat "$W/e2.txt")" "additional property 'notPartOfSarif' is not allowed" \
    'and names the offending key'
fi

t_case 'an out-of-enum result.level value is rejected (SARIF has no "critical" level)'
BAD3=$W/bad-level.json
_mutate "$BAD3" "d['runs'][0]['results'][0]['level'] = 'critical'"
if python3 "$VALIDATOR" "$SCHEMA" "$BAD3" >"$W/e3.txt" 2>&1; then
  _t_no 'validator rejects level:"critical"' \
    'validator exited 0 - FAILS under a validator that only checks JSON well-formedness, which "critical" as a bare string trivially satisfies'
else
  assert_contains "$(cat "$W/e3.txt")" 'is not one of' 'and reports it as an enum violation'
fi

t_case 'a location pointing at a path that exists nowhere is rejected by --check-locations, and ONLY by it'
BAD4=$W/bad-location.json
_mutate "$BAD4" "d['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'this/file/does/not/exist.py'"
if python3 "$VALIDATOR" "$SCHEMA" "$BAD4" >/dev/null 2>&1; then
  _t_ok 'schema validation ALONE still passes - a syntactically fine but non-existent path is still type:string, exactly tension 22'"'"'s own point that a schema pass alone is insufficient'
else
  _t_no 'schema-only validation of the location mutation' 'expected schema-only to still pass, since nothing about the JSON shape changed'
fi
if python3 "$VALIDATOR" "$SCHEMA" "$BAD4" --check-locations "$D" "$REPO" >"$W/e4.txt" 2>&1; then
  _t_no 'validator rejects a uri resolving to a real file with --check-locations' 'validator exited 0'
else
  assert_contains "$(cat "$W/e4.txt")" 'LOCATION' 'and the failure is attributed to the LOCATION check, not SCHEMA'
  assert_contains "$(cat "$W/e4.txt")" 'resolves under neither' 'with the specific reason'
fi

t_case 'an empty ruleId is schema-legal (the schema declares no minLength on it) - the discriminating fixture for THIS is the rich, multi-case document above, not this document alone'
BAD5=$W/empty-ruleid.json
_mutate "$BAD5" "d['runs'][0]['results'][0]['ruleId'] = ''"
if python3 "$VALIDATOR" "$SCHEMA" "$BAD5" >"$W/e5.txt" 2>&1; then
  _t_ok 'the vendored schema itself has no opinion on an empty ruleId - the reason a schema pass alone is not the whole story tension 22 requires, and the reason "no orphan ruleId" is asserted separately (tests/suites/sarif-results.sh) rather than by this validator'
else
  _t_no 'schema validation of an empty ruleId' "unexpectedly rejected: $(cat "$W/e5.txt")"
fi

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID='' SCOURSH_SCAN_ROOT_PATH=''

t_summary sarif-schema
