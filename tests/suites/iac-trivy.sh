#!/usr/bin/env bash
# tests/suites/iac-trivy.sh - modules/iac/adapters/trivy/{adapter.sh,
# vendor.sh} and its wiring into modules/iac/run.sh (docs/DESIGN.md §6.6's
# "same pattern as §6.4" note, §13 step 9; docs/ADAPTERS.md; this ticket,
# the second concrete adapter and the first for a module other than sast).
#
# Modeled directly on tests/suites/sast-semgrep.sh's own structure and
# sections, so a reviewer already familiar with that suite recognises the
# shape immediately; the differences are exactly the differences between
# the two engines' own JSON shapes and adapter contracts (documented at
# each divergence point below).
#
# Covers this ticket's acceptance criteria:
#   - the three-function contract (trivy_detect/trivy_run/trivy_normalize)
#     against a small, purpose-built JSON parser proven directly (section
#     A) - trivy's JSON nests findings two levels deep
#     (Results[].Misconfigurations[]), unlike semgrep's single flat
#     "results" array, so section A also proves the nested split does not
#     desynchronise on either level
#   - trivy_detect requires ONLY bin/trivy (no rules/), unlike
#     semgrep_detect - docs/ADAPTERS.md §4's "self-contained binary" case,
#     because trivy's misconfiguration checks are compiled into the binary
#   - graceful degradation: --use-engines with the adapter genuinely absent
#     from disk is a clean coverage_reduction (reason=engine_not_vendored),
#     never an error, and a scan.sh iac run behaves identically whether or
#     not --use-engines is given, as long as nothing is vendored (section B)
#   - the round-trip requirement (docs/ADAPTERS.md §8): a normalized trivy
#     finding survives fingerprinting, redaction and every report format
#     identically to a native finding, exercised end to end through a REAL
#     `scan.sh iac --use-engines` subprocess against a FAKE vendored
#     "trivy" (section C)
#   - merge/dedup against native modules/iac/*.rules findings (this
#     ticket's scope item 3): section C's fixture is engineered so a
#     native IAC-TF-OPEN_CIDR-01 finding and a trivy:AVD-AWS-0107 finding
#     land on the EXACT SAME file and line (so their match_digest is
#     identical) - proving the two remain distinct findings rather than
#     accidentally collapsing, because their check_id namespaces differ
#     (docs/ADAPTERS.md §6 / rules/RULE-FORMAT.md §9.1.1a), not because
#     their text happened to differ
#   - a boundary/security check: a trivy result reporting a Target outside
#     the scan root is rejected, never trusted as a finding's location
#     (section A)
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: lib/report.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/lib/report.sh"
# shellcheck source=modules/iac/parse.sh
source "$ROOT/modules/iac/parse.sh"
# shellcheck source=modules/iac/adapters/trivy/adapter.sh
source "$ROOT/modules/iac/adapters/trivy/adapter.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/iac-trivy-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- section A: the three-function contract, in-process --\n'
# =============================================================================
SCANROOT=$W/scanroot
rm -rf "$SCANROOT"
mkdir -p "$SCANROOT/infra"
cat >"$SCANROOT/infra/main.yaml" <<'CFN'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Name: app
          Image: registry.example.com/app:latest
          Privileged: true
CFN
PRIV_LINE=$(grep -n 'Privileged: true' "$SCANROOT/infra/main.yaml" | head -n1 | cut -d: -f1)

t_case 'trivy_detect: absent bin/ -> 1'
TRIVY_ADAPTER_DIR=$W/no-bin
rm -rf "$TRIVY_ADAPTER_DIR"
mkdir -p "$TRIVY_ADAPTER_DIR"
TRIVY_BIN=$TRIVY_ADAPTER_DIR/bin/trivy
assert_status 1 'no bin/trivy at all: detect fails' trivy_detect

t_case 'trivy_detect: bin/trivy present but not executable -> 1'
mkdir -p "$TRIVY_ADAPTER_DIR/bin"
: >"$TRIVY_ADAPTER_DIR/bin/trivy"
chmod -x "$TRIVY_ADAPTER_DIR/bin/trivy"
assert_status 1 'a non-executable bin/trivy still fails detect' trivy_detect

t_case 'trivy_detect: bin/trivy executable -> 0, with NO rules/ present anywhere'
chmod +x "$TRIVY_ADAPTER_DIR/bin/trivy"
assert_status 0 'unlike semgrep_detect, trivy_detect never checks for a rules/ dir - fails under a reading that copied semgrep_detect verbatim' trivy_detect
assert_file_absent "$TRIVY_ADAPTER_DIR/rules" \
  'sanity: this test suite never created a rules/ dir for this adapter at all'

t_case '_trivy_split_results / _trivy_split_misconfigs: two targets, each with one misconfiguration, messages containing the literal words "Results" and "Misconfigurations" do not desynchronise either level of the split'
cat >"$W/two-results.json" <<'JSON'
{"Results":[{"Target":"a.tf","Class":"config","Type":"terraform","Misconfigurations":[{"ID":"AVD-AWS-0001","Title":"t1","Message":"talks about Results inline, a comma, and a brace {","Severity":"HIGH","Status":"FAIL","Resolution":"fix1","CauseMetadata":{"Resource":"r1","StartLine":1}}]},{"Target":"b.tf","Class":"config","Type":"terraform","Misconfigurations":[{"ID":"AVD-AWS-0002","Title":"t2","Message":"second, mentions Misconfigurations too, with a ] bracket","Severity":"MEDIUM","Status":"FAIL","Resolution":"fix2","CauseMetadata":{"Resource":"r2","StartLine":2}}]}]}
JSON
_trivy_split_results "$W/two-results.json" >"$W/split-results.out"
assert_eq 2 "$(wc -l <"$W/split-results.out" | tr -d ' ')" \
  'exactly two Result objects were split out at the top level, despite messages containing "Results", "Misconfigurations", a brace and a bracket'
FIRST_RESULT=$(sed -n '1p' "$W/split-results.out")
assert_eq 'a.tf' "$(_trivy_json_string_field "$FIRST_RESULT" Target)" 'first Result Target extracted correctly'
_trivy_split_misconfigs "$FIRST_RESULT" >"$W/split-misconfigs-a.out"
assert_eq 1 "$(wc -l <"$W/split-misconfigs-a.out" | tr -d ' ')" \
  'exactly one Misconfiguration object was split out of the first target'
SECOND_RESULT=$(sed -n '2p' "$W/split-results.out")
_trivy_split_misconfigs "$SECOND_RESULT" >"$W/split-misconfigs-b.out"
assert_eq 1 "$(wc -l <"$W/split-misconfigs-b.out" | tr -d ' ')" \
  'exactly one Misconfiguration object was split out of the second target too'

t_case '_trivy_json_string_field / _trivy_json_object_field / _trivy_json_number_field round-trip'
OBJ='{"Type":"CloudFormation Security Check","ID":"AVD-AWS-0107","Title":"An ingress security group rule allows traffic from /0","Message":"Security group rule allows ingress from public internet.","Severity":"CRITICAL","Status":"FAIL","Resolution":"Set a more restrictive cidr range","CauseMetadata":{"Resource":"aws_security_group_rule.example","Provider":"AWS","Service":"ec2","StartLine":4,"EndLine":8}}'
assert_eq 'AVD-AWS-0107' "$(_trivy_json_string_field "$OBJ" ID)" 'ID extracted correctly'
assert_eq 'Security group rule allows ingress from public internet.' "$(_trivy_json_string_field "$OBJ" Message)" 'Message extracted correctly'
CAUSE_OBJ=$(_trivy_json_object_field "$OBJ" CauseMetadata)
assert_eq 4 "$(_trivy_json_number_field "$CAUSE_OBJ" StartLine)" 'CauseMetadata.StartLine extracted correctly, not confused with EndLine'
assert_eq 'aws_security_group_rule.example' "$(_trivy_json_string_field "$CAUSE_OBJ" Resource)" 'CauseMetadata.Resource extracted correctly'

t_case '_trivy_json_string_field: JSON escapes are decoded'
ESC_OBJ='{"Message":"quote \" backslash \\ tab\tend"}'
assert_eq 'quote " backslash \ tab	end' "$(_trivy_json_string_field "$ESC_OBJ" Message)" \
  'standard JSON escapes (\", \\\\, \t) decode to their real characters, not left literal'

t_case '_trivy_severity_map: CRITICAL maps to critical, unlike semgrep_severity_map which never emits critical'
assert_eq critical "$(_trivy_severity_map CRITICAL)" \
  'fails under a reading that copied _semgrep_severity_map verbatim and capped this adapter at high - modules/iac/*.rules native packs already author severity: critical directly (e.g. IAC-TF-PUBLIC_ACL-01), so withholding it here would be an inconsistency invented for this adapter alone'
assert_eq high "$(_trivy_severity_map HIGH)" 'HIGH maps to high'
assert_eq medium "$(_trivy_severity_map MEDIUM)" 'MEDIUM maps to medium'
assert_eq low "$(_trivy_severity_map LOW)" 'LOW maps to low'
assert_eq medium "$(_trivy_severity_map UNKNOWN)" 'an unrecognised/UNKNOWN severity falls back to medium, never a crash'

t_case 'trivy_normalize: full round-trip through finding_emit for a real fixture on disk, a CloudFormation shape no native modules/iac/*.rules pack covers yet'
SCOURSH_RUN_DIR=$W/run-a
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
_SCAN_RESOLVED_PATH=$SCANROOT
SCOURSH_PATH_ROOT=.
cat >"$W/one-result.json" <<JSON
{"Results":[{"Target":"infra/main.yaml","Class":"config","Type":"cloudformation","Misconfigurations":[{"Type":"CloudFormation Security Check","ID":"AVD-AWS-0102","Title":"ECS Task Definition container running in privileged mode","Message":"Container is privileged","Severity":"CRITICAL","Status":"FAIL","Resolution":"Remove the Privileged property or set it to false","CauseMetadata":{"Resource":"TaskDefinition","Provider":"AWS","Service":"ecs","StartLine":$PRIV_LINE,"EndLine":$PRIV_LINE}}]}]}
JSON
trivy_normalize "$W/one-result.json"
SHARD=$(cat "$SCOURSH_RUN_DIR"/shards/*.jsonl 2>/dev/null)
assert_contains "$SHARD" '"check_id":"trivy:AVD-AWS-0102"' \
  'the finding check_id is namespaced trivy:<AVD ID> per rules/RULE-FORMAT.md §9.1.1a'
assert_contains "$SHARD" '"module":"iac"' 'the finding module is iac, not sast'
assert_contains "$SHARD" '"base_severity":"critical"' 'CRITICAL round-trips to base_severity critical'
EXPECTED_EVIDENCE=$(sed -n "${PRIV_LINE}p" "$SCANROOT/infra/main.yaml")
assert_contains "$SHARD" "$(json_string "$EXPECTED_EVIDENCE")" \
  'evidence is the REAL line read from the file on disk (its actual content, JSON-escaped by the same json_string helper the report emitters use), not trivy'"'"'s own reported Message - proves the "re-derive match_digest from the file at the reported path/line" requirement (docs/FOUNDATION.md tension 5/11), mirroring modules/sast/adapters/semgrep/adapter.sh'"'"'s identical proof for semgrep'
assert_contains "$SHARD" '"cwe":"none"' 'trivy misconfiguration results carry no CWE - normalised to the literal "none", same convention iac_scan_file'"'"'s own truncated-match finding already uses'
assert_contains "$SHARD" '"owasp":"none"' 'same for owasp'

t_case 'trivy_normalize: a reported Target outside the scan root is rejected, never trusted as a finding location'
SCOURSH_RUN_DIR=$W/run-b
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
cat >"$W/evil-path.json" <<'JSON'
{"Results":[{"Target":"../../../../etc/passwd","Class":"config","Type":"terraform","Misconfigurations":[{"ID":"AVD-GENERIC-0001","Title":"leak","Message":"leak","Severity":"HIGH","Status":"FAIL","Resolution":"fix","CauseMetadata":{"Resource":"x","StartLine":1}}]}]}
JSON
trivy_normalize "$W/evil-path.json"
SHARD_COUNT=0
for _f in "$SCOURSH_RUN_DIR"/shards/*.jsonl; do
  [[ -e $_f ]] || continue
  SHARD_COUNT=$(( SHARD_COUNT + $(wc -l <"$_f" | tr -d ' ') ))
done
assert_eq 0 "$SHARD_COUNT" \
  'zero findings were emitted for the traversal-Target result - fails under "trust whatever Target trivy reports"'
assert_contains "$(cat "$SCOURSH_RUN_DIR/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_reported_path_outside_scan_root' \
  'the rejection is recorded as a coverage_reduction, not silently dropped'

unset SCOURSH_RUN_DIR _SCAN_RESOLVED_PATH SCOURSH_PATH_ROOT

# =============================================================================
printf -- '\n-- section B: graceful degradation, real scan.sh subprocess, adapter absent --\n'
# =============================================================================
ROOT_NO_ADAPTER=$W/root-no-adapter
rm -rf "$ROOT_NO_ADAPTER"
mkdir -p "$ROOT_NO_ADAPTER/config" "$ROOT_NO_ADAPTER/modules/iac" "$ROOT_NO_ADAPTER/modules/sast"
printf 'id: scanner\n' >"$ROOT_NO_ADAPTER/config/scanner.conf"
cp "$ROOT/modules/iac/run.sh" "$ROOT/modules/iac/parse.sh" "$ROOT_NO_ADAPTER/modules/iac/"
cp "$ROOT/modules/sast/engine.sh" "$ROOT_NO_ADAPTER/modules/sast/engine.sh"
ROOT_NO_ADAPTER=$(cd -- "$ROOT_NO_ADAPTER" && pwd -P)
FIXTURES=$ROOT/tests/fixtures/iac-scope

t_case 'without --use-engines: no engine coverage_reduction fact at all - true "behaves identically to today"'
rm -rf "$W/run-no-flag"
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" iac --path "$FIXTURES" \
  --out "$W/run-no-flag" >/dev/null 2>&1
assert_not_contains "$(cat "$W/run-no-flag/meta/coverage_reduction" 2>/dev/null)" 'engine=trivy' \
  'no --use-engines: not even a coverage_reduction mentions the engine - it is never even consulted'

t_case '--use-engines with the adapter genuinely absent from disk: clean coverage_reduction, exit code unaffected'
rm -rf "$W/run-flag-no-adapter"
rc=0
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" iac --path "$FIXTURES" \
  --use-engines --out "$W/run-flag-no-adapter" >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" \
  '--use-engines with nothing vendored still exits 0 (no --fail-on given) - never errors just because the engine is absent'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/coverage_reduction" 2>/dev/null)" \
  'module=iac reason=engine_not_vendored engine=trivy' \
  'the absence is recorded plainly, per docs/ADAPTERS.md §7'

t_case 'run.json records use_engines for audit regardless of outcome'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/use_engines" 2>/dev/null)" 'true' \
  '--use-engines was given: recorded true'
assert_contains "$(cat "$W/run-no-flag/meta/use_engines" 2>/dev/null)" 'false' \
  '--use-engines was NOT given: recorded false'

# =============================================================================
printf -- '\n-- section C: full round-trip, real scan.sh subprocess, FAKE vendored trivy, merged alongside a native finding at the SAME location --\n'
# =============================================================================
ROOT_VENDORED=$W/root-vendored
rm -rf "$ROOT_VENDORED"
mkdir -p "$ROOT_VENDORED/config" "$ROOT_VENDORED/modules/iac" "$ROOT_VENDORED/modules/sast"
printf 'id: scanner\n' >"$ROOT_VENDORED/config/scanner.conf"
cp "$ROOT/modules/iac/run.sh" "$ROOT/modules/iac/parse.sh" "$ROOT/modules/iac/terraform.rules" \
  "$ROOT_VENDORED/modules/iac/"
cp "$ROOT/modules/sast/engine.sh" "$ROOT_VENDORED/modules/sast/engine.sh"
mkdir -p "$ROOT_VENDORED/modules/iac/adapters/trivy/bin"
cp "$ROOT/modules/iac/adapters/trivy/adapter.sh" \
  "$ROOT_VENDORED/modules/iac/adapters/trivy/adapter.sh"
# The FAKE vendored binary: a tiny script standing in for the real trivy
# (docs/ADAPTERS.md §1 - zero real engines are vendored anywhere in this
# repository), ignoring its own arguments and printing one canned result
# pointed at the SAME file and line the native IAC-TF-OPEN_CIDR-01 check
# below also fires on - proving the whole pipeline (trivy_run's own
# invocation shape, trivy_normalize, the --use-engines gate in
# modules/iac/run.sh, findings_merge, and every report format) AND this
# ticket's own merge/dedup requirement in one fixture: two tools reporting
# the identical location under two different check-id namespaces remain
# two distinct findings, never collapsed into one.
cat >"$ROOT_VENDORED/modules/iac/adapters/trivy/bin/trivy" <<'FAKETRIVY'
#!/usr/bin/env bash
printf '{"Results":[{"Target":"main.tf","Class":"config","Type":"terraform","Misconfigurations":[{"Type":"Terraform Security Check","ID":"AVD-AWS-0107","Title":"An ingress security group rule allows traffic from /0","Message":"Security group rule allows ingress from public internet.","Severity":"CRITICAL","Status":"FAIL","Resolution":"Set a more restrictive cidr range","CauseMetadata":{"Resource":"aws_security_group_rule.web","StartLine":10,"EndLine":10}}]}]}'
FAKETRIVY
chmod +x "$ROOT_VENDORED/modules/iac/adapters/trivy/bin/trivy"
ROOT_VENDORED=$(cd -- "$ROOT_VENDORED" && pwd -P)

VTARGET=$W/vtarget
rm -rf "$VTARGET"
mkdir -p "$VTARGET"
cp "$ROOT/tests/fixtures/vuln/tf_open_cidr.tf" "$VTARGET/main.tf"

t_case '--use-engines with a genuinely vendored (fake) trivy: the adapter finding reaches every report format, alongside the native finding at the same location'
rm -rf "$W/run-vendored"
SCOURSH_INSTALL_ROOT=$ROOT_VENDORED bash "$ROOT/scan.sh" iac --path "$VTARGET" \
  --use-engines --out "$W/run-vendored" >/dev/null 2>&1
assert_contains "$(cat "$W/run-vendored/findings.jsonl" 2>/dev/null)" \
  '"check_id":"trivy:AVD-AWS-0107"' \
  'findings.jsonl carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/findings.jsonl" 2>/dev/null)" \
  '"check_id":"IAC-TF-OPEN_CIDR-01"' \
  'findings.jsonl STILL carries the native finding at the same location - fails under a reading where the adapter finding replaced or collapsed onto the native one'
NATIVE_AND_ADAPTER_COUNT=$(grep -c '"check_id":"IAC-TF-OPEN_CIDR-01"\|"check_id":"trivy:AVD-AWS-0107"' \
  "$W/run-vendored/findings.jsonl" 2>/dev/null || true)
assert_eq 2 "$NATIVE_AND_ADAPTER_COUNT" \
  'exactly two findings at this one location (one native, one adapter) - fails under a reading that merged/deduped them into one just because they share a file, line and matched text'
assert_contains "$(cat "$W/run-vendored/findings.json" 2>/dev/null)" \
  '"check_id":"trivy:AVD-AWS-0107"' \
  'findings.json carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.md" 2>/dev/null)" \
  'trivy:AVD-AWS-0107' \
  'report.md carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.html" 2>/dev/null)" \
  'trivy:AVD-AWS-0107' \
  'report.html carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_boosted_not_a_replacement engine=trivy results=1' \
  'the run honestly declares this as an engine-boosted addition, never a silent replacement of the native pack'

t_summary iac-trivy
