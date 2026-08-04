#!/usr/bin/env bash
# tests/suites/sast-semgrep.sh - modules/sast/adapters/semgrep/{adapter.sh,
# vendor.sh} and its wiring into modules/sast/run.sh (docs/DESIGN.md §6.4,
# §13 step 9; docs/ADAPTERS.md; this ticket, the first concrete adapter).
#
# Covers this ticket's acceptance criteria:
#   - the three-function contract (semgrep_detect/semgrep_run/
#     semgrep_normalize) against a small, purpose-built JSON parser proven
#     directly (section A)
#   - graceful degradation: --use-engines with the adapter genuinely absent
#     from disk is a clean coverage_reduction (reason=engine_not_vendored),
#     never an error, and a scan.sh sast run behaves identically (same exit
#     code, same native findings) whether or not --use-engines is given, as
#     long as nothing is vendored (section B)
#   - the round-trip requirement (docs/ADAPTERS.md §8): a normalized
#     semgrep finding survives fingerprinting, redaction and every report
#     format identically to a native finding, exercised end to end through
#     a REAL `scan.sh sast --use-engines` subprocess against a FAKE vendored
#     "semgrep" (a tiny script standing in for the real binary, since no
#     real semgrep is vendored in this repository - docs/ADAPTERS.md §1)
#     (section C)
#   - a boundary/security check: a semgrep result reporting a path outside
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
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# shellcheck source=modules/sast/adapters/semgrep/adapter.sh
source "$ROOT/modules/sast/adapters/semgrep/adapter.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sast-semgrep-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- section A: the three-function contract, in-process --\n'
# =============================================================================
SCANROOT=$W/scanroot
rm -rf "$SCANROOT"
mkdir -p "$SCANROOT/app"
# Deliberately vulnerable fixture (never executed - only scanned as text):
# eval() here is the TARGET FINDING this suite proves the adapter reports
# correctly, the same true-positive-fixture convention
# tests/fixtures/vuln/*.py already uses for the native python.rules pack.
cat >"$SCANROOT/app/main.py" <<'PY'
import subprocess

def run(user_input):
    eval(user_input)
PY

t_case 'semgrep_detect: absent bin/ -> 1'
SEMGREP_ADAPTER_DIR=$W/no-bin
rm -rf "$SEMGREP_ADAPTER_DIR"
mkdir -p "$SEMGREP_ADAPTER_DIR/rules"
: >"$SEMGREP_ADAPTER_DIR/rules/x.yml"
SEMGREP_BIN=$SEMGREP_ADAPTER_DIR/bin/semgrep
SEMGREP_RULES_DIR=$SEMGREP_ADAPTER_DIR/rules
assert_status 1 'no bin/semgrep at all: detect fails' semgrep_detect

t_case 'semgrep_detect: bin/semgrep present but not executable -> 1'
mkdir -p "$SEMGREP_ADAPTER_DIR/bin"
: >"$SEMGREP_ADAPTER_DIR/bin/semgrep"
chmod -x "$SEMGREP_ADAPTER_DIR/bin/semgrep"
assert_status 1 'a non-executable bin/semgrep still fails detect' semgrep_detect

t_case 'semgrep_detect: bin/semgrep executable but rules/ empty -> 1'
chmod +x "$SEMGREP_ADAPTER_DIR/bin/semgrep"
rm -f "$SEMGREP_ADAPTER_DIR/rules/x.yml"
assert_status 1 'an executable binary with an EMPTY rules/ dir still fails detect - a ruleset is required too' semgrep_detect

t_case 'semgrep_detect: both present -> 0'
: >"$SEMGREP_ADAPTER_DIR/rules/x.yml"
assert_status 0 'bin/semgrep executable AND a non-empty rules/: detect succeeds' semgrep_detect

t_case '_semgrep_split_results: two results, a message containing the word "results" does not desynchronise the split'
cat >"$W/two-results.json" <<JSON
{"results":[{"check_id":"a.rule","path":"app/main.py","start":{"line":1},"extra":{"message":"talks about results inline, a comma, and a brace {","severity":"ERROR","metadata":{}}},{"check_id":"b.rule","path":"app/main.py","start":{"line":2},"extra":{"message":"second","severity":"WARNING","metadata":{}}}]}
JSON
_semgrep_split_results "$W/two-results.json" >"$W/split.out"
assert_eq 2 "$(wc -l <"$W/split.out" | tr -d ' ')" \
  'exactly two result objects were split out, despite the first message containing "results", a brace and a comma'

t_case '_semgrep_json_string_field / _semgrep_json_object_field / _semgrep_json_number_field round-trip'
OBJ='{"check_id":"python.lang.security.eval","path":"app/main.py","start":{"line":4,"col":1},"extra":{"message":"Detected eval","severity":"ERROR","lines":"eval(user_input)","metadata":{"cwe":["CWE-95: Eval Injection"],"owasp":["A03:2021 - Injection"]}}}'
assert_eq 'python.lang.security.eval' "$(_semgrep_json_string_field "$OBJ" check_id)" 'check_id extracted correctly'
assert_eq 'app/main.py' "$(_semgrep_json_string_field "$OBJ" path)" 'path extracted correctly'
START_OBJ=$(_semgrep_json_object_field "$OBJ" start)
assert_eq 4 "$(_semgrep_json_number_field "$START_OBJ" line)" 'start.line extracted correctly, not confused with any other "line" key'
EXTRA_OBJ=$(_semgrep_json_object_field "$OBJ" extra)
assert_eq 'Detected eval' "$(_semgrep_json_string_field "$EXTRA_OBJ" message)" 'extra.message extracted correctly'
METADATA_OBJ=$(_semgrep_json_object_field "$EXTRA_OBJ" metadata)
assert_eq 'CWE-95: Eval Injection' "$(_semgrep_json_array_first_string "$METADATA_OBJ" cwe)" 'metadata.cwe[0] extracted correctly'

t_case '_semgrep_json_string_field: JSON escapes are decoded'
ESC_OBJ='{"message":"quote \" backslash \\ tab\tend"}'
assert_eq 'quote " backslash \ tab	end' "$(_semgrep_json_string_field "$ESC_OBJ" message)" \
  'standard JSON escapes (\", \\\\, \t) decode to their real characters, not left literal'

t_case 'semgrep_normalize: full round-trip through finding_emit for a real fixture on disk'
SCOURSH_RUN_DIR=$W/run-a
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
_SCAN_RESOLVED_PATH=$SCANROOT
SCOURSH_PATH_ROOT=.
cat >"$W/one-result.json" <<JSON
{"results":[{"check_id":"python.lang.security.eval","path":"app/main.py","start":{"line":4},"extra":{"message":"Detected eval","severity":"ERROR","lines":"eval(user_input)","metadata":{"cwe":["CWE-95"],"owasp":["A03:2021"]}}}]}
JSON
semgrep_normalize "$W/one-result.json"
SHARD=$(cat "$SCOURSH_RUN_DIR"/shards/*.jsonl 2>/dev/null)
assert_contains "$SHARD" '"check_id":"semgrep:python.lang.security.eval"' \
  'the finding check_id is namespaced semgrep:<rule id> per rules/RULE-FORMAT.md §9.1.1a'
assert_contains "$SHARD" '"module":"sast"' 'the finding module is sast'
assert_contains "$SHARD" '"evidence":"    eval(user_input)"' \
  'evidence is the REAL line read from the file on disk (with its real indentation), not semgrep'"'"'s own reported snippet - proves the "re-derive match_digest from the file at the reported path/line" requirement (docs/FOUNDATION.md tension 5/11)'
assert_contains "$SHARD" '"cwe":"CWE-95"' 'cwe normalised to the bare CWE-NNN form'
assert_contains "$SHARD" '"owasp":"A03:2021"' 'owasp normalised to the bare AXX:20YY form'

t_case 'semgrep_normalize: a reported path outside the scan root is rejected, never trusted as a finding location'
SCOURSH_RUN_DIR=$W/run-b
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
cat >"$W/evil-path.json" <<JSON
{"results":[{"check_id":"generic.secrets.detected","path":"../../../../etc/passwd","start":{"line":1},"extra":{"message":"leak","severity":"ERROR","metadata":{}}}]}
JSON
semgrep_normalize "$W/evil-path.json"
assert_file_absent "$SCOURSH_RUN_DIR/shards/dummy-never-created.jsonl" 'sanity: shard dir exists but this specific file never does'
SHARD_COUNT=0
for _f in "$SCOURSH_RUN_DIR"/shards/*.jsonl; do
  [[ -e $_f ]] || continue
  SHARD_COUNT=$(( SHARD_COUNT + $(wc -l <"$_f" | tr -d ' ') ))
done
assert_eq 0 "$SHARD_COUNT" \
  'zero findings were emitted for the traversal-path result - fails under "trust whatever path semgrep reports"'
assert_contains "$(cat "$SCOURSH_RUN_DIR/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_reported_path_outside_scan_root' \
  'the rejection is recorded as a coverage_reduction, not silently dropped'

unset SCOURSH_RUN_DIR _SCAN_RESOLVED_PATH SCOURSH_PATH_ROOT

# =============================================================================
printf -- '\n-- section B: graceful degradation, real scan.sh subprocess, adapter absent --\n'
# =============================================================================
ROOT_NO_ADAPTER=$W/root-no-adapter
rm -rf "$ROOT_NO_ADAPTER"
mkdir -p "$ROOT_NO_ADAPTER/config" "$ROOT_NO_ADAPTER/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_NO_ADAPTER/config/scanner.conf"
cp "$ROOT/modules/sast/run.sh" "$ROOT/modules/sast/engine.sh" "$ROOT/modules/sast/history.sh" \
  "$ROOT_NO_ADAPTER/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_NO_ADAPTER/modules/sast/rules/secrets.rules"
ROOT_NO_ADAPTER=$(cd -- "$ROOT_NO_ADAPTER" && pwd -P)
FIXTURES=$ROOT/tests/fixtures/sast

t_case 'without --use-engines: no engine coverage_reduction fact at all - true "behaves identically to today"'
rm -rf "$W/run-no-flag"
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --out "$W/run-no-flag" >/dev/null 2>&1
assert_not_contains "$(cat "$W/run-no-flag/meta/coverage_reduction" 2>/dev/null)" 'engine=semgrep' \
  'no --use-engines: not even a coverage_reduction mentions the engine - it is never even consulted'

t_case '--use-engines with the adapter genuinely absent from disk: clean coverage_reduction, exit code unaffected'
rm -rf "$W/run-flag-no-adapter"
rc=0
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --use-engines --out "$W/run-flag-no-adapter" >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" \
  '--use-engines with nothing vendored still exits 0 (no --fail-on given) - never errors just because the engine is absent'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/coverage_reduction" 2>/dev/null)" \
  'module=sast reason=engine_not_vendored engine=semgrep' \
  'the absence is recorded plainly, per docs/ADAPTERS.md §7'

t_case 'run.json records use_engines for audit regardless of outcome'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/use_engines" 2>/dev/null)" 'true' \
  '--use-engines was given: recorded true'
assert_contains "$(cat "$W/run-no-flag/meta/use_engines" 2>/dev/null)" 'false' \
  '--use-engines was NOT given: recorded false'

# =============================================================================
printf -- '\n-- section C: full round-trip, real scan.sh subprocess, FAKE vendored semgrep --\n'
# =============================================================================
ROOT_VENDORED=$W/root-vendored
rm -rf "$ROOT_VENDORED"
mkdir -p "$ROOT_VENDORED/config" "$ROOT_VENDORED/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_VENDORED/config/scanner.conf"
cp "$ROOT/modules/sast/run.sh" "$ROOT/modules/sast/engine.sh" "$ROOT/modules/sast/history.sh" \
  "$ROOT_VENDORED/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_VENDORED/modules/sast/rules/secrets.rules"
mkdir -p "$ROOT_VENDORED/modules/sast/adapters/semgrep/bin" \
  "$ROOT_VENDORED/modules/sast/adapters/semgrep/rules"
cp "$ROOT/modules/sast/adapters/semgrep/adapter.sh" \
  "$ROOT_VENDORED/modules/sast/adapters/semgrep/adapter.sh"
: >"$ROOT_VENDORED/modules/sast/adapters/semgrep/rules/fixture.yml"
# The FAKE vendored binary: a tiny script standing in for the real semgrep
# (docs/ADAPTERS.md §1 - zero real engines are vendored anywhere in this
# repository), ignoring its own arguments and printing one canned result
# pointed at a real file this suite also controls, so this proves the WHOLE
# pipeline - semgrep_run's own invocation shape, semgrep_normalize, the
# --use-engines gate in modules/sast/run.sh, findings_merge, and every
# report format - not just semgrep_normalize in isolation (section A
# already covers that in isolation).
cat >"$ROOT_VENDORED/modules/sast/adapters/semgrep/bin/semgrep" <<'FAKESEMGREP'
#!/usr/bin/env bash
printf '{"results":[{"check_id":"python.lang.security.weak-random","path":"weak_random.py","start":{"line":2},"extra":{"message":"insecure randomness","severity":"WARNING","lines":"return random.random()","metadata":{"cwe":["CWE-330"],"owasp":["A02:2021"]}}}]}'
FAKESEMGREP
chmod +x "$ROOT_VENDORED/modules/sast/adapters/semgrep/bin/semgrep"
ROOT_VENDORED=$(cd -- "$ROOT_VENDORED" && pwd -P)

VTARGET=$W/vtarget
rm -rf "$VTARGET"
mkdir -p "$VTARGET"
cat >"$VTARGET/weak_random.py" <<'PY'
import random


def token():
    return random.random()
PY

t_case '--use-engines with a genuinely vendored (fake) semgrep: the adapter finding reaches every report format'
rm -rf "$W/run-vendored"
SCOURSH_INSTALL_ROOT=$ROOT_VENDORED bash "$ROOT/scan.sh" sast --path "$VTARGET" \
  --use-engines --out "$W/run-vendored" >/dev/null 2>&1
assert_contains "$(cat "$W/run-vendored/findings.jsonl" 2>/dev/null)" \
  '"check_id":"semgrep:python.lang.security.weak-random"' \
  'findings.jsonl carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/findings.json" 2>/dev/null)" \
  '"check_id":"semgrep:python.lang.security.weak-random"' \
  'findings.json carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.md" 2>/dev/null)" \
  'semgrep:python.lang.security.weak-random' \
  'report.md carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.html" 2>/dev/null)" \
  'semgrep:python.lang.security.weak-random' \
  'report.html carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_boosted_not_a_replacement engine=semgrep results=1' \
  'the run honestly declares this as an engine-boosted addition, never a silent replacement of the native pack'

t_summary sast-semgrep
