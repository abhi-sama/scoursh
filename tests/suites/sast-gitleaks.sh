#!/usr/bin/env bash
# tests/suites/sast-gitleaks.sh - modules/sast/adapters/gitleaks/{adapter.sh,
# vendor.sh} and its wiring into modules/sast/run.sh (docs/DESIGN.md §6.4,
# §13 step 9; docs/ADAPTERS.md; this ticket, the SECOND concrete adapter,
# built on the plumbing the semgrep ticket shipped).  Mirrors
# tests/suites/sast-semgrep.sh's own section shape throughout.
#
# Covers this ticket's acceptance criteria:
#   - the three-function contract (gitleaks_detect/gitleaks_run/
#     gitleaks_normalize) against a small, purpose-built JSON parser proven
#     directly, including the BARE top-level array shape (unlike semgrep's
#     {"results":[...]} envelope) (section A)
#   - a boundary/security check: a gitleaks result reporting a path outside
#     the scan root is rejected, never trusted as a finding's location
#     (section A)
#   - the cross-check-id dedup against modules/sast/rules/secrets.rules'
#     native findings this ticket's own scope item 3 adds, both in
#     isolation and through the full pipeline (section A and section D)
#   - graceful degradation: --use-engines with the adapter genuinely absent
#     from disk is a clean coverage_reduction (reason=engine_not_vendored),
#     never an error, and a scan.sh sast run behaves identically whether or
#     not --use-engines is given, as long as nothing is vendored (section B)
#   - the round-trip requirement (docs/ADAPTERS.md §8): a normalized
#     gitleaks finding survives fingerprinting, redaction and every report
#     format identically to a native finding, exercised end to end through
#     a REAL `scan.sh sast --use-engines` subprocess against a FAKE vendored
#     "gitleaks" (section C)
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
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# shellcheck source=modules/sast/adapters/gitleaks/adapter.sh
source "$ROOT/modules/sast/adapters/gitleaks/adapter.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sast-gitleaks-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- section A: the three-function contract, in-process --\n'
# =============================================================================
SCANROOT=$W/scanroot
rm -rf "$SCANROOT"
mkdir -p "$SCANROOT/app"
cat >"$SCANROOT/app/creds.py" <<'PY'
import os

AWS_KEY = "AKIAQWERTYUIOPASDFGH"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
PY

t_case 'gitleaks_detect: absent bin/ -> 1'
GITLEAKS_ADAPTER_DIR=$W/no-bin
rm -rf "$GITLEAKS_ADAPTER_DIR"
mkdir -p "$GITLEAKS_ADAPTER_DIR/rules"
: >"$GITLEAKS_ADAPTER_DIR/rules/gitleaks.toml"
GITLEAKS_BIN=$GITLEAKS_ADAPTER_DIR/bin/gitleaks
GITLEAKS_CONFIG=$GITLEAKS_ADAPTER_DIR/rules/gitleaks.toml
assert_status 1 'no bin/gitleaks at all: detect fails' gitleaks_detect

t_case 'gitleaks_detect: bin/gitleaks present but not executable -> 1'
mkdir -p "$GITLEAKS_ADAPTER_DIR/bin"
: >"$GITLEAKS_ADAPTER_DIR/bin/gitleaks"
chmod -x "$GITLEAKS_ADAPTER_DIR/bin/gitleaks"
assert_status 1 'a non-executable bin/gitleaks still fails detect' gitleaks_detect

t_case 'gitleaks_detect: bin/gitleaks executable but rules/gitleaks.toml missing -> 1'
chmod +x "$GITLEAKS_ADAPTER_DIR/bin/gitleaks"
rm -f "$GITLEAKS_ADAPTER_DIR/rules/gitleaks.toml"
assert_status 1 'an executable binary with no gitleaks.toml still fails detect - a ruleset is required too' gitleaks_detect

t_case 'gitleaks_detect: both present -> 0'
: >"$GITLEAKS_ADAPTER_DIR/rules/gitleaks.toml"
assert_status 0 'bin/gitleaks executable AND rules/gitleaks.toml present: detect succeeds' gitleaks_detect

t_case '_gitleaks_split_results: BARE top-level array (not a {"results":[...]} envelope), a description containing a brace/comma does not desynchronise the split'
cat >"$W/two-results.json" <<JSON
[{"RuleID":"a-rule","File":"app/creds.py","StartLine":3,"Secret":"x","Description":"talks about results inline, a comma, and a brace {"},{"RuleID":"b-rule","File":"app/creds.py","StartLine":4,"Secret":"y","Description":"second"}]
JSON
_gitleaks_split_results "$W/two-results.json" >"$W/split.out"
assert_eq 2 "$(wc -l <"$W/split.out" | tr -d ' ')" \
  'exactly two result objects were split out, despite the first description containing a brace and a comma - fails under a reading that requires a "results" wrapper key like semgrep'"'"'s'

t_case '_gitleaks_split_results: an EMPTY array (gitleaks own "no leaks found" shape) yields zero objects'
printf '[]' >"$W/empty.json"
_gitleaks_split_results "$W/empty.json" >"$W/empty.out"
assert_eq 0 "$(wc -l <"$W/empty.out" | tr -d ' ')" 'an empty [] array produces zero split objects, not an error'

t_case '_gitleaks_json_string_field / _gitleaks_json_number_field round-trip'
OBJ='{"RuleID":"aws-access-token","File":"app/creds.py","StartLine":3,"Secret":"AKIAQWERTYUIOPASDFGH","Description":"AWS Access Key"}'
assert_eq 'aws-access-token' "$(_gitleaks_json_string_field "$OBJ" RuleID)" 'RuleID extracted correctly'
assert_eq 'app/creds.py' "$(_gitleaks_json_string_field "$OBJ" File)" 'File extracted correctly'
assert_eq 3 "$(_gitleaks_json_number_field "$OBJ" StartLine)" 'StartLine extracted correctly'
assert_eq 'AWS Access Key' "$(_gitleaks_json_string_field "$OBJ" Description)" 'Description extracted correctly'

t_case '_gitleaks_json_string_field: JSON escapes are decoded'
ESC_OBJ='{"Description":"quote \" backslash \\ tab\tend"}'
assert_eq 'quote " backslash \ tab	end' "$(_gitleaks_json_string_field "$ESC_OBJ" Description)" \
  'standard JSON escapes (\", \\\\, \t) decode to their real characters, not left literal'

t_case 'gitleaks_normalize: full round-trip through finding_emit for a real fixture on disk'
SCOURSH_RUN_DIR=$W/run-a
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
_SCAN_RESOLVED_PATH=$SCANROOT
SCOURSH_PATH_ROOT=.
cat >"$W/one-result.json" <<JSON
[{"RuleID":"generic-api-key","File":"app/creds.py","StartLine":4,"Secret":"sk_live_abcdefghijklmnopqrstuvwx","Description":"Generic API Key"}]
JSON
gitleaks_normalize "$W/one-result.json"
SHARD=$(cat "$SCOURSH_RUN_DIR"/shards/*.jsonl 2>/dev/null)
assert_contains "$SHARD" '"check_id":"gitleaks:generic-api-key"' \
  'the finding check_id is namespaced gitleaks:<rule id> per rules/RULE-FORMAT.md §9.1.1a'
assert_contains "$SHARD" '"module":"sast"' 'the finding module is sast'
assert_contains "$SHARD" '"evidence":"sk_live_abcdefghijklmnopqrstuvwx"' \
  'evidence is gitleaks'"'"'s own reported Secret field - the exact matched substring, not a re-derived whole line - which is what makes this adapter'"'"'s match_digest comparable to a native secrets.rules finding'"'"'s own (both hash just the matched bytes; see _gitleaks_match_text'"'"'s own comment for why this adapter differs from the semgrep one here)'
assert_contains "$SHARD" '"cwe":"CWE-798"' 'cwe is fixed to CWE-798 (hardcoded credential), per this adapter'"'"'s own comment'
assert_contains "$SHARD" '"owasp":"A07:2021"' 'owasp is fixed to A07:2021 (identification and authentication failures)'
assert_contains "$SHARD" '"sensitive_data":true' 'every gitleaks finding is marked sensitive_data - never a heuristic, unlike semgrep_normalize'"'"'s substring guess'

t_case 'gitleaks_normalize: a reported path outside the scan root is rejected, never trusted as a finding location'
SCOURSH_RUN_DIR=$W/run-b
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
cat >"$W/evil-path.json" <<JSON
[{"RuleID":"generic-api-key","File":"../../../../etc/passwd","StartLine":1,"Secret":"leak","Description":"leak"}]
JSON
gitleaks_normalize "$W/evil-path.json"
SHARD_COUNT=0
for _f in "$SCOURSH_RUN_DIR"/shards/*.jsonl; do
  [[ -e $_f ]] || continue
  SHARD_COUNT=$(( SHARD_COUNT + $(wc -l <"$_f" | tr -d ' ') ))
done
assert_eq 0 "$SHARD_COUNT" \
  'zero findings were emitted for the traversal-path result - fails under "trust whatever path gitleaks reports"'
assert_contains "$(cat "$SCOURSH_RUN_DIR/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_reported_path_outside_scan_root' \
  'the rejection is recorded as a coverage_reduction, not silently dropped'

t_case '_gitleaks_dup_of_native_secret: a native SAST-SEC-* finding at the same (path, match_digest) IS a duplicate'
SCOURSH_RUN_DIR=$W/run-dedup
rm -rf "$SCOURSH_RUN_DIR"
mkdir -p "$SCOURSH_RUN_DIR/meta" "$SCOURSH_RUN_DIR/shards"
finding_new
finding_set check_id SAST-SEC-AWS_AKID-01
finding_set module sast
finding_set title 'Hardcoded AWS access key id'
finding_set base_severity critical
finding_set confidence high
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path app/creds.py
finding_set loc_line 3
finding_set cell .
finding_set logical_kind file
finding_set logical_fqn 'app/creds.py:3'
finding_set remediation 'rotate it'
finding_set_match 'AWS_KEY = "AKIAQWERTYUIOPASDFGH"'
finding_set_evidence 'AWS_KEY = "AKIAQWERTYUIOPASDFGH"'
finding_emit
SAME_DIGEST=$(fingerprint_digest 'AWS_KEY = "AKIAQWERTYUIOPASDFGH"')
assert_status 0 'the identical (path, match_digest) pair the native finding above just wrote to this run'"'"'s own shard IS reported as a duplicate - fails under a reading that only checks check_id equality' \
  _gitleaks_dup_of_native_secret app/creds.py "$SAME_DIGEST"

t_case '_gitleaks_dup_of_native_secret: a DIFFERENT match_digest at the same path is NOT a duplicate'
DIFFERENT_DIGEST=$(fingerprint_digest 'STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"')
assert_status 1 'same file, different underlying secret text: not a duplicate - fails under a reading that dedups on loc_path alone' \
  _gitleaks_dup_of_native_secret app/creds.py "$DIFFERENT_DIGEST"

t_case '_gitleaks_dup_of_native_secret: no run dir at all is never a duplicate (fails closed toward "keep the finding", not toward "silently drop it")'
unset SCOURSH_RUN_DIR
assert_status 1 'SCOURSH_RUN_DIR unset: never claims a duplicate' _gitleaks_dup_of_native_secret app/creds.py "$SAME_DIGEST"

unset SCOURSH_RUN_DIR _SCAN_RESOLVED_PATH SCOURSH_PATH_ROOT

# =============================================================================
printf -- '\n-- section B: graceful degradation, real scan.sh subprocess, adapter absent --\n'
# =============================================================================
ROOT_NO_ADAPTER=$W/root-no-adapter
rm -rf "$ROOT_NO_ADAPTER"
mkdir -p "$ROOT_NO_ADAPTER/config" "$ROOT_NO_ADAPTER/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_NO_ADAPTER/config/scanner.conf"
# Copied via a glob, deliberately, never by spelling out each of
# modules/sast/'s three top-level scripts by name: tools/gen-status.sh's own
# witness-matching (gs_first_match) picks the first tests/suites/*.sh file,
# in LC_ALL=C order, whose CONTENT contains a given artifact's basename as a
# substring.  This suite file's own name sorts alphabetically ahead of the
# suite that is the real, semantically correct witness for the third
# script (the one §13 step 3e shipped, for replaying secrets checks against
# git history) - spelling that script's exact filename out here would make
# THIS file win that match instead, purely by sort order, and misattribute
# the witness in the generated status tables.  Caught by tests/lint-status.sh
# while building this ticket; avoided at the source (never write the literal
# filename in this suite at all) rather than by special-casing the generator.
cp "$ROOT"/modules/sast/*.sh "$ROOT_NO_ADAPTER/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_NO_ADAPTER/modules/sast/rules/secrets.rules"
ROOT_NO_ADAPTER=$(cd -- "$ROOT_NO_ADAPTER" && pwd -P)
FIXTURES=$ROOT/tests/fixtures/sast

t_case 'without --use-engines: no engine coverage_reduction fact at all - true "behaves identically to today"'
rm -rf "$W/run-no-flag"
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --out "$W/run-no-flag" >/dev/null 2>&1
assert_not_contains "$(cat "$W/run-no-flag/meta/coverage_reduction" 2>/dev/null)" 'engine=gitleaks' \
  'no --use-engines: not even a coverage_reduction mentions the engine - it is never even consulted'

t_case '--use-engines with the adapter genuinely absent from disk: clean coverage_reduction, exit code unaffected'
rm -rf "$W/run-flag-no-adapter"
rc=0
SCOURSH_INSTALL_ROOT=$ROOT_NO_ADAPTER bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --use-engines --out "$W/run-flag-no-adapter" >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" \
  '--use-engines with nothing vendored still exits 0 (no --fail-on given) - never errors just because the engine is absent'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/coverage_reduction" 2>/dev/null)" \
  'module=sast reason=engine_not_vendored engine=gitleaks' \
  'the absence is recorded plainly, per docs/ADAPTERS.md §7'

t_case 'gitleaks absence is independent of semgrep: the same run also (honestly) reports semgrep not vendored, neither one masking the other'
assert_contains "$(cat "$W/run-flag-no-adapter/meta/coverage_reduction" 2>/dev/null)" \
  'module=sast reason=engine_not_vendored engine=semgrep' \
  'both adapters are absent from ROOT_NO_ADAPTER, and both are reported - fails under a reading where wiring one adapter suppresses the other'"'"'s own gate'

# =============================================================================
printf -- '\n-- section C: full round-trip, real scan.sh subprocess, FAKE vendored gitleaks --\n'
# =============================================================================
ROOT_VENDORED=$W/root-vendored
rm -rf "$ROOT_VENDORED"
mkdir -p "$ROOT_VENDORED/config" "$ROOT_VENDORED/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_VENDORED/config/scanner.conf"
# See the identical comment on the ROOT_NO_ADAPTER copy above.
cp "$ROOT"/modules/sast/*.sh "$ROOT_VENDORED/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_VENDORED/modules/sast/rules/secrets.rules"
mkdir -p "$ROOT_VENDORED/modules/sast/adapters/gitleaks/bin" \
  "$ROOT_VENDORED/modules/sast/adapters/gitleaks/rules"
cp "$ROOT/modules/sast/adapters/gitleaks/adapter.sh" \
  "$ROOT_VENDORED/modules/sast/adapters/gitleaks/adapter.sh"
: >"$ROOT_VENDORED/modules/sast/adapters/gitleaks/rules/gitleaks.toml"
# The FAKE vendored binary: a tiny script standing in for the real gitleaks
# (docs/ADAPTERS.md §1 - zero real engines are vendored anywhere in this
# repository), ignoring its own arguments and writing gitleaks' own bare-array
# JSON shape to whatever --report-path names, so this proves the WHOLE
# pipeline - gitleaks_run's own invocation shape (including --report-path,
# which this fake reads out of its own argv), gitleaks_normalize, the
# --use-engines gate, findings_merge, and every report format.
cat >"$ROOT_VENDORED/modules/sast/adapters/gitleaks/bin/gitleaks" <<'FAKEGITLEAKS'
#!/usr/bin/env bash
out=''
while (( $# > 0 )); do
  if [[ $1 == --report-path ]]; then
    out=$2
  fi
  shift
done
printf '[{"RuleID":"generic-api-key","File":"weak_secret.py","StartLine":2,"Secret":"sk_live_abcdefghijklmnopqrstuvwx","Description":"Generic API Key"}]' >"$out"
exit 0
FAKEGITLEAKS
chmod +x "$ROOT_VENDORED/modules/sast/adapters/gitleaks/bin/gitleaks"
ROOT_VENDORED=$(cd -- "$ROOT_VENDORED" && pwd -P)

VTARGET=$W/vtarget
rm -rf "$VTARGET"
mkdir -p "$VTARGET"
cat >"$VTARGET/weak_secret.py" <<'PY'
import os
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
PY

t_case '--use-engines with a genuinely vendored (fake) gitleaks: the adapter finding reaches every report format'
rm -rf "$W/run-vendored"
SCOURSH_INSTALL_ROOT=$ROOT_VENDORED bash "$ROOT/scan.sh" sast --path "$VTARGET" \
  --use-engines --out "$W/run-vendored" >/dev/null 2>&1
assert_contains "$(cat "$W/run-vendored/findings.jsonl" 2>/dev/null)" \
  '"check_id":"gitleaks:generic-api-key"' \
  'findings.jsonl carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/findings.json" 2>/dev/null)" \
  '"check_id":"gitleaks:generic-api-key"' \
  'findings.json carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.md" 2>/dev/null)" \
  'gitleaks:generic-api-key' \
  'report.md carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/report.html" 2>/dev/null)" \
  'gitleaks:generic-api-key' \
  'report.html carries the adapter finding'
assert_contains "$(cat "$W/run-vendored/meta/coverage_reduction" 2>/dev/null)" \
  'reason=engine_boosted_not_a_replacement engine=gitleaks results=1' \
  'the run honestly declares this as an engine-boosted addition, never a silent replacement of the native pack'

# =============================================================================
printf -- '\n-- section D: end-to-end dedup against modules/sast/rules/secrets.rules through a real scan.sh subprocess --\n'
# =============================================================================
ROOT_DEDUP=$W/root-dedup
rm -rf "$ROOT_DEDUP"
mkdir -p "$ROOT_DEDUP/config" "$ROOT_DEDUP/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_DEDUP/config/scanner.conf"
# See the identical comment on the ROOT_NO_ADAPTER copy above.
cp "$ROOT"/modules/sast/*.sh "$ROOT_DEDUP/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_DEDUP/modules/sast/rules/secrets.rules"
mkdir -p "$ROOT_DEDUP/modules/sast/adapters/gitleaks/bin" \
  "$ROOT_DEDUP/modules/sast/adapters/gitleaks/rules"
cp "$ROOT/modules/sast/adapters/gitleaks/adapter.sh" \
  "$ROOT_DEDUP/modules/sast/adapters/gitleaks/adapter.sh"
: >"$ROOT_DEDUP/modules/sast/adapters/gitleaks/rules/gitleaks.toml"
# This fake gitleaks reports TWO findings: one at the SAME file+line as a
# native SAST-SEC-AWS_AKID-01 match (expected to be deduped away) and one at
# a DIFFERENT line gitleaks alone catches (expected to survive).
cat >"$ROOT_DEDUP/modules/sast/adapters/gitleaks/bin/gitleaks" <<'FAKEGITLEAKS'
#!/usr/bin/env bash
out=''
while (( $# > 0 )); do
  if [[ $1 == --report-path ]]; then
    out=$2
  fi
  shift
done
printf '[{"RuleID":"aws-access-token","File":"creds.py","StartLine":2,"Secret":"AKIAQWERTYUIOPASDFGH","Description":"AWS Access Key"},{"RuleID":"generic-api-key","File":"creds.py","StartLine":3,"Secret":"sk_live_abcdefghijklmnopqrstuvwx","Description":"Generic API Key"}]' >"$out"
exit 0
FAKEGITLEAKS
chmod +x "$ROOT_DEDUP/modules/sast/adapters/gitleaks/bin/gitleaks"
ROOT_DEDUP=$(cd -- "$ROOT_DEDUP" && pwd -P)

DTARGET=$W/dtarget
rm -rf "$DTARGET"
mkdir -p "$DTARGET"
cat >"$DTARGET/creds.py" <<'PY'
import os
AWS_KEY = "AKIAQWERTYUIOPASDFGH"
STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwx"
PY

t_case 'end-to-end: gitleaks duplicate of the native AWS-key finding is dropped; the non-overlapping stripe-key finding survives'
rm -rf "$W/run-dedup"
SCOURSH_INSTALL_ROOT=$ROOT_DEDUP bash "$ROOT/scan.sh" sast --path "$DTARGET" \
  --use-engines --out "$W/run-dedup" >/dev/null 2>&1
JSONL=$(cat "$W/run-dedup/findings.jsonl" 2>/dev/null)
assert_contains "$JSONL" '"check_id":"SAST-SEC-AWS_AKID-01"' \
  'the native AWS-key finding is present exactly as it always is, unaffected by the adapter running alongside it'
assert_not_contains "$JSONL" '"check_id":"gitleaks:aws-access-token"' \
  'the gitleaks duplicate of that SAME file+line is dropped, never double-reported - fails under a reading that only dedups by full fingerprint (module+check_id+loc), which gitleaks:aws-access-token and SAST-SEC-AWS_AKID-01 never share'
assert_contains "$JSONL" '"check_id":"gitleaks:generic-api-key"' \
  'the gitleaks-only stripe-key finding, which no native secrets.rules pattern covers, still survives - proves the dedup is narrow (same file+matched text), not a blanket "drop every gitleaks finding once any native secret exists"'
assert_contains "$(cat "$W/run-dedup/meta/coverage_reduction" 2>/dev/null)" \
  'reason=dedup_native_secret engine=gitleaks count=1' \
  'the dedup itself is recorded, not silently invisible'

t_summary sast-gitleaks
