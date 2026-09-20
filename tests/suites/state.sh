#!/usr/bin/env bash
# tests/suites/state.sh - lib/state.sh (STATE-01: the state/ schema, writer,
# loader).
#
# docs/STEP7-STATE-PLAN.md's STATE-01 row is the ticket-level scope: the
# frozen JSON shape (docs/FOUNDATION.md tension 12), a writer (tension 11
# stage 8), and a loader that treats a missing OR unparsable state file as
# "no prior state" while REJECTING a malformed record outright rather than
# half-loading it.  Classification, coverage recording, and any scan.sh/
# scan_main wiring are later tickets and are not exercised here.
#
# Every case that pins a rejection names the reading it fails under, per this
# project's testing rule: a test that would also pass a half-loading reader
# pins nothing.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/JSON syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/state.sh
source "$ROOT/lib/state.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/state
mkdir -p "$W"
FIX=$ROOT/tests/fixtures/state

# ---------------------------------------------------------------------------
printf '\n-- write side: the builder API round-trips through the loader --\n'
# ---------------------------------------------------------------------------
SD1=$W/store1
mkdir -p "$SD1"

state_reset
state_set_run 'run-1' 'git-remote:https://example.invalid/org/proj' 'fp/1' '0.9.0' '2026-06-01T09:05:00Z'
state_add_covered 'SAST-PY-EVAL-01' 'digestA' 'path-root' 'src'
state_add_covered 'SAST-PY-EVAL-01' 'digestA' 'path-root' '.'
state_add_covered 'SAST-HIST-AWSKEY-01' 'digestB' 'path-root' '.'
state_add_history_boundary 'SAST-HIST-AWSKEY-01' 'deadbeef' '2025-08-01T00:00:00Z' 12345 'window-days'
state_add_covered 'DAST-XSS-REFLECT-01' 'digestC' 'target' 'staging'
state_add_covered 'CLOUD-EC2-SG_OPEN-01' 'digestD' 'account-region' '123456789012/us-east-1'
state_add_covered 'CLOUD-EC2-SG_OPEN-01' 'digestD' 'account-region' '123456789012/eu-west-1'
state_add_covered 'POSTURE-SAML-ENFORCED-01' 'digestE' 'scope-key' 'prod-sso'
state_add_finding 'fp-ordinary-1' 'SAST-PY-EVAL-01' 'src' 'high' \
  '2026-05-01T00:00:00Z' '2026-06-01T09:05:00Z' false
state_add_finding 'fp-history-1' 'SAST-HIST-AWSKEY-01' '.' 'critical' \
  '2026-04-01T00:00:00Z' '2026-06-01T09:05:00Z' true '2025-08-15T00:00:00Z'
state_add_finding 'fp-composite-1' 'COMPOSITE-TOKEN-HIJACK' '' 'critical' \
  '2026-06-01T00:00:00Z' '2026-06-01T09:05:00Z' false '' 'fp-ordinary-1,fp-history-1'
state_write "$SD1" 30

t_case 'state_write creates <run_id>.json'
assert_file_exists "$SD1/run-1.json" 'the canonical run file exists'

t_case 'state_write updates latest.json to the identical bytes'
assert_eq "$(cat "$SD1/run-1.json")" "$(cat "$SD1/latest.json")" \
  'latest.json is a byte copy of the run just written, not a second render'

t_case 'state_write leaves no temporary file behind'
assert_eq '' "$(find "$SD1" -maxdepth 1 -name '.tmp.*' 2>/dev/null)" \
  'the write-then-rename tmp files were renamed away, not left as litter'

state_load_file "$SD1/run-1.json"
t_case 'the just-written file loads back'
assert_true "$([[ $(state_loaded; echo $?) == 0 ]] && echo 0 || echo 1)" 'state_loaded is true'
assert_eq 'fp/1' "$(state_field fp_schema)" 'fp_schema round-trips'
assert_eq '0.9.0' "$(state_field tool_version)" 'tool_version round-trips'
assert_eq 'run-1' "$(state_field run_id)" 'run_id round-trips'
assert_eq '2026-06-01T09:05:00Z' "$(state_field completed_at)" 'completed_at round-trips'
assert_eq 'git-remote:https://example.invalid/org/proj' "$(state_field scan_root_id)" \
  'scan_root_id round-trips'

t_case 'covered_checks round-trips every coverage-scope kind (tension 12)'
assert_eq "$(printf 'CLOUD-EC2-SG_OPEN-01\nDAST-XSS-REFLECT-01\nPOSTURE-SAML-ENFORCED-01\nSAST-HIST-AWSKEY-01\nSAST-PY-EVAL-01')" \
  "$(state_covered_check_ids | LC_ALL=C sort)" 'every check_id that was covered is present'
assert_eq 'path-root' "$(state_covered_scope SAST-PY-EVAL-01)" 'path-root scope round-trips (SAST)'
assert_eq 'target' "$(state_covered_scope DAST-XSS-REFLECT-01)" 'target scope round-trips (DAST)'
assert_eq 'scope-key' "$(state_covered_scope POSTURE-SAML-ENFORCED-01)" \
  'scope-key scope round-trips (posture)'
assert_eq "$(printf 'src\n.')" "$(state_covered_cells SAST-PY-EVAL-01)" \
  'multiple cells for one check round-trip, in the order they were added'
assert_true "$(state_covered_has_cell SAST-PY-EVAL-01 . && echo 0 || echo 1)" \
  'state_covered_has_cell finds a cell that was added'
assert_true "$(state_covered_has_cell SAST-PY-EVAL-01 nope && echo 1 || echo 0)" \
  'state_covered_has_cell does not find a cell that was never added'

t_case 'the account-region coverage-scope kind round-trips (KNOWN GAP: schema-only - no real step-6 cloud emitter exists yet to produce this data end to end, see lib/state.sh header)'
assert_eq 'account-region' "$(state_covered_scope CLOUD-EC2-SG_OPEN-01)" \
  'account-region scope round-trips'
assert_eq "$(printf '123456789012/us-east-1\n123456789012/eu-west-1')" \
  "$(state_covered_cells CLOUD-EC2-SG_OPEN-01)" \
  'both account-region cells round-trip'

t_case 'the history_boundary block round-trips (tension 13), and only for the check it was set on'
assert_eq 'deadbeef' "$(state_history_boundary_field SAST-HIST-AWSKEY-01 oldest_commit)" 'oldest_commit'
assert_eq '2025-08-01T00:00:00Z' "$(state_history_boundary_field SAST-HIST-AWSKEY-01 oldest_commit_time)" \
  'oldest_commit_time'
assert_eq '12345' "$(state_history_boundary_field SAST-HIST-AWSKEY-01 objects_scanned)" 'objects_scanned'
assert_eq 'window-days' "$(state_history_boundary_field SAST-HIST-AWSKEY-01 bound_by)" 'bound_by'
assert_eq '' "$(state_history_boundary_field SAST-PY-EVAL-01 oldest_commit)" \
  'a non-history check carries no history_boundary at all'

t_case 'findings round-trip, including the history and derived special cases'
assert_eq "$(printf 'fp-ordinary-1\nfp-history-1\nfp-composite-1')" "$(state_finding_fingerprints)" \
  'every finding fingerprint round-trips, in the order state_add_finding was called'
assert_eq 'SAST-PY-EVAL-01' "$(state_finding_field fp-ordinary-1 check_id)" 'ordinary finding check_id'
assert_eq 'src' "$(state_finding_field fp-ordinary-1 cell)" 'ordinary finding cell'
assert_eq 'high' "$(state_finding_field fp-ordinary-1 severity)" 'severity'
assert_eq '2026-05-01T00:00:00Z' "$(state_finding_field fp-ordinary-1 first_seen)" 'first_seen preserved'
assert_eq 'false' "$(state_finding_field fp-ordinary-1 suppressed)" 'suppressed=false round-trips'
assert_eq '' "$(state_finding_field fp-ordinary-1 oldest_reaching_commit_time)" \
  'an ordinary finding has no oldest_reaching_commit_time'

t_case 'a SAST-HIST-* finding carries oldest_reaching_commit_time and can be suppressed'
assert_eq '2025-08-15T00:00:00Z' "$(state_finding_field fp-history-1 oldest_reaching_commit_time)" \
  'oldest_reaching_commit_time round-trips'
assert_eq 'true' "$(state_finding_field fp-history-1 suppressed)" \
  'a SUPPRESSED finding is still persisted (tension 11 stage 8: ALL findings, including suppressed)'

t_case 'a derived finding has a JSON null cell, never the string "none" or an empty string sentinel confused with a real cell (tension 12)'
assert_eq '' "$(state_finding_field fp-composite-1 cell)" \
  'the in-memory representation of a derived finding cell is empty, matching the invariant that a real cell is never empty'
assert_true "$(grep -q '"cell":null' "$SD1/run-1.json" && echo 0 || echo 1)" \
  'the ON-DISK byte is the JSON literal null, never a quoted string'
assert_eq "$(printf 'fp-ordinary-1\nfp-history-1')" "$(state_finding_field fp-composite-1 contributors)" \
  'contributors round-trip, in the order given, only for a derived finding'
assert_eq '' "$(state_finding_field fp-ordinary-1 contributors)" \
  'an ordinary (non-derived) finding carries no contributors'

# ---------------------------------------------------------------------------
printf '\n-- pruning: state_retain_runs (default 30), never latest.json --\n'
# ---------------------------------------------------------------------------
SD2=$W/store2
mkdir -p "$SD2"
for id in run-a run-b run-c run-d run-e; do
  state_reset
  state_set_run "$id" 'path:/x' 'fp/1' '0.9.0' '2026-01-01T00:00:00Z'
  state_write "$SD2" 3
done

t_case 'state_prune (via state_write) keeps only the newest RETAIN_COUNT run files'
assert_eq "$(printf 'run-c\nrun-d\nrun-e')" \
  "$(find "$SD2" -maxdepth 1 -name '*.json' ! -name latest.json -exec basename {} .json \; | LC_ALL=C sort)" \
  'FAILS under a pruning rule keyed on anything other than the newest N names (run-a, run-b were pruned)'
assert_file_exists "$SD2/latest.json" 'latest.json is never a pruning candidate'
assert_eq "$(cat "$SD2/run-e.json")" "$(cat "$SD2/latest.json")" \
  'latest.json still tracks the most recently written run after pruning'

t_case 'a non-numeric retain count falls back to the documented default rather than pruning everything or nothing'
SD2B=$W/store2b
mkdir -p "$SD2B"
state_reset
state_set_run 'only-run' 'path:/x' 'fp/1' '0.9.0' '2026-01-01T00:00:00Z'
state_write "$SD2B" not-a-number
assert_file_exists "$SD2B/only-run.json" \
  'FAILS if a bad retain argument prunes the one file that was just written'

# ---------------------------------------------------------------------------
printf '\n-- state_load_latest reads STATE_DIR/latest.json --\n'
# ---------------------------------------------------------------------------
t_case 'state_load_latest with an explicit directory'
state_load_latest "$SD1"
assert_true "$(state_loaded && echo 0 || echo 1)" 'loads the same run state_write just produced'
assert_eq 'run-1' "$(state_field run_id)" 'and it is the right one'

# ---------------------------------------------------------------------------
printf '\n-- the loader on a hand-authored fixture (never touched by our own writer) --\n'
# ---------------------------------------------------------------------------
t_case 'a hand-authored fixture with shuffled key order loads identically to the API-built one'
state_load_file "$FIX/valid-full.json"
assert_true "$(state_loaded && echo 0 || echo 1)" \
  'FAILS if the loader silently depends on the order the writer happens to use'
assert_eq 'fp/1' "$(state_field fp_schema)" 'fp_schema'
assert_eq 'git-remote:https://example.invalid/org/proj' "$(state_field scan_root_id)" 'scan_root_id'
assert_eq "$(printf 'CLOUD-EC2-SG_OPEN-01\nDAST-XSS-REFLECT-01\nPOSTURE-SAML-ENFORCED-01\nSAST-HIST-AWSKEY-01\nSAST-PY-EVAL-01')" \
  "$(state_covered_check_ids | LC_ALL=C sort)" 'all five covered checks are present'
assert_eq '' "$(state_finding_field fp-composite-1 cell)" \
  'the JSON null cell in a hand-authored fixture decodes the same way the one this file writes does'
assert_eq "$(printf 'fp-ordinary-1\nfp-history-1')" "$(state_finding_field fp-composite-1 contributors)" \
  'contributors decode correctly from a hand-authored array too'

# ---------------------------------------------------------------------------
printf '\n-- missing or unreadable state: "no prior state", never an error --\n'
# ---------------------------------------------------------------------------
t_case 'a state file that does not exist'
state_load_file "$W/does-not-exist.json"
assert_true "$(state_loaded && echo 1 || echo 0)" \
  'FAILS if a missing file is somehow reported loaded'
assert_contains "$(state_load_reason)" 'no prior state' \
  'the reason says "no prior state", not "error" - this is the ordinary first-run case (tension 12)'

t_case 'a state directory that does not exist at all'
state_load_latest "$W/no-such-state-dir"
assert_true "$(state_loaded && echo 1 || echo 0)" 'FAILS if an absent directory is somehow loaded'
assert_contains "$(state_load_reason)" 'no prior state' 'same "no prior state" reason, not a hard error'

# ---------------------------------------------------------------------------
printf '\n-- the loader REJECTS a malformed record; it never half-loads one --\n'
# ---------------------------------------------------------------------------
# Every case below is chosen to fail under "parse what you can, ignore the
# rest": each fixture is otherwise well-formed, so a reader that stops
# validating after the first usable field would report state_loaded=true with
# some fields populated - the failure mode this section exists to catch.

t_case 'syntactically invalid JSON is rejected, not partially parsed'
state_load_file "$FIX/malformed-truncated.json"
assert_true "$(state_loaded && echo 1 || echo 0)" 'FAILS if truncated JSON is accepted'
assert_contains "$(state_load_reason)" 'unparsable' 'the reason names it unparsable'
assert_eq '' "$(state_field fp_schema)" \
  'FAILS under half-loading: the fp_schema field DOES appear before the truncation point'
assert_eq '' "$(state_field run_id)" 'run_id is likewise not exposed after rejection'

t_case 'a duplicate fingerprint across two findings is rejected (tension 5: fingerprints are unique per run)'
state_load_file "$FIX/malformed-duplicate-fingerprint.json"
assert_true "$(state_loaded && echo 1 || echo 0)" 'FAILS if a duplicate fingerprint is silently accepted'
assert_contains "$(state_load_reason)" 'duplicate fingerprint' 'the reason names the duplicate'
assert_eq '' "$(state_finding_fingerprints)" \
  'FAILS under half-loading: neither finding is exposed after rejection, not even the first one seen'

t_case 'a finding missing its required "cell" key entirely is rejected, never treated as a derived (null-cell) finding'
state_load_file "$FIX/malformed-missing-cell.json"
assert_true "$(state_loaded && echo 1 || echo 0)" \
  'FAILS if an absent key is silently conflated with an explicit JSON null'
assert_contains "$(state_load_reason)" 'missing cell' 'the reason names the missing field'

t_case 'a covered_checks entry with a scope outside the frozen five-kind table is rejected'
state_load_file "$FIX/malformed-invalid-scope.json"
assert_true "$(state_loaded && echo 1 || echo 0)" 'FAILS if an unrecognised coverage-scope value is accepted'
assert_contains "$(state_load_reason)" 'invalid scope' 'the reason names the bad scope value'

t_case 'a finding with a non-boolean suppressed value is rejected'
BAD1=$W/bad-suppressed.json
cat >"$BAD1" <<'JSON'
{"fp_schema":"fp/1","tool_version":"0.9.0","run_id":"r1",
 "completed_at":"2026-01-01T00:00:00Z","scan_root_id":"path:/x",
 "covered_checks":{},
 "findings":[{"fingerprint":"f1","check_id":"C1","cell":".","severity":"low",
              "first_seen":"a","last_seen":"a","suppressed":"yes"}]}
JSON
state_load_file "$BAD1"
assert_true "$(state_loaded && echo 1 || echo 0)" \
  'FAILS if a non-boolean JSON value for suppressed is accepted'
assert_contains "$(state_load_reason)" 'non-boolean suppressed' 'the reason names the type mismatch'

t_case 'a covered_checks entry with an empty cells array is rejected'
BAD2=$W/bad-empty-cells.json
cat >"$BAD2" <<'JSON'
{"fp_schema":"fp/1","tool_version":"0.9.0","run_id":"r1",
 "completed_at":"2026-01-01T00:00:00Z","scan_root_id":"path:/x",
 "covered_checks":{"C1":{"rule_digest":"d","scope":"path-root","cells":[]}},
 "findings":[]}
JSON
state_load_file "$BAD2"
assert_true "$(state_loaded && echo 1 || echo 0)" \
  'FAILS if a check covered over zero cells is accepted as coverage'
assert_contains "$(state_load_reason)" 'no cells' 'the reason names the empty cell set'

t_case 'a state file missing a required top-level field (scan_root_id) is rejected'
BAD3=$W/bad-no-root.json
cat >"$BAD3" <<'JSON'
{"fp_schema":"fp/1","tool_version":"0.9.0","run_id":"r1",
 "completed_at":"2026-01-01T00:00:00Z",
 "covered_checks":{},"findings":[]}
JSON
state_load_file "$BAD3"
assert_true "$(state_loaded && echo 1 || echo 0)" \
  'FAILS if a state file with no scan_root_id is accepted - the STATE-03 guards read this field unconditionally'
assert_contains "$(state_load_reason)" "scan_root_id" 'the reason names the missing field'

t_case 'a state file missing a required per-finding field (severity) is rejected'
BAD4=$W/bad-no-severity.json
cat >"$BAD4" <<'JSON'
{"fp_schema":"fp/1","tool_version":"0.9.0","run_id":"r1",
 "completed_at":"2026-01-01T00:00:00Z","scan_root_id":"path:/x",
 "covered_checks":{},
 "findings":[{"fingerprint":"f1","check_id":"C1","cell":".",
              "first_seen":"a","last_seen":"a","suppressed":false}]}
JSON
state_load_file "$BAD4"
assert_true "$(state_loaded && echo 1 || echo 0)" 'FAILS if a finding with no severity is accepted'
assert_contains "$(state_load_reason)" 'missing severity' 'the reason names the missing field'

t_case 'after ANY rejection, a stale prior load does not leak through the accessors'
# Load something good first, then something bad, and confirm the bad load did
# not just leave the previous good data sitting there unnoticed.
state_load_file "$SD1/run-1.json"
assert_true "$(state_loaded && echo 0 || echo 1)" 'sanity: the good load really did succeed'
state_load_file "$FIX/malformed-duplicate-fingerprint.json"
assert_true "$(state_loaded && echo 1 || echo 0)" 'the bad load is reported as not loaded'
assert_eq '' "$(state_field run_id)" \
  'FAILS if state_load_file forgets to clear the PREVIOUS successful load on a later failure'
assert_eq '' "$(state_finding_fingerprints)" 'no findings from the earlier good load remain visible either'

# ---------------------------------------------------------------------------
printf '\n-- escaping fidelity: a value with a quote, a backslash and a real newline --\n'
# ---------------------------------------------------------------------------
t_case 'json_string/the flattener agree on round-tripping hostile bytes'
HOSTILE=$'tool "v" \\1.0\nline2'
SD3=$W/store3
mkdir -p "$SD3"
state_reset
state_set_run 'run-hostile' 'path:/x' 'fp/1' "$HOSTILE" '2026-01-01T00:00:00Z'
state_write "$SD3" 30
state_load_file "$SD3/run-hostile.json"
assert_true "$(state_loaded && echo 0 || echo 1)" 'the hostile-value run still loads'
assert_eq "$HOSTILE" "$(state_field tool_version)" \
  'a quote, a backslash and an embedded newline all survive a write/read round trip byte for byte'

# ---------------------------------------------------------------------------
printf '\n-- misuse of the write-side API dies loudly rather than silently corrupting state --\n'
# ---------------------------------------------------------------------------
t_case 'state_write before state_set_run'
state_reset
assert_status 5 'FAILS if writing with no run_id silently produces a file' state_write "$W/should-not-exist"
assert_file_absent "$W/should-not-exist" 'no directory was created by the failed call'

t_case 'state_add_finding called twice for the same fingerprint'
state_reset
state_set_run 'run-dup' 'path:/x' 'fp/1' '0.9.0' '2026-01-01T00:00:00Z'
state_add_finding 'dup' 'C1' '.' 'low' 'a' 'a' false
assert_status 5 'FAILS if a second call for the same fingerprint is silently accepted' \
  state_add_finding dup C1 . low a a false

t_case 'state_add_covered with an empty cell'
state_reset
state_set_run 'run-emptycell' 'path:/x' 'fp/1' '0.9.0' '2026-01-01T00:00:00Z'
assert_status 5 'FAILS if an empty cell string is silently persisted (it collides with the derived-finding null sentinel)' \
  state_add_covered C1 digest path-root ''

t_summary state
