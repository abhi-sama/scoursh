#!/usr/bin/env bash
# tests/suites/sast.sh - modules/sast/{engine.sh,run.sh} and the four seed
# rule packs (docs/DESIGN.md §13 step 3a).
#
# Covers this ticket's acceptance criteria:
#   - the engine walks via scan_match only (tension 4), never bare grep/rg
#     (proved indirectly: every assertion below depends on scan_match
#     working, and tests/lint-shell.sh separately proves no bare call exists)
#   - the four seed packs load/validate through lib/records.sh
#   - check selection goes through lib/checks.sh (checks_run reflects real
#     execution)
#   - fingerprints exclude the line number and carry a correct occurrence
#     ordinal for repeat matches in one file
#   - F4 is closed, with a test that fails under the pre-fix (window-2)
#     reading
#   - true-positive detection for each pack
#   - `scan.sh sast --fail-on ... --fail-on-new` against tests/fixtures/vuln
#     exits non-zero
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sast/engine.sh
source "$ROOT/modules/sast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIXTURES=$ROOT/tests/fixtures/sast
W=$SCOURSH_SCRATCH/sast-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- glob matching (rules/RULE-FORMAT.md §9.1.2) --\n'
# =============================================================================
t_case '`*` matches within one path segment, not across `/`'
assert_status 0 '*.py matches a top-level file' sast_glob_match '*.py' 'app.py'
assert_status 0 '*.py matches at any depth when unanchored' sast_glob_match '*.py' 'a/b/app.py'
assert_status 1 '*.py does NOT match a .pyc file - fails if * were treated as .*' \
  sast_glob_match '*.py' 'app.pyc'

t_case '`**` matches across `/`, `*` does not'
assert_status 0 '**/Dockerfile matches at depth' sast_glob_match '**/Dockerfile' 'infra/x/Dockerfile'
# An ANCHORED comparison, since an UNANCHORED glob is deliberately tried at
# every depth (§9.1.2: "without [a leading /] the glob may match at any
# depth") - `*/Dockerfile` unanchored matching `infra/x/Dockerfile` two
# segments deep is therefore correct (it starts matching at "x/Dockerfile"),
# not evidence that `*` crossed a `/`.  Anchoring removes that "start
# anywhere" leniency, which is what isolates whether `*` itself crossed `/`.
assert_status 1 '/*/Dockerfile (anchored) does NOT match two directories deep - fails if * were read as **' \
  sast_glob_match '/*/Dockerfile' 'infra/x/Dockerfile'
assert_status 0 '/*/Dockerfile (anchored) DOES match exactly one directory deep' \
  sast_glob_match '/*/Dockerfile' 'infra/Dockerfile'

t_case 'a leading `/` anchors to the scan root'
assert_status 0 '/infra/**/*.tf matches from the root' sast_glob_match '/infra/**/*.tf' 'infra/net/vpc.tf'
assert_status 1 '/infra/**/*.tf does NOT match elsewhere - fails if a leading / were ignored' \
  sast_glob_match '/infra/**/*.tf' 'other/infra/net/vpc.tf'

t_case 'without a leading `/` the glob may match at any depth, not only the root'
assert_status 0 'app.py (no leading /) matches at depth too' sast_glob_match 'app.py' 'a/b/app.py'

# =============================================================================
printf -- '\n-- F4 (docs/FOUNDATION.md): context-deny window discipline --\n'
# =============================================================================
# The exact hazard F4 closes: a context-deny with context-window: 2 lets a
# SafeLoader mention belonging to a DIFFERENT, unrelated call suppress a
# genuine finding two lines away.  context-window: 0 does not.
CTXFILE=$W/yaml_context.py
cat >"$CTXFILE" <<'PYEOF'
data = yaml.load(request.body)
# unrelated comment two lines below
loader = SafeLoader
PYEOF
TOTAL=$(awk 'END{print NR}' "$CTXFILE")

t_case 'F4 regression: the SAME file, the SAME line, two different context-window readings disagree'
# Two complete, valid pattern-rule records sharing everything but
# context-window, loaded through the real lib/records.sh parser (not poked
# into its internal maps), so this exercises exactly the path a shipped pack
# does.
F4RULES=$W/context-f4.rules
cat >"$F4RULES" <<'RULEEOF'
id: SAST-TEST-F4-WIN0
title: F4 regression fixture, context-window 0 (the fixed reading)
severity: high
confidence: medium
cwe: none
owasp: none
pattern: \byaml\.load\s*\(
dialect: ere
context-deny: (SafeLoader|CSafeLoader|BaseLoader|yaml\.safe_load)
context-window: 0
tags: static
remediation: Test fixture only.

id: SAST-TEST-F4-WIN2
title: F4 regression fixture, context-window 2 (the PRE-FIX reading this ticket closes)
severity: high
confidence: medium
cwe: none
owasp: none
pattern: \byaml\.load\s*\(
dialect: ere
context-deny: (SafeLoader|CSafeLoader|BaseLoader|yaml\.safe_load)
context-window: 2
tags: static
remediation: Test fixture only.
RULEEOF
records_load "$F4RULES" pattern-rule f4set >/dev/null

assert_status 0 \
  'context-window: 0 (the F4-fixed reading) still reports the genuine finding on line 1 - fails under a reading where the deny leaks across lines even at window 0' \
  sast_context_ok f4set 0 "$CTXFILE" 1 "$TOTAL"
assert_status 1 \
  'context-window: 2 (the PRE-FIX reading this ticket closes) suppresses the SAME genuine finding - this is F4 itself: a test that FAILS under the old reading (i.e. this assertion is false under context-window:2, which is exactly the bug)' \
  sast_context_ok f4set 1 "$CTXFILE" 1 "$TOTAL"

t_case 'the SHIPPED SAST-PY-YAML_UNSAFE_LOAD-01 pins context-window: 0, not the pre-fix 2'
records_load "$ROOT/modules/sast/rules/python.rules" pattern-rule pyset
idx=$(records_index_of_id pyset SAST-PY-YAML_UNSAFE_LOAD-01)
assert_eq 0 "$(records_field pyset "$idx" context-window)" \
  'shipped python.rules yaml.load rule carries context-window: 0 - fails if it were ever reverted to the pre-fix 2'

# =============================================================================
printf -- '\n-- true-positive detection, one pack at a time --\n'
# =============================================================================
_scan_one_pack() {
  local pack=$1 fixture=$2 rundir=$3
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=sast-suite
  SCOURSH_PATH_ROOT=$(path_root_cell "$fixture")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$fixture")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_SAST_MAX_MATCHES_PER_FILE=200
  CHECKS_REGISTRY_SETS=(pkset)
  records_load "$ROOT/modules/sast/rules/$pack.rules" pattern-rule pkset >/dev/null
  sast_index_checks
  local -a ids=()
  local n i
  n=$(records_count pkset)
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id pkset "$i")"); done
  # `fixture` is always a DIRECTORY (docs/DESIGN.md §5's grammar is `--path
  # DIR`, never a single file), so loc_path/`files` glob matching resolve
  # against the scan root exactly like a real invocation, no single-file
  # edge case to route around.
  sast_scan_tree "$fixture" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
}

_ids_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[check_id]}"
  done <"$rundir/findings.fields"
}

for _pair in \
  'secrets:SAST-SEC-AWS_AKID-01 SAST-SEC-PRIVATE_KEY-01 SAST-SEC-GENERIC_API_KEY-01 SAST-SEC-GENERIC_PASSWORD-01 SAST-SEC-JWT-01' \
  'crypto:SAST-CRY-WEAK_HASH-01 SAST-CRY-DES_ECB-01 SAST-CRY-HARDCODED_IV-01 SAST-CRY-TLS_VERIFY_DISABLED-01 SAST-CRY-WEAK_RANDOM_TOKEN-01' \
  'injection:SAST-INJ-OS_COMMAND-01 SAST-INJ-SQL_CONCAT-01 SAST-INJ-CRLF_HEADER-01 SAST-INJ-HOST_HEADER_TRUST-01 SAST-INJ-SSTI-01 SAST-INJ-OPEN_REDIRECT-01 SAST-INJ-MASS_ASSIGNMENT-01 SAST-INJ-XXE-01' \
  'python:SAST-PY-PICKLE_LOAD-01 SAST-PY-SUBPROCESS_SHELL-01 SAST-PY-OS_SYSTEM-01 SAST-PY-FLASK_DEBUG-01 SAST-PY-JINJA_AUTOESCAPE_FALSE-01' \
  ; do
  _pack=${_pair%%:*}
  _want=${_pair#*:}
  _scan_one_pack "$_pack" "$FIXTURES" "$W/run-$_pack"
  _found=$(_ids_found "$W/run-$_pack")
  for _want_id in $_want; do
    t_case "$_pack: $_want_id true-positive detection"
    assert_contains "$_found" "$_want_id" \
      "$_want_id fires on its fixture - fails if the pattern, files glob, or context directive silently drops the match"
  done
done
unset _pair _pack _want _fixture _found _want_id

# =============================================================================
printf -- '\n-- go.rules (docs/DESIGN.md §13 step 3c): one fixture per rule id --\n'
# =============================================================================
# Unlike the four §13 step 3a packs above (one combined fixture per pack
# under tests/fixtures/sast/), go.rules ships one true-positive fixture per
# rule id under tests/fixtures/vuln/ and one true-negative (safe-equivalent)
# fixture per rule id under tests/fixtures/clean/, per this ticket's own
# acceptance criteria. Both directories already carry non-Go fixtures used
# by other suites/cases in this file, so scanning them wholesale (as the
# exit-code-flip cases below already do) is exactly the real-world shape:
# a mixed-language tree, one rule pack's `files: *.go` glob doing the
# filtering.
_scan_one_pack go "$ROOT/tests/fixtures/vuln" "$W/run-go-vuln"
_go_vuln_found=$(_ids_found "$W/run-go-vuln")
for _go_id in SAST-GO-EXEC_CONCAT-01 SAST-GO-TEMPLATE_HTML-01 SAST-GO-WEAK_RANDOM-01 \
  SAST-GO-SQL_CONCAT-01 SAST-GO-TLS_SKIP_VERIFY-01; do
  t_case "go: $_go_id true-positive detection"
  assert_contains "$_go_vuln_found" "$_go_id" \
    "$_go_id fires on tests/fixtures/vuln/*.go - fails if the pattern, files glob, or context directive silently drops the match"
done

_scan_one_pack go "$ROOT/tests/fixtures/clean" "$W/run-go-clean"
_go_clean_found=$(_ids_found "$W/run-go-clean")
for _go_id in SAST-GO-EXEC_CONCAT-01 SAST-GO-TEMPLATE_HTML-01 SAST-GO-WEAK_RANDOM-01 \
  SAST-GO-SQL_CONCAT-01 SAST-GO-TLS_SKIP_VERIFY-01; do
  t_case "go: $_go_id stays quiet on its safe equivalent"
  assert_not_contains "$_go_clean_found" "$_go_id" \
    "$_go_id does NOT fire on tests/fixtures/clean/*.go - fails if the safe equivalent were not actually safe, or the rule over-matched"
done
unset _go_id _go_vuln_found _go_clean_found

t_case 'secrets: the placeholder password literal is suppressed by context-deny (context-window: 0)'
assert_not_contains "$(_ids_found "$W/run-secrets")" 'nonexistent-marker-CHANGEME_PLACEHOLDER' \
  'sanity: the suppressed literal never appears as its own check id (guards the test itself against a typo)'
# A DIRECT count check: SAST-SEC-GENERIC_PASSWORD-01 must fire exactly ONCE
# (the real "correcthorsebattery" password), not twice (the CHANGEME one too).
_pw_count=$(_ids_found "$W/run-secrets" | grep -c '^SAST-SEC-GENERIC_PASSWORD-01$' || true)
assert_eq 1 "$_pw_count" \
  'exactly one password finding, not two - fails if the CHANGEME placeholder were not suppressed by context-deny'

# =============================================================================
printf -- '\n-- occurrence ordinal and fingerprint (docs/FOUNDATION.md tension 5) --\n'
# =============================================================================
# tests/fixtures/vuln/app.py already carries three byte-identical eval()
# matches in one file - the exact fixture step 1 built for this discriminator.
occurrence_reset_all
_scan_one_pack python "$ROOT/tests/fixtures/vuln" "$W/run-vuln-occ"

t_case 'three byte-identical eval() matches in one file get three DIFFERENT fingerprints'
_fps=()
while IFS= read -r _line; do
  [[ -n $_line ]] || continue
  finding_decode "$_line"
  [[ ${_DF[check_id]} == SAST-PY-EVAL_EXEC-01 ]] || continue
  _fps+=("${_DF[fingerprint]}")
done <"$W/run-vuln-occ/findings.fields"
assert_eq 3 "${#_fps[@]}" 'three eval() findings were emitted for the fixture file'
assert_ne "${_fps[0]:-a}" "${_fps[1]:-b}" 'occurrence 0 and 1 fingerprints differ'
assert_ne "${_fps[1]:-a}" "${_fps[2]:-b}" 'occurrence 1 and 2 fingerprints differ'
assert_ne "${_fps[0]:-a}" "${_fps[2]:-c}" 'occurrence 0 and 2 fingerprints differ'
unset _fps _line

t_case 'the fingerprint excludes the line number (tension 5): re-running the identical fixture is byte-reproducible'
occurrence_reset_all
_scan_one_pack python "$ROOT/tests/fixtures/vuln" "$W/run-vuln-occ2"
# first_seen/last_seen are the run's own wall-clock timestamp (SCOURSH_RUN_TIMESTAMP,
# lib/core.sh run_init) and are the ONE field this comparison must blank before
# diffing: two runs a second apart are still byte-reproducible in every
# FINGERPRINT-relevant field, which is what tension 17 actually claims. Left
# unblanked, this assertion would spuriously fail on nothing but wall-clock
# drift between the two runs, which is not the hazard this test guards
# against - a volatile value INSIDE the fingerprint (a line number) would
# instead show up as a different `fingerprint=` value, still caught below.
_normalise_timestamps() {
  # A field-aware normaliser, not a `sed` character class: `\t` inside a
  # POSIX/BSD bracket expression is NOT a tab (it is the two literal bytes
  # `\` and `t`, a GNU-only extension elsewhere) - measured, not assumed:
  # `[^\t]*` under BSD sed happily crosses a REAL tab and only stops at the
  # next literal `t` byte, corrupting every field after the first one.  awk's
  # own field splitting has no such ambiguity.
  awk -F'\t' 'BEGIN{OFS="\t"} {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^(first_seen|last_seen)=/) $i = substr($i, 1, index($i, "=")) "X"
    }
    print
  }' "$1"
}
assert_eq "$(_normalise_timestamps "$W/run-vuln-occ/findings.fields" | LC_ALL=C sort)" \
  "$(_normalise_timestamps "$W/run-vuln-occ2/findings.fields" | LC_ALL=C sort)" \
  'two independent runs over the identical tree produce byte-identical findings.fields once wall-clock timestamps are normalised (docs/FOUNDATION.md tension 17) - would fail if any FINGERPRINT-relevant field (loc_path, loc_occurrence, loc_match_digest, fingerprint itself) were a volatile value such as a line number'

# =============================================================================
printf -- '\n-- check selection integration: lib/checks.sh really gates what runs --\n'
# =============================================================================
ROOT_REAL_REGISTRY=$W/root-real-registry
mkdir -p "$ROOT_REAL_REGISTRY/config" "$ROOT_REAL_REGISTRY/modules/sast/rules"
printf 'id: scanner\n' >"$ROOT_REAL_REGISTRY/config/scanner.conf"
# The real run.sh/engine.sh too, not just the rules - scan_dispatch resolves
# $SCOURSH_INSTALL_ROOT/modules/sast/run.sh, so a fixture root carrying only
# *.rules would silently take the "module has no run.sh yet" no-op path
# instead of actually running anything.
cp "$ROOT/modules/sast/run.sh" "$ROOT/modules/sast/engine.sh" "$ROOT_REAL_REGISTRY/modules/sast/"
cp "$ROOT/modules/sast/rules/secrets.rules" "$ROOT_REAL_REGISTRY/modules/sast/rules/secrets.rules"
cp "$ROOT/modules/sast/rules/crypto.rules" "$ROOT_REAL_REGISTRY/modules/sast/rules/crypto.rules"
ROOT_REAL_REGISTRY=$(cd -- "$ROOT_REAL_REGISTRY" && pwd -P)

t_case '--profile-scan quick selects only quick-tagged checks; a full-only check from the SAME pack does not run'
rm -rf "$W/run-quick-profile"
SCOURSH_INSTALL_ROOT=$ROOT_REAL_REGISTRY bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --profile-scan quick --out "$W/run-quick-profile" >/dev/null 2>&1
assert_contains "$(cat "$W/run-quick-profile/meta/checks_run" 2>/dev/null)" 'SAST-SEC-AWS_AKID-01' \
  'quick-tagged SAST-SEC-AWS_AKID-01 is recorded as actually run under --profile-scan quick'
assert_not_contains "$(cat "$W/run-quick-profile/meta/checks_run" 2>/dev/null)" 'SAST-CRY-HARDCODED_IV-01' \
  'full-only SAST-CRY-HARDCODED_IV-01 is NOT recorded as run under --profile-scan quick - this is checks_run reflecting REAL execution, not the placeholder'

t_case '--profile-scan full (the default) runs both'
rm -rf "$W/run-full-profile"
SCOURSH_INSTALL_ROOT=$ROOT_REAL_REGISTRY bash "$ROOT/scan.sh" sast --path "$FIXTURES" \
  --out "$W/run-full-profile" >/dev/null 2>&1
assert_contains "$(cat "$W/run-full-profile/meta/checks_run" 2>/dev/null)" 'SAST-SEC-AWS_AKID-01' \
  'quick-tagged check still runs under the default full profile'
assert_contains "$(cat "$W/run-full-profile/meta/checks_run" 2>/dev/null)" 'SAST-CRY-HARDCODED_IV-01' \
  'full-only check ALSO runs under the default - fails under "no --profile-scan silently narrows the scan"'

# =============================================================================
printf -- '\n-- exit-code flip (this ticket''s last acceptance criterion) --\n'
# =============================================================================
t_case 'scan.sh sast tests/fixtures/vuln --fail-on high --fail-on-new now exits non-zero'
assert_status "$SCOURSH_EXIT_GATE" \
  'a real subprocess against the vuln fixture, gated on high+, exits the GATE code - fails under the pre-ticket reading where scan_dispatch sast was a no-op and every gate stayed 0' \
  bash "$ROOT/scan.sh" sast --path "$ROOT/tests/fixtures/vuln" --fail-on high --fail-on-new --out "$W/run-gate"

t_case 'the SAME command against the clean fixture still exits 0 - the gate is not a blanket failure'
assert_status 0 \
  'no findings at/above high on the clean fixture, so the gate does not trip' \
  bash "$ROOT/scan.sh" sast --path "$ROOT/tests/fixtures/clean" --fail-on high --fail-on-new --out "$W/run-gate-clean"

t_case 'without --fail-on, the vuln fixture still exits 0 - the gate is opt-in, never ambient'
assert_status 0 \
  'no --fail-on given means not-evaluated, never a silent gate - fails if the gate fired without being asked' \
  bash "$ROOT/scan.sh" sast --path "$ROOT/tests/fixtures/vuln" --out "$W/run-no-gate"

t_summary 'sast' || FAILED=1
exit "${FAILED:-0}"
