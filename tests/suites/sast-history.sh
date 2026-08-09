#!/usr/bin/env bash
# tests/suites/sast-history.sh - modules/sast/history.sh (docs/DESIGN.md §6.3,
# docs/FOUNDATION.md tension 13, §13 step 3e).
#
# Covers this ticket's acceptance criteria:
#   - history.sh only does real work when --history was requested AND the
#     scan root is a git repo; every other case (not requested, not a repo,
#     a shallow clone, a repo with zero commits) is a clean no-op with a
#     logged reason
#   - it replays secrets.rules ONLY, never the full check registry, within a
#     bounded and operator-configurable commit/time window
#     (history-window-days / history-max-commits, config/scanner.conf's own
#     CLI > env > file > default precedence - proved here through the env
#     layer, SCOURSH_CONFIG_HISTORY_WINDOW_DAYS /
#     SCOURSH_CONFIG_HISTORY_MAX_COMMITS)
#   - a history finding carries the SAST-HIST-* check-id family and the
#     blob_sha/cell/oldest_reaching_commit_time fields lib/findings.sh's
#     tension 12/13 machinery (the `history` fingerprint profile,
#     `_contributor_covered`'s SAST-HIST-* branch) already reads
#   - THE fixture: a secret committed then removed in a later commit - the
#     history scan finds it, the working-tree scan (modules/sast/engine.sh,
#     from the step 3a engine ticket) does not
#   - never a bare grep/rg over `git log -p`/`git rev-list` output (tension
#     4) - proved indirectly, same as tests/suites/sast.sh's own header
#     explains: every assertion below depends on scan_match_offsets working,
#     and tests/lint-shell.sh separately proves no bare call exists in
#     modules/sast/history.sh
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/sast/history.sh
source "$ROOT/modules/sast/history.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sast-history-suite
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
_new_repo() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" config user.email 'test@example.com'
  git -C "$dir" config user.name 'test'
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

# Runs ONLY _sast_history_run against REPO - the module under test - and
# merges its shard.  Callers set SCAN_FLAGS themselves first, so each t_case
# states its own intent rather than this helper hiding it.
_run_history() {
  local repo=$1 rundir=$2
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=sast-history-suite
  SCOURSH_PATH_ROOT=$(path_root_cell "$repo")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$repo")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  occurrence_reset_all
  _sast_history_run "$repo"
  findings_merge "$rundir"
}

# The working-tree engine (modules/sast/engine.sh), against secrets.rules
# only, over the SAME repo's current HEAD - the fixture's other half.
_run_working_tree_secrets() {
  local repo=$1 rundir=$2
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_PATH_ROOT=$(path_root_cell "$repo")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$repo")
  export SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  occurrence_reset_all
  local set=sast_history_suite_wt
  records_load "$ROOT/modules/sast/rules/secrets.rules" pattern-rule "$set" >/dev/null
  CHECKS_REGISTRY_SETS=("$set")
  sast_index_checks
  local -a ids=()
  local i n
  n=$(records_count "$set")
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id "$set" "$i")"); done
  sast_scan_tree "$repo" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
}

# =============================================================================
printf -- '\n-- gating: real work only when requested AND the scan root is a usable git repo --\n'
# =============================================================================
GATEREPO=$W/gate-repo
_new_repo "$GATEREPO"
printf 'print("hello")\n' >"$GATEREPO/app.py"
git -C "$GATEREPO" add app.py
git -C "$GATEREPO" commit -q -m 'a real commit, so this repo alone is not what any gate test below is pinning'

NONGIT=$W/non-git-dir
rm -rf "$NONGIT"
mkdir -p "$NONGIT"
printf 'aws_key = "AKIAABCDEFGHIJKLMNOP"\n' >"$NONGIT/app.py"

t_case '--history not requested (SCAN_FLAGS[history] unset): clean no-op even against a real, git-repo secret'
declare -A SCAN_FLAGS=()
printf 'aws_key = "AKIAABCDEFGHIJKLMNOP"\n' >>"$GATEREPO/app.py"
_run_history "$GATEREPO" "$W/run-not-requested"
assert_eq '' "$(_ids_found "$W/run-not-requested")" \
  'no findings when history was never requested - fails if the module scanned anyway regardless of the flag'
assert_contains "$(cat "$W/run-not-requested/meta/coverage_reduction" 2>/dev/null)" 'reason=history_not_requested' \
  'the skip reason is recorded even though nothing ran'
git -C "$GATEREPO" checkout -q -- app.py

t_case '--history requested against a directory that is not inside a git repository: clean no-op with a logged reason'
declare -A SCAN_FLAGS=([history]=true)
_run_history "$NONGIT" "$W/run-non-git"
assert_eq '' "$(_ids_found "$W/run-non-git")" 'no findings against a non-git directory - fails if the module tried to git -C a directory with no repo'
assert_contains "$(cat "$W/run-non-git/meta/coverage_reduction" 2>/dev/null)" 'reason=not_a_git_repo' \
  'the skip reason names the real cause'

t_case '--history requested against a shallow clone: clean no-op - fails if a truncated walk were silently reported as clean'
ORIGIN=$W/shallow-origin
_new_repo "$ORIGIN"
printf 'one\n' >"$ORIGIN/f.txt"
git -C "$ORIGIN" add f.txt
git -C "$ORIGIN" commit -q -m one
printf 'two\n' >>"$ORIGIN/f.txt"
git -C "$ORIGIN" add f.txt
git -C "$ORIGIN" commit -q -m two
SHALLOW=$W/shallow-clone
rm -rf "$SHALLOW"
git clone -q --depth 1 "file://$ORIGIN" "$SHALLOW"
_run_history "$SHALLOW" "$W/run-shallow"
assert_eq '' "$(_ids_found "$W/run-shallow")" 'no findings from a shallow clone'
assert_contains "$(cat "$W/run-shallow/meta/coverage_reduction" 2>/dev/null)" 'reason=shallow_clone' \
  'a shallow clone is skipped entirely (docs/FOUNDATION.md tension 13), not walked partially'

t_case '--history requested against a git repo with zero commits: clean no-op - fails if HEAD were dereferenced blindly'
EMPTYREPO=$W/empty-repo
_new_repo "$EMPTYREPO"
_run_history "$EMPTYREPO" "$W/run-empty-repo"
assert_eq '' "$(_ids_found "$W/run-empty-repo")" 'no findings from a commit-less repository'
assert_contains "$(cat "$W/run-empty-repo/meta/coverage_reduction" 2>/dev/null)" 'reason=no_commits' \
  'a commit-less repository is a clean no-op, not an error'

# =============================================================================
printf -- '\n-- THE fixture: a secret committed then removed in a later commit --\n'
# =============================================================================
SECRETREPO=$W/secret-history-repo
_new_repo "$SECRETREPO"
printf 'print("hello")\n' >"$SECRETREPO/app.py"
git -C "$SECRETREPO" add app.py
git -C "$SECRETREPO" commit -q -m 'initial commit'

printf 'print("hello")\naws_key = "AKIAABCDEFGHIJKLMNOP"\n' >"$SECRETREPO/app.py"
git -C "$SECRETREPO" add app.py
git -C "$SECRETREPO" commit -q -m 'oops, committed a secret'

printf 'print("hello")\n' >"$SECRETREPO/app.py"
git -C "$SECRETREPO" add app.py
git -C "$SECRETREPO" commit -q -m 'remove the secret from the working tree'

declare -A SCAN_FLAGS=([history]=true)
_run_history "$SECRETREPO" "$W/run-secret-history"
_run_working_tree_secrets "$SECRETREPO" "$W/run-secret-workingtree"

HIST_FOUND=$(_ids_found "$W/run-secret-history")
WT_FOUND=$(_ids_found "$W/run-secret-workingtree")

t_case 'history scan finds the secret that only ever exists in a now-superseded commit'
assert_contains "$HIST_FOUND" 'SAST-HIST-AWS_AKID-01' \
  'the AWS key blob is reachable within the window and gets replayed - fails if history.sh only ever looked at the current tree, exactly like the working-tree engine'

t_case 'the working-tree scan of the SAME repo, at the SAME HEAD, does not find it'
assert_eq '' "$WT_FOUND" \
  'the secret is absent from HEAD, so the working-tree engine (modules/sast/engine.sh) correctly reports nothing - fails if this assertion pins nothing, i.e. if the fixture were not actually clean at HEAD'

# =============================================================================
printf -- '\n-- the finding composes with tension 12/13: SAST-HIST-* family, blob_sha, cell, oldest_reaching_commit_time --\n'
# =============================================================================
t_case 'the check id is in the SAST-HIST-* family, never the working-tree SAST-SEC-* id'
assert_contains "$HIST_FOUND" 'SAST-HIST-' 'at least one SAST-HIST-* id fired'
assert_not_contains "$HIST_FOUND" 'SAST-SEC-' \
  'no working-tree SAST-SEC-* id ever comes out of history.sh - fails if it replayed the check under its original id, which would collide the two fingerprint profiles (path vs history, lib/findings.sh _fp_profile_for)'

FIELDS=$(cat "$W/run-secret-history/findings.fields")
t_case 'the finding record carries loc_blob_sha - the history fingerprint profile needs it (blob_sha, match_digest, occurrence)'
assert_contains "$FIELDS" 'loc_blob_sha=' \
  'fails if loc_blob_sha were left unset, silently falling back to the path profiles empty component and colliding every history finding onto one fingerprint'

t_case 'the finding carries a cell (the path-root coverage cell, tension 12) - required for the (check, cell) coverage test'
assert_contains "$FIELDS" 'cell=.' 'cell is recorded as "." (the repo root) - fails if history findings carried no cell at all, which tension 12s own text says must never happen'

t_case 'the finding carries oldest_reaching_commit_time - what lib/findings.sh _contributor_covered already reads out of a persisted prior-state line for SAST-HIST-* contributors'
assert_contains "$FIELDS" 'oldest_reaching_commit_time=' \
  'fails if left blank: once step 7 persists state/, every future composite depending on this contributor would read an empty c_time and could never be judged fixed'

t_case 'the finding carries a commit sha for navigation (tension 13: "the path, the earliest reaching commit, the line ... and the blob sha")'
assert_contains "$FIELDS" 'commit=' 'a commit= field is present'

# =============================================================================
printf -- '\n-- only secrets.rules is replayed, never the full check registry --\n'
# =============================================================================
MIXEDREPO=$W/mixed-repo
_new_repo "$MIXEDREPO"
cat >"$MIXEDREPO/app.py" <<'PYEOF'
import pickle, subprocess
pickle.loads(data)
subprocess.call(cmd, shell=True)
aws_key = "AKIAABCDEFGHIJKLMNOP"
PYEOF
git -C "$MIXEDREPO" add app.py
git -C "$MIXEDREPO" commit -q -m 'a secret alongside python.rules/injection.rules-style patterns, all in one commit'

declare -A SCAN_FLAGS=([history]=true)
_run_history "$MIXEDREPO" "$W/run-mixed-history"
MIXED_FOUND=$(_ids_found "$W/run-mixed-history")

t_case 'the secrets.rules check still fires from the same blob'
assert_contains "$MIXED_FOUND" 'SAST-HIST-AWS_AKID-01' 'the one secrets.rules-family pattern present fires'

t_case 'python.rules/injection.rules are never replayed against history - only secrets.rules (this tickets 2nd acceptance criterion)'
assert_not_contains "$MIXED_FOUND" 'SAST-HIST-PY-' \
  'no SAST-HIST-PY-* id - fails if history.sh loaded the full check registry (CHECKS_REGISTRY_SETS) instead of secrets.rules alone'
assert_not_contains "$MIXED_FOUND" 'SAST-HIST-INJ-' 'no SAST-HIST-INJ-* id for the same reason'

# =============================================================================
printf -- '\n-- the commit/time window is bounded AND operator-configurable --\n'
# =============================================================================
# Commit dates are set via GIT_AUTHOR_DATE/GIT_COMMITTER_DATE="@<epoch>" -
# git's own raw-epoch env-var format, computed with plain bash arithmetic off
# now_epoch (never `date -d`/`date -v`, per tension 24's one-capability-layer
# rule this repository's own lint enforces).  ~500 days back, not an
# arbitrary huge offset: measured, git's OWN relative-date approxidate parser
# (`--since="N days ago"`) silently fails to reach back correctly for very
# large N (hundreds of years), and `--since=@<epoch>` for a near-zero epoch
# is a second, unrelated quirk (see history.sh's own since_epoch floor
# comment) - neither hazard is anywhere near a few hundred days, which is
# also the realistic scale a leaked secret is actually found at.
WINDOWREPO=$W/window-repo
_new_repo "$WINDOWREPO"
OLD_EPOCH=$(( $(now_epoch) - 500 * 86400 ))

printf 'print("hello")\n' >"$WINDOWREPO/app.py"
git -C "$WINDOWREPO" add app.py
GIT_AUTHOR_DATE="@$OLD_EPOCH" GIT_COMMITTER_DATE="@$OLD_EPOCH" \
  git -C "$WINDOWREPO" commit -q -m 'a commit from ~500 days ago'

printf 'print("hello")\naws_key = "AKIAABCDEFGHIJKLMNOP"\n' >"$WINDOWREPO/app.py"
git -C "$WINDOWREPO" add app.py
GIT_AUTHOR_DATE="@$OLD_EPOCH" GIT_COMMITTER_DATE="@$OLD_EPOCH" \
  git -C "$WINDOWREPO" commit -q -m 'a secret, committed ~500 days ago'

printf 'print("hello")\n' >"$WINDOWREPO/app.py"
git -C "$WINDOWREPO" add app.py
git -C "$WINDOWREPO" commit -q -m 'recent, unrelated commit'

declare -A SCAN_FLAGS=([history]=true)

t_case 'the default history-window-days (365) does not reach a ~500-day-old commit'
_run_history "$WINDOWREPO" "$W/run-window-default"
assert_eq '' "$(_ids_found "$W/run-window-default")" \
  'the ~500-day-old secret falls outside the default 365-day window - fails if the window were unbounded, i.e. the walk always covered full history regardless of config'
assert_contains "$(cat "$W/run-window-default/meta/history_boundary" 2>/dev/null)" 'bound_by=window-days' \
  'the run records that the WINDOW, not the commit cap or the repo root, is what stopped the walk short of the secret'

t_case 'widening history-window-days (via the documented env layer, SCOURSH_CONFIG_HISTORY_WINDOW_DAYS) reaches the same secret'
SCOURSH_CONFIG_HISTORY_WINDOW_DAYS=800 _run_history "$WINDOWREPO" "$W/run-window-wide"
assert_contains "$(_ids_found "$W/run-window-wide")" 'SAST-HIST-AWS_AKID-01' \
  'the ~500-day-old secret IS found once the window is widened past 500 days - proves the window is a real, live, operator-configurable bound and not a hardcoded constant'

t_case 'history-max-commits bounds the walk independently of the time window'
SCOURSH_CONFIG_HISTORY_WINDOW_DAYS=800 SCOURSH_CONFIG_HISTORY_MAX_COMMITS=1 \
  _run_history "$WINDOWREPO" "$W/run-window-maxcommits"
assert_eq '' "$(_ids_found "$W/run-window-maxcommits")" \
  'history-max-commits=1 only walks the single most recent commit, missing the older secret even with the time window wide open - fails if max-commits were ignored'

t_summary 'sast-history' || FAILED=1
exit "${FAILED:-0}"
