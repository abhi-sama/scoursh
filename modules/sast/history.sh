#!/usr/bin/env bash
# modules/sast/history.sh - replays modules/sast/rules/secrets.rules against
# git history rather than the working tree (docs/DESIGN.md §6.3, §13 step 3e;
# docs/FOUNDATION.md tension 13).
#
# Owns:
#   docs/DESIGN.md      §6.3 "history.sh - replays the same secret rules
#                        across git history (`git log -p` / `git rev-list`)
#                        ... Bounded by a commit/time window; skipped if not
#                        a git repo."
#   docs/FOUNDATION.md  tension 13 - "scan blobs, not diffs": every distinct
#                        blob is scanned exactly once regardless of how many
#                        commits reference it; the `SAST-HIST-*` id family and
#                        the `history` fingerprint profile (blob_sha,
#                        match_digest, occurrence) that lib/findings.sh
#                        already carries; the occurrence ordinal scoped to the
#                        blob, not the path (tension 13 case 8); the
#                        per-finding `oldest_reaching_commit_time` and the
#                        run's `history_boundary` fact, which §13 step 7's
#                        diff engine reads once state/ exists.  Populating
#                        both correctly now, even though nothing consumes
#                        them yet, is what "composes correctly with tension
#                        12/13's coverage and SAST-HIST-* boundary rules
#                        already implemented in lib/findings.sh" (this
#                        ticket's own acceptance criterion) requires:
#                        lib/findings.sh's `_contributor_covered` (tension 13
#                        half) already reads `oldest_reaching_commit_time`
#                        out of a persisted prior-state line - see its
#                        comment - so a SAST-HIST-* finding that left the
#                        field blank would silently make every future
#                        composite depending on it `unknown` forever once
#                        step 7 lands.
#
# A pure function library, sourced once - engine.sh's own contract, not
# run.sh's (nothing here does real work merely by being sourced; the real
# work happens only when _sast_history_run is called).  Depends on engine.sh
# for sast_rule_matches_file / sast_context_ok / _sast_check_is_sensitive /
# _sast_capture_max_matches, and sources it if not already present, exactly
# the way engine.sh itself conditionally sources lib/report.sh and
# lib/config.sh - so a test that sources this file standalone (rather than
# through run.sh, which already sourced engine.sh first) still works.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SAST_HISTORY_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SAST_HISTORY_SOURCED=1

if [[ -z ${SCOURSH_SAST_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=modules/sast/engine.sh
  source "${BASH_SOURCE[0]%/*}/engine.sh"
fi

# ---------------------------------------------------------------------------
# 1. Entry point - called from modules/sast/run.sh, once per run, AFTER the
#    working-tree scan and BEFORE findings_merge, so history findings land in
#    the same shard as everything else this run produced.
# ---------------------------------------------------------------------------
# `--history` (docs/DESIGN.md §5's `sast [--path DIR] [--lang ...] [--history]`)
# is the operator's own opt-in - scan.sh's `require_cmd git` guard in
# scan_main already fires only when it is true - so an unset/false flag is a
# clean, silent-ish no-op: recorded via coverage_reduction like every other
# declared no-op in this codebase, but NOT a log_warn, because choosing not
# to replay history is the documented default, not degraded coverage.
#
# Every OTHER reason to skip (no git, not a repo, a shallow clone, no commits
# at all) only matters once history scanning was actually REQUESTED, and IS
# log_warn'd, because in each of those cases the operator asked for something
# this run could not deliver.
_sast_history_run() {
  local root=$1
  # Standalone-safe: SCAN_FLAGS is scan.sh's own global associative array.
  # When this module is exercised without scan.sh (a test sourcing only
  # engine.sh + history.sh), it never existed at all, and
  # `${SCAN_FLAGS[history]:-}` against a wholly UNDECLARED array is not the
  # safe "unset" case under `set -u`.
  #
  # engine.sh's sast_evaluate_gate guards the identical case with
  # `[[ ${SCAN_FLAGS+set} ]] || declare -A SCAN_FLAGS=()`, and that form is
  # NOT reused here: measured (bash 5.3.9, and this is not version-specific -
  # it is how `${arr+set}` has always worked), `${arr+set}` on an
  # associative array tests element `[0]`/`["0"]`, not "is the array
  # declared" - `declare -A G=([fail-on-new]=true); [[ ${G+set} ]]` is FALSE,
  # because there is no key literally named `0`.  Called from inside a
  # function, that makes the guard's RHS run unconditionally, and
  # `declare -A SCAN_FLAGS=()` inside a function - with no `-g` - creates a
  # new LOCAL that shadows the real global for the rest of this function's
  # body, so every subsequent `${SCAN_FLAGS[...]}` read in this function
  # would silently see empty regardless of what the caller actually set.
  # `declare -p SCAN_FLAGS &>/dev/null` tests declaredness directly and is
  # unaffected by which keys happen to be populated.
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()
  if [[ ${SCAN_FLAGS[history]:-} != true ]]; then
    run_record coverage_reduction 'module=sast reason=history_not_requested'
    return 0
  fi

  if ! _have git; then
    log_warn 'sast history: --history was requested but git is not installed - skipping git-history secret replay'
    run_record coverage_reduction 'module=sast reason=git_not_available'
    return 0
  fi

  local resolved scan_root
  resolved=$(realpath_of "$root")
  if ! scan_root=$(git -C "$resolved" rev-parse --show-toplevel 2>/dev/null) || [[ -z $scan_root ]]; then
    log_warn "sast history: --history was requested but '$resolved' is not inside a git repository - skipping git-history secret replay"
    run_record coverage_reduction 'module=sast reason=not_a_git_repo'
    return 0
  fi

  # A shallow clone silently truncates history; walking it would look exactly
  # like a clean repository and report a still-present secret as absent -
  # docs/FOUNDATION.md tension 13's own reason to skip entirely rather than
  # walk a partial, misleading window.
  if [[ $(git -C "$scan_root" rev-parse --is-shallow-repository 2>/dev/null) == true ]]; then
    log_warn 'sast history: shallow clone - history is truncated and a truncated walk would silently look like remediation (docs/FOUNDATION.md tension 13) - skipping git-history secret replay'
    run_record coverage_reduction 'module=sast reason=shallow_clone'
    return 0
  fi

  if ! git -C "$scan_root" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    log_warn 'sast history: repository has no commits yet - skipping git-history secret replay'
    run_record coverage_reduction 'module=sast reason=no_commits'
    return 0
  fi

  _sast_history_scan "$scan_root"
}

# ---------------------------------------------------------------------------
# 2. Bounded config capture (mirrors engine.sh's own _sast_capture_max_matches:
#    config_scanner_value can `die()`, and wrapping a die-capable function in
#    $(...) makes that die unreliable - scan.sh's own `_scan_capture` comment
#    measures why - so the value is captured through a scratch file instead).
# ---------------------------------------------------------------------------
_sast_history_capture_config() {
  local tmp=$SCOURSH_SCRATCH/_sast_hist_window.$$
  config_scanner_value history-window-days '' >"$tmp"
  printf '\n' >>"$tmp"
  IFS= read -r SCOURSH_SAST_HIST_WINDOW_DAYS <"$tmp"
  rm -f "$tmp"

  tmp=$SCOURSH_SCRATCH/_sast_hist_maxcommits.$$
  config_scanner_value history-max-commits '' >"$tmp"
  printf '\n' >>"$tmp"
  IFS= read -r SCOURSH_SAST_HIST_MAX_COMMITS <"$tmp"
  rm -f "$tmp"
}

# `SAST-SEC-*` -> `SAST-HIST-*`: the one substitution that gives every history
# finding a check id in its own family (tension 13), reusing the same rule
# record (title/severity/cwe/owasp/pattern/context/...) rather than forking
# secrets.rules into a second, driftable copy.  Every id secrets.rules ships
# starts with `SAST-SEC-`, so this is a plain prefix swap, not a lookup table.
_sast_hist_check_id() {
  printf '%s' "${1/SAST-SEC-/SAST-HIST-}"
}

# ---------------------------------------------------------------------------
# 3. History-boundary classification (docs/FOUNDATION.md tension 13):
#    "bound_by" records WHY the walk ended where it did - a rolling
#    window-days cutoff, a max-commits cap that has started binding, or the
#    repository's own root - so a future report can say why coverage ended
#    there instead of just where.
#
#    Deliberately O(1) git plumbing calls rather than a full unbounded
#    `git rev-list --count HEAD` (which would cost the entire repository
#    history on every run, exactly the quadratic-ish cost tension 13 rejects
#    `git log -p` for): the oldest commit this run walked either has no
#    parent (repo-root) or it does, in which case a single one-commit `git
#    log --since` probe on that parent tells us whether the window or the
#    commit cap was the binding constraint.
# ---------------------------------------------------------------------------
_sast_history_classify_bound() {
  local scan_root=$1 oldest=$2 since_epoch=$3 max_commits=$4 count=$5
  if ! git -C "$scan_root" rev-parse --verify -q "${oldest}^" >/dev/null 2>&1; then
    printf 'repo-root'
    return 0
  fi
  if (( count >= max_commits )); then
    local next
    next=$(git -C "$scan_root" log -1 --since="@$since_epoch" --format=%H "${oldest}^" 2>/dev/null || printf '')
    if [[ -n $next ]]; then
      printf 'max-commits'
      return 0
    fi
  fi
  printf 'window-days'
}

# ---------------------------------------------------------------------------
# 4. Per-blob "earliest reaching commit within this run's walked window"
#    (tension 13: every history finding records `oldest_reaching_commit_time`,
#    the committer timestamp of the earliest commit THIS RUN could see that
#    reaches the blob - not the global earliest, which would push nearly
#    every old finding to `unknown` permanently once step 7's diff engine
#    reads it).
#
#    Computed lazily, once per blob (not per check, not per match): the
#    first call for a given blob does the work and caches it in the two
#    globals below; every later call for the SAME blob (a blob can match
#    several secrets.rules checks) is then a single string comparison.
#    Reset per blob by _sast_history_scan_blob.
# ---------------------------------------------------------------------------
_SAST_HIST_COMMIT_SHA=''
_SAST_HIST_COMMIT_TIME=''

_sast_history_ensure_commit_info() {
  local scan_root=$1 blob_sha=$2 relpath=$3 since_epoch=$4 max_commits=$5
  [[ -z $_SAST_HIST_COMMIT_SHA ]] || return 0
  local c want
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    want=$(git -C "$scan_root" rev-parse -q --verify "$c:$relpath" 2>/dev/null) || continue
    if [[ $want == "$blob_sha" ]]; then
      _SAST_HIST_COMMIT_SHA=$c
      break
    fi
  done < <(git -C "$scan_root" rev-list --date-order --reverse --since="@$since_epoch" \
    --max-count="$max_commits" HEAD -- "$relpath" 2>/dev/null)
  if [[ -n $_SAST_HIST_COMMIT_SHA ]]; then
    _SAST_HIST_COMMIT_TIME=$(git -C "$scan_root" show -s --format=%cI "$_SAST_HIST_COMMIT_SHA" 2>/dev/null)
  fi
}

# ---------------------------------------------------------------------------
# 5. Emitting a history finding.  Deliberately its own function rather than a
#    reuse of engine.sh's `_sast_emit_finding`: the two disagree on check_id
#    (SAST-HIST-* vs the record's own id), on `logical_kind`/`logical_fqn`
#    (blob-scoped here, file-scoped there), on `loc_blob_sha` (history-only),
#    and on `remediation` (rotate-then-purge, never "remove the line" - the
#    working tree may already be clean).
# ---------------------------------------------------------------------------
_sast_history_emit_finding() {
  local set=$1 idx=$2 blob_sha=$3 relpath=$4 ln=$5 text=$6
  local orig_id hist_id
  orig_id=$(records_id "$set" "$idx")
  hist_id=$(_sast_hist_check_id "$orig_id")

  finding_new
  finding_from_record "$set" "$idx"
  finding_set check_id "$hist_id"
  finding_set title "$(records_field "$set" "$idx" title) (found in git history)"
  finding_set module sast
  finding_set loc_path "$relpath"
  finding_set loc_line "$ln"
  finding_set loc_blob_sha "$blob_sha"
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set logical_kind blob
  finding_set logical_fqn "$blob_sha:$ln"
  if [[ -n $_SAST_HIST_COMMIT_SHA ]]; then
    finding_set commit "$_SAST_HIST_COMMIT_SHA"
  fi
  if [[ -n $_SAST_HIST_COMMIT_TIME ]]; then
    finding_set oldest_reaching_commit_time "$_SAST_HIST_COMMIT_TIME"
  fi
  finding_set remediation 'Rotate the credential immediately - it must be treated as compromised even though it is absent from the working tree (docs/FOUNDATION.md tension 13). Purging history does not un-disclose it, so rotation comes first; then purge the blob from history (for example git filter-repo), force-push, and have every clone re-clone rather than pull.'
  # Same split as modules/sast/engine.sh's own emitter: a secrets-family match
  # IS the credential, so it never reaches evidence in the clear (tension 9).
  # This path matters more than the working-tree one, not less - a SAST-HIST-*
  # finding reports a credential that is already committed and already has to be
  # treated as compromised, and its report is the artifact most likely to be
  # pasted into a ticket.
  if _sast_check_is_sensitive "$hist_id"; then
    finding_set sensitive_data true
    finding_set_secret_match "$text"
  else
    finding_set_match "$text"
    finding_set_evidence "$text"
  fi
  finding_emit
}

# ---------------------------------------------------------------------------
# 6. Per-check scan of one materialised blob file - the same two-pass shape
#    as engine.sh's sast_scan_file (scan_match_offsets, then per-match
#    sast_context_ok), routed through the identical scan_match wrapper
#    (tension 4: never a bare grep/rg over `git log -p` output or anything
#    else).
# ---------------------------------------------------------------------------
_sast_history_scan_check() {
  local scan_root=$1 set=$2 idx=$3 blob_sha=$4 relpath=$5 blobfile=$6 since_epoch=$7 max_commits=$8
  local pattern
  pattern=$(records_field "$set" "$idx" pattern)

  local hits=$SCOURSH_SCRATCH/sast-hist-hits.$$
  if ! scan_match_offsets "$hits" "$pattern" "$blobfile"; then
    rm -f "$hits"
    return 0
  fi

  local total='' ln off text count=0 overflow=0
  # off is read to consume the byte-offset field so `text` lands in the right
  # position, exactly like engine.sh's sast_scan_file.
  # shellcheck disable=SC2034
  while IFS=: read -r ln off text; do
    [[ -n $ln ]] || continue
    count=$(( count + 1 ))
    if (( count > SCOURSH_SAST_MAX_MATCHES_PER_FILE )); then
      overflow=1
      break
    fi
    [[ -n $total ]] || total=$(awk 'END{print NR}' "$blobfile")
    if sast_context_ok "$set" "$idx" "$blobfile" "$ln" "$total"; then
      _sast_history_ensure_commit_info "$scan_root" "$blob_sha" "$relpath" "$since_epoch" "$max_commits"
      _sast_history_emit_finding "$set" "$idx" "$blob_sha" "$relpath" "$ln" "$text"
    fi
  done <"$hits"
  rm -f "$hits"

  if (( overflow )); then
    run_record truncated_matches \
      "check=$(_sast_hist_check_id "$(records_id "$set" "$idx")") blob=$blob_sha max=$SCOURSH_SAST_MAX_MATCHES_PER_FILE"
  fi
}

# ---------------------------------------------------------------------------
# 7. Per-blob scan: every secrets.rules check against one materialised blob.
# ---------------------------------------------------------------------------
_sast_history_scan_blob() {
  local scan_root=$1 secretsset=$2 blob_sha=$3 relpath=$4 since_epoch=$5 max_commits=$6
  local blobfile=$SCOURSH_SCRATCH/sast-hist-blob.$$
  if ! git -C "$scan_root" cat-file -p "$blob_sha" >"$blobfile" 2>/dev/null; then
    rm -f "$blobfile"
    return 0
  fi
  # The scanning unit for occurrence is the BLOB, not the path (tension 13):
  # _occurrence_unit_for's own "history" branch reads loc_blob_sha, so this
  # reset (which only clears cached ordinals, exactly like engine.sh calling
  # it once per file) is here for parity with that convention, not because
  # occurrence_next itself consults SCOURSH_SCAN_UNIT for this profile.
  occurrence_reset_unit "$blob_sha"
  _SAST_HIST_COMMIT_SHA=''
  _SAST_HIST_COMMIT_TIME=''
  local n idx
  n=$(records_count "$secretsset")
  for (( idx = 0; idx < n; idx++ )); do
    sast_rule_matches_file "$secretsset" "$idx" "$relpath" || continue
    _sast_history_scan_check "$scan_root" "$secretsset" "$idx" "$blob_sha" "$relpath" "$blobfile" "$since_epoch" "$max_commits"
  done
  rm -f "$blobfile"
}

# ---------------------------------------------------------------------------
# 8. The bounded walk: enumerate commits within history-window-days /
#    history-max-commits, then the blobs reachable from exactly that bounded
#    commit set (docs/FOUNDATION.md tension 13's "scan blobs, not diffs" -
#    every distinct blob scanned exactly once, dedup by content sha, not by
#    path or commit).
# ---------------------------------------------------------------------------
_sast_history_scan() {
  local scan_root=$1
  _sast_capture_max_matches
  _sast_history_capture_config
  local window_days=$SCOURSH_SAST_HIST_WINDOW_DAYS max_commits=$SCOURSH_SAST_HIST_MAX_COMMITS

  local since_epoch
  since_epoch=$(( $(now_epoch) - window_days * 86400 ))
  # Measured, not assumed (git 2.54.0): `--since=@<epoch>` does not reliably
  # include old commits for small epoch magnitudes - `--since=@1` silently
  # EXCLUDES a real year-2000 commit that `--since=@946684800` (the same
  # date, spelled as a real Unix timestamp) correctly includes, and values in
  # between are worse still, excluding everything.  git's approxidate parser
  # is misreading a small `@N` as something other than a plain timestamp, not
  # a genuine "no commits that old" answer.  100000000 (1973-03-03) is a
  # floor comfortably inside the range measured to behave correctly, and
  # comfortably before git's own 2005 origin - no real repository's history
  # can predate it - so clamping here for a window-days value large enough to
  # underflow past the Unix epoch is equivalent to "no lower bound" for any
  # real target, without walking into the small-epoch misparse.
  local since_floor=100000000
  (( since_epoch > since_floor )) || since_epoch=$since_floor

  local -a commits=()
  local c
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    commits+=("$c")
  done < <(git -C "$scan_root" rev-list --date-order --since="@$since_epoch" \
    --max-count="$max_commits" HEAD 2>/dev/null)

  if (( ${#commits[@]} == 0 )); then
    log_warn 'sast history: no commits fall within history-window-days/history-max-commits - nothing to replay'
    run_record coverage_reduction 'module=sast reason=no_commits_in_window'
    return 0
  fi

  # commits[] is newest-first (git rev-list's default order); the oldest
  # commit this run actually walked is the LAST element - the run's
  # history_boundary.oldest_commit (tension 13).
  local oldest_commit=${commits[-1]} oldest_commit_time bound_by
  oldest_commit_time=$(git -C "$scan_root" show -s --format=%cI "$oldest_commit" 2>/dev/null)
  bound_by=$(_sast_history_classify_bound "$scan_root" "$oldest_commit" "$since_epoch" "$max_commits" "${#commits[@]}")

  local secretsset=sast_hist_secrets
  if ! records_load "${BASH_SOURCE[0]%/*}/rules/secrets.rules" pattern-rule "$secretsset" >/dev/null; then
    log_warn 'sast history: modules/sast/rules/secrets.rules failed to load - skipping git-history secret replay'
    run_record coverage_reduction 'module=sast reason=secrets_rules_failed_to_load'
    return 0
  fi

  # Bound the OBJECT walk to exactly the commits already selected above:
  # excluding everything reachable from the oldest commit's own parents
  # (`^@` - all parents, not just the first, so a merge at the boundary is
  # handled too) stops rev-list from re-walking the untouched rest of the
  # repository's history, which is both the correctness fix and the
  # performance fix tension 13's "scan blobs, not diffs" resolution asks for.
  # A root commit (no parents) needs no exclusion at all - "$oldest^@" on a
  # root commit is empty, and passing an empty `--not` argument to rev-list is
  # itself an error, so it is only added when a parent actually exists.
  local -a exclude_args=()
  if git -C "$scan_root" rev-parse --verify -q "${oldest_commit}^" >/dev/null 2>&1; then
    exclude_args=(--not "${oldest_commit}^@")
  fi

  local objfile=$SCOURSH_SCRATCH/sast-hist-objects.$$
  git -C "$scan_root" rev-list --objects "${commits[@]+"${commits[@]}"}" \
    "${exclude_args[@]+"${exclude_args[@]}"}" 2>/dev/null \
    | git -C "$scan_root" cat-file --batch-check='%(objectname) %(objecttype) %(rest)' >"$objfile" 2>/dev/null

  local -A seen_blob=()
  local objects_scanned=0 sha type rest
  while IFS=' ' read -r sha type rest; do
    [[ $type == blob ]] || continue
    [[ -n $sha ]] || continue
    [[ -n ${seen_blob[$sha]:-} ]] && continue
    seen_blob[$sha]=1
    objects_scanned=$(( objects_scanned + 1 ))
    _sast_history_scan_blob "$scan_root" "$secretsset" "$sha" "$rest" "$since_epoch" "$max_commits"
  done <"$objfile"
  rm -f "$objfile"

  run_record history_boundary \
    "oldest_commit=$oldest_commit oldest_commit_time=$oldest_commit_time objects_scanned=$objects_scanned bound_by=$bound_by"

  _sast_history_record_coverage "$secretsset" "$oldest_commit" "$oldest_commit_time" "$objects_scanned" "$bound_by"
}

# ---------------------------------------------------------------------------
# 9. docs/STEP7-STATE-PLAN.md STATE-02: path-root coverage for every
#    SAST-HIST-* check, plus its history_boundary block (tension 13).
#    Reached only from the tail of _sast_history_scan above, i.e. only once
#    the WHOLE bounded blob walk has finished - the same "the caller decides
#    completion by where it calls this from" discipline
#    modules/sast/engine.sh's sast_record_coverage documents, applied here
#    because every SAST-HIST-* check shares one walk over one materialised
#    blob set rather than each having its own scan-tree call to return from.
#    Every record in `secretsset` becomes a covered SAST-HIST-* id: the walk
#    evaluates every one of them against every blob it visits (see
#    _sast_history_scan_blob), so "the walk completed" is "every check in the
#    pack completed", uniformly.
# ---------------------------------------------------------------------------
_sast_history_record_coverage() {
  declare -F state_add_covered >/dev/null 2>&1 || return 0
  local secretsset=$1 oldest_commit=$2 oldest_commit_time=$3 objects_scanned=$4 bound_by=$5
  local n idx hist_id digest
  n=$(records_count "$secretsset")
  for (( idx = 0; idx < n; idx++ )); do
    hist_id=$(_sast_hist_check_id "$(records_id "$secretsset" "$idx")")
    digest=$(records_digest "$secretsset" "$idx")
    state_add_covered "$hist_id" "$digest" path-root "$SCOURSH_PATH_ROOT"
    if declare -F state_add_history_boundary >/dev/null 2>&1; then
      state_add_history_boundary "$hist_id" "$oldest_commit" "$oldest_commit_time" "$objects_scanned" "$bound_by"
    fi
  done
  return 0
}
