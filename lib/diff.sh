#!/usr/bin/env bash
# lib/diff.sh - the `diff` command, automatic per-run classification, and the
# report-delta wiring (docs/STEP7-STATE-PLAN.md STATE-06).
#
# Owns:
#   docs/DESIGN.md      §9a - "scan.sh diff --against <prior-run> (and every
#                        normal run, automatically) classifies each finding".
#   docs/FOUNDATION.md  tension 11 stage 5 (classify + diff_usable) and
#                        stage 9's delta reporting - both were pure and
#                        untested-against-real-data until this file.
#   docs/FOUNDATION.md  tension 12 - consumes lib/findings.sh's classification
#                        engine (section 17) and lib/state.sh's writer/loader
#                        (STATE-01/02) for the first time with REAL data.
#
# ============================ WHAT THIS FILE IS =============================
# lib/findings.sh section 16/17 (classify_derived, findings_classify_guard/
# present/absent/rule_digest_changed) are pure functions over plain scalars
# and line-oriented files - STATE-03/04/05 built and fixture-tested them, but
# wired them into nothing.  This file is the wiring: it converts a REAL
# loaded state/latest.json (or, for the standalone `diff` command, a
# named prior run's own state/<run-id>.json) and THIS run's own findings/
# coverage into the shapes those functions want, applies them, and persists
# the result where lib/report.sh's emitters can read it back.
#
# Two entry points, matching the two places §9a says classification happens:
#
#   diff_classify_run RUNDIR      - "every normal run, automatically".
#     Called once per module dispatch (modules/sast/run.sh and its three
#     siblings), between derive_findings (stage 4) and the module's own gate
#     call (stage 7) - tension 11's frozen stage order.  Safe to call more
#     than once in one process: `scan.sh all` calls it once per module over
#     the SAME, growing findings.fields, exactly as derive_findings already
#     tolerates repeat calls (its own header note) - only the LAST call's
#     rewritten statuses and counts matter, and each call is a full, correct
#     re-classification rather than an incremental patch.
#
#   diff_render_against DIR       - the standalone `scan.sh diff --against
#     <prior-run-dir>` command (scan.sh's own case arm).  Performs no scan of
#     its own; it classifies the most recently completed run's own recorded
#     state (state/latest.json) against the state recorded for DIR, the
#     identical mechanism tension 12 describes as "scan.sh diff --against
#     <dir> overrides the state source" - the source it overrides is WHICH
#     file plays "prior", never "this run", since a standalone diff performs
#     no new scan to be "this run".
#
# ======================= WHAT THIS FILE DOES NOT DO ==========================
#   * It does not redefine tension 12's four-row table, its two guards, or
#     tension 6's three-condition composite rule.  Those are
#     lib/findings.sh's job (STATE-03/04/05); this file only supplies them
#     real inputs.
#   * It does not implement baseline suppression (STATE-07) or
#     `--fail-on-new`'s carve-out (STATE-08).  `findings_mark_suppressed`
#     already exists and is untouched; nothing here calls it.
#
# shellcheck shell=bash
# SC2153: `$FP_SCHEMA` is lib/findings.sh's real, readonly constant (tension
#   5), used the identical way scan.sh and lib/report.sh already do; this file
#   as a `-x` entry point is what makes shellcheck unable to see the
#   assignment across the source graph and suggest a typo that does not exist.
# shellcheck disable=SC2153

if [[ -n ${SCOURSH_DIFF_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DIFF_SOURCED=1

# shellcheck source=lib/state.sh
source "${BASH_SOURCE[0]%/*}/state.sh"
# -x back-edge cut: lib/report.sh already reaches lib/state.sh's sibling,
# lib/findings.sh, through its own real edge - this file's own real edge to
# lib/state.sh above already supplies core.sh/records.sh once, and
# report.sh's chain supplies findings.sh once; a second real edge here would
# be the identical diamond AGENTS.md's "Sharp edges" section documents for
# lib/http.sh, re-expanded for every entry point that reaches both.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/report.sh"

# ---------------------------------------------------------------------------
# 1. Shared snapshot helpers
# ---------------------------------------------------------------------------
# These read the CURRENTLY LOADED read-side state (lib/state.sh section 3/4)
# into plain, line-oriented scratch files - the same shapes
# tests/suites/findings.sh already hand-authors for classify_derived's own
# PRIOR_STATE_FILE/COVERED_THIS_RUN/PRIOR_COVERED arguments (that file's own
# comment on the format), so nothing here invents a second convention.

# `_diff_snapshot_loaded_findings NARROW_OUT DETAIL_OUT` - two views of the
# SAME currently-loaded read-side findings, written in one pass:
#
#   NARROW_OUT: `fingerprint \t check_id \t cell \t oldest_reaching_commit_time`
#     - classify_derived's own frozen PRIOR_STATE_FILE shape
#     (tests/suites/findings.sh's own comment on the format), fed to it
#     UNCHANGED.  Its reader (`_contributor_covered`, lib/findings.sh) splits
#     on exactly 4 tab fields, so this file may never carry a fifth column -
#     one that did would silently absorb into the 4th field on read.
#   DETAIL_OUT: the same rows, WIDENED with severity/first_seen/contributors -
#     everything `_diff_lookup_detail` below needs to render an absent
#     finding's ledger row and classify a composite's contributors, kept
#     deliberately separate from NARROW_OUT rather than widening it in place.
#
# This is deliberately a SNAPSHOT, not a live view: `diff_render_against`
# loads "prior" first and these files are its only record of it once it loads
# "this" afterward into the SAME read-side globals (lib/state.sh has no
# support for holding two loaded states at once).  `diff_classify_run`'s
# prior state happens to stay loaded throughout (nothing overwrites it), but
# it snapshots too, for the identical reason `classify_derived`'s own
# PRIOR_STATE_FILE argument is a file rather than a live query in the first
# place: one shape per file, one reader each, regardless of which caller
# built it.
_diff_snapshot_loaded_findings() {
  local narrow_out=$1 detail_out=$2
  : >"$narrow_out"
  : >"$detail_out"
  state_loaded || return 0
  local fp oldest contrib_csv
  while IFS= read -r fp; do
    [[ -n $fp ]] || continue
    oldest=$(state_finding_field "$fp" oldest_reaching_commit_time)
    contrib_csv=$(state_finding_field "$fp" contributors | tr '\n' ',')
    contrib_csv=${contrib_csv%,}
    printf '%s\t%s\t%s\t%s\n' "$fp" \
      "$(state_finding_field "$fp" check_id)" \
      "$(state_finding_field "$fp" cell)" \
      "$oldest" \
      >>"$narrow_out"
    # 0x1f-separated, never tab: unlike NARROW_OUT (whose only-ever-empty
    # column is the trailing one, safe under tab-collapsing), a derived
    # finding's `cell` is empty here and it is NOT the last column, and a
    # non-history finding's `oldest` is empty and also not last - either
    # would silently shift `contributors` into the wrong field, or off the
    # end entirely, under a tab (an IFS-*whitespace* character that `read`
    # collapses across an empty field - AGENTS.md's own "Sharp edges" entry,
    # measured here directly: a composite's own `contributors` came back
    # empty and it was misclassified as an ORDINARY finding instead).
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$fp" \
      "$(state_finding_field "$fp" check_id)" \
      "$(state_finding_field "$fp" cell)" \
      "$(state_finding_field "$fp" severity)" \
      "$(state_finding_field "$fp" first_seen)" \
      "$oldest" \
      "$contrib_csv" \
      >>"$detail_out"
  done < <(state_finding_fingerprints)
}

# `_diff_lookup_detail DETAIL_FILE FINGERPRINT` - the one reader for the
# 0x1f-separated snapshot shape above.  Sets `_DIFF_LOOKUP_CHECK_ID`/`_CELL`/
# `_SEVERITY`/`_FIRST_SEEN`/`_OLDEST`/`_CONTRIBUTORS` (never printed - a
# caller needs all six at once, and this project's own convention for that,
# e.g. `worker_id_set`, is a setter rather than a subshell-losing `$(...)`).
# Clears all six first, so a fingerprint the file does not contain (never
# expected in practice - every caller looks up a fingerprint the SAME
# snapshot's own fingerprint list just yielded) is visibly empty rather than
# silently reusing the previous lookup's values.
_diff_lookup_detail() {
  local detail_file=$1 want=$2 fp
  _DIFF_LOOKUP_CHECK_ID='' _DIFF_LOOKUP_CELL='' _DIFF_LOOKUP_SEVERITY=''
  _DIFF_LOOKUP_FIRST_SEEN='' _DIFF_LOOKUP_OLDEST='' _DIFF_LOOKUP_CONTRIBUTORS=''
  while IFS=$'\x1f' read -r fp _DIFF_LOOKUP_CHECK_ID _DIFF_LOOKUP_CELL \
    _DIFF_LOOKUP_SEVERITY _DIFF_LOOKUP_FIRST_SEEN _DIFF_LOOKUP_OLDEST \
    _DIFF_LOOKUP_CONTRIBUTORS; do
    [[ $fp == "$want" ]] && return 0
  done <"$detail_file"
  _DIFF_LOOKUP_CHECK_ID='' _DIFF_LOOKUP_CELL='' _DIFF_LOOKUP_SEVERITY=''
  _DIFF_LOOKUP_FIRST_SEEN='' _DIFF_LOOKUP_OLDEST='' _DIFF_LOOKUP_CONTRIBUTORS=''
  return 1
}

# `check_id \t cell` per (check, cell) pair the currently loaded read-side
# state recorded as covered - classify_derived's own PRIOR_COVERED shape (or,
# equally, findings_classify_absent's own COVERED_NOW_FILE shape when what is
# loaded is "this" run rather than "prior" - see the call sites below).
_diff_snapshot_loaded_covered() {
  local out=$1
  : >"$out"
  state_loaded || return 0
  local id cell
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    while IFS= read -r cell; do
      [[ -n $cell ]] || continue
      printf '%s\t%s\n' "$id" "$cell" >>"$out"
    done < <(state_covered_cells "$id")
  done < <(state_covered_check_ids)
}

# The same shape, over THIS run's own (still write-side, not yet persisted)
# coverage - classify_present/classify_absent's own COVERED_NOW/COVERED_NOW_FILE
# argument.
_diff_snapshot_this_covered() {
  local out=$1
  : >"$out"
  local id cell
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    while IFS= read -r cell; do
      [[ -n $cell ]] || continue
      printf '%s\t%s\n' "$id" "$cell" >>"$out"
    done < <(state_covered_now_cells "$id")
  done < <(state_covered_now_ids)
}

# `check_id \t oldest_commit_time` per THIS run's own history-boundary
# record - the write-side one for `diff_classify_run` (a real scan still
# in progress; `state_covered_now_history_boundary_time` is the only place
# it exists), the read-side one for `diff_render_against` (already-completed
# state loaded via state_load_latest).  A caller-supplied file rather than a
# hardcoded accessor call, because `_diff_classify_one_absent` and
# `_diff_composite_this_boundary` below are shared by both callers and only
# the caller knows which side is authoritative for ITS "this run".
_diff_hb_lookup() {
  local hb_file=$1 want=$2 c t
  while IFS=$'\t' read -r c t; do
    [[ $c == "$want" ]] && { printf '%s' "$t"; return 0; }
  done <"$hb_file"
  return 0
}

# A composite's SAST-HIST-* contributor boundary, for classify_derived's own
# single THIS_RUN_OLDEST_COMMIT_TIME argument (docs/STEP7-STATE-PLAN.md
# STATE-05 froze that signature as one value per call, not one per
# contributor).  Among the record's requires/any-of check ids, the MINIMUM -
# most conservative - of whichever are SAST-HIST-* families' own boundary
# for THIS run.  Empty when none of the contributors are a history check,
# which is a no-op for layer 2 exactly as findings_classify_absent's own
# header documents for its two optional trailing arguments.
_diff_composite_this_boundary() {
  local ridx=$1 this_hb_file=$2 c boundary='' cur
  while IFS= read -r c; do
    [[ -n $c ]] || continue
    [[ $c == SAST-HIST-* ]] || continue
    cur=$(_diff_hb_lookup "$this_hb_file" "$c")
    [[ -n $cur ]] || continue
    if [[ -z $boundary || $cur < $boundary ]]; then
      boundary=$cur
    fi
  done <<<"$(_derived_contributors "$ridx")"
  printf '%s' "$boundary"
}

# `<status>` for one PRIOR fingerprint absent from THIS run - dispatches to
# classify_derived (composite: state/ persists `contributors` only for a
# derived finding, tension 12's own note) or findings_classify_absent
# (ordinary), and appends one `status <0x1f> reason <0x1f> check_id <0x1f>
# cell <0x1f> severity <0x1f> first_seen <0x1f> fingerprint` line to LEDGER.
# The separator is 0x1f, NEVER a tab: `reason` is empty for a `fixed` status
# and `cell` is empty for a derived finding, and a tab is an IFS-*whitespace*
# character - `read` folds a RUN of tabs into ONE delimiter and drops empty
# fields (AGENTS.md's own "Sharp edges" entry on this, for the identical
# reason `markup_engine.sh`'s DAST-11 record stream uses 0x1f) - so a
# tab-joined line with an empty field silently shifts every later column.
# Measured here, not assumed: a tab-separated `fixed` row (empty reason)
# shifted `cell` into the `check_id`-comparison slot and every read of this
# ledger returned nothing.
#
# `correlation` is deliberately empty for a composite: tension 12's frozen
# `state/` finding shape carries no `correlation` field (only fingerprint,
# check_id, cell, severity, first_seen, last_seen, suppressed,
# oldest_reaching_commit_time, contributors), and classify_derived reads its
# CORRELATION argument only to compose its own human-readable "reason"
# string, never to look anything up - so the reason is slightly less
# specific for a persisted composite than for one classified in the same run
# it fired, and never functionally wrong.
_diff_classify_one_absent() {
  local pfp=$1 guard=$2 this_covered_file=$3 prior_narrow=$4 prior_detail=$5 \
    prior_covered_file=$6 this_hb_file=$7 ledger=$8
  _diff_lookup_detail "$prior_detail" "$pfp"
  local check_id=$_DIFF_LOOKUP_CHECK_ID cell=$_DIFF_LOOKUP_CELL severity=$_DIFF_LOOKUP_SEVERITY \
    first_seen=$_DIFF_LOOKUP_FIRST_SEEN oldest=$_DIFF_LOOKUP_OLDEST \
    contributors=$_DIFF_LOOKUP_CONTRIBUTORS

  local out status reason
  if [[ -n $contributors ]]; then
    local ridx boundary
    ridx=$(records_index_of_id derivedset "$check_id") || ridx=''
    boundary=''
    [[ -n $ridx ]] && boundary=$(_diff_composite_this_boundary "$ridx" "$this_hb_file")
    out=$(classify_derived "$check_id" '' false "$contributors" "$guard" \
      "$prior_narrow" "$this_covered_file" "$prior_covered_file" "$boundary")
  else
    local scope this_boundary
    scope=$(_derived_contributor_scope "$check_id")
    this_boundary=$(_diff_hb_lookup "$this_hb_file" "$check_id")
    out=$(findings_classify_absent "$check_id" "$cell" "$scope" "$guard" \
      "$this_covered_file" "$oldest" "$this_boundary")
  fi
  status=${out%%$'\t'*}
  reason=${out#*$'\t'}
  printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$status" "$reason" "$check_id" "$cell" \
    "$severity" "$first_seen" "$pfp" >>"$ledger"
}

# ---------------------------------------------------------------------------
# 2. Automatic per-run classification
# ---------------------------------------------------------------------------
diff_classify_run() {
  local rundir=${1:-$SCOURSH_RUN_DIR}

  state_load_latest

  local prior_fp_schema='' prior_scan_root_id=''
  if state_loaded; then
    prior_fp_schema=$(state_field fp_schema)
    prior_scan_root_id=$(state_field scan_root_id)
  fi
  local this_has_path_root=false
  state_covered_now_has_scope path-root && this_has_path_root=true

  local guard
  guard=$(findings_classify_guard "$FP_SCHEMA" "${SCOURSH_SCAN_ROOT_ID:-}" "$this_has_path_root" \
    "$prior_fp_schema" "$prior_scan_root_id")
  SCOURSH_DIFF_USABLE=$(findings_diff_usable "$guard")
  SCOURSH_DIFF_GUARD=$guard
  export SCOURSH_DIFF_USABLE SCOURSH_DIFF_GUARD

  local prior_fp_file=$SCOURSH_SCRATCH/diff-prior-fp
  : >"$prior_fp_file"
  state_loaded && state_finding_fingerprints >"$prior_fp_file"

  local this_covered_file=$SCOURSH_SCRATCH/diff-this-covered
  _diff_snapshot_this_covered "$this_covered_file"

  _diff_record_rule_changed

  # Rewrite findings.fields in place - classify every PRESENT finding new/
  # recurring, and (STATE-06's own fix: tension 11 stage 8 says "persist ALL
  # findings ... with their first_seen preserved", and nothing before this
  # ticket ever carried a recurring finding's ORIGINAL first_seen forward -
  # every emitted finding stamped first_seen at emission time, unconditionally)
  # restore a recurring finding's persisted first_seen over today's stamp.
  #
  # Also records every finding into the write-side state/ builder
  # (state_add_finding), so THIS run's own findings are what a FUTURE run
  # classifies against - stage 8 of tension 11's pipeline, and the one half
  # of "persist all findings" nothing before this ticket ever did.  Guarded
  # by state_write_has_finding because `scan.sh all` calls this function once
  # per module over the SAME, growing findings.fields; a fingerprint already
  # recorded by an earlier call in this run is skipped rather than re-added
  # (state_add_finding itself dies on a genuine duplicate).
  local present_fp_file=$SCOURSH_SCRATCH/diff-present-fp
  : >"$present_fp_file"
  if [[ -s $rundir/findings.fields ]]; then
    local tmp=$SCOURSH_SCRATCH/diff-rewrite.$$
    : >"$tmp"
    local line fp check_id scope status prior_first_seen cell_for_state contrib_csv
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      finding_decode "$line"
      fp=${_DF[fingerprint]}
      printf '%s\n' "$fp" >>"$present_fp_file"
      check_id=${_DF[check_id]}
      if [[ -n ${_DF[cell]+set} ]]; then
        scope=$(_derived_contributor_scope "$check_id")
        cell_for_state=${_DF[cell]}
      else
        scope=''
        cell_for_state=''
      fi
      status=$(findings_classify_present "$fp" "$guard" "$scope" "$prior_fp_file")
      _DF[status]=$status
      if [[ $status == recurring ]] && state_loaded; then
        prior_first_seen=$(state_finding_field "$fp" first_seen)
        [[ -n $prior_first_seen ]] && _DF[first_seen]=$prior_first_seen
      fi
      _reencode_decoded >>"$tmp"
      printf '\n' >>"$tmp"
      if ! state_write_has_finding "$fp"; then
        contrib_csv=''
        if [[ -n ${_DF[contributors]:-} ]]; then
          contrib_csv=$(printf '%s' "${_DF[contributors]}" | tr '\n' ',')
          contrib_csv=${contrib_csv%,}
        fi
        state_add_finding "$fp" "$check_id" "$cell_for_state" "${_DF[severity]:-}" \
          "${_DF[first_seen]:-}" "${_DF[last_seen]:-}" "${_DF[suppressed]:-false}" \
          "${_DF[oldest_reaching_commit_time]:-}" "$contrib_csv"
      fi
    done <"$rundir/findings.fields"
    mv "$tmp" "$rundir/findings.fields"
  fi

  local absent_file=$rundir/meta/diff_absent
  : >"$absent_file"
  if state_loaded; then
    local -A seen=()
    local sfp
    while IFS= read -r sfp; do
      [[ -n $sfp ]] && seen[$sfp]=1
    done <"$present_fp_file"

    local prior_narrow=$SCOURSH_SCRATCH/diff-prior-narrow
    local prior_detail=$SCOURSH_SCRATCH/diff-prior-detail
    _diff_snapshot_loaded_findings "$prior_narrow" "$prior_detail"
    local prior_covered_file=$SCOURSH_SCRATCH/diff-prior-covered
    _diff_snapshot_loaded_covered "$prior_covered_file"
    # THIS run's own history boundary is still write-side (a scan in
    # progress never persists it until state_write, at the very end of
    # scan_main) - state_covered_now_history_boundary_time is the only place
    # it exists yet.
    local this_hb_file=$SCOURSH_SCRATCH/diff-this-hb
    : >"$this_hb_file"
    local hid hbtime
    while IFS= read -r hid; do
      [[ -n $hid ]] || continue
      hbtime=$(state_covered_now_history_boundary_time "$hid")
      [[ -n $hbtime ]] && printf '%s\t%s\n' "$hid" "$hbtime" >>"$this_hb_file"
    done < <(state_covered_now_ids)

    local pfp
    while IFS= read -r pfp; do
      [[ -n $pfp ]] || continue
      [[ -n ${seen[$pfp]:-} ]] && continue
      _diff_classify_one_absent "$pfp" "$guard" "$this_covered_file" \
        "$prior_narrow" "$prior_detail" "$prior_covered_file" "$this_hb_file" "$absent_file"
    done <"$prior_fp_file"
  fi
}

# `rule_changed_checks` (tension 12: "a rule_digest change classifies
# normally but flags the report").  Compares THIS run's own (write-side,
# not-yet-persisted) rule_digest for every check it has covered so far
# against `state/latest.json`'s persisted one for the same id.
_diff_record_rule_changed() {
  local id this_digest prior_digest
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    this_digest=$(state_covered_now_rule_digest "$id")
    prior_digest=''
    state_loaded && prior_digest=$(state_covered_rule_digest "$id")
    if [[ $(findings_rule_digest_changed "$prior_digest" "$this_digest") == true ]]; then
      run_record rule_changed_checks "$id"
    fi
  done < <(state_covered_now_ids)
}

# ---------------------------------------------------------------------------
# 3. The standalone `scan.sh diff --against <prior-run-dir>` command
# ---------------------------------------------------------------------------
# `--against` names a REPORTS directory (docs/DESIGN.md §5's own grammar,
# `_scan_require_prior_run` validates it holds a findings.jsonl or run.json),
# never a `state/` file directly - so the state/ record that shares its
# identity is found by the one thing tying the two together: `SCOURSH_RUN_ID`
# defaults to the basename of `SCOURSH_RUN_DIR` (lib/core.sh's `run_init`),
# so `reports/<run-id>/` and `state/<run-id>.json` are named by the identical
# run id.  A run whose own state/<run-id>.json has since been pruned
# (`state-retain-runs`) is not an error here: state_load_file's own "missing
# file" case already means "no prior state", exactly as it does everywhere
# else, and the run's own findings.jsonl is not read as a fallback - a
# fixed/unknown classification needs coverage, which only state/ carries.
diff_render_against() {
  local against_dir=$1 rundir=${2:-$SCOURSH_RUN_DIR}
  local resolved run_id
  resolved=$(realpath_of "$against_dir")
  run_id=$(basename -- "$resolved")
  local against_state
  against_state="$(state_default_dir)/$run_id.json"

  # Snapshot PRIOR (the --against run) before loading THIS overwrites the
  # read-side globals both share.
  state_load_file "$against_state"
  local prior_fp_schema='' prior_scan_root_id=''
  state_loaded && prior_fp_schema=$(state_field fp_schema)
  state_loaded && prior_scan_root_id=$(state_field scan_root_id)
  local prior_fp_file=$SCOURSH_SCRATCH/diffcmd-prior-fp
  : >"$prior_fp_file"
  state_loaded && state_finding_fingerprints >"$prior_fp_file"
  local prior_narrow=$SCOURSH_SCRATCH/diffcmd-prior-narrow
  local prior_detail=$SCOURSH_SCRATCH/diffcmd-prior-detail
  _diff_snapshot_loaded_findings "$prior_narrow" "$prior_detail"
  local prior_covered_file=$SCOURSH_SCRATCH/diffcmd-prior-covered
  _diff_snapshot_loaded_covered "$prior_covered_file"

  # Snapshot THIS (state/latest.json - the most recently completed real run).
  state_load_latest
  if ! state_loaded; then
    log_warn "diff: no completed run recorded in state/latest.json - run a scan before diffing"
    run_record coverage_reduction 'module=diff reason=no_completed_run_recorded'
    return 0
  fi
  local this_fp_schema this_scan_root_id this_has_path_root=false
  this_fp_schema=$(state_field fp_schema)
  this_scan_root_id=$(state_field scan_root_id)
  state_covered_has_scope path-root && this_has_path_root=true
  local this_fp_file=$SCOURSH_SCRATCH/diffcmd-this-fp
  state_finding_fingerprints >"$this_fp_file"
  local this_covered_file=$SCOURSH_SCRATCH/diffcmd-this-covered
  _diff_snapshot_loaded_covered "$this_covered_file"
  # THIS run's own history boundary, read-side (state/latest.json, already
  # loaded) rather than write-side - a standalone diff never calls
  # state_add_covered, so state_covered_now_* would see nothing here.
  local this_hb_file=$SCOURSH_SCRATCH/diffcmd-this-hb
  : >"$this_hb_file"
  local hid hbtime
  while IFS= read -r hid; do
    [[ -n $hid ]] || continue
    hbtime=$(state_history_boundary_field "$hid" oldest_commit_time)
    [[ -n $hbtime ]] && printf '%s\t%s\n' "$hid" "$hbtime" >>"$this_hb_file"
  done < <(state_covered_check_ids)
  # `state_finding_field` below reads THIS run's own loaded findings - safe
  # here because THIS is what is currently loaded (state_load_latest, above).
  # 0x1f-separated, never tab: `cell` is empty for a derived finding, and a
  # tab is an IFS-*whitespace* character that `read` folds across an empty
  # field, silently shifting every later column (see
  # _diff_classify_one_absent's own comment on the identical hazard).
  local this_all_detail=$SCOURSH_SCRATCH/diffcmd-this-detail
  local fp
  : >"$this_all_detail"
  while IFS= read -r fp; do
    [[ -n $fp ]] || continue
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$fp" \
      "$(state_finding_field "$fp" check_id)" \
      "$(state_finding_field "$fp" cell)" \
      "$(state_finding_field "$fp" severity)" \
      "$(state_finding_field "$fp" first_seen)" \
      >>"$this_all_detail"
  done <"$this_fp_file"

  local guard
  guard=$(findings_classify_guard "$this_fp_schema" "$this_scan_root_id" "$this_has_path_root" \
    "$prior_fp_schema" "$prior_scan_root_id")
  SCOURSH_DIFF_USABLE=$(findings_diff_usable "$guard")
  SCOURSH_DIFF_GUARD=$guard
  export SCOURSH_DIFF_USABLE SCOURSH_DIFF_GUARD

  # PRESENT (this run's own findings): new/recurring, into meta/diff_present
  # (lib/report.sh's report_count reads it exactly like meta/diff_absent,
  # since a standalone diff has no findings.fields of its own to classify in
  # place - nothing was scanned).
  local present_file=$rundir/meta/diff_present
  : >"$present_file"
  local check_id cell severity first_seen scope status
  while IFS=$'\x1f' read -r fp check_id cell severity first_seen; do
    [[ -n $fp ]] || continue
    if [[ -n $cell ]]; then
      scope=$(_derived_contributor_scope "$check_id")
    else
      scope=''
    fi
    status=$(findings_classify_present "$fp" "$guard" "$scope" "$prior_fp_file")
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$status" "$check_id" "$cell" "$severity" "$first_seen" "$fp" \
      >>"$present_file"
  done <"$this_all_detail"

  # ABSENT (prior findings not present this run): fixed/unknown, into
  # meta/diff_absent - the identical ledger diff_classify_run's automatic
  # path writes, so lib/report.sh's rendering has exactly one format to read.
  local absent_file=$rundir/meta/diff_absent
  : >"$absent_file"
  local -A seen=()
  while IFS= read -r fp; do
    [[ -n $fp ]] && seen[$fp]=1
  done <"$this_fp_file"
  local pfp
  while IFS= read -r pfp; do
    [[ -n $pfp ]] || continue
    [[ -n ${seen[$pfp]:-} ]] && continue
    _diff_classify_one_absent "$pfp" "$guard" "$this_covered_file" \
      "$prior_narrow" "$prior_detail" "$prior_covered_file" "$this_hb_file" "$absent_file"
  done <"$prior_fp_file"

  run_record notes "diff: comparing state/latest.json against $against_state (run_id=$run_id)"
  # scan_main's own end-of-run report_run_json (unconditional, every command)
  # writes run.json once this function returns - not called a second time
  # here, since SCOURSH_DIFF_USABLE/SCOURSH_DIFF_GUARD and the meta/diff_*
  # ledgers above are already in place by then.
  [[ -z ${SCOURSH_FORMATS:-} || $SCOURSH_FORMATS == *md* ]] && report_md "$rundir"
}
