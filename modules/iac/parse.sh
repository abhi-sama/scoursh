#!/usr/bin/env bash
# modules/iac/parse.sh - the IaC module's file walker + per-file scanner
# (docs/DESIGN.md §13 step 4, §6.6 "same .rules engine as SAST").
#
# This is a THIN layer, not a fork: every generic primitive - the directory
# walk, `files`/`exclude-files` glob matching, the `context-require`/
# `context-deny` window predicate, scan-root-relative path resolution, and
# the check-id registry index - already exists in modules/sast/engine.sh and
# is reused here UNCHANGED (sast_walk_files, sast_rule_matches_file,
# sast_context_ok, sast_relpath, sast_index_checks, scan_root_of,
# _sast_check_is_sensitive).  None of those functions are actually
# SAST-specific despite the `sast_` prefix - they operate on a `records.sh`
# set/idx and a file path, nothing more - so forking a parallel
# `iac_walk_files`/`iac_glob_match`/`iac_context_ok` would be exactly the
# "parallel implementation" this ticket's own text says not to build.
#
# What genuinely IS module-specific, and therefore genuinely IS defined here,
# is finding EMISSION: a finding's `module` field must read `iac`, not
# `sast` (lib/findings.sh's `_fp_profile_for` already has a dedicated
# `iac | containers) printf 'path'` branch precisely because the two are
# expected to diverge here), so `_sast_emit_finding` - which hardcodes
# `finding_set module sast` - cannot be reused as-is.  `iac_scan_file` /
# `_iac_emit_finding` below are the same two-pass shape as
# `sast_scan_file`/`_sast_emit_finding`, calling straight back into the
# shared engine.sh primitives for everything except that one field.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IAC_PARSE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IAC_PARSE_SOURCED=1

# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"

# ---------------------------------------------------------------------------
# `max-matches-per-file` capture, module-local so a sequential sast-then-iac
# dispatch (the `scan.sh all` case) never has one module's captured value
# clobber the other's - mirrors modules/sast/engine.sh's own
# `_sast_capture_max_matches`, including its `$(...)`-avoids-`die` reasoning
# (config_scanner_value config.sh comment) and its trailing-newline fix for
# config_scanner_value's own no-trailing-newline `printf '%s'` convention.
# ---------------------------------------------------------------------------
_iac_capture_max_matches() {
  local tmp=$SCOURSH_SCRATCH/_iac_max_matches.$$
  config_scanner_value max-matches-per-file '' >"$tmp"
  printf '\n' >>"$tmp"
  IFS= read -r SCOURSH_IAC_MAX_MATCHES_PER_FILE <"$tmp"
  rm -f "$tmp"
}

# iac_scan_file SET IDX RELPATH ABSPATH - the same two-pass design as
# modules/sast/engine.sh's sast_scan_file (§10.3): pass 1 collects every
# match with its byte offset via scan_match_offsets, pass 2 evaluates the
# context window per match and emits a finding with module=iac.
iac_scan_file() {
  local set=$1 idx=$2 relpath=$3 abspath=$4
  local pattern id
  pattern=$(records_field "$set" "$idx" pattern)
  id=$(records_id "$set" "$idx")

  local hits=$SCOURSH_SCRATCH/iac-hits.$$
  if ! scan_match_offsets "$hits" "$pattern" "$abspath"; then
    rm -f "$hits"
    return 0
  fi

  local total='' ln off text count=0 overflow=0
  # off is read to consume the byte-offset field so `text` lands in the right
  # position, the same shape sast_scan_file uses.
  # shellcheck disable=SC2034
  while IFS=: read -r ln off text; do
    [[ -n $ln ]] || continue
    count=$(( count + 1 ))
    if (( count > SCOURSH_IAC_MAX_MATCHES_PER_FILE )); then
      overflow=1
      break
    fi
    [[ -n $total ]] || total=$(awk 'END{print NR}' "$abspath")
    if sast_context_ok "$set" "$idx" "$abspath" "$ln" "$total"; then
      _iac_emit_finding "$set" "$idx" "$relpath" "$ln" "$text"
    fi
  done <"$hits"
  rm -f "$hits"

  if (( overflow )); then
    run_record truncated_matches "check=$id file=$relpath max=$SCOURSH_IAC_MAX_MATCHES_PER_FILE"
    finding_new
    finding_set check_id "$id"
    finding_set module iac
    finding_set title "Match count truncated at $SCOURSH_IAC_MAX_MATCHES_PER_FILE for $relpath"
    finding_set base_severity info
    finding_set confidence high
    finding_set cwe none
    finding_set owasp none
    finding_set loc_path "$relpath"
    finding_set loc_line "$SCOURSH_IAC_MAX_MATCHES_PER_FILE"
    finding_set cell "$SCOURSH_PATH_ROOT"
    finding_set logical_kind file
    finding_set logical_fqn "$relpath:truncated"
    finding_set remediation 'No action on this entry itself; it records that scanning stopped early for this (check, file) pair. Split the file or raise max-matches-per-file in config/scanner.conf if the remaining matches matter.'
    finding_set_match "truncated at $SCOURSH_IAC_MAX_MATCHES_PER_FILE matches"
    finding_set_evidence "truncated at $SCOURSH_IAC_MAX_MATCHES_PER_FILE matches"
    finding_emit
  fi
}

_iac_emit_finding() {
  local set=$1 idx=$2 relpath=$3 ln=$4 text=$5
  local id
  id=$(records_id "$set" "$idx")
  finding_new
  finding_from_record "$set" "$idx"
  finding_set module iac
  finding_set loc_path "$relpath"
  finding_set loc_line "$ln"
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set logical_kind file
  finding_set logical_fqn "$relpath:$ln"
  # Reused unchanged from engine.sh: it keys off the check id string alone
  # (*SECRET*, *PRIVATE_KEY*, *API_KEY*, *PASSWORD*, *AKID*, *JWT*), which is
  # exactly what IAC-TF-HARDCODED_SECRET-01 matches.
  if _sast_check_is_sensitive "$id"; then
    finding_set sensitive_data true
  fi
  finding_set_match "$text"
  finding_set_evidence "$text"
  finding_emit
}

# iac_scan_tree ROOT ID... - the same shape as sast_scan_tree, reusing
# sast_walk_files/sast_relpath/scan_root_of/sast_rule_matches_file unchanged;
# only the per-file scan call (iac_scan_file, not sast_scan_file) differs, so
# that findings land with module=iac.
iac_scan_tree() {
  local root=$1
  shift
  local -a ids=("$@")
  _iac_capture_max_matches
  local scan_root
  scan_root=$(scan_root_of "$root")
  local abspath rel id loc set idx
  while IFS= read -r abspath; do
    [[ -n $abspath ]] || continue
    rel=$(sast_relpath "$scan_root" "$abspath")
    occurrence_reset_unit "$rel"
    for id in "${ids[@]+"${ids[@]}"}"; do
      loc=${_SAST_CHECK_LOC[$id]:-}
      [[ -n $loc ]] || continue
      read -r set idx <<<"$loc"
      sast_rule_matches_file "$set" "$idx" "$rel" || continue
      iac_scan_file "$set" "$idx" "$rel" "$abspath"
    done
  done < <(sast_walk_files "$root")
}
