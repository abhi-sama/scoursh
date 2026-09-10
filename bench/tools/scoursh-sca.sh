#!/usr/bin/env bash
# bench/tools/scoursh-sca.sh - the scoursh SCA adapter (B5).
#
# A SEPARATE file from bench/tools/scoursh.sh, not a second mode of it:
# `<tool>_run` (bench/run-tool.sh) takes no category argument, so one file
# names one full scan command, and scoursh's SAST and SCA modules are two
# different `scan.sh` subcommands with two different required inputs (SAST
# needs nothing; SCA REQUIRES a populated data/advisories.db - see below).
# The function prefix is `scoursh-sca_*` - bash allows a hyphen in a function
# name, and the alternative (`scoursh_sca_*`) would collide with a
# hypothetical future `bench/tools/scoursh_sca.sh` typo in a way a hyphen
# cannot.
#
# ONE scan.sh INVOCATION PER CASE DIRECTORY, NOT ONE OVER THE WHOLE ROOT -
# measured, not a style choice.  The SCA location profile is
# `ecosystem package advisory_id` (AGENTS.md's own `_fp_components_for`
# table), which carries no path component at all, so a normalised record
# needs some OTHER field to recover which of the corpus's 26 manifests a
# finding came from.  The obvious candidate, `cell` (tension 12's
# (check, scope-cell) coverage unit), does carry a directory - but a
# multi-directory scan over the corpus root was measured here to record
# `cell` as the SCAN ROOT itself for every finding, not the specific
# manifest's containing directory: `modules/sca/*` never narrows the cell
# below the run's own `--path`, because SCA's coverage question is
# "was this MANIFEST walked", not "was this file's exact line reached" the
# way SAST's is.  A single-corpus run therefore collapses all 26 cases onto
# one `cell` string, which would make every case indistinguishable to the
# scorer.  Scanning one case directory at a time sidesteps the ambiguity
# entirely: `--path` IS the case directory, so `cell` (or, more simply, the
# directory name this adapter itself already knows from the loop below)
# names the case correctly by construction.  The cost is real and reported
# rather than hidden - see the wall-clock note in the leg's own results
# README: 26 invocations at scoursh's own ~34s fixed per-run cost (the scout
# report's §3.3) is the leg's own worked instance of that same finding.
#
# REQUIRES A POPULATED data/advisories.db, WHICH THIS ADAPTER DOES NOT BUILD.
# Per AGENTS.md's own tension-14 entry, an absent database is SCA's declared
# required input, not a clean zero-finding run - scan.sh itself refuses with
# exit 4.  Populating it is this leg's own documented prerequisite
# (`tools/vendor-engines.sh advisories bulk <ecosystem>`, run BY HAND, ON A
# NETWORKED BOX, exactly like every other command that script provides - see
# its own header) and is never invoked from here: this adapter is a
# measurement, not a provisioning step, and data/advisories.db is itself
# gitignored (.gitignore: "data/versions.db was committed by accident once"),
# so nothing this leg commits can carry it.  `scoursh-sca_run` fails loudly
# with the actual scan.sh exit code rather than silently treating an absent
# database as "found nothing" - see the case statement below.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SCOURSH_SCA_SOURCED:-} ]] && return 0
BENCH_TOOL_SCOURSH_SCA_SOURCED=1

BENCH_SCOURSH_ROOT=${BENCH_SCOURSH_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}

scoursh-sca_available() { [[ -x $BENCH_SCOURSH_ROOT/scan.sh || -r $BENCH_SCOURSH_ROOT/scan.sh ]]; }

scoursh-sca_version() {
  local v=''
  [[ -r $BENCH_SCOURSH_ROOT/VERSION ]] && IFS= read -r v <"$BENCH_SCOURSH_ROOT/VERSION"
  local sha=''
  sha=$(git -C "$BENCH_SCOURSH_ROOT" rev-parse --short=12 HEAD 2>/dev/null) || sha=''
  printf '%s' "${v:-unknown}${sha:++$sha}"
}

# Matches the corpus categories bench/fetch-sca-corpus.sh's own `_category`
# assigns - the three ecosystems bench/sca-advisories.lock actually covers,
# never `docs/DESIGN.md`'s full six: a category this corpus carries no case
# for would render as a vacuous 0-case row, which is not the same claim as
# "scoursh does not compete here" (bench/README.md's no-coverage rule).
scoursh-sca_scope() {
  printf '%s\n' sca-npm sca-pypi sca-go
}

scoursh-sca_run() {
  local raw=$1 root=$2
  mkdir -p "$raw/cases"
  local case_dir case_name rc=0 worst_rc=0
  for case_dir in "$root"/*/; do
    [[ -d $case_dir ]] || continue
    case_name=$(basename "$case_dir")
    rc=0
    (
      cd "$BENCH_SCOURSH_ROOT" &&
        bash scan.sh sca --path "$case_dir" --out "$raw/cases/$case_name" --format json
    ) >"$raw/cases/$case_name.stdout.txt" 2>"$raw/cases/$case_name.stderr.txt" || rc=$?
    printf '%s\n' "$rc" >"$raw/cases/$case_name.exit-code"
    case $rc in
      0 | 1) ;;
      4)
        printf 'bench: scoursh sca exited 4 on %s (required input missing - is data/advisories.db populated?) - see %s/cases/%s.stderr.txt\n' \
          "$case_name" "$raw" "$case_name" >&2
        (( rc > worst_rc )) && worst_rc=$rc
        ;;
      *)
        printf 'bench: scoursh sca exited %d on %s - see %s/cases/%s.stderr.txt\n' \
          "$rc" "$case_name" "$raw" "$case_name" >&2
        (( rc > worst_rc )) && worst_rc=$rc
        ;;
    esac
  done
  printf '%s\n' "$worst_rc" >"$raw/exit-code"
  return "$worst_rc"
}

scoursh-sca_normalise() {
  local raw=$1 root=$2
  local case_dir case_name jsonl
  for case_dir in "$raw"/cases/*/; do
    [[ -d $case_dir ]] || continue
    case_name=$(basename "$case_dir")
    jsonl=$case_dir/findings.jsonl
    [[ -r $jsonl ]] || continue
    _scoursh_sca_normalise_one "$jsonl" "$case_name"
  done
}

_scoursh_sca_normalise_one() {
  local jsonl=$1 case_name=$2
  local flat
  flat=$(
    {
      printf '['
      awk 'NF { if (n++) printf ","; printf "%s", $0 }' "$jsonl"
      printf ']'
    } | bench_json_flatten
  )
  # An empty findings.jsonl (0 bytes - the ordinary "patched" case) flattens
  # to a single empty-path root marker, which bench_flat_read now drops
  # (bench/lib/normalise.sh's own header explains why); the loop below then
  # finds no `0/check_id` and returns with zero records, exactly as it
  # should for a case where scoursh found nothing.
  bench_flat_read <<<"$flat"

  local i=0 p ck eco pkg adv sev
  while :; do
    p="$i/check_id"
    [[ -n ${BENCH_FLAT_TYPE[$p]:-} ]] || break
    ck=$(bench_flat_str "$i/check_id")
    # SCA-COV-* is a per-run coverage roll-up (AGENTS.md's own "Sharp edges"
    # entry: "must be emitted EXACTLY ONCE PER RUN ... names no dependency") -
    # it carries no ecosystem/package/advisory_id and is never a hit against
    # any one case.
    if [[ $ck != SCA-COV-* ]]; then
      eco=$(bench_flat_str "$i/location/ecosystem")
      pkg=$(bench_flat_str "$i/location/package")
      adv=$(bench_flat_str "$i/location/advisory_id")
      sev=$(_scoursh_sca_severity "$(bench_flat_str "$i/severity")")
      bench_record "$case_name" '' "$adv" "$sev" "$eco:$pkg"
    fi
    i=$(( i + 1 ))
  done
}

_scoursh_sca_severity() {
  case $1 in
    critical | high | medium | low | info) printf '%s' "$1" ;;
    *) printf 'info' ;;
  esac
}
