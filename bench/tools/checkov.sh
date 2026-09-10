#!/usr/bin/env bash
# bench/tools/checkov.sh - Checkov (Prisma Cloud / bridgecrewio), IaC.
#
# GATE: `checkov -d ROOT -o json --compact --quiet`, its documented default
# framework set (auto-detected), no `--skip-check`, no `--check`, no custom
# policy directory.  Nothing is tuned against the corpus - methodology rule R5.
#
# CHECKOV COMMUNITY EDITION SHIPS NO SEVERITY, AND THAT IS WHY THE B6 IaC LEG
# PUBLISHES ONLY THE ALL-FINDINGS COLUMN.  Measured on the TerraGoat AWS
# slice: 158 of 158 failed checks carry `"severity": null`, because severity is
# supplied by the Prisma Cloud platform and not by the open-source rule set.
# This adapter therefore maps an absent severity to `medium`, which is a
# CONVENTION and not a measurement - and a `--min-severity high` scorecard
# built on it would compare Trivy's and KICS's real severities against a
# placeholder and report Checkov at zero recall, which would be a fact about
# Checkov CE's JSON rather than about its detection.  Rule R5 asks for the gate
# to be declared; this is the declaration, and the leg README states the
# deviation and its reason rather than quietly printing the misleading column.
#
# WHY `--compact`: it drops the `code_block` echo of the scanned source from
# every finding.  The raw output is committed, and TerraGoat is Apache-2.0
# while some corpora are not, so keeping a tool from copying corpus text into a
# committed artefact is a licence property as well as a size one.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_CHECKOV_SOURCED:-} ]] && return 0
BENCH_TOOL_CHECKOV_SOURCED=1

checkov_available() { command -v checkov >/dev/null 2>&1; }

checkov_version() { checkov --version 2>/dev/null | head -1 | tr -d '\r'; }

checkov_scope() { printf '%s\n' terraform-aws kubernetes; }

# CHECKOV IS INVOKED FROM INSIDE THE SCAN ROOT AS `-d .`, AND THAT IS A
# CORRECTNESS REQUIREMENT RATHER THAN A STYLE CHOICE.  Two separate defects
# make the obvious `checkov -d "$root"` wrong, and each of them fails silently.
#
# 1. THE KUBERNETES RUNNER DISCARDS EVERY FILE UNDER A HIDDEN DIRECTORY.  A
#    path with a dot-prefixed component anywhere in it - a git worktree pool,
#    a `.cache`, a `.local/share` - produces exit 0, an empty stderr, and a
#    report with no `kubernetes` block at all.  Measured on 3.3.10 over one
#    identical tree:
#
#      /tmp/<no dot component>/root      kubernetes 253, secrets 2
#      /tmp/.hidden/root                 secrets 2      <- everything gone
#      <abs path under a dot-dir>/root   secrets 2      <- everything gone
#      cd <root> && checkov -d .         kubernetes 253, secrets 2
#
#    The Terraform runner does NOT apply this filter, which is why the
#    TerraGoat leg never showed it.  This harness was developed in a checkout
#    under a dot-directory and hit it, which is the only reason it is known.
#
# 2. THE TWO RUNNERS DISAGREE ABOUT WHETHER `file_path` INCLUDES THE `-d`
#    ARGUMENT'S BASENAME.  Passing the root's basename from its parent - the
#    first attempted fix for (1) - made the kubernetes runner report
#    `file_path: /root/cache-store/deployment.yaml` and `file_abs_path` with
#    `root/` DOUBLED, while terraform reported `/db-app.tf` with a correct
#    absolute path.  Every kubernetes case then failed to match and Checkov
#    scored 2 of 19 with 255 findings in hand.
#
# `cd` into the root and pass `.`: no dot-prefixed component reaches Checkov,
# both runners agree, and `file_abs_path` is the real path in both.
checkov_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  # Checkov exits 1 when a check FAILS, which is the normal outcome here.
  ( cd -- "$root" && checkov -d . -o json --compact --quiet ) \
    >"$raw/checkov.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *) printf 'bench: checkov exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2; return 2 ;;
  esac
}

# Checkov's JSON is an OBJECT when one framework ran and an ARRAY of such
# objects when several did, and which shape arrives depends on what the corpus
# happens to contain - so a normaliser written against either alone breaks on a
# corpus it was not developed on, silently, by finding no `results` key and
# emitting nothing.  Both shapes are handled by flattening the document and
# reading INDEXED paths when the top level is an array.
checkov_normalise() {
  local raw=$1 root=$2
  local f=$raw/checkov.json
  [[ -r $f ]] || { printf 'bench: no checkov.json under %s\n' "$raw" >&2; return 2; }

  local flat
  flat=$(bench_json_flatten <"$f") || return 2
  bench_flat_read <<<"$flat"

  # An array document has `0/check_type`; an object document has `check_type`.
  local prefixes=() i=0
  if [[ -n ${BENCH_FLAT_TYPE[0/check_type]:-} ]]; then
    while [[ -n ${BENCH_FLAT_TYPE[$i/check_type]:-} ]]; do
      prefixes+=("$i/"); i=$(( i + 1 ))
    done
  else
    prefixes=('')
  fi

  local pre j p file line rule
  for pre in "${prefixes[@]}"; do
    j=0
    while :; do
      p="${pre}results/failed_checks/$j/check_id"
      [[ -n ${BENCH_FLAT_TYPE[$p]:-} ]] || break
      rule=$(bench_flat_str "$p")
      # `file_abs_path` AND NOT `file_path`.  `file_path` is relative to the
      # `-d` argument and carries a leading slash (`/db-app.tf`), so it looks
      # absolute, bench_relpath cannot strip it, and every case matches
      # nothing - which reads as "this tool found nothing" rather than as an
      # error.  `file_abs_path` is the real location and needs no guessing
      # about what checkov_run passed as `-d`, which matters because that
      # function deliberately passes a basename from the parent directory (see
      # its header).
      file=$(bench_flat_str "${pre}results/failed_checks/$j/file_abs_path")
      if [[ -z $file ]]; then
        file=$(bench_flat_str "${pre}results/failed_checks/$j/file_path")
        file=${file#/}
      fi
      line=$(bench_flat_num "${pre}results/failed_checks/$j/file_line_range/0")
      # A range starting at 0 means "the whole file" and is not a line.
      [[ $line == 0 ]] && line=''
      file=$(bench_relpath "$file" "$root")
      # No CWE: Checkov's rules carry `bc_category` and a guideline URL, not a
      # CWE, and inventing one per rule id would put an unauditable mapping
      # between the tool's output and its score.  An empty CWE matches loosely
      # and never strictly, which is the honest treatment.
      bench_record "$file" "$line" '' "$(_checkov_severity "$(bench_flat_str "${pre}results/failed_checks/$j/severity")")" "$rule"
      j=$(( j + 1 ))
    done
  done
}

_checkov_severity() {
  case $1 in
    CRITICAL | critical) printf 'critical' ;;
    HIGH | high) printf 'high' ;;
    MEDIUM | medium) printf 'medium' ;;
    LOW | low) printf 'low' ;;
    INFO | info) printf 'info' ;;
    # Absent, which in Checkov CE is EVERY finding.  See the header.
    *) printf 'medium' ;;
  esac
}
