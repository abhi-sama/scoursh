#!/usr/bin/env bash
# bench/tools/trufflehog.sh - TruffleHog, secrets.
#
# GATE: `trufflehog filesystem ROOT --json --no-verification
# --results=verified,unknown,unverified`, its own default detector set.
#
# `--no-verification` IS NOT A HANDICAP, IT IS THE ONLY DEFENSIBLE SETTING
# HERE: TruffleHog's verified
# mode calls each provider's API to see whether a candidate credential still
# works, which is a deliberate EGRESS action.  Running it would (a) send this
# corpus's values to third-party APIs, (b) make the result depend on those
# APIs' availability on the day, and (c) make the number unreproducible on an
# air-gapped host - and every value in this corpus is a fake, so verification
# could only ever return "not valid" and would suppress real detections.
# `--results` is spelled out rather than left at its default so the run cannot
# silently start dropping unverified results if that default changes.
#
# `.git/` IS EXCLUDED, AND THIS IS A FAIRNESS FIX RATHER THAN A TUNING KNOB.
# Measured on leaky-repo: `trufflehog filesystem` walks `.git/objects/` and
# reports the SAME credential twice, once from the working tree and once from
# the loose object holding it - 12 of its 24 findings were `.git/objects/...`
# duplicates.  Neither `gitleaks dir` nor scoursh reads `.git/`, and the
# directory is an artefact of how bench/fetch-corpus.sh obtained the corpus
# rather than part of the corpus, so excluding it puts all three tools on one
# surface.  It can only LOWER TruffleHog's finding count, never raise it.
#
# NO SEVERITY.  A TruffleHog result carries a detector name and a verification
# state, not a severity, so every record lands at `medium` by adapter
# convention - see bench/tools/gitleaks.sh's header for why the B6 secrets leg
# therefore publishes only the all-findings column.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_TRUFFLEHOG_SOURCED:-} ]] && return 0
BENCH_TOOL_TRUFFLEHOG_SOURCED=1

trufflehog_available() { command -v trufflehog >/dev/null 2>&1; }

trufflehog_version() { trufflehog --version 2>&1 | head -1 | tr -d '\r'; }

trufflehog_scope() { printf '%s\n' secrets; }

trufflehog_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  # The exclude file is written beside the raw output rather than into the
  # corpus, so the corpus stays exactly as bench/fetch-corpus.sh left it and
  # the exclusion is visible in the committed artefact.
  # The pattern is matched against the path TruffleHog itself reports, which
  # is the full path it walked - so an anchored `^\.git/` matches nothing when
  # the scan root is absolute, which is how the first run of this adapter came
  # back with all 12 `.git/objects/` duplicates still present.  An unanchored
  # `/\.git/` matches the directory wherever the root happens to be rooted.
  printf '%s\n' '/\.git/' >"$raw/exclude-paths.txt"
  trufflehog filesystem "$root" --json --no-verification \
    --results=verified,unknown,unverified \
    --exclude-paths "$raw/exclude-paths.txt" \
    >"$raw/trufflehog.jsonl" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  (( rc == 0 )) || {
    printf 'bench: trufflehog exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
    return 2
  }
}

# TruffleHog writes JSONL - one result object per line, no envelope - and
# interleaves its own progress objects on the same stream, which carry no
# `SourceMetadata`.  The loop therefore keys on the metadata path being present
# rather than on the line being non-empty.
trufflehog_normalise() {
  local raw=$1 root=$2
  local f=$raw/trufflehog.jsonl
  [[ -r $f ]] || { printf 'bench: no trufflehog.jsonl under %s\n' "$raw" >&2; return 2; }

  local flat
  flat=$(
    {
      printf '['
      awk 'NF { if (n++) printf ","; printf "%s", $0 }' "$f"
      printf ']'
    } | bench_json_flatten
  ) || return 2
  bench_flat_read <<<"$flat"

  local i=0 p rule file line
  while :; do
    p="$i/SourceMetadata/Data/Filesystem/file"
    if [[ -z ${BENCH_FLAT_TYPE[$p]:-} ]]; then
      # Not a result object.  Keep walking - a progress line in the middle of
      # the stream must not truncate the read, which is what `break` here
      # would do and what would silently halve a long run's findings.
      [[ -n ${BENCH_FLAT_TYPE[$i/SourceType]:-} || -n ${BENCH_FLAT_TYPE[$i/level]:-} ]] || break
      i=$(( i + 1 ))
      continue
    fi
    rule=$(bench_flat_str "$i/DetectorName")
    file=$(bench_relpath "$(bench_flat_str "$p")" "$root")
    line=$(bench_flat_num "$i/SourceMetadata/Data/Filesystem/line")
    # THE SECRET ITSELF IS NEVER COPIED INTO A RECORD - TruffleHog reports it
    # in `Raw` and `Redacted`.  See bench/tools/gitleaks.sh's note.
    bench_record "$file" "$line" '' 'medium' "$rule"
    i=$(( i + 1 ))
  done
}
