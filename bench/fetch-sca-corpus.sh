#!/usr/bin/env bash
# bench/fetch-sca-corpus.sh - build the SCA benchmark leg's lockfile corpus
# from bench/sca-advisories.lock.
#
#   bench/fetch-sca-corpus.sh              # verify each pinned id live, then build
#   bench/fetch-sca-corpus.sh --offline    # build from the pin alone, no network
#
# THIS FILE TOUCHES THE NETWORK BY DEFAULT - the same quarantine
# bench/fetch-corpus.sh documents for itself applies here too, and this is
# the SECOND (and only other) file in bench/ that does.  Unlike a git-cloned
# corpus, though, every fact this corpus needs is already IN the pin
# (bench/sca-advisories.lock's own header explains why: there is no single
# third-party SCA benchmark repository to clone), so the network call here is
# a VERIFICATION - does the pinned osv-id still resolve, and does its
# database_specific.severity still read what the lock file recorded - not a
# fetch of content the pin lacks.  `--offline` skips it and builds the
# identical corpus from the pin alone, which is what lets this corpus,
# uniquely among bench/'s three, be reproduced on an air-gapped host.
#
# Never called by a measurement run, by the scanner, or by the test suite -
# tests/suites/bench.sh section G's both-directions assertion covers this
# file by the same path pattern it already uses for bench/fetch-corpus.sh.
#
# WHAT IT WRITES.  bench/corpora/_samples/sca-lockfiles-26/{root,truth,MANIFEST}
# - the exact shape bench/make-sample.sh produces for the OWASP sample, so
# bench/run-tool.sh --sample sca-lockfiles-26 and bench/score.sh work
# unmodified.  bench/corpora/ stays gitignored; nothing this script writes is
# committed (bench/.gitignore's existing rule already covers it).
#
# ONE CASE DIRECTORY PER (package, real/patched) PAIR, and the ground-truth
# `file` NAMES THE DIRECTORY, never the manifest file inside it.  This is a
# deliberate departure from the OWASP sample's one-file-per-case truth, and
# the reason is cross-tool disagreement: a Go case ships both go.mod and
# go.sum, and which one a given tool blames a finding on is that tool's own
# implementation detail (observed here: some tools report go.mod, some
# go.sum) - anchoring the truth to one specific filename would silently
# read a real detection as a miss purely because the tool named the sibling
# file instead.  Every bench/tools/*.sh SCA adapter normalises its `file`
# the same way, to the case's own directory, for exactly this reason - see
# each adapter's own header.
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BENCH_LIB_DIR=$BENCH_ROOT/lib
# shellcheck source=bench/lib/sca_advisories.sh
source "$BENCH_LIB_DIR/sca_advisories.sh"
# shellcheck source=bench/lib/truth.sh
source "$BENCH_LIB_DIR/truth.sh"

LOCK=${BENCH_SCA_ADVISORIES_LOCK:-$BENCH_ROOT/sca-advisories.lock}
CORPORA=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}
SAMPLE_NAME=sca-lockfiles-26
OUT=$CORPORA/_samples/$SAMPLE_NAME

usage() {
  cat <<'EOF'
bench/fetch-sca-corpus.sh [--offline]

  --offline   skip the live OSV.dev re-verification and build from
              bench/sca-advisories.lock alone (works with no network access)

Writes bench/corpora/_samples/sca-lockfiles-26/{root,truth,MANIFEST}.
EOF
}

# _osv_verify ID OSV_ID WANT_SEVERITY - GET the advisory and confirm its
# database_specific.severity still reads what the lock file pinned.  A
# mismatch is refused rather than silently accepted, the same "verify after
# fetch" discipline bench/fetch-corpus.sh applies to its own commit pin - an
# advisory whose severity has been revised since 2026-09-10 is a fact worth
# surfacing, not papering over.
_osv_verify() {
  local id=$1 osv_id=$2 want=$3 body got
  body=$(curl -fsS --max-time 15 "https://api.osv.dev/v1/vulns/$osv_id" 2>/dev/null) || {
    printf 'bench: %s: could not reach OSV.dev for %s - see --offline\n' "$id" "$osv_id" >&2
    return 5
  }
  got=$(printf '%s' "$body" | python3 -c '
import json,sys
d = json.load(sys.stdin)
print((d.get("database_specific") or {}).get("severity", ""))
' 2>/dev/null) || { printf 'bench: %s: could not parse OSV response for %s\n' "$id" "$osv_id" >&2; return 5; }
  if [[ $got != "$want" ]]; then
    printf 'bench: %s: OSV severity for %s is now `%s`, lock file pins `%s` - refusing (rebuild the lock entry)\n' \
      "$id" "$osv_id" "$got" "$want" >&2
    return 5
  fi
}

# _write_case DIR ECOSYSTEM PACKAGE VERSION - one manifest, one dependency.
_write_case() {
  local dir=$1 eco=$2 pkg=$3 ver=$4
  mkdir -p "$dir"
  case $eco in
    npm)
      cat >"$dir/package-lock.json" <<EOF
{
  "name": "sca-bench-case",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "sca-bench-case",
      "version": "1.0.0",
      "dependencies": {
        "$pkg": "$ver"
      }
    },
    "node_modules/$pkg": {
      "version": "$ver",
      "resolved": "https://registry.npmjs.org/$pkg/-/$pkg-$ver.tgz",
      "license": "MIT"
    }
  }
}
EOF
      ;;
    PyPI)
      cat >"$dir/requirements.txt" <<EOF
$pkg==$ver
EOF
      ;;
    Go)
      cat >"$dir/go.mod" <<EOF
module bench.example/sca-bench-case

go 1.21

require $pkg v$ver
EOF
      cat >"$dir/go.sum" <<EOF
$pkg v$ver h1:FAKEHASHFORBENCHMARKPURPOSESONLYAAAAAAAAAAA=
$pkg v$ver/go.mod h1:FAKEHASHMODFORBENCHMARKPURPOSESONLYAAAAAAAA=
EOF
      ;;
    *)
      printf 'bench: unknown ecosystem in sca-advisories.lock: %s\n' "$eco" >&2
      return 2
      ;;
  esac
}

# _category ECOSYSTEM -> the scoring category, matching every SCA adapter's
# own `_scope` output (bench/tools/scoursh-sca.sh et al.).
_category() {
  case $1 in
    npm) printf 'sca-npm' ;;
    PyPI) printf 'sca-pypi' ;;
    Go) printf 'sca-go' ;;
    *) printf '%s' "$1" ;;
  esac
}

main() {
  local offline=0
  while (( $# > 0 )); do
    case $1 in
      --offline) offline=1; shift ;;
      -h | --help) usage; return 0 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done

  sca_advisories_load "$LOCK" || return $?

  rm -rf "${OUT:?}"
  mkdir -p "$OUT/root"
  local truth=$OUT/truth
  : >"$truth"

  local id eco pkg vuln fixed osv_id sev cat rc=0
  for id in "${BENCH_SCA_ADV_IDS[@]}"; do
    eco=$(sca_advisory_field "$id" ecosystem)
    pkg=$(sca_advisory_field "$id" package)
    vuln=$(sca_advisory_field "$id" vuln-version)
    fixed=$(sca_advisory_field "$id" fixed-version)
    osv_id=$(sca_advisory_field "$id" osv-id)
    sev=$(sca_advisory_field "$id" severity)
    cat=$(_category "$eco")

    if (( ! offline )); then
      _osv_verify "$id" "$osv_id" "$sev" || rc=5
    fi

    _write_case "$OUT/root/$id-vuln" "$eco" "$pkg" "$vuln"
    _write_case "$OUT/root/$id-patched" "$eco" "$pkg" "$fixed"

    printf '%s%s%s%s%s%s%s%s%s\n' \
      "$id-vuln" "$BENCH_TRUTH_US" "$id-vuln" "$BENCH_TRUTH_US" \
      "$cat" "$BENCH_TRUTH_US" "$osv_id" "$BENCH_TRUTH_US" true >>"$truth"
    printf '%s%s%s%s%s%s%s%s%s\n' \
      "$id-patched" "$BENCH_TRUTH_US" "$id-patched" "$BENCH_TRUTH_US" \
      "$cat" "$BENCH_TRUTH_US" "" "$BENCH_TRUTH_US" false >>"$truth"
  done

  if (( rc != 0 )); then
    printf 'bench: sca corpus verification failed - see above (use --offline to skip)\n' >&2
    return "$rc"
  fi

  {
    printf 'sample: %s\n' "$SAMPLE_NAME"
    printf 'commit: n/a - see bench/sca-advisories.lock (not a git-cloned corpus)\n'
    printf 'source: bench/sca-advisories.lock\n'
    printf 'verified-live: %s\n' "$(( offline == 0 ))"
    printf 'cases: %d\n' "$(( ${#BENCH_SCA_ADV_IDS[@]} * 2 ))"
    printf 'real-cases: %d\n' "${#BENCH_SCA_ADV_IDS[@]}"
    printf 'trap-cases: %d (patched version of the same package - the sanitized-trap counterpart)\n' \
      "${#BENCH_SCA_ADV_IDS[@]}"
    printf 'selection: every record in bench/sca-advisories.lock, in file order\n'
  } >"$OUT/MANIFEST"

  printf 'bench: sca corpus built: %d case(s) under %s\n' "$(( ${#BENCH_SCA_ADV_IDS[@]} * 2 ))" "$OUT"
  cat "$OUT/MANIFEST"
}

main "$@"
