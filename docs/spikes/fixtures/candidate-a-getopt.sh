#!/usr/bin/env bash
# SPIKE FIXTURE - not production code, not wired into any build/test target.
# Candidate A: external `getopt(1)` (GNU/util-linux "enhanced" mode) for long-option parsing.
# See ../scan-arg-parsing-portability.md for the ADR and the captured GNU/BSD transcripts
# (docs/spikes/fixtures/transcript-*.txt) this fixture produced. REJECTED candidate.
set -Eeuo pipefail

EXIT_OK=0 EXIT_GATE=1 EXIT_USAGE=2 EXIT_SCOPE=3 EXIT_INPUT=4 EXIT_INCOMPLETE=5

die() { local code=$1; shift; echo "die($code): $*" >&2; exit "$code"; }

PARSED=$(getopt -o '' --long path:,lang:,history,jobs:,fail-on:,format:,out:,paranoid -n 'candidate-a' -- "$@") \
  || die "$EXIT_USAGE" "getopt(1) rejected the arguments (rc=$?)"
eval set -- "$PARSED"

path="" lang="" history=0 jobs="" fail_on="" format="" out="" paranoid=0
while true; do
  case "$1" in
    --path) path=$2; shift 2 ;;
    --lang) lang=$2; shift 2 ;;
    --history) history=1; shift ;;
    --jobs) jobs=$2; shift 2 ;;
    --fail-on) fail_on=$2; shift 2 ;;
    --format) format=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --paranoid) paranoid=1; shift ;;
    --) shift; break ;;
    *) die "$EXIT_USAGE" "unreachable getopt state: $1" ;;
  esac
done

echo "path=[$path] lang=[$lang] history=$history jobs=[$jobs] fail_on=[$fail_on] format=[$format] out=[$out] paranoid=$paranoid positional=[$*]"
exit "$EXIT_OK"
