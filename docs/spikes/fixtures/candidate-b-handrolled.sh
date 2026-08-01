#!/usr/bin/env bash
# SPIKE FIXTURE - not production code, not wired into any build/test target.
# Candidate B: hand-rolled while/case shift loop, no external getopt dependency.
# See ../scan-arg-parsing-portability.md for the ADR and the captured GNU/BSD transcripts
# (docs/spikes/fixtures/transcript-*.txt) this fixture produced. RECOMMENDED candidate -
# scan.sh (build order step 2) should adopt this shape, not this literal file.
set -Eeuo pipefail

EXIT_OK=0 EXIT_GATE=1 EXIT_USAGE=2 EXIT_SCOPE=3 EXIT_INPUT=4 EXIT_INCOMPLETE=5

die() { local code=$1; shift; echo "die($code): $*" >&2; exit "$code"; }

# require_val NAME "$1" "${2-}" REMAINING_ARGC
# Accepts both `--flag value` and `--flag=value`. Only tolerated in-loop.
path="" lang="" history=0 jobs="" fail_on="" format="" out="" paranoid=0

while (( $# > 0 )); do
  case "$1" in
    --path=*)     path=${1#*=}; shift ;;
    --path)       (( $# >= 2 )) || die "$EXIT_USAGE" "--path requires a value"; path=$2; shift 2 ;;
    --lang=*)     lang=${1#*=}; shift ;;
    --lang)       (( $# >= 2 )) || die "$EXIT_USAGE" "--lang requires a value"; lang=$2; shift 2 ;;
    --history)    history=1; shift ;;
    --jobs=*)     jobs=${1#*=}; shift ;;
    --jobs)       (( $# >= 2 )) || die "$EXIT_USAGE" "--jobs requires a value"; jobs=$2; shift 2 ;;
    --fail-on=*)  fail_on=${1#*=}; shift ;;
    --fail-on)    (( $# >= 2 )) || die "$EXIT_USAGE" "--fail-on requires a value"; fail_on=$2; shift 2 ;;
    --format=*)   format=${1#*=}; shift ;;
    --format)     (( $# >= 2 )) || die "$EXIT_USAGE" "--format requires a value"; format=$2; shift 2 ;;
    --out=*)      out=${1#*=}; shift ;;
    --out)        (( $# >= 2 )) || die "$EXIT_USAGE" "--out requires a value"; out=$2; shift 2 ;;
    --paranoid)   paranoid=1; shift ;;
    --)           shift; break ;;
    --*)          die "$EXIT_USAGE" "unknown option: $1" ;;
    *)            break ;;
  esac
done

echo "path=[$path] lang=[$lang] history=$history jobs=[$jobs] fail_on=[$fail_on] format=[$format] out=[$out] paranoid=$paranoid positional=[$*]"
exit "$EXIT_OK"
