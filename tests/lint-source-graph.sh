#!/usr/bin/env bash
# tests/lint-source-graph.sh - cap the shellcheck -x hub fan-out per entry
# point, per the scoursh-shellcheck-memory-root-cause finding.
#
# `shellcheck -x` inlines a sourced file EVERY time a real `# shellcheck
# source=<path>` directive is followed - it does not memoise - so a file
# reachable N times through N different source edges gets analysed N times
# over. That cost is NOT a function of how many lines get inlined: it is
# driven by how many times the `lib/` HUB chain (lib/core.sh, lib/records.sh,
# lib/findings.sh, lib/http.sh, lib/config.sh) is re-expanded into one
# analysis, and that relationship is exponential with a measured cliff
# between 6 and 8 copies (0.79 GB at 6 copies of lib/core.sh alone, 36.75 GB
# at 8). A file's HUB SUM - the total number of times those five files are
# reachable, counting every path to them - is a cheap, accurate predictor of
# that cost and is computable in milliseconds, unlike the shellcheck run
# itself, which can take minutes and tens of gigabytes to reach the same
# verdict (or never reach it - a run over budget is skipped, not failed, so
# without this lint a fan-out regression ships silently).
#
# This walks exactly the edges shellcheck's `-x` follows - a
# `# shellcheck source=<path>` directive, with only comment lines allowed
# between it and the `source`/`.` line it applies to, skipping any directive
# whose target is `/dev/null` - for every shell file in the tree, and fails
# when a file's hub sum exceeds the cap.
#
# THE CAP IS 17, AND IT IS NOW THE TREE'S OWN MEASURED WORST RATHER THAN A
# NUMBER WITH SLACK IN IT. It used to be 20, chosen to sit in a gap between
# `tests/suites/dast-ratelimit.sh` (hub sum 21, 5.92 GB) and
# `tests/suites/dast-hosthdr.sh` (hub sum 23 pre-fix, 30.39 GB). That slack
# is what let the tree grow back into a shape no hosted CI runner can hold:
# at cap 20, `tests/suites/dast-cors.sh` reached hub sum 18 and measured
# 22.86 GB peak RSS for ONE file, against the 16 GB an `ubuntu-latest`
# runner has in total. Re-measured on this tree after the back-edge cuts in
# the same change that lowered this cap (one `shellcheck -x` per file,
# /usr/bin/time -l, unconstrained):
#
#     tests/suites/dast-methods.sh    hub 17   5.75 GB
#     tests/suites/dast-cookies.sh    hub 16   5.44 GB
#     tests/suites/state-coverage.sh  hub 12   5.34 GB
#     scan.sh                         hub 12   4.41 GB
#     tests/suites/dast-hosthdr.sh    hub 13   4.07 GB
#     tests/suites/dast-cors.sh       hub 13   2.82 GB   (18 -> 13, 22.86 GB -> 2.82 GB)
#
# So 17 is the current worst and the cap is deliberately snug: the whole-tree
# stage now runs one `shellcheck` invocation per file on CI, which makes its
# peak the MAX over this column rather than the SUM over a batch, and this
# cap is what keeps that MAX inside a runner. A change that needs to exceed
# it is not blocked - it adds one `# shellcheck source=/dev/null` back-edge
# cut on an edge whose target the entry point already reaches another way,
# which is lossless (the target is still inlined once) and is the mechanism
# this whole lint exists to make cheap. Do not RAISE it without a fresh
# measurement showing the new worst file still fits a 16 GB runner.
#
# This is a guard rail that catches the SHAPE of the regression early, not a
# replacement for the shellcheck stage's own RSS watchdog - the report this
# lint implements found two cases (`b2` vs `b3`) with an identical hub
# multiset that still differed 3.6x in measured RSS, so hub sum is a strong
# predictor, not a perfect one.
#
# An optional ROOT argument points the lint at a different tree, mirroring
# tests/lint-aws-readonly.sh's SCAN_ROOT convention, so a self-test suite can
# prove both directions on a disposable fixture tree without mutating this
# repository.
#
# THE WALKER ITSELF LIVES IN tests/lib/hubsum.sh, sourced by relpath to
# SELF_ROOT (this file's own location) rather than SCAN_ROOT (the tree being
# analysed, which for a self-test fixture carries no tests/lib/ of its own).
# tests/run-tests.sh's `--shard` file-list planner sources the identical
# library, as a per-file COST PROXY rather than a cap - see that file's own
# `--shard` header for why this is the one signal it trusts.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shellcheck directive syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
SELF_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
SCAN_ROOT=$(cd -- "${1:-$SELF_ROOT}" && pwd -P)
# shellcheck source=tests/lib/hubsum.sh
source "$SELF_ROOT/tests/lib/hubsum.sh"
cd "$SCAN_ROOT"

CAP=17

mapfile -t ENTRY_POINTS < <(find . -name '*.sh' -not -path './.git/*' -type f | sed 's#^\./##' | LC_ALL=C sort)

printf '== source-graph hub fan-out (cap %d) ==\n' "$CAP"

FAILED=0
WORST_FILE='' WORST_SUM=-1
for entry in "${ENTRY_POINTS[@]}"; do
  sum=$(hubsum_for "$entry" "$SCAN_ROOT")
  if (( sum > WORST_SUM )); then
    WORST_SUM=$sum
    WORST_FILE=$entry
  fi
  if (( sum > CAP )); then
    FAILED=1
    printf '  FAIL  hub sum %3d > %d  %s\n' "$sum" "$CAP" "$entry" >&2
  fi
done

printf '\n'
if (( FAILED )); then
  printf 'lint-source-graph: FAILED (worst: hub sum %d, %s)\n' "$WORST_SUM" "$WORST_FILE"
  exit 1
fi
printf 'lint-source-graph: clean across %d files (worst: hub sum %d, %s)\n' "${#ENTRY_POINTS[@]}" "$WORST_SUM" "$WORST_FILE"
