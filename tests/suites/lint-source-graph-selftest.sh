#!/usr/bin/env bash
# tests/suites/lint-source-graph-selftest.sh - proves tests/lint-source-graph.sh
# both directions on a disposable fixture tree, never the real repository.
#
# Same shape as tests/suites/lint-no-ai-selftest.sh: plant the shape the lint
# claims to catch, assert failure, remove it, assert a pass. The fixture only
# needs a file named exactly one of the five hub basenames
# (lib/core.sh/records.sh/findings.sh/http.sh/config.sh) - the lint's HUBS
# list is a fixed path set, not a discovered one - so a trivial `lib/core.sh`
# stands in for the real hub chain.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shellcheck directive syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$SCOURSH_SCRATCH/lint-source-graph-fixture
rm -rf "$FIX"
mkdir -p "$FIX/lib"
printf '#!/usr/bin/env bash\n:\n' >"$FIX/lib/core.sh"

lint() { bash "$ROOT/tests/lint-source-graph.sh" "$FIX" >/dev/null 2>&1; }

# Writes N real `# shellcheck source=lib/core.sh` + `source` pairs into
# entry.sh, so its hub sum is exactly N.
_write_entry_with_n_real_edges() {
  local n=$1 i
  {
    printf '#!/usr/bin/env bash\n'
    for ((i = 0; i < n; i++)); do
      printf '# shellcheck source=lib/core.sh\nsource "$PWD/lib/core.sh"\n'
    done
  } >"$FIX/entry.sh"
}

t_case 'a single real edge to a hub is well under the cap and passes'
_write_entry_with_n_real_edges 1
assert_status 0 'hub sum 1 passes' lint

# THE CAP IS READ OUT OF THE LINT, NEVER RESTATED HERE.  This self-test used
# to hardcode 20 in four places, so lowering the real cap left it asserting a
# boundary the lint no longer had - two cases went red for the cap change
# itself rather than for any defect, which is a self-test that has to be
# edited every time the thing it guards is tuned.
CAP=$(sed -n 's/^CAP=\([0-9][0-9]*\)$/\1/p' "$ROOT/tests/lint-source-graph.sh")
[[ $CAP =~ ^[0-9]+$ ]] || die "$SCOURSH_EXIT_INPUT" \
  'could not read CAP out of tests/lint-source-graph.sh - this self-test asserts the boundary that file declares, and guessing it would test nothing'

t_case "exactly the cap ($CAP) still passes - the cap is a ceiling, not a floor"
_write_entry_with_n_real_edges "$CAP"
assert_status 0 "hub sum $CAP passes" lint

t_case "one past the cap ($((CAP + 1))) fails - the exact boundary the lint declares"
_write_entry_with_n_real_edges "$(( CAP + 1 ))"
assert_status 1 "hub sum $((CAP + 1)) is caught" lint
_write_entry_with_n_real_edges 1
assert_status 0 'restoring to hub sum 1 passes again' lint

t_case 'source=/dev/null is NOT a followed edge, however many times it repeats'
{
  printf '#!/usr/bin/env bash\n# shellcheck source=lib/core.sh\nsource "$PWD/lib/core.sh"\n'
  for _ in $(seq 1 30); do
    printf '# shellcheck source=/dev/null\nsource "$PWD/lib/core.sh"\n'
  done
} >"$FIX/entry.sh"
assert_status 0 '30 source=/dev/null repeats of a hub add nothing to its hub sum - this is the exact mechanism the 21 lossless repeat-cuts in the real fix rely on' lint

t_case 'the same hub reached through two different files is still counted twice'
mkdir -p "$FIX/a" "$FIX/b"
# The directive's target is root-relative, matching this repository's own
# convention (e.g. modules/dast/active/hosthdr_engine.sh:103's
# `# shellcheck source=lib/http.sh` from three directories down) and the
# lint's own resolution: SCAN_ROOT + target, never the sourcing file's own
# directory.
printf '#!/usr/bin/env bash\n# shellcheck source=lib/core.sh\nsource "$PWD/../lib/core.sh"\n' >"$FIX/a/one.sh"
printf '#!/usr/bin/env bash\n# shellcheck source=lib/core.sh\nsource "$PWD/../lib/core.sh"\n' >"$FIX/b/two.sh"
# Alternate between the two files so the total lands on ANY integer, not just
# an even one: a pair-at-a-time loop can never sit exactly on an odd cap, and
# "exactly the cap" is the boundary worth pinning.
_write_alternating() {
  local n=$1 i
  {
    printf '#!/usr/bin/env bash\n'
    for (( i = 0; i < n; i++ )); do
      if (( i % 2 == 0 )); then
        printf '# shellcheck source=a/one.sh\nsource "$PWD/a/one.sh"\n'
      else
        printf '# shellcheck source=b/two.sh\nsource "$PWD/b/two.sh"\n'
      fi
    done
  } >"$FIX/entry.sh"
}
# Each copy of one.sh or two.sh pulls lib/core.sh exactly once, so CAP copies
# spread across the two files sum to exactly CAP.
_write_alternating "$CAP"
assert_status 0 "two different files pulling the hub $CAP times between them sums to exactly $CAP and passes" lint
_write_alternating "$(( CAP + 1 ))"
assert_status 1 "one more copy tips the combined hub sum to $((CAP + 1)) and fails" lint
rm -rf "$FIX/a" "$FIX/b"

rm -rf "$FIX"
t_summary 'lint-source-graph self-test'
