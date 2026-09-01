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

t_case 'exactly the cap (20) still passes - the cap is a ceiling, not a floor'
_write_entry_with_n_real_edges 20
assert_status 0 'hub sum 20 passes' lint

t_case 'one past the cap (21) fails - the exact boundary the report measured'
_write_entry_with_n_real_edges 21
assert_status 1 'hub sum 21 is caught' lint
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
{
  printf '#!/usr/bin/env bash\n'
  for _ in $(seq 1 10); do
    printf '# shellcheck source=a/one.sh\nsource "$PWD/a/one.sh"\n'
    printf '# shellcheck source=b/two.sh\nsource "$PWD/b/two.sh"\n'
  done
} >"$FIX/entry.sh"
# 10 copies of one.sh + 10 copies of two.sh, each pulling lib/core.sh once = hub sum 20.
assert_status 0 'two files each pulling the hub 10 times sums to exactly 20 and passes' lint
{
  printf '#!/usr/bin/env bash\n'
  for _ in $(seq 1 11); do
    printf '# shellcheck source=a/one.sh\nsource "$PWD/a/one.sh"\n'
    printf '# shellcheck source=b/two.sh\nsource "$PWD/b/two.sh"\n'
  done
} >"$FIX/entry.sh"
assert_status 1 'one more pair of copies tips the combined hub sum to 22 and fails' lint
rm -rf "$FIX/a" "$FIX/b"

rm -rf "$FIX"
t_summary 'lint-source-graph self-test'
