#!/usr/bin/env bash
# tests/suites/vendor-engines.sh - tools/vendor-engines.sh, the sole
# network-permitted, quarantined script (docs/FOUNDATION.md tension 27;
# docs/ADAPTERS.md).
#
# What this suite proves, and what it honestly cannot:
#
#  - Usage/help, the registry-listing path, the unknown-engine error path,
#    the no-args usage error, and the exit-code contract (0/2/4, never
#    outside 0-5) are all exercised as REAL subprocess invocations of the
#    actual script (`bash "$TOOL" ...`), not by sourcing and stubbing -
#    there is nothing to stub: the registry is genuinely empty (this
#    ticket's own AC1), so every path this suite can exercise is the real
#    path a networked-box operator would hit today.
#  - It does NOT, and cannot, test a real engine vendoring flow (a real
#    fetch, verify, and populate of modules/<module>/adapters/<engine>/),
#    because zero engines are registered - there is nothing to vendor yet.
#    docs/ADAPTERS.md §1 states this is the correct state for this ticket;
#    the first concrete adapter ticket adds both the registry entry and the
#    fixture that proves ITS fetch path, using a stubbed `curl` the same way
#    tests/suites/http.sh already stubs the network for lib/http.sh.
#  - It asserts this script makes NO real network call in any path this
#    suite exercises, by running with PATH stripped of curl/wget entirely
#    (section B) - if any code path here tried to fetch something, the
#    subprocess would fail with "command not found", not silently succeed.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=tools/vendor-engines.sh
source "$ROOT/tools/vendor-engines.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

TOOL=$ROOT/tools/vendor-engines.sh
W=$SCOURSH_SCRATCH/vendor-engines

mkdir -p "$W"

# ---------------------------------------------------------------------------
# -- section A: in-process function tests (pure logic, nothing that exits) --
# ---------------------------------------------------------------------------
t_case 'registry'
assert_eq 0 "${#VENG_REGISTRY[@]}" \
  'the engine registry is empty - fails under the reading that this ticket ships a real adapter'

t_case 'veng_list, empty registry'
out=$(veng_list)
assert_contains "$out" 'no engine adapters registered' \
  'listing an empty registry says so in plain language rather than printing nothing'
rc=0
veng_list >/dev/null || rc=$?
assert_eq 0 "$rc" 'listing an empty registry is success, not an error - zero adapters is the expected state'

t_case 'veng_vendor_all, empty registry'
rc=0
veng_vendor_all >"$W/all.out" 2>&1 || rc=$?
assert_eq 0 "$rc" '--all with nothing registered is a documented no-op, not a failure'
assert_contains "$(cat "$W/all.out")" 'nothing to vendor' \
  'the no-op says explicitly that nothing was vendored, rather than exiting silently'

# ---------------------------------------------------------------------------
# -- section B: real subprocess invocations of the actual script, with
#    PATH stripped of curl/wget so any accidental fetch attempt fails
#    loudly (command not found) rather than silently reaching the network --
# ---------------------------------------------------------------------------
NO_NET_PATH=$W/no-curl-path
mkdir -p "$NO_NET_PATH"
for tool in bash cat sort mkdir dirname pwd printf true false grep sed date; do
  src=$(command -v "$tool" 2>/dev/null) || continue
  ln -sf "$src" "$NO_NET_PATH/$tool"
done

t_case 'usage/help'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --help 2>&1) || rc=$?
assert_eq 0 "$rc" '--help exits 0'
assert_contains "$out" 'usage: tools/vendor-engines.sh' \
  '--help prints the usage banner'
assert_contains "$out" 'never invoked by scan.sh' \
  '--help states the never-wired-into-a-scan contract, not just how to run it'

t_case 'no args'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" 2>&1) || rc=$?
assert_eq 2 "$rc" \
  'no command given is a usage error (exit 2), matching scan.sh'"'"'s own convention - fails under the reading that missing args silently no-op'

t_case 'unknown flag'
rc=0
PATH=$NO_NET_PATH bash "$TOOL" --bogus >/dev/null 2>&1 || rc=$?
assert_eq 2 "$rc" 'an unrecognised flag is a usage error (exit 2)'

t_case '--list, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --list 2>&1) || rc=$?
assert_eq 0 "$rc" '--list exits 0 with nothing registered'
assert_contains "$out" 'no engine adapters registered' \
  '--list reports the empty registry in plain language'

t_case 'unregistered engine name'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" semgrep 2>&1) || rc=$?
assert_eq 4 "$rc" \
  'vendoring an unregistered engine is exit 4 (SCOURSH_EXIT_INPUT) - fails under the reading that an unknown name is a usage error (2) or silently succeeds (0)'
assert_contains "$out" "unknown engine 'semgrep'" \
  'the error names the actual engine that was requested'
assert_contains "$out" 'docs/ADAPTERS.md' \
  'the error points at the convention document, not just "no"'

t_case '--all, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --all 2>&1) || rc=$?
assert_eq 0 "$rc" '--all with nothing registered exits 0 as a real subprocess too'
assert_contains "$out" 'nothing to vendor' \
  '--all as a real subprocess states the no-op explicitly'

t_case 'exit codes never leave 0-5 (tension 14, finding F16)'
for args in '' '--help' '--list' '--all' '--bogus' 'semgrep'; do
  rc=0
  # shellcheck disable=SC2086
  PATH=$NO_NET_PATH bash "$TOOL" $args >/dev/null 2>&1 || rc=$?
  if (( rc >= 0 && rc <= 5 )); then
    _t_ok "exit code for '$args' is $rc, within 0-5"
  else
    _t_no "exit code for '$args' is $rc, OUTSIDE 0-5" "args: [$args]"
  fi
done

# ---------------------------------------------------------------------------
# -- section C: the dual-mode source guard - sourcing this file (as section
#    A already did, above) must not run veng_main or exit the sourcing
#    shell.  If it did, this suite would never have reached this line.
# ---------------------------------------------------------------------------
t_case 'dual-mode source guard'
assert_eq 0 "$VENG_MAIN" \
  'sourcing tools/vendor-engines.sh sets VENG_MAIN=0 and does not run veng_main - fails under the reading that sourcing it also executes the CLI dispatch'

t_summary 'vendor-engines'
