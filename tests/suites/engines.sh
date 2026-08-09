#!/usr/bin/env bash
# tests/suites/engines.sh - lib/engines.sh: has_engine() and the
# docs/ADAPTERS.md §4 directory-convention detection layer (docs/DESIGN.md
# directory layout; docs/FOUNDATION.md tension 27; this ticket, the first
# concrete adapter ticket that builds this file for real).
#
# Deliberately does NOT depend on modules/sast/adapters/semgrep/ - every
# fixture here is a small, purpose-built fake adapter.sh under a scratch
# SCOURSH_INSTALL_ROOT, so this suite proves has_engine's OWN contract
# (docs/ADAPTERS.md §3/§5) independent of any one real engine.
# tests/suites/sast-semgrep.sh covers the semgrep adapter's own three
# functions and the modules/sast/run.sh wiring end to end.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/engines.sh
source "$ROOT/lib/engines.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/engines-suite
rm -rf "$W"
mkdir -p "$W"

_reset_memo() {
  # has_engine memoises by (module, engine) key (lib/engines.sh's own
  # header) - each t_case below wants a fresh probe, so the cache is reset
  # between cases rather than accumulating across an entire suite run.
  _ENGINES_DETECTED=()
}

# ---------------------------------------------------------------------------
# helpers: build a fake modules/<module>/adapters/<engine>/adapter.sh under
# a scratch root, declaring only <engine>_detect (the one function
# has_engine actually calls) - proof this suite works from docs/ADAPTERS.md
# §5's contract alone, not from anything semgrep-specific.
# ---------------------------------------------------------------------------
_make_fake_adapter() {
  local root=$1 module=$2 engine=$3 detect_body=$4
  local dir="$root/modules/$module/adapters/$engine"
  mkdir -p "$dir"
  cat >"$dir/adapter.sh" <<EOF
#!/usr/bin/env bash
${engine}_detect() {
  $detect_body
}
EOF
}

t_case 'engines_adapter_path prints the frozen docs/ADAPTERS.md §4 layout'
SCOURSH_INSTALL_ROOT=/fake/root
assert_eq '/fake/root/modules/sast/adapters/semgrep/adapter.sh' \
  "$(engines_adapter_path sast semgrep)" \
  'the path is $SCOURSH_INSTALL_ROOT/modules/MODULE/adapters/ENGINE/adapter.sh, exactly'
SCOURSH_INSTALL_ROOT=$ROOT

# =============================================================================
printf -- '\n-- no adapter.sh on disk at all: the "zero adapters present" default --\n'
# =============================================================================
_reset_memo
ROOT_EMPTY=$W/root-empty
mkdir -p "$ROOT_EMPTY/modules/sast"
t_case 'has_engine with no adapter.sh anywhere returns 1 (not vendored) - fails under "absent adapter is an error"'
rc=0
( SCOURSH_INSTALL_ROOT=$ROOT_EMPTY has_engine sast semgrep ) || rc=$?
assert_eq 1 "$rc" 'no modules/sast/adapters/semgrep/adapter.sh on disk: has_engine returns 1'

# =============================================================================
printf -- '\n-- adapter.sh present, <engine>_detect returns 0 (vendored) --\n'
# =============================================================================
_reset_memo
ROOT_VENDORED=$W/root-vendored
rm -rf "$ROOT_VENDORED"
_make_fake_adapter "$ROOT_VENDORED" sast fakeengine 'return 0'
t_case 'has_engine returns 0 when adapter.sh exists and <engine>_detect succeeds'
rc=0
( SCOURSH_INSTALL_ROOT=$ROOT_VENDORED has_engine sast fakeengine ) || rc=$?
assert_eq 0 "$rc" 'a present, self-reporting-vendored adapter: has_engine returns 0'

# =============================================================================
printf -- '\n-- adapter.sh present, <engine>_detect returns 1 (present but not vendored) --\n'
# =============================================================================
_reset_memo
ROOT_NOT_VENDORED=$W/root-not-vendored
rm -rf "$ROOT_NOT_VENDORED"
_make_fake_adapter "$ROOT_NOT_VENDORED" sast fakeengine 'return 1'
t_case 'has_engine returns 1 when adapter.sh exists but its own detect fails (e.g. bin/ empty) - collapses to the same caller-facing reason as "absent entirely", per docs/ADAPTERS.md §7'
rc=0
( SCOURSH_INSTALL_ROOT=$ROOT_NOT_VENDORED has_engine sast fakeengine ) || rc=$?
assert_eq 1 "$rc" 'a present-but-not-vendored adapter: has_engine still returns 1'

# =============================================================================
printf -- '\n-- --use-engines is NOT read here: has_engine answers a pure filesystem question --\n'
# =============================================================================
_reset_memo
t_case 'has_engine ignores SCAN_FLAGS entirely - fails under a reading that folds the --use-engines gate into this function'
# SC2034: SCAN_FLAGS is deliberately declared and never read by has_engine -
# that is exactly the property this case proves (lib/engines.sh's own
# header: has_engine never consults --use-engines itself).
# shellcheck disable=SC2034
declare -gA SCAN_FLAGS=([use-engines]=false)
rc=0
( SCOURSH_INSTALL_ROOT=$ROOT_VENDORED has_engine sast fakeengine ) || rc=$?
assert_eq 0 "$rc" \
  'with SCAN_FLAGS[use-engines]=false, has_engine STILL returns 0 for a genuinely vendored adapter - the flag gate lives at the call site (modules/sast/run.sh), never inside has_engine itself'
unset SCAN_FLAGS

# =============================================================================
printf -- '\n-- memoisation: <engine>_detect is not re-run once cached --\n'
# =============================================================================
_reset_memo
ROOT_COUNTING=$W/root-counting
rm -rf "$ROOT_COUNTING"
COUNTER_FILE=$W/detect-calls
: >"$COUNTER_FILE"
_make_fake_adapter "$ROOT_COUNTING" sast countingengine \
  "printf 'x' >>'$COUNTER_FILE'; return 0"
t_case 'has_engine memoises per (module, engine): a second call in the same process does not re-run <engine>_detect'
(
  SCOURSH_INSTALL_ROOT=$ROOT_COUNTING
  export SCOURSH_INSTALL_ROOT
  has_engine sast countingengine >/dev/null
  has_engine sast countingengine >/dev/null
  has_engine sast countingengine >/dev/null
)
assert_eq x "$(cat "$COUNTER_FILE")" \
  'the counter file holds exactly one "x" - detect ran once across three has_engine calls, fails under "re-probes every call"'

# =============================================================================
printf -- '\n-- two different (module, engine) pairs never collide in the memo cache --\n'
# =============================================================================
_reset_memo
ROOT_TWO=$W/root-two
rm -rf "$ROOT_TWO"
_make_fake_adapter "$ROOT_TWO" sast engine-a 'return 0'
_make_fake_adapter "$ROOT_TWO" sast engine-b 'return 1'
t_case 'has_engine sast engine-a and has_engine sast engine-b are independent - fails under a memo key collision'
rc_a=0 rc_b=0
( SCOURSH_INSTALL_ROOT=$ROOT_TWO has_engine sast engine-a ) || rc_a=$?
( SCOURSH_INSTALL_ROOT=$ROOT_TWO has_engine sast engine-b ) || rc_b=$?
assert_eq 0 "$rc_a" 'engine-a (vendored) is 0'
assert_eq 1 "$rc_b" 'engine-b (not vendored) is 1, independent of engine-a'

t_summary engines
