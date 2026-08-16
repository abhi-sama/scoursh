#!/usr/bin/env bash
# tests/suites/color.sh - lib/core.sh's colour precedence: SCOURSH_COLOR and
# NO_COLOR (https://no-color.org).
#
# The bug this pins is the non-TTY path: SCOURSH_COLOR=always must colour even
# when stderr is not a terminal, and the auto/unset case must stay uncoloured
# there regardless of NO_COLOR (there is nothing to strip). A test that only
# ever runs with stderr as a TTY cannot tell "always ignores TTY" from
# "auto happens to be on a TTY", so every case below is run BOTH with stderr
# redirected to a real file (definitely not a TTY - the case that matters
# most, since it is what "never colours" and "always colours" have to prove)
# and, where a real TTY is available, with is_tty stubbed to simulate one
# deterministically (real ttys are not guaranteed present in a CI sandbox).
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/color
mkdir -p "$W"

ESC=$'\033'

# Runs `_want_color` with the given env in a subshell so SCOURSH_COLOR/NO_COLOR
# never leak between cases, and reports its exit status (0 = colours).
_want_color_with() {
  local scourh_color=$1 no_color=$2 tty_sim=$3
  (
    if [[ -n $scourh_color ]]; then SCOURSH_COLOR=$scourh_color; else unset SCOURSH_COLOR; fi
    if [[ -n $no_color ]]; then NO_COLOR=$no_color; else unset NO_COLOR; fi
    if [[ $tty_sim == tty ]]; then
      is_tty() { return 0; }
    else
      is_tty() { return 1; }
    fi
    _want_color
  )
}

# ---------------------------------------------------------------------------
printf '\n-- stderr simulated as a TTY (is_tty stubbed true) --\n'
# ---------------------------------------------------------------------------
t_case 'tty: unset SCOURSH_COLOR, no NO_COLOR -> colour (auto, tty, no NO_COLOR)'
assert_status 0 'colours' _want_color_with '' '' tty

t_case 'tty: SCOURSH_COLOR=never -> never colour, even on a tty'
assert_status 1 'no colour' _want_color_with never '' tty

t_case 'tty: SCOURSH_COLOR=always -> colour'
assert_status 0 'colours' _want_color_with always '' tty

t_case 'tty: unset SCOURSH_COLOR, NO_COLOR=1 -> no colour (auto respects NO_COLOR)'
assert_status 1 'no colour' _want_color_with '' 1 tty

t_case 'tty: SCOURSH_COLOR=always AND NO_COLOR=1 -> colour wins (explicit flag beats NO_COLOR)'
assert_status 0 'colours' _want_color_with always 1 tty

t_case 'tty: SCOURSH_COLOR=never AND NO_COLOR=1 -> no colour either way'
assert_status 1 'no colour' _want_color_with never 1 tty

# ---------------------------------------------------------------------------
printf '\n-- stderr simulated as NOT a TTY (is_tty stubbed false) -- the bug this fixes --\n'
# ---------------------------------------------------------------------------
t_case 'non-tty: unset SCOURSH_COLOR -> no colour (auto never colours off a tty)'
assert_status 1 'no colour' _want_color_with '' '' notty

t_case 'non-tty: SCOURSH_COLOR=never -> no colour'
assert_status 1 'no colour' _want_color_with never '' notty

t_case 'non-tty: SCOURSH_COLOR=always -> COLOURS ANYWAY (this is the fix: forcing colour into a pipe)'
assert_status 0 'colours' _want_color_with always '' notty

t_case 'non-tty: SCOURSH_COLOR=always AND NO_COLOR=1 -> colour still wins'
assert_status 0 'colours' _want_color_with always 1 notty

t_case 'non-tty: unset SCOURSH_COLOR, NO_COLOR=1 -> no colour (already off; NO_COLOR changes nothing here)'
assert_status 1 'no colour' _want_color_with '' 1 notty

# ---------------------------------------------------------------------------
printf '\n-- end-to-end through _log, stderr redirected to a REAL FILE (genuinely not a tty) --\n'
# ---------------------------------------------------------------------------
# Redirecting to a regular file is not simulated: `[[ -t 2 ]]` is really false
# here, on both BSD and GNU userlands, with no stub involved.
t_case 'log line with SCOURSH_COLOR unset, stderr piped to a file: no escape codes'
out=$W/plain.log
( unset SCOURSH_COLOR NO_COLOR; log_info hello ) 2>"$out"
line=$(cat "$out")
assert_not_contains "$line" "$ESC" 'plain log line to a non-tty carries no ESC byte'
assert_contains "$line" hello 'the message itself still made it through'

t_case 'log line with SCOURSH_COLOR=always, stderr piped to a file: escape codes ARE present'
out=$W/forced.log
( unset NO_COLOR; SCOURSH_COLOR=always; log_info hello ) 2>"$out"
line=$(cat "$out")
assert_contains "$line" "$ESC" 'SCOURSH_COLOR=always colours a genuinely non-tty stderr'
assert_contains "$line" hello 'the message itself still made it through'

t_case 'log line with SCOURSH_COLOR=never, stderr piped to a file: still no escape codes'
out=$W/never.log
( SCOURSH_COLOR=never; log_info hello ) 2>"$out"
line=$(cat "$out")
assert_not_contains "$line" "$ESC" 'SCOURSH_COLOR=never never colours'

t_case 'log line with NO_COLOR=1 and SCOURSH_COLOR=always, stderr piped to a file: colour still wins'
out=$W/no_color_vs_always.log
( SCOURSH_COLOR=always; NO_COLOR=1; log_info hello ) 2>"$out"
line=$(cat "$out")
assert_contains "$line" "$ESC" 'the explicit SCOURSH_COLOR=always overrides NO_COLOR, as documented'

t_summary color
