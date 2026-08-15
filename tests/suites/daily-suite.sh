#!/usr/bin/env bash
# tests/suites/daily-suite.sh - tools/daily-suite.sh, the local once-daily suite
# runner that replaced this project's hosted CI (docs/CI-RUNBOOK.md).
#
# WHAT THIS SUITE IS FOR.  With GitHub Actions switched off there is no red tick
# on a pull request any more, so two properties of the runner carry the whole
# weight that CI used to:
#
#   1. It refuses to produce a result at all unless the userland it measured is
#      genuinely BSD.  On this class of machine an interactive PATH resolves
#      `grep` to ugrep and `find` to bfs; a run under those would go GREEN while
#      testing tools scoursh does not ship on, which is worse than no run.
#   2. A missing, stale, or unfinished result never reads as a pass.  A daily
#      job that silently stopped firing must look different from one that fired
#      and passed, or the whole arrangement is decoration.
#
# Both are asserted here against the REAL script as a real subprocess, and both
# are asserted in the direction that fails: section B shadows the system grep
# and requires the abort, section C fabricates every shape of stale/absent
# result and requires a non-zero verdict.  A guard nobody has watched fail is
# not known to work.
#
# WHAT THIS SUITE DELIBERATELY DOES NOT DO: run tools/daily-suite.sh with no
# arguments.  That would run the entire test suite - this file included -
# recursively, take many minutes, and start a docker build.  Every case below
# uses one of the four non-running modes (--check-userland, --status,
# --print-launchd, --help) or an argument error.
#
# HOST DEPENDENCE, stated rather than assumed.  Sections A and B are macOS
# assertions, because "the userland is BSD" is only a meaningful claim on
# Darwin.  On Linux - which is exactly where this suite runs when the daily
# runner's own GNU leg executes it inside the container - section A instead
# asserts the script REFUSES, which is the correct behaviour there, and section
# B is reported SKIPPED rather than silently passing.  Sections C, D, E and F are
# host-independent and run everywhere.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

TOOL=$ROOT/tools/daily-suite.sh
W=$SCOURSH_SCRATCH/daily-suite
mkdir -p "$W"
HOST=$(uname -s)

# Runs the tool as a real subprocess, capturing combined output and status.
# SCOURSH_DAILY_DIR is neutralised so a case that forgets --results-dir can
# never touch the operator's real result directory.
run_tool() {
  RT_OUT=''
  RT_RC=0
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used bash "$TOOL" "$@" 2>&1) || RT_RC=$?
}

printf -- '-- section A: the userland assertion, on this host --\n'

if [[ $HOST == Darwin ]]; then
  t_case '--check-userland accepts a genuine BSD userland'
  run_tool --check-userland
  assert_eq 0 "$RT_RC" \
    '--check-userland exits 0 on a machine whose pinned system path really does hold BSD tools'
  assert_contains "$RT_OUT" 'BSD grep' \
    'and reports the BSD grep it measured, so the result names the userland it was produced on'
  assert_contains "$RT_OUT" '/usr/bin/grep' \
    'and names the resolved binary, not just the version string'

  t_case 'pinning the system path does not also pin the system bash 3.2'
  # Measured on the first real end-to-end run: pinning /usr/bin ahead of PATH
  # (which is what defeats the ugrep/bfs shadow) also puts /bin/bash 3.2.57
  # ahead of the modern bash, and tests/run-tests.sh launches every suite and
  # linter as a bare `bash "$path"` - so all 35 of them died with "bash >= 4.2
  # required" while the runner itself was perfectly healthy.
  run_tool --check-userland
  ds_path_bash_line=''
  while IFS= read -r _l; do
    case $_l in *'bash on PATH :'*) ds_path_bash_line=$_l ;; esac
  done <<<"$RT_OUT"
  assert_ne '' "$ds_path_bash_line" \
    'the userland report states which bash a bare `bash` lands on, since that is the one every spawned suite gets'
  ds_path_bash_ver=${ds_path_bash_line##* }
  ds_path_bash_maj=${ds_path_bash_ver%%.*}
  assert_true "$(( ds_path_bash_maj >= 4 ? 0 : 1 ))" \
    "a bare \`bash\` resolves to $ds_path_bash_ver, at or above the frozen 4.2 major - FAILS under the reading 'pin the system path and stop', which hands every spawned suite bash 3.2.57"
  assert_contains "$RT_OUT" '/usr/bin/grep' \
    'and grep still comes from the system path, so the bash shim did not hand the grep shadow its win back'

  t_case 'a nested invocation sharing the scratch directory does not break the outer shim'
  # Also measured on a real end-to-end run, and the reason THIS suite is where
  # it bit: lib/core.sh exports SCOURSH_SCRATCH so `xargs -P` workers share the
  # parent's directory, so a daily-suite.sh started from inside another one gets
  # the same scratch directory - and its own $BASH IS the outer run's shim.  A
  # single fixed shim path plus an underefenced link target made the outer shim
  # point at itself; every suite and linter spawned after this one died with
  # "Too many levels of symbolic links", from a run that had been green until
  # the last suite ran.
  SHARED=$W/shared-scratch
  rm -rf "$SHARED"
  mkdir -p "$SHARED"
  RT_RC=0
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_SCRATCH=$SHARED \
    bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  assert_eq 0 "$RT_RC" 'the outer invocation succeeds and leaves a shim behind'

  # The shim the first invocation built, found without assuming its name.
  OUTER_SHIM=''
  # Globbed loosely on purpose: the shim directory's name is not what this
  # case is about, so a naming change must not be what makes it fail.
  for _d in "$SHARED"/bash-shim*; do
    if [[ -x $_d/bash ]]; then OUTER_SHIM=$_d; fi
  done
  assert_ne '' "$OUTER_SHIM" 'a usable bash shim exists in the shared scratch directory'

  # The nested case, reproduced exactly: invoked THROUGH the outer shim (so the
  # child's $BASH is that symlink) and sharing the same scratch directory.
  RT_RC=0
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_SCRATCH=$SHARED \
    "$OUTER_SHIM/bash" "$TOOL" --check-userland 2>&1) || RT_RC=$?
  assert_eq 0 "$RT_RC" \
    'the nested invocation succeeds - FAILS under a single fixed shim path, where it overwrites the outer shim with a link to itself'

  RT_RC=0
  RT_OUT=$("$OUTER_SHIM/bash" -c 'printf %s "$BASH_VERSION"' 2>&1) || RT_RC=$?
  assert_eq 0 "$RT_RC" \
    "the OUTER shim still runs after the nested invocation - FAILS with 'Too many levels of symbolic links' under an underefenced link target ($RT_OUT)"
else
  t_case '--check-userland refuses to certify a non-Darwin host'
  run_tool --check-userland
  assert_eq 4 "$RT_RC" \
    'on a non-Darwin host the BSD leg cannot mean anything, so the tool exits 4 rather than reporting a userland'
  assert_contains "$RT_OUT" 'uname -s' \
    'and says which host it found - FAILS under the reading that a Linux host may run the BSD leg'
fi

printf -- '\n-- section B: the guard bites (the trap this tool exists to avoid) --\n'

if [[ $HOST == Darwin ]]; then
  # SCOURSH_SYSTEM_PATH is the tool's own operator knob for "where the system
  # userland lives", and it is the honest injection point for this test: what
  # is being simulated is not "someone put a directory on PATH" (the tool pins
  # the system path ahead of PATH precisely to defeat that) but the residual
  # risk the pin cannot cover - the pinned directories no longer holding the
  # BSD tools they are supposed to hold.
  FAKE_FULL=$W/fake-full
  FAKE_PARTIAL=$W/fake-partial
  rm -rf "$FAKE_FULL" "$FAKE_PARTIAL"
  mkdir -p "$FAKE_FULL" "$FAKE_PARTIAL"
  cat >"$FAKE_FULL/grep" <<'FAKEGREP'
#!/bin/sh
# A shadow that answers --version as GNU grep but forwards everything else, so
# only the VERSION assertion can catch it.
if [ "${1:-}" = --version ]; then echo "grep (GNU grep) 3.11"; exit 0; fi
exec /usr/bin/grep "$@"
FAKEGREP
  chmod +x "$FAKE_FULL/grep"
  for _t in find sed awk; do ln -sf "/usr/bin/$_t" "$FAKE_FULL/$_t"; done
  cp "$FAKE_FULL/grep" "$FAKE_PARTIAL/grep"
  chmod +x "$FAKE_PARTIAL/grep"

  t_case 'a GNU grep sitting where the system grep should be aborts the run'
  RT_RC=0
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_SYSTEM_PATH=$FAKE_FULL \
    bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  # Fails under the reading "the resolved path is enough": this grep IS in the
  # pinned system path and IS the first grep found, so a path-only check passes
  # it and the run would proceed against GNU tools.
  assert_eq 4 "$RT_RC" \
    'the tool exits 4 rather than measuring a GNU userland - FAILS if the version string is not checked'
  assert_contains "$RT_OUT" 'GNU grep' \
    'and the message names what it actually found, so the operator can fix it'
  assert_not_contains "$RT_OUT" 'uname   :' \
    'and it aborts BEFORE printing a userland report, so no green-looking output exists for a bad userland'

  t_case 'a pinned system path that no longer provides the other tools aborts the run'
  RT_RC=0
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_SYSTEM_PATH=$FAKE_PARTIAL \
    bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  # Fails under the reading "checking grep is enough": find and sed differ
  # between the userlands too (bfs is the drop-in that has actually turned up
  # here), so each core tool has to come from the pinned path.
  assert_eq 4 "$RT_RC" \
    'a system path that supplies grep but not find/sed/awk is rejected - FAILS if only grep is checked'
  assert_contains "$RT_OUT" 'outside the pinned system path' \
    'and the message says which tool escaped the pin'

  t_case 'the pin defeats a shadowing tool that is merely early on PATH'
  RT_RC=0
  # The same fake grep, but reachable only through PATH rather than through the
  # pinned system path.  This must PASS: pinning the system path ahead of PATH
  # is the mechanism, and a test that could not tell the mechanism working from
  # the mechanism absent would pin nothing.
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used PATH="$FAKE_FULL:$PATH" \
    bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  assert_eq 0 "$RT_RC" \
    'a ugrep-shaped shadow earlier on PATH is overridden by the system-path pin, so the run proceeds on BSD tools'
  assert_contains "$RT_OUT" '/usr/bin/grep' \
    'and the grep actually used is the system one'
else
  printf '  -- SKIPPED on %s: "the userland is BSD" is a Darwin-only claim, and\n' "$HOST"
  printf '     shadowing the system grep here would pin nothing.  Section A above\n'
  printf '     asserts the correct behaviour for this host instead. --\n'
fi

printf -- '\n-- section C: a missing, stale or unfinished result never reads as a pass --\n'

# Writes a STATUS line of the given verdict, finished the given number of hours
# ago.  Mirrors ds_status_write's format exactly; if that format changes, these
# cases stop being about the real file, which is why the schema field is pinned.
fake_status() {
  local dir=$1 verdict=$2 hours_ago=$3 now
  mkdir -p "$dir/runs/x"
  now=$(date '+%s')
  printf 'schema=1 verdict=%s started=T started_epoch=%s finished=T finished_epoch=%s bsd=%s gnu=%s compare=%s run=%s\n' \
    "$verdict" "$(( now - hours_ago * 3600 ))" "$(( now - hours_ago * 3600 ))" \
    "$verdict" "$verdict" "$verdict" "$dir/runs/x" >"$dir/STATUS"
}

t_case 'a results directory that has never been written reports NEVER RUN, not a pass'
run_tool --results-dir "$W/absent" --status
# Fails under the reading "no news is good news", which is what a status command
# that exited 0 on a missing file would mean: a launchd agent that was never
# loaded would then look identical to one passing every day.
assert_eq 5 "$RT_RC" \
  'an absent result exits 5 (incomplete), never 0'
assert_contains "$RT_OUT" 'NEVER RUN' \
  'and says so in words, so the operator is told the schedule may not be installed'

t_case 'an unfinished run reports DID NOT FINISH, not the previous verdict'
mkdir -p "$W/incomplete"
printf 'schema=1 verdict=INCOMPLETE started=T started_epoch=1 finished= finished_epoch=0 bsd=INTERRUPTED gnu=PENDING compare=PENDING run=%s\n' \
  "$W/incomplete/runs/x" >"$W/incomplete/STATUS"
run_tool --results-dir "$W/incomplete" --status
assert_eq 5 "$RT_RC" \
  'a run killed part-way exits 5 - FAILS if the runner only ever writes a verdict on success, leaving the last PASS in place'
assert_contains "$RT_OUT" 'DID NOT FINISH' 'and names the outcome'

t_case 'a PASS older than the staleness threshold is STALE, not a pass'
fake_status "$W/stale" PASS 100
run_tool --results-dir "$W/stale" --status
# Fails under the reading "the last verdict is the answer": a cron job that
# stopped firing three weeks ago leaves a genuine PASS behind, and reporting it
# as a pass is exactly the silent absence this must never do.
assert_eq 5 "$RT_RC" \
  'a 100-hour-old PASS exits 5 against the 36-hour default threshold'
assert_contains "$RT_OUT" 'STALE' 'and is labelled STALE'
# A reported outcome is not an internal error.  Letting the non-zero return
# reach lib/core.sh's ERR trap printed "error scoursh: command failed (status 5)
# at ...daily-suite.sh:NNN" underneath the report, which reads as "the tool
# broke" rather than as the answer it is - and with no PR check to fall back on,
# an operator who mistrusts this output has nothing else.
assert_not_contains "$RT_OUT" 'command failed' \
  'and the report is not followed by an ERR-trap diagnostic - FAILS if the exit status is allowed to reach lib/core.sh ERR trap'
assert_contains "$RT_OUT" 'NOT a pass' \
  'and says in words that an old PASS is not a pass'

t_case 'the staleness threshold is configurable and is what decides'
run_tool --results-dir "$W/stale" --max-age-hours 200 --status
assert_eq 0 "$RT_RC" \
  'the same 100-hour-old PASS is fresh against a 200-hour threshold, so the threshold is really what decided the previous case'

t_case 'a fresh PASS is the only shape that exits 0'
fake_status "$W/pass" PASS 1
run_tool --results-dir "$W/pass" --status
assert_eq 0 "$RT_RC" 'a one-hour-old PASS exits 0'
assert_contains "$RT_OUT" 'PASS' 'and reports PASS'

t_case 'a fresh FAIL exits 1'
fake_status "$W/fail" FAIL 1
run_tool --results-dir "$W/fail" --status
assert_eq 1 "$RT_RC" 'a failed run exits 1 (the gate code), distinct from 5 (did not run)'

t_case 'a partial run exits 5, because a skipped leg is not a pass'
fake_status "$W/partial" PASS-PARTIAL 1
run_tool --results-dir "$W/partial" --status
# Fails under the reading "the BSD leg passed, so the run passed": tension 24's
# guarantee is about the two userlands AGREEING, and a run with only one leg has
# not checked it.
assert_eq 5 "$RT_RC" \
  'PASS-PARTIAL exits 5, so a run whose GNU leg was skipped cannot be mistaken for a full pass'

t_case 'a STATUS file this version cannot read is not a pass either'
mkdir -p "$W/garbage"
printf 'this is not a status line\n' >"$W/garbage/STATUS"
run_tool --results-dir "$W/garbage" --status
assert_eq 5 "$RT_RC" \
  'an unparseable result exits 5 - FAILS under a parser that defaults an unknown verdict to success'

printf -- '\n-- section D: the launchd agent it ships --\n'

t_case '--print-launchd emits a plist for THIS checkout'
run_tool --print-launchd
assert_eq 0 "$RT_RC" '--print-launchd succeeds'
assert_contains "$RT_OUT" 'sh.scoursh.daily-suite' 'and carries the agent label'
assert_contains "$RT_OUT" "$ROOT/tools/daily-suite.sh" \
  'and points at this checkout, resolved at generation time - which is why the plist is generated rather than committed (docs/DESIGN.md §1: no machine path in a shipped file)'
assert_contains "$RT_OUT" '<key>RunAtLoad</key>' 'and pins RunAtLoad explicitly'
assert_contains "$RT_OUT" '<false/>' \
  'to false, so installing the agent does not immediately start a full suite run'
assert_contains "$RT_OUT" '<key>StartCalendarInterval</key>' 'and schedules on a calendar interval'

t_case '--hour and --minute choose the slot'
run_tool --print-launchd --hour 4 --minute 7
assert_contains "$RT_OUT" '<key>Hour</key><integer>4</integer>' 'the hour is what was asked for'
assert_contains "$RT_OUT" '<key>Minute</key><integer>7</integer>' 'and so is the minute'

t_case 'an out-of-range slot is a usage error, not a silently clamped one'
run_tool --print-launchd --hour 25
assert_eq 2 "$RT_RC" '--hour 25 exits 2 rather than emitting a plist launchd would reject at load time'

if command -v plutil >/dev/null 2>&1; then
  t_case 'the emitted plist is well-formed by the system parser'
  run_tool --print-launchd
  printf '%s\n' "$RT_OUT" >"$W/agent.plist"
  rc=0
  plutil -lint "$W/agent.plist" >/dev/null 2>&1 || rc=$?
  assert_eq 0 "$rc" \
    'plutil -lint accepts it - the assertions above are about content, this is about the XML actually parsing'
else
  printf '  -- plutil absent on this host: the plist XML is asserted by content only --\n'
fi

printf -- '\n-- section E: the bash floor, and argument handling --\n'

t_case 'an unrecognised argument is a usage error'
run_tool --check-userland --wat
assert_eq 2 "$RT_RC" \
  'an unknown flag exits 2 rather than being ignored, so a typo in the LaunchAgent plist is loud'

t_case 'SCOURSH_BASH pointing at bash 3.2 is refused with a message naming 4.2'
RT_RC=0
# /bin/bash on macOS is 3.2.57.  On a Linux host /bin/bash is modern, so this
# case only means something where a sub-4.2 bash actually exists.
if [[ $HOST == Darwin ]]; then
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_BASH=/bin/bash \
    bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  assert_eq 4 "$RT_RC" \
    'the runner refuses to run the suite under bash 3.2 - FAILS under the reading "whatever bash is on PATH will do", which produces a scatter of syntax errors instead of one clear message'
  assert_contains "$RT_OUT" '4.2' 'and the message names the frozen minimum'
else
  printf '  -- SKIPPED on %s: /bin/bash here is already >= 4.2, so there is no sub-4.2 bash to refuse --\n' "$HOST"
fi

if [[ $HOST == Darwin ]]; then
  t_case 'invoking through the system bash 3.2 still works, which is what launchd does'
  RT_RC=0
  # launchd runs the agent with a minimal PATH, so `#!/usr/bin/env bash` lands
  # on /bin/bash (3.2).  This asserts the re-exec preamble carries it through.
  RT_OUT=$(SCOURSH_DAILY_DIR=$W/never-used SCOURSH_BASH=$BASH \
    /bin/bash "$TOOL" --check-userland 2>&1) || RT_RC=$?
  assert_eq 0 "$RT_RC" \
    'started under bash 3.2, the tool still completes - it re-execs itself into a modern bash rather than failing obscurely'
fi

t_case '--gnu only accepts the three documented modes'
run_tool --gnu sometimes
assert_eq 2 "$RT_RC" 'an unknown --gnu mode exits 2 rather than falling through to a default'

t_case '--help is not an error'
run_tool --help
assert_eq 0 "$RT_RC" '--help exits 0'
assert_contains "$RT_OUT" '--check-userland' 'and documents the userland assertion'
assert_contains "$RT_OUT" 'docs/FOUNDATION.md tension 14' 'and states the exit-code contract it honours'

printf -- '\n-- section F: the suite is handed a clean environment, not this runner'"'"'s --\n'

t_case 'a suite launched by the runner owns its own scratch directory'
# Measured on a real end-to-end run: `core` failed exactly one assertion, "the
# creating process IS the owner", with nothing wrong in lib/core.sh at all.
# tools/daily-suite.sh sources lib/core.sh (for `die` and the exit-code
# constants), lib/core.sh EXPORTS SCOURSH_SCRATCH so `xargs -P` workers share
# the parent's directory, and a suite that inherits it did not create it - so
# scratch_is_owned_here is false inside it, which is the opposite of what a
# person running tests/run-tests.sh by hand gets.
cat >"$W/own-probe.sh" <<PROBE
source "$ROOT/lib/core.sh"
if scratch_is_owned_here; then printf OWNED; else printf NOT-OWNED; fi
PROBE

# The probe is invoked through an explicit modern bash, not a bare `bash`:
# sourcing the tool pins the system path (so a bare `bash` would be macOS's
# 3.2.57) without installing the shim that a real run adds.  This case is about
# the ENVIRONMENT, so it must not turn into a case about PATH.
RT_OUT=$(bash -c "source '$TOOL' >/dev/null 2>&1; ds_run_clean_env '$BASH' '$W/own-probe.sh'" 2>&1)
assert_eq 'OWNED' "$RT_OUT" \
  'a child launched through ds_run_clean_env creates and owns its own scratch directory, exactly as a hand-run suite does'

# The same probe WITHOUT the clean environment, so this case can tell the
# mechanism working from the mechanism absent rather than only asserting the
# happy path.
RT_OUT=$(bash -c "source '$TOOL' >/dev/null 2>&1; '$BASH' '$W/own-probe.sh'" 2>&1)
assert_eq 'NOT-OWNED' "$RT_OUT" \
  'and a child launched WITHOUT it inherits the runner - which is the state that made tests/suites/core.sh fail on a run where scoursh itself was fine'

t_summary 'daily-suite'
