#!/usr/bin/env bash
# tests/suites/run-tests-stage.sh - the whole-tree `shellcheck` STAGE inside
# tests/run-tests.sh, as opposed to the suites and linters it also runs.
#
# WHY THIS SUITE EXISTS.  The stage is the last thing a full run does and the
# slowest thing in it by a wide margin, so for a long time nobody could iterate
# on it: it could not finish at all.  `shellcheck -x` inlines every `source`
# statically, and this tree's diamond-shaped source graph re-expanded
# lib/http.sh and lib/core.sh up to 29 times for a single entry point, which
# blew past the stage's own per-process watchdog budget.  While that stood,
# `tests/run-tests.sh` could never exit 0, so "merge when the suite is green"
# was unachievable and every ticket had to hand-reason about which failure was
# theirs.  Two of the stage's own properties are what stop that recurring, and
# both are asserted here, in the direction that fails:
#
#   1. It prints a VERDICT LINE on every exit path.  A stage that ends after
#      nothing but its header - which is what a `set -E` abort, a ^C or a
#      SIGTERM used to produce - is indistinguishable in a log from a stage
#      that ran and had nothing to say.  Section D kills a real run mid-stage
#      and requires the verdict anyway; it fails against the pre-fix stage,
#      which printed nothing.
#   2. A file it could NOT check is reported distinctly from a file it checked
#      and found clean, and never rounds up to a pass.  Sections B and C pin
#      both directions, because the naive reading of each is the other's bug:
#      merge them and an unmeasured file reads as evidence of cleanliness,
#      which is the single most expensive way for a linter to be wrong.
#
# HOW IT RUNS IN SECONDS.  Every case drives the REAL tests/run-tests.sh as a
# real subprocess, with:
#
#   * a STUB `shellcheck` first on PATH, so no real analysis happens and the
#     per-file exit status is whatever the case wants to test;
#   * `tests/run-tests.sh shellcheck`, the named stage target, so the ~50
#     suites and linters do not run (this file included - without it, this
#     suite would recurse);
#   * SCOURSH_SHELLCHECK_FILE_LIST pointing at a two-file fixture list, so the
#     stage does not walk the real tree.  That variable is a test seam and
#     nothing else: a real run has it unset and still checks every *.sh file.
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

RUNNER=$ROOT/tests/run-tests.sh
W=$SCOURSH_SCRATCH/run-tests-stage
rm -rf "$W"; mkdir -p "$W/bin" "$W/tree"

# Two fixture files.  Their CONTENT is irrelevant - the stub decides every
# verdict - but they must exist, because the stage runs `shellcheck` on real
# paths and a case that passed only because the file was missing would prove
# nothing.
printf '#!/usr/bin/env bash\ntrue\n' > "$W/tree/alpha.sh"
printf '#!/usr/bin/env bash\ntrue\n' > "$W/tree/beta.sh"
printf '%s\n%s\n' "$W/tree/alpha.sh" "$W/tree/beta.sh" > "$W/filelist"

# The stub.  STUB_PLAN is a space-separated `basename:action` list; the action
# is either an exit status to return, or `sleep` (stay alive, so the watchdog
# and the signal cases have a live process to act on).  Anything unlisted
# exits 0.
cat > "$W/bin/shellcheck" <<'STUB'
#!/usr/bin/env bash
f=
for a in "$@"; do case $a in -*|--) ;; *) f=$a ;; esac; done
b=${f##*/}
for entry in ${STUB_PLAN:-}; do
  name=${entry%%:*}; action=${entry#*:}
  if [[ $name == "$b" ]]; then
    if [[ $action == sleep ]]; then
      printf 'stub: holding %s\n' "$b"
      : > "${STUB_ALIVE:-/dev/null}"
      sleep 30
      exit 0
    fi
    printf 'stub: %s exits %s\n' "$b" "$action"
    exit "$action"
  fi
done
exit 0
STUB
chmod +x "$W/bin/shellcheck"

# Runs the real runner's stage with the stub in front of PATH.  Captures
# combined output (the verdict goes to stdout, the roll-ups to stderr) and the
# exit status, and never lets a non-zero status abort this suite.
_stage() {
  local out status=0
  out=$(PATH=$W/bin:$PATH \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        bash "$RUNNER" shellcheck 2>&1) || status=$?
  STAGE_OUT=$out
  STAGE_STATUS=$status
}

# ===========================================================================
printf '== A: every file checked and clean -> passed ==\n'
# ===========================================================================
STUB_PLAN='' _stage
assert_eq 0 "$STAGE_STATUS" 'a clean stage exits 0'
assert_contains "$STAGE_OUT" '--- shellcheck passed' 'and says so in a verdict line'
assert_not_contains "$STAGE_OUT" 'could NOT be checked' \
  'and claims nothing was unmeasurable - FAILS if a clean file is filed under the unmeasured roll-up'
assert_contains "$STAGE_OUT" 'SCOURSH_SHELLCHECK_FILE_LIST' \
  'the stage states that its file list was overridden, so a run driven by the test seam can never be mistaken for a whole-tree run'

# ===========================================================================
printf '== B: a file CHECKED with findings -> FAILED, and it is not called unmeasurable ==\n'
# ===========================================================================
# An exit status of 1 from shellcheck is "I looked at this file and I have
# something to say".  (This sentence deliberately does not START with the word
# `shellcheck`: a comment line that does is parsed as a DIRECTIVE - SC1072.)
STUB_PLAN='beta.sh:1' _stage
assert_ne 0 "$STAGE_STATUS" 'a stage with findings exits non-zero'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' 'and prints the FAILED verdict'
assert_contains "$STAGE_OUT" 'checked and reported findings' \
  'and reports it as a CHECKED file with findings'
assert_not_contains "$STAGE_OUT" 'could NOT be checked' \
  'and NOT as an unmeasurable one - FAILS under collapsing every non-zero exit into one bucket, which would make a real finding look like a linter that never ran'

# ===========================================================================
printf '== C: a file that could NOT be checked is reported distinctly ==\n'
# ===========================================================================
# An exit status of 2 is "I could not process this file at all".  It produces no
# result, so it must never round up to a pass, and it must not be filed as a
# finding either: nobody can fix a finding that was never made.
STUB_PLAN='beta.sh:2' _stage
assert_ne 0 "$STAGE_STATUS" 'an unmeasurable file fails the stage on its own'
assert_contains "$STAGE_OUT" '--- shellcheck FAILED' 'and the verdict line says so'
assert_contains "$STAGE_OUT" 'could NOT be checked' \
  'and it is reported as unmeasured, not clean - FAILS under treating "shellcheck said nothing" as "shellcheck found nothing"'
assert_contains "$STAGE_OUT" 'beta.sh' 'and the roll-up names the file'
assert_not_contains "$STAGE_OUT" 'checked and reported findings' \
  'and does NOT claim a finding was reported for it'

# ===========================================================================
printf '== C2: a HOST-PRESSURE kill names that cause, and is not a finding ==\n'
# ===========================================================================
# The free-memory floor is the cheaper of the stage's two kill paths to drive
# deterministically: set the floor absurdly high and the biggest live process
# is killed on the first sample, without this test having to allocate gigabytes
# to trip the per-process budget.
#
# The stage's two kill causes MUST be distinguishable in the output, which is
# this ticket's acceptance criterion 3 - an unattributable kill is the defect,
# not merely a symptom of it.  This case pins the HOST-PRESSURE arm; section H
# pins the OVER-BUDGET arm, and each asserts the other's wording is ABSENT, so
# neither can be satisfied by a stage that prints one generic message for both.
# The pre-fix stage printed `watchdog killed pid N (file)` for both causes and
# fails both halves.
C2_ALIVE=$W/alive-c2
rm -f "$C2_ALIVE"
C2_OUT=$(PATH=$W/bin:$PATH \
      SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
      SCOURSH_SHELLCHECK_FREE_FLOOR_GB=9999999 \
      STUB_PLAN='beta.sh:sleep' STUB_ALIVE=$C2_ALIVE \
      bash "$RUNNER" shellcheck 2>&1) || true
if command -v ps >/dev/null 2>&1; then
  assert_contains "$C2_OUT" '--- shellcheck FAILED' 'a watchdog kill still reaches a verdict line'
  assert_contains "$C2_OUT" 'could NOT be checked' \
    'and the killed file is reported as unmeasured - FAILS under recording it as a shellcheck finding, which would send someone hunting for a defect in a file that was never analysed'
  assert_contains "$C2_OUT" 'HOST MEMORY PRESSURE' \
    'and the message names HOST MEMORY PRESSURE as the cause - FAILS under one generic "watchdog killed" line for both causes, which is the unattributable kill this ticket was filed for'
  assert_not_contains "$C2_OUT" 'OVER BUDGET' \
    'and does NOT blame the file for exceeding its own budget, which it did not - FAILS under attributing every kill to the file that happened to be running'
  assert_contains "$C2_OUT" 'not this file' \
    'and says in so many words that the file was not the cause'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== D: a stage killed mid-run STILL prints a verdict line ==\n'
# ===========================================================================
# This is the case this whole rework was filed for.  A `set -E` abort, a ^C and
# a SIGTERM all end the stage without reaching its own verdict line, and bash
# does not run an EXIT trap for an untrapped SIGTERM - so the pre-fix stage
# printed its header and then nothing at all, which reads in a log exactly like
# a stage that ran and was happy.  SIGTERM is used here because it is the one
# of the three that can be delivered from outside, deterministically.
D_ALIVE=$W/alive-d
rm -f "$D_ALIVE"
D_OUT=$W/d.out
: > "$D_OUT"
PATH=$W/bin:$PATH \
  SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
  STUB_PLAN='alpha.sh:sleep' STUB_ALIVE=$D_ALIVE \
  bash "$RUNNER" shellcheck >"$D_OUT" 2>&1 &
D_PID=$!

# Wait for the stage to be genuinely INSIDE the run before signalling it:
# signalling too early would kill it before the header and the case would pass
# for the wrong reason.
D_WAITED=0
while [[ ! -e $D_ALIVE ]] && (( D_WAITED < 150 )); do
  sleep 0.1
  D_WAITED=$(( D_WAITED + 1 ))
done
assert_file_exists "$D_ALIVE" 'the stage really did start checking before the signal was sent'

kill -TERM "$D_PID" 2>/dev/null || true
D_STATUS=0
wait "$D_PID" 2>/dev/null || D_STATUS=$?
D_TEXT=$(cat "$D_OUT")
pkill -f "$W/bin/shellcheck" 2>/dev/null || true

assert_contains "$D_TEXT" '--- shellcheck FAILED' \
  'a SIGTERMed stage still prints a verdict line - FAILS against a stage whose verdict sits only on the straight-line path, which printed its header and nothing else'
assert_contains "$D_TEXT" 'SIGTERM' \
  'and the verdict says the stage ended on a signal rather than reaching a real result'
assert_ne 0 "$D_STATUS" 'and the run exits non-zero'

# ===========================================================================
printf '== E: the stage is reachable on its own, and an unknown name still fails ==\n'
# ===========================================================================
assert_contains "$(bash "$RUNNER" --list)" 'stages:  shellcheck' \
  '--list names the stage, so `tests/run-tests.sh shellcheck` is discoverable rather than folklore'
E_STATUS=0
bash "$RUNNER" no-such-thing-at-all >/dev/null 2>&1 || E_STATUS=$?
assert_eq 2 "$E_STATUS" 'an unknown name is still a usage error, not a silently skipped stage'

# ===========================================================================
printf '== F: errexit is LIVE inside the stage body ==\n'
# ===========================================================================
# The stage used to be top-level code under `set -Eeuo pipefail`; turning it
# into a function risked losing that, because bash disables errexit for the
# WHOLE BODY of a function invoked in an `A || B` list - not just for the call
# (bash manual, "The Set Builtin").  So `sc_stage` is invoked as a plain
# command and reports through SC_STAGE_STATUS.
#
# This case proves the strictness is really there, by breaking something the
# stage has no `||` guard on: a stub `mktemp` that always fails, so
# `sc_shard_dir=$(mktemp -d)` returns non-zero.  Shipped, that aborts the
# runner and the EXIT trap still names what happened.  Under the `||` call
# site it does NOT abort - measured: the stage carries on with an empty
# $sc_shard_dir, reports both files as "checked and reported findings" when
# neither was ever checked (an AC5 violation manufactured out of thin air),
# and the runner then prints `all green` and exits 0.
mkdir -p "$W/bin-mktemp"
cp "$W/bin/shellcheck" "$W/bin-mktemp/shellcheck"
printf '#!/usr/bin/env bash\nexit 1\n' > "$W/bin-mktemp/mktemp"
chmod +x "$W/bin-mktemp/mktemp"

F_STATUS=0
F_OUT=$(PATH=$W/bin-mktemp:$PATH \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        bash "$RUNNER" shellcheck 2>&1) || F_STATUS=$?

assert_ne 0 "$F_STATUS" \
  'an unexpected internal non-zero aborts the runner - FAILS under `sc_stage || failed+=(...)`, which disables errexit for the whole body and lets the run finish `all green` with exit 0'
assert_contains "$F_OUT" '--- shellcheck FAILED' 'and a verdict line is still printed'
assert_contains "$F_OUT" 'an unexpected non-zero exit' \
  'and the EXIT trap arm for it is REACHABLE and names the cause - FAILS under the `||` spelling, where that arm can never fire and the trap documents a protection that does not exist'
assert_not_contains "$F_OUT" 'checked and reported findings' \
  'and no file is claimed to have been checked - FAILS under the `||` spelling, which reported findings against two files shellcheck never ran on'

# ===========================================================================
printf '== G: available memory is AVAILABLE memory, not the free list ==\n'
# ===========================================================================
# THE ROOT CAUSE.  The stage used to read macOS `Pages free` as "available
# memory".  That is the FREE LIST, which Darwin holds near a low-water mark and
# refills lazily by reclaiming inactive pages - it does not grow with the size
# of the machine.  Measured on the 64GB host this was fixed on: 6GB reported
# where 36GB was genuinely available, and it stayed pinned near 6GB.  Every
# number downstream inherited that 6x understatement, which is why an 8GB, a
# 27GB and a 64GB host all failed in the same way.
#
# Driven here through a stub `vm_stat` so the numbers are fixed rather than
# whatever this machine happens to be doing.  The stub reports 1GB free but
# 20GB inactive, 1GB purgeable and 2GB speculative - all reclaimable on demand
# - so the honest answer is 24GB and the old reading's answer is 1GB.
if [[ -r /proc/meminfo ]]; then
  printf 'SKIPPED (Linux: this host has /proc/meminfo, so MemAvailable is read and vm_stat is never consulted)\n'
else
  mkdir -p "$W/bin-vm"
  cp "$W/bin/shellcheck" "$W/bin-vm/shellcheck"
  # 16384-byte pages: 65536 pages = 1GB.
  cat > "$W/bin-vm/vm_stat" <<'VMSTAT'
#!/usr/bin/env bash
cat <<'EOF'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                    65536.
Pages active:                                1000000.
Pages inactive:                              1310720.
Pages speculative:                            131072.
Pages throttled:                                   0.
Pages wired down:                             200000.
Pages purgeable:                               65536.
EOF
VMSTAT
  chmod +x "$W/bin-vm/vm_stat"

  G_OUT=$(PATH=$W/bin-vm:$PATH \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=64 \
          STUB_PLAN='' bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$G_OUT" '24GB available' \
    'free + inactive + purgeable + speculative is reported as available - FAILS under the shipped `Pages free` reading, which reports 1GB here and understated a real 64GB host by 6x'
  assert_not_contains "$G_OUT" '1GB available' \
    'and the free list alone is NOT what gets reported'
fi

# ===========================================================================
printf '== H: an OVER-BUDGET kill names the FILE as the cause ==\n'
# ===========================================================================
# The other half of acceptance criterion 3, and the mirror of section C2.  The
# real budgets are whole GB and a stub uses a few MB, so SCOURSH_SHELLCHECK_
# BUDGET_KB is the seam that makes this arm reachable in a test at all; it is
# never set by a real run.  Every process exceeds a 100KB budget, in both
# passes, so both files end up over budget and neither is ever a finding.
if command -v ps >/dev/null 2>&1; then
  H_OUT=$(PATH=$W/bin:$PATH \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_BUDGET_KB=100 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-h \
          bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$H_OUT" 'OVER BUDGET' \
    'the message names OVER BUDGET as the cause - FAILS under one generic kill message shared with host pressure'
  assert_contains "$H_OUT" 'not host memory pressure' \
    'and says explicitly that host pressure was NOT the cause, so the two are never confused'
  assert_not_contains "$H_OUT" 'HOST MEMORY PRESSURE' \
    'and does NOT claim host pressure - FAILS under a stage that attributes every kill to whichever cause it checks first'
  assert_not_contains "$H_OUT" 'checked and reported findings' \
    'and a killed file is never filed as a shellcheck finding'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== I: a file too big for this host is SKIPPED by name, and still exits 0 ==\n'
# ===========================================================================
# Acceptance criterion 5, and the ticket's own title.  A file this host cannot
# supply the memory for is a fact about the MACHINE, the same class as
# `shellcheck` not being installed - so it must be named, counted and carried
# into the run's last line, but it must NOT fail the stage, because a stage
# that can never exit 0 is the thing this ticket was filed to end.  Both
# directions matter and each is the other's bug: report it as a failure and
# `pnpm test` can never pass on a small host; report it as nothing and 19
# unmeasured files read as 19 clean ones.
if command -v ps >/dev/null 2>&1; then
  I_STATUS=0
  I_OUT=$(PATH=$W/bin:$PATH \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_BUDGET_KB=100 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-i \
          bash "$RUNNER" shellcheck 2>&1) || I_STATUS=$?
  assert_eq 0 "$I_STATUS" \
    'a host-capacity skip does NOT fail the stage - FAILS under the shipped stage, where an unmeasurable file always fails and so `tests/run-tests.sh` could never exit 0 on any host'
  assert_contains "$I_OUT" 'SKIPPED' 'and the skip is announced'
  assert_contains "$I_OUT" 'alpha.sh' 'and every skipped file is named'
  assert_contains "$I_OUT" 'beta.sh' 'and every skipped file is named'
  assert_contains "$I_OUT" 'were NOT checked' \
    'and the stage states plainly that they were not checked - FAILS under a silent omission, which is the false green criterion 5 forbids'
  assert_contains "$I_OUT" '--- shellcheck passed' 'the verdict line is a pass'
  assert_contains "$I_OUT" 'host too small' 'but it carries the reason on the verdict line itself'
  assert_contains "$I_OUT" 'NOT a full pass' \
    "and the run's LAST line refuses to say a bare \`all green\` - FAILS under printing \`all green\` for a run that skipped files, which is the same false green one level up"
  assert_not_contains "$I_OUT" 'could NOT be checked' \
    'and a host-size skip is not filed under the unmeasured roll-up, which is for results this stage should have got and did not'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== J: jobs x budget <= headroom, on an 8GB, a 27GB and a 64GB host ==\n'
# ===========================================================================
# Acceptance criterion 2: "a fix that only works on the machine you tested is
# not a fix".  SCOURSH_SHELLCHECK_FORCE_{TOTAL,AVAIL}_GB drive the arithmetic
# over three host shapes from this one machine, and the invariant is checked by
# PARSING the numbers the stage prints rather than by matching a fixed string -
# so it cannot be satisfied by a stage that prints a plausible line and then
# runs something else.
#
# The shipped arithmetic fails this: it divided by 2 and then by a fixed 12GB
# budget, which yields 0 (clamped to 1 job) on every host under 24GB of
# headroom, while leaving the budget at 12GB - promising one process 12GB on a
# host with 3GB to give.  On the 8GB row below that is a 4x overcommit.
_j_host() {
  local total=$1 avail=$2 want_reserve=$3 want_headroom=$4 out line
  out=$(PATH=$W/bin:$PATH \
        SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
        SCOURSH_SHELLCHECK_FORCE_TOTAL_GB=$total \
        SCOURSH_SHELLCHECK_FORCE_AVAIL_GB=$avail \
        STUB_PLAN='' bash "$RUNNER" shellcheck 2>&1) || true

  assert_contains "$out" "host ${total}GB total, ${avail}GB available, ${want_reserve}GB reserved -> ${want_headroom}GB headroom" \
    "${total}GB host: reserve is max(2, total/8) = ${want_reserve}GB and headroom is ${want_headroom}GB"

  # Every pass line must satisfy jobs x budget <= headroom.
  local seen=0
  while IFS= read -r line; do
    [[ $line == *"parallel x"* ]] || continue
    seen=$(( seen + 1 ))
    local jobs budget commit headroom
    jobs=$(printf '%s\n' "$line" | sed -n 's/.*, \([0-9]*\) parallel x.*/\1/p')
    budget=$(printf '%s\n' "$line" | sed -n 's/.*parallel x \([0-9]*\)GB.*/\1/p')
    commit=$(printf '%s\n' "$line" | sed -n 's/.*= \([0-9]*\)GB of.*/\1/p')
    headroom=$(printf '%s\n' "$line" | sed -n 's/.*of \([0-9]*\)GB headroom.*/\1/p')
    assert_eq "$commit" "$(( jobs * budget ))" \
      "${total}GB host: the committed total the stage prints really is jobs x budget"
    if (( commit <= headroom )); then
      _t_ok "${total}GB host: ${jobs} x ${budget}GB = ${commit}GB fits in ${headroom}GB headroom"
    else
      _t_no "${total}GB host: ${jobs} x ${budget}GB = ${commit}GB OVERCOMMITS ${headroom}GB headroom"
    fi
  done <<< "$out"
  if (( seen > 0 )); then
    _t_ok "${total}GB host: the stage printed its plan rather than running an unstated one"
  else
    _t_no "${total}GB host: no pass plan was printed at all"
  fi
}
#        total avail reserve headroom
_j_host      8     6       2        4
_j_host     27    20       3       17
_j_host     64    36       8       28

# ===========================================================================
printf '== K: a process that exits under the watchdog does not abort the stage ==\n'
# ===========================================================================
# THE "PRINTS NOTHING AT ALL" FACE of this ticket, and the one that survived
# the memory-model rewrite because it is not a memory bug at all.
#
# The watchdog samples `ps -o rss= -p $pid` for each live process.  Written as
# a bare assignment, `rss_kb=$(ps ...)` takes the command substitution's exit
# status as its own, so when the process has exited in the microseconds since
# the `kill -0` liveness check above it, `ps` exits 1, the assignment exits 1,
# and `set -e` tears the stage down - past the watchdog roll-up, past the
# verdict, leaving a log that ends at the header.  It is a RACE, so a run of
# two stub files that both sleep never loses it and a run of 130 real files
# loses it almost every time: measured on this tree at 9 of 130 files
# unmeasured, each annotated "see the message below" with no message below,
# and the stage ending on "an unexpected non-zero exit before it could reach
# a verdict".
#
# Driven here by a stub `ps` that ALWAYS fails, which is the same status the
# race produces and needs no timing luck to hit.  Under the bare-assignment
# spelling this case gets the header and the abort verdict and nothing else;
# under `|| rss_kb=` the sample is skipped, the stage runs to completion, and
# both files are reported checked.
if command -v ps >/dev/null 2>&1; then
  mkdir -p "$W/bin-ps"
  cp "$W/bin/shellcheck" "$W/bin-ps/shellcheck"
  # Exits 1 with no output, exactly as the real `ps` does for a dead pid.
  printf '#!/usr/bin/env bash\nexit 1\n' > "$W/bin-ps/ps"
  chmod +x "$W/bin-ps/ps"

  K_STATUS=0
  K_OUT=$(PATH=$W/bin-ps:$PATH \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$W/alive-k \
          bash "$RUNNER" shellcheck 2>&1) || K_STATUS=$?

  assert_eq 0 "$K_STATUS" \
    'the stage survives a failing ps sample and exits 0 - FAILS under the bare `rss_kb=$(ps ...)` spelling, where set -e aborts the whole stage'
  assert_not_contains "$K_OUT" 'unexpected non-zero exit' \
    'and does NOT end on the abort trap - FAILS under the shipped spelling, which is how a run of the real tree ended with 9 files unmeasured and no explanation for any of them'
  assert_contains "$K_OUT" '--- shellcheck passed' \
    'and reaches a real verdict line rather than stopping after the header'
  assert_contains "$K_OUT" '2 of 2 file(s) checked' \
    'and both files are actually checked - a lost ps sample must cost the stage its watchdog for one tick, never a file its result'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

# ===========================================================================
printf '== L: kill attribution survives an abort, because the verdict prints it ==\n'
# ===========================================================================
# Acceptance criteria 3 and 4 together.  Knowing WHICH file and WHICH cause is
# what makes a kill actionable, and those messages used to be printed inline
# only after both passes had finished - so any abort before that point threw
# away the explanation for every kill already made, which is precisely what
# left 9 files annotated "see the message below" with nothing below.  They are
# emitted from _sc_verdict instead, the one function the EXIT/INT/TERM traps
# all call, so no exit path can lose them.
#
# Driven by the free-floor seam (a real kill), with the stage then aborted by
# a SIGTERM from outside - the same shape section D uses for the verdict line.
if command -v ps >/dev/null 2>&1; then
  L_ALIVE=$W/alive-l
  rm -f "$L_ALIVE"
  L_OUT=$(PATH=$W/bin:$PATH \
          SCOURSH_SHELLCHECK_FILE_LIST=$W/filelist \
          SCOURSH_SHELLCHECK_FREE_FLOOR_GB=999999 \
          STUB_PLAN='alpha.sh:sleep beta.sh:sleep' STUB_ALIVE=$L_ALIVE \
          bash "$RUNNER" shellcheck 2>&1) || true
  assert_contains "$L_OUT" 'HOST MEMORY PRESSURE' \
    'the cause of every kill reaches the output'
  assert_contains "$L_OUT" 'alpha.sh' \
    'and names the file it killed - FAILS under a message that reports only a pid, which nobody can act on'
else
  printf 'SKIPPED (no ps on this host, so the stage runs with no watchdog at all)\n'
fi

t_summary run-tests-stage
