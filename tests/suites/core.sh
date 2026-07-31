#!/usr/bin/env bash
# tests/suites/core.sh - lib/core.sh.
#
# Four of the five defects queued against §13 step 1 live in this file, and each
# has a test below that FAILS under the original implementation rather than
# merely passing under the new one.  The register's own prescribed test for F13
# ("a subshell exit leaves the scratch dir intact") passes trivially and proves
# nothing, because a subshell never runs the trap in the first place; it is
# replaced here.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# SC2030/SC2031: the subshells here isolate a probe on purpose.
# SC2015: `cmd && ok || no` is the intended reporting shape.
# shellcheck disable=SC2016,SC2030,SC2031,SC2015

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/core
mkdir -p "$W"

elapsed_ms() { printf '%s' "$(( ($2 - $1) / 1000000 ))"; }

# ---------------------------------------------------------------------------
printf '\n-- tension 24: the capability layer --\n'
# ---------------------------------------------------------------------------
t_case 'sha256_of'
assert_eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' \
  "$(printf '%s' abc | sha256_of)" 'the published SHA-256 of "abc"'
assert_eq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
  "$(printf '%s' '' | sha256_of)" 'the published SHA-256 of the empty string'
# A provider that leaves its input filename in the output would make every
# fingerprint in the tool path-dependent, which tension 5 does not intend.
d=$(printf x | sha256_of)
assert_eq 64 "${#d}" 'the digest is bare lowercase hex, 64 characters with no filename appended'

t_case 'time'
assert_true "$([[ $(now_iso) =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] && echo 0 || echo 1)" \
  'now_iso is the portable %Y-%m-%dT%H:%M:%SZ form, never date -Iseconds'
assert_true "$([[ $(now_epoch) =~ ^[0-9]+$ ]] && echo 0 || echo 1)" 'now_epoch is an integer'
assert_true "$([[ $(now_epoch_ns) =~ ^[0-9]+$ ]] && echo 0 || echo 1)" 'now_epoch_ns is an integer'

t_case 'filesystem accessors'
printf 'x' >"$W/mode.txt"
chmod 600 "$W/mode.txt"
assert_eq 600 "$(stat_mode "$W/mode.txt")" 'stat_mode works on this userland'
assert_true "$([[ $(stat_mtime "$W/mode.txt") =~ ^[0-9]+$ ]] && echo 0 || echo 1)" \
  'stat_mtime exists (finding F15 added it; the frozen table had only stat_mode)'
WR=$(realpath_of "$W")
assert_eq "$WR/mode.txt" "$(realpath_of "$W/mode.txt")" \
  'realpath_of resolves symlinks and collapses duplicate separators'
assert_eq "$WR/does/not/exist" "$(realpath_of "$W/does/not/exist")" \
  'realpath_of resolves a path that does not exist yet - a run directory is named before it is created'

# ---------------------------------------------------------------------------
printf '\n-- finding F14: msleep must actually sleep --\n'
# ---------------------------------------------------------------------------
t_case 'the frozen fallback `read -t 0.05 </dev/null` does NOT sleep'
# This is the defect, reproduced.  40 iterations of a real 50 ms sleep take two
# seconds; reading from /dev/null returns at EOF immediately, so the mutex retry
# loop became a spin that exhausted its whole timeout in under a millisecond.
t0=$(now_epoch_ns)
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
  21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if read -r -t 0.05 _x </dev/null; then :; fi
done
t1=$(now_epoch_ns)
broken_ms=$(elapsed_ms "$t0" "$t1")
assert_true "$([[ $broken_ms -lt 500 ]] && echo 0 || echo 1)" \
  "40x read -t 0.05 </dev/null returned in ${broken_ms}ms, not the 2000ms it claims to sleep"

t_case 'a probe on EXIT STATUS cannot tell the broken fallback from a working one'
rc=0
if read -r -t 0.05 _x </dev/null; then rc=0; else rc=$?; fi
assert_ne 0 "$rc" 'read returns non-zero for EOF exactly as it does for a timeout'

t_case 'the selected msleep implementation does sleep (measured, not asserted)'
t0=$(now_epoch_ns)
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do msleep 50; done
t1=$(now_epoch_ns)
real_ms=$(elapsed_ms "$t0" "$t1")
assert_true "$([[ $real_ms -ge 800 ]] && echo 0 || echo 1)" \
  "20x msleep 50 took ${real_ms}ms (>= 800ms required; impl=$SCOURSH_CAP_MSLEEP)"

t_case 'the FIFO fallback sleeps too'
# Selected on a host with no fractional sleep(1).  It reads from a descriptor
# that never yields data - this process holds the FIFO open read-write, so there
# is always a writer and never an EOF - rather than from one already at EOF.
if command -v mkfifo >/dev/null 2>&1; then
  (
    SCOURSH_CAP_MSLEEP=readfifo
    t0=$(now_epoch_ns)
    for _ in 1 2 3 4 5 6 7 8 9 10; do msleep 50; done
    t1=$(now_epoch_ns)
    ms=$(( (t1 - t0) / 1000000 ))
    [[ $ms -ge 400 ]] || { printf 'fifo msleep only took %sms\n' "$ms"; exit 1; }
  ) && _t_ok '10x msleep 50 over a FIFO takes at least 400ms' \
    || _t_no '10x msleep 50 over a FIFO takes at least 400ms' 'it returned early'
else
  _t_ok 'mkfifo unavailable, FIFO fallback not applicable on this host'
fi

t_case 'the probe REJECTS a sleep(1) that returns instantly'
# A `sleep` that truncates a fractional argument to zero and exits 0 is accepted
# by any exit-status probe and rejected by a measuring one.  This is the test
# that discriminates the two probe designs.
mkdir -p "$W/fakebin"
printf '#!/bin/sh\nexit 0\n' >"$W/fakebin/sleep"
chmod +x "$W/fakebin/sleep"
picked=$(
  PATH=$W/fakebin:$PATH
  hash -r                       # bash caches command paths; the probe runs at
                                # startup in production, so this is test scaffolding
  unset SCOURSH_CAP_MSLEEP
  core_probe_msleep
  printf '%s' "$SCOURSH_CAP_MSLEEP"
)
assert_ne sleep "$picked" "a fake instantaneous sleep is not selected (probe chose '$picked')"

# ---------------------------------------------------------------------------
printf '\n-- finding F13: the EXIT-trap cleanup guard --\n'
# ---------------------------------------------------------------------------
t_case 'bash resets trapped EXIT actions in subshells (the hazard the old guard defended)'
out=$(bash -c 'trap "printf FIRED" EXIT; ( true ); x=$(exit 3); ( exit 5 ) & wait; printf DONE')
assert_eq 'DONEFIRED' "$out" \
  'a subshell exit does NOT run the handler, so the old guard defended a case bash never produces'

t_case 'an xargs -P worker is a fresh PROCESS, where the old guard PASSES'
cat >"$W/oldguard.sh" <<'SH'
cleanup_old() { [[ $BASHPID == $$ ]] || return 0; printf 'GUARD-PASSED\n' >>"$1"; }
trap 'cleanup_old "$1"' EXIT
SH
: >"$W/oldguard.log"
printf 'a\nb\nc\nd\n' | xargs -P 4 -n 1 -I{} bash "$W/oldguard.sh" "$W/oldguard.log" >/dev/null 2>&1
n=$(wc -l <"$W/oldguard.log" | tr -d ' ')
assert_eq 4 "$n" \
  'every worker passes `[[ $BASHPID == $$ ]]`, so under the old rule every worker would erase the shared scratch dir'

t_case 'the ownership guard: N xargs -P workers leave the scratch dir and all shards intact'
# The replacement for the register's vacuous prescribed test.  Each worker
# sources lib/core.sh for real (which installs the EXIT trap), writes a shard,
# and exits; the parent then checks that everything survived.
cat >"$W/worker.sh" <<SH
source "$ROOT/lib/core.sh"
printf 'worker %s\n' "\$BASHPID" >"\$SCOURSH_SCRATCH/shard.\$BASHPID"
SH
sentinel=$SCOURSH_SCRATCH/parent-sentinel
printf 'still here\n' >"$sentinel"
before=$SCOURSH_SCRATCH
printf '1\n2\n3\n4\n5\n6\n7\n8\n' | xargs -P 8 -n 1 -I{} bash "$W/worker.sh" >/dev/null 2>&1
assert_file_exists "$before" 'the shared scratch directory survives eight concurrent workers'
assert_file_exists "$sentinel" 'the parent-owned sentinel survives'
shards=$(find "$SCOURSH_SCRATCH" -maxdepth 1 -name 'shard.*' | wc -l | tr -d ' ')
assert_eq 8 "$shards" 'all eight worker shards survive until the parent exits'

t_case 'ownership does not inherit through the environment'
# SCOURSH_SCRATCH is exported so workers use the parent's directory;
# SCOURSH_SCRATCH_OWNER is deliberately NOT, and the on-disk marker is checked
# too, so even a manually re-exported value cannot make a worker the owner.
res=$(SCOURSH_SCRATCH_OWNER=$$ bash -c "source '$ROOT/lib/core.sh'; scratch_is_owned_here && echo OWNED || echo NOT-OWNED")
assert_eq 'NOT-OWNED' "$res" 'a child that claims the owner pid is still not the owner'
assert_true "$(scratch_is_owned_here && echo 0 || echo 1)" 'the creating process IS the owner'

# ---------------------------------------------------------------------------
printf '\n-- finding F16: shred is GNU-only and sits inside the mandated cleanup --\n'
# ---------------------------------------------------------------------------
t_case 'erase_dir works with no shred on the host'
mkdir -p "$W/erase/sub"
printf 'secret\n' >"$W/erase/sub/f"
erase_dir "$W/erase"
assert_file_absent "$W/erase" 'the scratch directory is removed whether or not shred exists'
assert_eq 0 "$?" 'erase_dir cannot fail: it runs inside the EXIT trap'

t_case 'a full run on a host without shred exits inside the frozen 0-5 contract'
# The defect: `shred` is absent on macOS, so the EXIT trap ran a missing command
# and, under the mandated `set -Eeuo pipefail`, the process exited 127 - outside
# the contract - leaving the scratch dir behind on exactly the platform the CI
# matrix mandates.
# SCOURSH_SCRATCH must be unset for the child, or it inherits the parent's
# directory and correctly declines to erase something it does not own.
out=$(env -u SCOURSH_SCRATCH -u SCOURSH_SCRATCH_OWNER SCOURSH_CAP_SHRED=none bash -c "
  source '$ROOT/lib/core.sh'
  printf '%s\n' \"\$SCOURSH_SCRATCH\"
" 2>/dev/null)
rc=$?
assert_eq 0 "$rc" 'a run with no shred available exits 0, not 127'
assert_file_absent "$out" 'and its scratch directory is gone'

t_case 'die refuses an out-of-contract exit code'
assert_status 5 'die 6 (the code two frozen samples use) is coerced to 5, not returned raw' \
  bash -c "source '$ROOT/lib/core.sh'; die 6 'pattern engine failed'"
for c in 1 2 3 4 5; do
  assert_status "$c" "die $c exits $c" bash -c "source '$ROOT/lib/core.sh'; die $c x"
done

# ---------------------------------------------------------------------------
printf '\n-- finding F15: the mutex --\n'
# ---------------------------------------------------------------------------
mk_lock() {                 # $1 dir, $2 pid, $3 age-seconds ('' = no owner file)
  mkdir -p "$1"
  if [[ -n $2 ]]; then
    printf '%s %s\n' "$2" "$(( $(now_epoch) - $3 ))" >"$1/owner"
  fi
}
DEAD_PID=$(bash -c 'printf %s $$')     # a pid that has certainly exited

t_case 'lock_is_stale is specified, not asserted'
rm -rf "$W/L"
mk_lock "$W/L" "$$" 0
assert_true "$(lock_is_stale "$W/L" && echo 1 || echo 0)" 'a fresh lock held by a live owner is NOT stale'
rm -rf "$W/L"
mk_lock "$W/L" "$$" 9999
assert_true "$(lock_is_stale "$W/L" && echo 1 || echo 0)" \
  'an OLD lock whose owner is still alive is NOT stale - this is what bounds pid reuse'
rm -rf "$W/L"
mk_lock "$W/L" "$DEAD_PID" 0
assert_true "$(lock_is_stale "$W/L" && echo 1 || echo 0)" \
  'a lock with a dead owner but no age is NOT stale - both conjuncts are required'
rm -rf "$W/L"
mk_lock "$W/L" "$DEAD_PID" 9999
assert_true "$(lock_is_stale "$W/L" && echo 0 || echo 1)" 'old AND dead IS stale'
rm -rf "$W/L"
mk_lock "$W/L" '' 0
assert_true "$(lock_is_stale "$W/L" && echo 1 || echo 0)" \
  'the window between mkdir and the owner file: a fresh lock with no owner is NOT stale'

t_case 'reclaim is single-winner and identity-bound: it cannot delete a LIVE lock'
# The defect: two waiters both judge one lock stale; the first reclaims it and
# acquires; the second, already past its check, `rm -rf`s the first's freshly
# acquired lock, putting two processes in the critical section.
rm -rf "$W/M" "$W/M".rcl.*
mk_lock "$W/M" "$DEAD_PID" 9999
token=$(_lock_token "$W/M")             # what BOTH waiters observed
_lock_reclaim "$W/M" "$token"
assert_file_absent "$W/M" 'waiter 1 reclaims the stale lock'
mkdir "$W/M"                            # waiter 1 now acquires it
printf '%s %s\n' "$$" "$(now_epoch)" >"$W/M/owner"
_lock_reclaim "$W/M" "$token"           # waiter 2, still holding the OLD token
assert_file_exists "$W/M" \
  "waiter 2's reclaim does NOT delete the live lock (a bare rm -rf would have)"
assert_eq "$$" "$(cut -d' ' -f1 <"$W/M/owner")" 'and the live holder is still the owner'
rm -rf "$W/M"

t_case 'mutual exclusion holds across concurrent processes'
cat >"$W/mx.sh" <<SH
source "$ROOT/lib/core.sh"
mutex_acquire demo
cs="\$SCOURSH_SCRATCH/critical-section"
if ! mkdir "\$cs" 2>/dev/null; then printf 'VIOLATION\n' >>"\$SCOURSH_SCRATCH/violations"; fi
printf 'x' >>"\$SCOURSH_SCRATCH/entered"
rmdir "\$cs" 2>/dev/null || true
mutex_release demo
SH
rm -f "$SCOURSH_SCRATCH/violations" "$SCOURSH_SCRATCH/entered"
rm -rf "$SCOURSH_SCRATCH/mx"
printf '1\n2\n3\n4\n5\n6\n7\n8\n' | xargs -P 8 -n 1 -I{} bash "$W/mx.sh" >/dev/null 2>&1
assert_file_absent "$SCOURSH_SCRATCH/violations" 'eight concurrent workers never overlap in the critical section'
assert_eq 8 "$(wc -c <"$SCOURSH_SCRATCH/entered" | tr -d ' ')" 'and all eight got in'

t_case 'the mutex retry loop uses the frozen msleep wrapper, not a literal sleep'
assert_not_contains "$(cat "$ROOT/lib/core.sh")" 'sleep 0.05; waited=' \
  'tension 16 sample called `sleep 0.05` literally, contradicting its own capability layer'

# ---------------------------------------------------------------------------
printf '\n-- tension 4: set -Eeuo pipefail versus a rule engine --\n'
# ---------------------------------------------------------------------------
t_case 'scan_match distinguishes no-match from engine failure'
printf 'x = eval(a); y = eval(b)\n' >"$W/s.txt"
assert_status 0 'a match returns 0' scan_match "$W/hits" -e 'eval' -- "$W/s.txt"
assert_status 1 'NO MATCH returns 1 and is not an error - it is the normal case' \
  scan_match "$W/hits" -e 'zzzz' -- "$W/s.txt"
# `|| true` would report a broken rule as clean, which is the silent
# coverage-hole failure mode this wrapper exists to prevent.
assert_status 5 'a broken pattern aborts the run rather than reporting zero findings' \
  bash -c "source '$ROOT/lib/core.sh'; scan_match /dev/null -e '[unterminated' -- '$W/s.txt'"

t_case 'scan_match_offsets yields one record per MATCH with its byte offset'
scan_match_offsets "$W/off" 'eval\(' "$W/s.txt" || true
assert_eq '1:4:eval(
1:17:eval(' "$(cat "$W/off")" \
  'two matches on one line are two records, ordered by byte offset (§10.3, tension 5)'

t_case '`set +e` appears nowhere in the repository'
# Matched as a COMMAND, not as a substring: the phrase appears in this file and
# in lib/core.sh's own comments explaining that it is forbidden.
found=0
while IFS= read -r f; do
  if scan_match "$W/setplus" -e '^[[:space:]]*set[[:space:]]+\+[a-zA-Z]*e' -- "$f"; then
    found=$(( found + 1 ))
  fi
done <<<"$(find "$ROOT/lib" "$ROOT/tests" -name '*.sh' -type f | LC_ALL=C sort)"
assert_eq 0 "$found" 'tension 4 rule 1: set +e is forbidden repository-wide'

# ---------------------------------------------------------------------------
printf '\n-- tension 12: the scan root --\n'
# ---------------------------------------------------------------------------
t_case 'scan_root_id never contains a credential'
if command -v git >/dev/null 2>&1; then
  rm -rf "$W/gl"
  git init -q "$W/gl"
  git -C "$W/gl" config --local remote.origin.url \
    'https://gitlab-ci-token:JOBTOKEN123@gitlab.example/org/proj.git'
  id=$(scan_root_id_of "$W/gl")
  assert_eq 'git-remote:https://gitlab.example/org/proj' "$id" \
    'the userinfo strip removes a live job token (the standard GitLab runner clone shape)'
  git -C "$W/gl" config --local remote.origin.url \
    'https://gitlab-ci-token:JOBTOKEN456@gitlab.example/org/proj.git'
  assert_eq "$id" "$(scan_root_id_of "$W/gl")" \
    'and a rotated token does not move the id, so the gate can converge'
  git -C "$W/gl" config --local remote.origin.url 'git@host.example:org/proj.git'
  assert_eq 'git-remote:host.example:org/proj' "$(scan_root_id_of "$W/gl")" \
    'scp-like userinfo is stripped by the second form of the rule'
  git -C "$W/gl" config --local remote.origin.url '.git'
  assert_eq "git-local:$(realpath_of "$W/gl")" "$(scan_root_id_of "$W/gl")" \
    'a degenerate url normalises to empty and falls through to git-local'

  rm -rf "$W/commitless"
  git init -q "$W/commitless"
  assert_eq "git-local:$(realpath_of "$W/commitless")" "$(scan_root_id_of "$W/commitless")" \
    'a commit-less repository has a DEFINED id (the root-commit recipe returned nothing)'

  t_case 'the path-root cell is cwd-independent'
  rm -rf "$W/repo"
  mkdir -p "$W/repo/src"
  git init -q "$W/repo"
  a=$(cd "$W/repo" && path_root_cell .)
  b=$(cd "$W/repo/src" && path_root_cell "$W/repo")
  assert_eq "$a" "$b" 'cd /repo && scan --path . equals cd /repo/src && scan --path /repo'
  assert_eq '.' "$a" 'the cell is "." when the resolved path is the scan root, never the empty string'
  assert_eq 'src' "$(path_root_cell "$W/repo/src")" 'and is scan-root-relative otherwise'
else
  _t_ok 'git unavailable, scan-root tests skipped'
fi

t_case 'a non-git tree falls back to its resolved path'
mkdir -p "$W/tarball/frontend"
assert_eq "path:$(realpath_of "$W/tarball")" "$(scan_root_id_of "$W/tarball")" 'path: kind'
assert_ne "$(scan_root_id_of "$W/tarball")" "$(scan_root_id_of "$W/tarball/frontend")" \
  'two nested non-git roots get different ids, so their cells are never comparable'

# ---------------------------------------------------------------------------
printf '\n-- json_string --\n'
# ---------------------------------------------------------------------------
t_case 'the single JSON writer'
assert_eq '"a\"b\\c"' "$(json_string 'a"b\c')" 'quote and backslash'
assert_eq '"a\nb\tc"' "$(json_string "$(printf 'a\nb\tc')")" 'LF and TAB'
assert_eq '"\u0001"' "$(json_string "$(printf '\001')")" 'a C0 control becomes \uXXXX'
assert_eq "$(printf '"caf\xc3\xa9"')" "$(json_string "$(printf 'caf\xc3\xa9')")" \
  'multi-byte UTF-8 passes through unescaped'

t_summary core
