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

t_case 'reading a lock owner is one operation, not a check followed by an open'
# The defect, found by lib/http.sh's tension-16 rate limiter - the first code
# in this repository to take this mutex from several processes at once, once
# per request.  lock_is_stale and _lock_token both tested `[[ -r $d/owner ]]`
# and THEN opened the file as a separate step.  Releasing a lock removes the
# whole directory, so under real contention the open lands after the owner
# file is gone, and bash reports the failed redirect on the run's stderr - on
# a path that is otherwise entirely CORRECT, since an unreadable owner file is
# exactly the "published lock with no owner file yet" case docs/FOUNDATION.md
# tension 16 already decides (fall through to the mtime branch, not stale).
# Measured before the fix: eight processes taking and releasing one mutex 40
# times each produced 16 such diagnostics across 6 runs.
#
# That race is probabilistic, and a test that only usually fails pins nothing,
# so the state it produces is reached here deterministically instead: an
# `owner` path that passes `-r` and cannot be read.  It is the same defect -
# readability was tested, the read still failed - and the fix (attempt the
# read once, with the group's stderr discarded, and treat any failure as "no
# owner line") is what both the stable case below and the field race need.
# The eight-worker case further down never caught it because it discards
# stderr and takes the lock once per worker.
rm -rf "$W/R"
mkdir -p "$W/R/owner"          # readable, and unopenable as a line of text
lock_err=$W/lock-read.err
: >"$lock_err"
{ lock_is_stale "$W/R" && stale=1 || stale=0; } 2>"$lock_err"
assert_eq 0 "$stale" \
  'a lock whose owner line cannot be read falls through to the mtime branch and is NOT stale - the verdict was already right, which is why the noise below is the only observable defect'
assert_eq '' "$(cat "$lock_err")" \
  'and lock_is_stale prints NOTHING while doing it - FAILS under a `[[ -r $d/owner ]]` test followed by a separate `read < $d/owner`, which reports the failed read on the run stderr and makes a correct path look like an error in every --jobs scan'
: >"$lock_err"
{ _lock_token "$W/R" >/dev/null; } 2>"$lock_err"
assert_eq '' "$(cat "$lock_err")" \
  'and so does _lock_token, which carries the identical check-then-open pair - FAILS if only one of the two call sites is fixed'
rm -rf "$W/R"

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
printf '\n-- tension 2: the register and the code pin the SAME invocation --\n'
# ---------------------------------------------------------------------------
# tension 2 pins both engine invocations "so the invocation exists in exactly one
# place" and requires byte-identical findings between them.  A register that
# specifies flags the code does not use is not a cosmetic slip: §13 step 3 builds
# the real file enumerator from that paragraph, and an implementer who follows it
# reintroduces the asymmetry the parity test exists to catch.
#
# This is a DRIFT test, not a spelling check: it reads what lib/core.sh actually
# binds for each engine and requires the register to contain that exact string,
# so changing either side alone fails.
t_case 'each pinned engine invocation appears verbatim in the register'
REG=$ROOT/docs/FOUNDATION.md
for eng in rg grep; do
  bound=$(
    SCOURSH_ENGINE=$eng
    core_bind_engine
    printf '%s' "${SCOURSH_GREP[*]}"
  )
  if /usr/bin/grep -qF -- "\`$bound\`" "$REG"; then
    _t_ok "the register pins '$bound' for $eng, exactly as lib/core.sh binds it"
  else
    _t_no "the register pins '$bound' for $eng, exactly as lib/core.sh binds it" \
      "docs/FOUNDATION.md does not contain that invocation"
  fi
done

t_case '-r is not PINNED for either engine'
# It is --recursive to grep and --replace to ripgrep, so a shared wrapper cannot
# carry it; file enumeration is the caller's job.  Scoped to the sentence that
# PINS the invocation, because the prose around it quotes the disproved command
# on purpose, as the evidence for removing it - a blunt whole-file check fires
# on the explanation of its own fix.
pinned=$(/usr/bin/grep -F 'The `grep` fallback is' "$REG" || true)
assert_not_contains "$pinned" ' -r' 'the pinned fallback carries no -r'
assert_contains "$pinned" 'grep -E -n' 'and pins the invocation the code binds'

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

  t_case 'a stray GLOBAL git config does not collide two remote-less repos onto one id'
  # tension 12, round 5 ("`git config --get` reads global config"): a bare
  # `git config --get remote.origin.url` also consults the GLOBAL config, so a
  # stray `remote.origin.url` in a developer's or a CI runner's global
  # gitconfig - not implausible, since some setups template one - would make
  # scan_root_id_of() read the SAME remote for every remote-less repository on
  # the box.  scan_root_id is a persisted cell-comparability key (the same one
  # the `_strip_userinfo` cases above pin), so two UNRELATED repositories would
  # collapse onto one `git-remote:` id and their `path-root` cells would become
  # wrongly comparable, defeating tension 12's "never infer fixed across
  # incomparable scopes" for them through a second channel.  The fix is
  # `git -C "$root" config --local --get remote.origin.url` (lib/core.sh);
  # this fails under the same call with `--local` dropped, which is the exact
  # regression the round-5 finding describes.
  GLOBAL_CONF=$W/global-gitconfig
  printf '[remote "origin"]\n\turl = https://global.example/leaked/proj\n' >"$GLOBAL_CONF"
  export GIT_CONFIG_GLOBAL=$GLOBAL_CONF
  rm -rf "$W/remoteless-a" "$W/remoteless-b"
  git init -q "$W/remoteless-a"
  git init -q "$W/remoteless-b"
  id_a=$(scan_root_id_of "$W/remoteless-a")
  id_b=$(scan_root_id_of "$W/remoteless-b")
  unset GIT_CONFIG_GLOBAL
  assert_eq "git-local:$(realpath_of "$W/remoteless-a")" "$id_a" \
    'repo A ignores the global remote and falls back to git-local'
  assert_eq "git-local:$(realpath_of "$W/remoteless-b")" "$id_b" \
    'repo B ignores the global remote too'
  assert_ne "$id_a" "$id_b" \
    'two unrelated remote-less repos still get DIFFERENT ids, so their cells are never wrongly comparable'

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

t_case 'userinfo is stripped from the AUTHORITY only, never from the path'
# tension 12 freezes the strip as
#   "<scheme>://<user>[:<pass>]@<rest>" -> "<scheme>://<rest>"
# where userinfo is by definition the component before the authority's
# terminating '/'.  Stripping to the first '@' ANYWHERE discards the host and the
# leading path when a repository path happens to contain one, and scan_root_id is
# a persisted cell-comparability key: two unrelated repositories whose paths
# share a suffix would collapse onto one id, `path-root` cells would become
# wrongly comparable, and tension 12's whole purpose - never infer `fixed` from
# absence across incomparable scopes - is defeated for them.
assert_eq 'https://host.example/org/pr@oj' "$(_strip_userinfo 'https://host.example/org/pr@oj')" \
  'an @ in the PATH is content, not a userinfo delimiter'
assert_eq 'host.example:org/pr@oj' "$(_strip_userinfo 'host.example:org/pr@oj')" \
  'and in an scp-like path, where userinfo would terminate at the first colon'
# The register's own documented cases must keep working.
assert_eq 'https://host.example/org/proj' "$(_strip_userinfo 'https://user:pass@host.example/org/proj')" \
  'user:pass userinfo is still stripped'
assert_eq 'https://gitlab.example/org/proj' "$(_strip_userinfo 'https://gitlab-ci-token:JOBTOKEN123@gitlab.example/org/proj')" \
  'the GitLab runner job token is still stripped'
assert_eq 'host.example:org/proj' "$(_strip_userinfo 'git@host.example:org/proj')" \
  'scp-like userinfo is still stripped'
assert_eq 'https://host.example/org/proj' "$(_strip_userinfo 'https://host.example/org/proj')" \
  'a URL with no userinfo is untouched'
assert_eq 'https://host.example/a@b/c' "$(_strip_userinfo 'https://user@host.example/a@b/c')" \
  'userinfo is stripped once, and a later @ in the path survives'

t_case 'a non-git tree falls back to its resolved path'
mkdir -p "$W/tarball/frontend"
assert_eq "path:$(realpath_of "$W/tarball")" "$(scan_root_id_of "$W/tarball")" 'path: kind'
assert_ne "$(scan_root_id_of "$W/tarball")" "$(scan_root_id_of "$W/tarball/frontend")" \
  'two nested non-git roots get different ids, so their cells are never comparable'

# ---------------------------------------------------------------------------
printf '\n-- finding F16 (look half) / tension 25: db_lookup_exact --\n'
# ---------------------------------------------------------------------------
# db_lookup_exact (lib/core.sh) is the ONE implementation modules/sca/engine.sh's
# sca_lookup_exact and sca_package_known both call: `LC_ALL=C look` on PREFIX when
# the capability probe found `look`, `LC_ALL=C grep -F -m 1` otherwise.  The
# asymmetry is deliberate (docs/FOUNDATION.md tension 25): `look` returns every
# line sharing the prefix, since more than one advisory can exist for one exact
# package@version, while the fallback returns only the first.
#
# tests/suites/sca.sh already exercises both call sites end-to-end against
# tests/fixtures/sca/advisories.db, but every fixture row there is the ONLY row
# for its (ecosystem, package, version), so neither branch's asymmetry is ever
# actually forced - a fallback that dropped `-m 1` (a bare `grep -F`, returning
# every matching line instead of just the first) would pass that suite
# unchanged.  The cases below force each branch directly, with a fixture that
# has two rows sharing one exact prefix, so each assertion fails under the
# reading its message names.
rm -rf "$W/lookup.db"
printf 'eco\tpkgA\t1.0\trecA1\neco\tpkgA\t1.0\trecA2\neco\tpkgA\t2.0\trecA3\neco\tpkgB\t1.0\trecB1\n' \
  >"$W/lookup.db"
DUP_PREFIX=$(printf 'eco\tpkgA\t1.0\t')
NOMATCH_PREFIX=$(printf 'eco\tpkgZ\t9.9\t')

t_case 'the grep -F -m 1 fallback returns only the FIRST line sharing the prefix'
out=$(SCOURSH_CAP_LOOK=none db_lookup_exact "$DUP_PREFIX" "$W/lookup.db")
assert_eq "$(printf 'eco\tpkgA\t1.0\trecA1')" "$out" \
  'FAILS under a fallback missing -m 1 (a bare grep -F): two rows share this exact prefix, and a bare grep -F would return BOTH, not just recA1'

t_case 'look returns EVERY line sharing the prefix, not just the first'
if _have look; then
  out=$(SCOURSH_CAP_LOOK=look db_lookup_exact "$DUP_PREFIX" "$W/lookup.db")
  assert_eq "$(printf 'eco\tpkgA\t1.0\trecA1\neco\tpkgA\t1.0\trecA2')" "$out" \
    'FAILS under an implementation that routes the look branch through grep -F -m 1 instead of a real `look` call: it would return only recA1, silently dropping recA2 - the second advisory for this exact package@version'
else
  _t_ok 'look unavailable on this host; the fallback branch above still covers it'
fi

t_case 'no match: both branches return status 1 with no output'
rc=0
out=$(SCOURSH_CAP_LOOK=none db_lookup_exact "$NOMATCH_PREFIX" "$W/lookup.db") || rc=$?
assert_eq 1 "$rc" 'the grep fallback returns 1, not 0, when nothing matches'
assert_eq '' "$out" 'and prints nothing'
if _have look; then
  rc=0
  out=$(SCOURSH_CAP_LOOK=look db_lookup_exact "$NOMATCH_PREFIX" "$W/lookup.db") || rc=$?
  assert_eq 1 "$rc" 'and look itself also returns 1, not 0, when nothing matches'
  assert_eq '' "$out" 'and prints nothing'
fi

t_case 'a missing or unreadable file returns 1 immediately, without invoking look or grep at all'
rc=0
db_lookup_exact "$DUP_PREFIX" "$W/does-not-exist.db" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" 'FAILS if the [[ -r $file ]] guard is dropped: look/grep would then run against a nonexistent path'

# ---------------------------------------------------------------------------
printf '\n-- docs/FOUNDATION.md tension 25 (npm-range amendment): db_lookup_prefix --\n'
# ---------------------------------------------------------------------------
# db_lookup_prefix's whole reason to exist, over db_lookup_exact, is the
# grep fallback: it must NOT carry -m 1, because modules/sca/engine.sh's
# sca_lookup_range prefixes on (ecosystem, package) alone and must evaluate
# EVERY row sharing that prefix against the semver comparator, unlike an
# exact (ecosystem, package, version) prefix where at most a handful of
# advisories share one exact version. Reuses $W/lookup.db above unchanged -
# pkgA has three rows, two of them sharing the DUP_PREFIX.
t_case 'db_lookup_prefix: the grep fallback returns EVERY line sharing the prefix, not just the first'
out=$(SCOURSH_CAP_LOOK=none db_lookup_prefix "$DUP_PREFIX" "$W/lookup.db")
assert_eq "$(printf 'eco\tpkgA\t1.0\trecA1\neco\tpkgA\t1.0\trecA2')" "$out" \
  'FAILS under a fallback carrying -m 1 (db_lookup_exact'"'"'s own): it would return only recA1, silently dropping recA2 - exactly the correctness bug db_lookup_prefix exists to avoid for a (ecosystem, package)-only prefix'

t_case 'db_lookup_prefix: look returns every line sharing the prefix too (unchanged from db_lookup_exact'"'"'s own look branch)'
if _have look; then
  out=$(SCOURSH_CAP_LOOK=look db_lookup_prefix "$DUP_PREFIX" "$W/lookup.db")
  assert_eq "$(printf 'eco\tpkgA\t1.0\trecA1\neco\tpkgA\t1.0\trecA2')" "$out" \
    'look already returns every matching line; db_lookup_prefix must not narrow that'
else
  _t_ok 'look unavailable on this host; the fallback branch above still covers it'
fi

t_case 'db_lookup_prefix: no match - status 1, no output, no crash'
rc=0
out=$(SCOURSH_CAP_LOOK=none db_lookup_prefix "$NOMATCH_PREFIX" "$W/lookup.db") || rc=$?
assert_eq 1 "$rc" 'the grep fallback returns 1 when nothing matches'
assert_eq '' "$out" 'and prints nothing'

t_case 'db_lookup_prefix: a missing or unreadable file returns 1 immediately'
rc=0
db_lookup_prefix "$DUP_PREFIX" "$W/does-not-exist.db" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" 'FAILS if the [[ -r $file ]] guard is dropped'

# ---------------------------------------------------------------------------
printf '\n-- docs/FOUNDATION.md tension 4'"'"'s trap, third instance: db_lookup_exact/db_lookup_prefix distinguish no-match from engine failure --\n'
# ---------------------------------------------------------------------------
# Operator-reported bug: `look`/`grep -F` both exit 1 on NO MATCH - the
# ordinary case, since most packages carry no advisory - and modules/sca/
# engine.sh's sca_lookup_range read db_lookup_prefix's output through
# `done < <(db_lookup_prefix ...)`, an untested process substitution under
# scoursh's mandatory `set -Eeuo pipefail`. That tripped the ERR trap and
# logged "error scoursh: command failed" once per clean package, even though
# the lookup behaved correctly (tests/suites/sca.sh's own section on this
# proves the fix at that exact reported shape). The unit-level half proved
# here is that both primitives now internally distinguish rc<=1 (returned
# cleanly, no matter how the caller invokes them) from rc>1 (a genuine
# engine/file failure, `die`'d loudly) - the same distinction scan_match
# already makes for the pattern-rule engine, mirrored here for `look`/`grep`.
_STUBDIR=$W/stub-bin-lookup-enginefail
mkdir -p "$_STUBDIR"
cat >"$_STUBDIR/grep" <<'STUBEOF'
#!/usr/bin/env bash
exit 2
STUBEOF
chmod +x "$_STUBDIR/grep"

t_case 'db_lookup_prefix: a stubbed grep exiting 2 (rc > 1) dies with SCOURSH_EXIT_INCOMPLETE, never returns as if it were an ordinary no-match'
_dlp_err=$W/dlp-stub-prefix.stderr
_dlp_rc=0
( PATH="$_STUBDIR:$PATH" SCOURSH_CAP_LOOK=none db_lookup_prefix "$DUP_PREFIX" "$W/lookup.db" ) \
  >/dev/null 2>"$_dlp_err" || _dlp_rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$_dlp_rc" \
  'FAILS under a naive `|| true`-only fix: rc=2 must never be read as "no match" (rc=1)'
assert_contains "$(cat "$_dlp_err")" 'db lookup engine failed' 'and the failure is reported, not silently discarded'

t_case 'db_lookup_exact: a stubbed grep exiting 2 (rc > 1) dies with SCOURSH_EXIT_INCOMPLETE too - the same audited hazard, same fix'
_dle_err=$W/dlp-stub-exact.stderr
_dle_rc=0
( PATH="$_STUBDIR:$PATH" SCOURSH_CAP_LOOK=none db_lookup_exact "$DUP_PREFIX" "$W/lookup.db" ) \
  >/dev/null 2>"$_dle_err" || _dle_rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$_dle_rc" \
  'db_lookup_exact shares db_lookup_prefix'"'"'s exact bare-last-statement shape, so it needs the identical guard'
assert_contains "$(cat "$_dle_err")" 'db lookup engine failed' 'and the failure is reported, not silently discarded'

t_case 'db_lookup_prefix: an ordinary no-match (rc=1) is unaffected by the engine-failure guard'
rc=0
out=$(SCOURSH_CAP_LOOK=none db_lookup_prefix "$NOMATCH_PREFIX" "$W/lookup.db") || rc=$?
assert_eq 1 "$rc" 'rc<=1 must still return cleanly rather than being escalated into a die'
assert_eq '' "$out" 'and print nothing, exactly as before this fix'

# ---------------------------------------------------------------------------
printf '\n-- json_string --\n'
# ---------------------------------------------------------------------------
t_case 'the single JSON writer'
assert_eq '"a\"b\\c"' "$(json_string 'a"b\c')" 'quote and backslash'
assert_eq '"a\nb\tc"' "$(json_string "$(printf 'a\nb\tc')")" 'LF and TAB'
assert_eq '"\u0001"' "$(json_string "$(printf '\001')")" 'a C0 control becomes \uXXXX'
assert_eq "$(printf '"caf\xc3\xa9"')" "$(json_string "$(printf 'caf\xc3\xa9')")" \
  'multi-byte UTF-8 passes through unescaped'

# ---------------------------------------------------------------------------
printf '\n-- lib/parallel.sh: bounded fan-out for --jobs N --\n'
# ---------------------------------------------------------------------------
# lib/parallel.sh is a LEAF (it sources nothing at all, deliberately - see its
# own header), so it can be exercised here on top of lib/core.sh alone.
# shellcheck source=lib/parallel.sh
source "$ROOT/lib/parallel.sh"

t_case 'parallel_workers_for: never more workers than units, never more than jobs'
parallel_workers_for 4 100; assert_eq 4 "$PARALLEL_WORKERS" 'jobs is the cap when there is plenty of work'
parallel_workers_for 8 3;   assert_eq 3 "$PARALLEL_WORKERS" \
  'FAILS under a bare `PARALLEL_WORKERS=$jobs`: 8 workers over 3 units means five forks with nothing to do'
parallel_workers_for 1 100; assert_eq 1 "$PARALLEL_WORKERS" '--jobs 1 is one worker'
parallel_workers_for 4 0;   assert_eq 1 "$PARALLEL_WORKERS" 'no units is still a valid single-worker answer, not zero'

t_case 'parallel_workers_for: a non-numeric or absent jobs falls back to 1, never to the documented default of 4'
parallel_workers_for '' 100;    assert_eq 1 "$PARALLEL_WORKERS" 'unset'
parallel_workers_for 'x' 100;   assert_eq 1 "$PARALLEL_WORKERS" 'not a number'
parallel_workers_for '0' 100;   assert_eq 1 "$PARALLEL_WORKERS" 'zero'
parallel_workers_for '-2' 100;  assert_eq 1 "$PARALLEL_WORKERS" \
  'negative - FAILS under a plain assignment, which would then produce a negative block count'

# THE honesty property of the partition, and the one worth a real test: every
# unit is assigned to exactly one worker.  A unit assigned twice is a
# double-counted file whose duplicate findings the fingerprint dedup would then
# hide; a unit assigned to nobody is a silent false negative - a file the run
# reports nothing about because it never opened it.  Neither is visible in the
# output, which is why it is asserted directly here rather than inferred from a
# scan.
t_case 'parallel_block_bounds: the blocks partition the unit list exactly - no gap, no overlap'
_pb_check() {
  local total=$1 nw=$2 i expect=0 bad=''
  for (( i = 0; i < nw; i++ )); do
    parallel_block_bounds "$total" "$nw" "$i"
    [[ $PARALLEL_BLOCK_START == "$expect" ]] || bad="worker $i starts at $PARALLEL_BLOCK_START, expected $expect"
    expect=$(( PARALLEL_BLOCK_START + PARALLEL_BLOCK_COUNT ))
  done
  [[ -z $bad ]] || { printf '%s' "$bad"; return 0; }
  [[ $expect == "$total" ]] || { printf 'blocks cover %s of %s units' "$expect" "$total"; return 0; }
  printf 'ok'
}
for _case in '100 4' '100 7' '7 4' '4 4' '1 1' '5 3' '2 2' '13 5'; do
  # shellcheck disable=SC2086
  assert_eq ok "$(_pb_check $_case)" "total/workers = $_case: contiguous, complete, non-overlapping"
done

t_case 'parallel_block_bounds: contiguous blocks, not round-robin - worker 0 owns the FIRST units'
parallel_block_bounds 100 4 0
assert_eq 0 "$PARALLEL_BLOCK_START" 'worker 0 starts at 0'
assert_eq 25 "$PARALLEL_BLOCK_COUNT" 'and owns a run of 25'
parallel_block_bounds 100 4 3
assert_eq 75 "$PARALLEL_BLOCK_START" 'worker 3 starts where worker 2 ended'
# Contiguity is not cosmetic: it is what makes the parent's worker-ordered fold
# of the per-worker meta directories reproduce the single-worker append order.
# A round-robin partition passes the "exactly once" test above and still breaks
# run.json's byte-reproducibility, so it needs its own assertion.

t_case 'parallel_map: one worker runs INLINE, in the current shell, with no fork and no aux directory'
_pm_inline() {
  _PM_PID=$BASHPID
  _PM_AUX=empty
  [[ -z ${SCOURSH_WORKER_AUX:-} ]] || _PM_AUX=$SCOURSH_WORKER_AUX
  _PM_ARGS="$1 $2 $3"
}
_PM_PID=''; _PM_AUX=''; _PM_ARGS=''
parallel_map 1 10 _pm_inline tag
assert_eq "$BASHPID" "$_PM_PID" \
  'FAILS if the single-worker path forks: the callback must run in THIS shell, so `--jobs 1` is byte-for-byte the code path the module always had'
assert_eq empty "$_PM_AUX" 'and gets no aux directory, which is what tells it to update in-process state directly'
assert_eq '0 10 tag' "$_PM_ARGS" 'called once with the whole range'
assert_eq 1 "$PARALLEL_WORKERS" 'reported as one worker'

t_case 'parallel_map: N workers each get their own private meta directory, and the parent folds them in worker order'
_PM_RUN=$W/pmrun
rm -rf "$_PM_RUN"; mkdir -p "$_PM_RUN/meta"
_pm_worker() {
  local start=$1 count=$2 i
  for (( i = start; i < start + count; i++ )); do
    run_record pmkey "unit-$i"
  done
}
# NOT in a subshell: parallel_map reports through globals (PARALLEL_WORKERS,
# PARALLEL_FAILED), and a subshell would throw them away - the same measured
# trap lib/findings.sh's `occurrence_next` header documents for `$(...)`.
_PM_SAVED_RUN_DIR=${SCOURSH_RUN_DIR:-}
SCOURSH_RUN_DIR=$_PM_RUN
parallel_map 4 8 _pm_worker
SCOURSH_RUN_DIR=$_PM_SAVED_RUN_DIR
assert_eq 4 "$PARALLEL_WORKERS" 'four workers over eight units'
_PM_EXPECT=$(for i in 0 1 2 3 4 5 6 7; do printf 'unit-%s\n' "$i"; done)
assert_eq "$_PM_EXPECT" "$(cat "$_PM_RUN/meta/pmkey")" \
  'FAILS if workers append straight to meta/ (their appends interleave by scheduling) and FAILS if the parent folds them in any order but worker 0 first - either way run.json stops being byte-reproducible'

t_case 'parallel_map: a failed worker is SURFACED, never silently dropped'
_pm_boom() {
  local start=$1
  (( start != 0 )) || return 0
  false
}
rc=0
parallel_map 4 8 _pm_boom || rc=$?
assert_eq 3 "$PARALLEL_FAILED" \
  'FAILS under a bare `wait` whose status is thrown away, or under `wait || true` - the shape that turns a half-scanned tree into a clean report - and says HOW MANY, so the module can name it in incomplete_reason'
assert_eq 0 "$rc" \
  'and parallel_map itself still returns 0 - deliberately, because a non-zero return forces every caller into `|| rc=1`, and bash suspends set -e for the whole call tree of a command whose status is tested, which on the single-worker path is the entire walk (measured below)'

t_case 'set -e really is suspended through a checked call - the measurement the return-0 contract rests on'
_se_inner() { false; _SE_REACHED=1; return 0; }
_se_outer() { _se_inner; }
_SE_REACHED=0
_se_rc=0
_se_outer || _se_rc=1
assert_eq 1 "$_SE_REACHED" \
  'a bare `false` deep inside a function invoked in a `||` context does NOT abort under set -Eeuo pipefail - which is why parallel_map, _sast_walk_parallel and the tree walks all signal failure through a global and are called bare'

t_case 'parallel_map: every worker succeeding reports none failed'
_pm_fine() { return 0; }
rc=0
parallel_map 4 8 _pm_fine || rc=$?
assert_eq 0 "$rc" 'the happy path is not accidentally the failure path'
assert_eq 0 "$PARALLEL_FAILED" 'nothing failed'
parallel_cleanup

t_case 'parallel_aux_read: worker side-channel files come back in worker order, and inline yields nothing'
_pm_aux() {
  local start=$1
  [[ -z ${SCOURSH_WORKER_AUX:-} ]] || printf 'from-%s\n' "$start" >"$SCOURSH_WORKER_AUX/probe"
}
parallel_map 4 8 _pm_aux
assert_eq "$(printf 'from-0\nfrom-2\nfrom-4\nfrom-6')" "$(parallel_aux_read probe)" \
  'worker 0 first - the same ordering guarantee the meta fold relies on'
parallel_cleanup
parallel_map 1 8 _pm_aux
assert_eq '' "$(parallel_aux_read probe)" \
  'an inline callback has no aux directory at all, so the parent must read nothing rather than a stale pool'

t_case 'run_record: SCOURSH_META_DIR redirects the append, and an unset one still means meta/'
_MD_RUN=$W/mdrun
rm -rf "$_MD_RUN"; mkdir -p "$_MD_RUN/meta" "$_MD_RUN/private"
(
  SCOURSH_RUN_DIR=$_MD_RUN
  run_record mdkey 'to the run'
  SCOURSH_META_DIR=$_MD_RUN/private
  run_record mdkey 'to the worker'
)
assert_eq 'to the run' "$(cat "$_MD_RUN/meta/mdkey")" 'unset means meta/, exactly as before'
assert_eq 'to the worker' "$(cat "$_MD_RUN/private/mdkey")" \
  'FAILS if run_record ignores the override - which is what lets N workers interleave in one file'

t_summary core
