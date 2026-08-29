#!/usr/bin/env bash
# lib/core.sh - logging, the portability capability layer, the scratch directory,
# traps, the pattern-engine wrapper, and the cross-process mutex.
#
# Owns:
#   docs/DESIGN.md   §4 (lib/core.sh)
#   docs/FOUNDATION.md tension  4 (set -Eeuo pipefail versus a rule engine)
#   docs/FOUNDATION.md tension 14 (exit codes)
#   docs/FOUNDATION.md tension 16 (shared state across processes; the mutex)
#   docs/FOUNDATION.md tension 24 (runtime freeze: bash and coreutils portability)
#
# This file is the ONLY place permitted to call the non-portable tools listed in
# tension 24 (sha256sum, shasum, stat -c/-f, readlink -f, sed -i, date -d,
# date -Iseconds, xargs -r, mktemp -p, grep -P, sort -V, shred).
# tests/lint-shell.sh enforces that.
#
# shellcheck shell=bash

# Sourced twice (a module and a library both source it) is a no-op the second time.
if [[ -n ${SCOURSH_CORE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CORE_SOURCED=1

# ---------------------------------------------------------------------------
# 0. Shell contract (tension 4)
# ---------------------------------------------------------------------------
# `set +e` is forbidden repository-wide; this line is never undone anywhere.
set -Eeuo pipefail

# Byte semantics everywhere: ${#s} counts bytes, sort/[[ =~ ]] are byte-oriented,
# and `sort` output is stable across hosts (tension 17 sorts under LC_ALL=C).
# All UTF-8 handling in this repository is explicit rather than locale-driven.
export LC_ALL=C
export LANG=C

umask 077

# bash >= 4.2 (tension 24). scan.sh (§13 step 2) performs the re-exec search;
# a library can only refuse to run.
if [[ -z ${BASH_VERSINFO[0]:-} ]] \
  || (( BASH_VERSINFO[0] < 4 )) \
  || { (( BASH_VERSINFO[0] == 4 )) && (( BASH_VERSINFO[1] < 2 )); }; then
  printf '%s\n' "scoursh: bash >= 4.2 required, found ${BASH_VERSION:-unknown}." >&2
  printf '%s\n' "scoursh: install a newer bash (brew install bash) or set SCOURSH_BASH." >&2
  exit 4
fi

# ---------------------------------------------------------------------------
# 1. Exit codes (tension 14)
# ---------------------------------------------------------------------------
# 0 clean · 1 gate failed · 2 usage · 3 scope violation · 4 missing required
# input · 5 incomplete run.  Nothing may exit outside this range: an exit 127
# from a missing tool inside a trap is what finding F16 was about.
readonly SCOURSH_EXIT_OK=0 SCOURSH_EXIT_GATE=1 SCOURSH_EXIT_USAGE=2 \
  SCOURSH_EXIT_SCOPE=3 SCOURSH_EXIT_INPUT=4 SCOURSH_EXIT_INCOMPLETE=5
export SCOURSH_EXIT_OK SCOURSH_EXIT_GATE SCOURSH_EXIT_USAGE \
  SCOURSH_EXIT_SCOPE SCOURSH_EXIT_INPUT SCOURSH_EXIT_INCOMPLETE

# ---------------------------------------------------------------------------
# 2. Logging
# ---------------------------------------------------------------------------
: "${SCOURSH_LOG_LEVEL:=info}"   # debug | info | warn | error | silent

_log_rank() {
  case $1 in
    debug) printf '%s' 10 ;;
    info) printf '%s' 20 ;;
    warn) printf '%s' 30 ;;
    error) printf '%s' 40 ;;
    silent) printf '%s' 99 ;;
    *) printf '%s' 20 ;;
  esac
}

is_tty() { [[ -t 2 ]]; }

# Precedence, deliberate: SCOURSH_COLOR=always wins even over NO_COLOR - an
# explicit user flag is the case NO_COLOR's own convention says should
# override it. SCOURSH_COLOR=never always wins over everything else. Only
# the auto/unset case defers to NO_COLOR and the TTY check.
_want_color() {
  case ${SCOURSH_COLOR:-auto} in
    never) return 1 ;;
    always) return 0 ;;
    *) [[ -z ${NO_COLOR:-} ]] && is_tty ;;
  esac
}

# `_redact_out TEXT` - docs/FOUNDATION.md tension 9 defines redact() as what is
# written ANYWHERE, and names run.json and logs in the same breath as evidence.
# Both writers in this file - `_log` and `run_record` - carry target-derived
# bytes: modules/dast/ratelimit.sh logs the burst endpoint it lifted out of the
# crawler's inventory, and a `coverage_gap` naming an endpoint it could not
# probe is appended verbatim into meta/, which lib/report.sh renders into
# run.json, report.md and report.html.  Measured before this helper existed: a
# single run_record carrying a userinfo URL put the credential in the clear into
# all three, plus meta/ itself.
#
# redact() lives in lib/findings.sh, which reaches this file through
# lib/records.sh, so it cannot be called unconditionally from here - a caller
# that loaded only lib/core.sh has no such function.  The `declare -F` guard is
# therefore forced, and it is exactly the shape AGENTS.md warns about: a
# misspelled name skips in SILENCE and leaves the credential in the clear, which
# reads precisely like a redacted run.  tests/suites/secret-redaction.sh section
# G pins the NAME by asserting, in a fully-loaded process, that run_record and
# _log output really are masked - so a rename fails the suite rather than
# quietly switching the net off.
#
# The reentrancy guard is not decoration.  redact() matches through
# `scan_match_stdin`, which calls `die` on an engine failure, and `die` logs -
# so an unguarded `_log` would recurse until the stack gave out on exactly the
# error path a scanner most needs to be able to report.  The flag is set in this
# shell and inherited by the `$(redact ...)` subshell, which is what makes the
# inner call bail; a redact() that dies takes only that subshell with it and the
# raw text is used, because a logger that aborts the run is worse than one that
# fails open on its own error path.
_REDACT_OUT_BUSY=0
_redact_out() {
  if (( _REDACT_OUT_BUSY )) || ! declare -F redact >/dev/null 2>&1; then
    printf '%s' "$1"
    return 0
  fi
  _REDACT_OUT_BUSY=1
  local out
  out=$(redact "$1") || out=$1
  _REDACT_OUT_BUSY=0
  printf '%s' "$out"
}

_log() {
  local level=$1 colour=$2
  shift 2
  local want cur
  want=$(_log_rank "$level")
  cur=$(_log_rank "$SCOURSH_LOG_LEVEL")
  (( want >= cur )) || return 0
  local prefix='' suffix=''
  if _want_color; then
    prefix=$'\033['"$colour"'m'
    suffix=$'\033[0m'
  fi
  printf '%s %s%-5s%s %s\n' "$(now_iso)" "$prefix" "$level" "$suffix" "$(_redact_out "$*")" >&2
}

log_debug() { _log debug '2;37' "$@"; }
log_info() { _log info '0;36' "$@"; }
log_warn() { _log warn '0;33' "$@"; }
log_error() { _log error '1;31' "$@"; }

# ---------------------------------------------------------------------------
# 3. die (tension 14)
# ---------------------------------------------------------------------------
# `die CODE MESSAGE...`.  The code is validated against the frozen 0-5 contract
# so no path can leave the process with an unclassifiable status.  A code of 5
# additionally records `incomplete_reason`, which tension 14 makes exactly the
# exit-5 predicate.
die() {
  local code=$1
  shift
  case $code in
    0 | 1 | 2 | 3 | 4 | 5) ;;
    *)
      log_error "internal: die called with out-of-contract code '$code' (message: $*)"
      code=$SCOURSH_EXIT_INCOMPLETE
      ;;
  esac
  if (( code == SCOURSH_EXIT_INCOMPLETE )); then
    run_record incomplete_reason "$*"
    run_json_refresh_incomplete
  fi
  log_error "$*"
  # An intentional exit is not an error to be re-reported by the ERR trap.
  trap - ERR
  exit "$code"
}

# The exit-5 half of tension 14, enforced on the CONSUMER SURFACE rather than
# only on the internal meta record.
#
# `die 5` terminates the process, so a run that aborts partway through never
# reaches scan.sh's own `report_run_json`.  In a combined scan the earlier
# modules have each already called `report_all`, so the run directory is left
# holding a `run.json`, `report.md` and `report.html` written by the PREVIOUS
# module - an empty `incomplete_reason` and a computed gate verdict - while the
# on-disk meta record says the run was truncated.  The exit code and the report
# then contradict each other, and it is the report a consumer reads.
# Re-running the run.json writer here closes that: whenever the exit code is 5,
# `run.json`'s `incomplete_reason` is non-empty.
#
# Three guards, each load-bearing:
#
#   * ONLY the process that created the run directory writes.  `run.json` is
#     written with a plain `>` redirect, so N `xargs -P` workers all aborting on
#     one open breaker would tear the file between them.  A worker's own abort
#     is still recorded, through the meta append `die` already made, and the
#     run-owning process folds it in when it writes.
#   * ONCE.  The latch is set before the call, so a `die` reached from inside
#     the writer cannot recurse into it.
#   * In a SUBSHELL with the ERR trap cleared, so a failure inside the writer
#     can neither replace the original exit code nor print a crash-shaped
#     second diagnostic over the real message.
#
# The writers run in that order, each in its own subshell, and run.json goes
# FIRST on purpose: it is the one the exit-5 contract is stated over, so a
# failure inside either of the heavier human-readable writers cannot cost the
# guarantee.  The two findings writers are deliberately NOT re-run - they merge
# every worker's shard, which is the one part of `report_all` that is unsafe
# while other workers may still be mid-write, and neither of them is what
# claims the run completed.
#
# These writers live in lib/report.sh, which lib/core.sh deliberately does not
# source (the dependency runs the other way).  A run that never loaded them has
# no report to contradict, so an absent function is a no-op rather than an
# error.
_SCOURSH_RUN_JSON_REFRESHED=0
run_json_refresh_incomplete() {
  local fn
  (( _SCOURSH_RUN_JSON_REFRESHED == 0 )) || return 0
  [[ -n ${SCOURSH_RUN_DIR:-} && -d ${SCOURSH_RUN_DIR:-}/meta ]] || return 0
  [[ ${_SCOURSH_RUN_OWNER:-} == "$$" ]] || return 0
  _SCOURSH_RUN_JSON_REFRESHED=1
  for fn in report_run_json report_md report_html; do
    declare -F "$fn" >/dev/null 2>&1 || continue
    ( trap - ERR; "$fn" "$SCOURSH_RUN_DIR" ) || true
  done
  return 0
}

# ---------------------------------------------------------------------------
# 4. Capability layer (tension 24)
# ---------------------------------------------------------------------------
# Probed once in the process that starts the run and exported, so an `xargs -P`
# worker inherits the decision instead of re-probing (which for msleep costs a
# real sleep).  Every capability is recorded in run.json.

_have() { command -v "$1" >/dev/null 2>&1; }

# --- SHA-256 -----------------------------------------------------------------
# Reads stdin ONLY (tension 9 handling rule 1: a secret is never in argv).
sha256_of() {
  local out=''
  case $SCOURSH_CAP_SHA256 in
    sha256sum)
      out=$(sha256sum)
      out=${out%%[[:space:]]*}
      ;;
    shasum)
      out=$(shasum -a 256)
      out=${out%%[[:space:]]*}
      ;;
    openssl)
      out=$(openssl dgst -sha256)
      out=${out##*[[:space:]]}
      ;;
    *)
      die "$SCOURSH_EXIT_INPUT" "no SHA-256 provider available"
      ;;
  esac
  # A provider that prints its input filename into the digest would make every
  # fingerprint in the tool path-dependent (tension 24), so the shape is checked.
  if [[ ! $out =~ ^[0-9a-f]{64}$ ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" "SHA-256 provider '$SCOURSH_CAP_SHA256' returned an unusable digest"
  fi
  printf '%s' "$out"
}

# --- time --------------------------------------------------------------------
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

now_epoch() {
  if [[ -n ${EPOCHSECONDS:-} ]]; then
    printf '%s' "$EPOCHSECONDS"
  else
    date -u +%s
  fi
}

# Nanoseconds since the epoch.  SCOURSH_CLOCK_NS records whether the underlying
# source is genuinely sub-second, so the rate limiter's arithmetic and the
# msleep probe both know what they are working with.
now_epoch_ns() {
  local v
  case $SCOURSH_CAP_CLOCK in
    epochrealtime)
      v=$EPOCHREALTIME
      printf '%s%s' "${v%%.*}" "$(_pad_micros "${v#*.}")"
      ;;
    date-ns) date -u +%s%N ;;
    *) printf '%s000000000' "$(now_epoch)" ;;
  esac
}

# EPOCHREALTIME has microsecond precision; pad to nanoseconds without arithmetic
# on a value that may carry a leading zero (which would be read as octal).
_pad_micros() {
  local frac=$1
  while (( ${#frac} < 6 )); do frac="${frac}0"; done
  printf '%s000' "${frac:0:6}"
}

# --- sleep (finding F14) -----------------------------------------------------
# `msleep MILLISECONDS`.
#
# The frozen fallback used to be `read -t 0.05 </dev/null`, which returns at EOF
# immediately and does not sleep at all, turning the mutex retry loop into a spin
# that exhausts its timeout in under a millisecond.  A probe based on `read`'s
# exit status cannot detect that, because `read` returns non-zero for both EOF
# and timeout.  So: read from a descriptor that never yields data (a FIFO this
# process holds open read-write, so there is always a writer and never an EOF),
# and select the implementation by MEASUREMENT rather than by exit status.
msleep() {
  local ms=$1 fifo
  case $SCOURSH_CAP_MSLEEP in
    sleep)
      sleep "$(_ms_to_seconds "$ms")"
      ;;
    readfifo)
      if [[ -z ${_SCOURSH_SLEEPFD:-} ]]; then
        fifo=$SCOURSH_SCRATCH/sleep.$$.fifo
        if [[ ! -p $fifo ]] && ! mkfifo "$fifo" 2>/dev/null; then
          SCOURSH_CAP_MSLEEP=floor
          msleep "$ms"
          return 0
        fi
        exec {_SCOURSH_SLEEPFD}<>"$fifo"
      fi
      # Always times out; there is a writer (this process) so EOF never arrives.
      if read -r -t "$(_ms_to_seconds "$ms")" -u "$_SCOURSH_SLEEPFD" _ 2>/dev/null; then :; fi
      ;;
    *)
      # No verified sub-second sleep on this host.  A whole second is the honest
      # floor; the warning was printed once at probe time.
      sleep 1
      ;;
  esac
}

# 50 -> 0.050 , 1200 -> 1.200 ; integer arithmetic only, so no locale decimal
# separator can leak in.
_ms_to_seconds() {
  local ms=$1
  printf '%d.%03d' "$(( ms / 1000 ))" "$(( ms % 1000 ))"
}

# --- filesystem --------------------------------------------------------------
stat_mode() {
  case $SCOURSH_CAP_STAT in
    gnu) stat -c %a -- "$1" ;;
    bsd) stat -f %Lp -- "$1" ;;
    *) printf '%s' '' ;;
  esac
}

# Added by finding F15: the mutex needs an mtime accessor and tension 24's table
# provided only stat_mode while linting `stat` out of every other file.
stat_mtime() {
  case $SCOURSH_CAP_STAT in
    gnu) stat -c %Y -- "$1" ;;
    bsd) stat -f %m -- "$1" ;;
    *) printf '%s' 0 ;;
  esac
}

# Resolves a path that does not necessarily exist yet: `readlink -f` accepts a
# missing final component on GNU but not on every BSD, so the deepest existing
# ancestor is resolved and the remainder appended.  A run directory is named
# before it is created, so this case is the normal one, not an edge case.
realpath_of() {
  local p=$1 tail='' base
  if [[ ${p:0:1} != / ]]; then
    p=$PWD/$p
  fi
  while [[ ! -e $p && $p == */* && $p != / ]]; do
    base=${p##*/}
    p=${p%/*}
    [[ -n $p ]] || p=/
    if [[ -n $tail ]]; then tail="$base/$tail"; else tail=$base; fi
  done
  local resolved
  if [[ -e $p ]]; then
    case $SCOURSH_CAP_REALPATH in
      readlink) resolved=$(readlink -f -- "$p") ;;
      *)
        if [[ -d $p ]]; then
          resolved=$(cd -- "$p" && pwd -P)
        else
          resolved=$(cd -- "${p%/*}" && pwd -P)/${p##*/}
        fi
        ;;
    esac
  else
    resolved=$p
  fi
  resolved=${resolved%/}
  [[ -n $resolved ]] || resolved=/
  if [[ -n $tail ]]; then
    printf '%s/%s' "$resolved" "$tail"
  else
    printf '%s' "$resolved"
  fi
}

sed_inplace() {
  local expr=$1 file=$2
  sed -i.scoursh-bak -e "$expr" -- "$file"
  rm -f -- "$file.scoursh-bak"
}

tmpdir_make() {
  mktemp -d "${SCOURSH_SCRATCH_BASE:-${TMPDIR:-/tmp}}/scoursh.XXXXXXXX"
}

# Added by finding F16.  `shred` is GNU-only, is absent on macOS, and sat inside
# the mandated EXIT cleanup where a 127 would escape the frozen 0-5 exit
# contract.  Overwrite-based erasure is best effort on any modern filesystem
# (APFS, journalled ext4, tmpfs, SSD wear levelling): the real control is
# `scratch-dir` on a tmpfs, which config/scanner.conf exposes.  Nothing here may
# fail, because it runs inside the EXIT trap.
erase_dir() {
  local dir=$1
  [[ -n $dir && -d $dir ]] || return 0
  if [[ $SCOURSH_CAP_SHRED == shred ]]; then
    # Best effort only; a failure here must never propagate out of the trap.
    if find "$dir" -type f -print0 2>/dev/null \
      | xargs -0 shred -u -n 1 -- 2>/dev/null; then :; fi
  fi
  if rm -rf -- "$dir" 2>/dev/null; then :; fi
  return 0
}

proc_alive() { kill -0 "$1" 2>/dev/null; }

# --- the probe ---------------------------------------------------------------
core_probe_capabilities() {
  if [[ -n ${SCOURSH_CAPS_PROBED:-} && -z ${SCOURSH_FORCE_PROBE:-} ]]; then
    # Inherited from the parent.  Arrays cannot be exported, so the engine
    # binding is redone here; everything else is read from the environment.
    core_bind_engine
    return 0
  fi

  if [[ -z ${SCOURSH_CAP_SHA256:-} ]]; then
    if _have sha256sum; then SCOURSH_CAP_SHA256=sha256sum
    elif _have shasum; then SCOURSH_CAP_SHA256=shasum
    elif _have openssl; then SCOURSH_CAP_SHA256=openssl
    else SCOURSH_CAP_SHA256=none
    fi
  fi

  if [[ -z ${SCOURSH_CAP_STAT:-} ]]; then
    if stat -c %a -- . >/dev/null 2>&1; then SCOURSH_CAP_STAT=gnu
    elif stat -f %Lp -- . >/dev/null 2>&1; then SCOURSH_CAP_STAT=bsd
    else SCOURSH_CAP_STAT=none
    fi
  fi

  if [[ -z ${SCOURSH_CAP_REALPATH:-} ]]; then
    if readlink -f -- . >/dev/null 2>&1; then SCOURSH_CAP_REALPATH=readlink
    else SCOURSH_CAP_REALPATH=cdpwd
    fi
  fi

  if [[ -z ${SCOURSH_CAP_SHRED:-} ]]; then
    if _have shred; then SCOURSH_CAP_SHRED=shred; else SCOURSH_CAP_SHRED=none; fi
  fi

  # tension 25 names `look` as the SCA lookup primitive; it is absent from
  # several minimal images, so it is probed and recorded rather than assumed.
  if [[ -z ${SCOURSH_CAP_LOOK:-} ]]; then
    if _have look; then SCOURSH_CAP_LOOK=look; else SCOURSH_CAP_LOOK=none; fi
  fi

  if [[ -z ${SCOURSH_CAP_CLOCK:-} ]]; then
    local probe
    if [[ -n ${EPOCHREALTIME:-} && $EPOCHREALTIME =~ ^[0-9]+\.[0-9]+$ ]]; then
      SCOURSH_CAP_CLOCK=epochrealtime
      SCOURSH_CLOCK_NS=1
    else
      probe=$(date -u +%s%N 2>/dev/null || printf '%s' '')
      if [[ $probe =~ ^[0-9]{16,}$ ]]; then
        SCOURSH_CAP_CLOCK=date-ns
        SCOURSH_CLOCK_NS=1
      else
        SCOURSH_CAP_CLOCK=seconds
        SCOURSH_CLOCK_NS=0
      fi
    fi
  fi
  : "${SCOURSH_CLOCK_NS:=0}"

  if [[ -z ${SCOURSH_CAP_MSLEEP:-} ]]; then
    core_probe_msleep
  fi

  if [[ -z ${SCOURSH_ENGINE:-} ]]; then
    if _have rg; then SCOURSH_ENGINE='rg'; else SCOURSH_ENGINE='grep'; fi
  fi
  core_bind_engine

  SCOURSH_CAPS_PROBED=1
  export SCOURSH_CAP_SHA256 SCOURSH_CAP_STAT SCOURSH_CAP_REALPATH \
    SCOURSH_CAP_SHRED SCOURSH_CAP_LOOK SCOURSH_CAP_CLOCK SCOURSH_CLOCK_NS \
    SCOURSH_CAP_MSLEEP SCOURSH_ENGINE SCOURSH_CAPS_PROBED
}

# Finding F14: select the sleep implementation by measuring elapsed time.
#
# An exit-status probe accepts three broken implementations: `read -t` at EOF
# (returns non-zero, which a naive probe reads as "timed out"), a `sleep` that
# truncates a fractional argument to zero and returns 0, and a shell builtin
# that ignores the timeout.  All three return in ~0 ms, so measurement rejects
# all three and exit status rejects none.
core_probe_msleep() {
  if [[ -n ${SCOURSH_FORCE_MSLEEP_IMPL:-} ]]; then
    SCOURSH_CAP_MSLEEP=$SCOURSH_FORCE_MSLEEP_IMPL
    return 0
  fi
  if (( SCOURSH_CLOCK_NS == 0 )); then
    # No sub-second clock, so no fractional sleep can be verified.  Refusing to
    # certify what cannot be measured is the point of this probe.
    SCOURSH_CAP_MSLEEP=floor
    log_warn "no sub-second clock on this host: msleep falls back to a 1-second floor"
    return 0
  fi
  if _core_measures_as_sleep sleep; then
    SCOURSH_CAP_MSLEEP='sleep'
    return 0
  fi
  if [[ -n ${SCOURSH_SCRATCH:-} ]] && _have mkfifo && _core_measures_as_sleep readfifo; then
    SCOURSH_CAP_MSLEEP=readfifo
    log_warn "fractional sleep(1) unavailable: msleep uses a FIFO read timeout"
    return 0
  fi
  SCOURSH_CAP_MSLEEP=floor
  log_warn "no verified sub-second sleep on this host: msleep falls back to a 1-second floor"
}

# True when candidate implementation $1, asked for 200 ms, actually blocks for at
# least 100 ms.
#
# The margin is wide on purpose.  What separates a working sleep from a broken
# one here is the REQUESTED interval, not a fixed threshold: a broken
# implementation returns after a fork and an exec, which costs single-digit
# milliseconds, while a working one blocks for the full 200 ms.  A tighter
# threshold makes the probe a race against process-startup cost on a loaded
# machine - and a probe that flakes gets deleted, which is how the defect it
# guards comes back.  Being wrong in the remaining direction is safe: the
# fallback is the one-second floor, which is slow but correct.
_core_measures_as_sleep() {
  local impl=$1 t0 t1 saved=${SCOURSH_CAP_MSLEEP:-}
  SCOURSH_CAP_MSLEEP=$impl
  # A discarded warm-up round first.  The very first exec of an external `sleep`
  # can cost far more than the interval being measured (175 ms cold versus 7 ms
  # warm, measured), and a cold-start artifact would make a broken sleep look
  # like a working one - which is the single failure this probe exists to catch.
  msleep 1 || true
  t0=$(now_epoch_ns)
  msleep 200 || true
  t1=$(now_epoch_ns)
  SCOURSH_CAP_MSLEEP=$saved
  (( t1 - t0 >= 100000000 ))
}

# --- pattern engine ----------------------------------------------------------
# tension 2 pins both invocations so they exist in exactly one place: rg's
# defaults (respecting .gitignore, skipping hidden files) would silently skip the
# generated and vendored files most likely to hold a secret.
core_bind_engine() {
  if [[ $SCOURSH_ENGINE == rg ]]; then
    # tension 2 froze this invocation as `--binary=false`, which ripgrep
    # rejects ("unexpected argument for option '--binary'", measured on
    # ripgrep 15.1.0); `--no-binary` is the spelling that expresses the same
    # thing.  The register is corrected to match.
    SCOURSH_GREP=(rg --no-config --no-ignore --hidden --no-binary
      --engine default -n --no-heading --color never)
    SCOURSH_GREP_PCRE=(rg --no-config --no-ignore --hidden --no-binary
      --engine pcre2 -n --no-heading --color never)
    SCOURSH_GREP_PLAIN=(rg --no-config --no-ignore --hidden --no-binary
      --engine default -N --no-heading --color never)
  else
    SCOURSH_GREP=(grep -E -n)
    SCOURSH_GREP_PCRE=()
    SCOURSH_GREP_PLAIN=(grep -E)
  fi
}

# `scan_match OUTFILE ENGINE-ARGS...` - writes hits to $1.
# 0 = matched, 1 = no match, and anything at or above 2 is a hard error.
#
# tension 4 rule 2: bare grep/rg is forbidden repository-wide, because `|| true`
# discards the distinction between "no match" (the normal case) and "the engine
# failed" (a bad pattern, an unreadable file), and a broken rule that reports
# clean is the silent-coverage-hole failure this tool exists to prevent.
scan_match() {
  local out=$1
  shift
  local rc=0
  # An unbound engine array would expand to nothing, leaving a bare redirect
  # that succeeds and writes an empty file - "no match" for every rule, which is
  # the silent coverage hole this wrapper exists to prevent.
  (( ${#SCOURSH_GREP[@]} > 0 )) || die "$SCOURSH_EXIT_INCOMPLETE" "pattern engine is not bound"
  "${SCOURSH_GREP[@]+"${SCOURSH_GREP[@]}"}" "$@" >"$out" || rc=$?
  (( rc <= 1 )) || die "$SCOURSH_EXIT_INCOMPLETE" "pattern engine failed (rc=$rc): $*"
  return "$rc"
}

# As above, against the PCRE2 engine (tension 2; `pcre` records degrade rather
# than fail, so callers check core_has_pcre first).
scan_match_pcre() {
  local out=$1
  shift
  local rc=0
  core_has_pcre || die "$SCOURSH_EXIT_INCOMPLETE" "scan_match_pcre called with no PCRE2 engine"
  "${SCOURSH_GREP_PCRE[@]+"${SCOURSH_GREP_PCRE[@]}"}" "$@" >"$out" || rc=$?
  (( rc <= 1 )) || die "$SCOURSH_EXIT_INCOMPLETE" "PCRE pattern engine failed (rc=$rc): $*"
  return "$rc"
}

# `scan_match_offsets OUTFILE PATTERN FILE` - one `line:byteoffset:match` record
# per MATCH, not one per matching line.
#
# rules/RULE-FORMAT.md §10.3: tension 5 orders the `occurrence` ordinal by line
# and then by byte offset, and settles that one line yielding two matches yields
# two findings, so a bare `-n` (one record per matching line, no offsets) cannot
# produce the frozen ordinal.  `-n -b -o` is byte-identical between `rg` and
# `grep -E` (measured on ripgrep 15.1.0 and BSD grep 2.6.0-FreeBSD), which is
# what tension 2's parity requirement needs.
scan_match_offsets() {
  local out=$1 pattern=$2 file=$3
  scan_match "$out" -b -o -e "$pattern" -- "$file"
}

# `scan_match_stdin PATTERN` - reads the text on stdin and prints one line per
# MATCH.  Used by redact() (lib/findings.sh), which must apply the frozen §8.2
# regex dialect to a string held in memory.
#
# A pipe rather than a file is not an accident: tension 9 handling rule 2
# forbids raw matched text touching disk, and handling rule 1 forbids it being a
# command-line argument.  The pattern is the argument here; the text is stdin.
scan_match_stdin() {
  local rc=0
  (( ${#SCOURSH_GREP_PLAIN[@]} > 0 )) || die "$SCOURSH_EXIT_INCOMPLETE" "pattern engine is not bound"
  "${SCOURSH_GREP_PLAIN[@]+"${SCOURSH_GREP_PLAIN[@]}"}" -o -e "$1" || rc=$?
  (( rc <= 1 )) || die "$SCOURSH_EXIT_INCOMPLETE" "pattern engine failed (rc=$rc) on stdin match"
  return "$rc"
}

core_has_pcre() {
  if [[ -z ${SCOURSH_CAP_PCRE:-} ]]; then
    SCOURSH_CAP_PCRE=none
    if [[ ${#SCOURSH_GREP_PCRE[@]} -gt 0 ]] \
      && "${SCOURSH_GREP_PCRE[@]+"${SCOURSH_GREP_PCRE[@]}"}" -e 'a' /dev/null >/dev/null 2>&1; then
      SCOURSH_CAP_PCRE=rg-pcre2
    elif grep -P -e 'a' /dev/null >/dev/null 2>&1; then
      SCOURSH_CAP_PCRE=grep-P
      SCOURSH_GREP_PCRE=(grep -P -n)
    fi
    export SCOURSH_CAP_PCRE
  fi
  [[ $SCOURSH_CAP_PCRE != none ]]
}

# --- required commands -------------------------------------------------------
# Reports EVERY missing command at once: discovering four missing dependencies
# one run at a time is a bad first experience for an air-gapped install.
require_cmd() {
  local missing=() c
  for c in "$@"; do
    _have "$c" || missing+=("$c")
  done
  if (( ${#missing[@]} > 0 )); then
    die "$SCOURSH_EXIT_INPUT" "missing required command(s): ${missing[*]}"
  fi
}

core_require_baseline() {
  require_cmd grep sed awk sort tr cut find xargs mktemp date
  [[ $SCOURSH_CAP_SHA256 != none ]] \
    || die "$SCOURSH_EXIT_INPUT" "missing required command(s): one of sha256sum, shasum, openssl"
}

# --- exact-prefix lookup (tension 25) -----------------------------------------
# db_lookup_exact PREFIX FILE - the ONE implementation of the lookup primitive
# docs/FOUNDATION.md tension 25 freezes for `data/advisories.db`
# (`ecosystem\tpackage\tversion\t`) and, by the same tension's own note, for
# `data/versions.db` later: `LC_ALL=C look` on FILE when the capability probe
# above found it, falling back to `LC_ALL=C grep -F -m 1` when it did not.
#
# The asymmetry is deliberate and is tension 25's own wording, not an
# oversight here: `look` returns every line sharing the prefix (there can be
# more than one advisory for one exact package@version), while the `grep`
# fallback returns only the first.  A host without `look` degrades to
# "one advisory reported per exact version" rather than none, which is the
# conservative direction for a vulnerability scanner - and it is safe against
# a false match landing mid-line rather than at a real record boundary,
# because `data/advisories.db`'s own frozen schema forbids a TAB inside any
# field (tension 25), so the literal 3-tab PREFIX byte sequence can only ever
# occur at a genuine field boundary.
#
# This lives here, next to the SCOURSH_CAP_LOOK probe it reads, rather than in
# a module: it is the "one capability layer" (tension 24) call site for `look`
# and the one exemption tests/lint-shell.sh's "no bare grep" rule grants
# outside this file - a second implementation in modules/sca/ would be exactly
# the "ad hoc parser, subtly different" failure tension 24 exists to prevent.
#
# Returns the underlying command's own exit status: 0 with output when at
# least one line matched, 1 with no output otherwise. FILE must already be
# sorted under `LC_ALL=C` (tension 25) - this function does not sort it.
db_lookup_exact() {
  local prefix=$1 file=$2
  [[ -r $file ]] || return 1
  if [[ ${SCOURSH_CAP_LOOK:-none} == look ]]; then
    LC_ALL=C look -- "$prefix" "$file"
  else
    LC_ALL=C grep -F -m 1 -- "$prefix" "$file"
  fi
}

# ---------------------------------------------------------------------------
# 5. JSON string writer (tension 10)
# ---------------------------------------------------------------------------
# The single writer.  No string is ever interpolated into JSON at a call site;
# tests/lint-shell.sh fails on it.
json_string() {
  local s=$1 out ch i n
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  # A bash string can never contain NUL, so the scan starts at 0x01.
  if [[ $s != *[$'\x01'-$'\x1f'$'\x7f']* ]]; then
    printf '"%s"' "$s"
    return 0
  fi
  out=''
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    case $ch in
      $'\n') out+='\n' ;;
      $'\r') out+='\r' ;;
      $'\t') out+='\t' ;;
      $'\b') out+='\b' ;;
      $'\f') out+='\f' ;;
      [$'\x01'-$'\x1f'$'\x7f']) out+=$(printf '\\u%04x' "'$ch") ;;
      *) out+=$ch ;;
    esac
  done
  printf '"%s"' "$out"
}

json_number() {
  local v=$1
  if [[ $v =~ ^-?(0|[1-9][0-9]*)(\.[0-9]+)?$ ]]; then
    printf '%s' "$v"
  else
    printf '%s' 'null'
  fi
}

json_bool() {
  if [[ $1 == true || $1 == 1 ]]; then printf 'true'; else printf 'false'; fi
}

# ---------------------------------------------------------------------------
# 6. The run directory (finding F12)
# ---------------------------------------------------------------------------
# Finding shards and the unit journal live HERE, not in the scratch directory,
# and unconditionally rather than under --keep-shards.  They were in the scratch
# directory, which the EXIT trap erases - including on SIGTERM, the very signal
# tension 18's own resume test uses - so resume could not read the shards it is
# defined to read.  The scratch directory now holds only genuinely transient
# data: scan_match line files, mutexes, and the rate/budget/breaker state.
run_init() {
  local dir=$1
  SCOURSH_RUN_DIR=$(realpath_of "$dir")
  mkdir -p "$SCOURSH_RUN_DIR"/{shards,units,meta,inventory,locations}
  export SCOURSH_RUN_DIR
  # Who owns the run's own report files.  Deliberately NOT exported, for the
  # same reason SCOURSH_SCRATCH_OWNER is not: an `xargs -P` worker inherits
  # SCOURSH_RUN_DIR and appends its own facts under meta/, but must never
  # rewrite run.json underneath the process that is still running the scan
  # (run_json_refresh_incomplete reads this).
  _SCOURSH_RUN_OWNER=$$
  _SCOURSH_RUN_JSON_REFRESHED=0
  : "${SCOURSH_RUN_ID:=$(basename -- "$SCOURSH_RUN_DIR")}"
  export SCOURSH_RUN_ID
  # One timestamp per run, shared by every finding it emits.  Per-finding
  # now_iso() would make two identical scans differ in every line, which is
  # exactly the byte-reproducibility tension 17 requires of the merged output.
  SCOURSH_RUN_TIMESTAMP=$(now_iso)
  export SCOURSH_RUN_TIMESTAMP
  run_record started_at "$SCOURSH_RUN_TIMESTAMP"
  run_record started_epoch "$(now_epoch)"
}

# Append a run-level fact.  Workers may call this concurrently, so each fact is
# its own file under meta/ and each append is a single short line, well below
# PIPE_BUF (tension 17's reasoning applied to a much smaller record).
run_record() {
  local key=$1
  shift
  [[ -n ${SCOURSH_RUN_DIR:-} && -d ${SCOURSH_RUN_DIR:-}/meta ]] || return 0
  printf '%s\n' "$(_redact_out "$*")" >>"$SCOURSH_RUN_DIR/meta/$key"
  return 0
}

run_facts() {
  local key=$1
  [[ -n ${SCOURSH_RUN_DIR:-} && -f $SCOURSH_RUN_DIR/meta/$key ]] || return 0
  cat -- "$SCOURSH_RUN_DIR/meta/$key"
}

# `run_fact_first_set VARNAME KEY` - the FIRST line of a run fact, for the keys
# that hold a single value rather than an append-only list
# (`authorization_affirmed`, `contact`, ...).  Yields the empty string, with
# status 0, when there is no run directory or no such fact: "not recorded" is a
# normal state for every caller of this, never an error, because a caller that
# never went through scan.sh's parser (the DAST smoke test, an interactive
# `source lib/http.sh`) legitimately has none.
#
# It SETS a variable rather than printing one, for the reason this file's own
# `worker_id_set` and `_lock_owner_line_set` are written that way: `$(...)`
# forks a subshell, and lib/http.sh reads several of these on EVERY request
# (the User-Agent's two halves and the affirmation, four times over for the
# four limit keys).  Written as an accessor, that is a handful of forks per
# request in the one path this codebase already counts them in; written as a
# setter, it is a builtin `read` and no fork at all.
#
# `printf -v` rather than `read -r "$__var"`: a here-string would materialise a
# temp file, which is the cost this is avoiding.
run_fact_first_set() {
  local __var=$1 __key=$2 __v=''
  if [[ -n ${SCOURSH_RUN_DIR:-} && -r $SCOURSH_RUN_DIR/meta/$__key ]]; then
    IFS= read -r __v <"$SCOURSH_RUN_DIR/meta/$__key" || true
  fi
  printf -v "$__var" '%s' "$__v"
}

# The per-worker shard id: $BASHPID plus the work-unit index, so it stays unique
# even if a pid is recycled (tension 17).
#
# It SETS a variable rather than printing one, and must be called in the current
# shell.  `wid=$(worker_id)` would evaluate $BASHPID inside the command
# substitution's subshell, which has a different pid on every call, so every
# finding would land in a shard of its own.
worker_id_set() {
  SCOURSH_WORKER_ID="$BASHPID-${SCOURSH_UNIT_INDEX:-0}"
  export SCOURSH_WORKER_ID
}

# `core_capture VARNAME CMD [ARGS...]` - run CMD with its stdout captured into
# VARNAME, WITHOUT ever wrapping the call in `$(...)`.
#
# The distinction is load-bearing rather than stylistic, and it is the same one
# `_scan_require_readable_path` in scan.sh documents at length: `die` inside a
# command substitution runs in a SUBSHELL, so its `trap - ERR` clears only that
# subshell's trap and its `exit` only ends the subshell.  The parent's ERR trap
# then fires on the failed assignment and prints a crash-shaped "command
# failed" diagnostic on top of the real message, and in a checked context
# (`||`, an `if` condition) the abort is swallowed entirely.  A plain output
# redirection does not fork a subshell, so CMD runs in the CURRENT shell and a
# `die` inside it aborts for real.
#
# scan.sh's own `_scan_capture` is this same helper, written before lib/core.sh
# had one; whoever next touches scan.sh should delete it and call this.
core_capture() {
  local __var=$1
  shift
  local __tmp=$SCOURSH_SCRATCH/_core_capture.$BASHPID
  "$@" >"$__tmp"
  # The config accessors print with `printf '%s'` and no trailing newline, for
  # which `read` returns 1 at EOF even though it captured the line.  Appending
  # one restores the normal contract without masking a real failure: CMD has
  # already run, and would have died above if it failed.
  printf '\n' >>"$__tmp"
  # SC2229: "$__var" is deliberately the INDIRECT target - read into the
  # variable NAMED by __var's value, the standard idiom for this (bash 4.2 has
  # no `local -n` nameref, per tension 24's frozen minimum).
  # shellcheck disable=SC2229
  IFS= read -r "$__var" <"$__tmp"
  rm -f "$__tmp"
  return 0
}

# ---------------------------------------------------------------------------
# 7. Scratch directory, cleanup, and traps (tension 4, finding F13)
# ---------------------------------------------------------------------------
# The guard is on scratch-dir OWNERSHIP, not on subshell-ness.
#
# The frozen rule was `cleanup() { [[ $BASHPID == $$ ]] || return 0; ... }`, and
# it is wrong in both directions.  Bash resets trapped EXIT actions in subshells,
# so `( ... )`, `$( ... )` and `( ... ) &` never run the handler and the guard
# defends a case that cannot occur.  Meanwhile an `xargs -P` worker is a fresh
# process, where `$BASHPID == $$` is TRUE, so the guard passes and the first
# worker to finish erases the shared scratch directory - the rate limiter, the
# budget counter, the breaker state, the AWS cache - while the run is still
# using it.  Both halves were measured; tests/suites/core.sh reproduces them.
#
# SCOURSH_SCRATCH is exported so workers use the parent's directory.
# SCOURSH_SCRATCH_OWNER is deliberately NOT exported, so a worker cannot
# inherit ownership, and the on-disk marker is checked as well so that a
# manually re-exported value still cannot make a worker the owner.
scratch_init() {
  if [[ -n ${SCOURSH_SCRATCH:-} && -d ${SCOURSH_SCRATCH:-} ]]; then
    return 0            # inherited from the parent: never create our own
  fi
  local d
  d=$(tmpdir_make)
  chmod 700 "$d"
  mkdir -p "$d/mx"
  printf '%s\n' "$$" >"$d/.owner"
  SCOURSH_SCRATCH=$d
  export SCOURSH_SCRATCH
  SCOURSH_SCRATCH_OWNER=$$      # NOT exported: ownership does not inherit
}

scratch_is_owned_here() {
  [[ -n ${SCOURSH_SCRATCH:-} && -d ${SCOURSH_SCRATCH:-} ]] || return 1
  [[ ${SCOURSH_SCRATCH_OWNER:-} == "$$" ]] || return 1
  local recorded=''
  [[ -r $SCOURSH_SCRATCH/.owner ]] || return 1
  IFS= read -r recorded <"$SCOURSH_SCRATCH/.owner" || true
  [[ $recorded == "$$" ]]
}

core_cleanup() {
  local status=$?
  if [[ -n ${_SCOURSH_SLEEPFD:-} ]]; then
    exec {_SCOURSH_SLEEPFD}>&- 2>/dev/null || true
    _SCOURSH_SLEEPFD=''
  fi
  if scratch_is_owned_here; then
    erase_dir "$SCOURSH_SCRATCH"
  fi
  return "$status"
}

core_on_err() {
  local status=$1 line=$2 src=$3 cmd=$4
  # Nothing here may itself fail (tension 4 rule 5), so it is printf only.
  printf '%s error scoursh: command failed (status %s) at %s:%s: %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" "$src" "$line" "$cmd" >&2
  return "$status"
}

core_on_signal() {
  local sig=$1
  SCOURSH_SIGNALLED=$sig
  export SCOURSH_SIGNALLED
  run_record incomplete_reason "run interrupted by SIG$sig"
  # Same exit-5 contract as `die`: an interrupted run must not leave a report
  # claiming it completed (see run_json_refresh_incomplete).
  run_json_refresh_incomplete
  # Exiting runs the EXIT trap, which is what erases the scratch dir; the run
  # directory (shards and the unit journal) is untouched, which is what makes
  # tension 18's resume possible at all (finding F12).
  exit "$SCOURSH_EXIT_INCOMPLETE"
}

core_install_traps() {
  trap 'core_on_err "$?" "$LINENO" "${BASH_SOURCE[0]}" "$BASH_COMMAND"' ERR
  trap core_cleanup EXIT
  trap 'core_on_signal INT' INT
  trap 'core_on_signal TERM' TERM
  trap 'core_on_signal HUP' HUP
}

# ---------------------------------------------------------------------------
# 8. The cross-process mutex (tension 16, finding F15)
# ---------------------------------------------------------------------------
# `xargs -P` gives N independent processes and shell variables are per-process,
# so the rate limiter, request budget, circuit breaker, and AWS cache all live in
# files guarded by this mutex.  It is built on mkdir, which is atomic on every
# POSIX filesystem and needs no external binary (flock(1) is util-linux and is
# absent on macOS and BSD).
#
# Finding F15: the frozen reclaim path was `if lock_is_stale "$d"; then rm -rf
# "$d"; continue; fi`, which can delete a LIVE lock - two waiters both judge one
# lock stale, the first reclaims it and acquires, and the second's `rm -rf` then
# deletes the first's freshly acquired lock, putting two processes in the
# critical section.  Reclaim is now single-winner and identity-bound, and
# lock_is_stale is specified rather than asserted.
: "${SCOURSH_LOCK_STALE_SECONDS:=30}"
: "${SCOURSH_MUTEX_TIMEOUT_SECONDS:=120}"
: "${SCOURSH_MUTEX_TICK_MS:=50}"

_mutex_dir() { printf '%s/mx/%s.lock' "$SCOURSH_SCRATCH" "$1"; }

# Reads a lock's owner line into _LOCK_OWNER_LINE, or leaves it empty when the
# file cannot be read for any reason.
#
# ONE operation, never a `[[ -r $d/owner ]]` test followed by a separate open.
# That pair is a check-then-open race against the lock's own holder: releasing
# a lock removes the whole directory, so under real contention the open lands
# after the owner file is gone and bash reports the failed redirect on the
# run's stderr - on a path that is otherwise entirely correct, because an
# unreadable owner file is exactly the "published lock with no owner file yet"
# case tension 16 already decides (fall through to the mtime branch, not
# stale).  Measured before this was fixed: eight processes taking and
# releasing one mutex 40 times each produced 16 such diagnostics across 6
# runs, and lib/http.sh's rate limiter - the first code here to take this
# mutex once per request from several processes - surfaced it on its first
# concurrent run.
#
# The stderr redirect is on the GROUP, not on the `read`.  Redirections are
# applied left to right, so a trailing `2>/dev/null` is established only after
# the input redirect has already failed and does not suppress it; the two
# failure shapes (a redirect that cannot open, and a `read` that cannot read
# what it opened) also report through different paths, and the group catches
# both.
#
# It SETS a variable rather than printing one, so it costs no fork on the
# mutex's hot path - the same reason worker_id_set does.
_lock_owner_line_set() {
  _LOCK_OWNER_LINE=''
  { IFS= read -r _LOCK_OWNER_LINE <"$1/owner"; } 2>/dev/null || true
  return 0
}

# The identity token of a lock instance: the owner it published, or its
# creation time when it has not published one yet.  Two different holders of one
# lock path can never produce the same token.
_lock_token() {
  local d=$1 line mtime
  _lock_owner_line_set "$d"
  line=$_LOCK_OWNER_LINE
  if [[ -n $line ]]; then
    printf 'owner:%s' "$line"
    return 0
  fi
  mtime=$(stat_mtime "$d" 2>/dev/null || printf '%s' 0)
  printf 'noowner:%s' "${mtime:-0}"
}

# Specified, not asserted.  A lock is reclaimable only when BOTH hold:
#
#   (a) it has been held for at least lock_stale_seconds, and
#   (b) the process that published it is no longer alive.
#
# Requiring both is what bounds pid reuse: a recycled pid belonging to some
# unrelated live process makes the lock look held, so the run waits and then
# fails loud on the mutex timeout rather than entering a critical section
# someone else may be in.  Age is measured from the timestamp the owner
# recorded, never from filesystem mtime, so a `touch` cannot extend a lock.
#
# The window between `mkdir` and the owner file being written is decided rather
# than left undefined: a published lock with no owner file is NOT stale until it
# is older than lock_stale_seconds by its directory mtime.  Treating it as stale
# would let a waiter delete a lock acquired microseconds earlier by a live
# holder; treating it as never stale would wedge the run if a holder died inside
# that window.
lock_is_stale() {
  local d=$1 now line pid='' ts='' mtime
  [[ -d $d ]] || return 1
  now=$(now_epoch)
  # One read attempt, never a readability test followed by an open: see
  # _lock_owner_line_set.  An empty line covers "no owner file", "the holder
  # released it while we were looking", and "it could not be read", which the
  # mtime branch below already decides identically.
  _lock_owner_line_set "$d"
  line=$_LOCK_OWNER_LINE
  if [[ -n $line ]]; then
    pid=${line%% *}
    ts=${line##* }
    [[ $pid =~ ^[0-9]+$ && $ts =~ ^[0-9]+$ ]] || return 1
    (( now - ts >= SCOURSH_LOCK_STALE_SECONDS )) || return 1
    proc_alive "$pid" && return 1
    return 0
  fi
  mtime=$(stat_mtime "$d" 2>/dev/null || printf '%s' '')
  [[ $mtime =~ ^[0-9]+$ ]] || return 1
  (( now - mtime >= SCOURSH_LOCK_STALE_SECONDS ))
}

# Single-winner, identity-bound reclaim.
#
# The claim marker's name embeds the token of the instance being reclaimed, so
# only one process can ever reclaim a given lock instance, and a process that
# judged an OLD instance stale cannot delete a NEW one: it re-verifies the token
# inside the claim and declines when it has changed.
#
# An abandoned claim (the reclaimer killed inside the microseconds it takes to
# remove a small directory) is itself reclaimed by the same staleness test, so
# the recovery path terminates.  Recovery cannot produce double occupancy,
# because deleting the lock still requires winning `mkdir` on the claim and
# re-verifying the token.
_lock_reclaim() {
  local d=$1 token=$2 claim slug
  slug=$(_token_slug "$token")
  claim="$d.rcl.$slug"
  if [[ -d $claim ]] && lock_is_stale "$claim"; then
    if rm -rf -- "$claim" 2>/dev/null; then :; fi
  fi
  mkdir "$claim" 2>/dev/null || return 1
  printf '%s %s\n' "$$" "$(now_epoch)" >"$claim/owner"
  if [[ $(_lock_token "$d") == "$token" ]]; then
    if rm -rf -- "$d" 2>/dev/null; then :; fi
  fi
  if rm -rf -- "$claim" 2>/dev/null; then :; fi
  return 0
}

_token_slug() {
  local t=$1
  t=${t//\//_}
  t=${t//[^A-Za-z0-9_.:-]/_}
  printf '%s' "$t"
}

mutex_acquire() {
  local name=$1 d waited=0 ticks token
  d=$(_mutex_dir "$name")
  mkdir -p "$SCOURSH_SCRATCH/mx"
  ticks=$(( SCOURSH_MUTEX_TIMEOUT_SECONDS * 1000 / SCOURSH_MUTEX_TICK_MS ))
  while ! mkdir "$d" 2>/dev/null; do
    token=$(_lock_token "$d")
    if lock_is_stale "$d"; then
      if _lock_reclaim "$d" "$token"; then continue; fi
    fi
    msleep "$SCOURSH_MUTEX_TICK_MS"
    waited=$(( waited + 1 ))
    (( waited < ticks )) || die "$SCOURSH_EXIT_INCOMPLETE" "mutex timeout: $name"
  done
  printf '%s %s\n' "$BASHPID" "$(now_epoch)" >"$d/owner"
  return 0
}

mutex_release() {
  local d
  d=$(_mutex_dir "$1")
  if rm -rf -- "$d" 2>/dev/null; then :; fi
  return 0
}

# ---------------------------------------------------------------------------
# 9. Small helpers
# ---------------------------------------------------------------------------

# tension 12's frozen scan-root recipe.  Reads a config value rather than the
# object graph, so it is defined for a commit-less repository, independent of
# clone depth and of which refs were fetched, and never contains a credential.
scan_root_of() {
  local p=$1 resolved root
  resolved=$(realpath_of "$p")
  root=''
  if _have git; then
    root=$(git -C "$resolved" rev-parse --show-toplevel 2>/dev/null || printf '%s' '')
  fi
  if [[ -n $root ]]; then printf '%s' "$root"; else printf '%s' "$resolved"; fi
}

scan_root_id_of() {
  local resolved root url is_git=0
  resolved=$(realpath_of "$1")
  if _have git && git -C "$resolved" rev-parse --show-toplevel >/dev/null 2>&1; then
    is_git=1
  fi
  root=$(scan_root_of "$resolved")
  if (( is_git == 0 )); then
    printf 'path:%s' "$resolved"
    return 0
  fi
  url=''
  # `git config --local --get` exits 1 when unset, so it must sit in a condition
  # context under `set -e` (tension 4 rule 3).  `--local` matters: `--get` alone
  # also reads global config, and a stray global remote.origin.url collides two
  # unrelated remote-less repositories onto one id.  `git remote get-url` is NOT
  # equivalent and must not be substituted: it applies insteadOf rewriting and
  # returns the first url of a multi-url remote.
  if url=$(git -C "$root" config --local --get remote.origin.url 2>/dev/null); then :; else url=''; fi
  url=${url%/}
  url=${url%.git}
  url=$(_strip_userinfo "$url")
  if [[ -n $url ]]; then
    printf 'git-remote:%s' "$url"
  else
    printf 'git-local:%s' "$root"
  fi
}

# scan_root_id MUST NOT contain credentials: it is written to state/, to
# run.json and into run_identity, and a GitLab runner's default clone URL is
# https://gitlab-ci-token:<TOKEN>@host/org/proj.git.
# Userinfo is by definition the component before the AUTHORITY's terminating
# delimiter, so the authority is split off before stripping.  Stripping to the
# first `@` anywhere discarded the host and the leading path whenever a
# repository path contained one - and `scan_root_id` is a persisted
# cell-comparability key, so two unrelated repositories whose paths share a
# suffix would collapse onto one id and their `path-root` cells would become
# wrongly comparable, defeating tension 12 for them.
_strip_userinfo() {
  local u=$1 scheme rest authority path before
  case $u in
    *://*@*)
      scheme=${u%%://*}
      rest=${u#*://}
      authority=${rest%%/*}
      if [[ $rest == */* ]]; then path=/${rest#*/}; else path=''; fi
      authority=${authority#*@}          # only within the authority
      printf '%s://%s%s' "$scheme" "$authority" "$path"
      ;;
    *@*:*)
      # scp-like `user@host:path`.  The userinfo terminates at the first `:`, so
      # an `@` after it is path content.
      before=${u%%:*}
      if [[ $before == *@* ]]; then
        printf '%s' "${u#*@}"
      else
        printf '%s' "$u"
      fi
      ;;
    *) printf '%s' "$u" ;;
  esac
}

# tension 12: the cell string for a path-scoped run.  "." when the resolved path
# is the scan root, never the empty string.
path_root_cell() {
  local resolved root rel
  resolved=$(realpath_of "$1")
  root=$(scan_root_of "$resolved")
  if [[ $resolved == "$root" ]]; then
    printf '%s' '.'
    return 0
  fi
  rel=${resolved#"$root"/}
  rel=${rel%/}
  printf '%s' "${rel:-.}"
}

scoursh_version() {
  local f=${SCOURSH_INSTALL_ROOT:-}/VERSION v='unknown'
  if [[ -r $f ]]; then
    IFS= read -r v <"$f" || true
  fi
  printf '%s' "${v:-unknown}"
}

# ---------------------------------------------------------------------------
# 10. Initialisation
# ---------------------------------------------------------------------------
# The install root is the directory containing scan.sh - tension 26's *install
# root*, which is a different thing from tension 12's *scan root* and is never
# called the repository root.
if [[ -z ${SCOURSH_INSTALL_ROOT:-} ]]; then
  SCOURSH_INSTALL_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
  export SCOURSH_INSTALL_ROOT
fi

# Order matters: the scratch directory must exist before the msleep probe, whose
# FIFO fallback lives in it.  scratch_init is a no-op in a worker, which
# inherits SCOURSH_SCRATCH from the parent and must never create its own.
scratch_init
core_probe_capabilities
core_install_traps
