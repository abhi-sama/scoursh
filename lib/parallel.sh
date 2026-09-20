#!/usr/bin/env bash
# lib/parallel.sh - bounded worker fan-out for the tree-walking modules
# (docs/DESIGN.md §5's `--jobs N`, docs/FOUNDATION.md tension 17).
#
# WHAT THIS FILE IS FOR.  `--jobs N` has been accepted, validated and
# documented since step 2, and until this file existed every SAST, SCA and IaC
# scan was single-worker regardless of it - each module said so honestly with a
# `single_worker_no_parallel_scan_yet` coverage_reduction rather than claiming a
# parallelism it did not have.  This is the mechanism that makes the flag real
# for those three modules.  DAST is deliberately NOT a consumer: `lib/http.sh`
# already reads the resolved `jobs` value as an in-flight CONNECTION ceiling
# (section 11b), which is a different meaning of the same number, and nothing
# here touches it.
#
# THIS FILE SOURCES NOTHING, DELIBERATELY - the same leaf property
# modules/dast/passive/response_engine.sh's own header defends and for the same
# measured reason: `shellcheck -x` re-expands every source edge it follows and
# does not memoise, so one edge added here is paid for once per consumer, and
# this file is reached from modules/sast/engine.sh, which is itself on the
# source path of every IaC and SCA entry point and every DAST phase test.  It
# calls `run_record`, `log_warn` and `die` BY NAME; every caller already has
# lib/core.sh loaded long before it reaches a tree walk.
#
# ---------------------------------------------------------------------------
# THE DETERMINISM CONTRACT, which is the whole difficulty
# ---------------------------------------------------------------------------
# A run at `--jobs 4` must produce byte-identical `findings.jsonl`, `run.json`,
# `report.md` and `report.html` to the same run at `--jobs 1`.  Three separate
# things could break that, and each is closed by construction here rather than
# by hoping the scheduler cooperates:
#
#   1. FINDINGS.  A worker writes only to its own shard
#      (`reports/<run>/shards/<worker-id>.fields`, keyed on `$BASHPID` via
#      lib/core.sh's `worker_id_set`), never to a shared file - tension 17.
#      `findings_merge` then sorts every shard together under `LC_ALL=C` by
#      (module, check_id, fingerprint) and dedups on fingerprint, so the merged
#      order is a pure function of the finding SET and carries no trace of
#      which worker found what, or when.  Nothing extra is needed here for
#      findings; this note exists so a later change does not "optimise" a
#      worker into appending to a shared file.
#
#   2. RUN FACTS (`meta/<key>`, and so `run.json`/`report.md`/`report.html`).
#      This is the half that a naive fan-out gets wrong, silently and in the
#      direction that still passes a findings-only test.  `run_record` appends a
#      line to `meta/<key>`, and lib/report.sh renders several of those keys -
#      `coverage_reduction`, `coverage_gap`, `notes`, `incomplete_reason` - in
#      FILE ORDER, not sorted (`_meta_array`, as against `_meta_array_unique`).
#      Concurrent appends from N workers therefore interleave differently on
#      every run and `run.json` stops being byte-reproducible, which is exactly
#      the audit-record claim docs/DESIGN.md §4 makes.  The fix is that a worker
#      never writes to `meta/` at all: `parallel_map` points each worker's
#      `SCOURSH_META_DIR` at a private per-worker directory under the scratch
#      dir (lib/core.sh's `run_record` honours that override), and the parent
#      concatenates them back, worker 0 first, once every worker has exited.
#
#   3. UNIT ORDER WITHIN A KEY.  Concatenating per-worker files in worker order
#      only reproduces the single-worker order if worker i's units all precede
#      worker i+1's in the walk.  That is why the partition is CONTIGUOUS BLOCKS
#      of the already-sorted unit list, never round-robin and never work-stealing:
#      block partitioning makes "the parent's concatenation equals the
#      single-worker walk order" true by construction, for every key, without any
#      per-line sequence number to sort on afterwards.  The cost is accepted and
#      is load imbalance when unit sizes are skewed; the benefit is that
#      determinism is a property of the shape rather than of a sort that a
#      future key could forget to apply.  Do not "improve" the balance by
#      interleaving without also giving every meta line a global ordinal.
#
# ---------------------------------------------------------------------------
# WHY `( ) &` SUBSHELLS AND NOT `xargs -P`
# ---------------------------------------------------------------------------
# docs/FOUNDATION.md tension 16 and 17 are written in terms of `xargs -P`
# workers, and the shard/mutex machinery they specify is exactly what makes
# either shape safe.  A forked subshell is chosen here because it inherits the
# already-loaded rule registry, the check index, the parsed config and every
# `lib/*.sh` function in memory, so the fan-out costs one `fork` per worker and
# not one full re-bootstrap of scan.sh per worker - which for a tree walk whose
# whole point is to be faster would be most of the speed-up spent on start-up.
# Two consequences, both measured on this codebase rather than assumed:
#
#   * Bash does NOT run a trapped `EXIT` action in a subshell (AGENTS.md's own
#     "things measured on this codebase" list, re-verified here), so a worker
#     cannot fire `core_cleanup` and erase the shared scratch dir out from under
#     its siblings.  That matters because `$$` stays the PARENT's pid inside a
#     subshell and `SCOURSH_SCRATCH_OWNER` is inherited, so `scratch_is_owned_here`
#     would answer TRUE in a worker - the guard that protects an `xargs -P`
#     worker (a fresh process, different `$$`) is not the guard protecting this
#     one.  Do not add an explicit `trap core_cleanup EXIT` to a worker.
#   * The `ERR` trap and `set -Eeuo pipefail` ARE inherited, so a worker that
#     fails, or that `die`s, exits non-zero and the parent's `wait` sees it.
#     That is what makes worker failure surfaceable at all - see
#     `PARALLEL_FAILED` below.
#
# Concurrency is bounded by forking exactly `PARALLEL_WORKERS` subshells and
# waiting for all of them, never more: `wait -n` (which a rolling pool would
# need) is bash 4.3, and lib/core.sh enforces a 4.2 minimum (tension 24).
#
# shellcheck shell=bash

[[ -n ${SCOURSH_PARALLEL_SOURCED:-} ]] && return 0
SCOURSH_PARALLEL_SOURCED=1

# ---------------------------------------------------------------------------
# 1. Results a caller reads after `parallel_map`
# ---------------------------------------------------------------------------
# PARALLEL_WORKERS  - how many workers actually ran (1 means the units were
#                     scanned inline in the current shell, with no fork at all).
# PARALLEL_FAILED   - how many of them exited non-zero.
declare -g PARALLEL_WORKERS=1
declare -g PARALLEL_FAILED=0

# `SCOURSH_WORKER_AUX` is the private per-worker directory a callback may write
# side-channel state into (a partial counter table, say) for the parent to fold
# back in.  It is EMPTY in the inline single-worker case, which is what tells a
# callback to update the in-process table directly instead.
declare -g SCOURSH_WORKER_AUX=''

# ---------------------------------------------------------------------------
# 2. Worker count
# ---------------------------------------------------------------------------
# `parallel_workers_for JOBS TOTAL` - SETS PARALLEL_WORKERS rather than printing
# it, for the reason lib/core.sh's own `worker_id_set` is written that way: a
# `$(...)` capture forks, and this is called on every tree walk.
#
# Never more workers than units - N workers over N-1 units means one worker with
# nothing to do and a fork spent for it - and never more than the resolved
# `jobs`.  A non-numeric or absent JOBS falls back to 1 rather than to the
# documented default of 4: this function is reached from module code that may be
# exercised standalone with no scan.sh parser anywhere in the path (every
# tests/suites/{sast,iac,sca}.sh case does exactly that), and silently running
# such a caller 4-way is a behaviour change it never asked for.  scan.sh's own
# `SCOURSH_JOBS` is always populated, from lib/config.sh's `jobs` default of 4.
parallel_workers_for() {
  local jobs=${1:-} total=${2:-0}
  [[ $jobs =~ ^[1-9][0-9]*$ ]] || jobs=1
  [[ $total =~ ^[0-9]+$ ]] || total=0
  PARALLEL_WORKERS=$jobs
  (( PARALLEL_WORKERS <= total )) || PARALLEL_WORKERS=$total
  (( PARALLEL_WORKERS >= 1 )) || PARALLEL_WORKERS=1
}

# ---------------------------------------------------------------------------
# 3. Block bounds
# ---------------------------------------------------------------------------
# `parallel_block_bounds TOTAL NWORKERS INDEX` - SETS PARALLEL_BLOCK_START (a
# 0-based offset into the unit list) and PARALLEL_BLOCK_COUNT.
#
# The first `TOTAL % NWORKERS` blocks are one unit longer than the rest, so
# every unit is assigned exactly once and no block is empty while another is
# two longer.  "Exactly once" is the honesty property: a unit assigned twice is
# a double-counted finding that the fingerprint dedup would then silently hide,
# and a unit assigned to nobody is a silent false negative.
declare -g PARALLEL_BLOCK_START=0
declare -g PARALLEL_BLOCK_COUNT=0
parallel_block_bounds() {
  local total=$1 nw=$2 idx=$3
  local base=$(( total / nw )) rem=$(( total % nw ))
  if (( idx < rem )); then
    PARALLEL_BLOCK_COUNT=$(( base + 1 ))
    PARALLEL_BLOCK_START=$(( idx * (base + 1) ))
  else
    PARALLEL_BLOCK_COUNT=$base
    PARALLEL_BLOCK_START=$(( rem * (base + 1) + (idx - rem) * base ))
  fi
}

# ---------------------------------------------------------------------------
# 4. The fan-out itself
# ---------------------------------------------------------------------------
# `parallel_map JOBS TOTAL FN [ARGS...]` - runs FN over TOTAL units, split into
# contiguous blocks, with at most the resolved JOBS running at once.  FN is
# called as:
#
#     FN START COUNT [ARGS...]
#
# with START a 0-based offset into the caller's own unit list and COUNT the
# number of units from it this call owns.  FN therefore never learns its worker
# index, which is deliberate: a callback that cannot see which worker it is
# cannot make its OUTPUT depend on that, which is half of the determinism
# contract above enforced by the interface rather than by review.
#
# IT ALWAYS RETURNS 0, AND REPORTS A FAILED WORKER ONLY THROUGH
# `PARALLEL_FAILED`.  That is not a style choice and the obvious alternative is
# a measured bug: returning non-zero forces every caller to write
# `parallel_map ... || rc=1`, and a function invoked in a `||` context has
# `set -e` SUSPENDED for its whole call tree - including, on the single-worker
# path, the callback itself and every per-file scan under it.  So the shape that
# looks like careful error handling would silently switch off `set -Eeuo
# pipefail` across the entire `--jobs 1` walk, which is the code path this
# change is otherwise at pains to leave byte-for-byte alone.  Measured directly:
# under `outer || rc=1`, a bare `false` deep inside `outer`'s callee does not
# abort and execution continues past it.  Every caller therefore invokes this
# BARE and tests `PARALLEL_FAILED` afterwards - the same "set a variable rather
# than return one" shape `occurrence_next` and `worker_id_set` already use, and
# for a related reason.
#
# It never `die`s on a worker failure either - deciding what a partial walk
# means (tension 14 puts it at exit 5, "unplanned incompleteness", with an
# `incomplete_reason`) belongs to the module, which is the only layer that knows
# what coverage it can still honestly claim.
#
# ONE WORKER IS RUN INLINE, IN THE CURRENT SHELL, WITH NO FORK AND NO PRIVATE
# META DIRECTORY.  That is not only an optimisation for the `--jobs 1` case: it
# is what makes `--jobs 1` byte-for-byte the code path this module has always
# had, so the parallel work can never regress it, and it is the reference the
# `--jobs 4` output is asserted against.
parallel_map() {
  local jobs=$1 total=$2 fn=$3
  shift 3

  PARALLEL_FAILED=0
  # Cleared at ENTRY, not only on the fork path: `parallel_aux_read` reads
  # whatever pool the LAST fan-out left behind, so an inline call that merely
  # declined to set one would hand a caller the previous walk's aux files as if
  # they were its own.  An inline callback has no aux directory by design and
  # must therefore see nothing.
  SCOURSH_PARALLEL_POOL=''
  parallel_workers_for "$jobs" "$total"
  (( total > 0 )) || { PARALLEL_WORKERS=1; return 0; }

  if (( PARALLEL_WORKERS <= 1 )); then
    PARALLEL_WORKERS=1
    SCOURSH_WORKER_AUX=''
    "$fn" 0 "$total" "$@"
    return 0
  fi

  local pool=$SCOURSH_SCRATCH/parallel.$$.$RANDOM
  mkdir -p "$pool"

  local i
  local -a pids=()
  for (( i = 0; i < PARALLEL_WORKERS; i++ )); do
    parallel_block_bounds "$total" "$PARALLEL_WORKERS" "$i"
    (( PARALLEL_BLOCK_COUNT > 0 )) || continue
    mkdir -p "$pool/w$i/meta"
    # The subshell inherits everything already in memory - the rule registry,
    # the check index, the resolved config - so a worker costs one fork and no
    # re-bootstrap.  `SCOURSH_META_DIR` is what keeps its run_record appends out
    # of the shared meta/ directory (see the determinism contract above);
    # `SCOURSH_WORKER_AUX` is where a callback puts anything the parent has to
    # fold back in by hand.  Both are plain assignments inside the subshell, so
    # the parent's own values are untouched.
    (
      # SC2034: both are read by OTHER files across the source boundary -
      # SCOURSH_META_DIR by lib/core.sh's run_record, SCOURSH_WORKER_AUX by the
      # module callback - which shellcheck cannot see from here.  The same
      # disable lib/checks.sh already carries for its own cross-file globals.
      # shellcheck disable=SC2034
      SCOURSH_META_DIR=$pool/w$i/meta
      # shellcheck disable=SC2034
      SCOURSH_WORKER_AUX=$pool/w$i
      "$fn" "$PARALLEL_BLOCK_START" "$PARALLEL_BLOCK_COUNT" "$@"
    ) &
    pids+=($!)
  done

  local p
  for p in "${pids[@]+"${pids[@]}"}"; do
    wait "$p" || PARALLEL_FAILED=$(( PARALLEL_FAILED + 1 ))
  done

  _parallel_merge_meta "$pool"
  SCOURSH_PARALLEL_POOL=$pool
  return 0
}

# `parallel_pool_dir` - the pool directory of the fan-out that just finished, so
# a caller can read its workers' aux files before `parallel_cleanup` removes
# them.  Empty when the last `parallel_map` ran inline.
declare -g SCOURSH_PARALLEL_POOL=''
parallel_pool_dir() {
  printf '%s' "${SCOURSH_PARALLEL_POOL:-}"
}

# `parallel_aux_read NAME` - prints every worker's `$SCOURSH_WORKER_AUX/NAME`
# file, worker 0 first, for the parent to fold back in.  Prints nothing at all
# when the last fan-out ran inline, which is correct: an inline callback has no
# aux directory and updated the in-process state directly.
parallel_aux_read() {
  local name=$1 i f
  [[ -n ${SCOURSH_PARALLEL_POOL:-} && -d ${SCOURSH_PARALLEL_POOL:-} ]] || return 0
  for (( i = 0; i < PARALLEL_WORKERS; i++ )); do
    f=$SCOURSH_PARALLEL_POOL/w$i/$name
    [[ -r $f ]] || continue
    cat -- "$f"
  done
  return 0
}

# `parallel_cleanup` - removes the pool once its aux files have been read.
parallel_cleanup() {
  [[ -n ${SCOURSH_PARALLEL_POOL:-} && -d ${SCOURSH_PARALLEL_POOL:-} ]] || return 0
  rm -rf -- "$SCOURSH_PARALLEL_POOL"
  SCOURSH_PARALLEL_POOL=''
  return 0
}

# Folds every worker's private meta/ back into the run's own, worker 0 first, so
# each key's lines land in exactly the order a single-worker walk would have
# appended them (see determinism note 3 above).  Keys are visited in a sorted
# order purely so the WORK is reproducible too; the order between keys cannot
# matter, since each key is its own file.
_parallel_merge_meta() {
  local pool=$1 i f key
  [[ -n ${SCOURSH_RUN_DIR:-} && -d ${SCOURSH_RUN_DIR:-}/meta ]] || return 0
  local -A keys=()
  for (( i = 0; i < PARALLEL_WORKERS; i++ )); do
    [[ -d $pool/w$i/meta ]] || continue
    for f in "$pool/w$i/meta"/*; do
      [[ -f $f ]] || continue
      keys[${f##*/}]=1
    done
  done
  (( ${#keys[@]} > 0 )) || return 0
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    for (( i = 0; i < PARALLEL_WORKERS; i++ )); do
      f=$pool/w$i/meta/$key
      [[ -r $f ]] || continue
      cat -- "$f" >>"$SCOURSH_RUN_DIR/meta/$key"
    done
  done < <(printf '%s\n' "${!keys[@]}" | LC_ALL=C sort)
  return 0
}
