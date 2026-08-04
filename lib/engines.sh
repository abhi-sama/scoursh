#!/usr/bin/env bash
# lib/engines.sh - detect optional vendored engine adapters; expose has_engine().
#
# Owns:
#   docs/DESIGN.md    directory layout ("engines.sh: detect optional vendored
#                      engines; expose has_engine()") and §6.4/§9
#                      ("--use-engines")
#   docs/ADAPTERS.md  §3 ("Runtime gating - not yet built"), §5 (the
#                      three-function contract this file calls into), §7
#                      (graceful degradation)
#   docs/FOUNDATION.md tension 27 ("the first concrete adapter ticket builds
#                      lib/engines.sh/has_engine() and wires --use-engines
#                      through scan.sh/lib/checks.sh together with its own
#                      adapter, mirroring how --paranoid's flag landed
#                      together with its first real enforcement")
#
# THIS TICKET (the first concrete adapter) is that first
# concrete adapter ticket.  Before it, docs/ADAPTERS.md §3 stated plainly
# that neither this file nor `--use-engines` existed, and a fully-populated
# `adapters/` directory would still be inert because nothing called
# `<engine>_detect`.  This file is what calls it.
#
# WHAT `has_engine` IS.  A thin, MODULE-AGNOSTIC detection layer over the
# docs/ADAPTERS.md §4 directory convention -
# `modules/<module>/adapters/<engine>/adapter.sh` - answering exactly one
# pure filesystem question: "would running this adapter's own
# `<engine>_detect` right now return 0?".  It never runs the vendored engine
# itself, never touches the network (adapter.sh's own contract, §2 of that
# document, already forbids that), and it carries NO opinion on whether the
# caller should actually use the result.
#
# `--use-engines` IS DELIBERATELY NOT CHECKED HERE.  docs/ADAPTERS.md §5's
# own pseudocode keeps "is it vendored" (`<engine>_detect`) and "was
# --use-engines given" as two INDEPENDENT conditions ANDed together AT THE
# CALL SITE, never collapsed into one function - exactly the shape
# `modules/sast/run.sh` uses (see its own "Optional semgrep engine adapter"
# section): `if [[ ${SCAN_FLAGS[use-engines]:-} == true ]] && has_engine
# sast semgrep; then ...`.  Folding the flag check in here would make
# `has_engine` lie about what it actually detected the one time a caller
# genuinely needs the raw filesystem answer (this suite's own "detection is
# independent of the flag" cases exercise exactly that seam).
#
# WHY MEMOISED.  `<engine>_detect` is a pure filesystem check by its own
# contract (docs/ADAPTERS.md §5), so re-sourcing adapter.sh and re-running
# detect on every call is safe but wasteful the moment a module calls
# `has_engine` more than once in one run - the same reasoning
# `lib/core.sh`'s `core_has_pcre` already applies to its own probe.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_ENGINES_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_ENGINES_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

declare -A _ENGINES_DETECTED=()

# engines_adapter_path MODULE ENGINE - the fixed adapter.sh path
# docs/ADAPTERS.md §4 freezes, whether or not it exists on disk.
engines_adapter_path() {
  local module=$1 engine=$2
  printf '%s/modules/%s/adapters/%s/adapter.sh' "$SCOURSH_INSTALL_ROOT" "$module" "$engine"
}

# has_engine MODULE ENGINE - 0 iff modules/<module>/adapters/<engine>/adapter.sh
# exists on disk AND, once sourced, <engine>_detect (docs/ADAPTERS.md §5)
# returns 0.  1 in every other case: no adapter.sh at all (the "zero
# adapters present" state every module still works under, per
# docs/ADAPTERS.md §1) or a present-but-not-vendored adapter (its own
# bin/ or rules/ missing) - both collapse to the SAME caller-side reason
# (`reason=engine_not_vendored`, docs/ADAPTERS.md §7), so this function does
# not need to distinguish them any further than its own return code does.
#
# Sourcing an adapter.sh found on disk is NOT gated on detect succeeding:
# the file is trusted, versioned, repository content (never target- or
# network-derived at scan time - docs/ADAPTERS.md §2), exactly like every
# other module file scan.sh sources, so there is no boundary here that
# needs the detect result to authorise the source.
has_engine() {
  local module=$1 engine=$2
  # A second `local` on its own line: `local module=$1 key="$module:..."` in
  # ONE `local` would not see `module`'s own assignment yet (AGENTS.md
  # "Things measured on this codebase": "local a=$1 b=${#a} gives b=0").
  local key="$module:$engine"
  if [[ -z ${_ENGINES_DETECTED[$key]:-} ]]; then
    local adapter_sh
    adapter_sh=$(engines_adapter_path "$module" "$engine")
    if [[ -f $adapter_sh ]]; then
      # shellcheck disable=SC1090
      source "$adapter_sh"
      if "${engine}_detect"; then
        _ENGINES_DETECTED[$key]=0
      else
        _ENGINES_DETECTED[$key]=1
      fi
    else
      _ENGINES_DETECTED[$key]=1
    fi
  fi
  return "${_ENGINES_DETECTED[$key]}"
}
