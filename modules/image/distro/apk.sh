#!/usr/bin/env bash
# modules/image/distro/apk.sh - apk installed-package ENUMERATION (IMG-04,
# data/scoursh-image-scan-design/report.md §2.1's apk row and §5.3's IMG-04
# row).
#
# WHAT THIS FILE IS.  Given the path of an already-extracted
# `lib/apk/db/installed` file (the exact byte-for-byte member
# `modules/image/acquire.sh`'s `image_collect_metadata` writes when a caller
# asks for it - this file never opens an archive, never resolves a layer
# winner, and never sees a tar itself), read every installed package as a
# (name, version) pair.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No version comparator (IMG-05: apk
# version ordering, `1.2.3-r4 < 1.2.3-r10`, is its own ticket precisely
# because report.md §2.4/§2.5 measured it as a real, separate piece of work),
# no advisory lookup, no finding, and no `modules/image/run.sh` wiring
# (IMG-06). `checks-apk.rules` (this ticket's sibling file) registers the
# check id the comparator will eventually emit under; nothing here calls
# `finding_emit`, `run_record`, or any other side-effecting library
# function, matching the `image_os_release_parse`/`image_tar_members`
# precedent in `modules/image/engine.sh`/`acquire.sh` of a pure reader that
# leaves recording to whichever caller has the run context.
#
# THE APK DB FORMAT (report.md §2.1's own delightful accident): blank-line
# separated blocks of single-letter `K:value` lines - no space after the
# colon, unlike scoursh's own frozen `key: value` record format
# (rules/RULE-FORMAT.md §4) - with no escaping and a value that runs to end
# of line, exactly the same "reuse the parsing INSTINCT, not the parser"
# read this ticket's brief gives.  A real block looks like:
#
#   C:Q1abc...                              (checksum)
#   P:musl                                  (package NAME - this file's key)
#   V:1.2.4-r2                              (VERSION - this file's other key)
#   A:x86_64
#   S:12345
#   I:67890
#   T:the musl c library (libc) implementation
#   U:https://musl.libc.org/
#   L:MIT
#   o:musl
#   D:so:libc.musl-x86_64.so.1
#
# `P` and `V` are the only two keys this ticket reads; every other key
# (checksum, arch, size, description, url, license, origin, depends,
# provides, maintainer, build time, commit, ...) is a real, legal line this
# parser must pass over WITHOUT treating it as a corrupt block - a `case`
# arm that only matches `P:*`/`V:*` and falls through to a silent no-op for
# everything else is what "handle a malformed/partial block sanely" means in
# practice: this file never dies, and never lets an unrecognised key line
# poison the block it sits in.
#
# TWO PARALLEL ARRAYS, NOT AN ASSOCIATIVE ONE, for the identical reason
# `modules/image/acquire.sh`'s own header gives for keeping layer state in
# order rather than collapsing it: a `name -> version` associative array
# would silently keep only the LAST entry for a package name apk's own
# tooling would never actually duplicate, and a caller auditing a corrupt or
# hand-edited database has no way to tell "one package, reinstalled" from
# "two distinct P: blocks, same name" if the second one already overwrote
# the first before it was ever looked at.  Parallel arrays preserve both.
#
# A SETTER, NEVER A `$(f)` PRINTER, for the reason `image_tar_listing_set`'s
# own header states and AGENTS.md's own "Things measured on this codebase"
# entry pins: a function called as `$(f)` runs in a subshell, so writes to
# arrays or to `_APK_INSTALLED_REASON` inside it would be silently discarded
# the instant a caller tried `x=$(apk_installed_enumerate "$f")`.  This file
# has no printing variant at all, on purpose, so there is no way to call it
# wrong.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_APK_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_APK_SOURCED=1

# `APK_INSTALLED_NAMES` / `APK_INSTALLED_VERSIONS` - the enumeration result,
# in file order, index-aligned (`APK_INSTALLED_NAMES[i]` and
# `APK_INSTALLED_VERSIONS[i]` are one package).  Reset at the start of every
# `apk_installed_enumerate` call, never accumulated across calls, so a
# caller enumerating a second image in one process never sees the first
# image's packages bleed into the second's result.
declare -ga APK_INSTALLED_NAMES=()
declare -ga APK_INSTALLED_VERSIONS=()

# `_APK_INSTALLED_REASON` - set only on a return-1 refusal, for the ONE
# refusal this file recognises: no readable database at the given path,
# which is the ordinary shape of a scratch or distroless image that carries
# no apk database at all (report.md §4.3's `no_package_db_found` reduction).
# A caller turns this into an actual `coverage_reduction`/finding - that
# wiring is IMG-06's scope, not this file's; this variable exists so a unit
# test (and, later, that wiring) can assert on WHY enumeration produced
# nothing without re-deriving the reason from a bare non-zero return code.
_APK_INSTALLED_REASON=''

# `apk_installed_enumerate FILE` - the one entry point.  Returns 0 with
# `APK_INSTALLED_NAMES`/`APK_INSTALLED_VERSIONS` populated (possibly with
# zero packages - an apk database that parses to nothing is a fact about the
# image, not a refusal) when FILE is readable; returns 1 with
# `_APK_INSTALLED_REASON=no_package_db_found` and both arrays left empty
# when it is not.
#
# A package is emitted only when its block carried a non-empty `P:` line -
# there is no such thing as a nameless installed package, so a block with no
# `P:` at all (or an empty one, `P:` with nothing after the colon) is
# dropped rather than enumerated as a package with an empty name.  A block
# that DOES carry `P:` but no `V:` is still emitted, with an empty version
# string, because "this apk database has no version for this package" is a
# real fact worth passing on to a version comparator rather than a parse
# failure to hide - IMG-05's comparator, not this file, is where "no version
# to compare against" gets its own decision.
apk_installed_enumerate() {
  local file=$1
  local line name='' version=''

  APK_INSTALLED_NAMES=()
  APK_INSTALLED_VERSIONS=()
  _APK_INSTALLED_REASON=''

  # `-f` as well as `-r`: a directory is commonly reported readable too (the
  # execute/search bit tracks with the read bit on most setups), and handing
  # a directory to `<"$file"` below fails inside the loop instead of here,
  # with a bash "Is a directory" read error rather than this function's own
  # clean refusal - measured in this ticket's own suite, section C.
  if [[ ! -f $file || ! -r $file ]]; then
    _APK_INSTALLED_REASON=no_package_db_found
    return 1
  fi

  # `|| [[ -n $line ]]` is the same "last line with no trailing newline is
  # not dropped" idiom `image_os_release_parse` already uses - an apk
  # `installed` file with no final blank line still has its last block
  # flushed below rather than silently discarded.
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ -z $line ]]; then
      if [[ -n $name ]]; then
        APK_INSTALLED_NAMES+=("$name")
        APK_INSTALLED_VERSIONS+=("$version")
      fi
      name=''
      version=''
      continue
    fi
    case $line in
      P:*) name=${line#P:} ;;
      V:*) version=${line#V:} ;;
      # Every other key (C/A/S/I/T/U/L/o/m/t/c/D/p/r/...) is real, legal apk
      # metadata this ticket does not read - fall through with no action,
      # never a diagnostic, so an unrecognised-but-legal line never poisons
      # the block it sits in.
      *) ;;
    esac
  done <"$file"

  # The file may end with no trailing blank line - flush whatever block was
  # still open when the loop ran out of input.
  if [[ -n $name ]]; then
    APK_INSTALLED_NAMES+=("$name")
    APK_INSTALLED_VERSIONS+=("$version")
  fi

  return 0
}
