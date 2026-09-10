#!/usr/bin/env bash
# modules/image/distro/dpkg.sh - dpkg installed-package ENUMERATION (IMG-07,
# data/scoursh-image-scan-design/report.md §2.1's dpkg row and §5.3's IMG-07
# row: "dpkg enumeration - Status gate + Source: fallback, own
# checks-dpkg.rules").
#
# WHAT THIS FILE IS.  Given the path of an already-extracted
# `var/lib/dpkg/status` file (the exact byte-for-byte member
# `modules/image/acquire.sh`'s `image_collect_metadata` writes when a caller
# asks for it - `var/lib/dpkg/status` has been in `IMAGE_METADATA_PATHS`
# since IMG-02, named for this ticket explicitly - this file never opens an
# archive, never resolves a layer winner, and never sees a tar itself), read
# every INSTALLED (see the Status gate below) package as a (name, version,
# resolved-source-name) triple.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No advisory lookup, no version
# comparator, and no finding emission - report.md §5.3's own row splits that
# out to IMG-08 (the dpkg version comparator: epoch + tilde) and IMG-09
# (Debian/Ubuntu advisory ecosystems), mirroring how `distro/apk.sh` shipped
# a pure enumerator at IMG-04 with matching landing only at IMG-06 once
# IMG-05's comparator existed.  No archive handling and no layer resolution
# (modules/image/acquire.sh's job, IMG-02) and no `modules/image/run.sh`
# orchestration either - `var/lib/dpkg/status` is not in run.sh's own
# explicit wanted-path list yet (its own header names this as IMG-07's
# scope, not IMG-06's), and wiring this enumerator into that dispatch is a
# later ticket's job, the identical "registered, not yet reachable" shape
# `checks-apk.rules` shipped at IMG-04.
#
# THE DPKG STATUS FORMAT (report.md §2.1: "blank-line-separated `Key: value`",
# SPACE after the colon, unlike apk's colon-with-no-space `K:value`): blocks
# of `Key: value` lines, one package per block, separated by a single blank
# line, with MULTI-LINE fields (Description, Conffiles, and others) continued
# on following lines that begin with a single leading space - never a bare
# `Key:` prefix, so they never collide with the four keys this file reads and
# fall through the same silent no-op arm every other unrecognised key does. A
# real block looks like:
#
#   Package: libssl3
#   Status: install ok installed
#   Priority: optional
#   Section: libs
#   Installed-Size: 1477
#   Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
#   Architecture: amd64
#   Multi-Arch: same
#   Source: openssl
#   Version: 3.0.11-1~deb12u2
#   Depends: libc6 (>= 2.34)
#   Description: Secure Sockets Layer toolkit - shared libraries
#    libssl3 is part of the OpenSSL project's implementation of the SSL and
#    TLS cryptographic protocols for secure communication over the Internet.
#    .
#    This package contains the shared libraries.
#
# `Package`, `Status`, `Version` and `Source` are the only four keys this
# ticket reads; every other key (Priority, Section, Installed-Size,
# Maintainer, Architecture, Multi-Arch, Depends, Conflicts, Description,
# Conffiles, ...) is real, legal dpkg metadata this parser must pass over
# WITHOUT treating it as a corrupt block - the identical "unrecognised but
# legal line never poisons the block it sits in" discipline
# `apk_installed_enumerate` already applies.
#
# TRAP 1 - THE STATUS GATE (report.md §2.1 item 1, BINDING).  Only a package
# whose `Status:` is EXACTLY `install ok installed` counts as installed. A
# package with `Status: deinstall ok config-files` has been removed - its
# files are gone and only its conffiles remain on disk - so reporting it is a
# false positive on nearly every Debian/Ubuntu image (dpkg keeps that block
# around specifically so a later reinstall can restore the operator's edited
# conffiles). The match is EXACT, not a substring/contains test: dpkg also
# has a THIRD word position that can read `installed` while the package is
# genuinely not usable - `install reinst-required installed` - so a check
# that only asks "does this line contain the word installed" is wrong in the
# same direction a bare Status-absent read would be. `tests/fixtures/image/
# dpkg/status` plants both a `deinstall ok config-files` and an
# `install reinst-required installed` package specifically so the suite fails
# if the gate is dropped or loosened to a substring test.
#
# TRAP 2 - SOURCE: VS PACKAGE: (report.md §2.1 item 2, BINDING). Distro
# advisories are published against the SOURCE package - binary `libssl3`
# comes from source `openssl` - so a matcher keyed only on the binary
# `Package:` name misses most advisories (a silent false negative, the
# direction report.md and this project's own tension 25 both treat as
# disqualifying). `Source:` is ABSENT from the block when it equals
# `Package:` (the common case: most Debian source packages build exactly one
# binary of the same name), so the fallback to `Package:` must be EXPLICIT
# rather than left as an accidentally-empty field. `Source:` can also carry
# an optional parenthesised version override - `Source: glibc (2.31-13)`,
# when the binary's own `Version:` differs from the source version a binNMU
# rebuild produced - and only the NAME half is what a future advisory
# matcher wants, so it is stripped here rather than deferred to a caller that
# would otherwise have to re-parse this same syntax a second time.
#
# THREE PARALLEL ARRAYS, NOT AN ASSOCIATIVE ONE, for the identical reason
# `apk_installed_enumerate`'s own header gives: an associative array keyed on
# name would silently keep only the LAST entry for a package name dpkg's own
# tooling would never actually duplicate, and a caller auditing a corrupt or
# hand-edited database has no way to tell "one package" from "two distinct
# Package: blocks, same name" if the second already overwrote the first
# before either was looked at. Parallel arrays preserve all of them,
# index-aligned.
#
# A SETTER, NEVER A `$(f)` PRINTER, for the reason `apk_installed_enumerate`'s
# own header states and AGENTS.md's own "Things measured on this codebase"
# entry pins: a function called as `$(f)` runs in a subshell, so writes to
# arrays inside it would be silently discarded the instant a caller tried
# `x=$(dpkg_installed_enumerate "$f")`. This file has no printing variant at
# all, on purpose, so there is no way to call it wrong.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_DPKG_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_DPKG_SOURCED=1

# `DPKG_INSTALLED_NAMES` / `DPKG_INSTALLED_VERSIONS` / `DPKG_INSTALLED_SOURCES`
# - the enumeration result, in file order, index-aligned (index `i` of all
# three arrays is one package). `DPKG_INSTALLED_SOURCES[i]` is already the
# RESOLVED source name - `Source:` when present (with any parenthesised
# version override stripped), else `DPKG_INSTALLED_NAMES[i]` itself (trap 2
# above) - never the raw, possibly-empty field. Reset at the start of every
# `dpkg_installed_enumerate` call, never accumulated across calls, so a
# caller enumerating a second image in one process never sees the first
# image's packages bleed into the second's result.
declare -ga DPKG_INSTALLED_NAMES=()
declare -ga DPKG_INSTALLED_VERSIONS=()
declare -ga DPKG_INSTALLED_SOURCES=()

# `_DPKG_INSTALLED_REASON` - set only on a return-1 refusal, for the ONE
# refusal this file recognises: no readable database at the given path,
# which is the ordinary shape of an Alpine image or a scratch/distroless
# image that carries no dpkg database at all (report.md §4.3's
# `no_package_db_found` reduction - the same reason apk's own enumerator
# reports for the mirror-image case). A caller turns this into an actual
# coverage_reduction/finding; that wiring is a later ticket's scope, not this
# file's - this variable exists so a unit test (and, later, that wiring) can
# assert on WHY enumeration produced nothing without re-deriving the reason
# from a bare non-zero return code.
_DPKG_INSTALLED_REASON=''

# `_DPKG_STATUS_INSTALLED` - the one exact string the Status gate accepts.
# Held as a variable, not inlined at each comparison site, so the whole
# codebase has exactly one place spelling it - report.md's own worked
# examples (`Status: install ok installed`, `Status: deinstall ok
# config-files`, `Status: install reinst-required installed`) are each three
# space-separated words, and only THIS exact three-word string means the
# package's files are genuinely present on disk.
readonly _DPKG_STATUS_INSTALLED='install ok installed'

# `dpkg_installed_enumerate FILE` - the one entry point. Returns 0 with
# `DPKG_INSTALLED_NAMES`/`DPKG_INSTALLED_VERSIONS`/`DPKG_INSTALLED_SOURCES`
# populated (possibly with zero packages - a dpkg database that parses to
# nothing, or one where every block fails the Status gate, is a fact about
# the image, not a refusal) when FILE is readable; returns 1 with
# `_DPKG_INSTALLED_REASON=no_package_db_found` and all three arrays left
# empty when it is not.
#
# A package is emitted only when its block carried a non-empty `Package:`
# line AND its `Status:` was exactly `install ok installed` (trap 1) - there
# is no such thing as a nameless installed package, and there is no such
# thing as an installed package this project reports on with any other
# status. A block that passes both gates but carries no `Version:` line is
# still emitted, with an empty version string, because "this dpkg database
# has no version for this package" is a real fact worth passing on to a
# future version comparator (IMG-08) rather than a parse failure to hide -
# the identical "an empty comparable field is IMG-05/08's decision to make,
# not this enumerator's" convention `apk_installed_enumerate` already
# applies to `V:`.
dpkg_installed_enumerate() {
  local file=$1
  local line pkg='' version='' status='' src=''

  DPKG_INSTALLED_NAMES=()
  DPKG_INSTALLED_VERSIONS=()
  DPKG_INSTALLED_SOURCES=()
  _DPKG_INSTALLED_REASON=''

  # `-f` as well as `-r`: a directory is commonly reported readable too (the
  # execute/search bit tracks with the read bit on most setups), and handing
  # a directory to `<"$file"` below fails inside the loop instead of here,
  # with a bash "Is a directory" read error rather than this function's own
  # clean refusal - the identical guard `apk_installed_enumerate` already
  # carries, for the identical reason.
  if [[ ! -f $file || ! -r $file ]]; then
    _DPKG_INSTALLED_REASON=no_package_db_found
    return 1
  fi

  # `|| [[ -n $line ]]` is the same "last line with no trailing newline is
  # not dropped" idiom `apk_installed_enumerate` already uses - a status file
  # with no final blank line still has its last block flushed below rather
  # than silently discarded.
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ -z $line ]]; then
      _dpkg_flush_block "$pkg" "$version" "$status" "$src"
      pkg=''
      version=''
      status=''
      src=''
      continue
    fi
    case $line in
      # A continuation line (Description, Conffiles, and others) begins with
      # a single leading space and so never matches any of the four
      # anchored `Key: ` prefixes below - it falls through to the catch-all
      # no-op arm exactly like every other unrecognised-but-legal line.
      'Package: '*) pkg=${line#Package: } ;;
      'Status: '*) status=${line#Status: } ;;
      'Version: '*) version=${line#Version: } ;;
      # The optional `(version)` suffix is stripped here so
      # `DPKG_INSTALLED_SOURCES` always carries a bare package name, never a
      # name-plus-version-override string a future caller would have to
      # re-parse - `${line#Source: }` then `${src%% (*}` removes everything
      # from the first literal " (" onward when one is present, and is a
      # no-op when it is not.
      'Source: '*)
        src=${line#Source: }
        src=${src%% (*}
        ;;
      *) ;;
    esac
  done <"$file"

  # The file may end with no trailing blank line - flush whatever block was
  # still open when the loop ran out of input.
  _dpkg_flush_block "$pkg" "$version" "$status" "$src"

  return 0
}

# `_dpkg_flush_block PACKAGE VERSION STATUS SOURCE` - applies both gates
# (trap 1: `STATUS` must equal `install ok installed`; the implicit
# "PACKAGE must be non-empty" gate every block is subject to) and, on
# success, applies trap 2's explicit fallback before appending to the three
# result arrays. A private helper rather than inlined at both of
# `dpkg_installed_enumerate`'s two call sites (the blank-line separator, and
# the end-of-file flush) so the two can never drift apart on the gate logic.
_dpkg_flush_block() {
  local pkg=$1 version=$2 status=$3 src=$4
  [[ -n $pkg ]] || return 0
  [[ $status == "$_DPKG_STATUS_INSTALLED" ]] || return 0
  DPKG_INSTALLED_NAMES+=("$pkg")
  DPKG_INSTALLED_VERSIONS+=("$version")
  DPKG_INSTALLED_SOURCES+=("${src:-$pkg}")
}
