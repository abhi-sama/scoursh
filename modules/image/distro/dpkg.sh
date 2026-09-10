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
# WHAT THIS FILE WAS AT IMG-07, AND WHAT IMG-09 ADDS ON TOP.  IMG-07 shipped
# section 1 below ONLY: enumeration, no advisory lookup, no version
# comparator, and no finding emission - report.md §5.3's own row split that
# out to IMG-08 (the dpkg version comparator, `dpkg_version.sh`, epoch +
# tilde) and IMG-09 (Debian/Ubuntu advisory ecosystems), mirroring how
# `distro/apk.sh` shipped a pure enumerator at IMG-04 with matching landing
# only at IMG-06 once IMG-05's comparator existed.  Section 2 below is
# IMG-09's own addition, landing in this same file for the identical reason
# `checks-dpkg.rules`' own header already named it as the owning driver.
# Section 1 is UNCHANGED by IMG-09 and remains a pure reader, still safely
# callable standalone.  No archive handling and no layer resolution
# (modules/image/acquire.sh's job, IMG-02) is added either way.
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

# ---------------------------------------------------------------------------
# 2. Advisory matching + finding emission (IMG-09, report.md §2.1/§2.3-2.5/
#    §4.1's IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 row, §5.3's IMG-09 row)
# ---------------------------------------------------------------------------
# WHAT CHANGED FROM IMG-07.  Section 1 above is UNCHANGED; this section is
# the wiring `modules/image/checks-dpkg.rules` already named this file as
# the owning driver for.  It calls run_record/finding_new/finding_emit/
# db_lookup_prefix, which this file still does not `source` - the identical
# "a leaf calls into an already-loaded stack rather than sourcing its own
# copy" shape `modules/image/distro/apk.sh`'s own section 2 already uses,
# relying on its caller (modules/image/engine.sh, reached only through the
# full lib/ stack scan.sh's own dispatch already loaded) having them in
# scope.
#
# THE LOOKUP KEY IS THE RESOLVED SOURCE NAME, NEVER THE BINARY PACKAGE NAME
# (report.md §2.1 item 2, TRAP 2, BINDING).  Distro advisories are published
# against the SOURCE package - `openssl`, not `libssl3` - and section 1's
# enumerator has already done the Source:-vs-Package: resolution for every
# entry (`DPKG_INSTALLED_SOURCES[i]`), so this section reads that array,
# never `DPKG_INSTALLED_NAMES[i]`, as the `data/advisories.db` lookup key -
# a matcher keyed on the binary name would miss most advisories, the exact
# silent false negative report.md and this project's own tension 25 both
# treat as disqualifying. `loc_package` on the emitted finding is therefore
# ALSO the source name - the identity the advisory row itself names, and
# the identity two binary packages built from one source (e.g. `libssl3`
# and a hypothetical `libssl-dev`, both `Source: openssl`) correctly
# collapse onto - while the specific binary package that carried the
# vulnerable version is recorded in the finding's evidence for traceability,
# never dropped.
#
# THE MATCHING RULE ITSELF mirrors `apk.sh`'s own section 2 exactly, and for
# the identical reason that file's header gives: `fixed_versions` IS
# compared here (via `db_lookup_prefix` on (ecosystem, source) ALONE, never
# a three-field exact prefix, which would silently miss every rebuild OSV
# did not happen to record) and `dpkg_version_cmp_v` (IMG-08) against it -
# `apk.sh`'s header's full reasoning for why this departs from
# docs/FOUNDATION.md tension 25's exact-match resolution applies here
# unchanged, substituting dpkg's own epoch+tilde comparator for apk's.
#
# `_DPKG_SCAN_SKIPPED` - installed packages with no comparable version (an
# empty `Version:` line, or one `dpkg_version_valid` rejects) are counted
# here, once per whole scan, mirroring `_APK_SCAN_SKIPPED`'s identical
# "one roll-up, not one finding per package" discipline.  The caller
# (modules/image/run.sh) turns a non-zero count into its own
# coverage_reduction; this file only counts.
_DPKG_SCAN_SKIPPED=0

# `dpkg_scan_installed FILE IMAGE_ID ECOSYSTEM [DB]` - the module's one dpkg
# match+emit entry point. FILE is an already-extracted var/lib/dpkg/status
# (image_collect_metadata's own output - this function never opens an
# archive or resolves a layer winner, exactly like
# `dpkg_installed_enumerate` above).
#
# Returns 0 (with `IMAGE-PKG-VULNERABLE_OS_PACKAGE-02` recorded into
# checks_run) when FILE was readable, REGARDLESS of whether any package
# matched - "the check ran and found nothing" is a real, honest outcome,
# mirroring `apk_scan_installed`'s identical contract. Returns 1 with
# `_DPKG_INSTALLED_REASON` set (`dpkg_installed_enumerate`'s own reason) and
# checks_run left untouched when FILE could not be read at all - the caller
# turns THAT into the `IMAGE-COV-UNKNOWN_DISTRO-01` reduction/finding.
dpkg_scan_installed() {
  local file=$1 image_id=$2 ecosystem=$3 db=${4:-$(image_advisories_db_path)}
  _DPKG_SCAN_SKIPPED=0

  dpkg_installed_enumerate "$file" || return 1

  run_record checks_run IMAGE-PKG-VULNERABLE_OS_PACKAGE-02

  local i n=${#DPKG_INSTALLED_NAMES[@]}
  local bin ver src prefix row marked row_eco pkg rver advisory sev fixed
  local -A seen_advisory=()
  for (( i = 0; i < n; i++ )); do
    bin=${DPKG_INSTALLED_NAMES[i]}
    ver=${DPKG_INSTALLED_VERSIONS[i]}
    src=${DPKG_INSTALLED_SOURCES[i]}
    # A package with no comparable installed version cannot be ordered
    # against anything, so it is counted (never silently dropped) and
    # skipped - the identical "MALFORMED INPUT IS UNORDERABLE" discipline
    # `dpkg_version.sh`'s own header states.
    if [[ -z $ver ]] || ! dpkg_version_valid "$ver"; then
      _DPKG_SCAN_SKIPPED=$(( _DPKG_SCAN_SKIPPED + 1 ))
      continue
    fi
    seen_advisory=()
    prefix=$(printf '%s\t%s\t' "$ecosystem" "$src")
    while IFS= read -r row; do
      [[ -n $row ]] || continue
      # data/advisories.db is real-TAB TSV; translate to \x1f first for the
      # identical reason `apk_scan_installed`'s own loop does - tab is IFS
      # whitespace even when IFS is set to only tab, so a middle-empty
      # field (an advisory with no published fixed_versions) silently
      # shifts every later field under a literal-tab `read`.
      marked=${row//$'\t'/$'\x1f'}
      IFS=$'\x1f' read -r row_eco pkg rver advisory sev fixed <<<"$marked"
      # One finding per (source package, advisory), never per matching row -
      # the identical reasoning `apk_scan_installed`'s own loop gives.
      [[ -n $advisory && -z ${seen_advisory[$advisory]:-} ]] || continue
      _dpkg_row_still_vulnerable "$ver" "$fixed" || continue
      seen_advisory[$advisory]=1
      _dpkg_emit_vulnerable_package "$image_id" "$ecosystem" "$src" "$bin" "$ver" "$advisory" "$sev" "$fixed"
    done < <(db_lookup_prefix "$prefix" "$db")
  done
  return 0
}

# `_dpkg_row_still_vulnerable INSTALLED FIXED_VERSIONS` - dpkg's own version
# of `_apk_row_still_vulnerable` (`modules/image/distro/apk.sh`), comparing
# through `dpkg_version_cmp_v`/`dpkg_version_valid` (IMG-08) instead of
# apk's comparator. FIXED_VERSIONS is a comma-separated list
# (docs/FOUNDATION.md tension 25's schema); every token that parses under
# `dpkg_version_valid` is compared and the LARGEST one wins as the fix
# threshold - conservative on purpose (report.md §2.4: a false positive is
# noisy but survivable, a false negative is not), so a package below ANY of
# several recorded fix points is still reported rather than only the
# smallest. An empty field, or one whose tokens all fail to parse, means no
# comparable fix is known at all - treated as still vulnerable, mirroring
# `apk.sh`'s own accept-risk convention for an unfixed advisory rather than
# a silent skip.
_dpkg_row_still_vulnerable() {
  local installed=$1 fixed_versions=$2
  local -a tokens
  IFS=',' read -r -a tokens <<<"$fixed_versions"
  local t best=''
  for t in "${tokens[@]+"${tokens[@]}"}"; do
    [[ -n $t ]] || continue
    dpkg_version_valid "$t" || continue
    if [[ -z $best ]]; then
      best=$t
    else
      dpkg_version_cmp_v "$t" "$best"
      (( _DPKGV_CMP <= 0 )) || best=$t
    fi
  done
  [[ -n $best ]] || return 0
  dpkg_version_cmp_v "$installed" "$best" || return 0
  (( _DPKGV_CMP < 0 ))
}

# `_dpkg_summary_for ADVISORY_ID` - data/advisory-summaries.db's own row, or
# a placeholder, mirroring `apk.sh`'s own `_apk_summary_for` (and, one layer
# further, `modules/sca/engine.sh`'s `_sca_summary_for`). A local copy
# rather than a `source modules/image/distro/apk.sh` edge - a sibling
# distro file is not this file's dependency any more than
# `modules/sca/engine.sh` is `apk.sh`'s, and the env var name is reused
# verbatim so a test pointing SCOURSH_SCA_SUMMARIES_DB at a fixture
# redirects this lookup too.
_dpkg_summary_for() {
  local advisory=$1 db prefix row marked _adv summary
  db=${SCOURSH_SCA_SUMMARIES_DB:-${SCOURSH_INSTALL_ROOT:-}/data/advisory-summaries.db}
  prefix=$(printf '%s\t' "$advisory")
  row=$(db_lookup_exact "$prefix" "$db") || { printf 'no summary available'; return 0; }
  marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r _adv summary <<<"$marked"
  printf '%s' "${summary:-no summary available}"
}

# `_dpkg_emit_vulnerable_package IMAGE_ID ECOSYSTEM SOURCE BINARY INSTALLED
# ADVISORY SEVERITY FIXED_VERSIONS` - one finding. `base_severity` is the
# ROW's own value, not the registry's declared default, mirroring
# `checks-dpkg.rules`' own comment and `apk.sh`'s identical convention.
# SOURCE (the resolved source package name, report.md §2.1 trap 2) is what
# becomes `loc_package` - the identity the advisory row itself names; BINARY
# (the actually-installed dpkg package, e.g. `libssl3`) is recorded in the
# evidence only, so an operator can see exactly which installed package
# carries the vulnerable version even when it differs from the source name.
_dpkg_emit_vulnerable_package() {
  local image_id=$1 ecosystem=$2 src=$3 bin=$4 installed=$5 advisory=$6 sev=$7 fixed=$8
  local summary
  summary=$(_dpkg_summary_for "$advisory")

  finding_new
  finding_set check_id IMAGE-PKG-VULNERABLE_OS_PACKAGE-02
  finding_set module image
  finding_set title "$ecosystem: dpkg package $src@$installed is vulnerable ($advisory)"
  finding_set base_severity "$sev"
  finding_set confidence high
  finding_set cwe CWE-1104
  finding_set owasp A06:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set loc_ecosystem "$ecosystem"
  finding_set loc_package "$src"
  finding_set loc_version "$installed"
  finding_set loc_advisory_id "$advisory"
  finding_set logical_kind package
  finding_set logical_fqn "image $image_id: $ecosystem/$src@$installed"
  finding_set fix_fixed_versions "$fixed"
  if [[ -n $fixed ]]; then
    finding_set remediation "Rebuild the image against an updated base layer (or upgrade the $src source package directly, where the Dockerfile installs it explicitly) to at least $fixed, then re-scan. A base-image bump alone can carry this fix silently."
  else
    finding_set remediation "No fixed version is published upstream yet for $advisory against $src; this is an accept-risk candidate pending an upstream fix."
  fi
  finding_set_evidence "image: $image_id
source_package: $src@$installed
binary_package: $bin
ecosystem: $ecosystem
advisory: $advisory ($sev)
fixed_versions: ${fixed:-none published}
summary: $summary"
  finding_emit
}
