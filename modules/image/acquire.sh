#!/usr/bin/env bash
# modules/image/acquire.sh - offline image ACQUISITION and untrusted-archive
# handling (IMG-02, data/scoursh-image-scan-design/report.md §1).
#
# WHAT THIS FILE IS.  Everything between "the operator handed us a file" and
# "these are the bytes of the metadata paths we asked for, from the layer that
# actually wins".  It reads config/images.conf (rules/RULE-FORMAT.md §9.6.8),
# opens report.md §1.2's two offline shapes - a `docker save` tarball (A) and
# an OCI image layout directory (B) - resolves layers in manifest order with
# OCI whiteouts applied (§1.6), and extracts ONLY the handful of named
# metadata paths a later ticket will parse.
#
# WHAT IT DELIBERATELY IS NOT.  No package enumeration, no version comparator,
# no advisory lookup and no finding: IMG-04 onward own those, and this file
# must be complete and reviewable on its own before any of them is written,
# because it is the file that touches attacker-controlled bytes.  It also
# never materialises a rootfs - report.md §1.6 makes "extract only the
# metadata paths" a design invariant rather than an optimisation, and the
# extraction API below has no whole-archive mode to reach for.
#
# IMG-06 ADDED SECTION 10 (`image_config_blob_read`), the one exception to
# "no finding" above being a statement about THIS file's scope rather than a
# promise that it never grows: reading the image's CONFIG blob (never a
# layer member) to decide `IMAGE-CFG-RUNS_AS_ROOT-01`
# (modules/image/config.sh) is still acquisition, not enumeration or
# matching, and belongs here for the identical reason section 7/8's
# manifest/index readers do - it is attacker-controlled content reached
# through the same extraction gate.
#
# WHO CALLS THIS, AND WHEN - stated because "no caller" is the shape a
# reviewer should always question.  At IMG-02 landing, nothing in
# modules/image/run.sh reached this file yet, deliberately: IMG-01 shipped
# that dispatch as an honestly declared no-op, and wiring the dispatch here
# would have meant this ticket changing IMG-01's just-landed coverage
# records for a run that still enumerates no packages - a run that opened
# an image and then said nothing about it is not more honest than one that
# says it has no enumerator, only louder.  IMG-03 IS that first real
# consumer now: modules/image/engine.sh sources this file and
# modules/image/run.sh calls image_source_resolve/image_open/
# image_collect_metadata to read `etc/os-release` out of a collected
# metadata set and detect the distro release.  What made the gap acceptable
# rather than dead code in between is unchanged - every function below is
# exercised directly against real committed fixtures by
# tests/suites/image-acquire.sh, independent of whatever wires into it.
#
# WHY IT SOURCES ONLY lib/config.sh.  The lesson
# modules/dast/passive/response_engine.sh's own header records: `shellcheck
# -x` re-expands every source edge it follows rather than memoising it, so an
# edge added here is paid for once per consumer, and every later
# modules/image/distro/*.sh is a consumer.  lib/config.sh is the one edge that
# buys something this file cannot do without - records_load, and the
# config_load_if_present "an ABSENT file is a clean fallback, a MALFORMED one
# is always exit 4" discipline (rules/RULE-FORMAT.md §11) - and it brings
# lib/records.sh and lib/core.sh with it, which is where `die`, the exit-code
# constants and `scratch_dir` live.  modules/image/engine.sh is deliberately
# NOT sourced: it pulls modules/sast/engine.sh and lib/checks.sh for the
# check-gate half of the module, none of which acquisition needs.
#
# ===========================================================================
# THE SECURITY STATEMENT, IN ONE PLACE (report.md §1.5)
# ===========================================================================
# A layer tarball is attacker-controlled content and is the most hostile input
# this tool processes.  Three classic escapes are refused HERE, IN BASH,
# before any tar process is started:
#
#   1. a member name with a `..` path component      (`../../etc/passwd`)
#   2. a member name that is absolute                (`/etc/passwd`)
#   3. a member whose own PARENT is declared by the archive as something
#      other than a directory - the symlink escape, where a layer ships
#      `lib -> /etc` and then `lib/passwd` and a naive extractor writes
#      through the link it just created
#
# `image_member_is_safe` decides 1 and 2 from the name alone;
# `image_member_parents_are_dirs` decides 3 from the archive's own listing,
# which `tar -tf` prints with a trailing `/` on a directory member and without
# one on every other type, in both userlands this project supports.  That
# listing test is used rather than `tar -tvf`'s mode column on purpose: the
# verbose format is not portable between bsdtar and GNU tar, and a security
# control parsed out of a format that varies by userland is a control that
# silently stops working on the other one.
#
# **The bash validation is THE control, and it does not rest on tar's own
# containment.**  bsdtar 3.5.3 / libarchive 3.7.4 was measured on this host
# refusing all three (report.md §1.5's table, re-measured while writing this
# file: `Path contains '..'`, a leading `/` stripped, extraction through a
# symlink refused) - and that is ONE userland's behaviour, not a guarantee.
# The GNU-tar half of that cross-check is deferred to tools/daily-suite.sh's
# container leg, where a GNU userland actually exists; NOTHING IN THIS FILE
# DEPENDS ON ITS OUTCOME.  Every refusal above is reached with no tar process
# involved at all, which is exactly what tests/suites/image-acquire.sh asserts
# - it plants a canary outside the extraction root and proves it survives each
# of the three.
#
# Two further belts, because the checks above are decided from a listing the
# attacker also wrote:
#
#   - Only members whose names EXACTLY equal a caller-supplied wanted path are
#     ever extracted.  The wanted set is scoursh's own (`IMAGE_METADATA_PATHS`
#     below); nothing derived from archive content ever selects a file to
#     extract.
#   - After extraction the resulting path is re-checked in bash: it must be a
#     regular file, must not be a symlink, and its realpath must still be
#     inside the extraction root.
#
# AND ONE RULE ABOUT DELETION, WHICH IS ITS OWN HAZARD.  Every path this file
# removes is attacker-influenced, so `rm` is never reached with a bare
# variable.  `image_rm_under_root` is the single deletion primitive: it
# refuses an empty root, refuses an empty or non-admissible relative name,
# proves the resolved target is inside the root, and only then removes it -
# through the `"${var:?}"` form, so even a bug that got past all of that
# aborts rather than expanding to the root itself or to `/`.  A whiteout
# member is data an attacker wrote too, so a malformed one (`.wh.` naming no
# file at all) is REFUSED rather than turned into a deletion of its own
# directory; tests/suites/image-acquire.sh pins that with the extraction root
# populated, and asserts it survives.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_ACQUIRE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_ACQUIRE_SOURCED=1

# shellcheck source=lib/config.sh
source "${BASH_SOURCE[0]%/*}/../../lib/config.sh"

# ---------------------------------------------------------------------------
# 1. The JSON reader - the FIFTH byte-identical copy, and why it is a copy
# ---------------------------------------------------------------------------
# Both offline shapes are driven by JSON (`manifest.json` for a docker-save
# tarball, `index.json` plus a manifest blob for an OCI layout), and this
# project already ships a purpose-built, depth- and string-aware flattener in
# four byte-identical copies: lib/state.sh's `_state_json_flatten`,
# modules/cloud/aws/engine.sh's `cloud_json_flatten`,
# modules/dast/crawl_engine.sh's `crawl_json_flatten`, and the adapters' own.
#
# This is the fifth copy, and it is a COPY BY POLICY rather than by
# convenience.  `cloud_json_flatten`'s own header states the rule this file
# obeys: a NEW `lib/` hub would be re-expanded once per consumer across the
# whole tree, and this project has already paid twice for that lesson (30+ GB
# static-analysis runs, an OOM-killed CI leg) - tests/lint-source-graph.sh now
# caps that fan-out and would fail the build.  (A comment line beginning with
# the linter's own name is parsed as a DIRECTIVE, which is why that sentence
# does not start with it - AGENTS.md records the same trap.)  What is forbidden is not a fifth
# copy; it is a fifth DIFFERENT parser.  So the awk program below is
# byte-identical to lib/state.sh's and modules/cloud/aws/engine.sh's, a bug
# found in any of them is the same bug in all of them, and
# tests/suites/image-acquire.sh asserts the agreement leaf for leaf on one
# document rather than trusting this paragraph.
#
# Reading the two manifests through it rather than through grep is not
# fastidiousness.  `manifest.json` is a top-level ARRAY whose `Layers` entries
# are ordered and whose order IS the layer application order (§1.6); an OCI
# `index.json` nests a digest under `manifests[n].digest` beside an
# annotations map that can carry any operator text at all.  A grep for
# `sha256:` over either one reads a digest out of a field it never meant to,
# which for this module means extracting and trusting the wrong blob.
image_json_flatten() {
  awk '
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    function readstr(  s, c) {
      i++
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    function emit(path, type, val) { print path "\t" type "\t" val }
    function value(path,   c, k, idx, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          value(path == "" ? k : path SEP k)
          first = 0
        }
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "]") { i++; return }
          value(path == "" ? idx : path SEP idx)
          idx++
          first = 0
        }
      }
      if (c == "\"") { emit(path, "s", readstr()); return }
      k = readtok()
      if (k == "") fail("unparseable value at byte " i)
      if (k == "true" || k == "false") { emit(path, "b", k); return }
      if (k == "null") { emit(path, "z", k); return }
      emit(path, "n", k)
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      skipws()
      if (i > n) exit 0
      value("")
    }
  '
}

# The inverse of the "still escaped" contract above, applied once a leaf's raw
# text is about to become a real bash value.  Byte-identical to
# modules/cloud/aws/engine.sh's `cloud_json_unescape`, for the same reason the
# flattener is a byte-identical copy.
# SC1003: `'\'` is a literal single backslash, the character this function
# exists to interpret.
# shellcheck disable=SC1003
image_json_unescape() {
  local s=$1 out='' i n ch nx code decoded
  if [[ $s != *'\'* ]]; then
    printf '%s' "$s"
    return 0
  fi
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch != '\' ]]; then out+=$ch; continue; fi
    nx=${s:i+1:1}
    case $nx in
      '"') out+='"'; i=$(( i + 1 )) ;;
      '\') out+='\'; i=$(( i + 1 )) ;;
      '/') out+='/'; i=$(( i + 1 )) ;;
      b) out+=$'\b'; i=$(( i + 1 )) ;;
      f) out+=$'\f'; i=$(( i + 1 )) ;;
      n) out+=$'\n'; i=$(( i + 1 )) ;;
      r) out+=$'\r'; i=$(( i + 1 )) ;;
      t) out+=$'\t'; i=$(( i + 1 )) ;;
      u)
        code=${s:i+2:4}
        if [[ $code == 0000 ]]; then
          out+=' '
          i=$(( i + 5 ))
        elif [[ $code =~ ^00[0-7][0-9A-Fa-f]$ ]]; then
          # shellcheck disable=SC2059
          printf -v decoded "\\x${code:2:2}"
          out+=$decoded
          i=$(( i + 5 ))
        else
          out+='\u'
          i=$(( i + 1 ))
        fi
        ;;
      *) out+='\' ;;
    esac
  done
  printf '%s' "$out"
}

# `image_json_leaf VARNAME FILE PATH` - sets VARNAME to the UNESCAPED scalar at
# the US-joined structural PATH in FILE, returning 1 with VARNAME empty when
# the document has no such leaf.
#
# A SETTER, NEVER A PRINTER, for the reason modules/cloud/aws/engine.sh's
# `cloud_json_leaf` gives: a reader called as `v=$(...)` runs in a subshell,
# so any outcome global a nested call sets dies with it.
image_json_leaf() {
  local __var=$1 __file=$2 __want=$3
  local __path __type __val
  printf -v "$__var" '%s' ''
  [[ -r $__file ]] || return 1
  while IFS=$'\t' read -r __path __type __val; do
    [[ $__path == "$__want" ]] || continue
    [[ $__type == s ]] && __val=$(image_json_unescape "$__val")
    printf -v "$__var" '%s' "$__val"
    return 0
  done < <(image_json_flatten <"$__file")
  return 1
}

# ---------------------------------------------------------------------------
# 2. `image_tar_members` - the `scan_match` of tar
# ---------------------------------------------------------------------------
# report.md §1.4, measured rather than reasoned about, and re-measured on this
# host (bsdtar 3.5.3 / libarchive 3.7.4) while writing this file:
#
#   tar -tf ARCHIVE                     -> 0    (whole listing)
#   tar -tf ARCHIVE ABSENT-MEMBER       -> 1
#   tar -xf ARCHIVE ABSENT-MEMBER       -> 1
#   tar -xf ARCHIVE PRESENT-MEMBER      -> 0
#   tar -xf ARCHIVE PRESENT ABSENT      -> 1    (one absent poisons the call)
#
# This is docs/FOUNDATION.md tension 4's grep rule in a new place.  An ABSENT
# member is the NORMAL case here - most layers carry no package database at
# all, an Alpine layer has no /var/lib/dpkg/status and a Debian layer has no
# /lib/apk/db/installed - so under the mandatory `set -Eeuo pipefail` a
# per-member `tar -xf` aborts the run on the ordinary case.  And a blanket
# `|| true` is WORSE than the abort: exit 1 is also what a hostile or corrupt
# archive returns, so swallowing it swallows a security refusal.
#
# So this wrapper does what `scan_match` does: it makes the one call whose
# exit status is unambiguous - list the WHOLE archive, 0 unless the archive is
# genuinely unreadable - and every "is this member here" question is then
# answered in bash against that listing.  Nothing in this file ever hands tar
# a member name it has not already proved present.
#
# Returns 0 and prints the listing; returns 5 (SCOURSH_EXIT_INCOMPLETE's
# value, "the tool could not do its job") WITHOUT printing, on a genuine
# failure.  It does not `die`: the caller knows whether an unreadable layer is
# a fatal missing input or a recorded coverage reduction, and a wrapper that
# decided that for every caller would take the choice away from the one that
# has the context.
image_tar_members() {
  local archive=$1
  local out rc=0
  if [[ ! -r $archive ]]; then
    log_error "image: unreadable archive: $archive"
    return 5
  fi
  out=$(tar -tf "$archive" 2>/dev/null) || rc=$?
  if (( rc != 0 )); then
    log_error "image: tar could not list the archive (rc=$rc); it is corrupt or not a tar: $archive"
    return 5
  fi
  printf '%s\n' "$out"
  return 0
}

# `image_tar_listing_set VARNAME ARCHIVE` - image_tar_members into a variable.
# A setter for the identical reason image_json_leaf is one, plus a second:
# `l=$(image_tar_members x)` under `set -e` takes the ASSIGNMENT's status,
# which is the command substitution's, so the distinction this wrapper exists
# to preserve is lost at exactly the call site that needed it (AGENTS.md, "the
# exit status of `var=$(cmd)` IS `cmd`'s").
image_tar_listing_set() {
  local __var=$1 __archive=$2 __out __rc=0
  printf -v "$__var" '%s' ''
  __out=$(image_tar_members "$__archive") || __rc=$?
  (( __rc == 0 )) || return "$__rc"
  printf -v "$__var" '%s' "$__out"
  return 0
}

# ---------------------------------------------------------------------------
# 3. Member-name validation - THE security control (report.md §1.5)
# ---------------------------------------------------------------------------

# `image_member_normalize NAME` - the one normalisation applied before every
# comparison in this file: a leading `./` is stripped, because `tar -cf . `
# writes `./etc/os-release` where a layer built another way writes
# `etc/os-release`, and they name the same file.
#
# It is deliberately the ONLY normalisation.  Collapsing `a/../b` to `b`, or
# folding `//`, would make a hostile name LOOK safe to the checks below by
# rewriting the very component they exist to reject.  Normalisation that can
# turn an unsafe name into a safe-looking one is not normalisation, it is a
# bypass: `..` is refused, never simplified.
image_member_normalize() {
  local n=$1
  while [[ $n == ./* ]]; do n=${n#./}; done
  printf '%s' "$n"
}

# `image_member_is_safe NAME` - 0 if NAME may be extracted or removed, 1
# otherwise.  Refuses, and for these reasons:
#
#   empty                  - names nothing.  An extractor handed it asks tar
#                            for "everything"; a remover handed it is a bare
#                            `rm` of the extraction root
#   absolute (`/x`)        - report.md §1.5's second escape.  bsdtar happens
#                            to strip the leading slash; that is bsdtar's
#                            choice, not a property of tar, and this refusal
#                            does not depend on it
#   a `..` COMPONENT       - report.md §1.5's first escape.  Tested per
#                            component, never as a substring: a file
#                            legitimately named `..foo` or `x..y` contains
#                            those bytes and is not a traversal, and refusing
#                            it would be a coverage hole dressed as caution
#   a `.` component        - contributes nothing after normalisation, and is
#                            the shape `x/./y` uses to dodge an exact compare
#   a leading `~`          - never meaningful in an archive, and is the byte a
#                            downstream consumer might expand
#   a control byte         - a name carrying a newline splits `tar -tf`'s
#                            line-oriented listing in two and would let an
#                            archive forge a listing entry
#
# Note what is NOT refused: an ordinary name with a space, a colon, a hash or
# a quote in it.  Those are legal filenames, this file never puts a member
# name into a shell word or a glob, and refusing them would drop real files
# from a scan for the comfort of the reader.
image_member_is_safe() {
  local name=$1 comp rest
  [[ -n $name ]] || return 1
  [[ $name != /* ]] || return 1
  [[ $name != '~'* ]] || return 1
  [[ $name != *[$'\001'-$'\037']* ]] || return 1
  rest=$name
  while [[ -n $rest ]]; do
    comp=${rest%%/*}
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=''; fi
    [[ $comp != '..' ]] || return 1
    [[ $comp != '.' ]] || return 1
  done
  return 0
}

# `image_member_parents_are_dirs LISTING NAME` - report.md §1.5's THIRD escape,
# the one neither name-shape check above can see.
#
# The attack is a layer that ships `lib` as a SYMLINK pointing outside the
# extraction root and then ships `lib/passwd`; a naive extractor creates the
# link and writes the second member straight through it.  Both names are
# individually well formed - `lib/passwd` has no `..`, no leading slash,
# nothing to object to - so the refusal has to come from the archive's own
# declaration of what `lib` IS.
#
# `tar -tf` prints a directory member with a trailing `/` and every other type
# without one, on both userlands this project supports.  So: a member is
# refused when any STRICT path prefix of it appears in the listing as a
# non-directory.  A real layer declares `lib/` when it declares `lib` at all,
# so this costs nothing on a well-formed layer, and it refuses every
# ill-formed parent - symlink, hardlink, regular file, device node - rather
# than only the type today's attack happens to use.
image_member_parents_are_dirs() {
  local listing=$1 name=$2
  local prefix rest comp line
  local -A nondir=()
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ $line != */ ]] || continue
    nondir[$(image_member_normalize "$line")]=1
  done <<<"$listing"
  name=$(image_member_normalize "$name")
  prefix=''
  rest=$name
  while [[ $rest == */* ]]; do
    comp=${rest%%/*}
    rest=${rest#*/}
    if [[ -n $prefix ]]; then prefix="$prefix/$comp"; else prefix=$comp; fi
    [[ -z ${nondir[$prefix]:-} ]] || return 1
  done
  return 0
}

# `image_member_admissible LISTING NAME` - the whole gate in one call, so a
# caller cannot apply two of the three checks and believe it applied all
# three.  Same "a control each caller must remember to assemble is not a
# control" argument docs/FOUNDATION.md tension 19 makes for the network
# chokepoint, one module over.
#
# Sets `_IMAGE_REFUSE_REASON` to a machine-readable reason on a refusal, and
# CLEARS IT AT ENTRY on every call - the mistake modules/dast/passive/
# transport.sh found the expensive way, where a roll-up read a stale reason
# left over from an earlier, unrelated refusal and so degraded to a generic
# message on exactly the ordinary case.
_IMAGE_REFUSE_REASON=''
image_member_admissible() {
  local listing=$1 name=$2 norm
  _IMAGE_REFUSE_REASON=''
  norm=$(image_member_normalize "$name")
  if ! image_member_is_safe "$norm"; then
    if [[ $name == /* ]]; then
      _IMAGE_REFUSE_REASON=absolute_member_name
    elif [[ $norm == '..' || $norm == '..'/* || $norm == */'..'/* || $norm == */'..' ]]; then
      _IMAGE_REFUSE_REASON=parent_traversal_member_name
    else
      _IMAGE_REFUSE_REASON=malformed_member_name
    fi
    return 1
  fi
  if ! image_member_parents_are_dirs "$listing" "$norm"; then
    _IMAGE_REFUSE_REASON=member_parent_is_not_a_directory
    return 1
  fi
  return 0
}

# `image_member_present LISTING NAME` - exact-equality membership against the
# normalised listing.  Never a glob and never a substring: `*"$name"*` would
# match `etc/os-release.bak` for `etc/os-release`, and the whole point of the
# listing pass is that only a member proved present is ever named to tar.
image_member_present() {
  local listing=$1 want line
  want=$(image_member_normalize "$2")
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ $(image_member_normalize "$line") == "$want" ]] || continue
    return 0
  done <<<"$listing"
  return 1
}

# `image_member_raw_name LISTING NAME` - the listing's OWN spelling of the
# member whose normalised form is NAME, printed for handing back to tar.
# `./etc/os-release` and `etc/os-release` normalise to one name, but tar
# extracts only the spelling its own listing used, so the two must not be
# conflated at the point of extraction.
image_member_raw_name() {
  local listing=$1 want line
  want=$(image_member_normalize "$2")
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ $(image_member_normalize "$line") == "$want" ]] || continue
    printf '%s' "$line"
    return 0
  done <<<"$listing"
  return 1
}

# ---------------------------------------------------------------------------
# 4. Deletion - the one primitive, and why there is only one
# ---------------------------------------------------------------------------
# `image_rm_under_root ROOT REL` - remove ROOT/REL, where REL is a name this
# module derived from attacker-controlled bytes (an extracted member it is
# rejecting, or the target of an OCI whiteout).
#
# Every guard here exists because the value being removed is attacker-
# influenced, and a deletion bug in this file is worse than an extraction bug:
# an extraction bug writes a file somewhere it should not be, a deletion bug
# removes files that were already there.
#
#   1. ROOT must be non-empty and an existing directory.  An unset ROOT is
#      how `rm -rf "$ROOT/$REL"` becomes `rm -rf /...`.
#   2. REL must be non-empty and must pass image_member_is_safe - the SAME
#      validation extraction uses, so no `..`, no leading `/`, no `.`
#      component, no control byte.  A malformed whiteout member (`.wh.`,
#      naming no file at all) therefore yields a REFUSAL rather than a
#      deletion of the directory that contained it.
#   3. The target's own parent must resolve INSIDE ROOT's realpath, which is
#      what catches a symlinked parent that got created between validation and
#      deletion.
#   4. Only then, and through `"${var:?}"` on BOTH components, so a bug that
#      got past 1-3 and left either one empty aborts the shell instead of
#      expanding to the root itself.
#
# It returns 1 with `_IMAGE_REFUSE_REASON` set rather than dying, because the
# refusals above are things a hostile archive can cause at will and the run
# should record them, not abort on them.
image_rm_under_root() {
  local root=$1 rel=$2 norm parent
  _IMAGE_REFUSE_REASON=''
  if [[ -z $root || ! -d $root ]]; then
    _IMAGE_REFUSE_REASON=no_extraction_root
    return 1
  fi
  norm=$(image_member_normalize "$rel")
  if [[ -z $norm ]] || ! image_member_is_safe "$norm"; then
    _IMAGE_REFUSE_REASON=unsafe_delete_target
    return 1
  fi
  [[ -e $root/$norm || -L $root/$norm ]] || return 0
  parent=$(cd -- "$root" && cd -- "$(dirname -- "$norm")" 2>/dev/null && pwd -P) || {
    _IMAGE_REFUSE_REASON=unsafe_delete_target
    return 1
  }
  local rootreal
  rootreal=$(cd -- "$root" && pwd -P)
  if [[ $parent != "$rootreal" && $parent != "$rootreal"/* ]]; then
    _IMAGE_REFUSE_REASON=delete_target_escaped_the_extraction_root
    return 1
  fi
  rm -rf -- "${root:?}/${norm:?}"
  return 0
}

# ---------------------------------------------------------------------------
# 5. Extraction
# ---------------------------------------------------------------------------
# `_image_scratch_dir LABEL` - a fresh, private, unpredictably-named directory
# to unpack into.  `mktemp -d` and never a `$BASHPID`-derived fixed name: the
# lesson tests/suites/dast-cors.sh section A2 pins is that a predictable path
# under a shared scratch directory is one a local user can pre-create as a
# symlink that the process then writes THROUGH (CWE-377 via CWE-59), and the
# thing being written here is the contents of an untrusted archive.  `0700`
# for the same reason: what lands in here is an image's own files, which are
# nobody else's business while they are on this host.
_image_scratch_dir() {
  local base=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}} d
  d=$(mktemp -d "$base/scoursh-image-$1.XXXXXX") || return 1
  chmod 700 "$d" 2>/dev/null || true
  printf '%s' "$d"
  return 0
}

# `image_extract_member ARCHIVE LISTING MEMBER DESTROOT` - extract exactly one
# member, into DESTROOT.  0 on success; 1 on a refusal, with
# `_IMAGE_REFUSE_REASON` set; 5 when tar itself failed on a member its own
# listing named.
#
# Everything this function refuses, it refuses BEFORE running tar.  The one
# check that runs after is the belt this file's header describes: the result
# must be a regular file, must not be a symlink, and its realpath must still
# be inside DESTROOT.  That check cannot save a canary a write already
# destroyed, which is exactly why it is the belt and section 3 is the control
# - it exists to catch an escape that got past every earlier check, and to
# make sure nothing downstream ever reads bytes from outside the root.
image_extract_member() {
  local archive=$1 listing=$2 member=$3 destroot=$4
  local raw norm rc=0 real rootreal out
  _IMAGE_REFUSE_REASON=''

  if [[ -z $destroot || ! -d $destroot ]]; then
    _IMAGE_REFUSE_REASON=no_extraction_root
    return 1
  fi
  image_member_admissible "$listing" "$member" || return 1
  if ! image_member_present "$listing" "$member"; then
    _IMAGE_REFUSE_REASON=member_absent
    return 1
  fi
  raw=$(image_member_raw_name "$listing" "$member")
  norm=$(image_member_normalize "$member")

  # `-x` with one explicit, already-proved-present member.  No `-P`: nothing
  # here wants tar's "keep absolute paths and .." mode, and asking for it
  # would switch off containment this file does not rely on but has no reason
  # to disable.
  out=$(tar -xf "$archive" -C "$destroot" -- "$raw" 2>&1) || rc=$?
  if (( rc != 0 )); then
    log_warn "image: tar failed to extract '$raw' from $archive (rc=$rc): $out"
    return 5
  fi

  # `-L` first: a symlink whose target happens to be a regular file passes
  # `-f`, so testing `-f` alone would ACCEPT exactly the shape section 3's
  # third check exists to refuse.
  if [[ -L $destroot/$norm ]]; then
    image_rm_under_root "$destroot" "$norm" || true
    _IMAGE_REFUSE_REASON=extracted_member_is_a_symlink
    return 1
  fi
  if [[ ! -f $destroot/$norm ]]; then
    _IMAGE_REFUSE_REASON=extracted_member_is_not_a_regular_file
    return 1
  fi
  rootreal=$(cd -- "$destroot" && pwd -P)
  real=$(cd -- "$(dirname -- "$destroot/$norm")" && pwd -P)/$(basename -- "$norm")
  if [[ $real != "$rootreal"/* ]]; then
    _IMAGE_REFUSE_REASON=extracted_member_escaped_the_extraction_root
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 6. config/images.conf (rules/RULE-FORMAT.md §9.6.8)
# ---------------------------------------------------------------------------
# The reader lives here rather than in lib/config.sh for the reason section 1
# gives about the JSON flattener: lib/config.sh is a HUB and every edge added
# to it is paid for by every consumer in the tree, while this file is read by
# exactly one module.  What it reuses from lib/config.sh is the POLICY, not a
# copy of it - `config_load_if_present` is what makes an absent file a clean
# fallback and a MALFORMED file exit 4 rather than a silent "behaves as if
# absent" (rules/RULE-FORMAT.md §11), which for a file naming what to scan is
# the difference between "you have no images configured" and "your typo
# disabled the image you thought you were scanning".
# Read by consumers and by tests/suites/image-acquire.sh rather than inside
# this file, exactly as lib/config.sh's own CONFIG_SCOPE_LOADED is: it is what
# lets a caller tell "no config file" from "a config file with no record for
# this id", which are different facts about a run.
# shellcheck disable=SC2034
IMAGE_SOURCES_LOADED=0

image_sources_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/images.conf}
  IMAGE_SOURCES_LOADED=0
  config_load_if_present "$path" image-source images || return 1
  # shellcheck disable=SC2034
  IMAGE_SOURCES_LOADED=1
  return 0
}

# `image_source_resolve ID [OVERRIDE_PATH] [CONF_PATH]` - resolve an operator
# id to a (kind, path, reference) triple in `_IMAGE_SRC_KIND` /
# `_IMAGE_SRC_PATH` / `_IMAGE_SRC_REF`, with `_IMAGE_SRC_ORIGIN` recording
# WHERE the answer came from.  Returns 1, all four empty, when the id names
# nothing and no override was given.
#
# A SETTER, and void on purpose, for the reason `config_scope_require` is: it
# loads a record set as a side effect, and a caller writing
# `k=$(image_source_resolve ...)` would run that load inside the command
# substitution's subshell and throw the record set away.
#
# `--source PATH` overrides the configured path and is the only way to run
# with no config/images.conf at all.  It supplies a PATH and never a KIND: the
# kind is inferred from the filesystem - a directory is an OCI layout, a file
# is a docker-save tarball - because the two shapes are not confusable on disk
# and asking an operator to declare which one their own tarball is would be
# asking a question the tool can answer.  Where a record for the id DOES
# exist, the record's own `source` and `reference` still apply: an operator
# pointing at a rebuilt copy of the same image has not changed which shape it
# is, or which image inside it they meant.
#
# `_IMAGE_SRC_ORIGIN` exists so the caller can RECORD which of those happened.
# "scoursh read the image your config names" and "scoursh read whatever
# --source pointed at, and guessed its shape" are different facts, and a run
# that cannot tell them apart cannot report honestly about what it opened.
_IMAGE_SRC_KIND='' _IMAGE_SRC_PATH='' _IMAGE_SRC_REF='' _IMAGE_SRC_ORIGIN=''
image_source_resolve() {
  local id=$1 override=${2:-} path=${3:-$SCOURSH_INSTALL_ROOT/config/images.conf}
  local idx have_record=0
  _IMAGE_SRC_KIND='' _IMAGE_SRC_PATH='' _IMAGE_SRC_REF='' _IMAGE_SRC_ORIGIN=''
  [[ -n $id ]] || die "$SCOURSH_EXIT_USAGE" 'image_source_resolve called with no image id'

  if image_sources_load "$path"; then
    if idx=$(records_index_of_id images "$id" 2>/dev/null); then
      have_record=1
      _IMAGE_SRC_KIND=$(records_field images "$idx" source)
      _IMAGE_SRC_PATH=$(records_field images "$idx" path)
      _IMAGE_SRC_REF=$(records_field_or images "$idx" reference '')
      _IMAGE_SRC_ORIGIN=images_conf
    fi
  fi

  if [[ -n $override ]]; then
    _IMAGE_SRC_PATH=$override
    if (( have_record )); then
      _IMAGE_SRC_ORIGIN=images_conf_path_overridden_by_source_flag
    else
      _IMAGE_SRC_ORIGIN=source_flag_kind_inferred
      if [[ -d $override ]]; then
        _IMAGE_SRC_KIND=oci-layout
      else
        _IMAGE_SRC_KIND=docker-archive
      fi
    fi
    return 0
  fi

  # No record and no override: there is nothing to open.  Returning 1 rather
  # than inventing a path is the honest outcome - a run that silently examined
  # nothing would render as a clean image.
  (( have_record )) || return 1
  return 0
}

# ---------------------------------------------------------------------------
# 7. Shape A - a `docker save` tarball (report.md §1.2 shape A)
# ---------------------------------------------------------------------------
# The archive holds `manifest.json` (a top-level ARRAY, one entry per image),
# a config JSON blob, and one member per layer.  A layer is a tar INSIDE the
# tar, so acquisition here is two levels deep and both levels go through this
# file's own validation: a layer member name comes out of attacker-written
# JSON and is no more trusted than a name out of the listing.
#
# Sets `_IMAGE_LAYERS` (ordered, layer 0 first - manifest order IS application
# order, §1.6) and `_IMAGE_CONFIG_MEMBER`.
declare -ga _IMAGE_LAYERS=()
_IMAGE_CONFIG_MEMBER=''
_IMAGE_ENTRY=''

# Which entry of the manifest.json array to read.  With no `reference` and
# exactly one entry, that entry; with a `reference`, the entry whose
# `RepoTags` carries it; with several entries and no reference, a REFUSAL.
#
# Never "the first one".  report.md's coverage-honesty argument applies
# directly: "scoursh scanned an image from this file" and "scoursh scanned the
# image you meant" are different facts, only an operator can tell them apart,
# and a silent pick reports the second while having done the first.
#
# A SETTER (`_IMAGE_ENTRY`), and this one was written as a printer first and
# corrected by a test rather than by review.  Called as
# `entry=$(_image_docker_select_entry ...)` it runs in a SUBSHELL, so the
# `_IMAGE_REFUSE_REASON` it sets on a refusal dies with that subshell and the
# caller reports an empty reason - which is the same class of defect
# lib/awscli.sh's `aws_ro_account_id_set` and this file's own image_json_leaf
# already carry a comment about, and it was caught here by asserting the
# REASON and not only the status.
_image_docker_select_entry() {
  local flat=$1 want=$2
  local path type val idx best='' count=0
  local -A seen=()
  _IMAGE_ENTRY=''
  while IFS=$'\t' read -r path type val; do
    [[ $path == *$'\x1f'Layers$'\x1f'* ]] || continue
    idx=${path%%$'\x1f'*}
    [[ -z ${seen[$idx]:-} ]] || continue
    seen[$idx]=1
    count=$(( count + 1 ))
  done <<<"$flat"
  if [[ -z $want ]]; then
    if (( count == 1 )); then
      for idx in "${!seen[@]}"; do best=$idx; done
      _IMAGE_ENTRY=$best
      return 0
    fi
    if (( count == 0 )); then
      _IMAGE_REFUSE_REASON=manifest_names_no_layers
    else
      _IMAGE_REFUSE_REASON=multi_image_archive_needs_a_reference
    fi
    return 1
  fi
  while IFS=$'\t' read -r path type val; do
    [[ $path == *$'\x1f'RepoTags$'\x1f'* ]] || continue
    [[ $type == s ]] || continue
    [[ $(image_json_unescape "$val") == "$want" ]] || continue
    best=${path%%$'\x1f'*}
    break
  done <<<"$flat"
  if [[ -z $best ]]; then
    _IMAGE_REFUSE_REASON=reference_not_found_in_archive
    return 1
  fi
  _IMAGE_ENTRY=$best
  return 0
}

image_docker_archive_open() {
  local archive=$1 want=${2:-}
  local listing flat entry path type val manifest_dir line
  _IMAGE_LAYERS=()
  _IMAGE_CONFIG_MEMBER=''
  _IMAGE_REFUSE_REASON=''

  image_tar_listing_set listing "$archive" || return 5
  if ! image_member_present "$listing" manifest.json; then
    _IMAGE_REFUSE_REASON=no_manifest_json_in_archive
    return 1
  fi

  manifest_dir=$(_image_scratch_dir manifest) || return 5
  if ! image_extract_member "$archive" "$listing" manifest.json "$manifest_dir"; then
    erase_dir "$manifest_dir"
    return 1
  fi
  if ! flat=$(image_json_flatten <"$manifest_dir/manifest.json" 2>/dev/null); then
    erase_dir "$manifest_dir"
    _IMAGE_REFUSE_REASON=manifest_json_is_not_valid_json
    return 1
  fi
  erase_dir "$manifest_dir"

  _image_docker_select_entry "$flat" "$want" || return 1
  entry=$_IMAGE_ENTRY

  while IFS=$'\t' read -r path type val; do
    [[ $path == "$entry"$'\x1f'Config ]] || continue
    [[ $type == s ]] || continue
    _IMAGE_CONFIG_MEMBER=$(image_json_unescape "$val")
  done <<<"$flat"

  # The layer list, in the manifest's own INDEX order.  It is read out of the
  # index component of each leaf's path and then numerically sorted, rather
  # than taken in the order the flattener happened to print it: that order is
  # document order, which is the same thing for a well-formed array and is not
  # something a hostile document has to respect.  Layer order is what decides
  # which copy of a package database wins (§1.6), so it is derived from the
  # structure rather than from the serialisation.
  local -a idxs=()
  local declared=0
  while IFS=$'\t' read -r path type val; do
    [[ $path == "$entry"$'\x1f'Layers$'\x1f'* ]] || continue
    [[ $type == s ]] || continue
    declared=$(( declared + 1 ))
    idxs+=("${path##*$'\x1f'}"$'\t'"$(image_json_unescape "$val")")
  done <<<"$flat"
  if (( declared == 0 )); then
    _IMAGE_REFUSE_REASON=manifest_names_no_layers
    return 1
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    val=${line#*$'\t'}
    if ! image_member_admissible "$listing" "$val"; then
      log_warn "image: refusing layer member '$val' named by manifest.json ($_IMAGE_REFUSE_REASON)"
      return 1
    fi
    if ! image_member_present "$listing" "$val"; then
      _IMAGE_REFUSE_REASON=manifest_names_a_layer_the_archive_does_not_contain
      return 1
    fi
    _IMAGE_LAYERS+=("$val")
  done < <(printf '%s\n' "${idxs[@]+"${idxs[@]}"}" | LC_ALL=C sort -t$'\t' -k1,1n)
  (( declared == ${#_IMAGE_LAYERS[@]} )) || {
    _IMAGE_REFUSE_REASON=layer_list_did_not_round_trip
    return 1
  }
  return 0
}

# ---------------------------------------------------------------------------
# 8. Shape B - an OCI image layout directory (report.md §1.2 shape B)
# ---------------------------------------------------------------------------
# `index.json` names one or more manifests by digest; each manifest names a
# config and its layers by digest; every digest is a file under
# `blobs/<algo>/<hex>`.  Layers here are ordinary files on disk, not members
# of an outer tar, so there is no nested extraction - but a digest is
# attacker-written text that becomes a PATH, which is the traversal hazard
# this shape has instead of the tar one.
#
# `_image_oci_blob_path` is where that is refused: a digest must match
# `^[a-z0-9]+:[0-9a-f]{32,}$` exactly, so no `..`, no `/` and no absolute path
# can survive into the path it builds.  That is stricter than "reject `..`"
# and it is deliberately stricter - a digest has exactly one legal shape, and
# anything else is a malformed layout rather than a file to go looking for.
_image_oci_blob_path() {
  local root=$1 digest=$2 algo hex
  [[ $digest =~ ^([a-z0-9]+):([0-9a-f]{32,})$ ]] || return 1
  algo=${BASH_REMATCH[1]}
  hex=${BASH_REMATCH[2]}
  printf '%s' "$root/blobs/$algo/$hex"
}

image_oci_layout_open() {
  local root=$1 want=${2:-}
  local flat idx mdigest mpath mflat path type val best='' count=0
  local -A seen=()
  _IMAGE_LAYERS=()
  _IMAGE_CONFIG_MEMBER=''
  _IMAGE_REFUSE_REASON=''

  if [[ ! -d $root ]]; then
    _IMAGE_REFUSE_REASON=oci_layout_path_is_not_a_directory
    return 1
  fi
  if [[ ! -r $root/index.json ]]; then
    _IMAGE_REFUSE_REASON=no_index_json_in_layout
    return 1
  fi
  if ! flat=$(image_json_flatten <"$root/index.json" 2>/dev/null); then
    _IMAGE_REFUSE_REASON=index_json_is_not_valid_json
    return 1
  fi

  while IFS=$'\t' read -r path type val; do
    [[ $path == manifests$'\x1f'*$'\x1f'digest ]] || continue
    idx=${path#manifests$'\x1f'}
    idx=${idx%%$'\x1f'*}
    [[ -z ${seen[$idx]:-} ]] || continue
    seen[$idx]=1
    count=$(( count + 1 ))
  done <<<"$flat"

  if [[ -n $want ]]; then
    while IFS=$'\t' read -r path type val; do
      [[ $path == manifests$'\x1f'*$'\x1f'annotations$'\x1f'org.opencontainers.image.ref.name ]] || continue
      [[ $type == s ]] || continue
      [[ $(image_json_unescape "$val") == "$want" ]] || continue
      idx=${path#manifests$'\x1f'}
      best=${idx%%$'\x1f'*}
      break
    done <<<"$flat"
    if [[ -z $best ]]; then
      _IMAGE_REFUSE_REASON=reference_not_found_in_layout
      return 1
    fi
  else
    if (( count == 0 )); then
      _IMAGE_REFUSE_REASON=index_json_names_no_manifest
      return 1
    fi
    if (( count != 1 )); then
      _IMAGE_REFUSE_REASON=multi_image_layout_needs_a_reference
      return 1
    fi
    for idx in "${!seen[@]}"; do best=$idx; done
  fi

  if ! image_json_leaf mdigest "$root/index.json" "manifests"$'\x1f'"$best"$'\x1f'"digest"; then
    _IMAGE_REFUSE_REASON=manifest_entry_has_no_digest
    return 1
  fi
  if ! mpath=$(_image_oci_blob_path "$root" "$mdigest"); then
    _IMAGE_REFUSE_REASON=malformed_manifest_digest
    return 1
  fi
  if [[ ! -r $mpath ]]; then
    _IMAGE_REFUSE_REASON=manifest_blob_missing_from_layout
    return 1
  fi
  if ! mflat=$(image_json_flatten <"$mpath" 2>/dev/null); then
    _IMAGE_REFUSE_REASON=manifest_blob_is_not_valid_json
    return 1
  fi

  while IFS=$'\t' read -r path type val; do
    [[ $path == config$'\x1f'digest ]] || continue
    [[ $type == s ]] || continue
    _IMAGE_CONFIG_MEMBER=$(_image_oci_blob_path "$root" "$(image_json_unescape "$val")") \
      || _IMAGE_CONFIG_MEMBER=''
  done <<<"$mflat"

  local -a idxs=()
  local line blob
  while IFS=$'\t' read -r path type val; do
    [[ $path == layers$'\x1f'*$'\x1f'digest ]] || continue
    [[ $type == s ]] || continue
    idx=${path#layers$'\x1f'}
    idx=${idx%%$'\x1f'*}
    idxs+=("$idx"$'\t'"$(image_json_unescape "$val")")
  done <<<"$mflat"
  if (( ${#idxs[@]} == 0 )); then
    _IMAGE_REFUSE_REASON=manifest_names_no_layers
    return 1
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    val=${line#*$'\t'}
    if ! blob=$(_image_oci_blob_path "$root" "$val"); then
      _IMAGE_REFUSE_REASON=malformed_layer_digest
      return 1
    fi
    if [[ ! -r $blob ]]; then
      _IMAGE_REFUSE_REASON=layer_blob_missing_from_layout
      return 1
    fi
    _IMAGE_LAYERS+=("$blob")
  done < <(printf '%s\n' "${idxs[@]+"${idxs[@]}"}" | LC_ALL=C sort -t$'\t' -k1,1n)
  return 0
}

# `image_open KIND PATH [REFERENCE]` - the one door.  Both shapes end with
# `_IMAGE_LAYERS` populated in application order, so nothing downstream has to
# know which shape it came from - the same reason `scan_dispatch` exists one
# level up.  For a docker-archive the entries are MEMBER NAMES inside PATH;
# for an OCI layout they are BLOB PATHS on disk, which is why
# `image_layer_listing_set` below takes the kind rather than guessing.
image_open() {
  local kind=$1 path=$2 want=${3:-}
  case $kind in
    docker-archive) image_docker_archive_open "$path" "$want" ;;
    oci-layout) image_oci_layout_open "$path" "$want" ;;
    *)
      _IMAGE_REFUSE_REASON=unknown_image_source_kind
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 9. Layers, ordering, and whiteouts (report.md §1.6)
# ---------------------------------------------------------------------------
# Layers apply in manifest order and LATER WINS.  Deletions are OCI whiteouts:
# `<dir>/.wh.<name>` deletes one entry, `<dir>/.wh..wh..opq` clears everything
# the layers below contributed to `<dir>`.  A package database is rewritten
# wholesale by each `apk add` / `apt install`, so only the final state matters
# and a plain in-order overwrite is correct - no union filesystem and no
# per-file merge.
#
# `IMAGE_METADATA_PATHS` is the whole of what this module ever asks for.  It
# is a list of LOCATIONS and nothing here parses a single byte of any of them:
# the apk and dpkg readers are IMG-04 and IMG-07, and rpm - a binary database
# needing a new `sqlite3` dependency - is IMG-12 and is deliberately ABSENT
# rather than listed and unread, so this list never claims a coverage the
# module does not have.  Keeping it a handful of paths is what report.md §1.6
# calls a design invariant: scoursh never materialises a rootfs, so scanning a
# 900 MB image costs its layer INDEXES plus a few kilobytes.
declare -ga IMAGE_METADATA_PATHS=(
  etc/os-release
  usr/lib/os-release
  lib/apk/db/installed
  var/lib/dpkg/status
)

# `image_whiteout_names PATH` - every whiteout member name that would delete
# PATH: its own `.wh.` marker, plus the opaque marker of each ancestor
# directory.  One per line, most specific first.
#
# The opaque markers are included because `.wh..wh..opq` in `var/lib` clears
# what the layers below put in `var/lib`, which includes `var/lib/dpkg/status`
# - a reading that only looked for `var/lib/dpkg/.wh.status` reports a package
# database the final image does not have.
image_whiteout_names() {
  local p=$1 dir base rest
  p=$(image_member_normalize "$p")
  [[ -n $p ]] || return 0
  dir=${p%/*}
  base=${p##*/}
  if [[ -z $base ]]; then
    return 0
  fi
  if [[ $dir == "$p" ]]; then
    printf '%s\n' ".wh.$base"
  else
    printf '%s\n' "$dir/.wh.$base"
  fi
  rest=$p
  while [[ $rest == */* ]]; do
    rest=${rest%/*}
    [[ -n $rest ]] || break
    printf '%s\n' "$rest/.wh..wh..opq"
  done
  printf '%s\n' '.wh..wh..opq'
  return 0
}

# `image_whiteout_target NAME` - the path a whiteout member deletes, or 1 if
# NAME is not a usable whiteout member.
#
# The refusals are the point of this function existing at all.  `.wh.` with an
# empty basename names no file; a naive reading strips the prefix, gets the
# empty string, and hands it to a deleter that then removes the whole
# DIRECTORY the marker sat in - or, with an unguarded `rm "$root/$rel"`, the
# extraction root itself.  An attacker writes these names, so `.wh.` and
# `x/.wh.` are REFUSED here, and `image_rm_under_root` refuses them a second
# time even if this function is ever bypassed.
image_whiteout_target() {
  local name=$1 dir base
  name=$(image_member_normalize "$name")
  [[ -n $name ]] || return 1
  base=${name##*/}
  dir=${name%/*}
  [[ $base == .wh.* ]] || return 1
  [[ $base != '.wh..wh..opq' ]] || return 1
  base=${base#.wh.}
  [[ -n $base ]] || return 1
  if [[ $dir == "$name" ]]; then
    printf '%s' "$base"
  else
    printf '%s' "$dir/$base"
  fi
  return 0
}

# `image_layer_listing_set VARNAME KIND ARCHIVE LAYER` - the listing of ONE
# layer, whichever shape it came from.  A docker-archive layer is a member of
# the outer tar and has to be unpacked to scratch first; an OCI layer is
# already a file.  Sets VARNAME to the listing and `_IMAGE_LAYER_TAR` to the
# path of the tar the listing describes, which is what a later extraction
# names.
_IMAGE_LAYER_TAR=''
_IMAGE_LAYER_SCRATCH=''
image_layer_listing_set() {
  local __var=$1 kind=$2 archive=$3 layer=$4
  local outer rc=0
  printf -v "$__var" '%s' ''
  _IMAGE_LAYER_TAR=''
  image_layer_release
  case $kind in
    oci-layout)
      _IMAGE_LAYER_TAR=$layer
      ;;
    docker-archive)
      image_tar_listing_set outer "$archive" || return 5
      _IMAGE_LAYER_SCRATCH=$(_image_scratch_dir layer) || return 5
      if ! image_extract_member "$archive" "$outer" "$layer" "$_IMAGE_LAYER_SCRATCH"; then
        rc=$?
        image_layer_release
        return "$rc"
      fi
      _IMAGE_LAYER_TAR=$_IMAGE_LAYER_SCRATCH/$(image_member_normalize "$layer")
      ;;
    *)
      _IMAGE_REFUSE_REASON=unknown_image_source_kind
      return 1
      ;;
  esac
  image_tar_listing_set "$__var" "$_IMAGE_LAYER_TAR" || { image_layer_release; return 5; }
  return 0
}

# Release whatever `image_layer_listing_set` unpacked.  Named rather than
# inlined so the "unpack one layer, read it, throw it away" cycle is visible
# at every call site: a loop that forgot this would accumulate every layer of
# every image in scratch, which for a real image is exactly the full-rootfs
# materialisation §1.6 forbids.
image_layer_release() {
  if [[ -n $_IMAGE_LAYER_SCRATCH ]]; then
    erase_dir "$_IMAGE_LAYER_SCRATCH"
    _IMAGE_LAYER_SCRATCH=''
  fi
  return 0
}

# `image_layer_winner KIND ARCHIVE PATH` - the index into `_IMAGE_LAYERS` of
# the layer that supplies PATH in the final image, or 1 with nothing printed
# when the final image does not contain it.
#
# The walk is FORWARD, and every layer is examined, rather than backwards with
# an early exit on the first layer carrying the file.  A backwards walk reads
# a whiteout in a LOWER layer as if it deleted an UPPER layer's copy, which
# inverts the one rule this section has: later wins.  Both readings agree on
# the common case of a file written once and never deleted, which is why the
# fixture tree carries a path that is written, whited out, and written again -
# a test built only from the common case passes under both.
image_layer_winner() {
  local kind=$1 archive=$2 path=$3
  local i n winner=-1 listing wh
  path=$(image_member_normalize "$path")
  n=${#_IMAGE_LAYERS[@]}
  for (( i = 0; i < n; i++ )); do
    image_layer_listing_set listing "$kind" "$archive" "${_IMAGE_LAYERS[$i]}" || return 5
    while IFS= read -r wh; do
      [[ -n $wh ]] || continue
      if image_member_present "$listing" "$wh"; then winner=-1; fi
    done < <(image_whiteout_names "$path")
    if image_member_present "$listing" "$path"; then
      winner=$i
    fi
    image_layer_release
  done
  (( winner >= 0 )) || return 1
  printf '%d' "$winner"
  return 0
}

# `image_collect_metadata KIND ARCHIVE DESTROOT [PATH...]` - the module's one
# acquisition entry point, and the only function outside this file a later
# ticket needs.  For each wanted path (default `IMAGE_METADATA_PATHS`) it
# resolves the winning layer, extracts that one member into DESTROOT, and
# prints one `<path><TAB><layer index>` line per path it actually obtained.
#
# Sets `IMAGE_COLLECT_MISSING` to the paths the final image does not carry,
# and `IMAGE_COLLECT_REFUSED` to `<path><TAB><reason>` for the ones a refusal
# stopped.  Those two are NOT the same fact and are deliberately not merged:
# "this Alpine image has no dpkg database" is the ordinary case and says
# nothing is wrong, while "this image's dpkg database sat behind a member this
# scanner refused to extract" is a coverage hole a later ticket has to
# report rather than render as a clean scan.
declare -ga IMAGE_COLLECT_MISSING=()
declare -ga IMAGE_COLLECT_REFUSED=()
image_collect_metadata() {
  local kind=$1 archive=$2 destroot=$3
  shift 3
  local -a wanted=()
  if (( $# > 0 )); then
    wanted=("$@")
  else
    wanted=("${IMAGE_METADATA_PATHS[@]+"${IMAGE_METADATA_PATHS[@]}"}")
  fi
  IMAGE_COLLECT_MISSING=()
  IMAGE_COLLECT_REFUSED=()

  if [[ -z $destroot || ! -d $destroot ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" 'image_collect_metadata called with no extraction root'
  fi

  local p idx listing rc
  for p in "${wanted[@]+"${wanted[@]}"}"; do
    rc=0
    idx=$(image_layer_winner "$kind" "$archive" "$p") || rc=$?
    if (( rc == 5 )); then
      IMAGE_COLLECT_REFUSED+=("$p"$'\t'unreadable_layer)
      continue
    fi
    if (( rc != 0 )); then
      IMAGE_COLLECT_MISSING+=("$p")
      continue
    fi
    if ! image_layer_listing_set listing "$kind" "$archive" "${_IMAGE_LAYERS[$idx]}"; then
      IMAGE_COLLECT_REFUSED+=("$p"$'\t'unreadable_layer)
      continue
    fi
    if image_extract_member "$_IMAGE_LAYER_TAR" "$listing" "$p" "$destroot"; then
      printf '%s\t%s\n' "$p" "$idx"
    else
      IMAGE_COLLECT_REFUSED+=("$p"$'\t'"${_IMAGE_REFUSE_REASON:-unknown}")
    fi
    image_layer_release
  done
  return 0
}

# ---------------------------------------------------------------------------
# 10. The image CONFIG BLOB (IMG-06, report.md §4.1's IMAGE-CFG-* row)
# ---------------------------------------------------------------------------
# `image_config_blob_read KIND ARCHIVE DESTROOT` - resolves `_IMAGE_CONFIG_MEMBER`
# (set by image_open, whichever shape opened) to a real, readable file and
# sets `_IMAGE_CONFIG_PATH` to it.  Unlike a layer member, the config blob is
# never inside a layer, so this does not go through image_layer_winner/
# image_collect_metadata at all.
#
# For an oci-layout the config is already a real file on disk -
# `_image_oci_blob_path` resolved it at image_open time, through the same
# digest-shape validation every blob path in section 8 goes through - so this
# is a plain readability check, no extraction.
#
# For a docker-archive the config is a member of the OUTER tar (never a
# layer), so it goes through the identical image_extract_member security gate
# every other extraction in this file does: a config blob is attacker-
# controlled content exactly like a layer is, and "it is only metadata, not a
# layer" is not a reason to extract it any differently.
#
# Returns 0 with `_IMAGE_CONFIG_PATH` set; returns 1 with
# `_IMAGE_REFUSE_REASON` set (never dies) when the manifest/index declared no
# config member at all, or when the blob is missing/refused - the caller
# turns that into a `coverage_reduction reason=image_config_unreadable`
# (report.md §4.3's own row), never a fatal error, since a malformed or
# missing config blob is a fact about the image, not about this tool.
_IMAGE_CONFIG_PATH=''
image_config_blob_read() {
  local kind=$1 archive=$2 destroot=$3
  _IMAGE_CONFIG_PATH=''
  _IMAGE_REFUSE_REASON=''

  if [[ -z $_IMAGE_CONFIG_MEMBER ]]; then
    _IMAGE_REFUSE_REASON=config_member_not_declared
    return 1
  fi

  case $kind in
    oci-layout)
      if [[ ! -r $_IMAGE_CONFIG_MEMBER ]]; then
        _IMAGE_REFUSE_REASON=config_blob_missing_from_layout
        return 1
      fi
      _IMAGE_CONFIG_PATH=$_IMAGE_CONFIG_MEMBER
      return 0
      ;;
    docker-archive)
      if [[ -z $destroot || ! -d $destroot ]]; then
        _IMAGE_REFUSE_REASON=no_extraction_root
        return 1
      fi
      local outer rc=0
      image_tar_listing_set outer "$archive" || return 5
      if ! image_extract_member "$archive" "$outer" "$_IMAGE_CONFIG_MEMBER" "$destroot"; then
        rc=$?
        (( rc == 5 )) && return 5
        return 1
      fi
      _IMAGE_CONFIG_PATH=$destroot/$(image_member_normalize "$_IMAGE_CONFIG_MEMBER")
      return 0
      ;;
    *)
      _IMAGE_REFUSE_REASON=unknown_image_source_kind
      return 1
      ;;
  esac
}
