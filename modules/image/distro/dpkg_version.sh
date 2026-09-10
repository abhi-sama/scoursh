#!/usr/bin/env bash
# modules/image/distro/dpkg_version.sh - the dpkg (Debian/Ubuntu) VERSION
# COMPARATOR (IMG-08; data/scoursh-image-scan-design/report.md §2.4 "THE
# BLOCKER" and §5.3's IMG-08 row, "dpkg comparator - epoch + tilde,
# differential-tested").
#
# WHAT THIS FILE IS.  A total ordering over Debian/Ubuntu package version
# strings, in pure bash: no fork, no `sort -V`, no external command, and no
# arithmetic on an untrusted digit run.  It is the piece a later ticket needs
# to decide whether an installed `Version:` read by
# `modules/image/distro/dpkg.sh` is below an advisory's fixed-in version.
#
# WHAT THIS FILE DELIBERATELY IS NOT.  No advisory lookup, no
# `data/advisories.db` read, no finding, no `run_record`, no coverage
# reduction, and no `modules/image/run.sh` wiring - all of that is IMG-09 and
# later.  Like `modules/image/distro/apk_version.sh` (IMG-05),
# `modules/image/distro/dpkg.sh` (IMG-07) and `modules/sca/semver.sh` before
# it, this is a LEAF: it sources nothing, so it adds no edge to the
# `shellcheck -x` source graph `tests/lint-source-graph.sh` caps (AGENTS.md,
# "the memory model").  Keep it that way.
#
# ---------------------------------------------------------------------------
# WHY THIS IS NOT `modules/sca/semver.sh`, AND NOT `apk_version.sh` EITHER
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh` is npm-only by explicit, measured decision - its own
# header records 1.66% divergence against real PEP 440, "a false-NEGATIVE
# divergence, the exact direction tension 25 calls disqualifying", as the
# reason it never generalised into a shared `version_cmp`.
#
# report.md §2.4 applied that same standard to OS versions and measured the
# shipped comparator at 5 correct / 7 WRONG out of 12.  Three of those seven
# are dpkg's, and they are this file's reason to exist:
#
#     MISMATCH  1:2.30.2-1  vs  2.39.5-1   semver=-1  true= 1
#     MISMATCH  1.0         vs  1.0~beta   semver= 0  true= 1
#     MISMATCH  5:1.0-1     vs  10.0-1     semver=-1  true= 1
#
# `_sv_split` strips a leading `v`, drops `+build`, splits on the FIRST `-`
# and coerces a non-numeric component to `0`, so `1:2.30.2-1`'s major becomes
# the non-numeric `1:2` and therefore `0`.  The epoch, the tilde and the
# revision - the three things that actually order a Debian version - are
# invisible to it.  The first row above is the false-POSITIVE direction (a
# patched package reported vulnerable: noisy, survivable) and the second is
# worse: `semver= 0`, EQUAL, which a caller asking "is the installed version
# below the fixed-in version" reads as "not below", reads as "not
# vulnerable", and reports with no diagnostic at all.  Reuse is ruled out by
# the project's own frozen standard, measured the same way that standard was
# originally set.
#
# `apk_version.sh` is equally unusable here, and the inverse temptation - one
# `os_version_cmp` for both distros - is just as wrong.  apk and dpkg
# disagree on cases both consider ordinary:
#
#     1.0 vs 1.0-r0 / 1.0-0     apk: LESS (an absent pkgrel is not -r0)
#                               dpkg: EQUAL (an absent revision IS "0")
#     1.0~beta                  apk: invalid, `~` is not in its grammar
#                               dpkg: the single most important ordering rule
#     1.0_git1                  apk: a post-release suffix, sorts ABOVE 1.0
#                               dpkg: `_` is not a legal character at all
#
# so a merged comparator is necessarily wrong for one of its two callers.
# Three distros, three files, by measurement rather than by preference.
#
# ---------------------------------------------------------------------------
# THE GRAMMAR, AND THE ALGORITHM
# ---------------------------------------------------------------------------
# `deb-version(7)`:
#
#     [epoch:]upstream_version[-debian_revision]
#
#   epoch              a single unsigned integer, default 0 when absent.
#                      Compared FIRST, and NUMERICALLY - which is the whole
#                      of report.md §2.4's `5:1.0-1 > 10.0-1`: epoch 5 beats
#                      epoch 0 without ever looking at 1.0 against 10.0.
#   upstream_version   alphanumerics plus `. + - : ~`, starting with a digit.
#                      A `-` may appear only when a revision is present (the
#                      LAST `-` is the separator); a `:` only when an epoch
#                      is present (the FIRST `:` is that separator, so a
#                      second one survives into the upstream part).
#   debian_revision    alphanumerics plus `. + ~`.  ABSENT is not "no
#                      revision" but the empty string, which compares EQUAL
#                      to `0` - see the `1.0 = 1.0-0` row below, and note it
#                      is the exact case where apk goes the other way.
#
# The comparison is dpkg's own `dpkg_version_compare`: epochs as integers,
# then `verrevcmp` on the upstream parts, then `verrevcmp` on the revisions.
# The first non-zero result wins.
#
# `verrevcmp` walks the two strings in lockstep, alternating two phases until
# both are exhausted:
#
#   1. NON-DIGIT PHASE.  While either side is at a non-digit that is not the
#      end of its string, compare the two characters under the MODIFIED ASCII
#      order below and return on the first difference.
#   2. DIGIT PHASE.  Strip leading zeros from both, then walk the two digit
#      runs together remembering the FIRST differing digit.  Whichever run is
#      still going when the other stops is the LARGER number; if both stop
#      together, the remembered digit decides.
#
# THE MODIFIED ASCII ORDER, which is where every interesting dpkg case lives:
#
#     order('~')      = -1     lowest of all, BELOW the end of the string
#     order(digit)    =  0     ) and the end of the string is also 0, which
#     order(end)      =  0     ) is why a digit never beats an exhausted side
#                                in phase 1 - phase 1 is not entered at all
#     order(letter)   = the code point            (65..122)
#     order(anything) = the code point + 256      (>= 289)
#
# so LETTERS SORT BEFORE EVERY OTHER NON-ALPHANUMERIC, and a TILDE SORTS
# BEFORE EVERYTHING INCLUDING THE EMPTY STRING.  Worked, because reading the
# table is not the same as believing it:
#
#     1.0~beta  <  1.0        `~`(-1) against the end of "1.0"(0)
#     1.0~~     <  1.0~       a second `~` against the end
#     1.0       <  1.0a       the end(0) against `a`(97)
#     1.0a      <  1.0+       `a`(97) against `+`(299) - a letter first
#     1.0a      <  1.0.1      `a`(97) against `.`(302), same rule
#     1.0       =  1.0-0      an absent revision IS "0" once zeros are
#                             stripped; contrast apk, where it is not
#     1.09      =  1.9        leading zeros are stripped before the run
#                             comparison, so these are the same number
#     3.11      >  3.10+nmu1  the digit runs decide before `+` is reached
#     1.0-1~bpo11+1 < 1.0-1   the tilde rule inside the REVISION, which is
#                             what makes a Debian backport sort below the
#                             release it was backported from
#
# The tilde rule is the one this file exists for, and it fails in the
# direction that reads as a clean scan: `1.0~beta` is a PRE-release, so a
# comparator that ranks it at or above `1.0` reports a pre-release build as
# already carrying `1.0`'s fixes.
#
# MALFORMED INPUT IS UNORDERABLE, NOT "EQUAL" AND NOT "LESS".  Anything
# `deb-version(7)` does not accept - an empty string, an upstream part not
# starting with a digit, a non-numeric or empty epoch, an empty revision
# after a trailing `-`, an out-of-alphabet byte - makes the version
# UNORDERABLE.  `dpkg_version_cmp_v` then returns rc 1 and sets
# `_DPKGV_REASON` to `invalid_version_a` or `invalid_version_b`, leaving
# `_DPKGV_CMP` at 0; it never invents an ordering.  This matters more than it
# looks: the two silent alternatives are "call it equal" and "call it less",
# and BOTH render an unreadable version identically to a version that was
# read and found safe.  A caller owes a `coverage_reduction` on rc 1, never a
# silent skip - and `modules/image/distro/dpkg.sh` deliberately emits a
# package with an EMPTY version string when its block carried no `Version:`
# line (that file's own §"a block that passes both gates but carries no
# Version:"), so an unorderable input is an ordinary, expected arrival here
# rather than a corrupt-database edge case.
#
# TWO WELL-FORMED VERSIONS ARE ALWAYS ORDERED.  `verrevcmp` is total by
# construction - it consumes both strings - so unlike `apk_version.sh` this
# file needs no field-order rule and has NO divergence from the reference
# tool's own ordering.  `invalid_version_a`/`invalid_version_b` are the only
# two reasons it can report.
#
# NO ARITHMETIC ON UNTRUSTED DIGITS.  A version string comes out of a scanned
# image's package database and is untrusted text (the same caution
# `modules/sca/semver.sh`'s header raises for OSV-supplied strings, one step
# more exposed).  `$(( 10#$run ))` on a 400-digit run silently wraps at 64
# bits, so a hostile or corrupt database could make a low version compare
# high.  dpkg's own algorithm never needs the value of a run - "whichever run
# is still going is larger, else the first differing digit decides" is exact
# at any width - and this file keeps that property, comparing the EPOCH the
# same way (`_dpkgv_cmp_digits`: stripped length first, bytes second).  The
# only values fed to `(( ))` are character orders minted from this file's own
# table.
#
# FORK-FREE BY CONSTRUCTION.  `dpkg_version_cmp_v` SETS `_DPKGV_CMP` rather
# than printing it - the `occurrence_next`/`worker_id_set` idiom AGENTS.md
# mandates, because a side-effecting function called as `$(f)` runs in a
# subshell and its writes are discarded.  `dpkg_version_cmp` (printing) is
# kept only for the differential harness, exactly as `semver_cmp` and
# `apk_version_cmp` are.
#
# ---------------------------------------------------------------------------
# THE TWO DELIBERATE STRICTNESSES, BOTH IN THE FAIL-SAFE DIRECTION
# ---------------------------------------------------------------------------
# `dpkg`'s own `parseversion` is looser than this file in two places, and in
# both this file REFUSES where dpkg answers, or ANSWERS where dpkg refuses -
# never the other way round, so neither can turn a finding into silence:
#
#   1. LEADING WHITESPACE.  dpkg trims leading blanks before parsing, so it
#      orders " 1.0" as "1.0".  This file rejects it.  A `Version:` line with
#      a stray leading blank is a database this scanner should report as
#      unreadable rather than quietly normalise, and rc 1 is what makes that
#      visible.  No corpus row carries whitespace, so the deferred live
#      `dpkg --compare-versions` differential is unaffected.
#   2. A HUGE EPOCH.  dpkg refuses an epoch above INT_MAX ("epoch in version
#      is too big").  This file orders it, width-exact and correctly.  That
#      can only turn a refusal into a right answer.
#
# ---------------------------------------------------------------------------
# THE OFFLINE-CORPUS LIMIT, AND THE FOLLOW-UP HARDENING THIS OWES
# ---------------------------------------------------------------------------
# `modules/sca/semver.sh`'s bar is "differential-tested against a reference,
# 0 mismatches".  `tests/suites/image-dpkg-version.sh` meets it twice over -
# against a committed, provenance-annotated corpus of known orderings
# (`tests/fixtures/image/dpkg-version-corpus.tsv`) and against an independent
# Python reference over a generated sweep - but BOTH references are derived
# from `deb-version(7)`'s documented algorithm and from dpkg's own published
# test vectors rather than harvested by running the tool.  scoursh is
# egress-restricted and no `dpkg` binary exists on the development host, so
# `dpkg --compare-versions` could not be run and nothing was fetched.
#
# The follow-up hardening is therefore: on a networked box with dpkg
# installed, replay the committed corpus through
# `dpkg --compare-versions A lt|eq|gt B`, harvest real `Version:` pairs from
# a Debian and an Ubuntu package index, and extend the corpus with whatever
# it disagrees on.  The corpus file's `<`/`=`/`>` column is deliberately the
# same vocabulary `apk-version-corpus.tsv` uses and maps one-for-one onto
# dpkg's `lt`/`eq`/`gt` operators, so that run is a direct column diff rather
# than a translation.  This is the same shape as the GNU-tar cross-check
# `tools/daily-suite.sh` already defers - a stated gap with a named
# discharge, not an unmeasured claim.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_IMAGE_DPKG_VERSION_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_IMAGE_DPKG_VERSION_SOURCED=1

# ---------------------------------------------------------------------------
# 1. The modified ASCII order table
# ---------------------------------------------------------------------------

# `_DPKGV_ORDER[c]` is `order(c)` from the header, precomputed once at source
# time over exactly the alphabet `deb-version(7)` allows, so the hot loop does
# a table lookup rather than a `printf -v` per character.  The END of a string
# is handled at the two call sites (its order is 0, the same as a digit's,
# which is what keeps phase 1 out of the "digit against exhausted side" case
# entirely); it is not a key here because an associative array has no empty
# subscript.
declare -A _DPKGV_ORDER
_dpkgv_build_order_table() {
  local c code
  for c in 0 1 2 3 4 5 6 7 8 9; do
    _DPKGV_ORDER[$c]=0
  done
  for c in {a..z} {A..Z}; do
    printf -v code '%d' "'$c"
    _DPKGV_ORDER[$c]=$code
  done
  # `~` is the one character below the end of the string.
  _DPKGV_ORDER['~']=-1
  # Every other legal character sorts above every letter.  `.` `+` `-` `:`
  # is the whole of the rest of the upstream alphabet; the revision alphabet
  # is a subset of it, so one table serves both parts.
  for c in . + - :; do
    printf -v code '%d' "'$c"
    _DPKGV_ORDER[$c]=$(( code + 256 ))
  done
}
_dpkgv_build_order_table
unset -f _dpkgv_build_order_table

# ---------------------------------------------------------------------------
# 2. Parsing
# ---------------------------------------------------------------------------

# _dpkgv_parse VERSION - splits VERSION into `_DPKGV_EPOCH`,
# `_DPKGV_UPSTREAM` and `_DPKGV_REVISION` and returns 0, or returns 1 leaving
# all three unspecified when VERSION is not a legal Debian version.
#
# The order of the three splits is dpkg's own and is not interchangeable: the
# epoch comes off at the FIRST `:` (so a second colon stays in the upstream
# part), and the revision comes off at the LAST `-` (so `1.0-1-2` is upstream
# `1.0-1`, revision `2`).  Doing either the other way round silently
# re-partitions real versions.
_dpkgv_parse() {
  local v=$1 rest ep rev up

  [[ -n $v ]] || return 1

  # 2a. Epoch, at the FIRST colon.  Both halves must be non-empty and the
  # epoch must be digits only - which is also what rejects a negative epoch,
  # since `-` is not a digit.
  if [[ $v == *:* ]]; then
    ep=${v%%:*}
    rest=${v#*:}
    [[ -n $ep && -n $rest ]] || return 1
    [[ $ep != *[!0-9]* ]] || return 1
  else
    ep=0
    rest=$v
  fi

  # 2b. Revision, at the LAST hyphen.  A trailing hyphen leaves an empty
  # revision, which dpkg refuses outright ("revision number is empty").
  if [[ $rest == *-* ]]; then
    rev=${rest##*-}
    up=${rest%-*}
    [[ -n $rev ]] || return 1
  else
    rev=''
    up=$rest
  fi

  # 2c. The upstream part must be non-empty and must start with a digit.
  [[ -n $up ]] || return 1
  [[ ${up:0:1} == [0-9] ]] || return 1

  # 2d. The two alphabets, and the whole of the character validation - there
  # is deliberately no per-character loop after this.  `*[!SET]*` is enough on
  # its own because bash's `*` matches ANY byte including a newline and a tab,
  # so a value carrying one still presents an out-of-alphabet character to the
  # bracket negation and is refused.  That was worth measuring rather than
  # assuming: an earlier draft carried a second, per-character scan for
  # exactly the newline case, on the belief that a glob could not see it, and
  # it was pure cost on the hot path - `_dpkgv_parse` runs twice per
  # comparison.  `tests/suites/image-dpkg-version.sh` section C keeps the
  # newline, tab and space operands so a later "simplification" of this glob
  # cannot quietly reopen the hole.
  #
  # The set is spelled out rather than reached through a named character class
  # so it behaves identically under every locale.  A `-` inside the brackets
  # must be LAST or it would be read as a range; putting it anywhere else here
  # silently widens the accepted alphabet.
  [[ $up != *[!0-9a-zA-Z.+:~-]* ]] || return 1
  [[ $rev != *[!0-9a-zA-Z.+~]* ]] || return 1

  _DPKGV_EPOCH=$ep
  _DPKGV_UPSTREAM=$up
  _DPKGV_REVISION=$rev
  return 0
}

# ---------------------------------------------------------------------------
# 3. Comparison
# ---------------------------------------------------------------------------

# _dpkgv_cmp_digits A B - sets _DPKGV_R to -1/0/1 comparing two digit runs as
# INTEGERS, at any width and with no arithmetic evaluation.  Leading zeros are
# stripped, then the longer stripped run is the larger number, and equal
# lengths fall to a plain byte comparison (digits collate in ascending order
# in every locale, so this needs no LC_ALL pin).  Used for the EPOCH; the
# upstream and revision runs are compared in-line by `_dpkgv_verrevcmp`,
# which gets the same width-exactness out of dpkg's own two-pointer walk.
_dpkgv_cmp_digits() {
  local a=$1 b=$2
  while (( ${#a} > 1 )) && [[ $a == 0* ]]; do a=${a#0}; done
  while (( ${#b} > 1 )) && [[ $b == 0* ]]; do b=${b#0}; done
  if (( ${#a} != ${#b} )); then
    if (( ${#a} < ${#b} )); then _DPKGV_R=-1; else _DPKGV_R=1; fi
    return 0
  fi
  if [[ $a < $b ]]; then _DPKGV_R=-1
  elif [[ $a > $b ]]; then _DPKGV_R=1
  else _DPKGV_R=0
  fi
  return 0
}

# _dpkgv_verrevcmp A B - sets _DPKGV_R to -1/0/1 for one PART of a version
# (an upstream part, or a revision).  This is dpkg's `verrevcmp`, transcribed
# from the algorithm `deb-version(7)` documents rather than from any source
# file, with the two phases and the sentinel handling described in the
# header.
#
# Termination: every iteration of the outer loop either returns or advances at
# least one of the two cursors.  The one shape that could stall - neither side
# at a comparable non-digit, and no digit run to walk - can only arise when
# one side is exhausted and the other is at a digit, and that is precisely the
# "trailing digits win" case, which returns.
_dpkgv_verrevcmp() {
  local a=$1 b=$2
  local na=${#a} nb=${#b}
  local i=0 j=0
  local first_diff ca cb oa ob

  while (( i < na || j < nb )); do
    first_diff=0

    # Phase 1: the non-digit run.  Entered while EITHER side is at a
    # non-digit that is not the end of its string - which is what lets a
    # tilde be compared against the empty end of the other side, the whole
    # point of the rule.
    while :; do
      if (( i < na )); then ca=${a:i:1}; else ca=''; fi
      if (( j < nb )); then cb=${b:j:1}; else cb=''; fi
      if { [[ -n $ca && $ca != [0-9] ]] || [[ -n $cb && $cb != [0-9] ]]; }; then
        if [[ -n $ca ]]; then oa=${_DPKGV_ORDER[$ca]-0}; else oa=0; fi
        if [[ -n $cb ]]; then ob=${_DPKGV_ORDER[$cb]-0}; else ob=0; fi
        if (( oa != ob )); then
          if (( oa < ob )); then _DPKGV_R=-1; else _DPKGV_R=1; fi
          return 0
        fi
        i=$(( i + 1 ))
        j=$(( j + 1 ))
        continue
      fi
      break
    done

    # Phase 2: the digit run.  Leading zeros come off FIRST, which is what
    # makes `1.09` and `1.9` the same number and `1.0000-1` and `1.0-1` the
    # same version.
    while (( i < na )) && [[ ${a:i:1} == 0 ]]; do i=$(( i + 1 )); done
    while (( j < nb )) && [[ ${b:j:1} == 0 ]]; do j=$(( j + 1 )); done
    while (( i < na && j < nb )) && [[ ${a:i:1} == [0-9] && ${b:j:1} == [0-9] ]]; do
      if (( first_diff == 0 )); then
        ca=${a:i:1}
        cb=${b:j:1}
        if [[ $ca != "$cb" ]]; then
          if [[ $ca < $cb ]]; then first_diff=-1; else first_diff=1; fi
        fi
      fi
      i=$(( i + 1 ))
      j=$(( j + 1 ))
    done
    # A run that is still going once the other has stopped is the LARGER
    # number - the width comparison, done without ever evaluating either run.
    if (( i < na )) && [[ ${a:i:1} == [0-9] ]]; then _DPKGV_R=1; return 0; fi
    if (( j < nb )) && [[ ${b:j:1} == [0-9] ]]; then _DPKGV_R=-1; return 0; fi
    if (( first_diff != 0 )); then _DPKGV_R=$first_diff; return 0; fi
  done

  _DPKGV_R=0
  return 0
}

# ---------------------------------------------------------------------------
# 4. Public interface
# ---------------------------------------------------------------------------

# dpkg_version_valid VERSION - rc 0 when VERSION is a legal Debian version,
# rc 1 when it is not.  Callers that want to report an unreadable version
# WITHOUT ordering it use this.
dpkg_version_valid() {
  _dpkgv_parse "$1"
}

# dpkg_version_cmp_v A B - sets _DPKGV_CMP to -1 (A<B), 0 (A==B) or 1 (A>B)
# and returns 0.  Returns 1 WITHOUT ordering - leaving _DPKGV_CMP at 0, which
# a caller must never read as "equal" - and sets _DPKGV_REASON to one of:
#
#   invalid_version_a / invalid_version_b   that side is not a legal Debian
#                                           version
#
# Two WELL-FORMED versions are always ordered, so a refusal always means an
# unreadable input rather than "I could not decide".  This is the fork-free
# production entry point.
dpkg_version_cmp_v() {
  _DPKGV_CMP=0
  _DPKGV_REASON=''
  local ea ua ra eb ub rb

  if ! _dpkgv_parse "$1"; then _DPKGV_REASON=invalid_version_a; return 1; fi
  ea=$_DPKGV_EPOCH; ua=$_DPKGV_UPSTREAM; ra=$_DPKGV_REVISION
  if ! _dpkgv_parse "$2"; then _DPKGV_REASON=invalid_version_b; return 1; fi
  eb=$_DPKGV_EPOCH; ub=$_DPKGV_UPSTREAM; rb=$_DPKGV_REVISION

  # The epoch decides on its own when it differs - report.md §2.4's
  # `5:1.0-1 > 10.0-1` never reaches the upstream comparison at all.
  _dpkgv_cmp_digits "$ea" "$eb"
  if (( _DPKGV_R != 0 )); then _DPKGV_CMP=$_DPKGV_R; return 0; fi

  _dpkgv_verrevcmp "$ua" "$ub"
  if (( _DPKGV_R != 0 )); then _DPKGV_CMP=$_DPKGV_R; return 0; fi

  # An ABSENT revision is the empty string here, not a missing field: it
  # compares EQUAL to "0" once phase 2 strips the zeros, and BELOW any
  # non-zero revision.  This is the case where dpkg and apk go opposite ways.
  _dpkgv_verrevcmp "$ra" "$rb"
  _DPKGV_CMP=$_DPKGV_R
  return 0
}

# dpkg_version_cmp A B - prints `-1`, `0` or `1`, or prints `?` and returns 1
# when either side is unorderable.  Kept for the differential harness only,
# exactly as `modules/sca/semver.sh` keeps `semver_cmp` and
# `modules/image/distro/apk_version.sh` keeps `apk_version_cmp`; production
# callers use dpkg_version_cmp_v.
dpkg_version_cmp() {
  if dpkg_version_cmp_v "$1" "$2"; then
    printf '%s' "$_DPKGV_CMP"
    return 0
  fi
  printf '?'
  return 1
}
