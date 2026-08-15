#!/usr/bin/env bash
# tests/lint-status.sh - the committed status blocks in AGENTS.md, README.md and
# docs/FOUNDATION.md must equal what tools/gen-status.sh generates today.
#
# WHY.  Both files carried the module inventory as prose, and prose that states
# negatives ("neither has landed yet", "nothing beyond X remains") has to be
# rewritten by every ticket that lands any module, so concurrent branches
# conflicted on it by construction and it went stale three separate times.  The
# inventory is now generated; this lint is what makes staleness a build failure
# rather than a convention nobody enforces.
#
# It has FOUR parts, and parts 2-4 exist because a guard nobody has watched fail
# is not known to be a guard at all:
#
#   1. positive - every committed block matches a fresh generation.
#   2. negative - a HAND-EDITED block is caught.  Three separate perturbations,
#      each on its own copy: a flipped status word, a deleted table row, and an
#      appended line.  A `--check` that passed against any of these would be
#      decorative.  This is the reading the lint fails under: "the block is
#      close enough / only the numbers matter".
#   3. scope - an edit OUTSIDE the markers is NOT caught, because the whole
#      point is that the hand-written narrative stays hand-written.  A guard
#      that also policed the prose would be reverted the first time someone
#      wanted to write a paragraph.
#   4. mirror - all three files carry byte-identical blocks.  The "mirror" that
#      used to be maintained by hand (and drifted: AGENTS.md said ten pattern
#      packs, docs/FOUNDATION.md said eleven, and the tree held twelve) is now
#      mechanically the same bytes in every copy.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
cd "$ROOT"

FAILED=0
WORK=$SCOURSH_SCRATCH/lint-status
mkdir -p "$WORK"

ok() { printf '  ok  %s\n' "$1"; }
bad() {
  FAILED=1
  printf 'lint-status: %s\n' "$1" >&2
}

GEN=(bash tools/gen-status.sh)

# --- 1. the committed blocks are current ------------------------------------
printf '== the committed blocks match a fresh generation ==\n'
if "${GEN[@]}" --check >"$WORK/check.out" 2>"$WORK/check.err"; then
  ok 'every file carrying a generated block is up to date'
else
  bad 'a committed status block is stale - run: tools/gen-status.sh --write'
  cat -- "$WORK/check.err" >&2
fi

# --- 2. a hand-edited block is caught ---------------------------------------
# Each case perturbs a COPY, so the committed files are never touched.
printf '== a hand-edited block fails the check ==\n'

perturb_case() {
  local name=$1 script=$2 copy=$WORK/perturbed.md
  cat -- AGENTS.md >"$copy"
  "$script" "$copy"
  if "${GEN[@]}" --check "$copy" >/dev/null 2>&1; then
    bad "a hand-edited block passed --check ($name) - the guard does not bite"
  else
    ok "caught: $name"
  fi
}

# A flipped status word: the exact shape of the three staleness bugs this
# replaces ("Java and PHP have landed" written over a "still open" line).
#
# _flip_first_row writes the perturbed copy and reports whether it found a row
# to flip, so flip_status can try either direction.  Which direction is
# available depends on the inventory, and BOTH have to be, because the
# inventory is allowed to be COMPLETE: the moment `nosql.rules` and
# `ldap.rules` landed, SAST reached 10 of 10 alongside SCA's and IaC's
# existing 6 of 6, no `| not landed |` row remained anywhere in the block, and
# this case died on its own `die` with no input left.  Finishing the catalog
# is not a failure, and a guard that switches itself off the moment the
# project completes its own inventory switches off at exactly the wrong time -
# from then on nothing would prove the staleness check still bites.
#
# The overcount direction (`not landed` -> `landed`) stays FIRST because it is
# the historical bug: a status word edited by hand to claim work that had not
# shipped.  The undercount direction is the fallback and is always available,
# since a landed row exists whenever the block has any content at all.  Either
# perturbation yields a block that a fresh generation disagrees with, which is
# the only thing perturb_case asserts.
_flip_first_row() {                 # FILE FROM TO -> 0 if a row was flipped
  local file=$1 from=$2 to=$3 line out=$WORK/flip.md inside=0 done_once=0
  : >"$out"
  while IFS= read -r line; do
    if [[ $line == '<!-- BEGIN GENERATED STATUS -->' ]]; then inside=1; fi
    if [[ $line == '<!-- END GENERATED STATUS -->' ]]; then inside=0; fi
    if (( inside )) && (( done_once == 0 )) && [[ $line == *"$from"* ]]; then
      line=${line/"$from"/"$to"}
      done_once=1
    fi
    printf '%s\n' "$line" >>"$out"
  done <"$file"
  (( done_once ))
}

flip_status() {
  local file=$1
  _flip_first_row "$file" '| not landed |' '| landed |' \
    || _flip_first_row "$file" '| landed |' '| not landed |' \
    || die "$SCOURSH_EXIT_INPUT" "no status row to flip in $file"
  cat -- "$WORK/flip.md" >"$file"
}

# A deleted row: the undercount failure, where a real pack silently vanishes.
delete_row() {
  local file=$1 line out=$WORK/del.md inside=0 dropped=0
  : >"$out"
  while IFS= read -r line; do
    if [[ $line == '<!-- BEGIN GENERATED STATUS -->' ]]; then inside=1; fi
    if [[ $line == '<!-- END GENERATED STATUS -->' ]]; then inside=0; fi
    if (( inside )) && (( dropped == 0 )) && [[ $line == '| `modules/'* ]]; then
      dropped=1
      continue
    fi
    printf '%s\n' "$line" >>"$out"
  done <"$file"
  (( dropped )) || die "$SCOURSH_EXIT_INPUT" "no artifact row to delete in $file"
  cat -- "$out" >"$file"
}

# An appended line: a well-meant hand annotation inside the machine's territory.
append_line() {
  local file=$1 line out=$WORK/app.md
  : >"$out"
  while IFS= read -r line; do
    if [[ $line == '<!-- END GENERATED STATUS -->' ]]; then
      printf '%s\n' 'Note: nosql.rules is nearly done.' >>"$out"
    fi
    printf '%s\n' "$line" >>"$out"
  done <"$file"
  cat -- "$out" >"$file"
}

perturb_case 'a status word flipped by hand' flip_status
perturb_case 'a table row deleted by hand' delete_row
perturb_case 'a line appended inside the markers' append_line

# --- 3. the hand-written narrative is not policed ---------------------------
printf '== an edit OUTSIDE the markers is left alone ==\n'
narrative_copy=$WORK/narrative.md
cat -- AGENTS.md >"$narrative_copy"
# Regenerate the COPY's block first, so this case tests only the prose edit.
# Without it a stale committed block (part 1's failure) would resurface here as
# a second, misattributed failure that reads as "the guard polices prose".
"${GEN[@]}" --write "$narrative_copy" >/dev/null
printf '%s\n' '' 'A new hand-written paragraph, outside every marker.' >>"$narrative_copy"
if "${GEN[@]}" --check "$narrative_copy" >/dev/null 2>&1; then
  ok "prose outside the markers stays the author's, not the generator's"
else
  bad 'an edit outside the markers failed --check - the guard is policing prose it must not touch'
fi

# --- 4. every copy carries the same block -----------------------------------
printf '== the copies mirror each other byte for byte ==\n'
extract_block() {
  local file=$1 line inside=0
  while IFS= read -r line; do
    if [[ $line == '<!-- BEGIN GENERATED STATUS -->' ]]; then inside=1; fi
    if (( inside )); then printf '%s\n' "$line"; fi
    if [[ $line == '<!-- END GENERATED STATUS -->' ]]; then inside=0; fi
  done <"$file"
}
extract_block AGENTS.md >"$WORK/block.reference"
for mirror in README.md docs/FOUNDATION.md; do
  extract_block "$mirror" >"$WORK/block.mirror"
  if diff -u -- "$WORK/block.reference" "$WORK/block.mirror" >"$WORK/mirror.diff"; then
    ok "$mirror carries the same block as AGENTS.md"
  else
    bad "$mirror's generated block differs from AGENTS.md's"
    cat -- "$WORK/mirror.diff" >&2
  fi
done

printf '\n'
if (( FAILED )); then
  printf 'lint-status: FAILED\n'
  exit 1
fi
printf 'lint-status: clean\n'
