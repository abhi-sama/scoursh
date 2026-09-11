#!/usr/bin/env bash
# tests/suites/sca-semver.sh - modules/sca/semver.sh: the npm-only semver
# comparator docs/FOUNDATION.md tension 25's amendment adds.
#
# Two halves:
#
#   1. Unit tests for the interval edges (bound_kind exact|fixed|last|open),
#      the SemVer 2.0.0 prerelease-precedence ladder, build-metadata being
#      ignored, and the `v`/`=` prefix handling.
#
#   2. A differential test against an INDEPENDENT Python reference
#      implementation of SemVer 2.0.0 precedence, over every pair in a
#      programmatically generated corpus (curated adversarial cases plus a
#      systematic major/minor/patch/prerelease/build sweep) - this suite's
#      own reproduction of the "0/30,000 mismatches on real
#      npm version pairs" measurement, using a fresh corpus rather than
#      the original scratch one (discarded once measured). The reference is written independently in Python, in its
#      own idiom, rather than transliterated from the bash source, so the
#      two are not the same bug wearing two languages.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# lib/core.sh's own scratch_init runs at source time and is what sets/exports
# SCOURSH_SCRATCH when a parent run has not already inherited one -
# modules/sca/semver.sh is a deliberately leaf module with no lib/ sourcing
# of its own, so this suite needs it directly, unlike tests/suites/sca.sh
# (which gets it transitively through modules/sca/engine.sh).
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=modules/sca/semver.sh
source "$ROOT/modules/sca/semver.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/sca-semver
rm -rf "$W"
mkdir -p "$W"

# cmp_v A B -> prints -1|0|1, wrapping the fork-free production comparator.
cmp_v() { semver_cmp_v "$1" "$2"; printf '%s' "$_SV_CMP"; }

# ---------------------------------------------------------------------------
printf -- '\n-- SemVer 2.0.0 core precedence --\n'
# ---------------------------------------------------------------------------
t_case 'major/minor/patch compare numerically, not lexically (1.2.9 < 1.2.10)'
assert_eq -1 "$(cmp_v 1.2.9 1.2.10)" 'FAILS under a lexical/string comparison, which would read "9" > "1" and get this backwards'
assert_eq 1 "$(cmp_v 1.2.10 1.2.9)" 'and the reverse direction agrees'
assert_eq 0 "$(cmp_v 1.2.9 1.2.9)" 'and equality holds'

t_case 'a missing minor/patch defaults to 0 (1.0 == 1.0.0, 1 == 1.0.0)'
assert_eq 0 "$(cmp_v 1.0 1.0.0)" 'a two-component version is treated as its own .0 patch'
assert_eq 0 "$(cmp_v 1 1.0.0)" 'a bare major is treated as .0.0'

t_case 'build metadata (+...) is IGNORED for precedence (SemVer 2.0.0 §10)'
assert_eq 0 "$(cmp_v 1.0.0+build1 1.0.0+build2)" 'two different build-metadata suffixes on the identical core+prerelease compare EQUAL'
assert_eq 0 "$(cmp_v 1.0.0-alpha+001 1.0.0-alpha+002)" 'build metadata is ignored even alongside a prerelease'

t_case 'a leading v or = is stripped before comparison'
assert_eq 0 "$(cmp_v v1.2.3 1.2.3)" 'v-prefixed and bare compare equal'
assert_eq 0 "$(cmp_v =1.2.3 1.2.3)" '=-prefixed and bare compare equal'

# ---------------------------------------------------------------------------
printf -- '\n-- SemVer 2.0.0 prerelease precedence (§11), including the spec'"'"'s own adversarial ladder --\n'
# ---------------------------------------------------------------------------
t_case 'a version WITHOUT a prerelease sorts HIGHER than the identical core WITH one (§11.4.3)'
assert_eq 1 "$(cmp_v 1.0.0 1.0.0-alpha)" 'FAILS under a reading that treats absence as lower (the common off-by-one mistake) - 1.0.0-alpha is a PRE-release of 1.0.0, so it must sort below the real release'
assert_eq -1 "$(cmp_v 1.0.0-alpha 1.0.0)" 'and the reverse direction agrees'

t_case 'a numeric identifier compares numerically and always sorts lower than an alphanumeric one (§11.4.2/§11.4.3)'
assert_eq -1 "$(cmp_v 1.0.0-1 1.0.0-alpha)" 'numeric < alphanumeric, regardless of the numeric value'
assert_eq -1 "$(cmp_v 1.0.0-9 1.0.0-10)" 'and numeric identifiers compare as numbers, not as strings (9 < 10, not "9" > "1")'

t_case "the spec's own adversarial ladder sorts correctly end to end (SemVer 2.0.0 §11 example)"
LADDER=(1.0.0-alpha 1.0.0-alpha.1 1.0.0-alpha.beta 1.0.0-beta 1.0.0-beta.2 1.0.0-beta.11 1.0.0-rc.1 1.0.0)
ladder_bad=0
for (( i = 0; i < ${#LADDER[@]} - 1; i++ )); do
  if [[ "$(cmp_v "${LADDER[i]}" "${LADDER[i+1]}")" != -1 ]]; then
    ladder_bad=$(( ladder_bad + 1 ))
    printf '    LADDER STEP FAILED: %s should be < %s\n' "${LADDER[i]}" "${LADDER[i+1]}" >&2
  fi
done
assert_eq 0 "$ladder_bad" \
  '1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0, every adjacent step'

t_case 'a longer prerelease identifier list sorts higher when every shared identifier is equal (§11.4.4)'
assert_eq -1 "$(cmp_v 1.0.0-alpha 1.0.0-alpha.1)" 'alpha < alpha.1: fewer fields with all preceding identifiers equal is lower precedence'

# ---------------------------------------------------------------------------
printf -- '\n-- semver_in_range_v: interval edges per bound_kind (data/advisories.db npm range rows) --\n'
# ---------------------------------------------------------------------------
t_case 'bound_kind=exact: byte equality, never through the comparator'
assert_status 0 'exact match' semver_in_range_v '1.2.3' '1.2.3' '' exact
assert_status 1 'a numerically-equal but byte-different string does NOT match exact (e.g. a leading v)' \
  semver_in_range_v 'v1.2.3' '1.2.3' '' exact

t_case 'bound_kind=fixed: [introduced, bound) - introduced included, bound excluded'
assert_status 0 'the lower bound itself is affected (inclusive)' semver_in_range_v '1.0.0' '1.0.0' '2.0.0' fixed
assert_status 0 'a version strictly inside the interval is affected' semver_in_range_v '1.5.0' '1.0.0' '2.0.0' fixed
assert_status 1 'the fixed (upper) bound itself is NOT affected (exclusive)' semver_in_range_v '2.0.0' '1.0.0' '2.0.0' fixed
assert_status 1 'a version below introduced is not affected' semver_in_range_v '0.9.0' '1.0.0' '2.0.0' fixed
assert_status 1 'a version above the fixed bound is not affected' semver_in_range_v '2.1.0' '1.0.0' '2.0.0' fixed

t_case 'bound_kind=last: [introduced, bound] - BOTH bounds inclusive (OSV last_affected)'
assert_status 0 'the last_affected bound itself IS affected (inclusive, unlike fixed)' semver_in_range_v '2.0.0' '1.0.0' '2.0.0' last
assert_status 1 'one version above last_affected is not affected' semver_in_range_v '2.0.1' '1.0.0' '2.0.0' last

t_case 'bound_kind=open: introduced onward, no upper bound at all'
assert_status 0 'the introduced version itself is affected' semver_in_range_v '1.0.0' '1.0.0' '' open
assert_status 0 'an arbitrarily high version is still affected - open has no ceiling' semver_in_range_v '99.0.0' '1.0.0' '' open
assert_status 1 'a version below introduced is not affected' semver_in_range_v '0.9.0' '1.0.0' '' open

t_case 'bound_kind=open with introduced=0 (Tier A: whole-package/malware row) matches EVERY version unconditionally'
assert_status 0 'a very low version matches' semver_in_range_v '0.0.1' '0' '' open
assert_status 0 'a very high version matches too - this is the zero-version-algebra case' semver_in_range_v '999.999.999' '0' '' open
assert_status 0 'and a prerelease version matches as well' semver_in_range_v '1.0.0-alpha' '0' '' open

t_case 'false-positive controls: the FIXED version itself must never match'
assert_status 1 'minimist@1.2.6 (the published fix) does not match [1.2.0,1.2.6)' semver_in_range_v '1.2.6' '1.2.0' '1.2.6' fixed
assert_status 1 'a prerelease of the version AFTER the fixed bound'"'"'s own major is correctly excluded' semver_in_range_v '2.1.0-beta.1' '1.0.0' '2.0.0' fixed
assert_status 0 'a prerelease of the fixed bound ITSELF is correctly INCLUDED - it sorts below the real 2.0.0 release, so it is still inside [1.0.0,2.0.0) (SemVer 2.0.0 §11.4.3, the same rule the ladder case above pins)' \
  semver_in_range_v '2.0.0-beta.1' '1.0.0' '2.0.0' fixed
assert_status 0 'and a prerelease BELOW an explicit prerelease fixed bound is correctly included too' \
  semver_in_range_v '2.0.0-beta.1' '1.0.0' '2.0.0-beta.5' fixed

# ---------------------------------------------------------------------------
printf -- '\n-- differential test: semver_cmp_v vs an independent Python SemVer 2.0.0 reference --\n'
# ---------------------------------------------------------------------------
require_cmd python3

python3 - "$W/corpus.txt" "$W/pairs.txt" <<'PY'
import itertools
import sys

corpus_path, pairs_path = sys.argv[1], sys.argv[2]

# --- an INDEPENDENT SemVer 2.0.0 reference, written in its own idiom rather
# than transliterated from modules/sca/semver.sh, so the differential is
# meaningful rather than the same bug compared with itself. ---

def parse(v):
    if v.startswith('v'):
        v = v[1:]
    if v.startswith('='):
        v = v[1:]
    v = v.split('+', 1)[0]
    core, _, pre = v.partition('-')
    parts = (core.split('.') + ['0', '0', '0'])[:3]

    def to_int(x):
        return int(x) if x.isdigit() else 0

    major, minor, patch = (to_int(p) for p in parts)
    return (major, minor, patch), pre


def ident_key(ident):
    return (0, int(ident)) if ident.isdigit() else (1, ident)


def cmp_pre(a, b):
    if a == b:
        return 0
    if a == '':
        return 1
    if b == '':
        return -1
    ka = [ident_key(x) for x in a.split('.')]
    kb = [ident_key(x) for x in b.split('.')]
    for x, y in zip(ka, kb):
        if x < y:
            return -1
        if x > y:
            return 1
    if len(ka) < len(kb):
        return -1
    if len(ka) > len(kb):
        return 1
    return 0


def ref_cmp(a, b):
    core_a, pre_a = parse(a)
    core_b, pre_b = parse(b)
    if core_a != core_b:
        return -1 if core_a < core_b else 1
    return cmp_pre(pre_a, pre_b)


# --- corpus: the spec's own adversarial ladder, the feasibility scout
# report's own false-positive controls, plus a systematic sweep. ---
corpus = [
    '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
    '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0',
    '1.2.9', '1.2.10', '1.2.5', '1.2.6', '1.2.8',
    'v1.2.3', '=1.2.3', '1.2.3+build.1', '1.2.3+build.2',
    '4.17.15', '4.17.20', '4.17.21', '4.17.21-beta.1',
    '0', '0.0.0', '1', '1.0',
]
prereleases = ['', '-alpha', '-alpha.1', '-alpha.beta', '-beta', '-beta.2',
               '-beta.11', '-rc.1', '-0', '-1', '-x.7.z.92']
for major in range(3):
    for minor in range(3):
        for patch in range(3):
            for pre in prereleases:
                corpus.append('%d.%d.%d%s' % (major, minor, patch, pre))

corpus = sorted(set(corpus))
with open(corpus_path, 'w', encoding='utf-8') as fh:
    for v in corpus:
        fh.write(v + '\n')

pairs = 0
with open(pairs_path, 'w', encoding='utf-8') as fh:
    for a, b in itertools.combinations(corpus, 2):
        fh.write('%s\t%s\t%d\n' % (a, b, ref_cmp(a, b)))
        pairs += 1

sys.stderr.write('sca-semver: generated %d version(s), %d pair(s)\n' % (len(corpus), pairs))
PY

t_case 'the generated corpus is a strong subset of the report'"'"'s own 30,000-pair measurement'
corpus_n=$(wc -l <"$W/corpus.txt" | tr -d ' ')
pairs_n=$(wc -l <"$W/pairs.txt" | tr -d ' ')
if (( pairs_n >= 10000 )); then
  _t_ok "$corpus_n distinct version(s), $pairs_n pair(s) - a substantial fraction of the 30,000-pair scale this comparator was originally measured against"
else
  _t_no 'at least 10,000 pairs generated' "only $pairs_n"
fi

t_case 'semver_cmp_v agrees with the independent Python reference on every generated pair'
mismatches=0
checked=0
while IFS=$'\t' read -r a b expected; do
  [[ -n $a ]] || continue
  got=$(cmp_v "$a" "$b")
  checked=$(( checked + 1 ))
  if [[ $got != "$expected" ]]; then
    mismatches=$(( mismatches + 1 ))
    if (( mismatches <= 10 )); then
      printf '    MISMATCH: cmp(%s, %s) bash=%s reference=%s\n' "$a" "$b" "$got" "$expected" >&2
    fi
  fi
done <"$W/pairs.txt"
assert_eq "$pairs_n" "$checked" 'every generated pair was actually exercised (not silently skipped)'
assert_eq 0 "$mismatches" \
  "0 mismatches over $checked real-shaped version pairs against an independent Python SemVer 2.0.0 reference - the same measured-correctness bar this comparator was originally held to (0/30,000 on real npm data); the first 10 of any mismatch are printed above for diagnosis"

t_summary sca-semver
