#!/usr/bin/env bash
# tests/lint-shell.sh - the repository shell lints the register mandates.
#
#   docs/FOUNDATION.md tension  4 rules 1, 2 and 5
#   docs/FOUNDATION.md tension  9 handling rules 1 and 3
#   docs/FOUNDATION.md tension 24 (one capability layer)
#   docs/FOUNDATION.md tension 26 / rules/RULE-FORMAT.md §11 (records are data)
#
# SCOPE, stated rather than assumed.  The engine rules (no bare grep/rg, one
# capability layer) apply to the code that produces findings: lib/, modules/ and
# tools/.  They do not apply to tests/, which is not the rule engine: a test
# grepping its own output cannot produce a silent coverage hole in a scan, which
# is the failure tension 4 rule 2 exists to prevent.  The rules that ARE about
# the process rather than the engine - `set +e`, sourcing a record file - apply
# everywhere, tests included.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
cd "$ROOT"

FAILED=0
HITS=$SCOURSH_SCRATCH/lint-hits

report() {
  FAILED=1
  printf '%s\n' "$@" >&2
}

# Files the engine rules apply to.  scan.sh is the entry point, not a
# module, but it is the same class of code (it dispatches to the engine and
# owns the exit-code/scratch-dir contract every engine file relies on), so it
# is held to the same discipline rather than living in an unlint-ed root.
engine_files() {
  local dirs=() d
  for d in lib modules tools aws; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f -name '*.sh'
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

all_files() {
  local dirs=() d
  for d in lib modules tools aws tests; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f -name '*.sh'
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

# `check NAME PATTERN FILE-LIST-FN [EXEMPT...]` - fails when PATTERN matches.
check() {
  local name=$1 pattern=$2 lister=$3
  shift 3
  local f rel exempt skip
  local found=0
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    rel=${f#./}
    skip=0
    for exempt in "$@"; do
      [[ $rel == "$exempt" ]] && skip=1
    done
    (( skip )) && continue
    if scan_match "$HITS" -e "$pattern" -- "$rel"; then
      found=1
      report "$name: $rel"
      while IFS= read -r hit; do
        [[ -n $hit ]] && printf '    %s\n' "$hit" >&2
      done <"$HITS"
    fi
  done <<<"$($lister)"
  (( found )) || printf '  ok  %s\n' "$name"
}

printf '== tension 4: the shell contract ==\n'

# Rule 1.  Matched as a COMMAND, not as a substring: the phrase appears in
# lib/core.sh's own comment explaining that it is forbidden.
check 'rule 1: `set +e` is forbidden repository-wide' \
  '^[[:space:]]*set[[:space:]]+\+[a-zA-Z]*e' all_files

# Rule 2.  A bare grep or rg discards the distinction between "no match" (the
# normal case) and "the engine failed", so a broken rule reports clean.
check 'rule 2: no bare grep/rg outside the wrapper' \
  '^[[:space:]]*(grep|rg|egrep|fgrep)[[:space:]]' engine_files lib/core.sh

# Rule 4.  mapfile discards the producer's exit status, which is the very thing
# rule 2 exists to check.
check 'rule 4: no mapfile in the engine' \
  '^[[:space:]]*mapfile[[:space:]]' engine_files

printf '== tension 24: one capability layer ==\n'
for tool in 'sha256sum' 'shasum' 'shred' 'sort[[:space:]]+-V' 'grep[[:space:]]+-P' \
  'readlink[[:space:]]+-f' 'sed[[:space:]]+-i' 'date[[:space:]]+-d' \
  'date[[:space:]]+-Iseconds' 'stat[[:space:]]+-c' 'stat[[:space:]]+-f' \
  'xargs[[:space:]]+-r[[:space:]]' 'mktemp[[:space:]]+-p'; do
  # Matched at COMMAND position, so a tool NAME appearing inside a string - a
  # run.json key, a diagnostic - is not a false positive.
  check "no direct '$tool' outside lib/core.sh" \
    "(^|[;&|(])[[:space:]]*$tool([[:space:]]|\$)" engine_files lib/core.sh
done

printf '== tension 24: empty-array expansion ==\n'
# bash before 4.4 errors on "${arr[@]}" for an empty array under `set -u`, which
# happens the first time a rule matches no files.  The frozen minimum is 4.2, so
# every array expansion is written "${arr[@]+"${arr[@]}"}".
# ${#arr[@]} and ${!arr[@]} are not expansions of the elements and are exempt.
#
# The guarded form CONTAINS the bare form as a substring, so the guarded ones are
# removed before looking for what is left.  A check that flagged its own fix
# would be worse than no check.
check_array_guard() {
  local f rel stripped=$SCOURSH_SCRATCH/lint-stripped found=0
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    rel=${f#./}
    sed -e 's/\${[A-Za-z_][A-Za-z0-9_]*\[@\]+"\${[A-Za-z_][A-Za-z0-9_]*\[@\]}"}//g' \
      -- "$rel" >"$stripped"
    if scan_match "$HITS" -n -e '\$\{[a-zA-Z_][a-zA-Z0-9_]*\[@\]\}' -- "$stripped"; then
      found=1
      report "array expansion is unguarded for bash 4.2: $rel"
      while IFS= read -r hit; do
        [[ -n $hit ]] && printf '    %s\n' "$hit" >&2
      done <"$HITS"
    fi
  done <<<"$(engine_files)"
  (( found )) || printf '  ok  array expansions are guarded for bash 4.2\n'
}
check_array_guard

printf '== tension 26 / §11: record files are data, never code ==\n'
check 'no source/eval of a record file' \
  '^[[:space:]]*(source|\.|eval)[[:space:]]+.*(config/|rules/|data/)' all_files

printf '== tension 9: secrets never reach argv or disk ==\n'
# sha256_of reads stdin only, so a secret never appears in any process's argv.
check 'sha256_of takes no argument' \
  'sha256_of[[:space:]]+[^|)&;]' engine_files

# Evidence is only ever set through finding_set_evidence, which applies redact,
# truncation and control-character stripping in that order.  The other
# target-derived fields are only ever set through finding_set, which redacts
# them.  A direct assignment to any of them bypasses redact() and writes a
# credential into every emitted format.
check 'no direct assignment to a redacted field' \
  '_F\[(evidence|title|remediation|url|logical_fqn|loc_path_template|loc_param_name)\]=' \
  engine_files lib/findings.sh

printf '\n'
if (( FAILED )); then
  printf 'lint-shell: FAILED\n'
  exit 1
fi
printf 'lint-shell: clean\n'
