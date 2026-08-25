#!/usr/bin/env bash
# tests/suites/lint-rules-paths.sh - the meta-test for rules/RULE-FORMAT.md §9's
# path table as tests/lint-rules.sh ENFORCES it (E070).
#
# tests/suites/records.sh already pins `records_schema_for_path`, the pure
# function.  This suite is deliberately a level up: it runs tests/lint-rules.sh
# as a REAL SUBPROCESS over a disposable fixture tree and asserts on its exit
# status, because "the classifier returns the right string" and "the linter
# accepts or refuses the right file" are two different claims, and only the
# second is what a merge actually depends on.  A linter whose refusal path is
# never observed firing is decoration - this repository's own history has an
# instance (tests/lint-aws-readonly.sh's allow-file lookup could never match, so
# it silently marked everything clean).
#
# The subject is §9's `checks-<name>.rules` row, added so that peers adding
# phase scripts to one module directory in parallel do not collide on a single
# co-owned `checks.rules`.  A row that legalises a new name is only safe if it
# legalises EXACTLY that name, so every case below is a PAIR: the legal spelling
# is accepted AND a near-miss at the same path is still refused.  Asserting only
# the acceptance half would pass equally well against a linter that had stopped
# checking paths at all.
#
# Fixture trees live entirely under $W and are never written into the real
# repository: tests/lint-rules.sh's optional SCAN_ROOT argument points it at
# each fixture instead of $ROOT.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/lint-rules-paths
mkdir -p "$W"

# Run the real linter against a fixture tree.  Output is captured so a passing
# suite stays quiet and so the E070 assertion below has something to read.
lint() {
  bash "$ROOT/tests/lint-rules.sh" "$1" >"$W/last.out" 2>&1
}

# A minimal, valid §9.5 script-check record.  Both the id prefix and the
# `coverage-scope` value are keyed off the OWNING MODULE, which §9.5.1 derives
# from the file's DIRECTORY: a `DAST-` id or a `target` scope under modules/iac/
# fails E018/E081/E079, and the suite would then be measuring the wrong refusal -
# a negative case that passes for a reason other than the one it names is exactly
# the failure this suite exists to rule out.
record() {
  cat <<EOF
id: $1
title: A placeholder check used only by this meta-test
script: passive/example.sh
severity: low
confidence: medium
cwe: CWE-693
owasp: A05:2021
tags: passive
coverage-scope: $2
remediation: Nothing to do; this record exists only to give the linter a file.
EOF
}

# Build a fresh fixture tree holding exactly one record file, at $1, and lint it.
# Everything else about the tree is constant, so a status change can only be
# attributed to the basename under test.
lint_with_record_at() {
  local rel=$1 id=DAST-META-EXAMPLE-01 scope=target tree="$W/tree"
  if [[ $rel == modules/iac/* ]]; then
    id=IAC-META-EXAMPLE-01
    # Quoted because the value contains a dash: unquoted, shellcheck reads
    # `scope=path-root` as an arithmetic subtraction and reports SC2100.
    scope='path-root'
  fi
  rm -rf "$tree"
  mkdir -p "$tree/$(dirname -- "$rel")"
  record "$id" "$scope" >"$tree/$rel"
  lint "$tree"
}

t_case 'tests/lint-rules.sh accepts the §9 checks-<name>.rules row'

assert_status 0 'the shared checks.rules spelling is still accepted' \
  lint_with_record_at modules/dast/passive/checks.rules
assert_status 0 'a per-owner checks-cookies.rules is accepted' \
  lint_with_record_at modules/dast/passive/checks-cookies.rules
assert_status 0 'the row is not directory-specific - checks-headers.rules too' \
  lint_with_record_at modules/dast/passive/checks-headers.rules
# Above the pattern-rule rows.  Under the opposite ordering this file takes the
# §9.1 pattern-rule schema and its record fails E023 for a missing `pattern`, so
# this case discriminates the ROW ORDER and not merely the row's existence.
assert_status 0 'checks-<name>.rules beats the modules/iac/*.rules glob' \
  lint_with_record_at modules/iac/checks-trivy.rules

t_case 'tests/lint-rules.sh still refuses everything else (E070)'

# The half that matters.  Each of these sits at a path an accepted case above
# also uses, so the only variable is the basename - and each is a name this
# repository has actually seen proposed.
assert_status 1 'an arbitrary *.rules at a module path is E070' \
  lint_with_record_at modules/dast/passive/cookies.rules
assert_status 1 'the SUFFIX spelling headers-checks.rules is E070' \
  lint_with_record_at modules/dast/passive/headers-checks.rules
assert_status 1 'checks-.rules names no owner and is E070' \
  lint_with_record_at modules/dast/passive/checks-.rules
# The reservation is on a FILENAME, not a path segment: bash's `*` matches `/`,
# so a `*/checks-?*.rules` glob would accept this and turn every .rules file
# under a directory called `checks-x` into a script-check registry.
assert_status 1 'a DIRECTORY named checks-x does not make its contents legal' \
  lint_with_record_at modules/dast/checks-x/arbitrary.rules

# The refusal is specifically E070 and not some unrelated non-zero exit.  Without
# this, every negative case above would be satisfied by a linter broken in any
# way at all.
lint_with_record_at modules/dast/passive/cookies.rules || true
assert_contains "$(cat "$W/last.out")" 'E070' \
  'the refusal names E070, not merely a non-zero exit'

t_case 'the real repository sweep is unaffected by the SCAN_ROOT argument'

# The default (no-argument) invocation must be exactly what it was before the
# argument existed, including over this directory's five split files.
assert_status 0 'the real repository still lints clean with no argument' \
  bash "$ROOT/tests/lint-rules.sh"

t_summary lint-rules-paths
