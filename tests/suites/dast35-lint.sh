#!/usr/bin/env bash
# tests/suites/dast35-lint.sh - the meta-test for DAST-35
# (tests/lint-shell.sh's "no bundled scan target" section,
# docs/STEP5-DAST-PLAN.md).
#
# "A convenient example target" is a helpful-looking contribution that would
# silently become the built-in demo host, and a lint that has never been
# observed failing on the thing it exists to catch is decoration, not a
# control (AGENTS.md's own standing rule - this repository's history already
# has an instance of a linter whose allow-file lookup could never match,
# which silently marked everything clean for months). This suite plants each
# of DAST-35's three violations in a disposable fixture tree, asserts the
# lint fails; fixes it, asserts the lint passes. Both directions, every time.
#
# The fixture trees live entirely under $W (the scratch dir) and are never
# written into the real repository: tests/lint-shell.sh's optional SCAN_ROOT
# argument (added alongside this suite, the same convention
# tests/lint-aws-readonly.sh already established) points it at each fixture
# instead of $ROOT, so the real config/lib/modules/rules trees are never
# touched.
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

W=$SCOURSH_SCRATCH/dast35-lint
mkdir -p "$W"

lint() {
  bash "$ROOT/tests/lint-shell.sh" "$1"
}

# A minimal, otherwise-clean fixture tree: a valid config/scope.conf.example
# (so checks 1 and 2 are quiet) plus the one authorized exemption file, byte-
# identical to the real tools/dast-test-target/scope.conf (so the path
# exemption itself is quiet). Every test below mutates exactly one thing on
# top of this baseline, so a failure can only be attributed to the one check
# under test - the same isolation aws-lint.sh's own fixture() establishes.
fixture_base() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir/config" "$dir/tools/dast-test-target" "$dir/lib" "$dir/rules"
  # A real checkout always has scan.sh at its root; the other lint-shell.sh
  # file listers (engine_files/all_files/dispatch_path_files) each end with
  # `[[ -f scan.sh ]] && printf ...` inside a `{ ... } | sort` group, and
  # under set -o pipefail an absent scan.sh makes that group's own exit
  # status (1, from the failed `[[ -f scan.sh ]]`) fail the whole pipeline -
  # a real repo never hits this because scan.sh always exists there, but a
  # from-scratch fixture tree does unless it recreates that same fact.
  : >"$dir/scan.sh"
  printf '%s\n' \
    'id: example-target' \
    'base-url: https://target.example/app' \
    'allow-subdomains: false' \
    'notes: fixture' \
    >"$dir/config/scope.conf.example"
  printf '%s\n' \
    'id: dast-test-target' \
    'base-url: http://127.0.0.1:3400/' \
    'allow-subdomains: false' \
    'allow-private-addresses: true' \
    'notes: fixture, mirrors the real tools/dast-test-target/scope.conf' \
    >"$dir/tools/dast-test-target/scope.conf"
}

# ---------------------------------------------------------------------------
printf '\n-- the clean fixture tree passes in full --\n'
# ---------------------------------------------------------------------------
FC=$W/clean
fixture_base "$FC"

t_case 'a tree with only scope.conf.example and the authorized exemption file passes'
assert_status 0 'clean baseline fixture' lint "$FC"

# ---------------------------------------------------------------------------
printf '\n-- check 1: config/ ships scope.conf.example only, both directions --\n'
# ---------------------------------------------------------------------------
F1=$W/scope-conf-shipped
fixture_base "$F1"
cp "$F1/config/scope.conf.example" "$F1/config/scope.conf"

t_case 'a shipped config/scope.conf fails the lint'
# FAILS under the reading "only scope.conf.example matters, a real
# scope.conf alongside it is fine" - it is not: a shipped scope.conf IS the
# built-in demo host DAST-35 exists to make impossible.
assert_status 1 'config/scope.conf must never be shipped' lint "$F1"
out=$(lint "$F1" 2>&1 || true)
assert_contains "$out" "config/scope.conf must never be shipped" 'the failure names check 1 specifically'

t_case 'removing config/scope.conf makes the same tree pass'
rm -f "$F1/config/scope.conf"
assert_status 0 'only scope.conf.example remains' lint "$F1"

# ---------------------------------------------------------------------------
printf '\n-- check 2: scope.conf.example must name a reserved example domain, both directions --\n'
# ---------------------------------------------------------------------------
F2=$W/example-not-reserved
fixture_base "$F2"
printf '%s\n' \
  'id: example-target' \
  'base-url: https://staging-api.internal-real-corp.com/app' \
  'allow-subdomains: false' \
  'notes: fixture' \
  >"$F2/config/scope.conf.example"

t_case 'scope.conf.example naming a non-reserved domain fails the lint'
# FAILS under the reading "any base-url in the shipped example is fine as
# long as it looks plausible" - a plausible-looking real domain in the
# shipped example is exactly the failure mode DAST-35 exists to catch.
assert_status 1 'internal-real-corp.com is not an RFC 2606/6761 reserved domain' lint "$F2"
out=$(lint "$F2" 2>&1 || true)
assert_contains "$out" "not an RFC 2606/6761 reserved example domain" 'the failure names check 2 specifically'
assert_contains "$out" "internal-real-corp.com" 'the failure names the offending host'

t_case 'restoring a reserved example domain makes the same tree pass'
printf '%s\n' \
  'id: example-target' \
  'base-url: https://target.example/app' \
  'allow-subdomains: false' \
  'notes: fixture' \
  >"$F2/config/scope.conf.example"
assert_status 0 'target.example is reserved' lint "$F2"

# ---------------------------------------------------------------------------
printf '\n-- check 3: no bundled scan target anywhere else in the tree, both directions --\n'
# ---------------------------------------------------------------------------
F3=$W/bundled-target
fixture_base "$F3"
printf '%s\n' \
  'id: convenient-demo' \
  'base-url: https://demo.a-real-company.net/' \
  'notes: a helpful-looking contribution' \
  >"$F3/lib/demo-scope.conf"

t_case 'a scope-target record naming a real-looking host anywhere else in the tree fails'
# FAILS under the reading "only config/scope.conf(.example) is checked" -
# DAST-35's own text is explicit that this must catch ANY shipped script,
# rule or config file, because a "convenient" demo target is exactly as
# dangerous bundled in a module as it is in config/.
assert_status 1 'lib/demo-scope.conf bundles a real-looking scan target' lint "$F3"
out=$(lint "$F3" 2>&1 || true)
assert_contains "$out" "a-real-company.net" 'the failure names the offending host'
assert_contains "$out" "resolvable third-party scan target" 'the failure explains why: DAST-35'

t_case 'removing the bundled record makes the same tree pass'
rm -f "$F3/lib/demo-scope.conf"
assert_status 0 'the tree is clean again' lint "$F3"

t_case 'an extra-host record (not just base-url) naming a real-looking host also fails'
fixture_base "$F3"
printf '%s\n' \
  'id: example-target' \
  'base-url: https://target.example/app' \
  'extra-host: api.a-real-company.net' \
  'notes: fixture' \
  >"$F3/lib/demo-scope.conf"
assert_status 1 'extra-host is checked the same as base-url' lint "$F3"
out=$(lint "$F3" 2>&1 || true)
assert_contains "$out" "extra-host names 'api.a-real-company.net'" 'the failure identifies the field and the host'

t_case 'a reserved/non-routable IP literal used as a scan target elsewhere in the tree still passes'
# The existing test fixtures under tests/fixtures/config/ use literals like
# 169.254.169.254 and 198.51.100.7 - reserved/non-routable ranges, never a
# real third party - and must not trip this check.
fixture_base "$F3"
printf '%s\n' \
  'id: ssrf-fixture' \
  'base-url: https://169.254.169.254/' \
  'notes: fixture, mirrors the deny-list unit tests' \
  >"$F3/lib/ssrf-fixture-scope.conf"
assert_status 0 'a link-local/metadata literal is reserved, not a third party' lint "$F3"

# ---------------------------------------------------------------------------
printf '\n-- the path exemption is tested in both directions --\n'
# ---------------------------------------------------------------------------
F4=$W/path-exemption
fixture_base "$F4"

t_case 'tools/dast-test-target/scope.conf itself does not trip the lint'
assert_status 0 'the one authorized exemption, at its real path, passes' lint "$F4"

t_case 'an identical file at any OTHER path is not exempt, and fails'
# FAILS under the reading "the loopback host itself is safe, wherever it
# appears" - it is not: 127.0.0.1 means "whatever this operator's own
# machine happens to be running" for every installation, which is exactly
# the built-in-demo-host risk DAST-35 exists to close. Only the ONE
# authorized file, at its real path, is exempt - the exemption is by path,
# never by pattern (docs/DAST-TEST-TARGET-AUTHORIZATION.md).
cp "$F4/tools/dast-test-target/scope.conf" "$F4/lib/copy-of-scope.conf"
assert_status 1 'the identical content is not exempt at a different path' lint "$F4"
out=$(lint "$F4" 2>&1 || true)
assert_contains "$out" "lib/copy-of-scope.conf" 'the failure names the unexempted copy'
assert_contains "$out" "127.0.0.1" 'the failure names the loopback host, which is not generically safe'

t_case 'removing the unexempted copy restores a clean pass'
rm -f "$F4/lib/copy-of-scope.conf"
assert_status 0 'only the real exemption remains' lint "$F4"

t_summary dast35-lint
