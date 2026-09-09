#!/usr/bin/env bash
# tests/suites/net01-lint.sh - the meta-test for NET-01's extension of
# tests/lint-shell.sh's tension-19 "no bypass" section to `/dev/tcp` and
# `/dev/udp`.
#
# `/dev/tcp`/`/dev/udp` are a second, un-gated path to the network: a bash
# redirection like `exec 3<>/dev/tcp/host/port` never goes near curl, so the
# existing no-bypass check cannot see it - AGENTS.md's own standing rule is
# that a lint never observed failing on the thing it exists to catch is
# decoration, not a control, so this suite plants the violation in a
# disposable fixture tree, asserts the lint fails; removes it, asserts the
# lint passes; and proves each of the two path exemptions is exempt AT ITS
# REAL PATH ONLY - the identical content one path over must still fail.
#
# The fixture trees live entirely under $W (the scratch dir) and are never
# written into the real repository: tests/lint-shell.sh's optional SCAN_ROOT
# argument (tests/suites/dast35-lint.sh's own convention) points it at each
# fixture instead of $ROOT.
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

W=$SCOURSH_SCRATCH/net01-lint
mkdir -p "$W"

lint() {
  bash "$ROOT/tests/lint-shell.sh" "$1"
}

# A minimal, otherwise-clean fixture tree, the same shape
# tests/suites/dast35-lint.sh's own fixture_base() establishes: a valid
# config/scope.conf.example and the one DAST-35-authorized exemption file, so
# every OTHER check in tests/lint-shell.sh stays quiet and a failure here can
# only be attributed to the /dev/tcp/udp check under test.
fixture_base() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir/config" "$dir/tools/dast-test-target" "$dir/lib" "$dir/rules"
  # engine_files/all_files each end with `[[ -f scan.sh ]] && printf ...`
  # inside a `{ ... } | sort` pipeline; under pipefail an absent scan.sh
  # fails that whole pipeline in a from-scratch fixture tree, though never in
  # a real checkout, where scan.sh always exists.
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

t_case 'a tree with no /dev/tcp or /dev/udp anywhere passes'
assert_status 0 'clean baseline fixture' lint "$FC"

# ---------------------------------------------------------------------------
printf '\n-- a planted /dev/tcp violation outside the exemptions fails, both directions --\n'
# ---------------------------------------------------------------------------
F1=$W/dev-tcp-violation
fixture_base "$F1"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '_probe_open() {' \
  '  exec 3<>/dev/tcp/host/22' \
  '}' \
  >"$F1/lib/scratch-probe.sh"

t_case 'a bare /dev/tcp redirection outside lib/paranoid.sh or lib/nettransport.sh fails the lint'
# FAILS under the reading "only a curl/wget/nc/openssl s_client invocation is
# a network bypass" - a bash /dev/tcp redirection never goes near any of
# those, so a pattern that does not also match it is a second, silent path
# to the network the tension-19 chokepoint was supposed to close.
assert_status 1 'no bypass: /dev/tcp outside the exemptions' lint "$F1"
out=$(lint "$F1" 2>&1 || true)
assert_contains "$out" 'no bypass: no /dev/tcp or /dev/udp outside the network transport primitive' \
  'the failure names this check specifically'
assert_contains "$out" 'lib/scratch-probe.sh' 'the failure names the offending file'

t_case 'removing the violation restores a clean pass'
rm -f "$F1/lib/scratch-probe.sh"
assert_status 0 'the /dev/tcp line is gone' lint "$F1"

# ---------------------------------------------------------------------------
printf '\n-- a planted /dev/udp violation outside the exemptions fails, both directions --\n'
# ---------------------------------------------------------------------------
F2=$W/dev-udp-violation
fixture_base "$F2"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '_ping_udp() {' \
  '  exec {fd}<>/dev/udp/198.51.100.1/9' \
  '}' \
  >"$F2/lib/scratch-udp.sh"

t_case 'a bare /dev/udp redirection outside lib/paranoid.sh or lib/nettransport.sh fails the lint'
assert_status 1 'no bypass: /dev/udp outside the exemptions' lint "$F2"
out=$(lint "$F2" 2>&1 || true)
assert_contains "$out" 'no bypass: no /dev/tcp or /dev/udp outside the network transport primitive' \
  'the failure names this check specifically'

t_case 'removing the violation restores a clean pass'
rm -f "$F2/lib/scratch-udp.sh"
assert_status 0 'the /dev/udp line is gone' lint "$F2"

# ---------------------------------------------------------------------------
printf '\n-- the lib/paranoid.sh exemption is tested in both directions --\n'
# ---------------------------------------------------------------------------
F3=$W/paranoid-exemption
fixture_base "$F3"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '# the real loopback control-socket probe (lib/paranoid.sh section on the lsof backend)' \
  '_paranoid_lsof_probe() {' \
  '  if ! { exec {pfd}<>/dev/udp/127.0.0.1/9; } 2>/dev/null; then' \
  '    return 1' \
  '  fi' \
  '}' \
  >"$F3/lib/paranoid.sh"

t_case 'lib/paranoid.sh itself, carrying its real /dev/udp control socket, does not trip the lint'
assert_status 0 'the one authorized paranoid.sh use, at its real path, passes' lint "$F3"

t_case 'the identical content at any OTHER path is not exempt, and fails'
# FAILS under the reading "/dev/udp is fine wherever it appears, since
# lib/paranoid.sh already uses it legitimately" - it is not: the exemption is
# BY PATH, exactly as tools/dast-test-target/scope.conf is in DAST-35 above,
# never by pattern, which would silently exempt every future file that
# happened to look similar.
cp "$F3/lib/paranoid.sh" "$F3/lib/copy-of-paranoid.sh"
assert_status 1 'the identical /dev/udp content is not exempt at a different path' lint "$F3"
out=$(lint "$F3" 2>&1 || true)
assert_contains "$out" 'lib/copy-of-paranoid.sh' 'the failure names the unexempted copy'

t_case 'removing the unexempted copy restores a clean pass'
rm -f "$F3/lib/copy-of-paranoid.sh"
assert_status 0 'only the real lib/paranoid.sh remains' lint "$F3"

# ---------------------------------------------------------------------------
printf '\n-- the lib/nettransport.sh exemption is tested in both directions --\n'
# ---------------------------------------------------------------------------
F4=$W/nettransport-exemption
fixture_base "$F4"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  '# the future network module transport primitive (NET-03)' \
  'net_connect_probe() {' \
  '  local host=$1 port=$2' \
  '  exec 4<>"/dev/tcp/$host/$port"' \
  '}' \
  >"$F4/lib/nettransport.sh"

t_case 'lib/nettransport.sh itself, carrying its own /dev/tcp connect, does not trip the lint'
assert_status 0 'the network transport primitive, at its real path, passes' lint "$F4"

t_case 'the identical content at any OTHER path is not exempt, and fails'
cp "$F4/lib/nettransport.sh" "$F4/modules-placeholder-copy.sh"
mkdir -p "$F4/lib/other"
mv "$F4/modules-placeholder-copy.sh" "$F4/lib/other/copy-of-nettransport.sh"
assert_status 1 'the identical /dev/tcp content is not exempt at a different path' lint "$F4"
out=$(lint "$F4" 2>&1 || true)
assert_contains "$out" 'lib/other/copy-of-nettransport.sh' 'the failure names the unexempted copy'

t_case 'removing the unexempted copy restores a clean pass'
rm -rf "$F4/lib/other"
assert_status 0 'only the real lib/nettransport.sh remains' lint "$F4"

t_summary net01-lint
