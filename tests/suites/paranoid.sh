#!/usr/bin/env bash
# tests/suites/paranoid.sh - lib/paranoid.sh, the --paranoid connection
# observer and abort mechanism (docs/FOUNDATION.md tension 20).
#
# DETERMINISM (mirrors tests/suites/http.sh's own header exactly, same
# reasoning applied to the sampler instead of the resolver/transport): `ss`
# and `strace` are Linux-only and this suite's CI matrix runs macOS too
# (AGENTS.md "GNU/BSD dual-runner"), so nothing here depends on either being
# installed.  SCOURSH_PARANOID_FORCE_BACKEND stands in for the ss/strace
# probe (same idiom as lib/core.sh's SCOURSH_FORCE_MSLEEP_IMPL) and
# SCOURSH_PARANOID_SAMPLE stands in for the sampler itself (same idiom as
# lib/http.sh's SCOURSH_HTTP_RESOLVE/SCOURSH_HTTP_TRANSPORT), so a passing
# run here means the ALLOWLIST + ABORT WIRING is correct, deterministically,
# on every host - exactly what tension 20 asks the no-egress fixture to
# prove ("a passing test means zero connections outside loopback rather than
# zero connections we did not expect").
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# REGRESSION PROOF (AC2/AC3 of this ticket): manually verified before this
# file was committed by copying the repo to a scratch directory and adding
# `return 0` as the first line of paranoid_addr_allowed's body (the gate
# defeated - every destination reads as allowed).  Re-running this suite
# against that copy failed every "is NOT allowed" / "is refused" assertion
# in the "allowlist building" section (they call the predicate directly)
# plus both "AC2/AC3" cases below (exit 3 became exit 0; no
# PARANOID-EGRESS-VIOLATION finding was written) - 7 failures in total -
# while every "IS allowed" positive case, the AWS-set/backend-probe/exit-4
# sections (which never reach the predicate on a denied path), and the
# already-allowlisted-destination case kept passing.  That is exactly the
# shape defeating one predicate, and only that predicate, should produce.
#
# shellcheck shell=bash
#
# SC2015/SC2016/SC2030/SC2031/SC2329: as tests/suites/scan.sh (assert_status
# subshell-scoping, prose quoting shell syntax, indirect invocation).
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=scan.sh
source "$ROOT/scan.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/paranoid
rm -rf "$W"
mkdir -p "$W"

# ---------------------------------------------------------------------------
# Fixture install root: a scope.conf target, a scanner.conf with
# paranoid_allow entries, and a fake /etc/resolv.conf.
# ---------------------------------------------------------------------------
FROOT=$W/root
mkdir -p "$FROOT/config"
cat >"$FROOT/config/scope.conf" <<'EOF'
id: fixture-target
base-url: https://svc.paranoid.fixture.example/api
EOF
cat >"$FROOT/config/scanner.conf" <<'EOF'
id: scanner
paranoid-allow: 198.51.100.7:9443
EOF
RESOLV=$W/resolv.conf
cat >"$RESOLV" <<'EOF'
# fixture resolv.conf - never the real one
nameserver 10.10.10.10
nameserver 10.10.10.11
EOF

_test_resolve() {
  case $1 in
    svc.paranoid.fixture.example) printf '203.0.113.9' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_test_resolve

# =============================================================================
printf -- '\n-- allowlist building: the four sets (docs/FOUNDATION.md tension 20) --\n'
# =============================================================================
# Populated directly in THIS shell (not a subshell) so every assert_status
# call below - each of which subshells only the one predicate call - sees
# the same populated _PARANOID_ADDR/_PARANOID_PORT arrays by ordinary fork
# inheritance.
SCOURSH_INSTALL_ROOT=$FROOT
SCOURSH_RESOLV_CONF=$RESOLV
config_scanner_load
paranoid_allowlist_build

t_case 'loopback (set 3) is allowed on an arbitrary port - the unrestricted half of set 3'
assert_status 0 '127.0.0.1 on an arbitrary port' paranoid_addr_allowed 127.0.0.1 9
assert_status 0 '::1 on an arbitrary port' paranoid_addr_allowed ::1 51234

t_case 'resolv.conf nameserver (set 3) is allowed on port 53 only - fails under the rejected reading (tension 20 option 1: "allowlist anything on port 53")'
assert_status 0 'nameserver:53 allowed' paranoid_addr_allowed 10.10.10.10 53
assert_status 1 'same nameserver address on port 80 is NOT allowed' paranoid_addr_allowed 10.10.10.10 80
assert_status 1 'a non-nameserver address on port 53 is NOT allowed' paranoid_addr_allowed 9.9.9.9 53

t_case 'in-scope resolved target (set 1) is allowed on its authorised port only'
assert_status 0 'resolved scope host:443 allowed' paranoid_addr_allowed 203.0.113.9 443
assert_status 1 'same resolved address on a DIFFERENT port is NOT allowed' paranoid_addr_allowed 203.0.113.9 8080

t_case 'scanner.conf paranoid_allow (set 4) is allowed on its declared addr:port exactly'
assert_status 0 'operator paranoid_allow entry allowed' paranoid_addr_allowed 198.51.100.7 9443
assert_status 1 'same address on a different port is NOT allowed (paranoid_allow is addr:port, not addr:*)' \
  paranoid_addr_allowed 198.51.100.7 80

t_case 'an address in none of the four sets is refused'
assert_status 1 'arbitrary out-of-scope destination refused' paranoid_addr_allowed 203.0.113.99 443

# =============================================================================
printf -- '\n-- AWS set (set 2): empty with a stated reason (no regions.sh yet) --\n'
# =============================================================================
_test_aws_set_no_cloud() {
  SCOURSH_INSTALL_ROOT=$FROOT
  SCOURSH_RESOLV_CONF=$RESOLV
  run_init "$W/aws-note-run"
  config_scanner_load
  SCAN_COMMAND=''
  paranoid_allowlist_build
  grep -q 'set=aws reason=no_aws_scan_this_run addresses=0' "$W/aws-note-run/meta/paranoid_allowlist_note"
}
t_case 'AWS allowlist set 2 records reason=no_aws_scan_this_run when SCAN_COMMAND is not cloud (docs/STEP8-PARANOID-PLAN.md forward-dependency pattern, DAST-09-style)'
assert_status 0 'no-cloud run: AWS set empty with reason=no_aws_scan_this_run' _test_aws_set_no_cloud

_test_aws_set_cloud_unbuilt() {
  SCOURSH_INSTALL_ROOT=$FROOT
  SCOURSH_RESOLV_CONF=$RESOLV
  run_init "$W/aws-note-run-cloud"
  config_scanner_load
  SCAN_COMMAND=cloud
  paranoid_allowlist_build
  grep -q 'set=aws reason=modules_cloud_aws_regions_sh_not_yet_built addresses=0' \
    "$W/aws-note-run-cloud/meta/paranoid_allowlist_note"
}
t_case 'AWS allowlist set 2 records reason=modules_cloud_aws_regions_sh_not_yet_built when SCAN_COMMAND=cloud - modules/cloud/aws/regions.sh genuinely does not exist on this branch'
assert_status 0 'cloud run with no regions.sh: AWS set empty with the unbuilt-module reason' _test_aws_set_cloud_unbuilt

# =============================================================================
printf -- '\n-- backend probe: forced override (SCOURSH_PARANOID_FORCE_BACKEND) --\n'
# =============================================================================
_test_forced_backend_none() {
  SCOURSH_PARANOID_FORCE_BACKEND=none
  paranoid_probe_backend
  [[ $PARANOID_BACKEND == none ]]
}
t_case 'SCOURSH_PARANOID_FORCE_BACKEND=none is honoured by the probe'
assert_status 0 'forced backend=none is read back as none' _test_forced_backend_none

# =============================================================================
printf -- '\n-- AC4: neither ss nor strace usable -> exit 4 (SCOURSH_EXIT_INPUT) --\n'
# =============================================================================
t_case '--paranoid with no usable backend dies exit 4, not silently running unobserved'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=none assert_status "$SCOURSH_EXIT_INPUT" \
  'no ss/strace: exit 4' scan_main sast --paranoid --out "$W/run-no-backend"

# =============================================================================
printf -- '\n-- AC5 (deterministic no-egress fixture): clean run, zero non-loopback --\n'
# =============================================================================
# The scripted samplers below are the "recorded mock response" tension 20
# asks for, applied to the OBSERVER rather than to DNS: each reports exactly
# what a real ss/strace sampler would see for a specific, scripted run -
# deterministic on every host, unlike a real ss/strace capture would be.
_test_paranoid_sample_clean() {
  printf '127.0.0.1 4321\n'
  printf '::1 53\n'
}

t_case 'a run whose only observed connections are loopback completes normally (exit 0), never aborting'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_clean SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_OK" 'clean loopback-only run exits 0 under --paranoid' \
  scan_main sast --paranoid --out "$W/run-clean"

t_case 'the clean run states the "detector, not guarantee" framing in run.json (the report output, AC6) - not just in docs'
RUNJSON=$(cat "$W/run-clean/run.json" 2>/dev/null || true)
assert_contains "$RUNJSON" 'detector' 'run.json coverage_gap mentions the mechanism is a detector'
assert_contains "$RUNJSON" 'run-in-netns' 'run.json coverage_gap names tools/run-in-netns.sh as the actual guarantee'

# =============================================================================
printf -- '\n-- AC2/AC3: an out-of-allowlist connection aborts the run, exit 3 --\n'
# =============================================================================
_test_paranoid_sample_violation() {
  printf '203.0.113.250 4444\n'   # TEST-NET-3 (RFC 5737); in none of the four sets
}

t_case 'a connection outside the four-set allowlist aborts the run with exit 3 (SCOURSH_EXIT_SCOPE), not a warning'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_violation SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_SCOPE" \
  'out-of-allowlist connection: exit 3, fails under "log a warning and continue" (tension 20 option 2, rejected)' \
  scan_main sast --paranoid --out "$W/run-violation"

_test_violation_finding_written() {
  local f
  for f in "$W"/run-violation/shards/*.jsonl; do
    [[ -e $f ]] || continue
    grep -q 'PARANOID-EGRESS-VIOLATION' "$f" && return 0
  done
  return 1
}
t_case 'the abort is auditable: a PARANOID-EGRESS-VIOLATION finding is written (mirrors lib/http.sh _http_gate_audit)'
assert_status 0 'violation finding recorded in a shard' _test_violation_finding_written

# =============================================================================
printf -- '\n-- an allowlisted destination never aborts, under the same backend/poll wiring --\n'
# =============================================================================
_test_paranoid_sample_allowed_only() {
  printf '198.51.100.7 9443\n'   # exactly the scanner.conf paranoid_allow entry
}
t_case 'an allowlisted (operator paranoid_allow) destination does not trip the observer - fails under "abort on ANY sampled connection" (an overly broad reading this suite must also rule out)'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=ss \
  SCOURSH_PARANOID_SAMPLE=_test_paranoid_sample_allowed_only SCOURSH_PARANOID_POLL_MS=20 \
  assert_status "$SCOURSH_EXIT_OK" 'allowlisted destination: exit 0' \
  scan_main sast --paranoid --out "$W/run-allowed-only"

# =============================================================================
printf -- '\n-- --paranoid absent: zero behaviour change (no attach, no observer) --\n'
# =============================================================================
t_case 'without --paranoid, a run with no usable backend still succeeds (the observer is never engaged)'
SCOURSH_INSTALL_ROOT=$FROOT SCOURSH_PARANOID_FORCE_BACKEND=none assert_status "$SCOURSH_EXIT_OK" \
  'no --paranoid flag: exit 0 regardless of backend availability' \
  scan_main sast --out "$W/run-no-paranoid"

t_summary paranoid
