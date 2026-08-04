#!/usr/bin/env bash
# tests/suites/vendor-engines.sh - tools/vendor-engines.sh, the sole
# network-permitted, quarantined script (docs/FOUNDATION.md tension 27;
# docs/ADAPTERS.md).
#
# What this suite proves, and what it honestly cannot:
#
#  - Usage/help, the registry-listing path, the unknown-engine error path,
#    the no-args usage error, and the exit-code contract (0/2/4, never
#    outside 0-5) are all exercised as REAL subprocess invocations of the
#    actual script (`bash "$TOOL" ...`).
#  - The first concrete adapter ticket registered the first real engine,
#    `semgrep` -> `veng_vendor_semgrep`, so "the registry is genuinely
#    empty" is no longer true; THIS ticket (the second concrete adapter,
#    the first for a module other than sast) registers a SECOND real
#    engine, `trivy` -> `veng_vendor_trivy`, so every assertion below that
#    used to assume "exactly one entry" is updated to the new, real shape:
#    `--list`/the registry itself now name both `semgrep` and `trivy`, and
#    vendoring an UNREGISTERED name still uses a different bogus engine id
#    so that path stays exercised regardless of how many real engines are
#    registered.
#  - Section D is the fetch/verify flow the scaffold suite's own comment
#    promised the first concrete adapter ticket would add: `veng_fetch`'s
#    checksum success and mismatch paths, and `semgrep_vendor`'s
#    required-env-var gate, all against a STUBBED `curl` (same idea
#    tests/suites/http.sh's header describes for lib/http.sh's own
#    resolver/transport hooks, applied here to an actual fake `curl`
#    binary on PATH since veng_fetch has no swappable-hook seam of its
#    own - it is meant to call the real `curl`, on a REAL networked box,
#    every time). Runs against a SCRATCH COPY of
#    modules/sast/adapters/semgrep/, never the real one - vendoring for
#    real would write a fake "binary" into this repository's own working
#    tree, which no test may do.  This ticket extends section D with the
#    equivalent proof for `trivy_vendor` (modules/iac/adapters/trivy/
#    vendor.sh) against its own SCRATCH COPY - a required-env-var gate and
#    a full success path, but only ONE artifact (bin/trivy - no rules/,
#    since trivy's checks are compiled into the binary; see that
#    vendor.sh's own header).
#  - It still asserts this script makes NO real network call in any path
#    that is not deliberately exercising the (stubbed) fetch flow, by
#    running those paths with PATH stripped of curl/wget entirely
#    (section B) - if any code path there tried to fetch something, the
#    subprocess would fail with "command not found", not silently succeed.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=tools/vendor-engines.sh
source "$ROOT/tools/vendor-engines.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

TOOL=$ROOT/tools/vendor-engines.sh
W=$SCOURSH_SCRATCH/vendor-engines

mkdir -p "$W"

# ---------------------------------------------------------------------------
# -- section A: in-process function tests (pure logic, nothing that exits) --
# ---------------------------------------------------------------------------
t_case 'registry'
assert_eq 2 "${#VENG_REGISTRY[@]}" \
  'the engine registry has exactly two entries (semgrep, trivy) after this ticket - fails under the reading that it is still empty, still one, or that a third adapter snuck in'
assert_eq veng_vendor_semgrep "${VENG_REGISTRY[semgrep]:-}" \
  'the semgrep entry maps to veng_vendor_semgrep specifically'
assert_eq veng_vendor_trivy "${VENG_REGISTRY[trivy]:-}" \
  'the trivy entry maps to veng_vendor_trivy specifically'

t_case 'veng_list, two registered engines'
out=$(veng_list)
assert_eq "$(printf 'semgrep\ntrivy')" "$out" \
  'listing the registry now prints "semgrep" then "trivy", LC_ALL=C sorted - fails under the stale reading that it still reports only semgrep, or in a different order'
rc=0
veng_list >/dev/null || rc=$?
assert_eq 0 "$rc" 'listing a non-empty registry is success'

t_case 'veng_vendor_all, two registered engines, no operator-supplied values: refuses on the first one it reaches, alphabetically'
rc=0
# In a subshell: semgrep_vendor's env-var gate calls die(), which calls
# exit() - run in-process it would terminate this whole suite, not just
# return a status, exactly the same subshell discipline scan.sh's own
# comment on _scan_require_readable_path documents for the identical
# reason.
( veng_vendor_all ) >"$W/all.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  '--all now reaches semgrep_vendor (first, alphabetically), which refuses (exit 4) rather than guessing a version/URL/checksum - fails under the stale reading that nothing is registered so this is still a no-op'
assert_contains "$(cat "$W/all.out")" 'SCOURSH_SEMGREP_VERSION' \
  'the refusal names the actual env var an operator must set, not just "no"'

# ---------------------------------------------------------------------------
# -- section B: real subprocess invocations of the actual script, with
#    PATH stripped of curl/wget so any accidental fetch attempt fails
#    loudly (command not found) rather than silently reaching the network --
# ---------------------------------------------------------------------------
NO_NET_PATH=$W/no-curl-path
mkdir -p "$NO_NET_PATH"
for tool in bash cat sort mkdir dirname pwd printf true false grep sed date; do
  src=$(command -v "$tool" 2>/dev/null) || continue
  ln -sf "$src" "$NO_NET_PATH/$tool"
done

t_case 'usage/help'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --help 2>&1) || rc=$?
assert_eq 0 "$rc" '--help exits 0'
assert_contains "$out" 'usage: tools/vendor-engines.sh' \
  '--help prints the usage banner'
assert_contains "$out" 'never invoked by scan.sh' \
  '--help states the never-wired-into-a-scan contract, not just how to run it'

t_case 'no args'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" 2>&1) || rc=$?
assert_eq 2 "$rc" \
  'no command given is a usage error (exit 2), matching scan.sh'"'"'s own convention - fails under the reading that missing args silently no-op'

t_case 'unknown flag'
rc=0
PATH=$NO_NET_PATH bash "$TOOL" --bogus >/dev/null 2>&1 || rc=$?
assert_eq 2 "$rc" 'an unrecognised flag is a usage error (exit 2)'

t_case '--list, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --list 2>&1) || rc=$?
assert_eq 0 "$rc" '--list exits 0'
assert_eq "$(printf 'semgrep\ntrivy')" "$out" \
  '--list reports "semgrep" then "trivy" as a real subprocess too'

t_case 'unregistered engine name'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" nonexistent-engine 2>&1) || rc=$?
assert_eq 4 "$rc" \
  'vendoring an unregistered engine is exit 4 (SCOURSH_EXIT_INPUT) - fails under the reading that an unknown name is a usage error (2) or silently succeeds (0)'
assert_contains "$out" "unknown engine 'nonexistent-engine'" \
  'the error names the actual engine that was requested'
assert_contains "$out" 'docs/ADAPTERS.md' \
  'the error points at the convention document, not just "no"'

t_case 'registered engine name, no operator-supplied values: refuses, never touches the network'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" semgrep 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'semgrep with none of SCOURSH_SEMGREP_VERSION/URL/SHA256/RULES_URL/RULES_SHA256 set is exit 4 - fails under the reading that a registered engine with no configuration silently no-ops (0) or crashes outside 0-5'
assert_contains "$out" 'SCOURSH_SEMGREP_VERSION' \
  'the refusal names the actual env vars an operator must set'
assert_contains "$out" 'never guesses or hardcodes a checksum' \
  'the refusal states the reason (no invented checksum), matching this file'"'"'s and vendor.sh'"'"'s own stated policy'

t_case 'trivy, no operator-supplied values: refuses, never touches the network'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" trivy 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'trivy with none of SCOURSH_TRIVY_VERSION/URL/SHA256 set is exit 4 - the same shape semgrep uses, with a smaller env-var set (no RULES_URL/RULES_SHA256 - trivy vendors one artifact, not two)'
assert_contains "$out" 'SCOURSH_TRIVY_VERSION' \
  'the refusal names the actual env vars an operator must set'
assert_contains "$out" 'never guesses or hardcodes a checksum' \
  'the refusal states the reason (no invented checksum), matching semgrep_vendor'"'"'s own stated policy'

t_case '--all, real subprocess'
rc=0
out=$(PATH=$NO_NET_PATH bash "$TOOL" --all 2>&1) || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  '--all as a real subprocess reaches semgrep (first, alphabetically) and refuses (exit 4) the same way, with curl entirely absent from PATH - proving the refusal happens before any network attempt, not because curl was unavailable'

t_case 'exit codes never leave 0-5 (tension 14, finding F16)'
for args in '' '--help' '--list' '--all' '--bogus' 'semgrep' 'trivy'; do
  rc=0
  # shellcheck disable=SC2086
  PATH=$NO_NET_PATH bash "$TOOL" $args >/dev/null 2>&1 || rc=$?
  if (( rc >= 0 && rc <= 5 )); then
    _t_ok "exit code for '$args' is $rc, within 0-5"
  else
    _t_no "exit code for '$args' is $rc, OUTSIDE 0-5" "args: [$args]"
  fi
done

# ---------------------------------------------------------------------------
# -- section D: veng_fetch and semgrep_vendor's real fetch/verify flow,
#    against a STUBBED curl and a SCRATCH COPY of
#    modules/sast/adapters/semgrep/ (never the real one - vendoring for
#    real would write a fake "binary" into this repository's own working
#    tree, which no test may do).
# ---------------------------------------------------------------------------
FAKE_BIN=$W/fake-bin
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/curl" <<'FAKECURL'
#!/usr/bin/env bash
# Test double for curl (tests/suites/vendor-engines.sh only) - never a real
# network call.  Writes deterministic bytes to the --output destination:
# FAKE_CURL_CONTENT_BIN when the requested URL contains "semgrep-bin",
# FAKE_CURL_CONTENT_RULES when it contains "semgrep-rules",
# FAKE_CURL_CONTENT_TRIVY_BIN when it contains "trivy-bin", else
# FAKE_CURL_CONTENT (or a fixed default) - letting one semgrep_vendor call,
# which fetches two different URLs, be verified against two different
# known-content checksums in a single real invocation.
set -Eeuo pipefail
out='' url=''
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  case ${args[i]} in
    --output) out=${args[$(( i + 1 ))]} ;;
    http*) url=${args[i]} ;;
  esac
  i=$(( i + 1 ))
done
if [[ -n ${FAKE_CURL_FAIL:-} ]]; then
  printf 'fake curl: simulated failure\n' >&2
  exit 22
fi
case $url in
  *semgrep-bin*) printf '%s' "${FAKE_CURL_CONTENT_BIN:-fake-semgrep-binary-bytes}" >"$out" ;;
  *semgrep-rules*) printf '%s' "${FAKE_CURL_CONTENT_RULES:-fake-semgrep-rules-bytes}" >"$out" ;;
  *trivy-bin*) printf '%s' "${FAKE_CURL_CONTENT_TRIVY_BIN:-fake-trivy-binary-bytes}" >"$out" ;;
  *) printf '%s' "${FAKE_CURL_CONTENT:-fake-artifact-bytes}" >"$out" ;;
esac
FAKECURL
chmod +x "$FAKE_BIN/curl"

t_case 'veng_fetch requires all three arguments'
rc=0
( veng_fetch '' "$W/x" abc ) >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" 'veng_fetch with an empty URL refuses (exit 4) rather than trying anyway'

t_case 'veng_fetch: checksum match succeeds and writes the verified bytes'
GOOD_SHA=$(printf '%s' 'known-good-bytes' | sha256_of)
rc=0
( PATH="$FAKE_BIN:$PATH" FAKE_CURL_CONTENT='known-good-bytes' \
  veng_fetch 'https://example.invalid/artifact' "$W/verified.bin" "$GOOD_SHA" ) >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" 'a checksum that matches what was fetched succeeds'
assert_eq 'known-good-bytes' "$(cat "$W/verified.bin" 2>/dev/null)" \
  'the verified file holds exactly the fetched bytes'

t_case 'veng_fetch: checksum mismatch refuses and removes the file - fails under "trust whatever arrived"'
rm -f "$W/mismatched.bin"
rc=0
( PATH="$FAKE_BIN:$PATH" FAKE_CURL_CONTENT='not-what-was-expected' \
  veng_fetch 'https://example.invalid/artifact' "$W/mismatched.bin" "$GOOD_SHA" ) >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" \
  'a checksum mismatch is exit 5 (incomplete/untrusted), not a silent success'
assert_file_absent "$W/mismatched.bin" \
  'a mismatched download is removed, never left on disk where semgrep_detect could later find it and trust it'

t_case 'veng_fetch: a download failure (curl itself fails) is exit 5, not a false success'
rc=0
( PATH="$FAKE_BIN:$PATH" FAKE_CURL_FAIL=1 \
  veng_fetch 'https://example.invalid/artifact' "$W/never-written.bin" "$GOOD_SHA" ) >/dev/null 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INCOMPLETE" "$rc" 'a curl failure propagates as exit 5, never exit 0'
assert_file_absent "$W/never-written.bin" 'nothing is written when the fetch itself failed'

# semgrep_vendor's own end-to-end orchestration, against a SCRATCH COPY of
# the adapter directory so this never touches the real
# modules/sast/adapters/semgrep/ in this repository's own working tree.
ADAPTER_COPY=$W/adapter-copy
rm -rf "$ADAPTER_COPY"
mkdir -p "$ADAPTER_COPY"
cp "$ROOT/modules/sast/adapters/semgrep/vendor.sh" "$ADAPTER_COPY/vendor.sh"

t_case 'semgrep_vendor: missing operator-supplied values refuses before ever calling curl'
rc=0
( unset SCOURSH_SEMGREP_VERSION SCOURSH_SEMGREP_URL SCOURSH_SEMGREP_SHA256 \
    SCOURSH_SEMGREP_RULES_URL SCOURSH_SEMGREP_RULES_SHA256
  # shellcheck source=/dev/null
  source "$ADAPTER_COPY/vendor.sh"
  PATH=$NO_NET_PATH semgrep_vendor ) >"$W/sv.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'semgrep_vendor with nothing set refuses (exit 4) even with curl entirely unavailable on PATH, proving the env-var gate runs before any fetch attempt'

t_case 'semgrep_vendor: full success path populates bin/ (executable) and rules/, verified end to end'
BIN_SHA=$(printf '%s' 'fake-semgrep-binary-bytes' | sha256_of)
RULES_SHA=$(printf '%s' 'fake-semgrep-rules-bytes' | sha256_of)
rc=0
( export SCOURSH_SEMGREP_VERSION=1.99.0
  export SCOURSH_SEMGREP_URL=https://example.invalid/semgrep-bin
  export SCOURSH_SEMGREP_SHA256=$BIN_SHA
  export SCOURSH_SEMGREP_RULES_URL=https://example.invalid/semgrep-rules
  export SCOURSH_SEMGREP_RULES_SHA256=$RULES_SHA
  # shellcheck source=/dev/null
  source "$ADAPTER_COPY/vendor.sh"
  PATH="$FAKE_BIN:$PATH" semgrep_vendor ) >"$W/sv-ok.out" 2>&1 || rc=$?
assert_eq 0 "$rc" 'semgrep_vendor succeeds end to end when every value and both checksums are correct'
assert_file_exists "$ADAPTER_COPY/bin/semgrep" 'the vendored binary lands at bin/semgrep'
if [[ -x $ADAPTER_COPY/bin/semgrep ]]; then
  _t_ok 'the vendored binary is executable'
else
  _t_no 'the vendored binary is executable' "not executable: $ADAPTER_COPY/bin/semgrep"
fi
assert_file_exists "$ADAPTER_COPY/rules/semgrep-rules.yml" 'the vendored ruleset lands at rules/semgrep-rules.yml'
assert_eq 'fake-semgrep-binary-bytes' "$(cat "$ADAPTER_COPY/bin/semgrep" 2>/dev/null)" \
  'the vendored binary holds exactly the checksum-verified bytes for its OWN URL, not the ruleset'"'"'s'
assert_eq 'fake-semgrep-rules-bytes' "$(cat "$ADAPTER_COPY/rules/semgrep-rules.yml" 2>/dev/null)" \
  'the vendored ruleset holds exactly the checksum-verified bytes for its OWN URL, not the binary'"'"'s - fails under a bug that swapped the two destinations'
rm -rf "$ADAPTER_COPY"

# trivy_vendor's own end-to-end orchestration (this ticket, the second
# concrete adapter), against a SCRATCH COPY of
# modules/iac/adapters/trivy/, never the real one, for the identical
# reason the semgrep block above uses one.
TRIVY_ADAPTER_COPY=$W/trivy-adapter-copy
rm -rf "$TRIVY_ADAPTER_COPY"
mkdir -p "$TRIVY_ADAPTER_COPY"
cp "$ROOT/modules/iac/adapters/trivy/vendor.sh" "$TRIVY_ADAPTER_COPY/vendor.sh"

t_case 'trivy_vendor: missing operator-supplied values refuses before ever calling curl'
rc=0
( unset SCOURSH_TRIVY_VERSION SCOURSH_TRIVY_URL SCOURSH_TRIVY_SHA256
  # shellcheck source=/dev/null
  source "$TRIVY_ADAPTER_COPY/vendor.sh"
  PATH=$NO_NET_PATH trivy_vendor ) >"$W/tv.out" 2>&1 || rc=$?
assert_eq "$SCOURSH_EXIT_INPUT" "$rc" \
  'trivy_vendor with nothing set refuses (exit 4) even with curl entirely unavailable on PATH, proving the env-var gate runs before any fetch attempt'

t_case 'trivy_vendor: full success path populates bin/ (executable) only - no rules/ at all, verified end to end'
TRIVY_BIN_SHA=$(printf '%s' 'fake-trivy-binary-bytes' | sha256_of)
rc=0
( export SCOURSH_TRIVY_VERSION=0.99.0
  export SCOURSH_TRIVY_URL=https://example.invalid/trivy-bin
  export SCOURSH_TRIVY_SHA256=$TRIVY_BIN_SHA
  # shellcheck source=/dev/null
  source "$TRIVY_ADAPTER_COPY/vendor.sh"
  PATH="$FAKE_BIN:$PATH" trivy_vendor ) >"$W/tv-ok.out" 2>&1 || rc=$?
assert_eq 0 "$rc" 'trivy_vendor succeeds end to end when the value and checksum are correct'
assert_file_exists "$TRIVY_ADAPTER_COPY/bin/trivy" 'the vendored binary lands at bin/trivy'
if [[ -x $TRIVY_ADAPTER_COPY/bin/trivy ]]; then
  _t_ok 'the vendored binary is executable'
else
  _t_no 'the vendored binary is executable' "not executable: $TRIVY_ADAPTER_COPY/bin/trivy"
fi
assert_eq 'fake-trivy-binary-bytes' "$(cat "$TRIVY_ADAPTER_COPY/bin/trivy" 2>/dev/null)" \
  'the vendored binary holds exactly the checksum-verified bytes'
assert_file_absent "$TRIVY_ADAPTER_COPY/rules" \
  'trivy_vendor never creates a rules/ directory at all - fails under a reading that copied semgrep_vendor'"'"'s two-artifact shape verbatim'
rm -rf "$TRIVY_ADAPTER_COPY"

# ---------------------------------------------------------------------------
# -- section C: the dual-mode source guard - sourcing this file (as section
#    A already did, above) must not run veng_main or exit the sourcing
#    shell.  If it did, this suite would never have reached this line.
# ---------------------------------------------------------------------------
t_case 'dual-mode source guard'
assert_eq 0 "$VENG_MAIN" \
  'sourcing tools/vendor-engines.sh sets VENG_MAIN=0 and does not run veng_main - fails under the reading that sourcing it also executes the CLI dispatch'

t_summary 'vendor-engines'
