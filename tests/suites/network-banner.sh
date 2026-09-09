#!/usr/bin/env bash
# tests/suites/network-banner.sh - modules/network/banner.sh: the NET-07
# read-on-connect service identification probe and the
# `NET-SVC-BANNER_DISCLOSURE-01` check (data/scoursh-network-scan-design/
# report.md §3.2 item 1, §5.1, §5.2, §5.3). NET-05's inventory.sh artifact
# and NET-06's open/not-open/filtered classification are this file's live
# inputs; tests/suites/network-inventory.sh and
# tests/suites/network-reachability.sh pin those separately, so this suite
# treats them as trusted producers/primitives and focuses on what THIS
# ticket adds.
#
# Six things this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. banner.sh reuses NET-06's own open/not-open/filtered classification
#      (the SAME net_connect_probe call, never a second way of deciding) -
#      a banner is only ever read from a listener classified `open`.
#   2. NET-SVC-BANNER_DISCLOSURE-01 fires when a listener volunteers a
#      product/version, unprompted, over one or more lines.
#   3. THIS PROBE SENDS ZERO BYTES - a not-open or filtered listener is never
#      even asked for a banner (SCOURSH_NET_BANNER_PROBE is never invoked for
#      one), and a real connect+read never writes to the socket
#      (pinned separately, and statically, in tests/suites/nettransport.sh).
#   4. An open listener that sends nothing is a counted `no_banner`
#      reduction, never a silent clean and never a finding.
#   5. A not-open/filtered declared listener is a counted
#      `net_check_not_applicable` reduction - report.md §5.2 rule 4's
#      "never collapsed" reasoning, applied one probe over.
#   6. A finding this phase emits carries the `net` fingerprint profile's own
#      location fields (target/host/port/transport) and round-trips through
#      every output format.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes flag/JSON syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation so a fixture root can never leak into the
#   next case.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=/dev/null
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/network-banner
rm -rf "$W"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# Fixture install root - tests/suites/network-reachability.sh's own shape.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

# banner.fixture.invalid is RFC 2606-reserved and resolves to a TEST-NET-3
# (RFC 5737) literal this suite never dials - both SCOURSH_NET_PROBE and
# SCOURSH_NET_BANNER_PROBE (below) replace the whole real-socket path, so
# what it resolves to only matters for lib/http.sh's own scope-gate/pinning
# logic to have something real to authorise.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  banner.fixture.invalid) printf '203.0.113.60' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"

# `SCOURSH_NET_PROBE` (lib/nettransport.sh, NET-03) replaces the whole
# real-socket classify step. This suite's fixture always uses ONE host at
# several distinct ports, so the stub switches on PORT ($2) alone.
NET_PROBE_STUB=$W/net-probe-stub
cat >"$NET_PROBE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${NET_PROBE_LOG:?}"
case $2 in
  443) printf 'open\n' ;;
  8443) printf 'open\n' ;;
  2121) printf 'open\n' ;;
  5432) printf 'not-open\n' ;;
  9999) printf 'filtered\n' ;;
  *) printf 'not-open\n' ;;
esac
STUBEOF
chmod 0755 "$NET_PROBE_STUB"

# `SCOURSH_NET_BANNER_PROBE` (lib/nettransport.sh, NET-07) replaces the whole
# real-socket read step. Every invocation is logged BEFORE it decides what to
# write, so "was this ever called for a non-open port" is a real, observable
# assertion rather than an inference from the absence of a finding.
NET_BANNER_STUB=$W/net-banner-stub
cat >"$NET_BANNER_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'host=%s port=%s max_bytes=%s\n' "$1" "$2" "$3" >>"${NET_BANNER_LOG:?}"
: >"$4"
case $2 in
  443) printf 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n' >"$4" ;;
  2121) printf '220-Welcome to a fixture FTP daemon\r\n220 ProFTPD 1.3.5e Server ready.\r\n' >"$4" ;;
  8443) : ;;   # sends nothing - the no_banner case
esac
STUBEOF
chmod 0755 "$NET_BANNER_STUB"

# `_net_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh network`
# subprocess. banner.sh's own phase tier is `passive` (modules/network/
# engine.sh's own phase table), so - unlike tests/suites/network-
# reachability.sh's own helper - NEITHER `--intensity` NOR `--i-own-target`
# is needed: scan.sh's `_scan_check_affirmation` requires the affirmation
# only when `--intensity` is given AND differs from the default
# (`passive`, lib/checks.sh), so a bare `scan.sh network --target X` already
# runs this check. Running it at the plain default is itself part of what
# report.md §5.1's `passive` tag for this check means, and is worth pinning
# by NOT passing those two flags here, unlike the reachability suite.
_net_scan() {
  local rundir=$1 root=$2 target=''
  shift 2
  local -a args=("$@")
  local i
  for (( i = 0; i < ${#args[@]}; i++ )); do
    if [[ ${args[i]} == --target ]]; then target=${args[i+1]}; fi
  done
  _LOG=$rundir.log
  _RC=0
  NET_PROBE_LOG=$W/net-probe.log NET_BANNER_LOG=$W/net-banner.log \
    SCOURSH_INSTALL_ROOT=$root SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
    SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_BANNER_PROBE=$NET_BANNER_STUB \
    bash "$ROOT/scan.sh" network --out "$rundir" \
    --target "$target" "${args[@]}" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf '\n-- an open listener that discloses a product+version fires the check; a not-open/filtered one never gets a banner probe at all --\n'
# =============================================================================

FIX_MULTI=$W/root-multi
_fixture_root "$FIX_MULTI"
cat >"$FIX_MULTI/config/scope.conf" <<'EOF'
id: net-banner
base-url: https://banner.fixture.invalid/
extra-host: banner.fixture.invalid:8443
extra-host: banner.fixture.invalid:5432
extra-host: banner.fixture.invalid:9999
allow-subdomains: false
EOF

rm -f "$W/net-probe.log" "$W/net-banner.log"
t_case 'a run over four declared listeners (open+banner, open+no-banner, not-open, filtered) exits 0'
_net_scan "$W/run-multi" "$FIX_MULTI" --target net-banner
assert_eq 0 "$_RC" \
  'scan.sh network --target net-banner exits 0 at the DEFAULT intensity - FAILS if this check required an affirmation it should not need at its own passive tier'

t_case 'net_connect_probe (the classification step) was invoked for every declared listener - the reuse this check makes of NET-06s own primitive'
PROBE_LOG=$(_slurp "$W/net-probe.log")
# NOT an exact total count: modules/network/engine.sh's own phase table now
# runs tlsport.sh (NET-08) alongside banner.sh at the SAME passive tier, and
# tlsport.sh calls this SAME net_connect_probe primitive on this SAME
# declared listener set for its own classification (modules/network/
# tlsport.sh's own header: "reachability.sh's own contract, for
# net_connect_probe/net_probe_capability"), into this SAME shared
# NET_PROBE_LOG file - a total-line assertion here would silently start
# asserting a fact about a SIBLING phase's call volume rather than this
# check's own, and break again the next time a further passive-tier peer
# lands. Each declared (address, port) pair is asserted individually
# instead, which is true regardless of how many phases share the primitive.
for p in 443 8443 5432 9999; do
  assert_contains "$PROBE_LOG" "203.0.113.60 $p" \
    "listener port $p was classified at its resolved address, not the hostname (the anti-TOCTOU guarantee report.md §2.5 names) - FAILS if this listener were never probed at all"
done

t_case 'the banner-read step was invoked ONLY for the two open listeners, never for not-open or filtered ones - THE PASSIVE CONTRACT'
BANNER_LOG=$(_slurp "$W/net-banner.log")
assert_eq 2 "$(grep -c . <<<"$BANNER_LOG")" \
  'exactly two banner-read invocations (ports 443 and 8443) - FAILS if a not-open or filtered listener were also asked for a banner, which report.md §5.2 rule 4s own "never collapsed" reasoning forbids for this probe just as much as for NET-06s own findings'
assert_contains "$BANNER_LOG" 'host=203.0.113.60 port=443' 'the open base-url listener was read'
assert_contains "$BANNER_LOG" 'host=203.0.113.60 port=8443' 'the other open listener was read too'
assert_not_contains "$BANNER_LOG" 'port=5432' \
  'the not-open listener (5432) was NEVER handed to the banner-read primitive - FAILS if this check probed every declared listener regardless of NET-06s own classification, re-implementing rather than reusing it'
assert_not_contains "$BANNER_LOG" 'port=9999' \
  'the filtered listener (9999) was NEVER handed to the banner-read primitive either'
assert_contains "$BANNER_LOG" 'max_bytes=1024' \
  'the module'"'"'s own read bound (modules/network/banner.sh _NET_BANNER_MAX_BYTES) reached the transport call unchanged'

RUN_MULTI_JSONL=$(_slurp "$W/run-multi/findings.jsonl")
t_case 'the disclosing listener (443, SSH) produced the finding, with the identified product and version in evidence'
assert_contains "$RUN_MULTI_JSONL" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'the check fires on a real disclosure - FAILS if the identification pass never ran or never matched the SSH wire-format identification string'
assert_contains "$RUN_MULTI_JSONL" '"location":{"target":"net-banner","host":"banner.fixture.invalid","port":"443","transport":"https"}' \
  'the finding location names the actual disclosing port, under the net fingerprint profile (lib/findings.sh _fp_components_for net: target host port transport)'
assert_contains "$RUN_MULTI_JSONL" "openssh" "the identified product is openssh (banner_normalize_product's own frozen normalisation, modules/dast/passive/banner_engine.sh, reused rather than re-implemented per docs/VERSIONS-DB.md §4)"
assert_contains "$RUN_MULTI_JSONL" '8.9p1' 'the identified version (8.9p1) appears in the evidence'

t_case 'the other open listener (8443), which sent NO banner, produced no finding at all'
NOFIND_8443=$(grep '"port":"8443"' <<<"$RUN_MULTI_JSONL" || true)
assert_eq '' "$NOFIND_8443" \
  'no finding of any kind names port 8443 - FAILS if a listener sending zero bytes were somehow reported as a disclosure'

RUN_MULTI_JSON=$(_slurp "$W/run-multi/run.json")
t_case 'the no-banner listener (8443) is a counted no_banner reduction, never a silent clean'
assert_contains "$RUN_MULTI_JSON" 'reason=no_banner checks=[NET-SVC-BANNER_DISCLOSURE-01] target=net-banner count=1' \
  'the reduction names the exact reason report.md §5.2 rule 2s own honesty vocabulary lists for this check, and the real count'

t_case 'the not-open and filtered listeners are ONE counted net_check_not_applicable reduction, naming both states'
assert_contains "$RUN_MULTI_JSON" 'reason=net_check_not_applicable checks=[NET-SVC-BANNER_DISCLOSURE-01] target=net-banner count=2 not_open=1 filtered=1' \
  'both non-open listeners are folded into one reduction with the real breakdown - FAILS if either were silently dropped or reported as a finding'

t_case 'checks_run records NET-SVC-BANNER_DISCLOSURE-01 once at least one listener was actually open and read'
assert_contains "$RUN_MULTI_JSON" 'NET-SVC-BANNER_DISCLOSURE-01' 'the check id is in checks_run'

t_case 'checks-banner.rules registers the id under coverage-scope target and tags passive, per rules/RULE-FORMAT.md §9.5.1 NET row'
RULES_FILE=$(_slurp "$ROOT/modules/network/checks-banner.rules")
assert_contains "$RULES_FILE" 'id: NET-SVC-BANNER_DISCLOSURE-01' 'the check id is registered'
assert_contains "$RULES_FILE" 'coverage-scope: target' 'the record declares coverage-scope: target - FAILS the linter'"'"'s E079 otherwise'
assert_contains "$RULES_FILE" 'tags: passive' \
  'the record is tagged passive, matching modules/network/engine.sh'"'"'s own banner.sh:passive phase-table floor and report.md §5.1'"'"'s own table for this check'

# =============================================================================
printf '\n-- a multi-line greeting (FTP, "220-..." continuation then "220 " with the product) is identified from its LATER line --\n'
# =============================================================================

FIX_MULTILINE=$W/root-multiline
_fixture_root "$FIX_MULTILINE"
cat >"$FIX_MULTILINE/config/scope.conf" <<'EOF'
id: net-multiline
base-url: https://banner.fixture.invalid/
extra-host: banner.fixture.invalid:2121
allow-subdomains: false
EOF

rm -f "$W/net-probe.log" "$W/net-banner.log"
t_case 'a two-line FTP-shaped greeting still identifies the product on its second line'
_net_scan "$W/run-multiline" "$FIX_MULTILINE" --target net-multiline
assert_eq 0 "$_RC" 'exits 0'
ML_JSONL=$(_slurp "$W/run-multiline/findings.jsonl")
assert_contains "$ML_JSONL" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'the check fires - FAILS if identification only ever looked at the first line of a multi-line banner'
assert_contains "$ML_JSONL" 'proftpd' \
  'proftpd (normalised) is the identified product, taken from the SECOND line of the greeting'
assert_contains "$ML_JSONL" '1.3.5e' 'the version 1.3.5e is named in the evidence too'

# =============================================================================
printf '\n-- report.md §5.2 rule 2: no_declared_listeners is a named, counted skip, not a silent clean run --\n'
# =============================================================================

FIX_SOLO=$W/root-solo
_fixture_root "$FIX_SOLO"
cat >"$FIX_SOLO/config/scope.conf" <<'EOF'
id: net-solo
base-url: https://solo.fixture.invalid/
allow-subdomains: false
EOF

t_case 'a base-url-only target (no listeners.json at all, NET-05 rule 3) records no_declared_listeners and exits 0'
_net_scan "$W/run-solo" "$FIX_SOLO" --target net-solo
assert_eq 0 "$_RC" 'exits 0'
SOLO_JSON=$(_slurp "$W/run-solo/run.json")
assert_contains "$SOLO_JSON" 'reason=no_declared_listeners checks=[NET-SVC-BANNER_DISCLOSURE-01]' \
  'the named reason from report.md §5.2 rule 2s own list appears, naming this check specifically'
SOLO_JSONL=$(_slurp "$W/run-solo/findings.jsonl")
assert_not_contains "$SOLO_JSONL" 'NET-SVC-BANNER_DISCLOSURE-01' \
  'no finding was fabricated with nothing to probe'

t_case 'this check is not ALSO flagged by modules/network/run.sh own honesty backstop as a selected-but-unexplained check'
assert_not_contains "$SOLO_JSON" 'reason=check_not_executed_no_reason_recorded' \
  'no check_not_executed_no_reason_recorded reduction names this run - FAILS if the reduction above were spelled check=ID (singular, reachability.sh'"'"'s own convention) rather than checks=[ID] (plural, bracketed): modules/network/run.sh'"'"'s _net_record_unaccounted reads run_facts coverage_reduction for the literal substring "checks=[" and would then see this check as selected (it is passive-tagged, so it IS selected even at this run'"'"'s own default --intensity passive, unlike NET-PORT-*'"'"'s safe-active tag, which is filtered out of selection below --intensity safe and so never reaches this backstop at all) but never accounted for, and would falsely report it as a defect in modules/network/ rather than the declared skip it actually is. Reproduced against the pre-fix spelling before writing this assertion.'

# =============================================================================
printf '\n-- report.md §5.2 rule 2: net_probe_cmd_absent is a named, counted, CHECK-LEVEL skip - nothing is probed at all --\n'
# =============================================================================

t_case 'with SCOURSH_NET_TCP_CAPABLE=0, the check is recorded as uncovered by name, and neither the classify nor the banner-read primitive is ever invoked'
rm -f "$W/net-probe.log" "$W/net-banner.log"
_CAP_RC=0
_CAP_LOG=$W/run-nocap.log
NET_PROBE_LOG=$W/net-probe.log NET_BANNER_LOG=$W/net-banner.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_BANNER_PROBE=$NET_BANNER_STUB \
  SCOURSH_NET_TCP_CAPABLE=0 \
  bash "$ROOT/scan.sh" network --out "$W/run-nocap" \
  --target net-banner \
  >"$_CAP_LOG" 2>&1 || _CAP_RC=$?
assert_eq 0 "$_CAP_RC" 'exits 0 - a bash without --enable-net-redirections is a coverage fact, never an error'
NOCAP_JSON=$(_slurp "$W/run-nocap/run.json")
assert_contains "$NOCAP_JSON" 'reason=net_probe_cmd_absent' \
  'the named reason from report.md §5.2 rule 2s own list appears'
assert_contains "$NOCAP_JSON" 'checks=[NET-SVC-BANNER_DISCLOSURE-01]' \
  'the reduction names this check id specifically, not only a generic module note'
assert_file_absent "$W/net-probe.log" \
  'net_connect_probe (SCOURSH_NET_PROBE) was NEVER invoked - FAILS if the capability check ran per-listener rather than once up front (AGENTS.md'"'"'s "checks_run must count what SUCCEEDED" lesson)'
assert_file_absent "$W/net-banner.log" \
  'net_read_banner (SCOURSH_NET_BANNER_PROBE) was NEVER invoked either'
NOCAP_JSONL=$(_slurp "$W/run-nocap/findings.jsonl")
assert_not_contains "$NOCAP_JSONL" 'NET-SVC-BANNER_DISCLOSURE-01' 'no finding was fabricated with no real signal'

# =============================================================================
printf '\n-- a finding carries the net fingerprint profile fields and round-trips through every format --\n'
# =============================================================================

t_case 'the finding round-trips into findings.json (--format json), report.md and report.html'
rm -f "$W/net-probe.log" "$W/net-banner.log"
_FMT_RC=0
NET_PROBE_LOG=$W/net-probe.log NET_BANNER_LOG=$W/net-banner.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_BANNER_PROBE=$NET_BANNER_STUB \
  bash "$ROOT/scan.sh" network --out "$W/run-fmt" \
  --target net-banner --format json,md,html,agent \
  >"$W/run-fmt.log" 2>&1 || _FMT_RC=$?
assert_eq 0 "$_FMT_RC" 'a run requesting every format still exits 0'
FMT_JSON=$(_slurp "$W/run-fmt/findings.json")
assert_contains "$FMT_JSON" '"check_id":"NET-SVC-BANNER_DISCLOSURE-01"' \
  'findings.json (the --format json emitter) carries the same finding'
FMT_MD=$(_slurp "$W/run-fmt/report.md")
assert_contains "$FMT_MD" 'NET-SVC-BANNER_DISCLOSURE-01' 'report.md names the check id'
FMT_HTML=$(_slurp "$W/run-fmt/report.html")
assert_contains "$FMT_HTML" 'NET-SVC-BANNER_DISCLOSURE-01' \
  'report.html names the check id too - FAILS if the network category were missing from _RPT_MODULES or the NET- prefix grep (lib/report.sh _rptc_prefix_grep)'
AGENT_JSON=$(_slurp "$W/run-fmt/agent-fix.json")
assert_contains "$AGENT_JSON" '"scoursh_agent":1' 'agent-fix.json was written'
assert_contains "$AGENT_JSON" 'NET-SVC-BANNER_DISCLOSURE-01' \
  'the finding round-trips into the agent format too'

# =============================================================================
printf '\n-- no transport tool outside lib/nettransport.sh/lib/http.sh is ever reached --\n'
# =============================================================================

t_case 'even with real, classified, disclosing listeners, banner.sh itself never invokes curl/wget/nc'
STUB=$W/stub-bin
mkdir -p "$STUB"
# `openssl` is stubbed here too (so a real handshake attempt from a SIBLING
# phase can never reach the network from inside this suite - see below),
# but it is deliberately not asserted against by name: modules/network/
# engine.sh's own phase table now runs tlsport.sh (NET-08) at this SAME
# passive tier alongside banner.sh, and tlsport.sh's own, entirely
# legitimate contract is to call openssl s_client for ITS check family
# (modules/network/tlsport.sh, exempted by path in tests/lint-shell.sh
# exactly for that). Asserting "openssl was never reached" here would be
# asserting a fact about a sibling phase this ticket does not own, and
# would break again the moment any further tool-using passive-tier phase
# lands - the identical reason the classify-count assertion above no
# longer counts a total. banner.sh'"'"'s OWN contract - no curl, no wget, no
# nc/ncat/netcat, ever - is what this case still proves.
for c in curl wget nc ncat netcat openssl; do
  cat >"$STUB/$c" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "$c" "\$*" >>"$W/network-attempts"
exit 1
EOF
  chmod 0755 "$STUB/$c"
done
rm -f "$W/network-attempts"
_NT_RC=0
NET_PROBE_LOG=$W/net-probe.log NET_BANNER_LOG=$W/net-banner.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_BANNER_PROBE=$NET_BANNER_STUB \
  PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" network --target net-banner \
  --out "$W/run-notraffic" \
  >"$W/run-notraffic.log" 2>&1 || _NT_RC=$?
assert_eq 0 "$_NT_RC" 'the run still exits 0 with a poisoned PATH'
NETWORK_ATTEMPTS=$(_slurp "$W/network-attempts")
assert_not_contains "$NETWORK_ATTEMPTS" 'curl ' 'no curl invocation was logged'
assert_not_contains "$NETWORK_ATTEMPTS" 'wget ' 'no wget invocation was logged'
assert_not_contains "$NETWORK_ATTEMPTS" 'nc ' 'no bare nc invocation was logged'
assert_not_contains "$NETWORK_ATTEMPTS" 'ncat ' 'no ncat invocation was logged'
assert_not_contains "$NETWORK_ATTEMPTS" 'netcat ' \
  'no netcat invocation was logged - banner.sh reaches the network exclusively through lib/nettransport.sh'"'"'s net_connect_probe and net_read_banner (which this suite'"'"'s hooks already replace) and lib/http.sh'"'"'s http_authorize_raw_connection (whose own resolution this suite'"'"'s SCOURSH_HTTP_RESOLVE hook already replaces) - FAILS if banner.sh (or a future edit to it) ever shelled out to one of these directly instead'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-banner'
