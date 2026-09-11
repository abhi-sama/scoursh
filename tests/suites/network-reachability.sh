#!/usr/bin/env bash
# tests/suites/network-reachability.sh - modules/network/reachability.sh: the
# THREE-STATE listener verification and the `NET-PORT-*` checks (NET-06,
# decision D5). NET-05's own inventory.sh artifact (reports/<run>/inventory/
# listeners.json) is this file's one live input; tests/suites/
# network-inventory.sh pins that artifact's own shape and honesty contract
# separately, so this suite treats it as a trusted producer and focuses on
# what THIS ticket adds.
#
# Six things this suite exists to pin, each with a plausible wrong reading
# that would ship silently - "a pack gone inert passes every silence
# assertion", so every positive case below has a matching negative:
#
#   1. open/not-open/filtered are each classified correctly off the SAME
#      declared listener set, purely by what SCOURSH_NET_PROBE returns.
#   2. `filtered` is NEVER a finding and NEVER folded into `not-open` -
#      it is its own counted coverage_reduction.
#   3. NET-PORT-UNEXPECTED_LISTENER-01 FIRES on an `open` listener a
#      config/posture.conf expect-closed expectation names, and stays QUIET
#      on an `open` listener no expectation names - both readings pinned in
#      the SAME run, so neither can be satisfied by breaking the other.
#   4. An ABSENT config/posture.conf makes the expect-closed half of this
#      check a DECLARED SKIP (a counted coverage_reduction), never exit 4 and
#      never silent - decision D5's own resolution.
#   5. Every skip path returns 0 with a recorded reason, drawn from one
#      named list: filtered, net_probe_cmd_absent, port_out_of_scope,
#      no_declared_listeners, net_check_not_applicable.
#   6. A finding this phase emits carries the `net` fingerprint profile's own
#      location fields (target/host/port/transport) and round-trips through
#      findings.jsonl, findings.json (--format json), report.md and
#      report.html unchanged.
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

W=$SCOURSH_SCRATCH/network-reachability
rm -rf "$W"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

# ---------------------------------------------------------------------------
# Fixture install root - tests/suites/network-inventory.sh's own shape.
# ---------------------------------------------------------------------------
_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

# net.fixture.invalid names below are RFC 2606-reserved and resolve to
# TEST-NET-3 (RFC 5737) literals this suite never dials - SCOURSH_NET_PROBE
# (below) replaces the whole real-socket path, so what these actually
# resolve to only matters for lib/http.sh's own scope-gate/pinning logic to
# have something real to authorise.
RESOLVE_STUB=$W/resolve-stub
cat >"$RESOLVE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  reach.fixture.invalid) printf '203.0.113.40' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$RESOLVE_STUB"

# `SCOURSH_NET_PROBE` (lib/nettransport.sh, NET-03) replaces the whole
# real-socket connect. This suite's fixture always uses ONE host at several
# distinct ports, so the stub switches on PORT ($2) alone - no real DNS, no
# real socket, ever.
NET_PROBE_STUB=$W/net-probe-stub
cat >"$NET_PROBE_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${NET_PROBE_LOG:?}"
case $2 in
  443) printf 'open\n' ;;
  8443) printf 'open\n' ;;
  5432) printf 'not-open\n' ;;
  9999) printf 'filtered\n' ;;
  *) printf 'not-open\n' ;;
esac
STUBEOF
chmod 0755 "$NET_PROBE_STUB"

# `_net_scan RUNDIR INSTALL_ROOT [ARGS...]` - one real `scan.sh network`
# subprocess. reachability.sh's own phase tier is `safe`, so every call here
# passes --intensity safe --i-own-target, matching scan.sh's own
# _scan_check_affirmation requirement.
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
  NET_PROBE_LOG=$W/net-probe.log \
    SCOURSH_INSTALL_ROOT=$root SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
    SCOURSH_NET_PROBE=$NET_PROBE_STUB \
    bash "$ROOT/scan.sh" network --out "$rundir" --intensity safe \
    --i-own-target "$target" "${args[@]}" \
    >"$_LOG" 2>&1 || _RC=$?
  return 0
}

_slurp() {
  local f=$1
  [[ -r $f ]] || { printf ''; return 0; }
  cat -- "$f"
}

# =============================================================================
printf '\n-- open/not-open/filtered are classified correctly, and each is reported accordingly --\n'
# =============================================================================

FIX_MULTI=$W/root-multi
_fixture_root "$FIX_MULTI"
cat >"$FIX_MULTI/config/scope.conf" <<'EOF'
id: net-reach
base-url: https://reach.fixture.invalid/
extra-host: reach.fixture.invalid:8443
extra-host: reach.fixture.invalid:5432
extra-host: reach.fixture.invalid:9999
allow-subdomains: false
EOF

rm -f "$W/net-probe.log"
t_case 'a run over four declared listeners (open, open, not-open, filtered) exits 0'
_net_scan "$W/run-multi" "$FIX_MULTI" --target net-reach
assert_eq 0 "$_RC" \
  'scan.sh network --intensity safe --i-own-target net-reach --target net-reach exits 0 - FAILS if any classification path were treated as a scan-ending error rather than a per-listener outcome'

t_case 'net_connect_probe was actually invoked once per declared listener, never more, never with a leftover host'
PROBE_LOG=$(_slurp "$W/net-probe.log")
assert_eq 4 "$(grep -c . <<<"$PROBE_LOG")" \
  'exactly four probe invocations - one per declared listener (base-url plus three extra-host entries) - FAILS if a listener were probed twice or skipped'
assert_contains "$PROBE_LOG" '203.0.113.40 443' 'the base-url listener was probed at its resolved address and port, not the hostname - FAILS if net_connect_probe were called with the raw hostname rather than the pinned _HTTP_RAW_ADDR (the anti-TOCTOU guarantee this pin exists to enforce)'

RUN_MULTI_JSONL=$(_slurp "$W/run-multi/findings.jsonl")
t_case 'the not-open listener produced the DECLARED_NOT_ANSWERING finding'
assert_contains "$RUN_MULTI_JSONL" '"check_id":"NET-PORT-DECLARED_NOT_ANSWERING-01"' \
  'the not-open (port 5432) listener emitted its own info finding - FAILS if not-open produced nothing at all, silently reading as a clean result'
assert_contains "$RUN_MULTI_JSONL" '"location":{"target":"net-reach","host":"reach.fixture.invalid","port":"5432","transport":"https"}' \
  'the finding location names the actual not-open port (lib/findings.sh _finding_json nests the net fingerprint components under "location", never as flat "loc_*" keys)'

t_case 'the filtered listener produced NO finding of either kind, and is never rendered as not-open'
assert_not_contains "$RUN_MULTI_JSONL" '"port":"9999"' \
  'no finding at all names port 9999 (filtered) - FAILS under a reading that collapses filtered into not-open, which would put a DECLARED_NOT_ANSWERING finding at port 9999'
CR_MULTI=$(_slurp "$W/run-multi/run.json")
assert_contains "$CR_MULTI" 'reason=filtered' \
  'run.json instead records the filtered listener as ITS OWN counted coverage_reduction'
assert_contains "$CR_MULTI" 'phase=reachability.sh reason=filtered target=net-reach count=1' \
  'the reduction names the real count (one filtered listener), not a generic note'

t_case 'the two OPEN listeners (443, 8443) produced no DECLARED_NOT_ANSWERING finding'
assert_not_contains "$RUN_MULTI_JSONL" '"port":"443"' \
  'port 443 (open, no posture.conf expectation this run) produced no finding of any kind - FAILS if an open, unremarkable listener were reported as a finding by itself'

t_case 'checks_run records DECLARED_NOT_ANSWERING once the phase actually produced real states'
assert_contains "$CR_MULTI" 'NET-PORT-DECLARED_NOT_ANSWERING-01' 'the check id is in checks_run'

# =============================================================================
printf '\n-- decision D5: an expect-closed posture.conf expectation fires on the SAME open listener, and stays quiet with none --\n'
# =============================================================================

cat >"$FIX_MULTI/config/posture.conf" <<'EOF'
id: reach-should-be-closed
check: NET-PORT-UNEXPECTED_LISTENER-01
scope-key: net-reach:8443
expect: absent
notes: Port 8443 on this target is decommissioned and must never answer.
EOF

rm -f "$W/net-probe.log"
t_case 'with a posture.conf expect-closed record naming port 8443, the SAME open listener now fires NET-PORT-UNEXPECTED_LISTENER-01'
_net_scan "$W/run-posture" "$FIX_MULTI" --target net-reach
assert_eq 0 "$_RC" 'the run still exits 0 - a policy violation is a finding, not a scan-ending error'
POSTURE_JSONL=$(_slurp "$W/run-posture/findings.jsonl")
assert_contains "$POSTURE_JSONL" '"check_id":"NET-PORT-UNEXPECTED_LISTENER-01"' \
  'the finding fires - FAILS if the expect-closed comparison were never wired up, the pack-gone-inert failure mode this whole suite exists to catch'
assert_contains "$POSTURE_JSONL" '"location":{"target":"net-reach","host":"reach.fixture.invalid","port":"8443","transport":"https"}' \
  'the finding names the expected-closed port'
assert_contains "$POSTURE_JSONL" 'reach-should-be-closed' \
  'the evidence names the expectation id that fired it, so an operator can find the exact posture.conf record responsible'

t_case 'the OTHER open listener (443), which no expectation names, still fires NOTHING - the same run, same posture.conf'
UNEXPECTED_443=$(grep '"check_id":"NET-PORT-UNEXPECTED_LISTENER-01"' <<<"$POSTURE_JSONL" | grep -c '"port":"443"' || true)
assert_eq 0 "$UNEXPECTED_443" \
  'no UNEXPECTED_LISTENER finding names port 443 - FAILS if the check fired on every open listener regardless of whether posture.conf named it, which would make --i-own-target the only thing standing between an operator and a false positive on every normal open service'
assert_eq 1 "$(grep -c '"check_id":"NET-PORT-UNEXPECTED_LISTENER-01"' <<<"$POSTURE_JSONL")" \
  'exactly one UNEXPECTED_LISTENER finding this run, not one per open listener'

t_case 'checks_run records UNEXPECTED_LISTENER once posture.conf was actually evaluated'
POSTURE_RUNJSON=$(_slurp "$W/run-posture/run.json")
assert_contains "$POSTURE_RUNJSON" 'NET-PORT-UNEXPECTED_LISTENER-01' 'the check id is in checks_run'
assert_not_contains "$POSTURE_RUNJSON" 'reason=net_check_not_applicable' \
  'no net_check_not_applicable skip is recorded, because config/posture.conf DOES exist and was read this run'

# =============================================================================
printf '\n-- decision D5: an ABSENT config/posture.conf is a declared skip, never exit 4, never silent --\n'
# =============================================================================

FIX_NOPOSTURE=$W/root-noposture
_fixture_root "$FIX_NOPOSTURE"
cat >"$FIX_NOPOSTURE/config/scope.conf" <<'EOF'
id: net-nopost
base-url: https://reach.fixture.invalid/
extra-host: reach.fixture.invalid:8443
allow-subdomains: false
EOF
rm -f "$FIX_NOPOSTURE/config/posture.conf"

t_case 'no config/posture.conf: the run exits 0, not 4, and the expect-closed half is a counted, named skip'
_net_scan "$W/run-nopost" "$FIX_NOPOSTURE" --target net-nopost
assert_eq 0 "$_RC" \
  'exits 0 - FAILS under "an absent operator config the tool looked for is a required-input failure (exit 4)", which decision D5 explicitly refuses for this expectation file'
NOPOST_JSON=$(_slurp "$W/run-nopost/run.json")
assert_contains "$NOPOST_JSON" 'reason=net_check_not_applicable check=NET-PORT-UNEXPECTED_LISTENER-01' \
  'the skip is recorded under the exact declared reason for this case'
assert_not_contains "$NOPOST_JSON" '"check_id":"NET-PORT-UNEXPECTED_LISTENER-01"' \
  'and no UNEXPECTED_LISTENER finding was fabricated in the absence of any baseline to compare against'
NOPOST_JSONL=$(_slurp "$W/run-nopost/findings.jsonl")
assert_not_contains "$NOPOST_JSONL" 'NET-PORT-UNEXPECTED_LISTENER-01' \
  'confirmed again against the finding shard itself, not only run.json prose'

# =============================================================================
printf '\n-- a posture.conf port not in the declared listener set is out_of_scope, never silently dropped --\n'
# =============================================================================

FIX_OOS=$W/root-oos
_fixture_root "$FIX_OOS"
cat >"$FIX_OOS/config/scope.conf" <<'EOF'
id: net-oos
base-url: https://reach.fixture.invalid/
extra-host: reach.fixture.invalid:8443
allow-subdomains: false
EOF
cat >"$FIX_OOS/config/posture.conf" <<'EOF'
id: oos-should-be-closed
check: NET-PORT-UNEXPECTED_LISTENER-01
scope-key: net-oos:6000
expect: absent
notes: Names a port config/scope.conf never declared for this target.
EOF

t_case 'a posture.conf expectation naming an undeclared port records port_out_of_scope and never probes it'
rm -f "$W/net-probe.log"
_net_scan "$W/run-oos" "$FIX_OOS" --target net-oos
assert_eq 0 "$_RC" 'exits 0 - an out-of-scope EXPECTATION is a coverage fact, never a scope-gate refusal (only an OPERATOR-configured scope.conf tuple is fatal)'
OOS_JSON=$(_slurp "$W/run-oos/run.json")
assert_contains "$OOS_JSON" 'reason=port_out_of_scope check=NET-PORT-UNEXPECTED_LISTENER-01 target=net-oos count=1' \
  'the reduction names the check, the target and the real count - FAILS if the expectation were silently ignored with no record at all'
assert_contains "$OOS_JSON" 'ports=[6000]' 'and names the actual out-of-scope port'
OOS_PROBE_LOG=$(_slurp "$W/net-probe.log")
assert_not_contains "$OOS_PROBE_LOG" ' 6000 ' \
  'port 6000 was never probed - FAILS if an expectation alone caused a connection attempt to a port config/scope.conf never authorised'

# =============================================================================
printf '\n-- no_declared_listeners is a named, counted skip, not a silent clean run --\n'
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
assert_contains "$SOLO_JSON" 'reason=no_declared_listeners' \
  'the named, declared reason appears - FAILS if this degraded to a generic or missing reduction'
SOLO_JSONL=$(_slurp "$W/run-solo/findings.jsonl")
assert_not_contains "$SOLO_JSONL" 'NET-PORT' 'no NET-PORT finding of either kind was fabricated with nothing to probe'

# =============================================================================
printf '\n-- net_probe_cmd_absent is a named, counted, CHECK-LEVEL skip --\n'
# =============================================================================

t_case 'with SCOURSH_NET_TCP_CAPABLE=0, both NET-PORT checks are recorded as uncovered by name, and nothing is probed'
rm -f "$W/net-probe.log"
_CAP_RC=0
_CAP_LOG=$W/run-nocap.log
NET_PROBE_LOG=$W/net-probe.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB SCOURSH_NET_TCP_CAPABLE=0 \
  bash "$ROOT/scan.sh" network --out "$W/run-nocap" --intensity safe \
  --i-own-target net-reach --target net-reach \
  >"$_CAP_LOG" 2>&1 || _CAP_RC=$?
assert_eq 0 "$_CAP_RC" 'exits 0 - a bash without --enable-net-redirections is a coverage fact, never an error'
NOCAP_JSON=$(_slurp "$W/run-nocap/run.json")
assert_contains "$NOCAP_JSON" 'reason=net_probe_cmd_absent' \
  'the named, declared reason appears'
assert_contains "$NOCAP_JSON" 'NET-PORT-DECLARED_NOT_ANSWERING-01' \
  'the reduction names the not-answering check id by name, not only a generic module note'
assert_contains "$NOCAP_JSON" 'NET-PORT-UNEXPECTED_LISTENER-01' \
  'and names the unexpected-listener check id too - both are uncovered, not just one'
assert_file_absent "$W/net-probe.log" \
  'net_connect_probe (SCOURSH_NET_PROBE) was NEVER invoked at all - FAILS if the capability check ran only per-listener rather than once up front, which would still record a real (if 100%-filtered) checks_run entry for a check that produced no real signal at all (AGENTS.md'"'"'s own authz.sh "checks_run must count what SUCCEEDED" lesson)'
NOCAP_JSONL=$(_slurp "$W/run-nocap/findings.jsonl")
assert_not_contains "$NOCAP_JSONL" 'NET-PORT' 'no NET-PORT finding of either kind was fabricated with no real signal'

# =============================================================================
printf '\n-- a finding carries the net fingerprint profile fields and round-trips through every format --\n'
# =============================================================================

t_case 'the DECLARED_NOT_ANSWERING finding carries target/host/port/transport (the frozen net fingerprint components, lib/findings.sh _fp_components_for), nested under "location" - never as flat "loc_*" keys, which only the internal _F[] record uses'
assert_contains "$RUN_MULTI_JSONL" '"location":{"target":"net-reach","host":"reach.fixture.invalid","port":"5432","transport":"https"}' \
  'target/host/port/transport are all set, in the exact order _fp_components_for net declares them'
assert_contains "$RUN_MULTI_JSONL" '"cwe":"CWE-16"' 'cwe is authored on the finding, not left to the registry alone'
assert_contains "$RUN_MULTI_JSONL" '"owasp":"A05:2021"' 'owasp is authored on the finding'

t_case 'the finding round-trips into findings.json (--format json), report.md and report.html'
RUN_JSON_FMT=$(_slurp "$W/run-multi/findings.json")
assert_contains "$RUN_JSON_FMT" '"check_id":"NET-PORT-DECLARED_NOT_ANSWERING-01"' \
  'findings.json (the --format json emitter) carries the same finding'
RUN_MD=$(_slurp "$W/run-multi/report.md")
assert_contains "$RUN_MD" 'NET-PORT-DECLARED_NOT_ANSWERING-01' \
  'report.md names the check id'
RUN_HTML=$(_slurp "$W/run-multi/report.html")
assert_contains "$RUN_HTML" 'NET-PORT-DECLARED_NOT_ANSWERING-01' \
  'report.html names the check id too - FAILS if the network category were missing from _RPT_MODULES or the NET- prefix grep (lib/report.sh _rptc_prefix_grep)'

t_case 'the finding round-trips into agent-fix.json (--format agent, docs/AGENT-FORMAT.md) as well'
rm -f "$W/net-probe.log"
_AGT_RC=0
NET_PROBE_LOG=$W/net-probe.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB \
  bash "$ROOT/scan.sh" network --out "$W/run-agent" --intensity safe \
  --i-own-target net-reach --target net-reach --format json,md,html,agent \
  >"$W/run-agent.log" 2>&1 || _AGT_RC=$?
assert_eq 0 "$_AGT_RC" 'a run requesting --format agent alongside the others still exits 0'
AGENT_JSON=$(_slurp "$W/run-agent/agent-fix.json")
assert_contains "$AGENT_JSON" '"scoursh_agent":1' 'agent-fix.json was written'
assert_contains "$AGENT_JSON" 'NET-PORT-DECLARED_NOT_ANSWERING-01' \
  'the finding round-trips into the agent format too - FAILS if _agent_print_findings/_agent_pass1 filtered on module in a way that dropped the net profile'

t_case 'checks-reachability.rules registers both check ids under coverage-scope target, per rules/RULE-FORMAT.md §9.5.1 NET row'
RULES_FILE=$(_slurp "$ROOT/modules/network/checks-reachability.rules")
assert_contains "$RULES_FILE" 'id: NET-PORT-UNEXPECTED_LISTENER-01' 'the finding check id is registered'
assert_contains "$RULES_FILE" 'id: NET-PORT-DECLARED_NOT_ANSWERING-01' 'the info check id is registered'
assert_eq 2 "$(grep -c '^coverage-scope: target' <<<"$RULES_FILE")" \
  'both records declare coverage-scope: target - FAILS the linter'"'"'s E079 otherwise (rules/RULE-FORMAT.md §9.5.1: NET requires target)'

# =============================================================================
printf '\n-- no transport tool outside lib/nettransport.sh/lib/http.sh is ever reached --\n'
# =============================================================================

t_case 'even with real, classified listeners, no curl/wget/nc/openssl is ever invoked'
STUB=$W/stub-bin
mkdir -p "$STUB"
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
NET_PROBE_LOG=$W/net-probe.log \
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$RESOLVE_STUB \
  SCOURSH_NET_PROBE=$NET_PROBE_STUB PATH="$STUB:$PATH" \
  bash "$ROOT/scan.sh" network --target net-reach --intensity safe \
  --i-own-target net-reach --out "$W/run-notraffic" \
  >"$W/run-notraffic.log" 2>&1 || _NT_RC=$?
assert_eq 0 "$_NT_RC" 'the run still exits 0 with a poisoned PATH'
assert_file_absent "$W/network-attempts" \
  'no curl/wget/nc/ncat/netcat/openssl was invoked - reachability.sh reaches the network exclusively through lib/nettransport.sh'"'"'s net_connect_probe (which this suite'"'"'s SCOURSH_NET_PROBE hook already replaces) and lib/http.sh'"'"'s http_authorize_raw_connection (whose own resolution this suite'"'"'s SCOURSH_HTTP_RESOLVE hook already replaces)'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-reachability'
