#!/usr/bin/env bash
# tests/suites/network-transport.sh - modules/network/transport.sh:
# transport POSTURE on non-HTTP listeners and the `NET-TRANSPORT-*` checks
# (NET-10).  NET-06's open/not-open/filtered
# classification, NET-07's zero-byte banner read and
# modules/dast/passive/tls_engine.sh's tls_probe/tls_parse_session are all
# reused rather than re-implemented (their own low-level parsing decisions
# are already pinned by tests/suites/network-reachability.sh, network-
# banner.sh and dast-tls.sh respectively, and are NOT re-pinned here); this
# suite focuses on what NET-10 itself adds. Modelled directly on
# tests/suites/network-tlsport.sh's own direct-source harness (phase env +
# a hand-written listeners.json), which this file reuses rather than the
# heavier real-`scan.sh`-subprocess shape tests/suites/network-banner.sh
# uses, for the identical reason that suite's own header gives: most cases
# here are proving what transport.sh does with an already-produced
# artifact, and only the very end of this file needs a real dispatch-chain
# proof.
#
# Nine things this suite exists to pin, each with a plausible wrong reading
# that would ship silently:
#
#   1. Only non-base-url (extra-host) listeners are probed - base-url is
#      DAST-TRANSPORT-*'s own subject.
#   2. NET-TRANSPORT-PLAINTEXT_SERVICE-01 fires only for a port in the
#      static plaintext-protocol table whose native TLS handshake produced
#      no completed session.
#   3. A port whose native TLS handshake DOES complete is NOT reported as
#      plaintext (the implicit-TLS deployment working as intended), and the
#      STARTTLS check does not apply to it either - there is no plaintext
#      exchange left to have exposed.
#   4. NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01 fires only when the
#      plaintext-confirmed listener's protocol is STARTTLS-readable (smtp,
#      imap, pop3 - never ldap or ftp, for two different stated reasons) AND
#      its zero-byte-read banner literally advertises STARTTLS/STLS.
#   5. A STARTTLS-capable, plaintext-confirmed listener whose banner does
#      NOT advertise it is a real, honest "checked, nothing to flag" - not
#      a finding, not a reduction, and its check id still ends up in
#      checks_run.
#   6. A port outside the static table at all is a counted
#      `proto_not_recognised`/`proto_not_starttls_capable` reduction for
#      each check respectively, never a silent clean or a finding.
#   7. not-open/filtered listeners are ONE combined, counted
#      `net_check_not_applicable` reduction naming both check ids, with the
#      not-open/filtered breakdown kept visible rather than actually
#      collapsed into each other.
#   8. openssl absence and no-TCP-capability are each a declared skip
#      naming both NET-TRANSPORT-* ids, never an error and never silent.
#   9. A finding this phase emits carries the `net` fingerprint profile's
#      own location fields and round-trips through every output format.
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
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=modules/network/engine.sh
source "$ROOT/modules/network/engine.sh"
# shellcheck source=modules/network/reachability_engine.sh
source "$ROOT/modules/network/reachability_engine.sh"
# shellcheck source=lib/nettransport.sh
source "$ROOT/lib/nettransport.sh"
# shellcheck source=modules/dast/passive/tls_engine.sh
source "$ROOT/modules/dast/passive/tls_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$ROOT/tests/fixtures/dast/tls
W=$SCOURSH_SCRATCH/network-transport
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): tests/suites/network-tlsport.sh's own
# comment on this same line documents why.
W=$(cd -- "$W" && pwd -P)

HAVE_OPENSSL=0
if command -v openssl >/dev/null 2>&1; then HAVE_OPENSSL=1; fi

# ---------------------------------------------------------------------------
# Direct-source harness - tests/suites/network-tlsport.sh's own shape.
# ---------------------------------------------------------------------------

SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOS'
id: net-transport
base-url: https://transport.fixture.invalid/
extra-host: transport.fixture.invalid:21
extra-host: transport.fixture.invalid:25
extra-host: transport.fixture.invalid:143
extra-host: transport.fixture.invalid:389
extra-host: transport.fixture.invalid:2121
extra-host: transport.fixture.invalid:5432
extra-host: transport.fixture.invalid:9999
notes: One target, seven extra-host listeners - plaintext FTP (21, no
  STARTTLS-capable protocol), plaintext SMTP with no STARTTLS advertised
  (25), plaintext IMAP WITH STARTTLS advertised (143), LDAP that in fact
  speaks TLS directly on this port (389), a port outside the static table
  entirely (2121), a not-open port (5432) and a filtered one (9999).

id: net-transport-solo
base-url: https://transport-solo.fixture.invalid/
notes: A target with no extra-host listener at all - NET-05's own rule 3,
  so this target's listeners.json is never written.
EOS

_transport_resolve() {
  case $1 in
    transport.fixture.invalid | transport-solo.fixture.invalid) printf '%s' '203.0.113.70' ;;
    *) return 1 ;;
  esac
}
export SCOURSH_HTTP_RESOLVE=_transport_resolve
export SCOURSH_INSTALL_ROOT=$ROOT

# `SCOURSH_NET_PROBE` (lib/nettransport.sh) replaces the TCP-only classify
# call this phase makes BEFORE ever attempting a handshake or a banner
# read - the mechanism this ticket's own header says is reused from NET-06.
NET_PROBE_LOG=$W/net-probe.log
_net_probe_stub() {
  printf '%s\n' "$*" >>"$NET_PROBE_LOG"
  case $2 in
    21 | 25 | 143 | 389 | 2121) printf 'open\n' ;;
    5432) printf 'not-open\n' ;;
    9999) printf 'filtered\n' ;;
    *) printf 'not-open\n' ;;
  esac
}
export SCOURSH_NET_PROBE=_net_probe_stub

# `SCOURSH_TLS_PROBE` (tls_engine.sh) replaces the ONE openssl s_client
# invocation this check reuses from modules/network/tlsport.sh's own
# dependency, keyed on port. 21/25/143/2121 never complete a session (no
# transcript at all, mirroring modules/network/tlsport.sh's own "open but
# not TLS" stub shape); 389 DOES complete one, reusing the identical
# already-committed clean transcript tests/suites/network-tlsport.sh reuses
# for its own "clean session" case.
TLS_PROBE_LOG=$W/tls-probe.log
_tls_stub_probe() {
  printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >>"$TLS_PROBE_LOG"
  case $2 in
    389) cat "$FIX/openssl3-tls13-host-specific.transcript" >"$5"; return 0 ;;
    *) return 1 ;;  # 21/25/143/2121: "open" at TCP but no completed TLS session
  esac
}
export SCOURSH_TLS_PROBE=_tls_stub_probe

# `SCOURSH_NET_BANNER_PROBE` (lib/nettransport.sh) replaces the whole
# real-socket read step for the STARTTLS-advertisement signal. Only ever
# invoked for a plaintext-confirmed, STARTTLS-capable listener (25, 143) -
# 21 (ftp, excluded) and 389 (tls-direct) must never reach it.
NET_BANNER_LOG=$W/net-banner.log
_net_banner_stub() {
  printf 'host=%s port=%s max_bytes=%s\n' "$1" "$2" "$3" >>"$NET_BANNER_LOG"
  : >"$4"
  case $2 in
    25) printf '220 mail.fixture.invalid ESMTP Postfix\r\n' >"$4" ;;
    143) printf '* OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot ready.\r\n' >"$4" ;;
  esac
}
export SCOURSH_NET_BANNER_PROBE=_net_banner_stub

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  : >"$NET_PROBE_LOG"
  : >"$TLS_PROBE_LOG"
  : >"$NET_BANNER_LOG"
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_meta_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/meta/*; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f")
    out+=$'\n'
  done
  printf '%s' "$out"
}

_checks_run_text() {
  cat -- "$SCOURSH_RUN_DIR/meta/checks_run" 2>/dev/null || printf ''
}

_phase_env() {
  SCOURSH_NET_TARGET=$1
  SCOURSH_NET_CELL=$1
  export SCOURSH_NET_TARGET SCOURSH_NET_CELL
  config_scope_load "$SCOPE"
  http_scope_load "$SCOPE"
}

# `_write_listeners TARGET ROLE:SCHEME:HOST:PORT...` - NET-05's own
# listeners.json shape, written directly - tests/suites/network-tlsport.sh's
# own helper, reproduced verbatim.
_write_listeners() {
  local target=$1
  shift
  mkdir -p "$SCOURSH_RUN_DIR/inventory"
  {
    printf '{\n  "schema": "scoursh.inventory.listeners/1",\n'
    printf '  "run_id": "%s",\n' "$SCOURSH_RUN_ID"
    printf '  "generated_by": "test-fixture",\n'
    printf '  "target": "%s",\n' "$target"
    printf '  "listeners": [\n'
    local first=1 rec role scheme host port
    for rec in "$@"; do
      IFS=: read -r role scheme host port <<<"$rec"
      (( first )) || printf ',\n'
      first=0
      printf '    {"target": "%s", "role": "%s", "scheme": "%s", "host": "%s", "port": %s}' \
        "$target" "$role" "$scheme" "$host" "$port"
    done
    printf '\n  ]\n}\n'
  } >"$SCOURSH_RUN_DIR/inventory/listeners.json"
}

if (( ! HAVE_OPENSSL )); then
  printf '  NOTICE openssl is not on PATH: this suite did NOT run. This is a SKIP, not a pass.\n'
else

# =============================================================================
printf '\n-- only non-base-url listeners are probed; base-url is skipped --\n'
# =============================================================================

_fresh_run
_phase_env net-transport
_write_listeners net-transport \
  'base-url:https:transport.fixture.invalid:443' \
  'extra-host:https:transport.fixture.invalid:21' \
  'extra-host:https:transport.fixture.invalid:25' \
  'extra-host:https:transport.fixture.invalid:143' \
  'extra-host:https:transport.fixture.invalid:389' \
  'extra-host:https:transport.fixture.invalid:2121' \
  'extra-host:https:transport.fixture.invalid:5432' \
  'extra-host:https:transport.fixture.invalid:9999'
t_case 'the phase runs cleanly over seven declared non-base-url listeners plus one base-url row'
RC=0
source "$ROOT/modules/network/transport.sh" || RC=$?
assert_eq '0' "$RC" 'transport.sh returns 0'

t_case 'the base-url listener (port 443) is never classified, handshaked or read for a banner'
assert_not_contains "$(cat "$NET_PROBE_LOG")" ' 443 ' 'net_connect_probe was never asked about port 443 - FAILS if the base-url row were treated as just another declared listener'
assert_not_contains "$(cat "$TLS_PROBE_LOG")" ' 443 ' 'no handshake was attempted against port 443 either'
assert_not_contains "$(cat "$NET_BANNER_LOG")" 'port=443' 'nor was a banner ever read from it'

t_case 'not-open (5432) and filtered (9999) never reach a TLS handshake or a banner read at all'
TLS_LOG=$(cat "$TLS_PROBE_LOG")
assert_not_contains "$TLS_LOG" ' 5432 ' 'port 5432 (not-open) never reached tls_probe - FAILS if open-state classification were skipped'
assert_not_contains "$TLS_LOG" ' 9999 ' 'port 9999 (filtered) never reached tls_probe either'
BANNER_LOG=$(cat "$NET_BANNER_LOG")
assert_not_contains "$BANNER_LOG" 'port=5432' 'nor a banner read'
assert_not_contains "$BANNER_LOG" 'port=9999' 'nor a banner read'

t_case 'a port outside the static plaintext-protocol table (2121) is classified at TCP but never handshaked or read'
PROBE_LOG=$(cat "$NET_PROBE_LOG")
assert_contains "$PROBE_LOG" '203.0.113.70 2121' 'port 2121 was classified - FAILS if unmapped ports were skipped before even the TCP probe'
assert_not_contains "$TLS_LOG" ' 2121 ' 'port 2121 never reached tls_probe - identification is by port number, and 2121 matches no table entry'
assert_not_contains "$BANNER_LOG" 'port=2121' 'nor was it ever read for a banner'

FIND=$(_shard_text); META=$(_meta_text)

t_case 'FTP (21) fires the plaintext-service check, and is NOT eligible for the STARTTLS check at all'
FTP_LINE=$(grep 'loc_port=21' <<<"$FIND" || true)
assert_contains "$FTP_LINE" 'check_id=NET-TRANSPORT-PLAINTEXT_SERVICE-01' 'the plaintext finding fires on port 21 - FAILS if the native-TLS-absence handshake or the port table were wrong'
assert_not_contains "$FTP_LINE" 'NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01' 'no STARTTLS finding on the same line'
assert_not_contains "$BANNER_LOG" 'port=21' 'FTP is explicitly excluded from the STARTTLS-capable subset (its AUTH TLS token differs from STARTTLS/STLS) - FAILS if the banner-read primitive were ever invoked for it'

t_case 'SMTP (25) fires the plaintext-service check; its banner advertises no STARTTLS, so the second check stays quiet - correctly, not silently'
SMTP_LINE=$(grep 'loc_port=25' <<<"$FIND" || true)
assert_contains "$SMTP_LINE" 'check_id=NET-TRANSPORT-PLAINTEXT_SERVICE-01' 'the plaintext finding fires on port 25'
assert_not_contains "$SMTP_LINE" 'NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01' 'no STARTTLS finding - the banner never mentions it'
assert_contains "$BANNER_LOG" 'port=25' 'the banner-read primitive WAS invoked for port 25 - FAILS if this check were skipped entirely rather than run and found clean'

t_case 'IMAP (143) fires BOTH checks: plaintext-service, and STARTTLS advertised in its inline capability list'
IMAP_LINES=$(grep 'loc_port=143' <<<"$FIND" || true)
assert_contains "$IMAP_LINES" 'check_id=NET-TRANSPORT-PLAINTEXT_SERVICE-01' 'the plaintext finding fires on port 143'
assert_contains "$IMAP_LINES" 'check_id=NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01' 'the STARTTLS finding fires too - FAILS if the literal STARTTLS token inside a bracketed CAPABILITY list were not matched'

t_case 'the LDAP listener (389) speaks TLS directly - no plaintext finding, and the STARTTLS check never even reads a banner'
assert_not_contains "$FIND" 'loc_port=389' 'no finding of any kind names port 389 - the native handshake completed, so the implicit-TLS deployment is working as intended (modules/network/tlsport.sh judges whether that session is any good)'
assert_contains "$META" 'plaintext_port_speaks_tls=true' 'the fact is still RECORDED as a note, so a reader can see the check ran rather than inferring it from silence'
assert_not_contains "$BANNER_LOG" 'port=389' 'no banner was ever read for port 389 - there is no plaintext exchange left to have exposed'

t_case 'the unmapped port (2121) produces no finding of any kind'
assert_not_contains "$FIND" 'loc_port=2121' 'no finding names port 2121 - it matches no entry in the static plaintext-protocol table'

t_case 'every NET-TRANSPORT-* finding carries the net location profile (target/host/port/transport), never dast''s'
assert_contains "$IMAP_LINES" 'loc_target=net-transport' 'loc_target is set'
assert_contains "$IMAP_LINES" 'loc_host=transport.fixture.invalid' 'loc_host is set'
assert_contains "$IMAP_LINES" 'loc_transport=https' 'loc_transport is set'
assert_not_contains "$IMAP_LINES" 'loc_method=' 'no loc_method field - that is the dast profile, not net''s (lib/findings.sh _fp_components_for net: target host port transport)'
assert_contains "$IMAP_LINES" 'module=net' 'the finding is module=net, never module=dast'
assert_not_contains "$IMAP_LINES" 'module=dast' 'confirmed the other way too'
assert_contains "$IMAP_LINES" 'confidence=medium' 'both checks report medium confidence, never high - port-based protocol identification is a stated limitation'

t_case 'not-open (5432) and filtered (9999) are ONE combined, counted net_check_not_applicable reduction naming both check ids'
assert_not_contains "$FIND" 'loc_port=5432' 'no finding names port 5432'
assert_not_contains "$FIND" 'loc_port=9999' 'no finding names port 9999'
NCA_LINE=$(grep 'reason=net_check_not_applicable' <<<"$META" || true)
assert_contains "$NCA_LINE" 'checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01]' 'the reduction names BOTH ids, since neither check applies to a listener that never even answered a TCP connect'
assert_contains "$NCA_LINE" 'count=2 not_open=1 filtered=1' 'the real breakdown is visible - FAILS if not-open and filtered were actually folded into one indistinguishable count'

t_case 'the unmapped port (2121) is a SEPARATE, per-check reduction from the not-open/filtered one'
assert_contains "$META" 'reason=proto_not_recognised checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01] target=net-transport count=1' 'the plaintext check names its own reduction, count 1 (port 2121 alone)'
assert_contains "$META" 'reason=proto_not_starttls_capable checks=[NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01] target=net-transport count=3' 'the STARTTLS check names a DIFFERENT reduction, count 3 - FTP (21, wrong token), LDAP (389, already TLS-direct) and the unmapped port (2121) all count toward it, but NOT SMTP (25, applicable and clean) or IMAP (143, applicable and fired)'

t_case 'checks_run records both ids exactly once each for this target'
CR=$(_checks_run_text)
assert_eq 1 "$(grep -c '^NET-TRANSPORT-PLAINTEXT_SERVICE-01$' <<<"$CR" || true)" \
  'NET-TRANSPORT-PLAINTEXT_SERVICE-01 appears in checks_run exactly ONCE - FAILS if it were recorded per listener (three listeners fired this run), which would make coverage accounting scale with the listener count rather than with "did this check run for real"'
assert_eq 1 "$(grep -c '^NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01$' <<<"$CR" || true)" \
  'NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01 appears exactly once too, and is recorded even though ONE of its two applicable listeners (SMTP) produced no finding - checks_run counts what was ATTEMPTED for real, not what fired'

t_case 'checks-transport.rules registers both ids under coverage-scope target and tags passive, per rules/RULE-FORMAT.md §9.5.1 NET row'
RULES_FILE=$(cat "$ROOT/modules/network/checks-transport.rules")
for id in NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01; do
  assert_contains "$RULES_FILE" "id: $id" "check id $id is registered"
done
assert_eq 2 "$(grep -c '^coverage-scope: target' <<<"$RULES_FILE")" \
  'both records declare coverage-scope: target - FAILS the linter''s E079 otherwise'
assert_eq 2 "$(grep -c '^tags: passive' <<<"$RULES_FILE")" \
  'both records are tagged passive, matching modules/network/engine.sh''s own transport.sh:passive phase-table floor'
assert_eq 2 "$(grep -c '^requires-cmd: openssl' <<<"$RULES_FILE")" \
  'both records declare requires-cmd: openssl, matching the phase''s own dependency check'

# =============================================================================
printf '\n-- no non-base-url listener is a named, counted, honest skip --\n'
# =============================================================================

t_case 'a base-url-only target (no listeners.json at all, NET-05 rule 3) records no_declared_listeners and exits 0'
_fresh_run
_phase_env net-transport-solo
RC=0
source "$ROOT/modules/network/transport.sh" || RC=$?
assert_eq '0' "$RC" 'exits 0'
META=$(_meta_text); FIND=$(_shard_text)
assert_contains "$META" 'reason=no_declared_listeners' \
  'the named reason report.md''s own vocabulary uses appears'
assert_contains "$META" 'checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01]' \
  'the reduction names BOTH check ids specifically, not only a generic module note'
assert_not_contains "$FIND" 'NET-TRANSPORT' 'no finding was fabricated with nothing to probe'
assert_not_contains "$(_checks_run_text)" 'NET-TRANSPORT' 'and neither id is recorded as having run for real'

t_case 'a listeners.json that names ONLY the base-url row collapses to the same no-listeners outcome'
_fresh_run
_phase_env net-transport
_write_listeners net-transport 'base-url:https:transport.fixture.invalid:443'
RC=0
source "$ROOT/modules/network/transport.sh" || RC=$?
assert_eq '0' "$RC" 'exits 0'
META=$(_meta_text)
assert_contains "$META" 'reason=no_declared_listeners' \
  'the base-url-only artifact is treated exactly like no artifact at all'

# =============================================================================
printf '\n-- requires-cmd: openssl absent is a declared, named skip - never an error, never silent --\n'
# =============================================================================

t_case 'with no openssl, both NET-TRANSPORT-* ids are named as uncovered, and no classify/handshake/banner-read is attempted'
_have_real=$(declare -f _have)
_have() { [[ $1 != openssl ]] && command -v "$1" >/dev/null 2>&1; }
RC=0
_fresh_run
_phase_env net-transport
_write_listeners net-transport \
  'base-url:https:transport.fixture.invalid:443' \
  'extra-host:https:transport.fixture.invalid:25'
source "$ROOT/modules/network/transport.sh" || RC=$?
META=$(_meta_text); FIND=$(_shard_text)
eval "$_have_real"
assert_eq '0' "$RC" 'the phase returns cleanly with no openssl'
assert_contains "$META" 'reason=requires_cmd_absent' 'the declared skip is recorded'
assert_contains "$META" 'cmd=openssl' 'naming the command'
assert_contains "$META" 'checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01]' 'the reduction names both ids by name, not only a generic module note'
assert_eq '0' "$(grep -c . "$NET_PROBE_LOG" || true)" \
  'net_connect_probe was NEVER invoked at all - openssl is checked before any classification is attempted, matching modules/network/tlsport.sh''s own ordering'
assert_not_contains "$FIND" 'NET-TRANSPORT' 'no finding of any kind was fabricated with no real signal'

# =============================================================================
printf '\n-- no TCP capability is a named, counted, CHECK-LEVEL skip - nothing is probed at all --\n'
# =============================================================================

t_case 'with SCOURSH_NET_TCP_CAPABLE=0, both ids are recorded as uncovered, and nothing is probed'
RC=0
_fresh_run
_phase_env net-transport
_write_listeners net-transport \
  'base-url:https:transport.fixture.invalid:443' \
  'extra-host:https:transport.fixture.invalid:25'
_NET_TCP_CAPABLE=''
export SCOURSH_NET_TCP_CAPABLE=0
source "$ROOT/modules/network/transport.sh" || RC=$?
unset SCOURSH_NET_TCP_CAPABLE
_NET_TCP_CAPABLE=''
META=$(_meta_text); FIND=$(_shard_text)
assert_eq '0' "$RC" 'exits 0 - a bash without --enable-net-redirections is a coverage fact, never an error'
assert_contains "$META" 'reason=net_probe_cmd_absent' 'the named reason appears'
assert_contains "$META" 'checks=[NET-TRANSPORT-PLAINTEXT_SERVICE-01 NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01]' 'the reduction names both ids specifically'
assert_eq '0' "$(grep -c . "$NET_PROBE_LOG" || true)" 'net_connect_probe was NEVER invoked'
assert_not_contains "$FIND" 'NET-TRANSPORT' 'no finding was fabricated with no TCP capability'

fi

# =============================================================================
printf '\n-- end to end: a full scan.sh network run wires the phase table row, checks-transport.rules, and every report format --\n'
# =============================================================================

_fixture_root() {
  local dir=$1 e
  mkdir -p "$dir/config"
  for e in lib modules rules data tools VERSION scan.sh; do
    [[ -e $ROOT/$e ]] || continue
    cp -RL "$ROOT/$e" "$dir/$e"
  done
}

FIX_MULTI=$W/root-e2e
_fixture_root "$FIX_MULTI"
cat >"$FIX_MULTI/config/scope.conf" <<'EOF'
id: net-transport-e2e
base-url: https://transport-e2e.fixture.invalid/
extra-host: transport-e2e.fixture.invalid:143
allow-subdomains: false
EOF

E2E_RESOLVE=$W/e2e-resolve
cat >"$E2E_RESOLVE" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  transport-e2e.fixture.invalid) printf '203.0.113.71' ;;
  *) exit 1 ;;
esac
STUBEOF
chmod 0755 "$E2E_RESOLVE"

E2E_NETPROBE=$W/e2e-netprobe
cat >"$E2E_NETPROBE" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'open\n'
STUBEOF
chmod 0755 "$E2E_NETPROBE"

if (( HAVE_OPENSSL )); then
  E2E_TLSPROBE=$W/e2e-tlsprobe
  cat >"$E2E_TLSPROBE" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 1
STUBEOF
  chmod 0755 "$E2E_TLSPROBE"

  E2E_BANNERPROBE=$W/e2e-bannerprobe
  cat >"$E2E_BANNERPROBE" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '* OK [CAPABILITY IMAP4rev1 STARTTLS] fixture ready.\r\n' >"$4"
STUBEOF
  chmod 0755 "$E2E_BANNERPROBE"

  t_case 'a full scan.sh network run at the default intensity dispatches transport.sh through the phase table and emits both findings'
  E2E_RC=0
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$E2E_RESOLVE \
    SCOURSH_NET_PROBE=$E2E_NETPROBE SCOURSH_TLS_PROBE=$E2E_TLSPROBE SCOURSH_NET_BANNER_PROBE=$E2E_BANNERPROBE \
    bash "$ROOT/scan.sh" network --out "$W/run-e2e" \
    --target net-transport-e2e --format json,md,html,agent \
    >"$W/run-e2e.log" 2>&1 || E2E_RC=$?
  assert_eq 0 "$E2E_RC" 'exits 0 at the DEFAULT intensity - transport.sh is passive-tagged, matching every sibling probe'
  E2E_JSONL=$(cat "$W/run-e2e/findings.jsonl" 2>/dev/null || printf '')
  assert_contains "$E2E_JSONL" '"check_id":"NET-TRANSPORT-PLAINTEXT_SERVICE-01"' 'the plaintext finding fires through the real dispatch chain'
  assert_contains "$E2E_JSONL" '"check_id":"NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01"' 'and so does the STARTTLS finding'
  assert_contains "$E2E_JSONL" '"location":{"target":"net-transport-e2e","host":"transport-e2e.fixture.invalid","port":"143","transport":"https"}' \
    'the location is the net fingerprint profile, nested under "location" (lib/findings.sh _finding_json)'

  t_case 'the findings round-trip into findings.json, report.md, report.html and agent-fix.json'
  E2E_JSON=$(cat "$W/run-e2e/findings.json" 2>/dev/null || printf '')
  assert_contains "$E2E_JSON" '"check_id":"NET-TRANSPORT-PLAINTEXT_SERVICE-01"' 'findings.json (--format json) carries the same finding'
  E2E_MD=$(cat "$W/run-e2e/report.md" 2>/dev/null || printf '')
  assert_contains "$E2E_MD" 'NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01' 'report.md names the check id'
  E2E_HTML=$(cat "$W/run-e2e/report.html" 2>/dev/null || printf '')
  assert_contains "$E2E_HTML" 'NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01' 'report.html names the check id too'
  E2E_AGENT=$(cat "$W/run-e2e/agent-fix.json" 2>/dev/null || printf '')
  assert_contains "$E2E_AGENT" 'NET-TRANSPORT-PLAINTEXT_SERVICE-01' 'agent-fix.json (--format agent) carries the finding too'

  t_case 'no curl/wget/nc/ncat/netcat is ever invoked, and the one openssl call site is fully stubbed'
  STUB=$W/stub-bin
  mkdir -p "$STUB"
  stub_tool=''
  for stub_tool in curl wget nc ncat netcat; do
    cat >"$STUB/$stub_tool" <<EOF
#!/usr/bin/env bash
printf '%s %s\n' "$stub_tool" "\$*" >>"$W/network-attempts"
exit 1
EOF
    chmod 0755 "$STUB/$stub_tool"
  done
  rm -f "$W/network-attempts"
  NT_RC=0
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$E2E_RESOLVE \
    SCOURSH_NET_PROBE=$E2E_NETPROBE SCOURSH_TLS_PROBE=$E2E_TLSPROBE SCOURSH_NET_BANNER_PROBE=$E2E_BANNERPROBE \
    PATH="$STUB:$PATH" \
    bash "$ROOT/scan.sh" network --target net-transport-e2e \
    --out "$W/run-notraffic" \
    >"$W/run-notraffic.log" 2>&1 || NT_RC=$?
  assert_eq 0 "$NT_RC" 'the run still exits 0 with a poisoned PATH'
  assert_file_absent "$W/network-attempts" \
    'no curl/wget/nc/ncat/netcat was invoked - transport.sh reaches the network exclusively through lib/nettransport.sh''s net_connect_probe/net_read_banner and tls_engine.sh''s tls_probe, all of which this suite''s stubs already replace'
else
  printf '  NOTICE openssl is not on PATH: the openssl-dependent end-to-end cases did NOT run. This is a SKIP, not a pass.\n'
fi

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-transport'
