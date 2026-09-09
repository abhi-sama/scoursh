#!/usr/bin/env bash
# tests/suites/network-tlsport.sh - modules/network/tlsport.sh: TLS
# identification on a non-`base-url` listener, and the `NET-TLS-*` checks
# (NET-08, data/scoursh-network-scan-design/report.md §3.2 item 2, §5.1,
# §5.2, the NET-08 row in its §7 staged plan).
#
# tls_engine.sh (modules/dast/passive/tls_engine.sh) IS REUSED VERBATIM BY
# modules/network/tlsport.sh, so its own low-level parsing decisions (the
# LibreSSL `New,` line trap, DN normalization across both userlands, the
# self-signed verify-code table, the wildcard leading-label rule, expiry
# boundary arithmetic, ...) are ALREADY exhaustively pinned by
# tests/suites/dast-tls.sh and are NOT re-pinned here - re-testing them here
# would be a second, driftable copy of the same eleven decisions that suite
# already names. What THIS suite exists to pin is everything specific to the
# NET-08 phase itself:
#
#   1. ONLY non-base-url (extra-host) listeners are probed - the base-url row
#      NET-05 also writes into listeners.json is skipped outright, because
#      modules/dast/passive/tls.sh (DAST-TLS-*) already assesses it.
#   2. A listener is TLS-identified only after net_connect_probe classifies it
#      `open` - reusing NET-06's own three-state mechanism on the SAME
#      gate-pinned address. `not-open` and `filtered` are each their own
#      counted coverage_reduction and NEVER a finding, NEVER collapsed into
#      each other (report.md §5.2 rule 4, one listener down).
#   3. An `open` listener that is not actually TLS (the handshake produces no
#      transcript, or a transcript with no session) is ALSO a counted
#      coverage_reduction, never a silent clean run.
#   4. Skip categories are AGGREGATED into one reduction per reason per
#      target, never one line per port - reachability.sh's own "do not flood
#      run.json" discipline, reused here across six listeners in one run.
#   5. checks_run is recorded ONCE per check id per target, gated on whether
#      ANY listener produced a completed session (WEAK_PROTOCOL/WEAK_CIPHER)
#      or a recovered certificate (the four cert-dependent checks) - AGENTS.md's
#      "checks_run must count what SUCCEEDED" lesson, applied across a loop.
#   6. A finding fires per LISTENER (host/port both differ), so two listeners
#      on one target with the same defect are two findings, not one collapsed
#      by the fingerprint - and each carries the `net` location profile
#      (target/host/port/transport), never the `dast` one.
#   7. openssl absence and no-TCP-capability are each a declared skip naming
#      all six NET-TLS-* ids, never an error and never silent.
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
W=$SCOURSH_SCRATCH/network-tlsport
rm -rf "$W"
mkdir -p "$W"
# Canonicalise (`cd && pwd -P`): lib/records.sh resolves every loaded file's
# path via realpath and strips $SCOURSH_INSTALL_ROOT as a literal prefix, so a
# fixture root reached through macOS's /var -> /private/var $TMPDIR symlink
# would make the strip fail - tests/suites/network.sh's own comment on this
# same line documents the same fact.
W=$(cd -- "$W" && pwd -P)

HAVE_OPENSSL=0
if command -v openssl >/dev/null 2>&1; then HAVE_OPENSSL=1; fi

# ---------------------------------------------------------------------------
# Direct-source harness - modelled on tests/suites/dast-tls.sh's own
# `_run_phase`, generalised to write a listeners.json (NET-05's own artifact
# shape) with several non-base-url listeners rather than one base-url.
# ---------------------------------------------------------------------------

SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOS'
id: net-tls
base-url: https://net-tls.fixture.invalid/
extra-host: net-tls.fixture.invalid:8443
extra-host: net-tls.fixture.invalid:8444
extra-host: net-tls.fixture.invalid:8445
extra-host: net-tls.fixture.invalid:5432
extra-host: net-tls.fixture.invalid:9999
extra-host: net-tls.fixture.invalid:2222
notes: One target, six extra-host listeners - one clean TLS session (8443),
  one weak-protocol/weak-cipher session (8444), one self-signed session
  (8445), one not-open (5432), one filtered (9999) and one open-but-not-TLS
  (2222, the handshake never produces a transcript).

id: net-tls-wildcard-ok
base-url: https://net-tls-wc.fixture.invalid/
extra-host: net-tls-wc.fixture.invalid:8443
tls-expect-wildcard: true
notes: A second target, one extra-host listener, WITH the wildcard
  expectation declared - so the wildcard finding must not fire on it.

id: net-tls-solo
base-url: https://net-tls-solo.fixture.invalid/
notes: A target with no extra-host listener at all - NET-05's own rule 3, so
  this target's listeners.json is never written.
EOS

SCANNERCONF=$W/scanner.conf
printf 'id: scanner\ntls-expiry-warn-days: 30\n' >"$SCANNERCONF"

_tls_resolve() {
  case $1 in
    net-tls.fixture.invalid | net-tls-wc.fixture.invalid | net-tls-solo.fixture.invalid)
      printf '%s' '203.0.113.50' ;;
    *) return 1 ;;
  esac
}
export SCOURSH_HTTP_RESOLVE=_tls_resolve
export SCOURSH_INSTALL_ROOT=$ROOT

# `SCOURSH_NET_PROBE` (lib/nettransport.sh) replaces the TCP-only classify
# call this phase makes BEFORE ever attempting a handshake - the mechanism
# report.md's own header for this ticket says is reused from NET-06.
TCP_PROBE_LOG=$W/tcp-probe.log
_net_probe_stub() {
  printf '%s\n' "$*" >>"$TCP_PROBE_LOG"
  case $2 in
    8443 | 8444 | 8445 | 2222) printf 'open\n' ;;
    5432) printf 'not-open\n' ;;
    9999) printf 'filtered\n' ;;
    *) printf 'not-open\n' ;;
  esac
}
export SCOURSH_NET_PROBE=_net_probe_stub

# `SCOURSH_TLS_PROBE` (tls_engine.sh) replaces the ONE openssl s_client
# invocation, keyed on port so one run can serve several distinct transcripts
# to several distinct listeners.
TLS_PROBE_LOG=$W/tls-probe.log
_tls_stub_probe() {
  printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >>"$TLS_PROBE_LOG"
  case $2 in
    8443) cat "$FIX/openssl3-tls13-host-specific.transcript" >"$5"; return 0 ;;
    8444) cat "$FIX/openssl3-tls10-3des.transcript" >"$5"; return 0 ;;
    8445) cat "$FIX/libressl-tls12-self-signed.transcript" >"$5"; return 0 ;;
    *) return 1 ;;  # 2222: "open" at TCP but no TLS transcript at all
  esac
}
export SCOURSH_TLS_PROBE=_tls_stub_probe

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  : >"$TCP_PROBE_LOG"
  : >"$TLS_PROBE_LOG"
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

# The `checks_run` fact ALONE (never the concatenated meta text, which also
# carries this ticket's own `coverage_reduction ... checks=[...]` lines
# naming the same six ids for a DIFFERENT reason) - the one file that answers
# "did this check run for real", precisely.
_checks_run_text() {
  cat -- "$SCOURSH_RUN_DIR/meta/checks_run" 2>/dev/null || printf ''
}

_phase_env() {
  SCOURSH_NET_TARGET=$1
  SCOURSH_NET_CELL=$1
  export SCOURSH_NET_TARGET SCOURSH_NET_CELL
  config_scope_load "$SCOPE"
  config_scanner_load "$SCANNERCONF" 2>/dev/null || true
  http_scope_load "$SCOPE"
}

# `_write_listeners TARGET ROLE:SCHEME:HOST:PORT...` - NET-05's own
# listeners.json shape (modules/network/inventory.sh's own header), written
# directly rather than run through inventory.sh itself: this suite is
# proving what tlsport.sh does with an already-produced artifact, the
# identical boundary tests/suites/network-reachability.sh draws for itself.
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
  printf '  NOTICE openssl is not on PATH: this suite did NOT run any case. This is a SKIP, not a pass.\n'
else

# =============================================================================
printf '\n-- only non-base-url listeners are probed; base-url is skipped --\n'
# =============================================================================

_fresh_run
_phase_env net-tls
_write_listeners net-tls \
  'base-url:https:net-tls.fixture.invalid:443' \
  'extra-host:https:net-tls.fixture.invalid:8443' \
  'extra-host:https:net-tls.fixture.invalid:8444' \
  'extra-host:https:net-tls.fixture.invalid:8445' \
  'extra-host:https:net-tls.fixture.invalid:5432' \
  'extra-host:https:net-tls.fixture.invalid:9999' \
  'extra-host:https:net-tls.fixture.invalid:2222'
t_case 'the phase runs cleanly over six declared non-base-url listeners plus one base-url row'
RC=0
source "$ROOT/modules/network/tlsport.sh" || RC=$?
assert_eq '0' "$RC" 'tlsport.sh returns 0'

t_case 'the base-url listener (port 443) is never classified or handshaked - it is dast-tls.sh''s job, not this one'
assert_not_contains "$(cat "$TCP_PROBE_LOG")" ' 443 ' 'net_connect_probe was never asked about port 443 - FAILS if the base-url row were treated as just another declared listener'
assert_not_contains "$(cat "$TLS_PROBE_LOG")" ' 443 ' 'no handshake was attempted against port 443 either'

t_case 'not-open (5432) and filtered (9999) never reach a TLS handshake at all'
TLS_LOG=$(cat "$TLS_PROBE_LOG")
assert_not_contains "$TLS_LOG" ' 5432 ' 'port 5432 (not-open) never reached tls_probe - FAILS if TLS identification were attempted before open-state classification'
assert_not_contains "$TLS_LOG" ' 9999 ' 'port 9999 (filtered) never reached tls_probe either'

FIND=$(_shard_text); META=$(_meta_text)

t_case 'the clean TLS 1.3 session (8443) produces no finding, and still reports what it negotiated'
assert_not_contains "$FIND" 'loc_port=8443' 'a modern, CA-issued, host-specific, long-lived certificate on 8443 is clean'
assert_contains "$META" 'endpoint=net-tls.fixture.invalid:8443 protocol=TLSv1.3' \
  'the negotiated protocol is RECORDED for this listener even with no finding'
assert_contains "$META" 'cipher=TLS_AES_256_GCM_SHA384' 'and so is the negotiated cipher'

t_case 'the weak-protocol/weak-cipher session (8444) fires both, located at THAT listener'
WP_LINE=$(grep 'check_id=NET-TLS-WEAK_PROTOCOL-01' <<<"$FIND" || true)
assert_contains "$WP_LINE" 'check_id=NET-TLS-WEAK_PROTOCOL-01' 'TLSv1 fires the weak-protocol check - FAILS under the LibreSSL "New," trap this file inherits from tls_engine.sh if it were reintroduced'
assert_contains "$WP_LINE" 'loc_port=8444' 'the weak-protocol finding names port 8444, not some other listener'
WC_LINE=$(grep 'check_id=NET-TLS-WEAK_CIPHER-01' <<<"$FIND" || true)
assert_contains "$WC_LINE" 'loc_port=8444' 'and so does the weak-cipher finding on the same listener'

t_case 'the self-signed session (8445) fires, located at THAT listener'
SS_LINE=$(grep 'check_id=NET-TLS-SELF_SIGNED-01' <<<"$FIND" || true)
assert_contains "$SS_LINE" 'check_id=NET-TLS-SELF_SIGNED-01' 'self-signed fires'
assert_contains "$SS_LINE" 'loc_port=8445' 'located at port 8445'
assert_not_contains "$SS_LINE" 'NET-TLS-WEAK_PROTOCOL' 'and does not also carry the weak-protocol check id on the same finding line'

t_case 'every NET-TLS-* finding carries the net location profile (target/host/port/transport), never dast''s'
assert_contains "$WP_LINE" 'loc_target=net-tls' 'loc_target is set'
assert_contains "$WP_LINE" 'loc_host=net-tls.fixture.invalid' 'loc_host is set'
assert_contains "$WP_LINE" 'loc_transport=https' 'loc_transport is set'
assert_not_contains "$WP_LINE" 'loc_method=' 'no loc_method field - that is the dast profile, not net''s (lib/findings.sh _fp_components_for net: target host port transport)'
assert_contains "$WP_LINE" 'module=net' 'the finding is module=net, never module=dast'
assert_not_contains "$WP_LINE" 'module=dast' 'confirmed the other way too'

t_case 'not-open (5432) and filtered (9999) are aggregated, counted reductions - never a finding, never collapsed into each other'
assert_not_contains "$FIND" 'loc_port=5432' 'no finding at all names port 5432'
assert_not_contains "$FIND" 'loc_port=9999' 'no finding at all names port 9999'
assert_contains "$META" 'reason=net_check_not_applicable' 'the not-open listener is recorded under this exact reason, per report.md''s own wording for this ticket'
assert_contains "$META" 'target=net-tls count=1' 'naming the real count for the not-open reduction'
assert_contains "$META" 'reason=filtered' 'the filtered listener is a SEPARATE, distinct reduction'
NCA_LINE=$(grep 'reason=net_check_not_applicable' <<<"$META" || true)
assert_not_contains "$NCA_LINE" 'reason=filtered' \
  'the two reasons never appear on the SAME line - FAILS if filtered were folded into not-open, report.md §5.2 rule 4 one module down'

t_case 'the open-but-not-TLS listener (2222) is ALSO a counted reduction, never a silent clean result'
assert_not_contains "$FIND" 'loc_port=2222' 'no finding names port 2222'
assert_contains "$META" 'reason=tls_probe_failed' 'the open-but-non-TLS listener is recorded, distinctly from not-open/filtered'
TPF_LINE=$(grep 'reason=tls_probe_failed' <<<"$META" || true)
assert_contains "$TPF_LINE" 'target=net-tls count=1' 'naming the real count'

t_case 'checks_run records all six ids exactly once each, gated on at least one real session/certificate this target'
CR=$(_checks_run_text)
CR_COUNT_PROTO=$(grep -c '^NET-TLS-WEAK_PROTOCOL-01$' <<<"$CR" || true)
assert_eq '1' "$CR_COUNT_PROTO" \
  'NET-TLS-WEAK_PROTOCOL-01 appears in checks_run exactly ONCE - FAILS if it were recorded per listener (three sessions completed this run), which would make coverage accounting scale with the listener count rather than with "did this check run for real"'
assert_contains "$CR" 'NET-TLS-WEAK_CIPHER-01' 'weak-cipher is recorded too'
assert_contains "$CR" 'NET-TLS-CERT_EXPIRED-01' 'the cert-dependent checks are recorded once a certificate was recovered from at least one listener'
assert_contains "$CR" 'NET-TLS-CERT_EXPIRING-01' 'expiring is recorded'
assert_contains "$CR" 'NET-TLS-SELF_SIGNED-01' 'self-signed is recorded'
assert_contains "$CR" 'NET-TLS-WILDCARD_CERT-01' 'wildcard is recorded'

# =============================================================================
printf '\n-- report.md §9.4 tls-expect-wildcard: the SAME certificate fires on one target and not the other --\n'
# =============================================================================

_tls_stub_probe_wc() {
  printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >>"$TLS_PROBE_LOG"
  cat "$FIX/openssl3-tls12-wildcard.transcript" >"$5"
  return 0
}

t_case 'a wildcard certificate fires when the target does not expect one'
export SCOURSH_TLS_PROBE=_tls_stub_probe_wc
_fresh_run
_phase_env net-tls
_write_listeners net-tls \
  'base-url:https:net-tls.fixture.invalid:443' \
  'extra-host:https:net-tls.fixture.invalid:8443'
source "$ROOT/modules/network/tlsport.sh"
FIND=$(_shard_text)
assert_contains "$FIND" 'check_id=NET-TLS-WILDCARD_CERT-01' \
  'net-tls does not set tls-expect-wildcard, so the wildcard certificate is reported'

t_case 'the SAME certificate on a target that DECLARES tls-expect-wildcard: true is not a finding'
_fresh_run
_phase_env net-tls-wildcard-ok
_write_listeners net-tls-wildcard-ok \
  'base-url:https:net-tls-wc.fixture.invalid:443' \
  'extra-host:https:net-tls-wc.fixture.invalid:8443'
source "$ROOT/modules/network/tlsport.sh"
FIND=$(_shard_text); META=$(_meta_text)
assert_not_contains "$FIND" 'NET-TLS-WILDCARD_CERT-01' \
  'no wildcard finding - FAILS under a hardcoded "wildcards are always bad" reading, and equally under one that never reports them'
assert_contains "$META" 'wildcard_certificate=' \
  'the satisfied expectation is still RECORDED, so a reader can see the check ran rather than inferring it from an absent finding'
export SCOURSH_TLS_PROBE=_tls_stub_probe

# =============================================================================
printf '\n-- report.md §5.2 rule 3: no non-base-url listener is a named, counted, honest skip --\n'
# =============================================================================

t_case 'a base-url-only target (no listeners.json at all) records no_declared_listeners and exits 0'
_fresh_run
_phase_env net-tls-solo
RC=0
source "$ROOT/modules/network/tlsport.sh" || RC=$?
assert_eq '0' "$RC" 'exits 0'
META=$(_meta_text); FIND=$(_shard_text)
assert_contains "$META" 'reason=no_declared_listeners' \
  'the named reason report.md''s own vocabulary uses appears - FAILS if this degraded to a generic or missing reduction'
assert_not_contains "$FIND" 'NET-TLS' 'no NET-TLS finding of any kind was fabricated with nothing to probe'
assert_not_contains "$(_checks_run_text)" 'NET-TLS' 'and none of the six ids is recorded as having run for real'

t_case 'a listeners.json that names ONLY the base-url row (defensive - NET-05 never writes this shape) collapses to the same no-listeners outcome'
_fresh_run
_phase_env net-tls
_write_listeners net-tls 'base-url:https:net-tls.fixture.invalid:443'
RC=0
source "$ROOT/modules/network/tlsport.sh" || RC=$?
assert_eq '0' "$RC" 'exits 0'
META=$(_meta_text)
assert_contains "$META" 'reason=no_declared_listeners' \
  'the base-url-only artifact is treated exactly like no artifact at all - FAILS if a lone base-url row were mistaken for a real non-base-url listener'

# =============================================================================
printf '\n-- requires-cmd: openssl absent is a declared, named skip - never an error, never silent --\n'
# =============================================================================

t_case 'with no openssl, all six NET-TLS-* ids are named as uncovered, and no handshake is attempted'
_have_real=$(declare -f _have)
_have() { [[ $1 != openssl ]] && command -v "$1" >/dev/null 2>&1; }
RC=0
_fresh_run
_phase_env net-tls
_write_listeners net-tls \
  'base-url:https:net-tls.fixture.invalid:443' \
  'extra-host:https:net-tls.fixture.invalid:8443'
source "$ROOT/modules/network/tlsport.sh" || RC=$?
META=$(_meta_text); FIND=$(_shard_text)
eval "$_have_real"
assert_eq '0' "$RC" 'the phase returns cleanly with no openssl'
assert_contains "$META" 'reason=requires_cmd_absent' 'the declared skip is recorded'
assert_contains "$META" 'cmd=openssl' 'naming the command'
assert_contains "$META" 'NET-TLS-WEAK_PROTOCOL-01' 'the reduction names each of the six ids by name, not only a generic module note'
assert_contains "$META" 'NET-TLS-WILDCARD_CERT-01' 'including the last of the six'
assert_eq '0' "$(grep -c . "$TCP_PROBE_LOG" || true)" \
  'net_connect_probe was NEVER invoked at all - openssl is checked before any classification is attempted, matching modules/dast/passive/tls.sh''s own ordering'
assert_not_contains "$FIND" 'NET-TLS' 'no finding of any kind was fabricated with no real signal'

fi

# =============================================================================
printf '\n-- end to end: a full scan.sh network run wires the phase table row, checks-tlsport.rules, and every report format --\n'
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
id: net-tls-e2e
base-url: https://tlsport-e2e.fixture.invalid/
extra-host: tlsport-e2e.fixture.invalid:8443
allow-subdomains: false
EOF

E2E_RESOLVE=$W/e2e-resolve
cat >"$E2E_RESOLVE" <<'STUBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case $1 in
  tlsport-e2e.fixture.invalid) printf '203.0.113.51' ;;
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

t_case 'with SCOURSH_NET_TCP_CAPABLE=0, a real scan.sh network run names all six NET-TLS-* ids as uncovered'
NOCAP_RC=0
SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$E2E_RESOLVE \
  SCOURSH_NET_PROBE=$E2E_NETPROBE SCOURSH_NET_TCP_CAPABLE=0 \
  bash "$ROOT/scan.sh" network --out "$W/run-nocap" --intensity passive \
  --i-own-target net-tls-e2e --target net-tls-e2e \
  >"$W/run-nocap.log" 2>&1 || NOCAP_RC=$?
assert_eq 0 "$NOCAP_RC" 'exits 0 - a bash without --enable-net-redirections is a coverage fact, never an error'
NOCAP_JSON=$(cat "$W/run-nocap/run.json" 2>/dev/null || printf '')
assert_contains "$NOCAP_JSON" 'reason=net_probe_cmd_absent' 'the named reason appears'
assert_contains "$NOCAP_JSON" 'NET-TLS-CERT_EXPIRED-01' 'names the check ids, not only a module-level note'
NOCAP_JSONL=$(cat "$W/run-nocap/findings.jsonl" 2>/dev/null || printf '')
assert_not_contains "$NOCAP_JSONL" 'NET-TLS' 'no finding of any kind was fabricated with no TCP capability'

if (( HAVE_OPENSSL )); then
  E2E_TLSPROBE=$W/e2e-tlsprobe
  cat >"$E2E_TLSPROBE" <<STUBEOF
#!/usr/bin/env bash
set -Eeuo pipefail
cat "$FIX/openssl3-tls10-3des.transcript" >"\$5"
STUBEOF
  chmod 0755 "$E2E_TLSPROBE"

  t_case 'a full scan.sh network run at --intensity passive dispatches tlsport.sh through the phase table and emits a finding'
  E2E_RC=0
  SCOURSH_INSTALL_ROOT=$FIX_MULTI SCOURSH_HTTP_RESOLVE=$E2E_RESOLVE \
    SCOURSH_NET_PROBE=$E2E_NETPROBE SCOURSH_TLS_PROBE=$E2E_TLSPROBE \
    bash "$ROOT/scan.sh" network --out "$W/run-e2e" --intensity passive \
    --i-own-target net-tls-e2e --target net-tls-e2e --format json,md,html,agent \
    >"$W/run-e2e.log" 2>&1 || E2E_RC=$?
  assert_eq 0 "$E2E_RC" \
    'exits 0 - and note this run uses --intensity passive, under which reachability.sh (NET-06, tier safe) does NOT run this pass, proving tlsport.sh does its own open-state classification rather than depending on a same-process reachability.sh pass'
  E2E_JSONL=$(cat "$W/run-e2e/findings.jsonl" 2>/dev/null || printf '')
  assert_contains "$E2E_JSONL" '"check_id":"NET-TLS-WEAK_PROTOCOL-01"' 'the finding fires through the real dispatch chain'
  assert_contains "$E2E_JSONL" '"location":{"target":"net-tls-e2e","host":"tlsport-e2e.fixture.invalid","port":"8443","transport":"https"}' \
    'the location is the net fingerprint profile, nested under "location" (lib/findings.sh _finding_json)'

  t_case 'the finding round-trips into findings.json, report.md, report.html and agent-fix.json'
  E2E_JSON=$(cat "$W/run-e2e/findings.json" 2>/dev/null || printf '')
  assert_contains "$E2E_JSON" '"check_id":"NET-TLS-WEAK_PROTOCOL-01"' 'findings.json (--format json) carries the same finding'
  E2E_MD=$(cat "$W/run-e2e/report.md" 2>/dev/null || printf '')
  assert_contains "$E2E_MD" 'NET-TLS-WEAK_PROTOCOL-01' 'report.md names the check id'
  E2E_HTML=$(cat "$W/run-e2e/report.html" 2>/dev/null || printf '')
  assert_contains "$E2E_HTML" 'NET-TLS-WEAK_PROTOCOL-01' 'report.html names the check id too'
  E2E_AGENT=$(cat "$W/run-e2e/agent-fix.json" 2>/dev/null || printf '')
  assert_contains "$E2E_AGENT" 'NET-TLS-WEAK_PROTOCOL-01' 'agent-fix.json (--format agent) carries the finding too'

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
    SCOURSH_NET_PROBE=$E2E_NETPROBE SCOURSH_TLS_PROBE=$E2E_TLSPROBE \
    PATH="$STUB:$PATH" \
    bash "$ROOT/scan.sh" network --target net-tls-e2e --intensity passive \
    --i-own-target net-tls-e2e --out "$W/run-notraffic" \
    >"$W/run-notraffic.log" 2>&1 || NT_RC=$?
  assert_eq 0 "$NT_RC" 'the run still exits 0 with a poisoned PATH'
  assert_file_absent "$W/network-attempts" \
    'no curl/wget/nc/ncat/netcat was invoked - tlsport.sh reaches the network exclusively through lib/nettransport.sh''s net_connect_probe and tls_engine.sh''s tls_probe, both of which this suite''s stubs already replace'
else
  printf '  NOTICE openssl is not on PATH: the transcript-dependent end-to-end cases did NOT run. This is a SKIP, not a pass.\n'
fi

t_case 'checks-tlsport.rules registers all six ids under coverage-scope target, per rules/RULE-FORMAT.md §9.5.1 NET row'
RULES_FILE=$(cat "$ROOT/modules/network/checks-tlsport.rules")
for id in NET-TLS-WEAK_PROTOCOL-01 NET-TLS-WEAK_CIPHER-01 NET-TLS-CERT_EXPIRED-01 \
  NET-TLS-CERT_EXPIRING-01 NET-TLS-SELF_SIGNED-01 NET-TLS-WILDCARD_CERT-01; do
  assert_contains "$RULES_FILE" "id: $id" "check id $id is registered"
done
assert_eq 6 "$(grep -c '^coverage-scope: target' <<<"$RULES_FILE")" \
  'all six records declare coverage-scope: target - FAILS the linter''s E079 otherwise (rules/RULE-FORMAT.md §9.5.1: NET requires target)'
assert_eq 6 "$(grep -c '^requires-cmd: openssl' <<<"$RULES_FILE")" \
  'all six records declare requires-cmd: openssl, matching the phase''s own dependency check'

SCOURSH_RUN_DIR='' SCOURSH_RUN_ID=''

t_summary 'network-tlsport'
