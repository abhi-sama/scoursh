#!/usr/bin/env bash
# tests/suites/dast-tls.sh - modules/dast/passive/tls.sh and tls_engine.sh:
# transport-security checks (docs/DESIGN.md §7.1, docs/STEP5-DAST-PLAN.md
# DAST-07).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_TLS_PROBE is stubbed throughout to
# replay a RECORDED `openssl s_client` transcript from
# tests/fixtures/dast/tls/, and SCOURSH_HTTP_RESOLVE is stubbed so the scope
# gate resolves without a resolver (docs/DESIGN.md §12: "DAST logic is testable
# with no live target").  The suite runs on a host with no network and no
# Docker, exactly like tests/suites/dast-auth.sh and dast-jwt.sh.
#
# `openssl` IS still needed - to read the fixture certificates, not to dial
# anything - because that is the very dependency the check declares
# (`requires-cmd: openssl`).  Its absence is asserted to be a recorded skip
# rather than an error, and the certificate-reading sections are themselves
# skipped with a NOTICE rather than silently passing, per this repository's rule
# that a suite which did not run is never reported as one that passed.
#
# The decisions this suite pins, each with a plausible wrong reading that would
# ship green on one userland and be wrong on the other:
#
#   1. THE NEGOTIATED PROTOCOL COMES FROM `SSL-Session:`, NOT FROM THE `New,`
#      LINE.  LibreSSL prints `New, TLSv1/SSLv3, ...` for a TLS 1.2 session, so
#      the naive reading reports every LibreSSL-probed target as TLSv1 and fires
#      the weak-protocol finding on all of them.
#   2. A DISTINGUISHED NAME HAS TWO SPELLINGS.  `/O=X/CN=h` and `O = X, CN = h`
#      must normalize to one string, or the self-signed test (subject==issuer)
#      is userland-dependent and the CN lookup finds nothing on the slash form.
#   3. A FAILED HANDSHAKE IS NOT A SESSION.  openssl still prints `Protocol  :`
#      and `Cipher    : 0000` when the handshake failed; accepting a protocol
#      alone reports the OFFERED version as negotiated.
#   4. BOTH EXPIRY BOUNDARIES ARE `<=`.  A certificate expiring in exactly the
#      window IS expiring; one whose notAfter is exactly now IS expired.
#   5. ONLY A LEADING LABEL IS A WILDCARD.  `a.*.example` is not one, and a
#      substring test for `*` says it is.
#   6. THE CN IS A FALLBACK ONLY, AND ONLY WITH NO SAN.  Reading it anyway
#      reports a wildcard no current client would ever be shown.
#   7. VERIFY CODES 20/21 ARE NOT "SELF-SIGNED".  They mean the chain could not
#      be built, which a missing intermediate also produces.
#   8. AN UNRECOGNISED PROTOCOL IS NOT REPORTED WEAK - it is a recorded gap, so
#      the next TLS version does not become a false finding on every target.
#   9. THE SCOPE GATE STILL BINDS THIS PHASE.  It is exempt from the transport,
#      not from the authorization: an out-of-scope target is exit 3.
#  10. EVERY DEGRADATION IS A RECORDED GAP - no openssl, a plain-http target, a
#      failed probe, an unreadable date - never an error and never a silent pass.
#  11. AN UNRESOLVABLE HOST IS NOT THE SAME REFUSAL AS AN OUT-OF-SCOPE ONE.  A
#      target that IS authorised in config/scope.conf but whose host does not
#      resolve is a recorded coverage reduction that lets the run continue -
#      it fails under the reading that collapses it into decision 9's exit 3,
#      which aborts every other phase and every other target over one
#      unreachable host (this project's DAST-07 tls.sh fix).
#
# Every case that pins a decision names the reading it FAILS under, per this
# repository's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell, DN and flag syntax literally.
# SC2030/SC2031: a prefix `VAR=val cmd` before a subprocess is DELIBERATELY
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/http.sh
source "$ROOT/lib/http.sh"
# shellcheck source=modules/dast/passive/tls_engine.sh
source "$ROOT/modules/dast/passive/tls_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

FIX=$ROOT/tests/fixtures/dast/tls
W=$SCOURSH_SCRATCH/dast-tls-workspace
rm -rf "$W"
mkdir -p "$W"

HAVE_OPENSSL=0
if command -v openssl >/dev/null 2>&1; then HAVE_OPENSSL=1; fi

# ---------------------------------------------------------------------------
# A. Time arithmetic (tls_time_to_epoch, tls_expiry_state) - decision 4
# ---------------------------------------------------------------------------
printf '\n== A. validity dates and the expiry window ==\n'

t_case 'tls_time_to_epoch'
# 1970-01-01T00:00:00Z is the definition of the epoch, so it is the one value
# that cannot be right by accident.
assert_eq '0' "$(tls_time_to_epoch 'Jan  1 00:00:00 1970 GMT')" \
  'the epoch itself converts to 0'
# 2024-06-01T12:00:00Z = 1717243200, an independently checkable constant.
assert_eq '1717243200' "$(tls_time_to_epoch 'Jun  1 12:00:00 2024 GMT')" \
  'a space-padded day converts to the right epoch'
assert_eq '1717243200' "$(tls_time_to_epoch 'notAfter=Jun  1 12:00:00 2024 GMT')" \
  'the notAfter= prefix openssl prints is tolerated'
# 2024 is a leap year: 2024-03-01 must be one day after 2024-02-29.  A converter
# with a naive leap rule (or none) lands a day out here and nowhere else.
assert_eq '86400' \
  "$(( $(tls_time_to_epoch 'Mar  1 00:00:00 2024 GMT') - $(tls_time_to_epoch 'Feb 29 00:00:00 2024 GMT') ))" \
  'the leap day is handled: 2024-03-01 is exactly one day after 2024-02-29'
# 1900 is NOT a leap year and 2000 IS - the two cases a "divisible by 4" rule
# gets wrong.  2000-03-01 minus 2000-02-29 must still be one day.
assert_eq '86400' \
  "$(( $(tls_time_to_epoch 'Mar  1 00:00:00 2000 GMT') - $(tls_time_to_epoch 'Feb 29 00:00:00 2000 GMT') ))" \
  'the 400-year leap rule is handled: 2000 is a leap year'
assert_status 1 'an unparseable date RETURNS 1 rather than printing 0 - a 0 would render as "expired since 1970" on every finding' \
  tls_time_to_epoch 'not a date at all'
assert_status 1 'a non-GMT date is refused rather than silently read in local time' \
  tls_time_to_epoch 'Jun  1 12:00:00 2024 PDT'

t_case 'tls_expiry_state boundaries'
NOW=1717243200
assert_eq 'expired' "$(tls_expiry_state $(( NOW - 1 )) "$NOW" 30)" 'a past notAfter is expired'
assert_eq 'expired' "$(tls_expiry_state "$NOW" "$NOW" 30)" \
  'notAfter EXACTLY now is expired - it is not valid AT this instant; fails under a strict < comparison'
assert_eq 'expiring' "$(tls_expiry_state $(( NOW + 30 * 86400 )) "$NOW" 30)" \
  'notAfter EXACTLY at the window edge is expiring - fails under a strict < window, which loses the warning on the day it matters'
assert_eq 'ok' "$(tls_expiry_state $(( NOW + 30 * 86400 + 1 )) "$NOW" 30)" \
  'one second past the window is ok'
assert_eq 'ok' "$(tls_expiry_state $(( NOW + 86400 )) "$NOW" 0)" \
  'a warn window of 0 disables expiring-soon without disabling expired'
assert_eq 'expired' "$(tls_expiry_state $(( NOW - 1 )) "$NOW" 0)" \
  'a warn window of 0 still reports an already-expired certificate'
assert_eq '30' "$(tls_days_until $(( NOW + 30 * 86400 )) "$NOW")" 'tls_days_until counts whole days'
assert_eq '2' "$(tls_days_until $(( NOW - 2 * 86400 )) "$NOW")" 'tls_days_until is unsigned in the past direction too'

# ---------------------------------------------------------------------------
# B. Distinguished names, both userlands - decision 2
# ---------------------------------------------------------------------------
printf '\n== B. distinguished names in both spellings ==\n'

t_case 'tls_dn_normalize'
OPENSSL_DN='subject=C = ZZ, O = Fixture Org, CN = api.fixture.example'
LIBRESSL_DN='subject=/C=ZZ/O=Fixture Org/CN=api.fixture.example'
assert_eq 'C=ZZ,O=Fixture Org,CN=api.fixture.example' "$(tls_dn_normalize "$OPENSSL_DN")" \
  "OpenSSL's comma form normalizes"
assert_eq 'C=ZZ,O=Fixture Org,CN=api.fixture.example' "$(tls_dn_normalize "$LIBRESSL_DN")" \
  "LibreSSL's slash form normalizes"
assert_eq "$(tls_dn_normalize "$OPENSSL_DN")" "$(tls_dn_normalize "$LIBRESSL_DN")" \
  'THE SAME DN FROM THE TWO USERLANDS IS THE SAME STRING - fails under any comparison of the raw values, which is what makes the self-signed test userland-dependent'
assert_eq 'CN=host' "$(tls_dn_normalize ' 0 s:CN = host')" \
  "the certificate-chain block's own 's:' prefix is stripped"
assert_eq 'CN=host' "$(tls_dn_normalize ' 0 s:/CN=host')" \
  "the chain block's slash form is stripped too"
assert_status 1 'an empty DN returns 1 rather than an empty success' tls_dn_normalize ''

t_case 'tls_dn_attr'
DN=$(tls_dn_normalize "$OPENSSL_DN")
assert_eq 'api.fixture.example' "$(tls_dn_attr "$DN" CN)" 'the CN is found'
assert_eq 'ZZ' "$(tls_dn_attr "$DN" C)" 'a non-CN attribute is found'
assert_status 1 'an absent attribute returns 1' tls_dn_attr "$DN" OU
# X.509 orders a DN least-specific first, so the entity's own CN is LAST.
assert_eq 'leaf.fixture.example' "$(tls_dn_attr 'CN=Issuing CA,O=Org,CN=leaf.fixture.example' CN)" \
  'the LAST CN wins, not the first - fails under a first-match lookup, which would return the issuing CA name as the host'

# ---------------------------------------------------------------------------
# C. Predicates - decisions 5, 7, 8
# ---------------------------------------------------------------------------
printf '\n== C. protocol, cipher, wildcard and self-signed predicates ==\n'

t_case 'tls_protocol_is_weak'
for p in SSLv2 SSLv3 TLSv1 TLSv1.0 TLSv1.1; do
  assert_status 0 "$p is reported weak" tls_protocol_is_weak "$p"
done
for p in TLSv1.2 TLSv1.3; do
  assert_status 1 "$p is not reported weak" tls_protocol_is_weak "$p"
done
assert_status 1 'an UNRECOGNISED version is NOT reported weak - fails under a "not in the modern list, therefore broken" reading, which would put a false high finding on every target that adopts TLSv1.4 before this table does' \
  tls_protocol_is_weak 'TLSv1.4'
assert_status 1 'and it is not reported KNOWN either, so the phase can record it as a gap' \
  tls_protocol_is_known 'TLSv1.4'

t_case 'tls_cipher_is_weak'
for c in ECDHE-RSA-RC4-SHA EXP-RC2-CBC-MD5 NULL-SHA256 ADH-AES256-SHA DES-CBC3-SHA \
  ECDHE-RSA-DES-CBC3-SHA TLS_RSA_WITH_RC4_128_MD5 IDEA-CBC-SHA SEED-SHA; do
  assert_status 0 "$c is reported weak" tls_cipher_is_weak "$c"
done
for c in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 \
  ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES128-GCM-SHA256; do
  assert_status 1 "$c is not reported weak" tls_cipher_is_weak "$c"
done
assert_status 0 "the IANA spelling of a weak suite is caught too, not just OpenSSL's own - a target probed from either userland reports the same verdict" \
  tls_cipher_is_weak 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'

t_case 'tls_is_wildcard'
assert_status 0 'a leading-label wildcard is one' tls_is_wildcard '*.fixture.example'
assert_status 1 'a plain name is not' tls_is_wildcard 'api.fixture.example'
assert_status 1 'a MIDDLE-label star is NOT a wildcard certificate (RFC 6125 §6.4.3 puts it in the left-most label and nowhere else) - fails under a substring test for *, which would report a wildcard finding on a target whose real problem is a name no client matches at all' \
  tls_is_wildcard 'a.*.fixture.example'
assert_status 1 'a bare star with no dot is not one either' tls_is_wildcard '*'

t_case 'tls_verify_is_self_signed / tls_is_self_signed'
assert_status 0 'verify code 18 (depth-zero self signed) is self-signed' tls_verify_is_self_signed 18
assert_status 0 'verify code 19 (self signed in chain) is self-signed' tls_verify_is_self_signed 19
assert_status 1 'verify code 20 (unable to get local issuer) is NOT self-signed - it is also what a server that simply omitted its intermediates produces, and calling it self-signed sends the operator to replace a certificate that is fine' \
  tls_verify_is_self_signed 20
assert_status 1 'verify code 21 (unable to verify the first certificate) is NOT self-signed either' \
  tls_verify_is_self_signed 21
assert_status 0 'subject == issuer is self-signed even with no verify code (a transcript captured without a trust store has none)' \
  tls_is_self_signed 'CN=h' 'CN=h' ''
assert_status 1 'subject != issuer with no verify code is not' \
  tls_is_self_signed 'CN=h' 'CN=Issuing CA' ''
assert_status 0 'a verify code of 18 is enough on its own, even when the DNs differ' \
  tls_is_self_signed 'CN=h' 'CN=Issuing CA' 18
assert_status 1 'an empty subject is never self-signed by DN equality alone' \
  tls_is_self_signed '' '' ''

# ---------------------------------------------------------------------------
# D. Transcript parsing, both userlands - decisions 1 and 3
# ---------------------------------------------------------------------------
printf '\n== D. s_client transcripts from both userlands ==\n'

t_case 'tls_parse_session: OpenSSL 3.x transcript'
assert_status 0 'a completed OpenSSL session parses' \
  tls_parse_session "$FIX/openssl3-tls13-host-specific.transcript"
tls_parse_session "$FIX/openssl3-tls13-host-specific.transcript"
assert_eq 'TLSv1.3' "$_TLS_PROTOCOL" 'the negotiated protocol is read'
assert_eq 'TLS_AES_256_GCM_SHA384' "$_TLS_CIPHER" 'the negotiated cipher is read'
assert_eq '0' "$_TLS_VERIFY_CODE" 'the verify return code is read'
assert_eq 'ok' "$_TLS_VERIFY_TEXT" 'the verify text is read'
assert_contains "$_TLS_SUBJECT" 'CN=api.fixture.example' 'the subject is normalized on the way out'
assert_ne "$_TLS_SUBJECT" "$_TLS_ISSUER" 'a CA-issued certificate has a different issuer'

t_case 'tls_parse_session: LibreSSL transcript - decision 1'
tls_parse_session "$FIX/libressl-tls12-self-signed.transcript"
assert_eq 'TLSv1.2' "$_TLS_PROTOCOL" \
  'THE PROTOCOL IS TLSv1.2, NOT TLSv1 - this transcript carries LibreSSL new, TLSv1/SSLv3, ... family label, and a parser that read THAT line would report TLSv1 here and fire the weak-protocol finding on every LibreSSL-probed target'
assert_status 1 'and TLSv1.2 is correctly not weak, which is the consequence that would have been inverted' \
  tls_protocol_is_weak "$_TLS_PROTOCOL"
assert_eq '18' "$_TLS_VERIFY_CODE" "LibreSSL's verify return code is read"
assert_eq 'self signed certificate' "$_TLS_VERIFY_TEXT" 'and its text'
assert_eq "$_TLS_SUBJECT" "$_TLS_ISSUER" \
  "the slash-form subject and issuer normalize to the same string - fails under a raw comparison, because LibreSSL's own spelling is what this transcript carries"

t_case 'tls_parse_session: a failed handshake is not a session - decision 3'
assert_status 1 'a handshake-failure transcript returns 1 - fails under a "protocol OR cipher" reading, because openssl fills in Protocol : with the version it OFFERED and prints Cipher : 0000' \
  tls_parse_session "$FIX/openssl3-handshake-failed.transcript"
tls_parse_session "$FIX/openssl3-handshake-failed.transcript" || true
assert_eq '' "$_TLS_CIPHER" 'Cipher : 0000 is not accepted as a negotiated cipher'
assert_status 1 'an absent transcript file returns 1' tls_parse_session "$W/does-not-exist"

t_case 'tls_extract_pem'
assert_status 0 'the leaf PEM is recovered from a transcript' \
  tls_extract_pem "$FIX/openssl3-tls13-host-specific.transcript" "$W/leaf.pem"
tls_extract_pem "$FIX/openssl3-tls13-host-specific.transcript" "$W/leaf.pem"
assert_eq '-----BEGIN CERTIFICATE-----' "$(head -1 "$W/leaf.pem")" 'it starts at the BEGIN line'
assert_eq '-----END CERTIFICATE-----' "$(tail -1 "$W/leaf.pem")" 'and stops at the first END line'
assert_eq '1' "$(grep -c 'BEGIN CERTIFICATE' "$W/leaf.pem" || true)" \
  'exactly ONE certificate is taken - the leaf; widening to the chain would report every root as self-signed'
assert_status 1 'a transcript with no certificate returns 1' \
  tls_extract_pem "$FIX/openssl3-handshake-failed.transcript" "$W/none.pem"
assert_eq '' "$(cat "$W/none.pem")" 'and leaves the output file empty rather than half-written'

# ---------------------------------------------------------------------------
# E. Reading a real certificate - decision 6
# ---------------------------------------------------------------------------
printf '\n== E. certificate fields (needs openssl) ==\n'
if (( ! HAVE_OPENSSL )); then
  printf '  NOTICE openssl is not on PATH: section E did NOT run.  This is a SKIP, not a pass.\n'
else
  t_case 'tls_cert_dn / tls_cert_enddate'
  assert_contains "$(tls_cert_dn "$FIX/host-specific.pem" subject)" 'CN=api.fixture.example' \
    'the subject is read and normalized from the PEM'
  assert_contains "$(tls_cert_dn "$FIX/self-signed.pem" issuer)" 'CN=api.fixture.example' \
    'a self-signed leaf reports itself as issuer'
  assert_eq "$(tls_cert_dn "$FIX/self-signed.pem" subject)" "$(tls_cert_dn "$FIX/self-signed.pem" issuer)" \
    'and its subject and issuer are equal'
  ENDDATE=$(tls_cert_enddate "$FIX/host-specific.pem")
  assert_contains "$ENDDATE" 'GMT' 'the notAfter is read'
  assert_status 0 'and it converts to an epoch' tls_time_to_epoch "$ENDDATE"

  t_case 'tls_sans_from_text - decision 6'
  SANS=$(tls_cert_text "$FIX/wildcard.pem" | tls_sans_from_text)
  assert_contains "$SANS" '*.fixture.example' 'a wildcard SAN is read out of the -text dump'
  assert_contains "$SANS" 'fixture.example' 'and so is the apex name beside it'
  assert_eq '2' "$(printf '%s\n' "$SANS" | grep -c . || true)" 'both SANs, and only those two'
  SANS=$(tls_cert_text "$FIX/host-specific.pem" | tls_sans_from_text)
  assert_eq 'api.fixture.example' "$SANS" 'a host-specific certificate reports its one SAN'
  assert_status 1 'and that name is not a wildcard' tls_is_wildcard "$SANS"
  # `-ext subjectAltName` does not exist on LibreSSL; `-text` does.  This
  # asserts the portable path is the one taken, by proving the SANs are found
  # from a -text dump with no -ext call anywhere.
  assert_eq '' "$(tls_cert_text "$FIX/no-san.pem" | tls_sans_from_text)" \
    'a certificate with no subjectAltName yields no names - which is what makes the CN fallback reachable and testable'
fi

# ---------------------------------------------------------------------------
# F. The phase, driven from recorded transcripts - decisions 6, 8, 9, 10
# ---------------------------------------------------------------------------
printf '\n== F. the phase end to end, from recorded transcripts ==\n'

SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOS'
id: tls-fixture
base-url: https://api.fixture.example/
allow-subdomains: false
tls-expect-wildcard: false
notes: Fixture target for tests/suites/dast-tls.sh. Never dialled - the probe is
  stubbed and replays a recorded transcript.

id: tls-wildcard-ok
base-url: https://api.fixture.example/
tls-expect-wildcard: true
notes: The same endpoint with the wildcard expectation DECLARED, so the wildcard
  finding must not fire.

id: tls-plain
base-url: http://plain.fixture.example/
notes: A plain-http target: nothing to handshake with.

id: tls-loopback
base-url: https://loopback.fixture.example/
notes: Resolves to loopback and does NOT set allow-private-addresses, so
  lib/http.sh's resolution-pinning deny list must refuse it. Present so the
  suite can prove the scope gate still binds this phase.

id: tls-unresolvable
base-url: https://unresolvable.fixture.example/
notes: An AUTHORISED target (it has a real entry here) whose host
  _tls_resolve below does not know, so it does not resolve. Present so the
  suite can prove that is a declared coverage reduction, not exit 3 - unlike
  tls-loopback above, which IS an authorization refusal and must stay fatal.
EOS

SCANNERCONF=$W/scanner.conf
printf 'id: scanner\ntls-expiry-warn-days: 30\n' >"$SCANNERCONF"

_tls_resolve() {
  case $1 in
    api.fixture.example | plain.fixture.example) printf '%s' '198.51.100.7' ;;
    loopback.fixture.example) printf '%s' '127.0.0.1' ;;
    *) return 1 ;;
  esac
}
export SCOURSH_HTTP_RESOLVE=_tls_resolve
export SCOURSH_INSTALL_ROOT=$ROOT

# The stub probe: copy a recorded transcript into the phase's output file and
# record that it was asked for, so a case can assert a handshake did NOT happen.
PROBE_LOG=$W/probe.log
: >"$PROBE_LOG"
TRANSCRIPT_TO_SERVE=$FIX/openssl3-tls13-host-specific.transcript
PROBE_RC=0
_tls_stub_probe() {
  printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >>"$PROBE_LOG"
  (( PROBE_RC == 0 )) || return "$PROBE_RC"
  cat "$TRANSCRIPT_TO_SERVE" >"$5"
  return 0
}
export SCOURSH_TLS_PROBE=_tls_stub_probe

RUN_N=0
_fresh_run() {
  RUN_N=$(( RUN_N + 1 ))
  run_init "$W/run.$RUN_N"
  : >"$PROBE_LOG"
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

_phase_env() {
  SCOURSH_DAST_TARGET=$1
  SCOURSH_DAST_CELL=$1
  SCOURSH_DAST_INTENSITY=passive
  SCOURSH_DAST_AUTHED=false
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_INTENSITY \
    SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
  config_scope_load "$SCOPE"
  config_scanner_load "$SCANNERCONF" 2>/dev/null || true
  http_scope_load "$SCOPE"
}

_run_phase() { # target transcript
  _fresh_run
  TRANSCRIPT_TO_SERVE=$2
  _phase_env "$1"
  source "$ROOT/modules/dast/passive/tls.sh"
}

if (( ! HAVE_OPENSSL )); then
  printf '  NOTICE openssl is not on PATH: section F did NOT run.  This is a SKIP, not a pass.\n'
else
  t_case 'a healthy TLS 1.3 endpoint produces no finding, and still reports what it negotiated'
  _run_phase tls-fixture "$FIX/openssl3-tls13-host-specific.transcript"
  FIND=$(_shard_text); META=$(_meta_text)
  assert_not_contains "$FIND" 'DAST-TLS-' 'a modern, CA-issued, host-specific, long-lived certificate is clean'
  assert_contains "$META" 'protocol=TLSv1.3' \
    'the negotiated protocol is RECORDED even with no finding - §7.1 asks for it to be reported, and a healthy session is not a finding'
  assert_contains "$META" 'cipher=TLS_AES_256_GCM_SHA384' 'and so is the negotiated cipher'
  assert_contains "$META" 'DAST-TLS-WEAK_PROTOCOL-01' \
    'the check is recorded in checks_run, so coverage reflects that it LOOKED - fails under "emit checks_run only when a finding fires", which would make a clean target indistinguishable from an unvisited one'
  assert_eq '1' "$(grep -c . "$PROBE_LOG" || true)" 'exactly one handshake was opened'
  assert_contains "$(cat "$PROBE_LOG")" '198.51.100.7 443 api.fixture.example' \
    'the probe was given the RESOLVED, gate-pinned address to connect to and the HOSTNAME for SNI - fails under a reading that hands s_client the hostname, which would be a second DNS lookup the gate never saw'

  t_case 'a deprecated protocol and a 3DES cipher each fire'
  _run_phase tls-fixture "$FIX/openssl3-tls10-3des.transcript"
  FIND=$(_shard_text)
  assert_contains "$FIND" 'DAST-TLS-WEAK_PROTOCOL-01' 'TLSv1 fires the weak-protocol check'
  assert_contains "$FIND" 'DAST-TLS-WEAK_CIPHER-01' 'DES-CBC3-SHA fires the weak-cipher check'
  assert_contains "$FIND" 'CWE-327' 'both carry the CWE the registry declares'

  t_case 'a LibreSSL-recorded RC4 session over TLS 1.1 fires both, from the other userland'
  _run_phase tls-fixture "$FIX/libressl-tls11-rc4.transcript"
  FIND=$(_shard_text)
  assert_contains "$FIND" 'DAST-TLS-WEAK_PROTOCOL-01' 'TLSv1.1 fires, read from SSL-Session and not from the New, line'
  assert_contains "$FIND" 'DAST-TLS-WEAK_CIPHER-01' 'RC4 fires'

  t_case 'a self-signed certificate fires, from a LibreSSL slash-form transcript'
  _run_phase tls-fixture "$FIX/libressl-tls12-self-signed.transcript"
  FIND=$(_shard_text)
  assert_contains "$FIND" 'DAST-TLS-SELF_SIGNED-01' \
    'the self-signed check fires on the slash-form DN - fails under a raw subject/issuer comparison only if the two spellings differed, which is why this case uses the LibreSSL transcript rather than the OpenSSL one'
  assert_contains "$FIND" 'CWE-295' 'and carries CWE-295'
  assert_not_contains "$FIND" 'DAST-TLS-WEAK_PROTOCOL-01' \
    'and TLSv1.2 does NOT also fire the protocol check - the New, TLSv1/SSLv3 line in this same transcript is what a naive parser would have used'

  t_case 'a wildcard certificate fires when the target does not expect one - and does not when it does'
  _run_phase tls-fixture "$FIX/openssl3-tls12-wildcard.transcript"
  FIND=$(_shard_text)
  assert_contains "$FIND" 'DAST-TLS-WILDCARD_CERT-01' \
    'tls-expect-wildcard is false for this target, so the wildcard is reported'
  _run_phase tls-wildcard-ok "$FIX/openssl3-tls12-wildcard.transcript"
  FIND=$(_shard_text); META=$(_meta_text)
  assert_not_contains "$FIND" 'DAST-TLS-WILDCARD_CERT-01' \
    'the SAME certificate on a target that DECLARES tls-expect-wildcard: true is not a finding - fails under a hardcoded "wildcards are always bad" reading, and equally under one that never reports them'
  assert_contains "$META" 'wildcard_certificate=' \
    'and the satisfied expectation is RECORDED, so a reader can see the check ran rather than inferring it from an absent finding'

  t_case 'the CN is a wildcard fallback ONLY when there is no SAN - decision 6'
  _run_phase tls-fixture "$FIX/openssl3-tls12-wildcard-cn-only.transcript"
  FIND=$(_shard_text)
  assert_contains "$FIND" 'DAST-TLS-WILDCARD_CERT-01' \
    'a certificate whose ONLY name is a wildcard CN is still reported'
  _run_phase tls-fixture "$FIX/openssl3-tls13-host-specific.transcript"
  FIND=$(_shard_text)
  assert_not_contains "$FIND" 'DAST-TLS-WILDCARD_CERT-01' \
    'and a host-specific SAN is not, even though its CN is read by the same code path'

  t_case 'expiry: the same fixture certificate reaches all three states via injected time'
  # The fixture certificates are long-lived on purpose, so `now` is computed
  # RELATIVE to the certificate's own notAfter.  That is what makes expired /
  # expiring / ok all reachable from one committed file and none of them
  # dependent on today's date.
  END=$(tls_time_to_epoch "$(tls_cert_enddate "$FIX/host-specific.pem")")
  assert_eq 'expired' "$(tls_expiry_state "$END" $(( END + 86400 )) 30)" \
    'a clock one day past notAfter reports expired'
  assert_eq 'expiring' "$(tls_expiry_state "$END" $(( END - 10 * 86400 )) 30)" \
    'a clock ten days before notAfter, with a 30-day window, reports expiring'
  assert_eq 'ok' "$(tls_expiry_state "$END" $(( END - 400 * 86400 )) 30)" \
    'a clock well outside the window reports ok'

  t_case 'a failed probe is a recorded gap, not an error and not a silent pass - decision 10'
  PROBE_RC=1
  _run_phase tls-fixture "$FIX/openssl3-tls13-host-specific.transcript"
  PROBE_RC=0
  META=$(_meta_text); FIND=$(_shard_text)
  assert_contains "$META" 'reason=tls_probe_failed' 'the failure is a declared coverage_reduction'
  assert_contains "$META" 'absence of a test' 'and a human-readable coverage_gap says a clean result is the absence of a test'
  assert_not_contains "$FIND" 'DAST-TLS-' 'and nothing is reported as clean'

  t_case 'a handshake that produced no session is a recorded gap - decision 3 at the phase level'
  _run_phase tls-fixture "$FIX/openssl3-handshake-failed.transcript"
  META=$(_meta_text); FIND=$(_shard_text)
  assert_contains "$META" 'reason=tls_handshake_failed' 'the phase records the failed handshake'
  assert_not_contains "$META" 'protocol=TLSv1.3' \
    'and does NOT record the OFFERED version as negotiated - fails under a parser that accepts a protocol with no cipher'
  assert_not_contains "$FIND" 'DAST-TLS-' 'no finding is emitted either way'

  t_case 'a plain-http target is a recorded gap, and NOT this check''s finding - decision 10'
  _run_phase tls-plain "$FIX/openssl3-tls13-host-specific.transcript"
  META=$(_meta_text); FIND=$(_shard_text)
  assert_contains "$META" 'reason=target_not_https' 'the plain-http target is declared'
  assert_contains "$META" 'DAST-30' \
    'and the gap NAMES the ticket that owns the HTTP-versus-HTTPS question, rather than this check inventing a second id for the same fact'
  assert_not_contains "$FIND" 'DAST-TLS-' 'no TLS finding is emitted for a target with no TLS listener'
  assert_eq '0' "$(grep -c . "$PROBE_LOG" || true)" 'and NO handshake was attempted'

  t_case 'the scope gate still binds this phase - decision 9'
  # The exemption is from the TRANSPORT, not from the authorization.  This
  # target resolves to loopback and does not set allow-private-addresses, so
  # lib/http.sh's resolution-pinning deny list must refuse it with exit 3 -
  # exactly as it would refuse an http_request, and through the same code.
  # NO `set +e` HERE.  It is forbidden repository-wide (docs/FOUNDATION.md
  # tension 4 rule 1) and tests/suites/core.sh asserts the string appears
  # nowhere in the tree, so a suite that reaches for it fails a DIFFERENT
  # suite - which is how this one was caught.  It is also unnecessary: the
  # `|| rc=$?` on the subshell is what keeps the outer errexit from firing,
  # and inside the subshell errexit is exactly what should stay on, because
  # the case asserts that the gate's own `die 3` is the reason the phase
  # stopped rather than any later command happening to return 3.
  rc=0
  (
    _fresh_run
    _phase_env tls-loopback
    source "$ROOT/modules/dast/passive/tls.sh"
  ) >/dev/null 2>&1 || rc=$?
  assert_eq '3' "$rc" \
    'a target the gate refuses is SCOURSH_EXIT_SCOPE (3) - fails under any reading in which the tls exemption also exempts the authorization, the pinned resolution, or the deny list'
  assert_eq '0' "$(grep -c . "$PROBE_LOG" || true)" \
    'and NO handshake was opened - the gate is consulted before the probe, never after'

  t_case 'an unresolvable but AUTHORISED host is a recorded gap, not exit 3 - decision 11'
  # tls-unresolvable IS in config/scope.conf (unlike tls-loopback above, which
  # the gate REFUSES): _tls_resolve simply does not know its host. This must
  # NOT abort the run - it fails under the reading that collapses "does not
  # resolve" into the same fatal path as "not authorised".
  rc=0
  (
    _fresh_run
    _phase_env tls-unresolvable
    source "$ROOT/modules/dast/passive/tls.sh"
  ) >/dev/null 2>&1 || rc=$?
  assert_eq '0' "$rc" \
    'an authorised target that does not resolve is NOT fatal - fails under the pre-fix reading, where this exits 3 (SCOURSH_EXIT_SCOPE) exactly as tls-loopback does'
  _fresh_run
  _phase_env tls-unresolvable
  source "$ROOT/modules/dast/passive/tls.sh"
  META=$(_meta_text); FIND=$(_shard_text)
  assert_contains "$META" 'reason=tls_host_unresolvable' \
    'the failure is a declared coverage_reduction, the same vocabulary this phase already uses for an absent openssl or a failed handshake'
  assert_contains "$META" "DNS resolution failed for 'unresolvable.fixture.example'" \
    'naming the actual reason rather than a generic one'
  assert_contains "$META" 'absence of a test' 'and a human-readable coverage_gap says a clean result is the absence of a test'
  assert_not_contains "$FIND" 'DAST-TLS-' 'and nothing is reported as clean'
  assert_eq '0' "$(grep -c . "$PROBE_LOG" || true)" 'and NO handshake was attempted - the gate refused before the probe ran'

  t_case 'openssl absent is a recorded skip, never an error - decision 10'
  # `_have` is overridden rather than PATH being emptied.  Emptying PATH takes
  # `mkdir`, `date` and `readlink` with it, so lib/core.sh cannot even open a run
  # directory and the case would pass for the wrong reason - it would be
  # asserting that a broken environment produces no records, not that an absent
  # openssl produces the right ones.  This stubs the exact predicate the phase
  # consults, the same way SCOURSH_TLS_PROBE stubs the exact call it makes.
  _have_real=$(declare -f _have)
  _have() { [[ $1 != openssl ]] && command -v "$1" >/dev/null 2>&1; }
  rc=0
  _fresh_run
  _phase_env tls-fixture
  source "$ROOT/modules/dast/passive/tls.sh" || rc=$?
  META=$(_meta_text)
  eval "$_have_real"
  assert_eq '0' "$rc" 'the phase returns cleanly with no openssl'
  assert_contains "$META" 'reason=requires_cmd_absent' 'and records the declared skip'
  assert_contains "$META" 'cmd=openssl' 'naming the command'
  assert_contains "$META" 'was not tested' 'and a human-readable gap says the transport was not tested'
  assert_eq '0' "$(grep -c . "$PROBE_LOG" || true)" 'and no handshake was attempted'

fi

# ---------------------------------------------------------------------------
# G. _tls_probe_default: the CWE-400 transcript-size cap
# ---------------------------------------------------------------------------
# THE ONLY SECTION IN THIS SUITE THAT EXERCISES `_tls_probe_default` DIRECTLY.
# Every case above stubs SCOURSH_TLS_PROBE, so the one function that actually
# shells out to `openssl s_client` is never reached - by design, per this
# file's own header ("NOTHING HERE TOUCHES THE NETWORK"). This section still
# touches no network and needs no REAL openssl at all: it PATH-shadows the
# `openssl` NAME with a tiny script ahead of whatever real one is (or is not)
# installed, so `_tls_probe_default` runs for real against a fake
# `openssl s_client` that behaves like a hostile-but-authorised listener
# instead of a TLS stack - exactly the gap this ticket names ("_tls_probe_
# default ... is untested by design").
printf '\n== G. _tls_probe_default: the transcript-size cap (CWE-400) ==\n'

GBIN=$W/g-bin
rm -rf "$GBIN"
mkdir -p "$GBIN"
OLD_PATH=$PATH

# A LISTENER THAT NEVER COMPLETES A HANDSHAKE AND JUST STREAMS BYTES: 64KiB
# every whole second (a PLAIN integer `sleep`, never a fractional one - BSD
# and GNU sleep agree on integer seconds, and this suite runs on both).  Left
# unbounded this writes 20 * 64KiB = 1.25MB over ~20s; the cap
# ($_TLS_TRANSCRIPT_CAP_BYTES, 256KiB) is crossed after the 4th chunk, around
# the 3-4 second mark - which the internal 100ms watchdog tick discovers and
# kills within, at most, one more tick.  What this case pins is BOTH halves at
# once: the FILE ON DISK is bounded, and the CALL RETURNS EARLY - and it fails
# under a watchdog that checks only the clock (`timeout_s`, generous here at
# 30s), which is exactly the code this ticket found: unmodified, this case
# would run the full ~20s and land the full ~1.25MB in $TR.
cat >"$GBIN/openssl" <<'EOS'
#!/usr/bin/env bash
if [[ $1 == s_client ]]; then
  chunk=$(head -c 65536 /dev/zero | tr '\0' 'A')
  n=0
  while (( n < 20 )); do
    printf '%s' "$chunk"
    n=$(( n + 1 ))
    sleep 1
  done
fi
exit 0
EOS
chmod +x "$GBIN/openssl"

t_case 'a listener that floods bytes instead of completing a handshake is capped, not just timed out'
TR=$W/g-flood.transcript
PATH="$GBIN:$OLD_PATH"
SECONDS=0
rc=0
_tls_probe_default '198.51.100.9' 443 flood.fixture.example 30 "$TR" || rc=$?
elapsed=$SECONDS
PATH=$OLD_PATH
size=$(wc -c <"$TR" 2>/dev/null) || size=0
size=${size//[[:space:]]/}
[[ $size =~ ^[0-9]+$ ]] || size=0

assert_eq '0' "$rc" \
  'a capped, truncated transcript is still reported as CAPTURED, matching the existing timeout-kill semantics this watchdog already had for a non-empty file - fails if truncation were (wrongly) treated as a probe failure of its own'
assert_true "$( (( size > 0 && size < 2 * _TLS_TRANSCRIPT_CAP_BYTES )) && printf 0 || printf 1 )" \
  "the transcript on disk is bounded to roughly the cap (got $size bytes, cap is $_TLS_TRANSCRIPT_CAP_BYTES) - fails under a clock-only watchdog, which would let this reach the unbounded flood's ~1.25MB"
assert_true "$( (( elapsed < 12 )) && printf 0 || printf 1 )" \
  "the probe returns in a handful of seconds, not the ~20s the unbounded flood would take (got ${elapsed}s) - fails under a clock-only watchdog with a 30s ceiling"

t_case 'the capped, session-less transcript is reported as a failed handshake, never a silent clean result'
assert_status 1 \
  'tls_parse_session refuses the capped flood transcript - it never contains an SSL-Session/Cipher block, so this is the SAME path modules/dast/passive/tls.sh already takes for any failed handshake (the tls_handshake_failed coverage_reduction plus coverage_gap pinned in section F) - fails if a truncated-but-nonempty transcript were read as a completed session' \
  tls_parse_session "$TR"

t_case 'a small, legitimate transcript captured through the SAME code path is unaffected by the cap'
cat >"$GBIN/openssl" <<EOS
#!/usr/bin/env bash
if [[ \$1 == s_client ]]; then
  cat "$FIX/openssl3-tls13-host-specific.transcript"
fi
exit 0
EOS
chmod +x "$GBIN/openssl"
TR2=$W/g-ok.transcript
PATH="$GBIN:$OLD_PATH"
rc=0
_tls_probe_default '198.51.100.9' 443 api.fixture.example 30 "$TR2" || rc=$?
PATH=$OLD_PATH
assert_eq '0' "$rc" 'a normal, small transcript still probes successfully with the size cap in place'
assert_status 0 'and it still parses as a completed session - the cap sits two orders of magnitude above any real transcript, so it never touches one' \
  tls_parse_session "$TR2"

t_summary 'dast-tls'
