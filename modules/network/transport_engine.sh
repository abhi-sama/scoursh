#!/usr/bin/env bash
# modules/network/transport_engine.sh - the pure half of the NET-10
# transport-posture probe (data/scoursh-network-scan-design/report.md §3.3,
# §5.1, §5.2; the NET-10 row in its §7 staged plan). Owned by
# modules/network/transport.sh.
#
# Owns:
#   report.md §3.3  "A plaintext service on a port whose TLS twin exists;
#                    STARTTLS advertised but not required; ... This is
#                    DAST-TRANSPORT-* and DAST-TLS-* reasoning applied one
#                    port over ... a web app can be perfectly configured
#                    while its database port answers in the clear."  The
#                    third case that sentence names - an expired or
#                    self-signed certificate on a non-web listener - is
#                    ALREADY NET-08's own coverage (modules/network/
#                    tlsport.sh assesses every non-base-url listener's
#                    certificate unconditionally, and "non-base-url" already
#                    means "non-web" for this module - modules/network/
#                    tlsport.sh's own header explains why the base-url row is
#                    skipped there), so this file adds exactly the TWO ids
#                    report.md §5.1's own finding table lists under the
#                    `NET-TRANSPORT-*` prefix that NET-08 does not already
#                    produce: NET-TRANSPORT-PLAINTEXT_SERVICE-01 and
#                    NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01.  Re-emitting a
#                    third id for the cert case here would collide onto the
#                    identical fact NET-08 already reports under a different
#                    check id on the same (target, host, port) location, and
#                    that is a coverage gap the honesty contract asks this
#                    file to name, never to paper over by re-probing.
#
# WHY THIS DOES ITS OWN TLS/BANNER PROBING RATHER THAN READING AN ARTIFACT
# NET-07 OR NET-08 WROTE.  Neither phase persists any per-listener state to
# disk - modules/network/banner.sh and modules/network/tlsport.sh both emit
# findings and coverage records directly from their own process and nothing
# else, the identical fact modules/network/tlsport.sh's own header states for
# why IT cannot read a NET-06 artifact either ("there is no 'reachability
# already ran this pass' fact this phase could depend on"). So "reuse
# NET-07/NET-08" here means exactly what it means for every sibling probe in
# this module: reuse the SAME shared primitives those two files call
# (lib/nettransport.sh's net_connect_probe/net_read_banner,
# modules/dast/passive/tls_engine.sh's tls_probe/tls_parse_session, all
# sourced verbatim rather than forked) on a second, independent connection -
# never invent a fourth way to classify a socket, read a banner, or
# handshake TLS.  What this file does NOT do, and what "do not re-probe"
# actually forbids: it never re-derives NET-07's product/version
# identification or NET-08's six-check certificate/cipher assessment on the
# SAME listener - each of those stays exactly where it already lives.
#
# THE TWO CHECKS, AND WHY EACH REUSED PRIMITIVE IS CALLED AT MOST ONCE PER
# LISTENER FOR EACH.
#
#   NET-TRANSPORT-PLAINTEXT_SERVICE-01.  A small, static table
#   (`_net_transport_plaintext_twin`) names the handful of well-known ports
#   whose protocol has a standard, widely-deployed encrypted variant - FTP
#   (990/tcp, implicit FTPS), SMTP (465/tcp, implicit SMTPS), POP3 (995/tcp,
#   implicit POP3S), IMAP (993/tcp, implicit IMAPS) and LDAP (636/tcp,
#   implicit LDAPS).  IDENTIFICATION IS BY PORT NUMBER ALONE, a stated
#   limitation rather than a silent one (this file's own header, and every
#   finding this check emits, says so): a service repurposing one of these
#   ports for something else would be misidentified, and confidence is
#   `medium` (report.md §5.1's own table) for exactly that reason - the
#   identical "confidence reflects what was actually measured" discipline
#   report.md §3.4 already applies to NET-11's banner-version lookup.  A
#   listener on one of those ports is then handed to `tls_probe` (the SAME
#   openssl s_client invocation modules/network/tlsport.sh already calls on
#   every non-base-url listener, reused here rather than forked): a
#   completed session (`tls_parse_session` succeeds) means the port already
#   speaks TLS directly and is NOT reported - that is the implicit-TLS
#   deployment the twin table is naming as the alternative, working as
#   intended, and modules/network/tlsport.sh's own six checks are what
#   assess whether THAT session is any good.  No completed session means the
#   port genuinely answers in the clear, which is the finding.
#
#   NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01.  Evaluated ONLY for a listener
#   that check 1 has just confirmed genuinely negotiates in cleartext (no
#   completed native TLS session) and whose protocol is one of the THREE in
#   the STARTTLS-capable subset of the table above that this scanner can
#   read a signal for without authenticating - SMTP, IMAP (whose command is
#   the literal word `STARTTLS`) and POP3 (RFC 2449's distinct `STLS`
#   spelling).  LDAP and FTP are BOTH excluded from this second check, for
#   two different reasons: LDAP supports the StartTLS extended operation,
#   but it is a binary protocol with no unprompted, human-readable greeting
#   for this check to read at all; FTP's equivalent (RFC 4217) is the
#   command `AUTH TLS`, a different token this check does not match, and
#   one FTP daemons essentially never volunteer unprompted in their `220`
#   greeting - it is discovered via `FEAT`, an explicit query this probe
#   never sends.  `net_read_banner`
#   (the SAME zero-byte read modules/network/banner.sh already calls) reads
#   whatever the listener volunteers unprompted; a literal `STARTTLS` or
#   `STLS` token (POP3's own RFC 2449 spelling) anywhere in that text is the
#   signal.  THIS IS DELIBERATELY A PASSIVE, READ-ONLY SIGNAL AND NOTHING
#   MORE: this scanner never issues a STARTTLS command, never attempts to
#   authenticate, and so cannot itself confirm that the server enforces
#   mandatory encryption before authentication - the finding's own evidence
#   and remediation say exactly that rather than overclaiming an enforcement
#   test this probe did not perform.  What IS measured, and what the finding
#   actually reports, is narrower and true: the initial protocol exchange
#   proceeded entirely in cleartext AND named STARTTLS as available, which
#   is the ordinary shape of an opportunistic (non-mandatory) TLS
#   configuration.  Real-world coverage is correspondingly limited to
#   servers that advertise capability inline in their greeting (common for
#   IMAP, e.g. Dovecot's `* OK [CAPABILITY ... STARTTLS] ...`) rather than
#   only after an explicit capability query (EHLO/CAPA/FEAT) this scanner
#   never sends, per report.md §2.6's "no protocol conversation" boundary -
#   a stated recall limitation, not a silent one, and why report.md §5.1
#   gives this check `confidence: medium` rather than `high`.
#
# THIS FILE IS A PURE FUNCTION LIBRARY, no side effect at source time beyond
# `set -Eeuo pipefail` and its own guarded sources, matching every sibling
# `*_engine.sh` in this tree.
#
# shellcheck shell=bash
source "${BASH_SOURCE[0]%/*}/../../lib/core.sh"
# `reach_listeners_load` (NET-06's own listeners.json reader) - reused for
# the identical reason modules/network/tlsport.sh's own header gives for
# reusing it rather than a third copy of a JSON reader this tree already has
# two of.
# shellcheck source=modules/network/reachability_engine.sh
source "${BASH_SOURCE[0]%/*}/reachability_engine.sh"
# `tls_probe`/`tls_parse_session` - reused verbatim, per this ticket's own
# instruction, exactly as modules/network/tlsport.sh already does.  No new
# `openssl s_client` call site is introduced anywhere in modules/network/ -
# the one that matters to tests/lint-shell.sh's tension-19 no-bypass check
# lives inside this sourced file's own `_tls_probe_default`, already
# exempted by path.
# shellcheck source=modules/dast/passive/tls_engine.sh
if [[ -z ${SCOURSH_DAST_TLS_ENGINE_SOURCED:-} ]]; then
  source "${BASH_SOURCE[0]%/*}/../dast/passive/tls_engine.sh"
fi

# ---------------------------------------------------------------------------
# 1. NUL-safe read of the captured banner file
# ---------------------------------------------------------------------------
# `net_transport_banner_read_text FILE [MAX_BYTES]` - a PRIVATE COPY of
# modules/network/banner_engine.sh's own `net_banner_read_text`, not a
# shared call: that file also sources modules/dast/passive/banner_engine.sh
# for the product/version identifier this file has no use for, and this
# ticket's own tests/lint-source-graph.sh hub budget is a real,
# per-shellcheck-invocation cost (AGENTS.md's "Things measured on this
# codebase") this file's tls_engine.sh edge already spends - the identical
# "a new source edge is measured, not free" reasoning
# modules/network/reachability_engine.sh's own private `_net_json_flatten`
# copy gives for a different function.  Bytes read off a raw socket are not
# text by construction (report.md §5.3, one probe over) and may carry a NUL
# a bash string cannot hold at all, so the substitution happens on the byte
# stream via `tr`, before the bytes ever reach a bash variable - the
# identical ordering the function this copies from documents at length.
net_transport_banner_read_text() {
  local file=$1 max=${2:-1024}
  [[ -r $file ]] || { printf ''; return 0; }
  head -c "$max" -- "$file" 2>/dev/null | tr '\0' '?'
}

# ---------------------------------------------------------------------------
# 2. The plaintext-port -> protocol/twin table
# ---------------------------------------------------------------------------
# `net_transport_plaintext_twin PORT` - sets `_NET_TRANSPORT_PROTO` (a short,
# lowercase protocol label, never a check field on its own - it only drives
# this file's own logic and the evidence text) and `_NET_TRANSPORT_TWIN` (the
# operator-facing sentence naming the standard encrypted variant).  Returns 0
# when PORT is a recognised entry, 1 otherwise - the caller's own signal that
# neither NET-TRANSPORT-* check applies to this listener at all.
#
# Five entries, each a protocol whose standard encrypted variant is a
# SEPARATE, well-known implicit-TLS port rather than STARTTLS-only (RFC 8314
# recommends implicit TLS as the primary transport for email submission
# specifically for this reason) - HTTP/HTTPS is deliberately absent: it is
# DAST-TRANSPORT-*'s own subject (modules/dast/passive/transport.sh), and
# port 80/443 are the base-url row this file never probes in the first
# place (see `net_transport_run` below).
net_transport_plaintext_twin() {
  local port=$1
  _NET_TRANSPORT_PROTO='' _NET_TRANSPORT_TWIN=''
  case $port in
    21)
      _NET_TRANSPORT_PROTO=ftp
      _NET_TRANSPORT_TWIN='990/tcp (FTPS, implicit TLS)'
      ;;
    25)
      _NET_TRANSPORT_PROTO=smtp
      _NET_TRANSPORT_TWIN='465/tcp (SMTPS, implicit TLS)'
      ;;
    110)
      _NET_TRANSPORT_PROTO=pop3
      _NET_TRANSPORT_TWIN='995/tcp (POP3S, implicit TLS)'
      ;;
    143)
      _NET_TRANSPORT_PROTO=imap
      _NET_TRANSPORT_TWIN='993/tcp (IMAPS, implicit TLS)'
      ;;
    389)
      _NET_TRANSPORT_PROTO=ldap
      _NET_TRANSPORT_TWIN='636/tcp (LDAPS, implicit TLS)'
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}

# `net_transport_proto_starttls_capable PROTO` - 0 for the subset of the
# table above this scanner can read an unprompted STARTTLS signal for
# without authenticating (this file's own header, section on
# NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01): `smtp` and `imap`, whose command
# is the literal word `STARTTLS` (RFC 3207/RFC 3501), and `pop3`, whose
# distinct RFC 2449 spelling is `STLS` -
# `net_transport_banner_advertises_starttls` below recognises both tokens.
# `ldap` and `ftp` are BOTH excluded, for two DIFFERENT reasons rather than
# one: LDAP's StartTLS is a binary-protocol extended operation with no
# unprompted greeting this passive probe could ever observe at all, while
# FTP's equivalent (RFC 4217) is the command `AUTH TLS` - a different token
# neither of the two this function's sibling matches, and one FTP daemons
# essentially never volunteer unprompted in their `220` greeting in any
# case (it is discovered via the `FEAT` command, an explicit query this
# probe never sends, per report.md §2.6's own boundary).  Matching `AUTH`
# here would be a false-positive generator on essentially every plaintext
# banner that happens to mention authentication at all.
net_transport_proto_starttls_capable() {
  case $1 in
    smtp | pop3 | imap) return 0 ;;
    *) return 1 ;;
  esac
}

# `net_transport_banner_advertises_starttls TEXT` - 0 when TEXT contains a
# literal `STARTTLS` token (SMTP/IMAP/FTP's own command name, RFC 3207/3501/
# 4217) or `STLS` (POP3's distinct RFC 2449 spelling), matched
# case-insensitively as a whole word so an unrelated substring
# ("liststarttlsoptions" in some unrelated banner) cannot manufacture a
# match.  A caller decides what an empty or non-matching TEXT means; this
# function only answers the one textual question.
net_transport_banner_advertises_starttls() {
  local text=${1^^}
  [[ $text =~ (^|[^A-Z0-9_])(STARTTLS|STLS)([^A-Z0-9_]|$) ]]
}

# ---------------------------------------------------------------------------
# 3. Finding emission
# ---------------------------------------------------------------------------
# Both share the `net` fingerprint location profile (lib/findings.sh: target
# host port transport), identical to every sibling emitter in this module -
# report.md gives this family no location component of its own to add.

transport_emit_plaintext_service() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5 proto=$6 twin=$7
  local evi
  evi="Declared listener $scheme://$host:$port (role=$role, config/scope.conf) is on port $port, a well-known ${proto^^} port whose protocol has a standard encrypted variant ($twin), and a native TLS handshake against THIS port produced no completed session - the listener answers ${proto^^} in the clear rather than over TLS. Port identification is by NUMBER ALONE (a stated limitation): a service repurposing this port for something else would be misidentified, which is why this finding is reported at medium confidence."
  finding_new
  finding_set check_id NET-TRANSPORT-PLAINTEXT_SERVICE-01
  finding_set module net
  finding_set title 'Network service answers in the clear on a port whose protocol has a standard encrypted variant'
  finding_set base_severity high
  finding_set confidence medium
  finding_set cwe CWE-319
  finding_set owasp A02:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$scheme"
  finding_set corr_target "$target"
  finding_set remediation "Run this service's encrypted variant instead ($twin), or require STARTTLS on this same port before any credential or protocol data is exchanged, and disable the plaintext listener once every real client has migrated. A client that authenticates against this service today is sending its credentials and data unencrypted to anyone positioned on the network path."
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

transport_emit_starttls_not_required() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5 proto=$6 raw=$7
  local safe_raw evi
  safe_raw=$(net_scope_safe_text "$raw" 200)
  evi="Declared listener $scheme://$host:$port (role=$role, config/scope.conf, protocol ${proto^^}) sent its initial protocol greeting entirely in cleartext, and that greeting advertises STARTTLS support. This scan sent no bytes and never attempted to authenticate, so it cannot confirm whether the server subsequently enforces mandatory TLS before authentication - it can only confirm that the unauthenticated protocol exchange up to and including the STARTTLS advertisement was not gated behind an upgrade, which is the ordinary shape of an opportunistic (non-mandatory) TLS configuration. Raw greeting (truncated, sanitised to printable): $safe_raw"
  finding_new
  finding_set check_id NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01
  finding_set module net
  finding_set title 'Network listener advertises STARTTLS but does not appear to require it'
  finding_set base_severity medium
  finding_set confidence medium
  finding_set cwe CWE-319
  finding_set owasp A02:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$scheme"
  finding_set corr_target "$target"
  finding_set remediation "Configure this service to require STARTTLS before any protocol command runs, rather than offering it opportunistically (e.g. Postfix \`smtpd_tls_security_level = encrypt\`, Dovecot \`disable_plaintext_auth = yes\` with \`ssl = required\`, ProFTPD \`TLSRequired on\`), or retire this port in favour of its implicit-TLS variant entirely. This scan did not attempt authentication and so could not confirm whether AUTH itself is blocked without STARTTLS - treat this finding as the protocol handshake being observably unencrypted regardless of that policy, and verify enforcement directly against the service's own configuration."
  finding_set_evidence "$evi"
  finding_emit
  return 0
}
