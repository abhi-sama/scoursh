#!/usr/bin/env bash
# modules/network/banner_engine.sh - the pure half of the NET-07 read-on-connect
# service identification probe (data/scoursh-network-scan-design/report.md
# §3.2 item 1, §5.1, §5.2, §5.3; the NET-07 row in its §7 staged plan).
#
# Owns:
#   report.md §3.2 item 1  "Connect, read up to N bytes with a deadline,
#                           close. SSH, SMTP, FTP, POP3, IMAP and many
#                           database and message-broker protocols announce
#                           themselves unprompted. This is the cheapest real
#                           coverage in the module and it sends ZERO bytes."
#                           The connect/read/close mechanics live in
#                           lib/nettransport.sh's `net_read_banner`
#                           (NET-03's file, extended for NET-07 - see that
#                           file's own header for why); THIS file owns
#                           turning whatever bytes come back into a
#                           product/version identification, or honestly
#                           finding none.
#   report.md §5.3         evidence is untrusted, one step further out than
#                           DAST's: a banner is bytes a SERVICE chose on a
#                           port that may not speak a protocol this scanner
#                           models at all, and is NOT text by construction -
#                           it may contain a NUL byte a bash STRING cannot
#                           hold.  Section 1 below is what makes it safe to
#                           bring into a bash variable at all.
#
# PRODUCT NORMALISATION IS REUSED, NOT RE-IMPLEMENTED, AND THAT IS A FROZEN
# REQUIREMENT, NOT A STYLE CHOICE.  docs/VERSIONS-DB.md §4: "An exact lookup
# is only as good as its key, so the normalisation is frozen here and
# implemented in exactly one place, `banner_normalize_product` in
# modules/dast/passive/banner_engine.sh."  `data/versions.db`'s `banner`
# namespace (docs/VERSIONS-DB.md §3) is shared across every producer that
# discovers a product@version pair, DAST's HTTP-surface banner check and
# this module's raw-socket one alike - NET-11 (the future version->vuln
# lookup this ticket deliberately does NOT build, report.md §7's own row)
# will read the SAME table this check's product key is meant to line up
# with.  A second, independently-drifting copy of the normalisation would be
# the exact "writer and reader disagree on the key" defect tension 25 exists
# to prevent for every SCA ecosystem - this is not a generic algorithm like
# `_net_json_flatten` (reachability_engine.sh's own header explains why THAT
# one is a deliberate private copy: it is arbitrary and each module owns its
# own artifact), it is a cross-module SHARED KEY SPACE, so it is sourced
# here rather than copied.  `modules/network/engine.sh` already sets the
# precedent for a guarded cross-module source of one shared pure function
# (`modules/sast/engine.sh` for `sast_evaluate_gate`), applied here to a
# DAST file instead of a SAST one for the identical reason.
#
# THE JSON/listeners.json READING IS REUSED TOO, deliberately, and for a
# different reason: reachability_engine.sh's own header says
# `reach_listeners_load` "is written to be a plain function call any future
# NET-0x phase can reuse" - an explicit invitation, one module-INTERNAL
# level down from the banner_normalize_product case above.  Sourced
# unconditionally: that file carries no source-once guard on purpose
# (redefining bash functions is idempotent), matching how
# modules/network/reachability.sh itself sources it.
#
# THIS FILE IS A PURE FUNCTION LIBRARY, no side effect at source time beyond
# `set -Eeuo pipefail` and its own guarded sources, matching every sibling
# `*_engine.sh` in this tree.
#
# shellcheck shell=bash
#
# SC2016: the remediation prose below is single-quoted on purpose and quotes
#   config directives (`Banner`, `smtpd_banner`) inside backticks, which is
#   the operator-facing spelling of them - nothing in it is meant to expand.
#   Same reason modules/dast/passive/banner_engine.sh carries this directive.
# shellcheck disable=SC2016
source "${BASH_SOURCE[0]%/*}/../../lib/core.sh"
# shellcheck source=modules/dast/passive/banner_engine.sh
if [[ -z ${SCOURSH_DAST_BANNER_ENGINE_SOURCED:-} ]]; then
  source "${BASH_SOURCE[0]%/*}/../dast/passive/banner_engine.sh"
fi
# shellcheck source=modules/network/reachability_engine.sh
source "${BASH_SOURCE[0]%/*}/reachability_engine.sh"

# ---------------------------------------------------------------------------
# 1. NUL-safe read of the captured banner file
# ---------------------------------------------------------------------------
# `net_banner_read_text FILE [MAX_BYTES]` - prints up to MAX_BYTES of FILE's
# content as a bash-safe string, with any NUL byte replaced by `?` BEFORE the
# bytes ever reach a bash variable.  This is the one place a raw connect-read
# artifact is allowed to become a shell string in this module: bash strings
# cannot hold an embedded NUL at all (they are silently dropped, not
# escaped - the identical trap `_net_json_flatten`'s own JSON reading guards
# against, AGENTS.md's "Things measured on this codebase"), and unlike that
# JSON case a raw service banner is target/service-controlled bytes with no
# schema at all (report.md §5.3), so a binary protocol's greeting WILL
# contain one.  `tr` runs on the byte stream, which is NUL-safe by
# construction (a real file can hold a NUL; only a bash variable cannot), so
# the substitution happens before assignment rather than after.
#
# Line endings (\r \n) and other control bytes are DELIBERATELY preserved
# here - `net_banner_identify_text` below is line-oriented (a multi-line SMTP
# greeting's product/version is routinely on a later "220 " line, not the
# first "220-" continuation line) and needs real line boundaries to split
# on. Reducing everything to one printable line happens only once, at
# finding-emission time, via `net_scope_safe_text`
# (modules/network/engine.sh) - the identical two-stage "parse the structure,
# sanitize only what reaches a human" split modules/dast/ already uses for
# HTML.
net_banner_read_text() {
  local file=$1 max=${2:-1024}
  [[ -r $file ]] || { printf ''; return 0; }
  head -c "$max" -- "$file" 2>/dev/null | tr '\0' '?'
}

# ---------------------------------------------------------------------------
# 2. Identification
# ---------------------------------------------------------------------------
# `net_banner_identify_line LINE` - sets `_NET_BANNER_PRODUCT` (the
# normalised product key, `banner_normalize_product`'s own frozen form) and
# `_NET_BANNER_VERSION` (empty when only a name was disclosed).  Returns 0
# when a product was identified, 1 otherwise - a line that identifies
# nothing is not a defect in the line, it is the ordinary case for most text
# a service could plausibly print.
#
# TWO PASSES, in the order report.md §3.2 item 1 names its examples:
#
#   1. SSH's own wire-format identification string (RFC 4253 §4.2):
#      "SSH-protoversion-softwareversion[ comments]", e.g.
#      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6". This is the one protocol in
#      the design's own list with a FROZEN, single-line, unambiguous banner
#      grammar, so it gets a dedicated pattern rather than being left to
#      pass 2's generic scan (which would still find "OpenSSH_8.9p1" as one
#      opaque token, since `_` is not the separator pass 2 looks for).
#   2. A generic "identifier-word immediately followed by a version-shaped
#      word" scan, which is what actually covers FTP/SMTP/POP3/IMAP and most
#      database/broker greetings without a bespoke parser per protocol -
#      their comment text is free-form ("220 (vsFTPd 3.0.3)",
#      "220 mail.example.com ESMTP Postfix", "+OK Dovecot ready.",
#      "220 ProFTPD 1.3.5e Server ready.") and the one thing they share is
#      exactly this shape whenever they disclose a version at all.  A name
#      with NO adjacent version-shaped word (bare "Postfix", bare "Dovecot")
#      is deliberately NOT reported by this pass: report.md's own honesty
#      contract requires a real, checkable disclosure, and guessing that any
#      capitalised word is a product name would manufacture findings out of
#      ordinary prose ("Server ready", "Mail Transfer") the way a keyword
#      allow-list of known product names would too, without ever being
#      complete.  `banner_is_version` (modules/dast/passive/banner_engine.sh,
#      sourced above) is the SAME "at least two dotted numeric components"
#      test DAST's own banner check applies, so a bare port number or build
#      id in the greeting cannot masquerade as a version here either.
net_banner_identify_line() {
  local line=$1
  _NET_BANNER_PRODUCT='' _NET_BANNER_VERSION=''

  if [[ $line =~ ^SSH-[0-9]+\.[0-9]+-([^\ ]+) ]]; then
    local tok=${BASH_REMATCH[1]}
    if [[ $tok =~ ^([A-Za-z][A-Za-z0-9.+]*)[_-]([0-9][0-9A-Za-z._+-]*)$ ]]; then
      _NET_BANNER_PRODUCT=$(banner_normalize_product "${BASH_REMATCH[1]}")
      _NET_BANNER_VERSION=${BASH_REMATCH[2]}
    else
      _NET_BANNER_PRODUCT=$(banner_normalize_product "$tok")
    fi
    [[ -n $_NET_BANNER_PRODUCT ]] && return 0
    return 1
  fi

  local -a words=()
  read -r -a words <<<"$line"
  local i w v
  for (( i = 0; i + 1 < ${#words[@]}; i++ )); do
    w=${words[i]}
    v=${words[i+1]}
    v=${v#[vV]}
    v=${v%,}
    v=${v%;}
    v=${v%)}
    v=${v%.}
    [[ $w =~ ^[\(]?[A-Za-z][A-Za-z0-9._+-]*$ ]] || continue
    banner_is_version "$v" || continue
    w=${w#\(}
    _NET_BANNER_PRODUCT=$(banner_normalize_product "$w")
    [[ -n $_NET_BANNER_PRODUCT ]] || continue
    _NET_BANNER_VERSION=$v
    return 0
  done
  return 1
}

# `net_banner_identify_text TEXT` - drives `net_banner_identify_line` over
# every line of TEXT (CRLF- or LF-terminated, either is accepted - a raw
# socket read is not guaranteed to end on a line boundary at all, since the
# read is bounded by MAX_BYTES/the deadline rather than by a delimiter), and
# stops at the first line that identifies anything.  A banner that
# identifies nothing on ANY line is the ordinary "read something, nothing
# recognisable in it" outcome (this file's own header, section 2) - not an
# error, and not `no_banner` either (report.md's own `no_banner` reason
# means the listener sent NO bytes at all, which this function is never
# reached for).
net_banner_identify_text() {
  local text=$1 line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    net_banner_identify_line "$line" && return 0
  done <<<"$text"
  return 1
}

# `_banner_safe_text TEXT [MAX]` - one line, printable, bounded.  A
# byte-identical-in-shape private copy of modules/network/engine.sh's own
# `net_scope_safe_text`, NOT a call to it: that function lives in the
# module's phase-script-facing engine.sh, which this file must not depend on
# (this file is a pure engine sourced on its own by a direct-engine test,
# exactly as reachability_engine.sh's own header states for its private copy
# of `crawl_json_flatten` - "a new source edge ... is a real, measured
# tests/lint-source-graph.sh hub-budget cost", applied here to avoid a
# reverse edge from an engine file up into the module's own driver instead).
# Needed here, unlike reachability_engine.sh's own emitters, because a raw
# banner is TARGET-CONTROLLED bytes (report.md §5.3), never operator-authored
# config like every field reach_emit_not_answering/reach_emit_unexpected_
# listener interpolate - so this file, not just the phase script, must be
# able to sanitize one on its own.
_banner_safe_text() {
  local s=$1 max=${2:-160} out='' i c
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  for (( i = 0; i < ${#s} && i < max; i++ )); do
    c=${s:i:1}
    case $c in
      [[:print:]]) out+=$c ;;
      *) out+='?' ;;
    esac
  done
  (( ${#s} > max )) && out+='...'
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 3. Finding emission
# ---------------------------------------------------------------------------
# The `net` fingerprint location profile (lib/findings.sh, `target host port
# transport`) is unchanged from NET-06's own reach_emit_* functions -
# report.md gives this check no location component of its own to add, and
# there is no need for one: one listener discloses at most one product this
# probe reports (net_banner_identify_text stops at the first hit), so
# (target, host, port) alone already identifies the finding uniquely.
banner_emit_disclosure() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5 product=$6 version=$7 raw=$8
  local what safe_raw evi
  safe_raw=$(_banner_safe_text "$raw" 200)
  if [[ -n $version ]]; then
    what="announces itself as '$product' version '$version'"
  else
    what="announces itself as '$product' (no version disclosed)"
  fi
  evi="Declared listener $scheme://$host:$port (role=$role, config/scope.conf) volunteered a banner without this scan sending any bytes to it: it $what. Raw greeting (truncated, sanitised to printable): $safe_raw"
  finding_new
  finding_set check_id NET-SVC-BANNER_DISCLOSURE-01
  finding_set module net
  finding_set title 'Network service discloses product/version unprompted'
  finding_set base_severity low
  finding_set confidence high
  finding_set cwe CWE-200
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$scheme"
  finding_set corr_target "$target"
  finding_set remediation 'A service greeting that names its own product and exact version lets an attacker select exploits for that product and version without probing for them first. Where the software supports it, suppress or generalise the banner (e.g. an SSH `Banner`/version-string override, an SMTP `smtpd_banner` set to a generic string, an FTP daemon login-message override) so it no longer names the product or the version. This is defence in depth, not a fix on its own: keep the component patched on its own schedule regardless of whether the banner is suppressed.'
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

# `banner_emit_outdated TARGET ROLE SCHEME HOST PORT PRODUCT VERSION` -
# NET-11, the `NET-SVC-OUTDATED_COMPONENT-01` check (report.md §3.2 item 1,
# §3.4, §5.1, §7 Tier 3; docs/VERSIONS-DB.md §3's `banner` namespace).
#
# CALLED ONLY AFTER `banner_db_match PRODUCT VERSION` (modules/dast/passive/
# banner_engine.sh, sourced above) HAS ALREADY RETURNED 0 for this exact
# product@version pair - this function does no lookup of its own and reads
# `_BANNER_ADVISORIES`/`_BANNER_SEVERITY`/`_BANNER_FIXED`/`_BANNER_SUMMARY`/
# `_BANNER_DB_GENERATED`, the globals that call leaves set.  An EXACT match
# against `data/versions.db`'s `banner` namespace, never a range or
# close-enough comparison (report.md §3.4; docs/FOUNDATION.md tension 25
# moved version-range arithmetic onto the networked box that populates that
# file - this scanner only ever does a table lookup).
#
# CONFIDENCE IS ALWAYS `medium`, NEVER `high` - not a per-call choice, a
# frozen property of this finding.  report.md §3.4's own backport problem:
# a version read off a raw TCP banner is the SOFTWARE'S OWN self-reported
# upstream version string, and a distribution that backports a security fix
# (Debian's or RHEL's own openssh package is the report's worked example)
# does so under an UNCHANGED version string, so an exact match against the
# vendored list can name a host that is genuinely already patched. The
# `remediation` field below states that limitation in words on every single
# finding this function emits, not only in this file's own comment - a
# reader of the finding alone, with no access to this source file, must be
# able to see why `confidence: medium` rather than `high` applies here.
#
# THE `net` LOCATION PROFILE (target host port transport) IS UNCHANGED FROM
# `banner_emit_disclosure` ABOVE, carrying no product/version component
# (lib/findings.sh `_fp_components_for net`) - the two checks share no
# fingerprint collision risk because they are two DIFFERENT check ids on the
# same listener, the identical reasoning modules/network/checks-banner.rules'
# own header gives for why disclosure alone needed only one id: one listener
# discloses at most one product per this probe (net_banner_identify_text
# stops at the first identifying line), so (target, host, port) already
# identifies each check's own finding uniquely.
banner_emit_outdated() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5 product=$6 version=$7
  local sev evi
  sev=${_BANNER_SEVERITY:-high}
  evi="Declared listener $scheme://$host:$port (role=$role, config/scope.conf) volunteered a banner identifying '$product' version '$version' without this scan sending any bytes to it, and that exact product@version has a row in the vendored known-vulnerable list at data/versions.db.${_BANNER_ADVISORIES:+ Advisory id(s): ${_BANNER_ADVISORIES}.}${_BANNER_SUMMARY:+ Summary: ${_BANNER_SUMMARY}.}${_BANNER_FIXED:+ Fixed in: ${_BANNER_FIXED}.} That list is an offline snapshot${_BANNER_DB_GENERATED:+ generated ${_BANNER_DB_GENERATED}} and is only as current as its last refresh (docs/VERSIONS-DB.md)."
  finding_new
  finding_set check_id NET-SVC-OUTDATED_COMPONENT-01
  finding_set module net
  finding_set title 'Network service version named in the vendored known-vulnerable list'
  finding_set base_severity "$sev"
  finding_set confidence medium
  finding_set cwe CWE-1104
  finding_set owasp A06:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set cell "${SCOURSH_NET_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_host "$host"
  finding_set loc_port "$port"
  finding_set loc_transport "$scheme"
  finding_set corr_target "$target"
  finding_set remediation 'Upgrade the component on this listener to a release the advisory does not name, or apply the vendor backport for it. Where an upgrade cannot be immediate, put a compensating control in front of the specific weakness the advisory describes and track the upgrade as the remediation rather than treating the control as one. Re-read the running version from the same listener afterwards. The version was read from a raw TCP banner the listener volunteered on connect, not a package manager or an authenticated check, so a distribution that backports a security fix under an unchanged upstream version string (e.g. Debian'"'"'s or RHEL'"'"'s own openssh packages) would not be visible here - confirm the running binary before treating this as a high-confidence claim about it.'
  finding_set_evidence "$evi"
  finding_emit
  return 0
}
