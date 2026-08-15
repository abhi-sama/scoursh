#!/usr/bin/env bash
# lib/http.sh - the scope-gate authorization chokepoint for every network call.
#
# Owns:
#   docs/DESIGN.md    §2, §7 ("the single most important safety control; do
#                      not make it bypassable by raw URL"), §13 step 5
#   docs/FOUNDATION.md tension 19 (scope-gate semantics - the frozen contract
#                      this file implements: entry point, normalization
#                      order, redirect-recheck parity, auditability)
#   docs/FOUNDATION.md tension  9 (a secret is never a command-line argument)
#   docs/FOUNDATION.md tension 26 (config files are data, never sourced)
#
# CONTRACT (tension 19 "Entry point"): `http_request` is the single chokepoint
# every network call in scoursh routes through.  No module, check script, or
# crawler calls `curl`, a language HTTP client, or any other transport
# primitive directly.  tests/lint-shell.sh's "No bypass" check fails the
# build the moment a second path to the network exists (lib/http.sh and the
# documented `modules/dast/passive/tls.sh` exception, which does not exist
# yet, are the only files exempted).
#
# `http_gate_url` is the pure predicate `http_request` gates on.  It is
# exposed separately so tests can exercise the normalization/matching/deny-
# list logic directly, but nothing outside this file and the test suites may
# call it instead of going through `http_request`: it never touches the
# network itself, so calling it alone proves nothing about what a module
# actually sent.
#
# THE SECOND CONTRACT THIS FILE OWNS (docs/FOUNDATION.md tension 16, section
# 11 below): the token-bucket rate limiter, the per-run request budget, and
# the circuit breaker.  They are shared cross-process state in mutex-guarded
# files, layered on top of this chokepoint rather than being part of the
# authorization gate itself, and http_request is the only place they hook in -
# for the same reason the gate lives there.  See section 11's own header.
#
# STILL DELIBERATELY NOT IN THIS FILE: the own-your-target affirmation that
# RAISES those limits (docs/STEP5-DAST-PLAN.md, DAST-32).  Section 11's
# `_http_effective_limit_set` and `_http_effective_rps_milli_set` are the seam
# it fills in; nothing else reads config_scanner_value for a limit.  IDN
# (A-label) conversion is also not implemented - hosts are compared as
# authored/discovered bytes, lowercased - which is a real, known gap for a
# homograph-style bypass and is tracked separately rather than silently
# dropped (see the ticket filed alongside that change).
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/URL syntax literally.
# SC2119/SC2120: http_scope_load takes an optional path override
#   (rules/RULE-FORMAT.md's config/scope.conf default), but every call SITE
#   inside this file (http_scope_match, http_gate_url) intentionally uses the
#   default and calls it bare; the argument form is exercised from
#   tests/suites/http.sh ("http_scope_load $FIXTURE_SCOPE"), which shellcheck's
#   per-file call graph does not see. Measured: ShellCheck 0.11.0 (this repo's
#   pinned local version) does not flag this; the version CI's `apt-get
#   install shellcheck` resolves does. Per AGENTS.md's "measured, not assumed"
#   convention, the finding is silenced with its reason rather than left to
#   depend on which ShellCheck build happens to run.
# shellcheck disable=SC2016,SC2119,SC2120

if [[ -n ${SCOURSH_HTTP_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_HTTP_SOURCED=1

# shellcheck source=lib/config.sh
source "${BASH_SOURCE[0]%/*}/config.sh"
# shellcheck source=lib/findings.sh
source "${BASH_SOURCE[0]%/*}/findings.sh"

# ---------------------------------------------------------------------------
# 1. Percent-decoding, userinfo-stripping, and bracket-aware host/port
#    splitting (normalization steps 1-2) now live in lib/findings.sh as
#    scope_split_authority - see the ADR comment above _host_of_url there.
#    They moved out of this file because attribution_load (lib/findings.sh)
#    must produce the IDENTICAL split this file's http_url_normalize does
#    (tension 19: attribution and the gate must never disagree on what a
#    scope.conf host STRING means), and lib/findings.sh cannot depend on
#    THIS file: cloud-only runs source lib/findings.sh and never
#    lib/http.sh, and http.sh already sources findings.sh, never the
#    reverse.  http_url_normalize below calls the shared function and then
#    layers its OWN numeric-literal canonicalization (this section and the
#    next) on top - that part stays here because it is gate-only SSRF
#    hardening a correlation-only lookup does not need.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 2. Numeric IPv4 literal canonicalization (normalization step 3)
# ---------------------------------------------------------------------------
# Every numeric token this file ever evaluates arithmetically is matched
# against a `^...$`-anchored digit-only regex FIRST.  That match is the actual
# safety boundary, not the base-prefixed `$(( ))` that follows it: bash
# arithmetic expansion recursively expands its operand, so handing a raw,
# attacker-controlled string (a crawled URL, a Location header) to `$(( ))`
# without first proving it contains nothing but digits would be an arithmetic-
# injection vector, not just a parsing bug.  Every conversion below reads a
# variable that a `[[ =~ ^...$ ]]` match has already fully consumed.
_http_ipv4_part_value() {
  local tok=$1 v
  if [[ $tok =~ ^0[xX][0-9A-Fa-f]{1,8}$ ]]; then
    v=$(( 16#${tok:2} ))
  elif [[ $tok =~ ^0[0-7]{1,11}$ ]]; then
    v=$(( 8#${tok:1} ))
  elif [[ $tok =~ ^(0|[1-9][0-9]{0,9})$ ]]; then
    v=$(( 10#$tok ))
  else
    return 1
  fi
  printf '%s' "$v"
}

# Accepts 1-4 dot-separated parts, each decimal/octal(leading 0)/hex(0x...),
# with classic inet_aton semantics: for N<4 parts the LAST part absorbs the
# remaining low-order bytes.  Prints the canonical dotted-quad on success;
# returns 1 for anything that is not a numeric IPv4 literal (in particular,
# any ordinary hostname, which can never match the all-digit part grammar).
_http_canon_ipv4() {
  local tok=$1
  local part_re='(0[xX][0-9A-Fa-f]{1,8}|0[0-7]{1,11}|0|[1-9][0-9]{0,9})'
  [[ $tok =~ ^${part_re}(\.${part_re}){0,3}$ ]] || return 1
  local -a parts=()
  local IFS=.
  read -r -a parts <<<"$tok"
  local n=${#parts[@]}
  local -a vals=()
  local p v
  for p in "${parts[@]+"${parts[@]}"}"; do
    v=$(_http_ipv4_part_value "$p") || return 1
    vals+=("$v")
  done
  local addr
  case $n in
    1)
      (( vals[0] <= 4294967295 )) || return 1
      addr=${vals[0]}
      ;;
    2)
      (( vals[0] <= 255 && vals[1] <= 16777215 )) || return 1
      addr=$(( (vals[0] << 24) | vals[1] ))
      ;;
    3)
      (( vals[0] <= 255 && vals[1] <= 255 && vals[2] <= 65535 )) || return 1
      addr=$(( (vals[0] << 24) | (vals[1] << 16) | vals[2] ))
      ;;
    4)
      (( vals[0] <= 255 && vals[1] <= 255 && vals[2] <= 255 && vals[3] <= 255 )) || return 1
      addr=$(( (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3] ))
      ;;
    *) return 1 ;;
  esac
  printf '%d.%d.%d.%d' $(( (addr >> 24) & 255 )) $(( (addr >> 16) & 255 )) \
    $(( (addr >> 8) & 255 )) $(( addr & 255 ))
}

# ---------------------------------------------------------------------------
# 3. IPv6 literal handling: loopback/link-local/ULA detection and the two
#    documented embedded-IPv4 forms (IPv4-mapped and IPv4-compatible).
# ---------------------------------------------------------------------------
# This is a deliberately narrow, testable subset - exact ::1, the fe80::/10
# and fd00::/8 prefixes by leading-hextet pattern, and the two embedded-IPv4
# shapes tension 19 names by example - rather than a general RFC 4291/5952
# canonicalizer.  A full general IPv6 CIDR matcher is real, out-of-scope work
# (filed as a follow-up); this covers every IPv6 case this ticket's contract
# text names and fails CLOSED (treated as opaque, non-numeric) on anything
# else, which a scope-tuple compare then simply will not match.
_http_ipv6_extract_v4() {
  local tok=${1,,}
  if [[ $tok =~ ^::ffff:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$ ]] \
    || [[ $tok =~ ^::([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$ ]]; then
    _http_canon_ipv4 "${BASH_REMATCH[1]}"
    return
  fi
  if [[ $tok =~ ^::(ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$ ]]; then
    local hi lo
    hi=$(( 16#${BASH_REMATCH[2]} ))
    lo=$(( 16#${BASH_REMATCH[3]} ))
    (( hi <= 65535 && lo <= 65535 )) || return 1
    printf '%d.%d.%d.%d' $(( (hi >> 8) & 255 )) $(( hi & 255 )) \
      $(( (lo >> 8) & 255 )) $(( lo & 255 ))
    return 0
  fi
  return 1
}

_http_ipv6_denied() {
  local tok=${1,,}
  tok=${tok#\[}
  tok=${tok%\]}
  [[ $tok == '::1' ]] && return 0
  [[ $tok =~ ^fe[89ab][0-9a-f]: ]] && return 0   # fe80::/10
  [[ $tok =~ ^fd[0-9a-f]{2}: ]] && return 0       # fd00::/8
  local v4
  if v4=$(_http_ipv6_extract_v4 "$tok"); then
    _http_ipv4_denied "$v4" && return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 4. Resolution-pinning deny list (docs/FOUNDATION.md tension 19)
# ---------------------------------------------------------------------------
# 127.0.0.0/8, 169.254.0.0/16 (covers 169.254.169.254), 100.64.0.0/10,
# 0.0.0.0/8.  ::1, fe80::/10, fd00::/8 and the IPv4-embedded forms of the
# IPv4 ranges above are handled by _http_ipv6_denied.
_http_ipv4_denied() {
  local ip=$1 a b c d addr
  local IFS=.
  read -r a b c d <<<"$ip"
  [[ $a =~ ^[0-9]{1,3}$ && $b =~ ^[0-9]{1,3}$ && $c =~ ^[0-9]{1,3}$ && $d =~ ^[0-9]{1,3}$ ]] || return 1
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  addr=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  local -a bases=(0 0x7F000000 0xA9FE0000 0x64400000)
  local -a bits=(8 8 16 10)
  local i base mask
  for i in 0 1 2 3; do
    base=${bases[i]}
    mask=$(( (0xFFFFFFFF << (32 - bits[i])) & 0xFFFFFFFF ))
    if (( (addr & mask) == (base & mask) )); then
      return 0
    fi
  done
  return 1
}

_http_default_port() {
  case $1 in
    https) printf '443' ;;
    http) printf '80' ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 5. URL normalization (docs/FOUNDATION.md tension 19 "Normalization order")
# ---------------------------------------------------------------------------
# One function, run exactly once per URL, in the fixed order the contract
# specifies: percent-decode the authority (once) -> split off and discard
# userinfo -> canonicalize a numeric host -> lowercase and strip one trailing
# dot.  A caller cannot invoke a subset of these steps: they are not separate
# call sites.
#
# On success, sets (and only ever reads back through these names):
#   _HN_SCHEME  _HN_HOST  _HN_PORT  _HN_PATH
#   _HN_HAD_USERINFO (true/false)   _HN_IS_LITERAL (true/false: numeric host)
# and returns 0.  Returns 1 for anything that is not a well-formed http(s)
# URL; the globals are then unreliable and must not be read.
http_url_normalize() {
  local url=$1
  _HN_SCHEME='' _HN_HOST='' _HN_PORT='' _HN_PATH=''
  _HN_HAD_USERINFO=false _HN_IS_LITERAL=false

  [[ $url =~ ^([A-Za-z][A-Za-z0-9+.-]*):// ]] || return 1
  local scheme=${BASH_REMATCH[1],,}
  case $scheme in
    http | https) ;;
    *) return 1 ;;
  esac

  local rest=${url#*://} authority path
  if [[ $rest =~ ^([^/?#]*)(.*)$ ]]; then
    authority=${BASH_REMATCH[1]}
    path=${BASH_REMATCH[2]}
  else
    authority=$rest
    path=''
  fi
  [[ -n $path ]] || path='/'
  [[ -n $authority ]] || return 1

  # Steps 1-2: percent-decode the authority (once), strip userinfo (up to
  # the LAST '@' per RFC 3986 - never placed on the wire: `http://allowed@
  # evil/` names host `evil`), and split a bracket-aware host/port.  This is
  # scope_split_authority (lib/findings.sh), shared with attribution_load so
  # the two can never disagree on what a scope.conf host STRING means - see
  # the ADR above _host_of_url there.  _SAH_HOST comes back already
  # lowercased and trailing-dot-stripped (_normalise_host).
  scope_split_authority "$authority" || return 1
  local host=$_SAH_HOST port=$_SAH_PORT
  local had_userinfo=$_SAH_HAD_USERINFO is_v6=$_SAH_BRACKETED

  if [[ -n $port ]]; then
    [[ $port =~ ^[0-9]{1,5}$ ]] || return 1
    port=$(( 10#$port ))
    (( port >= 1 && port <= 65535 )) || return 1
  else
    port=$(_http_default_port "$scheme") || return 1
  fi

  # Steps 3-4: canonicalize a numeric host, else keep the already-normalised
  # host scope_split_authority produced.  Gate-only SSRF hardening: a
  # correlation-only lookup (attribution_load) has no need of it, which is
  # why it stays here rather than folding into the shared function.
  local canon_host is_literal=false
  if [[ $is_v6 == true ]]; then
    # Step 3 applies to IPv6 too: an IPv4-mapped or IPv4-compatible literal
    # canonicalizes to the SAME dotted-quad the deny list and the scope-tuple
    # compare both use, "not just to the outcome of a lookup" (tension 19).
    # Anything else stays an (already-lowercased) opaque IPv6 literal.
    local v4
    if v4=$(_http_ipv6_extract_v4 "$host"); then
      canon_host=$v4
    else
      canon_host=$host
    fi
    is_literal=true
  elif canon_host=$(_http_canon_ipv4 "$host"); then
    is_literal=true
  else
    canon_host=$host
  fi

  _HN_SCHEME=$scheme
  _HN_HOST=$canon_host
  _HN_PORT=$port
  _HN_PATH=$path
  _HN_HAD_USERINFO=$had_userinfo
  _HN_IS_LITERAL=$is_literal
  return 0
}

# ---------------------------------------------------------------------------
# 6. The scope-tuple set, built from config/scope.conf
# ---------------------------------------------------------------------------
declare -a _HTTP_SCOPE_ID=() _HTTP_SCOPE_SCHEME=() _HTTP_SCOPE_HOST=() \
  _HTTP_SCOPE_PORT=() _HTTP_SCOPE_SUBS=() _HTTP_SCOPE_PRIV=()
_HTTP_SCOPE_LOADED=0

_http_scope_add() {
  _HTTP_SCOPE_ID+=("$1")
  _HTTP_SCOPE_SCHEME+=("$2")
  _HTTP_SCOPE_HOST+=("$3")
  _HTTP_SCOPE_PORT+=("$4")
  _HTTP_SCOPE_SUBS+=("$5")
  _HTTP_SCOPE_PRIV+=("$6")
}

# Every scope.conf host (base-url and each extra-host) is put through the
# IDENTICAL http_url_normalize pipeline a request URL is, so an operator
# authoring `EXAMPLE.COM` and a request arriving for `example.com` are the
# same tuple.  extra-host has no scheme of its own (rules/RULE-FORMAT.md
# §9.4); it inherits the target's base-url scheme.
http_scope_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  _HTTP_SCOPE_ID=() _HTTP_SCOPE_SCHEME=() _HTTP_SCOPE_HOST=()
  _HTTP_SCOPE_PORT=() _HTTP_SCOPE_SUBS=() _HTTP_SCOPE_PRIV=()
  _HTTP_SCOPE_LOADED=1
  config_scope_load "$path" || return 0

  local n i id url subs priv scheme h
  n=$(records_count scope)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id scope "$i")
    url=$(records_field scope "$i" base-url)
    subs=$(records_field_or scope "$i" allow-subdomains false)
    priv=$(records_field_or scope "$i" allow-private-addresses false)
    if ! http_url_normalize "$url"; then
      log_warn "config/scope.conf: target '$id' has an unparseable base-url, skipping: $url"
      continue
    fi
    scheme=$_HN_SCHEME
    _http_scope_add "$id" "$_HN_SCHEME" "$_HN_HOST" "$_HN_PORT" "$subs" "$priv"
    while IFS= read -r h; do
      [[ -n $h ]] || continue
      if http_url_normalize "$scheme://$h"; then
        _http_scope_add "$id" "$_HN_SCHEME" "$_HN_HOST" "$_HN_PORT" "$subs" "$priv"
      else
        log_warn "config/scope.conf: target '$id' has an unparseable extra-host, skipping: $h"
      fi
    done <<<"$(records_list scope "$i" extra-host)"
  done
}

# `http_scope_match SCHEME HOST PORT` - the normalised (scheme, host, port)
# tuple compare (docs/FOUNDATION.md tension 19 "What the gate matches"),
# including the one documented relaxation (an https target also authorises
# http on port 80 for the same host) and allow-subdomains.  Sets
# _HTTP_MATCH_ID and _HTTP_MATCH_ALLOW_PRIVATE on a match.
http_scope_match() {
  local scheme=$1 host=$2 port=$3
  (( _HTTP_SCOPE_LOADED )) || http_scope_load
  _HTTP_MATCH_ID='' _HTTP_MATCH_ALLOW_PRIVATE=false
  local i n=${#_HTTP_SCOPE_ID[@]}
  local s_scheme s_host s_port s_subs s_priv relaxed subdomain
  for (( i = 0; i < n; i++ )); do
    s_scheme=${_HTTP_SCOPE_SCHEME[i]} s_host=${_HTTP_SCOPE_HOST[i]}
    s_port=${_HTTP_SCOPE_PORT[i]} s_subs=${_HTTP_SCOPE_SUBS[i]} s_priv=${_HTTP_SCOPE_PRIV[i]}

    relaxed=false
    [[ $scheme == http && $port == 80 && $s_scheme == https ]] && relaxed=true

    subdomain=false
    [[ $s_subs == true && $host == *".$s_host" ]] && subdomain=true

    if { [[ $host == "$s_host" ]] || $subdomain; } \
      && { { [[ $scheme == "$s_scheme" && $port == "$s_port" ]]; } || $relaxed; }; then
      _HTTP_MATCH_ID=${_HTTP_SCOPE_ID[i]}
      [[ $s_priv == true ]] && _HTTP_MATCH_ALLOW_PRIVATE=true
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 7. DNS resolution, pinned once per (worker) run and cached by host
# ---------------------------------------------------------------------------
# Swappable via SCOURSH_HTTP_RESOLVE (a function name) so tests never touch a
# real resolver - consistent with the no-egress testing rule (docs/DESIGN.md
# §12: DAST logic is tested against recorded mock responses, not a live
# target).
_http_resolve_default() {
  local host=$1 out=''
  if _have getent; then
    out=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
  elif _have dscacheutil; then
    out=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/{print $2; exit}')
  elif _have host; then
    out=$(host -t A "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
  elif _have dig; then
    out=$(dig +short A "$host" 2>/dev/null | awk 'NR==1')
  fi
  [[ -n $out ]] || return 1
  printf '%s' "$out"
}

declare -A _HTTP_RESOLVE_CACHE=()

http_resolve_host() {
  local host=$1
  if [[ -n ${_HTTP_RESOLVE_CACHE[$host]+set} ]]; then
    printf '%s' "${_HTTP_RESOLVE_CACHE[$host]}"
    return 0
  fi
  local addr
  addr=$("${SCOURSH_HTTP_RESOLVE:-_http_resolve_default}" "$host") || return 1
  _HTTP_RESOLVE_CACHE[$host]=$addr
  printf '%s' "$addr"
}

# ---------------------------------------------------------------------------
# 8. Auditability (docs/FOUNDATION.md tension 19 "Auditability")
# ---------------------------------------------------------------------------
# A caught bypass attempt is not a silent abort: it is always logged, and -
# when a run is active - recorded as a finding via the SAME finding pipeline
# every other check uses, with the raw and canonicalized values going through
# finding_set_evidence (tension 9: redacted, so a userinfo credential in the
# rejected URL never lands in the report in the clear).
_http_gate_audit() {
  local raw_url=$1 canon=$2 reason=$3 method=${4:-GET} target=${5:-}
  log_warn "scope gate rejected $method $raw_url: $reason"
  [[ -n ${SCOURSH_RUN_DIR:-} ]] || return 0
  finding_new
  finding_set check_id 'DAST-SCOPE-GATE-VIOLATION'
  finding_set module dast
  finding_set title 'DAST scope gate rejected an out-of-scope network target'
  finding_set base_severity high
  finding_set cwe CWE-918
  finding_set owasp A10:2021
  finding_set confidence high
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set remediation 'Add the host to config/scope.conf if it is genuinely authorised for this scan. If this fired unexpectedly, treat it as a possible SSRF/redirect probe against the scanner and investigate the target that produced the URL.'
  finding_set loc_target "${target:-unattributed}"
  finding_set loc_method "$method"
  finding_set loc_path_template "$canon"
  finding_set loc_param_location url
  finding_set_evidence "reason=$reason raw=$raw_url canonical=$canon"
  finding_emit
}

# ---------------------------------------------------------------------------
# 9. The gate predicate
# ---------------------------------------------------------------------------
# `http_gate_url URL [TARGET_ID]` runs the full tension-19 pipeline: normalize
# -> reject userinfo -> match the scope tuple set -> resolve (or take the
# literal) and check the resolution-pinning deny list.  Returns 0 (allowed)
# or 1 (denied, with _HTTP_GATE_REASON set).  Never touches the network.
#
# On return, _HN_SCHEME/_HN_HOST/_HN_PORT/_HN_PATH/_HN_IS_LITERAL describe
# THIS call's URL.  http_scope_load (called lazily below) also calls
# http_url_normalize, once per scope.conf entry, which would otherwise
# clobber those same globals out from under the caller - the same class of
# "a nested call overwrites shared state" bug this codebase calls out
# elsewhere (occurrence_next, records_index_of_id).  The values are captured
# into locals immediately and re-published before every return.
http_gate_url() {
  local url=$1 target=${2:-}
  _HTTP_GATE_REASON='' _HTTP_GATE_CANON=''

  if ! http_url_normalize "$url"; then
    _HTTP_GATE_REASON='malformed URL, or a scheme other than http/https'
    return 1
  fi
  local scheme=$_HN_SCHEME host=$_HN_HOST port=$_HN_PORT path=$_HN_PATH
  local had_userinfo=$_HN_HAD_USERINFO is_literal=$_HN_IS_LITERAL
  _HTTP_GATE_CANON="$scheme://$host:$port$path"
  # Re-publish now, and again after http_scope_load below: see the comment
  # above this function.
  _HN_SCHEME=$scheme _HN_HOST=$host _HN_PORT=$port _HN_PATH=$path
  _HN_HAD_USERINFO=$had_userinfo _HN_IS_LITERAL=$is_literal

  if [[ $had_userinfo == true ]]; then
    _HTTP_GATE_REASON="URL authority carried userinfo ('user@host'), which is discarded and never compared - the host actually connected to is '$host'"
    return 1
  fi

  (( _HTTP_SCOPE_LOADED )) || http_scope_load
  _HN_SCHEME=$scheme _HN_HOST=$host _HN_PORT=$port _HN_PATH=$path
  _HN_HAD_USERINFO=$had_userinfo _HN_IS_LITERAL=$is_literal

  if ! http_scope_match "$scheme" "$host" "$port"; then
    _HTTP_GATE_REASON="'$scheme://$host:$port' has no entry in config/scope.conf"
    return 1
  fi

  local addr
  if [[ $is_literal == true ]]; then
    addr=$host
  elif ! addr=$(http_resolve_host "$host"); then
    _HTTP_GATE_REASON="DNS resolution failed for '$host'"
    return 1
  fi

  local denied=1
  if [[ $addr == *:* ]]; then
    _http_ipv6_denied "$addr" && denied=0
  else
    _http_ipv4_denied "$addr" && denied=0
  fi
  if (( denied == 0 )) && [[ $_HTTP_MATCH_ALLOW_PRIVATE != true ]]; then
    _HTTP_GATE_REASON="'$host' resolves to '$addr', which is loopback/link-local/private, and target '$_HTTP_MATCH_ID' does not set allow-private-addresses: true"
    return 1
  fi

  return 0
}

# ---------------------------------------------------------------------------
# 10. The transport (curl, invoked ONLY from here)
# ---------------------------------------------------------------------------
# Swappable via SCOURSH_HTTP_TRANSPORT (a function name) so the redirect-loop
# and gate-recheck logic in http_request is fully testable with no network,
# per docs/DESIGN.md §12.  Contract: METHOD SCHEME HOST PORT PATH ADDR on
# stdin/argv; on success prints exactly two lines to stdout (status code,
# then Location header value or an empty line) and returns 0; a transport-
# level failure returns non-zero.
_http_transport_default() {
  local method=$1 scheme=$2 host=$3 port=$4 path=$5 addr=$6
  require_cmd curl
  local hdrfile
  hdrfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/http-hdr.XXXXXX")
  local timeout=${SCOURSH_HTTP_TIMEOUT:-20}
  # --max-redirs 0, never -L: the manual, one-hop-at-a-time loop in
  # http_request is what re-runs the full gate on every hop (tension 19
  # "Redirects" / "Redirect-recheck parity").  --resolve pins the connection
  # to the address the gate itself just approved, closing the TOCTOU window
  # between the gate's resolution and curl's.
  if ! curl --silent --show-error --max-redirs 0 --max-time "$timeout" \
    --resolve "$host:$port:$addr" \
    -o /dev/null -D "$hdrfile" \
    -X "$method" -- "$scheme://$host:$port$path"; then
    rm -f "$hdrfile"
    return 1
  fi
  local status='' location='' line
  while IFS= read -r line; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+\ ([0-9]{3}) ]]; then
      status=${BASH_REMATCH[1]}
      location=''
    elif [[ $line =~ ^[Ll]ocation:\ (.*)$ ]]; then
      location=${BASH_REMATCH[1]}
    fi
  done <"$hdrfile"
  rm -f "$hdrfile"
  printf '%s\n%s\n' "$status" "$location"
}

# ---------------------------------------------------------------------------
# 11. The tension-16 rate limiter, request budget, and circuit breaker
# ---------------------------------------------------------------------------
# All three live HERE, inside the chokepoint, for the same reason the scope
# gate does: a limit a caller can go around is not a limit.
# tests/e2e/dast-target-smoke.sh already sends real HTTP by calling
# http_request directly, with no module and no scan.sh CLI parser anywhere in
# the path, so a throttle that lived in a future modules/dast/ dispatch layer
# would bind exactly the callers that had already come through it and nothing
# else - the property docs/FOUNDATION.md tension 19 states for the gate
# ("callers must not be trusted to apply it") holds identically for a
# throughput ceiling.
#
# All three keep their state in FILES under the run scratch directory, guarded
# by lib/core.sh's atomic-mkdir mutex, which is tension 16's already-frozen
# resolution and shipped at §13 step 1; this section implements the hook, not
# the mutex.  Shell variables are per-process and `xargs -P "$JOBS"` gives N
# independent processes, so a variable-backed limiter admits
# `jobs x requests_per_second`, a variable-backed budget is multiplied by
# `jobs`, and a variable-backed breaker never trips because each worker only
# ever sees its own share of the failures.  That is the entire reason the
# tension exists, and it is what tests/suites/http.sh's cross-process cases
# pin by running real, separate bash processes.
#
# Nothing here is disableable.  docs/STEP5-DAST-PLAN.md makes that explicit
# for the budget ("the number is raisable; the existence of a finite budget is
# not") and for the breaker ("disabling never offered"), so there is no
# environment variable, config key, or flag below that turns any of the three
# off - only ones that can lower a threshold, which moves in the safe
# direction.

_HTTP_LIMIT_MUTEX='http-limits'

# The bucket capacity, in milli-tokens.  Exactly one token: no burst.
# tension 16 freezes "token-bucket" and docs/DESIGN.md §4 freezes the rate,
# but neither names a burst size, so this is a chosen value.  A capacity of
# one makes the configured rate an upper bound over EVERY window rather than
# only over long ones, which is what "scans stay polite and don't DoS the
# target" asks for; a bucket that banks idle time hands the target a burst at
# exactly the moment a crawl finishes thinking.  DAST-28's burst probe is the
# one check that genuinely wants a burst, and docs/STEP5-DAST-PLAN.md already
# routes it through the own-your-target affirmation rather than through a
# larger default bucket here.
_HTTP_BUCKET_CAPACITY_MILLI=1000

# EVERY resolution helper in this section SETS a variable rather than printing
# one, and none of them may be called through `$(...)`.
#
# Two reasons, and the first is a correctness one.  `die` inside a command
# substitution runs in a subshell, so its `trap - ERR` clears the SUBSHELL's
# trap; the parent's trap then fires on the failed assignment and prints a
# crash-shaped "command failed" diagnostic on top of the real refusal, and in a
# checked context the abort is swallowed outright.  scan.sh already carries an
# explicit guard and a long comment about exactly this, and reading four limits
# per request through `$(...)` added four more such sites.  The second reason is
# that it also removes four forks from the path every single request takes -
# the same reasoning `worker_id_set` and `_lock_owner_line_set` are written for.
# `core_capture` (lib/core.sh) is how the one remaining value that comes from a
# die-capable accessor, `config_scanner_value`, is read without a subshell.

# Milli-units throughout, because `requests-per-second` is a decimal
# (rules/RULE-FORMAT.md §9.6.1 allows `0.5`) and bash has no floating point.
# 1 token = 1000 milli-tokens; a rate of R requests/second refills
# `R * 1000` milli-tokens per second, i.e. `rps_milli` of them.
#
# Sets `_HTTP_RPS_MILLI`.  Returns 1 (rather than truncating) for an integer
# part longer than 9 digits: the only value that can produce one has already
# passed the schema's shape check, so it is an absurd-but-well-formed number,
# and the caller reads a refusal as "far above any ceiling" instead of handing
# `$(( ))` an operand that would silently wrap a 64-bit integer.
_HTTP_RPS_RESOLUTION_MILLI=1
_http_rps_milli_set() {
  local v=$1 int frac
  _HTTP_RPS_MILLI=0
  [[ $v =~ ^([0-9]+)(\.([0-9]+))?$ ]] || return 1
  int=${BASH_REMATCH[1]}
  frac=${BASH_REMATCH[3]:-0}
  (( ${#int} <= 9 )) || return 1
  while (( ${#frac} < 3 )); do frac="${frac}0"; done
  frac=${frac:0:3}
  _HTTP_RPS_MILLI=$(( 10#$int * 1000 + 10#$frac ))
  return 0
}

# True when $1 is a decimal literal whose value is exactly zero, so a rate that
# rounds to nothing at this resolution can be told apart from one the operator
# genuinely set to zero.  `0`, `0.0` and `0.000` are zero; `0.0005` is not.
_http_decimal_is_zero() {
  [[ $1 =~ ^0+(\.0+)?$ ]]
}

# The conservative module ceilings (docs/STEP5-DAST-PLAN.md, "The conservative
# defaults, and the one place they are enforced").  They are applied to the
# RESOLVED value, here beside the limiter, so a caller that never went through
# scan.sh's parser - the smoke test, a future tool, an interactive
# `source lib/http.sh` - inherits the safe number rather than an unbounded one.
#
# DAST-32 owns the own-your-target affirmation that RAISES these, and this
# function is the seam it fills in.  That is why nothing below ever calls
# config_scanner_value directly: docs/STEP5-DAST-PLAN.md's own DAST-01
# amendment requires the limiter, budget and breaker to read an EFFECTIVE
# value, "or DAST-32 becomes a retrofit".  Until it lands there is no
# affirmation record to read, so the ceiling always applies.
#
# Two of the four clamp in opposite directions, which is worth stating rather
# than rediscovering: a HIGHER rate, a HIGHER budget and a HIGHER failure
# threshold each mean more traffic to a host this repository's authors cannot
# vet, so those clamp DOWN; a SHORTER breaker window counts fewer failures
# towards the same threshold, weakening the breaker, so that one clamps UP.
# Every clamp leaves the effective behaviour at least as conservative as the
# shipped default.
#
# Sets `_HTTP_LIMIT_CEIL`; returns 1 for a key with no ceiling defined.
_http_limit_ceiling_set() {
  case $1 in
    requests-per-second) _HTTP_LIMIT_CEIL=4 ;;
    request-budget) _HTTP_LIMIT_CEIL=5000 ;;
    circuit-breaker-failures) _HTTP_LIMIT_CEIL=10 ;;
    circuit-breaker-window) _HTTP_LIMIT_CEIL=60 ;;
    *) _HTTP_LIMIT_CEIL=''; return 1 ;;
  esac
  return 0
}

# The breaker window is the one key whose ceiling above is a FLOOR, and it
# therefore needs a second bound at the other end - which it did not have.
#
# Unbounded, a schema-valid value wider than a 64-bit integer reached
# `cutoff=$(( now - window ))` in `_http_breaker_record_failure`.  Bash wraps
# the oversized literal rather than failing, and for a value such as 10^19 the
# wrapped cutoff lands in the FUTURE: every stored failure stamp then prunes as
# out-of-window on every call, the count never reaches the threshold, and the
# breaker never opens.  One config key would have switched off the control that
# this section states in as many words is not disableable.
#
# A day, rather than the integer maximum, because the argument is operational
# rather than arithmetic: a rolling window longer than any plausible run is
# indistinguishable from one that never expires, so nothing is lost by capping
# it there, and the arithmetic is left far inside what it can hold.  The bound
# is applied with the same length-safe comparison the other three keys use,
# because the whole point is that the value cannot be trusted to fit.
_HTTP_BREAKER_WINDOW_MAX=86400

# Non-negative decimal-integer compare that cannot wrap: a value with more
# digits than a 64-bit integer holds is compared by LENGTH, because `$(( ))`
# on a 25-digit literal silently produces a different number instead of
# failing, and the operand here came out of a config file.
# Sets `_HTTP_INT_CMP` to -1, 0 or 1.
_http_int_cmp_set() {
  local a=$1 b=$2
  while (( ${#a} > 1 )) && [[ ${a:0:1} == 0 ]]; do a=${a:1}; done
  while (( ${#b} > 1 )) && [[ ${b:0:1} == 0 ]]; do b=${b:1}; done
  if (( ${#a} != ${#b} )); then
    if (( ${#a} > ${#b} )); then _HTTP_INT_CMP=1; else _HTTP_INT_CMP=-1; fi
    return 0
  fi
  if [[ $a == "$b" ]]; then
    _HTTP_INT_CMP=0
  elif [[ $a > $b ]]; then
    _HTTP_INT_CMP=1
  else
    _HTTP_INT_CMP=-1
  fi
  return 0
}

# One warning per RUN, not per worker: the clamp is a fact about the run, and
# eight `xargs -P` workers each printing it would bury it.  The marker is a
# directory because `mkdir` is atomic, which is the same primitive the mutex
# itself is built on.
#
# It warns ONLY when the operator actually asked for the value being refused.
# `request-budget`'s schema default is 20000 and its DAST ceiling is 5000, so a
# warning on any clamp fired on every run of an install with no config file at
# all, and told the operator that a config they never wrote was out of bounds -
# which contradicts docs/STEP5-DAST-PLAN.md's own stated intent that an
# unedited config produces no warning, and makes the one case the warning
# exists for (a RAISED value) indistinguishable from the shipped default.  A
# file value equal to the built-in default is treated the same as the default,
# because it asks for exactly what an absent file asks for.  The effective
# numbers are still stated every run, as an informational line naming what the
# limiter will use rather than a warning naming what it refused; see
# `_http_limit_announce_once`.
#
# `_scanner_default` is lib/config.sh's own §9.6.1 default table.  Copying its
# numbers here instead would be a second source of truth for the one fact this
# test needs, and they would drift; a public accessor for it belongs in
# lib/config.sh when that file is next touched.
_http_limit_warn_clamp() {
  local key=$1 raw=$2 eff=$3 def=''
  core_capture def _scanner_default "$key" || def=''
  [[ $raw != "$def" ]] || return 0
  _http_limit_dir_set
  _http_limit_slug_set "$key"
  if mkdir "$_HTTP_LIMIT_DIR/warned.$_HTTP_SLUG" 2>/dev/null; then
    log_warn "config '$key' is $raw, outside the conservative DAST limit for a host this scan cannot vouch for; using $eff for this run (docs/STEP5-DAST-PLAN.md, 'Safety defaults and authorisation')"
  fi
  return 0
}

# `_http_effective_limit_set KEY` - sets `_HTTP_EFF_LIMIT` to the resolved,
# clamped integer value.  The rate has its own accessor below because it is the
# one decimal key.
_http_effective_limit_set() {
  local key=$1 raw ceil eff
  _http_limit_ceiling_set "$key" \
    || die "$SCOURSH_EXIT_INCOMPLETE" "internal: no DAST ceiling defined for '$key'"
  ceil=$_HTTP_LIMIT_CEIL
  core_capture raw config_scanner_value "$key"
  _http_int_cmp_set "$raw" "$ceil"
  eff=$raw
  case $key in
    circuit-breaker-window)
      # A floor (a shorter window is a weaker breaker) AND a maximum, because
      # the value beyond it stops being arithmetic the cutoff can hold.
      [[ $_HTTP_INT_CMP == -1 ]] && eff=$ceil
      _http_int_cmp_set "$eff" "$_HTTP_BREAKER_WINDOW_MAX"
      [[ $_HTTP_INT_CMP == 1 ]] && eff=$_HTTP_BREAKER_WINDOW_MAX
      ;;
    *)
      [[ $_HTTP_INT_CMP == 1 ]] && eff=$ceil        # a bigger number is louder
      ;;
  esac
  [[ $eff == "$raw" ]] || _http_limit_warn_clamp "$key" "$raw" "$eff"
  _HTTP_EFF_LIMIT=$eff
  return 0
}

# The rate, in milli-tokens per second, already clamped.  Sets
# `_HTTP_EFF_RPS_MILLI`.
_http_effective_rps_milli_set() {
  local raw ms ceil_ms=4000
  core_capture raw config_scanner_value requests-per-second
  if ! _http_rps_milli_set "$raw"; then
    # Well-formed per the schema but absurd, so it is certainly above the
    # ceiling; clamping is the honest reading of "above the ceiling".
    _http_limit_warn_clamp requests-per-second "$raw" 4
    _HTTP_EFF_RPS_MILLI=$ceil_ms
    return 0
  fi
  ms=$_HTTP_RPS_MILLI
  if (( ms > ceil_ms )); then
    _http_limit_warn_clamp requests-per-second "$raw" 4
    ms=$ceil_ms
  fi
  if (( ms <= 0 )); then
    # Two different refusals, because they are two different mistakes.
    #
    # A genuinely zero rate means "no requests per second at all".  Waiting
    # forever for a token that can never arrive would look like a hang, so this
    # refuses instead; the plan names no value here, and a floor invented for
    # it would silently send traffic the operator asked not to send.
    #
    # A POSITIVE rate that rounds to zero at this resolution is a different
    # thing entirely: a deliberately very slow scan.  Telling that operator
    # their rate "permits no requests at all" is factually wrong about what
    # they asked for, and the only remedy it offers is to send MORE traffic.
    # Rounding it up to the smallest representable rate would do that for them,
    # silently and without consent, so the refusal names the precision floor
    # and the smallest rate this limiter can actually keep instead.
    if _http_decimal_is_zero "$raw"; then
      die "$SCOURSH_EXIT_INPUT" \
        "requests-per-second is '$raw', which permits no requests at all; set a positive rate or do not run a network module"
    fi
    die "$SCOURSH_EXIT_INPUT" \
      "requests-per-second is '$raw', which is positive but below the limiter's resolution of 0.001 requests per second (one request every 1000 seconds); the smallest supported rate is 0.001, and this run was not started at a rate faster than you asked for"
  fi
  _HTTP_EFF_RPS_MILLI=$ms
  return 0
}

# Filesystem-safe key for a per-target state file.  Scope ids are authored by
# an operator in config/scope.conf, so they are not trusted to be path-safe.
# Sets `_HTTP_SLUG`.
_http_limit_slug_set() {
  local s=$1
  s=${s//[^A-Za-z0-9_.-]/_}
  [[ -n $s ]] || s=unattributed
  _HTTP_SLUG=$s
  return 0
}

# The state root, under the RUN SCRATCH directory (finding F12: the scratch
# directory holds exactly this kind of genuinely transient data, and the
# EXIT-trap ownership guard means a worker never erases it).  Re-checked for
# existence on every call rather than memoised on the variable alone, so the
# directory is rebuilt if it goes away underneath a long run.
_http_limit_dir_set() {
  if [[ -n ${_HTTP_LIMIT_DIR:-} && -d ${_HTTP_LIMIT_DIR:-} ]]; then
    return 0
  fi
  [[ -n ${SCOURSH_SCRATCH:-} ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" "the request limiter needs the run scratch directory, which is not set"
  _HTTP_LIMIT_DIR=$SCOURSH_SCRATCH/http-limits
  mkdir -p "$_HTTP_LIMIT_DIR/rate" "$_HTTP_LIMIT_DIR/breaker" "$_HTTP_LIMIT_DIR/abort" \
    "$_HTTP_LIMIT_DIR/addr"
  _http_limit_warn_coarse_clock
  return 0
}

# The limiter's own capability disclosure, warned once per run at the seam
# every path into it goes through.
#
# On a host with no sub-second clock (`SCOURSH_CLOCK_NS == 0`, lib/core.sh's
# capability probe) `now_epoch_ns` returns whole-second granularity, so the
# capacity-one bucket can only ever observe a refill at a second boundary and
# the effective rate becomes one request per second rather than the configured
# four.  The DIRECTION is safe - a slower scan is never the hazard this section
# guards against - but a run four times slower than its own configuration with
# no stated cause reads as a hang, and an operator who cannot see the reason
# has no way to fix it.  msleep's own one-second floor lands on the same hosts
# and is already warned about by `core_probe_msleep`; this is the limiter's
# half of the same fact.
_http_limit_warn_coarse_clock() {
  (( ${SCOURSH_CLOCK_NS:-0} == 0 )) || return 0
  mkdir "$_HTTP_LIMIT_DIR/warned.clock" 2>/dev/null || return 0
  log_warn "this host has no sub-second clock, so the request limiter can only measure elapsed time in whole seconds: the token bucket refills on a second boundary and the effective request rate is one per second, not the configured rate (docs/FOUNDATION.md tension 24)"
  return 0
}

# The effective numbers, stated once per run as information rather than as a
# warning about a rejected one.  The budget in particular is ALWAYS clamped on
# a default install (schema default 20000, DAST ceiling 5000), and the number
# the limiter will actually keep is worth one line; what is not worth a warning
# is a config the operator never wrote.
#
# The `[[ -d ]]` test in front of the `mkdir` is not redundant: this runs on
# every request, and `mkdir` is an external command, so testing first is the
# difference between one fork per run and one fork per request.  The mkdir is
# still what decides, because it is the part that is atomic between workers.
_http_limit_announce_once() {
  local rps_milli=$1 budget=$2 failures=$3 window=$4
  [[ -d $_HTTP_LIMIT_DIR/announced ]] && return 0
  mkdir "$_HTTP_LIMIT_DIR/announced" 2>/dev/null || return 0
  log_info "request limiter armed for this run: $(( rps_milli / 1000 )).$(printf '%03d' $(( rps_milli % 1000 ))) requests/second, a per-run budget of $budget requests, and a circuit breaker at $failures failed requests within ${window}s (docs/FOUNDATION.md tension 16)"
  return 0
}

# docs/FOUNDATION.md tension 16 freezes ONE BUCKET PER SCOPE TARGET ("rate is a
# politeness property of the target"), and that keying is kept here rather than
# quietly re-decided in code.  It has an unsafe direction the register does not
# state, and this is where the run states it: N scope targets that resolve to
# the SAME address each get their own full bucket, their own budget-free rate
# and their own breaker, so that one host receives N times the configured rate.
# Two hostnames behind one load balancer are two natural scope entries, so this
# is an ordinary configuration rather than an exotic one, and it is the
# opposite of the conservative direction the surrounding clamps move in.
#
# Rather than leave it disclosed only in prose that an operator will not read
# at the moment it applies, the run says so when it becomes true, names the
# address and every target sharing it, and records a `coverage_gap` so run.json
# carries it too.  Whether the bucket should instead be keyed on the resolved
# address is a REGISTER question (it contradicts tension 16's frozen wording),
# and is left for that amendment rather than settled here.
#
# One directory per address, one marker per target under it: `mkdir` is atomic,
# so two workers racing on the same new pair cannot both warn.  The hot path is
# a `[[ -d ]]` test on an already-known pair, which costs no fork.
_http_note_target_address() {
  local bucket=$1 addr=$2 aslug bslug dir p n=0
  # Not spelled `seen`: shellcheck -x follows lib/findings.sh and lib/records.sh
  # from here, each of which has an ASSOCIATIVE local of that name, and then
  # reports SC2190 on the append below.
  local -a sharing=()
  [[ -n $addr && -n $bucket ]] || return 0
  _http_limit_dir_set
  _http_limit_slug_set "$addr"
  aslug=$_HTTP_SLUG
  _http_limit_slug_set "$bucket"
  bslug=$_HTTP_SLUG
  dir=$_HTTP_LIMIT_DIR/addr/$aslug
  [[ -d $dir/$bslug ]] && return 0
  mkdir -p "$dir/$bslug" 2>/dev/null || return 0
  for p in "$dir"/*/; do
    [[ -d $p ]] || continue
    p=${p%/}
    sharing+=("${p##*/}")
    n=$(( n + 1 ))
  done
  (( n > 1 )) || return 0
  # Once per COUNT, not once per address: a third scope target joining an
  # address two others already share triples the rate on it, and a warning
  # that still said "2 times" would understate the very number it exists to
  # state.  Bounded by the number of targets, and the mkdir is what makes two
  # workers discovering the same pair unable to both warn.
  mkdir "$dir.warned.$n" 2>/dev/null || return 0
  log_warn "scope targets [${sharing[*]}] all resolve to $addr, and the rate limiter keeps one bucket PER SCOPE TARGET (docs/FOUNDATION.md tension 16), so that one host receives $n times the configured request rate for this run"
  run_record coverage_gap "rate limiting is per scope target, not per host: targets [${sharing[*]}] all resolve to $addr, so that host received up to $n times the configured requests-per-second (docs/FOUNDATION.md tension 16 freezes one bucket per scope target)"
  return 0
}

# tension 16: "every worker checks for that file before every request and
# exits 5 if present".  It is a plain existence check with no mutex, because
# creation is atomic and the value never changes - the flag only ever goes
# from absent to present, so a racing reader can be stale by one request and
# never wrong.
_http_abort_check() {
  local bucket=$1
  _http_limit_dir_set
  _http_limit_slug_set "$bucket"
  [[ -e $_HTTP_LIMIT_DIR/abort/$_HTTP_SLUG ]] || return 0
  die "$SCOURSH_EXIT_INCOMPLETE" \
    "the circuit breaker is open for target '$bucket'; no further requests are sent to it in this run, so its coverage is incomplete"
}

# The rate limiter and the request budget, in ONE critical section.
#
# tension 16 puts the budget decrement "inside the same critical section as
# the token grant, so one mutex acquisition covers both and the two can never
# disagree" - a run that consumed a token and then failed to record the spend
# would slowly manufacture budget out of a crash.
#
# The wait is computed inside the critical section, the mutex is RELEASED, and
# the sleep happens OUTSIDE it.  Sleeping while holding it would serialise
# every worker behind the slowest wait and destroy the point of --jobs, which
# tension 16 says in as many words.
#
# The sleep is msleep, never `sleep` and never `read -t </dev/null`: finding
# F14 measured that `read -t` on /dev/null returns at EOF instantly, so a
# limiter built on it computes a perfect wait and then does not wait at all,
# and an exit-status probe cannot tell the two apart.  tests/suites/http.sh
# measures elapsed wall clock here for exactly that reason.
#
# The abort flag is re-checked at the top of EVERY iteration, which is to say
# after every sleep, and not only once before the wait.  A worker can be parked
# here for as long as the worker count times the token interval, and that is
# exactly the window in which another worker's breaker opens: checking the flag
# only on the way in meant every worker already queued for a token still sent
# its request, so a comprehensively-down target received threshold plus
# workers-minus-one requests rather than threshold.  The budget check has
# always been inside this loop and is re-evaluated after every sleep, which is
# why the budget is exact; the breaker's flag was the one that was stale-read.
#
# The check sits OUTSIDE the critical section deliberately.  `_http_abort_check`
# dies, and dying while holding the mutex would leave every other worker
# waiting on it until the staleness reclaim fired.
_http_throttle() {
  local bucket=$1 rps_milli=$2 budget=$3
  local slug state_file budget_file now last tokens elapsed need remaining wait_ms

  _http_limit_dir_set
  _http_limit_slug_set "$bucket"
  slug=$_HTTP_SLUG
  state_file=$_HTTP_LIMIT_DIR/rate/$slug.state
  budget_file=$_HTTP_LIMIT_DIR/budget.state

  while :; do
    _http_abort_check "$bucket"
    mutex_acquire "$_HTTP_LIMIT_MUTEX"

    remaining=''
    if [[ -r $budget_file ]]; then
      IFS= read -r remaining <"$budget_file" || true
    fi
    # An absent or unreadable counter means the budget has not been opened
    # yet, never "unlimited": the fallback is the budget itself.
    [[ $remaining =~ ^[0-9]+$ ]] || remaining=$budget
    if (( remaining <= 0 )); then
      mutex_release "$_HTTP_LIMIT_MUTEX"
      die "$SCOURSH_EXIT_INCOMPLETE" \
        "the per-run request budget of $budget requests is exhausted; the run stopped here rather than sending more traffic, so its coverage is incomplete"
    fi

    now=$(now_epoch_ns)
    last='' tokens=''
    if [[ -r $state_file ]]; then
      IFS=' ' read -r last tokens <"$state_file" || true
    fi
    # A fresh bucket starts FULL, so the first request of a run is not
    # delayed; it is the second and later ones that pay the rate.
    [[ $last =~ ^[0-9]+$ ]] || last=$now
    [[ $tokens =~ ^[0-9]+$ ]] || tokens=$_HTTP_BUCKET_CAPACITY_MILLI

    elapsed=$(( now - last ))
    (( elapsed >= 0 )) || elapsed=0
    # Refill by elapsed time, capped at capacity.  Testing "has enough time
    # passed to fill the bucket" BEFORE multiplying is what bounds the
    # arithmetic: in the multiply branch `elapsed` is strictly less than the
    # time to fill one token, so `elapsed * rps_milli` can never exceed
    # 1000 * 1e9 and cannot wrap, however long the process has been idle.
    need=$(( ( (_HTTP_BUCKET_CAPACITY_MILLI - tokens) * 1000000000 + rps_milli - 1 ) / rps_milli ))
    (( need >= 0 )) || need=0
    if (( elapsed >= need )); then
      tokens=$_HTTP_BUCKET_CAPACITY_MILLI
    else
      tokens=$(( tokens + elapsed * rps_milli / 1000000000 ))
    fi

    if (( tokens >= 1000 )); then
      tokens=$(( tokens - 1000 ))
      printf '%s %s\n' "$now" "$tokens" >"$state_file"
      printf '%s\n' "$(( remaining - 1 ))" >"$budget_file"
      mutex_release "$_HTTP_LIMIT_MUTEX"
      return 0
    fi

    printf '%s %s\n' "$now" "$tokens" >"$state_file"
    mutex_release "$_HTTP_LIMIT_MUTEX"
    wait_ms=$(( ( (1000 - tokens) * 1000 + rps_milli - 1 ) / rps_milli ))
    (( wait_ms >= 1 )) || wait_ms=1
    msleep "$wait_ms"
  done
}

# What counts as a failure, stated rather than assumed.  A transport-level
# failure (no usable response at all) and a 5xx.  NOT a 4xx: a 404 is the most
# common response a DAST run gets and is a RESULT, not a fault, so counting it
# would open the breaker on every healthy scan.  429 is deliberately left out
# too - docs/STEP5-DAST-PLAN.md's argument for the breaker is specifically
# that "a target returning sustained 5xx produces no useful findings", and
# whether a throttling target should also trip it is a real question that
# belongs in the register rather than being settled here by a regex.
_http_status_is_failure() {
  local status=$1
  [[ $status =~ ^[1-5][0-9][0-9]$ ]] || return 0
  [[ $status =~ ^5[0-9][0-9]$ ]]
}

# The circuit breaker, per scope target, over a ROLLING WINDOW.
#
# tension 16 freezes "the rolling window counters", and
# docs/STEP5-DAST-PLAN.md states the default as "10 failures in a 60s window",
# so a success does NOT reset the count - which is the one place this differs
# visibly from the consecutive-failures breaker people usually picture, and is
# what tests/suites/http.sh's interleaved-success case pins.  There is
# therefore no success path at all: recording an `ok` would take the mutex on
# every healthy request to change nothing.
#
# Only `closed` and `open` are ever written.  tension 16's sample names a
# `half-open` state, but opening the breaker aborts the run (exit 5) rather
# than pausing it, so no process ever survives to probe a recovery; inventing
# a half-open transition now would be designing past the frozen resolution.
_http_breaker_record_failure() {
  local bucket=$1 threshold=$2 window=$3
  local slug state_file line now cutoff i v count start out
  local -a fields=() kept=() bounded=()

  _http_limit_dir_set
  _http_limit_slug_set "$bucket"
  slug=$_HTTP_SLUG
  state_file=$_HTTP_LIMIT_DIR/breaker/$slug.state
  now=$(now_epoch)
  cutoff=$(( now - window ))

  mutex_acquire "$_HTTP_LIMIT_MUTEX"
  line=''
  if [[ -r $state_file ]]; then
    IFS= read -r line <"$state_file" || true
  fi
  IFS=' ' read -r -a fields <<<"$line" || true

  # fields[0] is the state word; the rest are the failure timestamps still
  # inside the window as of the last update.  They are re-pruned here rather
  # than trusted, because the window has moved since.
  for (( i = 1; i < ${#fields[@]}; i++ )); do
    v=${fields[i]}
    [[ $v =~ ^[0-9]+$ ]] || continue
    (( v >= cutoff )) || continue
    kept+=("$v")
  done
  kept+=("$now")

  # Keep at most `threshold` stamps so one line stays bounded over a long run:
  # anything older than that cannot change the answer.
  count=${#kept[@]}
  start=0
  if (( count > threshold )); then start=$(( count - threshold )); fi
  for (( i = start; i < count; i++ )); do bounded+=("${kept[i]}"); done

  if (( ${#bounded[@]} >= threshold )); then
    out=open
  else
    out=closed
  fi
  for v in "${bounded[@]+"${bounded[@]}"}"; do out+=" $v"; done
  printf '%s\n' "$out" >"$state_file"

  if [[ $out == open* ]]; then
    # The fan-out abort signal (tension 16).  Written before the mutex is
    # released so no worker can take a token against a target that is already
    # decided, and it is what makes the abort reach the OTHER workers: they
    # are separate processes and cannot see this one's return value.
    : >"$_HTTP_LIMIT_DIR/abort/$slug"
    mutex_release "$_HTTP_LIMIT_MUTEX"
    die "$SCOURSH_EXIT_INCOMPLETE" \
      "the circuit breaker opened for target '$bucket': ${#bounded[@]} failed requests within ${window}s (threshold $threshold); the run stopped rather than continuing against a target that is not answering, so its coverage is incomplete"
  fi
  mutex_release "$_HTTP_LIMIT_MUTEX"
  return 0
}

# ---------------------------------------------------------------------------
# 12. http_request - THE chokepoint
# ---------------------------------------------------------------------------
# `http_request METHOD URL [MAX_REDIRECTS] [TARGET_ID]`.
#
# The initial URL is gated FATALLY: a caller only ever reaches http_request
# with a URL it believes is authorised, so a rejection here means either a
# caller bug or an actual bypass attempt, and docs/DESIGN.md's exit-code
# table makes that exit 3 ("scope violation"), matching config_scope_require
# (lib/config.sh) - the two never disagree about what a scope violation costs
# a run.  A redirect hop's Location is gated NON-fatally (tension 19: "An
# out-of-scope Location is not followed and is recorded"): the loop stops and
# returns the last in-scope response instead of aborting the whole run over a
# link the SCANNED SITE chose, not the operator.
#
# Sets _HTTP_LAST_STATUS.  Never calls curl (or any transport) for a URL that
# has not just passed http_gate_url.
# The tension-16 controls sit between the gate and the transport, and inside
# the redirect loop rather than ahead of it: a followed hop is a real request
# and pays a real token, a real unit of budget, and a real breaker outcome.
# `_HTTP_MATCH_ID` is the scope target the gate matched, and it is
# re-established on every hop because the hop re-runs the full gate - so a
# redirect that crosses from one in-scope target to another draws down the
# second target's bucket, which is what "rate is a politeness property of the
# target" means.
http_request() {
  local method=$1 url=$2 max_redirects=${3:-5} target=${4:-}
  local cur=$url hop=0 addr out status location bucket
  local rps_milli budget breaker_failures breaker_window

  if ! http_gate_url "$cur" "$target"; then
    _http_gate_audit "$cur" "${_HTTP_GATE_CANON:-$cur}" "$_HTTP_GATE_REASON" "$method" "$target"
    die "$SCOURSH_EXIT_SCOPE" "scope gate refused $method $cur: $_HTTP_GATE_REASON"
  fi

  # Resolved once per call rather than once per hop or per retry: the values
  # cannot change inside one request.  Deliberately AFTER the gate, so a scope
  # violation is still exit 3 even on a run whose scanner config is also
  # unusable - the two never trade places.  Each accessor SETS a variable
  # rather than printing one; see the note above `_http_rps_milli_set` for why
  # reading these through `$(...)` was both wrong and expensive.
  _http_effective_rps_milli_set
  rps_milli=$_HTTP_EFF_RPS_MILLI
  _http_effective_limit_set request-budget
  budget=$_HTTP_EFF_LIMIT
  _http_effective_limit_set circuit-breaker-failures
  breaker_failures=$_HTTP_EFF_LIMIT
  _http_effective_limit_set circuit-breaker-window
  breaker_window=$_HTTP_EFF_LIMIT
  _http_limit_dir_set
  _http_limit_announce_once "$rps_milli" "$budget" "$breaker_failures" "$breaker_window"

  while :; do
    bucket=${_HTTP_MATCH_ID:-unattributed}
    _http_abort_check "$bucket"
    _http_throttle "$bucket" "$rps_milli" "$budget"
    # Again after the wait returns and before anything is sent.  The throttle
    # re-checks after every sleep, but a token granted at the same instant
    # another worker opens the breaker would otherwise still be spent on a
    # request to a target the run has already decided to stop talking to.
    _http_abort_check "$bucket"

    if [[ $_HN_IS_LITERAL == true ]]; then
      addr=$_HN_HOST
    elif ! addr=$(http_resolve_host "$_HN_HOST"); then
      die "$SCOURSH_EXIT_SCOPE" "scope gate: DNS resolution failed for '$_HN_HOST' after the gate had approved it"
    fi
    _http_note_target_address "$bucket" "$addr"

    if ! out=$("${SCOURSH_HTTP_TRANSPORT:-_http_transport_default}" \
      "$method" "$_HN_SCHEME" "$_HN_HOST" "$_HN_PORT" "$_HN_PATH" "$addr"); then
      # No usable response at all, which is the strongest evidence the breaker
      # gets; it is recorded before the failure is returned, so a caller that
      # swallows the non-zero status cannot also swallow the breaker.
      _http_breaker_record_failure "$bucket" "$breaker_failures" "$breaker_window"
      return 1
    fi
    status=${out%%$'\n'*}
    location=${out#*$'\n'}
    location=${location%$'\n'}

    if _http_status_is_failure "$status"; then
      _http_breaker_record_failure "$bucket" "$breaker_failures" "$breaker_window"
    fi

    if [[ $status =~ ^3[0-9][0-9]$ && -n $location ]] && (( hop < max_redirects )); then
      hop=$(( hop + 1 ))
      cur=$location
      if ! http_gate_url "$cur" "$target"; then
        _http_gate_audit "$cur" "${_HTTP_GATE_CANON:-$cur}" "$_HTTP_GATE_REASON" "$method" "$target"
        log_warn "redirect not followed (hop $hop): $cur"
        _HTTP_LAST_STATUS=$status
        return 0
      fi
      continue
    fi

    _HTTP_LAST_STATUS=$status
    return 0
  done
}
