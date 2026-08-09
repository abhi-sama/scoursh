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
# DELIBERATELY NOT IN THIS TICKET (docs/DESIGN.md §13 step 5's remaining
# pieces, tension 16): the rate limiter, the request budget, and the circuit
# breaker.  Those are shared cross-process state (tension 16's mutex-guarded
# files) layered on top of this chokepoint, not part of the authorization
# gate itself; http_request is the correct, and only, place they will hook in
# once built.  IDN (A-label) conversion is also not implemented - hosts are
# compared as authored/discovered bytes, lowercased - which is a real, known
# gap for a homograph-style bypass and is tracked separately rather than
# silently dropped (see the ticket filed alongside this change).
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell/URL syntax literally.
# shellcheck disable=SC2016

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
# 11. http_request - THE chokepoint
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
http_request() {
  local method=$1 url=$2 max_redirects=${3:-5} target=${4:-}
  local cur=$url hop=0 addr out status location

  if ! http_gate_url "$cur" "$target"; then
    _http_gate_audit "$cur" "${_HTTP_GATE_CANON:-$cur}" "$_HTTP_GATE_REASON" "$method" "$target"
    die "$SCOURSH_EXIT_SCOPE" "scope gate refused $method $cur: $_HTTP_GATE_REASON"
  fi

  while :; do
    if [[ $_HN_IS_LITERAL == true ]]; then
      addr=$_HN_HOST
    elif ! addr=$(http_resolve_host "$_HN_HOST"); then
      die "$SCOURSH_EXIT_SCOPE" "scope gate: DNS resolution failed for '$_HN_HOST' after the gate had approved it"
    fi

    out=$("${SCOURSH_HTTP_TRANSPORT:-_http_transport_default}" \
      "$method" "$_HN_SCHEME" "$_HN_HOST" "$_HN_PORT" "$_HN_PATH" "$addr") || return 1
    status=${out%%$'\n'*}
    location=${out#*$'\n'}
    location=${location%$'\n'}

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
