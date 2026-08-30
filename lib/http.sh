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
# documented `modules/dast/passive/tls.sh` exception - DAST-07, which has now
# landed - are the only files exempted).  That exception is exempted from the
# TRANSPORT only: it still takes its authorization, its pinned address and its
# tension-16 limiter/budget/breaker spend from `http_authorize_raw_connection`
# in section 9b below, which is this file's only concession to it.
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
# THE THIRD CONTRACT (docs/STEP5-DAST-PLAN.md DAST-31 and DAST-32, sections
# 10a and 11 below): the identifying `User-Agent` every request carries, and
# the own-your-target affirmation that raises the tension-16 limits.  Both live
# here for the same reason as the two above - a caller that never went through
# scan.sh's CLI parser must inherit the identified UA and the SAFE limit, not
# an anonymous request and an unbounded one.  The affirmation is read from a
# per-run RECORD under the run directory, never from an environment variable:
# an env var is settable by anything that can start the process, and the whole
# job of the ceiling is to bind callers whose command line nobody parsed.
#
# THE FOURTH CONTRACT (docs/STEP5-DAST-PLAN.md DAST-03, section 9a below): the
# per-request context - request headers, a request body, and capture of the
# response body and response headers.  It lives here for the same reason as the
# three above: §7.0's form login and OAuth2 grants cannot be expressed without
# it, and a module that could compose its own request would be exactly the
# second path to the network the scope gate exists to make impossible.  A
# credential in a header or a body reaches curl over STDIN, never through argv
# and never through a file (tension 9 handling rules 1 and 2).
#
# STILL DELIBERATELY NOT IN THIS FILE: IDN (A-label) conversion - hosts are
# compared as authored/discovered bytes, lowercased - which is a real, known
# gap for a homograph-style bypass and is tracked separately rather than
# silently dropped (see the ticket filed alongside that change).
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
# 9a. The per-request context (docs/STEP5-DAST-PLAN.md DAST-03)
# ---------------------------------------------------------------------------
# `http_request METHOD URL` could originally send neither a request header nor
# a request body, and discarded the response body - which is everything an
# authenticated scan needs and nothing a bare reachability probe does.
# §7.0's form login "POST creds, capture Set-Cookie" and its OAuth2 grants are
# not expressible without all four, so they are added HERE rather than in
# modules/dast/auth.sh, for the reason tension 19 gives for the gate itself: a
# module that could compose its own request would be a second path to the
# network, and the rate limiter, the budget, the breaker and the ceilings all
# hang off this one.
#
# THE CONTEXT IS SET BY A CALL AND CONSUMED BY EXACTLY ONE REQUEST.
# `http_request` takes it into locals at entry and resets these globals before
# it does anything else, so a credential a caller attached for one request can
# never ride along on the next one - the failure mode that matters here is not
# a lost header but a leaked one, and "reset at the end" would keep the header
# attached across any path that dies in between.
#
# THE SECRET NEVER REACHES `argv` AND NEVER REACHES DISK (tension 9 handling
# rules 1 and 2).  A header value and a request body are exactly the two places
# a credential travels, so neither is passed to curl as an argument (visible in
# `ps` to every user on the host) and neither is written to a file: they are
# serialised into a curl config that is piped to `curl -K -` over STDIN.  curl
# offers no other way to supply a header - there is no `-H @file` and no
# stdin-header option - so the alternatives really were argv or a scratch file,
# and this is the only one that is neither.  Bash function arguments are not
# argv (no process is forked to pass them), which is the same property that
# lets `printf '%s' "$x" | sha256_of` satisfy the same rule.
declare -ga _HTTP_REQ_HEADERS=()
_HTTP_REQ_BODY=''
_HTTP_REQ_HAS_BODY=false
_HTTP_REQ_CAPTURE_BODY=''
_HTTP_REQ_CAPTURE_HEADERS=''

# What the transport reads for the hop it is about to send.  Separate from the
# `_HTTP_REQ_*` set above because a redirect that crosses origins drops the
# caller's headers and body (see http_request), so "what the caller attached"
# and "what this hop actually carries" are two different facts.
#
# Passed as GLOBALS rather than as extra positional parameters deliberately:
# `SCOURSH_HTTP_TRANSPORT` is a documented swappable hook and every existing
# stub takes exactly six arguments and prints exactly two lines.  Widening the
# positional contract would silently change what those stubs receive; adding
# globals leaves a stub that ignores them behaving exactly as it did.
declare -ga _HTTP_TX_HEADERS=()
_HTTP_TX_BODY=''
_HTTP_TX_HAS_BODY=false
_HTTP_TX_BODY_OUT=''
_HTTP_TX_HEADERS_OUT=''

http_request_reset() {
  _HTTP_REQ_HEADERS=()
  _HTTP_REQ_BODY=''
  _HTTP_REQ_HAS_BODY=false
  _HTTP_REQ_CAPTURE_BODY=''
  _HTTP_REQ_CAPTURE_HEADERS=''
  return 0
}

# `http_request_header NAME VALUE` - attach one header to the NEXT request.
#
# The two refusals are deliberately different codes because they are different
# mistakes.  A malformed NAME can only come from this repository's own code, so
# it is an internal error; a VALUE carrying CR or LF comes from an operator's
# credential file or a target's response, and splitting it into two headers is
# request smuggling, so it is refused as an unusable input rather than sanitised
# into something the operator did not write.  The value is never echoed in the
# diagnostic: it is the one string in this function most likely to be a secret.
http_request_header() {
  local name=$1 value=$2
  local re='^[A-Za-z0-9!#$%&'"'"'*+.^_`|~-]+$'
  [[ $name =~ $re ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: '$name' is not a valid HTTP header field name (RFC 7230 token)"
  if [[ $value == *$'\r'* || $value == *$'\n'* ]]; then
    die "$SCOURSH_EXIT_INPUT" \
      "the value supplied for the '$name' request header contains a carriage return or newline, which would split one request into two; it is refused rather than truncated, and the value itself is not printed here because it may be a credential"
  fi
  _HTTP_REQ_HEADERS+=("$name: $value")
  return 0
}

# `http_request_body TEXT` - the body for the NEXT request, as a VALUE rather
# than a path, so a credential in it never touches disk (tension 9 rule 2).
http_request_body() {
  _HTTP_REQ_BODY=$1
  _HTTP_REQ_HAS_BODY=true
  return 0
}

# `http_request_capture [BODY_FILE] [HEADER_FILE]` - where the RESPONSE is put.
# Either may be empty, meaning "discard".  Both are created mode 600 by
# http_request before the first hop: a login response body carries the token
# the whole exchange existed to obtain, and the header capture carries every
# Set-Cookie.
#
# The body file holds the LAST hop's body (each hop truncates it, which is what
# a caller following a redirect wants); the header file ACCUMULATES every hop's
# response headers, because a 302 login sets its session cookie on the hop that
# redirects, not on the one that finally answers 200.
http_request_capture() {
  _HTTP_REQ_CAPTURE_BODY=${1:-}
  _HTTP_REQ_CAPTURE_HEADERS=${2:-}
  return 0
}

# curl's config-file quoting (`curl(1)`, "CONFIG FILE"): inside a double-quoted
# parameter curl understands \\, \", \t, \n, \r and \v, and nothing else.  A
# raw newline would end the line and turn the rest of a body into a bogus
# directive, so every one of them is escaped rather than rejected.
#
# Pure parameter expansion, no external command and no `$(...)`: the string
# passing through here is the credential, and a fork is the one thing that could
# put it somewhere another process can see.  Sets `_HTTP_CFG_Q`.
_http_curl_cfg_quote() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  _HTTP_CFG_Q=$s
  return 0
}


# ---------------------------------------------------------------------------
# 9b. The ONE documented non-HTTP caller (docs/FOUNDATION.md tension 19)
# ---------------------------------------------------------------------------
# `http_authorize_raw_connection URL [TARGET_ID]` - everything `http_request`
# does EXCEPT sending an HTTP request: gate the URL, resolve and pin the
# address, check the circuit breaker, and spend one token of the rate limiter
# and the per-run request budget.  On success it publishes
#
#   _HTTP_RAW_ADDR    the resolved, gate-approved address to connect to
#   _HTTP_RAW_HOST    the normalised hostname (what SNI must carry)
#   _HTTP_RAW_PORT    the normalised port
#   _HTTP_RAW_SCHEME  http | https
#   _HTTP_RAW_BUCKET  the scope target id the spend was charged to
#
# and returns 0.  A scope violation is exit 3 through the same audit path
# `http_request` uses, so the two can never disagree about what is authorised.
#
# WHY THIS EXISTS AT ALL, GIVEN THAT TENSION 19 SAYS THERE IS ONE CHOKEPOINT.
# `modules/dast/passive/tls.sh` (docs/STEP5-DAST-PLAN.md DAST-07) is that
# tension's single documented exception: a transport-security check needs a RAW
# TLS HANDSHAKE and the certificate the server presents, which is not an HTTP
# request and cannot be expressed as one.  The exception is narrow, and this
# function is what keeps it narrow: the AUTHORIZATION half - the scope tuple
# compare, the userinfo refusal, the resolution-pinning deny list, the
# tension-16 limiter, budget and breaker, and the audit finding on refusal -
# stays here, in this file, unforked.  What the exempted module owns is the wire
# protocol and nothing else.
#
# Putting this here rather than letting the module call `http_gate_url` and
# `_http_throttle` itself is the same argument tension 19 makes for the gate:
# a control that each caller has to remember to apply is not a control.  A
# second exempted caller, if one is ever justified, calls this and inherits
# every one of them; it does not get to assemble its own subset.
#
# IT IS NOT A GENERAL ESCAPE HATCH, AND THE LINT IS WHAT KEEPS IT FROM BECOMING
# ONE.  This function hands back an address; it opens nothing.  Anything that
# then wants to talk to that address needs a transport primitive, and
# tests/lint-shell.sh's "no bypass" check still fails the build for a bare
# curl/wget/nc/`openssl s_client` in any file but the two it exempts by path.
http_authorize_raw_connection() {
  local url=$1 target=${2:-}
  local rps_milli budget breaker_failures breaker_window
  _HTTP_RAW_ADDR='' _HTTP_RAW_HOST='' _HTTP_RAW_PORT='' _HTTP_RAW_SCHEME=''
  _HTTP_RAW_BUCKET=''

  if ! http_gate_url "$url" "$target"; then
    _http_gate_audit "$url" "${_HTTP_GATE_CANON:-$url}" "$_HTTP_GATE_REASON" 'TLS' "$target"
    die "$SCOURSH_EXIT_SCOPE" "scope gate refused a raw TLS connection to $url: $_HTTP_GATE_REASON"
  fi

  local scheme=$_HN_SCHEME host=$_HN_HOST port=$_HN_PORT is_literal=$_HN_IS_LITERAL
  local bucket=${_HTTP_MATCH_ID:-${target:-unattributed}}

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

  _http_abort_check "$bucket"
  _http_throttle "$bucket" "$rps_milli" "$budget"
  _http_abort_check "$bucket"

  local addr
  if [[ $is_literal == true ]]; then
    addr=$host
  elif ! addr=$(http_resolve_host "$host"); then
    die "$SCOURSH_EXIT_SCOPE" "scope gate: DNS resolution failed for '$host' after the gate had approved it"
  fi
  _http_note_target_address "$bucket" "$addr"

  _HTTP_RAW_ADDR=$addr
  _HTTP_RAW_HOST=$host
  _HTTP_RAW_PORT=$port
  _HTTP_RAW_SCHEME=$scheme
  _HTTP_RAW_BUCKET=$bucket
  return 0
}

# ---------------------------------------------------------------------------
# 10. The transport (curl, invoked ONLY from here)
# ---------------------------------------------------------------------------
# Swappable via SCOURSH_HTTP_TRANSPORT (a function name) so the redirect-loop
# and gate-recheck logic in http_request is fully testable with no network,
# per docs/DESIGN.md §12.  Contract: METHOD SCHEME HOST PORT PATH ADDR
# [BODY_OUT] [HEADERS_OUT] on argv; on success prints up to THREE lines to
# stdout - the status code,
# the Location header value (or an empty line), and the Content-Type header
# value (or an empty line, or no line at all) - and returns 0; a transport-
# level failure returns non-zero.  Section 9a's `_HTTP_TX_*` globals carry the
# request headers, the request body, and the two response-capture paths; a
# transport that ignores them behaves exactly as this one did before they
# existed, which is what keeps every already-written stub valid.
#
# THE THIRD LINE IS ADDITIVE, AND ONLY THE THIRD LINE (DAST-04).  A crawler
# needs the response BODY and its Content-Type, and there is exactly one legal
# place to obtain either: here, behind the gate, the rate limiter, the budget
# and the breaker.  A crawler that fetched its own bodies would be tension 19's
# bypass with a different name.
#
# THE TWO CAPTURE SINKS ARRIVE BOTH WAYS, AND THAT IS DELIBERATE.  DAST-03
# introduced them as the `_HTTP_TX_*` globals; DAST-04 needs them to reach a
# transport that is an EXECUTABLE rather than a function, and a global does not
# cross a fork - a wrapper that `source`s this file even re-runs the
# initialisation below and erases what the environment carried.  So
# `http_request` sets the globals AND appends the two paths as arguments 7 and
# 8, and this transport prefers the argument.  Appending is safe by
# construction: a six-argument stub never reads $7 or $8.
# Only the PATHS travel as arguments; the request headers and body stay globals
# because argv is world-readable (tension 9).
# A stub transport that prints only two lines stays conformant: http_request
# reads a missing third line as an empty Content-Type.
_http_transport_default() {
  local method=$1 scheme=$2 host=$3 port=$4 path=$5 addr=$6
  require_cmd curl
  local hdrfile
  hdrfile=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/http-hdr.XXXXXX")
  chmod 600 "$hdrfile"
  local timeout=${SCOURSH_HTTP_TIMEOUT:-20}
  # ARGUMENT FIRST, GLOBAL AS FALLBACK.  The argument is what reaches a forked
  # transport; the global is what an in-process one has always read.  Same value
  # either way - http_request sets both from the same local.
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local outarg=/dev/null
  [[ -n $bodyout ]] && outarg=$bodyout
  # The identifying User-Agent (section 10a).  Composed HERE and nowhere else,
  # which is what makes it unconditional: there is no second curl invocation in
  # this repository for a later ticket to add an unidentified request through.
  _http_user_agent_set

  # The config curl reads from stdin.  It is frequently EMPTY - a plain
  # reachability request attaches no header and no body - and `-K -` is still
  # passed in that case, deliberately: there must remain exactly ONE curl
  # invocation in this file, because "every request carries the identifying
  # User-Agent" is only a structural fact while there is a single command line
  # for a later ticket to have to notice.  tests/suites/http.sh counts the
  # invocations for precisely that reason, and a second, header-free branch
  # would have been the first place an unidentified request could appear.
  local cfg='' item
  for item in "${_HTTP_TX_HEADERS[@]+"${_HTTP_TX_HEADERS[@]}"}"; do
    _http_curl_cfg_quote "$item"
    cfg+="header = \"$_HTTP_CFG_Q\""$'\n'
  done
  if [[ ${_HTTP_TX_HAS_BODY:-false} == true ]]; then
    _http_curl_cfg_quote "$_HTTP_TX_BODY"
    # data-binary, never data: `--data` strips newlines when it reads a file
    # and this repository should not have to remember which of the two forms
    # it is using to know whether the bytes it sent are the bytes it composed.
    cfg+="data-binary = \"$_HTTP_CFG_Q\""$'\n'
  fi

  # --max-redirs 0, never -L: the manual, one-hop-at-a-time loop in
  # http_request is what re-runs the full gate on every hop (tension 19
  # "Redirects" / "Redirect-recheck parity").  --resolve pins the connection
  # to the address the gate itself just approved, closing the TOCTOU window
  # between the gate's resolution and curl's.
  local rc=0
  printf '%s' "$cfg" | curl --silent --show-error --max-redirs 0 --max-time "$timeout" \
    --resolve "$host:$port:$addr" \
    -A "$_HTTP_UA" \
    -o "$outarg" -D "$hdrfile" \
    -K - \
    -X "$method" -- "$scheme://$host:$port$path" || rc=$?
  if (( rc != 0 )); then
    rm -f "$hdrfile"
    return 1
  fi

  [[ -n $hdrsout ]] && cat -- "$hdrfile" >>"$hdrsout"
  local status='' location='' ctype='' line
  while IFS= read -r line; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+\ ([0-9]{3}) ]]; then
      status=${BASH_REMATCH[1]}
      # Both reset on every status line, so an intermediate 1xx/3xx response's
      # headers can never be attributed to the final one.
      location='' ctype=''
    elif [[ $line =~ ^[Ll]ocation:[[:space:]]*(.*)$ ]]; then
      location=${BASH_REMATCH[1]}
    elif [[ $line =~ ^[Cc]ontent-[Tt]ype:[[:space:]]*(.*)$ ]]; then
      ctype=${BASH_REMATCH[1]}
    fi
  done <"$hdrfile"
  rm -f "$hdrfile"
  printf '%s\n%s\n%s\n' "$status" "$location" "$ctype"
}

# ---------------------------------------------------------------------------
# 10a. The identifying User-Agent (docs/STEP5-DAST-PLAN.md DAST-31)
# ---------------------------------------------------------------------------
# Every request this tool sends says what it is and how to reach whoever is
# running it.  The argument is a practical one rather than a courtesy: a target
# owner who notices unusual traffic and can identify the tool and its operator
# can send one email; an owner who cannot has escalation as their only
# available response.
#
# THE `scoursh/<version>` PRODUCT TOKEN IS NEVER REMOVABLE, AT ANY SETTING.
# There is no flag, config key or environment variable below that replaces or
# suppresses it, and there deliberately never will be: an authorised scan has
# no need to be unidentifiable and an unauthorised one has every need, so a
# switch whose only function is hiding the tool's identity is a switch for
# scanning something you do not own.  Expect it to be requested as WAF evasion.
# `--user-agent-suffix` APPENDS an extra product token and cannot displace the
# prefix, because it is concatenated after it.
#
# The two operator-supplied halves reach this file by two different routes, and
# the difference is deliberate.  `contact` is a scanner-config key, so a caller
# with no run directory at all still resolves it through the ordinary
# CLI > env > file > default chain; the per-run record is what carries the CLI
# LAYER of that chain (scan.sh's `--contact`) across into a module, since
# nothing here can see `SCAN_FLAGS`.  `--user-agent-suffix` has no config key
# (docs/STEP5-DAST-PLAN.md DAST-31 names only `contact` as a schema addition),
# so the run record is its only route.
#
# Both are re-validated here even though scan.sh already validated them.  The
# run record is a file under a directory an operator can edit, and this value
# is concatenated into an HTTP header, so trusting it because "we wrote it"
# would be trusting a file for a header - the same reasoning that puts the
# scope gate inside http_request rather than in its callers.  An invalid value
# is dropped with a warning rather than aborting the run: it degrades the
# request's identification, which is not worth failing an authorised scan over.
_HTTP_PROJECT_URL='https://github.com/abhi-sama/scoursh'

# Sets `_HTTP_UA`.  Never printed through `$(...)`: `config_scanner_value` can
# `die`, and section 11's own note explains at length why that is unreliable
# inside a command substitution.
_http_user_agent_set() {
  local contact suffix ua
  run_fact_first_set contact contact
  if [[ -z $contact ]]; then
    core_capture contact config_scanner_value contact ''
  fi
  if ! config_valid_ua_text "$contact"; then
    log_warn "the configured 'contact' value is not usable in a User-Agent header and is being ignored for this run; the request will identify the tool but not the operator (rules/RULE-FORMAT.md §9.6.1)"
    contact=''
  fi
  run_fact_first_set suffix user_agent_suffix
  if ! config_valid_ua_text "$suffix"; then
    log_warn "the --user-agent-suffix value is not usable in a User-Agent header and is being ignored for this run"
    suffix=''
  fi

  ua="scoursh/$(scoursh_version)"
  if [[ -n $contact ]]; then
    ua="$ua (+$contact)"
  else
    # The documented no-contact form.  It still identifies the TOOL, which is
    # the half that is never removable; what it cannot supply is the operator,
    # so it says so in as many words rather than leaving the owner to guess
    # whether the missing contact is a policy or an oversight.
    ua="$ua (+$_HTTP_PROJECT_URL; no operator contact configured)"
  fi
  [[ -n $suffix ]] && ua="$ua $suffix"
  _HTTP_UA=$ua
  return 0
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
# The own-your-target affirmation (DAST-32) is what RAISES these, and it is
# read from a per-run record rather than from an environment variable - see
# `_http_affirmation_set` below.  An ABSENT record means the conservative
# ceiling, which is what makes a caller that never went through scan.sh's
# parser inherit the safe value rather than an unbounded one.
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

# The own-your-target affirmation, read from the per-run record scan.sh writes
# at parse time (docs/STEP5-DAST-PLAN.md, "How the affirmation reaches the
# limiter, and why it is not an environment variable").
#
# Re-read on every call rather than memoised: one process can run more than one
# scan_main (tests/suites/scan.sh does exactly that), and a memoised
# affirmation would carry an earlier run's answer into a later run that never
# made one - which is the "no persisted affirmation" non-goal, arrived at by
# accident instead of by design.  It costs one builtin `read` and forks
# nothing.
#
# Sets `_HTTP_AFFIRMED` (true/false) and `_HTTP_AFFIRMED_TARGET`.
_http_affirmation_set() {
  _HTTP_AFFIRMED=false
  _HTTP_AFFIRMED_TARGET=''
  local v
  run_fact_first_set v authorization_affirmed
  [[ $v == true ]] || return 0
  _HTTP_AFFIRMED=true
  run_fact_first_set _HTTP_AFFIRMED_TARGET authorization_target
  return 0
}

# The asymmetric clamp policy (docs/STEP5-DAST-PLAN.md DAST-32), which matches
# lib/config.sh's own precedent: `config_scanner_value` dies exit 2 for a bad
# CLI *or env* value and exit 4 for a bad FILE value, because the first two are
# the operator's own invocation.  The same split applies to a value that is
# valid but above a module ceiling:
#
#   file / default  -> CLAMP down, one log_warn, and a recorded delta.
#   cli  / env      -> EXIT 2, naming --i-own-target.
#
# Both halves are deliberate and neither is the "obvious" uniform choice.
# Clamping the file/default case rather than refusing it is what stops an
# operator being pushed to affirm reflexively just to get any scan at all - an
# affirmation people click through to make the tool work is worth nothing, and
# that is the only thing the affirmation has to sell.  Refusing the explicit
# case rather than clamping it is what stops this tool quietly running at a
# different number than the operator typed: everywhere else in this codebase an
# invocation is authoritative or fatal, never silently rewritten.
#
# Dies, so it must be called directly and never through `$(...)`.
_http_limit_refuse_or_clamp() {
  local key=$1 raw=$2 eff=$3 src=$4 where env_name
  case $src in
    cli | env)
      if [[ $src == env ]]; then
        env_name=$(_scanner_env_name "$key")
        where="the environment variable $env_name"
      else
        where="the command line"
      fi
      die "$SCOURSH_EXIT_USAGE" \
        "'$key' is $raw, above the conservative limit of $eff that applies to a running-endpoint scan against a host this tool cannot vouch for. It was given explicitly, on $where, and scoursh does not silently run at a number other than the one you asked for. Either lower it to $eff or below, or affirm that you own the target by re-running with '--i-own-target <the same id you passed to --target>' (docs/STEP5-DAST-PLAN.md, 'Safety defaults and authorisation')."
      ;;
  esac
  _http_limit_warn_clamp "$key" "$raw" "$eff"
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
# clamped integer value, and `_HTTP_EFF_SRC` to the level it was resolved from.
# The rate has its own accessor below because it is the one decimal key.
#
# WHICH BOUNDS AN AFFIRMATION LIFTS, AND WHICH IT NEVER DOES.  The affirmation
# raises the three UPPER bounds - rate, budget, breaker threshold - because
# those are the numbers whose only justification is that this tool cannot vet
# the host, and against a host that genuinely is the operator's, a 4/s cap has
# no safety content.  It lifts NEITHER of `circuit-breaker-window`'s two
# bounds, and both refusals have their own reason:
#
#   * The 60s FLOOR is not relaxable because a shorter window counts fewer
#     failures towards the same threshold, so relaxing it is a way of weakening
#     the breaker, and docs/STEP5-DAST-PLAN.md offers "threshold raisable,
#     disabling never offered".  A dial that reaches "never trips" by a
#     different route is the disable switch wearing a hat.
#   * The 86400s MAXIMUM is not relaxable because it is not a safety limit at
#     all - it is what keeps `now - window` inside 64-bit arithmetic.  An
#     affirmation is a statement about who owns a host; it cannot make a
#     wrapped integer mean what it says.
#
# The budget stays FINITE under an affirmation for the same class of reason:
# raising it is allowed, and the schema's own positive-integer shape is what
# makes "no budget" unrepresentable, so there is nothing here to switch off.
_http_effective_limit_set() {
  local key=$1 raw ceil eff src
  _http_limit_ceiling_set "$key" \
    || die "$SCOURSH_EXIT_INCOMPLETE" "internal: no DAST ceiling defined for '$key'"
  ceil=$_HTTP_LIMIT_CEIL
  core_capture raw config_scanner_value "$key"
  src=$CONFIG_SCANNER_LAST_SOURCE
  _http_affirmation_set
  _http_int_cmp_set "$raw" "$ceil"
  eff=$raw
  # "Was the resolved value above the RELAXABLE upper ceiling", which is what
  # decides whether this key contributes a `limits_relaxed` or a
  # `limits_clamped` line to the run's authorisation record.  It is false for
  # `circuit-breaker-window` by construction: that key's ceiling is a floor and
  # neither of its bounds is affirmable, so it can never be relaxed.
  _HTTP_EFF_ABOVE=false
  [[ $key != circuit-breaker-window && $_HTTP_INT_CMP == 1 ]] && _HTTP_EFF_ABOVE=true
  case $key in
    circuit-breaker-window)
      # A floor (a shorter window is a weaker breaker) AND a maximum, because
      # the value beyond it stops being arithmetic the cutoff can hold.
      # Neither is affirmable; see this function's own header for why each.
      [[ $_HTTP_INT_CMP == -1 ]] && eff=$ceil
      _http_int_cmp_set "$eff" "$_HTTP_BREAKER_WINDOW_MAX"
      [[ $_HTTP_INT_CMP == 1 ]] && eff=$_HTTP_BREAKER_WINDOW_MAX
      [[ $eff == "$raw" ]] || _http_limit_warn_clamp "$key" "$raw" "$eff"
      ;;
    *)
      if [[ $_HTTP_INT_CMP == 1 && $_HTTP_AFFIRMED != true ]]; then
        eff=$ceil                                   # a bigger number is louder
        _http_limit_refuse_or_clamp "$key" "$raw" "$eff" "$src"
      fi
      ;;
  esac
  _HTTP_EFF_LIMIT=$eff
  _HTTP_EFF_SRC=$src
  return 0
}

# The rate, in milli-tokens per second, already clamped.  Sets
# `_HTTP_EFF_RPS_MILLI`.
_http_effective_rps_milli_set() {
  local raw ms src ceil_ms=4000
  core_capture raw config_scanner_value requests-per-second
  src=$CONFIG_SCANNER_LAST_SOURCE
  _HTTP_EFF_RPS_RAW=$raw
  _HTTP_EFF_RPS_SRC=$src
  _http_affirmation_set
  if ! _http_rps_milli_set "$raw"; then
    # Well-formed per the schema but absurd, so it is certainly above the
    # ceiling.  An affirmed run cannot honour it either - the value does not
    # fit the limiter's own arithmetic, which is a representability fact rather
    # than a safety one - so this clamps in BOTH cases and never refuses.
    _http_limit_warn_clamp requests-per-second "$raw" 4
    _HTTP_EFF_RPS_MILLI=$ceil_ms
    return 0
  fi
  ms=$_HTTP_RPS_MILLI
  _HTTP_EFF_RPS_ABOVE=false
  (( ms > ceil_ms )) && _HTTP_EFF_RPS_ABOVE=true
  if (( ms > ceil_ms )) && [[ $_HTTP_AFFIRMED != true ]]; then
    _http_limit_refuse_or_clamp requests-per-second "$raw" 4 "$src"
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
  log_info "request limiter armed for this run: $(_http_rps_render "$rps_milli") requests/second, a per-run budget of $budget requests, and a circuit breaker at $failures failed requests within ${window}s (docs/FOUNDATION.md tension 16)"
  return 0
}

# Milli-tokens back to the decimal an operator recognises.
_http_rps_render() {
  printf '%s.%03d' $(( $1 / 1000 )) $(( $1 % 1000 ))
}

# `http_budget_remaining_set VARNAME` - how many requests of the per-run budget
# are still unspent, into VARNAME, plus `_HTTP_BUDGET_TOTAL` (the effective
# budget this run resolved) and `_HTTP_BUDGET_RPS_MILLI` (the effective rate)
# alongside.
#
# IT LIVES HERE RATHER THAN IN THE ONE MODULE THAT NEEDS IT, and that is the
# same argument tension 19 makes for the gate and this section makes for the
# limiter.  `modules/dast/ratelimit.sh` (DAST-28) is the one check
# docs/DESIGN.md §7.4 flags as intentionally multi-request, and
# docs/STEP5-DAST-PLAN.md's own DAST-28 amendment requires it to draw down the
# SAME budget rather than carry one of its own - "a burst probe that had its
# own budget would double-spend the ceiling the whole tier depends on".  A
# module-local reader would be a second definition of where the counter lives
# and of what an absent counter means, and the two would drift the first time
# this file changed the file name or the fallback.
#
# IT IS A READ, NEVER A RESERVATION, and the distinction is load-bearing.
# Nothing here takes the budget out of circulation: the only place a request is
# actually charged is `_http_throttle`, inside the one critical section that
# also grants the token, and the only place exhaustion is enforced is the
# `remaining <= 0` refusal there.  So a caller sizing a burst from this number
# is sizing it from a value another worker may already have spent against, and
# must leave headroom rather than treat the answer as a reservation it holds -
# which is exactly why DAST-28 spends at most half of what this reports.
# Promoting it to a reservation would mean a caller that died mid-burst leaked
# budget for the rest of the run, which is the failure this section's own
# "manufacture budget out of a crash" note rejects in the other direction.
#
# An absent or unparseable counter means the budget has not been OPENED yet,
# never "unlimited" - the identical fallback `_http_throttle` applies, kept in
# step with it deliberately.
http_budget_remaining_set() {
  local _hbr_out=$1 _hbr_file _hbr_remaining=''
  _http_effective_limit_set request-budget
  _HTTP_BUDGET_TOTAL=$_HTTP_EFF_LIMIT
  _http_effective_rps_milli_set
  _HTTP_BUDGET_RPS_MILLI=$_HTTP_EFF_RPS_MILLI
  _http_limit_dir_set
  _hbr_file=$_HTTP_LIMIT_DIR/budget.state
  # Under the same mutex the decrement takes, so a caller never reads a
  # half-written counter mid-update.
  mutex_acquire "$_HTTP_LIMIT_MUTEX"
  if [[ -r $_hbr_file ]]; then
    IFS= read -r _hbr_remaining <"$_hbr_file" || true
  fi
  mutex_release "$_HTTP_LIMIT_MUTEX"
  [[ $_hbr_remaining =~ ^[0-9]+$ ]] || _hbr_remaining=$_HTTP_BUDGET_TOTAL
  printf -v "$_hbr_out" '%s' "$_hbr_remaining"
  return 0
}

# ---------------------------------------------------------------------------
# 11a. The run's authorisation record (docs/STEP5-DAST-PLAN.md DAST-32/33/34)
# ---------------------------------------------------------------------------
# `http_limits_record` - resolve all four network limits ONCE, at run start,
# and write what actually happened to each into the run's own meta records, so
# run.json can state it (DAST-33) and the report can banner it (DAST-34).
#
# Recording is separate from ENFORCING on purpose, and the separation is the
# point rather than an implementation detail.  Enforcement happens per request,
# at the chokepoint, where a caller cannot go around it.  Recording happens once
# per run, because a run that sends ZERO requests still made an authorisation
# decision, and today's DAST module sends exactly zero - so a record written
# only by the request path would be absent from precisely the runs a reader is
# most likely to be looking at.  Both call the same resolution helpers, so the
# numbers a run REPORTS and the numbers it KEEPS cannot drift.
#
# Calling this at run start also moves an explicit over-ceiling refusal from
# "the first request" to "before anything ran", which is the better failure: a
# usage error that fires after a scan has started is a usage error that has
# already sent traffic.
#
# Dies (exit 2) for an explicit CLI/env value above a ceiling with no
# affirmation, so it must be called directly and never through `$(...)`.
http_limits_record() {
  local rps_milli budget failures window contact
  local rps_ceil='4.000'

  _http_effective_rps_milli_set
  rps_milli=$_HTTP_EFF_RPS_MILLI
  if [[ $_HTTP_EFF_RPS_ABOVE == true ]]; then
    if [[ $_HTTP_AFFIRMED == true ]]; then
      run_record limits_relaxed "requests-per-second:$rps_ceil->$(_http_rps_render "$rps_milli")"
    else
      run_record limits_clamped "requests-per-second:$_HTTP_EFF_RPS_RAW->$rps_ceil reason=no_owner_affirmation source=$_HTTP_EFF_RPS_SRC"
    fi
  fi

  _http_effective_limit_set request-budget
  budget=$_HTTP_EFF_LIMIT
  _http_limit_delta_record request-budget 5000 "$budget"

  _http_effective_limit_set circuit-breaker-failures
  failures=$_HTTP_EFF_LIMIT
  _http_limit_delta_record circuit-breaker-failures 10 "$failures"

  _http_effective_limit_set circuit-breaker-window
  window=$_HTTP_EFF_LIMIT

  # What was NOT relaxed, so the record is a complete statement rather than a
  # partial one.  The usual question after an incident is what the tool could
  # not have done, and a list of what stayed on is the answer; without it a
  # reader has to reason from the version number.
  run_record limits_enforced "request-budget:$budget (finite, never removable)"
  run_record limits_enforced "circuit-breaker:$failures-failures/${window}s (never disableable)"
  run_record limits_enforced 'scope-gate:config/scope.conf (every URL and every redirect hop; no affirmation authorises a target)'
  run_record limits_enforced 'payloads:detection-only (docs/DESIGN.md §7.3; no destructive payload exists at any setting)'
  run_record limits_enforced 'ssrf:in-scope-sentinels-only'
  run_record limits_enforced 'user-agent:scoursh-identified (the product token is never removable)'

  # DAST-31's run-start notice.  A warning would overstate it: an unset contact
  # is a perfectly legal configuration, and the request is still identified as
  # scoursh.  What it costs is the target owner's ability to reach the person
  # running it, so the line names the key that fixes it rather than scolding.
  run_fact_first_set contact contact
  if [[ -z $contact ]]; then
    log_info "no operator contact is configured, so requests will identify this tool but not you; set 'contact' in config/scanner.conf (rules/RULE-FORMAT.md §9.6.1) or pass --contact so a target owner who notices the traffic can reach you"
  fi
  return 0
}

# One `limits_relaxed` or `limits_clamped` line for an integer key, from the
# state `_http_effective_limit_set` just published.  Split out because the two
# integer keys are identical here and the rate is not (it is the one decimal).
_http_limit_delta_record() {
  local key=$1 ceil=$2 eff=$3
  [[ $_HTTP_EFF_ABOVE == true ]] || return 0
  if [[ $_HTTP_AFFIRMED == true ]]; then
    run_record limits_relaxed "$key:$ceil->$eff"
  else
    # `_http_effective_limit_set` has already clamped and warned (or died, for
    # an explicit value); this only states the delta durably, since a warning
    # on stderr is not an artifact a reader has a month later.
    core_capture _HTTP_DELTA_RAW config_scanner_value "$key"
    run_record limits_clamped "$key:$_HTTP_DELTA_RAW->$eff reason=no_owner_affirmation source=$_HTTP_EFF_SRC"
  fi
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
# A caller that wants the RESPONSE BODY asks for it with `http_request_capture`
# (section 9a) before the call, rather than by passing a sink positionally.
# DAST-04's crawler originally took a fifth argument for exactly this; DAST-03
# landed the same capability first as part of the per-request context, so there
# is ONE mechanism here rather than two - see section 10's note.  The body sink
# is truncated at the top of every hop, so a caller can never read a previous
# hop's body as if it were this one's, and a transport failure leaves it empty
# rather than stale - the crawler in modules/dast/crawl.sh reads it immediately
# after the call returns and treats emptiness as "no body", which is only a
# true statement if nothing else can have put bytes there.  It is a
# caller-chosen path rather than a value this file invents so that a caller
# running under `xargs -P` owns its own sink.
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
# Sets _HTTP_LAST_STATUS and _HTTP_LAST_CONTENT_TYPE.  Never calls curl (or
# any transport) for a URL that has not just passed http_gate_url.
# The tension-16 controls sit between the gate and the transport, and inside
# the redirect loop rather than ahead of it: a followed hop is a real request
# and pays a real token, a real unit of budget, and a real breaker outcome.
# `_HTTP_MATCH_ID` is the scope target the gate matched, and it is
# re-established on every hop because the hop re-runs the full gate - so a
# redirect that crosses from one in-scope target to another draws down the
# second target's bucket, which is what "rate is a politeness property of the
# target" means.
#
# THE REQUEST CONTEXT (section 9a) IS CONSUMED HERE, ONCE, BEFORE ANYTHING ELSE
# CAN FAIL.  A caller attaches headers and a body for the next request; this
# function takes them into locals and clears the globals immediately, so no
# later path - a gate refusal, a budget exhaustion, an opened breaker - can
# leave a credential attached to whatever request happens to come next.
#
# Two response artifacts are published on success: `_HTTP_LAST_BODY_FILE` and
# `_HTTP_LAST_HEADER_FILE`, each empty when the caller asked for no capture.
http_request() {
  local method=$1 url=$2 max_redirects=${3:-5} target=${4:-}
  local cur=$url hop=0 addr out status location ctype bucket line
  local rps_milli budget breaker_failures breaker_window
  local origin prev_origin='' item
  local -a req_headers=() kept=() outlines=()

  _HTTP_LAST_CONTENT_TYPE=''

  req_headers=("${_HTTP_REQ_HEADERS[@]+"${_HTTP_REQ_HEADERS[@]}"}")
  local req_body=$_HTTP_REQ_BODY req_has_body=$_HTTP_REQ_HAS_BODY
  local cap_body=$_HTTP_REQ_CAPTURE_BODY cap_hdrs=$_HTTP_REQ_CAPTURE_HEADERS
  http_request_reset
  _HTTP_LAST_BODY_FILE=$cap_body
  _HTTP_LAST_HEADER_FILE=$cap_hdrs
  # Created empty and 600 BEFORE the first hop, not by whoever writes to them
  # first: the header capture is appended to per hop, so it needs to start
  # empty, and a response body that turns out to hold a session token must
  # never exist for even one hop at the umask's default mode.
  if [[ -n $cap_body ]]; then
    : >"$cap_body"
    chmod 600 "$cap_body"
  fi
  if [[ -n $cap_hdrs ]]; then
    : >"$cap_hdrs"
    chmod 600 "$cap_hdrs"
  fi

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

    # AN `Authorization` HEADER IS BOUND TO THE ORIGIN IT WAS ISSUED FOR, AND
    # BOTH ORIGINS BEING IN SCOPE DOES NOT MAKE THEM THE SAME PRINCIPAL.  The
    # gate answers "may this tool talk to that host at all"; it does not answer
    # "should this credential be shown to it".  config/scope.conf routinely
    # authorises several hosts of one estate, so a redirect from one to another
    # is an ordinary event, and resending the header would hand host B a
    # credential the operator issued for host A - the classic credential-leak-
    # on-redirect bug, which every HTTP client drops the header for.  The body
    # goes with it: it is the other place the credential lives on a login POST.
    origin="$_HN_SCHEME://$_HN_HOST:$_HN_PORT"
    if [[ -n $prev_origin && $origin != "$prev_origin" ]]; then
      if (( ${#req_headers[@]} > 0 )) || [[ $req_has_body == true ]]; then
        log_warn "redirect crossed origin ($prev_origin -> $origin): the request headers and body this call carried are NOT resent, because a credential is bound to the origin it was issued for and both origins being in config/scope.conf does not make them the same principal"
      fi
      req_headers=()
      req_body=''
      req_has_body=false
    fi
    prev_origin=$origin

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

    _HTTP_TX_HEADERS=("${req_headers[@]+"${req_headers[@]}"}")
    _HTTP_TX_BODY=$req_body
    _HTTP_TX_HAS_BODY=$req_has_body
    _HTTP_TX_BODY_OUT=$cap_body
    _HTTP_TX_HEADERS_OUT=$cap_hdrs

    # Truncated per HOP, not per call.  curl truncates the sink itself on every
    # hop it actually runs, so this only bites when the transport FAILS: without
    # it a followed redirect would leave the previous hop's body sitting in the
    # sink for a caller that reads it after the later hop died, which is the one
    # case that makes "the body file holds the last hop's body" false.
    [[ -n $cap_body ]] && : >"$cap_body"

    # The two CAPTURE PATHS are ALSO APPENDED AS ARGUMENTS 7 AND 8, and that is
    # not redundancy - it is the only channel that survives a fork.
    # `SCOURSH_HTTP_TRANSPORT` may name an EXECUTABLE, not just a function, and
    # a shell global is invisible across a fork; worse, a wrapper that `source`s
    # this file re-runs section 9a's own `_HTTP_TX_BODY_OUT=''` initialisation
    # and so ERASES any value inherited through the environment.  Measured, not
    # reasoned: with the globals alone, tests/e2e/dast-crawl-target.sh's
    # delegating wrapper crawled the live target and got 1 endpoint instead of
    # 13, because every response body was silently discarded.
    #
    # Passing them in the ENVIRONMENT instead would also be wrong on its own
    # terms: anything able to set the environment could then choose where this
    # process writes response bodies.  An argument is chosen by the caller.
    #
    # Appending cannot disturb an existing stub - a six-argument transport
    # simply never reads $7 or $8 - which is the property DAST-03's own note
    # about not widening the contract was protecting.
    #
    # ONLY THE PATHS CROSS THE BOUNDARY.  `_HTTP_TX_BODY` and `_HTTP_TX_HEADERS`
    # carry the credential and stay globals precisely because argv is world-
    # readable in `ps` (tension 9 handling rule 1).  So an external transport
    # gets the sinks and never the request context, and the in-process default
    # transport - the only one that sends a credential - reads those globals in
    # this same process, where no fork is involved.
    if ! out=$("${SCOURSH_HTTP_TRANSPORT:-_http_transport_default}" \
      "$method" "$_HN_SCHEME" "$_HN_HOST" "$_HN_PORT" "$_HN_PATH" "$addr" \
      "$cap_body" "$cap_hdrs"); then
      # No usable response at all, which is the strongest evidence the breaker
      # gets; it is recorded before the failure is returned, so a caller that
      # swallows the non-zero status cannot also swallow the breaker.
      _http_breaker_record_failure "$bucket" "$breaker_failures" "$breaker_window"
      return 1
    fi
    # Read as up to three whole LINES rather than by suffix-stripping the
    # captured string.  `$(...)` strips trailing newlines, so a transport that
    # legitimately reports an empty Location and an empty Content-Type yields
    # one line, and the older `${out#*$'\n'}` form returns the WHOLE string
    # unchanged when the pattern does not match - i.e. it reported the status
    # code as the Location.  That was harmless while only a 3xx read the
    # Location; a Content-Type read the same way would mis-type every body.
    # No `mapfile`: tension 4 rule 4 forbids it in the engine.
    outlines=()
    while IFS= read -r line; do outlines+=("$line"); done <<<"$out"
    status=${outlines[0]:-}
    location=${outlines[1]:-}
    ctype=${outlines[2]:-}
    _HTTP_LAST_CONTENT_TYPE=$ctype

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
      # RFC 7231 §6.4.4: a 303 is re-issued as GET, always.  A 301 or 302 after
      # a non-GET/HEAD method is re-issued as GET by every browser and by
      # `curl -L`, and this follows them rather than inventing a third
      # behaviour: re-POSTing a credential to a path the SCANNED TARGET chose
      # is exactly what a login flow must not do, and it would also double-
      # submit whatever the original body was.  307 and 308 exist precisely to
      # preserve the method and body, so they are left alone.
      if [[ $status == 303 ]] \
        || { [[ $status == 301 || $status == 302 ]] && [[ $method != GET && $method != HEAD ]]; }; then
        method=GET
        req_body=''
        req_has_body=false
        kept=()
        for item in "${req_headers[@]+"${req_headers[@]}"}"; do
          # Compared lowercased, because a header field name is
          # case-insensitive (RFC 7230 §3.2) and a caller is entitled to spell
          # it any way it likes; matching the one spelling this repository
          # happens to use today would leave the entity header attached to a
          # bodyless GET the first time somebody wrote it differently.
          case ${item%%:*} in
            [Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee] \
              | [Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]) continue ;;
          esac
          kept+=("$item")
        done
        req_headers=("${kept[@]+"${kept[@]}"}")
      fi
      continue
    fi

    _HTTP_LAST_STATUS=$status
    return 0
  done
}
