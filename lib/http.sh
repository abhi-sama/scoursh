#!/usr/bin/env bash
# lib/http.sh - the destination-allowlist enforcement chokepoint for every
# curl-based network call.
#
# Owns:
#   docs/DESIGN.md          §2 (the egress model), §4 (lib/http.sh)
#   docs/FOUNDATION.md tension 19 (scope-gate semantics: the tuple this file matches)
#   docs/FOUNDATION.md tension 27 (the "air-gapped" premise was wrong)
#   docs/adr/0001-egress-model-correction.md
#
# SCOPE OF THIS FILE, stated rather than assumed.  Tension 19 gives the full
# scope gate a resolution-pinning cache, a private-address deny list, and a
# manual redirect loop; none of that exists yet, and none of it is this
# ticket's job.  What landed here, ahead of §13 step 5, is the destination
# check itself: does a (scheme, host, port) tuple appear in a caller's
# allowlist. That is deliberately NOT host-only matching - tension 19 names
# and rejects that exact design ("silently authorises every port on the
# host"), so this file matches the full tuple from the start rather than
# shipping the rejected shortcut and fixing it at step 5. AWS's destination
# category is a SEPARATE call path (the `aws` CLI, not curl) and is gated by
# the sibling chokepoint lib/awscli.sh, not by this file.
#
# Callers opt into exactly the destination categories they need by calling
# http_allow_scope_hosts and/or http_allow_update_endpoint before
# http_request.  A DAST caller only ever calls the former; the update channel
# only ever calls the latter.  There is no single global "everything scan-time
# needs" allowlist - each caller's blast radius is only what it asked for.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_HTTP_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_HTTP_SOURCED=1

# shellcheck source=lib/records.sh
source "${BASH_SOURCE[0]%/*}/records.sh"

: "${SCOURSH_HTTP_TIMEOUT:=20}"

# ---------------------------------------------------------------------------
# 1. The allowlist
# ---------------------------------------------------------------------------
# "scheme host port" tuple -> category label ("scope" | "update-channel"), used
# for logging and introspection, never for authorization itself (that reads
# the map directly).
declare -A _HTTP_ALLOW_TUPLE=()
# "scheme port basehost" -> 1, for scope targets whose allow-subdomains is
# true.  The update endpoint never gets subdomain matching: it is one
# operator-configured, first-party host, not an operator-approved target list.
declare -A _HTTP_ALLOW_SUBDOMAIN=()
_HTTP_UPDATE_URL=''

http_reset_allowlist() {
  _HTTP_ALLOW_TUPLE=()
  _HTTP_ALLOW_SUBDOMAIN=()
  _HTTP_UPDATE_URL=''
}

_http_tuple_key() { printf '%s %s %s' "$1" "$2" "$3"; }

_http_allow_add() {
  local scheme=$1 host=$2 port=$3 category=$4 subs=$5
  [[ -n $host ]] || return 0
  _HTTP_ALLOW_TUPLE[$(_http_tuple_key "$scheme" "$host" "$port")]=$category
  [[ $subs == true ]] && _HTTP_ALLOW_SUBDOMAIN["$scheme $port $host"]=1
  return 0
}

# Splits an http(s) URL into `scheme\thost\tport`, or fails on anything that is
# not a well-formed http(s) authority.  Port defaults from the scheme when
# absent (tension 19: "the port defaulted from the scheme when absent").
#
# Credentials embedded in a URL (`user:pass@host`) are refused outright rather
# than stripped: scope and update-endpoint URLs never legitimately carry them
# (auth.conf is where DAST credentials belong, tension 9), and silently
# stripping would let `https://allowed.example@evil.example/` resolve to a
# host nobody reviewed.
_http_split_url() {
  local u=$1 scheme rest authority host port
  case $u in
    http://*)
      scheme=http
      rest=${u#http://}
      ;;
    https://*)
      scheme=https
      rest=${u#https://}
      ;;
    *) return 1 ;;
  esac
  authority=${rest%%/*}
  authority=${authority%%\?*}
  authority=${authority%%\#*}
  [[ $authority != *@* ]] || return 1
  if [[ $authority == *:* ]]; then
    host=${authority%%:*}
    port=${authority#*:}
    [[ $port =~ ^[0-9]+$ ]] || return 1
  else
    host=$authority
    case $scheme in
      http) port=80 ;;
      https) port=443 ;;
    esac
  fi
  host=${host%.}
  host=${host,,}
  [[ -n $host ]] || return 1
  # A trailing newline is required: `read` from a process substitution with no
  # final delimiter returns non-zero even after successfully assigning every
  # field (measured), which would make every caller's `|| die`/`|| continue`
  # fire on the SUCCESS path too.
  printf '%s\t%s\t%s\n' "$scheme" "$host" "$port"
}

# `http_allow_scope_hosts [PATH]` - admits every config/scope.conf target's
# (scheme, host, port) tuple (base-url + extra-host entries), honouring
# allow-subdomains.  Host matching alone is deliberately not offered (see the
# file header): every admission goes through the full tuple.
#
# extra-host entries are `host` or `host:port`, carrying no scheme; they are
# admitted on the SAME scheme as the target's base-url, since §11 gives them no
# scheme of their own and tension 19 does not either.
# shellcheck disable=SC2120
http_allow_scope_hosts() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  [[ -r $path ]] || return 0
  records_load "$path" scope-target httpscope || die "$SCOURSH_EXIT_INPUT" \
    "config/scope.conf failed to parse"
  local n i url subs h scheme host port extraport
  n=$(records_count httpscope)
  for (( i = 0; i < n; i++ )); do
    url=$(records_field httpscope "$i" base-url)
    subs=$(records_field_or httpscope "$i" allow-subdomains false)
    IFS=$'\t' read -r scheme host port < <(_http_split_url "$url") || continue
    _http_allow_add "$scheme" "$host" "$port" scope "$subs"
    while IFS= read -r h; do
      [[ -n $h ]] || continue
      if [[ $h == *:* ]]; then
        extraport=${h#*:}
        h=${h%%:*}
      else
        extraport=$port
      fi
      [[ $extraport =~ ^[0-9]+$ ]] || continue
      h=${h%.}
      _http_allow_add "$scheme" "${h,,}" "$extraport" scope "$subs"
    done <<<"$(records_list httpscope "$i" extra-host)"
  done
  return 0
}

# `http_allow_update_endpoint [PATH]` - admits exactly the (scheme, host,
# port) tuple of scanner.conf's advisory-update-url, and nothing else.  A
# scanner.conf with no such key leaves the update channel unconfigured: no
# destination is admitted, rather than guessing one.
http_allow_update_endpoint() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scanner.conf}
  _HTTP_UPDATE_URL=''
  [[ -r $path ]] || return 0
  records_load "$path" scanner-config httpscanner || die "$SCOURSH_EXIT_INPUT" \
    "config/scanner.conf failed to parse"
  (( $(records_count httpscanner) > 0 )) || return 0
  local url scheme host port
  url=$(records_field_or httpscanner 0 advisory-update-url '')
  [[ -n $url ]] || return 0
  IFS=$'\t' read -r scheme host port < <(_http_split_url "$url") || die "$SCOURSH_EXIT_INPUT" \
    "config/scanner.conf: advisory-update-url '$url' is not a well-formed http(s) URL"
  _HTTP_UPDATE_URL=$url
  _http_allow_add "$scheme" "$host" "$port" update-channel false
  return 0
}

http_update_url() { printf '%s' "$_HTTP_UPDATE_URL"; }

# `http_url_allowed URL` - the authorization predicate.  Never called with a
# bare host: a host-only check is precisely the design tension 19 rejects.
http_url_allowed() {
  local url=$1 scheme host port base
  IFS=$'\t' read -r scheme host port < <(_http_split_url "$url") || return 1
  [[ -n ${_HTTP_ALLOW_TUPLE[$(_http_tuple_key "$scheme" "$host" "$port")]:-} ]] && return 0
  for base in "${!_HTTP_ALLOW_SUBDOMAIN[@]}"; do
    [[ $base == "$scheme $port "* ]] || continue
    base=${base#"$scheme $port "}
    [[ $host == "$base" || $host == *".$base" ]] && return 0
  done
  return 1
}

http_url_category() {
  local url=$1 scheme host port
  IFS=$'\t' read -r scheme host port < <(_http_split_url "$url") || return 0
  printf '%s' "${_HTTP_ALLOW_TUPLE[$(_http_tuple_key "$scheme" "$host" "$port")]:-}"
}

# `scheme\thost\tport\tcategory` per admitted destination, sorted - for
# run.json/tests, never for authorization (that is http_url_allowed alone).
http_allowed_destinations() {
  local k
  for k in "${!_HTTP_ALLOW_TUPLE[@]}"; do
    printf '%s\t%s\n' "${k// /$'\t'}" "${_HTTP_ALLOW_TUPLE[$k]}"
  done | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 2. The chokepoint
# ---------------------------------------------------------------------------
# `http_request METHOD URL [curl-args...]` - every curl-based network call
# goes through here.  Extra arguments pass straight to curl (`-o FILE`,
# `-H ...`), so this stays the single place the allowlist is consulted without
# dictating every caller's curl usage.
#
# Aborts with exit 3 (SCOURSH_EXIT_SCOPE) on any destination not admitted by
# the caller's own http_allow_* calls - the same exit code and the same
# "scope violation" framing docs/FOUNDATION.md tension 19 already uses for
# DAST. Resolution pinning against the private-address deny list (tension 19)
# is step-5 work and is not implemented here; this chokepoint gates the
# DESTINATION, not yet the resolved address.
http_request() {
  local method=$1 url=$2
  shift 2
  case $method in
    GET | HEAD) ;;
    *) die "$SCOURSH_EXIT_USAGE" "http_request: unsupported method '$method'" ;;
  esac
  _http_split_url "$url" >/dev/null || die "$SCOURSH_EXIT_SCOPE" \
    "refusing '$url': not a well-formed http(s) URL"
  http_url_allowed "$url" || die "$SCOURSH_EXIT_SCOPE" \
    "refusing '$url': not in the resolved destination allowlist"
  require_cmd curl
  log_info "http_request: $method $url (category: $(http_url_category "$url"))"
  curl -sS --fail --max-time "$SCOURSH_HTTP_TIMEOUT" \
    -A "scoursh/$(scoursh_version)" -X "$method" "$@" -- "$url"
}
