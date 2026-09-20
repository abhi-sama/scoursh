#!/usr/bin/env bash
# modules/network/httpport_engine.sh - the pure, testable half of NET-09:
# HTTP identification on a non-standard port - one `http_request` GET.
# Everything modules/dast/passive/banner.sh already does, pointed at port
# 8080 instead of 443, and it reuses banner_engine.sh's product
# normalisation and the data/versions.db `banner` namespace unchanged.
#
# THE ENGINE.SH / PHASE-SCRIPT SPLIT IS modules/sast/'s, reused one level
# down exactly as modules/network/inventory.sh and every modules/dast/
# phase already do: this file has the standard sourced-once guard and no
# side effects at source time beyond the one listener reader below, and
# modules/network/httpport.sh is the file `net_run_phase` sources.
#
# NOTHING NEW ON THE DETECTION SIDE.  banner_engine.sh's product
# normalisation (`banner_normalize_product`/`banner_is_version`/...), its
# three disclosure channels (a response header, an HTML generator meta tag,
# a versioned bundle filename) and its `data/versions.db` `banner`-namespace
# lookup (`banner_db_state`/`banner_db_known`/`banner_db_match`) are sourced
# and used UNCHANGED - report.md's own explicit instruction, and the reason
# this file is small: the only thing NET-09 adds is WHERE the bytes it hands
# to those functions came from (a declared non-standard-port listener
# instead of a crawled DAST endpoint) and WHAT identity the finding carries
# (the `net` location profile, not DAST's).
#
# THE ONE THING THIS FILE DOES OWN: reading
# `reports/<run>/inventory/listeners.json` (NET-05,
# modules/network/inventory.sh) and picking out the candidates - the
# declared EXTRA-HOST tuples, never the target's own `base-url` row.
# `base-url` is the target's STANDARD web endpoint and is already covered by
# the whole of `modules/dast/`'s own passive/active tiers at full depth; an
# `extra-host` row is, by construction, every OTHER declared listener
# config/scope.conf names for this target - which is exactly what "a
# non-standard HTTP port" means here, and it needs no port-number heuristic
# (8080 vs 443 vs anything else) to decide: NET-05's own inventory.sh
# already drew that line when it split `role: base-url` from
# `role: extra-host` (modules/network/inventory.sh's own header).
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_NETWORK_HTTPPORT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_NETWORK_HTTPPORT_ENGINE_SOURCED=1

# banner_engine.sh carries its own sourced-once guard and pulls in
# lib/core.sh, lib/records.sh and modules/dast/crawl_engine.sh (for
# `crawl_json_flatten`, reused below for the identical reason
# banner_endpoints_load reuses it for endpoints.json: a producer that
# formats listeners.json differently is still read correctly through the
# one depth- and string-aware parser this repository has, rather than a
# second, purpose-built one for a schema NET-05 already owns).
# shellcheck source=modules/dast/passive/banner_engine.sh
source "${BASH_SOURCE[0]%/*}/../dast/passive/banner_engine.sh"

# ---------------------------------------------------------------------------
# The declared listener set (NET-05's own reports/<run>/inventory/listeners.json)
# ---------------------------------------------------------------------------
# `httpport_listeners_load [FILE] [TARGET]` - reads the artifact
# `net_inventory_read` (modules/network/engine.sh) already located, and sets:
#
#   _HTTPPORT_L_N                   candidate extra-host listener count
#   _HTTPPORT_L_SCHEME/_HOST/_PORT  one entry each, parallel arrays
#
# Content NOT parsed by net_inventory_read itself (modules/network/engine.sh's
# own header: "no NET-06+ consumer exists yet to agree with a shape ... each
# future consumer's own job") - this is that consumer, and it is the ONLY
# place in this ticket that reads listeners.json's own shape.
#
# AN ABSENT, EMPTY OR UNUSABLE INVENTORY IS THE NORMAL STATE and leaves
# `_HTTPPORT_L_N` at 0; it is never an error here, mirroring
# banner_endpoints_load's own contract for endpoints.json one module over.
#
# THE ORDER IS SORTED (`LC_ALL=C`), NOT THE FILE'S - the identical reasoning
# banner_endpoints_load's own header gives: a deterministic order is what
# keeps a listener's identity (and therefore its finding's fingerprint)
# stable across two runs over an unchanged declared set, and what makes a
# future per-run cap (there is none today; every declared listener is
# probed) test a consistent subset rather than whichever the file happened
# to list first.
httpport_listeners_load() {
  local file=${1:-} want_target=${2:-}
  local sep=$'\x1f' p type v idx key rest last_idx=''
  declare -ga _HTTPPORT_L_SCHEME=() _HTTPPORT_L_HOST=() _HTTPPORT_L_PORT=()
  declare -g _HTTPPORT_L_N=0
  [[ -n $file && -r $file && -s $file ]] || return 0

  # `-g` is load-bearing for the identical reason
  # modules/dast/passive/banner_engine.sh's own `_BANNER_EP_RAW` is declared
  # `-g`: `_httpport_flush_listener` below writes to it by its literal
  # (global) name rather than through an indirection, which is what bash
  # 4.2 - tension 24's frozen minimum, with no `local -n` nameref - can do
  # without one.
  declare -ga _HTTPPORT_L_RAW=()
  local -A cur=()
  while IFS=$'\t' read -r p type v; do
    [[ $p == listeners* ]] || continue
    rest=${p#listeners}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _httpport_flush_listener cur "$want_target"
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    cur[$key]=$v
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _httpport_flush_listener cur "$want_target"

  (( ${#_HTTPPORT_L_RAW[@]} > 0 )) || return 0
  local scheme host port
  while IFS=$'\t' read -r scheme host port; do
    [[ -n $host && -n $port ]] || continue
    _HTTPPORT_L_SCHEME+=("$scheme")
    _HTTPPORT_L_HOST+=("$host")
    _HTTPPORT_L_PORT+=("$port")
    _HTTPPORT_L_N=$(( _HTTPPORT_L_N + 1 ))
  done < <(printf '%s\n' "${_HTTPPORT_L_RAW[@]+"${_HTTPPORT_L_RAW[@]}"}" | LC_ALL=C sort -u)
  return 0
}

# Bash 4.2 has no namerefs (tension 24's frozen minimum), so the in-progress
# record is passed BY NAME and read through `${!...}` indirection - the
# identical shape modules/dast/passive/banner_engine.sh's own
# `_banner_flush_endpoint` uses for the same reason. The output accumulator
# (`_HTTPPORT_L_RAW`, declared `-g` by the caller just above) is written by
# its literal global name instead, exactly as `_BANNER_EP_RAW` is there -
# nothing here needs a second indirection for it.
#
# SC2034: `cur` is written by the caller and read here only through that
# indirection, which shellcheck cannot see.
# shellcheck disable=SC2034
_httpport_flush_listener() {
  local curname=$1 want_target=$2
  local rr="${curname}[role]" sr="${curname}[scheme]" hr="${curname}[host]" pr="${curname}[port]" tr="${curname}[target]"
  local role=${!rr:-} scheme=${!sr:-} host=${!hr:-} port=${!pr:-} target=${!tr:-}
  # `base-url` is the target's standard web endpoint, already covered in
  # full by modules/dast/ - never a candidate here (this file's own header).
  [[ $role == extra-host ]] || return 0
  [[ -n $scheme && -n $host && -n $port ]] || return 0
  if [[ -n $want_target && -n $target && $target != "$want_target" ]]; then
    return 0
  fi
  # Only http/https are meaningful to an `http_request` GET. NET-05's own
  # header states scheme is always inherited from the target's base-url
  # scheme, so this is a defensive floor rather than an expected filter -
  # a future scope.conf scheme this module does not model must not be
  # handed to http_request as if it were HTTP.
  case $scheme in
    http | https) ;;
    *) return 0 ;;
  esac
  _HTTPPORT_L_RAW+=("$scheme"$'\t'"$host"$'\t'"$port")
  return 0
}
