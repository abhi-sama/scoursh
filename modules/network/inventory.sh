#!/usr/bin/env bash
# modules/network/inventory.sh - the network module's `crawl.sh` analogue
# (NET-05, Tier 1, serial).
#
# THIS IS A PHASE SCRIPT, NOT A LIBRARY.  `net_run_phase`
# (modules/network/engine.sh) `source`s it once per target under the phase
# table's own 'inventory.sh:passive' row, so it DOES something at source
# time and carries no sourced-once guard - a guard would silently make a
# second target (or a second scan_main invocation in one process) a no-op,
# the identical contract modules/dast/crawl.sh's own header states.
#
# WHAT IT PRODUCES, AND WHY THAT IS THE WHOLE POINT: every Tier 2+ ticket
# reads this one artifact.
#
#     reports/<run>/inventory/listeners.json
#
# `net_inventory_read` (modules/network/engine.sh) is the one reader a future
# NET-06+ phase calls - the byte-identical `dast_inventory_read` shape one
# module down, so absent/empty/present is a vocabulary a reader never has to
# reinvent. THE SHAPE, deliberately kept small since nothing downstream exists
# yet to widen it against:
#
#   {
#     "schema": "scoursh.inventory.listeners/1",
#     "run_id": "...",
#     "generated_by": "modules/network/inventory.sh",
#     "target": "<the config/scope.conf target id>",
#     "listeners": [
#       {"target": "...", "role": "base-url", "scheme": "https",
#        "host": "...", "port": 443},
#       {"target": "...", "role": "extra-host", "scheme": "https",
#        "host": "...", "port": 8443}
#     ]
#   }
#
# `role` is `base-url` for the target's own base-url tuple and `extra-host`
# for every declared listener beyond it (rules/RULE-FORMAT.md §9.4).  `scheme`
# is the scheme config/scope.conf ATTRIBUTES to the tuple, not a claim about
# what the listener actually speaks: an extra-host tuple inherits its
# target's base-url scheme by construction (lib/http.sh's `http_scope_load`),
# so `https` on a declared SSH port is fiction the same way it already is at
# `http_authorize_raw_connection` - a future NET-07/NET-08
# probe decides what a listener really speaks by reading it, never by
# trusting this field.  `port` is a JSON number; every other field is a JSON
# string, through `json_string`/`json_number` (lib/core.sh, tension 10's one
# JSON writer) with no exception, because every value here came out of an
# operator's own config/scope.conf file.
#
# ONE FILE PER TARGET, OVERWRITTEN EACH RUN, not merged across runs or
# targets - the identical "producer owns its own artifact fully" contract
# modules/dast/crawl.sh's own endpoints.json write follows.  docs/DESIGN.md
# §5's grammar gives one `--target` per invocation, so there is exactly one
# target's worth of listeners to describe per run; a later ticket widening
# `--target` to a list changes this file's own loop, not its shape.
#
# HONESTY CONTRACT THIS FILE OWNS (rules 1 and 3 of the module's honesty
# contract - rules 2 and
# 4 belong to a future PROBE, since this ticket sends no traffic of its own
# and opens no socket):
#
#   RULE 1 (both halves).  Every tuple this file reads comes straight out of
#   config/scope.conf (`_HTTP_SCOPE_HOST`/`_HTTP_SCOPE_PORT`, populated by
#   `http_scope_load`), so every one of them is OPERATOR-CONFIGURED, never an
#   artifact this scanner authored itself.  The non-fatal, ARTIFACT-tuple path
#   modules/network/engine.sh already ships (`net_endpoint_keep`/
#   `net_scope_record_skips`) is reserved for a FUTURE tuple source - a
#   config/posture.conf `expect-closed` expectation, a cross-module inventory
#   row - that does not exist yet, and is
#   deliberately NOT called here: calling it on an operator-authored tuple
#   would silently soften the ONE authorization this module can actually rely
#   on being correct.  Every declared tuple is gated through
#   `http_authorize_raw_connection` DIRECTLY, which is fatal (die exit 3) on
#   every refusal reason - an out-of-scope port config/scope.conf never
#   declared (structurally unreachable here, since the tuple came FROM that
#   same scope, but the private/loopback deny list and a userinfo-bearing
#   authority are both real, independent refusal paths the gate re-checks
#   regardless of source - lib/http.sh's `http_gate_url` section 8) - WITH ONE
#   NAMED SOFTENING: a transient DNS-resolution failure on an otherwise
#   in-scope host (`dns_fatal=false`) degrades to one counted
#   `coverage_reduction` rather than aborting the run.  This is not a new
#   rule invented for this file - it is modules/dast/passive/tls.sh's own
#   established call shape, reused verbatim for the identical reason its own
#   header gives: a target here can declare SEVERAL listeners, and one bad
#   lookup aborting every sibling listener and every downstream NET-06+ probe
#   for the WHOLE RUN is exactly the disproportionate cost that comment
#   argues against.  There is no equivalent softening for the other refusal
#   reasons, because there is no non-fatal path for an operator's own
#   config/scope.conf entry: an operator-declared listener that resolves to a
#   private address without `allow-private-addresses: true`, or one that
#   somehow carries userinfo, is a config mistake to surface loudly, the
#   identical "an operator-authored scope.conf mistake reads as 'this scanner
#   refused to even ask', never as 'this port is closed'" argument
#   tests/suites/network.sh's own tuple section already pins for
#   `http_authorize_raw_connection` directly.
#
#   RULE 3.  A target whose declared set holds ONLY its base-url - no
#   extra-host tuple exists in config/scope.conf for it at all - writes NO
#   `listeners.json`.  "Absent" is deliberately reused rather than a third
#   state invented for this one case: docs/FOUNDATION.md tension 21's own
#   vocabulary already treats "no producer had anything to say" as a state a
#   consumer must expect, and modules/dast/engine.sh's `dast_inventory_read`
#   already gives it a name (`absent`) this file's own `net_inventory_read`
#   reuses.  ONE `coverage_gap` is recorded naming why, then this phase
#   returns 0 - "this host has one listener"
#   and "scoursh did not look" are different facts, and a silent
#   zero-listener run would collapse them into one.  The SAME "absent, one
#   named coverage_gap" shape is used, for a DIFFERENT reason worded
#   accordingly, when at least one extra-host tuple WAS declared but every
#   one of them was dropped by the DNS softening above: the authorised set
#   still reduces to base-url alone, and a reader of `listeners.json`'s
#   absence must not have to guess which of the two happened - the
#   coverage_gap text always says which.
#
# shellcheck shell=bash

_net_inv_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    log_warn 'network/inventory: no target in context; nothing to inventory'
    return 0
  fi
  local rundir=${SCOURSH_RUN_DIR:-}
  if [[ -z $rundir || ! -d $rundir ]]; then
    log_warn 'network/inventory: no run directory; nothing to write'
    return 0
  fi

  # A direct-engine test suite can source this file with no lib/http.sh
  # anywhere in the process (the identical shape tests/suites/dast-cors.sh's
  # own `dast_check_selected` guard exists for) - permissive-when-absent
  # here too, recorded as a declared reduction rather than an unbound-array
  # crash under `set -u`.
  if ! declare -F http_scope_load >/dev/null 2>&1 \
    || ! declare -F http_authorize_raw_connection >/dev/null 2>&1; then
    declare -F run_record >/dev/null 2>&1 && run_record coverage_reduction "module=network phase=inventory.sh reason=net_http_lib_not_loaded target=$(net_scope_safe_text "$target" 80) - lib/http.sh was not sourced in this process, so config/scope.conf's declared listener set could not be read or authorised. A real scan.sh run always loads it; this is the shape a direct-engine test suite deliberately creates."
    return 0
  fi

  http_scope_load

  # -- 1. read the declared tuples for this target off _HTTP_SCOPE_* --------
  # http_scope_load's own loop (lib/http.sh) adds the base-url row for a
  # target FIRST, then one row per extra-host in file order - so the first
  # array index carrying this target's id is base-url and every later one is
  # a declared additional listener.  Never re-sorted: config/scope.conf's own
  # file order is the operator's, and there is no reason to reorder it.
  local i n=${#_HTTP_SCOPE_ID[@]} seen_base=false
  local base_scheme='' base_host='' base_port=''
  local -a extra_scheme=() extra_host=() extra_port=()
  for (( i = 0; i < n; i++ )); do
    [[ ${_HTTP_SCOPE_ID[i]} == "$target" ]] || continue
    if ! $seen_base; then
      seen_base=true
      base_scheme=${_HTTP_SCOPE_SCHEME[i]}
      base_host=${_HTTP_SCOPE_HOST[i]}
      base_port=${_HTTP_SCOPE_PORT[i]}
      continue
    fi
    extra_scheme+=("${_HTTP_SCOPE_SCHEME[i]}")
    extra_host+=("${_HTTP_SCOPE_HOST[i]}")
    extra_port+=("${_HTTP_SCOPE_PORT[i]}")
  done

  # config_scope_require already validated this target exists in
  # config/scope.conf before net_run_phase ever reached this file
  # (modules/network/run.sh's own pre-loop) - a target with no scope row at
  # all here means its base-url failed to normalise (http_scope_load's own
  # log_warn-and-skip path), a config defect rather than a clean result.
  if ! $seen_base; then
    run_record coverage_reduction "module=network phase=inventory.sh reason=net_target_has_no_scope_tuple target=$(net_scope_safe_text "$target" 80)"
    run_record coverage_gap "network inventory: target '$(net_scope_safe_text "$target" 80)' produced no usable (scheme,host,port) tuple from config/scope.conf - its base-url likely failed to parse - so its declared listener set is unknown, not empty. This is a configuration defect, not a clean result."
    return 0
  fi

  if (( ${#extra_host[@]} == 0 )); then
    run_record coverage_gap "network inventory: target '$(net_scope_safe_text "$target" 80)' declares only its base-url ($base_scheme://$base_host:$base_port) and no additional extra-host listener in config/scope.conf, so modules/network/'s declared listener set for it is empty. 'This host has one listener' and 'scoursh did not look' are different facts - this is a stated fact about the target's configuration, not a failed probe."
    return 0
  fi

  # -- 2. gate every declared listener, base-url included -------------------
  # An operator-configured tuple is refused FATALLY
  # (this file's own header, above) except for the one named DNS softening.
  # `_NET_INV_LISTENERS` accumulates one packed record per authorised
  # listener, 0x1f-joined (role/scheme/host/port) - a `declare -g` module
  # accumulator that `_net_inv_write_listeners` reads directly, never a
  # by-name argument: `local -n` namerefs need bash 4.3 and lib/core.sh's own
  # frozen minimum is 4.2, so this repository's own precedent
  # (modules/dast/crawl_engine.sh's `_CRAWL_EP`,
  # modules/cloud/aws/live/route53.sh's `_R53_KNOWN_BUCKETS`) is a global
  # accumulator, never an eval-based array-by-name workaround.
  declare -ga _NET_INV_LISTENERS=()
  local url j dns_dropped=0 dns_reasons=''
  local -A dns_reason_seen=()

  url="$base_scheme://$base_host:$base_port/"
  if http_authorize_raw_connection "$url" "$target" false; then
    _NET_INV_LISTENERS+=("base-url"$'\x1f'"$base_scheme"$'\x1f'"$base_host"$'\x1f'"$base_port")
  else
    dns_dropped=$(( dns_dropped + 1 ))
    if [[ -z ${dns_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
      dns_reason_seen[$_HTTP_RAW_REASON]=1
      dns_reasons+="${dns_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
    fi
  fi

  for (( j = 0; j < ${#extra_host[@]}; j++ )); do
    url="${extra_scheme[j]}://${extra_host[j]}:${extra_port[j]}/"
    if http_authorize_raw_connection "$url" "$target" false; then
      _NET_INV_LISTENERS+=("extra-host"$'\x1f'"${extra_scheme[j]}"$'\x1f'"${extra_host[j]}"$'\x1f'"${extra_port[j]}")
    else
      dns_dropped=$(( dns_dropped + 1 ))
      if [[ -z ${dns_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        dns_reason_seen[$_HTTP_RAW_REASON]=1
        dns_reasons+="${dns_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
    fi
  done

  if (( dns_dropped > 0 )); then
    # ONE reduction naming the count, never one per dropped tuple - the
    # identical "do not flood run.json with a line per port" discipline
    # modules/network/engine.sh's own `net_scope_record_skips` documents.
    run_record coverage_reduction "module=network phase=inventory.sh reason=net_listener_unresolvable target=$(net_scope_safe_text "$target" 80) count=$dns_dropped - that many declared listener(s) for this target did not resolve and were dropped from the authorised set; nothing about them will be tested by a later phase. Reason(s): $dns_reasons."
  fi

  # -- 3. write the authorised set, or the rule-3 absent-artifact case -------
  if (( ${#_NET_INV_LISTENERS[@]} <= 1 )); then
    # Every extra-host tuple was declared but none survived gating (the
    # base-url row alone remains, or - if even it failed to resolve -
    # nothing at all).  Content-equivalent to the "nothing declared" case
    # above, so it gets the SAME absent-artifact shape; the coverage_gap
    # text is what tells the two apart for a reader.
    run_record coverage_gap "network inventory: target '$(net_scope_safe_text "$target" 80)' declared ${#extra_host[@]} extra-host listener(s) in config/scope.conf, but none of them survived authorisation this run (see the net_listener_unresolvable reduction above), so the authorised listener set is effectively empty. This is the absence of a test, not the absence of a problem."
    return 0
  fi

  mkdir -p "$rundir/inventory"
  _net_inv_write_listeners "$rundir/inventory/listeners.json" "$target"

  run_record notes "module=network phase=inventory target=$(net_scope_safe_text "$target" 80) listeners=${#_NET_INV_LISTENERS[@]}"
  return 0
}

# `_net_inv_write_listeners OUT TARGET` - reads the module-global
# `_NET_INV_LISTENERS` accumulator (set 2, above) directly, the identical
# shape `modules/dast/crawl_engine.sh`'s own `crawl_inv_write_endpoints`
# reads `_CRAWL_EP` (a global, never a by-name argument - bash 4.2's frozen
# minimum has no nameref).  Each record is 0x1f-joined
# "role<0x1f>scheme<0x1f>host<0x1f>port", unpacked with
# `IFS=$'\x1f' read -r ...`.  Written through `json_string`/`json_number` for
# every field, with no exception - lib/core.sh's writer is the ONE place a
# string becomes JSON in this repository (tension 10).
_net_inv_write_listeners() {
  local out=$1 target=$2
  local rec role scheme host port first=1
  {
    printf '{\n'
    printf '  "schema": %s,\n' "$(json_string 'scoursh.inventory.listeners/1')"
    printf '  "run_id": %s,\n' "$(json_string "${SCOURSH_RUN_ID:-}")"
    printf '  "generated_by": %s,\n' "$(json_string 'modules/network/inventory.sh')"
    printf '  "target": %s,\n' "$(json_string "$target")"
    printf '  "listeners": ['
    for rec in "${_NET_INV_LISTENERS[@]+"${_NET_INV_LISTENERS[@]}"}"; do
      IFS=$'\x1f' read -r role scheme host port <<<"$rec"
      (( first )) && printf '\n' || printf ',\n'
      first=0
      printf '    {"target": %s, "role": %s, "scheme": %s, "host": %s, "port": %s}' \
        "$(json_string "$target")" "$(json_string "$role")" \
        "$(json_string "$scheme")" "$(json_string "$host")" \
        "$(json_number "$port")"
    done
    (( first )) || printf '\n  '
    printf ']\n}\n'
  } >"$out"
}

_net_inv_run
