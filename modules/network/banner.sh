#!/usr/bin/env bash
# modules/network/banner.sh - the NET-07 tier-2 probe (read-on-connect
# service identification, `NET-SVC-BANNER_DISCLOSURE-01`) AND NET-11 (the
# version->vulnerability lookup against that same disclosure,
# `NET-SVC-OUTDATED_COMPONENT-01`, staged as depending on NET-07).
#
# NET-11 LANDS INSIDE THIS FILE, NOT AS A NEW PHASE SCRIPT.  The
# original staging sketched NET-11 as though it might be a peer file, but
# modules/network/engine.sh's `_NET_PHASES` phase table carries no row for
# one, and modules/network/httpport.sh (NET-09) already set the real
# precedent this ticket follows instead: its own
# `NET-SVC-HTTP_OUTDATED_COMPONENT-01` check lives inside NET-09's OWN phase
# script, driven off the SAME response NET-09's disclosure checks already
# read, rather than as a second phase re-reading an artifact this module
# writes none of (modules/network/engine.sh's own header: "Every declared
# listener is classified via the SAME net_connect_probe ... with a SECOND,
# independent connection - not a read of any artifact reachability.sh
# produced, because that phase writes no persisted per-listener state").  A
# separate NET-11 phase would need EITHER a third redundant connection to
# every listener (this module's own deliberate "no exploit or
# version-confirmation probe" boundary already treats a second read of the
# same banner as pointless traffic) OR a new on-disk artifact this module
# has never needed before, for a check whose entire input - `_NET_BANNER_PRODUCT` /
# `_NET_BANNER_VERSION` - this file's own identification pass already holds
# in-process the moment it identifies something. So the outdated-component
# check is evaluated in the SAME listener-loop iteration, immediately after
# `net_banner_identify_text` succeeds, exactly where NET-09's own
# `_httpport_consider` evaluates it immediately after ITS identification
# pass succeeds.
#
# THIS IS A PHASE SCRIPT: modules/network/engine.sh's `net_run_phase` reaches
# it with a plain `source` (at tier `passive`, so it runs on every network
# run, including the default intensity), so it inherits the whole run
# context and anything it emits lands in this process's shard.  Per that
# function's contract it carries NO sourced-once guard.  The pure half - the
# banner sanitizer, the product/version identifier, the finding emitters
# (`banner_emit_disclosure` and NET-11's own `banner_emit_outdated`) - is
# modules/network/banner_engine.sh.
#
# NET-11'S CONFIDENCE IS ALWAYS `medium`, NEVER `high` - the same backport
# problem, restated at every call site that can raise the finding:
# a version read off a raw TCP banner is the listener's own self-reported
# upstream string, and a distribution that backports a security fix (the
# canonical Debian/RHEL openssh example) does so under an UNCHANGED
# version string, so an exact `data/versions.db` match can name a host that
# is genuinely already patched. `banner_emit_outdated`
# (modules/network/banner_engine.sh) hardcodes `confidence: medium` and
# states the limitation in the finding's OWN `remediation` field - never a
# per-call choice this file could get wrong by omission.
#
# NET-11 IS AN EXACT TABLE LOOKUP, NEVER RANGE ARITHMETIC (docs/FOUNDATION.md
# tension 25).  `banner_db_match` (modules/dast/passive/
# banner_engine.sh, sourced transitively below) is a byte-for-byte
# `(product, version)` match against `data/versions.db`'s `banner` namespace
# - there is no "close enough" comparison anywhere in this path, and none is
# ever added to it.
#
# WHAT THIS PROBE SENDS, AND WHY IT IS `passive` AND NOT `safe-active`.  ZERO
# BYTES, ever, to any listener - lib/nettransport.sh's `net_read_banner`
# opens a socket, reads whatever the far end volunteers within a bounded
# deadline, and closes it, never writing to the fd (that file's own header
# states the same about `net_connect_probe`, and this function shares its
# connect step).  This check carries the `passive`
# tag for exactly that reason, distinct from NET-06's `safe-active` connect
# probe - see modules/network/checks-banner.rules' own header for the
# contrast in full.
#
# THIS PROBE REUSES NET-06'S OWN OPEN/NOT-OPEN/FILTERED CLASSIFICATION, AND
# DOES NOT RE-IMPLEMENT IT.  Every declared listener is classified via the
# SAME `net_connect_probe` (lib/nettransport.sh) modules/network/
# reachability.sh itself calls, with a SECOND, independent connection - not
# a read of any artifact reachability.sh produced, because that phase writes
# no persisted per-listener state (the three-state classification lives
# entirely in that phase's own process; there is nothing on disk for a
# sibling phase to read).  "Reuse the classification" therefore means "call
# the same shared primitive reachability.sh calls", never "invent a second
# way to decide whether a port is open" - the identical division of labour
# every §7.3 DAST probe already applies to `http_request` rather than
# growing its own transport.  Only an `open` listener is ever handed to
# `net_read_banner`; a not-open or filtered one is counted into this check's
# own `net_check_not_applicable` reduction and is never read from.
#
# shellcheck shell=bash
#
# SC2016: see modules/network/banner_engine.sh's own header for why.
# shellcheck disable=SC2016
#
# shellcheck source=modules/network/banner_engine.sh
source "${BASH_SOURCE[0]%/*}/banner_engine.sh"
# lib/nettransport.sh (NET-03/NET-07) carries no sourced-once guard of its
# own (redefining bash functions is idempotent) - sourced unconditionally
# here, matching modules/network/reachability.sh's own identical comment,
# for `net_connect_probe`, `net_probe_capability` and `net_read_banner`.
# shellcheck source=lib/nettransport.sh
source "${BASH_SOURCE[0]%/*}/../../lib/nettransport.sh"
# For http_authorize_raw_connection - re-authorized and re-resolved
# immediately before THIS probe's own connections, for the identical
# anti-TOCTOU reasoning modules/network/reachability.sh's own header states
# at length (listeners.json is already-authorized operator config, but the
# pinned-resolution guarantee is only real when re-asserted at the moment a
# probe actually dials out, which can happen an arbitrary amount of time
# after inventory.sh wrote that artifact).  Permissive-when-absent via
# `declare -F` everywhere this file calls it, the identical
# direct-engine-test shape reachability.sh's own header names.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# The number of bytes read per listener.  Large enough for a multi-line SMTP
# greeting (several "220-..." lines plus a final "220 ..." line) while
# staying well inside `SCOURSH_EVIDENCE_MAX_BYTES` (512, lib/findings.sh)
# once the evidence text around it is added - `_banner_safe_text`'s own 200
# byte bound is what actually reaches a finding, this is only how much is
# ever read off the wire.
: "${_NET_BANNER_MAX_BYTES:=1024}"

# `_banner_capability_reduction TARGET` - the ONE check-level reduction for a
# bash built without --enable-net-redirections, similar in shape to
# modules/network/reachability.sh's own `_reach_capability_reduction` and
# for the identical reason (AGENTS.md's "checks_run must count what
# SUCCEEDED" lesson): checked BEFORE the listener loop rather than left to
# happen per-listener, so a host with no /dev/tcp support records ONE named
# reduction naming this check, not a `checks_run` entry the moment any
# listener was merely attempted.
#
# `checks=[ID]`, PLURAL and BRACKETED, is deliberate and is NOT the same
# spelling reachability.sh's own two reductions use (`check=ID`/
# `check=[ID ID]`, singular).  `modules/network/run.sh`'s own
# `_net_record_unaccounted` - the honesty backstop that flags a selected
# check no phase ever explained - reads `run_facts coverage_reduction` for
# the literal substring `checks=[`, never `check=` alone (that singular form
# is only recognised inside a DIFFERENT fact, `skipped_checks`, which no
# phase in this module writes today).  This check is `passive`-tagged and so
# IS selected under this module's own default `--intensity passive` -
# unlike NET-PORT-*'s `safe-active` tag, which is filtered out of selection
# entirely below `--intensity safe` and so never reaches that backstop at
# all - so a reduction spelled the other way here would leave a live,
# reachable false positive: `check_not_executed_no_reason_recorded` naming
# this id on the very target this function is explaining.  Measured by
# reproducing it against `tests/suites/network.sh`'s own `net-fixture`
# scenario before writing this note.
_banner_capability_reduction() {
  local target=$1
  run_record coverage_reduction "module=network phase=banner.sh reason=net_probe_cmd_absent checks=[NET-SVC-BANNER_DISCLOSURE-01 NET-SVC-OUTDATED_COMPONENT-01] target=$target - this bash was built without --enable-net-redirections (lib/nettransport.sh), so no TCP connect could be attempted for any of this target's declared listeners; neither check produced a real result and neither is recorded as covered."
  return 0
}

_banner_no_listeners_reduction() {
  local target=$1 why=$2
  run_record coverage_reduction "module=network phase=banner.sh reason=no_declared_listeners checks=[NET-SVC-BANNER_DISCLOSURE-01 NET-SVC-OUTDATED_COMPONENT-01] target=$target - $why"
  run_record coverage_gap "network banner: target '$(net_scope_safe_text "$target" 80)' has no usable declared listener set this run ($why), so no listener was read for a banner. This is the absence of a test, not the absence of a problem."
  return 0
}

# `_banner_db_state_reduction TARGET` - NET-11's own once-per-run versions.db
# state check, mirroring modules/network/httpport.sh's `db_outdated_ok`
# exactly (its own header names httpport.sh as the precedent this ticket
# follows).  Its state decides only whether the outdated-component check can
# run; disclosure needs no data at all, so a fresh clone still gets it.  Sets
# `_BANNER_OUTDATED_OK` (0/1) as its one output; called once, before the
# listener loop, never per-listener (AGENTS.md's "checks_run must count what
# SUCCEEDED" lesson - a run-level fact does not belong inside a per-item
# loop).
_banner_db_state_reduction() {
  local target=$1
  _BANNER_OUTDATED_OK=1
  banner_db_state
  case $_BANNER_DB_STATE in
    absent)
      _BANNER_OUTDATED_OK=0
      run_record coverage_reduction "module=network phase=banner.sh reason=versions_db_absent checks=[NET-SVC-OUTDATED_COMPONENT-01] target=$target - the vendored known-vulnerable version list at data/versions.db is missing or unreadable, so a discovered banner product/version was not checked against it. NET-SVC-BANNER_DISCLOSURE-01 was still checked. Populate the list on a networked box (docs/VERSIONS-DB.md); nothing in a scan ever fetches it."
      ;;
    no_banner_rows)
      _BANNER_OUTDATED_OK=0
      run_record coverage_reduction "module=network phase=banner.sh reason=versions_db_no_banner_rows checks=[NET-SVC-OUTDATED_COMPONENT-01] target=$target - data/versions.db exists but carries no \`banner\` rows, so no discovered banner product/version could be matched against a known-vulnerable one. This is the state of a fresh clone: the list is vendored by an operator action, never by a scan (docs/VERSIONS-DB.md). NET-SVC-BANNER_DISCLOSURE-01 was still checked."
      ;;
    present)
      run_record notes "module=network phase=banner target=$target versions_db=present${_BANNER_DB_GENERATED:+ generated=$_BANNER_DB_GENERATED}"
      ;;
  esac
  return 0
}

_banner_run() {
  local target=${SCOURSH_NET_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/network/banner.sh was reached with no target; net_run_phase publishes SCOURSH_NET_TARGET'
  fi

  if declare -F net_probe_capability >/dev/null 2>&1 && ! net_probe_capability; then
    _banner_capability_reduction "$target"
    return 0
  fi

  if declare -F net_inventory_read >/dev/null 2>&1; then
    net_inventory_read
  else
    _NET_LISTENERS_FILE='' _NET_LISTENERS_STATE=absent
  fi

  case $_NET_LISTENERS_STATE in
    absent)
      _banner_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json was not written this run (modules/network/inventory.sh writes no artifact for a target with only base-url, or every extra-host dropped)"
      return 0
      ;;
    empty)
      _banner_no_listeners_reduction "$target" \
        "reports/<run>/inventory/listeners.json exists but is empty"
      return 0
      ;;
  esac

  reach_listeners_load "$_NET_LISTENERS_FILE" "$target"
  if (( _REACH_N == 0 )); then
    _banner_no_listeners_reduction "$target" \
      "reports/<run>/inventory/listeners.json named no listener for target '$(net_scope_safe_text "$target" 80)'"
    return 0
  fi

  _banner_db_state_reduction "$target"
  local do_outdated=$_BANNER_OUTDATED_OK
  if declare -F net_check_selected >/dev/null; then
    net_check_selected NET-SVC-OUTDATED_COMPONENT-01 || do_outdated=0
  fi

  local i role scheme host port url addr state
  local open_ct=0 notopen_ct=0 filtered_ct=0 unresolvable_ct=0 nobanner_ct=0 disclosed_ct=0 outdated_ct=0
  local unresolvable_reasons=''
  local -A unresolvable_reason_seen=()
  local bfile=$SCOURSH_SCRATCH/net-banner.$BASHPID

  for (( i = 0; i < _REACH_N; i++ )); do
    role=${_REACH_ROLE[i]}
    scheme=${_REACH_SCHEME[i]}
    host=${_REACH_HOST[i]}
    port=${_REACH_PORT[i]}
    url="$scheme://$host:$port/"

    # The identical re-authorization
    # modules/network/reachability.sh's own header explains at length.
    if ! http_authorize_raw_connection "$url" "$target" false; then
      unresolvable_ct=$(( unresolvable_ct + 1 ))
      if [[ -z ${unresolvable_reason_seen[$_HTTP_RAW_REASON]:-} ]]; then
        unresolvable_reason_seen[$_HTTP_RAW_REASON]=1
        unresolvable_reasons+="${unresolvable_reasons:+; }$(net_scope_safe_text "$_HTTP_RAW_REASON")"
      fi
      continue
    fi
    addr=$_HTTP_RAW_ADDR

    # THE ONE PLACE THIS FILE REUSES NET-06'S CLASSIFICATION: the SAME
    # net_connect_probe call reachability.sh makes, on a second, independent
    # connection - see this file's own header for why that is "reuse", not
    # "re-implement".
    state=$(net_connect_probe "$addr" "$port")
    case $state in
      open)
        open_ct=$(( open_ct + 1 ))
        rm -f "$bfile"
        net_read_banner "$addr" "$port" "$_NET_BANNER_MAX_BYTES" "$bfile" || true
        if [[ -s $bfile ]]; then
          local text
          text=$(net_banner_read_text "$bfile" "$_NET_BANNER_MAX_BYTES")
          rm -f "$bfile"
          if [[ -n $text ]] && net_banner_identify_text "$text"; then
            disclosed_ct=$(( disclosed_ct + 1 ))
            banner_emit_disclosure "$target" "$role" "$scheme" "$host" "$port" \
              "$_NET_BANNER_PRODUCT" "$_NET_BANNER_VERSION" "$text"
            # NET-11: an exact data/versions.db `banner`-namespace match on
            # THIS SAME identification, never a second connection and never a
            # range/heuristic comparison. A name-only
            # disclosure (no version) has nothing to look up.
            if (( do_outdated )) && [[ -n $_NET_BANNER_VERSION ]] \
                && banner_db_match "$_NET_BANNER_PRODUCT" "$_NET_BANNER_VERSION"; then
              outdated_ct=$(( outdated_ct + 1 ))
              banner_emit_outdated "$target" "$role" "$scheme" "$host" "$port" \
                "$_NET_BANNER_PRODUCT" "$_NET_BANNER_VERSION"
            fi
          fi
          # A banner that arrived but identified nothing recognisable is a
          # real, honest "checked, nothing to flag" outcome (this check's
          # own registry header) - it is NOT no_banner (which
          # names a listener that sent NOTHING at all), so it is
          # neither a finding nor a reduction.
        else
          rm -f "$bfile"
          nobanner_ct=$(( nobanner_ct + 1 ))
        fi
        ;;
      not-open)
        notopen_ct=$(( notopen_ct + 1 ))
        ;;
      filtered | *)
        # `*` catches an unrecognised SCOURSH_NET_PROBE stub result the
        # identical way modules/network/reachability.sh's own case does,
        # folding it into the same honest "we could not tell" accounting
        # rather than reading it as not-open.
        filtered_ct=$(( filtered_ct + 1 ))
        ;;
    esac
  done

  # Every coverage_reduction below names this check as `checks=[ID]` - plural
  # and bracketed, per `_banner_capability_reduction`'s own note above on
  # why that spelling (not reachability.sh's singular `check=`) is what
  # modules/network/run.sh's `_net_record_unaccounted` backstop actually
  # recognises. `net_listener_unresolvable` and `net_check_not_applicable`
  # can each be the ONLY reduction this run writes (every declared listener
  # unresolvable, or every one not-open/filtered), in which case `open_ct`
  # is 0 and `checks_run` below is never reached - so the id must be
  # accounted for here rather than assumed accounted elsewhere.
  # `no_banner` cannot occur without `open_ct > 0`, so `checks_run` already
  # covers it, but it is spelled identically for the same reason
  # consistency is worth more here than the few bytes saved: a reader
  # comparing four sibling reductions should not have to work out which one
  # is exempt.
  # Both reductions below name NET-SVC-OUTDATED_COMPONENT-01 alongside
  # NET-SVC-BANNER_DISCLOSURE-01 - the outdated-component check
  # never runs on a listener that was never read for a banner in the first
  # place, so a run where EVERY declared listener is unresolvable or
  # not-open/filtered (open_ct stays 0, so `checks_run` below is never
  # reached for either id) must still account for both here, or a selected,
  # db-usable NET-SVC-OUTDATED_COMPONENT-01 falls through to modules/network/
  # run.sh's own check_not_executed_no_reason_recorded honesty backstop -
  # the identical "id must be accounted for here rather than assumed
  # accounted elsewhere" reasoning the comment above this block already
  # states for the disclosure id alone.
  if (( unresolvable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=net_listener_unresolvable checks=[NET-SVC-BANNER_DISCLOSURE-01 NET-SVC-OUTDATED_COMPONENT-01] target=$target count=$unresolvable_ct - that many declared listener(s) could not be re-authorised/re-resolved at probe time, so no banner was attempted for them. Reason(s): $unresolvable_reasons."
  fi

  local not_applicable_ct=$(( notopen_ct + filtered_ct ))
  if (( not_applicable_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=net_check_not_applicable checks=[NET-SVC-BANNER_DISCLOSURE-01 NET-SVC-OUTDATED_COMPONENT-01] target=$target count=$not_applicable_ct not_open=$notopen_ct filtered=$filtered_ct - that many declared listener(s) were not open ('did not answer in time' and 'refused' are different facts, and neither is read for a banner), so this check was not applicable to them and nothing was read."
  fi

  if (( nobanner_ct > 0 )); then
    run_record coverage_reduction "module=network phase=banner.sh reason=no_banner checks=[NET-SVC-BANNER_DISCLOSURE-01] target=$target count=$nobanner_ct - that many OPEN declared listener(s) accepted a TCP connection but sent no bytes within the read deadline, so no banner could be examined. Most services (a bare web server, most databases without a greeting) never send one unprompted; this is not evidence of anything about them by itself."
  fi

  if (( open_ct > 0 )); then
    run_record checks_run NET-SVC-BANNER_DISCLOSURE-01
    (( _BANNER_OUTDATED_OK )) && run_record checks_run NET-SVC-OUTDATED_COMPONENT-01
  else
    run_record coverage_gap "network banner: none of this target's declared listener(s) were open on target '$(net_scope_safe_text "$target" 80)' (${unresolvable_ct} unresolvable, ${notopen_ct} not-open, ${filtered_ct} filtered of ${_REACH_N} declared), so no connection was ever read for a banner. This is not evidence of safety."
  fi

  log_info "network banner: target '$target' - $open_ct of $_REACH_N declared listener(s) open, read $disclosed_ct disclosure(s), $outdated_ct outdated-component match(es) ($nobanner_ct sent nothing, versions_db=$_BANNER_DB_STATE)"
  return 0
}

_banner_run
