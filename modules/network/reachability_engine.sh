#!/usr/bin/env bash
# modules/network/reachability_engine.sh - the pure half of the NET-06
# reachability probe.
#
# Owns:
#   THREE-STATE      the THREE-STATE classification a probe reports as -
#   classification   open/not-open/filtered - and what each is REPORTED AS:
#                    `open` is input to the expect-closed comparison below;
#                    `not-open` is the NET-PORT-DECLARED_NOT_ANSWERING-01
#                    finding; `filtered` is NEVER a finding and NEVER folded
#                    into `not-open` - it is a
#                    counted coverage_reduction, because "the port did not
#                    answer" and "the port refused" are different facts.
#   expect-closed    RESOLVED option (a): the "this port should be closed"
#                    expectation lives in config/posture.conf
#                    (rules/RULE-FORMAT.md §9.6.4, already frozen), keyed on
#                    `scope-key`.  §9.6.4's own key table describes scope-key
#                    as "a target id, an account id, or account/region" but
#                    does not say those are the ONLY legal shapes - the field
#                    is a free single-line string with no format validation
#                    anywhere in lib/records.sh beyond non-emptiness.  This
#                    ticket therefore introduces ONE new scope-key SHAPE for
#                    this module's own checks - `<target>:<port>` - the
#                    identical `host[:port]` colon convention
#                    rules/RULE-FORMAT.md §9.4's own `extra-host` already
#                    uses.  This costs no format_version bump and no
#                    state/ migration (rules/RULE-FORMAT.md §14 item 2 only):
#                    no key changes cardinality, no key becomes required that
#                    was optional, and every existing config/posture.conf
#                    record for a POSTURE-* check keeps parsing and meaning
#                    exactly what it always did.  A target id can never
#                    itself contain ':' (rules/RULE-FORMAT.md §9.4's target-id
#                    grammar is `^[a-z][a-z0-9-]*$`), so splitting a
#                    `scope-key` on its LAST ':' unambiguously recovers
#                    (target, port).
#
#                    `check: NET-PORT-UNEXPECTED_LISTENER-01` on that record
#                    is the one thing worth flagging for a future reader:
#                    rules/RULE-FORMAT.md §9.6.4's own prose says the `check`
#                    field names a check id "with MODULE = POSTURE", but nothing
#                    that actually PARSES or LINTS config/posture.conf enforces
#                    that module prefix - lib/records.sh's posture-expectation
#                    schema (section 1) declares `check` as a plain required
#                    single-line string with no id-form regex applied to its
#                    VALUE (only a record's own `id` field is checked against
#                    a form, in _records_check_id_form), and
#                    tests/lint-rules.sh's E077 check (the only place `check`
#                    is cross-referenced at all) verifies only that the named
#                    id is DEFINED by some checks.rules somewhere in the
#                    repository-wide check-id namespace - it does not
#                    restrict which MODULE defined it.  So a `NET-PORT-*`
#                    check named here passes every check this repository
#                    actually runs.  This was a captain-level call (D5,
#                    already RESOLVED per the brief this ticket implements)
#                    to spend the field's real, enforced flexibility rather
#                    than open a second config file for one new check family;
#                    it is recorded here rather than left to look like an
#                    oversight the next time someone re-reads §9.6.4's prose
#                    literally.
#
# THIS FILE IS A PURE FUNCTION LIBRARY, no side effect at source time beyond
# `set -Eeuo pipefail` and its own `source lib/core.sh` (guarded internally),
# matching every sibling `*_engine.sh` in this tree.  It has no source-once
# guard on purpose: redefining bash functions is idempotent, and every
# sibling that is safe to source more than once (lib/nettransport.sh
# included) is unguarded for the identical reason.
#
# shellcheck shell=bash
# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/../../lib/core.sh"

# ---------------------------------------------------------------------------
# 1. The listeners.json reader
# ---------------------------------------------------------------------------
# A PRIVATE COPY of modules/dast/crawl_engine.sh's `crawl_json_flatten`
# algorithm, not a shared lift, for the identical reason
# modules/cloud/aws/engine.sh keeps its own copy of lib/state.sh's
# `_state_json_flatten` rather than sourcing it (AGENTS.md's "Things measured
# on this codebase": `shellcheck -x` does not memoise, so a new source edge
# into modules/dast/ from modules/network/ is a real, measured
# tests/lint-source-graph.sh hub-budget cost for a generic JSON tokenizer
# this file's own tiny, FROZEN, scanner-authored schema does not need the
# rest of crawl_engine.sh for).  Prints one line per scalar leaf,
# `<path><TAB><type><TAB><raw value>` - identical contract, so a future
# consumer that already knows crawl_json_flatten's shape needs nothing new.
_net_json_flatten() {
  awk '
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    function readstr(  s, c) {
      i++
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    function emit(path, type, val) { print path "\t" type "\t" val }
    function value(path,   c, k, idx, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          value(path == "" ? k : path SEP k)
          first = 0
        }
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "]") { i++; return }
          value(path == "" ? idx : path SEP idx)
          idx++
          first = 0
        }
      }
      if (c == "\"") { emit(path, "s", readstr()); return }
      k = readtok()
      if (k == "") fail("unparseable value at byte " i)
      if (k == "true" || k == "false") { emit(path, "b", k); return }
      if (k == "null") { emit(path, "z", k); return }
      emit(path, "n", k)
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      skipws()
      if (i > n) exit 0
      value("")
    }
  '
}

# `_net_json_unescape RAW` - the inverse of `_net_json_flatten`'s "still
# escaped" leaf values, scoped to exactly what `lib/core.sh`'s `json_string`
# (the ONE JSON writer, tension 10) can ever produce: `\\`, `\"`, and the
# five named control escapes plus a bare `\uXXXX` for a control byte outside
# those five.  A private, narrower sibling of
# modules/dast/crawl_engine.sh's `crawl_json_unescape` for the identical
# reason `_net_json_flatten` above is - and narrower because this file only
# ever unescapes a scanner-authored value, never target-controlled bytes.
_net_json_unescape() {
  local s=$1 out='' i n ch nx code decoded
  if [[ $s != *'\'* ]]; then
    printf '%s' "$s"
    return 0
  fi
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch != '\' ]]; then out+=$ch; continue; fi
    nx=${s:i+1:1}
    case $nx in
      '"') out+='"'; i=$(( i + 1 )) ;;
      '\') out+='\'; i=$(( i + 1 )) ;;
      n) out+=$'\n'; i=$(( i + 1 )) ;;
      r) out+=$'\r'; i=$(( i + 1 )) ;;
      t) out+=$'\t'; i=$(( i + 1 )) ;;
      b) out+=$'\b'; i=$(( i + 1 )) ;;
      f) out+=$'\f'; i=$(( i + 1 )) ;;
      u)
        code=${s:i+2:4}
        if [[ $code =~ ^00[0-7][0-9A-Fa-f]$ ]]; then
          # shellcheck disable=SC2059
          printf -v decoded "\\x${code:2:2}"
          out+=$decoded
          i=$(( i + 5 ))
        else
          out+='\u'
          i=$(( i + 1 ))
        fi
        ;;
      *) out+='\' ;;
    esac
  done
  printf '%s' "$out"
}

# `reach_listeners_load FILE TARGET` - reads NET-05's `listeners.json`
# (docs comment in modules/network/inventory.sh is the frozen shape) into
# `_REACH_ROLE`/`_REACH_SCHEME`/`_REACH_HOST`/`_REACH_PORT`, one array index
# per listener, and sets `_REACH_N`.  A row whose own `target` field does not
# match TARGET is dropped (defensive only - NET-05 writes one file per
# target - the identical belt-and-braces `_resp_row_collect`
# (modules/dast/passive/response_engine.sh) already applies to a shared
# inventory one module over).  An absent, empty or unparseable file leaves
# `_REACH_N=0` - never an error - the caller decides what a zero-listener
# read means.
reach_listeners_load() {
  local file=$1 target=$2
  declare -ga _REACH_ROLE=() _REACH_SCHEME=() _REACH_HOST=() _REACH_PORT=()
  _REACH_N=0
  [[ -n $file && -r $file && -s $file ]] || return 0

  local sep=$'\x1f' p type v rest idx key last_idx=''
  local -A cur=()
  while IFS=$'\t' read -r p type v; do
    [[ $p == listeners* ]] || continue
    rest=${p#listeners}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _reach_row_collect "$target" "${cur[target]:-}" "${cur[role]:-}" \
        "${cur[scheme]:-}" "${cur[host]:-}" "${cur[port]:-}"
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(_net_json_unescape "$v")
    cur[$key]=$v
  done < <(_net_json_flatten <"$file" 2>/dev/null)
  if [[ -n $last_idx ]]; then
    _reach_row_collect "$target" "${cur[target]:-}" "${cur[role]:-}" \
      "${cur[scheme]:-}" "${cur[host]:-}" "${cur[port]:-}"
  fi
  return 0
}

_reach_row_collect() {
  local want_target=$1 row_target=$2 role=$3 scheme=$4 host=$5 port=$6
  [[ -n $host && -n $port ]] || return 0
  if [[ -n $row_target && -n $want_target && $row_target != "$want_target" ]]; then
    return 0
  fi
  _REACH_ROLE+=("$role")
  _REACH_SCHEME+=("$scheme")
  _REACH_HOST+=("$host")
  _REACH_PORT+=("$port")
  _REACH_N=${#_REACH_HOST[@]}
  return 0
}

# ---------------------------------------------------------------------------
# 2. The config/posture.conf expect-closed reader
# ---------------------------------------------------------------------------
# `reach_posture_load TARGET [PATH]` - sets:
#
#   _REACH_POSTURE_STATE   absent | loaded
#   _REACH_EXPECT_CLOSED   assoc array, port -> the expectation's own `id`
#                          (for evidence text), for every posture.conf
#                          record with `check: NET-PORT-UNEXPECTED_LISTENER-01`,
#                          `expect: absent`, and a `scope-key` of
#                          `<TARGET>:<port>`.
#
# `expect: absent` is the only `expect` value this check consults - it reads
# literally as "the operator expects this listener to be absent", the exact
# shape rules/RULE-FORMAT.md §9.6.4 already defines with no `value` key
# needed.  A record naming this check with any OTHER `expect` value is not
# an error (posture.conf's schema does not know what a given `check` value
# means) - it is simply not applicable to this check today, and is silently
# not consulted; nothing about that omission is silent in the RUN'S own
# accounting, since a target with zero matching `expect: absent` records is
# indistinguishable, from this check's point of view, from a target with no
# posture.conf records at all, and both are the ordinary "checked, nothing to
# flag" outcome.
#
# ABSENT IS A DECLARED SKIP, NEVER exit 4 - the identical contract
# modules/cloud/aws/run.sh's own `_cloud_run_posture_phase` already
# establishes for config/posture.conf; this function reuses
# `config_load_if_present`, the same generic loader, rather than a second
# reader.
reach_posture_load() {
  local target=$1 path=${2:-${SCOURSH_NET_POSTURE_CONF:-${SCOURSH_INSTALL_ROOT:-}/config/posture.conf}}
  declare -gA _REACH_EXPECT_CLOSED=()
  _REACH_POSTURE_STATE=absent
  _REACH_POSTURE_PATH=$path

  if ! declare -F config_load_if_present >/dev/null 2>&1; then
    return 0
  fi
  if ! config_load_if_present "$path" posture-expectation netposture; then
    return 0
  fi
  _REACH_POSTURE_STATE=loaded

  local n i ck sk expect id port want_prefix=$target:
  n=$(records_count netposture)
  for (( i = 0; i < n; i++ )); do
    ck=$(records_field netposture "$i" check)
    [[ $ck == NET-PORT-UNEXPECTED_LISTENER-01 ]] || continue
    expect=$(records_field netposture "$i" expect)
    [[ $expect == absent ]] || continue
    sk=$(records_field netposture "$i" scope-key)
    [[ $sk == "$want_prefix"* ]] || continue
    port=${sk#"$want_prefix"}
    [[ $port =~ ^[0-9]+$ ]] || continue
    id=$(records_id netposture "$i")
    _REACH_EXPECT_CLOSED[$port]=$id
  done
  return 0
}

# ---------------------------------------------------------------------------
# 3. Finding emission
# ---------------------------------------------------------------------------
reach_emit_not_answering() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5
  local evi="Declared listener $scheme://$host:$port (role=$role, config/scope.conf) did not accept a TCP connection during this run: net_connect_probe classified it 'not-open' (the connection was actively refused, or the host answered with no listener there). This is an observation about a listener the operator declared as authorised, not proof of a defect by itself - the entry may be stale, or the service may be intentionally offline."
  finding_new
  finding_set check_id NET-PORT-DECLARED_NOT_ANSWERING-01
  finding_set module net
  finding_set title 'Declared network listener did not answer'
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe CWE-16
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
  finding_set remediation 'No action is required for this finding by itself: it records that a listener config/scope.conf declares for this target did not answer during this run. If the listener is decommissioned, remove its extra-host entry from config/scope.conf so future runs do not keep probing a port nothing is meant to be running on. If it should be running, verify the service and any network path (firewall, security group, load balancer health) between the scanner and the host.'
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

reach_emit_unexpected_listener() {
  local target=$1 role=$2 scheme=$3 host=$4 port=$5 expectation_id=$6
  local evi="Declared listener $scheme://$host:$port (role=$role) answered a TCP connect - it is reachable - but config/posture.conf's expectation '$expectation_id' (check: NET-PORT-UNEXPECTED_LISTENER-01, scope-key: $target:$port, expect: absent) states this port is expected to be CLOSED. The listener is exposed contrary to the operator's own declared baseline."
  finding_new
  finding_set check_id NET-PORT-UNEXPECTED_LISTENER-01
  finding_set module net
  finding_set title 'Declared listener answers on a port expected to be closed'
  finding_set base_severity high
  finding_set confidence high
  finding_set cwe CWE-668
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
  finding_set remediation "Close this listener, restrict it to a private network or VPN/bastion path, or add a firewall/security-group rule that denies the source this scan ran from, so the port no longer answers a plain TCP connect from an untrusted network. If it is now intentionally open, update or remove config/posture.conf's expectation for scope-key '$target:$port' so this baseline reflects the current, reviewed configuration rather than continuing to report drift."
  finding_set_evidence "$evi"
  finding_emit
  return 0
}
