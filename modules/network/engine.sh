#!/usr/bin/env bash
# modules/network/engine.sh - the network/host-scanning module's pure
# function library (data/scoursh-network-scan-design/report.md; the NET-04
# row in its §7 staged plan).
#
# Owns:
#   report.md §4    the phase table / intensity-gate / one-door-into-a-phase
#                    shape, mirrored from modules/dast/engine.sh one level
#                    down (the exact precedent this ticket was asked to
#                    follow).
#   report.md §5.2  the four-rule HONESTY CONTRACT: (1) an operator-configured
#                    tuple is refused fatally (http_authorize_raw_connection,
#                    exit 3, lib/http.sh - a FUTURE phase calls that function
#                    directly and needs no wrapper here), and a tuple lifted
#                    out of an ARTIFACT (a future posture.conf expectation or
#                    cross-module inventory row) degrades non-fatally to a
#                    counted coverage_reduction - both halves this file ships;
#                    (2) a probe that did not run is a counted reduction,
#                    never silent; (3) a target with only base-url records a
#                    coverage_gap and exits 0; (4) filtered/not-open are never
#                    collapsed (lib/nettransport.sh, NET-03, already keeps
#                    that distinction - nothing here touches it).
#
# The run.sh / engine.sh split is modules/sast/'s and modules/dast/'s, reused
# verbatim: this file is a pure function library with the standard
# sourced-once guard and no side effects at source time, and
# modules/network/run.sh is the file that DOES something when sourced.
#
# THIS FILE ISSUES NO TRAFFIC, AND NEITHER DOES run.sh.  NET-04 ships NO
# phase script, on purpose (report.md §7's own row for this ticket: "Zero
# phase scripts - every row is absent, every run records a declared
# reduction. This is DAST-02's shape and it is what makes Tier 2
# parallelisable."). A future phase reaches the network exclusively through
# lib/nettransport.sh's `net_connect_probe` (NET-03) for a plain TCP connect,
# or through lib/http.sh's `http_authorize_raw_connection` /
# `http_request` for anything HTTP- or TLS-shaped (report.md §2.5's own
# table: "One TCP connect therefore costs exactly what one HTTP request
# costs, and is refused in exactly the same place, by exactly the same
# code").  scan.sh sources neither lib/http.sh nor lib/nettransport.sh
# unconditionally, so a network run today loads no transport at all -
# tests/suites/network.sh proves that from the outside, the same way
# tests/suites/dast.sh does for DAST.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_NETWORK_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_NETWORK_ENGINE_SOURCED=1

# modules/sast/engine.sh is sourced for `sast_evaluate_gate` ALONE, reused
# rather than forked for the identical reason modules/dast/engine.sh's own
# comment gives: despite its name that function is module-agnostic - it
# re-reads every finding in $rundir/findings.fields and applies the severity /
# confidence / fail-on-new filter chain with no module check anywhere in its
# body.  Guarded internally (its own sourced-once guard), so this source line
# is safe to leave unconditional exactly as modules/dast/engine.sh's is.
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"
if [[ -z ${SCOURSH_CHECKS_SOURCED:-} ]]; then
  # shellcheck source=lib/checks.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/checks.sh"
fi

# ---------------------------------------------------------------------------
# 1. The phase table
# ---------------------------------------------------------------------------
# `<module-relative script>:<minimum run intensity>`, transcribed from
# data/scoursh-network-scan-design/report.md §7's own staged plan (Tier 1's
# NET-05 through Tier 3's NET-10 - report.md's own "no CIDR/discovery/OS
# fingerprinting" §2.6 boundary is what keeps this table short rather than
# open-ended). One row per future ticket; nothing here exists on disk yet,
# and `net_run_phase` treats an absent script as a clean no-op - the
# identical shape that lets modules/dast/engine.sh's own table be complete
# now rather than grown one edit at a time.
#
# THE TIER IS A FLOOR, transcribed from report.md §3's own capability
# write-ups and §5.1's per-check type-tag table, not a judgement made here:
# `inventory.sh` (NET-05) sits at `passive` for the identical reason
# `auth.sh`/`crawl.sh` do in modules/dast/engine.sh - later checks depend on
# it and it establishes no traffic of its own beyond reading config/scope.conf
# and gating the declared listener set. `reachability.sh` (NET-06) and
# `httpport.sh` (NET-09) sit at `safe` (report.md's own `safe-active` type tag
# for NET-PORT-*/an HTTP GET on a non-standard port - `safe`, never `active`,
# is the CHECKS_INTENSITIES name that tag maps onto, the identical mapping
# modules/dast/active/discovery.sh and active/methods.sh already use for
# their own `safe-active`-tagged checks). `banner.sh` (NET-07), `tlsport.sh`
# (NET-08) and `transport.sh` (NET-10) sit at `passive`, matching report.md
# §5.1's `passive` type tag for NET-SVC-BANNER_DISCLOSURE-01/NET-TLS-*/
# NET-TRANSPORT-*.
#
# A later ticket whose checks legitimately carry a DIFFERENT tier than
# declared here must correct the row in the same change and say why, rather
# than leaving two gates that disagree - the identical instruction
# modules/dast/engine.sh's own phase-table comment gives (see its
# passive/transport.sh note for a worked example of exactly this
# correction).
#
# `declare -ga`, never a bare `declare -a`, for the reason
# modules/dast/engine.sh's own phase-table comment documents at length: in a
# real run NOTHING sources this file at top level - `scan_dispatch` is a
# FUNCTION and reaches every module by running `source "$script"` from
# inside itself, so `declare -a` with no `-g` there would create a LOCAL that
# dies with the first `scan_dispatch` call.
declare -ga _NET_PHASES=(
  # Tier 1 - the authorised listener set (report.md §7's NET-05, serial).
  # Reads _HTTP_SCOPE_HOST/_HTTP_SCOPE_PORT for the run's --target, produces
  # the declared listener set, records a coverage_gap when it holds only
  # base-url, and gates every entry through http_authorize_raw_connection.
  'inventory.sh:passive'
  # Tier 2 - probes (peers; each needs no edit to this table once it lands -
  # the '\''active/ssti.sh:active'\'' precedent modules/dast/engine.sh's own
  # comment names).
  'reachability.sh:safe'
  'banner.sh:passive'
  'tlsport.sh:passive'
  'httpport.sh:safe'
  # Tier 3 - posture and correlation.
  'transport.sh:passive'
)

# ---------------------------------------------------------------------------
# 2. The intensity tier order
# ---------------------------------------------------------------------------
# `net_intensity_rank NAME` / `net_intensity_permits RUN_INTENSITY
# PHASE_TIER` - byte-identical in shape and reasoning to
# modules/dast/engine.sh's `dast_intensity_rank`/`dast_intensity_permits`: the
# array index into lib/checks.sh's own CHECKS_INTENSITIES is used rather than
# a hardcoded 0/1/2 table so the order can never drift from the ceiling
# lib/checks.sh's `checks_intensity_keeps` actually applies, and both fail
# CLOSED on an unrecognised name at either end so a typo cannot resolve to
# the shipped default and run something the operator did not ask for.
net_intensity_rank() {
  local want=$1 i
  _NET_INTENSITY_RANK=''
  for (( i = 0; i < ${#CHECKS_INTENSITIES[@]}; i++ )); do
    if [[ ${CHECKS_INTENSITIES[i]} == "$want" ]]; then
      _NET_INTENSITY_RANK=$i
      return 0
    fi
  done
  return 1
}

net_intensity_permits() {
  local run=$1 tier=$2 run_rank
  net_intensity_rank "$run" || return 1
  run_rank=$_NET_INTENSITY_RANK
  net_intensity_rank "$tier" || return 1
  (( run_rank >= _NET_INTENSITY_RANK ))
}

# ---------------------------------------------------------------------------
# 3. Per-check selection (docs/FOUNDATION.md tension 15)
# ---------------------------------------------------------------------------
# `net_check_selected ID` - byte-identical in shape to
# modules/dast/engine.sh's `dast_check_selected`: 0 when a run at this
# --profile-scan/--intensity/--allow-intrusive may run check ID, 1 when the
# operator's filter chain excluded it.  The unset/empty fallback is
# PERMISSIVE and must stay that way - lib/findings.sh's
# `_derived_record_selected` rule (tension 6 condition (a)) verbatim: no
# filter chain means everything is selected, which is also what lets a
# direct-engine suite that sources a phase script with no scan.sh anywhere in
# the process stay non-inert.  Membership is WHOLE-LINE, never substring, for
# dast_check_selected's own stated reason: a bare `*"$id"*` glob would select
# an id that is merely a suffix of another selected line.
net_check_selected() {
  local id=$1
  [[ -n ${SCOURSH_SELECTED_CHECKS:-} ]] || return 0   # no filter chain: all selected
  [[ $'\n'"$SCOURSH_SELECTED_CHECKS"$'\n' == *$'\n'"$id"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 4. The artifact-tuple scope pre-check (report.md §5.2 rule 1, second half)
# ---------------------------------------------------------------------------
# THE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - modules/dast/engine.sh
# section 3b's own reasoning, generalised from a crawled URL to a network
# listener tuple. `http_authorize_raw_connection`/`http_request` gate a URL
# they are handed FATALLY (die exit 3), which is right for an
# operator-configured `config/scope.conf` tuple (report.md §5.2 rule 1, first
# half - a future phase calls that function directly and needs no wrapper
# here). It is NOT right for a tuple lifted out of an ARTIFACT this scanner
# did not author - a future `config/posture.conf` `expect-closed` expectation
# or a cross-module inventory row (report.md §9's decision D5) - because any
# one of those emitting a single out-of-scope row would turn an ordinary
# network run into an exit-3 abort over a row the operator never typed.  So
# THIS predicate decides only whether a tuple is worth asking about; anything
# that survives still goes to http_authorize_raw_connection, which re-gates
# it fatally.  Deleting either half is a real defect in opposite directions -
# without the pre-check the run is fragile (one bad artifact row aborts it),
# without the fatal gate nothing re-checks a tuple the artifact's own
# producer got wrong.
#
# FORKED HERE RATHER THAN LIFTED INTO lib/, AND THAT IS A DELIBERATE,
# NOTED CHOICE (report.md §5.2 rule 1: "ideally lift the three functions
# ... into a shared home rather than forking a fourth copy").  Two reasons,
# both measured rather than assumed:
#   1. modules/dast/engine.sh is a maximally-loaded shellcheck -x entry point
#      that AGENTS.md's own "Things measured on this codebase" section
#      documents at length (the lib/http.sh diamond, the per-suite repeated
#      -source multiplier, the 20-hub-sum lint-source-graph cap) - editing it
#      to source a new shared lib/ file, or to re-point its own five call
#      sites at one, is a real, re-measurable cost to a file already this
#      close to that cap, for the sake of a function this ticket's own scope
#      ships ZERO callers of (no NET phase script exists yet to use it).
#   2. AGENTS.md's own cloud-P3 precedent already answers "shared home or
#      local copy" the same way for the identical shellcheck -x reason:
#      modules/cloud/aws/engine.sh keeps a byte-identical COPY of
#      lib/state.sh's `_state_json_flatten` rather than lifting it, "to
#      protect tests/lint-source-graph.sh's hub budget", with its own suite
#      asserting the two agree leaf-for-leaf rather than trusting a comment.
#      This file follows that precedent rather than modules/dast/'s
#      response_engine.sh lift (which consolidated FOUR pre-existing, already
#      drifted copies inside one already-huge directory - a different
#      problem from "avoid ever writing a first network copy").
# A real second caller (a future NET-05+ phase, or a second module) is the
# trigger to revisit this as a lift, not a hypothetical one.
net_endpoint_in_scope() {
  local url=$1 target=${2:-${SCOURSH_NET_TARGET:-}}
  _NET_SCOPE_REASON=''
  declare -F http_gate_url >/dev/null || return 0
  if http_gate_url "$url" "$target"; then
    return 0
  fi
  _NET_SCOPE_REASON=${_HTTP_GATE_REASON:-declined by the scope gate}
  return 1
}

# `net_scope_skips_reset` - starts a fresh accumulation; a phase calls this
# before the loop it filters, so a second phase in the same process never
# inherits the first one's count.
net_scope_skips_reset() {
  declare -g _NET_SCOPE_SKIPPED=0
  declare -g _NET_SCOPE_REASONS=''
  declare -gA _NET_SCOPE_REASON_SEEN=()
  return 0
}

# `net_endpoint_keep URL [TARGET]` - the predicate above, with the refusal
# counted.  0 keep, 1 drop.  THE REASON IS CAPTURED AT REFUSAL TIME, never
# read after a loop - `http_gate_url` clears `_HTTP_GATE_REASON` at entry on
# EVERY call, so reading it after a loop ends silently degrades to whatever
# the LAST call left (empty after a success, the ordinary case), exactly the
# trap modules/dast/passive/transport.sh's own suite found and pins.
net_endpoint_keep() {
  local url=$1 target=${2:-${SCOURSH_NET_TARGET:-}} why
  net_endpoint_in_scope "$url" "$target" && return 0
  [[ -n ${_NET_SCOPE_SKIPPED:-} ]] || net_scope_skips_reset
  _NET_SCOPE_SKIPPED=$(( _NET_SCOPE_SKIPPED + 1 ))
  why=$_NET_SCOPE_REASON
  if [[ -z ${_NET_SCOPE_REASON_SEEN[$why]:-} ]]; then
    _NET_SCOPE_REASON_SEEN[$why]=1
    _NET_SCOPE_REASONS+="${_NET_SCOPE_REASONS:+; }$(net_scope_safe_text "$why")"
  fi
  return 1
}

# `net_scope_safe_text TEXT [MAX]` - one line, printable, bounded.  Report.md
# §5.3 raises this one step further than modules/dast/engine.sh's own
# `dast_scope_safe_text` (which this is a byte-identical copy of, for the
# reason section 4 above states): a network banner is bytes a SERVICE chose
# on a port that may not speak a protocol this scanner models at all, so it
# is not text by construction the way an HTTP response is - a future phase
# reads via lib/nettransport.sh's `net_connect_probe`, never builds a scope
# reason from raw banner bytes, but a gate reason CAN still interpolate a
# host lifted out of an artifact this scanner did not author, which is
# reason enough to keep the same sanitizer here.
net_scope_safe_text() {
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

# `net_scope_record_skips PHASE [TARGET]` - emits the one coverage_reduction
# for everything `net_endpoint_keep` dropped, and nothing at all when it
# dropped nothing.  A dropped row is recorded, never silent - report.md
# §5.2 rule 4's own "the filtered/not-open distinction is never collapsed"
# reasoning applies one level up here too: "this tuple was out of scope so it
# was not probed" and "this tuple was probed and was clean" are different
# facts.
net_scope_record_skips() {
  local phase=$1 target=${2:-${SCOURSH_NET_TARGET:-}}
  (( ${_NET_SCOPE_SKIPPED:-0} > 0 )) || return 0
  declare -F run_record >/dev/null || return 0
  run_record coverage_reduction "module=network phase=$phase reason=artifact_tuple_out_of_scope target=$target count=$_NET_SCOPE_SKIPPED - that many host:port tuple(s) lifted from an artifact this scanner did not author (report.md §5.2 rule 1, e.g. a future config/posture.conf expectation or cross-module inventory row) name a tuple config/scope.conf does not authorise for this target, so they were NOT probed and nothing about them was tested. The run continued; an out-of-scope artifact row is a fact about the artifact's producer, not a reason to abandon every in-scope listener beside it. Gate reason(s): ${_NET_SCOPE_REASONS:-declined by the scope gate}."
  return 0
}

# ---------------------------------------------------------------------------
# 5. The one door into a phase script
# ---------------------------------------------------------------------------
# `net_run_phase SPEC RUN_INTENSITY TARGET` - byte-identical shape to
# modules/dast/engine.sh's `dast_run_phase`.  Sets `_NET_PHASE_OUTCOME` to
# one of `skipped_intensity` / `absent` / `ran`, and `_NET_PHASE_PRESENT` to
# 1/0 independently, so a caller can tell "we refused a phase that exists"
# from "we refused a phase that does not" and report only the first.
#
# THE INTENSITY GATE IS EVALUATED FIRST, before the script is even looked
# for - the boundary is then structural rather than a convention a later
# ticket has to remember, since modules/network/run.sh never sources a phase
# directly.  SETS variables rather than printing them, and must never be
# called through `$(...)`: sourcing a phase script inside a command
# substitution would run the phase in a subshell and discard every finding
# it emitted (lib/core.sh's `worker_id_set` lesson, applied one level up).
#
# A phase script is `source`d and must NOT carry a sourced-once guard: one
# run can legitimately reach the same phase twice (a second scope target, a
# second scan_main invocation in one process), and a guard would silently
# make the second a no-op.
net_run_phase() {
  local _net_spec=$1 _net_run_intensity=$2 _net_target=$3
  local _net_script=${_net_spec%%:*} _net_tier=${_net_spec##*:} _net_path
  _net_path=${SCOURSH_INSTALL_ROOT:-}/modules/network/$_net_script

  _NET_PHASE_PRESENT=0
  [[ -f $_net_path ]] && _NET_PHASE_PRESENT=1

  if ! net_intensity_permits "$_net_run_intensity" "$_net_tier"; then
    _NET_PHASE_OUTCOME=skipped_intensity
    return 0
  fi
  if (( ! _NET_PHASE_PRESENT )); then
    _NET_PHASE_OUTCOME=absent
    return 0
  fi

  SCOURSH_NET_TARGET=$_net_target
  export SCOURSH_NET_TARGET
  # shellcheck disable=SC1090
  source "$_net_path"
  _NET_PHASE_OUTCOME=ran
  return 0
}
