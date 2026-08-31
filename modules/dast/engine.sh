#!/usr/bin/env bash
# modules/dast/engine.sh - the DAST module's pure function library
# (docs/DESIGN.md §7, §13 step 5; docs/STEP5-DAST-PLAN.md DAST-02).
#
# Owns:
#   docs/STEP5-DAST-PLAN.md  DAST-02's "target and intensity orchestration
#                        skeleton" - the ordered phase table, the intensity
#                        tier comparison, the inventory reader, and the ONE
#                        door a phase script is ever reached through.
#   docs/FOUNDATION.md   tension 21 - reports/<run>/inventory/{endpoints,
#                        parameters}.json are OPTIONAL input; absent or thin
#                        is a recorded coverage_gap, never an error.
#   docs/FOUNDATION.md   tension 12 / rules/RULE-FORMAT.md §9.5.1 - DAST's
#                        coverage cell is `target`, the config/scope.conf
#                        target id.
#
# The run.sh / engine.sh split is modules/sast/'s, reused verbatim: this file
# is a pure function library with the standard sourced-once guard and no side
# effects at source time, and modules/dast/run.sh is the file that DOES
# something when sourced.
#
# THIS FILE ISSUES NO TRAFFIC, AND NEITHER DOES run.sh.  DAST-02 ships no
# check and sends no request, on purpose: there is nothing yet to ask a
# target, and a probe invented so that the skeleton has something to run
# would be traffic no operator asked for.  When a phase script below does
# need the network it goes through lib/http.sh's `http_request` like
# everything else (docs/FOUNDATION.md tension 19's "No bypass"), which is
# also where DAST-01's rate limiter, per-run request budget and circuit
# breaker already sit - so a phase inherits all four controls by using the
# chokepoint and can inherit none of them by going around it.  Note that
# `scan.sh` does not even source lib/http.sh, so a dast run today loads no
# transport at all; tests/suites/dast.sh proves that from the outside by
# running a whole scan with a poisoned PATH.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_ENGINE_SOURCED=1

# modules/sast/engine.sh is sourced for `sast_evaluate_gate` ALONE, and it is
# reused rather than forked for exactly the reason modules/iac/run.sh already
# records for itself: despite its name that function is module-agnostic - it
# re-reads every finding in $rundir/findings.fields and applies the severity /
# confidence / fail-on-new filter chain with no module check anywhere in its
# body.  A fork would be a second copy of tension 14's gate semantics to keep
# in step with the first, and the first is the one the exit-code matrix suite
# pins.
#
# lib/checks.sh supplies CHECKS_INTENSITIES and checks_valid_intensity, which
# `dast_intensity_rank` below derives the tier order from rather than typing a
# second copy of the three names.  Both are sourced only when an outer caller
# has not already done so - scan.sh sources both before `scan_dispatch` ever
# runs, so in a real run these are no-ops; the conditional is what lets
# tests/suites/dast.sh source THIS file on its own.  (The same shape, and the
# same reason, as modules/sast/engine.sh's own lib/report.sh guard.)
# shellcheck source=modules/sast/engine.sh
source "${BASH_SOURCE[0]%/*}/../sast/engine.sh"
if [[ -z ${SCOURSH_CHECKS_SOURCED:-} ]]; then
  # shellcheck source=lib/checks.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/checks.sh"
fi

# ---------------------------------------------------------------------------
# 1. The phase table
# ---------------------------------------------------------------------------
# `<module-relative script>:<minimum run intensity>`, in the order
# docs/DESIGN.md §13 step 5 freezes: `lib/http.sh -> auth.sh (§7.0) ->
# crawl.sh (§7.5) -> DAST passive (§7.1) -> safe-active (§7.2) -> injection
# probes one file at a time (§7.3) -> §7.4 auth/API/authz`.  One row per
# ticket DAST-03..DAST-30; nothing here exists on disk yet, and
# `dast_run_phase` treats an absent script as a clean no-op, which is what
# lets this table be complete now rather than grown one edit at a time.
#
# THE TIER IS A FLOOR, TRANSCRIBED FROM docs/DESIGN.md's OWN SECTION
# HEADINGS, NOT A JUDGEMENT MADE HERE: §7.1 is "Passive", §7.2 is "Safe
# active", §7.3 is "Active injection", §7.4 is "Active - auth, API, and
# access-control checks".  §7.0 (`auth.sh`, session acquisition) and §7.5
# (`crawl.sh`, "fetch in-scope pages ... honoring the rate limiter and scope
# gate") sit at `passive` because the passive checks depend on them and run
# at `passive`.
#
# It is deliberately the COARSE control.  The fine one is each check's own
# type tag in its `checks.rules` record, which lib/checks.sh's tension-15
# ceiling already filters (`checks_intensity_keeps`).  Both must permit, and
# neither can widen the other - the intersection rule tension 15 froze.  A
# later ticket whose checks legitimately carry a LOWER type tag than the tier
# its row declares here must change that row in the same change and say why,
# rather than leaving two gates that disagree: the coarser one wins, and the
# loss would otherwise be silent.  modules/dast/run.sh records every phase
# the intensity gate refused whose script actually exists, so it is visible in
# run.json rather than inferred.
#
# `declare -ga`, never a bare `declare -a`, and the `-g` is load-bearing for
# the reason modules/sast/engine.sh's own check-index declaration documents at
# length: in a real run NOTHING sources this file at top level.
# `scan_dispatch` (scan.sh §7) is a FUNCTION and reaches every module by
# running `source "$script"` from inside itself, so this line executes in that
# function's scope, and `declare -a` with no `-g` there creates a LOCAL that
# dies with the first `scan_dispatch` - while the sourced-once guard above is
# a plain assignment, which IS global and DOES survive.  The guard would then
# outlive the very thing it guards.  Any array a phase script declares is
# subject to the identical rule.
declare -ga _DAST_PHASES=(
  # Tier 1 - session and surface discovery (DAST-03, DAST-04)
  'auth.sh:passive'
  'crawl.sh:passive'
  # Tier 2 - passive checks, docs/DESIGN.md §7.1 (DAST-05..DAST-11).
  # passive/tls.sh is the one documented exception to "every network call
  # goes through lib/http.sh" (docs/FOUNDATION.md tension 19): it shells out
  # to `openssl s_client`.  IT HAS NOW LANDED (DAST-07) and carries its
  # exemption in tests/lint-shell.sh's no-bypass check, exempted BY PATH.
  # That exemption is from the TRANSPORT alone: the phase still takes its
  # authorization, its pinned address and its tension-16 limiter/budget/breaker
  # spend from lib/http.sh's `http_authorize_raw_connection`, so a handshake
  # is gated and budgeted exactly as a request is.  A future non-HTTP probe
  # calls that function; it does not assemble its own subset of the gate.
  'passive/headers.sh:passive'
  'passive/cookies.sh:passive'
  'passive/tls.sh:passive'
  'passive/cors.sh:passive'
  'passive/banner.sh:passive'
  'passive/leakage.sh:passive'
  'passive/markup.sh:passive'
  # passive/transport.sh (DAST-30) is listed HERE, at tier `passive`, and NOT in
  # the tier-5 block below where docs/DESIGN.md §7.4 puts its bullet.  The row
  # was `transport.sh:active` from DAST-02 until DAST-30 landed, transcribed
  # from §7.4's section HEADING ("Active - auth, API, and access-control
  # checks") like its four siblings; that transcription is right for them and
  # wrong for this one, and moving it is the correction this file's own note
  # above demands ("a later ticket whose checks legitimately carry a LOWER type
  # tag than the tier its row declares here must change that row in the same
  # change and say why").  The why, in short - the long form is in
  # modules/dast/passive/transport.sh's header:
  #
  #   1. It mutates no target state.  Every request it sends is a plain GET to
  #      the operator's own base-url or to an endpoint an earlier phase already
  #      fetched; it submits no form and re-sends no discovered POST.  That is
  #      §7.1's whole admission criterion.  What makes §7.4's other four scripts
  #      active is their shared "prove the weakness with a signal" contract;
  #      this one proves nothing by probing and reads what the target already
  #      volunteers.
  #   2. §7.4's own wording for this bullet calls it a complement to "the TLS
  #      passive check".  Its placement in §7.4 is topical, not an intensity
  #      claim.
  #   3. At `active` it would never run: `--intensity` defaults to `passive` and
  #      anything above it additionally requires `--i-own-target`, so a plain
  #      `scan.sh dast --target <t>` would skip it and both exposure classes it
  #      reports would be invisible on the ordinary run.
  #
  # Its records in modules/dast/passive/checks-transport.rules carry the matching
  # `passive` type tag, so the two gates tension 15 intersects agree.
  'passive/transport.sh:passive'
  # Tier 3 - safe active, docs/DESIGN.md §7.2 (DAST-12, DAST-13)
  'active/discovery.sh:safe'
  'active/methods.sh:safe'
  # Tier 4 - active injection probes, docs/DESIGN.md §7.3 (DAST-14..DAST-25)
  'active/sqli.sh:active'
  'active/xss.sh:active'
  'active/cmdi.sh:active'
  'active/pathtraversal.sh:active'
  'active/ssti.sh:active'
  'active/openredirect.sh:active'
  'active/xxe_ssrf.sh:active'
  'active/nosqli.sh:active'
  'active/ldapi.sh:active'
  'active/crlf.sh:active'
  'active/hosthdr.sh:active'
  'active/protopollution.sh:active'
  # Tier 5 - auth, API and access-control checks, docs/DESIGN.md §7.4
  # (DAST-26..DAST-29; DAST-30's `transport.sh` is in the passive block above -
  # see the note there for why it moved)
  'jwt.sh:active'
  'graphql.sh:active'
  'ratelimit.sh:active'
  'authz.sh:active'
)

# ---------------------------------------------------------------------------
# 2. The intensity tier order
# ---------------------------------------------------------------------------
# `dast_intensity_rank NAME` - sets `_DAST_INTENSITY_RANK` to the tier's
# position in lib/checks.sh's own CHECKS_INTENSITIES, which is ordered
# least-permissive first (passive, safe, active) and is the single place that
# vocabulary is declared.  Returns 1 for a name that is not in it, and leaves
# the rank empty rather than guessing.
#
# The array index is used rather than a hardcoded 0/1/2 table so the order can
# never drift from the ceiling lib/checks.sh's `checks_intensity_keeps`
# actually applies; tests/suites/dast.sh pins the resulting order with cases
# that fail under a LEXICAL comparison of the names, which is the mistake this
# function exists to prevent - alphabetically `active` < `passive` < `safe`,
# the exact reverse of the tier order in two of the three pairs.
dast_intensity_rank() {
  local want=$1 i
  _DAST_INTENSITY_RANK=''
  for (( i = 0; i < ${#CHECKS_INTENSITIES[@]}; i++ )); do
    if [[ ${CHECKS_INTENSITIES[i]} == "$want" ]]; then
      _DAST_INTENSITY_RANK=$i
      return 0
    fi
  done
  return 1
}

# `dast_intensity_permits RUN_INTENSITY PHASE_TIER` - 0 when a run at
# RUN_INTENSITY may run a phase declared at PHASE_TIER, 1 otherwise.
#
# Fails CLOSED on an unrecognised name at either end.  A typo must not resolve
# to the shipped default, because the shipped default is a real intensity and
# resolving to it would turn a mistyped flag into a scan the operator did not
# ask for.
dast_intensity_permits() {
  local run=$1 tier=$2 run_rank
  dast_intensity_rank "$run" || return 1
  run_rank=$_DAST_INTENSITY_RANK
  dast_intensity_rank "$tier" || return 1
  (( run_rank >= _DAST_INTENSITY_RANK ))
}

# ---------------------------------------------------------------------------
# 3. The cross-module inventory (docs/FOUNDATION.md tension 21)
# ---------------------------------------------------------------------------
# `dast_inventory_read [RUNDIR]` - sets, for each of the two frozen artifacts:
#
#   _DAST_ENDPOINTS_FILE   / _DAST_PARAMETERS_FILE    the path, '' when unusable
#   _DAST_ENDPOINTS_STATE  / _DAST_PARAMETERS_STATE   present | empty | absent
#
# ABSENT IS THE NORMAL CASE AND IS NEVER AN ERROR.  Tension 21's whole point
# is that modules exchange data only through run-directory artifacts and every
# consumer treats them as optional: `crawl.sh` (DAST-04) is the first producer
# DAST has, SAST route extraction and `aws/live/apigw.sh` are the others, and
# none of the three exists yet.  What a consumer owes instead is a
# coverage_gap naming what was missing, so a standalone dast run never reports
# the same coverage as a full one - modules/dast/run.sh records that.
#
# `empty` is kept distinct from `absent` deliberately.  A file some producer
# created and never wrote to is not the same fact as no producer having run,
# and collapsing the two would let a zero-byte artifact read as real coverage.
# The content is NOT parsed here: no producer exists, so there is no shape to
# agree with, and inventing a reader for a schema nothing writes would be a
# second definition of it.  Publishing the path is what a later phase needs.
dast_inventory_read() {
  local rundir=${1:-${SCOURSH_RUN_DIR:-}} f
  _DAST_ENDPOINTS_FILE='' _DAST_PARAMETERS_FILE=''
  _DAST_ENDPOINTS_STATE=absent _DAST_PARAMETERS_STATE=absent

  f=$rundir/inventory/endpoints.json
  if [[ -f $f && -r $f ]]; then
    if [[ -s $f ]]; then
      _DAST_ENDPOINTS_STATE=present
      _DAST_ENDPOINTS_FILE=$f
    else
      _DAST_ENDPOINTS_STATE=empty
    fi
  fi

  f=$rundir/inventory/parameters.json
  if [[ -f $f && -r $f ]]; then
    if [[ -s $f ]]; then
      _DAST_PARAMETERS_STATE=present
      _DAST_PARAMETERS_FILE=$f
    else
      _DAST_PARAMETERS_STATE=empty
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3a. Per-check selection (docs/FOUNDATION.md tension 15)
# ---------------------------------------------------------------------------
# `dast_check_selected ID` - 0 when a run at this --profile-scan / --intensity
# / --allow-intrusive may run check ID, 1 when the operator's filter chain
# excluded it.
#
# scan.sh's `_scan_apply_profile_filter` runs lib/checks.sh's filter chain over
# every dispatched module's registry and joins the surviving ids into
# SCOURSH_SELECTED_CHECKS, one per line.  This function is the DAST side's
# reader of that list, and it is the ONLY one: a phase script never parses the
# variable itself, for the same reason no phase parses config/scope.conf itself.
#
# WHY IT MATTERS MORE HERE THAN IN A PATTERN MODULE.  A filtered-out SAST check
# that runs anyway costs a wasted regex over a file already on disk.  A
# filtered-out DAST check that runs anyway puts a request on someone else's live
# system - a forged JWT, a SQLi payload, a content-discovery sweep - for a check
# the operator explicitly excluded.  Until this function existed the four call
# sites were all guarded with `declare -F dast_check_selected`, so every one of
# them silently no-opped: --profile-scan and --intensity narrowed the DAST check
# REGISTRY and narrowed nothing a run actually SENT.
#
# THE UNSET/EMPTY FALLBACK IS PERMISSIVE, AND MUST STAY THAT WAY.  It is
# lib/findings.sh's `_derived_record_selected` rule verbatim (tension 6
# condition (a)): no filter chain means everything is selected.  scan.sh exports
# the variable unconditionally and possibly empty, so BOTH the unset and the
# empty case have to answer "selected" - and every direct-engine suite
# (tests/suites/dast-{cookies,headers,sqli,discovery}.sh) sources a phase script
# with no scan.sh anywhere in the process, so a fail-closed default would make
# every DAST phase inert while every "stays quiet" assertion in those suites
# still passed green.  That is the worst available failure: invisible from the
# test output, and it reads as coverage.
#
# One consequence is deliberate and worth naming rather than fixing: "the filter
# chain ran and kept nothing" is indistinguishable from "there is no filter
# chain", because both leave the variable empty.  Distinguishing them needs a
# second variable in scan.sh, which is a change to a shared contract three other
# readers already agree on; the surviving reading is the same permissive one
# lib/findings.sh has shipped since step 1, so nothing diverges.
#
# The membership test is WHOLE-LINE, never substring.  A bare `*"$id"*` glob
# would select `DAST-INJ-SQLI_ERROR-01` because some other selected line ends
# with those bytes, which is the failure that delivers a payload the operator
# filtered out; wrapping both the list and the needle in newlines is what makes
# the comparison line-anchored at both ends, including the first and last lines.
dast_check_selected() {
  local id=$1
  [[ -n ${SCOURSH_SELECTED_CHECKS:-} ]] || return 0   # no filter chain: all selected
  [[ $'\n'"$SCOURSH_SELECTED_CHECKS"$'\n' == *$'\n'"$id"$'\n'* ]]
}

# ---------------------------------------------------------------------------
# 3b. The inventory scope pre-check (docs/FOUNDATION.md tensions 19 and 21)
# ---------------------------------------------------------------------------
# THE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED.  This is
# modules/dast/crawl.sh's `_crawl_in_scope` reasoning, generalised from a
# crawled link to an INVENTORY row, and it is the shared implementation the
# per-phase copies in passive/{headers,leakage,markup,transport}.sh,
# ratelimit.sh, active/discovery.sh and authz_engine.sh each grew for
# themselves.
#
# `http_request` gates the URL it is handed FATALLY - `die "$SCOURSH_EXIT_SCOPE"`,
# exit 3, aborting the whole run - because a caller is assumed to have reached
# it with a URL it believes is authorised.  That assumption holds for an
# operator-configured `base-url`.  It does NOT hold for a URL lifted out of
# `reports/<run>/inventory/endpoints.json`: tension 21 makes that artifact a
# cross-module contract that `crawl.sh`, SAST route extraction and
# `modules/cloud/aws/live/apigw.sh` may each write, and that an operator may
# supply by hand.  Any one of them emitting a single out-of-scope row would
# turn an ordinary `scan.sh dast` run into an exit-3 abort rather than a
# skipped endpoint plus a recorded reason.  That failure is fail-CLOSED
# (safe, never a bypass) and it still kills the run over one row of a file the
# scanner did not author.
#
# So this decides only whether a URL is worth ASKING FOR.  Everything that
# survives still goes through `http_request`, which re-gates it and re-gates
# every redirect hop.  DELETING EITHER HALF IS A REAL DEFECT, in opposite
# directions: without the pre-check the run is fragile (one bad row aborts it),
# without `http_request`'s own gate the run is unsafe (nothing re-checks a
# redirect the target chose).  A test asserts this on the REQUEST LOG, never on
# a return value - "it refused" must not be satisfiable by a phase that sent
# the request and then returned non-zero.
#
# It is built on `http_gate_url`'s non-fatal return rather than on a second URL
# parser, for tension 19's own reason: a second definition of "in scope" is a
# second thing to keep in step with `config/scope.conf`, and the copy that
# drifts is the one nobody re-reads.

# `dast_endpoint_in_scope URL [TARGET]` - 0 when the URL is worth requesting,
# 1 when the scope gate declines it, with `_DAST_SCOPE_REASON` set to the
# gate's OWN reason.
#
# THE `declare -F` GUARD IS PERMISSIVE ON PURPOSE, and inverting it is the
# trap.  `scan.sh` does not source `lib/http.sh` at all for a module that
# issues no traffic, and every direct-engine suite in tests/suites/ sources a
# phase script with no transport in the process; a fail-CLOSED default there
# would make every inventory consumer inert while every "stays quiet"
# assertion in those suites still passed green - invisible from the test
# output and reading as coverage.  It is the same reading `dast_check_selected`
# above and `_crawl_in_scope`, `_discovery_in_scope` and `_authz_in_scope`
# already ship.  Nothing is made unsafe by it: with no `lib/http.sh` loaded
# there is no `http_request` either, so nothing can send the URL this
# function just waved through.
dast_endpoint_in_scope() {
  local url=$1 target=${2:-${SCOURSH_DAST_TARGET:-}}
  _DAST_SCOPE_REASON=''
  declare -F http_gate_url >/dev/null || return 0
  if http_gate_url "$url" "$target"; then
    return 0
  fi
  _DAST_SCOPE_REASON=${_HTTP_GATE_REASON:-declined by the scope gate}
  return 1
}

# `dast_scope_skips_reset` - starts a fresh accumulation.  A phase calls this
# before the loop it filters, so a second phase in the same process never
# inherits the first one's count.
dast_scope_skips_reset() {
  declare -g _DAST_SCOPE_SKIPPED=0
  declare -g _DAST_SCOPE_REASONS=''
  declare -gA _DAST_SCOPE_REASON_SEEN=()
  return 0
}

# `dast_endpoint_keep URL [TARGET]` - the predicate above, with the refusal
# counted.  0 keep, 1 drop.  This is what a consumer's loop calls.
#
# THE REASON IS CAPTURED AT REFUSAL TIME, NEVER READ AFTER THE LOOP.
# `http_gate_url` clears `_HTTP_GATE_REASON` at entry on EVERY call, so by the
# time a loop ends it holds whatever the last call left - empty after a
# success, which is the ordinary case, so a roll-up reading it afterwards
# silently degrades to a generic fallback and the operator never learns why the
# row was declined.  With more than one refusal it would also attribute one
# URL's reason to all of them.  Distinct reasons are collected and reported
# together instead; passive/transport.sh found this the expensive way and its
# own suite pins it.
dast_endpoint_keep() {
  local url=$1 target=${2:-${SCOURSH_DAST_TARGET:-}} why
  dast_endpoint_in_scope "$url" "$target" && return 0
  [[ -n ${_DAST_SCOPE_SKIPPED:-} ]] || dast_scope_skips_reset
  _DAST_SCOPE_SKIPPED=$(( _DAST_SCOPE_SKIPPED + 1 ))
  why=$_DAST_SCOPE_REASON
  if [[ -z ${_DAST_SCOPE_REASON_SEEN[$why]:-} ]]; then
    _DAST_SCOPE_REASON_SEEN[$why]=1
    _DAST_SCOPE_REASONS+="${_DAST_SCOPE_REASONS:+; }$(dast_scope_safe_text "$why")"
  fi
  return 1
}

# `dast_scope_safe_text TEXT [MAX]` - one line, printable, bounded.  A gate
# reason interpolates a host lifted out of an artifact this scanner did not
# author (tension 10's "evidence is untrusted target output", one artifact
# further out), and it is written into a `run.json` record, so a raw newline or
# control byte in it would forge a second record.
dast_scope_safe_text() {
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

# `dast_scope_record_skips PHASE [TARGET]` - emits the one
# `coverage_reduction` for everything `dast_endpoint_keep` dropped, and
# nothing at all when it dropped nothing.
#
# A DROPPED ROW IS RECORDED, NEVER SILENT.  "this endpoint was out of scope so
# it was not tested" and "this endpoint was tested and was clean" are different
# facts, and a phase that drops rows quietly reports the second when only the
# first is true - the overstated coverage docs/DESIGN.md §15 forbids.
dast_scope_record_skips() {
  local phase=$1 target=${2:-${SCOURSH_DAST_TARGET:-}}
  (( ${_DAST_SCOPE_SKIPPED:-0} > 0 )) || return 0
  declare -F run_record >/dev/null || return 0
  run_record coverage_reduction "module=dast phase=$phase reason=inventory_endpoint_out_of_scope target=$target count=$_DAST_SCOPE_SKIPPED - that many rows from the cross-module inventory (docs/INVENTORY-FORMAT.md, docs/FOUNDATION.md tension 21) name a URL config/scope.conf does not authorise for this target, so they were NOT requested and nothing about them was tested. The count is of ROWS DROPPED, not of distinct URLs or of distinct hosts, so one out-of-scope host reachable from several rows is counted once per row - each row is a separate thing this run declined to compose a request from. The run continued; an out-of-scope row is a fact about the artifact's producer, not a reason to abandon every in-scope endpoint beside it. Gate reason(s): ${_DAST_SCOPE_REASONS:-declined by the scope gate}."
  return 0
}

# ---------------------------------------------------------------------------
# 4. The one door into a phase script
# ---------------------------------------------------------------------------
# `dast_run_phase SPEC RUN_INTENSITY TARGET` - SPEC is one `_DAST_PHASES` row.
# Sets `_DAST_PHASE_OUTCOME` to one of:
#
#   skipped_intensity  the run's intensity is below the phase's declared tier
#   absent             the phase's script has not landed yet
#   ran                the script was sourced
#
# and `_DAST_PHASE_PRESENT` to 1/0 independently, so a caller can tell "we
# refused a phase that exists" from "we refused a phase that does not", and
# report only the first.  It SETS variables rather than printing them and must
# never be called through `$(...)`: sourcing a phase script inside a command
# substitution would run the phase in a subshell and discard every finding it
# emitted, which is lib/core.sh's `worker_id_set` lesson applied one level up.
#
# THE INTENSITY GATE IS EVALUATED FIRST, BEFORE THE SCRIPT IS EVEN LOOKED FOR.
# The order is the point: a phase that is refused by intensity is refused for
# that reason whether or not it happens to be installed, so the boundary
# cannot be reached by any path that thinks about the file first.  Every phase
# runs through this function and nothing else - modules/dast/run.sh never
# sources a phase directly - which is what makes the ceiling structural rather
# than a convention a later ticket has to remember.
#
# A phase script is `source`d, exactly as scan.sh sources a module's run.sh,
# so it inherits the whole run context and its findings land in this process's
# shard.  It therefore must NOT carry a sourced-once guard: one run can
# legitimately reach the same phase twice (a second scope target, a second
# scan_main invocation in one process), and a guard would silently make the
# second one a no-op.  Any array it declares needs `declare -g` for the reason
# this file's own phase table documents.
dast_run_phase() {
  local _dast_spec=$1 _dast_run_intensity=$2 _dast_target=$3
  local _dast_script=${_dast_spec%%:*} _dast_tier=${_dast_spec##*:} _dast_path
  _dast_path=${SCOURSH_INSTALL_ROOT:-}/modules/dast/$_dast_script

  _DAST_PHASE_PRESENT=0
  [[ -f $_dast_path ]] && _DAST_PHASE_PRESENT=1

  if ! dast_intensity_permits "$_dast_run_intensity" "$_dast_tier"; then
    _DAST_PHASE_OUTCOME=skipped_intensity
    return 0
  fi
  if (( ! _DAST_PHASE_PRESENT )); then
    _DAST_PHASE_OUTCOME=absent
    return 0
  fi

  # The phase reads its target from the exported context modules/dast/run.sh
  # publishes; it is passed here as well so a phase never has to trust an
  # environment variable it did not see set.
  SCOURSH_DAST_TARGET=$_dast_target
  export SCOURSH_DAST_TARGET
  # shellcheck disable=SC1090
  source "$_dast_path"
  _DAST_PHASE_OUTCOME=ran
  return 0
}
