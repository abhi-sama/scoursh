#!/usr/bin/env bash
# modules/dast/graphql.sh - the §7.4 GraphQL introspection PHASE
# (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-27).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - one run can legitimately reach the same phase
# twice (a second scope target, a second `scan_main` in one process) and a guard
# would silently make the second one a no-op.  The pure functions - endpoint
# classification, the introspection document, the response classifier and the
# finding - live in modules/dast/graphql_engine.sh, which DOES have a guard.
#
# `modules/dast/engine.sh`'s phase table already carried `graphql.sh:active`
# from DAST-02, so this file landing IS the registration: `dast_run_phase`
# treats an absent script as a clean no-op and a present one as a phase, which
# is what let that table be complete before any of its rows existed.  Nothing in
# engine.sh needed editing for this ticket, and the `active` tier on that row is
# the coarse gate this check's own `tags: active` in modules/dast/checks.rules
# then intersects with (tension 15).
#
# WHAT THIS PHASE DOES NOT DO, so the boundary is not rediscovered:
#   - It executes no mutation, sends no batched or aliased document, and makes
#     no attempt at field-level authorisation testing.  Every request carries
#     the read-only introspection `query` in graphql_engine.sh section 3.
#   - It does not brute-force field names to recover a schema when introspection
#     is off.  A `disabled` classification is reported as the real negative it
#     is and the phase stops there.
#   - It does not detect the leaked API key itself.  That is DAST-10
#     (`passive/leakage.sh`); this phase emits the CORRELATION INPUT the derived
#     layer joins against it, which graphql_engine.sh section 6 states in full.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/graphql_engine.sh
source "${BASH_SOURCE[0]%/*}/graphql_engine.sh"
# crawl_engine.sh for the frozen endpoints.json reader.  It carries a
# sourced-once guard and no source-time side effect, so in a real run - where
# crawl.sh already sourced it - this is a no-op, and standalone it is what lets
# tests/suites/dast-graphql.sh drive this phase without scan.sh.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/crawl_engine.sh"

# `_dast_gql_candidates TARGET FILE` - print one
# `URL<TAB>PATH<TAB>WHY` line per GraphQL endpoint in the inventory FILE that
# belongs to TARGET.
#
# It walks `crawl_json_flatten` directly rather than going through
# inject_engine.sh's `inject_inventory_load`, and the reason is a real one
# rather than a preference: that loader keeps only method, url and path, and
# this phase's classification needs `source`, `host` and `content_type` as well
# - three of its four signals.  jwt.sh's own `_dast_jwt_candidates` walks the
# flattener for the same kind of reason (it needs `target`), so this is the
# established shape in this directory, not a new one.  The flatten output is
# `path<TAB>type<TAB>value` with segments separated by US (\x1f), and an
# endpoint's fields arrive as `endpoints<US><idx><US><field>`.
_dast_gql_candidates() {
  local target=$1 file=$2
  [[ -n $file && -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p type v rest idx key last_idx=''
  local u='' pa='' ho='' so='' ct='' tg=''
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _dast_gql_candidate_emit "$target" "$u" "$pa" "$ho" "$so" "$ct" "$tg"
      u='' pa='' ho='' so='' ct='' tg=''
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    case $key in
      url) u=$v ;;
      path) pa=$v ;;
      host) ho=$v ;;
      source) so=$v ;;
      content_type) ct=$v ;;
      target) tg=$v ;;
    esac
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _dast_gql_candidate_emit "$target" "$u" "$pa" "$ho" "$so" "$ct" "$tg"
  return 0
}

# Emit one candidate line if the endpoint belongs to TARGET and classifies as
# GraphQL.  The target check is `empty or equal`, matching jwt.sh: an inventory
# entry with no `target` field predates the field or came from a producer that
# does not set it, and excluding it would silently drop a real endpoint.
_dast_gql_candidate_emit() {
  local target=$1 u=$2 pa=$3 ho=$4 so=$5 ct=$6 tg=$7
  [[ -n $u ]] || return 0
  [[ -z $tg || $tg == "$target" ]] || return 0
  # `path` is optional in practice; fall back to the URL's own path so the
  # classifier's mount-path signal still has something to read.
  if [[ -z $pa ]]; then
    pa=${u#*://}
    if [[ $pa == */* ]]; then pa=/${pa#*/}; else pa=/; fi
    pa=${pa%%\?*}
    pa=${pa%%#*}
  fi
  if [[ -z $ho ]]; then
    ho=${u#*://}
    ho=${ho%%/*}
    ho=${ho%%\?*}
    ho=${ho%%:*}
  fi
  graphql_is_endpoint "$so" "$ho" "$pa" "$ct" || return 0
  printf '%s\t%s\t%s\n' "$u" "$pa" "$_GQL_WHY"
  return 0
}

_dast_graphql_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local line url path why
  local -a candidates=()
  local probed=0 found=0 disabled=0 unclassified=0 failed=0 truncated=0

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/graphql.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The check-selection gate, exactly as passive/cookies.sh and active/sqli.sh
  # apply it: `dast_check_selected` does not exist on every path this file is
  # reachable from, so it is called only when it is defined, and absent it
  # everything the tier already permitted runs.
  local do_introspection=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-GQL-INTROSPECTION-01 || do_introspection=0
  fi
  if (( ! do_introspection )); then
    run_record coverage_reduction "module=dast reason=graphql_no_check_selected target=$target - DAST-GQL-INTROSPECTION-01 was filtered out by --profile-scan/--intensity, so no GraphQL endpoint was probed."
    return 0
  fi

  # SCOURSH_DAST_ENDPOINTS is now always the fixed
  # `$SCOURSH_RUN_DIR/inventory/endpoints.json` path (modules/dast/run.sh),
  # published unconditionally whether or not crawl.sh has written it yet - so
  # reading it alone, and testing it with `-r`/`-s` below, is now enough; the
  # per-file fallback to the run directory's own artifact (the general fix
  # that landed instead) is no longer needed.  SCOURSH_DAST_GQL_ENDPOINTS
  # still overrides it, so this file stays testable against a fixture without
  # a crawl.
  local epf=${SCOURSH_DAST_GQL_ENDPOINTS:-${SCOURSH_DAST_ENDPOINTS:-}}

  if [[ ! -r $epf || ! -s $epf ]]; then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory check=graphql target=$target - no endpoint inventory (docs/INVENTORY-FORMAT.md) was readable, so scoursh could not tell whether this target has a GraphQL endpoint and sent no introspection query."
    run_record coverage_gap "dast graphql: target '$target' has no endpoint inventory, so no GraphQL or AppSync endpoint could be identified and introspection was not tested. This is a coverage gap - nothing was tested - not a finding that introspection is disabled."
    return 0
  fi

  while IFS= read -r line; do
    [[ -n $line ]] && candidates+=("$line")
  done < <(_dast_gql_candidates "$target" "$epf" | LC_ALL=C sort -u)

  # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - modules/dast/
  # engine.sh section 3b carries the long form. `http_request` gates FATALLY,
  # which is right for an operator-configured URL and exactly wrong for one
  # lifted out of an inventory another module wrote, where one bad row aborts
  # the whole run at exit 3. It is applied to the candidate LIST, once, rather
  # than in the probe loop, so the empty check and the cap below both see the
  # surface this phase can actually reach. `graphql_probe` still goes through
  # `http_request`, which re-gates the URL and every redirect hop.
  if declare -F dast_endpoint_keep >/dev/null; then
    dast_scope_skips_reset
    local -a _gql_kept=()
    for line in "${candidates[@]+"${candidates[@]}"}"; do
      dast_endpoint_keep "${line%%$'\t'*}" "$target" || continue
      _gql_kept+=("$line")
    done
    candidates=("${_gql_kept[@]+"${_gql_kept[@]}"}")
    dast_scope_record_skips graphql "$target"
  fi

  # THE FIRST ACCEPTANCE CRITERION, MADE CONCRETE: no GraphQL endpoint in the
  # inventory means a DECLARED coverage reduction and ZERO requests.  It is
  # deliberately not silence: "this application has no GraphQL" and "scoursh did
  # not look for GraphQL" are different facts and an operator reading a clean
  # report cannot tell them apart unless the run says which one happened.
  if (( ${#candidates[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_graphql_endpoint check=graphql target=$target inventory=$epf - the endpoint inventory carries no GraphQL or AppSync endpoint, so no introspection query was sent. Nothing was requested."
    run_record coverage_gap "dast graphql: no GraphQL or AppSync endpoint was identified for target '$target' in the endpoint inventory (docs/INVENTORY-FORMAT.md), so introspection was not tested. scoursh identifies one by an ingested GraphQL schema, a GraphQL media type, the managed-GraphQL DNS shape, or the conventional mount path; a GraphQL API served somewhere else is invisible to a static crawl and needs an OpenAPI/GraphQL schema or a HAR capture in config/discovery.conf to be seen (docs/DESIGN.md §7.5). The absence of a GraphQL finding here is the absence of a test, not the absence of a problem."
    return 0
  fi

  local max=${SCOURSH_DAST_GQL_MAX_ENDPOINTS:-10}
  [[ $max =~ ^[0-9]+$ ]] || max=10
  (( max < 1 )) && max=1
  if (( ${#candidates[@]} > max )); then
    truncated=$(( ${#candidates[@]} - max ))
    candidates=("${candidates[@]:0:max}")
  fi

  # The optional authenticated pass, using ONLY the session DAST-03 already
  # acquired - building a GraphQL-specific login is explicitly out of scope for
  # this ticket.  Introspection is frequently reachable only behind a session,
  # so an unauthenticated-only probe has a real hole, which is stated below when
  # the run did not close it.  Guarded on `declare -F` for the same reason
  # `dast_check_selected` is: auth.sh has not necessarily been sourced on every
  # path this file is reachable from.
  local auth_apply='' auth_label=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] \
    && declare -F dast_auth_authenticated_labels_set >/dev/null \
    && declare -F dast_auth_apply >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      auth_label=${_DAST_AUTH_AUTHED_LABELS[0]}
      # A tiny closure over the identity, because `graphql_probe` takes an
      # applier by NAME so it can re-attach the credential on the 405 fallback
      # (see graphql_engine.sh section 5) and `dast_auth_apply` needs two
      # arguments it cannot pass.  `declare -g` on the two globals for the
      # reason modules/dast/engine.sh's phase table documents: this file is
      # sourced from inside `dast_run_phase`, so an undecorated declaration
      # would be a local that dies with the phase.
      declare -g _DAST_GQL_AUTH_TARGET=$target _DAST_GQL_AUTH_LABEL=$auth_label
      auth_apply=_dast_gql_auth_apply
      run_record notes "module=dast phase=graphql target=$target identity=$auth_label authenticated_pass=1"
    fi
  fi
  if [[ -z $auth_label ]]; then
    run_record coverage_reduction "module=dast reason=graphql_unauthenticated_only check=graphql target=$target - the introspection probe below ran UNAUTHENTICATED. A deployment that serves its schema only to an authenticated caller is not covered by this run; run with --authed and a config/auth.conf to cover it."
  fi

  for line in "${candidates[@]+"${candidates[@]}"}"; do
    url=${line%%$'\t'*}
    why=${line##*$'\t'}
    path=${line#*$'\t'}
    path=${path%%$'\t'*}

    graphql_probe "$target" "$url" "$auth_apply"
    if (( ! _GQL_PROBE_OK )); then
      failed=$(( failed + 1 ))
      continue
    fi
    probed=$(( probed + 1 ))

    case $_GQL_CLASS in
      schema)
        found=$(( found + 1 ))
        graphql_emit_introspection "$target" "$url" "$path" "$why"
        ;;
      disabled)
        disabled=$(( disabled + 1 ))
        ;;
      *)
        # Classified as GraphQL from the inventory, but the response was not a
        # GraphQL response.  That is NOT a clean result for this endpoint - the
        # probe proved nothing about it - so it is recorded rather than counted
        # as a pass.  The single most likely cause is the weakest signal in
        # graphql_engine.sh section 2 (the mount path) matching a URL that is
        # not a GraphQL endpoint at all, and saying so is what lets an operator
        # correct their inventory instead of trusting a silence.
        unclassified=$(( unclassified + 1 ))
        run_record coverage_reduction "module=dast reason=graphql_response_not_graphql check=graphql target=$target status=${_GQL_PROBE_STATUS:-none} - an endpoint identified as GraphQL ($why) did not answer the introspection query with a GraphQL response, so its introspection posture is unknown. It was neither reported nor cleared."
        ;;
    esac
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's coverage
  # roll-up reads.  It is recorded ONLY when a GraphQL response was actually
  # classified, so a run whose every probe failed at the transport is never
  # reported as having covered this check - which is the difference between "we
  # looked and it is off" and "we could not look".
  if (( found > 0 || disabled > 0 )); then
    run_record checks_run DAST-GQL-INTROSPECTION-01
  fi

  if (( disabled > 0 && found == 0 )); then
    # The good outcome, stated positively and bounded to what was inspected.
    run_record notes "module=dast phase=graphql target=$target endpoints=$disabled introspection=disabled - every GraphQL endpoint inspected refused the introspection query. This is a real negative over the endpoints named in the inventory, bounded by this phase's other coverage records."
  fi
  if (( truncated > 0 )); then
    run_record coverage_gap "dast graphql: target '$target' has more GraphQL endpoints in its inventory than this phase's cap of $max, so $truncated endpoint(s) were not probed and their introspection posture is unknown. Raise SCOURSH_DAST_GQL_MAX_ENDPOINTS to widen it. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( failed > 0 )); then
    run_record coverage_reduction "module=dast reason=graphql_request_failed check=graphql target=$target count=$failed - $failed introspection request(s) failed at the transport, so those endpoints' introspection posture was not established."
  fi
  if (( probed == 0 )); then
    run_record coverage_gap "dast graphql: every one of the ${#candidates[@]} GraphQL endpoint probe(s) on target '$target' failed at the transport, so introspection was not tested anywhere - a coverage gap, not a clean result."
  fi

  log_info "dast graphql: target '$target' - ${#candidates[@]} GraphQL endpoint(s) identified, $probed probed, $found with introspection enabled, $disabled with it disabled, $unclassified unclassified"
  return 0
}

# The authenticated applier `_dast_graphql_phase` hands to `graphql_probe` by
# name.  Defined at file scope rather than inside the phase function because a
# nested function definition would be re-created on every phase invocation for
# no benefit, and `graphql_probe` looks it up by name in any case.
_dast_gql_auth_apply() {
  dast_auth_apply "$_DAST_GQL_AUTH_TARGET" "$_DAST_GQL_AUTH_LABEL" || return 0
  return 0
}

_dast_graphql_phase
