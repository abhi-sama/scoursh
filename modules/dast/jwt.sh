#!/usr/bin/env bash
# modules/dast/jwt.sh - the §7.4 JWT-weakness PHASE
# (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-26).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - one run can legitimately reach the same phase
# twice (a second scope target, a second `scan_main` in one process) and a guard
# would silently make the second one a no-op.  The pure functions - the token
# forgeries and the replay oracle - live in modules/dast/jwt_engine.sh, which
# does have a guard; this file resolves the two LIVE inputs the check needs (a
# sample token and a protected endpoint) and drives that engine.
#
# THE TWO LIVE INPUTS, AND WHY EACH ABSENCE IS A RECORDED GAP RATHER THAN AN
# ERROR (docs/DESIGN.md §7.4, docs/STEP5-DAST-PLAN.md DAST-26's "NEEDS FROM
# OPERATOR").  docs/DESIGN.md §7.4 says this check is "given a sample token ...
# derive variants and replay each against a protected endpoint".  This phase
# takes the sample token from the AUTHENTICATED SESSION that auth.sh (DAST-03)
# already acquired for a configured identity - so no new credential config key is
# needed, and a token minted for the operator's own test account is exactly what
# §7.4 asks for - and it takes the protected endpoint from the CRAWL INVENTORY
# (endpoints.json, docs/INVENTORY-FORMAT.md) restricted to idempotent methods.
# When either input is missing - no `--authed`, no JWT-shaped session, no
# openssl, or no idempotent protected endpoint in the inventory - the check does
# not error and does not silently pass: it records a `coverage_reduction` and a
# human-readable `coverage_gap`, so an absent finding never reads as a clean
# result.  That is the honesty docs/DESIGN.md §15 requires and the exact posture
# auth.sh already established.
#
# NON-DESTRUCTIVE, DETECTION-ONLY (docs/STEP5-DAST-PLAN.md DAST-14..26 amendment,
# DAST-36).  Every probe is a GET/HEAD replay of the SAME claims the sample token
# carried; the replay is restricted to idempotent methods so a "protected
# endpoint" that is a mutation is skipped, never exercised; a forged token is
# sent once and never persisted or reused; and the response body is discarded, so
# a forgery's response never reaches an artifact.  See jwt_engine.sh's header for
# the full statement and the oracle argument.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/jwt_engine.sh
source "${BASH_SOURCE[0]%/*}/jwt_engine.sh"
# auth_engine.sh for the session store (the sample token) and crawl_engine.sh for
# the frozen endpoints.json reader (crawl_json_flatten).  Both carry a
# sourced-once guard and neither has a side effect at source time, so in a real
# run - where auth.sh and crawl.sh have already run and sourced them - these are
# no-ops, and standalone they are what lets tests/suites/dast-jwt.sh drive this
# phase without scan.sh.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/auth_engine.sh"
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/crawl_engine.sh"

# `_dast_jwt_session_token TARGET LABEL` - the raw session token an authenticated
# identity holds, printed, or empty.  Read directly from the session store file
# auth.sh wrote (mode 600 under the run scratch dir); this is the "sample token"
# §7.4 replays.  It is never logged and never becomes an argv argument - it is
# read into a shell variable and handed to jwt_engine, which presents it to curl
# over a stdin config (tension 9).
_dast_jwt_session_token() {
  local target=$1 label=$2 token=''
  _dast_auth_dir_set "$target" "$label"
  if [[ -r $_DAST_AUTH_DIR/token ]]; then
    IFS= read -r token <"$_DAST_AUTH_DIR/token" || true
  fi
  printf '%s' "$token"
}

# `_dast_jwt_candidates TARGET FILE` - print `METHOD<TAB>URL` for every endpoint
# in the inventory FILE that belongs to TARGET and uses an IDEMPOTENT method
# (GET or HEAD).  Restricting to idempotent methods is the non-destructive
# guarantee made concrete: a JWT replay against a POST/PUT/DELETE endpoint could
# change state, so such an endpoint is never a candidate even when it is the only
# protected one the crawler found.
#
# It reuses crawl_engine.sh's `crawl_json_flatten` - the same frozen JSON reader
# every inventory producer and consumer shares (docs/INVENTORY-FORMAT.md) -
# rather than a second parser that could disagree with it.  The flatten output is
# `path<TAB>type<TAB>value` with path segments separated by US (\x1f), and an
# endpoint's fields arrive as `endpoints<US><idx><US><field>`, exactly as
# `crawl_inv_merge_endpoints` reads them.
_dast_jwt_candidates() {
  local target=$1 file=$2
  [[ -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p type v rest idx key last_idx='' m='' u='' t=''
  local flush
  # A small closure-by-convention: emit the accumulated endpoint if it matches.
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _dast_jwt_candidate_emit "$target" "$m" "$u" "$t"
      m='' u='' t=''
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    case $key in
      method) m=$v ;;
      url) u=$v ;;
      target) t=$v ;;
    esac
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _dast_jwt_candidate_emit "$target" "$m" "$u" "$t"
  return 0
}

# Emit one `METHOD<TAB>URL` line if the endpoint is for TARGET and idempotent.
_dast_jwt_candidate_emit() {
  local target=$1 m=${2:-GET} u=$3 t=$4
  [[ -n $u ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  case $m in
    GET | HEAD | get | head) ;;
    *) return 0 ;;
  esac
  printf '%s\t%s\n' "${m^^}" "$u"
  return 0
}

_dast_jwt_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local authed=${SCOURSH_DAST_AUTHED:-false}
  local endpoints_file=${SCOURSH_DAST_ENDPOINTS:-}
  local label token method url line
  local -a labels=() candidates=()
  local any_oracle=0 rs_missing=0

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/jwt.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # A JWT replay needs a valid session token, so without --authed there is
  # nothing to forge from.  Recorded, not silent: "no JWT check ran" is a fact
  # about this run's coverage.
  if [[ $authed != true ]]; then
    run_record coverage_reduction "module=dast reason=authed_not_requested check=jwt target=$target - the JWT weakness checks replay a real session token, and --authed was not given, so no token was acquired and none was tested. No forged token was sent."
    run_record coverage_gap "dast jwt: --authed was not given for target '$target', so no session token exists to derive alg:none/weak-HMAC/algorithm-confusion variants from. The JWT verification of this target was not tested; a clean result is the absence of a test, not the absence of a problem."
    return 0
  fi

  # openssl is this check's one external dependency (base64url and HMAC).  Absent
  # is a declared skip with a reason (rules/RULE-FORMAT.md §9.5 `requires-cmd`),
  # never an error - the same graceful degradation the whole tool owes.
  if ! _have openssl; then
    run_record coverage_reduction "module=dast reason=requires_cmd_absent cmd=openssl check=jwt target=$target - the JWT checks need openssl for base64url and HMAC and it is not on PATH, so they were skipped."
    run_record coverage_gap "dast jwt: openssl is not available, so the JWT weakness checks (alg:none, empty/weak HMAC, RS->HS confusion) did not run on target '$target'."
    return 0
  fi

  dast_auth_authenticated_labels_set "$target"
  labels=("${_DAST_AUTH_AUTHED_LABELS[@]+"${_DAST_AUTH_AUTHED_LABELS[@]}"}")
  if (( ${#labels[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_authenticated_identity check=jwt target=$target - --authed was requested but no identity for this target authenticated, so there is no session token to replay."
    run_record coverage_gap "dast jwt: no identity for target '$target' is authenticated (see the auth phase's own coverage records for why), so the JWT weakness checks had no session token to derive variants from and did not run."
    return 0
  fi

  # The protected endpoint.  This is the operator/live-gated input DAST-26's
  # ticket names: it comes from the crawl inventory, restricted to idempotent
  # methods.  Absent is a recorded gap - there is deliberately no config key that
  # hardcodes a "jwt replay path", both because the record format is frozen and
  # because a path that varies per app belongs in the inventory the crawler
  # already builds, not in a second place that could drift from it.
  while IFS= read -r line; do
    [[ -n $line ]] && candidates+=("$line")
  done < <(_dast_jwt_candidates "$target" "$endpoints_file")

  if (( ${#candidates[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_protected_endpoint check=jwt target=$target - the JWT checks replay against a protected endpoint, and no idempotent (GET/HEAD) endpoint was available in the inventory (${endpoints_file:-none}) to establish the accept/reject oracle."
    run_record coverage_gap "dast jwt: no idempotent protected endpoint was available for target '$target' (docs/INVENTORY-FORMAT.md endpoints.json was ${endpoints_file:-absent}), so there was nowhere to replay forged tokens and prove whether they are accepted. Supply an authenticated crawl or an OpenAPI/HAR spec that lists a GET endpoint this identity's token is authorised for (docs/STEP5-DAST-PLAN.md DAST-26). The JWT verification of this target was not tested."
    return 0
  fi

  for label in "${labels[@]+"${labels[@]}"}"; do
    token=$(_dast_jwt_session_token "$target" "$label")
    if [[ -z $token ]] || ! jwt_is_jwt "$token"; then
      run_record coverage_reduction "module=dast reason=session_token_not_jwt check=jwt target=$target identity=$label - the session token for this identity is not a JSON Web Token, so the JWT weakness checks do not apply to it."
      run_record coverage_gap "dast jwt: identity '$target.$label' holds a session token that is not a JWT (it is opaque or a reference token), so alg:none/weak-HMAC/algorithm-confusion are not meaningful against it and were not run for this identity."
      continue
    fi

    # The identity's own header and scheme, so the forged token is presented
    # exactly as its genuine session presents it - a server keying on a custom
    # header must see the same one.
    dast_auth_state "$target" "$label"
    local header=${_DAST_AUTH_HEADER:-Authorization}
    local scheme=${_DAST_AUTH_SCHEME:-Bearer}

    local ran_for_identity=0
    for line in "${candidates[@]+"${candidates[@]}"}"; do
      method=${line%%$'\t'*}
      url=${line#*$'\t'}
      jwt_run "$target" "$method" "$url" "$token" "$header" "$scheme"
      case ${_JWT_RUN_STATUS:-} in
        ran | no_verify)
          ran_for_identity=1
          any_oracle=1
          (( ${_JWT_RUN_RS_PUBKEY_MISSING:-0} )) && rs_missing=1
          break
          ;;
        token_rejected)
          # This endpoint is not one this identity's token is authorised for;
          # try the next candidate rather than giving up on the identity.
          continue
          ;;
        not_jwt)
          break
          ;;
      esac
    done

    if (( ! ran_for_identity )); then
      run_record coverage_reduction "module=dast reason=no_oracle_endpoint check=jwt target=$target identity=$label - none of the ${#candidates[@]} candidate endpoint(s) accepted this identity's real token, so no accept/reject oracle could be established and no forged token was tested for it."
      run_record coverage_gap "dast jwt: identity '$target.$label' could not establish a JWT oracle - none of the crawled idempotent endpoints accepted its real token (see its last reason: ${_JWT_RUN_REASON:-unknown}). Its JWT verification was not tested."
    fi
  done

  if (( rs_missing )); then
    run_record coverage_reduction "module=dast reason=rs_hs_confusion_no_pubkey check=jwt target=$target - a token declared an asymmetric algorithm (RS/PS/ES), but scoursh has no public key for the target, so RS->HS algorithm confusion could not be tested. The forging mechanism exists and is unit-tested; only the live replay was skipped."
    run_record coverage_gap "dast jwt: RS->HS algorithm confusion on target '$target' was NOT tested - it needs the target's public key (a JWKS endpoint or an operator-supplied key), which no input to this run provided. A clean result here is not evidence the target pins its verification algorithm."
  fi

  if (( ! any_oracle )); then
    run_record coverage_gap "dast jwt: no JWT oracle was established on target '$target' across ${#labels[@]} authenticated identity(ies), so no forged token was actually replayed. The JWT verification of this target was not proven either way."
  fi

  log_info "dast jwt: target '$target' - ${#labels[@]} identity(ies), ${#candidates[@]} candidate endpoint(s), oracle established=$any_oracle"
  return 0
}

_dast_jwt_phase
