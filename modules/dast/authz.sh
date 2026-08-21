#!/usr/bin/env bash
# modules/dast/authz.sh - the §7.4 object-level authorization and
# data-exposure PHASE (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-29).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - one run can legitimately reach the same phase
# twice (a second scope target, a second `scan_main` in one process) and a guard
# would silently make the second one a no-op.  The pure functions - candidate
# extraction, the oracle, the field scan - live in modules/dast/authz_engine.sh,
# which does have one; this file resolves the LIVE inputs and drives it.
#
# ---------------------------------------------------------------------------
# THE THREE INPUTS, AND WHY EACH ABSENCE IS A RECORDED GAP RATHER THAN AN ERROR
# ---------------------------------------------------------------------------
# 1. TWO AUTHENTICATED IDENTITIES.  rules/RULE-FORMAT.md §9.5 gives this check
#    `requires-identities: 2` by name.  They come from auth.sh (DAST-03), which
#    already supports labelled multi-identity configuration for exactly this
#    consumer, and the phase asks `dast_auth_authenticated_labels_set` rather
#    than reading config/auth.conf itself: two CONFIGURED identities of which
#    one failed to log in are not two identities, and a check that discovers
#    that at runtime tends to discover it by reporting a clean result.
# 2. OBJECT REFERENCES.  From the crawl inventory (DAST-04,
#    docs/INVENTORY-FORMAT.md) - endpoint paths carrying an id-shaped segment,
#    and `location: query` parameters whose recorded example is one.  There is
#    deliberately NO config key naming an "IDOR path": a path that varies per
#    application belongs in the inventory the crawler already builds, not in a
#    second place that can drift from it, and rules/RULE-FORMAT.md §9.6.1's key
#    set is frozen besides.
# 3. THE SENSITIVE-FIELD LIST, vendored at modules/dast/sensitive-fields.txt
#    and overridable through SCOURSH_DAST_SENSITIVE_FIELDS_FILE.
#
# When any of the three is missing the phase does not error and does not
# silently pass: it records a `coverage_reduction` and a human-readable
# `coverage_gap`, so an absent finding never reads as a clean result.  That is
# docs/DESIGN.md §15's requirement and the posture auth.sh, crawl.sh, sqli.sh
# and jwt.sh have each already established.  THE TICKET'S OWN WORDING - "if two
# identities are not supplied, the module must skip cleanly and say why, not
# fail" - is this paragraph made executable, and the suite asserts the exit
# status AND the recorded reason for every one of the skip paths.
#
# ---------------------------------------------------------------------------
# READ-ONLY, RESTATED HERE BECAUSE IT IS THIS TICKET'S SAFETY PROPERTY
# ---------------------------------------------------------------------------
# docs/STEP5-DAST-PLAN.md's own safety amendment for DAST-29 is "read-only
# object references only, no writes".  Every request this phase makes is a GET
# or a HEAD with no body, and the restriction is applied where CANDIDATES are
# chosen rather than where requests are sent, so a mutating method is never even
# a candidate.  Nothing is created, modified or deleted on the target; nothing a
# forged or substituted reference returns is persisted; no response body reaches
# any artifact.  See modules/dast/authz_engine.sh's header for the full
# statement and the oracle argument.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/authz_engine.sh
source "${BASH_SOURCE[0]%/*}/authz_engine.sh"

_dast_authz_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local authed=${SCOURSH_DAST_AUTHED:-false}
  local label_a label_b
  local -a labels=()

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/authz.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # --- input 1: two live sessions ------------------------------------------
  if [[ $authed != true ]]; then
    run_record coverage_reduction "module=dast reason=authed_not_requested check=authz target=$target - the object-level authorization checks compare what two authenticated identities can read, and --authed was not given, so no session was acquired and nothing was compared. No request was sent."
    run_record coverage_gap "dast authz: --authed was not given for target '$target', so the §7.4 object-level authorization (IDOR) and excessive-data-exposure checks did not run. They need two labelled identities in config/auth.conf (rules/RULE-FORMAT.md §9.6.2) and a run with --authed. A clean result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  dast_auth_authenticated_labels_set "$target"
  labels=("${_DAST_AUTH_AUTHED_LABELS[@]+"${_DAST_AUTH_AUTHED_LABELS[@]}"}")
  if (( ${#labels[@]} < 2 )); then
    run_record coverage_reduction "module=dast reason=requires_identities_unmet check=authz target=$target required=2 authenticated=${#labels[@]} - object-level authorization cannot be established from one session: with a single identity there is no way to distinguish 'this object is mine' from 'this object is anybody's'. The checks were skipped rather than run against one identity and reported."
    run_record coverage_gap "dast authz: target '$target' has ${#labels[@]} authenticated identity(ies) and this check needs 2 (rules/RULE-FORMAT.md §9.5 requires-identities). Configure a second labelled identity for this target in config/auth.conf and re-run with --authed; if two are already configured, see the auth phase's own coverage records for why one did not obtain a session. The §7.4 IDOR and excessive-data-exposure checks did not run on this target."
    return 0
  fi

  # THE FIRST TWO, IN config/auth.conf's OWN ORDER.  `dast_auth_labels_set`
  # documents why that order is the file's rather than sorted: "identity A" and
  # "identity B" are whichever two the operator wrote first, which is the only
  # reading that does not silently swap the two identities when somebody renames
  # one.  A third identity is not an error and is not used; the run says so.
  label_a=${labels[0]}
  label_b=${labels[1]}
  if (( ${#labels[@]} > 2 )); then
    run_record coverage_reduction "module=dast reason=extra_identities_unused check=authz target=$target used=2 available=${#labels[@]} - the object-level authorization checks compare the FIRST TWO identities in config/auth.conf order ('$label_a' and '$label_b'). Every additional pairing multiplies the requests made against the target, so the remaining identity(ies) were not probed."
  fi

  # --- input 2: the inventory ----------------------------------------------
  # THE INVENTORY PATH IS RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE.
  # modules/dast/run.sh reads the inventory and exports SCOURSH_DAST_ENDPOINTS /
  # SCOURSH_DAST_PARAMETERS BEFORE the phase loop starts, while crawl.sh writes
  # reports/<run>/inventory/*.json several phases later in that same loop - so
  # on a first run, the ordinary case, the exports are EMPTY on exactly the run
  # that has just discovered a surface.  The run directory's own artifact is the
  # authority (docs/INVENTORY-FORMAT.md §1), so it is consulted when the export
  # is empty.  modules/dast/passive/headers.sh does the same and pins it with a
  # test; fixing the export itself belongs to modules/dast/run.sh and is filed
  # separately rather than changed under a peer ticket.
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  local prf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  if [[ -z $prf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    prf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi

  local scratch=${SCOURSH_RUN_DIR:-${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}}/authz.$$
  mkdir -p "$scratch"
  chmod 700 "$scratch" 2>/dev/null || true

  # --- the IDOR pass --------------------------------------------------------
  authz_candidates_set "$target" "$epf" "$prf"
  local ncand=${#_AUTHZ_CANDIDATES[@]}
  if (( ncand == 0 )); then
    run_record coverage_reduction "module=dast reason=no_object_reference check=authz target=$target endpoints=${epf:-none} parameters=${prf:-none} - no idempotent endpoint path or query parameter in the inventory carried an object-reference-shaped value (an integer, a UUID, a ULID, or 16+ hex characters), so there was no reference to substitute between the two identities."
    run_record coverage_gap "dast authz: no object reference was found for target '$target' (docs/INVENTORY-FORMAT.md endpoints.json was ${epf:-absent}, parameters.json was ${prf:-absent}), so the IDOR check had nothing to substitute and did not run. Supply an authenticated crawl or an OpenAPI/HAR specification that reaches an object-keyed endpoint. Note also that a SLUG-keyed reference (/users/jane) is deliberately not treated as an object reference here, because admitting arbitrary path words would spend the whole request budget on ordinary pages - slug-keyed IDOR on this target was therefore not assessed either."
  else
    run_record checks_run 'DAST-AUTHZ-IDOR-01'
    run_record checks_run 'DAST-AUTHZ-CROSS_IDENTITY_READ-01'
    authz_idor_run "$target" "$label_a" "$label_b" "$scratch"
    _dast_authz_record_idor "$target" "$ncand"
  fi

  # --- the excessive-data-exposure pass ------------------------------------
  if ! authz_sensitive_load; then
    run_record coverage_reduction "module=dast reason=sensitive_field_list_unavailable check=authz target=$target - the sensitive-field list (modules/dast/sensitive-fields.txt, or SCOURSH_DAST_SENSITIVE_FIELDS_FILE) is absent, unreadable or empty, so the excessive-data-exposure check did not run. This is a coverage reduction, not a clean result."
    run_record coverage_gap "dast authz: the excessive-data-exposure check on target '$target' did not run because its field list could not be read. Restore modules/dast/sensitive-fields.txt or point SCOURSH_DAST_SENSITIVE_FIELDS_FILE at a readable one."
  elif [[ -z $epf ]]; then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory check=authz target=$target - the excessive-data-exposure check calls an authenticated endpoint from the crawl inventory, and no endpoints.json was available, so it did not run."
    run_record coverage_gap "dast authz: no endpoint inventory was available for target '$target', so no authenticated response was examined for over-exposed fields (docs/DESIGN.md §7.4's 'profile/bootstrap endpoint'). A clean result here is the absence of a test."
  else
    run_record checks_run 'DAST-AUTHZ-EXCESSIVE_DATA-01'
    run_record checks_run 'DAST-AUTHZ-OTHER_IDENTITY_DATA-01'
    authz_exposure_run "$target" "$label_a" "$label_b" "$epf" "$scratch"
    _dast_authz_record_exposure "$target" "$label_b"
  fi

  rm -rf "$scratch"
  log_info "dast authz: target '$target' - identities '$label_a'/'$label_b', $ncand object reference candidate(s), ${_AUTHZ_GROUPS_TESTED:-0} endpoint group(s) probed, ${_AUTHZ_EXPOSURE_TESTED:-0} response(s) field-scanned"
  return 0
}

# The honest statement of what the IDOR pass did and did not reach.  Every
# counter that can hide a missed finding gets a sentence; a bound that bit is
# never silent (docs/INVENTORY-FORMAT.md §8).
_dast_authz_record_idor() {
  local target=$1 ncand=$2
  if (( ${_AUTHZ_GROUPS_TRUNCATED:-0} > 0 )); then
    run_record coverage_reduction "module=dast reason=object_reference_groups_capped check=authz target=$target tested=${_AUTHZ_GROUPS_TESTED:-0} dropped=$_AUTHZ_GROUPS_TRUNCATED cap=$_AUTHZ_MAX_GROUPS - this check makes up to three requests per object reference, so the number of distinct endpoint groups probed per target is capped. The dropped groups were not tested."
  fi
  if (( ${_AUTHZ_REFS_TRUNCATED:-0} > 0 )); then
    run_record coverage_reduction "module=dast reason=object_references_capped check=authz target=$target tested=${_AUTHZ_REFS_TESTED:-0} dropped=$_AUTHZ_REFS_TRUNCATED cap=$_AUTHZ_MAX_REFS_PER_GROUP - the number of distinct object references probed within one endpoint group is capped for the same reason. The dropped references were not tested."
  fi
  if (( ${_AUTHZ_PUBLIC_SKIPPED:-0} > 0 )); then
    run_record coverage_reduction "module=dast reason=object_reference_public check=authz target=$target count=$_AUTHZ_PUBLIC_SKIPPED - an unauthenticated request returned the byte-identical object, so these references are served publicly and are not an object-level authorization question. They are excluded rather than reported."
  fi
  if (( ${_AUTHZ_DIGEST_DIFFERED:-0} > 0 )); then
    run_record coverage_gap "dast authz: on target '$target', ${_AUTHZ_DIGEST_DIFFERED} object reference(s) were readable by BOTH identities but returned different bytes to each, so this check drew no conclusion about them. That is the correct outcome for an endpoint that renders per-identity content, and it is also what a shared object embedding a per-request nonce, CSRF token or timestamp looks like - the comparison is over raw response bytes. Those references were not proven safe."
  fi
  if (( ${_AUTHZ_SKIPPED_METHOD:-0} > 0 )); then
    run_record coverage_gap "dast authz: ${_AUTHZ_SKIPPED_METHOD} inventory entry(ies) for target '$target' carrying an object reference were skipped because their method is not GET or HEAD. docs/DESIGN.md §7.4 restricts this check to read-only references, so object-level authorization on write endpoints was NOT assessed - by design, not by omission."
  fi
  if (( ${_AUTHZ_SKIPPED_SCOPE:-0} > 0 )); then
    run_record coverage_gap "dast authz: ${_AUTHZ_SKIPPED_SCOPE} inventory entry(ies) for target '$target' were skipped because their URL is not authorised by config/scope.conf. An inventory URL is chosen by the scanned target, not by the operator, so it is dropped here rather than allowed to abort the run."
  fi
  log_info "dast authz: IDOR pass on '$target' - $ncand candidate(s), ${_AUTHZ_REFS_TESTED:-0} reference(s) probed, ${_AUTHZ_REQUESTS:-0} request(s)"
  return 0
}

_dast_authz_record_exposure() {
  local target=$1 label_b=$2
  if (( ${_AUTHZ_EXPOSURE_TESTED:-0} == 0 )); then
    run_record coverage_gap "dast authz: no idempotent, in-scope endpoint was available for target '$target', so no authenticated response was examined for over-exposed fields."
    return 0
  fi
  if (( ${_AUTHZ_EXPOSURE_OVERSIZE:-0} > 0 )); then
    run_record coverage_reduction "module=dast reason=response_too_large_to_field_scan check=authz target=$target count=$_AUTHZ_EXPOSURE_OVERSIZE cap=$_AUTHZ_MAX_BODY_BYTES - these responses exceeded the parse bound and their field names were not read. They were not proven free of over-exposed fields."
  fi
  if (( ${_AUTHZ_NEEDLE_AMBIGUOUS:-0} > 0 )); then
    run_record coverage_reduction "module=dast reason=identity_identifier_not_discriminating check=authz target=$target - the identifier configured for identity '$label_b' is a substring of the other identity's own identifier, so finding it in a response would prove nothing. The \"other identity's data\" arm of the check was skipped for this target; give the two test identities identifiers that are not prefixes of each other."
  fi
  run_record coverage_gap "dast authz: the excessive-data-exposure check on target '$target' examined ${_AUTHZ_EXPOSURE_TESTED} authenticated response(s), matching FIELD NAMES against the vendored list in modules/dast/sensitive-fields.txt. It reads no field VALUES, so a sensitive value under an unsuggestive name is not detected, and it examines only the endpoints the crawl inventory named. A clean result is not a statement that this application returns no more than it should."
  return 0
}

_dast_authz_phase
