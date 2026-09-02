#!/usr/bin/env bash
# modules/dast/passive/banner.sh - the §7.1 PASSIVE server/framework banner and
# version-disclosure check (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md
# DAST-09, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs on every dast run), so it
# inherits the whole run context and anything it emits lands in this process's
# shard.  Per that function's contract it carries NO sourced-once guard - one
# run can legitimately reach the same phase twice.  The pure, testable half is
# modules/dast/passive/banner_engine.sh.
#
# WHAT IT REPORTS, IN THE ORDER §7.1 NAMES THEM:
#   * DAST-BANNER-SERVER_DISCLOSURE-01   a server or framework NAME in a
#                                        response header, with no version.
#   * DAST-BANNER-VERSION_DISCLOSURE-01  a name AND a version, from a header
#                                        value, an HTML `<meta name=generator>`
#                                        tag, or a versioned bundle filename.
#   * DAST-BANNER-OUTDATED_COMPONENT-01  a discovered `product@version` that the
#                                        VENDORED list at `data/versions.db`
#                                        names as known-vulnerable.
#
# PASSIVE MEANS PASSIVE.  One plain GET per already-discovered endpoint, no
# payload, no header the operator did not configure, no mutation of state, and
# only endpoints the inventory records as GET or HEAD - a POST endpoint is
# counted and skipped rather than dialled.  The endpoint list is READ from
# `reports/<run>/inventory/endpoints.json` (DAST-04); this phase never crawls
# and never invents a URL.
#
# EVERY REQUEST GOES THROUGH lib/http.sh's `http_request` (tension 19's "No
# bypass"), which is where the scope gate, DAST-01's rate limiter, the per-run
# request budget, the circuit breaker and DAST-32's ceilings all sit.
#
# THE VERSION LIST IS OFFLINE AND VENDORED, AND THAT IS THE WHOLE POINT.  No
# request is ever made to look a version up; `data/versions.db` is read from
# disk.  An install whose list is missing or carries no `banner` rows - which is
# the state of a fresh clone - degrades that ONE sub-check to a recorded
# `coverage_reduction` and keeps the other two, because "we did not look" must
# never render as "we looked and it was fine" (docs/DESIGN.md §15).
# docs/VERSIONS-DB.md is the format and the refresh procedure.
#
# shellcheck shell=bash
#
# SC2016: the remediation prose is single-quoted on purpose and quotes config
#   directives (`server_tokens off`, `ServerTokens Prod`, `expose_php = Off`)
#   inside backticks, which is the operator-facing spelling of them.  Nothing
#   in it is meant to expand, and double-quoting it would make the backticks
#   command substitutions - the opposite of what is wanted.  Same reason
#   banner_engine.sh carries this directive.
# shellcheck disable=SC2016
#
# shellcheck source=modules/dast/passive/banner_engine.sh
source "${BASH_SOURCE[0]%/*}/banner_engine.sh"
# lib/http.sh is the chokepoint; a dast run does not otherwise load it (see
# modules/dast/engine.sh's header), so a phase that issues traffic sources it,
# guarded exactly as modules/dast/auth_engine.sh and inject_engine.sh do.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi

# `_banner_path_of URL` - the path component, query and fragment removed, for
# the finding's location (the fingerprint templates it via `path_template_of`).
# A URL with no path is `/`.
_banner_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_banner_channel_prose CHANNEL` - the sentence fragment that names where the
# disclosure was read, so the evidence says which surface to change.
_banner_channel_prose() {
  case $1 in
    header) printf 'a response header' ;;
    meta) printf 'an HTML <meta name="generator"> tag' ;;
    bundle) printf 'a versioned bundle filename in the served markup' ;;
    *) printf 'the response' ;;
  esac
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# The DAST location profile is (target, method, path_template, param_location,
# param_name) (lib/findings.sh).  This check has no request parameter, so the
# two location fields carry what identity actually means here:
#
#   param_location  the disclosure CHANNEL - header | meta | bundle
#   param_name      the product key, and for the outdated-component check the
#                   `product@version` pair
#
# The version is part of the key for OUTDATED_COMPONENT and NOT part of it for
# the two disclosure checks, and the asymmetry is the point.  "This endpoint
# discloses its jQuery version" is one issue that survives an upgrade, so its
# identity must not change when the version does.  "This endpoint runs jQuery
# 3.4.1, which is named in the vendored list" is a claim ABOUT 3.4.1: upgrading
# must make that finding `fixed` and a new one appear if the new version is also
# listed, which only happens if the version is in the fingerprint.
_banner_emit() {
  local kind=$1 channel=$2 product=$3 version=$4 url=$5 method=$6 raw=$7
  local target=${SCOURSH_DAST_TARGET:-} path check title base conf cwe owasp remed evi pname where
  path=$(_banner_path_of "$url")
  where=$(_banner_channel_prose "$channel")

  case $kind in
    server)
      check=DAST-BANNER-SERVER_DISCLOSURE-01; base=info; conf=high
      pname=$product
      cwe=CWE-200; owasp=A05:2021
      title='Server or framework disclosed in a response header'
      remed='Suppress or overwrite the product token in the response. On the origin server this is `server_tokens off` (nginx), `ServerTokens Prod` plus `ServerSignature Off` (Apache), `expose_php = Off` (PHP) or removing `X-Powered-By` in the application framework; where the origin cannot be changed, strip the header at the reverse proxy or CDN. This is defence in depth, not a fix on its own: treat it as one, and patch the component itself on its own schedule.'
      evi="$where on $method $path names the component '$product' (raw value: $raw). The running software identifies itself to every client, which lets an attacker select exploits for that product without probing for them." ;;
    version)
      check=DAST-BANNER-VERSION_DISCLOSURE-01; base=low; conf=high
      pname=$product
      cwe=CWE-200; owasp=A05:2021
      title='Framework or component version disclosed'
      remed='Stop publishing the exact version to unauthenticated clients: suppress the product token in the response header, remove the generator meta tag your CMS or static-site generator emits, and serve bundles under a content-hashed filename rather than a version-numbered one. Then keep the component patched, because a version an attacker can also fingerprint by behaviour is only hidden, not fixed.'
      evi="$where on $method $path discloses '$product' version $version (raw value: $raw). An exact version turns exploit selection into a lookup: an attacker no longer has to probe to learn which published vulnerabilities apply." ;;
    outdated)
      check=DAST-BANNER-OUTDATED_COMPONENT-01; base=${_BANNER_SEVERITY:-high}; conf=medium
      pname="$product@$version"
      cwe=CWE-1104; owasp=A06:2021
      title='Component version named in the vendored known-vulnerable list'
      remed='Upgrade the component to a release that is not named in the advisory, or apply the vendor backport for it. Where an upgrade is not immediately possible, put a compensating control in front of the specific weakness the advisory describes and track the upgrade as remediation rather than treating the control as one. Verify the running version afterwards from the same surface this was read from.'
      evi="$where on $method $path identifies '$product' version $version, which the vendored list at data/versions.db names as affected by ${_BANNER_ADVISORIES:-an advisory with no id recorded}.${_BANNER_SUMMARY:+ Summary: ${_BANNER_SUMMARY}.}${_BANNER_FIXED:+ Fixed in: ${_BANNER_FIXED}.} That list is an offline snapshot${_BANNER_DB_GENERATED:+ generated ${_BANNER_DB_GENERATED}} and is only as current as its last refresh (docs/VERSIONS-DB.md), so its silence about any other component is not evidence about that component." ;;
    *)
      die "$SCOURSH_EXIT_INCOMPLETE" "internal: modules/dast/passive/banner.sh emitted an unknown finding kind '$kind'" ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set remediation "$remed"
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$channel"
  finding_set loc_param_name "$pname"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

_dast_banner_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/banner.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # tension-15 per-check selection, consulted only if the function exists - the
  # same guarded shape active/sqli.sh uses, so a direct-engine test that never
  # ran scan.sh's filter chain still exercises everything the tier permitted.
  local do_disclosure=1 do_outdated=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-BANNER-SERVER_DISCLOSURE-01 || do_disclosure=0
    dast_check_selected DAST-BANNER-OUTDATED_COMPONENT-01 || do_outdated=0
  fi

  # The vendored list, read once per run.  Its state decides only whether the
  # THIRD sub-check can run; the two disclosure checks need no data at all, so a
  # fresh clone still gets them.
  banner_db_state
  if (( do_outdated )); then
    case $_BANNER_DB_STATE in
      absent)
        do_outdated=0
        run_record coverage_reduction "module=dast reason=versions_db_absent target=$target - the vendored known-vulnerable version list at data/versions.db is missing or unreadable, so discovered component versions were not checked against it. Version DISCLOSURE was still checked. Populate the list on a networked box (docs/VERSIONS-DB.md); nothing in a scan ever fetches it."
        ;;
      no_banner_rows)
        do_outdated=0
        run_record coverage_reduction "module=dast reason=versions_db_no_banner_rows target=$target - data/versions.db exists but carries no \`banner\` rows, so no discovered component version could be matched against a known-vulnerable one. This is the state of a fresh clone: the list is vendored by an operator action, never by a scan (docs/VERSIONS-DB.md). Version DISCLOSURE was still checked."
        ;;
      present)
        run_record notes "module=dast phase=banner target=$target versions_db=present${_BANNER_DB_GENERATED:+ generated=$_BANNER_DB_GENERATED}"
        ;;
    esac
  fi

  banner_endpoints_load "${SCOURSH_DAST_ENDPOINTS:-}" "$target"
  if (( _BANNER_EP_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory target=$target - no endpoint the crawler recorded for this target is requestable with a passive GET (docs/INVENTORY-FORMAT.md), so no response was read for a banner. skipped_non_idempotent=$_BANNER_EP_SKIPPED"
    run_record coverage_gap "dast banner: target '$target' has no GET-able discovered endpoint, so no response header, generator tag or bundle filename was examined. A clean result here is the absence of a test, not the absence of a disclosure."
    return 0
  fi

  local n=$_BANNER_EP_N truncated=0
  if (( n > _BANNER_MAX_ENDPOINTS )); then
    truncated=$(( n - _BANNER_MAX_ENDPOINTS ))
    n=$_BANNER_MAX_ENDPOINTS
  fi

  local bodyf=$SCOURSH_SCRATCH/dast-banner.body.$$
  local hdrf=$SCOURSH_SCRATCH/dast-banner.hdr.$$

  # Seen keys, so one product disclosed by fifty pages is one finding.  The
  # disclosure checks key on (channel, product) and the outdated check on
  # (channel, product, version), matching each one's own fingerprint.
  local -A seen_disc=() seen_out=() unknown_products=()
  local i url method hname hvalue prod ver line pair key raw
  local requested=0 read_ok=0 disclosures=0 capped=0 unknown_n=0

  # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - the shared
  # implementation lives in modules/dast/engine.sh section 3b and its long form
  # is there. In short: `http_request` gates FATALLY, which is right for the
  # operator's own base-url and exactly wrong for a URL lifted out of an
  # inventory some other module wrote, where one bad row would abort the whole
  # run at exit 3. Everything that survives still goes through `http_request`,
  # which re-gates it and re-gates every redirect hop.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi
  for (( i = 0; i < n; i++ )); do
    url=${_BANNER_EP_URL[$i]}
    if declare -F dast_endpoint_keep >/dev/null; then
      dast_endpoint_keep "$url" "$target" || continue
    fi
    method=GET
    http_request_reset
    http_request_capture "$bodyf" "$hdrf"
    : >"$hdrf"
    requested=$(( requested + 1 ))
    # A transport failure on one endpoint is not a reason to abandon the phase:
    # the breaker inside http_request already decides when a target has stopped
    # answering, and that decision must not be duplicated here.
    http_request "$method" "$url" 3 "$target" || continue
    read_ok=$(( read_ok + 1 ))

    # Channel 1: the allow-listed response headers.
    for hname in "${_BANNER_HEADERS[@]+"${_BANNER_HEADERS[@]}"}"; do
      hvalue=$(banner_header_value "$hdrf" "$hname")
      [[ -n $hvalue ]] || continue
      while IFS=$'\t' read -r prod ver; do
        [[ -n $prod ]] || continue
        _banner_consider header "$prod" "$ver" "$url" "$method" "$hname: $hvalue"
      done < <(banner_products_from_header "$hname" "$hvalue")
    done

    # Channels 2 and 3 need the body, bounded.  Only a markup-ish response is
    # parsed: a JSON API answer or an image carries no generator tag and no
    # bundle reference, and reading one for them is work with no signal.
    # `*html*` covers `application/xhtml+xml` too - the substring is there - so
    # there is deliberately no separate `*xhtml*` arm: it could never be
    # reached, and shellcheck's SC2221/SC2222 pair says so.  The empty arm is
    # the response that carried no Content-Type at all, which is parsed rather
    # than skipped, because "the server did not say" is not "it is not markup".
    case ${_HTTP_LAST_CONTENT_TYPE:-} in
      *html* | '' )
        if [[ -s $bodyf ]]; then
          local trimmed=$SCOURSH_SCRATCH/dast-banner.trim.$$
          head -c "$_BANNER_MAX_BODY_BYTES" -- "$bodyf" >"$trimmed" 2>/dev/null || true
          while IFS=$'\t' read -r prod ver; do
            [[ -n $prod && -n $ver ]] || continue
            _banner_consider meta "$prod" "$ver" "$url" "$method" "<meta name=\"generator\"> $prod $ver"
          done < <(banner_products_from_meta "$trimmed")
          while IFS=$'\t' read -r prod ver; do
            [[ -n $prod && -n $ver ]] || continue
            _banner_consider bundle "$prod" "$ver" "$url" "$method" "$prod $ver"
          done < <(banner_products_from_bundles "$trimmed")
          rm -f -- "$trimmed"
        fi
        ;;
    esac
  done
  rm -f -- "$bodyf" "$hdrf"

  # Recorded BEFORE the `read_ok == 0` return below, not after it. A run whose
  # every inventory row was out of scope reaches that branch with nothing read,
  # and a roll-up placed after it would be the one case it never printed - the
  # exact case it exists to explain.
  if declare -F dast_scope_record_skips >/dev/null; then
    dast_scope_record_skips banner "$target"
  fi

  # `checks_run` records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up reads.
  # Recorded only when a response was actually read, so a run that reached
  # nothing is not reported as covered.
  if (( read_ok > 0 )); then
    if (( do_disclosure )); then
      run_record checks_run DAST-BANNER-SERVER_DISCLOSURE-01
      run_record checks_run DAST-BANNER-VERSION_DISCLOSURE-01
    fi
    (( do_outdated )) && run_record checks_run DAST-BANNER-OUTDATED_COMPONENT-01
  else
    run_record coverage_gap "dast banner: every one of the $requested request(s) to target '$target' failed at the transport, so no response was examined for a banner or a version."
    return 0
  fi

  if (( unknown_n > 0 )); then
    # The banner equivalent of tension 25's SCA-COV-UNKNOWN_VERSION-01, and one
    # roll-up rather than one record per product for the same reason: per-product
    # noise would drown the findings.  "The list has never heard of this product"
    # and "this version is not listed" are different facts and only the second is
    # reassuring.
    run_record coverage_reduction "module=dast reason=versions_db_product_unknown target=$target count=$unknown_n products=[${!unknown_products[*]}] - the vendored list carries no row at all for these components, so their versions were neither confirmed vulnerable nor confirmed unaffected."
  fi
  if (( _BANNER_EP_SKIPPED > 0 )); then
    run_record coverage_reduction "module=dast reason=banner_non_idempotent_endpoint target=$target count=$_BANNER_EP_SKIPPED - $_BANNER_EP_SKIPPED discovered endpoint(s) are not GET or HEAD; a passive check does not request them (docs/DESIGN.md §7.1, no mutation of state), so their responses were not examined."
  fi
  if (( truncated > 0 )); then
    run_record coverage_gap "dast banner: target '$target' has $_BANNER_EP_N GET-able endpoints and this check requested the first $_BANNER_MAX_ENDPOINTS of them, so $truncated were not examined for a banner. That is a coverage bound, not a clean result."
  fi
  if (( capped > 0 )); then
    run_record coverage_gap "dast banner: target '$target' disclosed more than $_BANNER_MAX_DISCLOSURES distinct components and $capped further disclosure(s) were not reported individually. The cap is what keeps one misconfigured page from filling the report."
  fi

  log_info "dast banner: target '$target' - read $read_ok of $requested response(s), reported $disclosures disclosure(s) (versions_db=$_BANNER_DB_STATE)"
  return 0
}

# `_banner_consider CHANNEL PRODUCT VERSION URL METHOD RAW` - the one place a
# discovered component becomes findings, so the dedup, the cap and the
# vendored-list lookup cannot be applied in one channel and forgotten in another.
#
# Written as a function that reads the enclosing phase's locals by name (they are
# in scope because bash is dynamically scoped) rather than as inline code
# repeated three times, which is what the three channels would otherwise be.
_banner_consider() {
  local channel=$1 product=$2 version=$3 url=$4 method=$5 raw=$6
  local key okey
  # ONE FINDING PER TARGET, NOT PER ENDPOINT.  A `Server` header is set once and
  # every page carries it, so keying the dedup on the path would report the same
  # single misconfiguration ten times - once per endpoint the cap allowed.  The
  # path that does end up in the finding is the FIRST endpoint that disclosed
  # the component in the sorted endpoint order (banner_endpoints_load), which is
  # what makes that path, and therefore the fingerprint, the same on the next
  # run over the same surface.
  key="$channel|$product"
  okey="$channel|$product|$version"

  if (( do_disclosure )) && [[ -z ${seen_disc[$key]:-} ]]; then
    if (( disclosures >= _BANNER_MAX_DISCLOSURES )); then
      capped=$(( capped + 1 ))
    else
      seen_disc[$key]=1
      disclosures=$(( disclosures + 1 ))
      if [[ -n $version ]]; then
        _banner_emit version "$channel" "$product" "$version" "$url" "$method" "$raw"
      elif [[ $channel == header ]]; then
        # A name with no version is only a finding from a header: a bundle or a
        # generator tag with no version is not a disclosure at all, and the two
        # readers above already drop those.
        _banner_emit server "$channel" "$product" '' "$url" "$method" "$raw"
      fi
    fi
  fi

  [[ -n $version ]] || return 0
  (( do_outdated )) || return 0
  [[ -z ${seen_out[$okey]:-} ]] || return 0
  seen_out[$okey]=1
  if banner_db_match "$product" "$version"; then
    _banner_emit outdated "$channel" "$product" "$version" "$url" "$method" "$raw"
  elif ! banner_db_known "$product"; then
    if [[ -z ${unknown_products[$product]:-} ]]; then
      unknown_products[$product]=1
      unknown_n=$(( unknown_n + 1 ))
    fi
  fi
  return 0
}

_dast_banner_phase
