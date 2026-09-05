#!/usr/bin/env bash
# ADR: Converge the eight hand-rolled DAST scope pre-checks onto the ONE
#   decision in modules/dast/engine.sh section 3b, without forcing one grain.
# Context: Eight DAST consumers (this file, active/discovery.sh,
#   authz_engine.sh, passive/headers.sh, passive/leakage.sh, passive/markup.sh,
#   passive/transport.sh, ratelimit.sh) each grew their own inline copy of the
#   same non-fatal `http_gate_url` pre-check ahead of the shared helper
#   (commit 0efd731) landing - four had already drifted on reason-capture
#   (reading `_HTTP_GATE_REASON` after a loop, which the gate clears on every
#   call) and none of them agreed on wording.  This file is the hardest case:
#   `_crawl_in_scope` guards THREE different sources (the frontier URL, a
#   crawled `<a href>`, a form action), two of which are NOT an inventory row.
# Decision: Every call site now decides through `dast_endpoint_in_scope` /
#   `dast_endpoint_keep` (modules/dast/engine.sh), so there is one predicate
#   and one reason-capture-at-refusal-time property.  Five of the eight
#   consumers additionally converge their ROLL-UP onto the shared
#   `dast_scope_record_skips PHASE`, whose fixed wording is correct because
#   their URLs really are docs/INVENTORY-FORMAT.md rows.  This file's crawled
#   link/form case and active/discovery.sh's derived candidate do NOT: their
#   own `notes`/`coverage_reduction` wording is kept, because the shared
#   roll-up's text ("a row from the cross-module inventory") would misstate
#   where the URL came from.  Every `declare -F` guard stays permissive
#   (engine.sh is reached at runtime with no `source` line, per
#   `dast_run_phase`), and no module file gained a `source` line to it - see
#   modules/dast/engine.sh section 3b and this ticket's own "watch the shellcheck
#   budget" note.
# Alternatives considered: force every consumer through `dast_scope_record_skips`
#   verbatim -> rejected, it would report a crawled link or a derived wordlist
#   candidate as an inventory row, which is a factually wrong coverage record.
#   Leave the four degraded (post-loop reason read) copies as-is -> rejected,
#   that is the drift this ticket exists to close.
# Consequences: one place decides "in scope" for every DAST phase and one
#   place decides how the reason is captured; a future ninth consumer copies
#   this pattern rather than `http_gate_url` directly.  What it does not buy:
#   a single coverage_reduction WORDING - the emission grain still belongs to
#   each phase, deliberately, because the source of the URL differs.
# Pointer: modules/dast/active/discovery.sh, modules/dast/authz_engine.sh,
#   modules/dast/authz.sh, modules/dast/passive/headers.sh,
#   modules/dast/passive/leakage.sh, modules/dast/passive/markup.sh,
#   modules/dast/passive/transport.sh and modules/dast/ratelimit.sh each carry
#   a short pointer comment back to this block at their own converged call
#   site.
#
# modules/dast/crawl.sh - the crawling / parameter / specification discovery
# phase (docs/DESIGN.md §7.5, §13 step 5; docs/STEP5-DAST-PLAN.md DAST-04).
#
# THIS IS A PHASE SCRIPT, NOT A LIBRARY.  `dast_run_phase` (modules/dast/
# engine.sh) `source`s it once per target, so it DOES something at source time
# and carries no sourced-once guard - a guard would silently make the second
# target of a multi-target run a no-op, which is that function's own header
# note.  Every array it declares uses `declare -g` for the reason the phase
# table documents: this file is sourced from inside a function.
#
# WHAT IT PRODUCES, AND WHY THAT IS THE WHOLE POINT.  Twenty-seven tickets in
# docs/STEP5-DAST-PLAN.md's tiers 2 through 5 read the two artifacts this file
# writes:
#
#     reports/<run>/inventory/endpoints.json
#     reports/<run>/inventory/parameters.json
#
# docs/INVENTORY-FORMAT.md is their normative shape.  An injection probe tests
# what is in them and nothing else, so a thin inventory is not a small problem
# that shows up as a smaller report - it is a run that reports CLEAN for every
# endpoint it never heard of.  That is why almost everything below that can
# reduce coverage records a `coverage_gap` or a `coverage_reduction` rather
# than just logging: docs/DESIGN.md §15's standard is that a scan which
# overstates coverage is worse than one which names its blind spots.
#
# THE ORDER OF THE FOUR INPUTS IS DELIBERATE, cheapest and most complete
# first:
#
#   1. An inventory another module already wrote (tension 21 - SAST route
#      extraction, aws/live/apigw.sh).  Costs no request at all.
#   2. A specification the operator supplied in config/discovery.conf -
#      OpenAPI/Swagger, GraphQL, Postman, HAR.  docs/DESIGN.md §7.5 calls this
#      "the preferred, most complete input" and means it: a spec describes
#      endpoints a crawler can never reach by following links.
#   3. The static crawl, which costs a request per page and can only find what
#      something links to.
#   4. Nothing else.  There is no fourth input, and the gap between what 1-3
#      can see and what a client-rendered application actually exposes is
#      declared rather than papered over - see "THE SPA GAP" below.
#
# THE SPA GAP IS SHIPPED, NOT FIXED.  A pure-shell crawler cannot execute
# JavaScript, so a React/Next.js-style application's routes - constructed at
# runtime, with no `href` to follow - are invisible to step 3 above.
# docs/DESIGN.md §7.5 states this as an "Honest limitation" and says a
# headless browser is "outside the pure-shell/no-egress envelope and should be
# a documented, separate opt-in tool - not smuggled into the core".
# docs/STEP5-DAST-PLAN.md then makes the acceptance criterion stronger than
# prose: when no specification or HAR is supplied, the gap must actually
# appear in run.json and in the report.  `_crawl_record_spa_gap` below is that
# requirement, and tests/suites/dast-crawl.sh asserts it on report.md and
# run.json rather than on an internal variable.
#
# EVERY REQUEST GOES THROUGH lib/http.sh (tension 19), which is also where
# DAST-01's rate limiter, per-run request budget and circuit breaker sit.  A
# crawler is the single component most likely to hammer a target, so that is
# not decoration here: `_crawl_fetch` calls `http_request` and there is no
# other path to the network in this file.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes URL and flag syntax literally.
# shellcheck disable=SC2016

# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/crawl_engine.sh"

# ---------------------------------------------------------------------------
# 1. Where the discovery inputs come from (rules/RULE-FORMAT.md §9.6.3)
# ---------------------------------------------------------------------------
# `config/discovery.conf` holds one record per target: the four specification
# paths, the crawl depth, and the include/exclude path globs.  An absent file
# is the normal case and is never an error - it means "crawl with the
# documented defaults" - but it is also the condition that makes the SPA gap
# unavoidable, so its absence is recorded rather than assumed benign.
#
# NEVER `source`d, always parsed as records (tension 26): a config file is
# data, and sourcing one would execute operator-supplied text before the scope
# gate is consulted.  tests/lint-shell.sh fails the build on the attempt.
_crawl_discovery_load() {
  local target=$1 path=${SCOURSH_INSTALL_ROOT:-.}/config/discovery.conf idx
  _CRAWL_D_OPENAPI='' _CRAWL_D_GRAPHQL='' _CRAWL_D_POSTMAN='' _CRAWL_D_HAR=''
  _CRAWL_D_DEPTH=3
  declare -ga _CRAWL_D_INCLUDE=()
  declare -ga _CRAWL_D_EXCLUDE=()
  _CRAWL_D_PRESENT=0

  config_load_if_present "$path" discovery-input discovery || return 0
  idx=$(records_index_of_id discovery "$target") || return 0
  _CRAWL_D_PRESENT=1

  _CRAWL_D_OPENAPI=$(records_field_or discovery "$idx" openapi-path '')
  _CRAWL_D_GRAPHQL=$(records_field_or discovery "$idx" graphql-schema-path '')
  _CRAWL_D_POSTMAN=$(records_field_or discovery "$idx" postman-path '')
  _CRAWL_D_HAR=$(records_field_or discovery "$idx" har-path '')
  _CRAWL_D_DEPTH=$(records_field_or discovery "$idx" crawl-depth 3)
  [[ $_CRAWL_D_DEPTH =~ ^[0-9]+$ ]] || _CRAWL_D_DEPTH=3

  local g
  while IFS= read -r g; do
    [[ -n $g ]] && _CRAWL_D_INCLUDE+=("$g")
  done <<<"$(records_list discovery "$idx" include-path)"
  while IFS= read -r g; do
    [[ -n $g ]] && _CRAWL_D_EXCLUDE+=("$g")
  done <<<"$(records_list discovery "$idx" exclude-path)"
  return 0
}

# A specification path is resolved relative to the INSTALL ROOT when it is not
# absolute, the same convention every other `config/*.conf` path key follows.
_crawl_resolve_input_path() {
  local p=$1
  [[ -n $p ]] || { printf ''; return 0; }
  if [[ $p == /* ]]; then printf '%s' "$p"; else printf '%s/%s' "${SCOURSH_INSTALL_ROOT:-.}" "$p"; fi
}

# ---------------------------------------------------------------------------
# 2. include-path / exclude-path
# ---------------------------------------------------------------------------
# Globs are matched against the TARGET-RELATIVE path (§9.6.3's own wording),
# through modules/sast/engine.sh's `sast_glob_match` - the one glob
# implementation this repository has (rules/RULE-FORMAT.md §9.1.2), reused
# rather than forked so an operator's `/admin/**` means the same thing here as
# it does in a rule pack.
#
# EXCLUDE WINS OVER INCLUDE, and an exclude is honoured BEFORE the request
# rather than after: §9.6.3 defines exclude-path as "never to request", which
# a filter applied to the results would not deliver.
_crawl_path_allowed() {
  local path=$1 g
  for g in "${_CRAWL_D_EXCLUDE[@]+"${_CRAWL_D_EXCLUDE[@]}"}"; do
    if sast_glob_match "$g" "${path#/}"; then return 1; fi
  done
  (( ${#_CRAWL_D_INCLUDE[@]} )) || return 0
  for g in "${_CRAWL_D_INCLUDE[@]+"${_CRAWL_D_INCLUDE[@]}"}"; do
    if sast_glob_match "$g" "${path#/}"; then return 0; fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 3. The one door to the network
# ---------------------------------------------------------------------------
# `_crawl_fetch METHOD URL BODYFILE` - one request through the chokepoint.
# Sets `_CRAWL_STATUS` and `_CRAWL_CTYPE`; returns 1 when no response was
# obtained at all.
#
# It does NOT gate: `http_request` gates, fatally, and re-gates every redirect
# hop.  What the CALLER must do first is `_crawl_in_scope`, and the difference
# between the two is the single most important thing in this file - see that
# function's header.
#
# THE BODY IS REQUESTED WITH `http_request_capture`, DAST-03's per-request
# context, rather than with a sink argument of this module's own: there is one
# way to ask lib/http.sh for a response body, and a second one would be the
# start of the second network path tension 19 exists to prevent.  The capture
# is set immediately before the call because `http_request` consumes and clears
# the context at entry, so it can never ride along on a later request.
_crawl_fetch() {
  local method=$1 url=$2 bodyfile=$3 rc=0
  _CRAWL_STATUS='' _CRAWL_CTYPE=''
  http_request_capture "$bodyfile" ''
  http_request "$method" "$url" "${SCOURSH_MAX_REDIRECTS:-5}" \
    "${SCOURSH_DAST_TARGET:-}" || rc=$?
  (( rc == 0 )) || return 1
  _CRAWL_STATUS=${_HTTP_LAST_STATUS:-}
  _CRAWL_CTYPE=${_HTTP_LAST_CONTENT_TYPE:-}
  return 0
}

# `_crawl_in_scope URL` - the PRE-FILTER, and the reason this file calls
# `http_gate_url` at all.
#
# A URL discovered on a crawled page is not a URL the operator authorised: it
# is a string the SCANNED SITE chose.  `http_request` treats an out-of-scope
# URL as a caller bug and `die`s with exit 3 (tension 19, and its own header
# says so), which is exactly right for a caller that believed the URL was
# authorised - and exactly wrong here.  Handing a crawled link straight to
# `http_request` would mean that ANY page carrying one off-target `<a href>`
# aborts the operator's whole run, so a site could stop its own scan by
# linking to a search engine.  The suite pins this with a page whose only
# extra link is off-target, and asserts both halves: the run completes, and no
# request was made to that host.
#
# This is not a second gate and never becomes one.  It decides only whether a
# URL is worth ENQUEUEING; every URL that survives is still requested through
# `http_request`, which applies the real gate again on the way out and on
# every redirect hop.  Deleting this function would make the crawler fragile;
# deleting the `http_request` call would make it unsafe, and only one of those
# two is a gate.
#
# Delegates to the shared, non-counting predicate `dast_endpoint_in_scope`
# (modules/dast/engine.sh section 3b) rather than calling `http_gate_url`
# directly, so every DAST consumer's reading of "in scope" is the same one.
# This is the bare PREDICATE, used where this file keeps its OWN counter
# (`_CRAWL_UNREACHABLE`, below) rather than the shared one - a crawled link or
# form action uses the shared counting wrapper `dast_endpoint_keep` instead,
# because that is a genuinely different source (a URL the SCANNED SITE chose)
# from the frontier URL this predicate guards, and the two are reported in
# different words for that reason (see the "every bound that bit" block near
# the end of `_crawl_run_phase`, which reads `_DAST_SCOPE_SKIPPED` rather than
# a local counter). The `declare -F` guard is permissive on purpose -
# engine.sh is reached by every phase through `dast_run_phase` at runtime
# WITHOUT a `source` line, and several suites source this file with no
# engine.sh in the process.
_crawl_in_scope() {
  local url=$1
  if declare -F dast_endpoint_in_scope >/dev/null; then
    dast_endpoint_in_scope "$url" "${SCOURSH_DAST_TARGET:-}"
    return $?
  fi
  http_gate_url "$url" "${SCOURSH_DAST_TARGET:-}"
}

# ---------------------------------------------------------------------------
# 4. The static crawl
# ---------------------------------------------------------------------------
# Breadth-first from the target's own `base-url`, bounded by `crawl-depth`
# (§9.6.3, default 3) and by `_CRAWL_MAX_PAGES`.  Breadth-first rather than
# depth-first because a page cap that bites should cost the DEEPEST pages, not
# a random branch: with a depth-first walk, hitting the cap means one long
# chain was explored and the target's own top-level navigation was not.
_crawl_static() {
  local target=$1 base=$2
  local body=$SCOURSH_SCRATCH/crawl-body.$BASHPID
  local frontier=$SCOURSH_SCRATCH/crawl-frontier.$BASHPID
  local nextf=$SCOURSH_SCRATCH/crawl-next.$BASHPID
  local -A visited=()
  local depth=0 pages=0 url kind a b
  local form_method='' form_action='' formurl='' formep=''

  _CRAWL_PAGES=0
  _CRAWL_PAGECAP=0
  _CRAWL_DEPTHCAP=0
  _CRAWL_NONHTML=0
  _CRAWL_UNFETCHED=0
  _CRAWL_FORMS=0
  _CRAWL_UNREACHABLE=0
  _CRAWL_GATE_REASON=''
  # A crawled link or form action is dropped through the shared counting
  # wrapper `dast_endpoint_keep` (modules/dast/engine.sh section 3b), reset
  # once for the whole static crawl so `_DAST_SCOPE_SKIPPED`/
  # `_DAST_SCOPE_REASONS` below counts every page's discoveries together.
  # `_CRAWL_OFFSCOPE` no longer exists as a separate counter for this - it IS
  # `_DAST_SCOPE_SKIPPED` now.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi

  printf '%s\n' "$base" >"$frontier"

  while (( depth <= _CRAWL_D_DEPTH )); do
    : >"$nextf"
    while IFS= read -r url; do
      [[ -n $url ]] || continue
      [[ -z ${visited[$url]:-} ]] || continue
      visited[$url]=1

      if (( pages >= _CRAWL_MAX_PAGES )); then
        _CRAWL_PAGECAP=$(( _CRAWL_PAGECAP + 1 ))
        continue
      fi

      crawl_url_split "$url"
      local upath=/ uquery=''
      if [[ $_CRAWL_U_BASE =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$ ]]; then
        upath=${BASH_REMATCH[1]:-/}
      fi
      uquery=$_CRAWL_U_QUERY
      if ! _crawl_path_allowed "$upath"; then
        continue
      fi

      # THE GATE, RE-ASSERTED IMMEDIATELY BEFORE THE REQUEST.  For a link this
      # is belt-and-braces - it was already checked at enqueue time, which is
      # where "an off-target link never becomes a request" is actually proven.
      # For the ROOT URL, which nothing enqueued, it is the only check there
      # is, and it is what keeps a target that does not resolve (or whose
      # base-url the operator changed without updating scope.conf) from
      # reaching `http_request`, which treats a refusal as a caller bug and
      # exits 3, taking the whole run with it.  A target we cannot reach is a
      # crawl that found nothing, which is a recorded gap; it is not a scope
      # VIOLATION, and conflating the two would abort an otherwise good run.
      if ! _crawl_in_scope "$url"; then
        _CRAWL_UNREACHABLE=$(( _CRAWL_UNREACHABLE + 1 ))
        [[ -n $_CRAWL_GATE_REASON ]] || _CRAWL_GATE_REASON=${_HTTP_GATE_REASON:-}
        continue
      fi

      pages=$(( pages + 1 ))
      : >"$body"
      if ! _crawl_fetch GET "$url" "$body"; then
        _CRAWL_UNFETCHED=$(( _CRAWL_UNFETCHED + 1 ))
        continue
      fi

      # The endpoint is recorded whatever the response was.  A 404 or a 500 is
      # still a route the application answers on, and a §7.3 probe that only
      # ever sees the 200s tests the half of the surface that already works.
      crawl_add_endpoint "$target" GET "$url" crawl "$depth" \
        "$_CRAWL_STATUS" "$_CRAWL_CTYPE" || true
      local pageep=$_CRAWL_LAST_EP_ID
      if [[ -n $uquery && -n $pageep ]]; then
        local qn qv
        while IFS=$'\t' read -r qn qv; do
          crawl_add_param "$pageep" "$target" GET "$_CRAWL_U_BASE" "$qn" query crawl "$qv" || true
        done < <(crawl_query_names "$uquery")
      fi

      # Only markup is parsed.  A content type this does not recognise is
      # counted rather than guessed at: running the tag scanner over a PDF or
      # a minified bundle produces "links" that are byte sequences, and every
      # one of them would become a real request downstream.
      # `*html*` already covers `application/xhtml+xml`, so xhtml is NOT
      # listed separately: a second pattern that can never be reached reads
      # like coverage it does not add.
      case ${_CRAWL_CTYPE,,} in
        *html* | '') ;;
        *)
          _CRAWL_NONHTML=$(( _CRAWL_NONHTML + 1 ))
          continue
          ;;
      esac
      [[ -s $body ]] || continue
      if [[ -z ${_CRAWL_CTYPE} ]]; then
        # No Content-Type at all: parse only if the bytes actually look like
        # markup, so a headerless binary is still not fed to the scanner.
        # crawl_body_looks_like_markup matches on the file directly (never by
        # reading it into a bash string) because a response body is arbitrary
        # target-controlled bytes and can legitimately contain a NUL - see
        # that function's own header for the full defect this avoids.
        if ! crawl_body_looks_like_markup "$body"; then
          _CRAWL_NONHTML=$(( _CRAWL_NONHTML + 1 )); continue
        fi
      fi

      # The SPA heuristic is sampled on the ROOT page only - the one page whose
      # shape is representative of how the application renders.
      if (( depth == 0 )) && crawl_html_looks_client_rendered "$body"; then
        _CRAWL_SPA_SHAPED=1
      fi

      form_method='' form_action='' formurl='' formep=''
      # Three fields, because `crawl_html_extract`'s widest record is
      # `form<TAB>METHOD<TAB>ACTION`.  A fourth read variable would be dead,
      # and reading one field FEWER would silently fold ACTION into METHOD.
      while IFS=$'\t' read -r kind a b; do
        case $kind in
          base)
            # `<base href>` changes what every relative reference on the page
            # resolves against.  Ignoring it silently produces requests to
            # paths that do not exist, at the depth where it matters most.
            local nb
            if nb=$(crawl_url_resolve "$url" "$a"); then url=$nb; fi
            ;;
          link)
            local abs
            if ! abs=$(crawl_url_resolve "$url" "$a"); then continue; fi
            if declare -F dast_endpoint_keep >/dev/null; then
              dast_endpoint_keep "$abs" "${SCOURSH_DAST_TARGET:-}" || continue
            elif ! _crawl_in_scope "$abs"; then
              continue
            fi
            crawl_url_split "$abs"
            local lpath=/
            if [[ $_CRAWL_U_BASE =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$ ]]; then
              lpath=${BASH_REMATCH[1]:-/}
            fi
            _crawl_path_allowed "$lpath" || continue
            if (( depth + 1 > _CRAWL_D_DEPTH )); then
              _CRAWL_DEPTHCAP=$(( _CRAWL_DEPTHCAP + 1 ))
              continue
            fi
            printf '%s\n' "$abs" >>"$nextf"
            ;;
          form)
            form_method=${a:-GET}
            form_action=$b
            formurl=''
            formep=''
            local faction=${form_action:-$url}
            local fabs
            if ! fabs=$(crawl_url_resolve "$url" "$faction"); then continue; fi
            # A form POSTing to an off-target host is a real thing (a payment
            # gateway, an SSO provider) and it is NOT this run's to submit or
            # to inventory.  Dropped and counted, exactly like an off-target
            # link.
            if declare -F dast_endpoint_keep >/dev/null; then
              dast_endpoint_keep "$fabs" "${SCOURSH_DAST_TARGET:-}" || continue
            elif ! _crawl_in_scope "$fabs"; then
              continue
            fi
            crawl_url_split "$fabs"
            formurl=$_CRAWL_U_BASE
            # The form's ACTION is an endpoint even though nothing was
            # submitted to it.  THE CRAWLER NEVER SUBMITS A FORM: a POST is a
            # state change, and docs/DESIGN.md §7.1's "no mutation of state"
            # is the tier this phase runs at.  Recording the endpoint and its
            # input names is what lets a §7.3 probe - which runs at a tier
            # that IS allowed to send one - do it later.
            if crawl_add_endpoint "$target" "$form_method" "$formurl" crawl "$depth" '' ''; then
              formep=$_CRAWL_LAST_EP_ID
              _CRAWL_FORMS=$(( _CRAWL_FORMS + 1 ))
            fi
            ;;
          input)
            [[ -n $formep ]] || continue
            local ploc=body
            [[ ${form_method^^} == GET ]] && ploc=query
            crawl_add_param "$formep" "$target" "$form_method" "$formurl" \
              "$a" "$ploc" crawl '' || true
            ;;
          formend)
            form_method='' form_action='' formurl='' formep=''
            ;;
        esac
      done < <(head -c "$_CRAWL_MAX_BODY_BYTES" -- "$body" | crawl_html_extract)
    done <"$frontier"

    LC_ALL=C sort -u -- "$nextf" >"$frontier" 2>/dev/null || : >"$frontier"
    [[ -s $frontier ]] || break
    depth=$(( depth + 1 ))
  done

  # Anything still queued when the depth loop ended is a page the depth bound
  # cost us, and it is counted so the bound is visible in the report rather
  # than only in this file.
  if [[ -s $frontier ]]; then
    local remaining=0
    while IFS= read -r url; do [[ -n $url ]] && remaining=$(( remaining + 1 )); done <"$frontier"
    _CRAWL_DEPTHCAP=$(( _CRAWL_DEPTHCAP + remaining ))
  fi

  rm -f "$body" "$frontier" "$nextf"
  _CRAWL_PAGES=$pages
  return 0
}

# ---------------------------------------------------------------------------
# 5. The SPA / client-rendered gap (docs/DESIGN.md §7.5, docs/STEP5-DAST-PLAN.md)
# ---------------------------------------------------------------------------
# Recorded whenever no specification of any kind was ingested for this target.
# It is `run_record coverage_gap`, not a log line, because lib/report.sh's
# limitations section is the surface a consumer actually reads and
# docs/STEP5-DAST-PLAN.md's acceptance criterion is explicitly "must appear in
# run.json/the report, not just be true in prose".
#
# THE CONDITION IS "NO SPEC WAS INGESTED", NOT "THE TARGET LOOKS LIKE AN SPA".
# The heuristic can only sharpen the sentence, never decide whether it is
# printed - a detector that decided would fail in the direction that hides the
# warning, and this whole mechanism exists because a scanner that finds three
# endpoints in a fifty-route application and reports success is the failure
# this project keeps rooting out.
_crawl_record_spa_gap() {
  local target=$1 pages=$2 endpoints=$3
  local shape=''
  if (( ${_CRAWL_SPA_SHAPED:-0} )); then
    shape=", and this target's own root document has script tags and almost no links, which is what a client-rendered application looks like from here"
  fi
  run_record coverage_gap "dast/crawl: no OpenAPI, GraphQL schema, Postman collection or HAR capture was supplied for target '$(crawl_safe_text "$target" 80)' (config/discovery.conf, rules/RULE-FORMAT.md §9.6.3), so the surface below is only what a static crawl could reach by following links: $pages page(s) fetched, $endpoints endpoint(s) known$shape. scoursh executes no JavaScript and has no browser, so a client-rendered application's routes and its XHR/fetch endpoints are INVISIBLE here and every later DAST check will report clean for them because it never saw them - that is the absence of a test, not the absence of a problem (docs/DESIGN.md §7.5). To close this, supply a spec or a HAR capture of real usage in config/discovery.conf; failing that, a SAST route extraction merged through reports/<run>/inventory/endpoints.json covers the server-side half (docs/FOUNDATION.md tension 21)."
  run_record coverage_reduction "module=dast phase=crawl reason=no_specification_supplied target=$(crawl_safe_text "$target" 80) pages=$pages endpoints=$endpoints spa_shaped=${_CRAWL_SPA_SHAPED:-0}"
}

# ---------------------------------------------------------------------------
# 6. The phase body
# ---------------------------------------------------------------------------
_crawl_run_phase() {
  declare -p SCAN_FLAGS &>/dev/null || declare -A SCAN_FLAGS=()

  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    log_warn 'dast/crawl: no target in context; nothing to crawl'
    return 0
  fi
  local rundir=${SCOURSH_RUN_DIR:-}
  if [[ -z $rundir || ! -d $rundir ]]; then
    log_warn 'dast/crawl: no run directory; nothing to write'
    return 0
  fi

  crawl_inv_reset
  _CRAWL_SPA_SHAPED=0

  local base
  base=$(config_scope_field "$target" base-url)
  # `base-url` is required by the §9.4 schema, so an empty one means the
  # record set was not what this thinks it is - refuse rather than crawl `/`
  # of an unknown host.
  if [[ -z $base ]]; then
    run_record coverage_gap "dast/crawl: target '$(crawl_safe_text "$target" 80)' has no base-url in config/scope.conf, so no crawl was attempted and no endpoint was discovered"
    return 0
  fi
  base=${base%/}
  [[ -n $base ]] || base=/

  _crawl_discovery_load "$target"

  # -- 1. the inventory another module may already have written (tension 21) --
  #
  # modules/dast/run.sh has ALREADY recorded the absent/empty coverage_gap for
  # both artifacts before this phase runs (`_dast_record_inventory_gaps`), so
  # this records the merge RESULT and never a second copy of that gap.
  local imported=0
  local inv_endpoints=$rundir/inventory/endpoints.json
  if [[ -s $inv_endpoints ]]; then
    # Read from a COPY.  This phase writes the same path at the end, and a
    # producer that read the file it is about to overwrite would be one
    # interrupted run away from an inventory that lost every route SAST found.
    local snapshot=$SCOURSH_SCRATCH/crawl-inv-in.$BASHPID
    cp -- "$inv_endpoints" "$snapshot" 2>/dev/null || : >"$snapshot"
    if crawl_inv_merge_endpoints "$snapshot" "$target"; then
      imported=$_CRAWL_MERGED_COUNT
    fi
    rm -f "$snapshot"
    run_record notes "module=dast phase=crawl inventory_merged=$imported source=$(crawl_safe_text "reports/${SCOURSH_RUN_ID:-run}/inventory/endpoints.json" 120)"
    if (( imported == 0 )); then
      run_record coverage_gap "dast/crawl: an endpoint inventory existed at inventory/endpoints.json but no endpoint could be read out of it (docs/FOUNDATION.md tension 21, docs/INVENTORY-FORMAT.md) - a producer wrote a shape this run does not understand, which costs every route it found"
    fi
  fi

  # -- 2. specifications (docs/DESIGN.md §7.5's preferred input) --------------
  local spec_count=0 spec_kinds='' f
  local -a spec_failures=()

  f=$(_crawl_resolve_input_path "$_CRAWL_D_OPENAPI")
  if [[ -n $f ]]; then
    if [[ ! -r $f ]]; then
      spec_failures+=("openapi:unreadable")
    elif crawl_spec_openapi "$f" "$target" "$base"; then
      spec_count=$(( spec_count + _CRAWL_SPEC_COUNT ))
      spec_kinds+='openapi '
    else
      spec_failures+=("openapi:$_CRAWL_SPEC_ERROR")
    fi
  fi
  f=$(_crawl_resolve_input_path "$_CRAWL_D_POSTMAN")
  if [[ -n $f ]]; then
    if [[ ! -r $f ]]; then
      spec_failures+=("postman:unreadable")
    elif crawl_spec_postman "$f" "$target" "$base"; then
      spec_count=$(( spec_count + _CRAWL_SPEC_COUNT ))
      spec_kinds+='postman '
    else
      spec_failures+=("postman:$_CRAWL_SPEC_ERROR")
    fi
  fi
  f=$(_crawl_resolve_input_path "$_CRAWL_D_HAR")
  if [[ -n $f ]]; then
    if [[ ! -r $f ]]; then
      spec_failures+=("har:unreadable")
    elif crawl_spec_har "$f" "$target" "$base"; then
      spec_count=$(( spec_count + _CRAWL_SPEC_COUNT ))
      spec_kinds+='har '
    else
      spec_failures+=("har:$_CRAWL_SPEC_ERROR")
    fi
  fi
  f=$(_crawl_resolve_input_path "$_CRAWL_D_GRAPHQL")
  if [[ -n $f ]]; then
    if [[ ! -r $f ]]; then
      spec_failures+=("graphql:unreadable")
    elif crawl_spec_graphql "$f" "$target" "$base/graphql"; then
      spec_count=$(( spec_count + _CRAWL_SPEC_COUNT ))
      spec_kinds+='graphql '
    else
      spec_failures+=("graphql:$_CRAWL_SPEC_ERROR")
    fi
  fi

  # A SPECIFICATION THAT WAS SUPPLIED AND DID NOT PARSE IS THE WORST CASE OF
  # ALL, because the operator has every reason to believe the gap is closed.
  # It is reported as its own gap, with the parser's own one-line reason -
  # in particular the YAML front-end's "this document uses a construct I would
  # have had to guess at", which is a fixable, actionable message and not a
  # shrug.
  local sf
  for sf in "${spec_failures[@]+"${spec_failures[@]}"}"; do
    run_record coverage_gap "dast/crawl: the ${sf%%:*} input configured for target '$(crawl_safe_text "$target" 80)' contributed NOTHING - $(crawl_safe_text "${sf#*:}" 300). The endpoints it describes are therefore absent from this run's inventory and no later check will test them, even though a specification was supplied."
    run_record coverage_reduction "module=dast phase=crawl reason=specification_unusable kind=${sf%%:*} target=$(crawl_safe_text "$target" 80)"
  done

  # -- 3. the static crawl ---------------------------------------------------
  _crawl_static "$target" "$base/"

  # -- 4. the authenticated pass --------------------------------------------
  #
  # DAST-03 (`auth.sh`) owns session acquisition and is a sibling ticket.  The
  # seam is deliberate and one-directional: this phase never calls into
  # auth.sh and never imports its code (tension 21's "modules never invoke each
  # other" applied inside a module), it only observes whether a session was
  # established for this run.  Until that exists, `--authed` is a request this
  # phase cannot honour, and saying so is the whole difference between an
  # unauthenticated crawl and an unauthenticated crawl that LOOKS
  # authenticated.  An authenticated crawl reaches strictly more of an
  # application than an anonymous one, so the gap is real coverage, not a
  # formality.
  local authed=${SCAN_FLAGS[authed]:-false}
  local session=''
  run_fact_first_set session dast_session_established
  if [[ $authed == true && -z $session ]]; then
    run_record coverage_gap "dast/crawl: --authed was requested for target '$(crawl_safe_text "$target" 80)' but no session was established for this run, so the crawl below is UNAUTHENTICATED - every page, form and parameter that only exists behind a login is missing from this run's inventory and no later check will test it (docs/DESIGN.md §7.0; docs/STEP5-DAST-PLAN.md DAST-03)"
    run_record coverage_reduction "module=dast phase=crawl reason=authenticated_crawl_unavailable target=$(crawl_safe_text "$target" 80)"
  fi

  # -- 5. write the two artifacts -------------------------------------------
  mkdir -p "$rundir/inventory"
  crawl_inv_write_endpoints "$rundir/inventory/endpoints.json"
  crawl_inv_write_parameters "$rundir/inventory/parameters.json"

  local nep=${#_CRAWL_EP[@]} npar=${#_CRAWL_PARAM[@]}
  run_record notes "module=dast phase=crawl target=$(crawl_safe_text "$target" 80) pages=$_CRAWL_PAGES endpoints=$nep parameters=$npar imported=$imported spec_endpoints=$spec_count spec_kinds=[$(crawl_safe_text "${spec_kinds% }" 80)] forms=$_CRAWL_FORMS"

  # -- 6. every bound that bit, on the surface a reader sees -----------------
  # A crawled link or form action, not an inventory row - dropped through the
  # shared counting wrapper `dast_endpoint_keep` (modules/dast/engine.sh
  # section 3b), whose accumulator (`_DAST_SCOPE_SKIPPED`/`_DAST_SCOPE_REASONS`)
  # is what this reads. Deliberately NOT the shared roll-up
  # (`dast_scope_record_skips`) and NOT a coverage_gap: that helper's fixed
  # wording names "the cross-module inventory" (docs/INVENTORY-FORMAT.md),
  # which would misstate where this URL came from - a page the scanner itself
  # fetched chose it, not a producer of endpoints.json. And refusing an
  # out-of-scope host is the tool working, not a hole in what it examined; it
  # is recorded because "we saw N links we were not authorised to follow" is a
  # fact an operator reviewing a scan's blast radius genuinely wants.
  if (( ${_DAST_SCOPE_SKIPPED:-0} > 0 )); then
    run_record notes "module=dast phase=crawl scope_refused_links=$_DAST_SCOPE_SKIPPED target=$(crawl_safe_text "$target" 80) reasons=[$(crawl_safe_text "${_DAST_SCOPE_REASONS:-declined by the scope gate}" 200)] (each was dropped before any request; docs/FOUNDATION.md tension 19)"
  fi
  if (( _CRAWL_PAGECAP > 0 )); then
    run_record coverage_gap "dast/crawl: the crawl stopped at its page ceiling of $_CRAWL_MAX_PAGES for target '$(crawl_safe_text "$target" 80)' with $_CRAWL_PAGECAP more page(s) still queued, so part of this target was never fetched and nothing below tested it"
    run_record coverage_reduction "module=dast phase=crawl reason=page_ceiling_reached target=$(crawl_safe_text "$target" 80) ceiling=$_CRAWL_MAX_PAGES unvisited=$_CRAWL_PAGECAP"
  fi
  if (( _CRAWL_DEPTHCAP > 0 )); then
    run_record coverage_gap "dast/crawl: $_CRAWL_DEPTHCAP link(s) on target '$(crawl_safe_text "$target" 80)' sat deeper than crawl-depth $_CRAWL_D_DEPTH and were never fetched (rules/RULE-FORMAT.md §9.6.3) - raise crawl-depth in config/discovery.conf to reach them"
    run_record coverage_reduction "module=dast phase=crawl reason=crawl_depth_reached target=$(crawl_safe_text "$target" 80) depth=$_CRAWL_D_DEPTH unvisited=$_CRAWL_DEPTHCAP"
  fi
  if (( ${_CRAWL_UNREACHABLE:-0} > 0 )); then
    run_record coverage_gap "dast/crawl: $_CRAWL_UNREACHABLE URL(s) for target '$(crawl_safe_text "$target" 80)' could not be requested - $(crawl_safe_text "${_CRAWL_GATE_REASON:-the scope gate declined them}" 200). When this is the target's own base-url, the static crawl discovered NOTHING and every later check works from whatever the specification and inventory inputs supplied, which may be nothing at all"
    run_record coverage_reduction "module=dast phase=crawl reason=url_not_requestable target=$(crawl_safe_text "$target" 80) count=$_CRAWL_UNREACHABLE"
  fi
  if (( _CRAWL_UNFETCHED > 0 )); then
    run_record coverage_gap "dast/crawl: $_CRAWL_UNFETCHED page(s) of target '$(crawl_safe_text "$target" 80)' returned no response at all, so any endpoint or parameter they would have revealed is missing from this run's inventory"
  fi
  if (( _CRAWL_NONHTML > 0 )); then
    run_record notes "module=dast phase=crawl non_markup_responses=$_CRAWL_NONHTML target=$(crawl_safe_text "$target" 80) (recorded as endpoints, not parsed for links)"
  fi
  if (( ${_CRAWL_EP_TRUNCATED:-0} > 0 || ${_CRAWL_PARAM_TRUNCATED:-0} > 0 )); then
    run_record coverage_gap "dast/crawl: the inventory hit its own ceiling on target '$(crawl_safe_text "$target" 80)' - ${_CRAWL_EP_TRUNCATED:-0} endpoint(s) and ${_CRAWL_PARAM_TRUNCATED:-0} parameter(s) were discovered and DISCARDED (ceilings $_CRAWL_MAX_ENDPOINTS / $_CRAWL_MAX_PARAMS), so they are absent from every later check"
  fi

  # -- 7. the SPA gap, which is this ticket's own acceptance criterion -------
  if [[ -z $spec_kinds ]]; then
    _crawl_record_spa_gap "$target" "$_CRAWL_PAGES" "$nep"
  fi

  if (( nep == 0 )); then
    run_record coverage_gap "dast/crawl: NOTHING was discovered on target '$(crawl_safe_text "$target" 80)' - no page answered, no specification was readable, and no inventory was imported, so every later DAST check has an empty surface to work from and a clean result from any of them means only that there was nothing to test"
  fi
  return 0
}

_crawl_run_phase
