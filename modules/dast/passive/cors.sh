#!/usr/bin/env bash
# modules/dast/passive/cors.sh - the §7.1 CORS origin-reflection PHASE
# (docs/DESIGN.md §7.1 "cors.sh - origin-reflection (`Origin: <sentinel>` ->
# check `Access-Control-Allow-Origin` + credentials)";
# docs/STEP5-DAST-PLAN.md DAST-08, tier 2).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `passive`, so it runs at every intensity), so it
# inherits the whole run context and anything it emits lands in this process's
# shard.  Per that function's contract it carries NO sourced-once guard - one run
# can legitimately reach the same phase twice (a second scope target, a second
# `scan_main` in one process) and a guard would silently make the second one a
# no-op.  The pure half - the header reader, the classifier and the emission -
# is modules/dast/passive/cors_engine.sh, which does have a guard; this file
# resolves the ONE live input the check needs (the endpoint list) and drives it.
#
# HOW THE PASSIVE TIER'S NO-STATE-MUTATION CONTRACT IS KEPT WHILE SENDING A
# REQUEST.  §7.1 says "No mutation of state"; it does not say "no traffic", and
# its own cors.sh bullet defines this check AS a request.  cors_engine.sh's
# header states the six properties in full and the suite asserts each; the two
# this file itself is responsible for are the first and the third:
#   * ONLY GET AND HEAD ENDPOINTS ARE PROBED.  `_cors_candidate_emit` drops
#     every other method, so a POST/PUT/PATCH/DELETE endpoint the crawler
#     inventoried is never requested - not under its own method and not under a
#     substituted one.  A method the inventory does not name is never invented.
#   * ONE REQUEST PER CANDIDATE, AND CANDIDATES ARE DEDUPED AND CAPPED.  Two
#     URLs that share a method and a path template (`/orders/1` and
#     `/orders/2`) are one candidate, because they are one route and therefore
#     one CORS policy; and the candidate list is capped, with the remainder
#     recorded as a coverage bound rather than silently dropped.
#
# WHAT THIS TICKET DELIBERATELY DID NOT BUILD, so the boundary is not
# rediscovered:
#   * An AUTHENTICATED probe pass.  DECIDED, NOT DEFERRED (DAST-08 follow-up,
#     "authenticated CORS probe pass, or a decision that we will not send
#     credentials cross-origin"): scoursh will not attach a session to this
#     probe, ever, and that is permanent rather than a placeholder for a future
#     ticket.  Three reasons, recorded here so a later change does not reopen
#     this without re-deriving them:
#       1. This check runs at tier `passive`, which every `--intensity` level
#          reaches with NO `--i-own-target` gate.  That gate exists precisely so
#          a run that raises risk needs an explicit operator affirmation
#          (docs/FOUNDATION.md tension 16's ceiling-lift).  Sending a live
#          credential on a request that ALSO carries an attacker-shaped `Origin`
#          is exactly that kind of elevated risk - it is the specific request
#          shape a WAF or a fraud stack treats as a credential-riding attack -
#          and nothing in the passive contract asks the operator to accept it.
#       2. `active/sqli.sh` and `jwt.sh`'s authenticated passes are not a valid
#          precedent: neither ever attaches a foreign `Origin` alongside the
#          credential.  A real session plus an attacker-controlled `Origin` in
#          the SAME request is the specific new combination this ticket was
#          asked to decide on, not "an authenticated DAST check" in general.
#       3. The failure mode is not contained to this check.  If the target's
#          WAF/fraud stack reacts by locking the test account, DAST-03's own
#          transparent re-auth (auth_engine.sh) retries once and then marks
#          that identity `failed` for the REST OF THE RUN - so a passive check
#          nobody had to opt into could silently degrade every other
#          authenticated check in the same run (DAST-29 authz, DAST-26 jwt, the
#          authenticated crawl pass, ...) as collateral damage.
#     The resulting gap stays real and stays RECORDED
#     (`_cors_record_unauthenticated_bound` below) rather than silently
#     dropped: a run with `--authed` and an acquired session is told plainly
#     that the CORS probe still went out unauthenticated, so a clean result
#     there is never misread as "the authenticated surface was checked too."
#     See docs/STEP5-DAST-PLAN.md's DAST-08 landing note for the same decision
#     recorded alongside the rest of that ticket's history.
#   * An `OPTIONS` PREFLIGHT probe.  The actual-request response already carries
#     Access-Control-Allow-Origin and -Allow-Credentials, which is what §7.1
#     names; a preflight would double this check's request count for
#     Access-Control-Allow-Methods/-Headers, and HTTP method enumeration is
#     DAST-13 (`active/methods.sh`) at the safe-active tier.
#
# DAST-08 FOLLOW-UP: `Access-Control-Allow-Origin: null` NOW HAS ITS OWN
# CHECK, via a SECOND request per candidate route.  The gap the paragraph
# above used to describe is closed: reflecting the `null` origin is
# separately exploitable from a sandboxed iframe (`<iframe sandbox=
# "allow-scripts" srcdoc=...>`), a `data:` URL document, or several redirect
# shapes, and it was previously invisible because `cors_classify` (correctly)
# buckets a `null` answer to the SENTINEL probe as `allowlisted` - it says
# nothing about how the server answers an ACTUAL `Origin: null` request.
#
#   * ONE ADDITIONAL REQUEST, AND ONLY WHEN IT CAN LEARN SOMETHING NEW.  The
#     second, `Origin: null` probe is sent only when the first probe's verdict
#     was NOT already `reflected` or `wildcard` - a route already shown to
#     trust an arbitrary sentinel origin, or to be openly public, needs no
#     second finding, and paying for a second request there is pure cost.
#     `SCOURSH_DAST_CORS_MAX_ENDPOINTS` still bounds the number of ROUTES (as
#     it always has); what changed is that a route counted against that cap
#     can now cost up to TWO requests instead of one, which is why the
#     truncation coverage_gap below states that explicitly.
#   * TWO CHECK IDS, mirroring the plain/credentialed split
#     `DAST-CORS-ORIGIN_REFLECTED-01`/`-REFLECTED_WITH_CREDENTIALS-01` already
#     use, for the identical reason: `severity` is a fixed, per-check-id
#     registry field (rules/RULE-FORMAT.md §9.5), so a verdict whose severity
#     depends on whether credentials ride along cannot be one id with a
#     runtime-raised base_severity - it has to be two ids, with the
#     credentialed one SUBSUMING the plain one on the same route.  See
#     `_cors_emit_null_origin` below and `cors_engine.sh`'s
#     `cors_null_reflected`.
#
# DAST-08 FOLLOW-UP (audited alongside leakage.sh, per lib/http.sh §12's
# `_HTTP_LAST_URL`): the finding's `url`/path fields are read off
# `cors_probe`'s own `_CORS_LAST_URL` - the DELIVERED response's canonical
# url - rather than the raw inventory literal.  Unlike markup.sh and
# leakage.sh, this check can never actually OBSERVE a cross-origin delivery:
# `cors_probe` sends with `max_redirects` 0 (passive property 5), so a 3xx
# response is always returned as-is and `_CORS_LAST_URL` is always the
# requested URL's own canonical form, same origin, every time.  See
# cors_engine.sh's `cors_probe` for the full argument for switching anyway -
# in short, it is the correct source even where it happens to equal the
# literal today, and it stops being a silent trap if `max_redirects` here is
# ever raised.
#
# shellcheck shell=bash
# shellcheck source=modules/dast/passive/cors_engine.sh
source "${BASH_SOURCE[0]%/*}/cors_engine.sh"
# crawl_engine.sh for the frozen endpoints.json reader (crawl_json_flatten,
# docs/INVENTORY-FORMAT.md).  It carries a sourced-once guard and has no side
# effect at source time, so on a real run - where crawl.sh has already run and
# sourced it - this is a no-op, and standalone it is what lets
# tests/suites/dast-cors.sh drive this phase without scan.sh.  Reusing that one
# reader rather than writing a second parser is what keeps producer and consumer
# from drifting apart on the inventory schema.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of).  A URL with no
# path is `/`.
_cors_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `_cors_candidates TARGET FILE` - print `METHOD<TAB>URL` for every endpoint in
# the inventory FILE that belongs to TARGET and uses an idempotent method.
#
# It reads through crawl_engine.sh's `crawl_json_flatten` - the same frozen JSON
# reader every inventory producer and consumer shares - whose output is
# `path<TAB>type<TAB>value` with path segments separated by US (\x1f), so an
# endpoint's fields arrive as `endpoints<US><idx><US><field>`, exactly as
# `crawl_inv_merge_endpoints` reads them.
_cors_candidates() {
  local target=$1 file=$2
  [[ -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p type v rest idx key last_idx='' m='' u='' t=''
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _cors_candidate_emit "$target" "$m" "$u" "$t"
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
  [[ -n $last_idx ]] && _cors_candidate_emit "$target" "$m" "$u" "$t"
  return 0
}

# Emit one `METHOD<TAB>URL` line if the endpoint is for TARGET and idempotent.
#
# THE METHOD FILTER IS THE PASSIVE CONTRACT MADE CONCRETE, not an efficiency
# measure.  GET and HEAD are the two methods RFC 7231 §4.2.1 defines as both
# safe and idempotent; every other method the crawler may have inventoried is
# dropped here and never requested.  A check that "downgraded" a POST endpoint
# to a GET to read its headers would be requesting a resource under a method the
# application never advertised for it, which is content discovery (DAST-12) at
# the safe-active tier, not a passive read.
_cors_candidate_emit() {
  local target=$1 m=${2:-GET} u=$3 t=$4
  [[ -n $u ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  case ${m^^} in
    GET | HEAD) ;;
    *) return 0 ;;
  esac
  printf '%s\t%s\n' "${m^^}" "$u"
  return 0
}

# `_cors_record_unauthenticated_bound TARGET` - the stated bound for a run that
# asked for authentication and did get it.  Recorded ONLY in that case: on a run
# with no `--authed` the reader already knows nothing was authenticated, and
# printing this on every passive run would bury the records that are about a
# real reduction.
_cors_record_unauthenticated_bound() {
  local target=$1
  [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] || return 0
  declare -F dast_auth_authenticated_labels_set >/dev/null || return 0
  dast_auth_authenticated_labels_set "$target"
  (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )) || return 0
  run_record coverage_reduction "module=dast reason=cors_probe_is_unauthenticated check=cors target=$target - this run holds an authenticated session, but the CORS probe was sent WITHOUT it. An application that sets Access-Control-Allow-Origin only on its authenticated API surface would answer this probe with no CORS header at all, so a clean CORS result for such a target is not evidence its authenticated responses are safe."
  return 0
}

_dast_cors_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  local endpoints_file=${SCOURSH_DAST_ENDPOINTS:-}
  local line method url path key
  local -a candidates=()
  local -A seen=()

  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/passive/cors.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # tension-15 per-check selection.  scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; `dast_check_selected` is the DAST-side reader of it.
  # Consulted only if that function exists, exactly as
  # modules/dast/active/sqli.sh already guards it - it is NOT defined anywhere in
  # this repository today, which is a real gap this ticket found and filed rather
  # than closed inside a check (see the ticket comment). Absent, everything the
  # tier already permitted runs, which is the same "empty means all selected"
  # fallback a direct-engine test relies on.
  local do_reflect=1 do_wildcard=1 do_null=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-CORS-ORIGIN_REFLECTED-01 || do_reflect=0
    dast_check_selected DAST-CORS-WILDCARD-01 || do_wildcard=0
    # Gating on the PLAIN null-origin id alone, exactly as do_reflect gates
    # both DAST-CORS-ORIGIN_REFLECTED-01 and its credentialed sibling: the two
    # null ids come from the same second probe, so there is no daylight
    # between "the plain id is selected" and "the second probe should run".
    dast_check_selected DAST-CORS-NULL_ORIGIN-01 || do_null=0
  fi
  if (( do_reflect == 0 && do_wildcard == 0 && do_null == 0 )); then
    run_record coverage_reduction "module=dast reason=all_cors_checks_deselected check=cors target=$target - every CORS check id was removed by the check-selection filters, so no Origin probe was sent."
    return 0
  fi

  # THE ONE LIVE INPUT.  Absent is a recorded gap, never an error and never a
  # silent pass: there is deliberately no config key naming a "cors probe path",
  # both because the record format is frozen and because a path that varies per
  # application belongs in the inventory the crawler already builds, not in a
  # second place that could drift from it.
  while IFS= read -r line; do
    [[ -n $line ]] && candidates+=("$line")
  done < <(_cors_candidates "$target" "$endpoints_file")

  if (( ${#candidates[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=no_endpoint_inventory check=cors target=$target - the endpoint inventory (${endpoints_file:-none}, docs/INVENTORY-FORMAT.md) named no idempotent (GET/HEAD) endpoint for this target, so the CORS check had nowhere to send an Origin probe."
    run_record coverage_gap "dast cors: target '$target' has no known idempotent endpoint (docs/INVENTORY-FORMAT.md endpoints.json was ${endpoints_file:-absent}), so no 'Origin:' probe was sent and its cross-origin resource-sharing policy was not tested. A clean result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  # DEDUPE BY (METHOD, PATH TEMPLATE), NOT BY URL.  A CORS policy is a property
  # of a route, so `/orders/1` and `/orders/2` are one thing to test; probing
  # both would send a second request for an answer already held AND, because the
  # finding location profile templates the path, would produce two findings that
  # dedupe to one anyway - paying for traffic to learn nothing. The cap that
  # follows then bounds a genuinely wide surface.
  #
  # THIS CAP BOUNDS ROUTES, NOT REQUESTS, AND THAT DISTINCTION NOW MATTERS.
  # Since the DAST-08 follow-up (the null-origin probe below), a single capped
  # route can cost up to TWO requests: the original sentinel probe, plus a
  # second `Origin: null` probe when the sentinel verdict was neither
  # `reflected` nor `wildcard`.  $max still limits the ROUTE count exactly as
  # before; it is the per-route request cost that doubled, which is why the
  # truncation coverage_gap below states the up-to-two-requests-per-route cost
  # explicitly rather than leaving a reader to assume 1:1.
  local max=${SCOURSH_DAST_CORS_MAX_ENDPOINTS:-25}
  [[ $max =~ ^[0-9]+$ ]] || max=25
  (( max < 1 )) && max=1
  local -a probe=()
  local truncated=0
  # THE SCOPE PRE-CHECK IS NOT THE GATE, AND BOTH ARE REQUIRED - modules/dast/
  # engine.sh section 3b carries the long form. `http_request` gates FATALLY,
  # which is right for an operator-configured URL and exactly wrong for one
  # lifted out of an inventory another module wrote, where one bad row aborts
  # the whole run at exit 3. It is applied HERE, before the dedupe and the cap,
  # so an out-of-scope row cannot spend a slot of a bounded route budget that an
  # in-scope route would otherwise have had. Everything that survives still goes
  # through `http_request`, which re-gates it and every redirect hop.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi
  for line in "${candidates[@]+"${candidates[@]}"}"; do
    method=${line%%$'\t'*}
    url=${line#*$'\t'}
    if declare -F dast_endpoint_keep >/dev/null; then
      dast_endpoint_keep "$url" "$target" || continue
    fi
    path=$(_cors_path_of "$url")
    key="$method $(path_template_of "$path")"
    [[ -n ${seen[$key]+set} ]] && continue
    seen[$key]=1
    if (( ${#probe[@]} >= max )); then
      truncated=$(( truncated + 1 ))
      continue
    fi
    probe+=("$line")
  done

  if declare -F dast_scope_record_skips >/dev/null; then
    dast_scope_record_skips cors "$target"
  fi

  _cors_record_unauthenticated_bound "$target"

  local tested=0 failed=0 reflected=0 credentialed=0 wildcard=0
  local null_tested=0 null_failed=0 null_reflected=0 null_credentialed=0 null_skipped=0
  for line in "${probe[@]+"${probe[@]}"}"; do
    method=${line%%$'\t'*}
    url=${line#*$'\t'}
    if ! cors_probe "$target" "$method" "$url" "$CORS_SENTINEL_ORIGIN"; then
      # A TRANSPORT FAILURE IS NOT "NO CORS HEADER".  Counting it as tested
      # would let a breaker-opened run report a target clean for endpoints it
      # never reached, which is the exact overstated coverage docs/DESIGN.md §15
      # forbids.
      failed=$(( failed + 1 ))
      continue
    fi
    tested=$(( tested + 1 ))
    # THE DELIVERED URL, NOT THE ONE THIS PHASE ASKED FOR - `cors_probe`'s own
    # `_CORS_LAST_URL` (cors_engine.sh, itself lib/http.sh's `_HTTP_LAST_URL`).
    # This probe always sends with `max_redirects` 0, so in practice this is
    # always the requested URL's own canonical form (same origin, default port
    # filled in) rather than a genuinely different origin - see cors_engine.sh's
    # own note on `cors_probe` for why that is structurally guaranteed here and
    # is NOT true of markup.sh/leakage.sh, which do follow redirects.  Using it
    # for the finding's location is still correct rather than merely harmless:
    # it is the URL that actually delivered this response.
    local delivered_url=${_CORS_LAST_URL:-$url}
    path=$(_cors_path_of "$delivered_url")
    cors_classify "$_CORS_ACAO_PRESENT" "$_CORS_ACAO" "$CORS_SENTINEL_ORIGIN"
    case $_CORS_POLICY in
      reflected)
        if (( do_reflect )); then
          if cors_credentials_true "$_CORS_ACAC"; then
            credentialed=$(( credentialed + 1 ))
          else
            reflected=$(( reflected + 1 ))
          fi
          _cors_emit_reflection "$target" "$method" "$delivered_url" "$path"
        fi
        ;;
      wildcard)
        if (( do_wildcard )); then
          wildcard=$(( wildcard + 1 ))
          _cors_emit_wildcard "$target" "$method" "$delivered_url" "$path"
        fi
        ;;
    esac

    # THE SECOND, `Origin: null` PROBE (DAST-08 follow-up).  Sent only when
    # do_null is selected AND the sentinel verdict just observed was NEITHER
    # `reflected` NOR `wildcard` - a route that already trusts an arbitrary
    # sentinel origin, or is openly public, needs no second finding, so a
    # route in either state is counted as a deliberate SKIP rather than
    # probed again.  This is evaluated regardless of do_reflect/do_wildcard's
    # own selection state (a deselected reflection CHECK does not mean the
    # route stopped reflecting), which is why the case above no longer
    # `continue`s out of the loop on a deselected verdict.
    if (( do_null )); then
      if [[ $_CORS_POLICY == reflected || $_CORS_POLICY == wildcard ]]; then
        null_skipped=$(( null_skipped + 1 ))
      elif ! cors_probe "$target" "$method" "$url" null; then
        null_failed=$(( null_failed + 1 ))
      else
        null_tested=$(( null_tested + 1 ))
        # A fresh capture of the SECOND probe's own delivered url, not a reuse
        # of the sentinel probe's - the two are separate `http_request` calls
        # (both against the identical `$url` with `max_redirects` 0, so in
        # practice this equals the first probe's `$delivered_url` too, but
        # reading it off THIS probe's own `_CORS_LAST_URL` is what stays
        # correct if that ever stops being true).
        local null_delivered_url=${_CORS_LAST_URL:-$url}
        if cors_null_reflected "$_CORS_ACAO_PRESENT" "$_CORS_ACAO"; then
          if cors_credentials_true "$_CORS_ACAC"; then
            null_credentialed=$(( null_credentialed + 1 ))
          else
            null_reflected=$(( null_reflected + 1 ))
          fi
          _cors_emit_null_origin "$target" "$method" "$null_delivered_url" "$(_cors_path_of "$null_delivered_url")"
        fi
      fi
    fi
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up reads.
  # Recorded only when at least one probe actually got a response, so a run whose
  # every request failed is not reported as having covered anything.
  #
  # ALL THREE IDS ARE RECORDED WHENEVER THE PROBE RAN, INCLUDING THE ONES THAT
  # PRODUCED NO FINDING.  That is what `checks_run` means here: a probe that came
  # back with no Access-Control-Allow-Origin header has genuinely TESTED for
  # reflection, for the credentialed case and for the wildcard - all three
  # verdicts come from the one response - and reporting only the ids that
  # happened to fire would make coverage a function of the result, so a clean
  # target would look like an unscanned one.
  if (( tested > 0 )); then
    if (( do_reflect )); then
      run_record checks_run DAST-CORS-ORIGIN_REFLECTED-01
      run_record checks_run DAST-CORS-REFLECTED_WITH_CREDENTIALS-01
    fi
    (( do_wildcard )) && run_record checks_run DAST-CORS-WILDCARD-01
  fi
  # Recorded from null_tested, not from tested: `checks_run` means "loaded AND
  # EXECUTED" (AGENTS.md), and the second probe genuinely does not execute at
  # all on a run where every route already came back reflected or wildcard -
  # reporting coverage there would claim a probe that was never sent.
  if (( null_tested > 0 && do_null )); then
    run_record checks_run DAST-CORS-NULL_ORIGIN-01
    run_record checks_run DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01
  fi

  if (( truncated > 0 )); then
    run_record coverage_gap "dast cors: the idempotent endpoint surface on target '$target' exceeded this check's per-run cap of $max distinct routes, so $truncated route(s) were not probed for origin reflection (each covered route may cost up to two requests - the sentinel probe and, where applicable, a second Origin: null probe). Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( failed > 0 )); then
    run_record coverage_reduction "module=dast reason=cors_probe_transport_failed check=cors target=$target count=$failed - $failed CORS probe(s) never received a response (the circuit breaker, the per-run request budget or name resolution stopped them), so those routes were not tested either way."
  fi
  if (( null_failed > 0 )); then
    run_record coverage_reduction "module=dast reason=cors_null_probe_transport_failed check=cors target=$target count=$null_failed - $null_failed second, Origin: null CORS probe(s) never received a response, so whether those routes trust the null origin was not tested either way."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast cors: none of the ${#probe[@]} candidate route(s) on target '$target' returned a response, so no cross-origin policy was observed. Nothing was tested; this is not a finding of safety."
  fi

  log_info "dast cors: target '$target' - probed $tested of ${#probe[@]} route(s) (reflection=$reflected reflection+credentials=$credentialed wildcard=$wildcard, ${failed} unreachable; null-origin probe: tested=$null_tested reflected=$null_reflected reflected+credentials=$null_credentialed skipped=$null_skipped unreachable=$null_failed)"
  return 0
}

# `_cors_emit_reflection` - the origin-reflection verdict, split by whether
# credentials are allowed alongside it.
#
# THESE ARE TWO CHECK IDS AND EXACTLY ONE OF THEM FIRES.  Reflection alone lets
# any origin read the response as an ANONYMOUS client; reflection plus
# `Access-Control-Allow-Credentials: true` lets any origin read it as the VICTIM,
# with their cookies attached - a different bug class in impact if not in cause,
# and DAST-08's own ticket asks for the credentials case to be "weighted
# accordingly".  Emitting both for one endpoint would report one root cause
# twice and make the count of CORS problems meaningless, so the credentialed
# finding SUBSUMES the plain one, the same discipline jwt_engine.sh applies when
# SIG_NOT_VERIFIED subsumes its per-variant probes.
_cors_emit_reflection() {
  local target=$1 method=$2 url=$3 path=$4
  # No backticks in this sentence: it is single-quoted evidence prose, and a
  # backtick run inside single quotes trips SC2016 for a command substitution
  # that is not there.  The plain header name reads the same to an operator.
  local vary_note=' The response also carried no Vary: Origin header, so a shared cache may store the response minted for one origin and serve it to another.'
  (( _CORS_VARY_ORIGIN )) && vary_note=''

  if cors_credentials_true "$_CORS_ACAC"; then
    cors_emit_finding \
      DAST-CORS-REFLECTED_WITH_CREDENTIALS-01 \
      'CORS origin reflection with credentials allowed' \
      high high CWE-346 \
      "$target" "$method" "$url" "$path" \
      "$method $path echoed the probe's own Origin header back verbatim in Access-Control-Allow-Origin and answered Access-Control-Allow-Credentials: $_CORS_ACAC (HTTP $_CORS_STATUS). Any web page on any origin can therefore make a credentialed cross-origin request to this route with the victim's cookies attached and READ the response, because the server trusts whatever origin asks.$vary_note" \
      "$(cors_remediation_reflection)" \
      true
    return 0
  fi

  cors_emit_finding \
    DAST-CORS-ORIGIN_REFLECTED-01 \
    'CORS origin reflection (arbitrary origin trusted)' \
    medium high CWE-346 \
    "$target" "$method" "$url" "$path" \
    "$method $path echoed the probe's own Origin header back verbatim in Access-Control-Allow-Origin (HTTP $_CORS_STATUS), so the server performs no origin validation - it trusts whichever origin asks. Access-Control-Allow-Credentials was ${_CORS_ACAC:-not set}, so a cross-origin read is anonymous today; turning credentials on, or any change that starts serving user-specific data from this route, converts this into a full cross-origin read of authenticated responses.$vary_note" \
    "$(cors_remediation_reflection)" \
    false
  return 0
}

# `_cors_emit_null_origin` - the verdict from the SECOND probe (`Origin: null`,
# DAST-08 follow-up), split by credentials the identical way
# `_cors_emit_reflection` splits the sentinel-reflection verdict, and for the
# identical reason: `severity` is fixed per check id in the registry, so the
# credentialed case is a SEPARATE id that SUBSUMES the plain one on one route,
# never a plain id with a severity raised at runtime.
_cors_emit_null_origin() {
  local target=$1 method=$2 url=$3 path=$4
  local vary_note=' The response also carried no Vary: Origin header, so a shared cache may store the response minted for one origin and serve it to another.'
  (( _CORS_VARY_ORIGIN )) && vary_note=''

  if cors_credentials_true "$_CORS_ACAC"; then
    cors_emit_finding \
      DAST-CORS-NULL_ORIGIN_WITH_CREDENTIALS-01 \
      'CORS null-origin trust with credentials allowed' \
      high high CWE-346 \
      "$target" "$method" "$url" "$path" \
      "$method $path answered Access-Control-Allow-Origin: null to a request that carried Origin: null, and Access-Control-Allow-Credentials: $_CORS_ACAC (HTTP $_CORS_STATUS). The null origin is what a browser sends for a sandboxed iframe (<iframe sandbox=\"allow-scripts\" srcdoc=...>), a data: URL document, and several redirect shapes - all contexts an attacker fully controls - so a page that gets a victim into one of those can make a credentialed cross-origin request to this route and READ the response with the victim's cookies attached.$vary_note" \
      "$(cors_remediation_null)" \
      true
    return 0
  fi

  cors_emit_finding \
    DAST-CORS-NULL_ORIGIN-01 \
    'CORS null-origin trust (arbitrary attacker-controlled context accepted)' \
    medium high CWE-346 \
    "$target" "$method" "$url" "$path" \
    "$method $path answered Access-Control-Allow-Origin: null to a request that carried Origin: null (HTTP $_CORS_STATUS), so the server trusts the null origin - a value every browser sends for a sandboxed iframe, a data: URL document, and several redirect shapes, all of which an attacker can put a victim into. Access-Control-Allow-Credentials was ${_CORS_ACAC:-not set}, so a cross-origin read from one of those contexts is anonymous today; turning credentials on, or any change that starts serving user-specific data from this route, converts this into a full cross-origin read of authenticated responses.$vary_note" \
    "$(cors_remediation_null)" \
    false
  return 0
}

# `_cors_emit_wildcard` - the literal `*` verdict, which is deliberately NOT the
# reflection finding.  See cors_engine.sh's `cors_classify` for the full
# argument; the short form is that `*` is a statement that a resource is public
# and a browser will refuse to combine it with credentials, whereas reflection
# is a failure to validate that composes with cookies.  Same family, different
# severity, different remediation - so, different check id.
_cors_emit_wildcard() {
  local target=$1 method=$2 url=$3 path=$4
  local cred_note=''
  if cors_credentials_true "$_CORS_ACAC"; then
    # Worth stating and NOT worth a higher severity: the Fetch standard makes a
    # browser reject `*` together with credentials outright, so this combination
    # is a broken configuration rather than an exploitable one - and the fact
    # that someone INTENDED credentialed cross-origin access here is exactly
    # what makes the eventual fix likely to be a reflection bug.
    cred_note=' The response also set Access-Control-Allow-Credentials: '"$_CORS_ACAC"', which a browser refuses to honour alongside a wildcard - so credentialed cross-origin reads fail today, and whoever configured this intended cross-origin access that does not currently work. Fixing it by echoing the request Origin instead would create an origin-reflection vulnerability.'
  fi

  cors_emit_finding \
    DAST-CORS-WILDCARD-01 \
    'CORS wildcard: Access-Control-Allow-Origin is *' \
    low high CWE-942 \
    "$target" "$method" "$url" "$path" \
    "$method $path answered Access-Control-Allow-Origin: * (HTTP $_CORS_STATUS), so script running on any origin may read this response. This is a wildcard policy, NOT origin reflection - the server returned a literal asterisk rather than echoing the probe's Origin - and it is correct only if this route is deliberately public and carries no user-specific data.$cred_note" \
    "$(cors_remediation_wildcard)" \
    false
  return 0
}

_dast_cors_phase
