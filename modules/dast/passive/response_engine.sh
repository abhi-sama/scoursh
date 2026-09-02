#!/usr/bin/env bash
# modules/dast/passive/response_engine.sh - the HTTP response reader every DAST
# check that looks at a response head shares.  Lifted out of
# modules/dast/passive/headers_engine.sh, which asked for exactly this once it
# had a second consumer.
#
# ADR: the shared response reader is its own LEAF module, and keeps the `hdr_`
#      prefix.
# Context: `hdr_parse_capture` and friends were written for DAST-05 and lived in
#      `passive/headers_engine.sh`.  Six landed files now need them -
#      `passive/headers.sh`, `passive/leakage_engine.sh`,
#      `passive/transport_engine.sh`, `active/crlf.sh`,
#      `active/hosthdr_engine.sh` and `ratelimit_engine.sh` - so five of them
#      sourced a file named for, and owned by, one ticket, and four dragged in
#      that ticket's CSP/HSTS/Referrer parsers, its recommended-header loader,
#      its endpoint chooser, `lib/http.sh` and `crawl_engine.sh` merely to read
#      a header block.  `shellcheck -x` re-expands every source edge it follows
#      (docs/CI-RUNBOOK.md, "the memory model"), so that subtree was paid for
#      once per consumer.
# Decision: this file holds the reader ONLY and sources NOTHING - it is a leaf
#      in the static source graph, pure bash, with no side effect at source
#      time.  `headers_engine.sh` sources it and keeps its own parsers and
#      endpoint chooser; the four reader-only consumers source this file
#      instead of it.  Function and global names are UNCHANGED, so no call site
#      moves.
# Alternatives considered: leave the reader in `headers_engine.sh` and keep
#      sourcing it - rejected, the false ownership and the duplicated subtree
#      both grow with every new consumer.  Rename `hdr_*` to `resp_*` -
#      rejected, the published contract is not only these eight functions but
#      the globals `_HDR_STATUS`/`_HDR_NAMES`/`_HDR_VALUE`/`_HDR_COUNT`/`_HDR_V`
#      that consumers read directly, so a function-only rename leaves the
#      contract half-renamed, and a full one doubles the blast radius across
#      eleven landed files, buys no behaviour, and turns `git blame` on every
#      one of them into a redirect.
# Consequences: a check that only reads a response head now costs one small,
#      dependency-free file instead of the whole DAST-05 subtree, and any future
#      response-level helper has an obvious, unowned home.  The cost is that
#      `hdr_` no longer names the file it lives in - which is why this block
#      says so, and why `headers_engine.sh` points here.
#
# ADR: the endpoint CHOOSER is lifted too, once a second real copy existed -
#      but as a caller-fed function, not by sourcing its dependencies.
# Context: this file's own note directly above used to reject moving
#      `hdr_endpoints_load` here, on exactly one caller existing.  That
#      changed: `modules/dast/passive/markup_engine.sh` (DAST-11) shipped a
#      byte-identical second copy (`markup_endpoints_load`, differing only in
#      variable prefix), stated the duplication in its own header rather than
#      hiding it, and filed the ticket that landed this block.  Two real copies
#      of "GET endpoints out of the frozen inventory, base-url first, deduped
#      by path template, sorted, capped" is what tension-generalization is for
#      (AGENTS.md: "generalize only when there are two real concrete cases,
#      never one and a hypothesis") - and by the time this landed,
#      `passive/leakage_engine.sh` (`leak_endpoints_load`) had shipped a THIRD
#      byte-identical copy and `passive/transport_engine.sh`
#      (`tr_endpoints_load`) a fourth, near-identical one (its own dedup key is
#      `(scheme, path template)`, for a stated reason specific to mixed-content
#      detection).  Those two are OUT OF SCOPE for this change - the ticket
#      that landed this block named only headers_engine.sh and
#      markup_engine.sh - and are left as a follow-up rather than folded in
#      silently under a ticket that did not ask for them.
# Decision: `resp_endpoints_load EPF TARGET BASE MAX_ENDPOINTS` lives here and
#      calls `crawl_json_flatten`/`crawl_json_unescape` (crawl_engine.sh) and
#      `path_template_of` (lib/findings.sh) BY NAME, without this file sourcing
#      either.  That is deliberately not the same move the rejected note above
#      describes: sourcing crawl_engine.sh here would reattach the exact
#      subtree the reader lift removed to every one of the FIVE reader-only
#      consumers (`passive/leakage_engine.sh`, `passive/transport_engine.sh`,
#      `active/crlf.sh`, `active/hosthdr_engine.sh`, `ratelimit_engine.sh`),
#      which is the `shellcheck -x` cost this file exists to avoid
#      (docs/CI-RUNBOOK.md, "the memory model").  Calling an unsourced function
#      by name adds no source edge and costs `shellcheck -x` nothing; it only
#      requires that a CALLER of `resp_endpoints_load` has already sourced
#      `crawl_engine.sh` and `lib/http.sh` (which pulls in `lib/findings.sh`)
#      itself - true of every real caller (`headers_engine.sh`,
#      `markup_engine.sh`), and the same "pure library, caller supplies
#      context" shape `crawl_engine.sh` itself already uses for `die`/`log_warn`.
#      `hdr_endpoints_load` and `markup_endpoints_load` themselves are kept as
#      thin wrappers in their own files, forwarding to `resp_endpoints_load`
#      and copying its `_RESP_*` outputs into their historic `_HDR_*`/
#      `_MARKUP_*` globals - so no call site in `headers.sh`, `markup.sh`, or
#      `ratelimit_engine.sh` (a fifth, indirect consumer of
#      `hdr_endpoints_load` via `headers_engine.sh`) moves, and this refactor
#      changes no external behaviour.
# Alternatives considered: source `crawl_engine.sh` from this file so
#      `resp_endpoints_load` is fully self-contained - rejected for the
#      `shellcheck -x` cost described above.  Fold
#      `modules/dast/active/inject_engine.sh`'s
#      `inject_inventory_load` (the THIRD shape `passive/cookies.sh` uses) into
#      this same function - rejected, it is not a clean fit: it joins
#      parameters to endpoints by `endpoint_id` for injection probes, applies
#      `dast_endpoint_keep`'s scope pre-check at load time, has no path-template
#      dedup or cap, and is keyed by endpoint id rather than a sorted list.
#      Generalizing one function to cover both shapes would need a parameter
#      for nearly every line of it, which is the "two hypotheses, not two
#      cases" trap AGENTS.md warns against; `cookies.sh` keeps using
#      `inject_inventory_load` unchanged.
# Consequences: one place decides "which GET endpoints does a passive check
#      request", so a future dedup/cap/ordering bug is fixed once instead of
#      four times.  The cost is that `resp_endpoints_load`, unlike every other
#      function in this file, is not safely callable after sourcing this file
#      alone - `tests/suites/dast-response-engine.sh` states that boundary
#      explicitly rather than leaving it to be discovered by a `command not
#      found`.
#
# ADR: the two remaining copies fold in too - one because it turned out to be a
#      third identical case, the other by parameterising the one axis its own
#      header always said was different.
# Context: the ADR above landed `resp_endpoints_load` for `headers_engine.sh`
#      and `markup_engine.sh` only, and named `passive/leakage_engine.sh`
#      (`leak_endpoints_load`) and `passive/transport_engine.sh`
#      (`tr_endpoints_load`) as real but OUT OF SCOPE, left for a ticket that
#      asked for them rather than folded in silently.  `docs/STEP5-DAST-PLAN.md`
#      (its DAST-05 and DAST-11 landing notes), `docs/FOUNDATION.md` (its
#      DAST-11 paragraph) and `AGENTS.md` (the shared-response-reader bullet)
#      each said so and each is corrected in the same change that lands this
#      block.  Direct comparison confirmed `leak_endpoints_load` byte-identical
#      to `hdr_endpoints_load` bar its own `_LEAK_MAX_ENDPOINTS` cap - a THIRD
#      real case, not a hypothesis.  `tr_endpoints_load` differs in exactly the
#      one place its own header always said it did and nowhere else: the dedup
#      key is `(scheme, path template)`, because the plaintext and HTTPS twin
#      of one path are the SAME candidate to every other caller and are the
#      finding itself to this one.
# Decision: `leak_endpoints_load` becomes a thin wrapper over
#      `resp_endpoints_load`, identically to `hdr_endpoints_load` and
#      `markup_endpoints_load` - it needed no new parameter, since its dedup
#      key was already the default one.  `resp_endpoints_load` gains exactly
#      one new, optional parameter, `DEDUP_KEY` (`template` by default,
#      `scheme_template` the only other value), and `tr_endpoints_load`
#      becomes a thin wrapper passing `scheme_template` - the one line that
#      ever differed.  `tr_url_scheme` (the scheme extractor
#      `scheme_template` needs) moves here as `resp_url_scheme`, for the same
#      reason `hdr_path_of` already lives here rather than in every caller: it
#      is pure, dependency-free, and the dedup mode needs it by name.
#      `tr_url_scheme` stays in `transport_engine.sh` as a one-line wrapper, so
#      `tr_url_origin` and the mixed-content scanner - which use it for
#      reasons that have nothing to do with the chooser - do not change.
# Alternatives considered: leave `tr_endpoints_load` and `leak_endpoints_load`
#      as recorded, cross-linked duplicates (this ticket's own second honest
#      outcome) - rejected, because the dedup key is the ONLY axis that varies
#      across all four callers, so a one-parameter fork costs less to keep
#      correct than four function bodies kept in step by hand and a header
#      comment asking nicely.  Pass a whole dedup FUNCTION by name instead of a
#      mode string - rejected as speculative generalisation: exactly two keys
#      exist today, not an open set, and a mode string matches how this
#      function's other per-caller knob (`MAX_ENDPOINTS`) already works.
# Consequences: a dedup-key bug is fixed once for four callers instead of once
#      for the `template` family and once more for `transport_engine.sh`, and
#      `tests/suites/dast-response-engine.sh` section G is the one place that
#      pins both keys against each other.  The cost is a parameter whose only
#      real second value exists to serve one caller - accepted, since the
#      alternative was a second, near-identical function to keep in step by
#      hand.
#
# THE LOAD-BEARING PROPERTY IN THIS FILE IS `hdr_parse_capture`'S RESET.
# `http_request_capture`'s header sink ACCUMULATES every redirect hop
# (lib/http.sh section 9a), so a capture file for a request that redirected
# holds two or more header blocks, and a whole-file match reads the REDIRECT's
# header and reports it as the delivered response's - backwards for every header
# whose absence on the final response is the finding.  The parse resets on every
# `HTTP/x.y NNN` status line for that reason.  It is pinned three times, each
# failing under a different shape of the mistake: at the unit level in
# tests/suites/dast-response-engine.sh, and end to end in
# tests/suites/dast-headers.sh and tests/suites/dast-leakage.sh.
#
# THIS FILE DOES NOT TALK TO THE NETWORK AND CANNOT.  It sources no transport
# and defines no request function; every request a DAST phase sends goes through
# `http_request` (lib/http.sh) - docs/FOUNDATION.md tension 19's single
# chokepoint, where the scope gate, the rate limiter, the per-run request budget,
# the circuit breaker and DAST-32's ceilings all sit.  This file parses what came
# back; a phase script is what asks.
#
# NEVER A BARE `grep` (tension 4).  Nothing here shells out to a match engine at
# all: a response-header block is line-structured and small, so it is read with
# bash's own `read`, which cannot confuse "no match" with "the engine failed" -
# the failure mode that rule exists to prevent.
#
# EVERYTHING PARSED HERE IS UNTRUSTED TARGET OUTPUT (tension 10).  A header value
# is attacker-controlled text; it reaches a report only through
# `finding_set_evidence`, and `hdr_safe_text` bounds it first so one absurd
# 40 KiB CSP cannot become the report.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_RESPONSE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_RESPONSE_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 0. Bounds
# ---------------------------------------------------------------------------
# Bytes of any one header value carried into evidence.  It travels WITH
# `hdr_safe_text` rather than staying behind in headers_engine.sh: that function
# reads it as a parameter default, so a consumer sourcing this file alone would
# otherwise hit an unbound variable under `set -u` - the shape a lift most
# easily leaves behind, because the owning file's own tests never notice.
: "${_HDR_MAX_EVIDENCE_FIELD:=200}"

# `hdr_safe_text TEXT [MAX]` - bounded, single-line target-derived text for a
# diagnostic or an evidence sentence.  `finding_set_evidence` still does the
# real escaping and redaction (tension 9/10); this only stops one pathological
# header from dominating the sentence it appears in.
hdr_safe_text() {
  local s=$1 max=${2:-$_HDR_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# 1. The response-header reader
# ---------------------------------------------------------------------------
# `hdr_parse_capture FILE` - reads a lib/http.sh header capture and publishes the
# FINAL hop's response headers:
#
#   _HDR_STATUS              the final status line's code, '' when there is none
#   _HDR_NAMES               the field names seen, lowercased, in arrival order
#   _HDR_VALUE[name]         the value; several same-named headers join with LF
#   _HDR_COUNT[name]         how many times the field appeared
#
# Returns 1 (leaving everything empty) when the file is unreadable or carries no
# status line, so a caller can tell "no response" from "a response with no
# headers" - a distinction the whole honesty story here rests on.
#
# ONLY THE FINAL HOP COUNTS, AND THAT IS THE WHOLE REASON THIS IS NOT A GREP -
# see this file's header block for the measurement and for where it is pinned.
#
# `declare -g`, never bare: in a real run this file is sourced from inside
# `dast_run_phase`, so an undecorated `declare` would create a local that dies
# with the phase (modules/dast/engine.sh's phase table documents this at length).
hdr_parse_capture() {
  local f=$1 line name value lower
  declare -gA _HDR_VALUE=() _HDR_COUNT=()
  declare -ga _HDR_NAMES=()
  declare -g _HDR_STATUS=''
  [[ -n $f && -r $f && -s $f ]] || return 1

  local seen_status=0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
      # A new hop: everything read so far belonged to a response that is not
      # the one the caller received.
      _HDR_STATUS=${BASH_REMATCH[1]}
      _HDR_VALUE=() _HDR_COUNT=() _HDR_NAMES=()
      seen_status=1
      continue
    fi
    (( seen_status )) || continue
    [[ $line == *:* ]] || continue
    name=${line%%:*}
    # A field name is an RFC 7230 token.  Anything else on a header line is not
    # a header - a folded continuation, or garbage - and is dropped rather than
    # guessed at.
    [[ $name =~ ^[A-Za-z0-9!#\$%\&\'*+.^_\`|~-]+$ ]] || continue
    value=${line#*:}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    lower=${name,,}
    if [[ -n ${_HDR_COUNT[$lower]:-} ]]; then
      _HDR_VALUE[$lower]="${_HDR_VALUE[$lower]}"$'\n'"$value"
      _HDR_COUNT[$lower]=$(( _HDR_COUNT[$lower] + 1 ))
    else
      _HDR_VALUE[$lower]=$value
      _HDR_COUNT[$lower]=1
      _HDR_NAMES+=("$lower")
    fi
  done <"$f"

  (( seen_status )) || return 1
  return 0
}

# `hdr_present NAME` - 0 when the final response carried the (case-insensitive)
# field at all.  A field present with an EMPTY value is present:
# `X-Frame-Options:` with nothing after it is a misconfiguration, not an
# absence, and the two get different sentences.
hdr_present() {
  local n=${1,,}
  [[ -n ${_HDR_COUNT[$n]:-} ]]
}

# `hdr_value NAME` - sets `_HDR_V` to the field's value (LF-joined if repeated).
hdr_value() {
  local n=${1,,}
  _HDR_V=${_HDR_VALUE[$n]:-}
}

# `hdr_first NAME` - sets `_HDR_V` to the FIRST value only, for the fields where
# a repeat is itself the defect and the analysis wants one of them to talk about.
hdr_first() {
  local n=${1,,}
  _HDR_V=${_HDR_VALUE[$n]:-}
  _HDR_V=${_HDR_V%%$'\n'*}
}

# ---------------------------------------------------------------------------
# 2. Content-Type classification
# ---------------------------------------------------------------------------
# `hdr_is_document CTYPE` - 0 for a media type a browser renders as a top-level
# document, which is the only kind of response `Content-Security-Policy` and
# `X-Frame-Options` govern.
#
# THIS GATE IS THE DIFFERENCE BETWEEN A REPORT AND A WALL OF NOISE, and it is
# also the honest reading: a JSON API response is not framed and executes no
# script, so "this endpoint has no CSP" is not a statement about it.  Its
# callers apply it SELECTIVELY - passive/headers.sh gates CSP-absence and
# clickjacking on it and nothing else, because sniffing, transport downgrade and
# referrer leakage are not document-only problems.
hdr_is_document() {
  local ct=${1,,}
  ct=${ct%%;*}
  ct=${ct%"${ct##*[![:space:]]}"}
  case $ct in
    text/html | application/xhtml+xml | text/xml | application/xml) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 3. What a response check needs to know about the request it made
# ---------------------------------------------------------------------------
# The path component of a URL, query and fragment removed.  A URL with no path
# is `/`.  Same helper, same reason, as modules/dast/active/sqli.sh's own.
hdr_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# `hdr_url_is_https URL` - 0 for an `https://` URL.  HSTS is meaningless on a
# plaintext response (RFC 6797 section 7.2: a UA MUST ignore an STS header
# received over non-secure transport), so neither its absence nor its value is a
# finding there - the cleartext transport is, and that is DAST-30's check.
hdr_url_is_https() {
  [[ ${1,,} == https://* ]]
}

# `resp_url_scheme URL` - prints the lowercased scheme for an absolute http(s)
# URL, or nothing for anything else (relative, scheme-relative, or a scheme
# this tool never requests).  Moved here from `transport_engine.sh`'s
# `tr_url_scheme` once section 4's `scheme_template` dedup mode needed it by
# name - see this file's third ADR block.  `transport_engine.sh` keeps
# `tr_url_scheme` as a one-line wrapper, so `tr_url_origin` and the
# mixed-content scanner, which use it for reasons unrelated to the chooser,
# read identically to before.
resp_url_scheme() {
  local u=${1,,}
  case $u in
    https://*) printf 'https' ;;
    http://*) printf 'http' ;;
    *) printf '' ;;
  esac
}

# ---------------------------------------------------------------------------
# 4. Choosing what to request (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# THIS SECTION IS NOT A LEAF, AND IS THE ONE EXCEPTION TO THIS FILE'S OWN
# HEADER CLAIM.  `resp_endpoints_load` calls `crawl_json_flatten`/
# `crawl_json_unescape` (modules/dast/crawl_engine.sh) and `path_template_of`
# (lib/findings.sh) BY NAME.  This file sources NEITHER - see this file's own
# ADR blocks for why - so a caller that has not itself sourced both before
# calling this function gets a plain `command not found`, not a silent wrong
# answer.  Every real caller already has: `headers_engine.sh`,
# `markup_engine.sh`, `leakage_engine.sh` and `transport_engine.sh` all source
# `lib/http.sh` (which pulls in `lib/findings.sh`) and `crawl_engine.sh` before
# ever reaching this function.
#
# `resp_endpoints_load ENDPOINTS_FILE TARGET BASE_URL MAX_ENDPOINTS [DEDUP_KEY]`
# publishes the URL list a passive check will request, in `_RESP_URL[]` with
# `_RESP_PATH[]` alongside, and sets `_RESP_N`, `_RESP_TRUNCATED` and
# `_RESP_SKIPPED_NON_GET`.  Four decisions are baked in for every caller, and
# each has a reason worth keeping:
#
# 1. THE TARGET'S OWN `base-url` IS ALWAYS FIRST, when the caller supplies one.
#    It is config-derived (the operator wrote it) rather than target-derived,
#    it is the one URL that exists on every run whatever the crawl found, and
#    being first makes it the finding's location in the overwhelming majority
#    of runs - which is what keeps a fingerprint from churning when the
#    crawl's ordering changes between runs.
# 2. GET ONLY.  §7.1 is "no mutation of state"; re-sending a discovered POST to
#    read its headers or its markup is a state change dressed as a passive
#    check.  Non-GET endpoints are counted and reported, never silently
#    dropped.
# 3. DEDUPED, by default on PATH TEMPLATE alone.  `/order/1` and `/order/2`
#    are one handler serving one response, and requesting both spends two
#    units of the request budget to learn one fact.
# 4. SORTED, then capped.  A deterministic order is what makes the chosen set -
#    and therefore the finding locations - reproducible across runs; an
#    inventory-order walk would reshuffle them whenever the crawl did.
#
# DEDUP_KEY IS THE ONE AXIS THAT GENUINELY VARIES ACROSS CALLERS, AND IT IS THE
# ONLY THING THIS FUNCTION PARAMETERISES.  It defaults to `template` (decision
# 3 above), which is what `headers_engine.sh`, `markup_engine.sh` and
# `leakage_engine.sh` all want: a security header, a page's markup and an
# information-disclosure family are each configured once per HANDLER, so the
# plaintext and HTTPS twin of one path are the same observation and dedupe to
# one candidate.  `transport_engine.sh` passes `scheme_template` instead:
# mixed-content and plaintext-exposure are properties of the SCHEME a document
# was fetched over, so its own plaintext twin - the same handler, reached over
# `http://` - is not a duplicate to collapse, it IS the finding.
# `tests/suites/dast-response-engine.sh` section G pins both keys against the
# same inventory, and `tests/suites/dast-transport.sh`'s "reading 7" case pins
# it again at the phase grain: two candidates survive under `scheme_template`
# where the `template` default would collapse them to one and drop the
# plaintext twin that is the defect.
#
# MAX_ENDPOINTS IS A PARAMETER, NEVER A `: "${VAR:=N}"` DEFAULT IN THIS FILE.
# `headers.sh` (cap 10), `markup.sh` (cap 25), `leakage.sh` (cap 20) and
# `transport.sh` (cap 10) can all run within the same `dast_run_phase` loop in
# one process, so a set-once-if-unset global would let whichever phase runs
# first pin the cap for the rest.  Each caller keeps its own knob
# (`_HDR_MAX_ENDPOINTS`, `_MARKUP_MAX_ENDPOINTS`, `_LEAK_MAX_ENDPOINTS`,
# `_TR_MAX_ENDPOINTS`) and passes it in explicitly.
#
# An absent, empty or unreadable inventory is the NORMAL case
# (docs/INVENTORY-FORMAT.md §1) and is never an error: with a base URL the
# caller still has something true to say about the target's front door, and
# without one `_RESP_N` is 0 and the caller records the gap.
resp_endpoints_load() {
  local epf=${1:-} target=${2:-} base=${3:-} max=${4:-10} dedup=${5:-template}
  local sep=$'\x1f' p type v idx key rest last_idx=''
  declare -ga _RESP_URL=() _RESP_PATH=()
  declare -g _RESP_N=0 _RESP_TRUNCATED=0 _RESP_SKIPPED_NON_GET=0 _RESP_MAX=$max \
    _RESP_DEDUP=$dedup
  declare -gA _RESP_TPL_SEEN=()

  # The base URL first, and outside the sort, for reason 1 above.
  if [[ -n $base ]]; then
    _resp_candidate_add "$base"
  fi

  if [[ -z $epf || ! -r $epf || ! -s $epf ]]; then
    _RESP_N=${#_RESP_URL[@]}
    return 0
  fi

  # One flattened record at a time, in the shape docs/INVENTORY-FORMAT.md §7
  # freezes.  Collected into a sortable list first (reason 4), then added.
  declare -ga _RESP_ROWS=()
  local -A cur=()
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _resp_row_collect "${cur[url]:-}" "${cur[method]:-GET}" "${cur[target]:-}" "$target"
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    cur[$key]=$v
  done < <(crawl_json_flatten <"$epf" 2>/dev/null)
  if [[ -n $last_idx ]]; then
    _resp_row_collect "${cur[url]:-}" "${cur[method]:-GET}" "${cur[target]:-}" "$target"
  fi

  local row
  while IFS= read -r row; do
    [[ -n $row ]] || continue
    _resp_candidate_add "$row"
  done < <(printf '%s\n' "${_RESP_ROWS[@]+"${_RESP_ROWS[@]}"}" | LC_ALL=C sort -u)

  _RESP_N=${#_RESP_URL[@]}
  return 0
}

# Appends one inventory row's URL to `_RESP_ROWS` when it is a GET for this
# target.  A module-scoped accumulator rather than a by-name parameter because
# Bash 4.2 has no namerefs (tension 24's frozen minimum) and an `eval`-based
# append would be evaluating target-derived text - which rules/RULE-FORMAT.md
# §11 ("record files are data, never code") forbids elsewhere in this tool.
_resp_row_collect() {
  local url=$1 method=$2 row_target=$3 want_target=$4
  [[ -n $url ]] || return 0
  # An inventory entry that names a DIFFERENT scope target belongs to that
  # target's cell, not this one (rules/RULE-FORMAT.md §9.5.1).  An entry with
  # no target at all is accepted: an imported inventory may legitimately carry
  # none, and http_request re-gates it on the way out regardless.
  if [[ -n $row_target && -n $want_target && $row_target != "$want_target" ]]; then
    return 0
  fi
  if [[ ${method^^} != GET ]]; then
    _RESP_SKIPPED_NON_GET=$(( _RESP_SKIPPED_NON_GET + 1 ))
    return 0
  fi
  _RESP_ROWS+=("$url")
  return 0
}

# Adds one URL if its dedup key is new and the cap has room.  The key is the
# path template alone under the default `template` mode, or
# `scheme<0x1f>template` under `scheme_template` - see section 4's own header
# for why `transport_engine.sh` needs the second.  Under `scheme_template`, a
# URL with no recognised http(s) scheme (relative, scheme-relative) is not
# requestable at all and is skipped before it is counted against the cap -
# `tr_endpoints_load`'s original behaviour, kept unchanged.
_resp_candidate_add() {
  local url=$1 path tpl key scheme
  path=$(hdr_path_of "$url")
  tpl=$(path_template_of "$path")
  if [[ $_RESP_DEDUP == scheme_template ]]; then
    scheme=$(resp_url_scheme "$url")
    [[ -n $scheme ]] || return 0
    key=$scheme$'\x1f'$tpl
  else
    key=$tpl
  fi
  [[ -n ${_RESP_TPL_SEEN[$key]:-} ]] && return 0
  if (( ${#_RESP_URL[@]} >= _RESP_MAX )); then
    _RESP_TRUNCATED=$(( _RESP_TRUNCATED + 1 ))
    return 0
  fi
  _RESP_TPL_SEEN[$key]=1
  _RESP_URL+=("$url")
  _RESP_PATH+=("$path")
  return 0
}
