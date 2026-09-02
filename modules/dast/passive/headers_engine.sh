#!/usr/bin/env bash
# modules/dast/passive/headers_engine.sh - the pure, testable half of the §7.1
# security-header family (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-05,
# tier 2).
#
# WHAT THIS FILE IS, AND WHY IT IS NAMED FOR ONE TICKET RATHER THAN FOR THE TIER.
# DAST-05..DAST-11 are peers with no ordering between them and were built in
# parallel, so a file called `passive/passive_engine.sh` would have been shared
# scaffolding three tickets each believed they owned.  What is left here is the
# header-analysis logic that only `passive/headers.sh` uses - the
# CSP/HSTS/Referrer-Policy parsers, the recommended-header loader and the
# endpoint chooser - and it is named accordingly.
#
# THE RESPONSE READER THAT USED TO LIVE HERE HAS BEEN LIFTED, AS THIS HEADER
# ASKED.  `hdr_parse_capture`, `hdr_present`, `hdr_value`, `hdr_first`,
# `hdr_is_document`, `hdr_safe_text`, `hdr_path_of` and `hdr_url_is_https` now
# live in `modules/dast/passive/response_engine.sh`, whose own ADR block records
# why and why the `hdr_` prefix was kept.  Nothing about their behaviour
# changed and no call site moved; this file sources that one, so a consumer
# that needs the parsers still gets the reader by sourcing this.  A consumer
# that needs the READER ALONE should source `response_engine.sh` directly
# rather than this file - that is the whole point of the split, and five
# already do.
#
# THE ENDPOINT CHOOSER MOVED THERE TOO, ONCE A SECOND REAL COPY EXISTED.
# `hdr_endpoints_load` below is now a thin wrapper over
# `response_engine.sh`'s `resp_endpoints_load`; see that file's own ADR block
# for the full account of why this one stayed a wrapper (so no call site here
# or in `ratelimit_engine.sh` had to change) rather than every caller reading
# `_RESP_*` directly.
#
# THE ONE THING THIS FILE DOES NOT DO IS TALK TO THE NETWORK.  Every request the
# phase sends goes through `http_request` (lib/http.sh) - docs/FOUNDATION.md
# tension 19's single chokepoint, which is where the scope gate, DAST-01's rate
# limiter, the per-run request budget, the circuit breaker and DAST-32's ceilings
# all sit.  This file parses what came back; `headers.sh` is what asks.
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

if [[ -n ${SCOURSH_DAST_HEADERS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_HEADERS_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint; a dast run does not otherwise load it (see
# modules/dast/engine.sh's header), so the first phase that issues traffic
# sources it, guarded exactly as modules/dast/auth_engine.sh and
# modules/dast/active/inject_engine.sh already do.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# crawl_engine.sh is reused for its depth- and string-aware JSON flattener
# (`crawl_json_flatten`/`crawl_json_unescape`, docs/INVENTORY-FORMAT.md §7): the
# inventory is read THROUGH the same reader that wrote it, so a producer that
# formats the file differently is still read correctly.  Its own sourced-once
# guard makes this a no-op on a run where the crawl already happened.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"
# response_engine.sh is the shared response reader this file used to hold.  It
# sources nothing itself - it is a leaf in the static source graph - so this
# edge is cheap under `shellcheck -x` and adds no runtime dependency.
# shellcheck source=modules/dast/passive/response_engine.sh
source "${BASH_SOURCE[0]%/*}/response_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds and knobs
# ---------------------------------------------------------------------------
# docs/DESIGN.md §15: a bound that truncates silently is indistinguishable from
# a surface that was really that small, so every one of these records a
# coverage_gap when it bites.
#
# How many distinct endpoints this phase will request.  Security headers are a
# response property, so in principle every endpoint is a separate observation;
# in practice they are configured once per application and re-requesting two
# hundred paths to learn the same fact is a request storm the operator did not
# ask for.  Ten is deliberately modest and is what the coverage_gap names.
: "${_HDR_MAX_ENDPOINTS:=10}"
# The `Strict-Transport-Security` `max-age` at or above which HSTS is considered
# adequate.  One year, which is both the value hstspreload.org requires and the
# common industry floor.  Overridable so an operator with a documented shorter
# policy can hold the scan to their own number rather than to this one.
: "${SCOURSH_DAST_HSTS_MIN_MAX_AGE:=31536000}"
# `_HDR_MAX_EVIDENCE_FIELD` (the evidence field cap) moved to
# response_engine.sh with `hdr_safe_text`, which reads it as a parameter
# default: leaving it here would have left that function unbound under `set -u`
# for any consumer that sources the reader alone.

# ---------------------------------------------------------------------------
# 1. The response-header reader - MOVED
# ---------------------------------------------------------------------------
# `hdr_parse_capture`, `hdr_present`, `hdr_value` and `hdr_first` now live in
# modules/dast/passive/response_engine.sh, sourced above.  Read that file's ADR
# block before changing any of them; the reset-on-every-status-line property is
# the most dangerous parse in this tier and is pinned in three suites.

# ---------------------------------------------------------------------------
# 2. Content-Type classification - MOVED
# ---------------------------------------------------------------------------
# `hdr_is_document` moved to response_engine.sh with the reader.  This file's
# own use of it is unchanged: passive/headers.sh gates CSP-absence and
# clickjacking on it, and nothing else.

# ---------------------------------------------------------------------------
# 3. Content-Security-Policy
# ---------------------------------------------------------------------------
# `hdr_csp_load POLICY` - splits one policy string into its directives and
# publishes `_HDR_CSP_DIR[name]` (the source list, lowercased and
# whitespace-normalised) plus `_HDR_CSP_ORDER`.
#
# A DUPLICATE DIRECTIVE IS THE FIRST ONE, NOT THE LAST (CSP3 §2.2: "if the set
# already contains a directive of that name, ignore this instance").  Taking the
# last would report a policy the browser does not enforce, which for a
# `script-src` appearing twice is the difference between flagging and not.
hdr_csp_load() {
  local policy=$1 part name rest
  declare -gA _HDR_CSP_DIR=()
  declare -ga _HDR_CSP_ORDER=()
  local IFS=';'
  # shellcheck disable=SC2206  # deliberate word split on ';', the CSP separator
  local -a parts=($policy)
  unset IFS
  for part in "${parts[@]+"${parts[@]}"}"; do
    # Collapse runs of whitespace to single spaces and trim.
    part=${part//$'\t'/ }
    part=${part//$'\r'/ }
    part=${part//$'\n'/ }
    while [[ $part == *'  '* ]]; do part=${part//  / }; done
    part=${part# }
    part=${part% }
    [[ -n $part ]] || continue
    name=${part%% *}
    name=${name,,}
    if [[ $part == *' '* ]]; then rest=${part#* }; else rest=''; fi
    [[ -n ${_HDR_CSP_DIR[$name]+set} ]] && continue
    _HDR_CSP_DIR[$name]=${rest,,}
    _HDR_CSP_ORDER+=("$name")
  done
  return 0
}

# `hdr_csp_effective NAME` - sets `_HDR_CSP_SRC` to the source list that actually
# governs NAME, falling back to `default-src` when NAME is absent, and sets
# `_HDR_CSP_VIA` to the directive the value came from ('' when neither exists).
#
# The fallback is what CSP itself does for a fetch directive, and skipping it
# would miss the single most common real-world shape:
# `default-src 'self' 'unsafe-inline'` with no `script-src` at all.
hdr_csp_effective() {
  local want=${1,,}
  _HDR_CSP_SRC='' _HDR_CSP_VIA=''
  if [[ -n ${_HDR_CSP_DIR[$want]+set} ]]; then
    _HDR_CSP_SRC=${_HDR_CSP_DIR[$want]}
    _HDR_CSP_VIA=$want
    return 0
  fi
  if [[ -n ${_HDR_CSP_DIR[default-src]+set} ]]; then
    _HDR_CSP_SRC=${_HDR_CSP_DIR[default-src]}
    # Quoted: an unquoted `default-src` reads as arithmetic to a linter
    # (SC2100), though bash assigns the literal string either way.
    _HDR_CSP_VIA='default-src'
    return 0
  fi
  return 1
}

# `hdr_csp_has_nonce_or_hash SOURCELIST` - 0 when the list carries a `'nonce-...'`
# or a `'sha256-...'`/`'sha384-...'`/`'sha512-...'` source.
#
# WHY THIS EXISTS: in CSP Level 2 and later a browser IGNORES `'unsafe-inline'`
# in a directive that also carries a nonce or a hash - it is there as a fallback
# for CSP1 browsers, and flagging it is a false positive on one of the few
# genuinely well-built policies in the wild.  This function is what keeps
# `DAST-HDR-CSP_UNSAFE-01` from firing on it.
hdr_csp_has_nonce_or_hash() {
  local src=" $1 "
  [[ $src == *" 'nonce-"* ]] && return 0
  [[ $src == *" 'sha256-"* || $src == *" 'sha384-"* || $src == *" 'sha512-"* ]] && return 0
  return 1
}

# `hdr_csp_wildcard_in SOURCELIST` - sets `_HDR_CSP_WILDCARD` to the first source
# whose HOST portion contains `*`, and returns 0; returns 1 when there is none.
#
# The scheme and the path are deliberately not consulted: `https://cdn.example/*`
# wildcards a PATH, which is ordinary and is not what docs/DESIGN.md §7.1's "no
# wildcard in the domain portion" means.  A bare `*`, `https://*` and
# `*.example.com` all are.
hdr_csp_wildcard_in() {
  local src=$1 tok host
  _HDR_CSP_WILDCARD=''
  for tok in $src; do
    # Quoted keywords ('self', 'none', 'unsafe-inline', nonces, hashes) are not
    # host sources at all.
    [[ ${tok:0:1} == "'" ]] && continue
    if [[ $tok == '*' ]]; then
      _HDR_CSP_WILDCARD=$tok
      return 0
    fi
    host=${tok#*://}
    host=${host%%/*}
    host=${host%%:*}
    if [[ $host == *'*'* ]]; then
      _HDR_CSP_WILDCARD=$tok
      return 0
    fi
  done
  return 1
}

# `hdr_csp_data_in SOURCELIST` - 0 when the list carries the `data:` scheme
# source.  Matched as a whole token so a host named `mydata:` cannot match.
hdr_csp_data_in() {
  local src=$1 tok
  for tok in $src; do
    [[ $tok == 'data:' ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Strict-Transport-Security
# ---------------------------------------------------------------------------
# `hdr_hsts_parse VALUE` - sets `_HDR_HSTS_STATE` to one of:
#
#   ok           a well-formed `max-age` was found (its value is in
#                `_HDR_HSTS_MAXAGE`)
#   no_max_age   the header is present but names no `max-age` at all
#   bad_max_age  `max-age` is present but its value is not a decimal integer
#
# and `_HDR_HSTS_SUBDOMAINS` to 1/0.  RFC 6797 §6.1 makes `max-age` REQUIRED and
# a header without it is to be ignored entirely by the user agent, which is why
# "present but unusable" is reported as its own defect rather than folded into
# "missing": an operator who set the header and got nothing for it is a
# different conversation from one who never set it.
hdr_hsts_parse() {
  local v=$1 part key val
  declare -g _HDR_HSTS_STATE=no_max_age _HDR_HSTS_MAXAGE='' _HDR_HSTS_SUBDOMAINS=0
  local IFS=';'
  # shellcheck disable=SC2206  # deliberate word split on ';', the HSTS separator
  local -a parts=($v)
  unset IFS
  for part in "${parts[@]+"${parts[@]}"}"; do
    part=${part//$'\t'/ }
    part=${part# }
    part=${part% }
    [[ -n $part ]] || continue
    key=${part%%=*}
    key=${key,,}
    key=${key% }
    if [[ $part == *=* ]]; then val=${part#*=}; else val=''; fi
    val=${val# }
    val=${val% }
    # RFC 6797 allows the value to be a quoted-string.
    val=${val#\"}
    val=${val%\"}
    case $key in
      max-age)
        if [[ $val =~ ^[0-9]+$ ]]; then
          _HDR_HSTS_STATE=ok
          _HDR_HSTS_MAXAGE=$val
        else
          _HDR_HSTS_STATE=bad_max_age
          _HDR_HSTS_MAXAGE=''
        fi
        ;;
      includesubdomains) _HDR_HSTS_SUBDOMAINS=1 ;;
    esac
  done
  return 0
}

# ---------------------------------------------------------------------------
# 5. Referrer-Policy
# ---------------------------------------------------------------------------
# `hdr_referrer_effective VALUE` - sets `_HDR_REF_TOKEN` to the token a browser
# actually applies: a `Referrer-Policy` value is a comma-separated list and the
# user agent takes the LAST token it RECOGNISES, so a site can list a modern
# policy after a legacy one and get the modern one everywhere it is understood.
# An unrecognised token is skipped rather than adopted, which is why
# `no-referrer, garbage` is `no-referrer` and not a finding.
# `_HDR_REF_TOKEN` is empty when no token is recognised at all.
hdr_referrer_effective() {
  local v=$1 tok
  declare -g _HDR_REF_TOKEN=''
  local IFS=','
  # shellcheck disable=SC2206  # deliberate word split on ',', the RP separator
  local -a toks=($v)
  unset IFS
  for tok in "${toks[@]+"${toks[@]}"}"; do
    tok=${tok// /}
    tok=${tok//$'\t'/}
    tok=${tok,,}
    case $tok in
      no-referrer | no-referrer-when-downgrade | origin | origin-when-cross-origin | \
        same-origin | strict-origin | strict-origin-when-cross-origin | unsafe-url)
        _HDR_REF_TOKEN=$tok
        ;;
    esac
  done
  return 0
}

# `hdr_referrer_leaks_full_url TOKEN` - 0 for the two policies that send the
# WHOLE URL - path, query and all - to a cross-origin destination.
#
# The list is exactly two and it is deliberately not longer.  `origin` and
# `origin-when-cross-origin` send only the origin cross-origin, so they leak no
# path or query and are not what docs/DESIGN.md §7.1 asks to flag; folding them
# in would turn a precise finding into a style opinion.  An ABSENT header is not
# here either: every current browser's default is
# `strict-origin-when-cross-origin`, so absence is a hardening gap rather than a
# leak, and it is reported by the recommended-headers roll-up instead.
hdr_referrer_leaks_full_url() {
  case $1 in
    unsafe-url | no-referrer-when-downgrade) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. The configurable recommended-header list
# ---------------------------------------------------------------------------
# `hdr_load_recommended [FILE]` - loads the operator's roll-up list into
# `_HDR_RECOMMENDED` (lowercased, deduped, order preserved) and returns 1 when
# nothing usable was found anywhere, so the caller degrades that one check
# rather than erroring.
#
# PRECEDENCE, THREE SOURCES, FIRST NON-EMPTY WINS:
#
#   1. config/scanner.conf's `recommended-header` key (rules/RULE-FORMAT.md
#      §9.6.1), resolved through lib/config.sh's own `config_scanner_list` -
#      which means CLI/`SCOURSH_CONFIG_RECOMMENDED_HEADER`/file precedence
#      applies exactly as it does for every other repeatable scanner.conf key.
#      Its stdout is captured through a PLAIN redirection into a scratch file,
#      never `$(...)` or `<(...)`: both fork a subshell, and
#      `config_scanner_list` calls `die()` on an invalid entry, whose `exit`
#      then only ends THAT subshell - a first draft here captured it as
#      `<(config_scanner_list ... 2>/dev/null || printf '')`, which silently
#      discarded both the diagnostic and the abort, and fell through to FILE
#      as though the key had never been set, instead of failing the run the
#      way every sibling scanner.conf key already does (scan.sh's own
#      `_scan_capture`/`_scan_capture_list` and lib/core.sh's `core_capture`
#      document and fix the identical hazard - AGENTS.md's "Things measured on
#      this codebase", the `var=$(cmd)`-under-`set -e` entry).  A plain `>`
#      redirection does not fork a subshell, so a `die()` inside
#      `config_scanner_list` aborts this process for real, and an invalid
#      entry is refused the moment this phase first asks for the list rather
#      than silently mis-reported as "not configured".
#   2. FILE (the caller's explicit argument, for a test or a script that wants
#      a specific list) or, absent that, `SCOURSH_DAST_RECOMMENDED_HEADERS_FILE`.
#   3. The vendored `recommended-headers.txt` beside this file.
#
# WHY THE CONFIG KEY DID NOT LAND WITH DAST-05, AND WHY LEVELS 2-3 STILL EXIST.
# §9.6.1's key set was FROZEN at the time: adding one moves `lib/records.sh`
# and `tests/lint-rules.sh` together (§14 item 2) and would have widened that
# tier-2 ticket into a format change five peer tickets then building in
# parallel would have had to rebase onto.  The vendored-file-plus-environment-
# seam shape (the same idiom as `SCOURSH_DAST_SQLI_PAYLOAD_DIR`) shipped
# instead, and is KEPT rather than removed now that the key exists: it is a
# strictly more forgiving path (a malformed LINE is skipped rather than dying
# the whole run, unlike an invalid config-key entry), so an operator who
# prefers editing a plain text file - or a script driving scoursh without a
# scanner.conf of its own - still has that route, and a run reachable through
# scan.sh's config loader (config_scanner_load) never has to have been called
# for the roll-up to still say something.
#
# A NAME A DEDICATED CHECK ALREADY OWNS IS DROPPED FROM THE LIST, FROM EITHER
# SOURCE.  Otherwise an operator who adds `content-security-policy` gets the
# same absence reported twice, once as `DAST-HDR-CSP_MISSING-01` and once
# inside the roll-up, and the second one carries no remediation specific to
# it.  The dropped names are published in `_HDR_RECOMMENDED_DROPPED` so the
# phase can say so rather than silently ignoring an operator's edit - true
# whichever source supplied the name.
hdr_load_recommended() {
  local f=${1:-}
  declare -ga _HDR_RECOMMENDED=() _HDR_RECOMMENDED_DROPPED=()
  declare -gA _HDR_RECOMMENDED_SEEN=()

  # -- 1. config/scanner.conf -------------------------------------------------
  # `config_scanner_list` is always defined by this point: this file sources
  # lib/http.sh (guarded against double-sourcing, not against never having
  # run), which unconditionally sources lib/config.sh.  Its own default for
  # this key is the empty list (lib/config.sh's `_scanner_default_list`), so
  # "zero items back" means exactly "the operator did not set this key at any
  # level" - CONFIG_SCANNER_LOADED being 0 (no config_scanner_load call this
  # process, the ordinary case for a direct-engine test) falls through here
  # the same way an operator who left the key out of a loaded file does.  See
  # this function's own header comment for why the capture below is a plain
  # redirection rather than `$(...)`/`<(...)`; the scratch path itself is
  # `mktemp`, never a name built from `$BASHPID` - a DAST-phase scratch file
  # with a predictable name is exactly `modules/dast/passive/cors_engine.sh`'s
  # own `cors_header_last`/CWE-377-via-CWE-59 lesson (AGENTS.md, "sharp
  # edges"), and this file falls back to a world-writable /tmp on every
  # standalone-engine caller (including this repository's own test suite)
  # whenever SCOURSH_SCRATCH is unset.
  local _hdr_cfg_tmp
  _hdr_cfg_tmp=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/hdr-recommended.XXXXXX")
  chmod 600 "$_hdr_cfg_tmp" 2>/dev/null || true
  config_scanner_list recommended-header >"$_hdr_cfg_tmp"
  local item
  while IFS= read -r item; do
    [[ -n $item ]] && _hdr_recommended_add "$item"
  done <"$_hdr_cfg_tmp"
  rm -f "$_hdr_cfg_tmp"
  if (( ${#_HDR_RECOMMENDED[@]} > 0 || ${#_HDR_RECOMMENDED_DROPPED[@]} > 0 )); then
    (( ${#_HDR_RECOMMENDED[@]} > 0 ))
    return
  fi

  # -- 2/3. the file, and its own shipped default ----------------------------
  f=${f:-${SCOURSH_DAST_RECOMMENDED_HEADERS_FILE:-${BASH_SOURCE[0]%/*}/recommended-headers.txt}}
  local line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    [[ $line =~ ^[A-Za-z0-9!#\$%\&\'*+.^_\`|~-]+$ ]] || continue
    _hdr_recommended_add "$line"
  done <"$f"
  (( ${#_HDR_RECOMMENDED[@]} > 0 ))
}

# `_hdr_recommended_add NAME` - lowercases, dedupes (case-insensitively) and
# applies the owned-name drop, appending to `_HDR_RECOMMENDED` or
# `_HDR_RECOMMENDED_DROPPED`.  Shared by both sources in `hdr_load_recommended`
# so config-supplied and file-supplied names can never diverge on either rule -
# the drop assertion in tests/suites/dast-headers.sh holds "whichever source
# the list came from" only because there is exactly one place that decides it.
_hdr_recommended_add() {
  local lower=${1,,}
  [[ -n $lower ]] || return 0
  [[ -n ${_HDR_RECOMMENDED_SEEN[$lower]:-} ]] && return 0
  _HDR_RECOMMENDED_SEEN[$lower]=1
  if hdr_recommended_is_owned "$lower"; then
    _HDR_RECOMMENDED_DROPPED+=("$lower")
    return 0
  fi
  _HDR_RECOMMENDED+=("$lower")
}

# The four header names this phase reports on with a dedicated check id.
hdr_recommended_is_owned() {
  case $1 in
    content-security-policy | strict-transport-security | x-frame-options | \
      x-content-type-options) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 7. Choosing what to request (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `hdr_endpoints_load [ENDPOINTS_FILE] [TARGET] [BASE_URL]` - publishes the URL
# list this phase will request, in `_HDR_URL[]` with `_HDR_PATH[]` alongside, and
# sets `_HDR_N`, `_HDR_TRUNCATED` and `_HDR_SKIPPED_NON_GET`.  The four
# decisions this makes (base-url first, GET only, deduped by path template,
# sorted then capped) are documented once now, in
# `response_engine.sh`'s `resp_endpoints_load` - not restated here to avoid
# the two copies drifting the way the CODE itself used to.
#
# A THIN WRAPPER over the shared chooser (response_engine.sh's own ADR block
# has the full account of why the chooser lives there rather than here now).
# `hdr_endpoints_load`'s name, its parameters and its four output globals
# (`_HDR_URL`/`_HDR_PATH`/`_HDR_N`/`_HDR_TRUNCATED`/`_HDR_SKIPPED_NON_GET`) are
# UNCHANGED, so `passive/headers.sh` and `ratelimit_engine.sh` (which sources
# this file for both halves) call this exactly as before - the refactor moves
# where the four decisions are decided, not what a caller of this function
# sees.
hdr_endpoints_load() {
  local epf=${1:-} target=${2:-} base=${3:-}
  resp_endpoints_load "$epf" "$target" "$base" "$_HDR_MAX_ENDPOINTS"
  declare -ga _HDR_URL=("${_RESP_URL[@]+"${_RESP_URL[@]}"}")
  declare -ga _HDR_PATH=("${_RESP_PATH[@]+"${_RESP_PATH[@]}"}")
  declare -g _HDR_N=$_RESP_N _HDR_TRUNCATED=$_RESP_TRUNCATED \
    _HDR_SKIPPED_NON_GET=$_RESP_SKIPPED_NON_GET
  return 0
}

# `hdr_path_of` and `hdr_url_is_https` moved to response_engine.sh with the
# reader, and the endpoint chooser's own four decisions moved there with it
# once a second real copy existed (`markup_engine.sh`'s `markup_endpoints_load`)
# - see that file's own ADR block.  `passive/headers.sh` still calls
# `hdr_url_is_https` unchanged, through the source edge at the top of this
# file.
