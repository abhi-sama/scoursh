#!/usr/bin/env bash
# modules/dast/passive/banner_engine.sh - the pure, testable half of the §7.1
# banner / version-disclosure check (docs/DESIGN.md §7.1;
# docs/STEP5-DAST-PLAN.md DAST-09, tier 2).
#
# The engine.sh / phase-script split is modules/sast/'s, reused one level down
# exactly as modules/dast/auth_engine.sh and active/inject_engine.sh already do:
# this file has the standard sourced-once guard and NO side effects at source
# time beyond building one lookup table, and modules/dast/passive/banner.sh is
# the file `dast_run_phase` sources.  Everything here is a pure function over
# bytes a caller already has, so the whole detection surface is testable from a
# RECORDED response with no network at all (docs/DESIGN.md §12).
#
# WHAT THIS FILE OWNS, STATED BECAUSE SIX PEER TICKETS ARE IN FLIGHT.
# DAST-05..DAST-11 are peers with no ordering between them, so this ticket
# deliberately builds NO shared passive scaffolding: `banner_header_each` and
# `banner_header_value` read the capture file lib/http.sh writes and are scoped
# to this file's own needs (iterate every field; look one field up
# case-insensitively).  A later passive ticket that wants the same two functions
# should LIFT them into a shared `passive/passive_engine.sh` in its own change
# and say so.  What must not happen is this ticket landing a half-designed
# shared library that headers.sh, cookies.sh and cors.sh then each bend in a
# different direction.
#
# THE THREE THINGS IT DETECTS, AND THE ONE IT REFUSES TO INVENT.
#   1. A product NAME in a response header (`Server`, `X-Powered-By`, ...).
#   2. A product name PLUS a version, from a header value, an HTML
#      `<meta name="generator">` tag, or a versioned bundle filename in the
#      served markup.
#   3. A discovered `product@version` that appears in the VENDORED
#      known-vulnerable list at `data/versions.db` (docs/VERSIONS-DB.md).
# There is no fourth, "this version looks old" heuristic, and there must not be
# one here: deciding that 1.18.0 is behind 1.27.0 is version-range arithmetic,
# which docs/FOUNDATION.md tension 25 moved off the scanner entirely and onto
# the networked box that has each ecosystem's real tooling.  The scanner does an
# exact table lookup and nothing else, so "out of date" means "this exact
# version is named in the vendored list", never a guess.
#
# NO NETWORK, NO INTERNET LOOKUP, EVER.  This file opens no socket and names no
# host: it is handed a header file and a body file that `banner.sh` obtained
# through lib/http.sh's `http_request` (tension 19's one chokepoint), and the
# vulnerable-version list is read from disk.  An online version check would
# break the egress-restricted premise of the whole tool, which is the reason
# `data/versions.db` exists at all.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes header, meta-tag and filename syntax
#   literally.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_BANNER_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_BANNER_ENGINE_SOURCED=1

# lib/core.sh is where `db_lookup_exact` - tension 25's ONE lookup primitive -
# lives.  In a real run scan.sh sourced it long ago; the guard is what lets a
# suite source THIS file on its own, the same shape modules/dast/engine.sh uses
# for lib/checks.sh.
if [[ -z ${SCOURSH_CORE_SOURCED:-} ]]; then
  # shellcheck source=lib/core.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/core.sh"
fi
# lib/records.sh owns `severity_rank`, the one severity ordering in this
# repository (section 6 reads it).  In a real run lib/findings.sh has already
# pulled it in; the guard is what keeps this file sourceable on its own.
if ! declare -F severity_rank >/dev/null; then
  # shellcheck source=lib/records.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/records.sh"
fi
# crawl_engine.sh is reused for its depth- and string-aware JSON flattener
# (`crawl_json_flatten`/`crawl_json_unescape`, docs/INVENTORY-FORMAT.md §7): the
# inventory is read THROUGH the same reader that wrote it, so a producer that
# formats the file differently is still read correctly.  Its own sourced-once
# guard makes this a no-op when a crawl already ran in this process.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds (docs/DESIGN.md §15: a bound that truncates silently is
#    indistinguishable from a surface that was really that small)
# ---------------------------------------------------------------------------
# Endpoints requested in one run.  The phase sends one plain GET per endpoint,
# so this bounds its whole traffic contribution on top of the per-run request
# budget the chokepoint already enforces.  When it bites, the phase records a
# coverage_gap naming what it did not reach.
: "${_BANNER_MAX_ENDPOINTS:=10}"
# Bytes of a response body parsed for meta tags and bundle filenames.  The
# crawler's own 512 KiB parse bound exists for the same reason: an unbounded
# read of a served download is a memory hazard, not thoroughness.
: "${_BANNER_MAX_BODY_BYTES:=262144}"
# Distinct (product, channel, version) disclosures reported per target.  A page
# that names forty bundles is one misconfiguration, not forty findings.
: "${_BANNER_MAX_DISCLOSURES:=40}"

# The response headers a product name is read out of.  A deliberate allow-list
# rather than "any header with a slash in it": `Server: nginx/1.18.0` is a
# disclosure and `Content-Type: text/html` is not.  Lowercase, because a header
# field name is case-insensitive (RFC 7230 §3.2) and every comparison here
# lowercases both sides.
#
# `declare -ga`, never bare, and the `-g` is load-bearing for the reason
# modules/dast/engine.sh's phase table documents at length: in a real run this
# file is sourced from inside `dast_run_phase`, so a declaration with no `-g`
# creates a local that dies with the phase.
declare -ga _BANNER_HEADERS=(
  server
  x-powered-by
  x-aspnet-version
  x-aspnetmvc-version
  x-generator
  x-litespeed-cache
  x-varnish
  via
)

# Trailing words a bundle filename carries that are not part of the product
# name.  `react-dom.production.min.16.8.0.js` is react-dom, not
# `react-dom-production-min`.
declare -ga _BANNER_BUNDLE_NOISE=(
  min
  slim
  production
  development
  bundle
  esm
  umd
  cjs
  dist
)

# ---------------------------------------------------------------------------
# 1. Normalisation
# ---------------------------------------------------------------------------
# The lowercase map every function below reads.  Built once at source time
# rather than per call, and with no `tr`: tension 24 keeps one capability layer,
# and this is 26 assignments against one fork per token on every response body.
declare -gA _BANNER_LOWER=()
_banner_init_lower() {
  local upper=ABCDEFGHIJKLMNOPQRSTUVWXYZ lower=abcdefghijklmnopqrstuvwxyz i
  for (( i = 0; i < 26; i++ )); do
    _BANNER_LOWER[${upper:i:1}]=${lower:i:1}
  done
}
_banner_init_lower

# `banner_lower TEXT` - TEXT lowercased.
banner_lower() {
  local s=$1 out='' i c
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    out+=${_BANNER_LOWER[$c]:-$c}
  done
  printf '%s' "$out"
}

# `banner_normalize_product NAME` - the product KEY, and therefore the second
# field of every `banner` row in data/versions.db.  Frozen in
# docs/VERSIONS-DB.md §3 and implemented HERE ONLY, for the reason tension 25
# gives for freezing each SCA ecosystem's normalisation: an exact lookup is only
# as good as its key, so the writer and the reader must not be able to drift.
#
# Lowercase; every run of characters outside [a-z0-9] collapses to a single `-`;
# leading and trailing `-` are stripped.  `Microsoft-IIS` -> `microsoft-iis`,
# `ASP.NET` -> `asp-net`, `jQuery` -> `jquery`, `OpenSSL` -> `openssl`.
banner_normalize_product() {
  local s=$1 out='' i c prev_dash=1
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    c=${_BANNER_LOWER[$c]:-$c}
    case $c in
      [a-z0-9]) out+=$c; prev_dash=0 ;;
      *) if (( ! prev_dash )); then out+='-'; prev_dash=1; fi ;;
    esac
  done
  out=${out%-}
  printf '%s' "$out"
}

# `banner_is_version TEXT` - 0 when TEXT is a version STRING this check is
# willing to report and to look up.
#
# At least two dotted numeric components are required, which is the line between
# a version and a number that happens to sit in a filename: `bootstrap4` and
# `analytics.2019.js` are not version disclosures, `1.18.0` and `2.4.41` are.  A
# trailing alphanumeric qualifier (`1.2.3-beta1`, `5.8.1p2`) is KEPT, because it
# is part of the key an advisory names.
banner_is_version() {
  [[ $1 =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*([-_.+][0-9A-Za-z]+)*$ ]]
}

# `banner_strip_bundle_noise KEY` - drops trailing `-min`, `-production` and
# friends from a normalised bundle-derived product key.  Applied to the bundle
# channel ONLY: `X-Powered-By: PHP` must never lose a component this way.
banner_strip_bundle_noise() {
  local key=$1 word changed=1
  while (( changed )); do
    changed=0
    for word in "${_BANNER_BUNDLE_NOISE[@]+"${_BANNER_BUNDLE_NOISE[@]}"}"; do
      if [[ $key == *-"$word" ]]; then
        key=${key%-"$word"}
        changed=1
      fi
    done
  done
  printf '%s' "$key"
}

# ---------------------------------------------------------------------------
# 2. Reading the response header capture
# ---------------------------------------------------------------------------
# lib/http.sh's `http_request_capture` accumulates the raw response headers of
# EVERY hop into one file, CRLF-terminated, status lines included.  These two
# readers are the only thing in this module that knows that.
#
# `banner_header_each FILE` - prints one `name<TAB>value` line per header field,
# name lowercased, value CR-stripped and trimmed.  A status line
# (`HTTP/1.1 200 OK`) and an obs-fold continuation line are skipped rather than
# parsed: neither carries a field name, and guessing at one is how a status
# reason phrase ends up reported as a product.
banner_header_each() {
  local file=$1 line name value
  [[ -n $file && -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    [[ $line == HTTP/* ]] && continue
    [[ $line == *:* ]] || continue
    [[ $line == [$' \t']* ]] && continue
    name=${line%%:*}
    value=${line#*:}
    while [[ $value == [$' \t']* ]]; do value=${value#?}; done
    while [[ $value == *[$' \t'] ]]; do value=${value%?}; done
    [[ -n $name ]] || continue
    printf '%s\t%s\n' "$(banner_lower "$name")" "$value"
  done <"$file"
  return 0
}

# `banner_header_value FILE NAME` - the LAST value seen for NAME, matched
# case-insensitively.  Last rather than first because a redirect chain
# accumulates in one file and the response that finally answered is the one a
# client sees.
banner_header_value() {
  local file=$1 want n v out=''
  want=$(banner_lower "$2")
  while IFS=$'\t' read -r n v; do
    [[ $n == "$want" ]] && out=$v
  done < <(banner_header_each "$file")
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 3. Channel 1: product and version from a header value
# ---------------------------------------------------------------------------
# `banner_products_from_header NAME VALUE` - prints `product<TAB>version` per
# product the value names, version empty when it discloses only a name.
#
# The value is split on whitespace and each token read as `name/version`
# (`nginx/1.18.0`, `PHP/7.4.3`, `Microsoft-IIS/10.0`), the shape RFC 7231 §7.4.2
# gives `Server` and the one `X-Powered-By` follows in practice.  Parenthesised
# platform comments (`(Ubuntu)`, `(Unix)`) are DROPPED: they name the OS
# distribution, not a component this check can look up, and reporting `ubuntu`
# as a product would put a row nothing can ever match into the report.
#
# A value that is a BARE VERSION takes its product from the HEADER NAME, which
# is the only place it is stated: `X-AspNet-Version: 4.0.30319` is ASP.NET
# 4.0.30319 and nothing else.  The name is reduced by dropping an `x-` prefix
# and a `-version` suffix before normalising, so `X-AspNet-Version` and
# `X-Aspnet-Version` reduce to the same key.
#
# `Via` is the one header whose LEADING bare version is a protocol version
# (`Via: 1.1 varnish`), never a product version, so it is skipped there.
banner_products_from_header() {
  local hname=$1 value=$2 tok name ver base lname
  lname=$(banner_lower "$hname")
  base=${lname#x-}
  base=${base%-version}
  base=$(banner_normalize_product "$base")

  local skip_leading_version=0
  [[ $lname == via ]] && skip_leading_version=1

  local first=1
  # Deliberately unquoted: whitespace splitting IS the tokeniser here.
  # shellcheck disable=SC2086
  for tok in $value; do
    tok=${tok%,}
    [[ -n $tok ]] || continue
    [[ $tok == \(* ]] && continue
    if [[ $tok == */* ]]; then
      name=${tok%%/*}
      ver=${tok#*/}
    else
      name=$tok
      ver=''
    fi
    if banner_is_version "$name" || [[ $name =~ ^[0-9]+$ ]]; then
      if (( first && skip_leading_version )); then
        first=0
        continue
      fi
      ver=$name
      name=$base
    fi
    first=0
    banner_is_version "$ver" || ver=''
    name=$(banner_normalize_product "$name")
    [[ -n $name ]] || continue
    # A "name" that is nothing but digits after normalisation is not a product.
    [[ $name =~ ^[0-9-]+$ ]] && continue
    printf '%s\t%s\n' "$name" "$ver"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 4. Channel 2: the HTML generator meta tag
# ---------------------------------------------------------------------------
# `banner_products_from_meta BODYFILE` - prints `product<TAB>version` for every
# `<meta name="generator" content="...">` in the body.
#
# The tag is lowercased before matching, because an HTML attribute name is
# case-insensitive and bash's `=~` is not; the CONTENT is lowercased with it,
# which is harmless - the name goes through `banner_normalize_product` (which
# lowercases anyway) and a version carries no case.  An UNQUOTED attribute value
# is not matched at all rather than guessed at: `content=WordPress 5.8` has no
# machine-decidable end.
banner_products_from_meta() {
  local file=$1 line low tag content name ver t rebuilt
  [[ -n $file && -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    # The cheap pre-filter is done on the LOWERCASED line, not on a
    # `*[Mm]eta*` glob over the raw one.  A tag spelled `<META NAME=...>` is
    # legal HTML and common in generator tags specifically; matching only the
    # two spellings a glob can afford silently skipped it, which reads in the
    # report as "this page discloses no generator".
    low=$(banner_lower "$line")
    case $low in
      *'<meta'*) ;;
      *) continue ;;
    esac
    while [[ $low == *'<meta'* ]]; do
      low=${low#*'<meta'}
      tag=${low%%'>'*}
      case $tag in
        *name=\"generator\"* | *name=\'generator\'* | *name=generator* ) ;;
        *) continue ;;
      esac
      content=''
      if [[ $tag =~ content=\"([^\"]*)\" ]]; then
        content=${BASH_REMATCH[1]}
      elif [[ $tag =~ content=\'([^\']*)\' ]]; then
        content=${BASH_REMATCH[1]}
      fi
      [[ -n $content ]] || continue
      ver=''
      rebuilt=''
      # `WordPress 5.8.1`, `Drupal 9 (https://www.drupal.org)`, `Hugo 0.83.1`.
      # The version is the last token that looks like one; the name is what is
      # left, and a parenthesised trailer ends the name.
      # A BARE MAJOR (`Drupal 9`) counts as a version HERE and nowhere else.
      # In a generator string the trailing number is the product's version by
      # convention; in a bundle filename it is part of the name (`bootstrap4`,
      # `angular2`), which is why `banner_is_version` itself stays strict and
      # this one arm relaxes it.  Without the relaxation `Drupal 9` normalises
      # to the product `drupal-9`, which is a key no vendored row can ever
      # match - a silent false negative rather than a visible mistake.
      # shellcheck disable=SC2086
      for t in $content; do
        [[ $t == \(* ]] && break
        if banner_is_version "${t#v}" || [[ ${t#v} =~ ^[0-9]+$ ]]; then
          ver=${t#v}
        else
          [[ -n $rebuilt ]] && rebuilt+=' '
          rebuilt+=$t
        fi
      done
      name=$(banner_normalize_product "${rebuilt:-$content}")
      [[ -n $name ]] || continue
      printf '%s\t%s\n' "$name" "$ver"
    done
  done <"$file"
  return 0
}

# ---------------------------------------------------------------------------
# 5. Channel 3: versioned bundle filenames in the served markup
# ---------------------------------------------------------------------------
# `banner_products_from_bundles BODYFILE` - prints `product<TAB>version` for
# every `.js`/`.css` reference whose basename carries a version.
#
# `jquery-3.4.1.min.js` -> jquery 3.4.1, `angular.1.7.2.js` -> angular 1.7.2,
# `bootstrap@4.3.1/dist/css/bootstrap.css` -> bootstrap 4.3.1.
# `app.js` and `bundle.4f3a1c.js` yield nothing: a content hash is not a
# version, which `banner_is_version`'s two-component rule already decides.
#
# The line is tokenised by replacing the characters that cannot appear inside a
# markup URL reference with spaces and letting word splitting do the rest.  That
# is a deliberate non-parse: the job is to find versioned filenames, not to
# understand the document, and an HTML parser here would be a second, worse copy
# of crawl_engine.sh's.
banner_products_from_bundles() {
  local file=$1 line tok name ver
  [[ -n $file && -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    case $line in
      *.js* | *.css*) ;;
      *) continue ;;
    esac
    line=${line//[\"\'<>()=,;]/ }
    # shellcheck disable=SC2086
    for tok in $line; do
      tok=${tok%%\?*}
      tok=${tok%%#*}
      case $tok in
        *.js | *.css) ;;
        *) continue ;;
      esac
      # The basename first, then each PATH SEGMENT.  A CDN reference carries
      # the version one level up from the file
      # (`/cdn/bootstrap@4.3.1/dist/css/bootstrap.css`), so a basename-only
      # reader reports `bootstrap` with no version and the out-of-date check
      # never gets a key to look up.
      name='' ver=''
      local cand
      # shellcheck disable=SC2086
      for cand in "$(banner_lower "${tok##*/}")" ${tok//\// }; do
        cand=$(banner_lower "$cand")
        cand=${cand%.js}
        cand=${cand%.css}
        [[ -n $cand ]] || continue
        if [[ $cand =~ ^([a-z][a-z0-9]*([-_.@][a-z][a-z0-9]*)*)[-_.@]v?([0-9]+(\.[0-9]+)+)([-_.][0-9a-z]+)*$ ]]; then
          name=${BASH_REMATCH[1]}
          ver=${BASH_REMATCH[3]}
          break
        fi
      done
      [[ -n $name ]] || continue
      banner_is_version "$ver" || continue
      name=$(banner_normalize_product "$name")
      name=$(banner_strip_bundle_noise "$name")
      [[ -n $name ]] || continue
      printf '%s\t%s\n' "$name" "$ver"
    done
  done <"$file"
  return 0
}

# ---------------------------------------------------------------------------
# 5a. The endpoint inventory (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `banner_endpoints_load [FILE] [TARGET]` - reads `endpoints.json` into the flat
# parallel arrays the phase iterates, keeping only the endpoints this check may
# request, and sets:
#
#   _BANNER_EP_N              how many are usable
#   _BANNER_EP_URL/_METHOD/_PATH   one entry each, parallel
#   _BANNER_EP_SKIPPED        endpoints dropped because their method is not
#                             GET or HEAD
#
# An absent, empty or unusable inventory is the NORMAL state
# (docs/INVENTORY-FORMAT.md §1) and leaves `_BANNER_EP_N` at 0; it is never an
# error.  This check READS the inventory and never crawls: DAST-04 owns
# discovery, and a passive check that went looking for URLs of its own would be
# a second crawler with none of the first one's scope pre-check.
#
# ONLY GET AND HEAD.  §7.1 is "no mutation of state", and a POST endpoint the
# crawler merely inventoried (it never submits a form either) is exactly the
# request a passive check must not send.  The count of what was dropped is
# reported rather than swallowed.
#
# The JSON is read through crawl_engine.sh's own depth- and string-aware
# flattener, never a second parser, so a producer that formats the file
# differently is still read correctly - the identical reasoning
# active/inject_engine.sh records for its parameter reader.
# THE ENDPOINT ORDER IS SORTED, NOT THE FILE'S.  Two things depend on it and
# both are correctness rather than tidiness.  The per-run cap takes the FIRST
# `_BANNER_MAX_ENDPOINTS` entries, so an unsorted read would test a different
# subset every time the crawler happened to discover pages in a different order.
# And a disclosure is reported once per target (see banner.sh), at the endpoint
# that disclosed it, so an unsorted read would move a finding's `path_template`
# - and therefore its fingerprint - between two runs that found the identical
# thing.  `LC_ALL=C` because that is the only ordering this repository sorts
# under.
banner_endpoints_load() {
  local file=${1:-${SCOURSH_DAST_ENDPOINTS:-}} want_target=${2:-}
  local sep=$'\x1f' p type v idx key rest last_idx='' url method path line
  declare -ga _BANNER_EP_URL=() _BANNER_EP_METHOD=() _BANNER_EP_PATH=()
  declare -ga _BANNER_EP_RAW=()
  declare -g _BANNER_EP_N=0 _BANNER_EP_SKIPPED=0
  _BANNER_WANT_TARGET=$want_target
  [[ -n $file && -r $file && -s $file ]] || return 0

  local -A cur=()
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _banner_flush_endpoint cur
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    cur[$key]=$v
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  [[ -n $last_idx ]] && _banner_flush_endpoint cur

  (( ${#_BANNER_EP_RAW[@]} > 0 )) || return 0
  while IFS=$'\t' read -r url method path; do
    [[ -n $url ]] || continue
    _BANNER_EP_URL+=("$url")
    _BANNER_EP_METHOD+=("$method")
    _BANNER_EP_PATH+=("$path")
    _BANNER_EP_N=$(( _BANNER_EP_N + 1 ))
  done < <(printf '%s\n' "${_BANNER_EP_RAW[@]+"${_BANNER_EP_RAW[@]}"}" | LC_ALL=C sort -u)
  return 0
}

# Bash 4.2 has no namerefs (tension 24's frozen minimum), so the record is
# passed BY NAME and read through `${!...}` indirection, exactly as
# crawl_engine.sh's and inject_engine.sh's own flush helpers do.
#
# SC2034: `cur` is written by the caller and read here only through that
# indirection, which shellcheck cannot see.
# shellcheck disable=SC2034
_banner_flush_endpoint() {
  local arrname=$1
  local ur="${arrname}[url]" mr="${arrname}[method]" pr="${arrname}[path]" tr="${arrname}[target]"
  local url=${!ur:-} method=${!mr:-GET} path=${!pr:-} target=${!tr:-}
  [[ -n $url ]] || return 0
  if [[ -n ${_BANNER_WANT_TARGET:-} && -n $target && $target != "$_BANNER_WANT_TARGET" ]]; then
    return 0
  fi
  case $method in
    GET | HEAD) ;;
    *) _BANNER_EP_SKIPPED=$(( _BANNER_EP_SKIPPED + 1 )); return 0 ;;
  esac
  _BANNER_EP_RAW+=("$url"$'\t'"$method"$'\t'"$path")
  return 0
}

# ---------------------------------------------------------------------------
# 6. The vendored known-vulnerable list (data/versions.db)
# ---------------------------------------------------------------------------
# The file, its schema, and how an operator refreshes it are docs/VERSIONS-DB.md.
# What matters here: it is the frozen tension-25 TSV
# (`ecosystem package version advisory_id severity fixed_versions summary`),
# every row this check reads carries the literal `banner` in field 1, and the
# lookup is `db_lookup_exact` - lib/core.sh's ONE implementation of tension 25's
# `look`-with-a-`grep -F`-fallback primitive - on the
# `banner<TAB>product<TAB>version<TAB>` prefix.  No range arithmetic, no
# comparison, no network.
: "${SCOURSH_DAST_VERSIONS_DB:=}"

# `banner_db_path` - the database this run reads.  The environment override is
# the swappable-seam idiom lib/http.sh's transport and resolver hooks already
# use, and it is what lets a suite point at a fixture database instead of the
# shipped one.
banner_db_path() {
  if [[ -n ${SCOURSH_DAST_VERSIONS_DB:-} ]]; then
    printf '%s' "$SCOURSH_DAST_VERSIONS_DB"
    return 0
  fi
  printf '%s' "${SCOURSH_INSTALL_ROOT:-${BASH_SOURCE[0]%/*}/../../..}/data/versions.db"
}

# `banner_db_state` - sets `_BANNER_DB_STATE` to one of:
#
#   absent          no readable, non-empty file at all
#   no_banner_rows  a file with no `banner` row in it - the state of a fresh
#                   clone, and also of an install whose SCA half is populated
#                   while its banner catalogue is not
#   present         at least one `banner` row
#
# and `_BANNER_DB_GENERATED` to the `# generated:` stamp when the file carries
# one.  The stamp is REPORTED, not merely read: tension 25 requires the
# database's own generation date to reach the report, so "only as current as the
# last refresh" is a dated fact in the output rather than a caveat in a document
# nobody opens.
#
# `no_banner_rows` is kept distinct from `absent` for the reason
# modules/dast/engine.sh keeps `empty` distinct from `absent` for the inventory:
# a database somebody generated and a database nobody has are different facts,
# and collapsing them lets a half-populated file read as a missing one.
banner_db_state() {
  local db line n=0
  db=$(banner_db_path)
  _BANNER_DB_STATE=absent
  _BANNER_DB_GENERATED=''
  [[ -n $db && -r $db && -s $db ]] || return 0
  _BANNER_DB_STATE=no_banner_rows
  while IFS= read -r line || [[ -n $line ]]; do
    case $line in
      '# generated: '*) _BANNER_DB_GENERATED=${line#'# generated: '} ;;
      'banner'$'\t'*) n=$(( n + 1 )); break ;;
    esac
  done <"$db"
  (( n > 0 )) && _BANNER_DB_STATE=present
  return 0
}

# `banner_db_known PRODUCT` - 0 when the vendored list carries ANY row for
# PRODUCT, whatever the version.
#
# This is what separates "this version is not known to be vulnerable" from "the
# list has never heard of this product".  Those are wildly different statements
# and only the first is reassuring; tension 25 makes the same distinction for
# SCA with `SCA-COV-UNKNOWN_VERSION-01`, and the phase rolls the second case up
# into ONE coverage record rather than one finding per product.
banner_db_known() {
  local product=$1 db
  [[ -n $product ]] || return 1
  db=$(banner_db_path)
  db_lookup_exact "banner"$'\t'"$product"$'\t' "$db" >/dev/null 2>&1
}

# `banner_db_match PRODUCT VERSION` - 0 when the vendored list names this exact
# `product@version`, setting:
#
#   _BANNER_ADVISORIES   space-separated advisory ids, in file order
#   _BANNER_SEVERITY     the highest severity across the matched rows
#   _BANNER_FIXED        the first non-empty `fixed_versions` field
#   _BANNER_SUMMARY      the first non-empty `summary` field
#
# ONE result, not one per advisory, and that is not a convenience: the DAST
# fingerprint (target, method, path_template, param_location, param_name) has no
# advisory component, so a finding per matched row would be N findings that all
# hash identically and `findings_merge` would silently keep one - the exact
# collision modules/sca/'s roll-up documents, met here before it could ship.
# The advisory ids therefore travel in the EVIDENCE of a single finding.
banner_db_match() {
  local product=$1 version=$2 db eco pkg ver adv sev fixed summary found=0
  _BANNER_ADVISORIES='' _BANNER_SEVERITY='' _BANNER_FIXED='' _BANNER_SUMMARY=''
  [[ -n $product && -n $version ]] || return 1
  db=$(banner_db_path)
  while IFS=$'\t' read -r eco pkg ver adv sev fixed summary; do
    [[ $eco == banner && $pkg == "$product" && $ver == "$version" ]] || continue
    found=1
    [[ -n $adv ]] && _BANNER_ADVISORIES+="${_BANNER_ADVISORIES:+ }$adv"
    _banner_severity_max "${_BANNER_SEVERITY:-}" "$sev"
    _BANNER_SEVERITY=$_BANNER_SEV_MAX
    [[ -z $_BANNER_FIXED && -n $fixed ]] && _BANNER_FIXED=$fixed
    [[ -z $_BANNER_SUMMARY && -n $summary ]] && _BANNER_SUMMARY=$summary
  done < <(db_lookup_exact "banner"$'\t'"$product"$'\t'"$version"$'\t' "$db" 2>/dev/null || true)
  (( found )) || return 1
  [[ -n $_BANNER_SEVERITY ]] || _BANNER_SEVERITY=high
  return 0
}

# `_banner_severity_max A B` - sets `_BANNER_SEV_MAX` to the more severe of the
# two, ignoring anything that is not one of the five names.  The ordering comes
# from lib/records.sh's `severity_rank` - the one table this repository has, and
# the one lib/findings.sh's own rubric reads - rather than a sixth copy of five
# names; `severity_rank` returns -1 for a value it does not know, which is what
# makes "unrecognised" distinguishable from `info` here.
#
# The database is operator-refreshed data, so an unrecognised severity must not
# be able to SILENCE a row: an unusable value falls back to the other side, and
# a row with no usable severity at all lands on `banner_db_match`'s `high`
# default rather than on nothing at all.
_banner_severity_max() {
  local a=$1 b=$2 ra rb
  ra=$(severity_rank "$a")
  rb=$(severity_rank "$b")
  if (( rb > ra )); then _BANNER_SEV_MAX=$b; else _BANNER_SEV_MAX=$a; fi
  if (( ra < 0 && rb < 0 )); then _BANNER_SEV_MAX=''; fi
  return 0
}
