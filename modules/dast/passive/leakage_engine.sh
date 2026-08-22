#!/usr/bin/env bash
# modules/dast/passive/leakage_engine.sh - the pure, testable half of the §7.1
# INFORMATION-DISCLOSURE family (docs/DESIGN.md §7.1;
# docs/STEP5-DAST-PLAN.md DAST-10, tier 2).
#
# WHAT THIS FILE IS.  Five families of "what does the target hand an
# unauthenticated client that it did not mean to": a verbose error or stack
# trace, an upstream proxy header naming internal infrastructure, an email
# address, a client-config value embedded in served JavaScript, and the set of
# third-party origins the page pulls active content from.  Everything here is a
# pure decision over bytes that already arrived; modules/dast/passive/leakage.sh
# is what asks for them, through `http_request` and nothing else.
#
# IT IS NAMED FOR ONE TICKET, NOT FOR THE TIER, and that is the convention
# modules/dast/passive/headers_engine.sh set for exactly this reason: DAST-05
# through DAST-11 are peers with no ordering between them, built in parallel, so
# a `passive/passive_engine.sh` would be shared scaffolding several tickets each
# believed they owned.  A later ticket needing the same body reader should LIFT
# it deliberately into a shared file, with these tests moving with it, rather
# than growing a second copy.
#
# PRECISION OVER RECALL, WHICH IS THIS TICKET'S WHOLE POINT.  Every one of these
# five families has an obvious naive implementation that is unusable in the
# field, and each is rejected here by a NAMED technique.  All five are pinned by
# a negative fixture in tests/suites/dast-leakage.sh that the naive reading
# flags and this implementation does not:
#
#   1. STACK TRACE - naive: the body contains "error", "exception", "stack" or a
#      framework name.  That flags every branded 404 page on the internet.
#      TECHNIQUE: require a STRUCTURED FRAME - a source location (file plus line
#      number) in one of six runtime-specific shapes - or an unambiguous
#      interactive-debugger banner.  A page that merely says "Error" carries no
#      frame and is not flagged.  `leak_stack_frame_in`.
#   2. PROXY HEADER - naive: any `Via`, `X-Served-By` or `X-Cache` header is
#      infrastructure leakage.  That flags every site behind a public CDN, whose
#      edge POP code is a published, deliberate identifier.
#      TECHNIQUE: the HEADER NAME only selects a candidate; the finding needs the
#      VALUE to carry an INTERNAL IDENTITY - an RFC 1918 / loopback / link-local
#      / CGN IPv4 literal, or a reserved-internal DNS suffix.  A dotless token
#      (`varnish`, `cache-lhr7364-LHR`) is genuinely ambiguous between a product
#      name, a POP code and an internal hostname, so it is deliberately NOT
#      flagged.  `leak_internal_identity_in`.
#   3. EMAIL - naive: an `x@y.z` regex over the body.  That flags the contact
#      address the site published on purpose, and `logo@2x.png` in a srcset.
#      TECHNIQUE: three subtractions, in order - an address published as a
#      `mailto:` link is DELIBERATE and is excluded wherever else it also
#      appears; an RFC 2142-style role alias (`info@`, `support@`, ...) and the
#      standard placeholder localparts are excluded; and a "domain" whose final
#      label is a file extension is not a domain.  `leak_emails_in`.
#   4. JS CONFIG - naive: a `key: "value"` pair whose key contains "key" or
#      "token".  That flags the Stripe publishable key, the Google browser API
#      key and the analytics id - three values that are PUBLIC BY DESIGN and
#      appear in served JavaScript on purpose.
#      TECHNIQUE: an explicit ALLOW-LIST of known-public key names and value
#      prefixes is subtracted FIRST; what remains is flagged only on a
#      never-client-safe key NAME with a non-placeholder literal, or on a
#      high-confidence secret VALUE SHAPE.  `leak_js_config_in`.
#   5. THIRD-PARTY ORIGIN - naive: every absolute URL in the page is a third
#      party.  That flags the site's own CDN subdomain and its own absolute
#      self-links.
#      TECHNIQUE: subtract the response's own host and every host sharing its
#      registrable domain (approximated by the last two labels - see
#      `leak_same_site`, which errs toward NOT reporting).  `leak_origins_in`.
#
# NEVER A BARE `grep` (docs/FOUNDATION.md tension 4), AND IN FACT NO MATCH ENGINE
# AT ALL.  Nothing here shells out: a response body is read with bash's own
# `read` and decided with bash's own `[[ =~ ]]`, which cannot confuse "no match"
# with "the engine failed" - the failure mode that rule exists to prevent.  Every
# regex here uses POSIX bracket expressions only: `\b`, `\w`, `\s` and `\d` are
# GNU extensions that the system regcomp bash `=~` uses supports on Linux and
# does NOT support on macOS/BSD (AGENTS.md, "Things measured on this codebase"),
# so a pattern using them would silently match nothing on half the hosts this
# tool runs on.
#
# EVERYTHING PARSED HERE IS UNTRUSTED TARGET OUTPUT (tension 10).  It reaches a
# report only through `finding_set_evidence`, and `leak_safe_text` bounds it
# first.  A CANDIDATE SECRET IS NEVER CARRIED INTO EVIDENCE AT ALL - family 4
# reports the key name, the value's shape and its length, and never the value,
# because a finding that quotes the credential has copied it into the report,
# the shard file and the operator's terminal scrollback (tension 9's handling
# rules applied to a secret this tool found rather than one it was given).
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes header, URL and JS syntax
#   literally.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_LEAKAGE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_LEAKAGE_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint; a dast run does not otherwise load it, so the
# first phase that issues traffic sources it, guarded exactly as
# modules/dast/passive/headers_engine.sh and modules/dast/auth_engine.sh do.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# crawl_engine.sh for the frozen inventory flattener
# (docs/INVENTORY-FORMAT.md §7): the inventory is read THROUGH the same reader
# that wrote it.  Its own sourced-once guard makes this a no-op on a run where
# the crawl already happened.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"
# headers_engine.sh for its RESPONSE-HEADER READER ALONE - `hdr_parse_capture`,
# `hdr_present`, `hdr_value` and `hdr_first`.
#
# THIS IS REUSE, AND THE ALTERNATIVE WAS A SECOND COPY OF THE ONE PARSER IN THIS
# TIER THAT IS EASY TO GET WRONG.  `http_request_capture`'s header sink
# ACCUMULATES every redirect hop (lib/http.sh §9a: DAST-03 needs that for a
# login's `Set-Cookie`), so a reader that matches across the whole file reports
# the REDIRECT's header as the delivered response's - backwards for exactly the
# infrastructure headers family 2 looks at.  `hdr_parse_capture` resets on every
# status line and is measured against that reading in tests/suites/dast-headers.sh;
# writing a second one here would be re-earning that lesson, and would put two
# implementations of it in one directory for a later change to fix in one place.
#
# It is a PURE function library with a sourced-once guard and no side effects at
# source time, so sourcing it neither runs the header PHASE (that is
# `passive/headers.sh`, a separate file `dast_run_phase` reaches on its own) nor
# emits anything.  Sourcing it is deliberately NOT the "lift into a shared
# passive/response_engine.sh" that headers_engine.sh's own header asks a later
# ticket to do: that lift moves a peer's file AND its tests and is a refactor
# with an owner, which this ticket files as its own follow-up rather than
# performing under six parallel peers.
# shellcheck source=modules/dast/passive/headers_engine.sh
source "${BASH_SOURCE[0]%/*}/headers_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds and knobs
# ---------------------------------------------------------------------------
# docs/DESIGN.md §15: a bound that truncates silently is indistinguishable from
# a surface that was really that small, so every one of these records a
# coverage_gap or a coverage_reduction when it bites.

# How many distinct endpoints this phase requests.  Higher than the header
# phase's ten because leakage is genuinely per-response - a stack trace lives on
# one broken handler, not on the whole application - and lower than the whole
# inventory because re-fetching two hundred paths is a request storm the
# operator did not ask for.
: "${_LEAK_MAX_ENDPOINTS:=20}"
# Lines of any one response body inspected.  A minified bundle is one enormous
# line, so there is a byte cap too.
: "${_LEAK_MAX_BODY_LINES:=4000}"
# Bytes of any one response body inspected.
: "${_LEAK_MAX_BODY_BYTES:=262144}"
# Bytes of any one line inspected.  A minified bundle's single line is longer
# than this; it is chunked rather than truncated (see `leak_body_read`).
: "${_LEAK_MAX_LINE_BYTES:=4096}"
# Distinct third-party origins named in the roll-up finding evidence.
: "${_LEAK_MAX_ORIGINS_REPORTED:=25}"
# Bytes of any one target-derived string carried into an evidence sentence.
: "${_LEAK_MAX_EVIDENCE_FIELD:=160}"

# `leak_safe_text TEXT [MAX]` - bounded, single-line target-derived text for a
# diagnostic or an evidence sentence.  `finding_set_evidence` still does the
# real escaping and redaction (tension 9/10); this only stops one pathological
# 40 KiB line from becoming the report.
leak_safe_text() {
  local s=$1 max=${2:-$_LEAK_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# 1. The response-body reader
# ---------------------------------------------------------------------------
# `leak_body_read FILE` - reads a lib/http.sh BODY capture into `_LEAK_LINES[]`,
# and sets `_LEAK_NLINES`, `_LEAK_BYTES` and `_LEAK_BODY_TRUNCATED`.
#
# Returns 1 (leaving the array empty) when the file is unreadable or empty, so a
# caller can tell "no body" from "a body with nothing in it" - the distinction
# the whole honesty story rests on, exactly as `hdr_parse_capture` draws it one
# family over.
#
# A MINIFIED BUNDLE IS ONE LINE, AND CHUNKING IT IS NOT COSMETIC.  A whole
# webpack bundle arrives as a single 900 KiB line; truncating it at the line cap
# would inspect its first 4 KiB and silently declare the other 99% clean, which
# is precisely the overstated coverage docs/DESIGN.md §15 forbids.  Long lines
# are therefore SPLIT into `_LEAK_MAX_LINE_BYTES` chunks and every chunk is
# inspected.  A token straddling a chunk boundary is the cost, and it is the
# right direction to lose in: it can only cause a MISS, never a false positive,
# which is this family's stated bias.
leak_body_read() {
  local f=$1 line n=0 bytes=0 chunk rest
  declare -ga _LEAK_LINES=()
  declare -g _LEAK_NLINES=0 _LEAK_BYTES=0 _LEAK_BODY_TRUNCATED=0
  [[ -n $f && -r $f && -s $f ]] || return 1

  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    bytes=$(( bytes + ${#line} + 1 ))
    if (( bytes > _LEAK_MAX_BODY_BYTES )); then
      _LEAK_BODY_TRUNCATED=1
      break
    fi
    rest=$line
    while [[ -n $rest ]]; do
      chunk=${rest:0:_LEAK_MAX_LINE_BYTES}
      rest=${rest:_LEAK_MAX_LINE_BYTES}
      _LEAK_LINES+=("$chunk")
      n=$(( n + 1 ))
      if (( n >= _LEAK_MAX_BODY_LINES )); then
        _LEAK_BODY_TRUNCATED=1
        break 2
      fi
    done
    # A genuinely empty line still counts as inspected, so the caller's "did we
    # read anything" question has one answer.
    if [[ -z $line ]]; then
      n=$(( n + 1 ))
      (( n >= _LEAK_MAX_BODY_LINES )) && { _LEAK_BODY_TRUNCATED=1; break; }
    fi
  done <"$f"

  _LEAK_NLINES=${#_LEAK_LINES[@]}
  _LEAK_BYTES=$bytes
  (( _LEAK_NLINES > 0 ))
}

# `leak_ctype_kind CTYPE` - the coarse body class a family's applicability is
# decided on.  Prints one of `html`, `js`, `json`, `text`, `other`.
#
# THE CLASS IS WHAT MAKES "NOT EVALUATED" DIFFERENT FROM "CLEAN".  The JS-config
# family has nothing to say about a PNG, and reporting it as covered on a run
# that only ever fetched images would be a claim about a test that never
# happened.  The phase records a coverage_reduction naming every family no
# response was ever applicable to.
leak_ctype_kind() {
  local ct=${1,,}
  ct=${ct%%;*}
  ct=${ct#"${ct%%[![:space:]]*}"}
  ct=${ct%"${ct##*[![:space:]]}"}
  case $ct in
    text/html | application/xhtml+xml) printf 'html' ;;
    application/javascript | text/javascript | application/x-javascript | \
      application/ecmascript | text/ecmascript | module) printf 'js' ;;
    application/json | application/*+json | text/json) printf 'json' ;;
    # `text/xml` is deliberately NOT listed: `text/*` already covers it, and
    # a later duplicate arm would be dead code, which SC2222 flags (a comment
    # line may not START with the linter's name - it parses as a directive).
    text/* | application/xml) printf 'text' ;;
    '') printf 'other' ;;
    *) printf 'other' ;;
  esac
}

# ---------------------------------------------------------------------------
# 2. Family 1 - verbose error and stack-trace disclosure (CWE-209)
# ---------------------------------------------------------------------------
# `leak_stack_frame_in TEXT` - 0 when TEXT carries a STRUCTURED STACK FRAME or an
# unambiguous interactive-debugger banner.  Sets `_LEAK_STACK_KIND` (the runtime
# the shape belongs to) and `_LEAK_STACK_HIT` (the matched text, bounded).
#
# THE ENTIRE PRECISION OF THIS FAMILY IS THE WORD "STRUCTURED".  The naive check
# - "the body mentions error, exception, stack or a framework name" - fires on
# every branded 404 and every "an error occurred, please try again" page in
# existence, which makes the finding worthless and the report unreadable.  What
# distinguishes a leaked trace from a handled error page is that a trace carries
# a SOURCE LOCATION: a filesystem path and a line number from the server's own
# disk.  That is the thing an attacker harvests (framework, version, deployment
# layout, absolute paths, sometimes credentials in a query echo), and it is the
# thing a polite error page never has.  So every shape below anchors on a
# file:line pair, with exactly one deliberate exception - an INTERACTIVE
# debugger banner, which is worse than a trace (it usually offers a REPL) and is
# identified by a product string that only appears when the debugger is on.
#
# SQL DRIVER ERROR STRINGS ARE DELIBERATELY NOT HERE.  `SQLSTATE[`,
# `ORA-01756`, "You have an error in your SQL syntax" and their siblings are the
# error-based oracle modules/dast/active/sqli.sh (DAST-14) already owns and
# already emits `DAST-SQLI-*` findings for.  Matching them here would report one
# defect under two check ids, which the fingerprint cannot dedup because
# `check_id` is one of its own components.
leak_stack_frame_in() {
  local t=$1
  declare -g _LEAK_STACK_KIND='' _LEAK_STACK_HIT=''

  # Python: the banner, or a frame line.  The banner alone is enough - it is
  # never present on a rendered page that is not a traceback.
  if [[ $t == *'Traceback (most recent call last)'* ]]; then
    _LEAK_STACK_KIND=python
    _LEAK_STACK_HIT='Traceback (most recent call last)'
    return 0
  fi
  if [[ $t =~ File\ \"[^\"]+\",\ line\ [0-9]+ ]]; then
    _LEAK_STACK_KIND=python
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # JVM: `at pkg.Class.method(File.java:42)`.  The `(File.ext:NN)` suffix is the
  # anchor; `at` alone appears in ordinary English prose.
  if [[ $t =~ at\ [A-Za-z_\$][A-Za-z0-9_\$.]*\([A-Za-z0-9_\$]+\.(java|kt|scala|groovy):[0-9]+\) ]]; then
    _LEAK_STACK_KIND=jvm
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # Node / V8: `at fn (/srv/app/x.js:12:9)`.  Requires BOTH the line and the
  # column, which is what a V8 frame always carries and a prose sentence never
  # does.
  if [[ $t =~ at\ [^\(\)]*\(([A-Za-z]:)?[/\\][^\(\):]+:[0-9]+:[0-9]+\) ]]; then
    _LEAK_STACK_KIND=node
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # PHP / xdebug: `#0 /var/www/html/index.php(42): foo()`.
  if [[ $t =~ (^|[^0-9])#[0-9]+\ [/\\][^\(\)]+\([0-9]+\): ]]; then
    _LEAK_STACK_KIND=php
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # Ruby: `/app/controllers/x.rb:42:in `show'`.
  if [[ $t =~ [^[:space:]]+\.(rb|erb):[0-9]+:in\  ]]; then
    _LEAK_STACK_KIND=ruby
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # .NET: `at Ns.Cls.M() in C:\src\Cls.cs:line 42`.
  if [[ $t =~ \ in\ ([A-Za-z]:)?[^[:space:]]+:line\ [0-9]+ ]]; then
    _LEAK_STACK_KIND=dotnet
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # Go: the panic goroutine header.
  if [[ $t =~ ^goroutine\ [0-9]+\ \[[a-z\ ]+\]: ]]; then
    _LEAK_STACK_KIND=go
    _LEAK_STACK_HIT=${BASH_REMATCH[0]}
    return 0
  fi
  # The one non-file:line shape: an INTERACTIVE debugger, which is a worse
  # finding than a trace because it commonly offers code execution.  Each string
  # below is emitted only when the debugger is enabled.
  local b
  for b in 'Werkzeug Debugger' 'werkzeug.debug' 'Whoops\Run' 'Whoops\Handler' \
    'ActionView::Template::Error' 'Rails.root:' 'Symfony\Component\Debug' \
    'Symfony\Component\ErrorHandler' 'django.views.debug' \
    'You are seeing this error because you have DEBUG = True'; do
    if [[ $t == *"$b"* ]]; then
      _LEAK_STACK_KIND=debugger
      _LEAK_STACK_HIT=$b
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 3. Family 2 - upstream proxy / infrastructure header leakage (CWE-200)
# ---------------------------------------------------------------------------
# The response header names whose value CAN name an internal host.  Being on
# this list makes a header a CANDIDATE and nothing more; the finding needs
# `leak_internal_identity_in` to agree about the value.  Splitting it this way
# is what keeps the check off every site behind a public CDN.
declare -ga _LEAK_INFRA_HEADERS=(
  via
  x-backend
  x-backend-server
  x-served-by
  x-server
  x-server-name
  x-node
  x-host
  x-real-ip
  x-forwarded-for
  x-forwarded-host
  x-forwarded-server
  x-upstream
  x-upstream-addr
  x-upstream-server
  x-cache-server
  x-application-context
  x-nginx-upstream
)

# `leak_ipv4_is_internal ADDR` - 0 for an IPv4 literal in a range that only ever
# names infrastructure inside someone's perimeter: RFC 1918 (10/8, 172.16/12,
# 192.168/16), loopback (127/8), link-local (169.254/16), CGN (100.64/10) and
# 0/8.
#
# WHY THIS IS NOT JUST `_http_ipv4_denied`.  That function answers a DIFFERENT
# question - "may this tool open a connection to this address" - and its range
# set is deliberately narrower: it omits all three RFC 1918 blocks, because the
# scope gate handles those through a target's `allow-private-addresses` flag
# rather than by denying them outright.  10.0.0.0/8 is the single commonest
# internal address to find in a `Via` header, so reusing that function alone
# would miss the main case.  It is still CALLED, so the ranges the two share can
# never drift apart, and only the three RFC 1918 blocks are added here.
leak_ipv4_is_internal() {
  local ip=$1 a b c d
  local IFS=.
  read -r a b c d <<<"$ip"
  unset IFS
  [[ $a =~ ^[0-9]{1,3}$ && $b =~ ^[0-9]{1,3}$ && $c =~ ^[0-9]{1,3}$ && $d =~ ^[0-9]{1,3}$ ]] || return 1
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  # The three RFC 1918 blocks lib/http.sh's own deny list does not carry.
  (( a == 10 )) && return 0
  (( a == 172 && b >= 16 && b <= 31 )) && return 0
  (( a == 192 && b == 168 )) && return 0
  # Everything the gate already denies, read from the gate's own function.
  _http_ipv4_denied "$ip" && return 0
  return 1
}

# DNS suffixes that name a network's own inside.  `.local` is mDNS, `.internal`
# is the GCE/EC2 internal zone, `.svc.cluster.local` is Kubernetes, and
# `.home.arpa` is RFC 8375.  None of them resolve on the public internet, so a
# response naming one has disclosed a name that only exists behind the
# perimeter.
declare -ga _LEAK_INTERNAL_SUFFIXES=(
  .internal .local .localdomain .lan .intranet .corp .home.arpa
  .cluster.local .svc .in-addr.arpa
)

# `leak_internal_identity_in VALUE` - 0 when VALUE names an internal identity.
# Sets `_LEAK_IDENTITY` (the token that matched) and `_LEAK_IDENTITY_KIND`
# (`ipv4` or `dns`).
#
# THE DOTLESS TOKEN IS DELIBERATELY NOT AN INTERNAL IDENTITY, and this is the
# whole precision decision for this family.  `Via: 1.1 varnish` names a PRODUCT.
# `X-Served-By: cache-lhr7364-LHR` names a public CDN's edge POP, which that CDN
# publishes on purpose and which tells an attacker nothing about the origin.
# `X-Backend-Server: web03` names an internal host.  All three are a token with
# no dot in it, and NOTHING IN THE RESPONSE distinguishes them - so flagging the
# shape would flag every site behind a public CDN, and this check would be
# turned off by the first operator who ran it.  Only the two unambiguous signals
# are used: an address in a range that cannot be routed on the public internet,
# and a DNS suffix that cannot resolve there.  The cost is a real miss on
# `web03`, and it is accepted and stated rather than hidden.
leak_internal_identity_in() {
  local v=$1 tok host suf
  declare -g _LEAK_IDENTITY='' _LEAK_IDENTITY_KIND=''
  # A header value is a list; split on the separators a Via / X-Forwarded-For /
  # X-Served-By value actually uses.
  local t=${v//,/ }
  t=${t//;/ }
  for tok in $t; do
    # Strip a scheme, a userinfo, a port and any path, leaving the host.
    host=${tok#*://}
    host=${host##*@}
    host=${host%%/*}
    host=${host%%\?*}
    # An IPv6 literal in brackets, or a host:port.
    if [[ $host == \[*\]* ]]; then
      host=${host#\[}
      host=${host%%\]*}
    else
      host=${host%%:*}
    fi
    host=${host%.}
    [[ -n $host ]] || continue
    if [[ $host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      if leak_ipv4_is_internal "$host"; then
        _LEAK_IDENTITY=$host
        _LEAK_IDENTITY_KIND=ipv4
        return 0
      fi
      continue
    fi
    local lower=${host,,}
    for suf in "${_LEAK_INTERNAL_SUFFIXES[@]+"${_LEAK_INTERNAL_SUFFIXES[@]}"}"; do
      if [[ $lower == *"$suf" || $lower == *"$suf".* ]]; then
        _LEAK_IDENTITY=$host
        _LEAK_IDENTITY_KIND=dns
        return 0
      fi
    done
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Family 3 - email address disclosure (CWE-200)
# ---------------------------------------------------------------------------
# RFC 2142-style role aliases plus the standard placeholder localparts.  A role
# alias exists in order to be published - that is what makes it a role alias -
# so reporting one as a leak is reporting the site's own contact page.
declare -ga _LEAK_ROLE_LOCALPARTS=(
  abuse admin billing careers contact enquiries feedback help hello hostmaster
  info inquiries jobs legal mail marketing media newsletter noc no-reply
  noreply donotreply do-not-reply office orders postmaster press privacy sales
  security signup subscribe support team webmaster
  # Placeholder localparts, which are sample data rather than an address.
  email example name someone user you youremail your-email foo bar test
)

# A "domain" whose final label is one of these is a FILENAME.  `logo@2x.png` in
# an `srcset` matches every naive email regex ever written, and a report whose
# top finding is a retina image asset is a report nobody reads again.
declare -ga _LEAK_NOT_TLDS=(
  png jpg jpeg gif svg webp avif ico bmp css js mjs cjs map json html htm xml
  php asp aspx jsp woff woff2 ttf eot otf pdf zip gz txt md yml yaml
)

# `leak_emails_in TEXT` - appends every address in TEXT that is a genuine
# DISCLOSURE to `_LEAK_EMAILS` (deduped), and every address published as a
# `mailto:` link to `_LEAK_MAILTO` (also deduped).  Both arrays and the
# `_LEAK_EMAIL_SEEN` / `_LEAK_MAILTO_SEEN` maps are the CALLER's to reset, once
# per endpoint set, because the mailto subtraction below is only correct across
# a whole response rather than one line of it.
#
# TWO PASSES, AND THE ORDER IS THE POINT.  An address the site publishes as a
# `mailto:` link is deliberate publication, not leakage - so it must be excluded
# WHEREVER ELSE it appears in the same response, including from an HTML comment
# or a JSON blob further down the page.  A single-pass implementation cannot do
# that, because it meets the comment before it meets the contact link half the
# time.  `leak_emails_finish` is what applies the subtraction, after every line
# of every response has been scanned.
leak_emails_reset() {
  declare -ga _LEAK_EMAILS=() _LEAK_MAILTO=()
  declare -gA _LEAK_EMAIL_SEEN=() _LEAK_MAILTO_SEEN=() _LEAK_EMAIL_WHERE=()
}

# `_leak_email_candidates TEXT` - sets `_LEAK_CANDS` to the addresses in TEXT.
# Pure bash: the string is walked for `@`, then the local part is taken
# backwards and the domain forwards, because bash's `=~` gives one match per
# evaluation and a line can carry several addresses.
_leak_email_candidates() {
  local t=$1 rest lp dom c i
  declare -ga _LEAK_CANDS=()
  rest=$t
  while [[ $rest == *@* ]]; do
    lp=${rest%%@*}
    rest=${rest#*@}
    # Walk backwards off the end of `lp` for the local part's legal bytes.
    # Two lines, never `local n=... start=$n`: assignments in ONE `local` do
    # not see each other (AGENTS.md, "Things measured on this codebase"), so the
    # second would read an unset variable - fatal under `set -u`.
    local n=${#lp}
    local start=$n
    for (( i = n - 1; i >= 0; i-- )); do
      c=${lp:i:1}
      case $c in
        [A-Za-z0-9._%+-]) start=$i ;;
        *) break ;;
      esac
    done
    lp=${lp:start}
    # Walk forwards into `rest` for the domain's legal bytes.
    local m=${#rest} end=0
    for (( i = 0; i < m; i++ )); do
      c=${rest:i:1}
      case $c in
        [A-Za-z0-9.-]) end=$(( i + 1 )) ;;
        *) break ;;
      esac
    done
    dom=${rest:0:end}
    dom=${dom%.}
    dom=${dom%-}
    [[ -n $lp && -n $dom ]] || continue
    [[ $dom == *.* ]] || continue
    [[ $lp =~ ^[A-Za-z0-9] ]] || continue
    [[ $dom =~ ^[A-Za-z0-9] ]] || continue
    [[ $dom =~ \.[A-Za-z]{2,}$ ]] || continue
    _LEAK_CANDS+=("$lp@$dom")
  done
  return 0
}

# `leak_email_is_reportable ADDR` - 0 when ADDR is a candidate DISCLOSURE, i.e.
# it survives the role-alias, placeholder and file-extension subtractions.  The
# `mailto:` subtraction is applied later, in `leak_emails_finish`, because it
# needs the whole response.
leak_email_is_reportable() {
  local addr=${1,,} lp dom tld r x
  lp=${addr%@*}
  dom=${addr#*@}
  tld=${dom##*.}
  for x in "${_LEAK_NOT_TLDS[@]+"${_LEAK_NOT_TLDS[@]}"}"; do
    [[ $tld == "$x" ]] && return 1
  done
  # A localpart with a `+tag` is still the same alias.
  r=${lp%%+*}
  for x in "${_LEAK_ROLE_LOCALPARTS[@]+"${_LEAK_ROLE_LOCALPARTS[@]}"}"; do
    [[ $r == "$x" ]] && return 1
  done
  return 0
}

# `leak_emails_scan LINE WHERE` - one line of one response.  WHERE is a short
# label (the path) recorded against the first sighting of each address, so the
# finding can say where it came from.
leak_emails_scan() {
  local line=$1 where=$2 addr low
  # Pass 1: `mailto:` links, which are deliberate publication.
  local rest=$line seg
  while [[ $rest == *[Mm][Aa][Ii][Ll][Tt][Oo]:* ]]; do
    # Advance past the literal, case-insensitively, without a match engine.
    local idx=0 n=${#rest} found=-1
    for (( idx = 0; idx + 7 <= n; idx++ )); do
      seg=${rest:idx:7}
      if [[ ${seg,,} == 'mailto:' ]]; then found=$idx; break; fi
    done
    (( found < 0 )) && break
    rest=${rest:found+7}
    # The address is the run of legal bytes at the head of what follows.
    seg=${rest%%[\"\'\>\<\ ?&]*}
    _leak_email_candidates "@$seg"
    if (( ${#_LEAK_CANDS[@]} > 0 )); then
      low=${_LEAK_CANDS[0],,}
      if [[ -z ${_LEAK_MAILTO_SEEN[$low]:-} ]]; then
        _LEAK_MAILTO_SEEN[$low]=1
        _LEAK_MAILTO+=("$low")
      fi
    fi
  done
  # Pass 2: every address on the line.
  _leak_email_candidates "$line"
  for addr in "${_LEAK_CANDS[@]+"${_LEAK_CANDS[@]}"}"; do
    low=${addr,,}
    leak_email_is_reportable "$low" || continue
    [[ -n ${_LEAK_EMAIL_SEEN[$low]:-} ]] && continue
    _LEAK_EMAIL_SEEN[$low]=1
    _LEAK_EMAIL_WHERE[$low]=$where
    _LEAK_EMAILS+=("$low")
  done
  return 0
}

# `leak_emails_finish` - applies the `mailto:` subtraction and republishes
# `_LEAK_EMAILS` as the reportable set, sorted for a deterministic evidence
# sentence.  Sets `_LEAK_EMAILS_PUBLISHED` to how many were subtracted, so the
# finding can say "3 further addresses are published as contact links and are
# not reported" rather than silently dropping them.
leak_emails_finish() {
  local a out=() n=0
  for a in "${_LEAK_EMAILS[@]+"${_LEAK_EMAILS[@]}"}"; do
    if [[ -n ${_LEAK_MAILTO_SEEN[$a]:-} ]]; then
      n=$(( n + 1 ))
      continue
    fi
    out+=("$a")
  done
  declare -g _LEAK_EMAILS_PUBLISHED=$n
  declare -ga _LEAK_EMAILS=()
  local row
  while IFS= read -r row; do
    [[ -n $row ]] || continue
    _LEAK_EMAILS+=("$row")
  done < <(printf '%s\n' "${out[@]+"${out[@]}"}" | LC_ALL=C sort -u)
  return 0
}

# ---------------------------------------------------------------------------
# 5. Family 4 - client-config leakage in served JavaScript (CWE-540)
# ---------------------------------------------------------------------------
# KEY NAMES that are PUBLIC BY DESIGN in a browser.  A publishable key, an
# OAuth client id, an analytics measurement id and a reCAPTCHA site key are all
# meant to be readable by every visitor; the vendor documents them that way and
# the application cannot work without shipping them.  Reporting one is a false
# positive that costs the operator's trust in the other four families.
declare -ga _LEAK_PUBLIC_KEY_NAMES=(
  publishablekey publishable_key publickey public_key sitekey site_key
  measurementid measurement_id trackingid tracking_id gtmid gtm_id
  clientid client_id appid app_id projectid project_id authdomain auth_domain
  storagebucket storage_bucket messagingsenderid messaging_sender_id
  sentrydsn sentry_dsn dsn recaptchasitekey recaptcha_site_key
  pusherkey pusher_key mapsapikey maps_api_key
)

# VALUE PREFIXES that are public by design, whatever the key is called.
declare -ga _LEAK_PUBLIC_VALUE_PREFIXES=(
  'pk_live_' 'pk_test_' 'pk_' 'UA-' 'G-' 'GTM-' 'AW-' 'DC-' 'AIza' '6L'
  'pi_' 'whsec_test_'
)

# KEY NAMES that are NEVER client-safe.  A browser has no use for a secret, and
# a build pipeline that put one in a bundle has shipped a credential to every
# visitor.
declare -ga _LEAK_SECRET_KEY_NAMES=(
  secret secretkey secret_key apisecret api_secret clientsecret client_secret
  privatekey private_key password passwd pwd dbpassword db_password
  connectionstring connection_string awssecretaccesskey aws_secret_access_key
  secrettoken secret_token signingkey signing_key encryptionkey encryption_key
  masterkey master_key rootpassword root_password
)

# VALUE SHAPES that are a credential whatever they are called.  Each is a
# vendor-published, unambiguous prefix - a value carrying one of these is a
# secret by the vendor's own definition of its own format.
_leak_secret_value_shape() {
  local v=$1
  declare -g _LEAK_SECRET_SHAPE=''
  case $v in
    sk_live_* | sk_test_*) _LEAK_SECRET_SHAPE='a Stripe SECRET key (sk_ prefix; the browser-safe one is pk_)'; return 0 ;;
    rk_live_* | rk_test_*) _LEAK_SECRET_SHAPE='a Stripe restricted key'; return 0 ;;
    whsec_*) _LEAK_SECRET_SHAPE='a webhook signing secret'; return 0 ;;
    ghp_* | gho_* | ghs_* | ghu_* | github_pat_*) _LEAK_SECRET_SHAPE='a GitHub access token'; return 0 ;;
    xoxb-* | xoxp-* | xoxa-* | xoxr-* | xoxs-*) _LEAK_SECRET_SHAPE='a Slack API token'; return 0 ;;
    glpat-*) _LEAK_SECRET_SHAPE='a GitLab personal access token'; return 0 ;;
    'SG.'*) _LEAK_SECRET_SHAPE='a SendGrid API key'; return 0 ;;
    'npm_'*) _LEAK_SECRET_SHAPE='an npm access token'; return 0 ;;
    *'-----BEGIN '*'PRIVATE KEY-----'*) _LEAK_SECRET_SHAPE='a PEM-encoded private key'; return 0 ;;
    '-----BEGIN '*) _LEAK_SECRET_SHAPE='a PEM-encoded private key'; return 0 ;;
  esac
  if [[ $v =~ ^AKIA[0-9A-Z]{16}$ ]]; then
    _LEAK_SECRET_SHAPE='an AWS access key id (AKIA prefix)'
    return 0
  fi
  # A database or broker URL carrying an inline password.
  if [[ $v =~ ^(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps)://[^:/@]+:[^@/]+@ ]]; then
    _LEAK_SECRET_SHAPE='a database or broker connection string with an inline password'
    return 0
  fi
  return 1
}

# `leak_value_is_placeholder VALUE` - 0 for a value that is not a real secret:
# empty, a sentinel, a template hole a build step never filled, or too short to
# be a credential.
leak_value_is_placeholder() {
  local v=$1 low=${1,,}
  [[ -z $v ]] && return 0
  (( ${#v} < 8 )) && return 0
  case $v in
    '${'*'}' | '{{'*'}}' | '%'*'%' | '<'*'>' | 'process.env.'* | 'import.meta.env.'* | '$'[A-Z_]*) return 0 ;;
  esac
  case $low in
    null | undefined | none | false | true | changeme | change_me | changeit | \
      todo | tbd | placeholder | redacted | xxxxxxxx* | your*key* | your*secret* | \
      your*password* | 'my'*'secret'* | 'test'*'secret'* | example* | 'insert'*) return 0 ;;
  esac
  # A value of one repeated character carries no entropy.
  local first=${v:0:1}
  local squashed=${v//"$first"/}
  [[ -z $squashed ]] && return 0
  return 1
}

# `leak_js_config_in LINE` - appends every candidate client-config disclosure on
# LINE to `_LEAK_JSCFG` as `KEY<US>WHY<US>SHAPE<US>LEN`.  Reset by
# `leak_js_reset`.
#
# THE VALUE IS NEVER APPENDED, AND THAT IS THE POINT.  A finding that quotes the
# credential has copied it into the report, into the run's shard file and into
# the operator's scrollback - so what travels is the key name, a description of
# the shape that matched and the value's LENGTH, which is enough to find it in
# the bundle and not enough to use it.  `rules/redaction.rules` would redact
# many of these on the way out anyway; not carrying the value is the control
# that does not depend on the redaction list being complete.
leak_js_reset() {
  declare -ga _LEAK_JSCFG=()
  declare -gA _LEAK_JSCFG_SEEN=()
  declare -g _LEAK_JSCFG_PUBLIC=0
}

leak_js_config_in() {
  local line=$1 where=${2:-}
  local sep=$'\x1f'
  local rest=$line key val why shape
  # Walk `name` <sep> `"value"` pairs in the three shapes served JavaScript
  # actually uses: `"k":"v"` (JSON), `k: "v"` (object literal) and `k = "v"`
  # (assignment).  Single and double quotes both.
  local i n=${#line} c q
  for (( i = 0; i < n; i++ )); do
    c=${line:i:1}
    [[ $c == ':' || $c == '=' ]] || continue
    # The key: walk backwards over identifier bytes, then past an optional quote.
    local j=$i k='' ch
    j=$(( i - 1 ))
    while (( j >= 0 )) && [[ ${line:j:1} == ' ' || ${line:j:1} == $'\t' ]]; do j=$(( j - 1 )); done
    if (( j >= 0 )) && [[ ${line:j:1} == '"' || ${line:j:1} == "'" ]]; then j=$(( j - 1 )); fi
    while (( j >= 0 )); do
      ch=${line:j:1}
      case $ch in
        [A-Za-z0-9_.-]) k=$ch$k; j=$(( j - 1 )) ;;
        *) break ;;
      esac
    done
    [[ -n $k ]] || continue
    # The value: skip whitespace, require a quote, take to the closing quote.
    local p=$(( i + 1 ))
    while (( p < n )) && [[ ${line:p:1} == ' ' || ${line:p:1} == $'\t' ]]; do p=$(( p + 1 )); done
    (( p < n )) || continue
    q=${line:p:1}
    [[ $q == '"' || $q == "'" ]] || continue
    p=$(( p + 1 ))
    val=''
    while (( p < n )); do
      ch=${line:p:1}
      # SC1003: a single-quoted backslash is exactly one literal backslash,
      # which is what a JS string escape is.  Nothing here wants to escape a
      # quote.
      # shellcheck disable=SC1003
      if [[ $ch == '\' ]]; then
        val+=${line:p+1:1}
        p=$(( p + 2 ))
        continue
      fi
      [[ $ch == "$q" ]] && break
      val+=$ch
      p=$(( p + 1 ))
    done
    (( p < n )) || continue
    key=$k
    _leak_js_decide "$key" "$val" "$where"
  done
  return 0
}

# The decision for one key/value pair.  ALLOW-LIST FIRST: a public-by-design key
# is never reported, whatever else it also matches, because "this looks like a
# secret" is exactly what a publishable key is designed to look like.
_leak_js_decide() {
  local key=$1 val=$2 where=$3
  local low=${key,,} norm pfx x why='' shape=''
  norm=${low//-/_}
  # Take the last dotted segment: `window.cfg.apiSecret` is `apisecret`.
  local tail=${norm##*.}
  for x in "${_LEAK_PUBLIC_KEY_NAMES[@]+"${_LEAK_PUBLIC_KEY_NAMES[@]}"}"; do
    if [[ $tail == "$x" || $tail == *"$x" ]]; then
      _LEAK_JSCFG_PUBLIC=$(( _LEAK_JSCFG_PUBLIC + 1 ))
      return 0
    fi
  done
  for pfx in "${_LEAK_PUBLIC_VALUE_PREFIXES[@]+"${_LEAK_PUBLIC_VALUE_PREFIXES[@]}"}"; do
    if [[ $val == "$pfx"* ]]; then
      _LEAK_JSCFG_PUBLIC=$(( _LEAK_JSCFG_PUBLIC + 1 ))
      return 0
    fi
  done

  # A vendor-declared secret shape, whatever the key is called.
  if _leak_secret_value_shape "$val"; then
    why='the value has the shape of'
    shape=$_LEAK_SECRET_SHAPE
  else
    # A never-client-safe key name with a real literal behind it.
    local hit=''
    for x in "${_LEAK_SECRET_KEY_NAMES[@]+"${_LEAK_SECRET_KEY_NAMES[@]}"}"; do
      if [[ $tail == "$x" || $tail == *"_$x" || $tail == "$x"_* || $tail == *"$x" ]]; then
        hit=$x
        break
      fi
    done
    if [[ -n $hit ]]; then
      leak_value_is_placeholder "$val" && return 0
      why='the key name is never client-safe -'
      shape="a non-placeholder literal behind a '$hit' key"
    else
      # An internal service URL committed into the bundle.
      if [[ $val =~ ^https?:// ]] && leak_internal_identity_in "$val"; then
        why='the value is'
        shape="an internal service URL naming $_LEAK_IDENTITY, which is not reachable from the public internet and discloses the deployment's internal topology"
      else
        return 0
      fi
    fi
  fi

  local sep=$'\x1f'
  local id="$key$sep$shape"
  [[ -n ${_LEAK_JSCFG_SEEN[$id]:-} ]] && return 0
  _LEAK_JSCFG_SEEN[$id]=1
  _LEAK_JSCFG+=("$key$sep$why$sep$shape$sep${#val}$sep$where")
  return 0
}

# ---------------------------------------------------------------------------
# 6. Family 5 - third-party / CDN origin inventory (informational)
# ---------------------------------------------------------------------------
# `leak_same_site HOST SELF` - 0 when HOST is the response's own host or shares
# its registrable domain.
#
# THE REGISTRABLE DOMAIN IS APPROXIMATED BY THE LAST TWO LABELS, and the error
# is deliberately in the safe direction.  There is no Public Suffix List in this
# repository and vendoring one would be a data-freshness dependency the no-egress
# rule makes expensive (docs/FOUNDATION.md tension 25's whole argument, applied
# to a different table).  The approximation OVER-matches on a multi-label public
# suffix - it treats `a.co.uk` and `b.co.uk` as the same site - which means it
# UNDER-reports third parties.  For an informational inventory that is the right
# way to be wrong: a missing row is a smaller lie than a row asserting that a
# site's own CDN is somebody else's.  It is stated in the finding evidence, not
# only here.
leak_same_site() {
  local host=${1,,} self=${2,,} a b
  [[ -n $host && -n $self ]] || return 1
  [[ $host == "$self" ]] && return 0
  a=$host; b=$self
  # Last two labels of each.
  local ah=${a##*.} at=${a%.*}
  at=${at##*.}
  local bh=${b##*.} bt=${b%.*}
  bt=${bt##*.}
  [[ -n $at && -n $bt ]] || return 1
  [[ "$at.$ah" == "$bt.$bh" ]]
}

leak_origins_reset() {
  declare -ga _LEAK_ORIGINS=()
  declare -gA _LEAK_ORIGIN_SEEN=()
  declare -g _LEAK_ORIGINS_SAMESITE=0
}

# `leak_origins_in LINE SELFHOST` - appends every distinct third-party origin
# referenced on LINE to `_LEAK_ORIGINS`.  Scheme-relative (`//host/x`) counts;
# a relative path does not, because it is same-origin by construction.
leak_origins_in() {
  local line=$1 self=$2
  local i n=${#line} c host scheme origin
  for (( i = 0; i < n; i++ )); do
    scheme=''
    if [[ ${line:i:8} == 'https://' ]]; then
      scheme=https; i=$(( i + 8 ))
    elif [[ ${line:i:7} == 'http://' ]]; then
      scheme=http; i=$(( i + 7 ))
    elif [[ ${line:i:2} == '//' ]]; then
      # Scheme-relative, but only when what precedes it is a quote or an
      # attribute boundary - otherwise every `https://` already consumed above
      # and every `//` comment in the bundle would match.
      if (( i == 0 )) || [[ ${line:i-1:1} == '"' || ${line:i-1:1} == "'" || ${line:i-1:1} == '=' || ${line:i-1:1} == '(' ]]; then
        scheme=rel; i=$(( i + 2 ))
      else
        continue
      fi
    else
      continue
    fi
    host=''
    while (( i < n )); do
      c=${line:i:1}
      case $c in
        [A-Za-z0-9.:-]) host+=$c; i=$(( i + 1 )) ;;
        *) break ;;
      esac
    done
    i=$(( i - 1 ))
    host=${host%%:*}
    host=${host%.}
    [[ -n $host && $host == *.* ]] || continue
    [[ $host =~ ^[A-Za-z0-9] ]] || continue
    if leak_same_site "$host" "$self"; then
      _LEAK_ORIGINS_SAMESITE=$(( _LEAK_ORIGINS_SAMESITE + 1 ))
      continue
    fi
    [[ $scheme == rel ]] && scheme='//'
    origin="$scheme://$host"
    [[ $scheme == '//' ]] && origin="//$host"
    [[ -n ${_LEAK_ORIGIN_SEEN[${host,,}]:-} ]] && continue
    _LEAK_ORIGIN_SEEN[${host,,}]=1
    _LEAK_ORIGINS+=("${host,,}")
  done
  return 0
}

# ---------------------------------------------------------------------------
# 7. Choosing what to request (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `leak_endpoints_load [ENDPOINTS_FILE] [TARGET] [BASE_URL]` - publishes the URL
# list this phase requests in `_LEAK_URL[]`/`_LEAK_PATH[]`, and sets `_LEAK_N`,
# `_LEAK_TRUNCATED` and `_LEAK_SKIPPED_NON_GET`.
#
# The four decisions are `hdr_endpoints_load`'s and are deliberately identical,
# because they are properties of the tier rather than of a family: the
# operator's own `base-url` is always first and outside the sort (it is
# config-derived, it exists on every run, and being first keeps the finding
# location - and therefore the fingerprint - stable when the crawl reorders);
# GET only, because re-sending a discovered POST is a state change wearing a
# passive check's name; deduped by PATH TEMPLATE, since `/order/1` and
# `/order/2` are one handler; and sorted before the cap, so the chosen set is
# reproducible across runs.
#
# It is a SECOND COPY of that logic and not a call into it, for the reason
# headers_engine.sh's own header states: a shared `passive/*_engine.sh` is
# scaffolding several parallel tickets would each believe they owned, and
# lifting it is a refactor with an owner rather than a side effect of this
# landing.  The one substantive difference is the cap - see `_LEAK_MAX_ENDPOINTS`
# above for why leakage wants more endpoints than headers does.
leak_endpoints_load() {
  local epf=${1:-} target=${2:-} base=${3:-}
  local sep=$'\x1f' p type v idx key rest last_idx=''
  declare -ga _LEAK_URL=() _LEAK_PATH=()
  declare -g _LEAK_N=0 _LEAK_TRUNCATED=0 _LEAK_SKIPPED_NON_GET=0
  declare -gA _LEAK_TPL_SEEN=()

  if [[ -n $base ]]; then
    _leak_candidate_add "$base"
  fi

  if [[ -z $epf || ! -r $epf || ! -s $epf ]]; then
    _LEAK_N=${#_LEAK_URL[@]}
    return 0
  fi

  declare -ga _LEAK_ROWS=()
  local -A cur=()
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _leak_row_collect "${cur[url]:-}" "${cur[method]:-GET}" "${cur[target]:-}" "$target"
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    cur[$key]=$v
  done < <(crawl_json_flatten <"$epf" 2>/dev/null)
  if [[ -n $last_idx ]]; then
    _leak_row_collect "${cur[url]:-}" "${cur[method]:-GET}" "${cur[target]:-}" "$target"
  fi

  local row
  while IFS= read -r row; do
    [[ -n $row ]] || continue
    _leak_candidate_add "$row"
  done < <(printf '%s\n' "${_LEAK_ROWS[@]+"${_LEAK_ROWS[@]}"}" | LC_ALL=C sort -u)

  _LEAK_N=${#_LEAK_URL[@]}
  return 0
}

_leak_row_collect() {
  local url=$1 method=$2 row_target=$3 want_target=$4
  [[ -n $url ]] || return 0
  if [[ -n $row_target && -n $want_target && $row_target != "$want_target" ]]; then
    return 0
  fi
  if [[ ${method^^} != GET ]]; then
    _LEAK_SKIPPED_NON_GET=$(( _LEAK_SKIPPED_NON_GET + 1 ))
    return 0
  fi
  _LEAK_ROWS+=("$url")
  return 0
}

_leak_candidate_add() {
  local url=$1 path tpl
  path=$(leak_path_of "$url")
  tpl=$(path_template_of "$path")
  [[ -n ${_LEAK_TPL_SEEN[$tpl]:-} ]] && return 0
  if (( ${#_LEAK_URL[@]} >= _LEAK_MAX_ENDPOINTS )); then
    _LEAK_TRUNCATED=$(( _LEAK_TRUNCATED + 1 ))
    return 0
  fi
  _LEAK_TPL_SEEN[$tpl]=1
  _LEAK_URL+=("$url")
  _LEAK_PATH+=("$path")
  return 0
}

# The path component of a URL, query and fragment removed.  A URL with no path
# is `/`.
leak_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# The host component of a URL, userinfo and port removed.
leak_host_of() {
  local url=$1 rest
  rest=${url#*://}
  rest=${rest%%/*}
  rest=${rest##*@}
  if [[ $rest == \[*\]* ]]; then
    rest=${rest#\[}
    rest=${rest%%\]*}
  else
    rest=${rest%%:*}
  fi
  printf '%s' "${rest,,}"
}
