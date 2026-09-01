#!/usr/bin/env bash
# tests/suites/dast-transport.sh - modules/dast/passive/transport.sh and
# modules/dast/passive/transport_engine.sh: the transport-exposure family
# (docs/DESIGN.md §7.4's `transport.sh` bullet; docs/STEP5-DAST-PLAN.md
# DAST-30).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and the whole suite is driven
# from RECORDED RESPONSES - a table of header blocks and bodies this file
# writes, replayed into lib/http.sh's own capture sinks exactly as curl would
# write them (docs/DESIGN.md §12: "DAST logic is testable with no live
# target").  It runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing.  The readings pinned here:
#
#   1. a plaintext <a href> is NOT mixed content.  Flagging every `http://`
#      string in the markup is the naive reading and it fires on every external
#      link on the page.
#   2. a PROTOCOL-RELATIVE (`//host/x`) or ROOT-RELATIVE (`/x`) reference on an
#      HTTPS page inherits https and is NOT mixed content.  Pinned in two
#      halves, because a mutation run showed the obvious single assertion pins
#      nothing: the OUTCOME (no finding) is asserted through the phase, and the
#      MECHANISM (the reference is resolved and counted, not skipped for having
#      no scheme) is asserted on `_TR_REF_TOTAL` - findings alone cannot
#      distinguish resolving from skipping, since only an absolute `http://`
#      reference can be mixed content in the first place.
#   3. active and passive mixed content are separate check ids at separate
#      severities, because browsers block one and merely warn on the other.
#   4. an `http://` URL is requested with ZERO redirect hops.  Letting
#      `http_request` follow the redirect makes a correct 301-to-HTTPS and a
#      page served on port 80 both report `200`.
#   5. a 301 to another `http://` URL, and a scheme-relative Location, are NOT
#      redirects to TLS - the naive "is it a 3xx" reading passes both.
#   6. plaintext EXPOSURE and no-TLS-REDIRECT are different checks.  A plain
#      marketing page over http gets the transport finding and NOT the
#      sensitive-exposure one.
#   7. the endpoint dedup key is (SCHEME, path template).  Borrowing
#      `hdr_endpoints_load`'s path-template-only key drops the plaintext twin of
#      an HTTPS endpoint, which IS the finding.
#   8. one finding per check per target, with the affected/tested count in the
#      evidence - not one per endpoint.  BOTH endpoints in that case must
#      actually exhibit the defect, or a per-endpoint emitter yields one finding
#      too and the assertion is blind; the fixture and a `2 of the 3`
#      precondition assertion now enforce that.
#   9. a reference inside an HTML COMMENT is loaded by nothing and is not a
#      finding.
#  10. mixed-content checks are DOCUMENT-only; a JSON response over HTTPS makes
#      them inapplicable rather than clean.
#  11. `transport_check_not_applicable` is recorded when no HTTPS response was
#      observed - "nothing was mixed" is never "nothing was testable".
#  12. an out-of-scope inventory URL is skipped, never handed to `http_request`
#      (which would abort the whole run with exit 3).
#  13. the phase is registered at tier `passive`, so a plain
#      `scan.sh dast --target <t>` reaches it.  Pinned by the _DAST_PHASES scan;
#      the `dast_run_phase` pair beside it proves REACHABILITY at the default
#      intensity and its `active` complement shows what the row would have cost,
#      since that function takes its tier from the spec argument rather than
#      from the table.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes URL and markup syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh
# -> lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and
# traps. Real edge: every OTHER mention of transport_engine.sh/transport.sh
# in this file is either already a /dev/null cut or sits inside the
# mutation-script heredoc below (an unanalysed string, not a followed edge),
# so this is the only real copy - measured via tests/lint-source-graph.sh's
# own walker, not assumed.
# shellcheck source=modules/dast/passive/transport_engine.sh
source "$ROOT/modules/dast/passive/transport_engine.sh"
# modules/dast/engine.sh supplies the phase table (`_DAST_PHASES`) and
# `dast_run_phase`, which section E asserts this ticket's row against.  It is
# sourced here rather than in that section so the whole suite runs under one
# load of the module, exactly as a real dispatch would.
# shellcheck source=modules/dast/engine.sh
source "$ROOT/modules/dast/engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-transport-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
# `tr-fixture` must be reachable over BOTH schemes on one host, which is what
# the plaintext-twin cases need.  That comes from lib/http.sh's own documented
# https->http:80 relaxation in `http_scope_match` rather than from a second
# scope entry - the same way a real operator's single `base-url` admits the
# plaintext origin these checks exist to inspect.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: tr-fixture
base-url: https://tr.fixture.example/
notes: Fixture target for tests/suites/dast-transport.sh. Never dialled: both
  the resolver and the transport are stubbed. The plaintext twin of this origin
  is in scope through lib/http.sh's own documented https->http:80 relaxation
  (http_scope_match), which is exactly the relaxation the plaintext checks below
  rely on in a real run - so it is exercised here rather than worked around with
  an extra-host entry.

id: tr-plain
base-url: http://plain.fixture.example/
notes: Plaintext-only fixture target, for the no-HTTPS-response applicability
  case.

id: tr-secure
base-url: https://secure.fixture.example/
notes: HTTPS-only fixture target, for the no-plaintext-response case and for
  the clean-document case.

id: tr-dead
base-url: https://dead.fixture.example/
notes: Fixture target whose transport always fails, for the "no response was
  readable" coverage-gap case.

id: tr-api
base-url: https://api.fixture.example/
notes: HTTPS-only fixture target every one of whose responses is JSON, for the
  document-only applicability case. It needs a target of its own because
  tr_endpoints_load always requests the base-url, so any target whose front
  door is HTML would make at least one HTTPS DOCUMENT observed and the
  mixed-content checks applicable after all.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

# A high request rate AND the authorization affirmation, so the DAST-32 ceiling
# does not clamp the rate and the throttle never real-sleeps.
cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_tr_resolve() {
  case $1 in
    tr.fixture.example | plain.fixture.example | secure.fixture.example | api.fixture.example | dead.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_tr_resolve

# ---------------------------------------------------------------------------
# The recorded responses.
# ---------------------------------------------------------------------------
# `_body <host> <path>` prints the recorded response BODY and `_head` the
# recorded response HEAD, exactly as curl writes them.  The transport below
# replays both into lib/http.sh's own sinks; nothing is invented at read time.

# An HTTPS document loading every class of plaintext sub-resource, plus the
# three shapes that must NOT be reported: a protocol-relative reference, a
# root-relative one, and a plaintext <a href>.
MIXED_ALL=$(cat <<'HTML'
<html><head>
<script src="http://cdn.example/app.js"></script>
<link rel="stylesheet" href="http://cdn.example/main.css">
<!-- <script src="http://commented.example/nope.js"></script> -->
</head><body>
<img src="http://img.example/logo.png">
<img src="//cdn.example/protocol-relative.png">
<img src="/local/root-relative.png">
<iframe src="http://frames.example/widget"></iframe>
<a href="http://external.example/page">an ordinary hyperlink</a>
<form action="http://forms.example/subscribe" method="POST"></form>
</body></html>
HTML
)

# An HTTPS document whose only http:// string is a hyperlink.  Reading 1: this
# must produce NO mixed-content finding of any kind.
NAV_ONLY=$(cat <<'HTML'
<html><body>
<a href="http://external.example/one">one</a>
<a href="http://external.example/two">two</a>
<img src="https://img.example/ok.png">
<script src="/app.js"></script>
</body></html>
HTML
)

# An HTTPS document with only protocol-relative and relative references.
# Reading 2: these inherit https and must produce NO finding.
RELATIVE_ONLY=$(cat <<'HTML'
<html><head>
<script src="//cdn.example/app.js"></script>
<link rel="stylesheet" href="/main.css">
</head><body>
<img src="assets/pic.png">
<iframe src="//frames.example/w"></iframe>
</body></html>
HTML
)

# An HTTPS document whose <base href> is a PLAINTEXT origin and whose own
# references are all relative.  Every one of them is therefore loaded over
# http://, and a check that resolved against the document URL instead of the
# base would report the page clean.
BASE_RETARGET=$(cat <<'HTML'
<html><head>
<base href="http://cdn.example/assets/">
<script src="app.js"></script>
<link rel="stylesheet" href="main.css">
</head><body>
<img src="logo.png">
</body></html>
HTML
)

# A plaintext login page: a password control makes it sensitive.
PLAIN_LOGIN=$(cat <<'HTML'
<html><body>
<form action="/session" method="POST">
<input type="text" name="email">
<input type="password" name="password">
</form>
</body></html>
HTML
)

# A plaintext page with nothing sensitive on it at all.  Reading 6: this gets
# the transport finding and NOT the exposure one.
PLAIN_BROCHURE='<html><body><h1>About us</h1><p>We make things.</p></body></html>'

# A document with no plaintext reference of any kind.  `/` MUST be this,
# because `tr_endpoints_load` always requests the target's own base-url first
# (and deliberately so - see its header), so every case below fetches `/` in
# addition to the URL it names.  Serving the mixed document there would
# contaminate every other case with the mixed one's findings, and a per-check
# case would then be asserting about a page it never chose.  The identical
# reason `tests/suites/dast-headers.sh` makes ITS base-url response fully
# hardened.
CLEAN_DOC=$(cat <<'HTML'
<html><head>
<script src="https://cdn.example/app.js"></script>
<link rel="stylesheet" href="/main.css">
</head><body>
<img src="https://img.example/ok.png">
<a href="https://external.example/page">a secure hyperlink</a>
</body></html>
HTML
)

_body() {
  local host=$1 path=$2
  case $host:$path in
    # BOTH paths serve the mixed document, and the second one is not
    # decoration: the "one finding per check per target" case below needs TWO
    # endpoints that each EXHIBIT the defect, or a per-endpoint emitter produces
    # exactly one finding too and the assertion passes under the very reading it
    # claims to fail under.  A `case` arm is a glob, not a prefix, so
    # `tr.fixture.example:/mixed` alone does NOT match `/mixed2` - it fell
    # through to CLEAN_DOC, which is precisely how that assertion came to pin
    # nothing.  `path_template_of` keeps the two paths distinct, so they survive
    # tr_endpoints_load's dedup as two candidates.
    tr.fixture.example:/mixed | tr.fixture.example:/mixed2) printf '%s' "$MIXED_ALL" ;;
    tr.fixture.example:/nav) printf '%s' "$NAV_ONLY" ;;
    tr.fixture.example:/based) printf '%s' "$BASE_RETARGET" ;;
    tr.fixture.example:/relative) printf '%s' "$RELATIVE_ONLY" ;;
    tr.fixture.example:/api | tr.fixture.example:/zjson) printf '%s' '{"ok":true,"note":"http://not-a-load.example/x"}' ;;
    tr.fixture.example:/login) printf '%s' "$PLAIN_LOGIN" ;;
    tr.fixture.example:/brochure) printf '%s' "$PLAIN_BROCHURE" ;;
    # The JSON body deliberately EMBEDS HTML-shaped markup carrying two
    # plaintext sub-resources.  A body with no markup at all would make the
    # document-only assertions below pass for the WRONG REASON - tr_html_scan
    # would emit nothing whether or not the hdr_is_document gate existed - so
    # the gate itself would be untested.  With this body, removing the gate
    # produces real findings and those assertions go red.
    #
    # The attributes are SINGLE-quoted, via a `tr` of a placeholder because this
    # is inside a single-quoted shell string.  Writing them as JSON-escaped
    # \" instead does not work and is worth knowing: the extractor then reads
    # the value as an UNQUOTED attribute and captures the backslash-quote as
    # part of the URL, so it no longer looks absolute, resolves relative to the
    # document, and comes back https - which quietly restores the wrong-reason
    # pass this fixture exists to remove.
    api.fixture.example:*) printf '%s' '{"ok":true,"template":"<script src=@http://internal.example/svc.js@></script><img src=@http://internal.example/px.png@>"}' | tr '@' "'" ;;
    plain.fixture.example:/login) printf '%s' "$PLAIN_LOGIN" ;;
    plain.fixture.example:*) printf '%s' "$PLAIN_BROCHURE" ;;
    *) printf '%s' "$CLEAN_DOC" ;;
  esac
}

REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

# The transport.  Its signature is lib/http.sh's own:
#   METHOD SCHEME HOST PORT PATH ADDR [BODY_OUT] [HEADERS_OUT]
# and it prints status, Location and Content-Type on up to three lines.  The
# header block is APPENDED, matching the real transport's accumulate-per-hop
# behaviour that `hdr_parse_capture` exists to unwind.
_tr_transport() {
  local method=$1 scheme=$2 host=$3 path=$5
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local hdrsout=${8:-${_HTTP_TX_HEADERS_OUT:-}}
  local status=200 location='' ctype='text/html; charset=utf-8' extra=''
  # The one JSON response, for the document-only reading.  Set BEFORE the header
  # block is written: `hdr_first content-type` reads the CAPTURE, not this
  # function's return lines, so a Content-Type decided afterwards would never
  # reach the code under test.
  # `/zjson` is `/api` under a name that sorts AFTER `/nav`, because
  # tr_endpoints_load sorts its candidates and the carry-over case below needs
  # the NON-DOCUMENT response to follow the link-bearing one.
  [[ $path == /api || $path == /zjson || $host == api.fixture.example ]] && ctype='application/json'

  if [[ $scheme == http ]]; then
    case $host:$path in
      # The correct answer: 301 straight to the https:// twin.
      tr.fixture.example:/good) status=301; location='https://tr.fixture.example/good'; ctype='' ;;
      # Reading 5a: a 3xx that lands on another http:// URL is not a TLS
      # redirect.  A "is it a 3xx" check passes this.
      tr.fixture.example:/hophttp) status=301; location='http://www.tr.fixture.example/hophttp'; ctype='' ;;
      # Reading 5b: a scheme-relative Location inherits http://.
      tr.fixture.example:/schemerel) status=302; location='//tr.fixture.example/schemerel'; ctype='' ;;
      tr.fixture.example:/noloc) status=301; location=''; ctype='' ;;
      # A plaintext response that issues a session cookie.
      tr.fixture.example:/cookie) extra=$'Set-Cookie: sid=abc123; Path=/\r\n' ;;
    esac
  fi

  printf '%s %s://%s%s\n' "$method" "$scheme" "$host" "$path" >>"$REQ_LOG"
  # A transport-level failure: no usable response at all, which is what
  # `http_request` reports by returning non-zero (lib/http.sh §12).
  [[ $host == dead.fixture.example ]] && return 1

  if [[ -n $hdrsout ]]; then
    { printf 'HTTP/1.1 %s X\r\n' "$status"
      [[ -n $ctype ]] && printf 'Content-Type: %s\r\n' "$ctype"
      [[ -n $location ]] && printf 'Location: %s\r\n' "$location"
      [[ -n $extra ]] && printf '%s' "$extra"
      printf '\r\n'
    } >>"$hdrsout"
  fi
  if [[ -n $bodyout ]]; then
    if [[ $status =~ ^3 ]]; then
      : >"$bodyout"
    else
      _body "$host" "$path" >"$bodyout"
    fi
  fi
  printf '%s\n%s\n%s\n' "$status" "$location" "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_tr_transport

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target "${2:-tr-fixture}"
  occurrence_reset_all
  _req_reset
}

# `_inv NAME TARGET URL...` writes an endpoints.json naming each URL and prints
# its path.  The shape is docs/INVENTORY-FORMAT.md's, written the way a
# conformant producer other than crawl.sh might - so the reader is exercised
# through the frozen flattener rather than against crawl.sh's exact bytes.
_inv() {
  local name=$1 target=$2; shift 2
  local f=$W/$name.endpoints.json u i=0 rows=''
  for u in "$@"; do
    rows+="${rows:+,}"$'\n'"  { \"id\": \"ep$i\", \"target\": \"$target\", \"method\": \"GET\", \"url\": \"$u\", \"path\": \"$(hdr_path_of "$u")\" }"
    i=$(( i + 1 ))
  done
  printf '{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [%s\n] }\n' "$rows" >"$f"
  printf '%s' "$f"
}

_count_check() {
  local check=$1 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && { n=$(( n + 1 )); break; }
      done
    done <"$f"
  done
  printf '%s' "$n"
}

_field_of() {
  local check=$1 want=$2 f line fld hit='' out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      hit='' out=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hit=1
        [[ $fld == "$want="* ]] && out=${fld#"$want="}
      done
      [[ -n $hit ]] && { printf '%s' "$out"; return 0; }
    done <"$f"
  done
  printf ''
}

_meta() { run_facts "$1" 2>/dev/null || printf ''; }

# `_run_case NAME TARGET [URL...]` - a fresh run, an inventory of the given
# URLs, and one invocation of the phase.  The phase is `source`d exactly as
# `dast_run_phase` sources it.
_run_case() {
  local name=$1 target=$2; shift 2
  _new_run "$name" "$target"
  if (( $# > 0 )); then
    SCOURSH_DAST_ENDPOINTS=$(_inv "$name" "$target" "$@")
  else
    SCOURSH_DAST_ENDPOINTS=''
  fi
  export SCOURSH_DAST_ENDPOINTS
  SCOURSH_DAST_TARGET=$target
  export SCOURSH_DAST_TARGET
  # -x back-edge cut: modules/dast/passive/transport.sh
  # is already inlined elsewhere in this file's own source graph, and shellcheck
  # re-expands EVERY source edge it follows.  Cutting this one loses no checking
  # and is what keeps the linter's memory bounded - see the shellcheck stage in
  # tests/run-tests.sh, and docs/CI-RUNBOOK.md.
  # shellcheck source=/dev/null
  source "$ROOT/modules/dast/passive/transport.sh"
}

# ===========================================================================
printf '== A. the sub-resource extractor and reference resolution ==\n'
# ===========================================================================
t_case 'every sub-resource class is extracted, and a hyperlink is a class of its own'
EX=$W/extract.html
printf '%s\n' "$MIXED_ALL" >"$EX"
OUT=$(tr_html_scan <"$EX")
assert_contains "$OUT" $'ref\tactive\tscript\thttp://cdn.example/app.js' \
  'a <script src> is extracted - FAILS under reusing crawl_html_extract, which skips <script> elements wholesale and would never see the archetypal blockable reference'
assert_contains "$OUT" $'ref\tactive\tlink\thttp://cdn.example/main.css' \
  'a <link rel=stylesheet href> is classed ACTIVE, because a stylesheet restyles the document'
assert_contains "$OUT" $'ref\tpassive\timg\thttp://img.example/logo.png' \
  'an <img src> is classed PASSIVE - FAILS under crawl_html_extract, which emits no record for <img> at all'
assert_contains "$OUT" $'ref\tactive\tiframe\thttp://frames.example/widget' \
  'an <iframe src> is classed ACTIVE'
assert_contains "$OUT" $'ref\tform\tform\thttp://forms.example/subscribe' \
  'a <form action> is its own class, because the defect is what LEAVES the browser'
assert_contains "$OUT" $'ref\tnav\ta\thttp://external.example/page' \
  'an <a href> is extracted as class `nav` - it must be EMITTED so its absence from the findings can be asserted, rather than dropped where nothing could tell a decision from an oversight'

t_case 'a reference inside an HTML comment is not a reference'
assert_not_contains "$OUT" 'commented.example' \
  'reading 9: a commented-out <script src="http://..."> loads nothing and is not a finding - FAILS under a line-oriented match for `http://` over the raw body, which cannot see comments at all'

t_case 'protocol-relative and root-relative references resolve to the document scheme'
assert_eq 'https://cdn.example/protocol-relative.png' \
  "$(crawl_url_resolve 'https://tr.fixture.example/' '//cdn.example/protocol-relative.png')" \
  'reading 2: `//host/x` on an HTTPS page IS https - FAILS under reading the raw attribute, which would see no scheme and could only guess'
assert_eq 'https://tr.fixture.example/local/root-relative.png' \
  "$(crawl_url_resolve 'https://tr.fixture.example/' '/local/root-relative.png')" \
  'a root-relative reference inherits the document scheme and host'

t_case 'a relative reference is RESOLVED and counted, not skipped for having no scheme'
# This is the case that actually discriminates resolution from the naive
# alternative, and it took a mutation run to find: simply SKIPPING any
# reference without an explicit scheme produces the same FINDINGS as resolving
# one, because only an absolute `http://` reference can ever be mixed content on
# an https page.  What it does not produce is the same ACCOUNTING.
# `_TR_REF_TOTAL` is "references this check could actually judge", and under the
# skip it silently becomes "references that happened to be written absolutely" -
# so a page whose every sub-resource is relative reports zero references
# examined while looking exactly like a page that was fully inspected.
REL=$W/relative.html
printf '%s\n' "$RELATIVE_ONLY" >"$REL"
tr_mixed_scan "$REL" 'https://tr.fixture.example/relative'
assert_eq 4 "$_TR_REF_TOTAL" \
  'all four references - two protocol-relative, one root-relative, one path-relative - are resolved against the document URL and counted as judged. FAILS under classifying the RAW attribute and skipping anything with no scheme of its own, which counts 0 here and so cannot tell "inspected, all secure" from "inspected nothing"'
assert_eq 0 "${_TR_MIX_N[active]:-0}" 'and none of them is a finding, because each inherits the document https scheme'

t_case 'the redirect verdict tells a TLS redirect from the three that are not'
tr_redirect_verdict 301 'https://h/x'; assert_eq to_https "$_TR_REDIR_VERDICT" 'a 301 to https:// is the correct answer'
tr_redirect_verdict 301 'http://h/x'; assert_eq to_http "$_TR_REDIR_VERDICT" \
  'reading 5a: a 301 to another http:// URL is NOT a TLS redirect - FAILS under "any 3xx counts", which is the obvious implementation'
tr_redirect_verdict 302 '//h/x'; assert_eq relative "$_TR_REDIR_VERDICT" \
  'reading 5b: a scheme-relative Location inherits http:// and stays in the clear - FAILS under "any 3xx counts" too'
tr_redirect_verdict 301 ''; assert_eq unknown "$_TR_REDIR_VERDICT" 'a 3xx with no Location redirects nowhere'
tr_redirect_verdict 200 ''; assert_eq none "$_TR_REDIR_VERDICT" 'a 200 on the plaintext origin is content served in the clear'

t_case 'the endpoint dedup key is (scheme, path template), not the path template alone'
EPF=$(_inv dedup tr-fixture 'https://tr.fixture.example/login' 'http://tr.fixture.example/login')
tr_endpoints_load "$EPF" tr-fixture ''
assert_eq 2 "$_TR_N" \
  'reading 7: the http:// and https:// twins of one path are TWO candidates - FAILS under hdr_endpoints_load key (the path template alone), which collapses them to one and so drops the plaintext twin that IS the finding'

# ===========================================================================
printf '== B. mixed content, through the real phase ==\n'
# ===========================================================================
t_case 'each mixed-content class is reported as its own check, once'
_run_case mixed tr-fixture 'https://tr.fixture.example/mixed'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'the blockable references (script, stylesheet, iframe) are ONE active finding'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_PASSIVE-01)" \
  'reading 3: the <img> is a SEPARATE check from the active ones - FAILS under one DAST-TRANSPORT-MIXED-01 id, which would collide on the fingerprint (the DAST location profile carries no component naming the defect) and dedupe two real findings to one'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_FORM-01)" \
  'the plaintext <form action> is its own check'
EVI=$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 evidence)
assert_contains "$EVI" 'http://cdn.example/app.js' 'the offending script URL is named in the evidence'
assert_contains "$EVI" 'http://frames.example/widget' 'and so is the iframe'

t_case 'severity separates blockable from optionally-blockable mixed content'
assert_eq high "$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 base_severity)" \
  'active mixed content is high - a browser blocks it, so the feature is already broken AND the reference could execute in-origin'
assert_eq low "$(_field_of DAST-TRANSPORT-MIXED_PASSIVE-01 base_severity)" \
  'reading 3: passive mixed content is LOW - FAILS under one severity for the whole family, which would either inflate every mixed image to high or understate a mixed script'

t_case 'a plaintext hyperlink is NOT mixed content'
_run_case nav tr-fixture 'https://tr.fixture.example/nav'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'reading 1: two <a href="http://..."> links and nothing else produce NO active finding - FAILS under matching `http://` anywhere in the body, which is the naive implementation and fires on every external link on the page'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_PASSIVE-01)" 'and no passive finding'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_FORM-01)" 'and no form finding'
assert_contains "$(_meta notes)" 'plaintext_navigation_links=2' \
  'the links are counted and STATED as a deliberate non-finding, so an operator who can see them in their own markup knows this phase looked and decided'

t_case 'the plaintext-link count is not carried over from the previous response'
# `_TR_NAV_PLAINTEXT` is a global that `tr_mixed_scan` resets - but
# `_tr_analyse_https` returns EARLY, before calling it, for a NON-DOCUMENT
# response.  Reading it after such a response adds the previous document's count
# again.  This case fetches the two-link page and then a JSON endpoint, so the
# bug is visible as a doubled count rather than as a wrong finding, which is
# exactly the kind that survives review.
_run_case navthenjson tr-fixture 'https://tr.fixture.example/nav' 'https://tr.fixture.example/zjson'
assert_contains "$(_meta notes)" 'plaintext_navigation_links=2' \
  'the count is 2, the number of links on the one page that had any - FAILS without zeroing _TR_NAV_PLAINTEXT before each response, which reports 4 because the JSON response never reached the reset inside tr_mixed_scan'

t_case 'protocol-relative and relative references produce no finding'
_run_case relative tr-fixture 'https://tr.fixture.example/relative'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'reading 2: `//cdn.example/app.js` and `/main.css` on an HTTPS page are https, so neither is reported. This is the OUTCOME half of reading 2; the mechanism half - that they are resolved rather than skipped - is pinned in section A on _TR_REF_TOTAL, because findings alone cannot tell the two apart'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_PASSIVE-01)" 'and the relative <img> is not reported either'

t_case 'a plaintext <base href> retargets every relative reference on the page'
_run_case based tr-fixture 'https://tr.fixture.example/based'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'the relative script and stylesheet resolve against the plaintext <base>, so they ARE mixed content - FAILS without honouring <base href>, which resolves them against the document URL instead and reports a wholly-mixed page as clean. That is a silent FALSE NEGATIVE on the one element that can make a whole page mixed at once'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_PASSIVE-01)" 'and the relative <img> too'
assert_contains "$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 evidence)" 'http://cdn.example/assets/app.js' \
  'the evidence names the RESOLVED URL, which is where the browser actually goes, rather than the bare "app.js" that appears in the markup'
assert_contains "$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 evidence)" '<base href=' \
  'and it names the <base> element as the likely single fix, rather than leaving the operator to change every reference'

t_case 'mixed-content checks are DOCUMENT-only'
_run_case jsonapi tr-api 'https://api.fixture.example/api'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'reading 10: a JSON response loads no sub-resources, so an `http://` string in its body is not mixed content - FAILS under scanning every response body regardless of Content-Type'
assert_contains "$(_meta coverage_reduction)" 'transport_check_not_applicable' \
  'and the three mixed-content checks are recorded NOT APPLICABLE rather than passing silently'
assert_contains "$(_meta coverage_reduction)" 'https_documents=0' \
  'the reduction says how many HTTPS DOCUMENTS were seen, which is the number that made the checks inapplicable'
assert_not_contains "$(_meta checks_run)" 'DAST-TRANSPORT-MIXED_ACTIVE-01' \
  'an inapplicable check is never in checks_run - reporting it would tell tension 12 the target was covered for a control nothing tested'

t_case 'a clean HTTPS document produces no finding but IS covered'
_run_case clean tr-secure 'https://secure.fixture.example/'
assert_eq 0 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" 'nothing to report on a document with no plaintext sub-resource'
assert_contains "$(_meta checks_run)" 'DAST-TRANSPORT-MIXED_ACTIVE-01' \
  'but the check IS in checks_run, because an HTTPS document was inspected - this is the difference between "tested and clean" and "not tested", and it is the whole point of tracking applicability separately from hits'

# ===========================================================================
printf '== C. plaintext exposure and the TLS redirect ==\n'
# ===========================================================================
t_case 'a plaintext login page is sensitive exposure AND a missing TLS redirect'
_run_case plainlogin tr-fixture 'http://tr.fixture.example/login'
assert_eq 1 "$(_count_check DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01)" 'the password control makes the response sensitive'
assert_eq 1 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" 'and the origin served content on port 80 rather than redirecting'
assert_contains "$(_field_of DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01 evidence)" 'password control' \
  'the evidence names what made it sensitive, rather than asserting sensitivity'
assert_eq true "$(_field_of DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01 sensitive_data)" \
  'the finding carries sensitive_data=true, which is exactly what this check means'

t_case 'a plaintext page with nothing sensitive is NOT reported as exposure'
_run_case brochure tr-fixture 'http://tr.fixture.example/brochure'
assert_eq 0 "$(_count_check DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01)" \
  'reading 6: a marketing page over http carries no credential, cookie or session - FAILS under "any plaintext 200 is sensitive exposure", which makes every plaintext site a high-severity data-exposure finding and drowns the ones that really are'
assert_eq 1 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" \
  'it IS still a missing TLS redirect, at the lower severity that fact deserves - so the two checks are not one check at two severities'

t_case 'a Set-Cookie on a plaintext response is exposure, and names the neighbouring check'
_run_case plaincookie tr-fixture 'http://tr.fixture.example/cookie'
assert_eq 1 "$(_count_check DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01)" 'a cookie issued over the clear channel was observable in transit'
assert_contains "$(_field_of DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01 evidence)" 'DAST-COOKIE-NO_SECURE-01' \
  'the evidence names the cookie-ATTRIBUTE check as the separate subject - FAILS under a family that silently re-reports DAST-06 findings, which is the boundary this ticket has to keep'

t_case 'a correct 301 to https is not a finding'
_run_case goodredir tr-fixture 'http://tr.fixture.example/good'
assert_eq 0 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" \
  'reading 4: the plaintext origin redirects to https, so there is nothing to report - FAILS under requesting with the default redirect budget, because http_request would FOLLOW the 301 and report the final 200, making a correct redirect indistinguishable from a page served on port 80'
assert_eq 0 "$(_count_check DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01)" 'and a redirect body carries nothing sensitive'
assert_contains "$(_meta checks_run)" 'DAST-TRANSPORT-NO_HTTPS_REDIRECT-01' 'the check ran and was covered; it simply found nothing'

t_case 'a 3xx that stays on http is still a missing TLS redirect'
_run_case hophttp tr-fixture 'http://tr.fixture.example/hophttp'
assert_eq 1 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" \
  'reading 5a: a 301 to another http:// URL leaves the visitor unencrypted - FAILS under "a 3xx means it redirects to TLS", which is the obvious implementation and passes a host-canonicalising redirect'
assert_contains "$(_field_of DAST-TRANSPORT-NO_HTTPS_REDIRECT-01 evidence)" 'another http:// URL' 'and the evidence says which shape it was'

_run_case schemerel tr-fixture 'http://tr.fixture.example/schemerel'
assert_eq 1 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" \
  'reading 5b: a scheme-relative Location is resolved by the browser against the CURRENT scheme, so it redirects http to http - FAILS under the same "any 3xx counts" reading'

_run_case noloc tr-fixture 'http://tr.fixture.example/noloc'
assert_eq 1 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" 'a 3xx with no Location redirects nowhere and leaves the browser on the plaintext origin'

# ===========================================================================
printf '== D. honesty: what was NOT tested is said, never implied clean ==\n'
# ===========================================================================
t_case 'a run that saw no HTTPS response at all records transport_check_not_applicable'
_run_case plainonly tr-plain 'http://plain.fixture.example/login'
RED=$(_meta coverage_reduction)
assert_contains "$RED" 'transport_check_not_applicable' \
  "reading 11: this ticket's own acceptance criterion - a plaintext-only run could not evaluate a single mixed-content check, and that is recorded rather than left to read as clean. FAILS under emitting nothing when no finding fired, which is exactly how 'nothing was mixed' becomes indistinguishable from 'nothing was testable'"
assert_contains "$RED" 'DAST-TRANSPORT-MIXED_ACTIVE-01' 'the reduction NAMES the uncovered ids rather than saying "some checks"'
assert_contains "$RED" 'https_responses=0' 'and gives the count that made them inapplicable'
assert_not_contains "$(_meta checks_run)" 'DAST-TRANSPORT-MIXED_ACTIVE-01' \
  'an inapplicable check is not in checks_run, so tension 12 never records coverage the run did not have'
assert_contains "$(_meta checks_run)" 'DAST-TRANSPORT-NO_HTTPS_REDIRECT-01' \
  'while the checks that DID apply are recorded, so the two are distinguishable'

t_case 'a run that saw no plaintext response records the mirror gap'
_run_case secureonly tr-secure 'https://secure.fixture.example/page'
RED=$(_meta coverage_reduction)
assert_contains "$RED" 'transport_check_not_applicable' 'the symmetric case is recorded too'
assert_contains "$RED" 'DAST-TRANSPORT-PLAINTEXT_SENSITIVE-01' 'naming the plaintext checks as uncovered'
assert_contains "$RED" 'http_responses=0' 'with the count that made them inapplicable'

t_case 'a target that offered no URL at all is a coverage gap, not a clean run'
# `base-url` is a REQUIRED scope.conf field (rules/RULE-FORMAT.md §9.6.2), so a
# well-formed target always yields at least one candidate and the phase's own
# `_TR_N == 0` branch is only reachable through the loader.  It is asserted
# there rather than faked with a malformed config, which would be testing the
# record parser instead of this check.
tr_endpoints_load '' tr-fixture ''
assert_eq 0 "$_TR_N" \
  'no inventory and no base-url yields no candidate'

# And the PHASE branch itself, which the assertion above does not reach.
# `base-url` is a required scope.conf field, so the only way a real run gets
# here is the direct-engine configuration the phase already guards for with
# `declare -F config_scope_field_or` - a caller that never loaded lib/config.sh.
# That is a supported state, not an artificial one, so it is simulated by
# removing the function for the duration rather than by writing a malformed
# config (which would be testing the record parser instead of this branch).
_tr_saved_cfg=$(declare -f config_scope_field_or)
unset -f config_scope_field_or
_new_run nobase tr-fixture
SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_ENDPOINTS
SCOURSH_DAST_TARGET=tr-fixture
export SCOURSH_DAST_TARGET
# -x back-edge cut: modules/dast/passive/transport.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/transport.sh"
eval "$_tr_saved_cfg"
assert_contains "$(_meta coverage_gap)" 'offered no URL to request' \
  'the phase records a GAP when it has nothing to ask for - FAILS under returning quietly, which reports a target that was never inspected as one with no transport problems'
assert_contains "$(_meta coverage_reduction)" 'no_endpoint_to_inspect' 'and the machine-readable reduction alongside it'
assert_eq 0 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" 'and emits nothing'
assert_eq '' "$(_meta checks_run)" 'and records no check as run, because none was'
assert_eq 0 "$(printf '%s' "$(cat "$REQ_LOG")" | wc -c | tr -d ' ')" 'and sent no request at all'

t_case 'a target whose every URL fails to answer records a gap, not a clean result'
_run_case dead tr-dead
assert_contains "$(_meta coverage_gap)" 'produced a response this phase could read' \
  'reading: a run where nothing answered reports a GAP - FAILS under returning quietly when no finding fired, which reports a target that was never successfully contacted as one with no transport problems'
assert_eq 0 "$(_count_check DAST-TRANSPORT-NO_HTTPS_REDIRECT-01)" 'and emits no finding'
assert_not_contains "$(_meta checks_run)" 'DAST-TRANSPORT-NO_HTTPS_REDIRECT-01' \
  'and records no check as run, because none was'

t_case 'an out-of-scope inventory URL is skipped, never handed to http_request'
_run_case oos tr-fixture 'https://tr.fixture.example/nav' 'https://not-authorised.example/evil'
assert_not_contains "$(cat "$REQ_LOG")" 'not-authorised.example' \
  'reading 12: the scope PRE-CHECK stops the URL before http_request sees it - FAILS under handing every inventory row straight to http_request, which die()s with exit 3 on an out-of-scope URL and would let one bad row abort the operator whole run'
TR_RED=$(_meta coverage_reduction)
assert_contains "$TR_RED" 'inventory_endpoint_out_of_scope' \
  'and the skip is RECORDED, so a narrowed surface is never silent - now the shared roll-up reason (modules/dast/engine.sh section 3b) this file originally built the reason-capture-at-refusal-time property for'
assert_contains "$TR_RED" 'phase=transport' 'and names this phase'
assert_not_contains "$TR_RED" 'declined by the scope gate' \
  'the record carries the gate OWN reason, not the generic fallback - FAILS under reading _HTTP_GATE_REASON after the loop, which http_gate_url clears at entry on every call, so a run whose last gate call SUCCEEDED (the ordinary case) reports the fallback and the operator never learns why the URL was declined'

# ---------------------------------------------------------------------------
# WITHOUT the shared pre-check, the same inventory kills the whole run.
# ---------------------------------------------------------------------------
MUT=$W/mutation.sh
cat >"$MUT" <<'EOM'
set -Eeuo pipefail
ROOT=$1 W=$2 INV=$3 SCOPE=$4 LOG=$5
source "$ROOT/modules/dast/engine.sh"
source "$ROOT/modules/dast/passive/transport_engine.sh"
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"
config_scanner_load "$W/scanner.conf"
_m_resolve() { printf '93.184.216.34'; }
SCOURSH_HTTP_RESOLVE=_m_resolve
_m_transport() {
  printf '%s %s://%s%s\n' "$1" "$2" "$3" "$5" >>"$LOG"
  if [[ -n ${_HTTP_TX_HEADERS_OUT:-} ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' >>"$_HTTP_TX_HEADERS_OUT"
  fi
  printf '200\n\ntext/html\n'
}
SCOURSH_HTTP_TRANSPORT=_m_transport
dast_endpoint_keep() { return 0; }
run_init "$W/run.mutation"
run_record authorization_affirmed true
run_record authorization_target tr-fixture
SCOURSH_DAST_TARGET=tr-fixture
SCOURSH_DAST_CELL=tr-fixture
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
SCOURSH_DAST_ENDPOINTS=$INV
export SCOURSH_DAST_ENDPOINTS
source "$ROOT/modules/dast/passive/transport.sh"
EOM
OOSINV=$(_inv oosmut tr-fixture 'https://not-authorised.example/evil')
MUT_LOG=$W/mutation-requests.log
: >"$MUT_LOG"
MUT_RC=0
bash "$MUT" "$ROOT" "$W" "$OOSINV" "$SCOPE" "$MUT_LOG" >"$W/mutation.out" 2>&1 || MUT_RC=$?

t_case 'WITHOUT the pre-check the same inventory kills the whole run'
assert_eq 3 "$MUT_RC" \
  'the mutated phase exits SCOURSH_EXIT_SCOPE (3) - reproduced rather than described, proving the pre-check above is load-bearing'
assert_not_contains "$(cat "$MUT_LOG")" 'not-authorised' \
  'and it never even reached the unauthorised host'

t_case 'one finding per check per target, with the count in the evidence'
_run_case perTarget tr-fixture 'https://tr.fixture.example/mixed' 'https://tr.fixture.example/mixed2'
# BOTH endpoints must actually exhibit the defect for this to pin anything -
# see the _body case arm above.  Asserted first, so a fixture regression that
# silently stops serving the mixed document at one of them fails HERE, naming
# the cause, rather than leaving the real assertion below quietly toothless.
# THREE endpoints are fetched, not two: tr_endpoints_load always puts the
# target's own base-url first (deliberately - see its header), and `/` serves
# the CLEAN document.  So the honest reading of this run is "3 responses the
# check applied to, 2 of which exhibited the defect".
assert_eq 3 "$_TR_N" 'the two named endpoints plus the always-first base-url'
assert_contains "$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 evidence)" 'Observed on 2 of the 3' \
  'TWO of the three responses exhibited it - this is the precondition that gives the next assertion its teeth, and it fails if the fixture serves the mixed document at only one of the two paths, which is exactly how this case previously pinned nothing'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_ACTIVE-01)" \
  'reading 8: two endpoints EACH exhibiting the same defect are ONE finding - FAILS under emitting per endpoint, which reports one deployment-wide misconfiguration once per page and buries everything else in the report'
assert_eq 1 "$(_count_check DAST-TRANSPORT-MIXED_PASSIVE-01)" 'and the same for the passive class, so the grain is the check rather than one lucky id'
assert_eq '/mixed' "$(_field_of DAST-TRANSPORT-MIXED_ACTIVE-01 loc_path_template)" \
  'and the one finding is located at the FIRST exhibiting endpoint in tr_endpoints_load deterministic order, which is what stops the fingerprint churning when the crawl reorders'

# ===========================================================================
printf '== E. registration, and the tier this ticket moved ==\n'
# ===========================================================================
t_case 'the phase table reaches this script, and at tier passive'
FOUND=0
for spec in "${_DAST_PHASES[@]+"${_DAST_PHASES[@]}"}"; do
  [[ $spec == 'passive/transport.sh:passive' ]] && FOUND=1
done
assert_eq 1 "$FOUND" \
  'reading 13: modules/dast/engine.sh names passive/transport.sh at tier `passive`, so a plain `scan.sh dast --target <t>` runs it - FAILS while the row reads `transport.sh:active`, which is what the table carried from DAST-02 until this ticket, and which --intensity`s passive default would skip on every ordinary run'

t_case 'a passive-intensity run actually sources it'
# `dast_run_phase` takes the tier from its SPEC ARGUMENT, not from _DAST_PHASES,
# so this pair proves the script is on disk and that a passive-intensity run
# sources it - it does NOT pin the table's row, and saying so would be claiming
# a discrimination it does not have.  The table scan immediately above is what
# pins the row; the pair below is what proves the row is reachable.
SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'passive/transport.sh:passive' passive tr-secure >/dev/null 2>&1 || true
assert_eq 1 "$_DAST_PHASE_PRESENT" 'dast_run_phase finds the script on disk'
assert_eq ran "$_DAST_PHASE_OUTCOME" \
  'a run at the DEFAULT intensity sources a phase declared at tier passive'
# And the complement, which is what makes the pair mean something: the SAME
# script declared at `active` is refused by a default-intensity run.  This is
# the concrete cost of leaving the table row where DAST-02 put it.
SCOURSH_INSTALL_ROOT=$ROOT dast_run_phase 'passive/transport.sh:active' passive tr-secure >/dev/null 2>&1 || true
assert_eq skipped_intensity "$_DAST_PHASE_OUTCOME" \
  'the identical script declared at tier `active` is NOT run by a default-intensity run - which is why the table row had to move, and what the whole family would have cost had it not'

t_case 'every check id this phase emits is in the registry, and the two copies agree'
# THE FILE IS SHARED WITH THE OTHER TIER-2 TICKETS, so the id count below is
# taken over THIS phase's own records only - the ones whose `script:` is
# `passive/transport.sh`.  Counting every `id:` in the file instead makes this
# assertion fail the moment a peer appends its block, which would make a
# correct, append-only merge look like a defect in this phase.  The same shape,
# and the same reason, as tests/suites/dast-headers.sh's own registry section.
_reg_ids=''
_key='' _val='' _cur_id=''
declare -A REG_SEV=() REG_CWE=() REG_OWASP=() REG_TITLE=() REG_SCRIPT=() REG_TAG=()
while IFS= read -r line || [[ -n $line ]]; do
  [[ -z $line || ${line:0:1} == '#' ]] && continue
  [[ $line == *': '* ]] || continue
  _key=${line%%': '*}; _val=${line#*': '}
  case $_key in
    id) _cur_id=$_val ;;
    title) REG_TITLE[$_cur_id]=$_val ;;
    severity) REG_SEV[$_cur_id]=$_val ;;
    cwe) REG_CWE[$_cur_id]=$_val ;;
    owasp) REG_OWASP[$_cur_id]=$_val ;;
    script) REG_SCRIPT[$_cur_id]=$_val ;;
    tags) [[ -z ${REG_TAG[$_cur_id]:-} ]] && REG_TAG[$_cur_id]=$_val ;;
  esac
done <"$ROOT/modules/dast/passive/checks-transport.rules"

for _id in "${!REG_SCRIPT[@]}"; do
  [[ ${REG_SCRIPT[$_id]} == 'passive/transport.sh' ]] && _reg_ids+="$_id "
done
assert_eq "${#_TR_CHECK_IDS[@]}" "$(printf '%s' "$_reg_ids" | wc -w | tr -d ' ')" \
  "the registry declares exactly the ids the phase can emit - FAILS if either grows without the other, which leaves tension 12 unable to compute coverage for an emitted check or tension 15 unable to filter it"

# And the registry is what `checks_registry_load` actually returns, not merely
# what the file says - so a record this loader rejects is caught here rather
# than at scan time.
SCOURSH_INSTALL_ROOT=$ROOT checks_registry_load dast DASTCK
REG=''
for s in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
  n=$(records_count "$s")
  for (( ri = 0; ri < n; ri++ )); do
    REG+=$(records_id "$s" "$ri")
    REG+=' '
  done
done
for id in "${_TR_CHECK_IDS[@]}"; do
  assert_contains "$REG" "$id" \
    "$id is loaded by checks_registry_load - FAILS if a check is emitted with no registry record the loader accepts"
done

t_case 'the shell catalog and the registry agree on every field'
for c in "${_TR_CHECK_IDS[@]}"; do
  _tr_catalog "$c"
  assert_eq "${REG_TITLE[$c]:-<absent>}" "$_TRC_TITLE" "$c: title agrees with the registry"
  assert_eq "${REG_SEV[$c]:-<absent>}" "$_TRC_SEV" "$c: severity agrees with the registry"
  assert_eq "${REG_CWE[$c]:-<absent>}" "$_TRC_CWE" "$c: CWE agrees with the registry"
  assert_eq "${REG_OWASP[$c]:-<absent>}" "$_TRC_OWASP" "$c: OWASP mapping agrees with the registry"
  assert_eq 'passive/transport.sh' "${REG_SCRIPT[$c]:-<absent>}" "$c: the registry names this phase script"
  assert_eq 'passive' "${REG_TAG[$c]:-<absent>}" \
    "$c: the type tag is 'passive', matching the phase table's own floor - FAILS if the two gates disagree, which tension 15's intersection rule forbids"
done

t_case 'the family does not restate its three neighbours checks'
# Asserted POSITIVELY, on the prefix every id must carry.  The previous shape
# here was a `case` arm matching DAST-HDR-*/DAST-COOKIE-*/DAST-TLS-* inside a
# loop over _TR_CHECK_IDS - whose entries are all DAST-TRANSPORT-* by
# construction, so the body could never execute and the assertion could never
# fail.  A test that cannot fail is not a test.
for c in "${_TR_CHECK_IDS[@]}"; do
  assert_eq 'DAST-TRANSPORT-' "${c:0:15}" \
    "$c carries this family's own prefix, so it can never collide with a DAST-HDR-*, DAST-COOKIE-* or DAST-TLS-* id"
done
assert_not_contains "$REG" 'DAST-TRANSPORT-HSTS' \
  'no HSTS check is minted here - Strict-Transport-Security is DAST-HDR-HSTS_*, and duplicating it is the boundary failure this ticket has to avoid'
assert_not_contains "$REG" 'DAST-TRANSPORT-CERT' \
  'and no certificate check either - the connection is passive/tls.sh (DAST-07)'

# ===========================================================================
printf '\n== dast-transport: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
