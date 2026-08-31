#!/usr/bin/env bash
# tests/suites/dast-markup.sh - modules/dast/passive/markup.sh and
# modules/dast/passive/markup_engine.sh: the §7.1 HTML-markup family
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-11, tier 2).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed throughout and the whole suite is driven
# from RECORDED RESPONSES - a table of documents this file writes, replayed into
# lib/http.sh's own capture sink exactly as curl would write them
# (docs/DESIGN.md §12: "DAST logic is testable with no live target"; §7.1: "one
# file per family so each is independently testable against a recorded
# response").  It runs on a host with no network and no Docker.
#
# Each case that pins a decision names the reading it FAILS under, per this
# repository's testing rule - a test that passes under both the correct and the
# rejected reading pins nothing, and buys false confidence instead.  The
# readings pinned here:
#
#   1. markup inside an HTML COMMENT is not markup.
#   2. markup inside an inline <script>, <textarea> or <template> body is not
#      markup either - `document.write("<a target=_blank>")` is a string.
#   3. an attribute spanning several lines is ONE attribute; a `>` inside a
#      quoted value does not end the tag; single-quoted, double-quoted and
#      unquoted values all parse.
#   4. `rel` is a TOKEN LIST: `rel="external noopener"` is protection and
#      `rel="noopenerx"` is not.  A substring test gets one of those wrong in
#      each direction and a whole-attribute comparison gets the first wrong.
#   5. SRI is a CROSS-ORIGIN concern: a same-origin script needs no integrity,
#      and `https://h/` and `https://h:443/` are ONE origin.
#   6. a `<link rel=icon>` does not take SRI; a `<link rel=stylesheet>` does.
#   7. tabnabbing on an authentication or redirect page carries the HIGHER-
#      severity id, decided by the path OR by a password field on the page.
#   8. one element yields at most one FRAME finding: a plaintext cross-origin
#      frame is reported as plaintext, not also as unsandboxed.
#   9. a `sandbox` attribute with an EMPTY value is still a sandbox.
#  10. a form control named `token` counts as a CSRF token only when HIDDEN.
#  11. a GET form is not state-changing, and a form POSTing to another origin
#      is not this application's CSRF problem - both are declared, not silent.
#  12. one finding per check per PAGE, not per element and not per target: two
#      defective pages are two findings with two path templates.
#  13. an out-of-scope inventory URL is skipped, never handed to `http_request`
#      (which would abort the whole run with exit 3).
#  14. a response that is not HTML is not parsed, and says so.
#  15. every bound and every gap is recorded; nothing truncates silently.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes HTML attribute syntax literally.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# SC2329: several cases REDEFINE `_doc` (and `markup_html_extract`) to stand in
#   a one-off recorded response, then restore the original from a `declare -f`
#   capture.  The replacement is reached only through the phase under test, so
#   the linter cannot see the call and reports it as never invoked; silenced
#   explicitly with a reason rather than left to the version, since this
#   repository runs the linter on two userlands whose versions disagree about
#   which findings exist at all.  (No line of prose here may BEGIN with the
#   linter name - such a line is parsed as a directive, SC1072.)
# shellcheck disable=SC2016,SC2030,SC2031,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the engine pulls in lib/http.sh -> lib/config.sh + lib/findings.sh ->
# lib/records.sh -> lib/core.sh, which bootstraps the scratch dir and traps.
# -x back-edge cut: modules/dast/passive/markup_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/passive/markup_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-markup-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope, resolver, scanner limits.
# ---------------------------------------------------------------------------
# ONE authorised target.  Every cross-origin host these documents reference
# (cdn.example, out.example, third.example, plain.example) is deliberately NOT
# in scope: this phase CLASSIFIES a reference and never requests one, and the
# request log below is what proves it.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: mk-fixture
base-url: https://mk.fixture.example/
notes: Fixture target for tests/suites/dast-markup.sh. Never dialled: both the
  resolver and the transport are stubbed.
EOF
http_scope_load "$SCOPE"
config_scope_load "$SCOPE"

cat >"$W/scanner.conf" <<'EOF'
id: scanner
requests-per-second: 5000
request-budget: 20000
circuit-breaker-failures: 100000
EOF
config_scanner_load "$W/scanner.conf"

_mk_resolve() {
  case $1 in
    mk.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_mk_resolve

# ---------------------------------------------------------------------------
# The recorded documents.
# ---------------------------------------------------------------------------
# `_doc <path>` prints the response BODY exactly as the target served it.  The
# transport below writes it into lib/http.sh's own body sink; nothing is
# invented at read time.
#
# `/` IS THE CLEAN PAGE AND THAT IS STRUCTURAL, not a convenience: the endpoint
# chooser always puts the target's own base-url first, so EVERY case below
# fetches `/` as well as whatever its own inventory names.  A defect there would
# appear in every case and no case could isolate anything.
_doc() {
  case $1 in
    /)
      cat <<'H'
<!DOCTYPE html><html><head><title>clean</title>
<script src="/own.js"></script>
<link rel="stylesheet" href="/own.css">
</head><body>
<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
<a href="https://out.example/x" rel="noopener noreferrer" target="_blank">safe external</a>
<form method="GET" action="/search"><input type="text" name="q"></form>
</body></html>
H
      ;;
    /sri)
      cat <<'H'
<!DOCTYPE html><html><head>
<script src="https://cdn.example/bad.js"></script>
<script src="https://cdn.example/good.js" integrity="sha384-AAA" crossorigin="anonymous"></script>
<script src="/own.js"></script>
<script src="https://mk.fixture.example:443/explicit-port.js"></script>
<link rel="stylesheet" href="https://cdn.example/bad.css">
<link rel="icon" href="https://cdn.example/favicon.ico">
<link rel="canonical" href="https://cdn.example/canonical">
<script>var x = "<script src=\"https://cdn.example/in-a-string.js\"></" + "script>";</script>
</head><body>
<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
</body></html>
H
      ;;
    /tab)
      cat <<'H'
<!DOCTYPE html><html><body>
<a href="https://out.example/1" target="_blank">bare, cross-origin: A FINDING</a>
<a href="https://out.example/2" target="_blank" rel="external noopener">token list: NOT a finding</a>
<a href="https://out.example/3" target="_blank" rel="noreferrer">noreferrer: NOT a finding</a>
<a href="https://out.example/4" target="_blank" rel="noopenerx">near miss: A FINDING</a>
<a href="/local" target="_blank">same origin: NOT a finding</a>
<a href="https://out.example/5">no target: NOT a finding</a>
<a href="https://out.example/6" target="other">named target: NOT a finding</a>
<a href="javascript:void(0)" target="_blank">not fetchable: NOT a finding</a>
</body></html>
H
      ;;
    /tricky)
      cat <<'H'
<!DOCTYPE html><html><body>
<!-- <a href="https://out.example/commented" target="_blank">inside a comment</a> -->
<script>document.write('<a href="https://out.example/scripted" target="_blank">x</a>');</script>
<textarea><a href="https://out.example/textarea" target="_blank">y</a></textarea>
<template><a href="https://out.example/template" target="_blank">z</a></template>
<a href="https://out.example/real?q=a&amp;r=b>c"
   target="_blank"
   class="btn">THE one real finding: multi-line, entity-encoded, > inside the value</a>
<a href='https://out.example/quoted' target='_blank' rel='noopener'>single quotes, protected</a>
<a href=https://out.example/unquoted target=_blank rel=noopener>unquoted, protected</a>
<a href="/x">x</a> <a href="/y">y</a> <a href="/z">z</a>
</body></html>
H
      ;;
    /login)
      cat <<'H'
<!DOCTYPE html><html><body>
<a href="https://out.example/help" target="_blank">help</a>
<form method="POST" action="/login">
  <input type="text" name="user"><input type="password" name="pw">
  <button type="submit">go</button>
</form>
<a href="/a">a</a> <a href="/b">b</a>
</body></html>
H
      ;;
    /account/settings)
      cat <<'H'
<!DOCTYPE html><html><body>
<a href="https://out.example/docs" target="_blank">docs</a>
<form method="POST" action="/account/settings">
  <input type="hidden" name="csrf_token" value="t"><input type="password" name="newpw">
</form>
<a href="/a">a</a> <a href="/b">b</a>
</body></html>
H
      ;;
    /frames)
      cat <<'H'
<!DOCTYPE html><html><body>
<iframe src="http://plain.example/widget"></iframe>
<iframe src="https://third.example/widget"></iframe>
<iframe src="https://third.example/safe" sandbox></iframe>
<iframe src="https://third.example/safe2" sandbox="allow-forms"></iframe>
<iframe src="/own/widget"></iframe>
<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
</body></html>
H
      ;;
    /forms)
      cat <<'H'
<!DOCTYPE html><html><body>
<form method="post" action="/transfer">
  <input type="text" name="amount"><input type="text" name="to">
</form>
<form method="POST" action="/settings">
  <input type="hidden" name="authenticity_token" value="t"><input type="text" name="nick">
</form>
<form method="POST" action="/verify">
  <input type="text" name="token">
</form>
<form method="GET" action="/search"><input type="text" name="q"></form>
<form method="POST" action="https://third.example/pay"><input type="text" name="card"></form>
<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
</body></html>
H
      ;;
    /spa)
      cat <<'H'
<!DOCTYPE html><html><head><script src="/own/bundle.js"></script></head>
<body><div id="root"></div></body></html>
H
      ;;
    /api)
      printf '%s\n' '{"ok":true,"html":"<a href=\"https://out.example/x\" target=\"_blank\">not markup</a>"}'
      ;;
    *)
      cat <<'H'
<!DOCTYPE html><html><body><a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a></body></html>
H
      ;;
  esac
}

REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

_mk_transport() {
  local method=$1 host=$3 path=$5
  local bodyout=${7:-${_HTTP_TX_BODY_OUT:-}}
  local ctype='text/html; charset=utf-8'
  [[ $path == /api ]] && ctype='application/json'
  printf '%s %s %s\n' "$method" "$host" "$path" >>"$REQ_LOG"
  if [[ -n $bodyout ]]; then
    _doc "$path" >"$bodyout"
  fi
  printf '%s\n%s\n%s\n' 200 '' "$ctype"
}
SCOURSH_HTTP_TRANSPORT=_mk_transport

# ---------------------------------------------------------------------------
# Per-case run isolation and readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  run_record authorization_affirmed true
  run_record authorization_target "${2:-mk-fixture}"
  occurrence_reset_all
  _req_reset
}

# `_inv NAME URL...` writes an endpoints.json naming each URL and prints its
# path.  The shape is docs/INVENTORY-FORMAT.md's, written the way a conformant
# producer OTHER than crawl.sh might - so the reader is exercised through the
# frozen flattener rather than against crawl.sh's exact bytes.
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

# The value of one field of the FIRST finding for a check id.
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

# Every value of one field, across every finding for a check id, newline-joined.
_fields_of() {
  local check=$1 want=$2 f line fld hit='' out='' acc=''
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
      [[ -n $hit ]] && acc+="$out"$'\n'
    done <"$f"
  done
  printf '%s' "$acc"
}

_meta() { run_facts "$1" 2>/dev/null || printf ''; }

# `_run_case NAME TARGET [URL...]` - a fresh run, an inventory of the given
# URLs, and one invocation of the phase.
_run_case() {
  local name=$1 target=$2; shift 2
  _new_run "$name" "$target"
  if (( $# > 0 )); then
    SCOURSH_DAST_ENDPOINTS=$(_inv "$name" "$target" "$@")
  else
    SCOURSH_DAST_ENDPOINTS=''
  fi
  SCOURSH_DAST_TARGET=$target
  SCOURSH_DAST_CELL=$target
  SCOURSH_DAST_INTENSITY=passive
  SCOURSH_DAST_AUTHED=false
  SCOURSH_DAST_ALLOW_INTRUSIVE=false
  export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL \
    SCOURSH_DAST_INTENSITY SCOURSH_DAST_AUTHED SCOURSH_DAST_ALLOW_INTRUSIVE
  unset SCOURSH_SELECTED_CHECKS
  _dast_markup_phase
}

B=https://mk.fixture.example

# ===========================================================================
# A. The tokenizer, on its own.
# ===========================================================================
t_case 'tokenizer'

_tok() { markup_html_extract; }

# 1/2/3: comments, raw-text bodies, and the three quoting styles.
_out=$(printf '%s\n' \
  '<!-- <a href="https://c.example" target="_blank">in a comment</a> -->' \
  '<script>document.write("<a href=\"https://s.example\" target=\"_blank\">x</a>")</script>' \
  '<textarea><a href="https://t.example" target="_blank">y</a></textarea>' \
  '<a href="https://d.example" target="_blank">double</a>' \
  "<a href='https://e.example' target='_blank'>single</a>" \
  '<a href=https://f.example target=_blank>unquoted</a>' | _tok)
assert_not_contains "$_out" 'c.example' \
  'an anchor inside an HTML comment is NOT a tag - FAILS if comments are not skipped'
assert_not_contains "$_out" 's.example' \
  'an anchor a string inside <script> spells out is NOT a tag - FAILS if the raw-text body is scanned as markup'
assert_not_contains "$_out" 't.example' \
  'an anchor inside <textarea> is NOT a tag - FAILS if escapable-raw-text bodies are scanned'
assert_contains "$_out" 'https://d.example' 'double-quoted attribute value parses'
assert_contains "$_out" 'https://e.example' 'single-quoted attribute value parses'
assert_contains "$_out" 'https://f.example' 'unquoted attribute value parses'

# 3: a multi-line tag is ONE tag, and a `>` inside a quoted value does not end it.
_out=$(printf '%s\n' \
  '<a' '   href="https://g.example/?q=a>b&amp;r=2"' '   target="_blank"' '   rel="external">multi</a>' | _tok)
assert_contains "$_out" $'anchor\x1f1\x1fhttps://g.example/?q=a>b&r=2\x1f_blank\x1fexternal\x1fa' \
  'a tag broken across four lines is one tag, its > inside the quoted value does not end it, and &amp; is decoded - FAILS under a line-oriented parse or a naive index(">")'

# The sandbox distinction (reading 9).
_out=$(printf '%s\n' '<iframe src="https://h.example" sandbox=""></iframe>' '<iframe src="https://i.example"></iframe>' | _tok)
assert_contains "$_out" $'frame\x1f1\x1fhttps://h.example\x1fiframe\x1f1\x1f' \
  'sandbox="" is still a sandbox - FAILS if presence is read off a non-empty value'
assert_contains "$_out" $'frame\x1f2\x1fhttps://i.example\x1fiframe\x1f0\x1f' \
  'no sandbox attribute at all is no sandbox'

# Truncation is declared, never silent (reading 15).
_out=$(printf '%s\n' '<a href="https://j.example" target="_blank">ok</a>' '<a href="unterminated>' '<a href="https://k.example" target="_blank">after</a>' | _tok)
assert_contains "$_out" $'trunc\x1f2\x1funterminated_attribute_value' \
  'an unterminated quoted value emits a trunc record'
assert_not_contains "$_out" 'k.example' \
  'and everything after the unterminated value is abandoned rather than guessed at'
_out=$(_MARKUP_MAX_BYTES=60 markup_html_extract <<'H'
<a href="https://l.example" target="_blank">l</a>
<a href="https://m.example" target="_blank">m</a>
<a href="https://n.example" target="_blank">n</a>
H
)
assert_contains "$_out" 'byte_cap' 'the byte cap emits a trunc record rather than truncating silently'
assert_not_contains "$_out" 'n.example' 'and the document really is cut'

# Every record carries exactly six 0x1f-separated fields, INCLUDING the empty
# ones - which is the whole reason the separator is 0x1f and not a tab.  A tab
# is IFS whitespace, so `read` folds a run of them into one delimiter: a <link>
# with no integrity and no crossorigin would arrive as four fields and its `rel`
# would land in the `integrity` variable, making every unhashed stylesheet on
# the internet pass the SRI check.  Counted by SEPARATOR rather than with
# `read -a`, because `read -a` under a whitespace IFS is precisely the reader
# that cannot see the difference.
_bad=0 _rows=0
while IFS= read -r _line; do
  [[ -n $_line ]] || continue
  _rows=$(( _rows + 1 ))
  _stripped=${_line//$'\x1f'/}
  (( ${#_line} - ${#_stripped} == 5 )) || _bad=$(( _bad + 1 ))
done < <(printf '%s\n' \
  '<a href="a b" target="_blank" rel="x y">t</a>' \
  '<link rel="stylesheet" href="/s.css">' \
  '<form method=post action=/p><input name="n" type="hidden" value="v"></form>' | _tok)
assert_eq 0 "$_bad" \
  'every record carries exactly six 0x1f-separated fields, empty ones included - FAILS under a tab separator, where a run of empty fields collapses and shifts every later value one column left'
_rows_ok=no; (( _rows >= 4 )) && _rows_ok=yes
assert_eq "yes (over $_rows rows)" "$_rows_ok (over $_rows rows)" \
  'and the fixture really produced records to count - a zero-row walk would satisfy the assertion above vacuously'

# The concrete regression the separator change fixed, pinned on its own.
_out=$(printf '%s\n' '<link rel="stylesheet" href="https://cdn.example/s.css">' | _tok)
IFS=$'\x1f' read -r _k _l _href _integ _cors _rel <<<"$_out"
assert_eq 'https://cdn.example/s.css' "$_href" 'the href reads back out of column 3'
assert_eq '' "$_integ" 'an absent integrity is an EMPTY column, not a missing one'
assert_eq 'stylesheet' "$_rel" \
  'and rel is still in column 6 - FAILS under a tab separator, where rel lands in the integrity variable and the SRI check reads an attribute that was never sent'

# ===========================================================================
# B. The pure predicates.
# ===========================================================================
t_case 'predicates'

# Reading 4: `rel` is a token list.
assert_status 0 'rel="external noopener" contains noopener - FAILS under a whole-attribute comparison' \
  markup_tokens_have 'external noopener' noopener
assert_status 1 'rel="noopenerx" does NOT contain noopener - FAILS under a substring test' \
  markup_tokens_have 'noopenerx' noopener
assert_status 0 'the comparison is case-insensitive (HTML token lists are)' \
  markup_tokens_have 'NOOPENER' noopener
assert_status 0 'a newline is ASCII whitespace and separates tokens' \
  markup_tokens_have $'external\nnoopener' noopener
assert_status 1 'an empty rel contains nothing' markup_tokens_have '' noopener

# Reading 6: which <link> relationships take SRI.
assert_status 0 'rel=stylesheet takes SRI' markup_link_takes_sri stylesheet
assert_status 0 'rel="preload" takes SRI' markup_link_takes_sri preload
assert_status 1 'rel=icon does NOT take SRI - FAILS if every <link href> is flagged, which puts a finding on every favicon' \
  markup_link_takes_sri icon
assert_status 1 'rel=canonical does NOT take SRI' markup_link_takes_sri canonical
assert_status 0 'rel="stylesheet alternate" takes SRI (token list again)' markup_link_takes_sri 'stylesheet alternate'

# Reading 5: origins, with the default port made explicit.
assert_status 0 'https://h/ and https://h:443/ are ONE origin - FAILS under a raw string comparison' \
  markup_same_origin 'https://h.example/a' 'https://h.example:443/b'
assert_status 1 'http:// and https:// on one host are DIFFERENT origins' \
  markup_same_origin 'http://h.example/a' 'https://h.example/a'
assert_status 1 'a different port is a different origin' \
  markup_same_origin 'https://h.example:8443/a' 'https://h.example/a'
assert_status 1 'a URL that will not normalise is not the same origin as anything - it fails toward being LOOKED AT, never toward being waved through' \
  markup_same_origin 'not a url' 'https://h.example/a'

# Reading 10: a `token` control counts only when it is hidden.
assert_status 0 'a hidden field named token is an anti-CSRF token' markup_field_is_csrf_token token hidden
assert_status 1 'a VISIBLE field named token is a one-time-code box, not a CSRF token - FAILS if the type is ignored, which would suppress the finding on exactly the 2FA form where a forged POST matters most' \
  markup_field_is_csrf_token token text
assert_status 0 'authenticity_token (Rails) is recognised' markup_field_is_csrf_token authenticity_token hidden
assert_status 0 'csrfmiddlewaretoken (Django) is recognised' markup_field_is_csrf_token csrfmiddlewaretoken hidden
assert_status 0 '__RequestVerificationToken (ASP.NET) is recognised, case-insensitively' markup_field_is_csrf_token __RequestVerificationToken hidden
assert_status 0 'a name is normalised over - and . before matching' markup_field_is_csrf_token 'csrf-token' text
assert_status 0 'the generic csrf stem matches as a substring' markup_field_is_csrf_token user_csrf_value text
assert_status 1 'an ordinary field name is not a token' markup_field_is_csrf_token amount text
assert_status 1 'an empty name is not a token' markup_field_is_csrf_token '' hidden

# Reading 7: which paths raise the severity.
assert_status 0 '/login is sensitive' markup_path_is_sensitive /login
assert_status 0 '/auth/callback is sensitive' markup_path_is_sensitive /auth/callback
assert_status 0 '/go?redirect= style paths are sensitive' markup_path_is_sensitive /account/redirect
assert_status 1 '/help is not' markup_path_is_sensitive /help
assert_status 1 '/ is not' markup_path_is_sensitive /

assert_status 0 'text/html; charset=utf-8 is markup' markup_is_html 'text/html; charset=utf-8'
assert_status 0 'application/xhtml+xml is markup' markup_is_html 'application/xhtml+xml'
assert_status 1 'application/json is not markup' markup_is_html 'application/json'
assert_status 1 'an absent Content-Type is not markup' markup_is_html ''

# ---------------------------------------------------------------------------
# Load the phase's functions.  A phase script has no sourced-once guard and runs
# _dast_markup_phase at source time (that is how dast_run_phase invokes it), so
# it is sourced once here against a throwaway run with no inventory - a run that
# still fetches the base URL - and then re-invoked per case below.
# ---------------------------------------------------------------------------
SCOURSH_DAST_TARGET=mk-fixture
SCOURSH_DAST_CELL=mk-fixture
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_ENDPOINTS=''
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED SCOURSH_DAST_ENDPOINTS
unset SCOURSH_SELECTED_CHECKS
_new_run boot
# shellcheck source=modules/dast/passive/markup.sh
source "$ROOT/modules/dast/passive/markup.sh"

# The boot run fetched only `/`, which is the clean page.
t_case 'clean page'
assert_eq 0 "$(_count_check DAST-MARKUP-SRI_MISSING-01)" \
  'the clean base page yields no SRI finding: its only script and stylesheet are same-origin'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'the clean base page yields no tabnabbing finding: its one external _blank link carries rel="noopener noreferrer"'
assert_eq 0 "$(_count_check DAST-MARKUP-CSRF_TOKEN_ABSENT-01)" \
  'a GET form with no token is NOT a finding - a GET submission is a navigation, not a state change (FAILS if the method is ignored)'
assert_contains "$(_meta checks_run)" 'DAST-MARKUP-SRI_MISSING-01' \
  'a check that ran and found nothing is still recorded in checks_run - a clean result and an untested one must not look alike'

# ===========================================================================
# C. Subresource Integrity.
# ===========================================================================
t_case 'SRI'
_run_case sri mk-fixture "$B/sri"
assert_eq 1 "$(_count_check DAST-MARKUP-SRI_MISSING-01)" \
  'the five SRI-relevant elements on /sri produce ONE finding for the page, not one per element'
_evi=$(_field_of DAST-MARKUP-SRI_MISSING-01 evidence)
assert_contains "$_evi" 'cdn.example/bad.js' 'the cross-origin script with no integrity is named'
assert_contains "$_evi" 'cdn.example/bad.css' 'the cross-origin stylesheet with no integrity is named'
assert_contains "$_evi" '2 element(s)' 'and exactly two elements were counted'
assert_not_contains "$_evi" 'good.js' \
  'a cross-origin script WITH integrity is not a finding'
assert_not_contains "$_evi" '/own.js' \
  'a same-origin script needs no integrity - FAILS if SRI is applied to every script[src], which puts a finding on every page of every site'
assert_not_contains "$_evi" 'explicit-port' \
  'https://host:443/ is the SAME origin as https://host/ - FAILS under a raw string comparison of the two URLs'
assert_not_contains "$_evi" 'favicon.ico' \
  'a <link rel=icon> does not take SRI - FAILS if every <link href> is flagged'
assert_not_contains "$_evi" 'canonical' 'nor does <link rel=canonical>'
assert_not_contains "$_evi" 'in-a-string.js' \
  'a <script src> spelled out inside an inline script BODY is a string, not an element'
assert_eq 'mk-fixture' "$(_field_of DAST-MARKUP-SRI_MISSING-01 loc_target)" 'the finding is located on the target'
assert_eq '/sri' "$(_field_of DAST-MARKUP-SRI_MISSING-01 loc_path_template)" 'and on the page that carries it'
assert_eq 'CWE-353' "$(_field_of DAST-MARKUP-SRI_MISSING-01 cwe)" 'it carries its CWE'
assert_eq 'A08:2021' "$(_field_of DAST-MARKUP-SRI_MISSING-01 owasp)" 'and its OWASP mapping'
assert_not_contains "$(cat "$REQ_LOG")" 'cdn.example' \
  'NOT ONE REQUEST WAS SENT TO A HOST NAMED IN THE MARKUP - this phase classifies references and never follows one (FAILS if a check fetches what it found, which is also out of scope and would abort the run)'

# ===========================================================================
# D. Reverse tabnabbing.
# ===========================================================================
t_case 'tabnabbing'
_run_case tab mk-fixture "$B/tab"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  '/tab is not an authentication or redirect page, so its finding carries the ordinary id'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING_SENSITIVE-01)" \
  'and not the elevated one'
_evi=$(_field_of DAST-MARKUP-TABNABBING-01 evidence)
assert_contains "$_evi" 'out.example/1' 'a bare cross-origin target=_blank is a finding'
assert_contains "$_evi" 'out.example/4' \
  'rel="noopenerx" is a finding - FAILS under a substring test, which reads it as protection'
assert_contains "$_evi" '2 element(s)' 'exactly two of the eight anchors qualify'
assert_not_contains "$_evi" 'out.example/2' \
  'rel="external noopener" is protection - FAILS under a whole-attribute comparison'
assert_not_contains "$_evi" 'out.example/3' 'rel="noreferrer" is protection too'
assert_not_contains "$_evi" '/local' \
  'a SAME-ORIGIN target=_blank is not a finding: window.opener access within one origin crosses no boundary'
assert_not_contains "$_evi" 'out.example/5' 'an anchor with no target is not a finding'
assert_not_contains "$_evi" 'out.example/6' 'a NAMED target reuses a context and is not a finding'
assert_not_contains "$_evi" 'javascript' 'a javascript: href opens no document and is not a finding'
assert_eq 'low' "$(_field_of DAST-MARKUP-TABNABBING-01 base_severity)" \
  'the ordinary id is low severity - current browsers imply noopener, and the remediation says so'

t_case 'tabnabbing: the comment/script/template traps'
_run_case tricky mk-fixture "$B/tricky"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING-01)" '/tricky yields exactly one finding'
_evi=$(_field_of DAST-MARKUP-TABNABBING-01 evidence)
assert_contains "$_evi" '1 element(s)' 'and exactly one element inside it'
assert_contains "$_evi" 'out.example/real' \
  'the multi-line, entity-encoded anchor with a > inside its value IS the finding'
assert_contains "$_evi" 'q=a&r=b' 'and &amp; was decoded on the way'
assert_not_contains "$_evi" 'commented' 'an anchor inside a comment is not'
assert_not_contains "$_evi" 'scripted' 'nor one a string inside <script> spells out'
assert_not_contains "$_evi" 'textarea' 'nor one inside <textarea>'
assert_not_contains "$_evi" 'template' \
  'nor one inside <template>, whose contents are inert until a script clones them'
assert_not_contains "$_evi" 'quoted' 'a single-quoted rel=noopener protects'
assert_not_contains "$_evi" 'unquoted' 'so does an unquoted one'

t_case 'tabnabbing: weighted higher on sensitive pages'
_run_case login mk-fixture "$B/login"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING_SENSITIVE-01)" \
  '/login carries the ELEVATED id - this ticket asks for the check to be weighted higher on login and redirect pages'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'and not the ordinary one as well - one element yields one finding'
assert_eq 'medium' "$(_field_of DAST-MARKUP-TABNABBING_SENSITIVE-01 base_severity)" \
  'the elevated id is medium where the ordinary one is low, which is what "weighted higher" means here'

_run_case pwpage mk-fixture "$B/account/settings"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING_SENSITIVE-01)" \
  '/account/settings matches no sensitive path token, but it carries an <input type="password">, so the CONTENT signal elevates it - FAILS if only the path is consulted'
assert_eq 0 "$(_count_check DAST-MARKUP-CSRF_TOKEN_ABSENT-01)" \
  'and its POST form has a csrf_token, so it is not a CSRF finding'

# ===========================================================================
# E. Insecure external frames.
# ===========================================================================
t_case 'frames'
_run_case frames mk-fixture "$B/frames"
assert_eq 1 "$(_count_check DAST-MARKUP-FRAME_INSECURE_SCHEME-01)" \
  'the one http:// frame produces the plaintext-transport finding'
assert_eq 1 "$(_count_check DAST-MARKUP-FRAME_UNTRUSTED-01)" \
  'and the one unsandboxed cross-origin https frame produces the untrusted-embedding finding'
_evi=$(_field_of DAST-MARKUP-FRAME_INSECURE_SCHEME-01 evidence)
assert_contains "$_evi" 'plain.example/widget' 'the plaintext frame is named'
assert_contains "$_evi" '1 element(s)' 'and it is the only one'
assert_contains "$_evi" 'ACTIVE MIXED CONTENT' \
  'the page is HTTPS, so the evidence says the browser blocks it outright rather than merely calling it insecure'
_evi=$(_field_of DAST-MARKUP-FRAME_UNTRUSTED-01 evidence)
assert_contains "$_evi" 'third.example/widget' 'the unsandboxed cross-origin frame is named'
assert_contains "$_evi" '1 element(s)' 'and exactly one of the five frames qualifies'
assert_not_contains "$_evi" 'plain.example' \
  'ONE ELEMENT YIELDS AT MOST ONE FRAME FINDING - the plaintext frame is also unsandboxed and cross-origin, and is deliberately NOT reported twice (FAILS if the two checks are evaluated independently)'
assert_not_contains "$_evi" '/safe2' \
  'sandbox="allow-forms" is a sandbox'
assert_not_contains "$_evi" 'third.example/safe' \
  'and a bare sandbox attribute with an empty value is one too - FAILS if presence is read off a non-empty value'
assert_not_contains "$_evi" '/own/widget' 'a same-origin frame is not a finding'

# ===========================================================================
# F. Anti-CSRF tokens in state-changing forms.
# ===========================================================================
t_case 'CSRF'
_run_case forms mk-fixture "$B/forms"
assert_eq 1 "$(_count_check DAST-MARKUP-CSRF_TOKEN_ABSENT-01)" \
  'the five forms on /forms produce ONE finding for the page'
_evi=$(_field_of DAST-MARKUP-CSRF_TOKEN_ABSENT-01 evidence)
assert_contains "$_evi" '/transfer' 'the POST form with no token at all is a finding'
assert_contains "$_evi" '/verify' \
  'so is the POST form whose only "token" is a VISIBLE input - that is a one-time-code box the user types into and it defends nothing against request forgery (FAILS if the type is ignored)'
assert_contains "$_evi" '2 element(s)' 'exactly two of the five forms qualify'
assert_not_contains "$_evi" '/settings' 'a POST form carrying authenticity_token is not a finding'
assert_not_contains "$_evi" '/search' \
  'a GET form is not state-changing and is not a finding - FAILS if the method is ignored'
assert_not_contains "$_evi" 'third.example/pay' \
  'a form POSTing to ANOTHER ORIGIN is that origin request-validation problem, not this application - FAILS if every cross-origin form is flagged, which puts a finding on the checkout page of most of the internet'
assert_contains "$(_meta coverage_reduction)" 'markup_form_posts_cross_origin' \
  'and the cross-origin form is DECLARED rather than silently dropped'
assert_eq 'medium' "$(_field_of DAST-MARKUP-CSRF_TOKEN_ABSENT-01 confidence)" \
  'confidence is medium: this reads only the markup as served, so a token injected at submit time, a double-submit cookie or a server-side Origin check are all invisible to it'
_rem=$(_field_of DAST-MARKUP-CSRF_TOKEN_ABSENT-01 remediation)
assert_contains "$_rem" 'SameSite' 'and the remediation names the accepted alternative defence rather than pretending a token is the only one'

t_case 'login form: both findings, on the same page'
_run_case login2 mk-fixture "$B/login"
assert_eq 1 "$(_count_check DAST-MARKUP-CSRF_TOKEN_ABSENT-01)" \
  'the /login POST form has no token, which is a finding'
assert_contains "$(_field_of DAST-MARKUP-CSRF_TOKEN_ABSENT-01 evidence)" 'login form' \
  'and the evidence says it is a login form, because it carries a password field'
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING_SENSITIVE-01)" \
  'the tabnabbing finding on the same page is a SEPARATE finding under a separate id - FAILS if two defects at one location are folded into one id, where they would collide on one fingerprint and findings_merge would silently keep one'

# ===========================================================================
# G. The grain: one finding per check per PAGE.
# ===========================================================================
t_case 'grain'
_run_case twopages mk-fixture "$B/tab" "$B/tricky"
assert_eq 2 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'two defective pages are TWO findings - markup is a template property, so collapsing them (as headers.sh does for a server-configuration property) would say "a page on this target" without saying which'
_tpls=$(_fields_of DAST-MARKUP-TABNABBING-01 loc_path_template)
assert_contains "$_tpls" '/tab' 'one is located on /tab'
assert_contains "$_tpls" '/tricky' 'the other on /tricky'
assert_eq '' "$(_field_of DAST-MARKUP-TABNABBING-01 loc_param_name)" \
  'the offending elements are NOT part of the location: a CDN URL routinely carries a content hash, and putting one in the identity would mint a new finding on every deploy and destroy the tension-12 diff'

# ===========================================================================
# H. Honesty: every bound and every gap.
# ===========================================================================
t_case 'gaps: client-rendered page'
_run_case spa mk-fixture "$B/spa"
assert_contains "$(_meta coverage_reduction)" 'markup_client_rendered_page' \
  'a page that looks client-rendered is DECLARED: scoursh executes no JavaScript, so the DOM a browser actually builds was never inspected'
assert_contains "$(_meta coverage_gap)" 'look client-rendered' \
  'and it reaches the coverage_gap the report renders, so a clean markup result for it does not read as "tested and sound"'

t_case 'gaps: a response that is not markup'
_run_case api mk-fixture "$B/api"
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'a JSON response is not parsed, so the <a target=_blank> inside one of its string values produces nothing - FAILS if the body is tokenised regardless of Content-Type, which reports findings about a document that does not exist'
assert_contains "$(_meta coverage_reduction)" 'markup_response_not_html' \
  'and the un-parsed response is declared'

t_case 'gaps: an out-of-scope inventory URL'
_run_case oos mk-fixture 'https://not-authorised.example/page' "$B/tab"
assert_not_contains "$(cat "$REQ_LOG")" 'not-authorised.example' \
  'an inventory URL the scope gate declines is never handed to http_request - FAILS without the pre-check, where http_request exits 3 and one bad inventory row aborts the whole run'
assert_contains "$(_meta coverage_reduction)" 'markup_endpoint_out_of_scope' \
  'and the refusal is declared'
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'while the in-scope URL alongside it is still tested'

t_case 'gaps: a non-GET endpoint'
_new_run nonget mk-fixture
cat >"$W/nonget.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "e0", "target": "mk-fixture", "method": "POST", "url": "https://mk.fixture.example/forms", "path": "/forms" }
] }
EOF
SCOURSH_DAST_ENDPOINTS=$W/nonget.json
SCOURSH_DAST_TARGET=mk-fixture SCOURSH_DAST_CELL=mk-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
_dast_markup_phase
assert_not_contains "$(cat "$REQ_LOG")" '/forms' \
  'a discovered POST endpoint is NOT re-sent to read its markup: §7.1 forbids mutating state, and a passive check that POSTs is one wearing the wrong name'
assert_contains "$(_meta coverage_reduction)" 'markup_non_get_endpoint_skipped' \
  'and the skip is declared rather than silent'

t_case 'gaps: the endpoint cap'
_new_run cap mk-fixture
SCOURSH_DAST_ENDPOINTS=$(_inv cap mk-fixture "$B/one" "$B/two" "$B/three" "$B/four")
SCOURSH_DAST_TARGET=mk-fixture SCOURSH_DAST_CELL=mk-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
_MARKUP_MAX_ENDPOINTS=2 _dast_markup_phase
assert_contains "$(_meta coverage_gap)" 'were NOT fetched (cap 2)' \
  'the endpoint cap is declared when it bites - docs/DESIGN.md §15: a bound that truncates silently is indistinguishable from a surface that was really that small'

t_case 'gaps: no URL at all'
_new_run nourl mk-fixture
SCOURSH_DAST_ENDPOINTS=''
SCOURSH_DAST_TARGET=mk-fixture SCOURSH_DAST_CELL=mk-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
# `config_scope_field_or` is what supplies the base-url; with it yielding
# nothing the phase has no URL at all, which is the state this case pins.  It is
# stubbed rather than pointed at a target that does not exist, because an
# unknown target is a CALLER bug that function deliberately dies on - a
# different fact from "this target has no base-url".
_mk_saved_scope_fn=$(declare -f config_scope_field_or)
config_scope_field_or() { printf ''; }
_dast_markup_phase
eval "$_mk_saved_scope_fn"
assert_contains "$(_meta coverage_gap)" 'offered no URL to request' \
  'no inventory and no base-url is a recorded coverage GAP, never a clean report'
assert_eq '' "$(_meta checks_run)" \
  'and NOTHING is recorded in checks_run, because nothing ran'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" 'and no finding is invented from nothing'

t_case 'gaps: a document the parser had to abandon'
_new_run trunc mk-fixture
_doc_orig=$(declare -f _doc)
_doc() { printf '%s\n' '<a href="https://out.example/a" target="_blank">a</a>' '<a href="unterminated>' '<a href="https://out.example/b" target="_blank">b</a>'; }
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_TARGET=mk-fixture SCOURSH_DAST_CELL=mk-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
_dast_markup_phase
assert_contains "$(_meta coverage_reduction)" 'markup_document_truncated' \
  'a document abandoned at an unterminated attribute value is declared'
assert_contains "$(_field_of DAST-MARKUP-TABNABBING-01 evidence)" 'did not read the whole of this document' \
  'and the finding it DID make says so too, so a reader is never told the count is complete when it is not'
eval "$_doc_orig"

# ===========================================================================
# I. The registry and the catalog agree.
# ===========================================================================
# modules/dast/passive/checks-markup.rules is what tension 12 computes coverage over
# and tension 15 filters; the `_mk_catalog` table is what a finding carries.
# They are two copies on purpose (see markup.sh's own comment), so they are
# pinned against each other here - counted over THIS script's own records,
# since the file is shared with its tier-2 peers.
t_case 'registry'
declare -A REG_TITLE=() REG_SEV=() REG_CWE=() REG_OWASP=() REG_SCRIPT=() REG_CONF=() REG_TAG=() REG_SCOPE=()
_cur_id=''
while IFS= read -r _line || [[ -n $_line ]]; do
  [[ ${_line:0:1} == '#' ]] && continue
  [[ $_line == *': '* ]] || continue
  _key=${_line%%': '*}
  _val=${_line#*': '}
  case $_key in
    id) _cur_id=$_val ;;
    title) REG_TITLE[$_cur_id]=$_val ;;
    severity) REG_SEV[$_cur_id]=$_val ;;
    confidence) REG_CONF[$_cur_id]=$_val ;;
    cwe) REG_CWE[$_cur_id]=$_val ;;
    owasp) REG_OWASP[$_cur_id]=$_val ;;
    script) REG_SCRIPT[$_cur_id]=$_val ;;
    coverage-scope) REG_SCOPE[$_cur_id]=$_val ;;
    tags) [[ -z ${REG_TAG[$_cur_id]:-} ]] && REG_TAG[$_cur_id]=$_val ;;
  esac
done <"$ROOT/modules/dast/passive/checks-markup.rules"

_reg_ids=''
for _id in "${!REG_SCRIPT[@]}"; do
  [[ ${REG_SCRIPT[$_id]} == 'passive/markup.sh' ]] && _reg_ids+="$_id "
done
assert_eq "${#_MK_CHECK_IDS[@]}" "$(printf '%s' "$_reg_ids" | wc -w | tr -d ' ')" \
  'the registry declares exactly the ids the phase can emit - FAILS if either grows without the other'
for c in "${_MK_CHECK_IDS[@]+"${_MK_CHECK_IDS[@]}"}"; do
  _mk_catalog "$c"
  assert_eq "${REG_TITLE[$c]:-<absent>}" "$_MKC_TITLE" "$c: title agrees with the registry"
  assert_eq "${REG_SEV[$c]:-<absent>}" "$_MKC_SEV" "$c: severity agrees with the registry"
  assert_eq "${REG_CONF[$c]:-<absent>}" "$_MKC_CONF" "$c: confidence agrees with the registry"
  assert_eq "${REG_CWE[$c]:-<absent>}" "$_MKC_CWE" "$c: CWE agrees with the registry"
  assert_eq "${REG_OWASP[$c]:-<absent>}" "$_MKC_OWASP" "$c: OWASP mapping agrees with the registry"
  assert_eq 'passive/markup.sh' "${REG_SCRIPT[$c]:-<absent>}" "$c: the registry names this phase script"
  assert_eq 'target' "${REG_SCOPE[$c]:-<absent>}" "$c: coverage-scope is 'target', the value rules/RULE-FORMAT.md §9.5.1 fixes for DAST"
  assert_eq 'passive' "${REG_TAG[$c]:-<absent>}" \
    "$c: the type tag is 'passive', matching the phase table's own floor - FAILS if the two gates disagree, which tension 15 forbids"
done

# The phase table already carries this file's row, and it must be at `passive`:
# a row at a higher tier would mean a check tagged `passive` never runs.
assert_contains "$(cat "$ROOT/modules/dast/engine.sh")" 'passive/markup.sh:passive' \
  'modules/dast/engine.sh registers this phase at the passive tier, so scan_dispatch dast runs it'

# ===========================================================================
# J. The observability and false-negative defects a QA correction found.
# ===========================================================================
# Every case in this section was watched FAILING against the code as it shipped
# before being written the right way round, and each names the reading it fails
# under.  They are grouped because they share one shape: all seven are silent in
# the direction that reads as a CLEAN SCAN RESULT, and none of the 189
# assertions above exercises the path, which is how they survived a review.

t_case 'J1: a run-level counter reset once per page'
# THE READING THIS FAILS UNDER: `_MK_FORMS_CROSS_ORIGIN` declared inside
# `_mk_analyse_one`, which runs once per PAGE, while it is read after the whole
# page loop - so only the LAST page's value survives.  The cross-origin form
# here is on the FIRST of two pages, so under that reading the count is 0 and
# the reduction is never recorded: the form is still correctly EXCLUDED from
# the CSRF check and the exclusion is silently lost, leaving the page reading
# as though it HAD been evaluated for an anti-CSRF token.
_run_case xopage mk-fixture "$B/forms" "$B/tab"
assert_contains "$(_meta coverage_reduction)" 'markup_form_posts_cross_origin' \
  'a cross-origin POST form on a page that is NOT the last one still declares its exclusion - FAILS when the counter is reset per page, where the last page (which has no form at all) zeroes it and the declaration vanishes'
assert_contains "$(_meta coverage_reduction)" 'count=1' \
  'and the count is the run total, not the last page total'

t_case 'J2: a tokenizer that failed is not a document that is clean'
# THE READING THIS FAILS UNDER: `markup_html_extract ... || true`, with the
# status discarded and `parsed` incremented unconditionally.  Under it the page
# yields an EMPTY record file that nothing guards on, so the run reports zero
# findings, zero gaps, zero reductions - and still records four check ids in
# `checks_run` as having executed against a page whose markup was never read.
_mk_extract_orig=$(declare -f markup_html_extract)
markup_html_extract() { printf 'markup_html_extract: simulated tokenizer failure\n' >&2; return 3; }
_run_case tokfail mk-fixture "$B/tab" "$B/frames"
eval "$_mk_extract_orig"
assert_contains "$(_meta coverage_gap)" 'could not be tokenized' \
  'a tokenizer that exits non-zero produces a coverage GAP naming the page - FAILS when the status is discarded, where a page with three real defects reports as tested-and-clean'
assert_contains "$(_meta coverage_reduction)" 'markup_tokenizer_failed' \
  'and a machine-readable reduction alongside it'
assert_contains "$(_meta coverage_reduction)" 'simulated tokenizer failure' \
  'and the tokenizer own stderr reaches the record - FAILS under 2>/dev/null, which throws away the only account of what went wrong'
assert_not_contains "$(_meta checks_run)" 'DAST-MARKUP-SRI_MISSING-01' \
  'and NOT ONE check id is recorded as having run - FAILS when `parsed` counts documents ATTEMPTED rather than documents TOKENIZED, which is the whole defect: checks_run is what modules/dast/run.sh honesty roll-up reads'
assert_not_contains "$(_meta checks_run)" 'DAST-MARKUP-CSRF_TOKEN_ABSENT-01' \
  'including the CSRF one'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'and no finding is invented from an empty record stream'

t_case 'J3: a token list is never glob-expanded against the working directory'
# THE READING THIS FAILS UNDER: `local -a toks=($list)` with pathname expansion
# left ON.  `$list` is a `rel` attribute lifted verbatim out of a scanned
# response, so a target serving rel="*" has that `*` expanded against the
# scanner CURRENT WORKING DIRECTORY - and on a host where a file called
# `noopener` happens to sit there, the target suppresses its own tabnabbing
# finding.  The assertion is run from inside a directory containing exactly
# such a file, which is what makes it discriminate: without it, both the
# correct and the broken implementation return 1 and the case pins nothing.
_globdir=$W/globtest
rm -rf "$_globdir"; mkdir -p "$_globdir"
: >"$_globdir/noopener"
: >"$_globdir/stylesheet"
_mk_glob_pwd=$PWD
# `markup_tokens_have` returns a STATUS, so each case is turned into a word
# first - `assert_true` takes a value, not a command string.
_tok_says() { if markup_tokens_have "$1" "$2"; then printf 'matched'; else printf 'no'; fi; }
_sri_says() { if markup_link_takes_sri "$1"; then printf 'matched'; else printf 'no'; fi; }
cd "$_globdir"
assert_eq no "$(_tok_says '*' noopener)" \
  'rel="*" does NOT satisfy a query for noopener - FAILS with globbing on, where a file named noopener in the scanner cwd lets attacker-authorable text switch off a security check, and the verdict depends on where the scanner was started rather than on the response'
assert_eq no "$(_tok_says 'external *' noopener)" \
  'and neither does a glob sitting alongside a real token'
assert_eq no "$(_sri_says '*')" \
  'the SRI check inherits the same function, so rel="*" does not make a <link> look like a stylesheet either - FAILS with globbing on, which is a second check the same one-character response switches off'
assert_eq matched "$(_tok_says 'external noopener' noopener)" \
  'and a genuine token list still matches from that same directory - FAILS if the fix disables the WORD SPLIT rather than the pathname expansion, which would make every multi-token rel attribute stop matching'
cd "$_mk_glob_pwd"
_noglob_leaked=no; [[ -o noglob ]] && _noglob_leaked=yes
assert_eq no "$_noglob_leaked" \
  'and pathname expansion is left ON for the caller - FAILS if `set -f` escapes the function, which is exactly what `local -` does on bash 4.2 (this project frozen minimum, enforced in lib/core.sh) where it is not a scoping construct at all'

t_case 'J4: a password field outside any form still marks the page sensitive'
# THE READING THIS FAILS UNDER: the tokenizer emitting a `field` record only
# `if (informs)`.  A single-page login page submits by XHR and has no <form>
# element at all, so its password box is outside one - and suppressed, the
# CONTENT half of the sensitive-page signal never fires and the page findings
# are downgraded from TABNABBING_SENSITIVE-01 to TABNABBING-01.  The path here
# is deliberately NOT sensitive-looking, so the path heuristic cannot rescue it
# and the content signal is the only thing under test.  NO inventory is given,
# so the only page fetched is the target own base-url `/` - an inventory entry
# would be fetched IN ADDITION to it and served this same document, making the
# expected finding count two and the case harder to read.
_doc_orig=$(declare -f _doc)
_doc() {
  cat <<'H'
<!DOCTYPE html><html><body>
<div id="app">
  <input type="text" name="user">
  <input type="password" name="pw">
  <button type="button">go</button>
</div>
<a href="https://out.example/help" target="_blank">help</a>
</body></html>
H
}
_run_case spapw mk-fixture
eval "$_doc_orig"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING_SENSITIVE-01)" \
  'a page whose password box is NOT nested in a <form> is still an authentication page - FAILS when field records are gated on an open form, which is exactly the single-page-application shape this signal exists for'
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'and it is NOT also reported under the ordinary id - the two are one finding carried by whichever id the page earns'

t_case 'J5: an attribute with no separator before it still parses'
# THE READING THIS FAILS UNDER: `attr()` requiring `[ \t\r\n/]` before the
# attribute name.  HTML does not require whitespace after a quoted value, so
# `<a href="..."target="_blank">` is markup every browser accepts - and under
# that class the `target` is never found, the `_blank` test fails, and the
# check cannot fire at all.
_doc_orig=$(declare -f _doc)
_doc() {
  cat <<'H'
<!DOCTYPE html><html><body>
<a href="https://out.example/nosep"target="_blank">no separator before target</a>
<iframe src="https://third.example/w"sandbox></iframe>
</body></html>
H
}
_run_case nosep mk-fixture
eval "$_doc_orig"
assert_eq 1 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'a target attribute written straight after a closing quote is read - FAILS when only whitespace and / count as separators, where the check is silently inert on markup browsers accept'
assert_eq 0 "$(_count_check DAST-MARKUP-FRAME_UNTRUSTED-01)" \
  'and a sandbox attribute written the same way is a sandbox - FAILS the other way, which would invent a finding about a frame that IS constrained'

t_case 'J6: deselecting one check never silences another'
# THE READING THIS FAILS UNDER: `_mk_selected FRAME_INSECURE_SCHEME || continue`
# skipping the whole record rather than falling through to the untrusted-frame
# arm.  The frame below is plaintext AND cross-origin AND unsandboxed; with the
# plaintext id filtered out of the run, that reading emits NEITHER finding.
# This was dormant only while `dast_check_selected` did not exist - it does now
# (modules/dast/engine.sh), so it is reachable on any --profile-scan run.
_doc_orig=$(declare -f _doc)
_doc() { printf '%s\n' '<html><body><iframe src="http://plain.example/w"></iframe></body></html>'; }
_new_run frameselect mk-fixture
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_TARGET=mk-fixture SCOURSH_DAST_CELL=mk-fixture
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_TARGET SCOURSH_DAST_CELL
# This suite sources markup_engine.sh alone, so modules/dast/engine.sh - where
# `dast_check_selected` lives - is not in the process and `_mk_selected` takes
# its documented "no filter chain: all selected" fallback.  The reader is
# defined here EXACTLY as engine.sh defines it (whole-line membership, empty
# means all selected) so this case exercises the real filtering rather than a
# convenient approximation of it.
dast_check_selected() {
  local id=$1
  [[ -n ${SCOURSH_SELECTED_CHECKS:-} ]] || return 0
  [[ $'\n'"$SCOURSH_SELECTED_CHECKS"$'\n' == *$'\n'"$id"$'\n'* ]]
}
SCOURSH_SELECTED_CHECKS='DAST-MARKUP-FRAME_UNTRUSTED-01'
export SCOURSH_SELECTED_CHECKS
_dast_markup_phase
unset SCOURSH_SELECTED_CHECKS
unset -f dast_check_selected
eval "$_doc_orig"
assert_eq 0 "$(_count_check DAST-MARKUP-FRAME_INSECURE_SCHEME-01)" \
  'the deselected check does not fire, which is tension 15 doing its job'
assert_eq 1 "$(_count_check DAST-MARKUP-FRAME_UNTRUSTED-01)" \
  'but the SELECTED check on that same element still does - FAILS when the plaintext arm `continue`s on being deselected, where filtering out one id silently switches off a different one the operator kept'

t_case 'J7: a tabnabbing id that ran clean is still recorded as having run'
# THE READING THIS FAILS UNDER: gating the two tabnabbing ids in `checks_run`
# on `_MK_FIRED > 0` - did this id produce a FINDING.  `/` carries a
# cross-origin target=_blank link that is correctly protected by
# rel="noopener noreferrer", so the check ran and found nothing; under that
# reading a clean page and an untested page look identical for these two ids
# alone, and tension 12 can never infer `fixed` for them - the run that would
# prove a fix is exactly the run that drops the coverage.
_run_case tabclean mk-fixture
assert_eq 0 "$(_count_check DAST-MARKUP-TABNABBING-01)" \
  'the protected link on / is not a finding'
assert_contains "$(_meta checks_run)" 'DAST-MARKUP-TABNABBING-01' \
  'and the id is STILL in checks_run, because a page was classified under it and evaluated - FAILS when the condition is "did it fire", which makes a clean result indistinguishable from an untested one for these two ids and only these two'
assert_not_contains "$(_meta checks_run)" 'DAST-MARKUP-TABNABBING_SENSITIVE-01' \
  'while the sensitive id is NOT claimed, because no page on this run was an authentication page - FAILS if the gate is dropped entirely rather than moved, which would over-claim coverage the run never had'

# ===========================================================================
printf '\n== dast-markup: %d passed, %d failed ==\n' "$T_PASS" "$T_FAIL"
# ===========================================================================
(( T_FAIL == 0 ))
