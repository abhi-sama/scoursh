#!/usr/bin/env bash
# tests/suites/dast-xss.sh - modules/dast/active/xss.sh: reflected-XSS
# marker-token unescaped-reflection detection (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-15, tier 4).
#
# NOTHING HERE TOUCHES THE NETWORK.  SCOURSH_HTTP_RESOLVE and
# SCOURSH_HTTP_TRANSPORT are stubbed for the whole file, so every "response" is
# a RECORDED one this suite composes itself.  That is the ticket's own
# requirement and it is not a convenience: a probe tested only against a live
# target proves nothing repeatable, because the target's own escaping is the
# variable under test.
#
# EVERY ASSERTION NAMES THE READING IT FAILS UNDER.  This project's review
# history is explicit that a test written after the rule, agreeing with its
# author, certifies the defect green - so the cases here are built in pairs
# wherever a decision has a plausible wrong answer: a raw reflection AND the
# byte-identical escaped one, `<` raw with `>` escaped as well as both raw, a
# quote raw inside the value it delimits as well as inside the other quote.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes HTML, JS and parameter syntax literally,
#   single-quoted on purpose.
# SC2030/SC2031: a `VAR=val cmd` prefix before a subprocess is deliberately
#   scoped to that one invocation.
# shellcheck disable=SC2016,SC2030,SC2031

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# Sourcing the shared inject engine pulls in lib/http.sh -> lib/config.sh +
# lib/findings.sh -> lib/records.sh -> lib/core.sh, which bootstraps the scratch
# dir and its traps.  The phase script itself is sourced LATER, once a throwaway
# run exists for it to execute against - it has no sourced-once guard and runs
# its phase function at source time.
# -x back-edge cut: modules/dast/active/inject_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "$ROOT/modules/dast/active/inject_engine.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/dast-xss-workspace
rm -rf "$W"; mkdir -p "$W"

# ---------------------------------------------------------------------------
# Scope and scanner config.
# ---------------------------------------------------------------------------
# The ceilings are set high so DAST-32's clamp and DAST-01's real throttle sleep
# never interfere with a test's timing or its request count.  The target is an
# RFC 2606 reserved example domain (DAST-35's lint requires it) and is never
# dialled: both the resolver and the transport below are stubs.
SCOPE=$W/scope.conf
cat >"$SCOPE" <<'EOF'
id: xss-fixture
base-url: https://xss.fixture.example/
notes: Fixture target for tests/suites/dast-xss.sh. Never dialled - both the
  resolver and the transport are stubbed for the whole suite.
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

_xss_resolve() {
  case $1 in
    xss.fixture.example) printf '203.0.113.7' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_TRANSPORT=_xss_transport
SCOURSH_HTTP_RESOLVE=_xss_resolve

# ---------------------------------------------------------------------------
# The mock target.
# ---------------------------------------------------------------------------
# The probe sends a marker with `<`, `>`, `"` and `'` appended, and inject_send
# percent-encodes that before it reaches the wire - so what this transport
# receives on the query string is `...%3C%3E%22%27`.  Each endpoint below models
# one way a real application handles those bytes on the way BACK out, which is
# the only thing this probe measures:
#
#   /html-raw       HTML text, decoded verbatim          -> HTML finding, high
#   /html-escaped   HTML text, entity-encoded            -> SAFE (the control)
#   /html-partial   HTML text, `<` encoded but `>` raw   -> SAFE (`<` alone
#                                                           opens nothing)
#   /attr-raw       double-quoted attribute, verbatim    -> ATTR finding, high
#   /attr-escaped   double-quoted attribute, encoded     -> SAFE
#   /attr-otherq    SINGLE-quoted attribute, only `"` raw-> SAFE (the raw quote
#                                                           is not the delimiter)
#   /attr-unquoted  unquoted attribute, verbatim         -> ATTR finding, medium
#   /js-raw         inside <script>, verbatim            -> JS finding, high
#   /js-escaped     inside <script>, entity-encoded      -> SAFE
#   /json-raw       verbatim BUT Content-Type json       -> SAFE + a recorded
#                                                           coverage reduction
#   /body-raw       verbatim, reached via a POST body    -> HTML finding
#                                                           (body-location proof)
#   /no-reflect     never echoes the marker at all       -> SAFE
REQ_LOG=$W/requests.log
_req_reset() { : >"$REQ_LOG"; }

# Percent-decode ONLY the four characters this probe sends.  A general decoder
# is not needed, and a `printf '%b'` one would be wrong here: it would also
# interpret backslash escapes the marker never contains.
_dec() {
  local v=$1
  v=${v//%3C/<}; v=${v//%3E/>}; v=${v//%22/\"}; v=${v//%27/\'}
  printf '%s' "$v"
}
# The entity encoding a correctly-written application applies.
#
# EVERY `&` HERE IS BACKSLASH-ESCAPED, AND THAT IS LOAD-BEARING RATHER THAN
# DECORATIVE.  Bash 5.2 made `&` in the REPLACEMENT half of `${var//pat/repl}`
# expand to the matched text, the way sed's does; bash 4.2 (this project's
# frozen minimum) treats it as a literal.  Written unescaped, `${v//%3C/&lt;}`
# therefore yields `%3Clt;` on a modern macOS bash instead of `&lt;` - and the
# failure is INVISIBLE in the direction that matters, because a mangled
# "escaped" fixture still contains no raw `<`, so every escaped-control case
# below still reports SAFE and still passes.  It passes for the wrong reason:
# the control would no longer be testing entity encoding at all, and the pair
# that gives this suite its whole value - the same marker, escaped versus raw -
# would have collapsed into "raw versus gibberish".  This was measured here, not
# reasoned about: the unescaped spelling shipped first and was caught only
# because the /attr-otherq case, whose `&` sits mid-string rather than at the
# front, failed loudly while its three siblings sat green.
_enc() {
  local v=$1
  v=${v//%3C/\&lt;}; v=${v//%3E/\&gt;}; v=${v//%22/\&quot;}; v=${v//%27/\&#39;}
  printf '%s' "$v"
}
# Pull the value of one key out of the received surface.
_val_of() {
  local surface=$1 key=$2 v
  case $surface in
    *"$key="*) v=${surface#*"$key="}; v=${v%%&*} ;;
    *) v='' ;;
  esac
  printf '%s' "$v"
}

_xss_transport() {
  local method=$1 path=$5
  local body=${_HTTP_TX_BODY:-}
  local surface="$path?$body"
  local status=200 ctype='text/html' out='<html><body>nothing here</body></html>'
  local q raw enc
  q=$(_val_of "$surface" q)
  raw=$(_dec "$q"); enc=$(_enc "$q")

  case $path in
    /html-raw*)
      out="<html><body><p>You searched for: $raw</p></body></html>" ;;
    /html-escaped*)
      out="<html><body><p>You searched for: $enc</p></body></html>" ;;
    /html-partial*)
      # `<` entity-encoded, `>` left raw.  A probe that flagged on either
      # character alone would call this vulnerable; it is not, because there is
      # no way to open a tag without a `<`.
      out="<html><body><p>You searched for: ${raw//</\&lt;}</p></body></html>" ;;
    /attr-raw*)
      out="<html><body><a href=\"/s?x=$raw\">link</a></body></html>" ;;
    /attr-escaped*)
      out="<html><body><a href=\"/s?x=$enc\">link</a></body></html>" ;;
    /attr-otherq*)
      # A SINGLE-quoted value in which only the DOUBLE quote came back raw.
      # The raw quote is not the one delimiting this value, so it breaks
      # nothing - a probe that flagged any raw quote in any attribute would
      # wrongly fire here.
      out="<html><body><a href='/s?x=${raw//\'/\&#39;}'>link</a></body></html>" ;;
    /attr-unquoted*)
      out="<html><body><a href=/s?x=$raw>link</a></body></html>" ;;
    /js-raw*)
      out="<html><head><script>var term = \"$raw\";</script></head><body>x</body></html>" ;;
    /js-escaped*)
      out="<html><head><script>var term = \"$enc\";</script></head><body>x</body></html>" ;;
    /json-raw*)
      ctype='application/json'
      out="{\"term\":\"$raw\",\"results\":[]}" ;;
    /body-raw*)
      q=$(_val_of "$surface" user); raw=$(_dec "$q")
      out="<html><body><p>Welcome back, $raw</p></body></html>" ;;
    /no-reflect*)
      out='<html><body><p>No results.</p></body></html>' ;;
  esac

  # The WHOLE surface is logged, not just the path: the non-destructive-posture
  # assertions below read this back to prove what was actually sent.
  printf '%s %s\n' "$method" "$surface" >>"$REQ_LOG"
  [[ -n ${_HTTP_TX_BODY_OUT:-} ]] && printf '%s' "$out" >"$_HTTP_TX_BODY_OUT"
  printf '%s\n\n%s\n' "$status" "$ctype"
}

# ---------------------------------------------------------------------------
# Inventory writers (docs/INVENTORY-FORMAT.md).
# ---------------------------------------------------------------------------
_write_full_inventory() {
  cat >"$W/endpoints.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_hraw",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/html-raw",      "path": "/html-raw" },
  { "id": "ep_hesc",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/html-escaped",  "path": "/html-escaped" },
  { "id": "ep_hpart", "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/html-partial",  "path": "/html-partial" },
  { "id": "ep_araw",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/attr-raw",      "path": "/attr-raw" },
  { "id": "ep_aesc",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/attr-escaped",  "path": "/attr-escaped" },
  { "id": "ep_aoth",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/attr-otherq",   "path": "/attr-otherq" },
  { "id": "ep_auq",   "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/attr-unquoted", "path": "/attr-unquoted" },
  { "id": "ep_jraw",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/js-raw",        "path": "/js-raw" },
  { "id": "ep_jesc",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/js-escaped",    "path": "/js-escaped" },
  { "id": "ep_json",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/json-raw",      "path": "/json-raw" },
  { "id": "ep_body",  "target": "xss-fixture", "method": "POST", "url": "https://xss.fixture.example/body-raw",      "path": "/body-raw" },
  { "id": "ep_none",  "target": "xss-fixture", "method": "GET",  "url": "https://xss.fixture.example/no-reflect",    "path": "/no-reflect" }
] }
EOF
  cat >"$W/parameters.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "q1",  "endpoint_id": "ep_hraw",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q2",  "endpoint_id": "ep_hesc",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q3",  "endpoint_id": "ep_hpart", "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q4",  "endpoint_id": "ep_araw",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q5",  "endpoint_id": "ep_aesc",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q6",  "endpoint_id": "ep_aoth",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q7",  "endpoint_id": "ep_auq",   "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q8",  "endpoint_id": "ep_jraw",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q9",  "endpoint_id": "ep_jesc",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q10", "endpoint_id": "ep_json",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" },
  { "id": "q11", "endpoint_id": "ep_body",  "target": "xss-fixture", "name": "user", "location": "body",  "example": "amy" },
  { "id": "q12", "endpoint_id": "ep_none",  "target": "xss-fixture", "name": "q",    "location": "query", "example": "abc" }
] }
EOF
}

# ---------------------------------------------------------------------------
# Per-case run isolation and shard readers.
# ---------------------------------------------------------------------------
_new_run() {
  local dir=$W/run.$1
  rm -rf "$dir"
  run_init "$dir"
  # The DAST-33 authorization affirmation the rate/budget ceilings read.
  run_record authorization_affirmed true
  run_record authorization_target xss-fixture
  occurrence_reset_all
  _req_reset
}

_shard_text() {
  local f out=''
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    out+=$(cat -- "$f"); out+=$'\n'
  done
  printf '%s' "$out"
}

# Count findings matching a check id AND a parameter name.
_count_finding() {
  local check=$1 param=$2 f line fld n=0
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      local hc=0 hp=0
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == "check_id=$check" ]] && hc=1
        [[ $fld == "loc_param_name=$param" ]] && hp=1
      done
      (( hc && hp )) && n=$(( n + 1 ))
    done <"$f"
  done
  printf '%s' "$n"
}

# Total findings for a check id, whatever the parameter.
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

# The value of one field on the first finding whose url names a given path.
_field_at_path() {
  local want_path=$1 want=$2 f line fld hit out
  for f in "$SCOURSH_RUN_DIR"/shards/*.fields; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      hit='' out=''
      local IFS=$'\t'
      for fld in $line; do
        [[ $fld == url=*"$want_path"* ]] && hit=1
        [[ $fld == "$want="* ]] && out=${fld#"$want="}
      done
      [[ -n $hit ]] && { printf '%s' "$out"; return 0; }
    done <"$f"
  done
  printf ''
}

# ===========================================================================
# Bootstrap: load the phase script.
# ===========================================================================
# xss.sh runs its phase function AT SOURCE TIME and carries no sourced-once
# guard (modules/dast/engine.sh reaches a phase with a plain `source`, and one
# run may legitimately reach the same phase twice).  So it is sourced exactly
# ONCE, here, against a throwaway run with an empty inventory - a no-op that
# records a coverage gap and emits nothing - and every case below invokes
# `_dast_xss_phase` as a plain function call instead.  It is sourced BEFORE the
# unit sections rather than after them because those sections exercise its own
# pure functions directly.
SCOURSH_DAST_TARGET=xss-fixture
SCOURSH_DAST_CELL=xss-fixture
SCOURSH_DAST_AUTHED=false
SCOURSH_DAST_INTENSITY=active
SCOURSH_DAST_ALLOW_INTRUSIVE=false
export SCOURSH_DAST_TARGET SCOURSH_DAST_CELL SCOURSH_DAST_AUTHED
export SCOURSH_DAST_INTENSITY SCOURSH_DAST_ALLOW_INTRUSIVE
unset SCOURSH_SELECTED_CHECKS
SCOURSH_DAST_ENDPOINTS='' SCOURSH_DAST_PARAMETERS=''
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_new_run boot
# shellcheck source=modules/dast/active/xss.sh
source "$ROOT/modules/dast/active/xss.sh"

# ===========================================================================
# A. The vendored character ledger, and the probe value derived from it
# ===========================================================================
# This section pins the defect this ticket found in the module as restored:
# `_XSS_PROBE_SUFFIX` was referenced when composing the probe value but never
# assigned anywhere, so under the mandatory `set -Eeuo pipefail` the phase
# aborted with "unbound variable" the first time it reached a parameter.  The
# suffix is now DERIVED from the ledger, and these cases fail under both the
# original (absent) reading and a hardcoded-literal one.
t_case 'ledger: the vendored file loads into parallel arrays in file order'
_xss_load_chars "$ROOT/modules/dast/payloads"
assert_eq 4 "${#_XSS_C_NAME[@]}" \
  'the shipped xss-marker-chars.txt declares exactly four characters'
assert_eq 'lt gt dq sq' "${_XSS_C_NAME[*]}" \
  'names load in FILE order - _xss_scan_window reads the window back in this same order, so a reordering here silently misaligns it'

t_case 'ledger: the probe suffix is DERIVED from the ledger, not hardcoded'
assert_eq '<>"'"'" "$_XSS_PROBE_SUFFIX" \
  'the probe suffix is the ledger characters concatenated in file order with NO separator - FAILS under the restored code, where _XSS_PROBE_SUFFIX was never assigned at all and the phase died on an unbound variable'
mkdir -p "$W/chars-trimmed"
printf 'lt\t<\t&lt;\ngt\t>\t&gt;\n' >"$W/chars-trimmed/xss-marker-chars.txt"
_xss_load_chars "$W/chars-trimmed"
assert_eq '<>' "$_XSS_PROBE_SUFFIX" \
  'trimming the ledger to two characters sends only those two - FAILS under a hardcoded literal suffix, which would keep sending characters the context rules can no longer reason about'
assert_eq 2 "${#_XSS_C_NAME[@]}" 'and the arrays shrink with it'

t_case 'ledger: an absent file yields an empty ledger rather than an error'
mkdir -p "$W/chars-empty"
_xss_load_chars "$W/chars-empty"
assert_eq 0 "${#_XSS_C_NAME[@]}" \
  'an absent xss-marker-chars.txt loads zero characters and does not abort - the phase turns this into a recorded coverage gap, tested in section G'
assert_eq '' "$_XSS_PROBE_SUFFIX" 'and the probe suffix is empty'

# Restore the real ledger for the sections below.
_xss_load_chars "$ROOT/modules/dast/payloads"

# ===========================================================================
# B. Raw versus escaped: the positional window walk
# ===========================================================================
# The heart of the probe.  A naive "does the body contain a raw `<` anywhere"
# test answers a question about the PAGE, not the reflection - every HTML
# document is full of raw `<`.  The mixed cases are the ones that fail under a
# fixed-offset reading.
t_case 'window: every character raw is read as every character raw'
_xss_scan_window "<>\"' and then some trailing text"
assert_eq '1 1 1 1' "${_XSS_RAW[*]}" \
  'a verbatim reflection marks all four characters raw'

t_case 'window: every character entity-encoded is read as none raw'
_xss_scan_window '&lt;&gt;&quot;&#39; and then some trailing text'
assert_eq '0 0 0 0' "${_XSS_RAW[*]}" \
  'a fully entity-encoded reflection marks nothing raw - FAILS under a "does the body contain the marker" test, which cannot tell escaped from raw and would flag every reflecting parameter on earth'

t_case 'window: a MIXED reflection stays aligned across the escaped characters'
_xss_scan_window '&lt;>&quot;&#39;'
assert_eq '0 1 0 0' "${_XSS_RAW[*]}" \
  'with `<` escaped and `>` raw, the walk consumes the 4-byte entity and reads `>` next - FAILS under a fixed-offset reading, which would look at byte 1 (the `l` of &lt;) for `>` and mark the wrong characters'
_xss_scan_window '<&gt;"&#39;'
assert_eq '1 0 1 0' "${_XSS_RAW[*]}" \
  'and the complementary mixture - `<` raw, `>` escaped, `"` raw - reads back correctly too'

t_case 'window: a DROPPED character is not raw, and does not derail the walk'
# A filter that strips `<` and `>` entirely rather than encoding them: the two
# quotes still follow, and must still be read as raw.
_xss_scan_window "\"'"
assert_eq '0 0 1 1' "${_XSS_RAW[*]}" \
  'characters removed by a filter are absent, not raw, and the walk consumes nothing for them so the two quotes that DID come back are still read - FAILS if a non-match consumed a byte, which would swallow the double quote'

t_case 'window: alternative encodings in the ledger are all recognised'
_xss_scan_window '&#60;&#x3E;&#x22;%27'
assert_eq '0 0 0 0' "${_XSS_RAW[*]}" \
  'decimal, hex and percent encodings all count as escaped - FAILS if only the named entity form were recognised, which would report a hex-encoding application as vulnerable'
_xss_scan_window '\u003c\u003e\u0022\u0027'
assert_eq '0 0 0 0' "${_XSS_RAW[*]}" \
  'and the JavaScript/JSON string escapes, which is how a correctly-written script block encodes them - FAILS if only the HTML entity forms were in the ledger, which would report a correctly-escaped script block as vulnerable'

t_case 'window: _xss_raw addresses characters by NAME, not by index'
_xss_scan_window '<&gt;&quot;&#39;'
assert_status 0 'lt came back raw here' _xss_raw lt
assert_status 1 'gt was escaped here' _xss_raw gt
assert_status 1 'a name the ledger does not carry is never raw - FAILS if an unknown name defaulted to raw, which would let trimming the ledger manufacture a finding rather than narrow coverage' _xss_raw nosuchname

# ===========================================================================
# C. Where in the document the reflection landed
# ===========================================================================
# `_xss_context` is a small auditable state test, not an HTML parser.  What it
# must get right is exactly three questions, and each answer below is paired
# with the wrong reading it fails under.
_ctx() {
  local body=$1
  _xss_first_index "$body" MARK
  _xss_context "$body" "$_XSS_IDX"
}

t_case 'context: ordinary element text is html'
_ctx '<html><body><p>hello MARK<>"</p></body></html>'
assert_eq html "$_XSS_CTX" 'a reflection between tags is HTML text'
assert_eq '' "$_XSS_ATTR_QUOTE" 'and has no delimiting quote'

t_case 'context: inside a tag is attr, and the delimiting quote is identified'
_ctx '<html><body><a href="/s?x=MARK">link</a>'
assert_eq attr "$_XSS_CTX" 'an unclosed `<` after the last `>` means we are inside a tag'
assert_eq '"' "$_XSS_ATTR_QUOTE" \
  'an ODD number of double quotes since the tag opened means one is still open - FAILS under a "was there any quote" test, which cannot tell an open value from a closed one'

t_case 'context: a single-quoted attribute value reports the single quote'
_ctx "<html><body><a href='/s?x=MARK'>link</a>"
assert_eq attr "$_XSS_CTX" 'still inside the tag'
assert_eq "'" "$_XSS_ATTR_QUOTE" 'and the single quote is what delimits this value'

t_case 'context: an UNQUOTED attribute value reports no quote'
_ctx '<html><body><a href=/s?x=MARK>link</a>'
assert_eq attr "$_XSS_CTX" 'inside the tag'
assert_eq '' "$_XSS_ATTR_QUOTE" \
  'an even (zero) count of both quotes means the value is unquoted - which needs a raw `>` to break out, not a raw quote'

t_case 'context: inside a script element is js'
_ctx '<html><head><script>var a = "MARK";</script></head>'
assert_eq js "$_XSS_CTX" \
  'the last <script opener is later than the last </script closer and its own tag is closed, so this is script text'

t_case 'context: AFTER a script element closed is html again'
_ctx '<html><head><script>var a = 1;</script></head><body><p>MARK</p>'
assert_eq html "$_XSS_CTX" \
  'the </script closer is later than the opener - FAILS under a "does the page contain <script" test, which would call every reflection on a scripted page a script-context one'

t_case 'context: inside a script SRC attribute is attr, NOT js'
_ctx '<html><head><script src="/j?x=MARK"></script></head>'
assert_eq attr "$_XSS_CTX" \
  'the <script opener has not been closed with `>` yet, so the marker is in an attribute value, not script text - FAILS if the opener/closer test alone decided it, which would apply the JS rules to an attribute and print the wrong remediation'
assert_eq '"' "$_XSS_ATTR_QUOTE" 'and its delimiter is the double quote'

t_case 'context: a stray unclosed `<` far back falls back to html text'
# _XSS_MAX_TAG_SPAN bounds how far back a `<` can be and still count as an open
# tag.  Beyond it the conservative reading is HTML text, because the attribute
# rules are the ones that fire on a bare quote.
_FAR=$(printf 'x%.0s' $(seq 1 9000))
_ctx "<p>a < b, and $_FAR MARK</p>"
assert_eq html "$_XSS_CTX" \
  'a `<` 9000 bytes back is prose, not an unclosed tag - FAILS without the span bound, which would classify every reflection on such a page as an attribute value and fire on a bare quote'

# ===========================================================================
# D. The decision rules: which raw character matters in which context
# ===========================================================================
_decide_at() {
  local body=$1 win
  _xss_first_index "$body" MARK
  win=${body:_XSS_IDX + 4:160}
  _xss_scan_window "$win"
  _xss_context "$body" "$_XSS_IDX"
  _xss_decide
}

t_case 'decide: HTML text needs BOTH < and > raw'
_decide_at "<p>MARK<>\"'</p>"
assert_eq html "$_XSS_KIND" 'both raw opens a new element'
assert_eq high "$_XSS_CONF" 'and that is a high-confidence break-out'
_decide_at '<p>MARK&lt;>&quot;&#39;</p>'
assert_eq '' "$_XSS_KIND" \
  'a raw `>` with `<` escaped is SAFE - there is nothing to open a tag with; FAILS under an "any raw character is XSS" rule, the classic false-positive generator'
_decide_at '<p>MARK<&gt;&quot;&#39;</p>'
assert_eq '' "$_XSS_KIND" \
  'and a raw `<` with `>` escaped is SAFE too - the tag can never be terminated'

t_case 'decide: HTML text ignores raw quotes entirely'
_decide_at "<p>MARK&lt;&gt;\"'</p>"
assert_eq '' "$_XSS_KIND" \
  'raw quotes in element text are just characters - FAILS if the attribute rule leaked into the html arm'

t_case 'decide: a double-quoted attribute needs its OWN delimiter raw'
_decide_at "<a href=\"MARK<>\"'\">x</a>"
assert_eq attr "$_XSS_KIND" 'the raw double quote closes the value'
assert_eq high "$_XSS_CONF" 'a delimiter break-out is high confidence'
_decide_at '<a href="MARK&lt;&gt;&quot;&#39;">x</a>'
assert_eq '' "$_XSS_KIND" 'the escaped control is SAFE'
_decide_at "<a href=\"MARK<>&quot;'\">x</a>"
assert_eq '' "$_XSS_KIND" \
  'inside a DOUBLE-quoted value, a raw single quote and a raw `<` break nothing while the double quote is encoded - FAILS under an "any raw quote in an attribute" rule'

t_case 'decide: a single-quoted attribute needs the single quote raw'
_decide_at "<a href='MARK&lt;&gt;&quot;'>x</a>"
assert_eq attr "$_XSS_KIND" 'the raw single quote closes a single-quoted value'
assert_eq high "$_XSS_CONF" 'also high confidence'

t_case 'decide: an UNQUOTED attribute needs a raw >'
_decide_at '<a href=MARK&lt;>&quot;&#39;>x</a>'
assert_eq attr "$_XSS_KIND" 'a raw `>` ends the tag when the value is unquoted'
assert_eq medium "$_XSS_CONF" \
  'reported at MEDIUM confidence, because an unquoted value is also the shape most likely to have been read wrong'

t_case 'decide: a script block, both angle brackets raw, is high confidence'
_decide_at "<script>var a = \"MARK<>\"';</script>"
assert_eq js "$_XSS_KIND" 'the script element itself can be closed'
assert_eq high "$_XSS_CONF" 'which needs no assumption about string literals'

t_case 'decide: a script block with only a raw quote is MEDIUM, and says why'
_decide_at "<script>var a = \"MARK&lt;&gt;\"';</script>"
assert_eq js "$_XSS_KIND" 'a raw quote can terminate a JavaScript string literal'
assert_eq medium "$_XSS_CONF" \
  'but only IF the value sits inside one, which this probe does not verify - so it is medium, not high; FAILS if it were reported at the same confidence as the angle-bracket case'
assert_contains "$_XSS_WHY" 'if the value is embedded in one' \
  'and the evidence states that assumption out loud rather than hiding it'

t_case 'decide: a fully escaped script reflection is SAFE'
_decide_at '<script>var a = "MARK&lt;&gt;&quot;&#39;";</script>'
assert_eq '' "$_XSS_KIND" 'the escaped control in script context is safe'

# ===========================================================================
# E. The content-type gate
# ===========================================================================
t_case 'content type: rendering types are classified html'
for ct in 'text/html' 'text/html; charset=utf-8' 'application/xhtml+xml' 'image/svg+xml' 'TEXT/HTML'; do
  _xss_ct_kind "$ct"
  assert_eq html "$_XSS_CT_KIND" "'$ct' renders as markup (parameters and case are ignored)"
done

t_case 'content type: an EMPTY type is treated as rendering'
_xss_ct_kind ''
assert_eq html "$_XSS_CT_KIND" \
  'a response with no declared type is exactly the one a browser may content-sniff, so it is judged - FAILS if an empty type were lumped in with `other` and silently skipped'

t_case 'content type: script types are js'
_xss_ct_kind 'application/javascript'
assert_eq js "$_XSS_CT_KIND" 'a served script is script'

t_case 'content type: non-rendering types are other'
for ct in 'application/json' 'text/plain' 'application/octet-stream'; do
  _xss_ct_kind "$ct"
  assert_eq other "$_XSS_CT_KIND" \
    "'$ct' does not render as markup - FAILS under a rule that flags a raw < anywhere, which would report every JSON API that echoes a search term"
done

# ===========================================================================
# F. The phase, end to end, against recorded responses
# ===========================================================================

t_case 'phase: a run with no parameter inventory records a GAP, not a clean result'
assert_eq '' "$(_shard_text | tr -d '[:space:]')" \
  'no inventory means no finding was emitted'
assert_contains "$(run_facts coverage_gap)" 'no known request parameters' \
  'and the run says so out loud - FAILS if an untested target were left to read as a tested one, the overstated coverage docs/DESIGN.md §15 forbids'
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-XSS_REFLECTED' \
  'nothing is recorded in checks_run when nothing was probed - checks_run means LOADED AND EXECUTED'

# --- the main pass ---------------------------------------------------------
_new_run main
_write_full_inventory
SCOURSH_DAST_ENDPOINTS=$W/endpoints.json
SCOURSH_DAST_PARAMETERS=$W/parameters.json
export SCOURSH_DAST_ENDPOINTS SCOURSH_DAST_PARAMETERS
_dast_xss_phase

t_case 'phase: a raw reflection into HTML text is found'
assert_eq 1 "$(_count_finding DAST-INJ-XSS_REFLECTED_HTML-01 q)" \
  'exactly one HTML-context finding on a query parameter, from the one endpoint that echoes the marker verbatim into element text'
assert_contains "$(_field_at_path /html-raw url)" '/html-raw' \
  'and it is located on /html-raw'

t_case 'phase: the ESCAPED endpoint - byte-identical but entity-encoded - is NOT flagged'
assert_eq '' "$(_field_at_path /html-escaped check_id)" \
  '/html-escaped reflects the very same marker and escapes it correctly, so it is silent - this is THE pair that separates a real probe from a reflection detector, and FAILS under any rule that flags reflection alone'
assert_eq '' "$(_field_at_path /html-partial check_id)" \
  '/html-partial reflects `>` raw with `<` encoded and is also silent'

t_case 'phase: an attribute-value break-out is found, and its non-pairs are not'
assert_contains "$(_field_at_path /attr-raw check_id)" 'XSS_REFLECTED_ATTR' \
  '/attr-raw closes its own double-quoted value'
assert_eq '' "$(_field_at_path /attr-escaped check_id)" \
  '/attr-escaped is silent'
assert_eq '' "$(_field_at_path /attr-otherq check_id)" \
  '/attr-otherq returns a raw DOUBLE quote inside a SINGLE-quoted value, which breaks nothing - FAILS under an "any raw quote in an attribute" rule'
assert_contains "$(_field_at_path /attr-unquoted check_id)" 'XSS_REFLECTED_ATTR' \
  '/attr-unquoted breaks out via a raw `>` instead'
assert_eq medium "$(_field_at_path /attr-unquoted confidence)" \
  'and is reported at medium confidence, unlike the delimiter break-out'

t_case 'phase: a script-block reflection is found and its escaped pair is not'
assert_contains "$(_field_at_path /js-raw check_id)" 'XSS_REFLECTED_JS' \
  '/js-raw reflects into script text with both angle brackets raw'
assert_eq '' "$(_field_at_path /js-escaped check_id)" \
  '/js-escaped is silent'

t_case 'phase: a BODY parameter is probed, not only the query string'
assert_eq 1 "$(_count_finding DAST-INJ-XSS_REFLECTED_HTML-01 user)" \
  'the POST body parameter `user` is injected and its raw reflection found - FAILS if the probe only ever touched top-level query strings, which docs/DESIGN.md §7.3 explicitly rules out'

t_case 'phase: a non-reflecting parameter yields nothing'
assert_eq '' "$(_field_at_path /no-reflect check_id)" \
  '/no-reflect never echoes the marker, so there is nothing to report'

t_case 'phase: a raw reflection into JSON is NOT a finding, but IS recorded'
assert_eq '' "$(_field_at_path /json-raw check_id)" \
  'the marker comes back verbatim but the Content-Type does not render as markup, so no browser would execute it and no finding is raised'
assert_contains "$(run_facts coverage_reduction)" 'xss_non_rendering_content_type' \
  'and the run COUNTS what it declined to judge rather than staying silent - FAILS if the skip were invisible, which is a coverage reduction wearing a clean result clothing'

t_case 'phase: checks_run records the three checks that executed'
CR=$(run_facts checks_run)
for id in DAST-INJ-XSS_REFLECTED_HTML-01 DAST-INJ-XSS_REFLECTED_ATTR-01 DAST-INJ-XSS_REFLECTED_JS-01; do
  assert_contains "$CR" "$id" "checks_run names $id"
done

t_case 'phase: the finding carries the metadata rules/RULE-FORMAT.md requires'
assert_eq CWE-79 "$(_field_at_path /html-raw cwe)" 'CWE-79 is recorded'
assert_eq 'A03:2021' "$(_field_at_path /html-raw owasp)" 'and the OWASP category'
assert_eq high "$(_field_at_path /html-raw base_severity)" 'severity is high'
assert_eq high "$(_field_at_path /html-raw confidence)" 'HTML-text both-brackets-raw is high confidence'
assert_contains "$(_field_at_path /html-raw remediation)" 'on OUTPUT' \
  'the remediation names output encoding as the fix'
assert_eq query "$(_field_at_path /html-raw loc_param_location)" 'the parameter location is recorded'
assert_eq q "$(_field_at_path /html-raw loc_param_name)" 'and the parameter name'
assert_eq dast "$(_field_at_path /html-raw module)" 'the module is dast'

t_case 'phase: the evidence shows the observed bytes and states nothing was executed'
EVI=$(_field_at_path /html-raw evidence)
assert_contains "$EVI" 'reflected the unique marker' 'the evidence names the marker'
assert_contains "$EVI" 'No payload was executed and none was sent' \
  'and states the non-destructive posture explicitly, so a reader of the report knows what the probe did'

# --- the non-destructive posture, measured on what was actually sent -------
t_case 'posture: the probe sends NO executable content whatsoever'
SENT=$(cat -- "$REQ_LOG")
assert_true "$([[ -s $REQ_LOG ]] && echo 0 || echo 1)" 'requests were in fact sent'
for bad in 'script' 'alert' 'javascript' 'onerror' 'onload' 'iframe' 'svg'; do
  assert_not_contains "${SENT,,}" "$bad" \
    "nothing resembling '$bad' is ever transmitted - §7.3's rule is prove the vuln via a signal, do NOT exploit it, and this asserts it against the RECORDED TRAFFIC rather than against the source comment claiming it"
done

t_case 'posture: no destructive or invented method is ever synthesised'
assert_not_contains "$SENT" 'DELETE ' 'no DELETE is ever sent'
assert_not_contains "$SENT" 'PUT ' 'no PUT is ever sent'
assert_contains "$SENT" 'POST /body-raw' \
  'the one POST sent is the endpoint the inventory itself declared as POST, not one this probe invented'

# ===========================================================================
# G. Graceful degradation
# ===========================================================================
t_case 'degradation: an absent character ledger tests nothing and says so'
_new_run nochars
SCOURSH_DAST_XSS_PAYLOAD_DIR=$W/chars-empty _dast_xss_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'no finding is emitted'
assert_contains "$(run_facts coverage_reduction)" 'xss_marker_chars_missing' \
  'the missing ledger is recorded as a coverage reduction'
assert_contains "$(run_facts coverage_gap)" 'the absence of a test' \
  'and the gap says plainly that a clean result here is the absence of a test - FAILS if a missing data file produced a silent zero-finding run, which reads identically to a clean target'
assert_eq 0 "$(wc -l <"$REQ_LOG" | tr -d ' ')" \
  'and NOT ONE request was sent, since there was nothing to measure'

t_case 'degradation: an inventory with only uninjectable parameters is a gap'
_new_run uninject
cat >"$W/ep-gql.json" <<'EOF'
{ "schema": "scoursh.inventory.endpoints/1", "endpoints": [
  { "id": "ep_g", "target": "xss-fixture", "method": "POST", "url": "https://xss.fixture.example/graphql", "path": "/graphql" }
] }
EOF
cat >"$W/pm-gql.json" <<'EOF'
{ "schema": "scoursh.inventory.parameters/1", "parameters": [
  { "id": "g1", "endpoint_id": "ep_g", "target": "xss-fixture", "name": "op", "location": "graphql", "example": "q" }
] }
EOF
SCOURSH_DAST_ENDPOINTS=$W/ep-gql.json SCOURSH_DAST_PARAMETERS=$W/pm-gql.json _dast_xss_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'a GraphQL operation is not a scalar this probe substitutes'
assert_contains "$(run_facts coverage_reduction)" 'xss_uninjectable_parameters' \
  'the uninjectable parameter is counted'
assert_contains "$(run_facts coverage_gap)" 'none were in a location this probe could inject' \
  'and the run states that nothing was tested, rather than reporting the target clean'

# ===========================================================================
# H. The tension-15 check-set filter
# ===========================================================================
# scan.sh's filter chain records which ids survived --profile/--intensity and
# modules/dast/engine.sh's `dast_check_selected` answers for them.  xss.sh
# consults it only when that function exists, so this defines a stub to prove
# both directions of the gate.
t_case 'selection: deselecting a context suppresses only that context'
dast_check_selected() { [[ $1 != DAST-INJ-XSS_REFLECTED_HTML-01 ]]; }
_new_run sel
_dast_xss_phase
assert_eq 0 "$(_count_check DAST-INJ-XSS_REFLECTED_HTML-01)" \
  'the deselected HTML check emits nothing'
assert_eq 1 "$(_count_check DAST-INJ-XSS_REFLECTED_JS-01)" \
  'while its selected JS sibling still fires - FAILS under an all-or-nothing gate'
assert_not_contains "$(run_facts checks_run)" 'DAST-INJ-XSS_REFLECTED_HTML-01' \
  'and the deselected check is NOT claimed in checks_run'

t_case 'selection: deselecting every context sends no request at all'
dast_check_selected() { return 1; }
_new_run selnone
_dast_xss_phase
assert_eq '' "$(_shard_text | tr -d '[:space:]')" 'nothing is emitted'
assert_contains "$(run_facts coverage_reduction)" 'xss_all_checks_deselected' \
  'the wholly-deselected run is recorded'
assert_eq 0 "$(wc -l <"$REQ_LOG" | tr -d ' ')" \
  'and no traffic is generated for checks that could not report anyway'
unset -f dast_check_selected

t_summary dast-xss
