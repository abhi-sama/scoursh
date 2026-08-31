#!/usr/bin/env bash
# modules/dast/active/xss.sh - the §7.3 reflected-XSS PHASE: marker-token
# unescaped-reflection detection (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-15, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the per-location request composer, the send helper), which
# every §7.3 probe reuses; this file is the XSS-specific part: the marker, the
# escape ledger, the context classifier, and the decision rules.
#
# WHAT IS SENT, AND WHY IT IS NOT AN EXPLOIT (docs/DESIGN.md §7.3's own words:
# "inject a unique marker token, check for unescaped reflection of that exact
# token in HTML/JS/attribute context.  Reflection = finding; no payload
# execution needed").  The probe value is ONE unique alphanumeric marker with
# four bare characters appended - `<`, `>`, `"`, `'` - read from the vendored,
# auditable modules/dast/payloads/xss-marker-chars.txt.  There is no `<script>`,
# no event-handler attribute, no `javascript:` URL, no `alert(`, and nothing
# that executes in any context.  Detection is the reflection itself: if those
# characters come back RAW, request-derived data reaches the response body
# unescaped, and that is the defect.  Sending a working payload would prove
# nothing this does not and would leave executable content in the target's
# logs, caches and stored fields.
#
# THE WHOLE POINT IS TELLING REFLECTED-RAW FROM REFLECTED-ESCAPED.  A parameter
# that comes back as `&lt;&gt;&quot;&#39;` is reflected and SAFE; one that comes
# back verbatim is reflected and VULNERABLE.  Almost every parameter on a real
# application reflects something, so a probe that flagged reflection alone would
# be a false-positive generator.  `_xss_scan_window` walks the bytes that follow
# the marker in the order the vendored file declares and, for each character,
# decides raw / escaped / dropped - a character that is neither raw nor one of
# its known encodings was filtered out, which is also not raw.
#
# CONTEXT DECIDES WHAT COUNTS AS DANGEROUS, WHICH IS WHY THERE ARE THREE CHECK
# IDS AND NOT ONE.  A raw `"` in HTML text is harmless; in a double-quoted
# attribute value it is a break-out.  A raw `<` in an attribute value is
# harmless; in HTML text (with `>`) it opens a tag.  The DAST fingerprint is
# (target, method, path_template, param_location, param_name) and carries NO
# component naming the context, so one shared check id would make an HTML-text
# and an attribute reflection on the same parameter collide and dedupe to one -
# exactly the reasoning modules/dast/active/checks.rules already records for
# sqli's three techniques.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test": no parameter inventory, an uninjectable location, a missing
# character file, or a response whose content type does not render as HTML or
# JavaScript are each recorded as a coverage_gap / coverage_reduction the report
# renders (docs/DESIGN.md §15).
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes HTML, JS and parameter syntax
#   literally, single-quoted on purpose.
# shellcheck disable=SC2016
#
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran).  Consulted only under --authed; a passive/unauthed run attaches
# nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds
# ---------------------------------------------------------------------------
# Bytes examined after each marker occurrence.  It must comfortably exceed the
# whole probe tail laid end to end in its longest form - every character in the
# vendored ledger at its longest declared encoding, which for the four shipped
# today (`&#x3C;`, `&quot;`, `&#039;`, ...) is six bytes each - and it bounds the
# work done per occurrence on a large body.  160 leaves an order of magnitude of
# headroom over that worst case, so an operator adding a character to the file
# does not silently truncate the walk.
: "${_XSS_WINDOW_BYTES:=160}"
# Occurrences of one marker examined per response.  A template that echoes a
# parameter into a page ten times has ten reflection points in ten different
# contexts; taking only the first would miss the dangerous one, and taking all
# of them is unbounded work on a generated page.
: "${_XSS_MAX_OCCURRENCES:=8}"
# A `<` this far back from the reflection point is not an unclosed tag, it is a
# stray literal `<` in prose that the document never closed.  Treating a
# 100-KiB gap as "inside an attribute value" would misclassify every reflection
# on such a page, so beyond this distance the classifier falls back to HTML
# text - the conservative reading, since the attribute rules are the ones that
# fire on a bare quote.
: "${_XSS_MAX_TAG_SPAN:=8192}"

# ---------------------------------------------------------------------------
# 1. The vendored character ledger
# ---------------------------------------------------------------------------
# `_xss_read_records FILE` - prints the file's records (dropping whole-line `#`
# comments and blanks).  Prints nothing and returns 0 when the file is
# unreadable, so a caller degrades by branching on the resulting empty array
# rather than on this function's own exit status - it is called from inside a
# process substitution (`< <(...)`), and a genuine `return 1` there fires
# lib/core.sh's ERR trap even on this designed degradation path.
_xss_read_records() {
  local f=$1 line
  [[ -r $f ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# `_xss_load_chars DIR` - reads DIR/xss-marker-chars.txt into the three parallel
# arrays the rest of this file walks, in FILE ORDER, which is the order the
# probe value below lays them out and the order the window walk reads them back.
#
# `declare -ga`, never bare: in a real run this file is sourced from inside
# `dast_run_phase`, so a declaration with no `-g` would create a local that dies
# with the phase (modules/dast/engine.sh's phase table documents this at
# length).
#
# It ALSO builds `_XSS_PROBE_SUFFIX`, the bytes appended to the marker to make
# the probe value, by concatenating `_XSS_C_CHAR` in that same file order with
# NO separator between them.  The suffix is derived here rather than written as
# a literal for two reasons: a literal would silently disagree with the file the
# operator actually edited (trim a line and the probe would still send the
# character its context rules can no longer reason about), and `_xss_scan_window`
# reads the window back by consuming one character's worth of bytes at a time in
# exactly this order - so the thing sent and the thing parsed are two views of
# one array and cannot drift.  No separator, because a separator byte would
# itself be subject to the application's escaping and the walk would then have
# to decide what a missing separator meant; consuming exactly the matched bytes
# (raw, encoded, or nothing at all for a dropped character) keeps the cursor
# aligned without one.  `declare -g`, for the same phase-scoping reason as the
# arrays above.
_xss_load_chars() {
  local dir=$1 name ch esc
  declare -ga _XSS_C_NAME=() _XSS_C_CHAR=() _XSS_C_ESC=()
  declare -g _XSS_PROBE_SUFFIX=''
  while IFS=$'\t' read -r name ch esc; do
    [[ -n $name && -n $ch ]] || continue
    _XSS_C_NAME+=("$name")
    _XSS_C_CHAR+=("${ch:0:1}")
    _XSS_C_ESC+=("$esc")
    _XSS_PROBE_SUFFIX+=${ch:0:1}
  done < <(_xss_read_records "$dir/xss-marker-chars.txt")
  return 0
}

# ---------------------------------------------------------------------------
# 2. The marker
# ---------------------------------------------------------------------------
# `_xss_marker_new` - sets `_XSS_MARKER` to a fresh, unique, wholly benign
# token: lowercase letters and digits only, so nothing in it can be interpreted
# as markup, as a URL, or as a shell or SQL metacharacter, and so a WAF has
# nothing to match on.  Uniqueness is what makes attribution sound - a
# reflection of THIS token in THIS response came from THIS request, not from
# stored content or from a sibling parameter.
#
# It SETS a variable rather than printing one: a `$(...)` caller would run the
# counter increment in a subshell and discard it, collapsing every marker in the
# run onto one value (lib/core.sh's `occurrence_next` lesson).
_xss_marker_new() {
  declare -g _XSS_SEQ=$(( ${_XSS_SEQ:-0} + 1 ))
  printf -v _XSS_MARKER 'sx%04x%04x%03x' "$RANDOM" "$RANDOM" "$(( _XSS_SEQ % 4096 ))"
}

# ---------------------------------------------------------------------------
# 3. Substring positions (pure bash; no engine call, no fork)
# ---------------------------------------------------------------------------
# The body is untrusted target output (tension 10) and may hold a credential, so
# it is never passed as an argument to an external process here.  These are
# plain parameter expansions: `%%` finds the first occurrence, `%` the last.
_xss_first_index() {
  local h=$1 n=$2 pre
  pre=${h%%"$n"*}
  if [[ $pre == "$h" ]]; then _XSS_IDX=-1; else _XSS_IDX=${#pre}; fi
}

_xss_last_index() {
  local h=$1 n=$2 pre
  pre=${h%"$n"*}
  if [[ $pre == "$h" ]]; then _XSS_LIDX=-1; else _XSS_LIDX=${#pre}; fi
}

# `_xss_count_char TEXT CHAR` - sets `_XSS_COUNT`.  Used only on a single tag's
# text, whose length this file bounds, so the repeated strip is cheap.
_xss_count_char() {
  local rest=$1 c=$2
  _XSS_COUNT=0
  while [[ $rest == *"$c"* ]]; do
    rest=${rest#*"$c"}
    _XSS_COUNT=$(( _XSS_COUNT + 1 ))
  done
}

# ---------------------------------------------------------------------------
# 4. Raw versus escaped
# ---------------------------------------------------------------------------
# `_xss_escape_matches WINDOW ESCLIST` - 0 when WINDOW starts with one of the
# comma-separated encodings in ESCLIST, setting `_XSS_ESC_LEN` to its byte
# length so the walk can step over it.  The list is split by hand rather than by
# word-splitting on `IFS=,`: an operator-editable file could legitimately carry
# a glob metacharacter, and unquoted word splitting would then let the shell
# expand it against the working directory.
_xss_escape_matches() {
  local win=$1 rest=$2 e
  _XSS_ESC_LEN=0
  while [[ -n $rest ]]; do
    e=${rest%%,*}
    if [[ $e == "$rest" ]]; then rest=''; else rest=${rest#*,}; fi
    [[ -n $e ]] || continue
    if [[ ${win:0:${#e}} == "$e" ]]; then
      _XSS_ESC_LEN=${#e}
      return 0
    fi
  done
  return 1
}

# `_xss_scan_window WINDOW` - walks the bytes that followed the marker, in the
# order the vendored file declares, and fills `_XSS_RAW[k]` with 1 (the
# character came back raw) or 0 (escaped, or dropped by a filter) per character.
#
# THE WALK IS POSITIONAL, AND THAT IS THE WHOLE DESIGN.  A naive
# "does the body contain a raw `<` anywhere" test answers a question about the
# PAGE, not about the reflection: every HTML document is full of raw `<`.  Even
# "does the body contain marker + `<`" is wrong for the second and later
# characters, because an escaped `<` shifts everything after it (the window
# reads `&lt;&gt;` rather than `<>`), so a fixed-offset test would read `&` as
# the reflected `>`.  Consuming exactly what was matched - one byte for a raw
# character, the encoding's length for an escaped one, and nothing at all for a
# dropped one - keeps the cursor aligned through any mixture of the three.
_xss_scan_window() {
  local win=$1 k ch
  declare -ga _XSS_RAW=()
  for (( k = 0; k < ${#_XSS_C_NAME[@]}; k++ )); do
    ch=${_XSS_C_CHAR[$k]}
    if [[ ${win:0:1} == "$ch" ]]; then
      _XSS_RAW[k]=1
      win=${win:1}
      continue
    fi
    _XSS_RAW[k]=0
    if _xss_escape_matches "$win" "${_XSS_C_ESC[$k]}"; then
      win=${win:$_XSS_ESC_LEN}
    fi
  done
  return 0
}

# `_xss_raw NAME` - 0 when the character labelled NAME came back raw.  A name
# the vendored file does not carry is never raw, so trimming a line from that
# file narrows what can be concluded rather than manufacturing a conclusion.
_xss_raw() {
  local want=$1 k
  for (( k = 0; k < ${#_XSS_C_NAME[@]}; k++ )); do
    if [[ ${_XSS_C_NAME[$k]} == "$want" ]]; then
      (( ${_XSS_RAW[$k]:-0} == 1 )) && return 0
      return 1
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 5. Where in the document the reflection landed
# ---------------------------------------------------------------------------
# `_xss_context BODY IDX [BODY_LOWERCASED]` - sets `_XSS_CTX` to `js`, `attr` or
# `html` and, for `attr`, `_XSS_ATTR_QUOTE` to the quote character delimiting
# the attribute value (empty for an unquoted value).
#
# The third argument is a caller-supplied lowercased copy of BODY, purely so a
# response with several reflection points folds case ONCE rather than once per
# occurrence; omitting it is correct and only slower, which is what keeps the
# function callable on its own from a test.
#
# This is deliberately a small, auditable state test over the text BEFORE the
# reflection point rather than an HTML parser: scoursh executes no JavaScript
# and ships no DOM, and a full parser would be a second, unverifiable
# implementation of the browsers' own error recovery.  What it must get right is
# the three questions the decision rules ask - are we inside a `<script>`
# element, inside a tag, or in ordinary text - and each answer is pinned by a
# test naming the reading it fails under.
_xss_context() {
  local body=$1 idx=$2 lower_all=${3:-} pre lower o c after lt gt tag
  pre=${body:0:idx}
  _XSS_CTX=html
  _XSS_ATTR_QUOTE=''
  if [[ -n $lower_all ]]; then lower=${lower_all:0:idx}; else lower=${pre,,}; fi

  # Inside a script element: the last `<script` opener is later than the last
  # `</script` closer, AND its own opening tag has been closed with `>` (a
  # marker sitting inside `<script src="HERE">` is an attribute value, not
  # script text - falling through to the tag test below gets that right).
  _xss_last_index "$lower" '<script'; o=$_XSS_LIDX
  _xss_last_index "$lower" '</script'; c=$_XSS_LIDX
  if (( o >= 0 && o > c )); then
    after=${pre:o}
    if [[ $after == *'>'* ]]; then
      _XSS_CTX=js
      return 0
    fi
  fi

  # Inside a tag: an unclosed `<` after the last `>`.
  _xss_last_index "$pre" '<'; lt=$_XSS_LIDX
  _xss_last_index "$pre" '>'; gt=$_XSS_LIDX
  if (( lt >= 0 && lt > gt && idx - lt <= _XSS_MAX_TAG_SPAN )); then
    _XSS_CTX=attr
    tag=${pre:lt}
    # Which quote (if either) is still open at the reflection point: an odd
    # number of that character since the tag began means we are inside one.
    _xss_count_char "$tag" '"'
    if (( _XSS_COUNT % 2 == 1 )); then
      _XSS_ATTR_QUOTE='"'
    else
      _xss_count_char "$tag" "'"
      (( _XSS_COUNT % 2 == 1 )) && _XSS_ATTR_QUOTE="'"
    fi
  fi
  return 0
}

# `_xss_ct_kind CONTENT_TYPE` - sets `_XSS_CT_KIND` to `html`, `js` or `other`.
#
# A raw `<` echoed into an `application/json` body is not script execution: no
# browser parses it as markup.  Reporting it as XSS is the false positive this
# gate exists to prevent - and skipping it silently would be the overstated
# coverage §15 forbids, so the phase COUNTS what it declined to judge and
# records it.  An EMPTY content type is treated as rendering, because a response
# with no declared type is exactly the one a browser may content-sniff.
_xss_ct_kind() {
  local ct=${1%%;*}
  ct=${ct// /}
  ct=${ct//$'\t'/}
  ct=${ct,,}
  case $ct in
    ''|text/html|application/xhtml+xml|application/xhtml|text/xml|application/xml|image/svg+xml)
      _XSS_CT_KIND=html ;;
    text/javascript|application/javascript|application/x-javascript|text/ecmascript|application/ecmascript)
      _XSS_CT_KIND=js ;;
    *)
      _XSS_CT_KIND=other ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. The decision
# ---------------------------------------------------------------------------
# `_xss_decide` - reads `_XSS_CTX`, `_XSS_ATTR_QUOTE` and `_XSS_RAW`, and sets
# `_XSS_KIND` (empty when the reflection is SAFE), `_XSS_CONF` and `_XSS_WHY`.
#
# Each arm requires the characters that a break-out in THAT context actually
# needs, and nothing else:
#
#   html  `<` AND `>` raw.  `<` alone, with `>` escaped, opens nothing - there
#         is no way to terminate the tag - so it is not flagged.
#   attr  the quote that DELIMITS this value, raw.  A raw `"` inside a
#         single-quoted value is just a character; a raw `<` inside any
#         attribute value is just a character.  An unquoted value needs `>`,
#         which ends the tag.
#   js    `<` and `>` raw closes the element outright (high); a raw quote can
#         terminate a string literal, which depends on the marker actually
#         sitting inside one - something this probe does not verify, so it is
#         reported at medium confidence and the evidence says why.
_xss_decide() {
  _XSS_KIND='' _XSS_CONF='' _XSS_WHY=''
  case $_XSS_CTX in
    js)
      if _xss_raw lt && _xss_raw gt; then
        _XSS_KIND=js; _XSS_CONF=high
        _XSS_WHY='the marker was reflected inside a <script> element with both < and > raw, so the element can be closed and arbitrary markup opened after it'
      elif _xss_raw dq || _xss_raw sq; then
        _XSS_KIND=js; _XSS_CONF=medium
        _XSS_WHY='the marker was reflected inside a <script> element with a quote character raw, which terminates a JavaScript string literal if the value is embedded in one'
      fi
      ;;
    attr)
      if [[ $_XSS_ATTR_QUOTE == '"' ]] && _xss_raw dq; then
        _XSS_KIND=attr; _XSS_CONF=high
        _XSS_WHY='the marker was reflected inside a double-quoted HTML attribute value and the double quote came back raw, so the attribute can be closed and an event-handler attribute added to the same tag'
      elif [[ $_XSS_ATTR_QUOTE == "'" ]] && _xss_raw sq; then
        _XSS_KIND=attr; _XSS_CONF=high
        _XSS_WHY="the marker was reflected inside a single-quoted HTML attribute value and the single quote came back raw, so the attribute can be closed and an event-handler attribute added to the same tag"
      elif [[ -z $_XSS_ATTR_QUOTE ]] && _xss_raw gt; then
        _XSS_KIND=attr; _XSS_CONF=medium
        _XSS_WHY='the marker was reflected inside an unquoted HTML attribute value and > came back raw, which ends the tag and lets following markup be interpreted'
      fi
      ;;
    html)
      if _xss_raw lt && _xss_raw gt; then
        _XSS_KIND=html; _XSS_CONF=high
        _XSS_WHY='the marker was reflected into HTML text with both < and > raw, so a new element can be opened at that point'
      fi
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# 7. Emit
# ---------------------------------------------------------------------------
# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of).
_xss_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

_xss_emit() {
  local i=$1 kind=$2 conf=$3 marker=$4 window=$5 why=$6
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title evi authv=none
  path=$(_xss_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $kind in
    html)
      check=DAST-INJ-XSS_REFLECTED_HTML-01
      title='Reflected cross-site scripting - unescaped reflection in HTML text' ;;
    attr)
      check=DAST-INJ-XSS_REFLECTED_ATTR-01
      title='Reflected cross-site scripting - unescaped reflection in an HTML attribute value' ;;
    js)
      check=DAST-INJ-XSS_REFLECTED_JS-01
      title='Reflected cross-site scripting - unescaped reflection in a script block' ;;
  esac
  evi="parameter '$name' ($loc) of $method $path reflected the unique marker '$marker' into the response, and $why. The bytes that followed the marker were [${window:0:48}] - the probe sent the marker with < > \" ' appended and nothing else, so those bytes are the application's own handling of them. No payload was executed and none was sent."

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity high
  finding_set confidence "$conf"
  finding_set cwe CWE-79
  finding_set owasp A03:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Escape request-derived data on OUTPUT, for the context it is written into: HTML-entity-encode in element text and attribute values, JavaScript-string-encode inside a script block, and quote every attribute. Prefer a template engine that escapes by default and never disable it for this value. Add a Content-Security-Policy without unsafe-inline as defence in depth, and validate input server-side as well - but escaping at the point of output is the fix, not input filtering.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# 8. The phase
# ---------------------------------------------------------------------------
_dast_xss_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/xss.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored character ledger.  SCOURSH_DAST_XSS_PAYLOAD_DIR overrides the
  # location so an operator can vendor a custom set (the same swappable-seam
  # idiom lib/http.sh's transport/resolver hooks use, and the one
  # active/sqli.sh already uses for its payloads) and so the
  # graceful-degradation branch is testable against an empty directory.
  local pdir=${SCOURSH_DAST_XSS_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  _xss_load_chars "$pdir"

  local do_html=1 do_attr=1 do_js=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it.  Consulted only if that function exists, so this file does not
  # hard-depend on it: absent, everything the tier already permitted runs.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-XSS_REFLECTED_HTML-01 || do_html=0
    dast_check_selected DAST-INJ-XSS_REFLECTED_ATTR-01 || do_attr=0
    dast_check_selected DAST-INJ-XSS_REFLECTED_JS-01 || do_js=0
  fi

  if (( ${#_XSS_C_NAME[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=xss_marker_chars_missing target=$target - modules/dast/payloads/xss-marker-chars.txt is absent or empty, so the probe has no characters to test and cannot tell an escaped reflection from a raw one. No XSS probe was sent. This is a coverage reduction, not a clean result."
    run_record coverage_gap "dast xss: no XSS marker characters are available on target '$target', so no reflection probe ran. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi
  if (( do_html == 0 && do_attr == 0 && do_js == 0 )); then
    run_record coverage_reduction "module=dast reason=xss_all_checks_deselected target=$target - every DAST-INJ-XSS_REFLECTED_* check was filtered out by the check-set filter chain, so no reflection probe was sent."
    return 0
  fi

  # THE INVENTORY PATHS ARE RESOLVED HERE, NOT TAKEN FROM THE EXPORT ALONE, AND
  # THAT IS NOT BELT-AND-BRACES.  modules/dast/run.sh reads the inventory and
  # exports SCOURSH_DAST_ENDPOINTS/SCOURSH_DAST_PARAMETERS BEFORE the phase loop
  # starts, so on an ordinary `scan.sh dast` run they are EMPTY, because crawl.sh
  # writes reports/<run>/inventory/{endpoints,parameters}.json several phases
  # later in that same loop.  A probe that trusted the export alone would
  # therefore see NO parameter surface on exactly the run that has just
  # discovered one, and would then record "no known request parameters" over an
  # application that has dozens - the overstated-coverage failure docs/DESIGN.md
  # §15 forbids, wearing a coverage_gap's clothing.  The run directory's own
  # artifact is the authority (docs/INVENTORY-FORMAT.md §1), so it is consulted
  # when the export is empty, exactly as modules/dast/passive/headers.sh already
  # does.  Fixing the export itself belongs to modules/dast/run.sh and is filed
  # separately rather than changed here, under peers editing the same tree.
  local epf=${SCOURSH_DAST_ENDPOINTS:-} pmf=${SCOURSH_DAST_PARAMETERS:-}
  # Two plain `if`s, never `[[ ... ]] && assign`: under `set -Eeuo pipefail` a
  # trailing `&&` chain whose test is false is a FAILING last command in the
  # block, which takes the whole run with it on the ordinary path where the
  # export was already set.
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  if [[ -z $pmf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pmf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi
  inject_inventory_load "$epf" "$pmf" xss
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so reflected XSS had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast xss: target '$target' has no known request parameters (query/body/JSON/header/path), so no reflected-XSS probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
    return 0
  fi

  # Optional authenticated pass.  Only under --authed, and only if auth.sh
  # obtained at least one session this run; otherwise the probe runs against the
  # public surface and attaches nothing.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=xss target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  local i loc marker value body ct search off abs seen_key win
  local tested=0 uninjectable=0 reflected=0 escaped_safe=0 nonrender=0 occ
  local -A emitted=()
  for (( i = 0; i < _INJ_N; i++ )); do
    loc=${_INJ_LOCATION[$i]}
    if [[ $loc == graphql ]]; then
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    _xss_marker_new
    marker=$_XSS_MARKER
    value=$marker$_XSS_PROBE_SUFFIX
    if ! inject_send "$i" "$value"; then
      # An uninjectable location (a path parameter with no template slot) or a
      # transport failure: nothing to observe a reflection in.
      uninjectable=$(( uninjectable + 1 ))
      continue
    fi
    tested=$(( tested + 1 ))
    body=$_INJ_BODY
    _xss_ct_kind "${_HTTP_LAST_CONTENT_TYPE:-}"

    _xss_first_index "$body" "$marker"
    (( _XSS_IDX >= 0 )) || continue
    reflected=$(( reflected + 1 ))
    if [[ $_XSS_CT_KIND == other ]]; then
      nonrender=$(( nonrender + 1 ))
      continue
    fi

    # Walk up to _XSS_MAX_OCCURRENCES reflection points.  `search` is the
    # remaining tail and `abs` the absolute offset of the current occurrence in
    # the whole body, which is what the context classifier needs.
    local found_any=0
    local body_lower=${body,,}
    search=$body
    off=0
    for (( occ = 0; occ < _XSS_MAX_OCCURRENCES; occ++ )); do
      _xss_first_index "$search" "$marker"
      (( _XSS_IDX >= 0 )) || break
      abs=$(( off + _XSS_IDX ))
      win=${body:abs + ${#marker}:_XSS_WINDOW_BYTES}
      _xss_scan_window "$win"
      if [[ $_XSS_CT_KIND == js ]]; then
        # The whole body IS script, so there is no markup to classify.
        _XSS_CTX=js
        _XSS_ATTR_QUOTE=''
      else
        _xss_context "$body" "$abs" "$body_lower"
      fi
      _xss_decide
      if [[ -n $_XSS_KIND ]]; then
        case $_XSS_KIND in
          html) (( do_html )) || { _XSS_KIND=''; } ;;
          attr) (( do_attr )) || { _XSS_KIND=''; } ;;
          js)   (( do_js ))   || { _XSS_KIND=''; } ;;
        esac
      fi
      if [[ -n $_XSS_KIND ]]; then
        found_any=1
        seen_key="$i:$_XSS_KIND"
        if [[ -z ${emitted[$seen_key]:-} ]]; then
          emitted[$seen_key]=1
          _xss_emit "$i" "$_XSS_KIND" "$_XSS_CONF" "$marker" "$win" "$_XSS_WHY"
        fi
      fi
      off=$(( abs + ${#marker} ))
      search=${body:off}
    done
    (( found_any )) || escaped_safe=$(( escaped_safe + 1 ))
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up reads -
  # recorded only when at least one parameter was actually probed, so a run with
  # a parameter surface but no coverage is not reported as covered.
  if (( tested > 0 )); then
    (( do_html )) && run_record checks_run DAST-INJ-XSS_REFLECTED_HTML-01
    (( do_attr )) && run_record checks_run DAST-INJ-XSS_REFLECTED_ATTR-01
    (( do_js )) && run_record checks_run DAST-INJ-XSS_REFLECTED_JS-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast xss: the parameter surface on target '$target' exceeded the per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) were not tested for reflected XSS. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=xss_uninjectable_parameters target=$target count=$uninjectable - $uninjectable discovered parameter(s) were a GraphQL operation or a path segment with no template slot this probe could substitute; they were not tested for reflected XSS here."
  fi
  if (( nonrender > 0 )); then
    run_record coverage_reduction "module=dast reason=xss_non_rendering_content_type target=$target count=$nonrender - $nonrender parameter(s) reflected the marker into a response whose Content-Type does not render as HTML or JavaScript (JSON, plain text, a download), so no browser would execute markup there and no finding was raised. If such a response is ever served or re-rendered as HTML, or is sniffable because X-Content-Type-Options is absent, review it by hand."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast xss: target '$target' had $_INJ_N discovered parameter(s) but none were in a location this probe could inject (or every request failed), so no reflected-XSS test was sent."
  fi
  run_record notes "module=dast phase=xss target=$target tested=$tested reflected=$reflected escaped_safely=$escaped_safe non_rendering=$nonrender"

  log_info "dast xss: target '$target' - probed $tested of $_INJ_N parameter(s); $reflected reflected the marker, $escaped_safe of those escaped it safely"
  return 0
}

_dast_xss_phase
