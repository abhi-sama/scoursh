#!/usr/bin/env bash
# modules/dast/passive/markup_engine.sh - the pure, testable half of the §7.1
# HTML-MARKUP family (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-11,
# tier 2).
#
# WHY THIS FILE IS NAMED FOR ONE TICKET RATHER THAN FOR THE TIER, and what that
# obliges it to say.  DAST-05..DAST-11 are peers with no ordering between them
# and are built in parallel, so a `passive/passive_engine.sh` would be shared
# scaffolding several tickets each believed they owned - `headers_engine.sh`
# records the same reasoning for itself.  Everything here is markup-analysis
# logic that only `passive/markup.sh` uses, and it is named accordingly.
#
# ONE THING IN HERE USED TO BE A SECOND COPY OF SOMETHING A PEER ALREADY HAD,
# AND HAS SINCE BEEN LIFTED OUT; ONE STILL IS, DELIBERATELY:
#
#   1. `markup_endpoints_load` used to choose GET endpoints out of the frozen
#      inventory with its own copy of `headers_engine.sh`'s
#      `hdr_endpoints_load` logic (differing only in variable prefix).  That
#      duplication was stated here rather than hidden, and the ticket it named
#      ("lift the shared passive endpoint chooser into
#      modules/dast/passive/response_engine.sh") has since landed: the four
#      decisions now live once, in `response_engine.sh`'s `resp_endpoints_load`
#      - see that file's own ADR block - and `markup_endpoints_load` below is a
#      thin wrapper over it, exactly as `hdr_endpoints_load` is.  Markup's own
#      extra concerns (fetching and parsing response BODIES, skipping any
#      response that is not markup, and carrying no HSTS/CSP concept) live in
#      `markup.sh`'s phase loop and in this file's parser, untouched by that
#      lift.
#   2. The tag tokenizer is not `crawl_engine.sh`'s `crawl_html_extract`.  That
#      function's output stream is `base`/`link`/`form`/`input`/`formend`
#      records carrying no attribute detail, and every check here is ABOUT an
#      attribute - `integrity`, `crossorigin`, `rel`, `target`, `sandbox`,
#      `type`.  Widening that stream would change a contract
#      docs/INVENTORY-FORMAT.md's consumers read.  The scanner core below
#      (comment skip, quote-aware `>` scan, the `attr`/`name_of`/`entities`
#      helpers) is that function's proven shape, reused on purpose so the two
#      cannot disagree about what a tag is; the emitter is this file's own.
#
# WHAT THE PARSER HANDLES, AND WHAT IT DOES NOT.  docs/DESIGN.md §15 and this
# ticket both require the limits to be STATED rather than discovered, so:
#
#   HANDLED
#     - Attributes spanning several lines.  The scan is character-oriented over
#       the whole document, not line-oriented, so a tag broken across ten lines
#       is one tag.
#     - Double-quoted, single-quoted and unquoted attribute values.
#     - A `>` inside a quoted attribute value does not end the tag.
#     - `<!-- ... -->` comments, including ones containing tag-like text and
#       downlevel-revealed conditional comments: the whole comment is skipped,
#       so markup quoted inside one is never reported.
#     - `<script>`, `<style>`, `<textarea>` and `<template>` BODIES are skipped,
#       so `document.write("<a target=_blank>")` in an inline script is not a
#       finding.  The `<script src=...>` tag itself is still read - it is the
#       element the SRI check is about.
#     - Upper, lower and mixed-case tag and attribute names.
#     - The five named character references plus a numeric `&`, in attribute
#       values (`&amp;` is the REQUIRED spelling of a literal `&` in an href).
#
#   NOT HANDLED, and each of these is a stated false-negative direction
#     - Markup a client-side script builds at runtime.  scoursh executes no
#       JavaScript and gets no browser (docs/DESIGN.md §7.5), so a single-page
#       application's real DOM is invisible here and every check below reports
#       clean for it because it never saw it.  `markup.sh` records that as a
#       coverage_gap on any response that looks client-rendered rather than
#       letting the silence read as a pass.
#     - Numeric and hex character references other than `&`, so an obfuscated
#       `&#x6a;avascript:` URL is not decoded and not classified.
#     - An UNTERMINATED quoted attribute value.  The scan runs to the end of
#       the document looking for the closing quote and then abandons the tag,
#       so a truncated attribute is DROPPED rather than guessed at - and
#       everything after it in that document is dropped with it.  The tokenizer
#       emits a `trunc` record so the phase can declare it.
#     - No DOM tree is built.  A control belongs to the most recent unclosed
#       `<form>`, which is what a browser does for well-formed markup and is
#       wrong for nested `<form>` elements (which HTML forbids anyway) and for
#       a control associated by the `form=` attribute rather than by nesting.
#       A control with no open `<form>` above it is still EMITTED and belongs
#       to no form - it is read for the document-wide password-field signal,
#       which is the shape a single-page login page has.
#     - `<svg>`/`<math>` foreign content is scanned as ordinary markup; its
#       self-closing syntax is not modelled.
#     - CDATA sections in XHTML are not recognised as such.
#     - The document is read up to `_MARKUP_MAX_BYTES` and truncated after it;
#       the truncation is declared, never silent.
#
# THE ONE THING THIS FILE DOES NOT DO IS TALK TO THE NETWORK.  Every request the
# phase sends goes through `http_request` (lib/http.sh) - docs/FOUNDATION.md
# tension 19's single chokepoint, where the scope gate, DAST-01's rate limiter,
# the per-run request budget, the circuit breaker and DAST-32's ceilings all
# sit.  This file parses what came back; `markup.sh` is what asks.
#
# NEVER A BARE `grep` OR `rg` (tension 4).  Nothing here shells out to a match
# engine at all: the tokenizer is one `awk` program and every decision after it
# is bash pattern matching, so "no match" can never be confused with "the engine
# failed" - the failure mode that rule exists to prevent.
#
# EVERYTHING PARSED HERE IS UNTRUSTED TARGET OUTPUT (tension 10).  An attribute
# value is attacker-authorable text; it reaches a report only through
# `finding_set_evidence`, and `markup_safe_text` bounds and flattens it first so
# one 40 KiB data: URI cannot become the report.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_MARKUP_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_MARKUP_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint; a dast run does not otherwise load it (see
# modules/dast/engine.sh's header), so the first phase that issues traffic
# sources it, guarded exactly as modules/dast/auth_engine.sh,
# modules/dast/passive/headers_engine.sh and
# modules/dast/active/inject_engine.sh already do.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# crawl_engine.sh is reused for its depth- and string-aware JSON flattener
# (`crawl_json_flatten`/`crawl_json_unescape`, docs/INVENTORY-FORMAT.md §7) and
# for `crawl_url_resolve` - the inventory is read THROUGH the same reader that
# wrote it, and a relative href is resolved by the same RFC 3986
# remove_dot_segments implementation the crawler already uses, so a link this
# phase classifies as cross-origin is the same URL the crawler would have
# enqueued.  Its own sourced-once guard makes this a no-op on a run where the
# crawl already happened.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"
# response_engine.sh is the shared GET-endpoint chooser this file used to
# carry its own copy of (`markup_endpoints_load`, see this file's own header).
# It sources nothing itself - it is a leaf in the static source graph - so
# this edge is cheap under `shellcheck -x` and adds no runtime dependency
# beyond what crawl_engine.sh and lib/http.sh above already brought in.
# shellcheck source=modules/dast/passive/response_engine.sh
source "${BASH_SOURCE[0]%/*}/response_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds and knobs
# ---------------------------------------------------------------------------
# docs/DESIGN.md §15: a bound that truncates silently is indistinguishable from
# a surface that was really that small, so every one of these is published and
# the phase records a coverage_gap when it bites.
#
# How many distinct endpoints this phase fetches.  Markup is a PER-PAGE
# property - unlike a security header, which is configured once for an
# application - so more pages genuinely means more coverage here, and the cap is
# correspondingly higher than `headers.sh`'s ten.  It is still a cap, because
# twenty-five full response bodies is already a real spend of the per-run
# request budget.
: "${_MARKUP_MAX_ENDPOINTS:=25}"
# Bytes of any one response body parsed.  A 5 MiB single-page-application
# bundle is not markup worth tokenising in awk.
: "${_MARKUP_MAX_BYTES:=1048576}"
# Bytes of any one target-derived string carried into evidence.
: "${_MARKUP_MAX_EVIDENCE_FIELD:=160}"
# Offending elements enumerated in one finding's evidence before it says "and N
# more".  A page with 300 unhashed CDN scripts must not produce a 300-line
# evidence string.
: "${_MARKUP_MAX_EVIDENCE_ITEMS:=5}"

# `markup_safe_text TEXT [MAX]` - bounded, single-line target-derived text for a
# diagnostic or an evidence sentence.  `finding_set_evidence` still does the
# real escaping and redaction (tension 9/10); this only stops one pathological
# attribute value from dominating the sentence it appears in.
markup_safe_text() {
  local s=$1 max=${2:-$_MARKUP_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# 1. The tokenizer
# ---------------------------------------------------------------------------
# `markup_html_extract` - reads an HTML document on stdin and prints one record
# per interesting element, in document order, as EXACTLY SIX tab-separated
# fields:
#
#     kind <US> line <US> f1 <US> f2 <US> f3 <US> f4
#
# where <US> is the ASCII unit separator, 0x1f.
#
#   base    line  href        -           -             -
#   script  line  src         integrity   crossorigin   -
#   link    line  href        integrity   crossorigin   rel
#   anchor  line  href        target      rel           tagname (a|area)
#   frame   line  src         tagname     sandbox(1|0)  -
#   form    line  method      action      -             -
#   field   line  name        type        hasvalue(1|0) tagname
#   formend line  -           -           -             -
#   trunc   line  reason      -           -             -
#
# SIX FIELDS ALWAYS, EVEN WHERE FOUR WOULD DO, AND THAT IS NOT COSMETIC.  The
# bash reader is one `IFS=$'\x1f' read -r kind ln a b c d`, and `read` puts every
# SURPLUS field into the LAST variable it was given.  A record type that emitted
# five fields where another emitted seven would silently glue two attribute
# values together in `d` on one row and leave `d` holding a whole record tail on
# another - a corruption with no error anywhere.  A fixed arity makes that
# unrepresentable.
#
# THE SEPARATOR IS 0x1f AND EMPHATICALLY NOT A TAB, AND THIS WAS MEASURED RATHER
# THAN CHOSEN ON TASTE.  A tab IS an IFS-whitespace character, so `read` folds a
# RUN of them into ONE delimiter and drops leading and trailing ones (POSIX
# XCU 2.6.5).  A `<link>` with no `integrity` and no `crossorigin` emits
# `link<T>7<T>href<T><T><T>stylesheet`, and a tab-separated reader collapses that
# to FOUR fields - so `rel` lands in the `integrity` variable, the SRI check
# reads an integrity attribute that was never there, and every unhashed
# stylesheet on the internet passes.  That is exactly what happened here, and
# `tests/suites/dast-markup.sh` pins it: 0x1f is not whitespace, so an empty
# field between two separators survives.  It is also the separator
# `crawl_json_flatten` already uses, for the same reason.  `clean()` strips 0x1f
# out of every value, so an attribute value carrying one cannot forge a column.
#
# `field` records belong to the most recent `form` record, which is what lets a
# caller in bash reconstruct the association without holding a DOM.  See this
# file's header for exactly what that association does not model.
# `LC_ALL=C` IS NOT DECORATION: IT IS WHAT MAKES `_MARKUP_MAX_BYTES` MEAN
# BYTES.  The cap below is enforced with awk's `length()`, which counts
# CHARACTERS, and in a UTF-8 locale a character is up to four bytes - so a
# "1 MiB" cap would read up to 4 MiB of a hostile response before biting, which
# is the opposite of what a resource bound is for.  In the C locale `length()`
# is bytes and the constant means what its name says.  It also makes
# `tolower`/`toupper` fold ASCII and nothing else, which is exactly HTML's own
# ASCII-case-insensitive matching rule for tag and attribute names; every
# pattern in this program is ASCII, and attribute VALUES are read out of the
# original-case text and pass through as opaque bytes either way.
markup_html_extract() {
  LC_ALL=C awk -v maxbytes="${_MARKUP_MAX_BYTES:-1048576}" '
    # HTML character references: the five named ones that matter in an
    # attribute value plus a numeric ampersand.  Same set, same reasoning, as
    # crawl_engine.sh - `&amp;` is not an optional nicety, it is the REQUIRED
    # spelling of a literal & in an href, and left undecoded a two-parameter
    # query reads as one parameter named "amp;...".  Other numeric references
    # are deliberately left alone rather than half-decoded (see the header).
    function entities(v) {
      gsub(/&#38;|&#x26;|&#X26;/, "\\&", v)
      gsub(/&amp;/, "\\&", v)
      gsub(/&lt;/, "<", v)
      gsub(/&gt;/, ">", v)
      gsub(/&quot;/, "\"", v)
      gsub(/&#39;|&apos;/, SQ, v)
      return v
    }
    # One attribute value out of a raw tag body.  Matched case-insensitively on
    # the NAME, then read out of the ORIGINAL-case text from the same offset so
    # the VALUE keeps its case - a URL path is case-sensitive and lowercasing
    # it would change which resource the finding names.
    #
    # THE CHARACTER BEFORE THE NAME MAY BE A QUOTE, AND OMITTING THAT IS A
    # SILENT FALSE NEGATIVE ON MARKUP EVERY BROWSER ACCEPTS.  HTML does not
    # require whitespace after a quoted attribute value, so
    # `<a href="..."target="_blank">` is one anchor with two attributes - but a
    # class of only `[ \t\r\n/]` never matches that `target`, `attr()` returns
    # "", the `_blank` test fails and the tabnabbing check CANNOT FIRE on it.
    # A quote is therefore an attribute separator here as well.  The known cost
    # is unchanged rather than new: this scanner is not quote-aware (it is
    # crawl_engine.sh`s proven shape, see the header), so a value that itself
    # contains ` name=` could already be misread, and admitting a quote only
    # widens that same pre-existing case - it errs toward LOOKING at an
    # element rather than toward silently skipping it.
    function attr(tag, name,   re, s, q, v, p) {
      re = "[ \t\r\n/\"" SQ "]" name "[ \t\r\n]*=[ \t\r\n]*"
      s = " " tolower(tag)
      p = match(s, re)
      if (p == 0) return ""
      v = substr(" " tag, p + RLENGTH)
      q = substr(v, 1, 1)
      if (q == "\"" || q == SQ) {
        v = substr(v, 2)
        p = index(v, q)
        if (p == 0) return entities(v)
        return entities(substr(v, 1, p - 1))
      }
      if (match(v, /[ \t\r\n>]/)) return entities(substr(v, 1, RSTART - 1))
      return entities(v)
    }
    # Presence of a BOOLEAN attribute - sandbox, disabled.  Distinct from attr()
    # returning the empty string: `sandbox` and `sandbox=""` are both the
    # maximally restrictive sandbox and both mean the control IS present, while
    # no sandbox attribute at all means it is not.  Reading presence off a
    # non-empty value would collapse the two and report a fully sandboxed frame
    # as unsandboxed - the false positive this function exists to prevent.
    function attr_present(tag, name,   s, pre) {
      s = " " tolower(tag) " "
      pre = "[ \t\r\n/\"" SQ "]"
      if (match(s, pre name "[ \t\r\n]*=")) return 1
      if (match(s, pre name "[ \t\r\n/>\"" SQ "]")) return 1
      return 0
    }
    function name_of(tag,   t) {
      t = tag
      sub(/^\//, "", t)
      if (match(t, /[ \t\r\n\/]/)) t = substr(t, 1, RSTART - 1)
      return tolower(t)
    }
    # Collapse whitespace runs and trim.  Applied to EVERY emitted value: it is
    # what keeps a multi-line attribute on one record and what stops an embedded
    # tab forging a column.
    function clean(v) {
      gsub(US, " ", v)
      gsub(/[ \t\r\n]+/, " ", v)
      sub(/^ /, "", v)
      sub(/ $/, "", v)
      return v
    }
    function emit(kind, ln, a, b, c, d) {
      printf "%s%s%d%s%s%s%s%s%s%s%s\n", kind, US, ln, US, clean(a), US, clean(b), US, clean(c), US, clean(d)
    }
    # The line a position sits on.  `i` only ever moves forward, so the newline
    # count is accumulated over the gap since the last query rather than
    # recounted from the start of the document - which would be quadratic on
    # exactly the large documents the byte cap exists for.
    function lineat(pos,   chunk, cnt) {
      if (pos > lastpos) {
        chunk = substr(doc, lastpos, pos - lastpos)
        cnt = gsub(/\n/, "\n", chunk)
        lastline += cnt
        lastpos = pos
      }
      return lastline
    }
    # SQ is built with sprintf rather than written literally: this awk program
    # lives inside a single-quoted shell string, so an apostrophe anywhere in
    # it - code or comment - would end that string.
    # SQ and US are built with sprintf rather than written literally: SQ because
    # an apostrophe would end this single-quoted shell string, US because a raw
    # 0x1f byte in a source file is unreadable and unreviewable.
    BEGIN { SQ = sprintf("%c", 39); US = sprintf("%c", 31); doc = ""; nbytes = 0; cut = 0 }
    {
      if (cut) next
      if (nbytes + length($0) + 1 > maxbytes) {
        doc = doc substr($0, 1, maxbytes - nbytes)
        cut = 1
        next
      }
      doc = doc $0 "\n"
      nbytes += length($0) + 1
    }
    END {
      n = length(doc)
      i = 1
      lastpos = 1; lastline = 1
      skipuntil = ""
      informs = 0
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c != "<") { i++; continue }
        if (substr(doc, i, 4) == "<!--") {
          p = index(substr(doc, i), "-->")
          # An unterminated comment swallows the rest of the document, which is
          # what a browser does too.  Declared, not silent.
          if (p == 0) { emit("trunc", lineat(i), "unterminated_comment", "", "", ""); break }
          i = i + p + 2
          continue
        }
        # Read to the closing >, honouring quoted attribute values so a > in a
        # URL cannot end the tag early.
        j = i + 1
        instr = 0; q = ""
        while (j <= n) {
          c = substr(doc, j, 1)
          if (instr) { if (c == q) instr = 0; j++; continue }
          if (c == "\"" || c == SQ) { instr = 1; q = c; j++; continue }
          if (c == ">") break
          j++
        }
        if (j > n) {
          # Either an unterminated tag or an unterminated quoted value.  Both
          # abandon this tag AND the rest of the document; the header states
          # this as a false-negative direction and the phase declares it.
          emit("trunc", lineat(i), instr ? "unterminated_attribute_value" : "unterminated_tag", "", "", "")
          break
        }
        tag = substr(doc, i + 1, j - i - 1)
        ln = lineat(i)
        i = j + 1
        nm = name_of(tag)
        closing = (substr(tag, 1, 1) == "/")
        if (skipuntil != "") {
          if (nm == skipuntil && closing) skipuntil = ""
          continue
        }
        # A raw-text or escapable-raw-text element: its BODY is not markup, so
        # tag-like text inside it is not a tag.  <template> is not raw text in
        # the specification, but its contents are inert until a script clones
        # them, so reporting a target=_blank anchor inside one as live markup
        # would be a false positive on a page that may never instantiate it.
        if (nm == "script" || nm == "style" || nm == "textarea" || nm == "template") {
          if (nm == "script" && !closing) {
            v = attr(tag, "src")
            if (v != "") emit("script", ln, v, attr(tag, "integrity"), attr(tag, "crossorigin"), "")
          }
          if (!closing && substr(tag, length(tag), 1) != "/") skipuntil = nm
          continue
        }
        if (closing) {
          if (nm == "form") { if (informs) emit("formend", ln, "", "", "", ""); informs = 0 }
          continue
        }
        if (nm == "base") {
          v = attr(tag, "href"); if (v != "") emit("base", ln, v, "", "", "")
          continue
        }
        if (nm == "link") {
          v = attr(tag, "href")
          if (v != "") emit("link", ln, v, attr(tag, "integrity"), attr(tag, "crossorigin"), attr(tag, "rel"))
          continue
        }
        if (nm == "a" || nm == "area") {
          v = attr(tag, "href")
          if (v != "") emit("anchor", ln, v, attr(tag, "target"), attr(tag, "rel"), nm)
          continue
        }
        if (nm == "iframe" || nm == "frame" || nm == "embed" || nm == "object") {
          v = attr(tag, "src"); if (v == "") v = attr(tag, "data")
          if (v != "") emit("frame", ln, v, nm, attr_present(tag, "sandbox") ? "1" : "0", "")
          continue
        }
        if (nm == "form") {
          if (informs) emit("formend", ln, "", "", "", "")
          m = attr(tag, "method"); if (m == "") m = "GET"
          emit("form", ln, toupper(m), attr(tag, "action"), "", "")
          informs = 1
          continue
        }
        # A CONTROL IS EMITTED WHETHER OR NOT A FORM IS OPEN, AND GATING THIS ON
        # `informs` WAS A FALSE NEGATIVE ON EXACTLY THE PAGE THAT MATTERS MOST.
        # Two different consumers read a `field` record and only one of them is
        # about forms.  markup.sh pass two associates controls with the most
        # recent unclosed <form> and guards on that itself, so nothing there
        # changes.  markup.sh pass ONE reads these records for a document-wide
        # fact - does this page carry an <input type="password">, the CONTENT
        # half of the sensitive-page signal (§5) - and a password box that is
        # not nested in a <form> is the ordinary shape on a single-page
        # application, where the submit is an XHR and there is no form element
        # at all.  Suppressed here, that login page was classified as ordinary
        # and its reverse-tabnabbing findings were downgraded from
        # DAST-MARKUP-TABNABBING_SENSITIVE-01 to DAST-MARKUP-TABNABBING-01.
        # The record contract is unchanged and is stated in this file header:
        # a field belongs to the most recent unclosed <form>, and one with no
        # open form belongs to no form.  (No apostrophe anywhere in this awk
        # program, comment or code - it is inside a single-quoted shell string
        # and one would end it; see the SQ note in BEGIN.)
        if (nm == "input" || nm == "select" || nm == "button") {
          emit("field", ln, attr(tag, "name"), tolower(attr(tag, "type")), (attr(tag, "value") != "") ? "1" : "0", nm)
          continue
        }
      }
      if (informs) emit("formend", lineat(n), "", "", "", "")
      if (cut) emit("trunc", lineat(n), "byte_cap", "", "", "")
    }
  '
}

# ---------------------------------------------------------------------------
# 2. Origins
# ---------------------------------------------------------------------------
# `markup_origin_of URL` - prints the canonical `scheme://host:port` origin of
# an ABSOLUTE http(s) URL, or returns 1.  The default port is made explicit by
# `http_url_normalize`, which is what makes `https://h/` and `https://h:443/`
# ONE origin rather than two - a comparison of the raw strings gets that wrong
# and would report a same-origin script as cross-origin on any site that spells
# its own port out.
#
# `http_url_normalize` publishes into the SAME `_HN_*` globals `http_gate_url`
# uses, and a nested call would clobber a caller's, so the values are captured
# into locals in the same breath - the class of bug lib/http.sh's own gate
# function documents at length for itself.
markup_origin_of() {
  local url=$1 scheme host port
  http_url_normalize "$url" || return 1
  scheme=$_HN_SCHEME host=$_HN_HOST port=$_HN_PORT
  [[ -n $scheme && -n $host ]] || return 1
  printf '%s://%s:%s' "$scheme" "$host" "$port"
}

# `markup_same_origin URL_A URL_B` - 0 when both are absolute http(s) URLs with
# the same scheme, host and effective port.
#
# A URL THAT WILL NOT NORMALISE IS NOT THE SAME ORIGIN AS ANYTHING, which fails
# in the safe direction: an unparseable reference is treated as external and
# gets looked at, rather than being waved through as "probably ours".
markup_same_origin() {
  local a b
  a=$(markup_origin_of "$1") || return 1
  b=$(markup_origin_of "$2") || return 1
  [[ $a == "$b" ]]
}

# `markup_is_plaintext_url URL` - 0 for an `http://` URL.
markup_is_plaintext_url() {
  [[ ${1,,} == http://* ]]
}

# `markup_path_of` (the path component of a URL, query and fragment removed)
# used to live here as a byte-identical copy of `hdr_path_of`.  It was removed
# when the endpoint chooser moved to response_engine.sh: `hdr_path_of` (sourced
# above via response_engine.sh) is the same function under the name it always
# had there, and it was the only caller of this one.

# ---------------------------------------------------------------------------
# 3. Token lists
# ---------------------------------------------------------------------------
# `markup_tokens_have LIST TOKEN` - 0 when the ASCII-whitespace-separated,
# case-insensitive token list LIST contains TOKEN exactly.
#
# A SUBSTRING TEST IS THE BUG THIS EXISTS TO PREVENT, IN BOTH DIRECTIONS.
# `rel="external noopener"` must satisfy a query for `noopener`, which a
# whole-attribute comparison gets wrong; and `rel="noopenerx"` must not, which
# `[[ $rel == *noopener* ]]` gets wrong.  `rel` and `crossorigin` are defined as
# token lists (HTML §2.4.7) and are read as ones.
# THE WORD SPLIT IS DELIBERATE; THE PATHNAME EXPANSION THAT COMES WITH IT IS
# NOT, AND DISABLING IT IS A SECURITY CONTROL RATHER THAN TIDINESS.  `$list` is
# a `rel` or `crossorigin` attribute lifted verbatim out of a scanned response,
# so it is attacker-authorable text (tension 10), and an unquoted expansion in
# bash performs word splitting AND globbing.  A target serving `rel="*"` would
# therefore have that `*` expanded against the scanner's CURRENT WORKING
# DIRECTORY: on a host where a file named `noopener` happens to sit there, the
# query for `noopener` succeeds and the target suppresses its own
# DAST-MARKUP-TABNABBING-01 finding.  Two things are wrong with that and both
# are fatal to the check - target-controlled text steering a security decision,
# and a verdict that depends on where the scanner was started from rather than
# on the response.  `markup_link_takes_sri` is built on this function, so the
# SRI check inherits the identical hole.  Reproduced before the fix:
#
#     mkdir /tmp/g && touch /tmp/g/noopener && cd /tmp/g
#     markup_tokens_have '*' noopener   # returned 0
#
# THE OPTION IS SAVED AND RESTORED BY HAND RATHER THAN WITH `local -`, WHICH IS
# THE OBVIOUS SPELLING AND IS WRONG HERE.  `local -` is a bash 4.4 feature and
# this project's frozen minimum is 4.2, which `lib/core.sh` enforces at load
# time - so on the oldest bash we support it does not scope anything, and the
# failure mode is the bad direction: `set -f` would ESCAPE this function and
# leave pathname expansion disabled for the rest of the run.  The restore is
# placed immediately after the split, which is the only glob-sensitive line, so
# an early `return` out of the loop below cannot skip it.
markup_tokens_have() {
  local list=${1,,} want=${2,,} tok noglob_was=0
  list=${list//$'\t'/ }
  list=${list//$'\n'/ }
  list=${list//$'\r'/ }
  [[ -o noglob ]] && noglob_was=1
  set -f
  # shellcheck disable=SC2206  # deliberate word split: a token list is exactly that
  local -a toks=($list)
  (( noglob_was )) || set +f
  for tok in "${toks[@]+"${toks[@]}"}"; do
    [[ $tok == "$want" ]] && return 0
  done
  return 1
}

# `markup_link_takes_sri REL` - 0 for a `<link>` whose relationship makes the
# `integrity` attribute meaningful.
#
# THE LIST IS EXACTLY THREE AND IS DELIBERATELY NOT LONGER.  Subresource
# Integrity is defined for elements that fetch a subresource the document then
# EXECUTES or APPLIES: a stylesheet, and a preloaded script or style.  A
# `rel="icon"`, `rel="canonical"`, `rel="dns-prefetch"`, `rel="manifest"` or
# `rel="alternate"` link either fetches nothing executable or is outside the SRI
# specification altogether, and flagging those would bury the real finding under
# every favicon on the internet.
markup_link_takes_sri() {
  local rel=$1
  markup_tokens_have "$rel" stylesheet && return 0
  markup_tokens_have "$rel" modulepreload && return 0
  markup_tokens_have "$rel" preload && return 0
  return 1
}

# ---------------------------------------------------------------------------
# 4. Anti-CSRF token recognition
# ---------------------------------------------------------------------------
# `markup_field_is_csrf_token NAME [TYPE]` - 0 when a form control's NAME is one
# a framework uses for a synchroniser token.
#
# THIS IS A NAME HEURISTIC AND IT IS ONLY EVER ALLOWED TO SUPPRESS A FINDING,
# never to raise one, which is what bounds the cost of it being wrong.  Reading
# a field as a token when it is not makes this phase MISS a genuinely
# undefended form - a false negative in the report, the direction
# docs/DESIGN.md §15 asks us to fail in when a heuristic must be wrong, and one
# the check's own `confidence: medium` and its remediation text both state.
# Reading a real token as an ordinary field would instead invent a finding about
# a form that is properly defended, which is the direction that destroys trust
# in the report - so the list is generous rather than strict.
#
# It is matched on the WHOLE name after normalisation (lowercased, `-` and `.`
# folded to `_`), then, for the two generic stems only, as a substring: a field
# called `user_csrf_token` is a CSRF token, and `csrfmiddlewaretoken` is one
# under another framework's spelling.
markup_field_is_csrf_token() {
  local name=${1,,} type=${2:-}
  [[ -n $name ]] || return 1
  name=${name//-/_}
  name=${name//./_}
  case $name in
    _token | __requestverificationtoken | authenticity_token | csrfmiddlewaretoken \
      | _csrf | _csrf_token | csrf_token | csrftoken | xsrf_token | xsrftoken \
      | __csrf_magic | anticsrf | veriftoken | form_key | _wpnonce | request_token \
      | state)
      return 0 ;;
  esac
  case $name in
    *csrf* | *xsrf*) return 0 ;;
  esac
  # A field named `token`, `..._token` or `..._nonce` counts only when it is
  # HIDDEN.  A VISIBLE input called `token` is a one-time-code box the user
  # types into, which defends nothing against request forgery - treating it as
  # a synchroniser token would suppress the finding on exactly the
  # two-factor-authentication form where a forged POST matters most.
  if [[ $type == hidden ]]; then
    case $name in
      token | *_token | *_nonce | nonce) return 0 ;;
    esac
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 5. Sensitive-page classification (this ticket's "weighted higher")
# ---------------------------------------------------------------------------
# `markup_path_is_sensitive PATH` - 0 when a URL path names a page whose
# reverse-tabnabbing exposure is materially worse: an AUTHENTICATION page, whose
# opener a tabnabbed window can navigate to a credential-harvesting clone the
# user believes they were already looking at; or a REDIRECT/continuation
# endpoint, which by construction hands control somewhere else and is where an
# opener rewrite is least likely to be noticed.
#
# A PATH HEURISTIC ONLY RAISES SEVERITY AND NEVER CREATES A FINDING.  The
# tabnabbing finding exists either way; this decides which of the two check ids
# carries it.  Being wrong therefore costs a severity grade, not a fabricated
# report entry.  `markup.sh` ALSO treats any page carrying an
# `<input type="password">` as sensitive whatever its path is - that signal is
# content-derived rather than name-derived and is the stronger of the two.
markup_path_is_sensitive() {
  local p=${1,,}
  case $p in
    *login* | *signin* | *sign_in* | *sign-in* | *logon* | *auth* | *sso* \
      | *session* | *password* | *passwd* | *credential* | *recover* \
      | *register* | *signup* | *sign_up* | *sign-up* | *2fa* | *mfa* | *otp* \
      | *redirect* | *continue* | *callback* | *logout* | *signout* \
      | *sign_out* | *sign-out*)
      return 0 ;;
  esac
  return 1
}

# `markup_is_html CTYPE` - 0 for a media type whose body is markup this parser
# should read.  A JSON, JavaScript or image response has no markup, and
# tokenising one would produce findings about a document that does not exist -
# a `<a target=_blank>` inside a JSON string value is data, not a link.
markup_is_html() {
  local ct=${1,,}
  ct=${ct%%;*}
  ct=${ct#"${ct%%[![:space:]]*}"}
  ct=${ct%"${ct##*[![:space:]]}"}
  case $ct in
    text/html | application/xhtml+xml | text/xml | application/xml) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. Choosing what to request (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `markup_endpoints_load [ENDPOINTS_FILE] [TARGET] [BASE_URL]` - publishes the
# URL list this phase will request in `_MARKUP_URL[]` with `_MARKUP_PATH[]`
# alongside, and sets `_MARKUP_N`, `_MARKUP_TRUNCATED` and
# `_MARKUP_SKIPPED_NON_GET`.  The four decisions this makes (base-url first,
# GET only, deduped by path template, sorted then capped) are `hdr_endpoints_
# load`'s, and are now documented exactly once, in `response_engine.sh`'s
# `resp_endpoints_load` - this file's own header records why the two used to
# be separate copies and why they no longer are.
#
# A THIN WRAPPER over the shared chooser, for the identical reason
# `headers_engine.sh`'s own `hdr_endpoints_load` is: no call site in
# `markup.sh` had to change, and `_MARKUP_MAX_ENDPOINTS` stays this file's own
# knob rather than becoming a second reader of a global the chooser owns.
markup_endpoints_load() {
  local epf=${1:-} target=${2:-} base=${3:-}
  resp_endpoints_load "$epf" "$target" "$base" "$_MARKUP_MAX_ENDPOINTS"
  declare -ga _MARKUP_URL=("${_RESP_URL[@]+"${_RESP_URL[@]}"}")
  declare -ga _MARKUP_PATH=("${_RESP_PATH[@]+"${_RESP_PATH[@]}"}")
  declare -g _MARKUP_N=$_RESP_N _MARKUP_TRUNCATED=$_RESP_TRUNCATED \
    _MARKUP_SKIPPED_NON_GET=$_RESP_SKIPPED_NON_GET
  return 0
}
