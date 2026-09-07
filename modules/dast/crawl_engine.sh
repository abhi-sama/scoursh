#!/usr/bin/env bash
# modules/dast/crawl_engine.sh - the crawler's pure function library
# (docs/DESIGN.md §7.5, §13 step 5; docs/STEP5-DAST-PLAN.md DAST-04).
#
# Owns:
#   docs/DESIGN.md      §7.5 - static crawl, spec ingestion, the deduped
#                        endpoints.json + parameters.json every §7.3/§7.4
#                        check iterates, and the honest SPA limitation.
#   docs/FOUNDATION.md  tension 21 - the run-directory inventory is the ONLY
#                        channel between modules.  This file both READS an
#                        inventory another module may have written and WRITES
#                        the merged result back.
#   docs/FOUNDATION.md  tension 10 - every byte here comes off a target and is
#                        attacker-controlled.  Nothing is interpolated into
#                        JSON except through lib/core.sh's `json_string`, and
#                        nothing reaches a run record except through
#                        `crawl_safe_text`.
#   docs/INVENTORY-FORMAT.md - the on-disk shape this file writes, which is a
#                        contract with twenty-seven downstream tickets.
#
# The run.sh / engine.sh split is modules/sast/'s: this file is a pure
# function library with the standard sourced-once guard and no side effects at
# source time; modules/dast/crawl.sh is the phase script that DOES something
# when `dast_run_phase` sources it.  It is a SECOND library beside
# modules/dast/engine.sh rather than an extension of it for the reason
# modules/sca/go_engine.sh is a second file beside modules/sca/engine.sh:
# engine.sh is DAST's dispatch skeleton, which every phase pays the cost of
# loading, and parsing HTML and four specification formats is not part of
# dispatching.
#
# ================= WHAT THE PARSERS IN THIS FILE DO NOT DO ==================
# Stated here rather than discovered later, the same way modules/sca/*.sh and
# the engine adapters state their own bounded-parser limits.
#
#   * `crawl_json_flatten` is a purpose-built, depth- and string-aware JSON
#     reader, NOT a general JSON library (no jq, no python at scan time).  It
#     handles objects, arrays, strings with the full escape set, numbers,
#     booleans and null.  It does NOT validate: trailing commas, duplicate
#     keys and truncated input are read as best it can rather than refused,
#     because a spec that is 99% readable should yield 99% of its endpoints.
#     `\uXXXX` escapes are decoded only for the ASCII range; anything above
#     U+007F is left as the literal escape text, which is a URL-safe outcome.
#   * `crawl_yaml_flatten` handles the BLOCK subset of YAML only - indented
#     mappings, `-` sequences, plain and single/double-quoted scalars, `#`
#     comments.  It REFUSES the whole document, loudly, on any construct it
#     cannot represent faithfully (flow style `{`/`[` in a value, anchors and
#     aliases `&`/`*`, merge keys `<<`, block scalars `|`/`>`, tabs used for
#     indentation, a second `---` document).  Refusing is deliberate: a YAML
#     reader that silently skips the constructs it does not know produces a
#     SHORT endpoint list that looks exactly like a complete one, which is the
#     overstated coverage docs/DESIGN.md §15 forbids.
#   * `crawl_html_extract` is a tag scanner, not an HTML5 parser.  It finds
#     `href`/`src`/`action`/`name` attributes and associates inputs with the
#     form element they are lexically inside.  It skips comments and the
#     contents of `<script>`/`<style>`.  It does NOT recover from malformed
#     nesting the way a browser does, and it deliberately does NOT mine
#     URL-shaped strings out of JavaScript: a string in a bundle is not
#     evidence of a route, and guessing produces a request to a path the
#     operator's application may never have had.
#   * `crawl_spec_openapi` resolves a `requestBody`/Swagger-2 `in: body`
#     schema's `$ref` against `components.schemas` (IMPORT-03) - bounded depth
#     and cycle-guarded, never followed forever - and picks the FIRST
#     subschema of a 3.1 `oneOf`/`anyOf`, recording a counted
#     coverage_reduction for both a dropped cycle/depth-bound and a
#     first-subschema pick.  `allOf` and Postman `{{variables}}` are still not
#     resolved; a construct this cannot represent costs that field/endpoint
#     rather than being guessed at, and is recorded rather than assumed away.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose and awk program text quote `$`, `{{`, and URL
#   syntax literally.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_CRAWL_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_CRAWL_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 0. Bounds
# ---------------------------------------------------------------------------
# Every one of these is a CHOSEN number, not a value from a frozen schema, and
# each is stated here so a reader can find them all in one place.  Where one
# of them bites, the crawler records a coverage_gap naming it - a bound that
# truncates silently is indistinguishable from a surface that was really that
# small (docs/DESIGN.md §15).
#
# `crawl-depth` is the ONE bound that is operator-configurable, because
# rules/RULE-FORMAT.md §9.6.3 already froze it as a config key; the rest have
# no key in that schema and inventing one would be a format change.
: "${_CRAWL_MAX_PAGES:=200}"        # pages fetched per target
: "${_CRAWL_MAX_BODY_BYTES:=524288}" # bytes of a response body parsed
: "${_CRAWL_MAX_ENDPOINTS:=5000}"   # endpoint records held per run
: "${_CRAWL_MAX_PARAMS:=20000}"     # parameter records held per run
: "${_CRAWL_MAX_SPEC_BYTES:=8388608}" # bytes of a specification file read
: "${_CRAWL_EXAMPLE_MAX:=64}"       # bytes of an observed parameter value kept

# ---------------------------------------------------------------------------
# 1. Untrusted text, on its way to a run record
# ---------------------------------------------------------------------------
# `crawl_safe_text TEXT [MAX]` - prints TEXT with every control character
# removed and the result truncated.
#
# `run_record` writes one LINE per fact (lib/core.sh), and lib/report.sh's
# markdown emitter renders that line as-is.  A form name carrying a raw
# newline would therefore become two coverage records, and one carrying an
# ANSI escape would repaint the terminal of whoever reads the report - the
# hostile-evidence cases tests/suites/report.sh already pins for findings,
# applied to the surface a crawler actually writes to.  The HTML emitter
# escapes independently (`html_escape`); this is not a substitute for that,
# it is the layer that keeps a record a record.
crawl_safe_text() {
  local text=$1 max=${2:-200} out=''
  # Control characters, DEL, and the bytes that would end a record.
  text=${text//[$'\x01'-$'\x1f'$'\x7f']/ }
  # Runs of space collapse, so a stripped escape sequence does not leave a
  # gap wide enough to hide the rest of the line past the report's margin.
  while [[ $text == *"  "* ]]; do text=${text//  / }; done
  text=${text# }
  text=${text% }
  if (( ${#text} > max )); then
    out=${text:0:max}
    printf '%s...' "$out"
  else
    printf '%s' "$text"
  fi
}

# ---------------------------------------------------------------------------
# 2. The JSON flattener
# ---------------------------------------------------------------------------
# `crawl_json_flatten` - reads JSON on stdin, prints one line per SCALAR leaf:
#
#     <path><TAB><type><TAB><raw value>
#
# `path` is the leaf's location, segments joined by US (0x1f): object keys as
# their raw (still JSON-escaped) text, array elements as their decimal index.
# `type` is one of `s` `n` `b` `z` (string, number, boolean, null).  For a
# string, `raw value` is the bytes BETWEEN the quotes, still escaped exactly as
# the document wrote them; for the other three it is the literal token.
#
# TWO PROPERTIES MAKE THIS SAFE TO READ LINE BY LINE FROM BASH, and both come
# from JSON's own grammar rather than from trust in the input.  A JSON string
# literal can contain neither a raw newline nor a raw tab (RFC 8259 §7 requires
# both to be escaped), so emitting the still-escaped bytes guarantees exactly
# one output line per leaf and an unambiguous TAB split - no length prefix and
# no second delimiter to get wrong.  And an object key cannot contain a literal
# US byte for the same reason, so the path split is unambiguous too.  A reader
# that unescaped first would lose both properties, which is why
# `crawl_json_unescape` is a SEPARATE, caller-invoked step.
#
# One awk process for a whole document, not one per query: `_sca_json_walk`
# (modules/sca/engine.sh) established the purpose-built-parser precedent here,
# and a HAR capture with ten thousand entries is the case that decides the
# shape.
crawl_json_flatten() {
  awk '
    # Accumulate the whole document.  A JSON document has no line semantics,
    # and a string cannot span a raw newline, so joining with \n is lossless.
    { doc = doc $0 "\n" }
    function fail(msg) { print "__JSON_ERROR__\t" msg > "/dev/stderr"; exit 1 }
    function skipws() { while (i <= n && substr(doc, i, 1) ~ /[ \t\r\n]/) i++ }
    # Reads one string literal starting at the opening quote; returns the raw
    # escaped body and leaves i past the closing quote.
    function readstr(  s, c) {
      i++            # opening quote
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c == "\\") { s = s c substr(doc, i + 1, 1); i += 2; continue }
        if (c == "\"") { i++; return s }
        s = s c
        i++
      }
      fail("unterminated string")
    }
    function readtok(  s, c) {
      s = ""
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c ~ /[]},: \t\r\n[]/) break
        s = s c
        i++
      }
      return s
    }
    function emit(path, type, val) { print path "\t" type "\t" val }
    function value(path,   c, k, idx, first) {
      skipws()
      if (i > n) fail("unexpected end of document")
      c = substr(doc, i, 1)
      if (c == "{") {
        i++
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "}") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "}") { i++; return }
          if (c != "\"") fail("object key is not a string at byte " i)
          k = readstr()
          skipws()
          if (substr(doc, i, 1) != ":") fail("expected : after object key")
          i++
          value(path == "" ? k : path SEP k)
          first = 0
        }
      }
      if (c == "[") {
        i++
        idx = 0
        first = 1
        while (1) {
          skipws()
          c = substr(doc, i, 1)
          if (c == "]") { i++; return }
          if (!first) {
            if (c == ",") { i++; skipws(); c = substr(doc, i, 1) }
          }
          if (c == "]") { i++; return }
          value(path == "" ? idx : path SEP idx)
          idx++
          first = 0
        }
      }
      if (c == "\"") { emit(path, "s", readstr()); return }
      k = readtok()
      if (k == "") fail("unparseable value at byte " i)
      if (k == "true" || k == "false") { emit(path, "b", k); return }
      if (k == "null") { emit(path, "z", k); return }
      emit(path, "n", k)
    }
    END {
      SEP = sprintf("%c", 31)
      n = length(doc)
      i = 1
      skipws()
      if (i > n) exit 0
      value("")
    }
  '
}

# `crawl_json_unescape RAW` - the inverse of the "still escaped" contract
# above, for ONE field, applied only where the value is about to be used.
#
# `\uXXXX` above U+007F is deliberately left as its literal escape text.
# Decoding it would mean composing UTF-8 by hand in bash for a value that is
# then concatenated into a URL, and a URL is compared against the scope
# allowlist as authored bytes (lib/http.sh's own note that IDN/A-label
# conversion is a KNOWN, tracked gap rather than a silently-handled one).
# Leaving it visible keeps that gap visible too.
#
# SC1003: `'\'` here is a literal single backslash - the character this
# function exists to interpret - not a botched attempt to escape a quote.
# Written any other way it stops being the JSON escape character.
# shellcheck disable=SC1003
crawl_json_unescape() {
  local s=$1 out='' i n ch nx code decoded
  # The overwhelmingly common case, checked once: a value with no escape at
  # all is returned untouched rather than walked one character at a time.  A
  # HAR capture is tens of thousands of such values.
  if [[ $s != *'\'* ]]; then
    printf '%s' "$s"
    return 0
  fi
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    if [[ $ch != '\' ]]; then out+=$ch; continue; fi
    nx=${s:i+1:1}
    case $nx in
      '"') out+='"'; i=$(( i + 1 )) ;;
      '\') out+='\'; i=$(( i + 1 )) ;;
      '/') out+='/'; i=$(( i + 1 )) ;;
      b) out+=$'\b'; i=$(( i + 1 )) ;;
      f) out+=$'\f'; i=$(( i + 1 )) ;;
      n) out+=$'\n'; i=$(( i + 1 )) ;;
      r) out+=$'\r'; i=$(( i + 1 )) ;;
      t) out+=$'\t'; i=$(( i + 1 )) ;;
      u)
        code=${s:i+2:4}
        if [[ $code == 0000 ]]; then
          # A bash string can never hold a NUL, so it becomes a space rather
          # than silently ending the value where a C string would stop.
          # Losing one character is visible; a truncated URL is not.
          out+=' '
          i=$(( i + 5 ))
        elif [[ $code =~ ^00[0-7][0-9A-Fa-f]$ ]]; then
          # ASCII range only.  `printf -v` INTO a variable, never `printf '%b'`
          # over the whole accumulated string at the end: that would also
          # re-interpret a backslash that came from the input's own `\\`
          # escape, turning target-controlled text into an escape sequence
          # this function had already decided was a literal character.
          # The hex digits have to be in the FORMAT string: bash's printf
          # interprets `\xNN` when it parses the format, so `'\x%s'` with the
          # digits as an argument emits a literal "missing hex digit" error
          # and the untranslated text.  The digits are safe to interpolate
          # into the format because the regex above has already proven the
          # whole four-character code is hex.
          # SC2059: the interpolation into the format string is the point
          # here, and the regex above is what makes it safe.
          # shellcheck disable=SC2059
          printf -v decoded "\\x${code:2:2}"
          out+=$decoded
          i=$(( i + 5 ))
        else
          out+='\u'
          i=$(( i + 1 ))
        fi
        ;;
      *) out+='\' ;;
    esac
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 3. The YAML block-subset flattener
# ---------------------------------------------------------------------------
# `crawl_yaml_flatten` - reads YAML on stdin and prints the SAME leaf stream
# `crawl_json_flatten` prints, so every specification extractor below reads one
# format and works against either encoding.  Values are emitted as type `s`
# with JSON escaping applied, so a consumer cannot tell which front-end
# produced a line.
#
# IT REFUSES RATHER THAN GUESSES.  On any construct outside the block subset it
# prints a single `__YAML_UNSUPPORTED__<TAB><reason>` line to stdout, exits
# non-zero, and emits nothing else.  See this file's header for the list and
# for why a partial read would be the worse failure.
crawl_yaml_flatten() {
  awk '
    # ALL-OR-NOTHING.  Leaves are buffered and printed only in END, and only
    # when nothing refused.  Printing as it went meant a document whose first
    # ten lines are ordinary and whose eleventh is flow style emitted those ten
    # leaves AND the refusal, so a caller reading the first line of the output
    # saw a leaf and reported "the document declared no paths" instead of the
    # operator-actionable "this uses a construct I would have had to guess at".
    # The promise this file makes in its header - refuse the WHOLE document -
    # is only true when the output is withheld until the whole document has
    # been read.
    #
    # NOTE FOR ANY LATER EDIT: this awk program is inside a single-quoted shell
    # string, so no comment in it may contain an apostrophe.
    function fail(reason) {
      bad = 1
      badreason = reason
      exit 1
    }
    function jesc(s,   out, i, c, o) {
      out = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") { out = out "\\\\"; continue }
        if (c == "\"") { out = out "\\\""; continue }
        o = index(CTL, c)
        if (o > 0) { out = out sprintf("\\u%04x", o); continue }
        out = out c
      }
      return out
    }
    # Trim a trailing unquoted `# comment`, then surrounding whitespace.
    function strip(s,   i, c, instr, q) {
      instr = 0; q = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (instr) { if (c == q) instr = 0; continue }
        if (c == "\"" || c == "'\''") { instr = 1; q = c; continue }
        if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) {
          s = substr(s, 1, i - 1)
          break
        }
      }
      sub(/[ \t\r]+$/, "", s)
      return s
    }
    function unquote(v,   c) {
      c = substr(v, 1, 1)
      if ((c == "\"" || c == "'\''") && substr(v, length(v), 1) == c && length(v) >= 2) {
        v = substr(v, 2, length(v) - 2)
        if (c == "\"") { gsub(/\\"/, "\"", v) }
        else { gsub(/'\'''\''/, "'\''", v) }
      }
      return v
    }
    function reject_scalar(v) {
      if (v == "") return
      if (v ~ /^[&*]/) fail("anchors and aliases are not supported (line " NR ")")
      if (v ~ /^[|>]/) fail("block scalars | and > are not supported (line " NR ")")
      if (v ~ /^[{[]/) fail("flow-style collections are not supported (line " NR ")")
    }
    # Pop the indent stack down to `ind`, then push `ind` with `key`.
    function setkey(ind, key,   d) {
      while (top > 0 && stack_ind[top] >= ind) top--
      top++
      stack_ind[top] = ind
      stack_key[top] = key
      # Reset any sequence counter that lived at a deeper level.
      for (d in seq) if (d + 0 > ind) delete seq[d]
    }
    function path(   p, d) {
      p = ""
      for (d = 1; d <= top; d++) p = (p == "" ? stack_key[d] : p SEP stack_key[d])
      return p
    }
    function emit(v) { buf[nbuf++] = sprintf("%s\ts\t%s", path(), jesc(v)) }
    BEGIN {
      SEP = sprintf("%c", 31)
      CTL = ""
      for (i = 1; i <= 31; i++) CTL = CTL sprintf("%c", i)
      CTL = CTL sprintf("%c", 127)
      top = 0
      nbuf = 0
    }
    /\t/ { if ($0 ~ /^[ \t]*\t/) fail("a TAB is used for indentation (line " NR ")") }
    # `---` is only a document START marker when nothing has been read yet.
    # One appearing after any content line means a SECOND document, which this
    # front-end has no way to represent in a single leaf stream.  Keying on
    # "have we seen a --- before" instead let a `key: value` block followed by
    # `---` through, silently parsing the first document and dropping the rest.
    /^---/ { if (nbuf > 0 || top > 0) fail("multi-document YAML is not supported (line " NR ")"); next }
    /^\.\.\./ { next }
    {
      line = strip($0)
      if (line ~ /^[ \t]*$/) next
      match(line, /^ */)
      ind = RLENGTH
      body = substr(line, ind + 1)
      if (body ~ /^<</) fail("merge keys << are not supported (line " NR ")")
      if (body ~ /^- /|| body == "-") {
        # A sequence entry.  Its index lives at this indent; a nested mapping
        # on the same physical line starts two columns further in, which is
        # what `ind + 2` reproduces.
        idx = seq[ind] + 0
        seq[ind] = idx + 1
        setkey(ind, idx)
        rest = body
        sub(/^-[ ]*/, "", rest)
        if (rest == "") next
        if (match(rest, /^[^ :]+:([ ]|$)/)) {
          # `- key: value` - re-enter as a mapping one level in.
          line = sprintf("%*s%s", ind + 2, "", rest)
          match(line, /^ */)
          ind = RLENGTH
          body = rest
        } else {
          reject_scalar(rest)
          emit(unquote(rest))
          next
        }
      }
      if (match(body, /^("[^"]*"|'\''[^'\'']*'\''|[^ :]+):([ ]|$)/) || body ~ /:$/) {
        ci = index(body, ":")
        # A quoted key may contain a colon; find the closing quote first.
        c = substr(body, 1, 1)
        if (c == "\"" || c == "'\''") {
          ci = 0
          for (i = 2; i <= length(body); i++) {
            if (substr(body, i, 1) == c) { ci = i + 1; break }
          }
          if (ci == 0 || substr(body, ci, 1) != ":") fail("unterminated quoted key (line " NR ")")
        }
        key = unquote(substr(body, 1, ci - 1))
        val = substr(body, ci + 1)
        sub(/^[ ]+/, "", val)
        setkey(ind, key)
        if (val == "") next
        reject_scalar(val)
        emit(unquote(val))
        next
      }
      fail("unrecognised block-YAML line (line " NR ")")
    }
    END {
      if (bad) {
        printf "__YAML_UNSUPPORTED__\t%s\n", badreason
        exit 1
      }
      for (bi = 0; bi < nbuf; bi++) print buf[bi]
    }
  '
}

# `crawl_spec_flatten FILE` - flatten FILE by whichever front-end its own bytes
# call for, JSON if the first non-space byte is `{` or `[`, block YAML
# otherwise.  Prints the leaf stream on stdout; returns 1 and prints the
# `__YAML_UNSUPPORTED__` line when the YAML front-end refuses.
#
# Detection is on CONTENT, never on the filename extension: an operator who
# names an OpenAPI document `api.txt` is not making a claim about its encoding,
# and a `.json` file holding YAML is a real and common mistake.
crawl_spec_flatten() {
  local file=$1 head=''
  [[ -r $file ]] || return 1
  head=$(head -c 4096 -- "$file" 2>/dev/null || true)
  head=${head#"${head%%[![:space:]]*}"}
  if [[ ${head:0:1} == '{' || ${head:0:1} == '[' ]]; then
    head -c "$_CRAWL_MAX_SPEC_BYTES" -- "$file" | crawl_json_flatten
    return $?
  fi
  head -c "$_CRAWL_MAX_SPEC_BYTES" -- "$file" | crawl_yaml_flatten
}

# ---------------------------------------------------------------------------
# 4. HTML extraction
# ---------------------------------------------------------------------------
# `crawl_html_extract` - reads an HTML document on stdin, prints one record per
# line, TAB-separated, in document order:
#
#     base<TAB><href>                  a <base href> element
#     link<TAB><url>                   an href/src worth following
#     form<TAB><method><TAB><action>   a <form> opened
#     input<TAB><name>                 a named control inside the open form
#     formend                          the form closed
#
# `input` records belong to the most recent `form` record, which is what lets a
# caller in bash reconstruct the association without holding the DOM.
#
# It skips `<!-- -->`, `<script>` and `<style>` bodies.  See this file's header
# for what it is not.
crawl_html_extract() {
  awk '
    # HTML character references, the five that matter in an attribute value.
    # `&amp;` is not an optional nicety: HTML REQUIRES a literal & in an href
    # to be written that way, so `?q=1&amp;page=2` is the NORMAL spelling of a
    # two-parameter query.  Left undecoded it yields one parameter named
    # "amp;page", so the second real parameter is missing from the inventory
    # and no later check ever fuzzes it.  Numeric references are decoded only
    # for & itself, which is the one that changes a URL structurally; the rest
    # are left alone rather than half-decoded.
    function entities(v) {
      gsub(/&#38;|&#x26;|&#X26;/, "\\&", v)
      gsub(/&amp;/, "\\&", v)
      gsub(/&lt;/, "<", v)
      gsub(/&gt;/, ">", v)
      gsub(/&quot;/, "\"", v)
      gsub(/&#39;|&apos;/, SQ, v)
      return v
    }
    function attr(tag, name,   re, s, q, v, p) {
      # name = "..." | name = '\''...'\'' | name = bare
      re = "[ \t\r\n/]" name "[ \t\r\n]*=[ \t\r\n]*"
      s = " " tolower(tag)
      p = match(s, re)
      if (p == 0) return ""
      # Work on the ORIGINAL-case tag from the same offset, so the value keeps
      # its case while the attribute name was matched case-insensitively.
      v = substr(" " tag, p + RLENGTH)
      q = substr(v, 1, 1)
      if (q == "\"" || q == "'\''") {
        v = substr(v, 2)
        p = index(v, q)
        if (p == 0) return entities(v)
        return entities(substr(v, 1, p - 1))
      }
      if (match(v, /[ \t\r\n>]/)) return entities(substr(v, 1, RSTART - 1))
      return entities(v)
    }
    function name_of(tag,   t) {
      t = tag
      sub(/^\//, "", t)
      if (match(t, /[ \t\r\n\/]/)) t = substr(t, 1, RSTART - 1)
      return tolower(t)
    }
    # SQ is built with sprintf rather than written literally: this awk program
    # lives inside a single-quoted shell string, so an apostrophe anywhere in
    # it - code or comment - would end that string.
    BEGIN { SQ = sprintf("%c", 39) }
    { doc = doc $0 "\n" }
    END {
      n = length(doc)
      i = 1
      skipuntil = ""
      informs = 0
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c != "<") { i++; continue }
        if (substr(doc, i, 4) == "<!--") {
          p = index(substr(doc, i), "-->")
          i = (p == 0) ? n + 1 : i + p + 2
          continue
        }
        # Read to the closing >, honouring quoted attribute values so a > in a
        # URL cannot end the tag early.
        j = i + 1
        instr = 0; q = ""
        while (j <= n) {
          c = substr(doc, j, 1)
          if (instr) { if (c == q) instr = 0; j++; continue }
          if (c == "\"" || c == "'\''") { instr = 1; q = c; j++; continue }
          if (c == ">") break
          j++
        }
        if (j > n) break
        tag = substr(doc, i + 1, j - i - 1)
        i = j + 1
        nm = name_of(tag)
        if (skipuntil != "") {
          if (nm == skipuntil && substr(tag, 1, 1) == "/") skipuntil = ""
          continue
        }
        if (nm == "script" || nm == "style") {
          if (substr(tag, 1, 1) != "/" && substr(tag, length(tag), 1) != "/") skipuntil = nm
          continue
        }
        if (nm == "base") {
          v = attr(tag, "href"); if (v != "") print "base\t" v
          continue
        }
        if (nm == "form" && substr(tag, 1, 1) != "/") {
          if (informs) print "formend"
          m = attr(tag, "method"); if (m == "") m = "GET"
          a = attr(tag, "action")
          print "form\t" toupper(m) "\t" a
          informs = 1
          continue
        }
        if (nm == "form" && substr(tag, 1, 1) == "/") {
          if (informs) print "formend"
          informs = 0
          continue
        }
        if (nm == "input" || nm == "select" || nm == "textarea" || nm == "button") {
          v = attr(tag, "name")
          if (v != "" && informs) print "input\t" v
          continue
        }
        if (nm == "a" || nm == "area" || nm == "link" || nm == "iframe" || nm == "frame") {
          v = attr(tag, "href"); if (v == "") v = attr(tag, "src")
          if (v != "") print "link\t" v
          continue
        }
      }
      if (informs) print "formend"
    }
  '
}

# `crawl_body_looks_like_markup FILE` - 0 when the first 512 bytes of FILE
# contain a case-folded HTML/markup marker. Used only when a fetched response
# carried no Content-Type at all, so a headerless binary is not fed to the tag
# scanner (crawl.sh's own caller comment explains why).
#
# Matched on the FILE, through scan_match, never by reading FILE into a bash
# string. A fetched response body is arbitrary target-controlled bytes and can
# legitimately contain a NUL; `sniff=$(head -c 512 -- "$file")` (the shape
# this used to have) runs the file through command substitution, which
# silently drops every NUL byte AND prints bash's own "warning: command
# substitution: ignored null byte in input" to stderr - a warning an operator
# running a real scan must never see. `-a`/`--text` on both bound pattern
# engines (tension 2's `core_bind_engine`) forces byte-for-byte text-mode
# matching straight off the file, bypassing rg's default NUL-triggered
# "binary file matches" heuristic, which would otherwise report no offsets at
# all. See modules/dast/active/hosthdr_engine.sh's `hh_body_reflects` for the
# fuller account of the same defect and the identical fix.
crawl_body_looks_like_markup() {
  local file=$1
  local bounded=$SCOURSH_SCRATCH/crawl-sniff.$BASHPID
  local hits=$SCOURSH_SCRATCH/crawl-sniff-hits.$BASHPID
  local rc=0
  [[ -s $file ]] || return 1
  head -c 512 -- "$file" >"$bounded" 2>/dev/null || : >"$bounded"
  scan_match "$hits" -a -i \
    -e '<html' -e '<!doctype html' -e '<body' -e '<a ' -e '<form' \
    -- "$bounded" || rc=$?
  rm -f "$bounded" "$hits"
  return "$rc"
}

# `crawl_html_looks_client_rendered FILE` - a bounded, stated heuristic, used
# ONLY to sharpen the wording of a coverage_gap that is emitted either way.
#
# It is never a gate on anything: the SPA gap is recorded whenever no
# specification was supplied (docs/STEP5-DAST-PLAN.md, "SPA / client-rendered-
# app limitation"), and this only decides whether the sentence a human reads
# says "and this target's own markup looks client-rendered" as well.  A
# heuristic that DECIDED whether to warn could be wrong in the direction that
# hides the warning; this one can only be wrong about an adjective.
crawl_html_looks_client_rendered() {
  local file=$1 hits=$SCOURSH_SCRATCH/crawl-spa.$BASHPID links=0 scripts=0
  [[ -r $file ]] || return 1
  if scan_match "$hits" -c -e '<script' -- "$file"; then
    IFS= read -r scripts <"$hits" || true
  fi
  if scan_match "$hits" -c -e '<a[ >]|<a$' -- "$file"; then
    IFS= read -r links <"$hits" || true
  fi
  rm -f "$hits"
  [[ $scripts =~ ^[0-9]+$ ]] || scripts=0
  [[ $links =~ ^[0-9]+$ ]] || links=0
  (( scripts >= 1 && links <= 2 ))
}

# ---------------------------------------------------------------------------
# 5. URL resolution
# ---------------------------------------------------------------------------
# `crawl_url_resolve BASE REF` - prints the absolute form of REF against BASE,
# or returns 1 for a reference that is not a fetchable http(s) URL.
#
# Returning 1 rather than a best-effort string for `mailto:`, `javascript:`,
# `data:`, `tel:` and a bare `#fragment` is the point: each of them, coerced
# into a URL, becomes a request to a path that was never a link.  The fragment
# is always dropped - it is not sent to a server, so two references differing
# only there are one endpoint, and keeping it would inflate the inventory with
# duplicates that each cost a real request downstream.
crawl_url_resolve() {
  local base=$1 ref=$2 scheme authority path q rest
  ref=${ref%%$'\r'*}
  # Leading/trailing ASCII whitespace is stripped by every browser.
  ref=${ref#"${ref%%[![:space:]]*}"}
  ref=${ref%"${ref##*[![:space:]]}"}
  [[ -n $ref ]] || return 1
  # Fragment: never sent, always dropped.
  ref=${ref%%#*}
  [[ -n $ref ]] || return 1

  case ${ref,,} in
    javascript:* | mailto:* | data:* | tel:* | sms:* | file:* | ftp:* | about:*)
      return 1
      ;;
  esac

  if [[ $ref =~ ^[Hh][Tt][Tt][Pp][Ss]?:// ]]; then
    printf '%s' "$ref"
    return 0
  fi
  # A scheme we do not speak, spelled out rather than lumped in with relative
  # references - `ws://` is a real link a page can carry and is not fetchable
  # through lib/http.sh.
  if [[ $ref =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]]; then
    return 1
  fi

  # Split BASE, which is always absolute here (the crawler only ever passes a
  # URL it already fetched).
  [[ $base =~ ^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$ ]] || return 1
  scheme=${BASH_REMATCH[1]}
  authority=${BASH_REMATCH[2]}
  rest=${BASH_REMATCH[3]}
  rest=${rest%%#*}
  path=${rest%%\?*}
  [[ -n $path ]] || path=/

  if [[ $ref == //* ]]; then
    printf '%s' "$scheme:$ref"
    return 0
  fi
  if [[ $ref == /* ]]; then
    printf '%s' "$scheme://$authority$(_crawl_path_normalize "$ref")"
    return 0
  fi
  if [[ $ref == \?* ]]; then
    printf '%s' "$scheme://$authority$path$ref"
    return 0
  fi
  # Relative to the base's directory.
  q=${path%/*}/
  printf '%s' "$scheme://$authority$(_crawl_path_normalize "$q$ref")"
}

# `_crawl_path_normalize PATH` - RFC 3986 §5.2.4's remove_dot_segments, on the
# path only (any query is carried through untouched).
#
# It is not cosmetic.  `/a/../../etc` must collapse to `/etc` and not to
# `/a/../../etc`, because the scope gate compares a normalised path prefix
# (lib/http.sh) and a path-scoped scope target would otherwise be escapable by
# a link the SCANNED SITE wrote.
_crawl_path_normalize() {
  local p=$1 query='' seg out=''
  local -a stack=()
  if [[ $p == *\?* ]]; then
    query=\?${p#*\?}
    p=${p%%\?*}
  fi
  local IFS=/
  # shellcheck disable=SC2206
  local -a parts=($p)
  for seg in "${parts[@]+"${parts[@]}"}"; do
    case $seg in
      '' | .) continue ;;
      ..) [[ ${#stack[@]} -gt 0 ]] && unset 'stack[-1]' && stack=("${stack[@]+"${stack[@]}"}") ;;
      *) stack+=("$seg") ;;
    esac
  done
  for seg in "${stack[@]+"${stack[@]}"}"; do out+=/$seg; done
  [[ -n $out ]] || out=/
  # A trailing slash is meaningful to most routers, so it is preserved.
  if [[ $p == */ && $out != */ ]]; then out+=/; fi
  printf '%s%s' "$out" "$query"
}

# `crawl_url_split URL` - sets `_CRAWL_U_BASE` (scheme://authority/path, no
# query, no fragment) and `_CRAWL_U_QUERY` (the raw query string, no `?`).
# SETS rather than prints, so a caller in a loop pays no fork.
crawl_url_split() {
  local url=$1
  url=${url%%#*}
  if [[ $url == *\?* ]]; then
    _CRAWL_U_BASE=${url%%\?*}
    _CRAWL_U_QUERY=${url#*\?}
  else
    _CRAWL_U_BASE=$url
    _CRAWL_U_QUERY=''
  fi
}

# `crawl_query_names QUERY` - prints one `name<TAB>value` line per parameter in
# a `a=1&b=2` query string.  A bare `a` (no `=`) is a real parameter with an
# empty value and is kept; an empty segment (`a=1&&b=2`) is not.
crawl_query_names() {
  local q=$1 pair name value
  local IFS='&'
  # shellcheck disable=SC2206
  local -a pairs=($q)
  for pair in "${pairs[@]+"${pairs[@]}"}"; do
    [[ -n $pair ]] || continue
    if [[ $pair == *=* ]]; then
      name=${pair%%=*}
      value=${pair#*=}
    else
      name=$pair
      value=''
    fi
    [[ -n $name ]] || continue
    printf '%s\t%s\n' "$name" "$value"
  done
}

# ---------------------------------------------------------------------------
# 6. The inventory accumulator
# ---------------------------------------------------------------------------
# Endpoints and parameters accumulate in memory, deduped as they arrive, and
# are written once at the end.  `declare -ga`/`-gA`, never bare, for the reason
# modules/dast/engine.sh's phase table documents at length: in a real run this
# file is sourced from INSIDE `dast_run_phase`, so a declaration without `-g`
# creates a local that dies with the phase while the sourced-once guard - a
# plain assignment, and therefore global - survives to suppress the reload.
crawl_inv_reset() {
  declare -ga _CRAWL_EP=()
  declare -ga _CRAWL_PARAM=()
  declare -gA _CRAWL_EP_SEEN=()
  declare -gA _CRAWL_PARAM_SEEN=()
  declare -g _CRAWL_EP_TRUNCATED=0
  declare -g _CRAWL_PARAM_TRUNCATED=0
  declare -g _CRAWL_PARAM_INVALID_LOCATION=0
  declare -g _CRAWL_PARAM_INVALID_HEADER_NAME=0
  declare -g _CRAWL_EP_CONTROL_BYTE=0
  declare -g _CRAWL_PARAM_CONTROL_BYTE=0
}

# `crawl_has_control_byte TEXT` - true (exit 0) when TEXT contains a C0
# control byte (0x01-0x1f) or DEL (0x7f), the identical class `crawl_safe_text`
# already strips for report output (section 1 above).
#
# `crawl_add_endpoint`/`crawl_add_param` join their fields with US (0x1f) to
# build one tuple string per row (sections 5/5a below), and that byte is the
# ONLY thing separating one field from the next when the tuple is later
# re-split with `IFS=$'\x1f' read`.  `crawl_json_unescape` (section 2 above)
# will happily turn a JSON `` escape - or any other `\u00XX` C0 escape -
# in an OpenAPI/HAR/Postman-supplied name, value, method or URL into that
# exact raw byte, which then shifts every field after it onto the wrong
# position once the row is re-split: a name meant for one column reappears as
# a location, a source, or a header name the IMPORT-05 token guard (below)
# never saw, because that guard runs against the PRE-corruption variable.
# The result ranges from a forged inventory row to `http_request_header`
# `die`-ing the whole run (exit 5) on a header name assembled from the
# shifted fragments - a hostile spec turning scoursh's own internal
# delimiter into denial-of-scan.
#
# Every field this function's two callers below receive from untrusted
# specification/HAR/Postman input is checked against it BEFORE the tuple is
# built, and a hit is REJECTED with a counted `coverage_reduction` rather
# than silently stripped: a control byte in a real header/parameter/method
# name or URL is never legitimate, so nothing real is lost, and rejecting
# keeps the record format's own "skip malformed input and say so" posture
# rather than quietly rewriting what a hostile document claimed.  This is
# also what closes a CRLF (0x0d/0x0a, both in the same C0 range) smuggled
# into a HAR entry's `request.method`.
crawl_has_control_byte() {
  local text=$1
  [[ $text == *[$'\x01'-$'\x1f'$'\x7f']* ]]
}

# `crawl_id KEY` - the 12-hex join key an endpoint and its parameters share.
#
# Twelve hex characters of SHA-256, the same width and the same reasoning as
# rules/RULE-FORMAT.md's own fingerprint truncation: long enough that a
# collision inside one run's inventory is not a thing that happens, short
# enough to read in a report.  `sha256_of` reads STDIN ONLY (tension 9), which
# tests/lint-shell.sh enforces, so the key is piped and never an argument.
crawl_id() {
  local key=$1 h
  h=$(printf '%s' "$key" | sha256_of)
  printf '%s' "${h:0:12}"
}

# `crawl_add_endpoint TARGET METHOD URL SOURCE DEPTH STATUS CONTENT_TYPE
# [REQUEST_BODY_TYPE]` - records one endpoint, deduped on (method,
# url-without-query).  Sets `_CRAWL_LAST_EP_ID` either way, so a caller can
# attach parameters to an endpoint that a previous page already discovered.
#
# THE QUERY STRING IS NOT PART OF THE ENDPOINT.  `?id=1` and `?id=2` are one
# endpoint with one parameter, not two endpoints: keeping them apart would make
# a paginated listing look like fifty endpoints, and every §7.3 probe would
# then re-test the identical handler fifty times against the same rate limit.
# The names go to parameters.json, which is the artifact the probes iterate
# (docs/DESIGN.md §7.3's closing paragraph).
#
# `REQUEST_BODY_TYPE` (IMPORT-02/03/04, docs/INVENTORY-FORMAT.md §2) is
# OPTIONAL and additive; empty or anything other than the literal `json` reads
# back as `form` at `inject_inventory_load` - so every caller before IMPORT-03
# needed no change.  Like every other field, it is set only on the FIRST write
# for a given (method, url) key: a dedup hit ignores it, matching `source`'s
# own "never rewritten" rule.
crawl_add_endpoint() {
  local target=$1 method=$2 url=$3 source=$4 depth=${5:-0} status=${6:-} ctype=${7:-}
  local body_type=${8:-}
  local key id host path
  if crawl_has_control_byte "$target" || crawl_has_control_byte "$method" ||
     crawl_has_control_byte "$url" || crawl_has_control_byte "$source" ||
     crawl_has_control_byte "$status" || crawl_has_control_byte "$ctype" ||
     crawl_has_control_byte "$body_type"; then
    _CRAWL_EP_CONTROL_BYTE=$(( _CRAWL_EP_CONTROL_BYTE + 1 ))
    _CRAWL_LAST_EP_ID=''
    return 0
  fi
  crawl_url_split "$url"
  url=$_CRAWL_U_BASE
  method=${method^^}
  key="$method $url"
  if [[ -n ${_CRAWL_EP_SEEN[$key]:-} ]]; then
    _CRAWL_LAST_EP_ID=${_CRAWL_EP_SEEN[$key]}
    return 0
  fi
  if (( ${#_CRAWL_EP[@]} >= _CRAWL_MAX_ENDPOINTS )); then
    _CRAWL_EP_TRUNCATED=$(( _CRAWL_EP_TRUNCATED + 1 ))
    _CRAWL_LAST_EP_ID=''
    return 1
  fi
  id=$(crawl_id "$key")
  host=''
  path=''
  if [[ $url =~ ^[A-Za-z][A-Za-z0-9+.-]*://([^/]*)(/.*)?$ ]]; then
    host=${BASH_REMATCH[1]}
    path=${BASH_REMATCH[2]:-/}
  fi
  [[ $body_type == json ]] || body_type=''
  _CRAWL_EP_SEEN[$key]=$id
  # US (0x1f), NEVER a tab: `status`/`content_type` are routinely BOTH empty
  # for a spec-added endpoint, and `body_type` - the field after them - is
  # routinely non-empty (`json`). A tab is an IFS-*whitespace* character, so
  # `crawl_inv_write_endpoints`'s `IFS=$'\t' read` folds that run of empty
  # fields into ONE delimiter and shifts `body_type`'s value left into
  # `status`'s slot - the exact DAST-11 lesson this file's own AGENTS.md entry
  # documents, reproduced here rather than avoided a second time. `cut -f`
  # (this file's own `crawl_url_split`-adjacent test helpers) is unaffected -
  # only `read`'s whitespace-folding is - but 0x1f sidesteps the question
  # entirely for anything that walks this tuple later.
  _CRAWL_EP+=("$id"$'\x1f'"$target"$'\x1f'"$method"$'\x1f'"$url"$'\x1f'"$host"$'\x1f'"$path"$'\x1f'"$source"$'\x1f'"$depth"$'\x1f'"$status"$'\x1f'"$ctype"$'\x1f'"$body_type")
  _CRAWL_LAST_EP_ID=$id
  return 0
}

# `crawl_add_param ENDPOINT_ID TARGET METHOD URL NAME LOCATION SOURCE [EXAMPLE]`
#
# EXAMPLE is an observed value and is therefore a credential until proven
# otherwise.  TWO independent controls apply to it, because each covers the
# other's blind spot (docs/FOUNDATION.md tension 9):
#
#   1. The VALUE goes through `redact` (lib/findings.sh, the frozen
#      rules/redaction.rules pass), which recognises credential SHAPES - an
#      AWS key id, a JWT, a private-key block - wherever they appear.
#   2. The NAME is matched against `_CRAWL_SECRETISH_NAME`, and a parameter
#      whose name says it carries a credential has its example DROPPED
#      outright rather than redacted.
#
# Control 2 exists because control 1 provably cannot cover it: a HAR capture
# of a real login carries `password=hunter2`, and no redaction rule can or
# should recognise an arbitrary human-chosen password as a secret by its
# shape.  Control 1 exists because control 2 provably cannot cover IT: a
# session token in a parameter innocently named `t` is a credential the name
# gives no hint of.  Neither is sufficient; together they are the honest
# best available, and the residual gap - an unrecognised secret in an
# unsuggestive parameter - is stated here rather than assumed away.
_CRAWL_SECRETISH_NAME='^(pass|passwd|password|pwd|secret|token|api[-_]?key|apikey|auth|authorization|session|sessionid|sid|jwt|bearer|credential|creds|otp|mfa|totp|pin|private[-_]?key|client[-_]?secret|refresh[-_]?token|access[-_]?token|csrf|xsrf|signature|sig)$'

# The frozen parameter-location vocabulary (docs/INVENTORY-FORMAT.md §3).
# `inject_engine.sh`'s `inject_send` has no arm for anything outside this set;
# admitting one anyway would let a hostile spec produce a row that later
# reports as "tested" while nothing is ever sent (IMPORT-05, report §7b).
_CRAWL_PARAM_LOCATIONS='^(query|body|path|header|cookie|formData|graphql)$'

# The RFC 7230 header-field-name token - the exact character class
# `lib/http.sh`'s `http_request_header` enforces at SEND time (and `die`s the
# whole run, exit 5, on a mismatch). A `header`-location parameter name is
# validated against the identical class HERE, at import time, so a hostile
# spec's malformed field name is skipped with a counted reduction instead of
# reaching that `die` and aborting the entire scan (IMPORT-05, report §7a).
_CRAWL_HEADER_TOKEN_RE='^[A-Za-z0-9!#$%&'"'"'*+.^_`|~-]+$'

crawl_add_param() {
  local epid=$1 target=$2 method=$3 url=$4 name=$5 location=$6 source=$7 example=${8:-}
  local key id lname
  method=${method^^}
  [[ -n $name ]] || return 0
  if crawl_has_control_byte "$target" || crawl_has_control_byte "$method" ||
     crawl_has_control_byte "$url" || crawl_has_control_byte "$name" ||
     crawl_has_control_byte "$source" || crawl_has_control_byte "$example"; then
    _CRAWL_PARAM_CONTROL_BYTE=$(( _CRAWL_PARAM_CONTROL_BYTE + 1 ))
    return 0
  fi
  if [[ ! $location =~ $_CRAWL_PARAM_LOCATIONS ]]; then
    _CRAWL_PARAM_INVALID_LOCATION=$(( _CRAWL_PARAM_INVALID_LOCATION + 1 ))
    return 0
  fi
  if [[ $location == header && ! $name =~ $_CRAWL_HEADER_TOKEN_RE ]]; then
    _CRAWL_PARAM_INVALID_HEADER_NAME=$(( _CRAWL_PARAM_INVALID_HEADER_NAME + 1 ))
    return 0
  fi
  key="$epid|$location|$name"
  [[ -z ${_CRAWL_PARAM_SEEN[$key]:-} ]] || return 0
  if (( ${#_CRAWL_PARAM[@]} >= _CRAWL_MAX_PARAMS )); then
    _CRAWL_PARAM_TRUNCATED=$(( _CRAWL_PARAM_TRUNCATED + 1 ))
    return 1
  fi
  if [[ -n $example ]]; then
    lname=${name,,}
    # A `body`-location NAME on a `json` endpoint (docs/INVENTORY-FORMAT.md
    # §3a, IMPORT-02) is an RFC 6901 POINTER, not a bare field name - `/token`
    # and `/user/token` both name a field a human would call "token", but the
    # pointer's own leading `/` makes it fail `_CRAWL_SECRETISH_NAME`'s
    # anchored `^(...)$` match outright.  Testing the pointer's LAST segment
    # instead is what keeps a JSON-body credential covered by the same control
    # a flat form field already gets; every other location's name never starts
    # with `/`, so this narrows nothing for them.
    [[ $lname == /* ]] && lname=${lname##*/}
    if [[ $lname =~ $_CRAWL_SECRETISH_NAME ]]; then
      example=''
    else
      example=$(redact "$example")
      (( ${#example} <= _CRAWL_EXAMPLE_MAX )) || example=${example:0:$_CRAWL_EXAMPLE_MAX}
    fi
  fi
  id=$(crawl_id "$key")
  _CRAWL_PARAM_SEEN[$key]=$id
  # US (0x1f), matching `_CRAWL_EP` above (and for the identical reason): a
  # tab is an IFS-*whitespace* character, so any empty field ahead of another
  # non-empty one is unsafe with `IFS=$'\t' read`, whatever field order this
  # tuple happens to have today.
  _CRAWL_PARAM+=("$id"$'\x1f'"$epid"$'\x1f'"$target"$'\x1f'"$method"$'\x1f'"$url"$'\x1f'"$name"$'\x1f'"$location"$'\x1f'"$source"$'\x1f'"$example")
  return 0
}

# ---------------------------------------------------------------------------
# 6a. RFC 6901 JSON pointers, shared by every `json`-body producer
#     (docs/INVENTORY-FORMAT.md §3a; IMPORT-03's requestBody schema walk and
#     IMPORT-04's HAR `postData.text` flattening both name a `body`-location
#     parameter this way, so the escaping lives once here rather than twice)
# ---------------------------------------------------------------------------

# `_crawl_json_pointer_escape_seg RAW_SEGMENT` - the RFC 6901 ENCODE direction:
# `~` first, then `/`, so a key containing a literal `~1` is never produced by
# accident.  The DECODE direction (`inject_engine.sh`'s
# `_inject_json_pointer_split`) applies the two substitutions in the opposite
# order for the identical reason.
_crawl_json_pointer_escape_seg() {
  local s=$1
  s=${s//\~/\~0}
  s=${s//\//\~1}
  printf '%s' "$s"
}

# `_crawl_json_path_to_pointer PATH` - PATH is a `crawl_json_flatten`-style
# leaf path (segments still JSON-escaped, joined by US 0x1f); the result is
# the RFC 6901 pointer naming the same leaf (`/orderLines/0/productId`). An
# array index segment is already a bare decimal number, which is also a valid
# (and here, unescaped) pointer segment, so no special-casing is needed for it.
_crawl_json_path_to_pointer() {
  local path=$1 sep=$'\x1f' rest seg out=''
  rest=$path
  while :; do
    seg=${rest%%"$sep"*}
    out+="/$(_crawl_json_pointer_escape_seg "$(crawl_json_unescape "$seg")")"
    if [[ $rest == *"$sep"* ]]; then
      rest=${rest#*"$sep"}
    else
      break
    fi
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 7. Writing and re-reading the inventory (docs/INVENTORY-FORMAT.md)
# ---------------------------------------------------------------------------
# Written through `json_string` for every single field, with no exception:
# every value in here came off a target or out of an operator's file, and
# lib/core.sh's writer is the ONE place a string becomes JSON in this
# repository (tension 10).
crawl_inv_write_endpoints() {
  local out=$1 rec first=1
  local id target method url host path source depth status ctype body_type
  {
    printf '{\n'
    printf '  "schema": %s,\n' "$(json_string "$CRAWL_INV_ENDPOINTS_SCHEMA")"
    printf '  "run_id": %s,\n' "$(json_string "${SCOURSH_RUN_ID:-}")"
    printf '  "generated_by": %s,\n' "$(json_string 'modules/dast/crawl.sh')"
    printf '  "endpoints": ['
    for rec in "${_CRAWL_EP[@]+"${_CRAWL_EP[@]}"}"; do
      IFS=$'\x1f' read -r id target method url host path source depth status ctype body_type <<<"$rec"
      (( first )) && printf '\n' || printf ',\n'
      first=0
      printf '    {"id": %s, "target": %s, "method": %s, "url": %s, "host": %s, "path": %s, "source": %s, "depth": %s, "status": %s, "content_type": %s, "request_body_type": %s}' \
        "$(json_string "$id")" "$(json_string "$target")" "$(json_string "$method")" \
        "$(json_string "$url")" "$(json_string "$host")" "$(json_string "$path")" \
        "$(json_string "$source")" "$(json_number "$depth")" \
        "$(json_string "$status")" "$(json_string "$ctype")" "$(json_string "$body_type")"
    done
    (( first )) || printf '\n  '
    printf ']\n}\n'
  } >"$out"
}

crawl_inv_write_parameters() {
  local out=$1 rec first=1
  local id epid target method url name location source example
  {
    printf '{\n'
    printf '  "schema": %s,\n' "$(json_string "$CRAWL_INV_PARAMETERS_SCHEMA")"
    printf '  "run_id": %s,\n' "$(json_string "${SCOURSH_RUN_ID:-}")"
    printf '  "generated_by": %s,\n' "$(json_string 'modules/dast/crawl.sh')"
    printf '  "parameters": ['
    for rec in "${_CRAWL_PARAM[@]+"${_CRAWL_PARAM[@]}"}"; do
      IFS=$'\x1f' read -r id epid target method url name location source example <<<"$rec"
      (( first )) && printf '\n' || printf ',\n'
      first=0
      printf '    {"id": %s, "endpoint_id": %s, "target": %s, "method": %s, "url": %s, "name": %s, "location": %s, "source": %s, "example": %s}' \
        "$(json_string "$id")" "$(json_string "$epid")" "$(json_string "$target")" \
        "$(json_string "$method")" "$(json_string "$url")" "$(json_string "$name")" \
        "$(json_string "$location")" "$(json_string "$source")" "$(json_string "$example")"
    done
    (( first )) || printf '\n  '
    printf ']\n}\n'
  } >"$out"
}

CRAWL_INV_ENDPOINTS_SCHEMA='scoursh.inventory.endpoints/1'
CRAWL_INV_PARAMETERS_SCHEMA='scoursh.inventory.parameters/1'

# `crawl_inv_merge_endpoints FILE TARGET_DEFAULT` - reads an endpoints.json
# ANOTHER module wrote (tension 21: SAST route extraction, aws/live/apigw.sh)
# and folds it into this run's accumulator.  Sets `_CRAWL_MERGED_COUNT`.
#
# THE SCOPE GATE IS APPLIED AFTER THE MERGE, NOT HERE (tension 21's own last
# paragraph, and docs/DESIGN.md §7.5's "Still scope-gated"): this function's
# job is to read faithfully.  The caller decides what may be requested, which
# keeps "an apigw-sourced endpoint is a candidate, never an authorisation"
# true in one place rather than in every producer.
#
# It reads through `crawl_json_flatten`, so it accepts any conformant JSON
# layout rather than the exact bytes `crawl_inv_write_endpoints` happens to
# emit - a producer that pretty-prints differently is still readable, which
# is what "frozen schema" has to mean when three modules write the file.
crawl_inv_merge_endpoints() {
  local file=$1 target_default=${2:-} p type v idx last_idx='' key
  # SC2034: `cur` is passed BY NAME to `_crawl_merge_flush_endpoint`, which
  # takes it as a nameref, so every read of it is invisible from here.
  # shellcheck disable=SC2034
  local -A cur=()
  _CRAWL_MERGED_COUNT=0
  [[ -r $file && -s $file ]] || return 1
  local sep=$'\x1f'
  while IFS=$'\t' read -r p type v; do
    [[ $p == endpoints* ]] || continue
    # endpoints<US><idx><US><field>
    local rest=${p#endpoints}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _crawl_merge_flush_endpoint cur "$target_default"
      cur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    # shellcheck disable=SC2034
    cur[$key]=$v
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  if [[ -n $last_idx ]]; then
    _crawl_merge_flush_endpoint cur "$target_default"
  fi
  return 0
}

# Bash 4.2 has no namerefs (tension 24's frozen minimum), so the associative
# array is passed by NAME and read through `${!...}` indirection rather than
# `local -n`.
_crawl_merge_flush_endpoint() {
  local arrname=$1 target_default=$2
  local m u t s
  local mref="${arrname}[method]" uref="${arrname}[url]"
  local tref="${arrname}[target]" sref="${arrname}[source]"
  m=${!mref:-GET}
  u=${!uref:-}
  t=${!tref:-}
  s=${!sref:-}
  [[ -n $u ]] || return 0
  [[ -n $t ]] || t=$target_default
  [[ -n $s ]] || s=imported
  # `imported` is never overwritten with this run's own provenance: a reader
  # asking "did a crawl actually reach this, or did SAST assert it exists"
  # must be able to tell, which is exactly the audit trail tension 21 asks for
  # when it says imported inventory is recorded with its source.
  crawl_add_endpoint "$t" "$m" "$u" "$s" 0 '' '' || return 0
  _CRAWL_MERGED_COUNT=$(( _CRAWL_MERGED_COUNT + 1 ))
  return 0
}

# ---------------------------------------------------------------------------
# 8. Specification ingestion (docs/DESIGN.md §7.5, "preferred, most complete")
# ---------------------------------------------------------------------------
# Each of the four returns 0 when it read something, 1 when the file was
# unusable, and sets `_CRAWL_SPEC_COUNT` to the number of endpoints added and
# `_CRAWL_SPEC_ERROR` to a one-line reason when it returns 1.
#
# ALL FOUR SHARE ONE RULE: a specification is a claim about what exists, never
# an authorisation to request it.  Every endpoint they add is gated by the
# caller against config/scope.conf before a single request is sent, exactly as
# an imported inventory is.

# `crawl_spec_openapi FILE TARGET BASE_URL` - OpenAPI 3.x and Swagger 2.0.
#
# The two differ in where the server prefix lives (`servers[].url` versus
# `basePath`), and in nothing else this function reads, so both are handled by
# looking for both rather than by branching on the version string - a document
# declaring `swagger: "2.0"` while carrying a `servers` array is a real thing
# that generators emit, and version-branching would drop its paths.
crawl_spec_openapi() {
  local file=$1 target=$2 base=$3
  local sep=$'\x1f' p type v
  local prefix='' server=''
  _CRAWL_SPEC_COUNT=0
  _CRAWL_SPEC_ERROR=''
  # IMPORT-03: reset per call, exactly like `_CRAWL_SPEC_COUNT` above - these
  # describe THIS document's requestBody resolution, not a running total.
  _CRAWL_SPEC_REF_UNRESOLVED=0
  _CRAWL_SPEC_POLY_UNSUPPORTED=0

  local flat=$SCOURSH_SCRATCH/crawl-openapi.$BASHPID
  if ! crawl_spec_flatten "$file" >"$flat" 2>/dev/null; then
    _CRAWL_SPEC_ERROR=$(head -n 1 -- "$flat" 2>/dev/null || true)
    [[ -n $_CRAWL_SPEC_ERROR ]] || _CRAWL_SPEC_ERROR='the document could not be parsed'
    rm -f "$flat"
    return 1
  fi

  # Loaded ONCE, whole-document, so `_crawl_openapi_schema_walk` (IMPORT-03)
  # and its helpers can answer "does this schema node exist / have these
  # children" without re-reading the file per node.  `declare -g`: these
  # helpers are separate functions, and bash 4.2 has no namerefs to pass a
  # local array by reference (tension 24's frozen minimum).
  declare -ga _CRAWL_OA_PATH=() _CRAWL_OA_TYPE=() _CRAWL_OA_VAL=()
  declare -g _CRAWL_OA_N=0
  while IFS=$'\t' read -r p type v; do
    _CRAWL_OA_PATH[_CRAWL_OA_N]=$p
    _CRAWL_OA_TYPE[_CRAWL_OA_N]=$type
    _CRAWL_OA_VAL[_CRAWL_OA_N]=$v
    _CRAWL_OA_N=$(( _CRAWL_OA_N + 1 ))
  done <"$flat"

  # Pass 1: the server prefix.  `servers/0/url` (OpenAPI 3) or `basePath`
  # (Swagger 2).  Both are looked for rather than branching on the declared
  # version, because a document declaring `swagger: "2.0"` while carrying a
  # `servers` array is a thing generators really emit, and version-branching
  # would silently drop its paths.
  while IFS=$'\t' read -r p type v; do
    case $p in
      "servers${sep}0${sep}url") server=$(crawl_json_unescape "$v") ;;
      basePath) prefix=$(crawl_json_unescape "$v") ;;
    esac
  done <"$flat"
  if [[ -n $server ]]; then
    if [[ $server =~ ^[Hh][Tt][Tt][Pp][Ss]?:// ]]; then
      crawl_url_split "$server"
      # AN ABSOLUTE `servers[].url` CONTRIBUTES ONLY ITS PATH.  Its host is not
      # this run's to decide: `--target` and config/scope.conf are.  A
      # specification that names a production host must not be able to point a
      # scan at it - that is the "do not make it bypassable by raw URL"
      # sentence docs/DESIGN.md §7 opens with, applied to a file rather than a
      # flag, and it is why this function takes BASE_URL as an argument
      # instead of reading one out of the document.
      if [[ $_CRAWL_U_BASE =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$ ]]; then
        prefix=${BASH_REMATCH[1]:-}
      fi
    else
      prefix=$server
    fi
  fi
  prefix=${prefix%/}

  # Pass 2: the operations, and every parameter object keyed by its own path.
  #
  # A leaf under `paths` is one of two shapes, distinguished by whether its
  # SECOND segment is an HTTP method name:
  #
  #   paths<US>/pets<US>get<US>parameters<US>0<US>name   operation-level
  #   paths<US>/pets<US>parameters<US>0<US>name          path-level, applying
  #                                                      to every operation
  #
  # Both are collected here and resolved below, because a path-level
  # `parameters` array is not an edge case - it is where generators put the
  # `{id}` path parameter that every operation on the path shares, i.e. the
  # single most useful parameter an IDOR check could be handed.
  local -A op_seen=()
  local -A pname=() pin=()
  local rest apath tail meth pkey leaf
  while IFS=$'\t' read -r p type v; do
    [[ $p == "paths${sep}"* ]] || continue
    rest=${p#"paths${sep}"}
    tail=${rest#*"$sep"}
    [[ $tail != "$rest" ]] || continue
    apath=$(crawl_json_unescape "${rest%%"$sep"*}")
    meth=${tail%%"$sep"*}
    case ${meth,,} in
      get | put | post | delete | patch | head | options | trace)
        op_seen["$apath"$'\t'"${meth^^}"]=1
        ;;
    esac
    case $p in
      *"${sep}parameters${sep}"*)
        pkey=${p%"${sep}"*}
        leaf=${p##*"$sep"}
        case $leaf in
          name) pname[$pkey]=$(crawl_json_unescape "$v") ;;
          in) pin[$pkey]=$(crawl_json_unescape "$v") ;;
        esac
        ;;
    esac
  done <"$flat"

  # Pass 2b (IMPORT-03): Swagger 2.0's `in: body` is a PARAMETER object, not a
  # `requestBody` - `pin[$pkey]` already says which parameter objects are one,
  # from Pass 2 above. Map each operation to its own body parameter object's
  # path prefix, so Pass 3 can resolve `<pkey>/schema` the same way it resolves
  # an OpenAPI 3 `requestBody`'s schema. Swagger 2.0 allows at most one `body`
  # parameter per operation, so a plain map (not a list) is the right shape.
  local -A body_pkey_for_op=()
  local bk bkapath bkseg2 bkopkey
  for bk in "${!pin[@]}"; do
    [[ ${pin[$bk]} == body ]] || continue
    rest=${bk#"paths${sep}"}
    bkapath=$(crawl_json_unescape "${rest%%"$sep"*}")
    bkseg2=${rest#*"$sep"}
    bkseg2=${bkseg2%%"$sep"*}
    if [[ $bkseg2 == parameters ]]; then
      for bkopkey in "${!op_seen[@]}"; do
        [[ ${bkopkey%%$'\t'*} == "$bkapath" ]] || continue
        body_pkey_for_op[$bkopkey]=$bk
      done
    else
      bkopkey="$bkapath"$'\t'"${bkseg2^^}"
      [[ -n ${op_seen[$bkopkey]:-} ]] || continue
      body_pkey_for_op[$bkopkey]=$bk
    fi
  done

  # Pass 3: emit the endpoints, remembering each one's id so the parameters
  # below can join to it. IMPORT-03: an operation whose `requestBody` declares
  # an `application/json` media type, OR whose Swagger 2 `in: body` parameter
  # exists (Pass 2b), gets `request_body_type=json` at CREATION time - the
  # field lives on the endpoint (docs/INVENTORY-FORMAT.md §2), so it has to be
  # known before `crawl_add_endpoint` runs, not patched in afterwards.
  local -A epof=()
  local k url added=0 methl rb_schema bt
  for k in "${!op_seen[@]}"; do
    IFS=$'\t' read -r apath meth <<<"$k"
    url="$base$prefix$apath"
    methl=${meth,,}
    rb_schema="paths${sep}${apath}${sep}${methl}${sep}requestBody${sep}content${sep}application/json${sep}schema"
    bt=''
    if _crawl_openapi_node_exists "$rb_schema"; then
      bt=json
    elif [[ -n ${body_pkey_for_op[$k]:-} ]]; then
      bt=json
    fi
    crawl_add_endpoint "$target" "$meth" "$url" openapi 0 '' '' "$bt" || continue
    epof[$k]=$_CRAWL_LAST_EP_ID
    added=$(( added + 1 ))
    if [[ $bt == json ]]; then
      if [[ -n ${body_pkey_for_op[$k]:-} ]]; then
        _crawl_openapi_schema_walk "${body_pkey_for_op[$k]}${sep}schema" '' '' 1 \
          "${epof[$k]}" "$target" "$meth" "$url"
      else
        _crawl_openapi_schema_walk "$rb_schema" '' '' 1 "${epof[$k]}" "$target" "$meth" "$url"
      fi
    fi
  done

  # Pass 4: attach the parameters.  An operation-level array joins to one
  # endpoint; a path-level array joins to every operation on that path.
  # `body` is excluded here (IMPORT-03): a Swagger 2 `in: body` parameter's own
  # `name` (typically "body" or "payload") is a human label, not a field name,
  # and Pass 3 above already resolved its `schema` into real body parameters -
  # calling crawl_add_param with the label itself would add a bogus one beside
  # them.
  local seg2 loc name opkey
  for k in "${!pname[@]}"; do
    name=${pname[$k]}
    [[ -n $name ]] || continue
    loc=${pin[$k]:-query}
    case $loc in
      query | path | header | cookie | formData) ;;
      body) continue ;;
      *) loc=query ;;
    esac
    rest=${k#"paths${sep}"}
    apath=$(crawl_json_unescape "${rest%%"$sep"*}")
    seg2=${rest#*"$sep"}
    seg2=${seg2%%"$sep"*}
    if [[ $seg2 == parameters ]]; then
      for opkey in "${!epof[@]}"; do
        [[ ${opkey%%$'\t'*} == "$apath" ]] || continue
        crawl_add_param "${epof[$opkey]}" "$target" "${opkey##*$'\t'}" \
          "$base$prefix$apath" "$name" "$loc" openapi '' || true
      done
    else
      opkey="$apath"$'\t'"${seg2^^}"
      [[ -n ${epof[$opkey]:-} ]] || continue
      crawl_add_param "${epof[$opkey]}" "$target" "${seg2^^}" \
        "$base$prefix$apath" "$name" "$loc" openapi '' || true
    fi
  done

  rm -f "$flat"
  _CRAWL_SPEC_COUNT=$added
  (( added )) || { _CRAWL_SPEC_ERROR='the document parsed but declared no paths'; return 1; }
  return 0
}

# ---------------------------------------------------------------------------
# 8a. OpenAPI `requestBody`/`in: body` schema resolution (IMPORT-03)
# ---------------------------------------------------------------------------
# `_crawl_openapi_schema_walk` (below) reads `_CRAWL_OA_PATH`/`_CRAWL_OA_TYPE`/
# `_CRAWL_OA_VAL` - the whole document, loaded once per `crawl_spec_openapi`
# call, above - to answer three structural questions a JSON Schema node can
# ask without ever building a real tree: does an exact leaf exist here, does
# ANY leaf exist under here, and what are the immediate child keys under here.
# The technique is `modules/dast/active/inject_engine.sh`'s own
# `_inject_json_node` (built for the identical reason: reconstructing a JSON
# document from a flat leaf list with no recursive-descent parser), applied to
# READING a schema instead of building a body.

# `_crawl_openapi_leaf_value WANT` - sets `_CRAWL_OA_FOUND` (0/1) and, when
# found, `_CRAWL_OA_VALUE` to the leaf's value (unescaped for a string, the
# literal token otherwise) at the EXACT path WANT.
_crawl_openapi_leaf_value() {
  local want=$1 i
  _CRAWL_OA_FOUND=0
  _CRAWL_OA_VALUE=''
  for (( i = 0; i < _CRAWL_OA_N; i++ )); do
    if [[ ${_CRAWL_OA_PATH[$i]} == "$want" ]]; then
      _CRAWL_OA_FOUND=1
      if [[ ${_CRAWL_OA_TYPE[$i]} == s ]]; then
        _CRAWL_OA_VALUE=$(crawl_json_unescape "${_CRAWL_OA_VAL[$i]}")
      else
        _CRAWL_OA_VALUE=${_CRAWL_OA_VAL[$i]}
      fi
      return 0
    fi
  done
  return 0
}

# `_crawl_openapi_has_prefix PREFIX` - true iff some leaf's path is PREFIX
# itself or begins with PREFIX followed by a path separator, i.e. PREFIX names
# a node (object or array) with at least one descendant leaf.  An object or
# array that is genuinely EMPTY in the source document (`{}`, `[]`) produces no
# leaf at all - `crawl_json_flatten`'s own documented limitation - so it reads
# as absent here too; a schema with no content is not one this can describe
# anyway.
_crawl_openapi_has_prefix() {
  local prefix=$1 sep=$'\x1f' i
  for (( i = 0; i < _CRAWL_OA_N; i++ )); do
    case ${_CRAWL_OA_PATH[$i]} in
      "$prefix" | "$prefix$sep"*) return 0 ;;
    esac
  done
  return 1
}

# `_crawl_openapi_node_exists PATH` - PATH names a node worth resolving,
# whether it is itself a scalar leaf (rare for a schema, but not impossible)
# or an object/array with descendants.
_crawl_openapi_node_exists() {
  local want=$1
  _crawl_openapi_leaf_value "$want"
  (( _CRAWL_OA_FOUND )) && return 0
  _crawl_openapi_has_prefix "$want"
}

# `_crawl_openapi_child_keys PREFIX` - sets `_CRAWL_OA_CHILDREN` to the
# distinct set of immediate child keys of the object/array at PREFIX, in
# first-seen order (order is irrelevant to the caller, which only iterates).
_crawl_openapi_child_keys() {
  local prefix=$1 sep=$'\x1f' i path rel first
  local -A seen=()
  _CRAWL_OA_CHILDREN=()
  for (( i = 0; i < _CRAWL_OA_N; i++ )); do
    path=${_CRAWL_OA_PATH[$i]}
    case $path in
      "$prefix$sep"*) rel=${path#"$prefix$sep"} ;;
      *) continue ;;
    esac
    first=${rel%%"$sep"*}
    [[ -n ${seen[$first]+x} ]] && continue
    seen[$first]=1
    _CRAWL_OA_CHILDREN+=("$first")
  done
}

# The `$ref` cycle/depth guard (docs/FOUNDATION.md tension-style bound): a
# chain longer than this is dropped with a counted `coverage_reduction`,
# exactly as a genuine cycle is - both are "this document asks for more
# resolution than a bounded engine will do", and only one of the two needs a
# repeated component name to detect.
: "${_CRAWL_OPENAPI_REF_MAX_DEPTH:=8}"

# `_crawl_openapi_schema_walk SCHEMA_PATH POINTER VISITED DEPTH EPID TARGET
# METHOD URL` - resolves ONE schema node (SCHEMA_PATH, a path into the
# whole-document leaf arrays above) and every node it structurally implies,
# emitting one `body` parameter per leaf `properties` field reached, named by
# its RFC 6901 pointer (POINTER, built up one segment per recursive call).
# VISTED is the SEP-joined chain of `components.schemas.<Name>` already
# followed on THIS pointer's own branch - passed by value, since bash 4.2 has
# no namerefs and each branch's cycle history is independent of its siblings'.
#
# Resolution order, each case handled once and returning immediately: (1) a
# depth bound, checked first so a cycle that never gets caught by name
# (shouldn't happen, but a defence-in-depth backstop) still terminates; (2)
# `$ref`, resolved against `#/components/schemas/<Name>` only - any other
# target (an external file, a fragment into a different root) is out of scope
# and costs the same reduction as an unresolved one; (3) a 3.1 `oneOf`/`anyOf`,
# which picks the FIRST subschema and counts a reduction, per the ticket's own
# "state the construct unsupported rather than silently drop it"; (4) an array
# (`type: array` or a bare `items`), which recurses into `items` with one `/0`
# segment appended to the pointer, exactly as docs/INVENTORY-FORMAT.md §3a's
# own `orderLines/0/productId` example describes; (5) an object (`properties`
# present), which recurses into every property with its own escaped segment
# appended; (6) otherwise, this node IS a leaf - a `body` parameter is emitted
# at POINTER, with `example` when the schema declares one. `allOf` is not
# case (5) - a schema with only `allOf` and no direct `properties` falls
# through to (6) and is read as one opaque leaf, a stated gap rather than a
# silent drop (see this file's own header).
_crawl_openapi_schema_walk() {
  local spath=$1 ptr=$2 visited=$3 depth=$4 epid=$5 target=$6 method=$7 url=$8
  local sep=$'\x1f' refkey='$ref'

  if (( depth > _CRAWL_OPENAPI_REF_MAX_DEPTH )); then
    _CRAWL_SPEC_REF_UNRESOLVED=$(( _CRAWL_SPEC_REF_UNRESOLVED + 1 ))
    return 0
  fi

  _crawl_openapi_leaf_value "${spath}${sep}${refkey}"
  if (( _CRAWL_OA_FOUND )); then
    local refv=$_CRAWL_OA_VALUE cname
    if [[ $refv =~ ^#/components/schemas/([^/]+)$ ]]; then
      cname=${BASH_REMATCH[1]}
      if [[ "$sep$visited$sep" == *"$sep$cname$sep"* ]]; then
        _CRAWL_SPEC_REF_UNRESOLVED=$(( _CRAWL_SPEC_REF_UNRESOLVED + 1 ))
        return 0
      fi
      _crawl_openapi_schema_walk "components${sep}schemas${sep}${cname}" "$ptr" \
        "$visited$sep$cname" $(( depth + 1 )) "$epid" "$target" "$method" "$url"
      return 0
    fi
    # An external ($ref to another file) or root-relative ref this resolver
    # does not follow - the same "costs that field, recorded" treatment.
    _CRAWL_SPEC_REF_UNRESOLVED=$(( _CRAWL_SPEC_REF_UNRESOLVED + 1 ))
    return 0
  fi

  local poly
  for poly in oneOf anyOf; do
    if _crawl_openapi_has_prefix "${spath}${sep}${poly}${sep}0"; then
      _CRAWL_SPEC_POLY_UNSUPPORTED=$(( _CRAWL_SPEC_POLY_UNSUPPORTED + 1 ))
      _crawl_openapi_schema_walk "${spath}${sep}${poly}${sep}0" "$ptr" "$visited" \
        $(( depth + 1 )) "$epid" "$target" "$method" "$url"
      return 0
    fi
  done

  _crawl_openapi_leaf_value "${spath}${sep}type"
  local styp=$_CRAWL_OA_VALUE
  if [[ $styp == array ]] || _crawl_openapi_has_prefix "${spath}${sep}items"; then
    _crawl_openapi_schema_walk "${spath}${sep}items" "${ptr}/0" "$visited" \
      $(( depth + 1 )) "$epid" "$target" "$method" "$url"
    return 0
  fi

  if _crawl_openapi_has_prefix "${spath}${sep}properties"; then
    _crawl_openapi_child_keys "${spath}${sep}properties"
    local k kdec kesc
    for k in "${_CRAWL_OA_CHILDREN[@]+"${_CRAWL_OA_CHILDREN[@]}"}"; do
      kdec=$(crawl_json_unescape "$k")
      kesc=$(_crawl_json_pointer_escape_seg "$kdec")
      _crawl_openapi_schema_walk "${spath}${sep}properties${sep}${k}" "${ptr}/${kesc}" \
        "$visited" $(( depth + 1 )) "$epid" "$target" "$method" "$url"
    done
    return 0
  fi

  # Terminal: a scalar (or otherwise unresolved) schema node.  An empty
  # POINTER means the walk never descended into any property at all (the
  # whole requestBody schema is itself opaque) - nothing nameable to emit.
  [[ -n $ptr ]] || return 0
  _crawl_openapi_leaf_value "${spath}${sep}example"
  local example=''
  (( _CRAWL_OA_FOUND )) && example=$_CRAWL_OA_VALUE
  crawl_add_param "$epid" "$target" "$method" "$url" "$ptr" body openapi "$example" || true
}

# `crawl_spec_postman FILE TARGET BASE_URL` - a Postman collection (v2.x).
#
# `item` nests arbitrarily deep (folders hold folders), so this reads every
# `.../request/method` and `.../request/url...` leaf wherever it appears
# rather than walking the folder tree - the shape of the tree is not
# information this needs.  `{{variable}}` placeholders are NOT resolved (their
# values live in an environment file this has no reference to) and an endpoint
# whose path still contains one is dropped with a recorded reason rather than
# requested literally.
crawl_spec_postman() {
  local file=$1 target=$2 base=$3
  local sep=$'\x1f' p type v
  _CRAWL_SPEC_COUNT=0
  _CRAWL_SPEC_ERROR=''
  local flat=$SCOURSH_SCRATCH/crawl-postman.$BASHPID
  if ! crawl_spec_flatten "$file" >"$flat" 2>/dev/null; then
    _CRAWL_SPEC_ERROR=$(head -n 1 -- "$flat" 2>/dev/null || true)
    [[ -n $_CRAWL_SPEC_ERROR ]] || _CRAWL_SPEC_ERROR='the collection could not be parsed'
    rm -f "$flat"
    return 1
  fi

  local -A meth=() raw=()
  while IFS=$'\t' read -r p type v; do
    case $p in
      *"${sep}request${sep}method")
        meth[${p%"${sep}request${sep}method"}]=$(crawl_json_unescape "$v") ;;
      *"${sep}request${sep}url${sep}raw")
        raw[${p%"${sep}request${sep}url${sep}raw"}]=$(crawl_json_unescape "$v") ;;
      *"${sep}request${sep}url")
        # The short form: `"url": "https://host/path"`.
        [[ $type == s ]] || continue
        raw[${p%"${sep}request${sep}url"}]=$(crawl_json_unescape "$v") ;;
    esac
  done <"$flat"

  local key url m ep added=0 dropped=0 epurl epquery qn qv
  for key in "${!raw[@]}"; do
    url=${raw[$key]}
    m=${meth[$key]:-GET}
    [[ -n $url ]] || continue
    if [[ $url == *'{{'* ]]; then
      dropped=$(( dropped + 1 ))
      continue
    fi
    if [[ ! $url =~ ^[Hh][Tt][Tt][Pp][Ss]?:// ]]; then
      # A collection-relative URL: attach it to this run's own base, never to
      # a host the collection names.
      url=${url#/}
      url="$base/$url"
    else
      # An absolute URL keeps only its path+query, for the same reason
      # crawl_spec_openapi drops a `servers[].url` host.
      crawl_url_split "$url"
      if [[ $_CRAWL_U_BASE =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$ ]]; then
        url="$base${BASH_REMATCH[1]:-/}"
      else
        url="$base/"
      fi
      [[ -n $_CRAWL_U_QUERY ]] && url="$url?$_CRAWL_U_QUERY"
    fi
    crawl_url_split "$url"
    # COPIED OUT BEFORE `crawl_add_endpoint`, WHICH CALLS `crawl_url_split`
    # ITSELF and therefore overwrites both of these.  Reading `_CRAWL_U_QUERY`
    # after the add silently found it empty for every entry, so a collection's
    # query parameters - the entire reason a Postman collection is worth
    # ingesting over a bare URL list - were dropped without a trace.  The
    # suite pins it with a collection whose only parameters are in the query.
    epurl=$_CRAWL_U_BASE
    epquery=$_CRAWL_U_QUERY
    crawl_add_endpoint "$target" "$m" "$epurl" postman 0 '' '' || continue
    ep=$_CRAWL_LAST_EP_ID
    added=$(( added + 1 ))
    if [[ -n $epquery ]]; then
      while IFS=$'\t' read -r qn qv; do
        crawl_add_param "$ep" "$target" "$m" "$epurl" "$qn" query postman "$qv" || true
      done < <(crawl_query_names "$epquery")
    fi
  done

  rm -f "$flat"
  _CRAWL_SPEC_COUNT=$added
  _CRAWL_SPEC_DROPPED=$dropped
  (( added )) || { _CRAWL_SPEC_ERROR='the collection parsed but held no usable request URL'; return 1; }
  return 0
}

# The bounded allowlist of HAR request-header names worth inventorying
# (IMPORT-04) - "interesting" meaning auth/session-carrying, the shape the
# report's own reproduction (`Authorization: Bearer ...`) names.  Everything
# else a browser sends on every request - `Accept*`, `User-Agent`, `Host`,
# `Referer`, `Origin`, `Cookie` (a distinct HAR array and a distinct §3
# location, not this one), caching and `Sec-*`/hop-by-hop headers - carries no
# injection-worthy signal and would otherwise bloat every endpoint's parameter
# set with the same handful of boilerplate names.  Matched case-insensitively
# against the whole header name.
_CRAWL_HAR_HEADER_ALLOW='^(authorization|x-api-key|apikey|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token|x-session-id|x-client-id|x-client-secret)$'

# `crawl_spec_har FILE TARGET BASE_URL` - a HAR capture.
#
# A HAR is the single highest-signal input this module accepts: it is a record
# of requests a real client actually made, so for a client-rendered app it
# contains exactly the XHR/fetch endpoints a static crawl provably cannot see
# (docs/DESIGN.md §7.5's mitigation 1).  Query and posted form parameters are
# taken from HAR's own parsed `queryString`/`params` arrays rather than
# re-parsed out of the URL, because the capturing tool already did that work
# against the real request.  IMPORT-04 adds three things a Chrome-shaped
# capture of a JSON API needs: `postData.text` (a JSON body, as opposed to
# `postData.params`'s classic HTML-form post), `request.headers[]` (the
# allowlist above), and path-template dedup, so `/api/BasketItems/1` and
# `.../2` land as one endpoint rather than two.
crawl_spec_har() {
  local file=$1 target=$2 base=$3
  local sep=$'\x1f' p type v
  _CRAWL_SPEC_COUNT=0
  _CRAWL_SPEC_ERROR=''
  # IMPORT-04: reset per call, like `_CRAWL_SPEC_COUNT` above.
  _CRAWL_HAR_DROPPED=0
  local flat=$SCOURSH_SCRATCH/crawl-har.$BASHPID
  if ! crawl_spec_flatten "$file" >"$flat" 2>/dev/null; then
    _CRAWL_SPEC_ERROR=$(head -n 1 -- "$flat" 2>/dev/null || true)
    [[ -n $_CRAWL_SPEC_ERROR ]] || _CRAWL_SPEC_ERROR='the HAR could not be parsed'
    rm -f "$flat"
    return 1
  fi

  local -A hmeth=() hurl=()
  local -A qn=() qv=() bn=() bv=()
  local -A pmime=() ptext=() hn=() hv=()
  while IFS=$'\t' read -r p type v; do
    case $p in
      "log${sep}entries${sep}"*"${sep}request${sep}method")
        hmeth[${p%"${sep}request${sep}method"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}url")
        hurl[${p%"${sep}request${sep}url"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}queryString${sep}"*"${sep}name")
        qn[${p%"${sep}name"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}queryString${sep}"*"${sep}value")
        qv[${p%"${sep}value"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}postData${sep}params${sep}"*"${sep}name")
        bn[${p%"${sep}name"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}postData${sep}params${sep}"*"${sep}value")
        bv[${p%"${sep}value"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}postData${sep}mimeType")
        pmime[${p%"${sep}request${sep}postData${sep}mimeType"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}postData${sep}text")
        # Left still-escaped (matching every other value collected here) - it
        # is unescaped ONCE, below, only for an entry whose mimeType is JSON,
        # and only after its own endpoint has survived the scope re-base.
        ptext[${p%"${sep}request${sep}postData${sep}text"}]=$v ;;
      "log${sep}entries${sep}"*"${sep}request${sep}headers${sep}"*"${sep}name")
        hn[${p%"${sep}name"}]=$(crawl_json_unescape "$v") ;;
      "log${sep}entries${sep}"*"${sep}request${sep}headers${sep}"*"${sep}value")
        hv[${p%"${sep}value"}]=$(crawl_json_unescape "$v") ;;
    esac
  done <"$flat"

  local key url m ep added=0 path_part bt
  local -A epof=() urlof=()
  for key in "${!hurl[@]}"; do
    url=${hurl[$key]}
    m=${hmeth[$key]:-GET}
    if [[ ! $url =~ ^[Hh][Tt][Tt][Pp][Ss]?:// ]]; then
      # A non-http(s) scheme (`chrome-extension://`, `data:`, `ws://`, ...) -
      # this run has nowhere authorised to re-base it onto, and never did.
      _CRAWL_HAR_DROPPED=$(( _CRAWL_HAR_DROPPED + 1 ))
      continue
    fi
    crawl_url_split "$url"
    # HAR entries are recorded against whatever host the client talked to,
    # which is routinely a CDN or a third party.  Only the PATH is reused,
    # against this run's own authorised base.
    if [[ $_CRAWL_U_BASE =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$ ]]; then
      path_part=${BASH_REMATCH[1]:-/}
      # IMPORT-04: a numbered listing (`/api/BasketItems/1`, `.../2`) is one
      # ENDPOINT with one path template, not two - the same tension-5 rule
      # `path_template_of` (lib/findings.sh) applies to a finding's location,
      # duplicated locally rather than sourced: this file has no existing edge
      # to lib/findings.sh, and CLAUDE.md's own shellcheck -x measurements
      # ("the shared response reader") are why a new one is not opened for one
      # small, pure function - `modules/dast/active/hosthdr_engine.sh`
      # duplicating `openredirect.sh`'s URL-authority parser is the same
      # precedent. Templating happens on the PATH, before it is glued back
      # onto `$base`, so the dedup key `crawl_add_endpoint` builds
      # (method + url-without-query) collapses both numbered requests onto
      # the SAME endpoint.
      path_part=$(_crawl_har_templatize_path "$path_part")
      url="$base$path_part"
    else
      # `_CRAWL_U_BASE` failed to re-parse as an authority - unreachable via
      # the guard just above for a well-formed http(s) URL in practice, but a
      # defensive drop rather than a request built from whatever survived.
      _CRAWL_HAR_DROPPED=$(( _CRAWL_HAR_DROPPED + 1 ))
      continue
    fi
    bt=''
    [[ ${pmime[$key]:-} == *[Jj][Ss][Oo][Nn]* ]] && bt=json
    crawl_add_endpoint "$target" "$m" "$url" har 0 '' '' "$bt" || continue
    ep=$_CRAWL_LAST_EP_ID
    epof[$key]=$ep
    urlof[$key]=$url
    added=$(( added + 1 ))
  done

  local pk entrykey nm lname
  for pk in "${!qn[@]}"; do
    entrykey=${pk%"${sep}request${sep}queryString${sep}"*}
    [[ -n ${epof[$entrykey]:-} ]] || continue
    nm=${qn[$pk]}
    crawl_add_param "${epof[$entrykey]}" "$target" "${hmeth[$entrykey]:-GET}" \
      "${urlof[$entrykey]}" "$nm" query har "${qv[$pk]:-}" || true
  done
  for pk in "${!bn[@]}"; do
    entrykey=${pk%"${sep}request${sep}postData${sep}params${sep}"*}
    [[ -n ${epof[$entrykey]:-} ]] || continue
    nm=${bn[$pk]}
    crawl_add_param "${epof[$entrykey]}" "$target" "${hmeth[$entrykey]:-POST}" \
      "${urlof[$entrykey]}" "$nm" body har "${bv[$pk]:-}" || true
  done

  # IMPORT-04: `postData.text`, for an entry whose `mimeType` says JSON. The
  # text is a JSON STRING inside the HAR's own JSON, so it is unescaped once
  # to recover the raw body, then re-flattened on its OWN terms - a second,
  # independent `crawl_json_flatten` call over the decoded bytes, not a
  # continuation of the outer parse.
  local decoded jp jt jv ptr val
  for entrykey in "${!ptext[@]}"; do
    [[ -n ${epof[$entrykey]:-} ]] || continue
    [[ ${pmime[$entrykey]:-} == *[Jj][Ss][Oo][Nn]* ]] || continue
    decoded=$(crawl_json_unescape "${ptext[$entrykey]}")
    while IFS=$'\t' read -r jp jt jv; do
      [[ -n $jp ]] || continue
      ptr=$(_crawl_json_path_to_pointer "$jp")
      if [[ $jt == s ]]; then val=$(crawl_json_unescape "$jv"); else val=$jv; fi
      crawl_add_param "${epof[$entrykey]}" "$target" "${hmeth[$entrykey]:-POST}" \
        "${urlof[$entrykey]}" "$ptr" body har "$val" || true
    done < <(printf '%s' "$decoded" | crawl_json_flatten 2>/dev/null)
  done

  # IMPORT-04: `request.headers[]`, filtered through the bounded allowlist
  # above.  `crawl_add_param` applies the same RFC 7230 token validation
  # (IMPORT-05) and the same two-control redaction (§8) a query or form
  # parameter already gets - `Authorization`'s name already matches
  # `_CRAWL_SECRETISH_NAME`, so its example is dropped outright, never merely
  # redacted.
  for pk in "${!hn[@]}"; do
    entrykey=${pk%"${sep}request${sep}headers${sep}"*}
    [[ -n ${epof[$entrykey]:-} ]] || continue
    nm=${hn[$pk]}
    lname=${nm,,}
    [[ $lname =~ $_CRAWL_HAR_HEADER_ALLOW ]] || continue
    crawl_add_param "${epof[$entrykey]}" "$target" "${hmeth[$entrykey]:-GET}" \
      "${urlof[$entrykey]}" "$nm" header har "${hv[$pk]:-}" || true
  done

  rm -f "$flat"
  _CRAWL_SPEC_COUNT=$added
  (( added )) || { _CRAWL_SPEC_ERROR='the HAR parsed but held no http(s) request entry'; return 1; }
  return 0
}

# `_crawl_har_templatize_path PATH` - the local port of `path_template_of`
# (lib/findings.sh) this file's own header explains: a segment that is
# entirely digits, a UUID, a ULID, or 16+ hex characters becomes `{id}`.
_crawl_har_templatize_path() {
  local p=$1 out='' seg rest first=1
  [[ ${p:0:1} == '/' ]] && p=${p#/}
  rest=$p
  while [[ -n $rest || $first == 1 ]]; do
    seg=${rest%%/*}
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=''; fi
    first=0
    if [[ $seg =~ ^[0-9]+$ ]] \
      || [[ $seg =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
      || [[ $seg =~ ^[0-7][0-9A-HJKMNP-TV-Z]{25}$ ]] \
      || [[ $seg =~ ^[0-9a-fA-F]{16,}$ ]]; then
      seg='{id}'
    fi
    out="$out/$seg"
    [[ -n $rest ]] || break
  done
  printf '%s' "$out"
}

# `crawl_spec_graphql FILE TARGET URL` - a GraphQL schema.
#
# GraphQL has ONE endpoint and many operations, which is the opposite shape to
# the other three, so it is recorded that way: one POST endpoint, and one
# parameter per root field of `Query`/`Mutation`/`Subscription` at location
# `graphql`.  A §7.3 probe iterating parameters therefore sees the operations,
# which is the thing that varies, rather than a single opaque `query` field.
#
# Both encodings are accepted: SDL (`type Query { ... }`) is read by the awk
# scanner below, and an introspection RESULT in JSON is read through the
# flattener.  Neither resolves interfaces or unions.
crawl_spec_graphql() {
  local file=$1 target=$2 url=$3
  local ep added=0 f
  _CRAWL_SPEC_COUNT=0
  _CRAWL_SPEC_ERROR=''
  [[ -r $file ]] || { _CRAWL_SPEC_ERROR='the schema file is not readable'; return 1; }

  crawl_add_endpoint "$target" POST "$url" graphql 0 '' '' || {
    _CRAWL_SPEC_ERROR='the endpoint inventory is full'
    return 1
  }
  ep=$_CRAWL_LAST_EP_ID

  local fields=$SCOURSH_SCRATCH/crawl-gql.$BASHPID
  : >"$fields"
  local head
  head=$(head -c 4096 -- "$file" 2>/dev/null || true)
  head=${head#"${head%%[![:space:]]*}"}
  if [[ ${head:0:1} == '{' ]]; then
    _crawl_graphql_from_introspection "$file" >"$fields"
  else
    _crawl_graphql_from_sdl "$file" >"$fields"
  fi

  while IFS= read -r f; do
    [[ -n $f ]] || continue
    crawl_add_param "$ep" "$target" POST "$url" "$f" graphql graphql '' || true
    added=$(( added + 1 ))
  done <"$fields"
  rm -f "$fields"

  _CRAWL_SPEC_COUNT=$added
  if (( added == 0 )); then
    _CRAWL_SPEC_ERROR='the schema parsed but declared no Query/Mutation/Subscription field'
    return 1
  fi
  return 0
}

# The SDL encoding (`type Query { ... }`).  Only the three ROOT operation types
# are read, because every other type in a schema is a shape rather than a
# callable operation, and enumerating shapes would fill the parameter
# inventory with names no request can carry.
_crawl_graphql_from_sdl() {
  head -c "$_CRAWL_MAX_SPEC_BYTES" -- "$1" | awk '
    /^[ \t]*(extend[ \t]+)?type[ \t]+(Query|Mutation|Subscription)([ \t]|[{]|$)/ {
      inroot = 1
      next
    }
    inroot && /^[ \t]*}/ { inroot = 0; next }
    inroot {
      line = $0
      sub(/#.*/, "", line)
      # A field is `name`, `name(args)` or `name: Type` at the start of a line;
      # a leading `"""docstring"""` line is not.
      if (line ~ /^[ \t]*"/) next
      if (match(line, /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[(:]/)) {
        f = substr(line, RSTART, RLENGTH)
        gsub(/[ \t(:]/, "", f)
        if (f != "") print f
      }
    }
  ' 2>/dev/null || true
}

# An introspection RESULT in JSON.  The root type names come from
# `__schema.queryType.name` and its two siblings; a field is reported only when
# the type it hangs off is one of those - so a schema whose Query type is named
# something other than `Query` still resolves, and a plain object type named
# `Query` in a schema that does not use it as a root does not.
_crawl_graphql_from_introspection() {
  local file=$1 sep=$'\x1f' p type v
  local flat=$SCOURSH_SCRATCH/crawl-gql-flat.$BASHPID
  head -c "$_CRAWL_MAX_SPEC_BYTES" -- "$file" | crawl_json_flatten >"$flat" 2>/dev/null || true

  local -A roots=()
  local -A tname=()
  local -A tfield=()
  local rest ti fpart fidx
  while IFS=$'\t' read -r p type v; do
    case $p in
      *"queryType${sep}name" | *"mutationType${sep}name" | *"subscriptionType${sep}name")
        roots[$(crawl_json_unescape "$v")]=1
        continue
        ;;
    esac
    case $p in
      *"types${sep}"*)
        rest=${p#*"types${sep}"}
        ti=${rest%%"$sep"*}
        [[ $ti =~ ^[0-9]+$ ]] || continue
        if [[ ${rest#*"$sep"} == name ]]; then
          tname[$ti]=$(crawl_json_unescape "$v")
          continue
        fi
        case $rest in
          *"fields${sep}"*"${sep}name")
            fpart=${rest#*"fields${sep}"}
            fidx=${fpart%%"$sep"*}
            [[ $fidx =~ ^[0-9]+$ ]] || continue
            [[ ${fpart#*"$sep"} == name ]] || continue
            tfield["$ti/$fidx"]=$(crawl_json_unescape "$v")
            ;;
        esac
        ;;
    esac
  done <"$flat"
  rm -f "$flat"

  local k
  for k in "${!tfield[@]}"; do
    ti=${k%%/*}
    [[ -n ${roots[${tname[$ti]:-}]:-} ]] || continue
    printf '%s\n' "${tfield[$k]}"
  done
}
