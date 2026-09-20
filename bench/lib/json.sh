#!/usr/bin/env bash
# bench/lib/json.sh - a depth- and string-aware JSON flattener for the
# benchmark harness.
#
# WHY THIS EXISTS RATHER THAN A REUSE.  The scanner already ships three
# purpose-built JSON readers - `crawl_json_flatten` (modules/dast/), the
# adapters' `_semgrep_split_results`/`_trivy_split_objects_from_marker`, and
# `_sca_json_walk` - and every one of them is reachable only by sourcing a
# scanner file.  bench/ is a SEPARATE HARNESS and must not become a consumer
# of the scanner runtime (see bench/README.md, "what bench/ is not"): a
# `source lib/...` edge from here would put benchmark code on the scan path's
# source graph, which tests/lint-source-graph.sh measures and which
# docs/FOUNDATION.md tension 27's "no wiring" check exists to keep clean.  So
# this is a fresh, standalone implementation of the same idea.
#
# CONTRACT.  `bench_json_flatten` reads one JSON document on stdin and writes
# one line per LEAF to stdout:
#
#     <path><US><type><US><value>
#
# where <US> is 0x1f, `path` is `/`-joined with array indices rendered as
# their ordinal (`results/0/extra/lines`), and `type` is one of:
#
#     s  string      value is the UNESCAPED string body
#     n  number      value is the literal number text
#     b  boolean     value is `true` or `false`
#     z  null        value is empty
#     o  object      an EMPTY object - value is empty
#     a  array       an EMPTY array  - value is empty
#
# The `o`/`a` rows exist so an empty container is still a leaf with a path:
# without them `{"findings":[]}` flattens to NOTHING, and "the tool reported
# an empty result set" becomes byte-indistinguishable from "the tool wrote no
# output at all", which is the honesty distinction this harness exists to
# preserve.
#
# THE TYPE COLUMN IS LOAD-BEARING AND IS NOT DECORATION.  A JSON string whose
# contents are the four bytes `null` and a JSON `null` flatten to the same
# path, and telling them apart is the difference between "this tool reported
# no CWE" and "this tool reported the CWE literally called null".  The scanner
# learned this the expensive way in `modules/dast/graphql_engine.sh`, whose
# own header records that `"mutationType": {"name": null}` and a real name
# land on the identical path - so the guard has to be the TYPE, not the path.
#
# THE SEPARATOR IS 0x1f AND NEVER A TAB, for the reason
# `modules/dast/passive/markup_engine.sh` records: a tab is an IFS-whitespace
# character, so `read` folds a RUN of them into one delimiter and drops
# leading and trailing ones (POSIX XCU 2.6.5).  A JSON value is routinely
# empty, so a tab-separated stream silently shifts every later column left on
# exactly the records that carry one.  Any 0x1f byte occurring INSIDE a value
# is stripped by the emitter, so target-derived text cannot forge a column.
#
# shellcheck shell=bash

[[ -n ${BENCH_JSON_SOURCED:-} ]] && return 0
BENCH_JSON_SOURCED=1

# ---------------------------------------------------------------------------
# bench_json_flatten - stdin: one JSON document.  stdout: leaf lines.
# ---------------------------------------------------------------------------
# Implemented in awk rather than bash because the scan is byte-at-a-time over
# documents that reach tens of megabytes (Semgrep's own output on a real
# corpus), and a bash character loop over that is minutes rather than seconds.
#
# Written to the PORTABLE awk subset both userlands ship, which rules out two
# things a first draft reached for:
#
#   * `strtonum` is a gawk extension and is absent from BSD awk, and BSD awk
#     evaluates a source hex constant such as `0x41` as `0` (AGENTS.md,
#     "Things measured on this codebase") - so \uXXXX decoding uses an
#     explicit digit table, never a hex literal and never strtonum.
#   * `RS` as a regular expression is a gawk extension; this reads whole
#     input with a plain byte loop instead.
bench_json_flatten() {
  awk -v US=$'\x1f' '
    # -- character classification ------------------------------------------
    function is_ws(c) { return (c == " " || c == "\t" || c == "\n" || c == "\r") }

    # hexval - one hex digit to its value.  Table-driven, because a bare
    # 0xNN source constant is 0 under BSD awk.
    function hexval(c,   i, lo) {
      lo = tolower(c)
      i = index("0123456789abcdef", lo)
      return (i > 0) ? i - 1 : -1
    }

    # utf8 - a Unicode scalar to its UTF-8 bytes.  Surrogate pairs are
    # recombined by the caller before reaching here, so cp is a real scalar.
    function utf8(cp) {
      if (cp < 128) return sprintf("%c", cp)
      if (cp < 2048)
        return sprintf("%c%c", 192 + int(cp / 64), 128 + (cp % 64))
      if (cp < 65536)
        return sprintf("%c%c%c", 224 + int(cp / 4096), \
                                 128 + int((cp % 4096) / 64), 128 + (cp % 64))
      return sprintf("%c%c%c%c", 240 + int(cp / 262144), \
                                 128 + int((cp % 262144) / 4096), \
                                 128 + int((cp % 4096) / 64), 128 + (cp % 64))
    }

    # scan_string - parse a JSON string starting at S[p] == the opening
    # quote.  Sets STRVAL to the unescaped body and returns the index just
    # past the closing quote.
    function scan_string(p,   c, out, e, cp, lo, k, d, v) {
      out = ""
      p++                                     # skip the opening quote
      while (p <= LEN) {
        c = substr(S, p, 1)
        if (c == "\"") { STRVAL = out; return p + 1 }
        if (c != "\\") { out = out c; p++; continue }
        e = substr(S, p + 1, 1)
        p += 2
        if      (e == "n") out = out "\n"
        else if (e == "t") out = out "\t"
        else if (e == "r") out = out "\r"
        else if (e == "b") out = out sprintf("%c", 8)
        else if (e == "f") out = out sprintf("%c", 12)
        else if (e == "u") {
          cp = 0
          for (k = 0; k < 4; k++) {
            d = substr(S, p + k, 1); v = hexval(d)
            if (v < 0) { cp = -1; break }
            cp = cp * 16 + v
          }
          p += 4
          if (cp < 0) { out = out "\\u"; continue }
          # A high surrogate must be recombined with the low one that
          # follows it, or every non-BMP character silently becomes two
          # replacement-shaped bytes.
          if (cp >= 55296 && cp <= 56319 && substr(S, p, 2) == "\\u") {
            lo = 0
            for (k = 0; k < 4; k++) {
              d = substr(S, p + 2 + k, 1); v = hexval(d)
              if (v < 0) { lo = -1; break }
              lo = lo * 16 + v
            }
            if (lo >= 56320 && lo <= 57343) {
              cp = 65536 + (cp - 55296) * 1024 + (lo - 56320)
              p += 6
            }
          }
          out = out utf8(cp)
        }
        else out = out e                      # \" \\ \/ and anything else
      }
      STRVAL = out
      return p
    }

    # emit - one leaf line, with any 0x1f inside the value stripped so a
    # value can never forge a column.
    function emit(path, type, value) {
      gsub(US, "", value)
      gsub(/\n/, " ", value)
      printf "%s%s%s%s%s\n", path, US, type, US, value
    }

    # parse_value - the recursive descent.  Returns the index just past the
    # value it consumed.
    function parse_value(p, path,   c, n, key, kend, vend, seen) {
      while (p <= LEN && is_ws(substr(S, p, 1))) p++
      c = substr(S, p, 1)

      if (c == "{") {
        p++
        seen = 0
        while (p <= LEN) {
          while (p <= LEN && is_ws(substr(S, p, 1))) p++
          c = substr(S, p, 1)
          if (c == "}") { if (!seen) emit(path, "o", ""); return p + 1 }
          if (c == ",") { p++; continue }
          if (c != "\"") { p++; continue }    # malformed: skip a byte
          STRVAL = ""
          kend = scan_string(p); key = STRVAL
          p = kend
          while (p <= LEN && is_ws(substr(S, p, 1))) p++
          if (substr(S, p, 1) == ":") p++
          seen = 1
          p = parse_value(p, (path == "") ? key : path "/" key)
        }
        return p
      }

      if (c == "[") {
        p++
        n = 0
        while (p <= LEN) {
          while (p <= LEN && is_ws(substr(S, p, 1))) p++
          c = substr(S, p, 1)
          if (c == "]") { if (n == 0) emit(path, "a", ""); return p + 1 }
          if (c == ",") { p++; continue }
          p = parse_value(p, (path == "") ? n : path "/" n)
          n++
        }
        return p
      }

      if (c == "\"") {
        STRVAL = ""
        vend = scan_string(p)
        emit(path, "s", STRVAL)
        return vend
      }

      if (substr(S, p, 4) == "true")  { emit(path, "b", "true");  return p + 4 }
      if (substr(S, p, 5) == "false") { emit(path, "b", "false"); return p + 5 }
      if (substr(S, p, 4) == "null")  { emit(path, "z", "");      return p + 4 }

      # a number: consume the run of characters a JSON number may contain
      n = p
      while (n <= LEN && index("-+.eE0123456789", substr(S, n, 1)) > 0) n++
      if (n == p) return p + 1                # malformed: skip a byte
      emit(path, "n", substr(S, p, n - p))
      return n
    }

    { BUF = BUF $0 "\n" }
    END {
      S = BUF; LEN = length(S)
      p = 1
      while (p <= LEN) {
        while (p <= LEN && is_ws(substr(S, p, 1))) p++
        if (p > LEN) break
        p = parse_value(p, "")
      }
    }
  '
}

# ---------------------------------------------------------------------------
# bench_json_string - one string, JSON-escaped, WITHOUT the surrounding
# quotes.  Every normaliser writes its output records through this.
# ---------------------------------------------------------------------------
# The five named escapes RFC 8259 §7 defines are handled by substitution; any
# OTHER C0 control byte is rewritten to its \u00XX form, because a raw one
# would make the emitted line invalid JSON and every downstream reader would
# then fail on a record it could not attribute to any tool.  Bytes at or above
# 0x20 pass through untouched, which is what keeps UTF-8 intact.
bench_json_string() {
  local s=$1 i esc lit
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  for (( i = 0; i < 32; i++ )); do
    case $i in 9 | 10 | 13) continue ;; esac
    printf -v lit '\\%03o' "$i"
    printf -v lit '%b' "$lit"
    [[ $s == *"$lit"* ]] || continue
    printf -v esc '\\u%04x' "$i"
    s=${s//"$lit"/$esc}
  done
  printf '%s' "$s"
}
