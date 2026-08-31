#!/usr/bin/env bash
# modules/dast/passive/transport_engine.sh - the pure, testable half of the
# TRANSPORT-EXPOSURE family (docs/DESIGN.md §7.4's `transport.sh` bullet;
# docs/STEP5-DAST-PLAN.md DAST-30).
#
# WHAT THIS FAMILY OWNS, AND WHAT IT DOES NOT.  Three neighbouring checks look
# like this one from a distance and each owns a piece this file must not touch:
#
#   passive/tls.sh   (DAST-07) owns the CONNECTION: the handshake, the
#                    certificate chain, its validity dates and its hostname
#                    binding, the negotiated protocol version and cipher suite.
#                    Everything about whether the encryption itself is any good.
#   passive/headers.sh (DAST-05) owns `Strict-Transport-Security` - all three of
#                    `DAST-HDR-HSTS_MISSING-01`, `_WEAK-01` and `_MALFORMED-01`.
#                    "This HTTPS response does not pin the browser to HTTPS" is
#                    that check and never one of these.
#   passive/cookies.sh (DAST-06) owns the `Secure` ATTRIBUTE
#                    (`DAST-COOKIE-NO_SECURE-01`): a cookie a browser would send
#                    over plaintext.  This file's plaintext check is about a
#                    cookie that was ALREADY SENT over plaintext, which is a
#                    different fact with a different fix, and its evidence says
#                    so rather than restating the attribute finding.
#
# What is left, and what this file is for, is the two exposure classes none of
# those three can see: content that TRAVELS unencrypted, and content an
# encrypted page LOADS unencrypted.  A target can pass every TLS check, set
# HSTS, mark every cookie `Secure`, and still serve its login page on port 80
# and pull its main bundle over `http://`.
#
# THE ONE THING THIS FILE DOES NOT DO IS TALK TO THE NETWORK.  Every request the
# phase sends goes through `http_request` (lib/http.sh) - docs/FOUNDATION.md
# tension 19's single chokepoint, which is where the scope gate, DAST-01's rate
# limiter, the per-run request budget, the circuit breaker and DAST-32's
# ceilings all sit.  This file parses what came back; `transport.sh` is what
# asks.
#
# EVERYTHING PARSED HERE IS UNTRUSTED TARGET OUTPUT (tension 10).  A `src`
# attribute is attacker-authorable text; it reaches a report only through
# `finding_set_evidence`, and `hdr_safe_text` bounds it first.
#
# NEVER A BARE `grep` (tension 4).  The one match engine used here is `awk`,
# whose exit status this file never reads as a match/no-match signal: it is a
# stream transformer that prints zero or more records, and zero records is the
# ordinary case rather than a failure.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_TRANSPORT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_TRANSPORT_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 0. What is reused, and why nothing is forked
# ---------------------------------------------------------------------------
# modules/dast/passive/headers_engine.sh is SOURCED, not copied, for its
# response-header reader (`hdr_parse_capture`/`hdr_present`/`hdr_value`/
# `hdr_first`), its `hdr_is_document` content-type gate, and its `hdr_path_of`,
# `hdr_url_is_https` and `hdr_safe_text` helpers.
#
# That file's own header asks a later ticket needing the same response reader to
# LIFT it into a shared `passive/response_engine.sh` rather than grow a second
# copy, and notes the lift is a refactor with an owner - DAST-05's - because
# that file's tests must move with it.  This ticket does neither of the two
# things it warns against: it does not fork the reader, and it does not
# unilaterally move a landed peer's tests.  It reuses the functions where they
# are.  The reader in particular MUST NOT be forked: `hdr_parse_capture`'s reset
# on every `HTTP/x.y NNN` status line is the most dangerous parse in this tier -
# a capture sink accumulates every redirect hop, so a whole-file match reads the
# REDIRECT's headers and reports them as the delivered page's - and two copies
# of it is two chances to lose that reset.  DAST-05's stated shared-file lift
# HAS SINCE HAPPENED: the reader now lives in `passive/response_engine.sh`, a
# leaf module that sources nothing and holds the reader alone, so this file
# names that instead of DAST-05's own engine and no longer pulls in the
# CSP/HSTS/Referrer parsers or the recommended-header loader, neither of which
# it ever used.  No call site changed.
#
# THE ENDPOINT CHOOSER HAS SINCE MOVED THERE TOO.  `tr_endpoints_load` below
# used to be a fourth, near-identical copy of `hdr_endpoints_load`, differing
# in exactly one place: its dedup key is `(scheme, path template)`, not the
# path template alone (see section 4's own chooser comment below for why -
# that reasoning is unchanged and still governs this file's behaviour).  It is
# now a thin wrapper over `response_engine.sh`'s `resp_endpoints_load`, which
# takes that one difference as an explicit `scheme_template` parameter rather
# than staying a forked function body - see `response_engine.sh`'s own third
# ADR block.  `tr_url_scheme` (below) is likewise now a one-line wrapper over
# that file's `resp_url_scheme`, which the `scheme_template` dedup mode needs
# by name; `tr_url_origin` and the mixed-content scanner, which use it for
# reasons unrelated to the chooser, are unaffected.
#
# response_engine.sh sources nothing, so lib/http.sh no longer arrives through
# it; the guarded source below is what supplies it, and was already present
# rather than being added here.
# shellcheck source=modules/dast/passive/response_engine.sh
source "${BASH_SOURCE[0]%/*}/response_engine.sh"
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # -x back-edge cut: lib/http.sh
  # is already inlined elsewhere in this file's own source graph, and shellcheck
  # re-expands EVERY source edge it follows.  Cutting this one loses no checking
  # and is what keeps the linter's memory bounded - see the shellcheck stage in
  # tests/run-tests.sh, and docs/CI-RUNBOOK.md.
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# crawl_engine.sh supplies the frozen inventory reader (`crawl_json_flatten`/
# `crawl_json_unescape`, docs/INVENTORY-FORMAT.md §7) and `crawl_url_resolve`,
# RFC 3986 §5.2 reference resolution.  Both are reused rather than
# reimplemented, for the same reason: the inventory is read THROUGH the reader
# that wrote it, and a second URL resolver would be a second answer to "what
# does this `src` actually point at".  Its own sourced-once guard makes this a
# no-op on a run where the crawl already happened.
# -x back-edge cut: modules/dast/crawl_engine.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"

# ---------------------------------------------------------------------------
# 1. Bounds and knobs
# ---------------------------------------------------------------------------
# docs/DESIGN.md §15: a bound that truncates silently is indistinguishable from
# a surface that was really that small, so each of these records a coverage_gap
# when it bites.
#
# How many distinct (scheme, path-template) endpoints this phase will request.
# Mixed content is a per-DOCUMENT property, unlike a security header, so more
# documents genuinely mean more coverage - but re-requesting two hundred paths
# is a request storm the operator did not ask for.  Ten matches the sibling
# passive phases' bound and is what the coverage_gap names.
: "${_TR_MAX_ENDPOINTS:=10}"
# How many distinct offending sub-resource URLs are carried into one finding's
# evidence.  A page loading forty plaintext images is one defect; naming all
# forty makes the finding unreadable, and the count is the honest summary.
: "${_TR_MAX_EVIDENCE_REFS:=5}"

# ---------------------------------------------------------------------------
# 2. URL shape helpers
# ---------------------------------------------------------------------------
# `tr_url_scheme URL` - prints the lowercased scheme, or nothing for a string
# that is not an absolute http(s) URL.  A one-line wrapper over
# `response_engine.sh`'s `resp_url_scheme`, which the shared chooser's
# `scheme_template` dedup mode needs by name (see this file's own header and
# `response_engine.sh`'s third ADR block); kept under its historic name so
# `tr_url_origin` and the mixed-content scanner below do not change.
tr_url_scheme() {
  resp_url_scheme "$1"
}

# `tr_url_origin URL` - prints `scheme://host[:port]`, the RFC 6454 origin, or
# nothing.  Used for the evidence sentence; never for a scope decision, which is
# `http_gate_url`'s alone.
tr_url_origin() {
  local u=$1 rest
  [[ $u =~ ^[Hh][Tt][Tt][Pp][Ss]?:// ]] || { printf ''; return 0; }
  rest=${u#*://}
  rest=${rest%%/*}
  rest=${rest%%\?*}
  rest=${rest%%#*}
  printf '%s://%s' "$(tr_url_scheme "$u")" "$rest"
}

# ---------------------------------------------------------------------------
# 3. The sub-resource extractor
# ---------------------------------------------------------------------------
# `tr_html_scan` - reads an HTML document on STDIN and prints one TAB-separated
# record per line:
#
#   base<TAB><href>                   the document's first <base href>, if any
#   ref<TAB><class><TAB><tag><TAB><raw reference>
#   pw<TAB><name>                     an <input type="password"> control
#
# `<class>` is one of:
#
#   active   script src, <link rel=stylesheet|import|preload as=script> href,
#            iframe/frame src, object data, embed src, applet code.  A browser
#            BLOCKS these outright on a secure page (Mixed Content Level 1
#            §4.3, "blockable"), because each can execute in, restyle, or
#            navigate the document.
#   passive  img/audio/video/source/track src, video poster, img srcset.
#            "Optionally-blockable": browsers still load them, downgrade the
#            lock icon, and let a network attacker replace the pixels.
#   form     a <form action> - its own class because the defect is what LEAVES
#            the browser rather than what arrives, and the browser's own warning
#            for it is a separate one.
#   nav      an <a>/<area> href.
#
# `nav` IS EXTRACTED AND IS NEVER A MIXED-CONTENT FINDING, AND THAT IS THE
# SINGLE MOST IMPORTANT DECISION IN THIS FILE.  A hyperlink to an `http://` site
# is not mixed content in any browser and never has been: nothing is loaded into
# the secure document, the user navigates away deliberately, and the address bar
# tells them where they went.  The naive reading - flag every `http://` string
# in the markup - fires on every external link on the page, so a site with a
# plaintext footer link outranks a site whose login bundle is fetched over port
# 80.  It is extracted rather than skipped precisely so the suite can assert it
# is NOT reported: a class that is never emitted cannot be tested for absence,
# and this is the false positive most worth pinning.
#
# WHY NOT `crawl_html_extract`.  That function exists and is deliberately the
# wrong tool here: it inventories NAVIGABLE endpoints, so it skips `<script>`
# and `<style>` elements wholesale (crawl_engine.sh's own `skipuntil`) and emits
# no record at all for `<img src>`, `<object data>` or `<embed src>`.  Those are
# exactly the references mixed content is about - a `<script src="http://...">`
# is invisible to it by design.  Extending it instead would change what the
# endpoint inventory contains, which is a frozen contract six later tickets read
# (docs/INVENTORY-FORMAT.md), to serve one check wanting a different question
# answered.
#
# The tag walk itself - quote-aware attribute reading, comment skipping, entity
# decoding - is the same shape as `crawl_html_extract`'s and for the same
# reasons, which its own comments give at length.  `&amp;` decoding matters here
# too: `src="http://cdn/x?a=1&amp;b=2"` is the NORMAL spelling of that URL.
tr_html_scan() {
  awk '
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
      re = "[ \t\r\n/]" name "[ \t\r\n]*=[ \t\r\n]*"
      s = " " tolower(tag)
      p = match(s, re)
      if (p == 0) return ""
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
    function emit(cls, tg, v) {
      if (v != "") print "ref\t" cls "\t" tg "\t" v
    }
    # The first URL of a srcset descriptor list.  A srcset is `url 1x, url 2x`;
    # one plaintext candidate in it is the finding, and reporting the whole list
    # as one reference would put a comma-separated blob in the evidence.
    function srcset_first(v,   p) {
      sub(/^[ \t\r\n]+/, "", v)
      p = match(v, /[ \t\r\n,]/)
      if (p > 0) v = substr(v, 1, p - 1)
      return v
    }
    # SQ is built with sprintf rather than written literally: this awk program
    # lives inside a single-quoted shell string, so an apostrophe anywhere in it
    # - code or comment - would end that string.
    BEGIN { SQ = sprintf("%c", 39) }
    { doc = doc $0 "\n" }
    END {
      n = length(doc)
      i = 1
      while (i <= n) {
        c = substr(doc, i, 1)
        if (c != "<") { i++; continue }
        if (substr(doc, i, 4) == "<!--") {
          # A reference inside a comment is loaded by nothing.  Skipping
          # comments is what keeps a commented-out `<script src="http://...">`
          # from being reported as a live defect.
          p = index(substr(doc, i), "-->")
          i = (p == 0) ? n + 1 : i + p + 2
          continue
        }
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
        closing = (substr(tag, 1, 1) == "/")

        # UNLIKE crawl_html_extract, a <script> element is READ, not skipped.
        # Its `src` is the archetypal blockable mixed-content reference.  Its
        # BODY is of no interest and is not consumed as markup: the tag walk
        # continues, and any "<" inside the script body that does not open a
        # real tag falls through the loop harmlessly.
        # <base href> retargets EVERY relative reference in the document
        # (HTML §4.2.3).  It is emitted first-wins, as browsers do, and the
        # caller resolves against it - without this, a page whose <base> is an
        # `http://` origin has every relative sub-resource loaded over plaintext
        # while this check reads them as inheriting the document scheme, which
        # is a silent FALSE NEGATIVE on precisely the shape that makes a whole
        # page mixed at once.
        if (nm == "base" && !closing) {
          v = attr(tag, "href")
          if (v != "" && !basedone) { print "base\t" v; basedone = 1 }
          continue
        }
        if (nm == "script" && !closing) { emit("active", "script", attr(tag, "src")); continue }
        if (nm == "link" && !closing) {
          rel = tolower(attr(tag, "rel"))
          as = tolower(attr(tag, "as"))
          href = attr(tag, "href")
          if (href == "") continue
          # A stylesheet restyles the document and can exfiltrate through
          # selectors; an imported or preloaded script executes.  Everything
          # else a <link> can name (icon, manifest, dns-prefetch, alternate) is
          # not loaded into the document as active content, so it is classed
          # passive rather than silently dropped.
          if (rel ~ /stylesheet/ || rel ~ /import/ || (rel ~ /preload/ && (as == "script" || as == "style")))
            emit("active", "link", href)
          else
            emit("passive", "link", href)
          continue
        }
        if ((nm == "iframe" || nm == "frame") && !closing) { emit("active", nm, attr(tag, "src")); continue }
        if (nm == "object" && !closing) { emit("active", "object", attr(tag, "data")); continue }
        if (nm == "embed" && !closing) { emit("active", "embed", attr(tag, "src")); continue }
        if (nm == "applet" && !closing) { emit("active", "applet", attr(tag, "code")); continue }

        if (nm == "img" && !closing) {
          emit("passive", "img", attr(tag, "src"))
          ss = attr(tag, "srcset")
          if (ss != "") emit("passive", "img", srcset_first(ss))
          continue
        }
        if ((nm == "audio" || nm == "video" || nm == "source" || nm == "track") && !closing) {
          emit("passive", nm, attr(tag, "src"))
          if (nm == "source") { ss = attr(tag, "srcset"); if (ss != "") emit("passive", nm, srcset_first(ss)) }
          if (nm == "video") emit("passive", "video", attr(tag, "poster"))
          continue
        }

        if (nm == "form" && !closing) { emit("form", "form", attr(tag, "action")); continue }

        # A password control is the strongest single signal that a response
        # carries a credential-collecting surface.  It is reported whether or
        # not it sits inside a <form>: a client-rendered login posts with
        # fetch() and often has no form element at all, and requiring one would
        # miss exactly the modern shape.
        if (nm == "input" && !closing) {
          if (tolower(attr(tag, "type")) == "password") {
            nmv = attr(tag, "name")
            if (nmv == "") nmv = attr(tag, "id")
            if (nmv == "") nmv = "(unnamed)"
            print "pw\t" nmv
          }
          continue
        }
        if ((nm == "a" || nm == "area") && !closing) { emit("nav", nm, attr(tag, "href")); continue }
      }
    }
  '
}

# ---------------------------------------------------------------------------
# 4. Choosing what to request (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `tr_endpoints_load [ENDPOINTS_FILE] [TARGET] [BASE_URL]` - publishes the URL
# list this phase will request in `_TR_URL[]`, with `_TR_PATH[]` alongside, and
# sets `_TR_N`, `_TR_TRUNCATED` and `_TR_SKIPPED_NON_GET`.
#
# A THIN WRAPPER over `response_engine.sh`'s `resp_endpoints_load`, exactly as
# `hdr_endpoints_load`, `markup_endpoints_load` and `leak_endpoints_load`
# already are - see that file's third ADR block.  This file's own difference
# from every OTHER caller is the one thing it still passes explicitly:
# THE DEDUP KEY IS (SCHEME, PATH TEMPLATE), NOT THE PATH TEMPLATE ALONE.
# `passive/headers.sh` is right to collapse `http://h/login` and
# `https://h/login` into one candidate - it asks about a header the application
# sets once, and either of the two answers it.  Here the two URLs are the entire
# question: the plaintext twin of an HTTPS endpoint IS the finding, and a
# path-template-only dedup drops whichever of the pair sorts second, so the
# check would report clean on exactly the target that has the defect.  The suite
# pins this with an inventory carrying both schemes of one path and an assertion
# that fails under the borrowed key.  `resp_endpoints_load`'s `scheme_template`
# mode IS that key; this file supplies it as a call-time argument rather than
# a forked function body.
#
# The other three decisions are `resp_endpoints_load`'s defaults, unchanged
# from before this file called it directly: the operator's own `base-url`
# first and outside the sort (config-derived, present on every run, and being
# first is what keeps a fingerprint from churning when the crawl reorders);
# GET only (§7.1's "no mutation of state" - re-sending a discovered POST to
# read its body is a state change wearing a passive check's name); sorted,
# then capped, so the chosen set is reproducible across runs.
#
# `tr_endpoints_load`'s name, its parameters and its three output globals
# (`_TR_URL`/`_TR_PATH`/`_TR_N`/`_TR_TRUNCATED`/`_TR_SKIPPED_NON_GET`) are
# UNCHANGED, so no call site in `transport.sh` moves.
tr_endpoints_load() {
  local epf=${1:-} target=${2:-} base=${3:-}
  resp_endpoints_load "$epf" "$target" "$base" "$_TR_MAX_ENDPOINTS" scheme_template
  declare -ga _TR_URL=("${_RESP_URL[@]+"${_RESP_URL[@]}"}")
  declare -ga _TR_PATH=("${_RESP_PATH[@]+"${_RESP_PATH[@]}"}")
  declare -g _TR_N=$_RESP_N _TR_TRUNCATED=$_RESP_TRUNCATED \
    _TR_SKIPPED_NON_GET=$_RESP_SKIPPED_NON_GET
  return 0
}

# ---------------------------------------------------------------------------
# 5. Mixed-content analysis of one document
# ---------------------------------------------------------------------------
# `tr_mixed_scan BODYFILE DOCUMENT_URL` - reads one HTML body and publishes, for
# each of the three mixed-content classes (`active`, `passive`, `form`):
#
#   _TR_MIX_N[class]     how many plaintext references of that class were found
#   _TR_MIX_REFS[class]  up to `_TR_MAX_EVIDENCE_REFS` of them, LF-separated
#   _TR_MIX_TAGS[class]  the element names involved, deduped, space-separated
#   _TR_NAV_PLAINTEXT    plaintext <a href> references seen and NOT reported
#   _TR_REF_TOTAL        every resolvable reference examined, of any class
#   _TR_BASE_HREF        the document's own <base href> when it set one, '' when
#                        it did not - so the evidence can say the whole page was
#                        retargeted rather than blaming each reference
#
# A REFERENCE IS RESOLVED BEFORE ITS SCHEME IS READ, AND THAT IS NOT A DETAIL.
# `crawl_url_resolve` applies RFC 3986 §5.2 against the EFFECTIVE BASE - the
# document's own `<base href>` where it set one, the document URL otherwise -
# which is what makes a PROTOCOL-RELATIVE reference, `//cdn.example/app.js`,
# come back as `https://cdn.example/app.js` on an ordinary HTTPS page.  It is
# not mixed content and never was: the whole point of the `//` form is that it
# inherits the document's scheme.  A check that read the raw attribute and
# looked for the absence of `https` would flag every one of them, and
# protocol-relative URLs are common enough on older sites that the check would
# be useless.  Equally a plain relative reference (`/app.js`, `app.js`) inherits
# the scheme and is never a finding.
#
# THE `<base href>` PASS IS WHY THIS IS TWO PASSES AND NOT ONE, and skipping it
# is a silent FALSE NEGATIVE rather than a cosmetic gap: `<base href>` retargets
# every relative reference in the document (HTML §4.2.3), so a page whose base
# is an `http://` origin loads its whole relative sub-resource set over
# plaintext while a document-URL-only resolver reads every one of them as
# inheriting https and reports the page clean.  One element, whole page mixed.
# A test pins it and fails when the base is ignored.
#
# BEWARE THE OTHER DIRECTION, WHICH THE SUITE ALSO PINS: the naive alternative
# to resolving at all - skipping any reference that carries no scheme of its own
# - produces the SAME FINDINGS as resolving, because only an absolute `http://`
# reference can be mixed content on an https page.  What it changes is
# `_TR_REF_TOTAL`, the honest count of references this check could judge, which
# under the skip silently becomes "references that happened to be written
# absolutely".  That was measured by mutation, not reasoned about.
#
# A reference `crawl_url_resolve` REJECTS - `data:`, `javascript:`, `mailto:`, a
# bare fragment - is not a network load at all and is skipped.  It is counted in
# `_TR_REF_TOTAL` only when it resolved, so the total is "references this check
# could actually judge" rather than "strings that looked like one".
tr_mixed_scan() {
  local bodyfile=$1 docurl=$2
  local kind cls tag raw abs scheme
  declare -gA _TR_MIX_N=() _TR_MIX_REFS=() _TR_MIX_TAGS=() _TR_MIX_TAGSEEN=()
  declare -g _TR_NAV_PLAINTEXT=0 _TR_REF_TOTAL=0 _TR_BASE_HREF=''
  [[ -n $bodyfile && -r $bodyfile && -s $bodyfile ]] || return 1

  # PASS 1: the document's own <base href>, resolved against the document URL.
  # It must be read before any reference is classified, because it changes what
  # every relative one resolves to - which is why this is two passes over a
  # small extractor output rather than one pass that would have to guess.
  local base_url=$docurl b
  while IFS=$'\t' read -r kind b; do
    [[ $kind == base ]] || continue
    [[ -n $b ]] || continue
    if base_url=$(crawl_url_resolve "$docurl" "$b" 2>/dev/null) && [[ -n $base_url ]]; then
      declare -g _TR_BASE_HREF=$base_url
    else
      base_url=$docurl
    fi
    # No `break`: the extractor already emits at most ONE `base` record (first
    # wins, as browsers do), so breaking buys nothing and would only close the
    # process substitution's pipe under it mid-stream.
  done < <(tr_html_scan <"$bodyfile")

  # PASS 2: classify every reference against the effective base.
  while IFS=$'\t' read -r kind cls tag raw; do
    [[ $kind == ref ]] || continue
    [[ -n $raw ]] || continue
    abs=$(crawl_url_resolve "$base_url" "$raw" 2>/dev/null) || continue
    [[ -n $abs ]] || continue
    scheme=$(tr_url_scheme "$abs")
    [[ -n $scheme ]] || continue
    _TR_REF_TOTAL=$(( _TR_REF_TOTAL + 1 ))
    [[ $scheme == http ]] || continue
    if [[ $cls == nav ]]; then
      # Seen, deliberately not reported.  See tr_html_scan's header.
      _TR_NAV_PLAINTEXT=$(( _TR_NAV_PLAINTEXT + 1 ))
      continue
    fi
    _TR_MIX_N[$cls]=$(( ${_TR_MIX_N[$cls]:-0} + 1 ))
    if (( ${_TR_MIX_N[$cls]} <= _TR_MAX_EVIDENCE_REFS )); then
      _TR_MIX_REFS[$cls]="${_TR_MIX_REFS[$cls]:+${_TR_MIX_REFS[$cls]}$'\n'}$abs"
    fi
    if [[ -z ${_TR_MIX_TAGSEEN[$cls$'\x1f'$tag]:-} ]]; then
      _TR_MIX_TAGSEEN[$cls$'\x1f'$tag]=1
      _TR_MIX_TAGS[$cls]="${_TR_MIX_TAGS[$cls]:+${_TR_MIX_TAGS[$cls]} }<$tag>"
    fi
  done < <(tr_html_scan <"$bodyfile")
  return 0
}

# `tr_mix_refs_sentence CLASS` - the offending URLs for one class, bounded and
# `, ` joined, for the evidence.
tr_mix_refs_sentence() {
  local cls=$1 out='' line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    out+="${out:+, }$(hdr_safe_text "$line" 120)"
  done <<<"${_TR_MIX_REFS[$cls]:-}"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 6. Sensitivity of a plaintext response
# ---------------------------------------------------------------------------
# `tr_sensitivity_scan BODYFILE` - publishes `_TR_SENS_REASONS` (LF-separated
# human sentences) and `_TR_SENS_PW` (the count of password controls): the
# BODY-derived half of "is this plaintext response sensitive".  The
# HEADER-derived half - a `Set-Cookie`, or a response the run only obtained
# because it held a session - is added by the phase through `tr_add_reason`,
# because it needs the response headers rather than the body and this file is
# not the one holding them.
#
# THE DEFINITION IS DELIBERATELY NARROW AND EVIDENCE-BEARING.  "Sensitive" could
# mean almost anything, and a check that guessed would either flag every
# plaintext page on the internet (true, useless, and not what §7.4 asks for) or
# nothing at all.  What is reported is a response over `http://` carrying one of
# four things the operator can be shown:
#
#   1. a password control - the response collects a credential in the clear.
#   2. a `Set-Cookie` - the server issued state over an unencrypted channel, so
#      it was observable in transit whatever the `Secure` attribute says
#      afterwards.  (The attribute itself is DAST-COOKIE-NO_SECURE-01's, and
#      this evidence says so rather than restating it.)
#   3. an authenticated request - the run held a session and sent it, so the
#      response is authenticated content that travelled in the clear.
#   4. a form posting a credential - a <form> on the plaintext document whose
#      controls include a password field.
#
# A plaintext page carrying none of the four is NOT this check: it is the
# no-redirect-to-TLS check's business, which fires on the transport rather than
# the content and carries a lower severity for exactly that reason.  Collapsing
# the two - reporting every plaintext 200 as sensitive exposure - is the
# rejected reading, and the suite pins it with a plain marketing page that must
# produce the transport finding and NOT the exposure one.
tr_sensitivity_scan() {
  local bodyfile=$1 kind v
  declare -g _TR_SENS_REASONS='' _TR_SENS_PW=0
  [[ -n $bodyfile && -r $bodyfile && -s $bodyfile ]] || return 1
  local pwnames=''
  while IFS=$'\t' read -r kind v; do
    [[ $kind == pw ]] || continue
    _TR_SENS_PW=$(( _TR_SENS_PW + 1 ))
    if (( _TR_SENS_PW <= _TR_MAX_EVIDENCE_REFS )); then
      pwnames+="${pwnames:+, }$(hdr_safe_text "$v" 40)"
    fi
  done < <(tr_html_scan <"$bodyfile")
  if (( _TR_SENS_PW > 0 )); then
    tr_add_reason "it carries $_TR_SENS_PW password control(s) ($pwnames), so a credential typed into this page is submitted from a document that arrived unencrypted and could have been rewritten in transit"
  fi
  return 0
}

# `tr_add_reason SENTENCE` - appends one sensitivity sentence.  A function
# rather than an inline append because this file adds the body-derived reason
# and the phase adds the header-derived ones, and both must join the same list
# in the same shape.
tr_add_reason() {
  local s=$1
  [[ -n $s ]] || return 0
  _TR_SENS_REASONS="${_TR_SENS_REASONS:+${_TR_SENS_REASONS}$'\n'}$s"
  return 0
}

# `tr_reasons_sentence` - the accumulated reasons as one `; `-joined sentence.
tr_reasons_sentence() {
  local out='' line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    out+="${out:+; }$line"
  done <<<"${_TR_SENS_REASONS:-}"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 7. The plaintext-redirect verdict
# ---------------------------------------------------------------------------
# `tr_redirect_verdict STATUS LOCATION` - classifies the FIRST response an
# `http://` URL gave, without following it.  Sets `_TR_REDIR_VERDICT` to:
#
#   to_https    a 3xx whose Location is an https:// URL - the correct answer,
#               and the one case that is NOT a finding
#   to_http     a 3xx whose Location is another http:// URL, so the redirect
#               does not leave plaintext (a host-canonicalising redirect is the
#               shape that most often hides a missing TLS redirect)
#   relative    a 3xx whose Location is scheme-relative or a bare path - it
#               inherits http:// and therefore stays in the clear
#   none        a 2xx/4xx/5xx: the plaintext endpoint answered with content
#   unknown     a 3xx with no Location at all
#
# THE REQUEST IS MADE WITH max_redirects 0, AND THAT IS THE WHOLE MECHANISM.
# `http_request` follows redirects internally and reports the FINAL status, so a
# target that correctly 301s port 80 to HTTPS and one that serves the page on
# port 80 both come back as `200` from an ordinary call - the two facts this
# check exists to tell apart become one string.  Asking for zero hops is what
# makes the first response readable.  The suite asserts the `to_https` case
# produces no finding, and that assertion fails under a call that lets the
# redirect be followed.
tr_redirect_verdict() {
  local status=$1 location=$2
  declare -g _TR_REDIR_VERDICT=none
  [[ $status =~ ^3[0-9][0-9]$ ]] || return 0
  if [[ -z $location ]]; then
    _TR_REDIR_VERDICT=unknown
    return 0
  fi
  case $(tr_url_scheme "$location") in
    https) _TR_REDIR_VERDICT=to_https ;;
    http) _TR_REDIR_VERDICT=to_http ;;
    *) _TR_REDIR_VERDICT=relative ;;
  esac
  return 0
}

# `tr_read_capture FILE` - the final header block's status and `Location`, via
# `hdr_parse_capture`'s reader rather than a match over the file, for the
# hop-accumulation reason that function's own header gives.  Sets `_TR_STATUS`
# and `_TR_LOCATION`; returns 1 when no response was captured at all, which the
# caller must tell apart from "a response with no Location".
tr_read_capture() {
  local f=$1
  declare -g _TR_LOCATION='' _TR_STATUS=''
  hdr_parse_capture "$f" || return 1
  _TR_STATUS=$_HDR_STATUS
  hdr_first location
  _TR_LOCATION=$_HDR_V
  return 0
}
