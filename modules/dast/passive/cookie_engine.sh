#!/usr/bin/env bash
# modules/dast/passive/cookie_engine.sh - the pure `Set-Cookie` parser and
# attribute analyser behind modules/dast/passive/cookies.sh (docs/DESIGN.md
# §7.1 "cookies.sh - Secure, HttpOnly, SameSite flags per cookie";
# docs/STEP5-DAST-PLAN.md DAST-06, tier 2).
#
# WHY THIS FILE EXISTS, AND WHY IT IS NOT SHARED SCAFFOLDING.  DAST-05..DAST-11
# are peers with no ordering between them, so this ticket deliberately adds
# nothing another passive ticket also needs: everything here is `Set-Cookie`
# grammar and nothing here is a header reader, an inventory reader, or a
# request composer.  The one general-purpose thing DAST-06 needed - a reader for
# the frozen endpoint inventory - was NOT written here; modules/dast/passive/
# cookies.sh reuses `inject_inventory_load` (modules/dast/active/
# inject_engine.sh), which is the shipped reader for that artifact, for exactly
# the reason that file's own header gives: a second, subtly different reader for
# one frozen artifact is the failure mode it exists to prevent.  The engine/phase
# split itself is modules/sast/'s, reused verbatim, as auth_engine.sh + auth.sh
# and inject_engine.sh + sqli.sh already do.
#
# THE PARSING IS THE SUBSTANCE, AND EVERY HAZARD BELOW IS ONE A NAIVE SPLIT GETS
# WRONG.  Each is pinned by a case in tests/suites/dast-cookies.sh that names the
# reading it fails under:
#
#   1. A `Set-Cookie` header value is NEVER split on a comma.  RFC 6265 §3 says
#      so in terms ("servers SHOULD NOT fold multiple Set-Cookie header fields
#      into a single header field"), and the reason is right here in the grammar:
#      `Expires=Wed, 09 Jun 2021 10:18:14 GMT` carries a comma inside ONE
#      attribute.  The generic RFC 7230 "a comma separates list members" rule
#      that holds for `Accept` or `Cache-Control` is precisely wrong for this
#      header, and applying it manufactures a second cookie named `09 Jun 2021
#      10` out of the first one's expiry date - a phantom finding about a cookie
#      that does not exist, on a header that may have been perfectly fine.
#   2. A `Set-Cookie` value IS split on `;`, but only OUTSIDE double quotes.
#      RFC 6265 §4.1.1's `cookie-value` may be `DQUOTE *cookie-octet DQUOTE`,
#      and real servers put a `;` inside those quotes.  A naive `${v%%;*}` reads
#      `pref="a; b"; HttpOnly` as the cookie `pref` with value `"a` and then
#      loses the `HttpOnly` attribute entirely - reporting a missing flag that
#      is right there in the header.
#   3. Attribute names are matched CASE-INSENSITIVELY and in ANY ORDER.
#      `httponly`, `HttpOnly` and `HTTPONLY` are one attribute (RFC 6265 §5.2
#      "case-insensitively"), and nothing in the grammar orders them, so
#      `Set-Cookie: a=1; samesite=strict; secure; HttpOnly` and
#      `Set-Cookie: a=1; HTTPONLY; Secure; SameSite=Strict` must analyse
#      identically.
#   4. An attribute's PRESENCE is what sets `Secure`/`HttpOnly`, not its value.
#      RFC 6265 §5.2.5/§5.2.6 discard the attribute-value for both, so
#      `HttpOnly=false` is an HttpOnly cookie in every browser, and reading the
#      value would report a flag as missing on a cookie that has it.
#   5. Multiple `Set-Cookie` headers in one response - and across the redirect
#      hops lib/http.sh accumulates into one capture file - are separate
#      cookies, each analysed on its own.
#
# THE ABSENT/WEAK SPLIT FOR SameSite IS A DELIBERATE TWO-CHECK DESIGN, not one
# check with two messages.  Browsers do not agree on what an ABSENT SameSite
# means - Chromium defaults it to `Lax`, and other engines have shipped both
# `Lax`-by-default and no default at all - so an absent attribute is a policy
# the SITE did not choose and the risk depends on the visitor's browser.  An
# EXPLICIT `SameSite=None` is a policy the site DID choose: the cookie is sent
# on every cross-site request, on every browser, deliberately.  Those are
# different facts with different remediations, and a single finding could only
# state one of them, so they are DAST-COOKIE-SAMESITE_ABSENT-01 and
# DAST-COOKIE-SAMESITE_WEAK-01 - two check ids, because `check_id` is a
# fingerprint component and one id would make the two states one finding that
# flips its own meaning between runs.
#
# THIS FILE ISSUES NO TRAFFIC AND TOUCHES NO DISK BEYOND READING A CAPTURE FILE
# lib/http.sh already wrote.  It is a pure library with the standard
# sourced-once guard and no side effects at source time.
#
# shellcheck shell=bash
#
# SC2016: the header/attribute grammar is quoted literally in the prose above
# and in diagnostics.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_COOKIE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_COOKIE_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 1. Extracting the Set-Cookie header values from a raw capture
# ---------------------------------------------------------------------------
# `cookie_extract_set_cookie HDRFILE` - prints one `Set-Cookie` header VALUE per
# line (the bytes after `Set-Cookie:`, leading whitespace trimmed, CR stripped).
# Returns 0 when at least one was found, 1 when none were, and never lies about
# the difference.
#
# THROUGH `scan_match`, NEVER A BARE GREP (docs/FOUNDATION.md tension 4 rule 2).
# `set -Eeuo pipefail` is mandatory in this repository and grep exits 1 on
# no-match, which is the ORDINARY case here - most responses set no cookie. A
# bare grep would either take the whole run down on a clean response or, wrapped
# in `|| true`, would report an engine failure as "this response set no cookie",
# which is a silent coverage hole in exactly the direction that reads as a pass.
#
# The header file lib/http.sh writes ACCUMULATES every redirect hop's response
# headers (its `http_request_capture` contract), which is what this check wants:
# a login that 302s sets its session cookie on the hop that redirects, not on
# the one that finally answers 200, and a cookie set on a hop is a cookie the
# browser stores.
#
# The regex requires a `=` before the first `;` or space, which is RFC 6265
# §4.1.1's `cookie-pair` - a `Set-Cookie` with no name/value pair at all sets no
# cookie in any browser and is dropped here rather than reported as a nameless
# one.
cookie_extract_set_cookie() {
  local hdrfile=$1 hits line value
  [[ -n $hdrfile && -r $hdrfile ]] || return 1
  hits=${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cookie-setcookie.$$
  if ! scan_match "$hits" -i -e '^set-cookie:[[:space:]]*[^;[:space:]]+=' -- "$hdrfile"; then
    rm -f "$hits"
    return 1
  fi
  local found=1
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    # SCOURSH_GREP binds `-n` unconditionally (lib/core.sh core_bind_engine), so
    # every hit arrives prefixed `<lineno>:`. Strip that, then the header name.
    # Both strips are non-greedy (`#`, not `##`), so a `:` inside the cookie
    # VALUE - a timestamp, a base64 padding-free token, an `a:b` pair - survives
    # intact; `##` would eat the value up to its last colon.
    line=${line#*:}
    line=${line%$'\r'}
    value=${line#*:}
    value=${value#"${value%%[![:space:]]*}"}
    [[ -n $value ]] || continue
    printf '%s\n' "$value"
    found=0
  done <"$hits"
  rm -f "$hits"
  return "$found"
}

# ---------------------------------------------------------------------------
# 2. The quote-aware `;` split (hazards 1 and 2 above)
# ---------------------------------------------------------------------------
# `cookie_split_attrs VALUE` - sets `_COOKIE_ATTRS` to the `;`-separated parts of
# one Set-Cookie value, splitting only OUTSIDE double quotes and never on a
# comma. Each part is whitespace-trimmed; empty parts are dropped (`a=1;; Secure`
# is two attributes, not three).
#
# Written as an explicit character walk rather than an `IFS=';' read -ra`,
# because IFS splitting has no notion of a quote and is the exact naive
# implementation hazard 2 describes. A Set-Cookie header is bounded at a few
# hundred bytes by every server and proxy in the path, so a per-character loop
# here costs nothing measurable and buys the one property the fast version
# cannot have.
#
# `declare -g` is load-bearing, for the reason modules/dast/engine.sh's phase
# table documents at length: in a real run this library is sourced from inside
# `dast_run_phase`, a function, so a bare `declare -a` would create a local that
# dies with the phase while the sourced-once guard above (a plain assignment,
# and therefore global) would outlive the very thing it guards.
cookie_split_attrs() {
  local value=$1 i c cur='' inq=0
  declare -ga _COOKIE_ATTRS=()
  for (( i = 0; i < ${#value}; i++ )); do
    c=${value:i:1}
    case $c in
      '"')
        inq=$(( 1 - inq ))
        cur+=$c
        ;;
      ';')
        if (( inq )); then
          cur+=$c
        else
          cur=${cur#"${cur%%[![:space:]]*}"}
          cur=${cur%"${cur##*[![:space:]]}"}
          [[ -n $cur ]] && _COOKIE_ATTRS+=("$cur")
          cur=''
        fi
        ;;
      *)
        cur+=$c
        ;;
    esac
  done
  cur=${cur#"${cur%%[![:space:]]*}"}
  cur=${cur%"${cur##*[![:space:]]}"}
  [[ -n $cur ]] && _COOKIE_ATTRS+=("$cur")
  return 0
}

# ---------------------------------------------------------------------------
# 3. The analysis
# ---------------------------------------------------------------------------
# `cookie_parse VALUE` - analyses ONE Set-Cookie header value and sets:
#
#   _COOKIE_NAME            the cookie name ('' when the header sets no cookie)
#   _COOKIE_SECURE          1 when the `Secure` attribute is present, else 0
#   _COOKIE_HTTPONLY        1 when the `HttpOnly` attribute is present, else 0
#   _COOKIE_SAMESITE_STATE  absent | strict | lax | none | unrecognised
#   _COOKIE_SAMESITE_RAW    the attribute value exactly as the server wrote it,
#                           '' when the attribute was absent
#   _COOKIE_PATH            the `Path` attribute value, '' when absent
#
# Returns 1 (and leaves `_COOKIE_NAME` empty) for a header that sets no cookie,
# so a caller skips it rather than emitting a finding about a nameless one.
#
# `unrecognised` is kept DISTINCT from `none` and from `absent`, and is a third
# state rather than being folded into either. `SameSite=Lax; SameSite=Bogus` and
# an empty `SameSite=` are things servers really emit, browsers really do not
# agree on what they mean, and reporting either as `absent` would state that the
# server chose nothing when it chose something unusable - the finding would then
# recommend the wrong fix. The CALLER decides which check id a state maps to
# (cookies.sh maps `none` and `unrecognised` to SAMESITE_WEAK and `absent` to
# SAMESITE_ABSENT); this function only reports what it saw.
cookie_parse() {
  local value=$1 a name lower
  declare -g _COOKIE_NAME='' _COOKIE_PATH='' _COOKIE_SAMESITE_RAW=''
  declare -g _COOKIE_SECURE=0 _COOKIE_HTTPONLY=0 _COOKIE_SAMESITE_STATE=absent

  cookie_split_attrs "$value"
  (( ${#_COOKIE_ATTRS[@]} > 0 )) || return 1

  # The FIRST part is the cookie-pair; every later part is an attribute
  # (RFC 6265 §4.1.1). A first part with no `=` sets no cookie.
  local pair=${_COOKIE_ATTRS[0]}
  [[ $pair == *=* ]] || return 1
  name=${pair%%=*}
  name=${name%"${name##*[![:space:]]}"}
  [[ -n $name ]] || return 1
  _COOKIE_NAME=$name

  local k=1
  for (( k = 1; k < ${#_COOKIE_ATTRS[@]}; k++ )); do
    a=${_COOKIE_ATTRS[k]}
    # Attribute name is everything before the first `=`; the value (if any) is
    # everything after it. Lowercased for the comparison because RFC 6265 §5.2
    # matches attribute names case-insensitively (hazard 3).
    if [[ $a == *=* ]]; then
      lower=${a%%=*}
    else
      lower=$a
    fi
    lower=${lower%"${lower##*[![:space:]]}"}
    lower=${lower,,}
    case $lower in
      # PRESENCE, not value (hazard 4): RFC 6265 §5.2.5 and §5.2.6 both discard
      # the attribute-value, so `Secure=false` is a Secure cookie. Reading the
      # value here would report a flag as missing on a cookie that has it.
      secure) _COOKIE_SECURE=1 ;;
      httponly) _COOKIE_HTTPONLY=1 ;;
      path) [[ $a == *=* ]] && _COOKIE_PATH=${a#*=} ;;
      samesite)
        local sv=''
        [[ $a == *=* ]] && sv=${a#*=}
        _COOKIE_SAMESITE_RAW=$sv
        # Trim, then strip one layer of surrounding double quotes, then fold
        # case: `SameSite="Strict"` and `samesite=strict` are one policy.
        sv=${sv#"${sv%%[![:space:]]*}"}
        sv=${sv%"${sv##*[![:space:]]}"}
        if [[ ${#sv} -ge 2 && ${sv:0:1} == '"' && ${sv: -1} == '"' ]]; then
          sv=${sv:1:${#sv}-2}
        fi
        case ${sv,,} in
          strict) _COOKIE_SAMESITE_STATE=strict ;;
          lax) _COOKIE_SAMESITE_STATE=lax ;;
          none) _COOKIE_SAMESITE_STATE=none ;;
          *) _COOKIE_SAMESITE_STATE=unrecognised ;;
        esac
        ;;
    esac
  done
  return 0
}

# `cookie_looks_session NAME` - 0 when the cookie NAME matches a conventional
# session/authentication cookie name.
#
# THIS CHANGES NO SEVERITY AND GATES NO FINDING. A missing `HttpOnly` is
# reported on every cookie either way, because a scanner cannot know what an
# application keeps in a cookie it did not issue, and letting a name pattern
# suppress a finding would silently drop every custom-named session cookie in
# existence. It is used for ONE thing: a sentence in the evidence telling a
# reader that this particular cookie's name is a conventional session-cookie
# name, so the triage order in a report with forty cookies in it is obvious.
# Severity stays where the check id declares it (rules/RULE-FORMAT.md §9.5), so
# a finding's severity never depends on a heuristic.
cookie_looks_session() {
  local n=${1,,}
  case $n in
    *sess*|*sid|sid|*auth*|*token*|*jwt*|*login*|*remember*|*csrf*|*xsrf*) return 0 ;;
  esac
  return 1
}
