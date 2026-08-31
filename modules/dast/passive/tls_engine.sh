#!/usr/bin/env bash
# modules/dast/passive/tls_engine.sh - the §7.1 transport-security PURE library
# (docs/DESIGN.md §7.1; docs/STEP5-DAST-PLAN.md DAST-07).
#
# The engine.sh / phase-script split modules/sast/ established and every DAST
# phase since has reused: THIS file is a pure function library with the standard
# sourced-once guard and no side effect at source time, and
# modules/dast/passive/tls.sh is the phase script that resolves the live inputs
# and drives it.
#
# NOTHING IN THIS FILE OPENS A SOCKET EXCEPT `_tls_probe_default`.  Every other
# function takes an already-captured `openssl s_client` transcript, or an
# already-captured PEM, as a file and decides something about it.  The handshake
# itself goes through `tls_probe`, a two-line dispatcher onto the swappable
# `SCOURSH_TLS_PROBE` hook - the same idiom lib/http.sh's own
# SCOURSH_HTTP_RESOLVE / SCOURSH_HTTP_TRANSPORT use, and what lets
# tests/suites/dast-tls.sh drive every case from a RECORDED transcript with no
# live target (docs/DESIGN.md §12).
#
# THE TENSION-19 EXEMPTION, STATED HERE BECAUSE THIS IS WHERE IT BITES.
# docs/FOUNDATION.md tension 19 requires every network call to go through
# lib/http.sh's `http_request`; `modules/dast/passive/tls.sh` is the ONE
# documented exception, because what this check needs is a raw TLS handshake and
# a look at the certificate the server presents, which is not an HTTP request
# and cannot be expressed as one.  THE EXEMPTION IS FROM THE TRANSPORT AND FROM
# NOTHING ELSE: the phase still puts the target URL through the identical
# authorization gate, still connects to the address that gate PINNED rather than
# re-resolving the name, and still spends a token of the identical rate limiter,
# per-run request budget and circuit breaker - all via lib/http.sh's
# `http_authorize_raw_connection`, which exists for this one caller.  See that
# function's header and tls.sh's.
#
# LIBRESSL AND OPENSSL DISAGREE, AND EVERY DIVERGENCE THIS FILE HANDLES IS
# NAMED RATHER THAN GUESSED AT.  macOS ships LibreSSL as /usr/bin/openssl; GNU
# hosts ship OpenSSL 1.1/3.x.  The three places their output differs, each with
# the reading that would ship green on one userland and be silently wrong on the
# other:
#
#   1. THE `New, ...` LINE IS NOT THE NEGOTIATED PROTOCOL ON LIBRESSL.  LibreSSL
#      prints `New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384` for a
#      TLS 1.2 session - the literal string `TLSv1/SSLv3` is a family label, not
#      a version.  A check that read it would report every LibreSSL-probed
#      target as speaking TLSv1 and fire the weak-protocol finding on all of
#      them.  `Protocol  :` inside the `SSL-Session:` block is authoritative on
#      BOTH userlands and is what tls_parse_session reads.
#   2. DISTINGUISHED NAMES COME IN TWO SPELLINGS.  OpenSSL 1.1/3.x prints
#      `subject=CN = example.test, O = Example`; LibreSSL and OpenSSL 1.0 print
#      `subject=/O=Example/CN=example.test`.  Comparing the raw strings makes the
#      self-signed test (subject == issuer) userland-dependent, and matching a
#      raw string against a `CN=` prefix finds nothing on the slash form.
#      `tls_dn_normalize` folds both to one `K=V,K=V` form; every comparison in
#      this file is made on the normalized value.
#   3. `openssl x509 -ext subjectAltName` DOES NOT EXIST ON LIBRESSL.  It is an
#      OpenSSL 1.1.1+ flag.  `-text` exists on both, so the SAN list is read out
#      of the certificate's own text dump instead.
#
# All three are pinned in tests/suites/dast-tls.sh against transcripts recorded
# from each userland, and each case names the reading it fails under.
#
# WHICH USERLANDS WERE ACTUALLY RUN, STATED PLAINLY RATHER THAN IMPLIED.  The
# transcripts pin the PARSING of each userland's s_client output and need no
# openssl at all; the `openssl x509` calls in section 5 below read a real
# certificate with whatever `openssl` is on PATH, so they are only as portable
# as the binary that ran them.  tests/suites/dast-tls.sh was therefore run twice
# on one macOS host - once under OpenSSL 3.6.3 and once under the system
# LibreSSL 3.3.6 (/usr/bin/openssl), reporting 131 passed, 0 failed under each.
# What that does NOT establish is a GNU/Linux host: the OpenSSL 3.x leg is a
# Homebrew build on macOS, so it exercises the OpenSSL output shape rather than
# the GNU userland around it.  tools/daily-suite.sh's container leg is what
# covers that, and saying so is better than implying a coverage never bought.
#
# EXPIRY IS DECIDED BY ARITHMETIC THIS FILE OWNS, NOT BY `date`.  `date -d` is
# GNU-only and `date -j -f` is BSD-only, so a portable converter is required
# either way; writing it here rather than shelling out also makes `now`
# INJECTABLE, which is what lets a committed fixture certificate exercise
# `expired`, `expiring` and `ok` deterministically instead of a suite whose
# verdict changes as the calendar moves.  `openssl x509 -checkend` was the
# obvious alternative and was rejected for exactly that: it hardcodes the system
# clock, so "expiring inside the window" could only be tested by minting a
# certificate at test time and "expired" only by committing one and waiting.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_TLS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_TLS_ENGINE_SOURCED=1

# ---------------------------------------------------------------------------
# 1. Time: an ASN.1 validity date to a UTC epoch, in bash
# ---------------------------------------------------------------------------
# `openssl x509 -noout -enddate` prints one shape on every userland this tool
# supports: `notAfter=Jun  1 12:00:00 2024 GMT`, with the day space-padded.
# Both the `notAfter=` prefix and the padding are tolerated here.
_tls_month_num() {
  case ${1,,} in
    jan) printf '%s' 1 ;;
    feb) printf '%s' 2 ;;
    mar) printf '%s' 3 ;;
    apr) printf '%s' 4 ;;
    may) printf '%s' 5 ;;
    jun) printf '%s' 6 ;;
    jul) printf '%s' 7 ;;
    aug) printf '%s' 8 ;;
    sep) printf '%s' 9 ;;
    oct) printf '%s' 10 ;;
    nov) printf '%s' 11 ;;
    dec) printf '%s' 12 ;;
    *) return 1 ;;
  esac
}

# Howard Hinnant's days-from-civil, exact for every proleptic Gregorian date and
# needing no leap-year table and no library.  Every operand reaching the
# arithmetic below has already been fully consumed by an anchored digit-only
# match in tls_time_to_epoch - the same discipline lib/http.sh's numeric-literal
# canonicalization documents, and for the same reason: `$(( ))` expands its
# operand recursively, so a raw target-derived string must never reach it.
_tls_days_from_civil() {
  local y=$1 m=$2 d=$3 era yoe doy doe
  (( m <= 2 )) && y=$(( y - 1 ))
  if (( y >= 0 )); then
    era=$(( y / 400 ))
  else
    era=$(( (y - 399) / 400 ))
  fi
  yoe=$(( y - era * 400 ))
  if (( m > 2 )); then
    doy=$(( (153 * (m - 3) + 2) / 5 + d - 1 ))
  else
    doy=$(( (153 * (m + 9) + 2) / 5 + d - 1 ))
  fi
  doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
  printf '%s' $(( era * 146097 + doe - 719468 ))
}

# `tls_time_to_epoch STR` - print the UTC epoch seconds of an OpenSSL validity
# date, or return 1 having printed nothing.  Returning 1 rather than guessing is
# load-bearing: an unparseable date must become a recorded coverage gap, never
# an epoch of 0, which would render as "expired since 1970" on every finding.
tls_time_to_epoch() {
  local s=$1 mon d hh mm ss yyyy m days
  s=${s#notAfter=}
  s=${s#notBefore=}
  while [[ $s == *"  "* ]]; do s=${s//  / }; done
  s=${s# }
  s=${s%"${s##*[![:space:]]}"}
  if [[ ! $s =~ ^([A-Za-z]{3})\ ([0-9]{1,2})\ ([0-9]{2}):([0-9]{2}):([0-9]{2})\ ([0-9]{4})\ GMT$ ]]; then
    return 1
  fi
  mon=${BASH_REMATCH[1]} d=${BASH_REMATCH[2]}
  hh=${BASH_REMATCH[3]} mm=${BASH_REMATCH[4]} ss=${BASH_REMATCH[5]}
  yyyy=${BASH_REMATCH[6]}
  m=$(_tls_month_num "$mon") || return 1
  days=$(_tls_days_from_civil "$(( 10#$yyyy ))" "$m" "$(( 10#$d ))")
  printf '%s' $(( days * 86400 + 10#$hh * 3600 + 10#$mm * 60 + 10#$ss ))
}

# `tls_expiry_state NOT_AFTER_EPOCH NOW_EPOCH WARN_DAYS` - print one of
# `expired`, `expiring`, `ok`.
#
# BOTH BOUNDARIES ARE `<=`, AND THAT IS A DECISION RATHER THAN AN ACCIDENT.  A
# certificate whose notAfter is exactly now is expired (it is not valid AT this
# instant), and one whose notAfter is exactly the window edge IS reported as
# expiring - a 30-day window that stayed silent on the certificate expiring in
# exactly 30 days is off by one in the direction that loses the warning.  Both
# edges are pinned by a case in tests/suites/dast-tls.sh that fails under `<`.
tls_expiry_state() {
  local not_after=$1 now=$2 warn_days=$3
  if (( not_after <= now )); then
    printf '%s' expired
    return 0
  fi
  if (( not_after - now <= warn_days * 86400 )); then
    printf '%s' expiring
    return 0
  fi
  printf '%s' ok
}

# `tls_days_until NOT_AFTER NOW` - whole days between the two, rounded DOWN and
# never signed; the caller already knows the direction from tls_expiry_state.
tls_days_until() {
  local delta=$(( $1 - $2 ))
  (( delta < 0 )) && delta=$(( -delta ))
  printf '%s' $(( delta / 86400 ))
}

# ---------------------------------------------------------------------------
# 2. Distinguished names
# ---------------------------------------------------------------------------
# `tls_dn_normalize STR` - fold either userland's spelling of a DN to one
# canonical `K=V,K=V` string, attribute order preserved.  See divergence 2 in
# this file's header.
#
# A value containing an escaped comma (`\,`, which OpenSSL 3 emits for a comma
# inside an attribute value) is a STATED limit rather than a silent one: the
# comma-form split treats it as a separator, so such a DN normalizes to more
# components than it has.  That is harmless for both uses this file makes of the
# result - equality of two DNs from the SAME transcript, split the same way, and
# a CN lookup, whose key half never contains a comma - and fixing it properly
# means an RFC 4514 parser, which is not what this check is for.
tls_dn_normalize() {
  local s=$1 out='' part k v
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  # The `Certificate chain` block prefixes each DN with its depth and a `s:` or
  # `i:` role marker (` 0 s:CN = host`).  Both halves are stripped, and the depth
  # is stripped FIRST, because after the leading space is trimmed the role marker
  # is no longer at the start of the string - a plain `${s#s:}` finds nothing
  # there and the depth ends up inside the first attribute key.
  [[ $s =~ ^[0-9]+[[:space:]]+([si]:.*)$ ]] && s=${BASH_REMATCH[1]}
  s=${s#subject=}
  s=${s#issuer=}
  s=${s#subject:}
  s=${s#issuer:}
  s=${s#s:}
  s=${s#i:}
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  [[ -n $s ]] || return 1

  local -a parts=()
  local rest
  if [[ $s == /* ]]; then
    rest=${s#/}
    while [[ -n $rest ]]; do
      if [[ $rest == */* ]]; then
        parts+=("${rest%%/*}")
        rest=${rest#*/}
      else
        parts+=("$rest")
        rest=''
      fi
    done
  else
    local IFS=','
    # shellcheck disable=SC2206
    parts=($s)
    unset IFS
  fi

  for part in "${parts[@]+"${parts[@]}"}"; do
    part=${part#"${part%%[![:space:]]*}"}
    part=${part%"${part##*[![:space:]]}"}
    [[ -n $part ]] || continue
    [[ $part == *=* ]] || continue
    k=${part%%=*}
    v=${part#*=}
    k=${k%"${k##*[![:space:]]}"}
    v=${v#"${v%%[![:space:]]*}"}
    v=${v%"${v##*[![:space:]]}"}
    [[ -n $out ]] && out+=','
    out+="$k=$v"
  done
  [[ -n $out ]] || return 1
  printf '%s' "$out"
}

# `tls_dn_attr NORMALIZED_DN KEY` - print the LAST occurrence of KEY, or return
# 1.  Last, not first: X.509 orders a DN least-specific first, so the entity's
# own CN follows any organisational ones.
tls_dn_attr() {
  local dn=$1 want=$2 part found=''
  local IFS=','
  # shellcheck disable=SC2206
  local -a parts=($dn)
  unset IFS
  for part in "${parts[@]+"${parts[@]}"}"; do
    [[ ${part%%=*} == "$want" ]] && found=${part#*=}
  done
  [[ -n $found ]] || return 1
  printf '%s' "$found"
}

# ---------------------------------------------------------------------------
# 3. The s_client transcript
# ---------------------------------------------------------------------------
# `tls_parse_session TRANSCRIPT_FILE` - read the negotiated session facts out of
# an `openssl s_client` transcript.  SETS variables rather than printing them,
# because there are six and because a `$(...)` call would put every one of them
# in a subshell (lib/core.sh's `occurrence_next` lesson, one level up):
#
#   _TLS_PROTOCOL      e.g. TLSv1.3, or '' when the handshake produced none
#   _TLS_CIPHER        e.g. TLS_AES_256_GCM_SHA384
#   _TLS_VERIFY_CODE   the numeric `Verify return code`, or ''
#   _TLS_VERIFY_TEXT   its parenthesised text, or ''
#   _TLS_SUBJECT       normalized subject DN, or ''
#   _TLS_ISSUER        normalized issuer DN, or ''
#
# Returns 1 when the transcript records no session at all (a refused connection,
# a handshake failure), with every variable left empty - so a caller can tell
# "the target speaks no TLS here" from "it does, and here is what it negotiated",
# and a failed handshake never reads as a clean transport.
tls_parse_session() {
  local file=$1 line v
  _TLS_PROTOCOL='' _TLS_CIPHER='' _TLS_VERIFY_CODE='' _TLS_VERIFY_TEXT=''
  _TLS_SUBJECT='' _TLS_ISSUER=''
  [[ -r $file ]] || return 1

  while IFS= read -r line || [[ -n $line ]]; do
    case $line in
      # Anchored on the SSL-Session block's spelling, never on the `New, ...`
      # line - divergence 1 in this file's header.
      *Protocol*:*)
        [[ $line =~ Protocol[[:space:]]*:[[:space:]]*([^[:space:]]+) ]] || continue
        v=${BASH_REMATCH[1]}
        [[ -z $_TLS_PROTOCOL ]] && _TLS_PROTOCOL=$v
        ;;
      *Cipher*:*)
        [[ $line =~ Cipher[[:space:]]*:[[:space:]]*([^[:space:]]+) ]] || continue
        v=${BASH_REMATCH[1]}
        # OpenSSL prints `Cipher    : 0000` for a session that never completed.
        [[ $v == 0000 ]] && continue
        [[ -z $_TLS_CIPHER ]] && _TLS_CIPHER=$v
        ;;
      *'Verify return code:'*)
        [[ $line =~ Verify\ return\ code:[[:space:]]*([0-9]+)[[:space:]]*\((.*)\) ]] || continue
        _TLS_VERIFY_CODE=${BASH_REMATCH[1]}
        _TLS_VERIFY_TEXT=${BASH_REMATCH[2]}
        ;;
      subject=* | 'subject: '*)
        [[ -n $_TLS_SUBJECT ]] || _TLS_SUBJECT=$(tls_dn_normalize "$line" || printf '')
        ;;
      issuer=* | 'issuer: '*)
        [[ -n $_TLS_ISSUER ]] || _TLS_ISSUER=$(tls_dn_normalize "$line" || printf '')
        ;;
    esac
  done <"$file"

  # A COMPLETED SESSION IS ONE WITH A CIPHER, NOT ONE WITH A PROTOCOL.  On a
  # handshake that failed - a TLS alert, a version or suite with no overlap -
  # openssl still prints an `SSL-Session:` block, still fills in `Protocol  :`
  # with the version it OFFERED, and prints `Cipher    : 0000`.  A caller that
  # accepted a protocol alone would therefore treat every failed handshake as a
  # session, report the offered version as negotiated, and - since 0000 is
  # skipped above - go on to report `cipher=unknown` for a connection that
  # agreed on nothing.  Requiring the cipher is what makes "the target speaks no
  # TLS here" and "it does, and here is what it negotiated" two different
  # answers.  Pinned by the handshake-failure transcript in
  # tests/suites/dast-tls.sh, which fails under the `||` reading.
  [[ -n $_TLS_CIPHER ]] || return 1
  return 0
}

# `tls_extract_pem TRANSCRIPT_FILE OUT_FILE` - write the FIRST PEM certificate in
# the transcript (the leaf: `s_client -showcerts` prints the chain leaf-first) to
# OUT_FILE.  Returns 1 and leaves OUT_FILE empty when there is none.
#
# THE LEAF IS THE ONLY CERTIFICATE THIS CHECK REASONS ABOUT.  An intermediate
# being self-signed is normal (a root is, by definition), and an intermediate's
# SANs are not the names a client validates the hostname against - so widening
# this to the chain would put a self-signed finding on every correctly
# configured target that happens to send its root.
tls_extract_pem() {
  local file=$1 out=$2 line inside=0 got=0
  [[ -r $file ]] || return 1
  : >"$out"
  while IFS= read -r line || [[ -n $line ]]; do
    if (( ! inside )); then
      [[ $line == '-----BEGIN CERTIFICATE-----' ]] || continue
      inside=1
      printf '%s\n' "$line" >>"$out"
      continue
    fi
    printf '%s\n' "$line" >>"$out"
    if [[ $line == '-----END CERTIFICATE-----' ]]; then
      got=1
      break
    fi
  done <"$file"
  if (( ! got )); then
    : >"$out"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. The certificate itself
# ---------------------------------------------------------------------------
# These shell out to `openssl x509`, which reads a LOCAL file and opens no
# socket.  The tension-19 exemption is not what permits them, and the no-bypass
# lint's pattern is `openssl[[:space:]]+s_client` for exactly that reason.
#
# `tls_cert_text PEM_FILE` - the certificate's text dump on stdout, or return 1.
tls_cert_text() {
  local pem=$1
  [[ -s $pem ]] || return 1
  openssl x509 -in "$pem" -noout -text 2>/dev/null
}

# `tls_cert_enddate PEM_FILE` - the raw `notAfter` value, or return 1.
tls_cert_enddate() {
  local pem=$1 out
  [[ -s $pem ]] || return 1
  out=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null) || return 1
  [[ -n $out ]] || return 1
  printf '%s' "${out#notAfter=}"
}

# `tls_cert_dn PEM_FILE subject|issuer` - the NORMALIZED DN, or return 1.
tls_cert_dn() {
  local pem=$1 which=$2 out
  [[ -s $pem ]] || return 1
  out=$(openssl x509 -in "$pem" -noout "-$which" 2>/dev/null) || return 1
  tls_dn_normalize "$out"
}

# `tls_sans_from_text` - read a certificate text dump on STDIN and print one
# dNSName per line, lowercased.  See divergence 3: `-ext subjectAltName` is not
# portable, `-text` is.
#
# The SAN values sit on the line AFTER the extension's own header line, which is
# why this is a two-state walk rather than one pattern match.
tls_sans_from_text() {
  local line want=0 part lower
  local -a parts=()
  while IFS= read -r line || [[ -n $line ]]; do
    if (( want )); then
      want=0
      local IFS=','
      # shellcheck disable=SC2206
      parts=($line)
      unset IFS
      for part in "${parts[@]+"${parts[@]}"}"; do
        part=${part#"${part%%[![:space:]]*}"}
        part=${part%"${part##*[![:space:]]}"}
        [[ $part == DNS:* ]] || continue
        lower=${part#DNS:}
        printf '%s\n' "${lower,,}"
      done
      continue
    fi
    [[ $line == *'X509v3 Subject Alternative Name:'* ]] && want=1
  done
  return 0
}

# `tls_is_wildcard NAME` - 0 when NAME is a wildcard DNS name.
#
# ONLY A LEADING LABEL COUNTS.  RFC 6125 §6.4.3 places the wildcard in the
# left-most label and nowhere else, so `a.*.example.test` is not a wildcard
# certificate - it is a name no conformant client matches at all.  A substring
# test for `*` would call it one and report a wildcard finding on a target whose
# real problem is a different one.
tls_is_wildcard() {
  [[ $1 == '*.'* ]]
}

# `tls_protocol_is_weak PROTO` - 0 for a protocol version deprecated for every
# use (RFC 8996 deprecates TLS 1.0 and 1.1; SSL 2 and 3 are broken).  TLS 1.2 and
# 1.3 return 1.
#
# It fails CLOSED in the direction that matters: an UNRECOGNISED string is NOT
# reported weak, because the alternative - reporting a version this table has
# not learned about yet as broken - puts a false high-severity finding on every
# target that negotiates the next TLS version before this table is updated.  The
# unknown case becomes a recorded coverage gap in tls.sh instead of a finding.
tls_protocol_is_weak() {
  case $1 in
    SSLv2 | SSLv3 | TLSv1 | TLSv1.0 | TLSv1.1) return 0 ;;
    *) return 1 ;;
  esac
}

# `tls_protocol_is_known PROTO` - 0 for a version this table has an opinion
# about, either way.  Separate from the predicate above so "modern" and "we have
# never heard of it" are two different answers rather than one.
tls_protocol_is_known() {
  case $1 in
    SSLv2 | SSLv3 | TLSv1 | TLSv1.0 | TLSv1.1 | TLSv1.2 | TLSv1.3) return 0 ;;
    *) return 1 ;;
  esac
}

# `tls_cipher_is_weak CIPHER` - 0 for a cipher suite with a broken or absent
# primitive, in either OpenSSL's own suite spelling (ECDHE-RSA-AES256-SHA) or the
# IANA one (TLS_AES_256_GCM_SHA384), since a target may be probed from either
# userland and the two name the same suites differently.
#
# The list is the union of: no encryption at all (NULL), export-grade key sizes,
# single DES and 40/56-bit RC2/RC4, RC4 at any size (RFC 7465), MD5 as the MAC,
# anonymous key exchange (aNULL/ADH/AECDH, which has no authentication), and
# 3DES, which is Sweet32-vulnerable and removed from TLS 1.3 entirely.
tls_cipher_is_weak() {
  local c=${1^^}
  case $c in
    *NULL* | *EXPORT* | EXP-* | *-EXP-* | *ANON* | ADH-* | AECDH-*) return 0 ;;
    *RC4* | *RC2* | *MD5*) return 0 ;;
    *3DES* | *DES-CBC3*) return 0 ;;
    DES-* | *-DES-* | *DES40*) return 0 ;;
    *IDEA* | *SEED*) return 0 ;;
    *) return 1 ;;
  esac
}

# `tls_verify_is_self_signed CODE` - 0 for the two OpenSSL verify codes that mean
# exactly "self-signed", and nothing else:
#
#   18  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT   the leaf signed itself
#   19  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN     a self-signed root not in the
#                                                trust store
#
# 20 (unable to get local issuer certificate) and 21 (unable to verify the first
# certificate) are DELIBERATELY ABSENT.  They mean the verifier could not build a
# chain, which a self-signed certificate produces and so does a perfectly
# ordinary server that simply did not send its intermediates - two different
# defects with two different fixes, and calling the second one "self-signed"
# sends the operator to replace a certificate that is fine.
tls_verify_is_self_signed() {
  [[ $1 == 18 || $1 == 19 ]]
}

# `tls_is_self_signed SUBJECT ISSUER VERIFY_CODE` - 0 when the LEAF is
# self-signed.  Both signals are consulted and either suffices, because each
# alone has a real hole: the verify code is absent from a transcript captured
# without a trust store, and subject==issuer is also true of a legitimate root CA
# certificate - which tls_extract_pem already excludes by only ever looking at
# the leaf.
tls_is_self_signed() {
  local subject=$1 issuer=$2 code=$3
  if [[ -n $code ]] && tls_verify_is_self_signed "$code"; then
    return 0
  fi
  [[ -n $subject && $subject == "$issuer" ]]
}

# ---------------------------------------------------------------------------
# 5. The one place a handshake happens
# ---------------------------------------------------------------------------
# `tls_probe ADDR PORT SERVERNAME TIMEOUT_S OUT_FILE` - capture one
# `openssl s_client` transcript into OUT_FILE.  Non-zero when none was captured.
#
# ADDR is the address lib/http.sh's gate ALREADY RESOLVED AND PINNED, never a
# hostname: re-resolving here would be a second lookup the gate never saw, which
# is precisely the DNS-rebinding hole tension 19's resolution pinning closes.
# SERVERNAME is the hostname, and it travels in SNI only.
#
# SCOURSH_TLS_PROBE names a function or an executable taking the same five
# arguments, and is how tests/suites/dast-tls.sh replays a RECORDED transcript
# instead of dialling anything (docs/DESIGN.md §12).  It is the SCOURSH_HTTP_*
# hook idiom, kept identical so there is one convention to know rather than two.
tls_probe() {
  "${SCOURSH_TLS_PROBE:-_tls_probe_default}" "$@"
}

# THE TRANSCRIPT SIZE CAP (CWE-400).  A real transcript - the committed
# fixtures under tests/fixtures/dast/tls/ are 25-80 lines, a few KB at most -
# is a chain of certificates plus a handful of session/verify lines.  This is
# two orders of magnitude above the largest legitimate one, so it never
# truncates a real handshake, while bounding what an authorised-but-hostile
# listener can make the scanner buffer: `s_client` writes to OUT_FILE whatever
# it receives, and a listener that accepts the connection and simply streams
# bytes instead of completing a handshake - or completes one and then floods
# post-handshake application data, which `s_client` decrypts and prints - was
# previously bounded on TIME alone (`timeout_s` below) and not on BYTES, so a
# fast link could park gigabytes in the scanner's scratch directory (and, per
# config/scanner.conf.example's own tmpfs recommendation, in memory) for the
# whole watchdog window.  Not a config/scanner.conf key: this is an
# implementation ceiling, not an operator policy, per this ticket's own
# instruction to keep the surface small.
_TLS_TRANSCRIPT_CAP_BYTES=262144

# THE ONE `openssl s_client` IN THE WHOLE TOOL.  tests/lint-shell.sh's tension-19
# no-bypass check exempts this file and modules/dast/passive/tls.sh BY PATH and
# nothing else; a second one anywhere fails the build.
#
# The flags, each because it is needed rather than because it is conventional:
#   -connect ADDR:PORT    the pinned address, see above.
#   -servername HOST      SNI, so a name-based virtual host presents ITS
#                         certificate rather than the default one; without it
#                         every vhost is assessed against a certificate no real
#                         client would ever receive.
#   -showcerts            the chain in PEM, which is where the leaf comes from.
#   </dev/null            s_client reads stdin and would otherwise sit forever
#                         waiting for application data.
# `-verify_return_error` is omitted DELIBERATELY: a verification failure must
# still produce a transcript, because the failure IS the finding.  `-brief` is
# not used either - it is OpenSSL-only and omits the `Verify return code` line
# this check reads.
#
# THE TIMEOUT IS A BASH WATCHDOG, NOT `timeout(1)` AND NOT AN OPENSSL FLAG.
# `timeout(1)` is GNU coreutils and is absent from a stock macOS, and neither
# userland's `s_client` has a portable connect timeout (`-timeout` is DTLS-only).
# Without one, a target that accepts a connection and never completes the
# handshake parks the whole run indefinitely - and unlike an http_request, no
# curl `--max-time` is standing behind this call.
#
# THE SAME LOOP ALSO ENFORCES THE BYTE CAP (CWE-400), REUSING THE KILL PATH
# THAT WAS ALREADY THERE.  Each 100ms tick now checks OUT_FILE's size as well
# as the clock, and `kill -TERM`s on either overrun - no pipeline, no new
# exit-status interaction with the existing "non-zero exit is not failure on
# its own" logic below.  Killing mid-write leaves a NON-EMPTY, truncated
# transcript, which is deliberately treated exactly like a timeout kill: this
# function still returns 0, and it is `tls_parse_session` in this same file
# that decides whether what was captured amounts to a completed session.  A
# listener that streams garbage instead of ever completing a handshake never
# gets as far as an `SSL-Session:`/`Cipher` block within the cap, so
# tls_parse_session fails exactly as it does for a genuine handshake failure,
# and modules/dast/passive/tls.sh's existing `tls_handshake_failed`
# coverage_reduction/coverage_gap path is what reports it - never a silent
# clean result.  A listener that completes a real handshake and THEN floods
# post-handshake data is unaffected: the session block lands in the transcript
# long before the cap, and only trailing garbage is cut.
_tls_probe_default() {
  local addr=$1 port=$2 servername=$3 timeout_s=$4 out=$5
  local pid waited=0 limit_ms rc=0 size
  [[ $timeout_s =~ ^[0-9]+$ ]] || timeout_s=20
  limit_ms=$(( timeout_s * 1000 ))
  [[ $addr == *:* && $addr != \[* ]] && addr="[$addr]"
  : >"$out"

  openssl s_client -connect "$addr:$port" -servername "$servername" \
    -showcerts </dev/null >"$out" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= limit_ms )); then
      kill -TERM "$pid" 2>/dev/null || true
      break
    fi
    size=$(wc -c <"$out" 2>/dev/null) || size=0
    size=${size//[[:space:]]/}
    [[ $size =~ ^[0-9]+$ ]] || size=0
    if (( size >= _TLS_TRANSCRIPT_CAP_BYTES )); then
      kill -TERM "$pid" 2>/dev/null || true
      break
    fi
    msleep 100
    waited=$(( waited + 100 ))
  done
  wait "$pid" || rc=$?

  # A non-zero exit is NOT failure on its own: openssl exits non-zero whenever
  # verification failed, which is exactly the case this check exists to report.
  # An empty transcript is the real failure.
  [[ -s $out ]] || return "$(( rc == 0 ? 1 : rc ))"
  return 0
}
