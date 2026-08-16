#!/usr/bin/env bash
# modules/dast/jwt_engine.sh - the DAST JWT check's pure function library
# (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-26).
#
# WHAT THIS FILE IS.  Every piece of DAST-26 that can be exercised with no
# network: base64url, JWT decode, the four token forgeries (alg:none,
# empty-secret HS256, bounded/vendored weak-secret HS256, RS->HS confusion), the
# bounded weak-secret loader, the non-destructive replay ORACLE, and the finding
# emission.  modules/dast/jwt.sh is the phase script that resolves the two live
# inputs - a sample token and a protected endpoint - and drives this file; it is
# the part that needs a target, and this is the part a mocked suite can pin in
# full (the sast/engine.sh + sast/run.sh split, one level down, exactly as
# auth_engine.sh / auth.sh already did for DAST-03).
#
# THE POSTURE THIS CHECK SHIPS UNDER (docs/STEP5-DAST-PLAN.md DAST-36).
#   * The weak-secret list is a BOUNDED, VENDORED file (jwt-weak-secrets.txt).
#     No flag enlarges it; this is weak-key detection, not a cracking rig.  See
#     that file's own header for the full statement.
#   * Every request goes through lib/http.sh's `http_request` (tension 19's one
#     chokepoint), so the rate limiter, the per-run request budget, the circuit
#     breaker and DAST-32's ceilings all bind these probes.  A forged token is
#     sent to a protected endpoint and NEVER persisted or reused beyond the
#     single probe (docs/DESIGN.md §7.4's own "never persist or reuse the forged
#     token beyond the single probe").
#   * It is DETECTION, not exploitation: it proves the weakness by a signal (a
#     protected resource answering success to a token it should have rejected)
#     and reads only.  Every probe is a re-play of the SAME claims the sample
#     token already carried, so no privilege is escalated and no data is
#     written.  The phase restricts the replay to an idempotent method
#     (GET/HEAD), so a "protected endpoint" that is a mutation is skipped rather
#     than exercised.
#
# THE ORACLE, STATED ONCE HERE BECAUSE IT IS THE WHOLE CORRECTNESS ARGUMENT.
# A forged token being "accepted" is only meaningful if the endpoint would have
# REJECTED an invalid one, so `jwt_run` establishes that first:
#   1. the real sample token must be accepted (2xx) - else it is not a valid
#      credential for this endpoint and cannot anchor anything;
#   2. a well-formed-but-wrong-signature token (same header and payload, signed
#      with a key the server cannot hold) must be REJECTED.
# If (2) is instead accepted, the endpoint does not verify signatures at all -
# a strictly stronger finding (DAST-JWT-SIG_NOT_VERIFIED-01) that subsumes the
# per-variant probes, so those are not run and cannot produce a spray of
# lower-severity duplicates of the same root cause.  Only when a bad signature
# is genuinely rejected is "the server accepted THIS forgery" a real finding.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_JWT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_JWT_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint every probe goes through.  Sourced only when an
# outer caller has not already done so - scan.sh sources it at top level before
# `scan_dispatch`, so in a real run this is a no-op, and the conditional is what
# lets tests/suites/dast-jwt.sh source THIS file on its own.  The same shape,
# and the same reason, as modules/dast/auth_engine.sh's own guard.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# ---------------------------------------------------------------------------
# 1. base64url (RFC 7515 §2), routed through `openssl base64`
# ---------------------------------------------------------------------------
# `openssl base64` rather than the `base64` command on purpose: the GNU coreutils
# `base64` decodes with `-d` and the BSD/macOS one with `-D`, and this codebase
# runs the whole suite under both userlands (tools/daily-suite.sh).  `openssl
# base64 -A` (encode) and `openssl base64 -d -A` (decode) behave identically
# across LibreSSL and OpenSSL, measured on this repository's own hosts, and
# openssl is already this check's declared `requires-cmd`, so it adds no new
# dependency.  `-A` keeps the whole payload on one line, without which openssl
# wraps at 64 columns and re-inserts newlines a base64url value must not carry.
#
# `tr` handles the alphabet swap (+/ <-> -_) and `tr -d '='` the padding; both
# are POSIX and portable.  Neither is in tension 24's one-capability-layer list.

# `jwt_b64url_encode` - reads RAW BYTES on stdin, prints base64url with no '='
# padding and no trailing newline.
jwt_b64url_encode() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# `jwt_b64url_decode VALUE` - prints the RAW BYTES VALUE decodes to.  Re-pads to
# a multiple of four before decoding, because base64url drops '=' and openssl
# needs it back.  A value of length %4 == 1 is not valid base64 and decodes to
# nothing rather than to garbage.
jwt_b64url_decode() {
  local v=$1 pad='' m
  v=${v//-/+}
  v=${v//_//}
  m=$(( ${#v} % 4 ))
  case $m in
    2) pad='==' ;;
    3) pad='=' ;;
    1) return 0 ;;
  esac
  printf '%s%s' "$v" "$pad" | openssl base64 -d -A 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 2. Reading a JWT
# ---------------------------------------------------------------------------
# A compact JWS is `header.payload.signature`, three base64url segments joined by
# dots (RFC 7515 §3.1).  These helpers SET variables rather than printing them so
# a caller in an `if` cannot lose the result to a subshell, the lesson
# lib/core.sh's `worker_id_set` records.

# `jwt_split TOKEN` - sets `_JWT_HEADER_B64` `_JWT_PAYLOAD_B64` `_JWT_SIG_B64` to
# the three raw segments, and `_JWT_SIGNING_INPUT` to `header.payload` (the exact
# bytes a signature covers).  Returns 1 unless the token has exactly two dots and
# a non-empty header and payload.  A `none` token has an EMPTY signature segment,
# which is valid, so the signature alone is allowed to be empty.
jwt_split() {
  local t=$1 rest
  _JWT_HEADER_B64='' _JWT_PAYLOAD_B64='' _JWT_SIG_B64='' _JWT_SIGNING_INPUT=''
  # Exactly two dots: three fields.  A token with more dots is not a compact JWS.
  [[ $t == *.*.* && $t != *.*.*.* ]] || return 1
  _JWT_HEADER_B64=${t%%.*}
  rest=${t#*.}
  _JWT_PAYLOAD_B64=${rest%%.*}
  _JWT_SIG_B64=${rest#*.}
  [[ -n $_JWT_HEADER_B64 && -n $_JWT_PAYLOAD_B64 ]] || return 1
  _JWT_SIGNING_INPUT=$_JWT_HEADER_B64.$_JWT_PAYLOAD_B64
  return 0
}

# `jwt_json_str_field JSON NAME` - the value of a top-level string member NAME,
# printed, or empty if absent.  A purpose-built reader for the ONE shape this
# check needs (a JWT header's `alg`/`typ`), never a general JSON parser - the
# same stated-scope choice modules/sca/engine.sh and modules/dast/crawl_engine.sh
# both make.  Matched in-process with bash's `=~`, not a bare grep, so tension 4
# rule 2 does not apply (it governs grep/rg over files).  The class is written
# with POSIX bracket expressions only, because bash on macOS/BSD supports none of
# `\s`/`\w` (AGENTS.md's "measured on this codebase").
jwt_json_str_field() {
  local json=$1 name=$2
  local re="\"$name\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
  if [[ $json =~ $re ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

# `jwt_alg_of TOKEN` - prints the token's declared `alg`, or empty.  This is the
# ATTACKER-CONTROLLED header field the whole family of attacks turns on: it is
# read to decide whether RS->HS confusion is even applicable, never trusted as a
# statement of how the token was really signed.
jwt_alg_of() {
  local t=$1
  jwt_split "$t" || return 0
  jwt_json_str_field "$(jwt_b64url_decode "$_JWT_HEADER_B64")" alg
}

# `jwt_is_jwt TOKEN` - 0 when TOKEN parses as a compact JWS whose header decodes
# to JSON declaring an `alg`.  The gate the phase uses before doing anything: a
# session token that is an opaque random string, or a reference token, is not a
# JWT and this whole check does not apply to it (and must not report as though it
# had run against one).
jwt_is_jwt() {
  local t=$1 hdr
  jwt_split "$t" || return 1
  hdr=$(jwt_b64url_decode "$_JWT_HEADER_B64")
  [[ $hdr == '{'*'}' ]] || return 1
  [[ -n $(jwt_json_str_field "$hdr" alg) ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# 3. Forging header variants
# ---------------------------------------------------------------------------
# `jwt_header_with_alg HEADER_JSON ALG` - HEADER_JSON with its `alg` member's
# value replaced by ALG, every other member preserved.  Preserving `kid`, `typ`
# and any other header claim is deliberate: a server that keys signature
# verification on `kid`, or rejects a missing `typ`, must see the same header it
# would from a genuine token, so the ONLY thing the forgery changes is the one
# field under test.  When the original header carries no `alg` string member (it
# always should, but a malformed token must not crash the check) a minimal
# `{"alg":"<ALG>","typ":"JWT"}` is emitted instead.
jwt_header_with_alg() {
  local json=$1 alg=$2 re
  # The `.*` on both ends is what carries the text SURROUNDING the match, which
  # BASH_REMATCH's group captures alone would drop: group 1 is everything up to
  # and including the opening quote of the alg value, group 2 is the closing
  # quote to end of string, so the whole header is reconstructed with only the
  # value between them replaced.  The leading `.*` is greedy and would bind the
  # LAST `"alg"` were there two, but a JWS header has exactly one.
  re='^(.*"alg"[[:space:]]*:[[:space:]]*")[^"]*(".*)$'
  if [[ $json =~ $re ]]; then
    printf '%s%s%s' "${BASH_REMATCH[1]}" "$alg" "${BASH_REMATCH[2]}"
    return 0
  fi
  printf '{"alg":"%s","typ":"JWT"}' "$alg"
}

# ---------------------------------------------------------------------------
# 4. Signing (HS256), and the forged tokens
# ---------------------------------------------------------------------------
# HMAC-SHA256 through `openssl dgst`, which both LibreSSL and OpenSSL support in
# this exact spelling (measured on this repository's hosts).
#
# THE KEY IS ON argv, AND THAT DOES NOT VIOLATE tension 9.  tension 9 forbids a
# SECRET reaching argv or disk.  Every key this function is ever called with is
# PUBLIC by construction: the empty string, a word from the vendored public
# weak-secret list, or - for RS->HS confusion - the target's own PUBLIC key,
# which is public by definition.  The operator's real credential and the sample
# token itself never pass through here; the token travels only inside a curl
# config piped over stdin by lib/http.sh (tension 9 handling rules 1 and 2).
# openssl offers no stdin-key channel for `dgst -hmac`, so argv is the only
# option, and it is a safe one precisely because nothing secret is ever the key.
#
# The signing input is piped on STDIN (not argv), because it is `header.payload`
# and, while not itself a secret, a fork to pass it would be a fork this does not
# need.  `printf '%s'` never appends a newline, which a signature must not cover.

# `jwt_hs256_sign SIGNING_INPUT KEY` - prints base64url(HMAC-SHA256(KEY,
# SIGNING_INPUT)), the third segment of an HS256 JWS.
jwt_hs256_sign() {
  local input=$1 key=$2
  printf '%s' "$input" \
    | openssl dgst -sha256 -hmac "$key" -binary \
    | jwt_b64url_encode
}

# `jwt_forge_alg_none TOKEN SPELLING` - the classic unsigned-token bypass: the
# header's `alg` is set to SPELLING (a case variant of "none"), the payload is
# unchanged, and the signature segment is EMPTY, yielding `header.payload.`
# (RFC 7515 §3.1's trailing dot with no signature).  The payload is deliberately
# left as-is: the proof is "the server accepted an unsigned token bearing these
# claims", not "the server accepted claims we escalated" - the latter would be
# exploitation, which §7.4 forbids.
jwt_forge_alg_none() {
  local t=$1 spelling=$2 hdr new_hdr
  jwt_split "$t" || return 1
  hdr=$(jwt_b64url_decode "$_JWT_HEADER_B64")
  new_hdr=$(jwt_header_with_alg "$hdr" "$spelling")
  printf '%s.%s.' "$(printf '%s' "$new_hdr" | jwt_b64url_encode)" "$_JWT_PAYLOAD_B64"
}

# `jwt_forge_hs256 TOKEN KEY` - re-sign the token as HS256 with KEY.  The header
# is rewritten to `alg:HS256` (this is the RS->HS downgrade when the original was
# asymmetric, and a straight re-sign when it was already HS*), the payload is
# unchanged, and the signature is a real HMAC over the new signing input.  KEY is
# the empty string for the empty-secret check, a vendored word for the weak-key
# check, or the target's public-key bytes for algorithm confusion.
jwt_forge_hs256() {
  local t=$1 key=$2 hdr new_hdr new_input new_payload
  jwt_split "$t" || return 1
  hdr=$(jwt_b64url_decode "$_JWT_HEADER_B64")
  new_hdr=$(jwt_header_with_alg "$hdr" HS256)
  new_payload=$(printf '%s' "$new_hdr" | jwt_b64url_encode)
  new_input=$new_payload.$_JWT_PAYLOAD_B64
  printf '%s.%s' "$new_input" "$(jwt_hs256_sign "$new_input" "$key")"
}

# `jwt_sig_tampered TOKEN` - the ORACLE CONTROL: the original header and payload,
# with a well-formed-but-wrong signature computed under a key the server cannot
# possibly hold.  A conformant server rejects it (the signature does not verify);
# a server that accepts it is not verifying signatures at all.  Using a real HMAC
# under a fixed nonsense key rather than a random string keeps the segment a
# valid base64url signature shape, so the rejection is "signature is wrong", not
# "signature is malformed" - the two can produce different status codes and only
# the first is the oracle this check needs.
jwt_sig_tampered() {
  local t=$1
  jwt_split "$t" || return 1
  printf '%s.%s' "$_JWT_SIGNING_INPUT" \
    "$(jwt_hs256_sign "$_JWT_SIGNING_INPUT" 'scoursh-oracle-control-not-a-real-signing-key')"
}

# ---------------------------------------------------------------------------
# 5. The bounded, vendored weak-secret list (DAST-36)
# ---------------------------------------------------------------------------
# `jwt_weak_secrets_load [FILE]` - fills `_JWT_WEAK_SECRETS` from the vendored
# list, skipping comment (`#`) and empty lines and taking every other line
# VERBATIM.  Default path is jwt-weak-secrets.txt beside this file; FILE is a
# parameter only so the test suite can point it at a fixture, exactly as
# tests/lint-shell.sh's SCAN_ROOT override does - there is deliberately no CLI
# flag, env var or config key that repoints it in a real run, which is what makes
# "no flag enlarges the list" (DAST-36) structural rather than a promise.
#
# Read with `while read`, never `mapfile` (tension 4 rule 4), and the file is
# read from disk with no network anywhere near it.
declare -ga _JWT_WEAK_SECRETS=()
jwt_weak_secrets_load() {
  local file=${1:-${BASH_SOURCE[0]%/*}/jwt-weak-secrets.txt} line
  _JWT_WEAK_SECRETS=()
  [[ -r $file ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ ${line:0:1} == '#' ]] && continue
    [[ -z $line ]] && continue
    _JWT_WEAK_SECRETS+=("$line")
  done <"$file"
  (( ${#_JWT_WEAK_SECRETS[@]} > 0 ))
}

# ---------------------------------------------------------------------------
# 6. The replay probe
# ---------------------------------------------------------------------------
# `jwt_probe TARGET METHOD URL TOKEN [HEADER_NAME] [SCHEME]` - send ONE request
# carrying TOKEN and set `_JWT_PROBE_STATUS` to the HTTP status (empty on a
# transport-level failure).  The token is presented exactly as a genuine session
# would present it - `Authorization: Bearer <token>` by default, or the
# operator's own header/scheme when the session used a different one - so the
# server sees a request indistinguishable from a real one except for the token's
# contents, which is the whole point.
#
# EVERYTHING SAFE ABOUT THIS CHECK CONVERGES ON THIS ONE FUNCTION.  It goes
# through `http_request`, so the scope gate, the rate limiter, the per-run budget,
# the breaker and DAST-32's ceilings all apply; the token rides in a header set
# through `http_request_header`, which serialises it into a curl config on stdin
# and never to argv or disk (tension 9); and the response body is DISCARDED (no
# capture sink is set), because this check reads a status code, not content, so a
# forged token's response - which may echo the very claims that make it
# dangerous - is never written anywhere.
jwt_probe() {
  local target=$1 method=$2 url=$3 token=$4
  local header=${5:-Authorization} scheme=${6:-Bearer}
  _JWT_PROBE_STATUS=''
  http_request_reset
  if [[ -n $scheme ]]; then
    http_request_header "$header" "$scheme $token"
  else
    http_request_header "$header" "$token"
  fi
  # A transport-level failure (breaker open, budget spent, resolution) is not an
  # acceptance and must never read as one; leave the status empty and let the
  # caller treat "no status" as "not accepted".
  http_request "$method" "$url" 0 "$target" || return 1
  _JWT_PROBE_STATUS=$_HTTP_LAST_STATUS
  return 0
}

# `jwt_status_is_success STATUS` - 0 for a 2xx.  Acceptance of a FORGED token is
# only ever asserted after the oracle has shown a bad signature is rejected, so a
# 2xx here means "the server treated this forgery as a valid credential".
jwt_status_is_success() {
  [[ $1 == 2[0-9][0-9] ]]
}

# ---------------------------------------------------------------------------
# 7. Emitting a finding
# ---------------------------------------------------------------------------
# One helper, so every JWT finding carries the same DAST location profile
# (tension 5: target, method, path_template, param_location, param_name) and the
# per-check id, title and severity are the only things that vary.  The JWT always
# travels in the request's `Authorization` header, so param_location is `header`
# and param_name is the header the session used - which is what makes two
# findings on one endpoint under two different weaknesses distinct (their
# check_id differs) while the same weakness on two endpoints is also distinct
# (their path_template differs).
#
# Evidence is the ONE actionable sentence, set through `finding_set_evidence` so
# it is redacted, truncated and control-stripped (tension 9/10).  It never
# contains the forged token or the response body: the token is a working forgery
# and the body may echo the claims, so neither belongs in an artifact.  The weak
# secret IS named, because it is a public dictionary word and naming which one
# signed the token is the actionable remediation, not a disclosure.
jwt_emit_finding() {
  local check_id=$1 title=$2 severity=$3 target=$4 method=$5 path=$6
  local param_name=$7 evidence=$8 remediation=$9

  finding_new
  finding_set check_id "$check_id"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$severity"
  finding_set confidence high
  finding_set cwe CWE-347
  finding_set owasp A02:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data true
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location header
  finding_set loc_param_name "$param_name"
  finding_set remediation "$remediation"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# 8. The whole check, driven by the phase (docs/DESIGN.md §7.4)
# ---------------------------------------------------------------------------
# `jwt_run TARGET METHOD URL BASE_TOKEN [HEADER_NAME] [SCHEME] [PUBKEY_FILE]`
#
# Sets `_JWT_RUN_STATUS` to one of:
#   ran            the oracle held and every applicable variant was replayed
#   not_jwt        BASE_TOKEN is not a JWT; this check does not apply
#   token_rejected the sample token was not accepted at URL; no oracle possible
#   no_verify      the endpoint accepted a bad signature; the strongest finding
#                  was emitted and the per-variant probes were not run
# and `_JWT_RUN_REASON` to the sentence the phase records as a coverage_gap when
# the status is anything other than `ran`.  It also sets
# `_JWT_RUN_RS_PUBKEY_MISSING` to 1 when the token is asymmetric and RS->HS
# confusion could not be tested for lack of a public key, so the phase records
# that specific gap rather than letting the absent finding read as clean.
#
# `checks_run` is recorded for every check id the run actually EXERCISES (reached
# the probe for), whether or not it found something - AGENTS.md's definition of
# checks_run, and the same discipline auth_engine.sh's enum scan already applies:
# a check that ran and found nothing is coverage, and recording it only on a hit
# would make a clean result indistinguishable from a check that never ran.
jwt_run() {
  local target=$1 method=$2 url=$3 base_token=$4
  local header=${5:-Authorization} scheme=${6:-Bearer} pubkey_file=${7:-}
  local alg forged spelling secret status
  _JWT_RUN_STATUS='' _JWT_RUN_REASON='' _JWT_RUN_RS_PUBKEY_MISSING=0

  if ! jwt_is_jwt "$base_token"; then
    _JWT_RUN_STATUS=not_jwt
    _JWT_RUN_REASON="the session token for target '$target' is not a JSON Web Token (it does not parse as three base64url segments whose header declares an 'alg'), so the JWT weakness checks do not apply to it - an opaque or reference token is verified server-side and none of alg:none, weak-HMAC or algorithm confusion is meaningful against it"
    return 0
  fi
  alg=$(jwt_alg_of "$base_token")

  # --- oracle step 1: the real token must be accepted -------------------------
  jwt_probe "$target" "$method" "$url" "$base_token" "$header" "$scheme" || true
  if ! jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
    _JWT_RUN_STATUS=token_rejected
    _JWT_RUN_REASON="the sample token was not accepted by $method $url (HTTP ${_JWT_PROBE_STATUS:-none}), so it is not a valid credential for this endpoint and cannot anchor the forgery oracle - point jwt.sh at an endpoint this identity's token is actually authorised for"
    return 0
  fi

  # --- oracle step 2: a bad signature must be rejected ------------------------
  forged=$(jwt_sig_tampered "$base_token")
  jwt_probe "$target" "$method" "$url" "$forged" "$header" "$scheme" || true
  if jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
    # The endpoint accepts a token whose signature does not verify at all.  This
    # is strictly stronger than any single-variant weakness and would make every
    # per-variant probe below a trivial true-positive, so we report it once and
    # stop: a report with five findings that are all one root cause is noise.
    run_record checks_run 'DAST-JWT-SIG_NOT_VERIFIED-01'
    jwt_emit_finding 'DAST-JWT-SIG_NOT_VERIFIED-01' \
      'JWT signature is not verified' critical \
      "$target" "$method" "$url" "$header" \
      "$method $url returned HTTP ${_JWT_PROBE_STATUS} for a token whose header and payload were left intact but whose signature was replaced with one computed under a key the server cannot hold; a conformant verifier rejects this, so the endpoint is not verifying the signature at all" \
      'Verify the JWT signature on every request against the expected algorithm and key before trusting any claim in it. Reject a token whose signature does not verify, whose alg is not the one you issued, or that carries alg:none. This endpoint accepted a token with an invalid signature, which lets anyone mint a token for any user.'
    _JWT_RUN_STATUS=no_verify
    _JWT_RUN_REASON="the endpoint accepted a token with an invalid signature, so it does not verify signatures at all; the per-variant probes (alg:none, empty/weak HMAC, RS->HS) were not run because they would each be a duplicate of that one root cause"
    return 0
  fi

  # --- the oracle holds: a bad signature is rejected, so any 2xx from a forged
  #     token below is a real acceptance of that specific forgery -------------

  # alg:none, including the case-variant spellings that slip past a check that
  # only string-compares against lowercase "none".
  run_record checks_run 'DAST-JWT-ALG_NONE-01'
  for spelling in none None NONE nOnE; do
    forged=$(jwt_forge_alg_none "$base_token" "$spelling")
    jwt_probe "$target" "$method" "$url" "$forged" "$header" "$scheme" || true
    if jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
      jwt_emit_finding 'DAST-JWT-ALG_NONE-01' \
        'JWT accepted with alg:none (unsigned token)' critical \
        "$target" "$method" "$url" "$header" \
        "$method $url returned HTTP ${_JWT_PROBE_STATUS} for an UNSIGNED token whose header set alg to '$spelling' and whose signature segment was empty; the server accepted a token it never signed" \
        'Reject any token whose header alg is "none" (in any capitalisation) and any token with an empty signature. Pin the accepted algorithm to the one you issue and verify the signature with the corresponding key. Accepting alg:none lets anyone forge a token for any user with no key at all.'
      break
    fi
  done

  # empty-secret HS256.
  run_record checks_run 'DAST-JWT-EMPTY_HMAC-01'
  forged=$(jwt_forge_hs256 "$base_token" '')
  jwt_probe "$target" "$method" "$url" "$forged" "$header" "$scheme" || true
  if jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
    jwt_emit_finding 'DAST-JWT-EMPTY_HMAC-01' \
      'JWT accepted when re-signed HS256 with an empty secret' critical \
      "$target" "$method" "$url" "$header" \
      "$method $url returned HTTP ${_JWT_PROBE_STATUS} for a token re-signed as HS256 with a zero-length key; the HMAC secret is empty" \
      'Sign tokens with a high-entropy secret of at least 256 bits and reject an empty or absent key at verification time. An empty HMAC secret means anyone can mint a valid token.'
  fi

  # weak/guessable HS256 secret, from the bounded vendored list only.
  run_record checks_run 'DAST-JWT-WEAK_HMAC-01'
  if jwt_weak_secrets_load; then
    for secret in "${_JWT_WEAK_SECRETS[@]+"${_JWT_WEAK_SECRETS[@]}"}"; do
      forged=$(jwt_forge_hs256 "$base_token" "$secret")
      jwt_probe "$target" "$method" "$url" "$forged" "$header" "$scheme" || true
      if jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
        jwt_emit_finding 'DAST-JWT-WEAK_HMAC-01' \
          'JWT accepted when re-signed HS256 with a common weak secret' critical \
          "$target" "$method" "$url" "$header" \
          "$method $url returned HTTP ${_JWT_PROBE_STATUS} for a token re-signed as HS256 with the well-known weak secret '$secret' from scoursh's bounded vendored list; the signing key is a guessable value" \
          'Replace the signing secret with a high-entropy value of at least 256 bits from a secrets manager, and rotate it. The current secret is a common value shipped in framework examples and documentation, so anyone who has read those can mint a valid token.'
        break
      fi
    done
  else
    _JWT_RUN_REASON="the vendored weak-secret list could not be read, so the weak-HMAC check did not run"
  fi

  # RS->HS algorithm confusion: only when the token is asymmetric AND a public
  # key is available.  The forging MECHANISM is unit-tested regardless; here it
  # runs only when both conditions hold, and records the specific gap when the
  # token is asymmetric but no key was supplied - so an absent finding never
  # reads as "tested and clean".
  case $alg in
    RS* | PS* | ES*)
      run_record checks_run 'DAST-JWT-ALG_CONFUSION-01'
      if [[ -n $pubkey_file && -r $pubkey_file ]]; then
        local pubkey
        pubkey=$(cat -- "$pubkey_file")
        forged=$(jwt_forge_hs256 "$base_token" "$pubkey")
        jwt_probe "$target" "$method" "$url" "$forged" "$header" "$scheme" || true
        if jwt_status_is_success "${_JWT_PROBE_STATUS:-}"; then
          jwt_emit_finding 'DAST-JWT-ALG_CONFUSION-01' \
            'JWT RS->HS algorithm confusion accepted' critical \
            "$target" "$method" "$url" "$header" \
            "$method $url declared alg '$alg' (asymmetric) but accepted HTTP ${_JWT_PROBE_STATUS} for a token re-signed as HS256 using the server's own PUBLIC key as the HMAC secret; the verifier picks the algorithm from the attacker-controlled header instead of pinning it" \
            'Pin the verification algorithm to the one you issue (RS256), and never let the token header choose it. A verifier that accepts alg:HS256 for an RS256-issued token can be forged with the public key alone, which is public by definition.'
        fi
      else
        _JWT_RUN_RS_PUBKEY_MISSING=1
      fi
      ;;
  esac

  _JWT_RUN_STATUS=ran
  return 0
}
