# tools/dast-test-target/http.sh - shared helpers for talking to the local
# DAST test target's API over tools/dast-test-target/http-client.js (docker
# exec, never a host curl - see that file's header for why). Sourced by
# tools/dast-test-identities.sh and tests/e2e/dast-target-smoke.sh; never
# executed directly and never part of scan.sh's dispatch path.
#
# Assumes the caller has already sourced lib/core.sh and
# tools/dast-test-target/env.sh (for DTT_CONTAINER).
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DTT_HTTP_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DTT_HTTP_SOURCED=1

# `dtt_call METHOD PATH [BEARER] [BODY_JSON]` - one request/response via the
# in-container node client. Prints "STATUS\nBODY". A secret (a password, a
# bearer token) travels only over this function's own stdin to docker exec,
# never as an argument (docs/FOUNDATION.md tension 9).
dtt_call() {
  local method=$1 path=$2 bearer=${3:-} body_json=${4:-}
  local headers='{}'
  if [[ -n $bearer ]]; then
    headers=$(printf '{"Authorization":"Bearer %s"}' "$bearer")
  fi
  local spec
  if [[ -n $body_json ]]; then
    spec=$(printf '{"method":"%s","path":"%s","headers":%s,"body":%s}' \
      "$method" "$path" "$headers" "$body_json")
  else
    spec=$(printf '{"method":"%s","path":"%s","headers":%s}' "$method" "$path" "$headers")
  fi
  printf '%s' "$spec" | docker exec -i "$DTT_CONTAINER" /nodejs/bin/node /tmp/scoursh-http-client.js
}

# Fixed-shape JSON field extraction via bash `[[ =~ ]]`, not a bare grep/rg
# (tests/lint-shell.sh rule 2) and not a general JSON parser - good enough
# for Juice Shop's known, stable response shapes.
dtt_json_string_field() {
  local json=$1 key=$2
  if [[ $json =~ \"$key\"\:\"([^\"]*)\" ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

dtt_json_number_field() {
  local json=$1 key=$2
  if [[ $json =~ \"$key\"\:([0-9]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

dtt_gen_password() {
  require_cmd openssl
  # A symbol plus random hex satisfies Juice Shop's password-strength rule
  # (upper/lower/digit/special) without hand-rolling a charset sampler.
  printf 'Sc0ursh!%s' "$(openssl rand -hex 16)"
}

# `dtt_login EMAIL PASSWORD` - prints "TOKEN BASKET_ID" on success, dies
# with SCOURSH_EXIT_INCOMPLETE on failure (this is setup/verification
# tooling, not a check that should ever report a soft failure).
dtt_login() {
  local email=$1 password=$2
  local body out status resp_body token bid
  body=$(printf '{"email":"%s","password":"%s"}' "$email" "$password")
  out=$(dtt_call POST /rest/user/login '' "$body")
  status=${out%%$'\n'*}
  resp_body=${out#*$'\n'}
  [[ $status == 200 ]] || die "$SCOURSH_EXIT_INCOMPLETE" \
    "dast-test-target: login failed for $email, status $status"
  token=$(dtt_json_string_field "$resp_body" token) \
    || die "$SCOURSH_EXIT_INCOMPLETE" "dast-test-target: no token in login response for $email"
  bid=$(dtt_json_number_field "$resp_body" bid) \
    || die "$SCOURSH_EXIT_INCOMPLETE" "dast-test-target: no basket id in login response for $email"
  printf '%s %s\n' "$token" "$bid"
}
