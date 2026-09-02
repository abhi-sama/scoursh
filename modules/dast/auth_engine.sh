#!/usr/bin/env bash
# modules/dast/auth_engine.sh - authentication and session acquisition for the
# running-endpoint scanner (docs/DESIGN.md §7.0; docs/STEP5-DAST-PLAN.md
# DAST-03, the first ticket of tier 1).
#
# Owns:
#   docs/DESIGN.md       §7.0 - the login modes, the session store, re-auth on
#                        expiry, and multi-identity
#   docs/DESIGN.md       §7.4's closing paragraph - the CONFIG-DERIVED half of
#                        the user-enumeration checks (the live `--allow-intrusive`
#                        probe is deliberately not built here; see section 10)
#   rules/RULE-FORMAT.md §9.6.2 - config/auth.conf, whose schema is FROZEN and
#                        is implemented against rather than redesigned
#   docs/FOUNDATION.md   tension  9 - a secret is never a command-line argument
#                        and never touches disk raw
#   docs/FOUNDATION.md   tension 16 - authentication traffic is real traffic: it
#                        pays the rate limiter, the per-run budget and the
#                        breaker like everything else, by going through
#                        http_request and nothing else
#   docs/FOUNDATION.md   tension 19 - every request goes through lib/http.sh
#
# The run.sh / engine.sh split modules/sast/ established, applied one level
# down: THIS file is a pure function library with the standard sourced-once
# guard and no side effects at source time, and modules/dast/auth.sh is the
# phase script that DOES something when `dast_run_phase` sources it.  The split
# is what lets tests/suites/dast-auth.sh exercise every mode against a stubbed
# transport without a scan.sh, a run directory, or a network.
#
# ---------------------------------------------------------------------------
# THE FOUR THINGS ABOUT THIS FILE THAT ARE EASY TO GET BACKWARDS
# ---------------------------------------------------------------------------
#
# 1. A FAILED AUTHENTICATION IS A DECLARED COVERAGE REDUCTION, NOT AN EXIT 5.
#    docs/DESIGN.md §7.0: "if refresh fails, mark the authenticated checks
#    `skipped` with a clear reason rather than emitting false negatives."  That
#    is the vocabulary of docs/FOUNDATION.md tension 14's DECLARED rows ("a
#    check skipped for an absent `requires-cmd` or `requires-config`"), not of
#    its unplanned ones, and the register's table is what settles it: a session
#    that could not be obtained makes the authenticated checks' required input
#    absent, exactly as a missing config/auth.conf does.  What is NOT allowed,
#    and is the whole reason this paragraph exists, is running the authenticated
#    checks unauthenticated and reporting their silence as a clean result.
#    `dast_auth_state` returns `failed` for the rest of the run and
#    `dast_auth_skip_reason` is the sentence every such check must state.
#
# 2. THE CREDENTIAL NEVER REACHES `argv` AND NEVER REACHES DISK IN THE CLEAR.
#    It is read from a mode-600 `secret-file` (§9.6.2's own preferred form) into
#    a shell variable, handed to lib/http.sh's request context as a VALUE, and
#    serialised by lib/http.sh into a curl config on curl's STDIN.  Bash
#    function arguments are not argv - no process is forked to pass them -
#    which is the same property that makes `printf '%s' "$x" | sha256_of`
#    satisfy tension 9 handling rule 1.  The session store under the run scratch
#    directory does hold the acquired token, mode 600 inside a mode-700
#    directory inside the umask-077 scratch tree that the EXIT trap erases; that
#    is the same trade tension 9 handling rule 2 already makes for `scan_match`
#    line files, and `scratch-dir` on a tmpfs remains the real control.
#
# 3. THE `form` MODE PROBES AT MOST THREE BODY SHAPES, AND THAT IS A CHOICE THE
#    FROZEN SCHEMA FORCED.  §9.6.2 gives `form` a `login-path`, a `username` and
#    a credential, and names no body encoding and no field names - so an
#    implementation must pick, and picking exactly one would make the mode work
#    against classic HTML form logins or against JSON login APIs but never
#    both.  The three shapes are tried in a fixed order (see
#    `_dast_auth_form_shapes`), the FIRST that yields a session wins, and the
#    winning shape is persisted so a later re-auth replays it directly and never
#    probes again.  Three is a real cost against a target with an account
#    lockout policy, which is why it is bounded, stated in the run record, and
#    never repeated.  Adding a `login-body-shape` key would be the better answer
#    and is a REGISTER change (§9.6.2 is frozen), not something to slip in here.
#
# 4. `srp` ACCEPTS A PRE-OBTAINED TOKEN; IT DOES NOT COMPUTE THE HANDSHAKE.
#    docs/DESIGN.md §7.0 offers the implementer both - "compute the SRP
#    handshake in shell, or accept a pre-obtained token to avoid re-implementing
#    crypto" - and this build takes the second.  A pure-shell SRP-6a
#    implementation means modular exponentiation over a 3072-bit group written
#    in bash arithmetic, which is unverifiable crypto in the one language this
#    project has no way to test it in.  The run RECORDS that the handshake was
#    not computed, so nobody reads `mode: srp` as evidence the provider's SRP
#    exchange was exercised.
#
# COOKIE-JAR FIDELITY, stated rather than discovered: the jar stores `name=value`
# pairs per (target, identity) and replays all of them to that target.  Cookie
# `Domain`, `Path`, `Secure`, `Expires` and `Max-Age` attributes are parsed off
# and discarded rather than honoured.  That is sound here and only here: every
# request a session is applied to has already passed the scope gate for the
# target the session belongs to, so there is no origin for a cookie to leak
# across, and a DAST run is short enough that expiry is the 401 path's job
# rather than the jar's.  A check that needs true path-scoped cookies must say
# so rather than assume this jar provides them.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes config keys and JSON syntax literally.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_AUTH_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_AUTH_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint every request here goes through.  Sourced only
# when an outer caller has not already done so: scan.sh sources it at top level
# before `scan_dispatch` ever runs, so in a real run this is a no-op, and the
# conditional is what lets tests/suites/dast-auth.sh source THIS file on its
# own.  The same shape, and the same reason, as modules/dast/engine.sh's own
# lib/checks.sh guard.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/http.sh"
fi

# ---------------------------------------------------------------------------
# 1. The session store
# ---------------------------------------------------------------------------
# One directory per (target, identity) under the RUN SCRATCH directory, which is
# finding F12's own description of what belongs there: genuinely transient data
# that must not outlive the run.  A session token is the clearest possible case
# of it.  Directories are 700 and every file is 600, inside a scratch tree
# lib/core.sh already created 700 under `umask 077`.
#
# Three files, because they are three different lifetimes: `token` is replaced
# wholesale on every re-auth, `cookies` accumulates across the login exchange,
# and `state` is the record a later check reads to decide whether to run at all.

# Filesystem-safe key.  Target ids and identity labels are authored by an
# operator in config/scope.conf and config/auth.conf, so they are not trusted to
# be path-safe - the same reasoning, and the same transformation, as
# lib/http.sh's `_http_limit_slug_set`.  Sets `_DAST_AUTH_SLUG`.
_dast_auth_slug_set() {
  local s=$1
  s=${s//[^A-Za-z0-9_.-]/_}
  [[ -n $s ]] || s=unlabelled
  _DAST_AUTH_SLUG=$s
  return 0
}

# `_dast_auth_dir_set TARGET LABEL` - sets `_DAST_AUTH_DIR`, creating it 700.
_dast_auth_dir_set() {
  local target=$1 label=$2 tslug lslug
  [[ -n ${SCOURSH_SCRATCH:-} ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      'the DAST session store needs the run scratch directory, which is not set'
  _dast_auth_slug_set "$target"
  tslug=$_DAST_AUTH_SLUG
  _dast_auth_slug_set "$label"
  lslug=$_DAST_AUTH_SLUG
  _DAST_AUTH_DIR=$SCOURSH_SCRATCH/dast-auth/$tslug/$lslug
  mkdir -p "$_DAST_AUTH_DIR"
  chmod 700 "$SCOURSH_SCRATCH/dast-auth" "$SCOURSH_SCRATCH/dast-auth/$tslug" "$_DAST_AUTH_DIR"
  return 0
}

# Create (or truncate) a session-store file at mode 600 before anything is
# written into it.  Writing first and chmod-ing after would leave a token
# readable for the width of one syscall, which is the kind of window this
# codebase does not leave open on purpose.
_dast_auth_touch600() {
  : >"$1"
  chmod 600 "$1"
  return 0
}

# `_dast_auth_state_write TARGET LABEL STATE REASON` - the durable per-identity
# verdict every later check reads.  `mode`, `header`, `scheme` and `shape` are
# taken from the globals the acquisition path has already published, so one
# writer owns the whole record and a partial update is impossible.
_dast_auth_state_write() {
  local target=$1 label=$2 state=$3 reason=$4
  # The reason can quote what a TARGET said (an OAuth2 `error` value, a status
  # line), and this record is line-structured, so a newline in it would make
  # every following key unreadable.  Flattened rather than refused: the reason
  # is diagnostic text, and losing its line breaks costs nothing.
  reason=${reason//$'\n'/ }
  reason=${reason//$'\r'/ }
  _dast_auth_dir_set "$target" "$label"
  local f=$_DAST_AUTH_DIR/state
  _dast_auth_touch600 "$f"
  {
    printf 'state=%s\n' "$state"
    printf 'mode=%s\n' "${_DAST_AUTH_MODE:-}"
    printf 'header=%s\n' "${_DAST_AUTH_HEADER:-}"
    printf 'scheme=%s\n' "${_DAST_AUTH_SCHEME:-}"
    printf 'shape=%s\n' "${_DAST_AUTH_SHAPE:-}"
    printf 'reason=%s\n' "$reason"
  } >"$f"
  return 0
}

# `dast_auth_state TARGET LABEL` - sets `_DAST_AUTH_STATE` to one of:
#
#   authenticated  a session exists and may be applied
#   failed         authentication was attempted and did not produce a session
#   absent         no identity is configured for this (target, label)
#
# and `_DAST_AUTH_REASON` to the stated reason, which is empty only for
# `authenticated`.  It SETS variables rather than printing them so a caller in
# an `if` cannot lose them to a subshell.
# It resets ALL SIX published variables before reading, not only the two it
# always sets.  Leaving `_DAST_AUTH_SHAPE`, `_DAST_AUTH_HEADER` or
# `_DAST_AUTH_SCHEME` untouched when there is no state file on disk would let
# one identity's values survive into the next identity's acquisition, which is
# the "a nested call reads a global the previous call left behind" bug this
# codebase already calls out for `occurrence_next` and `records_index_of_id` -
# here it would send identity A's header scheme with identity B's token.
dast_auth_state() {
  local target=$1 label=$2 line k v
  _DAST_AUTH_STATE=absent
  _DAST_AUTH_REASON='no identity is configured for this target and label in config/auth.conf'
  _DAST_AUTH_MODE='' _DAST_AUTH_HEADER='' _DAST_AUTH_SCHEME='' _DAST_AUTH_SHAPE=''
  _dast_auth_dir_set "$target" "$label"
  local f=$_DAST_AUTH_DIR/state
  [[ -r $f ]] || return 0
  while IFS= read -r line; do
    k=${line%%=*}
    v=${line#*=}
    case $k in
      state) _DAST_AUTH_STATE=$v ;;
      reason) _DAST_AUTH_REASON=$v ;;
      mode) _DAST_AUTH_MODE=$v ;;
      header) _DAST_AUTH_HEADER=$v ;;
      scheme) _DAST_AUTH_SCHEME=$v ;;
      shape) _DAST_AUTH_SHAPE=$v ;;
    esac
  done <"$f"
  if [[ $_DAST_AUTH_STATE == authenticated ]]; then
    _DAST_AUTH_REASON=''
  fi
  return 0
}

# `dast_auth_skip_reason TARGET LABEL` - the sentence an authenticated check
# states when it declines to run.  Never empty for a non-authenticated identity:
# "skipped" with no reason is the silent-unauthenticated outcome docs/DESIGN.md
# §15 exists to forbid.
dast_auth_skip_reason() {
  local target=$1 label=$2
  dast_auth_state "$target" "$label"
  case $_DAST_AUTH_STATE in
    authenticated) printf '' ;;
    *) printf 'identity %s.%s is not authenticated: %s' "$target" "$label" "$_DAST_AUTH_REASON" ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# 2. config/auth.conf (rules/RULE-FORMAT.md §9.6.2)
# ---------------------------------------------------------------------------
# E073 is enforced HERE as well as in tests/lint-rules.sh, and the duplication
# is deliberate for the reason tension 19 gives for the scope gate: the file
# whose permissions matter is the operator's own, on the operator's own host,
# and a lint that ran in this repository has said nothing at all about it.  A
# world-readable credential file is refused rather than warned about, because
# the run's next act would be to read a password out of it.
#
# The parse itself is `config_load_or_die`, so a syntax error or a schema
# violation - including E074, the mode-dependent required keys - is exit 4 with
# every file:line:col diagnostic already printed, exactly like every other
# config file in this repository.  It is never `source`d (tension 26).
DAST_AUTH_LOADED=0

dast_auth_conf_path() {
  printf '%s' "${SCOURSH_DAST_AUTH_CONF:-$SCOURSH_INSTALL_ROOT/config/auth.conf}"
  return 0
}

# `dast_auth_load [PATH]` - returns 0 when identities were loaded, 1 when the
# file is simply absent (the normal case for an unauthenticated scan, and never
# an error), and dies exit 4 when it exists but cannot be trusted.
dast_auth_load() {
  local path=${1:-}
  [[ -n $path ]] || path=$(dast_auth_conf_path)
  DAST_AUTH_LOADED=0
  [[ -e $path ]] || return 1

  local mode
  mode=$(stat_mode "$path")
  if [[ $mode != 600 ]]; then
    die "$SCOURSH_EXIT_INPUT" \
      "$path is mode $mode, not 600 (rules/RULE-FORMAT.md §9.6.2, E073). Every value in that file is a credential, so it is refused rather than read: run 'chmod 600 $path'."
  fi

  config_load_or_die "$path" auth-identity auth
  DAST_AUTH_LOADED=1
  return 0
}

# `dast_auth_labels_set TARGET` - sets `_DAST_AUTH_LABELS` to the identity
# labels configured for TARGET, in the order they appear in config/auth.conf.
#
# The ORDER IS THE FILE'S, not sorted: §9.6.2's id is `<target-id>.<label>` with
# no ordering rule, and DAST-29's "identity A" and "identity B" are whichever
# two the operator wrote first, which is the only reading that does not silently
# swap the two identities when somebody renames one.
dast_auth_labels_set() {
  local target=$1 n i id
  _DAST_AUTH_LABELS=()
  (( DAST_AUTH_LOADED )) || return 0
  n=$(records_count auth)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id auth "$i")
    [[ ${id%%.*} == "$target" ]] || continue
    _DAST_AUTH_LABELS+=("${id#*.}")
  done
  return 0
}

# `dast_auth_authenticated_labels_set TARGET` - the subset of the above whose
# session was actually obtained.  This is the plumbing DAST-29 (`authz.sh`,
# `requires-identities: 2`) reads: a cross-user check needs two LIVE sessions,
# and two CONFIGURED identities of which one failed to log in is not that.
# Built now, with its consumer named, because a check that discovers the
# difference at runtime tends to discover it by reporting a clean result.
dast_auth_authenticated_labels_set() {
  local target=$1 label
  _DAST_AUTH_AUTHED_LABELS=()
  dast_auth_labels_set "$target"
  for label in "${_DAST_AUTH_LABELS[@]+"${_DAST_AUTH_LABELS[@]}"}"; do
    dast_auth_state "$target" "$label"
    if [[ $_DAST_AUTH_STATE == authenticated ]]; then
      _DAST_AUTH_AUTHED_LABELS+=("$label")
    fi
  done
  return 0
}

# `_dast_auth_index_set TARGET LABEL` - sets `_DAST_AUTH_IDX` to the record
# index, or returns 1.
_dast_auth_index_set() {
  local target=$1 label=$2 n i
  _DAST_AUTH_IDX=''
  (( DAST_AUTH_LOADED )) || return 1
  n=$(records_count auth)
  for (( i = 0; i < n; i++ )); do
    if [[ $(records_id auth "$i") == "$target.$label" ]]; then
      _DAST_AUTH_IDX=$i
      return 0
    fi
  done
  return 1
}

_dast_auth_field() {
  records_field_or auth "$_DAST_AUTH_IDX" "$1" "${2:-}"
}

# ---------------------------------------------------------------------------
# 3. Reading the credential (docs/FOUNDATION.md tension 9)
# ---------------------------------------------------------------------------
# `secret-file` first, always: §9.6.2 calls it "preferred over inline values"
# and it is the only form that keeps the credential out of a file an operator
# might reasonably paste into a ticket.  The inline key is the fallback and is
# named per mode by the caller.
#
# It SETS the named variable rather than printing it.  `$(...)` would send the
# credential through a pipe between two processes for no reason at all, and this
# is the one value in this file worth spending a paragraph on.
#
# ONE LINE, not the whole file: a credential file written by `printf` has no
# trailing newline and one written by an editor has exactly one, and a login
# that silently sends the newline fails in a way nobody diagnoses.  `read`
# returns non-zero at EOF even when it read the line, which is why the `|| true`
# is here and in every other reader of a newline-less file in this repository.
_dast_auth_secret_set() {
  local __var=$1 inline_key=$2 __v='' file
  printf -v "$__var" '%s' ''
  file=$(_dast_auth_field secret-file)
  if [[ -n $file ]]; then
    [[ $file == /* ]] \
      || die "$SCOURSH_EXIT_INPUT" \
        "config/auth.conf: identity '$(records_id auth "$_DAST_AUTH_IDX")' has secret-file '$file', which is not an absolute path (rules/RULE-FORMAT.md §9.6.2)"
    [[ -f $file && -r $file ]] \
      || die "$SCOURSH_EXIT_INPUT" \
        "config/auth.conf: identity '$(records_id auth "$_DAST_AUTH_IDX")' names secret-file '$file', which does not exist or cannot be read"
    local m
    m=$(stat_mode "$file")
    [[ $m == 600 ]] \
      || die "$SCOURSH_EXIT_INPUT" \
        "the secret-file '$file' is mode $m, not 600 (rules/RULE-FORMAT.md §9.6.2). It holds a credential, so it is refused rather than read."
    IFS= read -r __v <"$file" || true
  else
    __v=$(_dast_auth_field "$inline_key")
  fi
  # shellcheck disable=SC2229  # indirect assignment; bash 4.2 has no namerefs
  printf -v "$__var" '%s' "$__v"
  # An EMPTY credential is a failure in both branches, not just the inline one.
  # A `secret-file` whose first line is blank is the likeliest real-world
  # version of this (a file created but never filled), and returning success for
  # it would send an empty password and report the rejection as the target's
  # fault rather than the config's.
  [[ -n $__v ]]
}

# ---------------------------------------------------------------------------
# 4. Encoding helpers
# ---------------------------------------------------------------------------
# Both are pure parameter expansion with no fork, for the reason section 3
# gives: the strings passing through them are the credential.

# Percent-encoding for an `application/x-www-form-urlencoded` body.
# `local LC_ALL=C` is load-bearing rather than tidiness: without it bash indexes
# a UTF-8 string by CHARACTER and `"'$c"` yields the code point, so a non-ASCII
# byte in a password would be encoded as a single out-of-range %XX instead of
# its two or three real bytes.  Under LC_ALL=C both are byte-wise and the
# encoding is correct for any credential.  Sets `_DAST_AUTH_ENC`.
_dast_auth_urlencode() {
  local LC_ALL=C
  local s=$1 out='' i n c
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    c=${s:i:1}
    case $c in
      [A-Za-z0-9.~_-]) out+=$c ;;
      *) printf -v c '%%%02X' "'$c"; out+=$c ;;
    esac
  done
  _DAST_AUTH_ENC=$out
  return 0
}

# Fixed-shape JSON string extraction, NOT a JSON parser - the same bounded,
# stated-scope choice modules/sca/engine.sh's `_sca_json_walk` and
# tools/dast-test-target/http.sh's `dtt_json_string_field` already make in this
# repository.  It finds `"key": "value"` at ANY nesting depth, which is what
# lets one reader handle both a flat `{"access_token":"..."}` OAuth2 response
# and a nested `{"authentication":{"token":"..."}}` login response without
# knowing either shape in advance.
#
# The limitation that follows, stated rather than left to be discovered: a key
# of the same name nested somewhere unintended would match first.  For the token
# names below that is a theoretical shape, and the alternative - a real JSON
# parser in bash - is a much larger, much less testable thing than the value it
# buys here.
_dast_auth_json_field() {
  local json=$1 key=$2 re
  re="\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
  if [[ $json =~ $re ]]; then
    _DAST_AUTH_JSON_VALUE=${BASH_REMATCH[1]}
    return 0
  fi
  _DAST_AUTH_JSON_VALUE=''
  return 1
}

# The token key names tried, in order.  `access_token` is RFC 6749's own name
# and comes first for that reason; `token` covers the very common login-API
# shape (including a nested `authentication.token`); `id_token` is OIDC's, last
# because an id_token is an assertion about the user rather than a credential
# for the API, and preferring it over an access_token that is present would send
# the wrong one.
_DAST_AUTH_TOKEN_KEYS=(access_token token id_token jwt)

# `_dast_auth_token_from_json JSON` - sets `_DAST_AUTH_TOKEN`.
_dast_auth_token_from_json() {
  local json=$1 key
  _DAST_AUTH_TOKEN=''
  for key in "${_DAST_AUTH_TOKEN_KEYS[@]+"${_DAST_AUTH_TOKEN_KEYS[@]}"}"; do
    if _dast_auth_json_field "$json" "$key"; then
      [[ -n $_DAST_AUTH_JSON_VALUE ]] || continue
      _DAST_AUTH_TOKEN=$_DAST_AUTH_JSON_VALUE
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 5. URLs
# ---------------------------------------------------------------------------
# `_dast_auth_url_set TARGET PATH` - the target's own base-url joined to a
# target-relative path.  The result still goes through `http_request`, so the
# gate re-derives everything about it; this only has to produce a well-formed
# URL, never to decide whether it is allowed.
_dast_auth_url_set() {
  local target=$1 path=$2 base
  base=$(config_scope_field "$target" base-url)
  base=${base%/}
  [[ ${path:0:1} == / ]] || path="/$path"
  _DAST_AUTH_URL="$base$path"
  return 0
}

# ---------------------------------------------------------------------------
# 6. The cookie jar
# ---------------------------------------------------------------------------
# Parsed out of the RAW response headers lib/http.sh captured, through
# `scan_match` and never a bare grep (tension 4 rule 2): a jar that silently
# read zero cookies because the engine failed, rather than because none were
# set, would report an unauthenticated session as a successful one.
#
# Later Set-Cookie lines for the same name replace earlier ones, which is what
# a login that first sets a pre-session cookie and then replaces it on success
# actually does.
_dast_auth_cookies_absorb() {
  local target=$1 label=$2 hdrfile=$3
  local hits line pair name existing out
  [[ -r $hdrfile ]] || return 0
  _dast_auth_dir_set "$target" "$label"
  local jar=$_DAST_AUTH_DIR/cookies
  hits=$_DAST_AUTH_DIR/.setcookie
  if ! scan_match "$hits" -i -e '^set-cookie:[[:space:]]*[^;[:space:]]+=' -- "$hdrfile"; then
    rm -f "$hits"
    return 0
  fi

  local -A jarmap=()
  local -a order=()
  if [[ -r $jar ]]; then
    while IFS= read -r existing; do
      [[ -n $existing ]] || continue
      name=${existing%%=*}
      [[ -n ${jarmap[$name]+set} ]] || order+=("$name")
      jarmap[$name]=${existing#*=}
    done <"$jar"
  fi

  while IFS= read -r line; do
    [[ -n $line ]] || continue
    # `grep -n` is bound into SCOURSH_GREP unconditionally (lib/core.sh
    # core_bind_engine), so every hit is prefixed `<lineno>:`.  Strip it before
    # anything reads the header value.
    line=${line#*:}
    line=${line%$'\r'}
    pair=${line#*:}                     # drop "Set-Cookie:"
    pair=${pair#"${pair%%[![:space:]]*}"}
    pair=${pair%%;*}
    [[ $pair == *=* ]] || continue
    name=${pair%%=*}
    [[ -n $name ]] || continue
    [[ -n ${jarmap[$name]+set} ]] || order+=("$name")
    jarmap[$name]=${pair#*=}
  done <"$hits"
  rm -f "$hits"

  _dast_auth_touch600 "$jar"
  out=''
  for name in "${order[@]+"${order[@]}"}"; do
    out+="$name=${jarmap[$name]}"$'\n'
  done
  printf '%s' "$out" >"$jar"
  return 0
}

# `_dast_auth_cookie_header_set TARGET LABEL` - sets `_DAST_AUTH_COOKIE` to the
# `Cookie:` header value, or the empty string when the jar is empty.
_dast_auth_cookie_header_set() {
  local target=$1 label=$2 line out=''
  _DAST_AUTH_COOKIE=''
  _dast_auth_dir_set "$target" "$label"
  local jar=$_DAST_AUTH_DIR/cookies
  [[ -r $jar ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ -n $out ]] && out+='; '
    out+=$line
  done <"$jar"
  _DAST_AUTH_COOKIE=$out
  return 0
}

# ---------------------------------------------------------------------------
# 7. Acquisition
# ---------------------------------------------------------------------------
# Every mode ends in the same place: a token (possibly empty), a cookie jar
# (possibly empty), and a state record.  A session is only `authenticated` when
# at least one of the two carries something - a login that returned 200 and set
# nothing is not a session, and treating it as one is how a scan reports clean
# results it never had the access to obtain.

# The three `form` body shapes, in order.  See this file's header, point 3, for
# why there are three and why the count is bounded.
#
# Each row is `<content-type>|<template>`, where the template's `%U` and `%P`
# are replaced by the encoded username and credential.  The encoding differs per
# row, so the row names it: `urlenc` percent-encodes, `json` JSON-escapes.
_dast_auth_form_shapes() {
  printf '%s\n' \
    'urlenc|application/x-www-form-urlencoded|username=%U&password=%P' \
    'json|application/json|{"email":%U,"password":%P}' \
    'json|application/json|{"username":%U,"password":%P}'
  return 0
}

# `_dast_auth_form_body_set SHAPE_ROW USERNAME SECRET` - sets
# `_DAST_AUTH_CTYPE` and `_DAST_AUTH_BODY`.
_dast_auth_form_body_set() {
  local row=$1 user=$2 secret=$3
  local enc=${row%%|*} rest=${row#*|}
  local ctype=${rest%%|*} tpl=${rest#*|}
  local u p
  if [[ $enc == urlenc ]]; then
    _dast_auth_urlencode "$user"; u=$_DAST_AUTH_ENC
    _dast_auth_urlencode "$secret"; p=$_DAST_AUTH_ENC
  else
    # json_string (lib/core.sh) is this repository's single JSON string writer
    # and it emits the surrounding quotes, which is why the templates above
    # carry a bare %U rather than "%U".  It runs in a command substitution,
    # which forks bash but never execs anything, so the credential still reaches
    # no process's argv.
    u=$(json_string "$user")
    p=$(json_string "$secret")
  fi
  _DAST_AUTH_CTYPE=$ctype
  _DAST_AUTH_BODY=${tpl//%U/$u}
  _DAST_AUTH_BODY=${_DAST_AUTH_BODY//%P/$p}
  return 0
}

# Bytes of a login-response body read back for the token/enumeration parsers
# below.  A login endpoint is still a URL an operator authorised, not a
# trusted one, so an unbounded read would materialise whatever it chose to
# send - a memory hazard, not a correctness one, since every parser here reads
# a top-level JSON field or a short substring that is overwhelmingly likely to
# sit well inside this cap. Mirrors modules/dast/active/inject_engine.sh's own
# `_INJ_MAX_BODY_BYTES` default for the identical reason: 256 KiB is generous
# for a login response and small enough that a hostile one cannot turn this
# into the memory hazard docs/DESIGN.md §15 warns about.
: "${_DAST_AUTH_MAX_BODY_BYTES:=262144}"

# `_dast_auth_post TARGET LABEL URL CTYPE BODY` - one credential-bearing POST
# through the chokepoint, with the response body and headers captured into the
# session directory.  Sets `_DAST_AUTH_STATUS` and `_DAST_AUTH_RESP_BODY`
# (bounded to `_DAST_AUTH_MAX_BODY_BYTES`).
#
# Returns 1 for a transport failure, in which case the status is empty; a 4xx is
# a normal RESULT here, not a failure, because probing for the right body shape
# means expecting to be told no.
_dast_auth_post() {
  local target=$1 label=$2 url=$3 ctype=$4 body=$5
  _dast_auth_dir_set "$target" "$label"
  local bodyf=$_DAST_AUTH_DIR/.resp.body hdrf=$_DAST_AUTH_DIR/.resp.hdr
  local corpus=$_DAST_AUTH_DIR/responses
  _DAST_AUTH_STATUS='' _DAST_AUTH_RESP_BODY=''

  http_request_reset
  http_request_header Content-Type "$ctype"
  http_request_header Accept 'application/json, */*'
  http_request_body "$body"
  http_request_capture "$bodyf" "$hdrf"
  if ! http_request POST "$url" "${SCOURSH_DAST_AUTH_MAX_REDIRECTS:-5}" "$target"; then
    rm -f "$bodyf" "$hdrf"
    return 1
  fi
  _DAST_AUTH_STATUS=$_HTTP_LAST_STATUS
  # Bounded AT READ TIME, not after a full slurp: `-N` stops once
  # _DAST_AUTH_MAX_BODY_BYTES bytes have been read, whatever else remains on
  # disk, so a target answering a login POST with a multi-hundred-MB body
  # never gets materialised into this variable before being trimmed - the
  # same fix shape modules/dast/active/discovery.sh's own `_discovery_probe`
  # applies to its own capped read. `read -N` returns non-zero at EOF for a
  # body smaller than the cap (the ordinary case), exactly as `-d ''` did for
  # its own ordinary case, so `|| true` stays required. NUL bytes in the body
  # are still lost either way - bash variables cannot hold one - but where
  # `-d ''` stopped dead at the first NUL, `-N` reads through embedded NULs
  # and keeps accumulating non-NUL bytes up to the cap; narrower loss in an
  # already-lossy edge case, not a new one.
  if [[ -r $bodyf ]]; then
    IFS= read -r -N "$_DAST_AUTH_MAX_BODY_BYTES" _DAST_AUTH_RESP_BODY <"$bodyf" || true
  fi
  _dast_auth_cookies_absorb "$target" "$label" "$hdrf"

  # EVERY authentication response is appended to one corpus, not just the last:
  # the `form` probe may try three body shapes, and the enumeration disclosure
  # is most likely to be in a REJECTED one.  Scanning only the final response
  # would examine the successful login and miss exactly the case the check is
  # for.  The corpus is 600 in the scratch tree and is erased by the phase as
  # soon as it has been scanned.
  if [[ ! -e $corpus ]]; then
    _dast_auth_touch600 "$corpus"
  fi
  if [[ -r $bodyf ]]; then
    cat -- "$bodyf" >>"$corpus"
    printf '\n' >>"$corpus"
  fi
  _DAST_AUTH_RESPONSE_COUNT=$(( ${_DAST_AUTH_RESPONSE_COUNT:-0} + 1 ))
  _DAST_AUTH_LAST_URL=$url
  rm -f "$bodyf" "$hdrf"
  return 0
}

# `_dast_auth_acquire_form TARGET LABEL` - §7.0's "form login (POST creds,
# capture Set-Cookie)".
#
# A session is anything the exchange left behind: a cookie in the jar OR a token
# in the response body.  Both count because both are what real login endpoints
# hand back, and requiring a cookie specifically would fail against every
# token-returning login API while reporting the target as unauthenticatable.
_dast_auth_acquire_form() {
  local target=$1 label=$2 user secret path row shape_i=0 tried=''
  user=$(_dast_auth_field username)
  if ! _dast_auth_secret_set secret password; then
    _DAST_AUTH_FAIL_REASON='mode form has no usable credential: secret-file is empty or neither secret-file nor password is set'
    return 1
  fi
  path=$(_dast_auth_field login-path)
  _dast_auth_url_set "$target" "$path"
  local url=$_DAST_AUTH_URL
  _DAST_AUTH_LOGIN_PATH=$path

  local -a shapes=()
  local pinned=${_DAST_AUTH_SHAPE:-}
  if [[ -n $pinned ]]; then
    # A re-auth replays the shape that already worked and never probes again.
    shapes=("$pinned")
  else
    while IFS= read -r row; do
      if [[ -n $row ]]; then
        shapes+=("$row")
      fi
    done <<<"$(_dast_auth_form_shapes)"
  fi

  for row in "${shapes[@]+"${shapes[@]}"}"; do
    shape_i=$(( shape_i + 1 ))
    _dast_auth_form_body_set "$row" "$user" "$secret"
    if ! _dast_auth_post "$target" "$label" "$url" "$_DAST_AUTH_CTYPE" "$_DAST_AUTH_BODY"; then
      _DAST_AUTH_FAIL_REASON="the login request to $url produced no response at all (a transport failure, not a rejection)"
      return 1
    fi
    tried+="${tried:+,}${_DAST_AUTH_CTYPE}=>${_DAST_AUTH_STATUS}"
    _dast_auth_token_from_json "$_DAST_AUTH_RESP_BODY" || true
    _dast_auth_cookie_header_set "$target" "$label"
    if [[ $_DAST_AUTH_STATUS == 2* || $_DAST_AUTH_STATUS == 3* ]] \
      && { [[ -n $_DAST_AUTH_TOKEN ]] || [[ -n $_DAST_AUTH_COOKIE ]]; }; then
      _DAST_AUTH_SHAPE=$row
      _DAST_AUTH_SCHEME=Bearer
      return 0
    fi
  done

  _DAST_AUTH_FAIL_REASON="the login at $url returned no session for any of the $shape_i request body shapes tried ($tried); neither a Set-Cookie nor a token was returned"
  return 1
}

# `_dast_auth_acquire_oauth2 TARGET LABEL GRANT` - RFC 6749 §4.3 (password) and
# §4.4 (client_credentials).
#
# Client authentication is sent as body parameters (`client_id`/`client_secret`)
# rather than as HTTP Basic.  RFC 6749 §2.3.1 permits both and requires servers
# to support Basic, but the body form is what every deployment accepts in
# practice, and choosing one is unavoidable: §9.6.2 has no key naming which.
_dast_auth_acquire_oauth2() {
  local target=$1 label=$2 grant=$3
  local url user secret client_id client_secret scope body=''
  url=$(_dast_auth_field token-url)
  client_id=$(_dast_auth_field client-id)
  scope=$(_dast_auth_field scope)

  _dast_auth_urlencode "$grant"
  body="grant_type=$_DAST_AUTH_ENC"

  if [[ $grant == password ]]; then
    user=$(_dast_auth_field username)
    if ! _dast_auth_secret_set secret password; then
      _DAST_AUTH_FAIL_REASON='mode oauth2-password has no usable credential: secret-file is empty or neither secret-file nor password is set'
      return 1
    fi
    _dast_auth_urlencode "$user"; body+="&username=$_DAST_AUTH_ENC"
    _dast_auth_urlencode "$secret"; body+="&password=$_DAST_AUTH_ENC"
    # A confidential client in the password grant may also need its secret; it
    # is optional here (a public client has none), so an absent one is not a
    # failure the way the user's password is.
    client_secret=$(_dast_auth_field client-secret)
  else
    if ! _dast_auth_secret_set client_secret client-secret; then
      _DAST_AUTH_FAIL_REASON='mode oauth2-client has no usable client secret: secret-file is empty or neither secret-file nor client-secret is set'
      return 1
    fi
  fi
  if [[ -n $client_id ]]; then
    _dast_auth_urlencode "$client_id"; body+="&client_id=$_DAST_AUTH_ENC"
  fi
  if [[ -n $client_secret ]]; then
    _dast_auth_urlencode "$client_secret"; body+="&client_secret=$_DAST_AUTH_ENC"
  fi
  if [[ -n $scope ]]; then
    _dast_auth_urlencode "$scope"; body+="&scope=$_DAST_AUTH_ENC"
  fi

  if ! _dast_auth_post "$target" "$label" "$url" 'application/x-www-form-urlencoded' "$body"; then
    _DAST_AUTH_FAIL_REASON="the token request to $url produced no response at all (a transport failure, not a rejection)"
    return 1
  fi
  if [[ $_DAST_AUTH_STATUS != 2* ]]; then
    # RFC 6749 §5.2 names the error in the body; it is the single most useful
    # thing to state and it is not a credential, but it goes through the same
    # bounded reader as everything else rather than being pasted whole.
    local detail=''
    if _dast_auth_json_field "$_DAST_AUTH_RESP_BODY" error; then
      detail=" (the endpoint reported error='$_DAST_AUTH_JSON_VALUE')"
    fi
    _DAST_AUTH_FAIL_REASON="the $grant grant at $url returned HTTP $_DAST_AUTH_STATUS$detail"
    return 1
  fi
  if ! _dast_auth_token_from_json "$_DAST_AUTH_RESP_BODY"; then
    _DAST_AUTH_FAIL_REASON="the $grant grant at $url returned HTTP $_DAST_AUTH_STATUS but no access_token in its response body"
    return 1
  fi
  _DAST_AUTH_SCHEME=Bearer
  if _dast_auth_json_field "$_DAST_AUTH_RESP_BODY" token_type; then
    if [[ -n $_DAST_AUTH_JSON_VALUE ]]; then
      _DAST_AUTH_SCHEME=$_DAST_AUTH_JSON_VALUE
    fi
  fi
  return 0
}

# `dast_auth_acquire TARGET LABEL` - obtain (or re-obtain) a session.
#
# Sets `_DAST_AUTH_STATE` and writes the durable state record either way, so a
# check that reads the state never has to know whether acquisition was even
# attempted.  Returns 0 on success, 1 on a stated failure; it does not die,
# because a failed login is a declared coverage reduction (this file's header,
# point 1) and not a reason to abandon the passive checks that need no session.
dast_auth_acquire() {
  local target=$1 label=$2 mode header
  _DAST_AUTH_TOKEN='' _DAST_AUTH_FAIL_REASON='' _DAST_AUTH_LOGIN_PATH=''
  _DAST_AUTH_RESPONSE_COUNT=0
  # Each acquisition owns its own response corpus, so a re-auth's responses are
  # never scanned together with a previous attempt's.
  _dast_auth_dir_set "$target" "$label"
  rm -f "$_DAST_AUTH_DIR/responses"
  # Reads the persisted record, which resets all six published variables and
  # then republishes whatever is on disk.  That is where a re-auth picks up the
  # pinned `form` body shape; a first acquisition finds it empty and probes.
  dast_auth_state "$target" "$label"

  if ! _dast_auth_index_set "$target" "$label"; then
    _DAST_AUTH_STATE=absent
    return 1
  fi

  mode=$(_dast_auth_field mode)
  header=$(_dast_auth_field header-name Authorization)
  _DAST_AUTH_MODE=$mode
  _DAST_AUTH_HEADER=$header

  local rc=0
  case $mode in
    bearer)
      # `Bearer <token>` under `header-name` (default Authorization, §9.6.2).
      _dast_auth_secret_set _DAST_AUTH_TOKEN token || rc=1
      _DAST_AUTH_SCHEME=Bearer
      [[ $rc == 0 ]] || _DAST_AUTH_FAIL_REASON='mode bearer has neither secret-file nor token'
      ;;
    api-key)
      # The RAW value under `header-name`.  An API key is not a bearer token and
      # prefixing it with `Bearer ` would send a credential the target never
      # issued; an operator wanting a non-default header sets `header-name`,
      # which is exactly what §9.6.2 provides it for.
      _dast_auth_secret_set _DAST_AUTH_TOKEN token || rc=1
      _DAST_AUTH_SCHEME=''
      [[ $rc == 0 ]] || _DAST_AUTH_FAIL_REASON='mode api-key has neither secret-file nor token'
      ;;
    external)
      # The operator obtained the credential out of band; scoursh performs no
      # authentication exchange at all.  Mechanically identical to api-key, and
      # recorded differently on purpose: a reader of the run needs to know the
      # session's freshness was nobody's job.
      _dast_auth_secret_set _DAST_AUTH_TOKEN token || rc=1
      _DAST_AUTH_SCHEME=''
      [[ $rc == 0 ]] || _DAST_AUTH_FAIL_REASON='mode external has neither secret-file nor token'
      ;;
    srp)
      # See this file's header, point 4.  The handshake is not computed; the
      # pre-obtained token docs/DESIGN.md §7.0 permits is accepted instead, and
      # the run says so rather than letting `mode: srp` read as evidence that
      # the provider's SRP exchange was exercised.
      _dast_auth_secret_set _DAST_AUTH_TOKEN token || rc=1
      _DAST_AUTH_SCHEME=Bearer
      if [[ $rc == 0 ]]; then
        run_record coverage_reduction "module=dast reason=srp_handshake_not_computed target=$target identity=$label - the identity-provider SRP exchange was NOT performed; the pre-obtained token from config/auth.conf was used instead (docs/DESIGN.md §7.0 permits either). Nothing here tested the provider's SRP implementation."
      else
        _DAST_AUTH_FAIL_REASON='mode srp needs a pre-obtained token via secret-file or token; scoursh does not compute the SRP handshake'
      fi
      ;;
    form)
      _dast_auth_acquire_form "$target" "$label" || rc=1
      ;;
    oauth2-password)
      _dast_auth_acquire_oauth2 "$target" "$label" password || rc=1
      ;;
    oauth2-client)
      _dast_auth_acquire_oauth2 "$target" "$label" client_credentials || rc=1
      ;;
    *)
      rc=1
      _DAST_AUTH_FAIL_REASON="unknown mode '$mode' (config/auth.conf should have been refused by E024 before reaching here)"
      ;;
  esac

  if (( rc != 0 )); then
    _DAST_AUTH_STATE=failed
    _dast_auth_state_write "$target" "$label" failed "$_DAST_AUTH_FAIL_REASON"
    return 1
  fi

  _dast_auth_cookie_header_set "$target" "$label"
  if [[ -z $_DAST_AUTH_TOKEN && -z $_DAST_AUTH_COOKIE ]]; then
    _DAST_AUTH_STATE=failed
    _DAST_AUTH_FAIL_REASON="mode $mode completed without producing either a token or a cookie, so there is no session to apply"
    _dast_auth_state_write "$target" "$label" failed "$_DAST_AUTH_FAIL_REASON"
    return 1
  fi

  _dast_auth_dir_set "$target" "$label"
  _dast_auth_touch600 "$_DAST_AUTH_DIR/token"
  printf '%s' "$_DAST_AUTH_TOKEN" >"$_DAST_AUTH_DIR/token"
  _DAST_AUTH_STATE=authenticated
  _dast_auth_state_write "$target" "$label" authenticated ''
  return 0
}

# ---------------------------------------------------------------------------
# 8. Applying a session, and transparent re-auth
# ---------------------------------------------------------------------------
# `dast_auth_apply TARGET LABEL` - attach the identity's credential and cookies
# to the NEXT `http_request`.  Returns 1 without attaching anything when the
# identity is not authenticated: attaching nothing and proceeding anyway is the
# silent-unauthenticated failure this whole file exists to prevent, so the
# caller is told rather than left to infer it from an empty result.
dast_auth_apply() {
  local target=$1 label=$2 token=''
  dast_auth_state "$target" "$label"
  [[ $_DAST_AUTH_STATE == authenticated ]] || return 1
  _dast_auth_dir_set "$target" "$label"
  if [[ -r $_DAST_AUTH_DIR/token ]]; then
    IFS= read -r token <"$_DAST_AUTH_DIR/token" || true
  fi
  if [[ -n $token ]]; then
    if [[ -n ${_DAST_AUTH_SCHEME:-} ]]; then
      http_request_header "${_DAST_AUTH_HEADER:-Authorization}" "$_DAST_AUTH_SCHEME $token"
    else
      http_request_header "${_DAST_AUTH_HEADER:-Authorization}" "$token"
    fi
  fi
  _dast_auth_cookie_header_set "$target" "$label"
  if [[ -n $_DAST_AUTH_COOKIE ]]; then
    http_request_header Cookie "$_DAST_AUTH_COOKIE"
  fi
  return 0
}

# `dast_auth_request TARGET LABEL METHOD URL [CAPTURE_BODY] [CAPTURE_HEADERS]
#  [MAX_REDIRECTS]` - an authenticated request with docs/DESIGN.md §7.0's
# "on 401/token-expiry, transparently refresh once and retry".
#
# ONCE, and exactly once.  A loop would turn an expired-credential state into an
# unbounded login storm against somebody's identity provider, which is both the
# rate-limit hazard tension 16 exists for and the account-lockout hazard the
# form probe is bounded for.  If the refresh fails, or the retry is 401 again,
# the identity is marked `failed` with the reason and every later check skips -
# it is NOT retried again on the next request.
#
# The capture paths are parameters rather than a pre-set context because this
# function may issue two requests and `http_request` consumes its context on the
# first one; a caller that set the context itself would silently lose it on the
# retry.  Sets `_DAST_AUTH_REQ_STATUS`.
dast_auth_request() {
  local target=$1 label=$2 method=$3 url=$4
  local cap_body=${5:-} cap_hdrs=${6:-} maxred=${7:-5}
  _DAST_AUTH_REQ_STATUS=''

  if ! dast_auth_apply "$target" "$label"; then
    return 1
  fi
  http_request_capture "$cap_body" "$cap_hdrs"
  http_request "$method" "$url" "$maxred" "$target" || return 1
  _DAST_AUTH_REQ_STATUS=$_HTTP_LAST_STATUS
  [[ $_DAST_AUTH_REQ_STATUS == 401 ]] || return 0

  log_info "identity $target.$label received HTTP 401; re-authenticating once and retrying (docs/DESIGN.md §7.0)"
  if ! dast_auth_acquire "$target" "$label"; then
    run_record coverage_reduction "module=dast reason=reauth_failed target=$target identity=$label - a 401 was answered by re-authenticating, which failed: $_DAST_AUTH_FAIL_REASON. Every check needing this identity is skipped for the rest of the run rather than run unauthenticated."
    return 1
  fi
  dast_auth_apply "$target" "$label" || return 1
  http_request_capture "$cap_body" "$cap_hdrs"
  http_request "$method" "$url" "$maxred" "$target" || return 1
  _DAST_AUTH_REQ_STATUS=$_HTTP_LAST_STATUS
  if [[ $_DAST_AUTH_REQ_STATUS == 401 ]]; then
    _DAST_AUTH_FAIL_REASON="a fresh session obtained after a 401 was itself rejected with 401 by $method $url, so the credential is not the problem and this identity cannot reach authenticated content"
    _dast_auth_state_write "$target" "$label" failed "$_DAST_AUTH_FAIL_REASON"
    run_record coverage_reduction "module=dast reason=reauth_rejected target=$target identity=$label - $_DAST_AUTH_FAIL_REASON"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 9. The config-derived user-enumeration check (docs/DESIGN.md §7.4, closing)
# ---------------------------------------------------------------------------
# §7.4's closing paragraph: "Enumeration-via-response checks (user-existence
# through login / password-reset / signup responses) stay CONFIG-DERIVED by
# default and only run live as an explicit opt-in (`--allow-intrusive`),
# single-request, never bulk, never mass-triggering email/SMS - because on a
# real identity provider these create users and send messages."
#
# THIS IS THE CONFIG-DERIVED HALF AND IT SENDS NOTHING.  It reads the login and
# token responses this run already received while authenticating its own
# configured identities, and reports a response that discloses ACCOUNT STATE -
# "no such user", "user not found", "wrong password" as distinct from a generic
# "invalid credentials".  Zero extra requests, zero new usernames tried, so it
# cannot create an account or trigger a message.
#
# The live half - submitting a username the operator did not configure and
# diffing the response - is deliberately NOT built here.  It is the half that
# needs `--allow-intrusive`, and it is a small follow-up on top of these modes
# rather than part of this ticket (docs/STEP5-DAST-PLAN.md's DAST-03 row says
# exactly that).  What this ticket owes instead is that a run never reads as
# having tested it: `dast_auth_enum_gap` records the gap.
#
# The patterns are a small vendored set, matched case-insensitively through
# `scan_match`.  They are deliberately narrow: a phrase that distinguishes WHICH
# of the two credentials was wrong, or that names an account's existence, is
# enumeration; "invalid credentials" or "login failed" is not, and matching
# those would report every login endpoint on earth.
declare -ga _DAST_AUTH_ENUM_PATTERNS=(
  '(no such|unknown|unrecognized|unrecognised) (user|account|e-?mail|username|login)'
  '(user|account|e-?mail address|e?mail|username)[^.]{0,24}(does ?n.?t exist|does not exist|not found|is not registered|is not recognized|is not recognised|doesn.t have an account)'
  '(incorrect|invalid|wrong|bad) password( for|,|\.|$)'
  '(password|passwort) (is )?(incorrect|invalid|wrong)'
  '(user|account|e-?mail|username)[^.]{0,24}already (exists|registered|taken|in use)'
)

# `dast_auth_enum_scan TARGET LABEL LOGIN_PATH` - emit
# `DAST-AUTH-ENUM_RESPONSE-01` when one of the authentication responses this run
# already received discloses account state.  It reads the corpus
# `_dast_auth_post` accumulated and sends nothing itself.
#
# Evidence goes through `finding_set_evidence` (tension 9 handling rule 3) and
# is the MATCHED PHRASE, never the response body: an authentication response is
# exactly the place a token lives, and pasting it whole into a report would put
# the credential in the artifact.
#
# The corpus is ERASED here, whether or not anything matched.  It exists only to
# be read once, and a file of raw login responses is not something to leave
# lying in the scratch tree for the rest of the run on the chance a later phase
# wants it.
dast_auth_enum_scan() {
  local target=$1 label=$2 login_path=${3:-/}
  local pattern hits hit matched='' corpus
  _dast_auth_dir_set "$target" "$label"
  corpus=$_DAST_AUTH_DIR/responses
  [[ -r $corpus ]] || return 0

  # RECORDED HERE, NOT AT THE EMIT.  `checks_run` is the set of checks the run
  # loaded and EXECUTED (AGENTS.md's own definition), not the set that found
  # something: a check that ran and found nothing is coverage, and recording it
  # only on a hit would make a clean result indistinguishable from a check that
  # never ran - which is the exact confusion modules/dast/run.sh's roll-up
  # exists to prevent, arrived at from the other side.
  run_record checks_run 'DAST-AUTH-ENUM_RESPONSE-01'

  hits=$_DAST_AUTH_DIR/.enum
  for pattern in "${_DAST_AUTH_ENUM_PATTERNS[@]+"${_DAST_AUTH_ENUM_PATTERNS[@]}"}"; do
    if scan_match "$hits" -i -o -e "$pattern" -- "$corpus"; then
      IFS= read -r hit <"$hits" || true
      # SCOURSH_GREP carries -n unconditionally, so a hit is `<lineno>:<match>`.
      matched=${hit#*:}
      break
    fi
  done
  rm -f "$hits" "$corpus"
  [[ -n $matched ]] || return 0

  finding_new
  finding_set check_id 'DAST-AUTH-ENUM_RESPONSE-01'
  finding_set module dast
  finding_set title 'Authentication response discloses whether an account exists'
  finding_set base_severity low
  finding_set confidence medium
  finding_set cwe CWE-204
  finding_set owasp A07:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data false
  finding_set remediation 'Return one generic failure for every unsuccessful authentication, with the same status code, the same body and a comparable response time, whichever of the identifier or the credential was wrong. The same applies to password-reset and signup responses. Distinguishing them lets an unauthenticated caller enumerate valid accounts, which is the input to credential stuffing and to targeted phishing.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method POST
  finding_set loc_path_template "$(path_template_of "$login_path")"
  finding_set loc_param_location body
  finding_set loc_param_name 'authentication-response'
  finding_set_evidence "an authentication response this run already received distinguishes account state rather than failing generically: $matched"
  finding_emit
  return 0
}

# The honest statement of what this check did NOT do.  Always recorded when a
# session was attempted, because a report that mentions user enumeration at all
# must say which half of it ran.
dast_auth_enum_gap() {
  local target=$1 examined=$2
  if (( examined > 0 )); then
    run_record coverage_gap "dast auth: user-enumeration on target '$target' was assessed ONLY from the $examined authentication response(s) this run already received while logging in as its own configured identities (docs/DESIGN.md §7.4's config-derived half). The live probe - submitting an identifier the operator did not configure and comparing the response - was not run: it creates accounts and sends messages on a real identity provider, so it needs --allow-intrusive, and it is not implemented yet. A clean result here is not evidence that this endpoint does not enumerate users."
  else
    run_record coverage_gap "dast auth: user-enumeration on target '$target' was NOT assessed at all - no authentication response was obtained this run, so there was nothing to read (docs/DESIGN.md §7.4's config-derived half examines only responses the run already has). The live --allow-intrusive probe is not implemented either."
  fi
  return 0
}
