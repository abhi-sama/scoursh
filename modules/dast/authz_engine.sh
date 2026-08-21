#!/usr/bin/env bash
# modules/dast/authz_engine.sh - the pure half of the §7.4 object-level
# authorization and data-exposure checks
# (docs/DESIGN.md §7.4; docs/STEP5-DAST-PLAN.md DAST-29).
#
# modules/dast/authz.sh is the PHASE script `dast_run_phase` sources; this file
# is the library it drives, in the engine.sh/run.sh split modules/sast/
# established and every DAST ticket since has reused.  It carries the standard
# sourced-once guard and has no side effect at source time, which is what lets
# tests/suites/dast-authz.sh source it directly and drive every function from a
# recorded transport with no network and no scan.sh.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECK IS, AND WHY IT NEEDS TWO IDENTITIES
# ---------------------------------------------------------------------------
# docs/DESIGN.md §7.4: "request an object-reference endpoint as identity A using
# identity B's reference; flag if A receives B's object. Read-only references
# only; no writes."  Object-level authorization is the one class of defect that
# CANNOT be established from a single session: with one identity there is no way
# to tell "this object is mine" from "this object is anybody's".  So the check
# declares `requires-identities: 2` (rules/RULE-FORMAT.md §9.5, which names
# `authz.sh` in that key's own row) and skips - cleanly, with a stated reason -
# when two LIVE sessions are not available.  Two CONFIGURED identities of which
# one failed to log in is not two identities, which is exactly why
# modules/dast/auth_engine.sh ships `dast_auth_authenticated_labels_set` rather
# than letting a consumer read the config and assume.
#
# ---------------------------------------------------------------------------
# READ-ONLY, AND WHAT THAT IS ENFORCED BY
# ---------------------------------------------------------------------------
# Every request this file issues is a GET or a HEAD, and the restriction is
# applied at CANDIDATE SELECTION (`_authz_method_ok`), not at the call site: an
# inventory entry whose method is POST/PUT/PATCH/DELETE never becomes a
# candidate, so there is no code path on which a mutation could be reached even
# if a later edit forgot to check.  No request carries a body.  The probe never
# writes anything back to the target.  tests/suites/dast-authz.sh asserts this
# over a REQUEST LOG - the only form of the claim a test can actually falsify -
# rather than over a return value.
#
# ---------------------------------------------------------------------------
# THE ORACLE, AND THE TWO READINGS IT HAS TO SEPARATE
# ---------------------------------------------------------------------------
# For one concrete object-reference URL U the phase makes at most three
# requests: U as identity A, U as identity B, and U with no credential at all.
# The third is not a nicety - without it the check reports every public object
# on the target as a cross-user read, because a public object is of course
# readable by both identities.
#
# "Public" is decided by DIGEST EQUALITY WITH AN IDENTITY'S OWN RESPONSE, never
# by the anonymous status code alone.  An application that answers an
# unauthenticated request with a 200 login page - the overwhelmingly common
# shape - would otherwise be read as serving every object publicly, and every
# real finding on it would be suppressed.  The naive reading fails in the
# direction that looks like a clean report, which is why it is pinned by a test
# that fails under it.
#
# Two outcomes are then possible, and they are DIFFERENT CHECK IDS because the
# DAST fingerprint (target, method, path_template, param_location, param_name)
# carries nothing that distinguishes them, so one id would make them collide and
# `findings_merge` would silently keep whichever sorted first:
#
#   DAST-AUTHZ-IDOR-01  Both identities received the byte-identical object AND
#     somewhere else under the SAME path template one of them was REFUSED
#     (401/403/404) a reference the other could read.  That refusal is the proof
#     that this endpoint does enforce per-object ownership in general, so the
#     shared object is a hole in that enforcement rather than a resource the
#     application intends to share.  Confidence `high`.
#
#   DAST-AUTHZ-CROSS_IDENTITY_READ-01  Both identities received the
#     byte-identical non-public object, and no refusal was observed anywhere in
#     the group, so the endpoint may legitimately serve a shared resource to
#     every authenticated user.  Confidence `medium`, and the finding says
#     plainly that it is the weaker of the two.
#
# A reference each identity can read but which renders DIFFERENTLY for each is
# not reported at all: that is what a correctly-scoped `/api/me`-shaped endpoint
# looks like.
#
# WHAT THE DIGEST COMPARISON COSTS, STATED RATHER THAN ASSUMED AWAY.  The
# comparison is over the RAW response bytes, so a response that embeds a
# per-request nonce, a CSRF token or a timestamp never compares equal and its
# IDOR goes unreported.  That is a FALSE NEGATIVE, not a false positive, and it
# is the direction to fail in for a check whose finding accuses an application
# of leaking one user's data to another.  The phase records it as a coverage
# note when it happens (both identities got 2xx and the digests differed).
#
# ---------------------------------------------------------------------------
# EXCESSIVE DATA EXPOSURE
# ---------------------------------------------------------------------------
# §7.4's second half: "call an authenticated profile/bootstrap endpoint and flag
# when the response body contains far more fields than the view needs
# (configurable sensitive-field list: tokens, internal IDs, other users' data)."
# This file reads the FIELD NAMES of an authenticated JSON response through
# modules/dast/crawl_engine.sh's `crawl_json_flatten` - the one frozen JSON
# reader every inventory producer and consumer already shares
# (docs/INVENTORY-FORMAT.md §7) rather than a second parser that could disagree
# with it - and matches them against the vendored, operator-editable list in
# modules/dast/sensitive-fields.txt.
#
# NO FIELD VALUE IS EVER READ, DIGESTED, LOGGED OR PUT IN A FINDING.  Only names
# reach the evidence, and even those are target-derived and therefore untrusted
# (docs/FOUNDATION.md tension 10), so they go through `finding_set_evidence` like
# any other response-derived text.  A check whose whole subject is a response
# that carries too much sensitive data must not be the thing that copies it into
# the report.
#
# The "other users' data" arm is DAST-AUTHZ-OTHER_IDENTITY_DATA-01: the response
# identity A received contains the IDENTIFIER the operator configured for
# identity B.  The comparison is a pure-bash substring test over a bounded read
# of the body, never a `scan_match`, because the identifier comes out of
# config/auth.conf - a mode-600 credential file - and a pattern argument is
# argv, which tension 9 handling rule 1 forbids for anything out of that file.
# The identifier is never echoed into the evidence for the same reason; the
# finding names the identity LABEL instead.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_DAST_AUTHZ_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_AUTHZ_ENGINE_SOURCED=1

# crawl_engine.sh for the frozen inventory reader (`crawl_json_flatten`,
# `crawl_json_unescape`, `crawl_url_split`) and auth_engine.sh for the session
# store.  Both carry a sourced-once guard and neither has a side effect at
# source time, so in a real run - where crawl.sh and auth.sh have already run
# and sourced them - these are no-ops; standalone they are what lets the suite
# drive this file without scan.sh.  This is exactly modules/dast/jwt.sh's own
# arrangement.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/crawl_engine.sh"
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/auth_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds
# ---------------------------------------------------------------------------
# Every one of these bounds the number of REQUESTS this phase makes against
# somebody's application, so they are deliberately small and deliberately not
# operator-configurable: rules/RULE-FORMAT.md §9.6.1's key set is frozen, and
# inventing a key here would widen a tier-5 ticket into a format change
# (§14 item 2).  Reaching one is never silent - the phase records a coverage
# note naming the bound, per docs/INVENTORY-FORMAT.md §8's own rule that no
# bound truncates silently.
#
# The worst case is MAX_GROUPS * MAX_REFS_PER_GROUP * 3 = 36 requests for the
# IDOR pass plus MAX_EXPOSURE_ENDPOINTS = 5 for the exposure pass, all of them
# drawn down from DAST-01's per-run request budget through the same chokepoint
# as every other request in this tool.
_AUTHZ_MAX_GROUPS=4
_AUTHZ_MAX_REFS_PER_GROUP=3
_AUTHZ_MAX_EXPOSURE_ENDPOINTS=5
# 512 KiB, the same body bound docs/INVENTORY-FORMAT.md §8 already fixes for a
# parsed response.  A larger body is still digested for the IDOR comparison (a
# digest of a stream costs nothing) but is not FIELD-scanned, because flattening
# an unbounded JSON document in bash is how a scan stops finishing.
_AUTHZ_MAX_BODY_BYTES=524288
_AUTHZ_MAX_FIELDS=2000
_AUTHZ_MAX_HITS_REPORTED=12

# ---------------------------------------------------------------------------
# 1. What an object reference is
# ---------------------------------------------------------------------------
# `authz_is_object_ref VALUE` - 0 when VALUE is the kind of token an
# application uses to name one row.
#
# THE FOUR SHAPES ARE lib/findings.sh's `path_template_of`'s FOUR SHAPES,
# DELIBERATELY AND EXACTLY.  That function decides which path segment becomes
# `{id}` in a finding's identity, and this one decides which path segment is
# worth substituting between two identities; if the two ever disagreed, this
# check would probe a segment the fingerprint then treats as a literal (so two
# objects under one endpoint become two findings) or would skip a segment the
# fingerprint collapses (so the check has no candidates on an endpoint whose
# findings it would happily merge).  tests/suites/dast-authz.sh asserts the
# agreement directly against `path_template_of` rather than restating the four
# patterns, so a later change to either is caught in one place.
#
# A slug (`/users/jane`), a word, and a filename are NOT object references here.
# They are extremely common and almost never enumerable, so admitting them would
# spend the whole request budget on `/about` and `/pricing`.  That is a stated
# narrowing, which the phase records, rather than a claim that slug-keyed IDOR
# does not exist.
authz_is_object_ref() {
  local v=$1
  [[ -n $v ]] || return 1
  [[ $v =~ ^[0-9]+$ ]] && return 0
  [[ $v =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] && return 0
  [[ $v =~ ^[0-7][0-9A-HJKMNP-TV-Z]{25}$ ]] && return 0
  [[ $v =~ ^[0-9a-fA-F]{16,}$ ]] && return 0
  return 1
}

# `authz_ref_param_name PATH INDEX` - the name this file gives the reference at
# 0-based path-segment INDEX, for the finding's `loc_param_name`.
#
# It is the PRECEDING segment, which is the collection the object belongs to:
# `/rest/basket/5` names `basket`, `/api/users/1/orders/2` names `users` and
# `orders`.  A positional name (`segment-3`) would be unreadable in a report,
# and a constant would make the two references in `/users/1/orders/2` collide on
# one fingerprint - which is the whole reason this component is populated at
# all.  A reference in the first segment has no preceding one and falls back to
# the positional form, which is honest rather than invented.
authz_ref_param_name() {
  local path=$1 idx=$2
  local -a segs=()
  local rest=${path#/} seg
  while [[ -n $rest ]]; do
    seg=${rest%%/*}
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=''; fi
    segs+=("$seg")
  done
  if (( idx > 0 )) && [[ -n ${segs[idx-1]:-} ]]; then
    printf '%s' "${segs[idx-1]}"
  else
    printf 'segment-%s' "$idx"
  fi
}

# Only GET and HEAD are ever candidates.  See this file's header: the read-only
# guarantee is enforced HERE, at selection, so no later code path can reach a
# mutating method at all.
_authz_method_ok() {
  case ${1:-GET} in
    GET | HEAD | get | head) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 2. Candidate extraction from the frozen inventory
# ---------------------------------------------------------------------------
# `_authz_walk_records FILE ARRAY_KEY` - print `idx<TAB>key<TAB>value` for every
# scalar leaf of the named top-level array in one inventory file, with string
# values already unescaped.
#
# It goes through `crawl_json_flatten`, the reader docs/INVENTORY-FORMAT.md §7
# freezes for exactly this, so a conformant producer may format the file however
# it likes and this consumer still reads it.  A second parser here would be a
# second definition of the schema.
_authz_walk_records() {
  local file=$1 key=$2
  [[ -n $file && -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p type v rest idx field
  while IFS=$'\t' read -r p type v; do
    [[ $p == "$key"* ]] || continue
    rest=${p#"$key"}
    rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}
    field=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ ]] || continue
    [[ $field != "$rest" ]] || continue
    # A nested object inside a record would arrive with a further US in `field`;
    # the schema has none, and one appearing is a schema this consumer does not
    # know, so it is skipped rather than guessed at.
    [[ $field != *"$sep"* ]] || continue
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    printf '%s\t%s\t%s\n' "$idx" "$field" "$v"
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  return 0
}

# The scope PRE-FILTER, and it is not the gate.
#
# An inventory entry is a URL the SCANNED TARGET or an operator-supplied
# specification chose, not one the operator authorised, so handing it straight
# to `http_request` - which treats an out-of-scope URL as a caller bug and dies
# exit 3 - would let one stray entry abort the operator's whole run.  This
# decides only whether a candidate is worth KEEPING; everything that survives is
# still requested through `http_request`, which applies the real gate again on
# the way out and on every redirect hop.  Exactly modules/dast/crawl.sh's
# `_crawl_in_scope` reasoning, and the same both-halves-required property.
_authz_in_scope() {
  local url=$1
  declare -F http_gate_url >/dev/null || return 0
  http_gate_url "$url" "${SCOURSH_DAST_TARGET:-}" >/dev/null 2>&1
}

# `_authz_path_of URL` - the path component of an absolute URL, or '' when the
# URL has no recoverable authority.  Kept here rather than reaching for a second
# URL parser: `crawl_url_split` already removed the query and the fragment, so
# what is left is `scheme://authority/path`.
_authz_path_of() {
  local u=$1 rest
  [[ $u == *://* ]] || return 0
  rest=${u#*://}
  if [[ $rest == */* ]]; then
    printf '/%s' "${rest#*/}"
  else
    printf '/'
  fi
}

_authz_emit_path_refs() {
  local target=$1 m=${2:-GET} u=$3 t=$4
  [[ -n $u ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  if ! _authz_method_ok "$m"; then
    _AUTHZ_SKIPPED_METHOD=$(( _AUTHZ_SKIPPED_METHOD + 1 ))
    return 0
  fi
  if ! _authz_in_scope "$u"; then
    _AUTHZ_SKIPPED_SCOPE=$(( _AUTHZ_SKIPPED_SCOPE + 1 ))
    return 0
  fi
  crawl_url_split "$u"
  local base=$_CRAWL_U_BASE path row
  path=$(_authz_path_of "$base")
  [[ -n $path ]] || return 0

  local rest=${path#/} seg i=0
  while [[ -n $rest ]]; do
    seg=${rest%%/*}
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=''; fi
    if authz_is_object_ref "$seg"; then
      printf -v row '%s\t%s\t%s\tpath\t%s\t%s' \
        "${m^^}" "$base" "$path" "$(authz_ref_param_name "$path" "$i")" "$seg"
      _AUTHZ_CANDIDATES+=("$row")
    fi
    i=$(( i + 1 ))
  done
  return 0
}

# A parameter NAME that reads like an object reference.  Narrow on purpose, for
# the same budget reason `authz_is_object_ref` is: `id`, `<thing>_id` /
# `<thing>Id`, `uuid`, `guid`, `ref`.  The name is normalised the same way a
# response field name is, so `user_id`, `userId` and `USERID` are one thing.
_authz_ref_name_ok() {
  local n
  n=$(authz_normalise_field "$1")
  case $n in
    id | uuid | guid | ref | *id) return 0 ;;
    *) return 1 ;;
  esac
}

_authz_emit_query_ref() {
  local target=$1 m=${2:-GET} u=$3 t=$4 name=$5 loc=$6 example=$7
  [[ -n $u && -n $name ]] || return 0
  [[ $loc == query ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  authz_is_object_ref "$example" || return 0
  _authz_ref_name_ok "$name" || return 0
  if ! _authz_method_ok "$m"; then
    _AUTHZ_SKIPPED_METHOD=$(( _AUTHZ_SKIPPED_METHOD + 1 ))
    return 0
  fi
  crawl_url_split "$u"
  local base=$_CRAWL_U_BASE path composed row
  path=$(_authz_path_of "$base")
  composed="$base?$name=$example"
  if ! _authz_in_scope "$composed"; then
    _AUTHZ_SKIPPED_SCOPE=$(( _AUTHZ_SKIPPED_SCOPE + 1 ))
    return 0
  fi
  printf -v row '%s\t%s\t%s\tquery\t%s\t%s' \
    "${m^^}" "$composed" "$path" "$name" "$example"
  _AUTHZ_CANDIDATES+=("$row")
  return 0
}

# `authz_candidates_set TARGET ENDPOINTS_FILE PARAMETERS_FILE` - sets
# `_AUTHZ_CANDIDATES` to one TSV row per concrete object reference worth
# probing:
#
#   METHOD <TAB> URL <TAB> PATH <TAB> PARAM_LOCATION <TAB> PARAM_NAME <TAB> REF
#
# and `_AUTHZ_SKIPPED_METHOD` / `_AUTHZ_SKIPPED_SCOPE` to how many inventory
# entries were passed over for each reason, so the phase can say what it did not
# look at rather than reporting a thin surface as a complete one.
#
# TWO SOURCES, BOTH REQUIRED (docs/STEP5-DAST-PLAN.md DAST-29's own "object
# reference endpoints from the parameter inventory"):
#
#   path  - an endpoint whose PATH carries an object-reference segment.
#           `/rest/basket/5` is the canonical case.
#   query - a `location: query` parameter whose recorded `example` is an object
#           reference and whose NAME reads like a reference.  The URL is composed
#           from the parameter's own `url` plus `?name=example`; a query string
#           is deliberately absent from `endpoints.json`
#           (docs/INVENTORY-FORMAT.md §4), so composing it here is that
#           document's own instruction rather than a workaround.
#
# THE `example` IS USED AS A REFERENCE, NEVER AS A CREDENTIAL.  §5 of that
# document is explicit that an example is redaction-processed and still not
# trustworthy, and that a parameter whose NAME says it carries a credential has
# its example dropped entirely by the producer.  What is left is a value the
# target itself put in a URL, replayed to the same target it came from, which is
# the weakest possible use of it.
authz_candidates_set() {
  local target=$1 epf=${2:-} pf=${3:-}
  _AUTHZ_CANDIDATES=()
  _AUTHZ_SKIPPED_METHOD=0
  _AUTHZ_SKIPPED_SCOPE=0

  local idx field value cur='' m='' u='' t=''

  while IFS=$'\t' read -r idx field value; do
    if [[ -n $cur && $idx != "$cur" ]]; then
      _authz_emit_path_refs "$target" "$m" "$u" "$t"
      m='' u='' t=''
    fi
    cur=$idx
    case $field in
      method) m=$value ;;
      url) u=$value ;;
      target) t=$value ;;
    esac
  done < <(_authz_walk_records "$epf" endpoints)
  [[ -n $cur ]] && _authz_emit_path_refs "$target" "$m" "$u" "$t"

  cur='' m='' u='' t=''
  local name='' loc='' example=''
  while IFS=$'\t' read -r idx field value; do
    if [[ -n $cur && $idx != "$cur" ]]; then
      _authz_emit_query_ref "$target" "$m" "$u" "$t" "$name" "$loc" "$example"
      m='' u='' t='' name='' loc='' example=''
    fi
    cur=$idx
    case $field in
      method) m=$value ;;
      url) u=$value ;;
      target) t=$value ;;
      name) name=$value ;;
      location) loc=$value ;;
      example) example=$value ;;
    esac
  done < <(_authz_walk_records "$pf" parameters)
  [[ -n $cur ]] && _authz_emit_query_ref "$target" "$m" "$u" "$t" "$name" "$loc" "$example"
  return 0
}

# `authz_group_key ROW` - the identity a group of candidates shares: same
# method, same path TEMPLATE, same parameter slot.  Two rows with the same key
# name the same handler and differ only in WHICH object they ask for, which is
# precisely the comparison the oracle needs.
authz_group_key() {
  local row=$1
  local -a f=()
  IFS=$'\t' read -r -a f <<<"$row"
  printf '%s|%s|%s|%s' "${f[0]:-}" "$(path_template_of "${f[2]:-/}")" \
    "${f[3]:-}" "${f[4]:-}"
}

# `authz_idempotent_endpoints TARGET FILE` - print `METHOD<TAB>URL<TAB>PATH` for
# every idempotent, in-scope endpoint belonging to TARGET, JSON-looking ones
# first.  This is the exposure pass's candidate list: §7.4 asks for "an
# authenticated profile/bootstrap endpoint" and the crawl inventory is where one
# is named.  A JSON `content_type` sorts first because a field-name scan of an
# HTML page finds nothing and still costs a request.
_authz_ep_collect() {
  local target=$1 m=${2:-GET} u=$3 t=$4 ct=$5 path row
  [[ -n $u ]] || return 0
  [[ -z $t || $t == "$target" ]] || return 0
  _authz_method_ok "$m" || return 0
  _authz_in_scope "$u" || return 0
  crawl_url_split "$u"
  path=$(_authz_path_of "$_CRAWL_U_BASE")
  [[ -n $path ]] || return 0
  printf -v row '%s\t%s\t%s' "${m^^}" "$_CRAWL_U_BASE" "$path"
  if [[ ${ct,,} == *json* ]]; then
    _AUTHZ_EP_JSON+=("$row")
  else
    _AUTHZ_EP_OTHER+=("$row")
  fi
  return 0
}

authz_idempotent_endpoints() {
  local target=$1 file=$2
  local idx field value cur='' m='' u='' t='' ct='' line
  _AUTHZ_EP_JSON=() _AUTHZ_EP_OTHER=()
  while IFS=$'\t' read -r idx field value; do
    if [[ -n $cur && $idx != "$cur" ]]; then
      _authz_ep_collect "$target" "$m" "$u" "$t" "$ct"
      m='' u='' t='' ct=''
    fi
    cur=$idx
    case $field in
      method) m=$value ;;
      url) u=$value ;;
      target) t=$value ;;
      content_type) ct=$value ;;
    esac
  done < <(_authz_walk_records "$file" endpoints)
  [[ -n $cur ]] && _authz_ep_collect "$target" "$m" "$u" "$t" "$ct"
  for line in "${_AUTHZ_EP_JSON[@]+"${_AUTHZ_EP_JSON[@]}"}" \
    "${_AUTHZ_EP_OTHER[@]+"${_AUTHZ_EP_OTHER[@]}"}"; do
    printf '%s\n' "$line"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 3. The vendored sensitive-field list
# ---------------------------------------------------------------------------
# `authz_normalise_field NAME` - lowercase, with `_`, `-` and `.` deleted.  The
# one normalisation both the list and every observed field name pass through, so
# `password_hash`, `passwordHash` and `Password-Hash` are one string and an
# operator writing the list does not have to guess the target's casing
# convention.
authz_normalise_field() {
  local n=${1,,}
  n=${n//_/}
  n=${n//-/}
  n=${n//./}
  printf '%s' "$n"
}

# `authz_sensitive_load [FILE]` - fills `_AUTHZ_SENSITIVE`.  Returns 1 when the
# list is absent, unreadable or empty, which is a recorded coverage reduction in
# the phase and never an error.
#
# The environment seam is the shape modules/dast/passive/recommended-headers.txt
# and SCOURSH_DAST_SQLI_PAYLOAD_DIR already established: a vendored, auditable
# data file plus a documented override, rather than a new config/scanner.conf
# key, because §9.6.1's key set is frozen and adding one moves lib/records.sh
# and tests/lint-rules.sh together (rules/RULE-FORMAT.md §14 item 2).
authz_sensitive_load() {
  local file=${1:-${SCOURSH_DAST_SENSITIVE_FIELDS_FILE:-}}
  [[ -n $file ]] || file=${BASH_SOURCE[0]%/*}/sensitive-fields.txt
  _AUTHZ_SENSITIVE=()
  [[ -r $file ]] || return 1
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line ]] || continue
    [[ ${line:0:1} == '#' ]] && continue
    # Leading and trailing whitespace is trimmed so a hand-edited list is
    # forgiving; nothing else about the line is interpreted, and nothing in it
    # is ever expanded or executed.
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -n $line ]] || continue
    if [[ ${line:0:1} == '=' ]]; then
      _AUTHZ_SENSITIVE+=("=$(authz_normalise_field "${line:1}")")
    else
      _AUTHZ_SENSITIVE+=("$(authz_normalise_field "$line")")
    fi
  done <"$file"
  (( ${#_AUTHZ_SENSITIVE[@]} > 0 ))
}

# `authz_field_matches NORMALISED_NAME` - 0 when the loaded list claims it, and
# sets `_AUTHZ_MATCHED_ENTRY` to the entry that did.  A `=` entry is an equality
# test, a bare entry a substring test; modules/dast/sensitive-fields.txt's own
# header says why `=` exists and when to reach for it.
authz_field_matches() {
  local n=$1 e
  _AUTHZ_MATCHED_ENTRY=''
  for e in "${_AUTHZ_SENSITIVE[@]+"${_AUTHZ_SENSITIVE[@]}"}"; do
    if [[ ${e:0:1} == '=' ]]; then
      if [[ $n == "${e:1}" ]]; then _AUTHZ_MATCHED_ENTRY=$e; return 0; fi
    else
      if [[ $n == *"$e"* ]]; then _AUTHZ_MATCHED_ENTRY=$e; return 0; fi
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Reading an authenticated response body
# ---------------------------------------------------------------------------
# `authz_body_within_bounds FILE` - 0 when FILE is small enough to parse.  Uses
# `wc -c` rather than a read: the whole point is to decide without loading it.
authz_body_within_bounds() {
  local file=$1 size
  [[ -r $file && -s $file ]] || return 1
  size=$(wc -c <"$file" 2>/dev/null || printf '0')
  size=${size//[[:space:]]/}
  [[ $size =~ ^[0-9]+$ ]] || return 1
  (( size <= _AUTHZ_MAX_BODY_BYTES ))
}

# `authz_field_names FILE` - print each distinct JSON field name in FILE, in
# first-seen order.
#
# `crawl_json_flatten` emits `path<TAB>type<TAB>raw-value` with path segments
# joined by US; the FIELD NAME is the last NON-NUMERIC segment.
#
# THE WALK BACK OVER TRAILING DIGITS IS LOAD-BEARING, AND NEITHER NAIVE READING
# WORKS.  An array contributes leaves at `tokens<US>0`, `tokens<US>1`, ..., so
# taking the last segment verbatim yields `0`, `1`, `2` - a list of ten strings
# becomes ten unnamed columns, and the field actually called `tokens` is never
# matched against the list at all, which is a silent false negative on exactly
# the shape (`"tokens": [...]`) the check most wants to catch.  Dropping a
# numeric last segment and stopping there loses the same field for the same
# reason.  Walking back to the nearest named ancestor keeps it.  A path that is
# ALL digits is a top-level array element with no name anywhere above it and is
# skipped, because there is nothing to report.
#
# The VALUE is never bound: this function reads names and nothing else.
authz_field_names() {
  local file=$1
  [[ -r $file && -s $file ]] || return 0
  local sep=$'\x1f' p name n=0
  local -A seen=()
  while IFS=$'\t' read -r p _ _; do
    name=${p##*"$sep"}
    while [[ $name =~ ^[0-9]+$ ]]; do
      [[ $p == *"$sep"* ]] || { name=''; break; }
      p=${p%"$sep"*}
      name=${p##*"$sep"}
    done
    [[ -n $name ]] || continue
    [[ -n ${seen[$name]:-} ]] && continue
    seen[$name]=1
    printf '%s\n' "$name"
    n=$(( n + 1 ))
    (( n >= _AUTHZ_MAX_FIELDS )) && break
  done < <(crawl_json_flatten <"$file" 2>/dev/null)
  return 0
}

# `authz_scan_body FILE` - sets `_AUTHZ_HITS` to the distinct sensitive field
# names FILE carries (capped, reported as the target spelled them so an operator
# can find them) and `_AUTHZ_HIT_TOTAL` to how many there were before the cap.
# Returns 1 when nothing matched.
authz_scan_body() {
  local file=$1 name n
  _AUTHZ_HITS=()
  _AUTHZ_HIT_TOTAL=0
  (( ${#_AUTHZ_SENSITIVE[@]} > 0 )) || return 1
  authz_body_within_bounds "$file" || return 1
  while IFS= read -r name; do
    n=$(authz_normalise_field "$name")
    authz_field_matches "$n" || continue
    _AUTHZ_HIT_TOTAL=$(( _AUTHZ_HIT_TOTAL + 1 ))
    if (( ${#_AUTHZ_HITS[@]} < _AUTHZ_MAX_HITS_REPORTED )); then
      _AUTHZ_HITS+=("$name")
    fi
  done < <(authz_field_names "$file")
  (( _AUTHZ_HIT_TOTAL > 0 ))
}

# `authz_body_contains FILE NEEDLE` - a pure-bash substring test over a bounded
# read.
#
# NOT `scan_match`, and that is the point.  NEEDLE here is an identifier out of
# config/auth.conf, a mode-600 credential file, and every engine this repository
# wraps takes its pattern on argv - which is world-readable in `ps`
# (docs/FOUNDATION.md tension 9 handling rule 1).  Bash function arguments are
# not argv, since no process is forked to pass them, which is the same property
# that lets `printf '%s' "$x" | sha256_of` satisfy the same rule.  The file is
# read whole rather than streamed because a needle can straddle a line boundary
# in a single-line JSON document, which is what an API returns.
authz_body_contains() {
  local file=$1 needle=$2 body=''
  [[ -n $needle ]] || return 1
  authz_body_within_bounds "$file" || return 1
  IFS= read -r -d '' body <"$file" || true
  [[ ${body,,} == *"${needle,,}"* ]]
}

# `authz_body_digest FILE` - the SHA-256 of the response bytes, or '' for an
# empty or unreadable body.  `sha256_of` reads stdin only (tension 9), so the
# body never becomes an argument.
authz_body_digest() {
  local file=$1
  [[ -r $file && -s $file ]] || return 0
  # The redirect feeds the file on STDIN; `sha256_of` still takes no argument,
  # which is what tension 9 requires and what tests/lint-shell.sh checks for
  # textually - it reads any following token as an argument, so the redirect is
  # applied to a group rather than to the command word.
  { sha256_of; } <"$file"
}

# ---------------------------------------------------------------------------
# 5. The probes
# ---------------------------------------------------------------------------
# `authz_probe_as TARGET LABEL METHOD URL BODYFILE` - one authenticated request.
# Sets `_AUTHZ_STATUS` and `_AUTHZ_DIGEST`; returns 1 when the request could not
# be made AT ALL (no session, transport failure), which is a different fact from
# a request that was refused and must never be read as one.
#
# It goes through `dast_auth_request`, not `http_request` directly, so §7.0's
# "on 401 refresh once and retry" applies here exactly as it does everywhere
# else - and so a 401 that is a genuine authorization refusal is separated from
# a 401 that is an expired session by that one mechanism rather than by a second
# copy of it here.
authz_probe_as() {
  local target=$1 label=$2 method=$3 url=$4 bodyfile=$5
  _AUTHZ_STATUS='' _AUTHZ_DIGEST=''
  : >"$bodyfile"
  dast_auth_request "$target" "$label" "$method" "$url" "$bodyfile" '' \
    "${SCOURSH_MAX_REDIRECTS:-5}" || return 1
  _AUTHZ_STATUS=${_DAST_AUTH_REQ_STATUS:-}
  _AUTHZ_DIGEST=$(authz_body_digest "$bodyfile")
  return 0
}

# `authz_probe_anon TARGET METHOD URL BODYFILE` - the same request with NO
# credential, which is the control that keeps a public object from being
# reported as a cross-user read.
#
# `http_request` consumes and clears the per-request context at entry, so the
# absence of a credential here is structural rather than something this function
# has to undo: nothing was attached.
authz_probe_anon() {
  local target=$1 method=$2 url=$3 bodyfile=$4 rc=0
  _AUTHZ_STATUS='' _AUTHZ_DIGEST=''
  : >"$bodyfile"
  http_request_capture "$bodyfile" ''
  http_request "$method" "$url" "${SCOURSH_MAX_REDIRECTS:-5}" "$target" || rc=$?
  (( rc == 0 )) || return 1
  _AUTHZ_STATUS=${_HTTP_LAST_STATUS:-}
  _AUTHZ_DIGEST=$(authz_body_digest "$bodyfile")
  return 0
}

# A 2xx.  Anything else - including a 3xx that lib/http.sh already followed as
# far as it was going to - is not a successful read.
authz_status_ok() {
  [[ ${1:-} =~ ^2[0-9][0-9]$ ]]
}

# A refusal: the statuses an application uses to say "not yours".  404 is
# included because hiding an object behind a 404 is the recommended way to
# refuse one without disclosing that it exists, so treating 404 as "no such
# endpoint" would discard the very evidence that this endpoint enforces
# ownership.
authz_status_refused() {
  case ${1:-} in
    401 | 403 | 404) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# 6. Emission
# ---------------------------------------------------------------------------
# The catalog is restated in this file as well as in modules/dast/checks.rules
# for the reason modules/dast/passive/headers.sh's own `_hdr_catalog` records:
# the record file is the REGISTRY that tension 12's coverage and tension 15's
# filter chain read, and the emitter needs the same facts at emit time without
# re-parsing it.  Keeping them in step is a one-file edit on both sides, and
# tests/suites/dast-authz.sh asserts that every id here is registered there and
# that the severities agree - so the duplication cannot drift silently.
_authz_catalog() {
  _AUTHZC_TITLE='' _AUTHZC_SEV='' _AUTHZC_CONF='' _AUTHZC_CWE='' _AUTHZC_OWASP='' _AUTHZC_REM=''
  case $1 in
    DAST-AUTHZ-IDOR-01)
      _AUTHZC_TITLE='Object reference is readable by an identity that does not own it'
      _AUTHZC_SEV=high; _AUTHZC_CONF=high; _AUTHZC_CWE=CWE-639; _AUTHZC_OWASP=A01:2021
      _AUTHZC_REM='Authorize every request against the object it names, not merely against the session. Load the object, then check that the authenticated principal is entitled to it, in the same server-side code path for every handler - a check performed in the client, in a route guard, or only on the listing endpoint is not one. Making the identifier unguessable (a UUID instead of a counter) narrows discovery but is not the fix: this finding is evidence that a reference obtained by any means is honoured for the wrong principal.' ;;
    DAST-AUTHZ-CROSS_IDENTITY_READ-01)
      _AUTHZC_TITLE='Two separate identities receive the identical non-public object'
      _AUTHZC_SEV=medium; _AUTHZC_CONF=medium; _AUTHZC_CWE=CWE-639; _AUTHZC_OWASP=A01:2021
      _AUTHZC_REM='Confirm whether this object is intended to be shared between all authenticated users. If it is, no change is needed and this finding can be baselined. If it is not, authorize the request against the object rather than against the session, exactly as for a confirmed insecure direct object reference. This check reports an observation rather than asserting a defect because, unlike DAST-AUTHZ-IDOR-01, it saw no evidence anywhere on this endpoint that per-object ownership is enforced at all.' ;;
    DAST-AUTHZ-EXCESSIVE_DATA-01)
      _AUTHZC_TITLE='Authenticated response carries fields beyond what the view needs'
      _AUTHZC_SEV=medium; _AUTHZC_CONF=medium; _AUTHZC_CWE=CWE-213; _AUTHZC_OWASP=A01:2021
      _AUTHZC_REM='Serialise a response from an explicit view model naming the fields the client needs, rather than returning a database row or a domain object and relying on the client to ignore the rest. A credential hash, an API token, a privilege flag or a regulated personal-data field that reaches the browser is disclosed to everything that can read that response - the page itself, an injected script, an intermediary log, and the browser cache - whether or not the interface renders it. The field list this check matches against is data, in modules/dast/sensitive-fields.txt.' ;;
    DAST-AUTHZ-OTHER_IDENTITY_DATA-01)
      _AUTHZC_TITLE="Authenticated response contains another identity's identifier"
      _AUTHZC_SEV=high; _AUTHZC_CONF=medium; _AUTHZC_CWE=CWE-200; _AUTHZC_OWASP=A01:2021
      _AUTHZC_REM='Scope every query to the authenticated principal where the data is fetched, not where it is rendered. A response carrying a second user identifier usually means a listing or a join returned every row and the filtering was left to the presentation layer, so the whole table is available to anyone who reads the response body directly.' ;;
    *) return 1 ;;
  esac
  return 0
}

# Every id this phase can emit, in report order.
declare -ga _AUTHZ_CHECK_IDS=(
  DAST-AUTHZ-IDOR-01
  DAST-AUTHZ-CROSS_IDENTITY_READ-01
  DAST-AUTHZ-EXCESSIVE_DATA-01
  DAST-AUTHZ-OTHER_IDENTITY_DATA-01
)

# tension-15 per-check selection.  scan.sh's filter chain records which ids
# survived --profile-scan/--intensity/--allow-intrusive and exports them as
# SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected` is the
# reader.  Consulted only if that function exists - it does not today, and
# modules/dast/active/sqli.sh and passive/headers.sh guard it the same way - so
# this file does not hard-depend on it: absent, everything the tier already
# permitted runs, which is the "empty means all selected" fallback a
# direct-engine test relies on.
authz_selected() {
  declare -F dast_check_selected >/dev/null || return 0
  dast_check_selected "$1"
}

# `authz_emit CHECK URL PATH PARAM_LOCATION PARAM_NAME EVIDENCE`
#
# `auth` is `user`, never `none`: every finding this file emits was established
# from an authenticated session, and recording it as unauthenticated would let
# the severity rubric treat a defect reachable only with a valid login as one
# reachable by anybody.  `sensitive_data` is true throughout, because in every
# one of these four cases the thing observed IS data reaching a principal that
# should not have it.
authz_emit() {
  local check=$1 url=$2 path=$3 ploc=$4 param_name=$5 evidence=$6
  local target=${SCOURSH_DAST_TARGET:-}
  _authz_catalog "$check" || return 0

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$_AUTHZC_TITLE"
  finding_set base_severity "$_AUTHZC_SEV"
  finding_set confidence "$_AUTHZC_CONF"
  finding_set cwe "$_AUTHZC_CWE"
  finding_set owasp "$_AUTHZC_OWASP"
  finding_set exposure external
  finding_set auth user
  finding_set sensitive_data true
  finding_set remediation "$_AUTHZC_REM"
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method GET
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$ploc"
  finding_set loc_param_name "$param_name"
  finding_set url "$url"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# 7. The IDOR pass
# ---------------------------------------------------------------------------
# `authz_idor_run TARGET LABEL_A LABEL_B SCRATCHDIR` - the whole object-level
# authorization probe over `_AUTHZ_CANDIDATES`, which `authz_candidates_set`
# must have filled first.
#
# THE TWO PHASES ARE SEPARATE AND THE ORDER MATTERS.  Every reference in a group
# is probed BEFORE anything is emitted, because whether a shared object is
# DAST-AUTHZ-IDOR-01 or DAST-AUTHZ-CROSS_IDENTITY_READ-01 depends on whether a
# refusal was observed ANYWHERE ELSE in that group - a fact that may only arrive
# on the last reference.  Emitting as we go would report the same object under
# the weaker id purely because of inventory ordering, which is the kind of
# non-determinism this repository already refuses in `_hdr_emit`'s "first
# endpoint in a fixed order" rule.
#
# Counters published for the phase's coverage records:
#   _AUTHZ_GROUPS_TESTED     groups actually probed
#   _AUTHZ_GROUPS_TRUNCATED  groups the MAX_GROUPS bound dropped
#   _AUTHZ_REFS_TESTED       object references probed
#   _AUTHZ_REFS_TRUNCATED    references the per-group bound dropped
#   _AUTHZ_PUBLIC_SKIPPED    references the anonymous control proved public
#   _AUTHZ_DIGEST_DIFFERED   both identities read it, but the bytes differed
#   _AUTHZ_REQUESTS          requests this pass issued
authz_idor_run() {
  local target=$1 a=$2 b=$3 dir=$4
  _AUTHZ_GROUPS_TESTED=0 _AUTHZ_GROUPS_TRUNCATED=0
  _AUTHZ_REFS_TESTED=0 _AUTHZ_REFS_TRUNCATED=0
  _AUTHZ_PUBLIC_SKIPPED=0 _AUTHZ_DIGEST_DIFFERED=0 _AUTHZ_REQUESTS=0

  (( ${#_AUTHZ_CANDIDATES[@]} > 0 )) || return 0
  mkdir -p "$dir"

  # Group keys in first-seen order.  An associative array records membership;
  # the ORDER comes from a plain array, because bash hash iteration order is not
  # defined and a report whose findings move between runs is a diff nobody can
  # read.
  local -a keys=()
  local -A seen_key=()
  local row key
  for row in "${_AUTHZ_CANDIDATES[@]+"${_AUTHZ_CANDIDATES[@]}"}"; do
    key=$(authz_group_key "$row")
    if [[ -z ${seen_key[$key]:-} ]]; then
      seen_key[$key]=1
      keys+=("$key")
    fi
  done

  local bodyA=$dir/a.body bodyB=$dir/b.body bodyN=$dir/anon.body
  local gi=0
  for key in "${keys[@]+"${keys[@]}"}"; do
    if (( gi >= _AUTHZ_MAX_GROUPS )); then
      _AUTHZ_GROUPS_TRUNCATED=$(( _AUTHZ_GROUPS_TRUNCATED + 1 ))
      continue
    fi
    gi=$(( gi + 1 ))
    _authz_group_probe "$target" "$a" "$b" "$key" "$bodyA" "$bodyB" "$bodyN"
  done
  _AUTHZ_GROUPS_TESTED=$gi
  rm -f "$bodyA" "$bodyB" "$bodyN"
  return 0
}

# One group: probe every reference, then decide.  Split out of `authz_idor_run`
# so the two phases are visibly separate rather than interleaved in one body.
_authz_group_probe() {
  local target=$1 a=$2 b=$3 key=$4 bodyA=$5 bodyB=$6 bodyN=$7
  local row rkey ref url path ploc param_name method
  local -a f=() shared=() refused_refs=()
  local -A ref_seen=()
  local n=0 refusal='' sA sB dA dB

  for row in "${_AUTHZ_CANDIDATES[@]+"${_AUTHZ_CANDIDATES[@]}"}"; do
    rkey=$(authz_group_key "$row")
    [[ $rkey == "$key" ]] || continue
    IFS=$'\t' read -r -a f <<<"$row"
    method=${f[0]} url=${f[1]} path=${f[2]} ploc=${f[3]} param_name=${f[4]} ref=${f[5]}
    # One probe per DISTINCT reference: an inventory that lists `/basket/5`
    # twice must not spend two requests on it.
    [[ -n ${ref_seen[$ref]:-} ]] && continue
    ref_seen[$ref]=1
    if (( n >= _AUTHZ_MAX_REFS_PER_GROUP )); then
      _AUTHZ_REFS_TRUNCATED=$(( _AUTHZ_REFS_TRUNCATED + 1 ))
      continue
    fi
    n=$(( n + 1 ))
    _AUTHZ_REFS_TESTED=$(( _AUTHZ_REFS_TESTED + 1 ))

    authz_probe_as "$target" "$a" "$method" "$url" "$bodyA" || continue
    _AUTHZ_REQUESTS=$(( _AUTHZ_REQUESTS + 1 ))
    sA=$_AUTHZ_STATUS dA=$_AUTHZ_DIGEST
    authz_probe_as "$target" "$b" "$method" "$url" "$bodyB" || continue
    _AUTHZ_REQUESTS=$(( _AUTHZ_REQUESTS + 1 ))
    sB=$_AUTHZ_STATUS dB=$_AUTHZ_DIGEST

    # The enforcement witness: one identity reads it, the other is refused it.
    # This is what separates the two check ids, and it is collected from EVERY
    # reference in the group rather than only from the one being reported.
    if { authz_status_ok "$sA" && authz_status_refused "$sB"; } \
      || { authz_status_ok "$sB" && authz_status_refused "$sA"; }; then
      refusal=$ref
      refused_refs+=("$ref")
      continue
    fi

    if ! authz_status_ok "$sA" || ! authz_status_ok "$sB"; then
      continue
    fi
    if [[ -z $dA || $dA != "$dB" ]]; then
      # Both read it but the bytes differ: either per-identity content (correct)
      # or a per-request nonce defeating the comparison (this file's stated
      # false-negative).  Counted, never reported as a finding.
      _AUTHZ_DIGEST_DIFFERED=$(( _AUTHZ_DIGEST_DIFFERED + 1 ))
      continue
    fi

    # The anonymous control.  PUBLIC is digest equality with what an identity
    # got, not a 2xx: an application answering an unauthenticated request with a
    # 200 login page would otherwise suppress every real finding on it.
    if authz_probe_anon "$target" "$method" "$url" "$bodyN"; then
      _AUTHZ_REQUESTS=$(( _AUTHZ_REQUESTS + 1 ))
      if authz_status_ok "$_AUTHZ_STATUS" && [[ -n $_AUTHZ_DIGEST && $_AUTHZ_DIGEST == "$dA" ]]; then
        _AUTHZ_PUBLIC_SKIPPED=$(( _AUTHZ_PUBLIC_SKIPPED + 1 ))
        continue
      fi
    fi
    shared+=("$row")
  done

  (( ${#shared[@]} > 0 )) || return 0

  local check evi
  for row in "${shared[@]+"${shared[@]}"}"; do
    IFS=$'\t' read -r -a f <<<"$row"
    method=${f[0]} url=${f[1]} path=${f[2]} ploc=${f[3]} param_name=${f[4]} ref=${f[5]}
    if [[ -n $refusal ]]; then
      check=DAST-AUTHZ-IDOR-01
      printf -v evi '%s' "identities '$a' and '$b' each requested $method $path (object reference '$ref', $ploc parameter '$param_name') and received a byte-identical response; an unauthenticated request for the same reference did not. Under the same path template, reference '$refusal' WAS refused to one of the two identities, so this endpoint does enforce per-object ownership - which makes this reference readable by an identity that does not own it rather than a resource the application shares. No response body is reproduced here and nothing was modified: every request was a $method."
    else
      check=DAST-AUTHZ-CROSS_IDENTITY_READ-01
      printf -v evi '%s' "identities '$a' and '$b' each requested $method $path (object reference '$ref', $ploc parameter '$param_name') and received a byte-identical response; an unauthenticated request for the same reference did not, so the object is not public. No reference under this path template was refused to either identity, so this endpoint may legitimately serve one shared resource to every authenticated user - confirm which it is. No response body is reproduced here and nothing was modified."
    fi
    authz_selected "$check" || continue
    authz_emit "$check" "$url" "$path" "$ploc" "$param_name" "$evi"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 8. The excessive-data-exposure pass
# ---------------------------------------------------------------------------
# `authz_other_identity_needle TARGET LABEL` - the identifier the operator
# configured for LABEL, or '' when there is none or it is too short to be
# discriminating.
#
# THE LENGTH FLOOR IS NOT COSMETIC.  A two- or three-character identifier
# ("bo", "abc") occurs inside ordinary English words, inside a base64 blob and
# inside a hex digest, so a substring test on it reports every response on the
# target.  Five is the shortest length at which the test carries information;
# below it the check declines to run rather than emitting a finding it cannot
# stand behind.  The value itself is never logged, never put in a finding, and
# never becomes an argument (see `authz_body_contains`).
authz_other_identity_needle() {
  local target=$1 label=$2 v=''
  _dast_auth_index_set "$target" "$label" || return 0
  v=$(_dast_auth_field username '')
  [[ ${#v} -ge 5 ]] || return 0
  printf '%s' "$v"
}

# `authz_exposure_run TARGET LABEL_A LABEL_B ENDPOINTS_FILE SCRATCHDIR` -
# §7.4's "call an authenticated profile/bootstrap endpoint and flag when the
# response body contains far more fields than the view needs".
#
# It requests up to `_AUTHZ_MAX_EXPOSURE_ENDPOINTS` idempotent endpoints as
# identity A - JSON-typed ones first, since a field-name scan of an HTML page
# finds nothing and still costs a request - and applies two independent tests to
# each response:
#
#   1. the vendored sensitive-field list, matched against FIELD NAMES only;
#   2. whether the response carries the identifier configured for identity B,
#      which is §7.4's "other users' data" arm and is the one test here that
#      genuinely needs the second identity.
#
# The two are separate check ids because they are separate claims: a field
# called `passwordHash` is over-exposure whoever it belongs to, while identity
# B's identifier in identity A's response is a cross-tenant leak whatever the
# field is called.  A single id would merge them and the report would lose which
# of the two was seen.
#
# ONE FINDING PER ENDPOINT PER CHECK, and the fingerprint's path template does
# the rest: a bootstrap payload reached under two concrete object references is
# one configuration mistake, not two.
authz_exposure_run() {
  local target=$1 a=$2 b=$3 file=$4 dir=$5
  _AUTHZ_EXPOSURE_TESTED=0 _AUTHZ_EXPOSURE_OVERSIZE=0 _AUTHZ_EXPOSURE_REQUESTS=0
  mkdir -p "$dir"
  local body=$dir/exposure.body needle line method url path evi joined
  needle=$(authz_other_identity_needle "$target" "$b")
  local needle_a
  needle_a=$(authz_other_identity_needle "$target" "$a")
  # An identifier that is a substring of identity A's OWN identifier proves
  # nothing: `alice` inside `alice2` would report A's own profile as carrying
  # B's data.  Refuse the test rather than emit a finding that is an artefact of
  # how the operator named two accounts.
  if [[ -n $needle && -n $needle_a && ${needle_a,,} == *"${needle,,}"* ]]; then
    needle=''
    _AUTHZ_NEEDLE_AMBIGUOUS=1
  else
    _AUTHZ_NEEDLE_AMBIGUOUS=0
  fi

  while IFS=$'\t' read -r method url path; do
    [[ -n $url ]] || continue
    (( _AUTHZ_EXPOSURE_TESTED >= _AUTHZ_MAX_EXPOSURE_ENDPOINTS )) && break
    _AUTHZ_EXPOSURE_TESTED=$(( _AUTHZ_EXPOSURE_TESTED + 1 ))
    authz_probe_as "$target" "$a" "$method" "$url" "$body" || continue
    _AUTHZ_EXPOSURE_REQUESTS=$(( _AUTHZ_EXPOSURE_REQUESTS + 1 ))
    authz_status_ok "$_AUTHZ_STATUS" || continue
    if ! authz_body_within_bounds "$body"; then
      _AUTHZ_EXPOSURE_OVERSIZE=$(( _AUTHZ_EXPOSURE_OVERSIZE + 1 ))
      continue
    fi

    if authz_selected DAST-AUTHZ-EXCESSIVE_DATA-01 && authz_scan_body "$body"; then
      joined=$(printf '%s, ' "${_AUTHZ_HITS[@]+"${_AUTHZ_HITS[@]}"}")
      joined=${joined%, }
      printf -v evi '%s' "the response to identity '$a' for $method $path carries $_AUTHZ_HIT_TOTAL field name(s) matching the sensitive-field list (modules/dast/sensitive-fields.txt): $joined. Only field NAMES were read and none of their values were read, digested or reproduced. Whether each field is genuinely over-exposed is a judgement about this application; what this check establishes is that the field reached an authenticated client."
      authz_emit DAST-AUTHZ-EXCESSIVE_DATA-01 "$url" "$path" body 'response-body' "$evi"
    fi

    if [[ -n $needle ]] && authz_selected DAST-AUTHZ-OTHER_IDENTITY_DATA-01 \
      && authz_body_contains "$body" "$needle"; then
      printf -v evi '%s' "the response to identity '$a' for $method $path contains the identifier configured for the SEPARATE identity '$b'. The identifier itself is not reproduced here because it comes from config/auth.conf, which is a credential file. Identity '$a' was authenticated as itself for this request and asked for nothing belonging to '$b'."
      authz_emit DAST-AUTHZ-OTHER_IDENTITY_DATA-01 "$url" "$path" body 'response-body' "$evi"
    fi
  done < <(authz_idempotent_endpoints "$target" "$file")
  rm -f "$body"
  return 0
}
