#!/usr/bin/env bash
# modules/dast/active/inject_engine.sh - the shared pure library every §7.3
# injection probe reuses (docs/DESIGN.md §7.3; docs/STEP5-DAST-PLAN.md tier 4,
# DAST-14..DAST-25).
#
# WHY A SHARED ENGINE, AND WHAT IS AND IS NOT IN IT.  Every injection probe
# does the same three things - read the tension-21 parameter inventory, put a
# probe VALUE into one parameter while leaving the request otherwise valid, and
# send it through the ONE chokepoint - and only the payloads and the
# signal-detection differ.  The identical `run.sh`/`engine.sh` split
# modules/sast/ established (and modules/dast/auth.sh + auth_engine.sh mirror
# one level down) is used here: this file is the pure, testable half with the
# standard sourced-once guard and no side effects at source time, and the
# per-technique work (`active/sqli.sh`, `active/xss.sh`, ...) is the file
# `dast_run_phase` sources.  Building the parameter reader and the
# request-composer once, here, is what stops twelve peers each writing their
# own subtly different JSON reader for the same frozen artifact.
#
# WHAT THIS ENGINE OWES ITS CALLER.  It reads faithfully and it composes
# faithfully; it decides NOTHING about what may be requested.  Every request it
# sends goes through `http_request` (lib/http.sh), which is where tension 19's
# scope gate, DAST-01's rate limiter, the per-run request budget, the circuit
# breaker and DAST-32's ceilings all sit - a probe that composed its own
# request off the inventory and dialled it itself would be the second path to
# the network tension 19 exists to make impossible.  The inventory is UNTRUSTED
# target output (tension 10, docs/INVENTORY-FORMAT.md §6): a parameter name and
# an endpoint URL are attacker-controlled text, so a discovered URL is re-gated
# by `http_request` on the way out exactly as a crawled link is.
#
# NON-DESTRUCTIVE IS A PROPERTY OF THE PAYLOADS, NOT OF THIS FILE.  This engine
# will send whatever VALUE a probe hands it; the "read-only, no data
# modification, evidence-only" contract docs/DESIGN.md §7.3 states (and the
# DAST-36 amendment restates for DAST-14..DAST-25) is enforced by each probe's
# vendored payloads carrying no `DROP`/`DELETE`/`UPDATE`/`INSERT`, no stacked
# write, and no exfiltration - see `modules/dast/payloads/` and each probe's
# own header.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes parameter and URL syntax literally.
# shellcheck disable=SC2016

if [[ -n ${SCOURSH_DAST_INJECT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_DAST_INJECT_ENGINE_SOURCED=1

# lib/http.sh is the chokepoint; a dast run does not otherwise load it (see
# modules/dast/engine.sh's header), so the first phase that issues traffic
# sources it, guarded exactly as modules/dast/auth_engine.sh does.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi
# crawl_engine.sh is reused for its depth- and string-aware JSON flattener
# (`crawl_json_flatten`/`crawl_json_unescape`, docs/INVENTORY-FORMAT.md §7):
# the inventory is read THROUGH the same reader that wrote it, so a producer
# that formats the file differently is still read correctly. Its own
# sourced-once guard makes this a no-op when a crawl already ran this process.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"

# ---------------------------------------------------------------------------
# 0. Bounds (docs/DESIGN.md §15: a bound that truncates silently is
#    indistinguishable from a surface that was really that small).
# ---------------------------------------------------------------------------
# The number of distinct (endpoint, parameter) pairs a single probe will test
# in one run. It exists so a large discovered surface cannot turn one probe
# into an unbounded request storm against an authorised target, on top of the
# per-run request budget the chokepoint already enforces. When it bites the
# probe records a coverage_gap naming it, rather than stopping silently.
: "${_INJ_MAX_PARAMS:=200}"
# Bytes of a response body read back for signal detection. A probe compares
# whole bodies, so an unbounded read on a large download would be the memory
# hazard the crawler's own 512 KiB parse bound guards against.
: "${_INJ_MAX_BODY_BYTES:=262144}"
# Bytes of the raw response-header capture read back for `_INJ_WANT_HEADERS`
# probes (DAST-19's Location-header signal, and any sibling that reads
# `_INJ_HEADERS`). A header block is normally a few hundred bytes to a few
# KiB; 64 KiB is generous headroom for a target that returns an unusually
# large or repeated header set while still being a real bound rather than none
# at all.
: "${_INJ_MAX_HEADERS_BYTES:=65536}"
# The two lengths are treated as "the same size" when they differ by no more
# than the LARGER of these two - an absolute floor for tiny pages and a
# proportion for large ones - so a boolean differential is a real content
# change rather than a one-token reflection difference. See `inject_body_sig`.
: "${_INJ_LEN_TOLERANCE_ABS:=24}"
: "${_INJ_LEN_TOLERANCE_PCT:=3}"

# ---------------------------------------------------------------------------
# 0a. Two OPT-IN knobs a probe sets for itself (both default to the behaviour
#     every probe written before them already had, so neither changes an
#     existing caller by one byte).
# ---------------------------------------------------------------------------
# `_INJ_WANT_HEADERS` - 1 to have `inject_send` capture the RESPONSE HEADERS and
# publish them in `_INJ_HEADERS`. Off by default because most §7.3 techniques
# read only the body, and a capture nobody reads is a scratch file per request.
# DAST-19 (`active/openredirect.sh`) needs it: its entire signal is a `Location`
# field, which `http_request` publishes to NO global - `_HTTP_LAST_STATUS` and
# `_HTTP_LAST_CONTENT_TYPE` are all it sets, and the Location it read stays a
# local of the redirect loop. The header CAPTURE is the only channel that
# carries it out, which is the same conclusion modules/dast/passive/headers.sh
# reached for its own family.
: "${_INJ_WANT_HEADERS:=0}"
# `_INJ_MAX_REDIRECTS` - hops `inject_send` lets `http_request` follow. Empty
# means "whatever SCOURSH_DAST_INJECT_MAX_REDIRECTS says, else 2", which is what
# every caller got before this existed.
#
# A PROBE THAT SETS IT TO 0 IS MAKING A SAFETY STATEMENT, NOT AN OPTIMISATION.
# An open-redirect probe's success condition is that the target hands back a
# `Location` pointing somewhere the operator never authorised; following it is
# the one thing the probe must not do, and "the scope gate would have refused
# the hop anyway" is not a reason to ask - a control you rely on having to fire
# is a control you are testing rather than using. Setting it to 0 means the
# question never reaches the gate.
: "${_INJ_MAX_REDIRECTS:=}"

# ---------------------------------------------------------------------------
# 1. Percent-encoding
# ---------------------------------------------------------------------------
# `inject_urlencode TEXT [KEEP_SLASH]` - sets `_INJ_ENC` to TEXT with every
# byte outside the RFC 3986 unreserved set percent-encoded. A path SEGMENT
# encodes `/` as well (KEEP_SLASH empty); a query/body value keeps nothing
# special beyond the unreserved set, which is always safe. Pure bash: the value
# may carry a credential-shaped example, and a fork is the one thing that could
# put it in another process's view (tension 9).
inject_urlencode() {
  local s=$1 keep_slash=${2:-} out='' i c
  for (( i = 0; i < ${#s}; i++ )); do
    c=${s:i:1}
    case $c in
      [A-Za-z0-9._~-]) out+=$c ;;
      /) if [[ -n $keep_slash ]]; then out+=$c; else printf -v c '%%%02X' "'$c"; out+=$c; fi ;;
      *) printf -v c '%%%02X' "'$c"; out+=$c ;;
    esac
  done
  _INJ_ENC=$out
}

# ---------------------------------------------------------------------------
# 2. The parameter inventory (docs/INVENTORY-FORMAT.md, tension 21)
# ---------------------------------------------------------------------------
# `inject_inventory_load [ENDPOINTS_FILE] [PARAMETERS_FILE] [PHASE]` - reads the
# two frozen artifacts into the flat, parallel arrays a probe iterates. Defaults
# to the paths modules/dast/run.sh exports (`SCOURSH_DAST_ENDPOINTS`,
# `SCOURSH_DAST_PARAMETERS`). Sets `_INJ_N` to the number of injectable
# parameters found and returns 0 always - an absent, empty, or unusable
# inventory is the normal state (docs/INVENTORY-FORMAT.md §1) and leaves `_INJ_N`
# at 0, never an error.
#
# EVERY ROW IS SCOPE PRE-CHECKED HERE, AND THAT IS DELIBERATELY NOT LEFT TO THE
# TWELVE CALLERS.  This function is the single door a dozen phase scripts reach
# the endpoint inventory through (every §7.3 injection probe, plus
# passive/cookies.sh and active/methods.sh), and each of them hands the URL it
# gets back to `http_request`, which gates FATALLY - one out-of-scope row in an
# artifact this scanner did not author would abort the whole run at exit 3.
# `modules/dast/engine.sh`'s `dast_endpoint_keep` (section 3b) is the shared,
# NON-fatal pre-check, and applying it at the load rather than at each of the
# twelve request sites is tension 19's own argument one level down: a control
# each caller must remember to apply is not a control, and the caller that
# forgets is the one that ships. `http_request` still re-gates every URL it is
# handed and every redirect hop - deleting either half is a real defect, in
# opposite directions.
#
# PHASE names the recorded `coverage_reduction` and nothing else; it defaults to
# `inject` so an existing two-argument caller is unchanged.
#
# `declare -g`, never bare, for the reason modules/dast/engine.sh's phase table
# documents at length: in a real run this file is sourced from inside
# `dast_run_phase`, so a declaration with no `-g` would create a local that dies
# with the phase.
#
# SC2034: the local `cur`/`pcur` accumulator maps are passed BY NAME to
# `_inject_flush_endpoint`/`_inject_flush_param`, which read them through
# `${!...}` indirection (Bash 4.2 has no namerefs), so every read is invisible
# to shellcheck here - exactly as crawl_engine.sh's own flush helpers.
# shellcheck disable=SC2034
inject_inventory_load() {
  local epf=${1:-${SCOURSH_DAST_ENDPOINTS:-}} pf=${2:-${SCOURSH_DAST_PARAMETERS:-}}
  local phase=${3:-inject}
  local sep=$'\x1f' p type v idx key rest last_idx=''
  declare -gA _INJ_EP_METHOD=() _INJ_EP_URL=() _INJ_EP_PATH=() _INJ_EP_BODY_TYPE=()
  declare -ga _INJ_TARGET=() _INJ_METHOD=() _INJ_URL=() _INJ_PATH=()
  declare -ga _INJ_NAME=() _INJ_LOCATION=() _INJ_EXAMPLE=() _INJ_EPID=() _INJ_BODY_TYPE=()
  declare -g _INJ_N=0 _INJ_TRUNCATED=0
  # The accumulator is reset per load, so a second phase in the same process
  # never inherits the first one's count. Guarded because a direct-engine suite
  # sources this file with no modules/dast/engine.sh in the process.
  if declare -F dast_scope_skips_reset >/dev/null; then
    dast_scope_skips_reset
  fi

  # A parameter without an endpoint to hang on cannot be composed into a
  # request, so the endpoints are read first into a by-id map the parameter
  # walk then joins against on `endpoint_id`.
  if [[ -n $epf && -r $epf && -s $epf ]]; then
    local -A cur=()
    last_idx=''
    while IFS=$'\t' read -r p type v; do
      [[ $p == endpoints* ]] || continue
      rest=${p#endpoints}; rest=${rest#"$sep"}
      idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
      [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
      if [[ -n $last_idx && $idx != "$last_idx" ]]; then
        _inject_flush_endpoint cur
        cur=()
      fi
      last_idx=$idx
      [[ $type == s ]] && v=$(crawl_json_unescape "$v")
      cur[$key]=$v
    done < <(crawl_json_flatten <"$epf" 2>/dev/null)
    [[ -n $last_idx ]] && _inject_flush_endpoint cur
  fi

  # The roll-up is recorded on BOTH exits, not only the one that reads a
  # parameter file. passive/cookies.sh and active/methods.sh both call this with
  # an empty PARAMETERS_FILE and so leave through the early return below - which
  # is exactly where an endpoints-only consumer's dropped rows would otherwise go
  # unrecorded, turning "out of scope, never asked" into a silent clean result.
  if [[ -z $pf || ! -r $pf || ! -s $pf ]]; then
    if declare -F dast_scope_record_skips >/dev/null; then
      dast_scope_record_skips "$phase"
    fi
    return 0
  fi

  local -A pcur=()
  last_idx=''
  while IFS=$'\t' read -r p type v; do
    [[ $p == parameters* ]] || continue
    rest=${p#parameters}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _inject_flush_param pcur
      pcur=()
    fi
    last_idx=$idx
    [[ $type == s ]] && v=$(crawl_json_unescape "$v")
    pcur[$key]=$v
  done < <(crawl_json_flatten <"$pf" 2>/dev/null)
  [[ -n $last_idx ]] && _inject_flush_param pcur
  if declare -F dast_scope_record_skips >/dev/null; then
    dast_scope_record_skips "$phase"
  fi
  return 0
}

# Bash 4.2 has no namerefs (tension 24's frozen minimum), so the record is
# passed BY NAME and read through `${!...}` indirection, exactly as
# crawl_engine.sh's own flush helpers do.
_inject_flush_endpoint() {
  local arrname=$1
  local idr="${arrname}[id]" mr="${arrname}[method]" ur="${arrname}[url]" pr="${arrname}[path]"
  local btr="${arrname}[request_body_type]"
  local id=${!idr:-} m=${!mr:-GET} u=${!ur:-} pa=${!pr:-} bt=${!btr:-form}
  [[ -n $id && -n $u ]] || return 0
  # The scope pre-check, applied where the row enters the arrays rather than
  # where the request leaves - see `inject_inventory_load`'s header. Guarded,
  # and PERMISSIVE when absent, for modules/dast/engine.sh section 3b's reason:
  # a direct-engine suite sources this file with no engine.sh and no
  # lib/http.sh in the process, and there it cannot send the URL either.
  if declare -F dast_endpoint_keep >/dev/null; then
    dast_endpoint_keep "$u" || return 0
  fi
  # `request_body_type` (IMPORT-02, docs/INVENTORY-FORMAT.md §3): an OPTIONAL
  # endpoint field, additive to `scoursh.inventory.endpoints/1` (§9 - removing
  # or repurposing a field is a major bump; adding one is not). Absent, or
  # anything other than the literal `json`, degrades to `form` - the behaviour
  # every endpoint had before this field existed - rather than rejecting the
  # row or guessing: an unrecognised value here is exactly the "out-of-
  # vocabulary input from an untrusted producer" shape docs/INVENTORY-FORMAT.md
  # §6 already treats as fail-safe-degrade, not fail-closed.
  [[ $bt == json ]] || bt=form
  _INJ_EP_METHOD[$id]=$m
  _INJ_EP_URL[$id]=$u
  _INJ_EP_PATH[$id]=$pa
  _INJ_EP_BODY_TYPE[$id]=$bt
}

_inject_flush_param() {
  local arrname=$1
  local epr="${arrname}[endpoint_id]" tr="${arrname}[target]" mr="${arrname}[method]"
  local ur="${arrname}[url]" nr="${arrname}[name]" lr="${arrname}[location]" xr="${arrname}[example]"
  local epid=${!epr:-} t=${!tr:-} m=${!mr:-} u=${!ur:-} name=${!nr:-} loc=${!lr:-} ex=${!xr:-}
  [[ -n $name && -n $loc ]] || return 0
  # An endpoint the parameter names but the endpoints file did not carry is not
  # a request this probe can compose safely (no method, no base URL it can
  # trust), so it is skipped rather than guessed at. The parameter's own `url`
  # is a fallback for the location/method, since a HAR/OpenAPI parameter carries
  # both even when its endpoint row was dropped.
  local method url path body_type
  if [[ -n $epid && -n ${_INJ_EP_URL[$epid]:-} ]]; then
    method=${_INJ_EP_METHOD[$epid]:-GET}
    url=${_INJ_EP_URL[$epid]}
    path=${_INJ_EP_PATH[$epid]:-}
    body_type=${_INJ_EP_BODY_TYPE[$epid]:-form}
  elif [[ -n $u ]]; then
    # This branch is the one path by which a URL reaches a request WITHOUT
    # having passed `_inject_flush_endpoint`'s pre-check: the parameter's own
    # `url` fallback, used when the endpoints file carried no row for the
    # `endpoint_id` it names. It therefore needs the same check, and omitting it
    # here would leave the whole mechanism reachable around.
    if declare -F dast_endpoint_keep >/dev/null; then
      dast_endpoint_keep "$u" || return 0
    fi
    method=${m:-GET}
    url=$u
    path=''
    # No endpoint row means no `request_body_type` to read either; default to
    # `form`, the same fail-safe `_inject_flush_endpoint` applies.
    body_type=form
  else
    return 0
  fi
  if (( _INJ_N >= _INJ_MAX_PARAMS )); then
    _INJ_TRUNCATED=$(( _INJ_TRUNCATED + 1 ))
    return 0
  fi
  _INJ_TARGET+=("${t:-${SCOURSH_DAST_TARGET:-}}")
  _INJ_METHOD+=("$method")
  _INJ_URL+=("$url")
  _INJ_PATH+=("$path")
  _INJ_NAME+=("$name")
  _INJ_LOCATION+=("$loc")
  _INJ_EXAMPLE+=("$ex")
  _INJ_EPID+=("${epid:-}")
  _INJ_BODY_TYPE+=("$body_type")
  _INJ_N=$(( _INJ_N + 1 ))
}

# `inject_benign_value INDEX` - the value a sibling (or a baseline of the
# parameter itself) is sent with: the observed example when it is a usable
# scalar, else `1`. The example is NOT trusted as a credential to replay
# (docs/INVENTORY-FORMAT.md §5) - it is only a plausible shape so the endpoint
# answers as it normally would rather than erroring on a missing field.
inject_benign_value() {
  local ex=${_INJ_EXAMPLE[$1]:-}
  if [[ -n $ex && $ex != *$'\n'* && $ex != *$'\r'* ]]; then
    printf '%s' "$ex"
  else
    printf '1'
  fi
}

# ---------------------------------------------------------------------------
# 2a. The JSON request-body model (IMPORT-02, docs/INVENTORY-FORMAT.md §3)
# ---------------------------------------------------------------------------
# A `request_body_type=json` endpoint sends ONE JSON document composed from
# every `body`-location parameter, rather than the flat form-urlencoded blob
# every endpoint gets today. A parameter's `name` is then not a form field but
# an RFC 6901 JSON pointer (`/email`, `/orderLines/0/productId`) naming where
# in that document its value belongs; a bare name with no leading `/` is
# treated as a single top-level key, so `email` keeps meaning exactly what it
# always did. This mirrors `_xs_send_xml` (`xxe_ssrf.sh`): compose one body,
# set its own Content-Type, and never let a second body model coexist in the
# same request.
#
# The three functions below build the document from the flat leaf list
# `inject_send` accumulates per request (`_INJ_JB_PATH`/`_INJ_JB_VAL`,
# reset every call): `_inject_json_node` decides, PER LEVEL, whether that
# level is a JSON array or a JSON object - an array iff every immediate child
# key at it is a canonical RFC 6901 array index (`0`, `12`, never `01`) -
# and recurses; `_inject_json_child` is a leaf's own value when one exists
# exactly there, else the nested node under it. Every value passes through
# `json_string` (lib/core.sh), the repository's one JSON-string writer
# (docs/INVENTORY-FORMAT.md §6), because a parameter's payload is exactly the
# kind of attacker/probe-controlled text that writer exists for.

# `_inject_json_pointer_split POINTER` - splits an RFC 6901 pointer into
# `_INJ_PTR_SEGS`, decoding the two pointer escapes in the RFC's own order
# (`~1` -> `/` first, then `~0` -> `~`, so `~01` decodes to the one-character
# `~1` rather than a stray `/`). A NAME with no leading `/` is not a pointer
# at all - treated as one top-level key, so a flat body parameter (`email`)
# never has to be rewritten as `/email` to keep working.
_inject_json_pointer_split() {
  local ptr=$1
  _INJ_PTR_SEGS=()
  if [[ -z $ptr ]]; then
    return 0
  fi
  if [[ ${ptr:0:1} != / ]]; then
    _INJ_PTR_SEGS=("$ptr")
    return 0
  fi
  local rest=${ptr#/}
  local IFS=/
  read -r -a _INJ_PTR_SEGS <<<"$rest"
  local i seg
  for (( i = 0; i < ${#_INJ_PTR_SEGS[@]}; i++ )); do
    seg=${_INJ_PTR_SEGS[$i]}
    seg=${seg//~1//}
    seg=${seg//~0/~}
    _INJ_PTR_SEGS[i]=$seg
  done
}

# `_inject_json_leaf_add NAME VALUE` - records one `body`-location parameter's
# resolved value (the payload under test, or a sibling's benign value) at its
# JSON pointer, into the flat leaf tables `_inject_json_build` renders from.
# Segments are joined by 0x1f, the same separator `crawl_json_flatten` already
# uses for a path (docs/INVENTORY-FORMAT.md §7), so a segment containing a
# literal `/` (already decoded out of `~1` above) can never be confused with a
# path boundary.
_inject_json_leaf_add() {
  local name=$1 val=$2
  _inject_json_pointer_split "$name"
  (( ${#_INJ_PTR_SEGS[@]} > 0 )) || return 0
  local joined='' seg first=1
  for seg in "${_INJ_PTR_SEGS[@]+"${_INJ_PTR_SEGS[@]}"}"; do
    if (( first )); then joined=$seg; first=0; else joined+=$'\x1f'"$seg"; fi
  done
  _INJ_JB_PATH+=("$joined")
  _INJ_JB_VAL+=("$val")
  _INJ_JB_N=$(( _INJ_JB_N + 1 ))
}

# `_inject_json_child CHILDPREFIX` - prints a leaf's own value when
# CHILDPREFIX names one exactly, else the nested object/array under it.
_inject_json_child() {
  local childprefix=$1
  local i
  for (( i = 0; i < _INJ_JB_N; i++ )); do
    if [[ ${_INJ_JB_PATH[$i]} == "$childprefix" ]]; then
      json_string "${_INJ_JB_VAL[$i]}"
      return 0
    fi
  done
  _inject_json_node "$childprefix"
}

# `_inject_json_node PREFIX` - prints the JSON value built from every
# `_INJ_JB_PATH` entry immediately or transitively under PREFIX (empty for
# the document root). See the section header above for the array/object
# decision.
_inject_json_node() {
  local prefix=$1
  local -a child_keys=()
  local -A seen=()
  local i path relative first
  for (( i = 0; i < _INJ_JB_N; i++ )); do
    path=${_INJ_JB_PATH[$i]}
    if [[ -z $prefix ]]; then
      relative=$path
    else
      case $path in
        "$prefix"$'\x1f'*) relative=${path#"$prefix"$'\x1f'} ;;
        *) continue ;;
      esac
    fi
    [[ -n $relative ]] || continue
    first=${relative%%$'\x1f'*}
    if [[ -z ${seen[$first]+x} ]]; then
      seen[$first]=1
      child_keys+=("$first")
    fi
  done

  if (( ${#child_keys[@]} == 0 )); then
    printf 'null'
    return 0
  fi

  # A level is an array iff EVERY immediate child key at it is a canonical
  # non-negative integer (RFC 6901's own array-index grammar - `0`, `12`,
  # never `01` or anything non-numeric). One non-numeric key anywhere at a
  # level makes the whole level an object instead, which is the same rule a
  # human reading a mixed set of keys would apply.
  local is_array=1
  for first in "${child_keys[@]+"${child_keys[@]}"}"; do
    [[ $first =~ ^(0|[1-9][0-9]*)$ ]] || { is_array=0; break; }
  done

  local out sep='' childprefix
  if (( is_array )); then
    local -a sorted=()
    while IFS= read -r first; do
      [[ -n $first ]] && sorted+=("$first")
    done < <(printf '%s\n' "${child_keys[@]+"${child_keys[@]}"}" | sort -n)
    out='['
    for first in "${sorted[@]+"${sorted[@]}"}"; do
      [[ -z $prefix ]] && childprefix=$first || childprefix="$prefix"$'\x1f'"$first"
      out+="$sep$(_inject_json_child "$childprefix")"
      sep=','
    done
    out+=']'
  else
    out='{'
    for first in "${child_keys[@]+"${child_keys[@]}"}"; do
      [[ -z $prefix ]] && childprefix=$first || childprefix="$prefix"$'\x1f'"$first"
      out+="$sep$(json_string "$first"):$(_inject_json_child "$childprefix")"
      sep=','
    done
    out+='}'
  fi
  printf '%s' "$out"
}

# `_inject_json_build` - sets `_INJ_JSON_DOC` to the document rendered from
# the current `_INJ_JB_*` leaf tables, or `{}` when the endpoint carried no
# `body`-location parameter at all. A JSON endpoint with nothing to inject
# still needs SOME valid JSON body to send; an empty object is the
# conservative choice, never invented content.
_inject_json_build() {
  if (( _INJ_JB_N == 0 )); then
    _INJ_JSON_DOC='{}'
    return 0
  fi
  _INJ_JSON_DOC=$(_inject_json_node "")
}

# ---------------------------------------------------------------------------
# 3. Request composition + send (the one door to the network)
# ---------------------------------------------------------------------------
# `inject_send INDEX VALUE` - send endpoint `_INJ_*[INDEX]` with its own
# parameter set to VALUE and every SIBLING parameter of the same endpoint set
# to its benign value, so the request is valid apart from the one field under
# test. Sets `_INJ_STATUS`, `_INJ_BODY` (up to _INJ_MAX_BODY_BYTES),
# `_INJ_ELAPSED_NS`, and `_INJ_SENT_URL`. Returns 0 on a usable response, 1 on
# a transport failure OR a location this engine cannot inject (graphql, a path
# parameter with no `{name}` slot, or a `location` outside the seven-value
# vocabulary), leaving `_INJ_STATUS` empty.
#
# THE INJECTED VALUE GOES WHERE THE PARAMETER'S `location` SAYS, which is the
# whole point of docs/INVENTORY-FORMAT.md §3's location vocabulary and
# docs/DESIGN.md §7.3's "query params, body/JSON fields, headers, and path
# segments - not just top-level query strings". A `body`-location parameter on
# an endpoint whose `request_body_type` is `json` (IMPORT-02) is composed into
# ONE JSON document instead of the flat form-urlencoded body every other
# endpoint gets - see section 2a.
inject_send() {
  local index=$1 value=$2
  local epid=${_INJ_EPID[$index]} inj_name=${_INJ_NAME[$index]} inj_loc=${_INJ_LOCATION[$index]}
  local method=${_INJ_METHOD[$index]} base=${_INJ_URL[$index]} tmpl_path=${_INJ_PATH[$index]}
  local target=${_INJ_TARGET[$index]:-${SCOURSH_DAST_TARGET:-}}
  local body_type=${_INJ_BODY_TYPE[$index]:-form}
  _INJ_STATUS='' _INJ_BODY='' _INJ_ELAPSED_NS=0 _INJ_SENT_URL='' _INJ_HEADERS=''
  # Reset every call (IMPORT-02): these never carry over from a prior
  # inject_send invocation, exactly like every other `_INJ_*` scratch state
  # reset above.
  _INJ_JB_PATH=() _INJ_JB_VAL=() _INJ_JB_N=0 _INJ_JSON_DOC=''

  # graphql is a body/operation shape DAST-25/DAST-27 own, not a scalar this
  # engine can substitute one field of; a path segment with no template slot to
  # replace cannot be injected either. Both are honest "cannot test", not
  # "tested and clean". The trailing `*)` is the same honesty applied to
  # anything OUTSIDE docs/INVENTORY-FORMAT.md §3's seven-value vocabulary: with
  # no default arm here, an unrecognised `location` (a future value, a typo, a
  # hand-written parameters.json) fell through to the dispatch loop below,
  # matched none of its cases, sent no payload, and still returned 0 - every
  # probe recorded it as "tested" while nothing was ever sent (IMPORT-05,
  # report §7b). `crawl_add_param` now rejects an out-of-vocabulary location at
  # import time, so this is a second, independent refusal for defence in depth.
  case $inj_loc in
    graphql) return 1 ;;
    path) [[ ${tmpl_path:-} == *"{$inj_name}"* || $base == *"{$inj_name}"* ]] || return 1 ;;
    query | body | formData | header | cookie) ;;
    *) return 1 ;;
  esac

  # Gather this endpoint's parameters, injecting into the one under test and
  # sending each sibling its benign value.
  local -a query=() form=()
  local -a hdr_names=() hdr_values=()
  local cookie='' path_out=$tmpl_path
  local j jn jl jv enc
  # The path we send comes from the endpoint's template when it has one, else
  # the base URL's own path is left as-is (query/body/header injection does not
  # touch the path).
  for (( j = 0; j < _INJ_N; j++ )); do
    [[ ${_INJ_EPID[$j]} == "$epid" && -n $epid ]] || { [[ $j == "$index" ]] || continue; }
    # Endpoints without an id (epid empty) group only the parameter itself.
    if [[ -z $epid && $j != "$index" ]]; then continue; fi
    jn=${_INJ_NAME[$j]}; jl=${_INJ_LOCATION[$j]}
    if [[ $j == "$index" ]]; then jv=$value; else jv=$(inject_benign_value "$j"); fi
    case $jl in
      query)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        inject_urlencode "$jn"; query+=("$_INJ_ENC=$enc")
        ;;
      body)
        # IMPORT-02: on a `json` endpoint, `name` is an RFC 6901 pointer into
        # ONE composed document rather than a form field - see section 2a.
        if [[ $body_type == json ]]; then
          _inject_json_leaf_add "$jn" "$jv"
        else
          inject_urlencode "$jv"; enc=$_INJ_ENC
          inject_urlencode "$jn"; form+=("$_INJ_ENC=$enc")
        fi
        ;;
      formData)
        # A `json` endpoint sends ONE body; a `formData` sibling is dropped
        # rather than merged into the JSON document, the same "two body
        # models cannot coexist in one request" rule `_xs_send_xml` already
        # applies to an XML body's own `body`/`formData` siblings.
        if [[ $body_type == json ]]; then
          :
        else
          inject_urlencode "$jv"; enc=$_INJ_ENC
          inject_urlencode "$jn"; form+=("$_INJ_ENC=$enc")
        fi
        ;;
      header)
        # A header value carrying CR/LF is refused by http_request_header as
        # request smuggling; a probe payload never contains one, and a sibling
        # example that did is dropped to a safe default rather than split.
        hdr_names+=("$jn"); hdr_values+=("$jv")
        ;;
      cookie)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        inject_urlencode "$jn"
        [[ -n $cookie ]] && cookie+='; '
        cookie+="$_INJ_ENC=$enc"
        ;;
      path)
        inject_urlencode "$jv"; enc=$_INJ_ENC
        path_out=${path_out//"{$jn}"/$enc}
        # The base URL may itself carry the template segment.
        base=${base//"{$jn}"/$enc}
        ;;
    esac
  done

  # Compose the URL: the endpoint base (query stripped by the crawler) with the
  # resolved path substituted in when a template was present, plus the query
  # string this probe built.
  local url=$base
  if [[ -n $path_out && $path_out != "$tmpl_path" ]]; then
    # Replace the base URL's path with the substituted template path, keeping
    # scheme://authority intact.
    local authority=${base#*://}
    local scheme=${base%%://*}
    authority=${authority%%/*}
    local slash=/
    [[ ${path_out:0:1} == / ]] && slash=''
    url="$scheme://$authority$slash$path_out"
  fi
  if (( ${#query[@]} > 0 )); then
    local IFS='&'
    url="$url?${query[*]}"
  fi
  _INJ_SENT_URL=$url

  http_request_reset
  # An authenticated identity, when the probe asked for one, is attached first;
  # dast_auth_apply is consulted only if it exists and the probe published the
  # identity, so a non-authed run attaches nothing (see modules/dast/active
  # probes' own auth wiring).
  if [[ -n ${_INJ_AUTH_TARGET:-} && -n ${_INJ_AUTH_LABEL:-} ]] \
    && declare -F dast_auth_apply >/dev/null; then
    dast_auth_apply "$_INJ_AUTH_TARGET" "$_INJ_AUTH_LABEL" || true
  fi
  local hi
  for (( hi = 0; hi < ${#hdr_names[@]}; hi++ )); do
    http_request_header "${hdr_names[$hi]}" "${hdr_values[$hi]}"
  done
  [[ -n $cookie ]] && http_request_header Cookie "$cookie"
  # IMPORT-02: a `json` endpoint always sends the composed document (even an
  # empty `{}` when it had no `body`-location parameter) and the form arm is
  # suppressed outright, never merely skipped-when-empty - two body models
  # cannot coexist in one request, mirroring `_xs_send_xml`. A `form`
  # endpoint is byte-identical to before this ticket.
  if [[ $body_type == json ]]; then
    _inject_json_build
    http_request_header Content-Type application/json
    http_request_body "$_INJ_JSON_DOC"
  elif (( ${#form[@]} > 0 )); then
    http_request_header Content-Type application/x-www-form-urlencoded
    local IFS='&'
    http_request_body "${form[*]}"
  fi

  local bodyf hdrf=''
  bodyf=$SCOURSH_SCRATCH/inj.$$.$index.body
  # The header sink is created only when a probe asked for one (section 0a), so
  # a probe that reads only bodies writes exactly the files it did before.
  (( _INJ_WANT_HEADERS )) && hdrf=$SCOURSH_SCRATCH/inj.$$.$index.hdrs
  http_request_capture "$bodyf" "$hdrf"

  # Timing is measured around http_request with the same clock the rest of the
  # codebase uses (now_epoch_ns, lib/core.sh), through a swappable hook so a
  # test can drive the time-based technique deterministically without a real
  # sleep - the same SCOURSH_HTTP_TRANSPORT/SCOURSH_HTTP_RESOLVE idiom lib/http.sh
  # already uses. The throttle (DAST-01) runs INSIDE http_request and adds delay
  # too, which is why a probe never reads one elapsed as truth: it takes the
  # MINIMUM across samples (throttle only ever ADDS), so the floor is the real
  # server time. See modules/dast/active/sqli.sh's time-based section.
  local t0 t1 maxred=${_INJ_MAX_REDIRECTS:-${SCOURSH_DAST_INJECT_MAX_REDIRECTS:-2}}
  [[ $maxred =~ ^[0-9]+$ ]] || maxred=2
  t0=$(_inject_now_ns)
  local rc=0
  http_request "$method" "$url" "$maxred" "$target" || rc=$?
  t1=$(_inject_now_ns)
  _INJ_ELAPSED_NS=$(( t1 - t0 ))
  (( _INJ_ELAPSED_NS >= 0 )) || _INJ_ELAPSED_NS=0

  if (( rc != 0 )); then
    rm -f "$bodyf" ${hdrf:+"$hdrf"}
    return 1
  fi
  _INJ_STATUS=$_HTTP_LAST_STATUS
  # Both reads are bounded AT READ TIME via `read -N`, never by a full slurp
  # trimmed afterward - the shared engine behind essentially every §7.3
  # injection probe (sqli, xss, cmdi, pathtraversal, ssti, nosqli, ldapi,
  # crlf, protopollution, and xxe/ssrf's parameter technique all call
  # `inject_send`), so this one call site has the widest blast radius of any
  # DAST body-capture site: the fix modules/dast/active/discovery.sh's own
  # `_discovery_probe` applies to its single caller applies here to all of
  # them at once. `read -N` returns non-zero at EOF for a response smaller
  # than the cap (the ordinary case, exactly as `-d ''` did for its own
  # ordinary case), so `|| true` stays required on both. NUL bytes are still
  # lost either way - bash variables cannot hold one - but `-N` reads through
  # an embedded NUL and keeps accumulating non-NUL bytes up to the cap, where
  # `-d ''` stopped dead at the first one; narrower loss in an already-lossy
  # edge case, not a new one.
  if [[ -r $bodyf ]]; then
    IFS= read -r -N "$_INJ_MAX_BODY_BYTES" _INJ_BODY <"$bodyf" || true
  fi
  if [[ -n $hdrf && -r $hdrf ]]; then
    IFS= read -r -N "$_INJ_MAX_HEADERS_BYTES" _INJ_HEADERS <"$hdrf" || true
  fi
  rm -f "$bodyf" ${hdrf:+"$hdrf"}
  return 0
}

# The clock hook. Overridable so the time-based technique is testable with no
# real sleep and no flakiness (a fake clock returns scripted timestamps).
_inject_now_ns() {
  if [[ -n ${SCOURSH_INJECT_NOW_NS:-} ]]; then
    "$SCOURSH_INJECT_NOW_NS"
  else
    now_epoch_ns
  fi
}

# ---------------------------------------------------------------------------
# 4. Response signals
# ---------------------------------------------------------------------------
# `inject_body_sig BODY [STRIP]` - a comparable signature of a response for the
# boolean differential: the byte length of BODY with every occurrence of STRIP
# (the exact injected value) removed first. Stripping the payload matters
# because a true and a false payload are DIFFERENT strings, so a page that
# merely reflects them back would differ by the reflection alone and read as a
# boolean signal that is not there. Sets `_INJ_SIG_LEN`.
inject_body_sig() {
  local body=$1 strip=${2:-}
  if [[ -n $strip ]]; then
    body=${body//"$strip"/}
  fi
  _INJ_SIG_LEN=${#body}
}

# `inject_len_similar A B` - 0 when two signature lengths are "the same size"
# within tolerance (see the bounds above), 1 otherwise. Two bodies that differ
# by no more than a couple of dozen bytes (a token, a whitespace run) are not a
# boolean differential; a page that changes structurally is.
inject_len_similar() {
  local a=$1 b=$2 diff tol pct
  diff=$(( a - b )); (( diff < 0 )) && diff=$(( -diff ))
  tol=$_INJ_LEN_TOLERANCE_ABS
  pct=$(( (a > b ? a : b) * _INJ_LEN_TOLERANCE_PCT / 100 ))
  (( pct > tol )) && tol=$pct
  (( diff <= tol ))
}

# `inject_body_has_signature BODY REGEX` - 0 when BODY matches the ERE REGEX,
# through scan_match (tension 4: grep exits 1 on no-match, which is the normal
# case, so a bare grep under pipefail would abort the run). BODY reaches the
# engine on stdin via a scratch file rather than as an argument, so a
# credential-shaped body never lands in argv.
inject_body_has_signature() {
  local body=$1 re=$2 f hits rc=0
  f=$SCOURSH_SCRATCH/inj.$$.sig.body
  hits=$SCOURSH_SCRATCH/inj.$$.sig.hits
  printf '%s' "$body" >"$f"
  # No `-E`: the engine array (SCOURSH_GREP) already selects ERE for grep and
  # regex for rg; passing grep's own `-E` to rg is an error. The signatures are
  # written in the portable ERE subset both engines read (rules/RULE-FORMAT.md).
  scan_match "$hits" -i -e "$re" -- "$f" || rc=$?
  rm -f "$f" "$hits"
  return "$rc"
}
