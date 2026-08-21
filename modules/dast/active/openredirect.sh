#!/usr/bin/env bash
# modules/dast/active/openredirect.sh - the §7.3 OPEN REDIRECT phase: an
# attacker-controlled host in the response's `Location` field, or in a
# meta-refresh pointing off-origin (docs/DESIGN.md §7.3;
# docs/STEP5-DAST-PLAN.md DAST-19, tier 4).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` (at tier `active`, so it does not run below
# `--intensity active`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
# The shared, testable half lives in modules/dast/active/inject_engine.sh (the
# inventory reader, the request composer, the one door to the network), which
# every §7.3 probe reuses; this file is the open-redirect-specific part: the
# sentinel, the candidate filter, and the two detections.
#
# THE SIGNAL, AND WHY IT NEEDS NO BASELINE. The probe puts a SENTINEL HOST into
# a redirect-influencing parameter and asks one question of the response: does
# the authority of the `Location` field (or of a meta-refresh URL) belong to
# that sentinel? The sentinel is a per-run RANDOM label under `.invalid`
# (RFC 6761 §6.4), so nothing but this run's own probe can have put it there -
# no cached page, no unrelated redirect, no earlier scan. That is what removes
# the baseline comparison every other §7.3 technique needs, and with it the
# whole class of "the endpoint always redirects somewhere, so we flagged it"
# false positive.
#
# NON-DESTRUCTIVE, RESTATED (docs/DESIGN.md §7.3; the DAST-36 amendment for
# DAST-14..DAST-25). Detection-only. Every payload is a URL; nothing is written,
# nothing is changed, nothing is exfiltrated. AND THE REDIRECT IS NEVER
# FOLLOWED: `_INJ_MAX_REDIRECTS=0` means `http_request` reads the `Location` and
# stops, so no hop off-origin is ever attempted. The scope gate would refuse
# such a hop anyway - it refuses everything not in config/scope.conf, and a
# `.invalid` label resolves nowhere in any case - but relying on a control to
# FIRE is testing it rather than using it, and the ticket's own wording is
# "detect the redirect; do not follow it off-origin". The sentinel's `.invalid`
# TLD is the third, independent layer: even a bug in the first two reaches a
# name the DNS root is required never to answer for.
#
# HONESTY. A clean result here must never read as "tested and safe" when it is
# "could not test". No parameter inventory, no redirect-influencing parameter
# among the ones discovered, or a missing payload file are each recorded as a
# coverage_gap/coverage_reduction the report renders, exactly as
# modules/dast/active/sqli.sh, auth.sh and crawl.sh do for their own gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic and evidence prose quotes URL and parameter syntax
#   literally, single-quoted on purpose.
# shellcheck disable=SC2016
# shellcheck source=modules/dast/active/inject_engine.sh
source "${BASH_SOURCE[0]%/*}/inject_engine.sh"
# For an authenticated probe pass, when the run asked for one and a session
# exists (its own sourced-once guard makes this cheap on a run where auth.sh
# already ran). Consulted only under --authed; a passive/unauthed run attaches
# nothing.
# shellcheck source=modules/dast/auth_engine.sh
source "${BASH_SOURCE[0]%/*}/../auth_engine.sh"

# ---------------------------------------------------------------------------
# Bounds (docs/DESIGN.md §15: a bound that truncates silently is
# indistinguishable from a surface that was really that small, so each one
# records a coverage_gap when it bites).
# ---------------------------------------------------------------------------
# Distinct parameters this probe will test in one run, on top of
# inject_engine.sh's own `_INJ_MAX_PARAMS` cap on the inventory read. Separate
# because this probe sends up to six requests per parameter: the engine's cap
# bounds the SURFACE, this one bounds THIS probe's share of the request budget.
: "${_OR_MAX_PARAMS:=60}"
# Bytes of a `Location` value or a meta-refresh URL carried into evidence.
: "${_OR_MAX_EVIDENCE_FIELD:=200}"

# `_or_safe_text TEXT [MAX]` - bounded, single-line target-derived text for an
# evidence sentence. `finding_set_evidence` still does the real escaping and
# redaction (tension 9/10); this only stops one pathological header from
# dominating the sentence it appears in.
_or_safe_text() {
  local s=$1 max=${2:-$_OR_MAX_EVIDENCE_FIELD}
  s=${s//$'\n'/ }
  s=${s//$'\r'/ }
  s=${s//$'\t'/ }
  if (( ${#s} > max )); then
    s="${s:0:max}..."
  fi
  printf '%s' "$s"
}

# `_or_read_payload_file FILE` - prints the file's lines with whole-line `#`
# comments and blanks dropped. Returns 1 when unreadable, so a caller degrades
# rather than erroring (the same helper, and the same contract, as
# modules/dast/active/sqli.sh's `_sqli_read_payload_file`).
_or_read_payload_file() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    printf '%s\n' "$line"
  done <"$f"
}

# ---------------------------------------------------------------------------
# The sentinel
# ---------------------------------------------------------------------------
# `_or_sentinel_set` - sets `_OR_SENTINEL` to a fresh random host under the
# RFC 6761 §6.4 `.invalid` special-use TLD.
#
# THREE PROPERTIES, EACH LOAD-BEARING, NONE OPTIONAL:
#
#   RESERVED. `.invalid` is reserved by RFC 6761 and is guaranteed never to
#   resolve, so this is not a host anybody owns - not the operator, not this
#   project, not an attacker. That keeps the probe target-agnostic (the
#   project's §1 hard rule, which tests/lint-shell.sh's DAST-35 checks enforce
#   over every shipped file) and it means a redirect followed by accident
#   reaches nothing rather than reaching somebody.
#
#   RANDOM. The label is fresh per call, so a `Location` naming it can only
#   have been produced by this probe's own request. That is what makes a
#   single response sufficient evidence, with no baseline and no retest.
#
#   NOT CONFIGURABLE. There is deliberately no flag, config key or environment
#   variable that replaces it. A knob here would be a way to point a scan's
#   redirects at a host the operator chose, which is a collaborator in an
#   attack rather than a scanner feature - the same argument
#   docs/STEP5-DAST-PLAN.md DAST-31 makes for the User-Agent product token
#   being unremovable.
#
# `$RANDOM` is used rather than /dev/urandom because this is an
# uniqueness-within-a-run label and not a secret: nothing about the probe's
# safety depends on an attacker being unable to guess it, only on no INNOCENT
# party having emitted it. It is drawn in four 15-bit chunks (bash's `$RANDOM`
# is 0..32767) and mixed with the pid so two probes in one process, and two
# processes started in the same second, still differ.
_or_sentinel_set() {
  local hex=''
  printf -v hex '%04x%04x%04x' "$(( RANDOM ))" "$(( RANDOM ))" "$(( RANDOM ^ $$ ))"
  _OR_SENTINEL="scoursh-or-${hex}.invalid"
}

# `_or_host_is_sentinel HOST` - 0 when HOST is the sentinel or any subdomain of
# it.
#
# THE SUBDOMAIN ARM IS NOT A LOOSENING, AND DROPPING IT WOULD MAKE PAYLOAD 6
# UNDETECTABLE. `https://<target>.<sentinel>/` has authority
# `www.example.com.scoursh-or-XXXX.invalid`, which is wholly under whoever owns
# the sentinel: every label to the RIGHT is what decides who a name belongs to.
# The mirror image - `scoursh-or-XXXX.invalid.www.example.com` - is a name the
# TARGET owns, and it correctly does NOT match, because the sentinel is a
# left-hand prefix there and not a suffix. Both directions are pinned in
# tests/suites/dast-openredirect.sh, because a `case $host in *$sentinel*)`
# substring test passes the first and WRONGLY passes the second.
_or_host_is_sentinel() {
  local h=${1,,}
  [[ $h == "$_OR_SENTINEL" || $h == *".$_OR_SENTINEL" ]]
}

# ---------------------------------------------------------------------------
# URL authority parsing - the one function this whole probe rests on
# ---------------------------------------------------------------------------
# `_or_url_host URL` - sets `_OR_HOST` to the lowercased HOST of URL and returns
# 0; returns 1 (leaving `_OR_HOST` empty) when URL carries no authority at all,
# which is the ordinary and SAFE case: a relative `Location: /dashboard` is an
# on-origin redirect and is not a finding.
#
# EVERY STEP BELOW EXISTS BECAUSE THE NAIVE VERSION OF IT SHIPS A DEFECT, AND
# THE TWO KINDS OF DEFECT FAIL IN OPPOSITE DIRECTIONS:
#
#   A SUBSTRING TEST OVER THE WHOLE URL IS A FALSE POSITIVE MACHINE. The single
#   commonest safe behaviour for a redirect parameter is to reflect it into the
#   response while redirecting on-origin -
#   `Location: https://www.example.com/login?next=https://<sentinel>/` contains
#   the sentinel and goes nowhere near it. Only the AUTHORITY counts.
#
#   IGNORING USERINFO IS A FALSE NEGATIVE, WHICH IS WORSE, BECAUSE IT READS AS
#   A PASS. In `https://www.example.com@<sentinel>/` the host is the sentinel
#   and `www.example.com` is a username. Splitting on the FIRST `@` gets this
#   backwards too when the userinfo itself contains one
#   (`https://user@example.com@<sentinel>/`), so the split is on the LAST `@`,
#   which is what WHATWG URL specifies.
#
# Backslashes are folded to slashes first, and leading slashes after a scheme
# are counted rather than required to be exactly two, because browsers do both
# (`/\host/` and `https:/host/` are off-origin redirects in a real browser) and
# a parser that is STRICTER than the browser is a parser that reports safe on a
# URL the browser will happily follow.
_or_url_host() {
  local u=$1 authority rest
  _OR_HOST=''
  # Leading/trailing whitespace, and the C0 controls a browser strips.
  u=${u#"${u%%[![:space:]]*}"}
  u=${u%"${u##*[![:space:]]}"}
  [[ -n $u ]] || return 1
  # WHATWG URL: for a special scheme `\` is equivalent to `/`. A target that
  # emits `/\evil/` is emitting an off-origin redirect, whatever it thought.
  u=${u//\\//}

  if [[ $u == //* ]]; then
    rest=${u#//}
  elif [[ $u =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]]; then
    rest=${u#*:}
    # `mailto:someone@example.com` and `javascript:...` have no authority at
    # all; only a form with at least one slash after the colon does. Browsers
    # normalise one slash to two for a special scheme, so one is enough.
    [[ $rest == /* ]] || return 1
    rest=${rest#"${rest%%[!/]*}"}
  else
    # Relative: same origin by construction. Not a finding, and saying so here
    # is what keeps every caller from having to know it.
    return 1
  fi

  # The authority ends at the first `/`, `?` or `#`.
  authority=${rest%%[/?#]*}
  [[ -n $authority ]] || return 1
  # Userinfo: everything through the LAST `@`.
  authority=${authority##*@}
  # Port. An IPv6 literal keeps its brackets until after the port is stripped,
  # so the colons inside it are never mistaken for a port separator.
  if [[ $authority == \[*\]* ]]; then
    authority=${authority%%\]*}
    authority=${authority#\[}
  else
    authority=${authority%%:*}
  fi
  [[ -n $authority ]] || return 1
  _OR_HOST=${authority,,}
  return 0
}

# `_or_location_of HEADERS` - sets `_OR_LOCATION` to the FINAL response's
# `Location` field value ('' when there is none) and `_OR_STATUS` to its status
# code. Returns 1 when HEADERS carries no status line at all.
#
# ONLY THE FINAL HOP COUNTS, AND THAT IS WHY THIS IS NOT A GREP.
# `http_request_capture`'s header sink ACCUMULATES every hop (lib/http.sh §9a),
# so a whole-file match would read an intermediate response's `Location` and
# report it as the delivered one's. This probe sets `_INJ_MAX_REDIRECTS=0` so
# there IS only ever one hop today - which is exactly the condition under which
# a whole-file grep would look correct and stay correct right up until somebody
# changed that number. The reset-on-status-line parse costs nothing and cannot
# be wrong either way; it is the same reading, and the same reason, as
# modules/dast/passive/headers_engine.sh's `hdr_parse_capture`.
_or_location_of() {
  # `_or_seen`, not `seen`: a plain `seen` is declared as an ARRAY in one of
  # the engines this phase sources, and shellcheck -x follows those sources, so
  # reusing the name earns an SC2178 on a variable that is correct.
  local blob=$1 line _or_seen=0
  _OR_LOCATION='' _OR_STATUS=''
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ $line =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}) ]]; then
      _OR_STATUS=${BASH_REMATCH[1]}
      _OR_LOCATION=''
      _or_seen=1
      continue
    fi
    (( _or_seen )) || continue
    if [[ $line =~ ^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*(.*)$ ]]; then
      _OR_LOCATION=${BASH_REMATCH[1]}
      _OR_LOCATION=${_OR_LOCATION%"${_OR_LOCATION##*[![:space:]]}"}
    fi
  done <<<"$blob"
  (( _or_seen )) || return 1
  return 0
}

# `_or_meta_refresh_url BODY` - sets `_OR_META_URL` to the URL of the first
# meta-refresh in BODY whose host belongs to the sentinel, and returns 0; 1 when
# there is none.
#
# The body is lowercased for the scan because every token being matched -
# `meta`, `http-equiv`, `refresh`, `url`, and a hostname - is case-insensitive
# by its own specification, and lowercasing once is cheaper and far less
# error-prone than a case-insensitive pattern for each. The tags are walked one
# at a time rather than matched with a single regex over the whole body because
# the attributes may appear in either order and with any quoting, and one
# all-cases regex for that is the kind of pattern nobody can read afterwards.
_or_meta_refresh_url() {
  local body=${1,,} rest tag u
  _OR_META_URL=''
  rest=$body
  while [[ $rest == *"<meta"* ]]; do
    rest=${rest#*<meta}
    tag=${rest%%>*}
    # A refresh directive needs both halves; `<meta name="refresh">` is not one.
    [[ $tag == *http-equiv* && $tag == *refresh* ]] || continue
    [[ $tag =~ url[[:space:]]*=[[:space:]]*[\'\"]?([^\'\"\>[:space:]]+) ]] || continue
    u=${BASH_REMATCH[1]}
    # A trailing quote can survive when the value was unquoted up to one.
    u=${u%\"}; u=${u%\'}
    _or_url_host "$u" || continue
    if _or_host_is_sentinel "$_OR_HOST"; then
      _OR_META_URL=$u
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# The candidate filter
# ---------------------------------------------------------------------------
# `_or_normalise_name NAME` - lowercased with `_`, `-` and `.` removed, so the
# single vendored entry `returnurl` matches `returnUrl`, `return_url`,
# `RETURN-URL` and `return.url`. FAILS under a plain case-sensitive exact match,
# which is the reading this exists to reject: `returnUrl` is the spelling half
# the web actually uses.
_or_normalise_name() {
  local n=${1,,}
  n=${n//_/}
  n=${n//-/}
  n=${n//./}
  printf '%s' "$n"
}

# `_or_is_candidate INDEX` - 0 when the parameter is worth probing for an open
# redirect. Sets `_OR_WHY` to `name` or `example` for the evidence sentence.
#
# TWO RULES, AND THE SECOND IS NOT A MAKEWEIGHT. The first is the vendored name
# list. The second is that the parameter's OBSERVED EXAMPLE is already an
# absolute or scheme-relative URL - which catches the redirect parameter this
# application happens to spell something the list has never heard of, and is
# frequently the stronger signal of the two. The example is used as a SHAPE and
# never replayed as a value (docs/INVENTORY-FORMAT.md §5).
#
# A parameter matching neither is NOT tested, and that is a coverage reduction
# the phase records with its count. It is a deliberate trade: probing all of
# them would turn one probe into six requests per discovered parameter.
_or_is_candidate() {
  local i=$1 name ex norm cand
  _OR_WHY=''
  name=${_INJ_NAME[$i]}
  norm=$(_or_normalise_name "$name")
  for cand in "${_OR_PARAM_NAMES[@]+"${_OR_PARAM_NAMES[@]}"}"; do
    if [[ $norm == "$cand" ]]; then
      _OR_WHY=name
      return 0
    fi
  done
  ex=${_INJ_EXAMPLE[$i]:-}
  if [[ $ex == http://* || $ex == https://* || $ex == //* ]]; then
    _OR_WHY=example
    return 0
  fi
  return 1
}

# `_or_authority_of URL` - the `host` or `host:port` of an endpoint URL, for the
# `%T` placeholder. Empty when the URL has no authority.
_or_authority_of() {
  local u=$1 rest
  rest=${u#*://}
  [[ $rest != "$u" ]] || { printf ''; return 0; }
  rest=${rest%%[/?#]*}
  rest=${rest##*@}
  printf '%s' "$rest"
}

# The path component of a URL, query and fragment removed, for the finding's
# location (the fingerprint templates it via path_template_of). A URL with no
# path is `/`. Same helper, same contract, as sqli.sh's `_sqli_path_of`.
_or_path_of() {
  local url=$1 rest
  url=${url%%#*}; url=${url%%\?*}
  rest=${url#*://}
  if [[ $rest == */* ]]; then printf '/%s' "${rest#*/}"; else printf '/'; fi
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
# TWO CHECK IDS, NOT ONE, FOR THE REASON sqli.sh's own three ids exist: the DAST
# location profile is (target, method, path_template, param_location,
# param_name) and carries nothing naming the SINK, so a `Location` finding and a
# meta-refresh finding on the same parameter would fingerprint identically and
# findings_merge would silently keep one. They are also genuinely different
# defects to fix and are graded differently - a `Location` redirect is followed
# by every client including a bare HTTP fetch, while a meta refresh is honoured
# only by a browser rendering the page.
_or_emit() {
  local i=$1 sink=$2 payload=$3 observed=$4 why=$5
  local name=${_INJ_NAME[$i]} loc=${_INJ_LOCATION[$i]} method=${_INJ_METHOD[$i]}
  local url=${_INJ_URL[$i]} target=${_INJ_TARGET[$i]:-${SCOURSH_DAST_TARGET:-}}
  local path check title base conf evi authv=none how
  path=$(_or_path_of "$url")
  [[ -n ${_INJ_AUTH_LABEL:-} ]] && authv=user
  case $why in
    name) how="it is named like a redirect destination" ;;
    *)    how="its observed example value was already an absolute URL" ;;
  esac
  case $sink in
    header)
      check=DAST-INJ-OPENREDIR_HEADER-01; base=medium; conf=high
      title='Open redirect: request parameter controls the Location header host'
      evi="parameter '$name' ($loc) of $method $path was probed because $how; sent the value '$(_or_safe_text "$payload")', the endpoint answered $_OR_STATUS with 'Location: $(_or_safe_text "$observed")', and the authority of that URL is the probe's own single-use sentinel host. Only this run's request can have put that name there, so the redirect destination is taken from request-controlled input without an allow-list. The redirect was NOT followed." ;;
    meta)
      check=DAST-INJ-OPENREDIR_META-01; base=medium; conf=high
      title='Open redirect: request parameter controls a meta-refresh destination'
      evi="parameter '$name' ($loc) of $method $path was probed because $how; sent the value '$(_or_safe_text "$payload")', and the response body carried a meta-refresh to '$(_or_safe_text "$observed")', whose authority is the probe's own single-use sentinel host. Only this run's request can have put that name there, so the client-side redirect destination is taken from request-controlled input without an allow-list. The redirect was NOT followed." ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe CWE-601
  finding_set owasp A01:2021
  finding_set exposure external
  finding_set auth "$authv"
  finding_set sensitive_data false
  finding_set remediation 'Do not build a redirect destination from request-controlled input. Redirect only to a server-side allow-list of paths or destination ids, resolving the request value to an entry in that list rather than using it as a URL. Where an absolute URL is unavoidable, parse it and compare the resulting HOST against an allow-list - never a prefix, substring or "starts with our domain" test, each of which is defeated by userinfo (https://yoursite@attacker/), by a target-prefixed subdomain (https://yoursite.attacker/), and by scheme-relative and backslash forms. Reject anything that is not a same-origin relative path.'
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method "$method"
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location "$loc"
  finding_set loc_param_name "$name"
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  return 0
}

# ---------------------------------------------------------------------------
# The phase
# ---------------------------------------------------------------------------
_dast_openredirect_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/openredirect.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  # The vendored data. SCOURSH_DAST_OPENREDIRECT_PAYLOAD_DIR overrides the
  # location so an operator can vendor their own set (the same swappable-seam
  # idiom lib/http.sh's transport/resolver hooks and sqli.sh's own payload dir
  # use) and so the graceful-degradation branch is testable against an empty
  # directory; unset, it is the shipped set.
  local pdir=${SCOURSH_DAST_OPENREDIRECT_PAYLOAD_DIR:-${BASH_SOURCE[0]%/*}/../payloads}
  local line
  _OR_PAYLOADS=() _OR_PARAM_NAMES=()
  # `|| true` inside the process substitution: an ABSENT data file is a normal,
  # handled state (the coverage_reduction branches below are what handle it),
  # and without it the reader's honest `return 1` fires lib/core.sh's ERR trap
  # in the subshell and prints a "command failed" line about a case nothing has
  # gone wrong in. The empty array is the signal; the diagnostic is noise.
  while IFS= read -r line; do _OR_PAYLOADS+=("$line"); done \
    < <(_or_read_payload_file "$pdir/openredirect-payloads.txt" || true)
  while IFS= read -r line; do _OR_PARAM_NAMES+=("$(_or_normalise_name "$line")"); done \
    < <(_or_read_payload_file "$pdir/openredirect-params.txt" || true)

  local do_header=1 do_meta=1
  # tension-15 per-check selection: scan.sh's filter chain records which ids
  # survived --profile-scan/--intensity/--allow-intrusive and exports them as
  # SCOURSH_SELECTED_CHECKS; modules/dast/engine.sh's `dast_check_selected`
  # answers it. Consulted only if that function exists (guarded exactly as
  # sqli.sh, cookies.sh and headers.sh already guard it), so this file does not
  # hard-depend on it: absent, everything the tier already permitted runs, which
  # is the "empty means all selected" fallback a direct-engine test relies on.
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-INJ-OPENREDIR_HEADER-01 || do_header=0
    dast_check_selected DAST-INJ-OPENREDIR_META-01 || do_meta=0
  fi

  if (( ${#_OR_PAYLOADS[@]} == 0 )); then
    run_record coverage_reduction "module=dast reason=openredirect_payloads_missing target=$target - modules/dast/payloads/openredirect-payloads.txt is absent or empty, so no open-redirect probe could be composed. This is a coverage reduction, not a clean result."
    run_record coverage_gap "dast openredirect: no open-redirect payloads are available on target '$target', so nothing was probed. A clean result is the absence of a test, not the absence of a problem."
    return 0
  fi
  if (( ${#_OR_PARAM_NAMES[@]} == 0 )); then
    # Not fatal to the probe: the URL-shaped-example rule still selects
    # candidates without the name list. It IS a reduction, and a large one on a
    # surface whose examples the crawler never captured, so it is recorded.
    run_record coverage_reduction "module=dast reason=openredirect_param_names_missing target=$target - modules/dast/payloads/openredirect-params.txt is absent or empty, so a redirect-influencing parameter was recognised only by its example value already being an absolute URL. Parameters named like a redirect destination but carrying no URL example were not probed."
  fi
  if (( do_header == 0 && do_meta == 0 )); then
    run_record coverage_gap "dast openredirect: every open-redirect check was filtered out of this run's check set on target '$target', so nothing was probed."
    return 0
  fi

  # `inject_inventory_load` defaults to SCOURSH_DAST_ENDPOINTS /
  # SCOURSH_DAST_PARAMETERS, and modules/dast/run.sh resolves BOTH before the
  # phase loop starts while modules/dast/crawl.sh writes them several phases
  # LATER in that same loop - so on the ordinary run the exports are empty on
  # exactly the run that has just discovered a surface. The run-directory
  # artifact is read as a fallback, the same fix (and the same paths)
  # modules/dast/passive/headers.sh already applies for itself; the export is
  # modules/dast/run.sh's own to correct and is filed as its own ticket rather
  # than changed under six parallel peers.
  local epf=${SCOURSH_DAST_ENDPOINTS:-} pf=${SCOURSH_DAST_PARAMETERS:-}
  if [[ -z $epf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/endpoints.json ]]; then
    epf=$SCOURSH_RUN_DIR/inventory/endpoints.json
  fi
  if [[ -z $pf && -n ${SCOURSH_RUN_DIR:-} && -s $SCOURSH_RUN_DIR/inventory/parameters.json ]]; then
    pf=$SCOURSH_RUN_DIR/inventory/parameters.json
  fi
  inject_inventory_load "$epf" "$pf"
  if (( _INJ_N == 0 )); then
    run_record coverage_reduction "module=dast reason=no_parameter_inventory target=$target - the crawler wrote no injectable parameter (docs/INVENTORY-FORMAT.md), so the open-redirect probe had no request field to test. Feed a spec/HAR (config/discovery.conf) or run the crawl against an application with discoverable parameters."
    run_record coverage_gap "dast openredirect: target '$target' has no known request parameters, so no open-redirect probe was sent. This is a coverage gap - nothing was tested - not a finding of safety."
    return 0
  fi

  # Optional authenticated pass. Only under --authed, and only if auth.sh
  # obtained at least one session this run; otherwise the probe runs against the
  # public surface and attaches nothing. A redirect parameter behind a login is
  # frequently the interesting one (the post-login `next=`), which is why this
  # is wired here rather than left to a later ticket.
  _INJ_AUTH_TARGET='' _INJ_AUTH_LABEL=''
  if [[ ${SCOURSH_DAST_AUTHED:-false} == true ]] && declare -F dast_auth_authenticated_labels_set >/dev/null; then
    dast_auth_authenticated_labels_set "$target"
    if (( ${#_DAST_AUTH_AUTHED_LABELS[@]} >= 1 )); then
      _INJ_AUTH_TARGET=$target
      _INJ_AUTH_LABEL=${_DAST_AUTH_AUTHED_LABELS[0]}
      run_record notes "module=dast phase=openredirect target=$target identity=$_INJ_AUTH_LABEL authenticated_probe=1"
    fi
  fi

  _or_sentinel_set
  # The two opt-in engine knobs (inject_engine.sh section 0a). Set for the whole
  # phase rather than per call: every request this probe sends wants the
  # response headers, and NONE of them may follow a redirect.
  _INJ_WANT_HEADERS=1
  _INJ_MAX_REDIRECTS=0

  local i tmpl value authority tested=0 skipped=0 uninjectable=0 capped=0
  local hit fired_header fired_meta
  for (( i = 0; i < _INJ_N; i++ )); do
    if ! _or_is_candidate "$i"; then
      skipped=$(( skipped + 1 ))
      continue
    fi
    if (( tested >= _OR_MAX_PARAMS )); then
      capped=$(( capped + 1 ))
      continue
    fi
    authority=$(_or_authority_of "${_INJ_URL[$i]}")
    hit=0 fired_header=0 fired_meta=0
    for tmpl in "${_OR_PAYLOADS[@]+"${_OR_PAYLOADS[@]}"}"; do
      value=${tmpl//%S/$_OR_SENTINEL}
      value=${value//%T/$authority}
      inject_send "$i" "$value" || continue
      # This parameter produced at least one usable response, so it really was
      # tested. Counted on the first success rather than before the loop, so a
      # parameter whose every request failed at the transport is not reported
      # as covered.
      (( hit )) || tested=$(( tested + 1 ))
      hit=1

      # BOTH SINKS ARE EVALUATED ON THE SAME RESPONSE BEFORE EITHER BREAKS OUT.
      # A page that 302s AND serves a meta refresh is two sinks reading the same
      # request field, and they are two check ids precisely so that both are
      # reported; checking the header first and breaking would report one and
      # silently drop the other, which is the collision the two ids exist to
      # prevent, reintroduced in control flow instead of in the fingerprint.
      if (( do_header && ! fired_header )) && _or_location_of "$_INJ_HEADERS" \
        && [[ -n $_OR_LOCATION ]] && _or_url_host "$_OR_LOCATION" \
        && _or_host_is_sentinel "$_OR_HOST"; then
        _or_emit "$i" header "$value" "$_OR_LOCATION" "$_OR_WHY"
        fired_header=1
      fi
      if (( do_meta && ! fired_meta )) && _or_meta_refresh_url "$_INJ_BODY"; then
        _or_emit "$i" meta "$value" "$_OR_META_URL" "$_OR_WHY"
        fired_meta=1
      fi
      # One confirmed signal is enough for this parameter: the remaining
      # payloads are alternative ways past a filter that has already been shown
      # not to hold, and sending them would spend the operator's request budget
      # to reach the same finding. The fix is the same allow-list whichever
      # payload got through.
      (( fired_header || fired_meta )) && break
    done
    (( hit )) || uninjectable=$(( uninjectable + 1 ))
  done

  # checks_run records the checks that LOADED AND EXECUTED (AGENTS.md's own
  # definition), which is the honest input modules/dast/run.sh's roll-up reads -
  # recorded only when at least one parameter was really probed, so a run with a
  # parameter surface but no candidate in it is not reported as covered.
  if (( tested > 0 )); then
    (( do_header )) && run_record checks_run DAST-INJ-OPENREDIR_HEADER-01
    (( do_meta )) && run_record checks_run DAST-INJ-OPENREDIR_META-01
  fi

  if (( _INJ_TRUNCATED > 0 )); then
    run_record coverage_gap "dast openredirect: the parameter surface on target '$target' exceeded the shared per-probe cap of $_INJ_MAX_PARAMS, so $_INJ_TRUNCATED parameter(s) never reached this probe at all. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( capped > 0 )); then
    run_record coverage_gap "dast openredirect: target '$target' had more redirect-influencing parameters than this probe's own cap of $_OR_MAX_PARAMS, so $capped candidate(s) were not probed for open redirect. This is a coverage bound, not a clean result."
  fi
  if (( skipped > 0 )); then
    run_record coverage_reduction "module=dast reason=openredirect_parameter_not_redirect_shaped target=$target count=$skipped - $skipped discovered parameter(s) were neither named like a redirect destination (modules/dast/payloads/openredirect-params.txt) nor carrying an absolute-URL example, so they were not probed for open redirect. Add the name to that file to include one."
  fi
  if (( uninjectable > 0 )); then
    run_record coverage_reduction "module=dast reason=openredirect_uninjectable_parameters target=$target count=$uninjectable - $uninjectable redirect-shaped parameter(s) were a GraphQL operation, a path segment with no template slot this probe could substitute, or an endpoint every request to which failed at the transport; they were not tested for open redirect here."
  fi
  if (( tested == 0 )); then
    run_record coverage_gap "dast openredirect: target '$target' had $_INJ_N discovered parameter(s) but none of them was a redirect-influencing parameter this probe could send a value to, so no open-redirect test was sent. A clean result here is the absence of a test."
  fi

  log_info "dast openredirect: target '$target' - probed $tested of $_INJ_N parameter(s) for open redirect (${#_OR_PAYLOADS[@]} payload(s), sentinel $_OR_SENTINEL, redirects never followed)"
  return 0
}

_dast_openredirect_phase
