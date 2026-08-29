#!/usr/bin/env bash
# modules/dast/active/discovery.sh - the §7.2 SAFE-ACTIVE content-discovery
# PHASE (docs/DESIGN.md §7.2; docs/STEP5-DAST-PLAN.md DAST-12, tier 3).
#
# This is a PHASE SCRIPT: modules/dast/engine.sh's `dast_run_phase` reaches it
# with a plain `source` at tier `safe` (so it does not run below
# `--intensity safe`), so it inherits the whole run context and anything it
# emits lands in this process's shard. Per that function's contract it carries
# NO sourced-once guard - one run can legitimately reach the same phase twice.
#
# WHAT §7.2 ASKS FOR, AND HOW EACH PART IS DONE.  "Content discovery from the
# vendored wordlist (status-code + length heuristics), directory-listing
# detection, backup/temp file patterns (.bak, ~, .git/, .env)."  Three
# candidate sources feed one probe/heuristic pipeline:
#   (A) a small FIXED, IN-CODE set of well-known sensitive paths (.git/HEAD,
#       .env, .htaccess, ...) - the two §7.2 names explicitly plus their close
#       siblings.  This is an algorithm constant, not "the wordlist".
#   (B) backup/temp variants DERIVED from the crawl inventory's own endpoint
#       paths by appending a small FIXED, IN-CODE suffix set (.bak, ~, .old,
#       ...).  Also not "the wordlist" - it needs no external list, it reshapes
#       paths the crawl already found.
#   (C) the VENDORED WORDLIST of candidate paths - see "THE WORDLIST" below.
# Every candidate is decided by the same soft-404 baseline + status/length
# heuristic, and any hit whose body looks like a directory index also emits a
# directory-listing finding.
#
# THE WORDLIST IS VENDORED AND NOT COMMITTED (docs/DESIGN.md §1, the no-egress
# rule; docs/STEP5-DAST-PLAN.md DAST-12).  No content-discovery wordlist ships
# in this repository: an online or unbounded list would break both the
# egress-restricted premise and the request budget.  The list is read FROM DISK
# at `$SCOURSH_INSTALL_ROOT/modules/dast/wordlists/content-discovery.txt` by
# default (absent in a fresh clone; only a README lives there), overridable to
# any vendored file with `SCOURSH_DAST_DISCOVERY_WORDLIST`.  It is BOUNDED: at
# most `_DISCOVERY_MAX_WORDS` entries are probed and a larger list is truncated
# with a recorded coverage_gap, so the list's size can never turn one phase
# into an unbounded request storm on top of the per-run budget the chokepoint
# already enforces.  An ABSENT or EMPTY wordlist degrades technique (C) to a
# recorded coverage_gap/coverage_reduction and never errors (docs/DESIGN.md
# §15); (A) and (B) still run, because neither needs the list.
#
# NON-DESTRUCTIVE (docs/DESIGN.md §7.2/§7.3 posture).  Every request is a plain
# read-only GET of a candidate path; nothing is written, submitted, or deleted.
# This is content DISCOVERY - it observes whether a resource is reachable, it
# never acts on one.
#
# EVERY REQUEST GOES THROUGH lib/http.sh (tension 19), which is also where
# DAST-01's rate limiter, per-run request budget, circuit breaker and DAST-32's
# ceilings all sit.  A candidate URL is composed from the target's own base-url
# (a candidate is always resolved UNDER the authorised authority) and is still
# re-gated by `http_request` on the way out - a discovered inventory endpoint
# is UNTRUSTED target output (tension 10), so a candidate that resolves off the
# authorised surface is pre-filtered (not fatally) and, if it survives, gated
# again by the chokepoint exactly as a crawled link is.
#
# HONESTY.  A clean result here must never read as "tested and safe" when it is
# "could not test": an unreachable base-url, an absent wordlist, or a truncating
# bound are each recorded as a coverage_gap/coverage_reduction the report
# renders, exactly as modules/dast/crawl.sh and active/sqli.sh do for their own
# gaps.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes path and flag syntax literally.
# shellcheck disable=SC2016

# crawl_engine.sh supplies `crawl_url_resolve` (RFC 3986 URL join, used to hang
# a candidate path off the target's base-url), `crawl_safe_text` (control-
# character-safe rendering of target-derived text on its way to a record), and
# the JSON flattener the backup-derivation reads the endpoints inventory
# through.  Its own sourced-once guard makes this a no-op when a crawl already
# ran this process.
# shellcheck source=modules/dast/crawl_engine.sh
source "${BASH_SOURCE[0]%/*}/../crawl_engine.sh"
# lib/http.sh is the chokepoint (and pulls in lib/config.sh for
# `config_scope_field`).  A dast run loads it lazily at the first phase that
# issues traffic - auth.sh already does before this phase runs in a real run,
# but this phase must not depend on that order, so it sources it here, guarded
# exactly as modules/dast/active/inject_engine.sh does.
if [[ -z ${SCOURSH_HTTP_SOURCED:-} ]]; then
  # shellcheck source=lib/http.sh
  source "${BASH_SOURCE[0]%/*}/../../../lib/http.sh"
fi

# ---------------------------------------------------------------------------
# 0. Bounds (docs/DESIGN.md §15: a bound that truncates silently is
#    indistinguishable from a surface that was really that small).
# ---------------------------------------------------------------------------
# The number of vendored wordlist entries probed in one run.  It bounds the
# request cost of technique (C) on top of the per-run budget the chokepoint
# enforces; when it bites, a coverage_gap names it.
: "${_DISCOVERY_MAX_WORDS:=500}"
# A hard ceiling on the TOTAL probe requests this phase sends in one run, across
# all three techniques.  A second, absolute backstop so a large inventory plus a
# large wordlist can never combine into an unbounded storm.
: "${_DISCOVERY_MAX_REQUESTS:=600}"
# Bytes of a response body read back for the directory-listing signal and the
# length heuristic.  An unbounded read on a large download would be the memory
# hazard the crawler's own parse bound guards against.
: "${_DISCOVERY_MAX_BODY_BYTES:=262144}"
# Two response lengths are "the same size" when they differ by no more than the
# LARGER of an absolute floor and a proportion - so a soft-404 page whose body
# carries the echoed path (a few bytes longer each time) is still recognised as
# the not-found baseline rather than read as a distinct resource.
: "${_DISCOVERY_LEN_TOL_ABS:=64}"
: "${_DISCOVERY_LEN_TOL_PCT:=5}"
# The longest candidate path accepted from a wordlist; a pathological entry is
# dropped rather than sent.
: "${_DISCOVERY_MAX_WORD_LEN:=128}"

# ---------------------------------------------------------------------------
# 1. The fixed, in-code candidate sets (NOT the vendored wordlist)
# ---------------------------------------------------------------------------
# Backup/temp suffixes appended to a KNOWN path (technique B).  docs/DESIGN.md
# §7.2 names `.bak` and `~` explicitly; the rest are the conventional editor and
# archive spellings of the same "a working copy was left served" hazard.
_discovery_backup_suffixes() {
  printf '%s\n' '.bak' '~' '.old' '.orig' '.save' '.swp' '.tmp' '.copy' '.backup'
}

# Well-known sensitive paths (technique A).  docs/DESIGN.md §7.2 names `.git/`
# and `.env` explicitly; the rest are the conventional siblings (other VCS
# metadata, server config, credential and dump files) of the same "a file that
# should never be web-served is".  Kept deliberately SMALL and bounded - this is
# the §7.2 constant set, not a content-discovery wordlist.
_discovery_sensitive_paths() {
  printf '%s\n' \
    '.git/HEAD' '.git/config' '.gitignore' \
    '.svn/entries' '.hg/requires' '.bzr/branch-format' \
    '.env' '.env.local' '.env.production' \
    '.htaccess' '.htpasswd' \
    '.DS_Store' 'web.config' \
    'backup.sql' 'dump.sql' 'database.sql' 'backup.zip' 'backup.tar.gz'
}

# ---------------------------------------------------------------------------
# 1a. The one safe-relative-path rule, applied to EVERY candidate source
# ---------------------------------------------------------------------------
# `_discovery_safe_rel REL` - prints REL as a safe relative candidate path, or
# prints nothing and returns 1 when it is not one.  Rejected: a control
# character (a CR/LF in a request line is the request/header-splitting shape),
# an absolute or scheme-relative URL (a candidate contributes a PATH, never an
# authority - the same rule modules/dast/crawl.sh applies to a specification's
# `servers[].url`), a `..` traversal, and an over-long token.  A leading `/` is
# stripped so the result always resolves UNDER the target's own base-url.
#
# IT IS DELIBERATELY APPLIED TO THE CRAWL INVENTORY AS WELL AS TO THE VENDORED
# WORDLIST.  An inventory `path` is UNTRUSTED TARGET OUTPUT (docs/FOUNDATION.md
# tension 10) - it comes from the scanned application's own markup, or from an
# operator-supplied specification - so it is strictly LESS trusted than a file
# an operator vendored deliberately.  Validating only the wordlist would have
# been the trust boundary drawn backwards, and it measurably was: before this
# guard, an endpoint recorded as `/a/../../../../etc/passwd` really did produce
# probe requests off the crawled surface (pinned by tests/suites/dast-discovery.sh's
# "an inventory-derived path is held to the SAME safe-path rule" section).
# `http_request`'s gate is authority-scoped and would still have refused another
# HOST, so this is not the last line of defence - it is the one that keeps a
# target from choosing which paths on its own authority the scanner walks, and
# from spending the DAST-01 request budget on paths nobody discovered.
_discovery_safe_rel() {
  local rel=$1
  rel=${rel#"${rel%%[![:space:]]*}"}
  rel=${rel%"${rel##*[![:space:]]}"}
  [[ -n $rel ]] || return 1
  [[ $rel == *[[:cntrl:]]* ]] && return 1
  [[ $rel == *://* ]] && return 1
  [[ $rel == //* ]] && return 1
  [[ $rel == *..* ]] && return 1
  rel=${rel#/}
  [[ -n $rel ]] || return 1
  (( ${#rel} <= _DISCOVERY_MAX_WORD_LEN )) || return 1
  printf '%s\n' "$rel"
}

# ---------------------------------------------------------------------------
# 2. Reading the vendored wordlist (technique C)
# ---------------------------------------------------------------------------
# `_discovery_read_wordlist FILE` - prints the file's candidate paths, one per
# line, dropping whole-line `#` comments and blanks and REJECTING any entry that
# is not a safe relative path: a control character, an absolute/scheme URL, a
# `..` traversal, or an over-long token is skipped rather than sent (the entry
# is UNTRUSTED file content and a `..` would try to escape the authorised path
# prefix a scope target may pin).  A leading `/` is stripped so every entry
# resolves relative to the base-url.  Returns 1 when the file is unreadable, so
# the caller degrades the technique rather than erroring.
_discovery_read_wordlist() {
  local f=$1 line
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || ${line:0:1} == '#' ]] && continue
    # ONE rule, shared with the inventory-derived candidates - see
    # `_discovery_safe_rel`. A second, hand-inlined copy here is how the two
    # sources drifted apart in the first place.
    _discovery_safe_rel "$line" || continue
  done <"$f"
}

# `_discovery_read_wordlist_into ARRNAME FILE` - fills the named array with the
# validated candidate paths, returning 1 (and leaving it empty) when the file is
# absent/unreadable OR present-but-empty, so the caller records the wordlist as
# `absent` in either case.  The array is filled through a by-name append, the
# same convention the rest of this codebase uses for Bash 4.2 (no namerefs,
# tension 24).
_discovery_read_wordlist_into() {
  local arrname=$1 file=$2 line n=0
  eval "$arrname=()"
  [[ -r $file ]] || return 1
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    eval "$arrname+=(\"\$line\")"
    n=$(( n + 1 ))
  done < <(_discovery_read_wordlist "$file")
  (( n > 0 ))
}

# ---------------------------------------------------------------------------
# 3. Response heuristics (docs/DESIGN.md §7.2 "status-code + length heuristics")
# ---------------------------------------------------------------------------
# `_discovery_len_similar A B` - 0 when two body lengths are the same size
# within tolerance, 1 otherwise.
_discovery_len_similar() {
  local a=$1 b=$2 diff tol pct
  diff=$(( a - b )); (( diff < 0 )) && diff=$(( -diff ))
  tol=$_DISCOVERY_LEN_TOL_ABS
  pct=$(( (a > b ? a : b) * _DISCOVERY_LEN_TOL_PCT / 100 ))
  (( pct > tol )) && tol=$pct
  (( diff <= tol ))
}

# `_discovery_is_hit STATUS LEN` - the core §7.2 decision, evaluated against the
# soft-404 baseline (`_DISC_BASE_STATUS`/`_DISC_BASE_LEN`) established from a
# random unlikely path.
#
#   * A response that matches the baseline in BOTH status and length is the
#     application's own not-found answer - NOT a hit.  This is what stops an
#     app that returns 200 for every path (a soft 404, an SPA shell) from
#     reporting every candidate as a discovered resource.
#   * A 404/410 is never a hit, whatever the baseline was.
#   * Otherwise a response in the "the resource is there" class is a hit,
#     INCLUDING 401/403 (the resource exists but is protected - itself worth
#     reporting) and a redirect.
_discovery_is_hit() {
  local status=$1 len=$2
  [[ -n $status ]] || return 1
  case $status in
    404 | 410) return 1 ;;
  esac
  if [[ $status == "$_DISC_BASE_STATUS" ]] && _discovery_len_similar "$len" "$_DISC_BASE_LEN"; then
    return 1
  fi
  case $status in
    200 | 201 | 202 | 203 | 204 | 206 | 301 | 302 | 303 | 307 | 308 | 401 | 403 | 405 | 500 | 503)
      return 0 ;;
  esac
  return 1
}

# `_discovery_body_is_dirlisting BODY` - 0 when BODY carries a directory-index
# signature, through scan_match (tension 4: grep exits 1 on no-match).  BODY
# reaches the engine on stdin via a scratch file, never as an argument.
_discovery_body_is_dirlisting() {
  local body=$1 f hits rc=0
  f=$SCOURSH_SCRATCH/disc.$$.dir.body
  hits=$SCOURSH_SCRATCH/disc.$$.dir.hits
  printf '%s' "$body" >"$f"
  scan_match "$hits" -i -e 'Index of /|Directory listing for|<title>Index of|Parent Directory</a>|autoindex' -- "$f" || rc=$?
  rm -f "$f" "$hits"
  return "$rc"
}

# ---------------------------------------------------------------------------
# 4. The one door to the network
# ---------------------------------------------------------------------------
# `_discovery_probe URL` - one read-only GET through the chokepoint.  Sets
# `_DISC_STATUS`, `_DISC_LEN`, `_DISC_BODY` (up to _DISCOVERY_MAX_BODY_BYTES).
# Returns 1 on a transport failure, leaving `_DISC_STATUS` empty.  Does NOT
# gate: `http_request` gates, fatally, and re-gates every redirect hop; the
# caller pre-filters an off-surface candidate with `_discovery_in_scope` for the
# reason modules/dast/crawl.sh's `_crawl_in_scope` header states at length.
# max_redirects is 0 so a 3xx is REPORTED (a redirect is a discovery signal),
# not chased onto a path the scanned target chose.
_discovery_probe() {
  local url=$1 target=${SCOURSH_DAST_TARGET:-} rc=0 bodyf
  _DISC_STATUS='' _DISC_LEN=0 _DISC_BODY=''
  bodyf=$SCOURSH_SCRATCH/disc.$$.body
  http_request_capture "$bodyf" ''
  http_request GET "$url" "${SCOURSH_DAST_DISCOVERY_MAX_REDIRECTS:-0}" "$target" || rc=$?
  if (( rc != 0 )); then
    rm -f "$bodyf"
    return 1
  fi
  _DISC_STATUS=${_HTTP_LAST_STATUS:-}
  if [[ -r $bodyf ]]; then
    IFS= read -r -d '' _DISC_BODY <"$bodyf" || true
    if (( ${#_DISC_BODY} > _DISCOVERY_MAX_BODY_BYTES )); then
      _DISC_BODY=${_DISC_BODY:0:_DISCOVERY_MAX_BODY_BYTES}
    fi
  fi
  _DISC_LEN=${#_DISC_BODY}
  rm -f "$bodyf"
  return 0
}

# `_discovery_in_scope URL` - the pre-filter (NOT the gate).  Decides only
# whether a URL is worth REQUESTING; everything that survives is still sent
# through `http_request`, which applies the real gate again.
_discovery_in_scope() {
  http_gate_url "$1" "${SCOURSH_DAST_TARGET:-}"
}

# ---------------------------------------------------------------------------
# 5. Emit
# ---------------------------------------------------------------------------
# The DAST finding location profile is (target, method, path_template,
# param_location, param_name) (lib/findings.sh).  A discovery finding is about a
# PATH, not a parameter, so param_location/param_name are empty; distinct
# discovered paths carry distinct path_templates and are distinct findings.
_discovery_emit() {
  local category=$1 rel=$2 url=$3 status=$4 dirlisting=${5:-0}
  local target=${SCOURSH_DAST_TARGET:-} path check base conf cwe title sens evi
  local safe_rel safe_status
  safe_rel=$(crawl_safe_text "$rel" 200)
  safe_status=$(crawl_safe_text "$status" 8)
  path=/$rel

  case $category in
    sensitive)
      check=DAST-DISC-SENSITIVE-01; base=high; conf=medium; cwe=CWE-538; sens=true
      title='Sensitive file or version-control metadata is web-accessible'
      evi="a request for the well-known sensitive path '/$safe_rel' on target '$target' returned HTTP $safe_status rather than the not-found baseline, so a file that should never be served over HTTP (source metadata, server config, a credential file, or a database dump) is reachable and may disclose secrets or source" ;;
    backup)
      check=DAST-DISC-BACKUP-01; base=high; conf=medium; cwe=CWE-530; sens=true
      title='Backup or temporary file is web-accessible'
      evi="a request for the backup/temporary variant '/$safe_rel' of a discovered resource on target '$target' returned HTTP $safe_status rather than the not-found baseline, so an editor or archive copy of application source or configuration is being served and may disclose source code, credentials, or internal logic" ;;
    content)
      check=DAST-DISC-CONTENT-01; base=low; conf=medium; cwe=CWE-200; sens=false
      title='Undisclosed resource discovered via content discovery'
      evi="a request for '/$safe_rel' on target '$target' returned HTTP $safe_status rather than the not-found baseline, so a resource that is not linked from the crawled surface is reachable; review whether it should be exposed and whether it enforces its own access control" ;;
    dirlisting)
      check=DAST-DISC-DIRLIST-01; base=medium; conf=high; cwe=CWE-548; sens=false
      title='Directory listing is enabled'
      evi="a request for '/$safe_rel' on target '$target' returned HTTP $safe_status with a body that matches an automatic directory-index signature, so the server is enumerating the directory's contents to any client and disclosing file names that were never meant to be advertised" ;;
    *) return 0 ;;
  esac

  finding_new
  finding_set check_id "$check"
  finding_set module dast
  finding_set title "$title"
  finding_set base_severity "$base"
  finding_set confidence "$conf"
  finding_set cwe "$cwe"
  finding_set owasp A05:2021
  finding_set exposure external
  finding_set auth none
  finding_set sensitive_data "$sens"
  case $category in
    sensitive)
      finding_set remediation 'Remove the file from the web root, or block it at the server/CDN (deny access to dotfiles, version-control directories, config and dump files). Rotate any credential that may have been exposed, and add a deployment check that fails when such a file is reachable.' ;;
    backup)
      finding_set remediation 'Delete backup and editor temporary files from the web root and stop deployments from copying them there; block the known suffixes (.bak, ~, .old, .orig, .swp, ...) at the server or CDN, and rotate any secret the file may have disclosed.' ;;
    content)
      finding_set remediation 'Confirm the resource is meant to be public; if not, remove it or move it behind authentication. Ensure every reachable endpoint enforces its own access control rather than relying on being unlinked.' ;;
    dirlisting)
      finding_set remediation 'Disable automatic directory indexing (Apache `Options -Indexes`, nginx `autoindex off`, or the equivalent) and serve an explicit index or a 403/404 so directory contents are never enumerated to clients.' ;;
  esac
  finding_set cell "${SCOURSH_DAST_CELL:-$target}"
  finding_set loc_target "$target"
  finding_set loc_method GET
  finding_set loc_path_template "$(path_template_of "$path")"
  finding_set loc_param_location ''
  finding_set loc_param_name ''
  finding_set url "$url"
  finding_set_evidence "$evi"
  finding_emit
  if (( dirlisting )) && [[ $category != dirlisting ]]; then
    _discovery_emit dirlisting "$rel" "$url" "$status" 0
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 6. Backup derivation (technique B) - reads the endpoints inventory
# ---------------------------------------------------------------------------
# `_discovery_inventory_path` - print the readable endpoints inventory, or
# return 1 when there is none.
#
# THE EXPORTED VARIABLE ALONE IS THE WRONG ANSWER, AND IT IS WRONG ON EXACTLY
# THE ORDINARY RUN. modules/dast/run.sh calls `dast_inventory_read` ONCE, before
# the phase loop, and exports SCOURSH_DAST_ENDPOINTS from what it found THEN -
# which on a fresh run is the empty string, because crawl.sh is itself a phase
# and has not run yet. crawl.sh writes reports/<run>/inventory/endpoints.json a
# few phases later in that same loop and nothing re-reads it, so a consumer
# trusting the exported variable sees an empty surface on precisely the run that
# HAS one: technique (B) would send not one backup probe on any real scan while
# still reporting DAST-DISC-BACKUP-01 as covered. This mirrors what
# passive/cookies.sh already does (its own header states the same trap at
# length) and what AGENTS.md records as a named sharp edge. It is the SAME
# artifact by the SAME path, just read after the producer wrote it. The general
# fix belongs to modules/dast/run.sh and affects every inventory consumer, so it
# stays filed rather than widened into this ticket.
_discovery_inventory_path() {
  local epf=${SCOURSH_DAST_ENDPOINTS:-}
  [[ -n $epf && -r $epf && -s $epf ]] || epf=${SCOURSH_RUN_DIR:-}/inventory/endpoints.json
  [[ -n $epf && -r $epf && -s $epf ]] || return 1
  printf '%s' "$epf"
}

# `_discovery_collect_backups EPFILE` - append a `backup` candidate for every (endpoint
# path, backup suffix) pair, reading the endpoints inventory through
# crawl_engine.sh's flattener.  Appends to the caller's `cats`/`rels` arrays,
# which are in scope because this is sourced into the phase and bash is
# dynamically scoped.  A path with no filename component (a bare directory) is
# skipped - a backup suffix only makes sense on a file.
#
# IT REPORTS A COUNT, AND THE COUNT - NOT THE FILE - IS WHAT COVERAGE TURNS ON.
# `_DISC_BACKUP_ADDED` is set to the number of candidates appended (0 when the
# inventory lists no endpoint, or when every path it lists is rejected by
# `_discovery_safe_rel` or carries no filename component). "A readable file
# exists" and "a candidate was derived" are different facts, and only the second
# is coverage: modules/dast/crawl.sh writes the endpoints envelope
# unconditionally and crawl_engine.sh emits it with `"endpoints": []`, so a
# crawl that found nothing still leaves a readable, non-empty inventory. Gating
# DAST-DISC-BACKUP-01 on the file would mint a (check, cell) coverage pair for a
# technique that sent zero probes, which is what lets step 7's state/ infer a
# prior real finding `fixed` (docs/FOUNDATION.md tension 12).
#
# SC2034: the local `cur` accumulator map is passed BY NAME to
# `_discovery_backup_flush`, which reads it through `${!...}` indirection (Bash
# 4.2 has no namerefs), so the read is invisible to shellcheck here - exactly as
# inject_engine.sh's and crawl_engine.sh's own flush helpers.
# shellcheck disable=SC2034
_discovery_collect_backups() {
  local epf=$1 sep=$'\x1f' p ptype v rest idx key
  local -A cur=()
  local last_idx=''
  # Assigned WITHOUT `local`, so the caller's own variable is the one set (bash
  # dynamic scope, the same mechanism `cats`/`rels` already rely on here).
  _DISC_BACKUP_ADDED=0
  [[ -n $epf && -r $epf && -s $epf ]] || return 0
  while IFS=$'\t' read -r p ptype v; do
    [[ $p == endpoints* ]] || continue
    rest=${p#endpoints}; rest=${rest#"$sep"}
    idx=${rest%%"$sep"*}; key=${rest#*"$sep"}
    [[ $idx =~ ^[0-9]+$ && $key != "$rest" ]] || continue
    if [[ -n $last_idx && $idx != "$last_idx" ]]; then
      _discovery_backup_flush cur
      cur=()
    fi
    last_idx=$idx
    [[ $ptype == s ]] && v=$(crawl_json_unescape "$v")
    cur[$key]=$v
  done < <(crawl_json_flatten <"$epf" 2>/dev/null)
  [[ -n $last_idx ]] && _discovery_backup_flush cur
  return 0
}

# `_discovery_backup_flush ARRNAME` - one endpoint record (passed by name, read
# through `${!...}` indirection like inject_engine.sh's own flush helpers) turned
# into its backup/temp candidates.
_discovery_backup_flush() {
  local arrname=$1
  local pr="${arrname}[path]"
  local path=${!pr:-}
  [[ -n $path ]] || return 0
  # An inventory path is untrusted target output, so it is held to the same
  # safe-relative-path rule as a vendored wordlist entry (see
  # `_discovery_safe_rel`). A rejected path contributes no candidate at all
  # rather than being repaired - a repaired traversal is still a path the
  # target chose, and there is no honest way to guess what it meant.
  path=$(_discovery_safe_rel "$path") || return 0
  local basename=${path##*/}
  [[ -n $basename ]] || return 0
  local suffix
  while IFS= read -r suffix; do
    cats+=(backup); rels+=("${path}${suffix}")
    # Counted where the candidate is actually appended, so the count and the
    # array cannot drift apart - a count kept anywhere else would be a second
    # statement of the same fact, and the two would disagree the first time an
    # early `return 0` above was added.
    _DISC_BACKUP_ADDED=$(( ${_DISC_BACKUP_ADDED:-0} + 1 ))
  done < <(_discovery_backup_suffixes)
  return 0
}

# ---------------------------------------------------------------------------
# 7. The phase
# ---------------------------------------------------------------------------
# `_discovery_random_path` - an unlikely path used to establish the soft-404
# baseline.  RANDOM is adequate here (a not-found probe, not a credential).
_discovery_random_path() {
  printf 'scoursh-nonexistent-%s%s-probe' "$RANDOM" "$RANDOM"
}

_dast_discovery_phase() {
  local target=${SCOURSH_DAST_TARGET:-}
  if [[ -z $target ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      'internal: modules/dast/active/discovery.sh was reached with no target; dast_run_phase publishes SCOURSH_DAST_TARGET'
  fi

  local base
  base=$(config_scope_field "$target" base-url)
  if [[ -z $base ]]; then
    run_record coverage_gap "dast discovery: target '$(crawl_safe_text "$target" 80)' has no base-url in config/scope.conf, so no content discovery was attempted"
    return 0
  fi

  # tension-15 per-check selection (guarded exactly as active/sqli.sh's).
  # `dast_check_selected` (modules/dast/engine.sh) now exists, so a discovery
  # family the operator filtered out genuinely issues no request; the guard
  # stays because tests/suites/dast-discovery.sh sources this file without
  # engine.sh, where an unguarded call would be exit 127 and would deselect all
  # four families instead of none.
  local do_content=1 do_backup=1 do_sensitive=1 do_dirlist=1
  if declare -F dast_check_selected >/dev/null; then
    dast_check_selected DAST-DISC-CONTENT-01   || do_content=0
    dast_check_selected DAST-DISC-BACKUP-01    || do_backup=0
    dast_check_selected DAST-DISC-SENSITIVE-01 || do_sensitive=0
    dast_check_selected DAST-DISC-DIRLIST-01   || do_dirlist=0
  fi

  # Establish the soft-404 baseline from a random path.  If even this cannot be
  # requested, the base-url itself is unreachable and there is nothing to
  # discover against - a coverage_gap, not a clean result.
  local rnd rurl
  rnd=$(_discovery_random_path)
  rurl=$(crawl_url_resolve "$base" "$rnd") || rurl=''
  _DISC_BASE_STATUS='' _DISC_BASE_LEN=0
  if [[ -n $rurl ]] && _discovery_in_scope "$rurl" && _discovery_probe "$rurl"; then
    _DISC_BASE_STATUS=$_DISC_STATUS
    _DISC_BASE_LEN=$_DISC_LEN
  fi
  if [[ -z $_DISC_BASE_STATUS ]]; then
    run_record coverage_reduction "module=dast reason=discovery_baseline_unreachable target=$target - the base-url could not be requested to establish a not-found baseline, so the status/length heuristic has no reference and no content discovery ran"
    run_record coverage_gap "dast discovery: target '$(crawl_safe_text "$target" 80)' could not be reached to establish a not-found baseline, so no content-discovery probe was sent. A clean result here is the absence of a test, not the absence of a problem."
    return 0
  fi

  # The candidate list, deduplicated by resolved URL and bounded by the total
  # request ceiling.  `cats`/`rels` are read by the backup-derivation helpers
  # (dynamic scope).
  local -A seen=()
  local sent=0 hits=0 truncated_words=0 wordlist_state=absent
  local -a cats=() rels=()

  # (A) well-known sensitive paths.
  local rel
  if (( do_sensitive )); then
    while IFS= read -r rel; do
      [[ -n $rel ]] || continue
      cats+=(sensitive); rels+=("$rel")
    done < <(_discovery_sensitive_paths)
  fi

  # (B) backup/temp variants of every crawl-inventory endpoint path. What is
  # tracked is whether the technique DERIVED A CANDIDATE, not whether an
  # inventory file was readable - the three states stay distinct so a run that
  # tested nothing says so, and says WHICH of the two ways it happened:
  #
  #   absent  - no inventory readable at either path;
  #   empty   - an inventory was readable but yielded no usable endpoint path
  #             (it lists none, or every one it lists was rejected by
  #             `_discovery_safe_rel` / carried no filename component);
  #   present - at least one candidate was derived.
  #
  # Only `present` may record DAST-DISC-BACKUP-01 below: at step 7 checks_run
  # feeds state/'s (check, cell) coverage pairs, where a falsely-covered check
  # lets a prior run's real finding be inferred `fixed` (docs/FOUNDATION.md
  # tension 12). Collapsing `empty` into `absent` would be the other half of the
  # same dishonesty - it would tell an operator to run a crawl that already ran.
  local inventory_state=absent invp='' _DISC_BACKUP_ADDED=0
  if (( do_backup )); then
    if invp=$(_discovery_inventory_path); then
      _discovery_collect_backups "$invp"
      if (( _DISC_BACKUP_ADDED > 0 )); then
        inventory_state=present
      else
        inventory_state=empty
      fi
    fi
  fi

  # (C) the vendored wordlist.
  local wl=${SCOURSH_DAST_DISCOVERY_WORDLIST:-${SCOURSH_INSTALL_ROOT:-.}/modules/dast/wordlists/content-discovery.txt}
  if (( do_content )); then
    local -a words=()
    if _discovery_read_wordlist_into words "$wl"; then
      wordlist_state=present
      local wi
      for (( wi = 0; wi < ${#words[@]}; wi++ )); do
        if (( wi >= _DISCOVERY_MAX_WORDS )); then
          truncated_words=$(( ${#words[@]} - _DISCOVERY_MAX_WORDS ))
          break
        fi
        cats+=(content); rels+=("${words[$wi]}")
      done
    fi
  fi

  # Probe every candidate through the one door, honouring the dedup and the
  # absolute request ceiling.
  local i cat url over=0 dl
  for (( i = 0; i < ${#rels[@]}; i++ )); do
    if (( sent >= _DISCOVERY_MAX_REQUESTS )); then over=1; break; fi
    cat=${cats[$i]}; rel=${rels[$i]}
    url=$(crawl_url_resolve "$base" "$rel") || continue
    [[ -n ${seen[$url]:-} ]] && continue
    seen[$url]=1
    _discovery_in_scope "$url" || continue
    _discovery_probe "$url" || continue
    sent=$(( sent + 1 ))
    if _discovery_is_hit "$_DISC_STATUS" "$_DISC_LEN"; then
      hits=$(( hits + 1 ))
      dl=0
      if (( do_dirlist )) && [[ $_DISC_STATUS == 200 ]] && _discovery_body_is_dirlisting "$_DISC_BODY"; then
        dl=1
      fi
      _discovery_emit "$cat" "$rel" "$url" "$_DISC_STATUS" "$dl"
    fi
  done

  # Honesty roll-up.  checks_run records only the techniques that actually
  # probed at least one candidate (AGENTS.md's definition), so a run that sent
  # no request is not reported as covered.
  if (( sent > 0 )); then
    (( do_sensitive )) && run_record checks_run DAST-DISC-SENSITIVE-01
    (( do_dirlist ))   && run_record checks_run DAST-DISC-DIRLIST-01
    # BACKUP is covered only when an inventory really supplied candidates -
    # `inventory_state` is `present` only when _DISC_BACKUP_ADDED > 0, never
    # merely because the inventory file was readable. A
    # technique that contributed nothing is not made covered by a sibling
    # technique's requests: at step 7 checks_run feeds state/'s (check, cell)
    # coverage pairs, where a falsely-covered check lets a prior run's real
    # finding be inferred `fixed` (docs/FOUNDATION.md tension 12).
    if (( do_backup )) && [[ $inventory_state == present ]]; then
      run_record checks_run DAST-DISC-BACKUP-01
    fi
    if (( do_content )) && [[ $wordlist_state == present ]]; then
      run_record checks_run DAST-DISC-CONTENT-01
    fi
  fi

  if (( do_content )) && [[ $wordlist_state == absent ]]; then
    run_record coverage_reduction "module=dast reason=discovery_wordlist_absent target=$target path=$(crawl_safe_text "$wl" 200) - no content-discovery wordlist is vendored at this path (none ships in this repository by design; vendor one offline and point SCOURSH_DAST_DISCOVERY_WORDLIST at it), so wordlist-based content discovery did not run. The backup/temp and sensitive-path techniques still ran."
    run_record coverage_gap "dast discovery: no content-discovery wordlist was available for target '$target', so the wordlist-based sweep tested nothing. This is a coverage gap, not a clean bill of health; the fixed sensitive-path and backup/temp checks still ran."
  fi
  if (( do_backup )) && [[ $inventory_state == absent ]]; then
    run_record coverage_reduction "module=dast reason=discovery_no_endpoint_inventory target=$target - no endpoint inventory (docs/INVENTORY-FORMAT.md) was readable at SCOURSH_DAST_ENDPOINTS or at \$SCOURSH_RUN_DIR/inventory/endpoints.json, so no backup/temp variant of a known endpoint path was derived or probed. The sensitive-path and wordlist techniques still ran."
    run_record coverage_gap "dast discovery: no endpoint inventory was available for target '$target', so the backup/temp sweep (docs/DESIGN.md §7.2) derived no candidate and tested nothing - a served .bak/.old/~ file would not have been found. This is a coverage gap, not a clean bill of health; run the crawl phase (or supply a specification) so this technique has endpoint paths to vary."
  fi
  if (( do_backup )) && [[ $inventory_state == empty ]]; then
    run_record coverage_reduction "module=dast reason=discovery_inventory_yielded_no_candidate target=$target path=$(crawl_safe_text "$invp" 200) candidates=0 - an endpoint inventory (docs/INVENTORY-FORMAT.md) was readable at this path but yielded no usable endpoint path: it lists no endpoints, or every path it lists was rejected as unsafe (traversal, scheme URL, control byte) or named a bare directory with no filename component. No backup/temp variant was derived or probed. The sensitive-path and wordlist techniques still ran."
    run_record coverage_gap "dast discovery: the endpoint inventory for target '$target' was readable but yielded no usable endpoint path, so the backup/temp sweep (docs/DESIGN.md §7.2) derived no candidate and tested nothing - a served .bak/.old/~ file would not have been found. This is a coverage gap, not a clean bill of health; the inventory exists, so re-run the crawl against a surface it can actually enumerate (a client-rendered application yields an empty one) or supply a specification."
  fi
  if (( truncated_words > 0 )); then
    run_record coverage_gap "dast discovery: the vendored wordlist for target '$target' exceeded the per-run cap of $_DISCOVERY_MAX_WORDS entries, so $truncated_words entry(ies) were not probed. Their absence from this report is a coverage bound, not a clean result."
  fi
  if (( over )); then
    run_record coverage_gap "dast discovery: the candidate surface on target '$target' hit the per-run request ceiling of $_DISCOVERY_MAX_REQUESTS, so some candidates were not probed. Their absence from this report is a coverage bound, not a clean result."
  fi

  log_info "dast discovery: target '$target' - probed $sent candidate path(s), $hits reachable (sensitive=$do_sensitive backup=$do_backup content=$do_content wordlist=$wordlist_state inventory=$inventory_state)"
  return 0
}

_dast_discovery_phase
