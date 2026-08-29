#!/usr/bin/env bash
# modules/sast/adapters/semgrep/adapter.sh - the semgrep optional engine
# adapter (docs/DESIGN.md §6.4, §13 step 9; docs/ADAPTERS.md; this ticket,
# the first concrete adapter, per docs/ADAPTERS.md §1/§3).
#
# Owns: docs/ADAPTERS.md §5's three-function contract, applied to semgrep.
#
# THE THREE FUNCTIONS (docs/ADAPTERS.md §5) - `semgrep_detect`,
# `semgrep_run`, `semgrep_normalize` - are this file's public interface and
# the only functions a caller (modules/sast/run.sh, via lib/engines.sh's
# `has_engine`) is ever meant to call.  Every other function here is a
# private `_semgrep_*` helper, the same public/private split every other
# module in this repository already uses (modules/sast/engine.sh:
# `sast_scan_file` versus `_sast_emit_finding`; modules/sca/engine.sh:
# `sca_scan_tree` versus `_sca_emit_finding`) - "exactly three functions" in
# docs/ADAPTERS.md §5 names the CONTRACT surface, not a ban on the ordinary
# decomposition every other engine file in this codebase already relies on.
#
# NEVER FETCHES ANYTHING (docs/ADAPTERS.md §2).  This file contains no
# curl/wget/nc/ncat/netcat/openssl-s_client invocation and never sources or
# calls tools/vendor-engines.sh - tests/lint-shell.sh's "no bypass" and "no
# wiring of tools/vendor-engines.sh" checks both cover this file like every
# other file under modules/.  `semgrep_run` invokes the vendored binary
# with `--offline` and metrics explicitly disabled (see its own comment) as
# a second, belt-and-suspenders control on top of that: semgrep's upstream
# default is to phone home anonymous usage metrics unless told not to, and
# an egress-restricted scanner cannot rely on a THIRD PARTY BINARY's own
# default being safe - the no-egress rule (AGENTS.md) has to hold even if the
# vendored tool's own defaults would not, on their own, guarantee it.
#
# UNTRUSTED OUTPUT (CLAUDE.md §6 / docs/FOUNDATION.md tension 9's "evidence
# is untrusted target output" applied to a THIRD-PARTY TOOL's output rather
# than a scanned target): semgrep's JSON is DATA, never instructions.
# `semgrep_normalize` never `eval`s any part of it, never uses it to build a
# command, and only ever reaches the finding model through
# `lib/findings.sh`'s existing public setters - `finding_set`/
# `finding_set_evidence`/`finding_set_match`/`finding_emit` - which already
# redact and JSON-escape everything they touch (tests/lint-shell.sh's
# existing "no direct assignment to a redacted field" check enforces this
# repository-wide, this file included).  The `path` field semgrep reports is
# additionally validated to resolve inside the scan root before it is ever
# trusted as a finding's location (see `_semgrep_resolve_location`'s own
# comment) - a defensive boundary check against a buggy or compromised
# vendored engine attributing a finding outside the authorised scan
# boundary, the same class of control OWASP A01 (broken access control /
# SSRF-style trust-the-input mistakes) asks for at every boundary.
#
# SEVERITY MAPPING: WHY THIS CAPS AT `high`, UNLIKE `_trivy_severity_map`
# (`_semgrep_severity_map` below - a decision record, not incidental).  An
# earlier version of that function's comment claimed no native `*.rules`
# pack ever authors `severity: critical`, as the reason a raw engine
# severity is never mapped there either.  That claim was false the moment it
# was written: `modules/sast/rules/secrets.rules`, `injection.rules`,
# `python.rules`, `go.rules`, `java.rules`, `javascript.rules`, and every
# landed `modules/iac/*.rules` pack (`terraform.rules`, `kubernetes.rules`,
# `helm.rules`, `dockerfile.rules`, `docker-compose.rules`) all author
# `severity: critical` directly today - `grep -rn 'severity: critical'
# modules/` shows it.  The cap stays, but on the real, considered reasoning
# below, not that one:
#   1. Vocabulary shape.  Trivy's own severity signal is CRITICAL/HIGH/
#      MEDIUM/LOW - four tiers that map 1:1 onto scoursh's own four
#      non-`info` tiers, so `_trivy_severity_map` is a rename, not a
#      judgement call (see that function's own comment).  Semgrep's signal
#      is coarser: ERROR/WARNING/INFO, three tiers, with no tier of its own
#      distinct from and above ERROR.  There is no native "more severe than
#      ERROR" signal to place at `critical`; ERROR is already semgrep's own
#      ceiling, and this mapping already treats it as this adapter's
#      ceiling (`high`, the top of the three tiers it actually uses).
#   2. Ruleset provenance.  Trivy's misconfiguration checks are COMPILED
#      INTO the vendored binary itself - a fixed, versioned catalog from
#      trivy's own upstream release (this file's sibling,
#      modules/iac/adapters/trivy/adapter.sh's own "WHICH ENGINE, AND WHY").
#      Semgrep's ruleset is a SEPARATE, operator-vendored artifact
#      (vendor.sh's `SCOURSH_SEMGREP_RULES_URL`) that can point at an
#      arbitrary community or custom rule pack this project has never
#      reviewed rule-by-rule.  Every native scoursh pack's `critical` is
#      earned one rule at a time, by review, in this repository; letting an
#      unreviewed, operator-swappable third-party ruleset auto-mint that
#      same ceiling merely by labelling a rule ERROR would hand it more
#      authority than this project's own curated packs get.
# Capping at `high` leaves `critical` reachable two ways that both still
# apply to a semgrep-sourced finding: scoursh's own native packs, and
# `data/severity-rubric.conf`'s escalation modifiers, which run over EVERY
# finding - semgrep-sourced ones included - and can still raise a `high`
# base_severity to `critical` when exposure/auth/sensitive-data/confidence
# facts warrant it.  It is a raw, unreviewed engine label alone that never
# gets to mint `critical` directly.  Revisit this if `docs/ADAPTERS.md`
# ever specifies a curated/reviewed semgrep ruleset as this project's own
# vendoring default rather than an arbitrary operator-supplied URL.
#
# shellcheck shell=bash
#
# SC2329: several `_semgrep_*` helpers are only reachable through the three
# contract functions above, not through a literal call shellcheck's static
# graph can follow from this file alone.
# SC1003: `[[ $c == '\' ]]` compares against a literal single backslash
# character, which is what it is for - lib/records.sh's own
# records_ere_violation and lib/findings.sh's own _dec carry the identical
# disable for the identical reason.
# shellcheck disable=SC2329,SC1003

if [[ -n ${SCOURSH_SEMGREP_ADAPTER_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SEMGREP_ADAPTER_SOURCED=1

SEMGREP_ADAPTER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SEMGREP_BIN=$SEMGREP_ADAPTER_DIR/bin/semgrep
SEMGREP_RULES_DIR=$SEMGREP_ADAPTER_DIR/rules

# Every finding this adapter can ever emit in one run is bounded, the same
# discipline modules/sast/engine.sh already applies per (check, file) via
# SCOURSH_SAST_MAX_MATCHES_PER_FILE - here bounding the whole adapter run
# against a malformed or hostile-sized semgrep JSON document (OWASP A10:
# an exceptional/adversarial-shaped input must not turn into unbounded work
# or a crashed scan; it degrades and says so).
SCOURSH_SEMGREP_MAX_RESULTS=${SCOURSH_SEMGREP_MAX_RESULTS:-5000}

# ---------------------------------------------------------------------------
# 1. semgrep_detect - pure filesystem check (docs/ADAPTERS.md §5).  Never
#    touches the network, never runs the engine, never writes anything.
# ---------------------------------------------------------------------------
semgrep_detect() {
  [[ -x $SEMGREP_BIN ]] || return 1
  [[ -d $SEMGREP_RULES_DIR ]] || return 1
  local f
  for f in "$SEMGREP_RULES_DIR"/*; do
    [[ -e $f ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# 2. semgrep_run OUTPUT_FILE TARGET... - runs the vendored binary fully
#    offline, writing its native JSON to OUTPUT_FILE.  Exits non-zero only
#    on a genuine engine failure (docs/ADAPTERS.md §5); the caller
#    (modules/sast/run.sh) is the one that turns that into a
#    coverage_reduction rather than aborting the run.
# ---------------------------------------------------------------------------
semgrep_run() {
  local out=$1
  shift
  (( $# > 0 )) || { : >"$out"; return 1; }

  local rc=0 errfile=$SCOURSH_SCRATCH/semgrep-stderr.$$
  # SEMGREP_SEND_METRICS/--metrics=off: two independent ways of saying the
  # same thing to semgrep's own CLI, deliberately redundant (see this
  # file's header) - an egress-restricted scan must not depend on getting
  # exactly one flag spelling right against a moving upstream default.
  # --offline: never resolve or fetch a registry ruleset; only the
  # vendored, on-disk $SEMGREP_RULES_DIR is ever consulted.
  SEMGREP_SEND_METRICS=off "$SEMGREP_BIN" \
    --offline --metrics=off --json --quiet --disable-version-check \
    --config "$SEMGREP_RULES_DIR" \
    -- "$@" >"$out" 2>"$errfile" || rc=$?

  if (( rc != 0 )); then
    log_warn "sast: semgrep adapter exited $rc - $(cat "$errfile" 2>/dev/null | head -n 5)"
  fi
  rm -f "$errfile"
  return "$rc"
}

# ---------------------------------------------------------------------------
# 3. semgrep_normalize INPUT_FILE - reads INPUT_FILE (semgrep's own JSON,
#    written by semgrep_run) and emits one scoursh finding per result via
#    lib/findings.sh's public API only (docs/ADAPTERS.md §5/§8).
# ---------------------------------------------------------------------------
semgrep_normalize() {
  local infile=$1
  [[ -r $infile ]] || return 0

  local objects=$SCOURSH_SCRATCH/semgrep-results.$$
  _semgrep_split_results "$infile" >"$objects"

  local scan_root=${_SCAN_RESOLVED_PATH:-.}
  scan_root=$(scan_root_of "$scan_root")

  local obj count=0 truncated=0
  while IFS= read -r obj; do
    [[ -n $obj ]] || continue
    if [[ $obj == __TRUNCATED__ ]]; then
      truncated=1
      break
    fi
    count=$(( count + 1 ))
    _semgrep_emit_finding "$obj" "$scan_root"
  done <"$objects"
  rm -f "$objects"

  if (( truncated )); then
    run_record coverage_reduction \
      "module=sast reason=engine_results_truncated engine=semgrep max=$SCOURSH_SEMGREP_MAX_RESULTS"
  fi
  run_record coverage_reduction "module=sast reason=engine_boosted_not_a_replacement engine=semgrep results=$count"
}

# ---------------------------------------------------------------------------
# Private helpers below.  Never called directly by anything outside this
# file (docs/ADAPTERS.md §5's contract is the three functions above).
# ---------------------------------------------------------------------------

# _semgrep_split_results FILE - writes one COMPLETE result object's raw JSON
# text (whitespace-flattened, so guaranteed to carry no embedded raw
# newline - safe by construction, since JSON forbids an unescaped newline
# inside a string in the first place: any physical line break in a
# well-formed JSON document can only ever be formatting whitespace between
# tokens) per output line, for every element of the top-level "results"
# array.  Depth- and string-aware (tracks `"`/`\` escaping) so a message
# field that happens to contain the English word "results", a brace, or a
# comma never desynchronises the split - the ONLY thing this walk trusts
# textually is that an UNESCAPED `"results"` token can only ever be a JSON
# key, never string content (an unescaped `"` inside a JSON string is
# invalid JSON in the first place, so a compliant producer like semgrep
# never emits one that way).  Bounded by SCOURSH_SEMGREP_MAX_RESULTS; prints
# a literal `__TRUNCATED__` sentinel line and stops if the bound is hit,
# which the caller (semgrep_normalize) turns into a coverage_reduction
# rather than silently dropping the remainder.
#
# This is a purpose-built extractor for semgrep's own JSON shape, not a
# general JSON parser (the same pragmatic, stated-scope choice
# modules/sca/engine.sh's _sca_json_walk already makes for lockfiles) -
# `awk`, not the pattern-rule engine, because this is walking a TOOL'S OWN
# structured output for a fixed set of known keys, not evaluating an
# authored regex against scanned source (tension 2 does not apply here).
_semgrep_split_results() {
  local file=$1
  awk -v max="$SCOURSH_SEMGREP_MAX_RESULTS" '
    { content = content $0 " " }
    END {
      n = length(content)
      marker = "\"results\""
      p = index(content, marker)
      if (p == 0) { exit }
      i = p + length(marker)
      while (i <= n && substr(content, i, 1) ~ /[ \t]/) i++
      if (substr(content, i, 1) != ":") { exit }
      i++
      while (i <= n && substr(content, i, 1) ~ /[ \t]/) i++
      if (substr(content, i, 1) != "[") { exit }
      i++
      depth = 0; instr = 0; esc = 0; capturing = 0; buf = ""; count = 0
      for (; i <= n; i++) {
        c = substr(content, i, 1)
        if (instr) {
          if (capturing) buf = buf c
          if (esc) { esc = 0 }
          else if (c == "\\") { esc = 1 }
          else if (c == "\"") { instr = 0 }
          continue
        }
        if (c == "\"") { instr = 1; if (capturing) buf = buf c; continue }
        if (c == "{") {
          if (depth == 0) { capturing = 1; buf = "{"; depth = 1; continue }
          depth++
          if (capturing) buf = buf c
          continue
        }
        if (c == "[") {
          depth++
          if (capturing) buf = buf c
          continue
        }
        if (c == "}") {
          depth--
          if (capturing) buf = buf c
          if (depth == 0) {
            print buf
            capturing = 0; buf = ""
            count++
            if (count >= max) { print "__TRUNCATED__"; exit }
          }
          continue
        }
        if (c == "]") {
          if (depth == 0) { exit }
          depth--
          if (capturing) buf = buf c
          continue
        }
        if (capturing) buf = buf c
      }
    }
  ' "$file"
}

# _semgrep_json_string_field OBJ KEY - the JSON-string value of the FIRST
# unescaped `"KEY"` token in OBJ, with standard JSON escapes decoded
# (\" \\ \/ \n \t \r \b \f).  A \uXXXX escape is a stated, narrow gap: it is
# consumed (never left dangling and corrupting the rest of the parse) but
# rendered as a literal `?` rather than a real codepoint-to-UTF-8
# conversion, which this repository's own pure-bash UTF-8 handling
# (AGENTS.md "BSD awk evaluates 0x80 as 0... hex literals are a GNU
# extension") would cost far more than a semgrep rule id, path, or message
# ever needs \uXXXX for in practice.
_semgrep_json_string_field() {
  local obj=$1 key=$2
  local marker="\"$key\""
  [[ $obj == *"$marker"* ]] || return 1
  local rest=${obj#*"$marker"}
  rest=${rest#*:}
  while [[ ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' ]]; do rest=${rest:1}; done
  [[ ${rest:0:1} == '"' ]] || return 1
  rest=${rest:1}
  local out='' i=0 c esc=0 n=${#rest}
  while (( i < n )); do
    c=${rest:i:1}
    if (( esc )); then
      case $c in
        n) out+=$'\n' ;;
        t) out+=$'\t' ;;
        r) out+=$'\r' ;;
        b) out+=$'\b' ;;
        f) out+=$'\f' ;;
        '"' | '\' | /) out+=$c ;;
        u) out+='?'; i=$(( i + 4 )) ;;
        *) out+=$c ;;
      esac
      esc=0
    elif [[ $c == '\' ]]; then
      esc=1
    elif [[ $c == '"' ]]; then
      break
    else
      out+=$c
    fi
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

# _semgrep_json_object_field OBJ KEY - the raw JSON text (still `{...}`) of
# the FIRST unescaped `"KEY"` token's object value, brace-depth- and
# string-aware for the same reason _semgrep_split_results is.
_semgrep_json_object_field() {
  local obj=$1 key=$2
  local marker="\"$key\""
  [[ $obj == *"$marker"* ]] || return 1
  local rest=${obj#*"$marker"}
  rest=${rest#*:}
  while [[ ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' ]]; do rest=${rest:1}; done
  [[ ${rest:0:1} == '{' ]] || return 1
  local depth=0 i=0 n=${#rest} c instr=0 esc=0 out=''
  while (( i < n )); do
    c=${rest:i:1}
    out+=$c
    if (( instr )); then
      if (( esc )); then
        esc=0
      elif [[ $c == '\' ]]; then
        esc=1
      elif [[ $c == '"' ]]; then
        instr=0
      fi
    else
      case $c in
        '"') instr=1 ;;
        '{') depth=$(( depth + 1 )) ;;
        '}')
          depth=$(( depth - 1 ))
          if (( depth == 0 )); then
            printf '%s' "$out"
            return 0
          fi
          ;;
      esac
    fi
    i=$(( i + 1 ))
  done
  return 1
}

# _semgrep_json_number_field OBJ KEY - the numeric value of the FIRST
# unescaped `"KEY"` token in OBJ.  Bash `=~` here is matched against
# already-isolated, already-trusted-shape JSON text (not raw scanned file
# content), using ONLY portable POSIX bracket-expression syntax
# ([0-9], [[:space:]]) - never \d/\s/\w/\b - exactly the same precedent
# lib/findings.sh's own path_template_of already sets for this class of use
# (docs/FOUNDATION.md tension 2's BSD-regcomp hazard is about authored
# rule/context patterns evaluated against scanned source, not this).
_semgrep_json_number_field() {
  local obj=$1 key=$2
  [[ $obj =~ \"$key\"[[:space:]]*:[[:space:]]*(-?[0-9]+) ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

# _semgrep_json_array_first_string OBJ KEY - the first string element of a
# JSON array value, e.g. metadata.cwe / metadata.owasp, both of which
# semgrep reports as arrays even though every real rule carries exactly one
# of each.  A stated narrowing, not a silent one: a second cwe/owasp entry
# (rare in practice) is simply not read.
_semgrep_json_array_first_string() {
  local obj=$1 key=$2
  local marker="\"$key\""
  [[ $obj == *"$marker"* ]] || return 1
  local rest=${obj#*"$marker"}
  rest=${rest#*:}
  while [[ ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' ]]; do rest=${rest:1}; done
  [[ ${rest:0:1} == '[' ]] || return 1
  rest=${rest:1}
  while [[ ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' ]]; do rest=${rest:1}; done
  [[ ${rest:0:1} == '"' ]] || return 1
  _semgrep_json_string_field "{\"_\":$rest" _
}

# _semgrep_severity_map SEMGREP_SEVERITY - semgrep's ERROR/WARNING/INFO onto
# scoursh's own info|low|medium|high|critical vocabulary
# (lib/records.sh's severity_rank/severity_name).  DELIBERATELY caps at
# `high`, never `critical` - see this file's own header ("SEVERITY MAPPING:
# WHY THIS CAPS AT `high`, UNLIKE `_trivy_severity_map`") for the full
# reasoning and the current decision record.  This is NOT because no native
# `*.rules` pack ever authors `critical` directly - several do today
# (modules/sast/rules/secrets.rules, injection.rules, python.rules,
# go.rules, java.rules, javascript.rules, and every landed
# modules/iac/*.rules pack) - that claim was simply false and is corrected
# here rather than repeated.
_semgrep_severity_map() {
  case $1 in
    ERROR) printf 'high' ;;
    WARNING) printf 'medium' ;;
    INFO) printf 'low' ;;
    *) printf 'medium' ;;
  esac
}

# _semgrep_resolve_location SCAN_ROOT REPORTED_PATH - prints a scan-root-
# relative path on success, or fails (empty stdout, non-zero return) when
# REPORTED_PATH does not resolve to somewhere inside SCAN_ROOT.  This is a
# deliberate boundary check, not incidental path math: REPORTED_PATH is
# UNTRUSTED - it comes from the vendored third-party binary's own JSON
# output (this file's header) - and a buggy or compromised engine reporting
# a path outside the authorised scan root (`..` traversal, an absolute path
# elsewhere on disk, a symlink escape) must never be trusted as a finding's
# `loc_path`, the same fingerprint- and report-facing field every native
# check's `sast_relpath` call already keeps root-relative
# (modules/sast/engine.sh's own comment: "loc_path is relative to the SCAN
# ROOT, never to --path itself").
_semgrep_resolve_location() {
  local root=$1 reported=$2
  [[ -n $reported ]] || return 1
  local abspath=$reported
  if [[ ${reported:0:1} != / ]]; then
    abspath=$root/$reported
  fi
  abspath=$(realpath_of "$abspath")
  case $abspath in
    "$root" | "$root"/*) ;;
    *) return 1 ;;
  esac
  printf '%s' "$abspath"
}

# _semgrep_match_text ABSPATH LINE FALLBACK - the RAW matched text for the
# fingerprint/evidence (docs/FOUNDATION.md tension 5/tension 11: "an adapter
# result is normalised onto the native location model first, re-deriving
# match_digest ... from the file at the adapter's reported path and line,
# and only then compared").  Reads the real line from disk when the
# reported location still resolves, so an adapter finding's match_digest is
# computed the identical way a native finding's already is
# (modules/sast/engine.sh's own _sast_emit_finding); falls back to
# semgrep's own reported snippet (`extra.lines`) when the file or line no
# longer resolves, per that same tension's "kept as its own finding rather
# than merged or dropped" branch - which this adapter's namespaced
# `semgrep:<rule id>` check id already keeps in a separate occurrence space
# from every native check regardless of which text source wins here.
_semgrep_match_text() {
  local abspath=$1 line=$2 fallback=$3
  if [[ -n $abspath && -r $abspath && $line =~ ^[0-9]+$ ]] && (( line > 0 )); then
    local text
    text=$(sed -n "${line}p" -- "$abspath" 2>/dev/null || true)
    if [[ -n $text ]]; then
      printf '%s' "$text"
      return 0
    fi
  fi
  printf '%s' "$fallback"
}

# _semgrep_emit_finding OBJ SCAN_ROOT - OBJ is one complete result object's
# raw JSON text (from _semgrep_split_results).  Mints a finding purely
# through lib/findings.sh's public API (docs/ADAPTERS.md §5/§8's round-trip
# requirement).
_semgrep_emit_finding() {
  local obj=$1 scan_root=$2

  local rule_id message severity_raw path_raw start_obj extra_obj metadata_obj
  rule_id=$(_semgrep_json_string_field "$obj" check_id) || rule_id=''
  [[ -n $rule_id ]] || return 0

  path_raw=$(_semgrep_json_string_field "$obj" path) || path_raw=''
  extra_obj=$(_semgrep_json_object_field "$obj" extra) || extra_obj=''
  message=$(_semgrep_json_string_field "$extra_obj" message) || message=''
  severity_raw=$(_semgrep_json_string_field "$extra_obj" severity) || severity_raw=''
  start_obj=$(_semgrep_json_object_field "$obj" start) || start_obj=''
  # `end` (end line/col) is reported by semgrep but not read: every location
  # this adapter mints is single-line (loc_line = start.line only), the same
  # shape every native pattern-rule finding already uses
  # (modules/sast/engine.sh's own _sast_emit_finding has no end-line field
  # either) - a stated narrowing, not an oversight.

  local line
  line=$(_semgrep_json_number_field "$start_obj" line) || line=''

  local resolved
  resolved=$(_semgrep_resolve_location "$scan_root" "$path_raw") || {
    run_record coverage_reduction \
      "module=sast reason=engine_reported_path_outside_scan_root engine=semgrep check=semgrep:$rule_id"
    return 0
  }
  local relpath
  relpath=$(sast_relpath "$scan_root" "$resolved")

  local snippet
  snippet=$(_semgrep_json_string_field "$extra_obj" lines) || snippet=''
  [[ -n $snippet ]] || snippet=$message
  local match_text
  match_text=$(_semgrep_match_text "$resolved" "${line:-0}" "$snippet")

  metadata_obj=$(_semgrep_json_object_field "$extra_obj" metadata) || metadata_obj=''
  local cwe_raw owasp_raw cwe=none owasp=none
  cwe_raw=$(_semgrep_json_array_first_string "$metadata_obj" cwe) || cwe_raw=''
  owasp_raw=$(_semgrep_json_array_first_string "$metadata_obj" owasp) || owasp_raw=''
  [[ $cwe_raw =~ (CWE-[0-9]+) ]] && cwe=${BASH_REMATCH[1]}
  [[ $owasp_raw =~ (A[0-9]{2}:20[0-9]{2}) ]] && owasp=${BASH_REMATCH[1]}

  local check_id="semgrep:$rule_id"
  local title=$message
  [[ -n $title ]] || title="semgrep: $rule_id"

  finding_new
  finding_set check_id "$check_id"
  finding_set module sast
  finding_set title "$title"
  finding_set base_severity "$(_semgrep_severity_map "$severity_raw")"
  finding_set confidence medium
  finding_set cwe "$cwe"
  finding_set owasp "$owasp"
  finding_set loc_path "$relpath"
  finding_set loc_line "${line:-0}"
  finding_set cell "${SCOURSH_PATH_ROOT:-.}"
  finding_set logical_kind file
  finding_set logical_fqn "$relpath:${line:-0}"
  local upper_id=${rule_id^^}
  local is_secret=0
  if _sast_check_is_sensitive "$upper_id"; then
    finding_set sensitive_data true
    is_secret=1
  fi
  finding_set remediation \
    "Review and remediate per semgrep rule '$rule_id': ${message:-no further detail reported}."
  # semgrep is general-purpose, so this stays conditional: only a rule whose
  # match IS a credential loses its evidence to a placeholder (lib/findings.sh
  # section 8a, tension 9).  A non-secret rule keeps its match verbatim, which
  # is the whole value of the adapter.
  if (( is_secret )); then
    finding_set_secret_match "$match_text"
  else
    finding_set_match "$match_text"
    finding_set_evidence "$match_text"
  fi
  finding_emit
}
