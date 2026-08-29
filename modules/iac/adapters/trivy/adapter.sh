#!/usr/bin/env bash
# modules/iac/adapters/trivy/adapter.sh - the trivy (trivy config) optional
# engine adapter (docs/DESIGN.md §6.6's "same pattern as §6.4" note;
# §13 step 9; docs/ADAPTERS.md; this ticket, the SECOND concrete adapter and
# the first for a module other than sast).
#
# Owns: docs/ADAPTERS.md §5's three-function contract, applied to trivy's
# offline IaC misconfiguration scanner (`trivy config`).
#
# WHICH ENGINE, AND WHY (docs/DESIGN.md §6.6 names three candidates -
# `checkov`, `tfsec`, `trivy config` - "operator/PM to confirm which; do not
# guess if genuinely ambiguous", per this ticket's own text).  This is
# resolved by the ticket's own scope sentence, not a coin flip: item 2 asks
# for one engine that runs "against IaC sources (Terraform/CloudFormation/
# Kubernetes/Helm/docker-compose)" - i.e. every format modules/iac/*.rules
# already covers plus CloudFormation.  Of the three named candidates, only
# `trivy config` natively scans all five of those shapes in one binary;
# `tfsec` is Terraform-only (it does not read Kubernetes, Helm,
# docker-compose or CloudFormation at all), and `checkov` is a Python
# application (a directory of interpreter + library dependencies, not a
# single vendorable artifact) rather than the single static, offline binary
# semgrep's own adapter already established as this project's vendoring
# shape (modules/sast/adapters/semgrep/adapter.sh's header: "a vendored,
# offline, third-party engine"). `trivy` ships as a single Go binary with
# its misconfiguration checks (OPA/Rego policies) COMPILED IN, so - like
# semgrep - it needs exactly one vendored artifact under bin/ and, unlike
# semgrep, needs no separate vendored ruleset under rules/ at all (see
# `trivy_detect` below and docs/ADAPTERS.md §4's "an adapter with no local
# ruleset (a self-contained binary) may omit rules/").
#
# THE THREE FUNCTIONS (docs/ADAPTERS.md §5) - `trivy_detect`, `trivy_run`,
# `trivy_normalize` - are this file's public interface and the only
# functions a caller (modules/iac/run.sh, via lib/engines.sh's
# `has_engine`) is ever meant to call.  Every other function here is a
# private `_trivy_*` helper, the same public/private split
# modules/sast/adapters/semgrep/adapter.sh already established.
#
# NEVER FETCHES ANYTHING (docs/ADAPTERS.md §2).  This file contains no
# curl/wget/nc/ncat/netcat/openssl-s_client invocation and never sources or
# calls tools/vendor-engines.sh - tests/lint-shell.sh's "no bypass" and "no
# wiring of tools/vendor-engines.sh" checks both cover this file like every
# other file under modules/.  `trivy_run` invokes the vendored binary with
# `--offline-scan` and `--skip-check-update` (belt-and-suspenders: the first
# stops trivy resolving license/OS metadata over the network, the second
# stops it fetching its own OPA check bundle from an OCI registry even
# though this binary's checks are already compiled in) - an egress-restricted
# scanner cannot rely on a THIRD PARTY BINARY's own default being safe, the
# same reasoning modules/sast/adapters/semgrep/adapter.sh's own header
# states for semgrep's `--offline`/`SEMGREP_SEND_METRICS=off` pair.
#
# UNTRUSTED OUTPUT (CLAUDE.md §6 / docs/FOUNDATION.md tension 9's "evidence
# is untrusted target output" applied to a THIRD-PARTY TOOL's output rather
# than a scanned target): trivy's JSON is DATA, never instructions.
# `trivy_normalize` never `eval`s any part of it, never uses it to build a
# command, and only ever reaches the finding model through
# `lib/findings.sh`'s existing public setters - `finding_set`/
# `finding_set_evidence`/`finding_set_match`/`finding_emit` - which already
# redact and JSON-escape everything they touch (tests/lint-shell.sh's
# existing "no direct assignment to a redacted field" check enforces this
# repository-wide, this file included).  The `Target` field trivy reports is
# additionally validated to resolve inside the scan root before it is ever
# trusted as a finding's `loc_path` (see `_trivy_resolve_location`'s own
# comment) - the identical OWASP A01 boundary check
# modules/sast/adapters/semgrep/adapter.sh's `_semgrep_resolve_location`
# already applies to semgrep's own `path` field.
#
# MERGE/DEDUP AGAINST NATIVE modules/iac/*.rules FINDINGS (this ticket's own
# scope item 3): no code in this file does that explicitly, because none is
# needed.  docs/FOUNDATION.md's frozen pipeline (tension 11, stage 3) already
# merges and dedups every finding - native and adapter alike - purely by
# fingerprint equality, AFTER every module's findings are collected
# (lib/findings.sh's `findings_merge`/`_findings_sort_and_dedup`, called once
# from modules/iac/run.sh's `_iac_run_module` after this adapter's own
# `trivy_normalize` call).  A trivy finding's check_id is namespaced
# `trivy:<AVD-ID>` (§6 below), which never collides with a native
# `IAC-TF-*`/`IAC-K8S-*`/... id, so two tools reporting the SAME real issue
# at the SAME location remain two distinct, non-duplicate findings unless
# their full fingerprint tuple (module, check_id, path, match_digest,
# occurrence - lib/findings.sh's `_fp_components_for path`) is byte-identical
# - exactly the same "merge is real but narrow" behaviour
# modules/sast/adapters/semgrep/adapter.sh already ships for SAST, restated
# here rather than reimplemented.
#
# shellcheck shell=bash
#
# SC2329: several `_trivy_*` helpers are only reachable through the three
# contract functions above, not through a literal call shellcheck's static
# graph can follow from this file alone.
# SC1003: `[[ $c == '\' ]]` compares against a literal single backslash
# character - the identical disable modules/sast/adapters/semgrep/adapter.sh
# carries for the identical reason.
# shellcheck disable=SC2329,SC1003

if [[ -n ${SCOURSH_TRIVY_ADAPTER_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_TRIVY_ADAPTER_SOURCED=1

TRIVY_ADAPTER_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TRIVY_BIN=$TRIVY_ADAPTER_DIR/bin/trivy

# Every finding this adapter can ever emit in one run is bounded - the same
# discipline modules/sast/adapters/semgrep/adapter.sh applies via
# SCOURSH_SEMGREP_MAX_RESULTS, here split into the two nesting levels
# trivy's own JSON shape has: a max number of scanned TARGETS (Results[])
# and a max number of misconfigurations PER TARGET
# (Results[].Misconfigurations[]), so one target with a pathological number
# of findings cannot silently starve every other target's own budget.
SCOURSH_TRIVY_MAX_RESULTS=${SCOURSH_TRIVY_MAX_RESULTS:-5000}
SCOURSH_TRIVY_MAX_MISCONFIGS_PER_TARGET=${SCOURSH_TRIVY_MAX_MISCONFIGS_PER_TARGET:-2000}

# ---------------------------------------------------------------------------
# 1. trivy_detect - pure filesystem check (docs/ADAPTERS.md §5).  Never
#    touches the network, never runs the engine, never writes anything.
#    UNLIKE semgrep_detect, this does not also require a rules/ directory:
#    trivy's misconfiguration checks are compiled into the binary itself
#    (this file's own header), so a vendored trivy needs nothing beyond an
#    executable bin/trivy - the "self-contained binary" case
#    docs/ADAPTERS.md §4 explicitly allows omitting rules/ for.
# ---------------------------------------------------------------------------
trivy_detect() {
  [[ -x $TRIVY_BIN ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# 2. trivy_run OUTPUT_FILE TARGET... - runs the vendored binary fully
#    offline, writing its native JSON to OUTPUT_FILE.  Exits non-zero only
#    on a genuine engine failure (docs/ADAPTERS.md §5); the caller
#    (modules/iac/run.sh) is the one that turns that into a
#    coverage_reduction rather than aborting the run.
# ---------------------------------------------------------------------------
trivy_run() {
  local out=$1
  shift
  (( $# > 0 )) || { : >"$out"; return 1; }

  local rc=0 errfile=$SCOURSH_SCRATCH/trivy-stderr.$$
  # --offline-scan: never resolve license/OS/package metadata over the
  # network for a target this adapter scans.
  # --skip-check-update / --skip-db-update: never fetch trivy's own
  # OPA check bundle or vulnerability DB from its OCI registry, even
  # though the misconfig checks this adapter uses are already compiled
  # into the vendored binary and do not need either. Deliberately
  # redundant with --offline-scan, the same "two independent ways of
  # saying the same thing to a moving third-party CLI" precedent
  # modules/sast/adapters/semgrep/adapter.sh's semgrep_run sets for
  # --offline plus SEMGREP_SEND_METRICS=off.
  # --scanners misconfig: this adapter is IaC-misconfiguration only; it
  # never asks trivy for vulnerability (SCA) or secret scanning, which
  # modules/sca/ and modules/sast/rules/secrets.rules already own.
  # --format json --quiet: machine-readable output only, no progress noise
  # mixed into stdout.
  "$TRIVY_BIN" config \
    --offline-scan --skip-check-update --skip-db-update \
    --scanners misconfig --format json --quiet \
    -- "$@" >"$out" 2>"$errfile" || rc=$?

  if (( rc != 0 )); then
    log_warn "iac: trivy adapter exited $rc - $(cat "$errfile" 2>/dev/null | head -n 5)"
  fi
  rm -f "$errfile"
  return "$rc"
}

# ---------------------------------------------------------------------------
# 3. trivy_normalize INPUT_FILE - reads INPUT_FILE (trivy's own JSON,
#    written by trivy_run) and emits one scoursh finding per FAILED
#    misconfiguration via lib/findings.sh's public API only
#    (docs/ADAPTERS.md §5/§8).  Trivy's JSON nests findings two levels
#    deep - a top-level "Results" array, one entry per SCANNED TARGET
#    (file), each carrying its own "Misconfigurations" array - unlike
#    semgrep's single flat "results" array, so this walks both levels.
# ---------------------------------------------------------------------------
trivy_normalize() {
  local infile=$1
  [[ -r $infile ]] || return 0

  local results=$SCOURSH_SCRATCH/trivy-results.$$
  _trivy_split_results "$infile" >"$results"

  local scan_root=${_SCAN_RESOLVED_PATH:-.}
  scan_root=$(scan_root_of "$scan_root")

  local result_obj count=0 results_truncated=0
  while IFS= read -r result_obj; do
    [[ -n $result_obj ]] || continue
    if [[ $result_obj == __TRUNCATED__ ]]; then
      results_truncated=1
      break
    fi

    local target
    target=$(_trivy_json_string_field "$result_obj" Target) || target=''

    local misconfigs=$SCOURSH_SCRATCH/trivy-misconfigs.$$
    _trivy_split_misconfigs "$result_obj" >"$misconfigs"
    local mobj target_truncated=0
    while IFS= read -r mobj; do
      [[ -n $mobj ]] || continue
      if [[ $mobj == __TRUNCATED__ ]]; then
        target_truncated=1
        break
      fi
      count=$(( count + 1 ))
      _trivy_emit_finding "$mobj" "$target" "$scan_root"
    done <"$misconfigs"
    rm -f "$misconfigs"

    if (( target_truncated )); then
      run_record coverage_reduction \
        "module=iac reason=engine_results_truncated engine=trivy max=$SCOURSH_TRIVY_MAX_MISCONFIGS_PER_TARGET target=$target"
    fi
  done <"$results"
  rm -f "$results"

  if (( results_truncated )); then
    run_record coverage_reduction \
      "module=iac reason=engine_results_truncated engine=trivy max=$SCOURSH_TRIVY_MAX_RESULTS"
  fi
  run_record coverage_reduction "module=iac reason=engine_boosted_not_a_replacement engine=trivy results=$count"
}

# ---------------------------------------------------------------------------
# Private helpers below.  Never called directly by anything outside this
# file (docs/ADAPTERS.md §5's contract is the three functions above).
# ---------------------------------------------------------------------------

# _trivy_split_objects_from_marker CONTENT MARKER MAX - shared depth- and
# string-aware array-of-objects splitter (the same technique
# modules/sast/adapters/semgrep/adapter.sh's own _semgrep_split_results
# uses): locates the FIRST unescaped `"MARKER":` token in CONTENT, expects
# a JSON array immediately after it, and prints one COMPLETE element
# object's flattened raw JSON text per output line.  Bounded by MAX;
# prints a literal `__TRUNCATED__` sentinel line and stops if the bound is
# hit.  Generalized (semgrep's version is single-purpose, single-level)
# because this file walks TWO separate arrays - the top-level "Results"
# array and each Result's own "Misconfigurations" array - and both need
# the identical walk, just against a different marker and a different
# slice of content.
_trivy_split_objects_from_marker() {
  local content=$1 marker=$2 max=$3
  printf '%s' "$content" | awk -v marker="$marker" -v max="$max" '
    { content = content $0 " " }
    END {
      n = length(content)
      m = "\"" marker "\""
      p = index(content, m)
      if (p == 0) { exit }
      i = p + length(m)
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
  '
}

# _trivy_split_results INFILE - the top-level split: one flattened "Result"
# object (one scanned target) per output line, from INFILE's own
# "Results" array.  Reads the file directly rather than loading it into a
# bash variable first (modules/sast/adapters/semgrep/adapter.sh's
# _semgrep_split_results does the same for the same reason: this can be
# the whole trivy run's output, potentially large).
_trivy_split_results() {
  local file=$1
  _trivy_split_objects_from_marker "$(cat -- "$file" 2>/dev/null)" Results "$SCOURSH_TRIVY_MAX_RESULTS"
}

# _trivy_split_misconfigs RESULT_OBJ - the nested split: one flattened
# "Misconfiguration" object per output line, from RESULT_OBJ's own
# "Misconfigurations" array.  RESULT_OBJ is already an in-memory string (one
# element _trivy_split_results already extracted), not a file, so this
# reuses the identical marker-walk against that string directly.
_trivy_split_misconfigs() {
  local result_obj=$1
  _trivy_split_objects_from_marker "$result_obj" Misconfigurations "$SCOURSH_TRIVY_MAX_MISCONFIGS_PER_TARGET"
}

# _trivy_json_string_field OBJ KEY - the JSON-string value of the FIRST
# unescaped `"KEY"` token in OBJ, with standard JSON escapes decoded
# (\" \\ \/ \n \t \r \b \f).  Identical contract and \uXXXX-as-literal-`?`
# narrowing to modules/sast/adapters/semgrep/adapter.sh's own
# _semgrep_json_string_field - see that function's own comment for why.
_trivy_json_string_field() {
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

# _trivy_json_object_field OBJ KEY - the raw JSON text (still `{...}`) of
# the FIRST unescaped `"KEY"` token's object value, brace-depth- and
# string-aware.  Identical to
# modules/sast/adapters/semgrep/adapter.sh's own _semgrep_json_object_field.
_trivy_json_object_field() {
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

# _trivy_json_number_field OBJ KEY - the numeric value of the FIRST
# unescaped `"KEY"` token in OBJ.  Bash `=~` here is matched against
# already-isolated, already-trusted-shape JSON text (not raw scanned file
# content), using ONLY portable POSIX bracket-expression syntax - the same
# precedent modules/sast/adapters/semgrep/adapter.sh's own
# _semgrep_json_number_field sets (docs/FOUNDATION.md tension 2's
# BSD-regcomp hazard does not apply to this class of use).
_trivy_json_number_field() {
  local obj=$1 key=$2
  [[ $obj =~ \"$key\"[[:space:]]*:[[:space:]]*(-?[0-9]+) ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

# _trivy_severity_map TRIVY_SEVERITY - trivy's own
# UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL vocabulary onto scoursh's
# info|low|medium|high|critical (lib/records.sh's severity_rank/
# severity_name).  UNLIKE modules/sast/adapters/semgrep/adapter.sh's own
# _semgrep_severity_map, this DOES map onto `critical` - see that file's own
# header ("SEVERITY MAPPING: WHY THIS CAPS AT `high`, UNLIKE
# `_trivy_severity_map`") for the full, current reasoning, which turns on
# two things neither of which applies here: (1) vocabulary shape - semgrep's
# own signal is the coarser three-tier ERROR/WARNING/INFO, with no tier of
# its own above ERROR, whereas trivy's CRITICAL/HIGH/MEDIUM/LOW is already
# four tiers that map 1:1 onto scoursh's own four non-`info` tiers, so this
# mapping is a rename, not a judgement call; and (2) ruleset provenance -
# trivy's misconfiguration checks are COMPILED INTO the vendored binary
# itself, a fixed, versioned catalog from trivy's own upstream release
# (see this file's own "WHICH ENGINE, AND WHY" above), unlike semgrep's
# separate, operator-vendored, arbitrary-and-unreviewed ruleset.  Both
# reasons argue for withholding `critical` from semgrep specifically, and
# neither argues against trivy's own CRITICAL reaching scoursh's `critical`
# here.
_trivy_severity_map() {
  case $1 in
    CRITICAL) printf 'critical' ;;
    HIGH) printf 'high' ;;
    MEDIUM) printf 'medium' ;;
    LOW) printf 'low' ;;
    *) printf 'medium' ;;
  esac
}

# _trivy_resolve_location SCAN_ROOT REPORTED_PATH - prints a scan-root-
# relative path on success, or fails (empty stdout, non-zero return) when
# REPORTED_PATH does not resolve to somewhere inside SCAN_ROOT.  Identical
# boundary check to modules/sast/adapters/semgrep/adapter.sh's own
# _semgrep_resolve_location, applied to trivy's own "Target" field instead
# of semgrep's "path" - see that function's comment for the full reasoning
# (OWASP A01: a buggy or compromised vendored engine must never be trusted
# to attribute a finding outside the authorised scan boundary).
_trivy_resolve_location() {
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

# _trivy_match_text ABSPATH LINE FALLBACK - the RAW matched text for the
# fingerprint/evidence, identical contract and reasoning to
# modules/sast/adapters/semgrep/adapter.sh's own _semgrep_match_text
# (docs/FOUNDATION.md tension 5/tension 11's "re-derive match_digest ...
# from the file at the adapter's reported path and line" requirement,
# applied here to trivy's own CauseMetadata.StartLine).
_trivy_match_text() {
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

# _trivy_emit_finding MISCONFIG_OBJ TARGET SCAN_ROOT - MISCONFIG_OBJ is one
# complete misconfiguration result object's raw JSON text (from
# _trivy_split_misconfigs); TARGET is the scanned file path trivy reported
# on the enclosing Result object (from _trivy_split_results).  Mints a
# finding purely through lib/findings.sh's public API (docs/ADAPTERS.md
# §5/§8's round-trip requirement).
_trivy_emit_finding() {
  local obj=$1 target_raw=$2 scan_root=$3

  # Defensive, not load-bearing under trivy's own default behaviour: trivy
  # only reports FAIL-status entries unless invoked with
  # --include-non-failures, which trivy_run above never passes - but a
  # future flag change or a vendored fork must not silently start reporting
  # PASS/EXCEPTION rows as findings just because this adapter stopped
  # checking.
  local status
  status=$(_trivy_json_string_field "$obj" Status) || status=''
  if [[ -n $status && $status != FAIL ]]; then
    return 0
  fi

  local rule_id
  rule_id=$(_trivy_json_string_field "$obj" ID) || rule_id=''
  [[ -n $rule_id ]] || return 0

  local title message severity_raw resolution cause_obj resource line
  title=$(_trivy_json_string_field "$obj" Title) || title=''
  message=$(_trivy_json_string_field "$obj" Message) || message=''
  severity_raw=$(_trivy_json_string_field "$obj" Severity) || severity_raw=''
  resolution=$(_trivy_json_string_field "$obj" Resolution) || resolution=''
  cause_obj=$(_trivy_json_object_field "$obj" CauseMetadata) || cause_obj=''
  resource=$(_trivy_json_string_field "$cause_obj" Resource) || resource=''
  line=$(_trivy_json_number_field "$cause_obj" StartLine) || line=''

  local resolved
  resolved=$(_trivy_resolve_location "$scan_root" "$target_raw") || {
    run_record coverage_reduction \
      "module=iac reason=engine_reported_path_outside_scan_root engine=trivy check=trivy:$rule_id"
    return 0
  }
  local relpath
  relpath=$(sast_relpath "$scan_root" "$resolved")

  local fallback=$message
  [[ -n $fallback ]] || fallback=$title
  local match_text
  match_text=$(_trivy_match_text "$resolved" "${line:-0}" "$fallback")

  local check_id="trivy:$rule_id"
  local finding_title=$title
  [[ -n $finding_title ]] || finding_title="trivy: $rule_id"
  if [[ -n $resource ]]; then
    finding_title="$finding_title ($resource)"
  fi

  finding_new
  finding_set check_id "$check_id"
  finding_set module iac
  finding_set title "$finding_title"
  finding_set base_severity "$(_trivy_severity_map "$severity_raw")"
  finding_set confidence medium
  finding_set cwe none
  finding_set owasp none
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
  local remediation_text=$resolution
  [[ -n $remediation_text ]] || remediation_text="Review and remediate per trivy check '$rule_id': ${message:-no further detail reported}."
  finding_set remediation "$remediation_text"
  # Conditional for the same reason semgrep's is: trivy is a general-purpose IaC
  # scanner, and only a check whose match IS a credential trades its evidence
  # for a placeholder (lib/findings.sh section 8a, tension 9).
  if (( is_secret )); then
    finding_set_secret_match "$match_text"
  else
    finding_set_match "$match_text"
    finding_set_evidence "$match_text"
  fi
  finding_emit
}
