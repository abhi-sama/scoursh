#!/usr/bin/env bash
# modules/sca/go_engine.sh - Go module-file (go.mod/go.sum) parsing and the
# data/advisories.db exact-match lookup for the Go ecosystem (docs/DESIGN.md
# §6.5, §13 step 4; docs/FOUNDATION.md tension 25's frozen Go normalisation
# rule: "full module path, /vN suffix retained, version without a
# +incompatible suffix").
#
# Landed as its OWN engine file, sourced by modules/sca/run.sh next to
# modules/sca/engine.sh's npm parser, per that file's own header instruction:
# "if a sibling ecosystem (Python, Go, ...) lands its own engine.sh...its own
# run function is called from _sca_run_module...do not fork this file per
# ecosystem." modules/sca/run.sh is the one shared file that changes for this
# ticket; this one is new and entirely additive.
#
# SCOPE (this ticket): go.mod and go.sum only. `replace`/`exclude` directives
# are not resolved - STATED LIMITATION, this repository's own convention for
# a cost paid deliberately rather than hidden: a `replace` that redirects a
# module to a fork or a local filesystem path is invisible to this parser,
# which reports the pre-`replace` `require` line as pinned, exactly the same
# class of limitation modules/sca/engine.sh's own npm hoisting heuristic
# states for itself.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SCA_GO_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SCA_GO_ENGINE_SOURCED=1

# modules/sca/engine.sh owns SCA_DEFAULT_EXCLUDE_DIRS, sca_relpath,
# sca_advisories_db_path, sca_lookup_exact, sca_package_known, and the
# lib/report.sh + lib/config.sh sourcing they need - shared across every SCA
# ecosystem, not re-declared here. Guarded exactly like modules/sca/engine.sh
# itself guards its own lib/*.sh sources, so a test can source this file
# standalone (without going through modules/sca/run.sh first) and still get
# a working shared layer underneath it.
if [[ -z ${SCOURSH_SCA_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=modules/sca/engine.sh
  source "${BASH_SOURCE[0]%/*}/engine.sh"
fi

# ---------------------------------------------------------------------------
# 1. go.mod / go.sum discovery
# ---------------------------------------------------------------------------

# sca_walk_go_manifests ROOT - one absolute path per line, LC_ALL=C sorted,
# to every go.mod and go.sum under ROOT, skipping SCA_DEFAULT_EXCLUDE_DIRS at
# any depth (that shared list already names "vendor" - a `go mod vendor` tree
# ships its own copies and must never be walked as this project's own pins).
# ROOT itself may be a single go.mod or go.sum file, mirroring
# sca_walk_npm_lockfiles's own "--path names one file directly" case.
sca_walk_go_manifests() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      go.mod | go.sum) printf '%s\n' "$root" ;;
    esac
    return 0
  fi
  local -a prune=()
  local d first=1
  for d in "${SCA_DEFAULT_EXCLUDE_DIRS[@]+"${SCA_DEFAULT_EXCLUDE_DIRS[@]}"}"; do
    (( first )) || prune+=(-o)
    prune+=(-path "$root/*/$d" -o -path "$root/$d")
    first=0
  done
  find "$root" \( "${prune[@]+"${prune[@]}"}" \) -prune -o -type f \
    \( -name go.mod -o -name go.sum \) \
    -print 2>/dev/null | LC_ALL=C sort
}

# _sca_go_manifest_dirs ROOT - one directory per line, LC_ALL=C sorted and
# de-duplicated, for every directory sca_walk_go_manifests found a go.mod
# and/or go.sum in (a directory holding both contributes exactly one line).
_sca_go_manifest_dirs() {
  local root=$1 f
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    dirname -- "$f"
  done < <(sca_walk_go_manifests "$root") | LC_ALL=C sort -u
}

# ---------------------------------------------------------------------------
# 2. Name normalisation (docs/FOUNDATION.md tension 25's frozen table)
# ---------------------------------------------------------------------------

# sca_go_normalize_module MODULE - the identity function: the FULL module
# path, /vN major-version suffix (e.g. ".../v3") RETAINED. Named and called
# explicitly, exactly like sca_npm_normalize_name, so this is a visible
# per-ecosystem decision rather than an assumption baked silently into the
# lookup call site.
sca_go_normalize_module() {
  printf '%s' "$1"
}

# sca_go_normalize_version VERSION - strips a trailing "+incompatible"
# build-tag suffix (Go's own marker for a pre-modules v2+ import path with no
# go.mod of its own), which tension 25's frozen table requires: the
# advisories.db key is the version WITHOUT it. A version carrying no such
# suffix passes through unchanged. This is the half of tension 25's Go rule a
# naive reading gets wrong by NOT stripping it - tests/suites/sca.sh pins
# this against that exact naive (unstripped) reading.
sca_go_normalize_version() {
  printf '%s' "${1%+incompatible}"
}

# ---------------------------------------------------------------------------
# 3. go.mod - the authoritative direct/transitive source
# ---------------------------------------------------------------------------
# go.mod's own `require` directives are the ONLY source consulted when go.mod
# exists (docs/DESIGN.md §6.5, this ticket's own AC): a bare `require` line
# is direct; one carrying a trailing `// indirect` comment - the exact marker
# `go mod tidy` itself writes - is transitive. go.sum is NOT also consulted
# in this case (see sca_go_scan_tree below): go.sum's entries exist for
# checksum verification, not as a dependency-kind signal, and re-deriving
# direct/transitive from it would just re-implement a worse version of what
# go.mod already states outright.
# STATED LIMITATION: Go's module-graph pruning (go.mod `go 1.17`+) can mean
# go.mod's own require list omits some transitively-required module that
# only appears in go.sum - the same class of coverage note the npm engine
# already states for its own heuristics, not silently hidden here either.

# _sca_go_mod_require_line LINE - LINE is one already-trimmed line found
# either as a block-form require ("module version [// indirect]") or as the
# tail of a single-line "require module version [// indirect]" statement.
# Prints "module<0x1F>version<0x1F>direct|transitive"; prints nothing (and
# returns 1) for a line this does not recognise as a require entry (blank, or
# a bare comment).
_sca_go_mod_require_line() {
  local line=$1 code module rest version indirect=0
  [[ -n $line ]] || return 1
  [[ $line == '//'* ]] && return 1
  case $line in
    *'// indirect'*) indirect=1 ;;
  esac
  code=${line%%//*}
  code="${code%"${code##*[![:space:]]}"}"
  [[ -n $code ]] || return 1
  module=${code%%[[:space:]]*}
  rest=${code#"$module"}
  rest="${rest#"${rest%%[![:space:]]*}"}"
  version="${rest%"${rest##*[![:space:]]}"}"
  [[ -n $module && -n $version ]] || return 1
  if (( indirect )); then
    printf '%s\x1f%s\x1ftransitive\n' "$module" "$version"
  else
    printf '%s\x1f%s\x1fdirect\n' "$module" "$version"
  fi
}

# _sca_go_parse_mod FILE - prints one "module<0x1F>version<0x1F>
# direct|transitive" row per `require` entry, covering both the single-line
# form (`require module version`) and the parenthesised block form.
_sca_go_parse_mod() {
  local file=$1 line t in_block=0
  while IFS= read -r line || [[ -n $line ]]; do
    t="${line#"${line%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    [[ -n $t ]] || continue
    if (( in_block )); then
      if [[ $t == ')'* ]]; then
        in_block=0
        continue
      fi
      _sca_go_mod_require_line "$t" || true
      continue
    fi
    case $t in
      'require ('*)
        in_block=1
        ;;
      'require '*)
        _sca_go_mod_require_line "${t#'require '}" || true
        ;;
    esac
  done <"$file"
}

# ---------------------------------------------------------------------------
# 4. go.sum - the honest "unknown" fallback when go.mod is absent
# ---------------------------------------------------------------------------
# go.sum has no direct/transitive signal of its own (docs/DESIGN.md §6.5,
# this ticket's own AC): every entry is reported "unknown" rather than
# guessed - the same "state it, don't guess it" discipline the npm engine's
# package.json-absent fallbacks use, taken one step further because go.sum
# (unlike yarn.lock) carries no internal dependency graph either: it is only
# a flat, LC_ALL=C-sorted list of `module version hash` and
# `module version/go.mod hash` lines, each module@version pinned twice (once
# for the module zip, once for its own go.mod) with no per-line
# direct/transitive marker at all.

# _sca_go_parse_sum FILE - prints one "module<0x1F>version<0x1F>unknown" row
# per DISTINCT (module, version) pair found in FILE, de-duplicating the
# module-zip line and its own "version/go.mod" sibling line down to one row.
_sca_go_parse_sum() {
  local file=$1 line module verfield version key
  local -A seen=()
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    module=${line%%[[:space:]]*}
    verfield=${line#"$module"}
    verfield="${verfield#"${verfield%%[![:space:]]*}"}"
    verfield=${verfield%%[[:space:]]*}
    [[ -n $module && -n $verfield ]] || continue
    version=${verfield%/go.mod}
    key="$module"$'\x1f'"$version"
    if [[ -z ${seen[$key]:-} ]]; then
      seen[$key]=1
      printf '%s\x1f%s\x1funknown\n' "$module" "$version"
    fi
  done <"$file"
}

# ---------------------------------------------------------------------------
# 5. Finding emission
# ---------------------------------------------------------------------------

# _sca_go_emit_finding DIRECT MANIFEST_RELPATH PINNED_VERSION ROW - ROW is
# one data/advisories.db TSV line already known to match the NORMALISED
# (module, version). Mirrors modules/sca/engine.sh's own _sca_emit_finding
# (same TSV-to-\x1f translation for the same literal-tab-IFS reason
# documented there) but mints SCA-GO-VULNERABLE_DEP-01, and additionally
# records PINNED_VERSION (the un-normalised, as-declared version) in the
# evidence whenever normalisation actually changed it - tension 25's Go rule
# strips "+incompatible" before lookup, and this makes that step visible in
# the report rather than silently rewriting what the operator pinned.
_sca_go_emit_finding() {
  local direct=$1 manifest_rel=$2 pinned_ver=$3 row=$4
  local eco pkg ver advisory sev fixed summary
  local marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r eco pkg ver advisory sev fixed summary <<<"$marked"

  local accept_risk=false
  [[ -z $fixed ]] && accept_risk=true

  finding_new
  finding_set check_id SCA-GO-VULNERABLE_DEP-01
  finding_set module sca
  finding_set title "Go: $pkg@$ver is vulnerable ($advisory)"
  finding_set base_severity "$sev"
  finding_set confidence high
  finding_set cwe none
  finding_set owasp A06:2021
  finding_set loc_ecosystem "$eco"
  finding_set loc_package "$pkg"
  finding_set loc_version "$ver"
  finding_set loc_advisory_id "$advisory"
  finding_set path "$manifest_rel"
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set logical_kind dependency
  finding_set logical_fqn "$eco:$pkg@$ver"
  if [[ -n $fixed ]]; then
    finding_set remediation "Upgrade $pkg to one of: $fixed."
  else
    finding_set remediation "No fixed version is published upstream yet for $advisory against $pkg; this is an accept-risk candidate pending an upstream fix."
  fi
  local evline
  evline="dependency: $pkg@$ver"$'\n'
  evline+="dependency_type: $direct"$'\n'
  evline+="manifest: $manifest_rel"$'\n'
  if [[ $pinned_ver != "$ver" ]]; then
    evline+="pinned_version: $pinned_ver (normalized to $ver for lookup, docs/FOUNDATION.md tension 25)"$'\n'
  fi
  evline+="advisory: $advisory ($sev)"$'\n'
  evline+="fixed_versions: ${fixed:-none published}"$'\n'
  evline+="accept_risk_candidate: $accept_risk"$'\n'
  evline+="summary: $summary"
  finding_set_evidence "$evline"
  finding_emit
}

# ---------------------------------------------------------------------------
# 6. Orchestration
# ---------------------------------------------------------------------------

# sca_go_scan_tree ROOT - the module's whole Go slice: walk ROOT for
# go.mod/go.sum directories, parse each (go.mod when present - direct or
# transitive; else go.sum - unknown), look every pinned dependency up
# against data/advisories.db, emit one SCA-GO-VULNERABLE_DEP-01 finding per
# vulnerable pinned dependency, and one roll-up SCA-COV-UNKNOWN_VERSION-01
# finding when any Go package the db tracks had its exact pinned version go
# unmatched - the same shape as modules/sca/engine.sh's sca_scan_tree, and
# still a second, independent invocation that never calls into it, exactly as
# modules/sca/run.sh's own header instructs each ecosystem's run function to
# be self-contained.  The ONE thing the two now share is the roll-up
# accumulator (modules/sca/engine.sh section 8a), for the reason immediately
# below.
#
# THE STATED LIMITATION THIS HEADER USED TO CARRY IS FIXED, and the fix is
# worth knowing about here because it is the one piece of shared state this
# file has.  It used to read: when a single run scans BOTH an npm and a Go
# manifest tree and BOTH have unknown-version gaps, this emits its OWN
# SCA-COV-UNKNOWN_VERSION-01 alongside the npm engine's - two roll-ups rather
# than one, because the two engines share no process state.  That was worse
# than "two roll-ups": both hashed to the SAME fingerprint (the SCA location
# profile is ecosystem/package/advisory_id and a roll-up populates none of
# them), so findings_merge's dedup silently dropped one and the operator was
# told a smaller number of unknown-version dependencies than the truth.
# modules/sca/engine.sh's section 8a is the shared accumulator that replaces
# the per-walk emission; this walk feeds it with `sca_rollup_add Go` and ends
# with `_sca_rollup_autoflush`, so it still emits its own roll-up when called
# standalone and contributes to the module's single one when called from
# modules/sca/run.sh.
#
# The db-absent guard below is SILENT for the same reason
# modules/sca/engine.sh's is: this file's warning and that one's meant every
# `sca` run announced the same absence twice, while the Python and Java walks
# announced nothing.  `sca_report_no_advisories_db` (engine.sh) now makes that
# announcement once, for the module, naming every ecosystem.
sca_go_scan_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  sca_advisories_db_readable "$db" || return 0

  local dir has_mod has_sum relpath hits name pinned_ver direct row processed=0
  hits=$SCOURSH_SCRATCH/sca-go-hits.$$

  while IFS= read -r dir; do
    [[ -n $dir ]] || continue
    has_mod=0
    has_sum=0
    [[ -f $dir/go.mod ]] && has_mod=1
    [[ -f $dir/go.sum ]] && has_sum=1
    if (( ! has_mod && ! has_sum )); then continue; fi
    processed=$(( processed + 1 ))

    if (( has_mod )); then
      relpath=$(sca_relpath "$root" "$dir/go.mod")
    else
      relpath=$(sca_relpath "$root" "$dir/go.sum")
    fi
    run_record checks_run SCA-GO-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name pinned_ver direct; do
      [[ -n $name && -n $pinned_ver ]] || continue
      local lookup_name lookup_ver
      lookup_name=$(sca_go_normalize_module "$name")
      lookup_ver=$(sca_go_normalize_version "$pinned_ver")
      if sca_lookup_exact Go "$lookup_name" "$lookup_ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_go_emit_finding "$direct" "$relpath" "$pinned_ver" "$row"
        done <"$hits"
      elif sca_package_known Go "$lookup_name" "$db"; then
        sca_rollup_add Go
      fi
    done < <(
      if (( has_mod )); then
        _sca_go_parse_mod "$dir/go.mod"
      else
        _sca_go_parse_sum "$dir/go.sum"
      fi
    )
  done < <(_sca_go_manifest_dirs "$root")
  rm -f "$hits"

  # Section 8a (modules/sca/engine.sh): accumulate always, emit only when no
  # deferred window is open.
  _sca_rollup_autoflush

  if (( processed > 0 )); then
    run_record coverage_reduction 'module=sca reason=go_replace_exclude_directives_not_resolved'
  fi
}
