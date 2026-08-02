#!/usr/bin/env bash
# lib/checks.sh - scan-profile check-set selection.
#
# Owns:
#   docs/DESIGN.md    §5 "Scan profiles" and the remainder of §13 step 2 that
#                      scan.sh's own header explicitly deferred: "tension 15's
#                      check-set filter chain and check registry".
#   docs/FOUNDATION.md tension 15 (check-set selection precedence) - the
#                      RESOLUTION this file implements verbatim, and its own
#                      wording is corrected here (see "compliance", below).
#   docs/FOUNDATION.md finding F3 (closed here) and F8 (closed here).
#   rules/RULE-FORMAT.md §9.1.3 (tags), §9.5 (script check).
#
# ---------------------------------------------------------------------------
# The three filters, and how they compose
# ---------------------------------------------------------------------------
# Three independent controls select which checks in a candidate set actually
# run: `--profile-scan quick|full|compliance`, `--intensity passive|safe|
# active` (a type-tag ceiling), and `--allow-intrusive` (removes `intrusive`-
# tagged checks unless given).  They are FILTERS applied in sequence and the
# result is their INTERSECTION - the most restrictive control always wins,
# and no filter can ever re-enable a check an earlier one dropped
# (docs/FOUNDATION.md tension 15's RESOLUTION, options 1 and 2 rejected).
#
# Each named profile's check set, precisely:
#   quick       Checks tagged `quick`.  "Passive + config-read, no active
#               probes" (docs/DESIGN.md §5) in practice, because nothing
#               active/safe-active is ever tagged `quick` in a shipped pack -
#               but the SELECTION rule itself is the tag, not the type.
#   full        Every check in the candidate set.  "A rule with no profile
#               tag runs only in full" (rules/RULE-FORMAT.md §9.1.3) is
#               exactly this: `full` needs no tag to keep a check.
#   compliance  Checks tagged `compliance`.  See below - this is finding F3,
#               closed by this file.
#
# `full` is the DEFAULT when `--profile-scan` is not given at all: scoursh's
# own positioning is "scan exhaustively" (AGENTS.md), so the absence of a
# profile flag must not silently narrow the scan.  `passive` is the DEFAULT
# `--intensity` when not given (including for `dast` itself, which the flag
# is defined on): every other guardrail in this tool defaults to the safest
# behaviour (`--allow-intrusive` off, `--paranoid` available, intrusive
# checks opt-in), and "no flag given" must never be the one place a scan
# defaults to firing active probes at a target.  Neither default was pinned
# in docs/DESIGN.md or docs/FOUNDATION.md before this file; both are settled
# here, for the reasons above, rather than left for the CLI layer to invent
# ad hoc.
#
# ---------------------------------------------------------------------------
# `compliance`: closing finding F3
# ---------------------------------------------------------------------------
# rules/RULE-FORMAT.md §9.1.3 and docs/FOUNDATION.md tension 15 gave two
# INCOMPATIBLE definitions of the `compliance` profile:
#   - §9.1.3: an explicit `compliance` PROFILE TAG, authored per check.
#   - tension 15 step 2 (as originally written): "keeps checks with a
#     non-empty `cis` OR `owasp` field", justified as "computable from the
#     record, with no separate list to drift".
# The field-derived reading is unusable as written: `owasp` is a REQUIRED
# key on every pattern rule and script check (rules/RULE-FORMAT.md §9.1,
# §9.5) - its value is a real category (`A03:2021`) or the literal `none`,
# but the KEY is never absent, so "non-empty owasp field" is true for every
# single check in the catalog, `compliance` and not alike.  This was tracked
# as open finding F3 ("`compliance` also has two incompatible definitions...
# and since `owasp` is required on every pattern rule the derived form
# selects the entire catalog", docs/FOUNDATION.md "Known follow-ups").
#
# This file settles F3 on the TAG reading, for three independent reasons:
#   1. It is the only one of the two that is actually computable as
#      described - "non-empty cis-or-owasp" is vacuously true, so it cannot
#      be what selects a strict subset.
#   2. lib/records.sh already enforces a CLOSED tag vocabulary where
#      `compliance` is a legal PROFILE tag value (`_records_check_tags`,
#      E044) - the tag-reading is already load-bearing in the shipped
#      parser, not a fresh design.
#   3. Both compliance-relevant worked examples in rules/RULE-FORMAT.md §12
#      (12.1 `SAST-SEC-AWS_AKID-01`, 12.5 `IAC-TF-OPEN_CIDR-01`) carry the
#      explicit `tags: compliance` line; a third worked example with a real
#      `owasp` value and no `cis` (12.2 `SAST-PY-YAML_LOAD-01`, `owasp:
#      A08:2021`, tags `static`/`quick` only) has NO compliance tag - the
#      frozen document's own examples already assume the tag reading.
# docs/FOUNDATION.md's tension 15 and its F3 entry are updated in the same
# change that adds this file, to record the closure rather than leave the
# register and the code disagreeing (AGENTS.md: "if you disagree with a
# resolution, change the register deliberately... do not quietly diverge in
# code").
#
# ---------------------------------------------------------------------------
# `derived` (composite) checks and `--intensity`: closing finding F8
# ---------------------------------------------------------------------------
# `derived` is a type tag with no tier in the passive/safe/active ceiling
# (rules/RULE-FORMAT.md §9.1.3 lists it as a type tag; tension 15 step 3's
# ceiling table never mentions it), so under a naive intersection filter
# ANY `--intensity` value drops every composite - `scan.sh all --intensity
# active` would drop `COMPOSITE-TOKEN-HIJACK` along with everything else,
# which is the opposite of what "active" means.  Composites consume other
# checks' findings rather than issuing requests of their own, so no
# intensity tier is a meaningful ceiling for one; this file exempts `derived`
# checks from the `--intensity` filter specifically (finding F8's own
# direction).  A `derived` check is still subject to `--profile-scan` and
# `--allow-intrusive` like any other - only the intensity ceiling is waived.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CHECKS_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CHECKS_SOURCED=1

# shellcheck source=lib/records.sh
source "${BASH_SOURCE[0]%/*}/records.sh"

# Exported (not just set) because their only reader is scan.sh, a separate
# file shellcheck cannot dataflow-trace a use back into (it follows a
# `source` forward, from scan.sh into this file, never the reverse) -
# `export` is what tells shellcheck's SC2034 "used externally" is true here,
# the same convention lib/core.sh uses for its own SCOURSH_EXIT_* constants.
CHECKS_PROFILE_DEFAULT=full
CHECKS_INTENSITY_DEFAULT=passive
export CHECKS_PROFILE_DEFAULT CHECKS_INTENSITY_DEFAULT
CHECKS_PROFILES=(quick full compliance)
CHECKS_INTENSITIES=(passive safe active)

checks_valid_profile() {
  local p=$1 x
  for x in "${CHECKS_PROFILES[@]+"${CHECKS_PROFILES[@]}"}"; do [[ $x == "$p" ]] && return 0; done
  return 1
}

checks_valid_intensity() {
  local p=$1 x
  for x in "${CHECKS_INTENSITIES[@]+"${CHECKS_INTENSITIES[@]}"}"; do [[ $x == "$p" ]] && return 0; done
  return 1
}

# ---------------------------------------------------------------------------
# 1. Per-record tag inspection
# ---------------------------------------------------------------------------

# checks_has_tag SET IDX TAG - true if the record's `tags` list contains TAG
# (an exact, case-sensitive match on one LF-separated entry).
checks_has_tag() {
  local set=$1 idx=$2 want=$3 t
  while IFS= read -r t; do
    [[ $t == "$want" ]] && return 0
  done <<<"$(records_list "$set" "$idx" tags)"
  return 1
}

# checks_type_tag SET IDX - the record's single TYPE tag (`static`,
# `passive`, `safe-active`, `active`, `config-read`, `posture`, or
# `derived`), or '' if none is present.  A well-formed record always has
# exactly one (rules/RULE-FORMAT.md §9.1.3, enforced by E044 at lint time);
# this function still returns '' rather than assuming that, because a caller
# fed an unvalidated fixture (as the test suite deliberately does, to prove
# the FAILURE mode) must not get a bogus match instead.
checks_type_tag() {
  local set=$1 idx=$2 t
  while IFS= read -r t; do
    case $t in
      static | passive | safe-active | active | config-read | posture | derived)
        printf '%s' "$t"
        return 0
        ;;
    esac
  done <<<"$(records_list "$set" "$idx" tags)"
  printf ''
}

checks_is_intrusive() { checks_has_tag "$1" "$2" intrusive; }

# ---------------------------------------------------------------------------
# 2. The three filters (docs/FOUNDATION.md tension 15)
# ---------------------------------------------------------------------------

# checks_profile_keeps SET IDX PROFILE - filter 1: the profile TAG filter.
checks_profile_keeps() {
  local set=$1 idx=$2 profile=$3
  case $profile in
    full) return 0 ;;
    quick) checks_has_tag "$set" "$idx" quick ;;
    compliance) checks_has_tag "$set" "$idx" compliance ;;
    *) return 1 ;;   # not one of the three named profiles: keep nothing
  esac
}

# checks_intensity_keeps SET IDX INTENSITY - filter 2: the type-tag ceiling.
# INTENSITY may be '' (no ceiling at all - used by callers that never apply
# one, e.g. a module with no --intensity concept); every OTHER value must be
# one of the three named tiers or nothing is kept, same "unknown means keep
# nothing" discipline as checks_profile_keeps.
checks_intensity_keeps() {
  local set=$1 idx=$2 intensity=$3 type
  [[ -n $intensity ]] || return 0
  type=$(checks_type_tag "$set" "$idx")
  [[ $type != derived ]] || return 0   # finding F8: composites are exempt
  case $intensity in
    passive) [[ $type == passive || $type == config-read || $type == posture || $type == static ]] ;;
    safe) [[ $type == passive || $type == config-read || $type == posture || $type == static || $type == safe-active ]] ;;
    active) [[ $type == passive || $type == config-read || $type == posture || $type == static \
      || $type == safe-active || $type == active ]] ;;
    *) return 1 ;;
  esac
}

# checks_intrusive_keeps SET IDX ALLOW - filter 3: `--allow-intrusive`.
# ALLOW is the literal string "true" or anything else (matching how scan.sh
# stores every boolean SCAN_FLAGS entry); '' (not given) behaves as "false",
# which is the documented default (docs/DESIGN.md §5: "off by default").
checks_intrusive_keeps() {
  local set=$1 idx=$2 allow=$3
  [[ $allow == true ]] && return 0
  ! checks_is_intrusive "$set" "$idx"
}

# checks_selection_reason SET IDX PROFILE INTENSITY ALLOW - prints the name
# of the FIRST filter (profile-scan, then intensity, then allow-intrusive -
# tension 15's own step order) that drops this check, in the exact shape
# used for run.json's `skipped_checks` (`FLAG=VALUE`).  Prints '' if the
# check survives every filter, i.e. is selected.
checks_selection_reason() {
  local set=$1 idx=$2 profile=$3 intensity=$4 allow=$5
  checks_profile_keeps "$set" "$idx" "$profile" \
    || { printf 'profile-scan=%s' "$profile"; return 0; }
  checks_intensity_keeps "$set" "$idx" "$intensity" \
    || { printf 'intensity=%s' "$intensity"; return 0; }
  checks_intrusive_keeps "$set" "$idx" "$allow" \
    || { printf 'allow-intrusive=false'; return 0; }
  printf ''
}

# ---------------------------------------------------------------------------
# 3. Selecting over one or more already-loaded record sets
# ---------------------------------------------------------------------------

# checks_select PROFILE INTENSITY ALLOW SET... - prints one selected check id
# per line, in (set order, then file order).  Never dies: an invalid
# PROFILE/INTENSITY selects zero checks (checks_profile_keeps/
# checks_intensity_keeps's own "unknown means keep nothing" - the CLI layer
# is what must refuse an unknown profile name outright, per this ticket's
# 2nd acceptance criterion; scan.sh's own flag validation already does that
# before this function is ever reached).
checks_select() {
  local profile=$1 intensity=$2 allow=$3
  shift 3
  local set n idx id reason
  for set in "$@"; do
    n=$(records_count "$set")
    for (( idx = 0; idx < n; idx++ )); do
      id=$(records_id "$set" "$idx")
      reason=$(checks_selection_reason "$set" "$idx" "$profile" "$intensity" "$allow")
      [[ -z $reason ]] && printf '%s\n' "$id"
    done
  done
  # Explicit, unconditional success: without this, the function's own return
  # status is whatever the LAST `[[ -z $reason ]] && printf ...` happened to
  # evaluate to - which is FALSE whenever the last record in the last set was
  # not selected, and would abort any `set -e` caller capturing this via
  # `VAR=$(checks_select ...)` (measured: tests/suites/checks.sh's
  # 'compliance' case hits exactly this, since the fixture's last record has
  # no compliance tag).
  return 0
}

# CHECKS_LAST_SELECTED_IDS - set by checks_record_run_selection on every
# call (overwritten, not accumulated) to the ids it selected, in the same
# global-rather-than-printed shape as CHECKS_REGISTRY_SETS and for the same
# reason.  This is how a caller learns the selected set WITHOUT re-walking
# the records a second time through checks_select: scan.sh's
# `_scan_apply_profile_filter` reads it to build `SCOURSH_SELECTED_CHECKS`,
# the LF-joined env var lib/findings.sh's `_derived_record_selected` already
# consumes (tension 6 condition (a) - a composite whose own record a run's
# filter chain dropped must classify `unknown`, not `fixed`).  That consumer
# was built at step 1, before this filter chain existed; wiring it is what
# makes it real instead of permanently falling back to its own "no filter
# chain: all selected" default.
CHECKS_LAST_SELECTED_IDS=()

# checks_record_run_selection PROFILE INTENSITY ALLOW SET... - the same walk
# as checks_select, but writes every outcome into the run's own record
# (lib/core.sh's run_record) instead of printing ids: a selected check goes
# into `checks_selected`, a dropped one into `skipped_checks` as `check=ID
# skipped_by=FLAG=VALUE` (the same "key=value key=value" shape scan.sh's own
# `coverage_reduction` facts already use), and CHECKS_LAST_SELECTED_IDS is
# reset to the selected ids.  Then logs ONE warning per distinct dropping
# flag, naming the flag and how many checks it dropped
# (docs/FOUNDATION.md tension 15: "prints a warning naming the flag that won
# and the count of checks dropped").
#
# Deliberately `checks_selected`, NOT `checks_run`: AGENTS.md's own "Build
# order and where we are" defines `checks_run` as "the set of checks the run
# LOADED AND EXECUTED" (`lib/records.sh`'s `records_register_checks`, called
# by `tests/e2e/fixture-scan.sh` right where it actually walks files against
# every loaded rule).  This function runs BEFORE `scan_dispatch`, and no
# module exists yet to execute anything a filter selects - claiming
# `checks_run` here would be false the moment a real module lands and a
# selected-but-`requires-cmd`-unmet script check never actually executes.
# `checks_selected` is the honest claim this step can make; a future
# module's run.sh owns calling `records_register_checks` (or appending to
# `checks_run` directly) once it has actually run a check, not merely
# selected it.
#
# Must be called directly, never through $(...) - run_record and log_warn
# have no output a caller needs to capture, but wrapping this function in a
# command substitution would still run it in a subshell and could hide a
# real failure inside it the same way scan.sh's own comment on
# _scan_require_readable_path explains for `die`.  Nothing here calls `die`,
# so today that is a latent hazard rather than a live bug; the discipline is
# kept anyway so a future edit that adds a `die` does not reintroduce tension
# 14's subshell trap silently.
checks_record_run_selection() {
  local profile=$1 intensity=$2 allow=$3
  shift 3
  local set n idx id reason
  local -A dropped_by=()
  CHECKS_LAST_SELECTED_IDS=()
  for set in "$@"; do
    n=$(records_count "$set")
    for (( idx = 0; idx < n; idx++ )); do
      id=$(records_id "$set" "$idx")
      reason=$(checks_selection_reason "$set" "$idx" "$profile" "$intensity" "$allow")
      if [[ -z $reason ]]; then
        run_record checks_selected "$id"
        CHECKS_LAST_SELECTED_IDS+=("$id")
      else
        run_record skipped_checks "check=$id skipped_by=$reason"
        dropped_by[$reason]=$(( ${dropped_by[$reason]:-0} + 1 ))
      fi
    done
  done
  # (( ${#dropped_by[@]} > 0 )) gates the loop rather than the
  # "${!dropped_by[@]+"${!dropped_by[@]}"}" guard idiom used elsewhere in
  # this file for VALUE expansions: combining `!` (keys) with a `+`
  # alternate-value guard does not parse the way that idiom implies (measured
  # - it raises "bad array subscript" on a NON-empty map, not just an empty
  # one, which is the opposite failure the guard exists to prevent).  A count
  # check ahead of the plain `${!dropped_by[@]}` form sidesteps the whole
  # question of whether the keys-form even needs guarding.
  if (( ${#dropped_by[@]} > 0 )); then
    local flag
    for flag in "${!dropped_by[@]}"; do
      log_warn "profile filter '$flag' dropped ${dropped_by[$flag]} check(s) that a less restrictive setting would have kept"
    done
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 4. The registry loader (docs/FOUNDATION.md tension 15's "Consequence for
#    the build": "§13 step 2 delivers the filter chain and the registry
#    loader").
# ---------------------------------------------------------------------------
# checks_module_dir MODULE - the on-disk directory a scan.sh subcommand's
# checks live under, relative to the install root.  Mirrors
# lib/records.sh's `records_owning_module` (path -> MODULE id) in the other
# direction (scan.sh command name -> directory); `cloud` deliberately does
# NOT special-case an `aws/` subdirectory the way scan.sh's own
# `_scan_module_script` does for run.sh, because a check registry is
# per-MODULE (rules/RULE-FORMAT.md §9.1.1's `CLOUD` id prefix covers
# `modules/cloud/**` as a whole, posture included) while run.sh is per
# cloud-provider entry point.
checks_module_dir() {
  case $1 in
    sast) printf 'modules/sast' ;;
    sca) printf 'modules/sca' ;;
    iac) printf 'modules/iac' ;;
    dast) printf 'modules/dast' ;;
    cloud) printf 'modules/cloud' ;;
    *) return 1 ;;
  esac
}

# CHECKS_REGISTRY_SETS - set by checks_registry_load, one lib/records.sh set
# name per file it loaded, in sorted-path order.  A global rather than a
# printed/captured list for the same reason lib/scan.sh's own
# _SCAN_RESOLVED_PATH is a global: this function can die() partway through
# (a malformed registry file is a genuine error, not "no data"), and a `die`
# inside a command-substitution subshell does not reliably abort the run
# (scan.sh's own comment on _scan_require_readable_path measures this).
CHECKS_REGISTRY_SETS=()

# checks_registry_load MODULE SET_PREFIX - loads every `*.rules` file that
# exists on disk right now under $SCOURSH_INSTALL_ROOT/modules/<module>/ (at
# any depth), each into its own lib/records.sh set named "${SET_PREFIX}_N",
# and leaves their names in CHECKS_REGISTRY_SETS.  Reads $SCOURSH_INSTALL_ROOT
# directly rather than taking a root argument - the same convention scan.sh's
# own `_scan_module_script` uses - because lib/records.sh's ownership checks
# (E018, E081) resolve a loaded file's path RELATIVE TO $SCOURSH_INSTALL_ROOT
# internally (`_records_relpath`) regardless of what a caller might otherwise
# think of as "the root"; a function-local root parameter that disagreed with
# it would make every fixture registry fail E081 for a reason that had
# nothing to do with the fixture itself, which is why a test that wants an
# alternate registry sets $SCOURSH_INSTALL_ROOT the same way
# tests/suites/scan.sh already does for `config/scope.conf`.
#
# This covers BOTH a module's own pattern-rule packs (e.g.
# `modules/sast/rules/secrets.rules`) and any `checks.rules` script-check
# registry nested anywhere under the module directory (rules/RULE-FORMAT.md
# §9's basename rule already resolves that schema regardless of depth) - one
# glob, because both share the `.rules` extension and lib/records.sh's own
# `records_schema_for_path` is what tells them apart.
#
# Finds NOTHING today: no module ships a rule pack or a checks.rules
# registry yet (docs/DESIGN.md §13 build order - modules/ is empty until
# step 3+), so CHECKS_REGISTRY_SETS is left empty and this is a silent,
# correct no-op, exactly like scan_dispatch's own "module has no run.sh yet"
# path.  It requires no changes once a real module lands: the glob picks up
# whatever exists.
#
# Must be called directly, never through $(...) (see CHECKS_REGISTRY_SETS's
# own comment on why `die` inside this function needs that).
checks_registry_load() {
  local module=$1 prefix=$2 root=${SCOURSH_INSTALL_ROOT:-} dir file set i=0
  CHECKS_REGISTRY_SETS=()
  dir=$(checks_module_dir "$module") || return 0
  [[ -n $root && -d $root ]] || return 0
  # Normalised through the same realpath_of every loaded file goes through
  # below (a trailing slash or a `.` segment must not produce a different
  # string than the file paths `find` returns, or nothing under it would
  # match).  This does NOT by itself guarantee lib/records.sh's own
  # `_records_relpath` - which strips $SCOURSH_INSTALL_ROOT as a literal
  # prefix from each file's OWN realpath - succeeds: that also requires
  # $SCOURSH_INSTALL_ROOT ITSELF to already be in canonical form.  Real usage
  # guarantees that (lib/core.sh sets it via `cd ... && pwd -P`); a test
  # fixture must do the same (measured: macOS's $TMPDIR resolves through a
  # `/var` -> `/private/var` symlink, so an uncanonicalised fixture root
  # silently fails E070 on every file, for a reason that has nothing to do
  # with the file's content - tests/suites/scan.sh's `ROOT_WITH_CHECKS`
  # fixture documents the same fact from the caller's side).
  root=$(realpath_of "$root")
  [[ -d $root/$dir ]] || return 0
  local -a files=()
  while IFS= read -r file; do
    [[ -n $file ]] || continue
    files+=("$file")
  done < <(find "$root/$dir" -type f -name '*.rules' 2>/dev/null | LC_ALL=C sort)
  for file in "${files[@]+"${files[@]}"}"; do
    set="${prefix}_$i"
    i=$(( i + 1 ))
    records_load "$file" '' "$set" \
      || die "$SCOURSH_EXIT_INPUT" "check registry '$file' failed to parse (rules/RULE-FORMAT.md diagnostics above)"
    # Same "load, then schema-validate, die loudly on either" discipline
    # lib/config.sh's own config_load_or_die uses for every other
    # operator/rule-authored file: a rule pack is exactly the kind of file a
    # team edits by hand, and a schema error in it (a bad tag, a malformed
    # owasp id, ...) must refuse the run rather than silently run a filter
    # chain over unvalidated data.
    records_validate "$set" \
      || die "$SCOURSH_EXIT_INPUT" "check registry '$file' failed schema validation (see diagnostics above)"
    CHECKS_REGISTRY_SETS+=("$set")
  done
  return 0
}
