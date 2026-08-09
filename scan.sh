#!/usr/bin/env bash
# scan.sh - the scoursh entry point / orchestrator.
#
# Owns:
#   docs/DESIGN.md    §5  (CLI grammar, exit codes) and §13 step 2 (this file)
#   docs/FOUNDATION.md tension 14 (exit-code precedence; required-inputs table)
#   docs/FOUNDATION.md tension 24 (bash >= 4.2; scan.sh performs the re-exec
#                       search, since "a library can only refuse to run" -
#                       lib/core.sh)
#
# What THIS file delivers, per the ticket that built it (docs/DESIGN.md §13
# step 2, scoped to the entry-point skeleton): a portable CLI parser for the
# §5 grammar, the tension-14 exit-code precedence function (unit-testable on
# its own), and wiring the config loader (lib/config.sh) in ahead of
# dispatch.  What it deliberately does NOT deliver, because the things they
# depend on do not exist yet: tension 12's diff/baseline logic (no `state/`
# writer yet) and real module execution (nothing under `modules/` exists yet
# - see AGENTS.md "Build order").  Each subcommand's dispatch is therefore a
# clearly-logged, `coverage_reduction` no-op until its module lands, per
# docs/FOUNDATION.md tension 14's "declared reduction" row: an invocation
# naming a module that is not yet built did what it was asked as far as
# scan.sh's own contract goes, so it is not an error and does not affect the
# exit code.
#
# Tension 15's check-set filter chain and check registry loader - the piece
# THIS comment used to list as undelivered - now ship in lib/checks.sh
# (a later ticket, "Wire scan profiles: quick, full, compliance").
# `_scan_apply_profile_filter` below calls it in front of every
# `scan_dispatch`: it discovers whatever `*.rules` files already exist under
# a module's directory (none do yet, so this remains an honest no-op today -
# see lib/checks.sh's own comment on `checks_registry_load`) and records
# `checks_selected` / `skipped_checks` into run.json exactly as it will once
# a module ships a real registry, so wiring a module in later never has to
# touch this filtering step.
#
# shellcheck shell=bash
#
# SC2329: several `cmd_*`/`_scan_*` functions are only ever called through
# the command dispatch table (`scan_dispatch`) or by scan_main, not by a
# literal call shellcheck's static graph can follow.
# shellcheck disable=SC2329

# Sourced twice (a test re-sourcing it) is a no-op the second time, same
# guard idiom as every lib/*.sh file.  This branch is only reachable via
# `source`: nothing in this repo exports SCOURSH_SCAN_SH_SOURCED before a
# direct execution, so a bare `return` here never hits the "not sourced"
# case in practice.
if [[ -n ${SCOURSH_SCAN_SH_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SCAN_SH_SOURCED=1

# A test suite sources this file to reach individual functions (scan_parse_args,
# scan_exit_code, ...) without running scan_main or the bash re-exec search.
# `${BASH_SOURCE[0]} == $0` is false when sourced, true when executed
# directly (`./scan.sh ...` or `bash scan.sh ...`).
if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  SCOURSH_SCAN_SH_MAIN=1
else
  SCOURSH_SCAN_SH_MAIN=0
fi

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# 0. bash >= 4.2, with the re-exec search (docs/FOUNDATION.md tension 24)
# -----------------------------------------------------------------------------
# lib/core.sh performs the SAME version check and simply refuses (exit 4) if
# it fails, because "a library can only refuse to run".  scan.sh is the
# entry point, so it gets one extra chance: search a short, documented list
# of places a newer bash is likely to be (an operator-set override, the two
# common Homebrew prefixes, then whatever PATH resolves) and re-exec itself
# under the first one that qualifies.  Only attempted when this file is
# actually the running script - a sourced-for-testing bash is never re-exec'd
# out from under the caller.
_scan_bash_qualifies() {
  # Runs the candidate with -c so a non-bash or unreadable binary just fails
  # this test rather than aborting the search.
  [[ -n $1 && -x $1 ]] || return 1
  # SC2016: the single quotes are deliberate - this must expand inside the
  # CANDIDATE bash being tested, never in the (possibly bash-3.2) shell
  # currently running this search.
  # shellcheck disable=SC2016
  "$1" -c '[[ ${BASH_VERSINFO[0]} -gt 4 || ( ${BASH_VERSINFO[0]} -eq 4 && ${BASH_VERSINFO[1]} -ge 2 ) ]]' \
    2>/dev/null
}

if (( SCOURSH_SCAN_SH_MAIN )) \
  && { [[ -z ${BASH_VERSINFO[0]:-} ]] \
    || (( BASH_VERSINFO[0] < 4 )) \
    || { (( BASH_VERSINFO[0] == 4 )) && (( BASH_VERSINFO[1] < 2 )); }; }; then
  _scan_found=''
  for _scan_candidate in "${SCOURSH_BASH:-}" /opt/homebrew/bin/bash /usr/local/bin/bash \
    "$(command -v bash 2>/dev/null || true)"; do
    [[ -n $_scan_candidate ]] || continue
    if _scan_bash_qualifies "$_scan_candidate"; then
      _scan_found=$_scan_candidate
      break
    fi
  done
  if [[ -n $_scan_found ]]; then
    exec "$_scan_found" "$0" "$@"
  fi
  printf '%s\n' "scoursh: bash >= 4.2 required, found ${BASH_VERSION:-unknown}." >&2
  printf '%s\n' "scoursh: install a newer bash (brew install bash) or set SCOURSH_BASH." >&2
  exit 4
fi
unset -f _scan_bash_qualifies
unset -v _scan_found _scan_candidate 2>/dev/null || true

# -----------------------------------------------------------------------------
# 1. Libraries.  lib/report.sh -> lib/findings.sh -> lib/records.sh ->
#    lib/core.sh; lib/config.sh -> lib/records.sh (already-sourced no-op).
#    Sourcing report.sh gets us FP_SCHEMA/UK_SCHEMA and report_run_json for
#    free, with zero findings emitted yet, so run.json is a real, honest
#    artifact from the very first invocation (docs/DESIGN.md §4: "every run
#    writes run.json").
# -----------------------------------------------------------------------------
SCOURSH_SCAN_SH_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/report.sh
source "$SCOURSH_SCAN_SH_DIR/lib/report.sh"
# shellcheck source=lib/config.sh
source "$SCOURSH_SCAN_SH_DIR/lib/config.sh"
# shellcheck source=lib/checks.sh
source "$SCOURSH_SCAN_SH_DIR/lib/checks.sh"
# shellcheck source=lib/paranoid.sh
source "$SCOURSH_SCAN_SH_DIR/lib/paranoid.sh"
# shellcheck source=lib/engines.sh
source "$SCOURSH_SCAN_SH_DIR/lib/engines.sh"

# -----------------------------------------------------------------------------
# 2. The §5 grammar, encoded as data rather than a chain of if/elif.
# -----------------------------------------------------------------------------
SCAN_COMMANDS=(sast sca iac dast cloud all diff report)

# One map, keyed "scope:flag" (global, or a command name), because bash 4.2
# has no namerefs (those are 4.3+, and tension 24 froze the minimum at 4.2)
# to index an array-of-arrays by a variable holding its name.
declare -A _SCAN_FLAG_KIND=(
  [global:profile-scan]=value
  [global:paranoid]=bool
  [global:use-engines]=bool
  [global:allow-intrusive]=bool
  [global:jobs]=value
  [global:format]=value
  [global:fail-on]=value
  [global:fail-on-new]=bool
  [global:min-confidence]=value
  [global:baseline]=value
  [global:out]=value

  [sast:path]=value
  [sast:lang]=value
  [sast:history]=bool

  [sca:path]=value

  [iac:path]=value

  [dast:target]=value
  [dast:intensity]=value
  [dast:authed]=bool

  [cloud:live]=bool
  [cloud:profile]=value
  [cloud:regions]=value
  [cloud:assume-role]=value

  [diff:against]=value

  # Not in docs/DESIGN.md §5's grammar block, which lists `report` with no
  # flags at all ("regenerate reports from a prior run's findings.json").  A
  # source run directory has to come from somewhere, and --against (diff's
  # flag) means "compare against", which is the wrong verb for "regenerate
  # from".  --from is this file's judgment call for that gap; flagged in the
  # ticket hand-off for a human to override if a different shape was
  # intended.
  [report:from]=value

  # `all` accepts the union of every module's own flags, since it "runs
  # every module for which inputs are configured" (docs/DESIGN.md §5) -
  # which flag input is configured depends on the same per-module flags the
  # standalone subcommands take.
  [all:path]=value
  [all:lang]=value
  [all:history]=bool
  [all:target]=value
  [all:intensity]=value
  [all:authed]=bool
  [all:live]=bool
  [all:profile]=value
  [all:regions]=value
  [all:assume-role]=value
)

# `scan_flag_kind CMD FLAG` - "bool", "value", or "" (unknown for this
# command).  Command-specific first, falling back to global; a command
# cannot be shadowed by a global flag of the same name because none collide.
scan_flag_kind() {
  local cmd=$1 flag=$2
  if [[ -n ${_SCAN_FLAG_KIND[$cmd:$flag]:-} ]]; then
    printf '%s' "${_SCAN_FLAG_KIND[$cmd:$flag]}"
  elif [[ -n ${_SCAN_FLAG_KIND[global:$flag]:-} ]]; then
    printf '%s' "${_SCAN_FLAG_KIND[global:$flag]}"
  else
    return 1
  fi
}

scan_usage() {
  cat <<'EOF'
scan.sh <command> [options]

Commands:
  sast     [--path DIR] [--lang py,js,go,java] [--history]
  sca      [--path DIR]
  iac      [--path DIR]
  dast     --target <name-from-scope> [--intensity passive|safe|active] [--authed]
                                        (--intensity default: passive)
  cloud    [--live] [--profile <p>] [--regions all|us-east-1,...] [--assume-role ARN]
  all      run every module for which inputs are configured
  diff     --against <prior-run-dir>
  report   --from <prior-run-dir>

Global:
  --profile-scan quick|full|compliance   (default: full - see lib/checks.sh)
  --paranoid                (connection DETECTOR, not a guarantee - aborts
                              (exit 3) on the first connection outside the
                              run's allowlist; exits 4 if neither `ss` nor a
                              usable `strace` is available. A sufficiently
                              short-lived connection can still evade
                              detection - tools/run-in-netns.sh is the actual
                              guarantee. See docs/FOUNDATION.md tension 20.)
  --use-engines             (opt in to optional vendored engine adapters,
                              e.g. semgrep for sast - docs/ADAPTERS.md. Only
                              runs an adapter whose own vendored binary +
                              ruleset is actually present on disk
                              (bin/, rules/ under
                              modules/<module>/adapters/<engine>/); absent
                              or not vendored is a silent, native-only
                              continue with a logged coverage_reduction,
                              never an error. Nothing is fetched at scan
                              time - see tools/vendor-engines.sh.)
  --allow-intrusive
  --jobs N
  --format json,sarif,html,md
  --fail-on SEVERITY        (critical|high|medium|low|info|none)
  --fail-on-new             (requires --fail-on; usage error otherwise)
  --min-confidence LEVEL    (high|medium|low; default low)
  --baseline FILE
  --out DIR                 (default: reports/<timestamp>)

Exit codes: 0 clean/below gate * 1 findings at/above --fail-on *
2 usage error * 3 scope violation * 4 missing required input *
5 incomplete run (circuit breaker / aborted mid-flight).
EOF
}

scan_die_usage() {
  scan_usage >&2
  die "$SCOURSH_EXIT_USAGE" "$*"
}

# -----------------------------------------------------------------------------
# 3. Value-shape validation, one flag at a time - mirrors lib/config.sh's own
#    _scanner_validate_value in spirit: shape is checked once, at the level
#    the value actually came from (here: always CLI, so always exit 2 on
#    failure - tension 14's "the invocation was invalid; nothing ran").
# -----------------------------------------------------------------------------
_scan_validate_csv() {
  local val=$1 re=$2 item
  local -a items=()
  IFS=',' read -r -a items <<<"$val"
  (( ${#items[@]} > 0 )) || return 1
  for item in "${items[@]+"${items[@]}"}"; do
    [[ -n $item && $item =~ $re ]] || return 1
  done
  return 0
}

scan_validate_flag_value() {
  local flag=$1 val=$2
  case $flag in
    # Delegate to lib/checks.sh's own CHECKS_PROFILES/CHECKS_INTENSITIES
    # membership checks rather than re-stating the three/three names as a
    # third hardcoded regex here: lib/checks.sh is sourced (step 1, above)
    # before this function is ever called, so checks_valid_profile/
    # checks_valid_intensity are always available by the time a flag is
    # actually parsed.  This is the single source of truth for "which names
    # are legal" that lib/checks.sh's own checks_profile_keeps/
    # checks_intensity_keeps gate on too (see their comments) - add a profile
    # or intensity tier by editing CHECKS_PROFILES/CHECKS_INTENSITIES once,
    # here included, rather than three places in lockstep.
    profile-scan) checks_valid_profile "$val" ;;
    intensity) checks_valid_intensity "$val" ;;
    fail-on) [[ $val =~ ^(critical|high|medium|low|info|none)$ ]] ;;
    min-confidence) [[ $val =~ ^(high|medium|low)$ ]] ;;
    jobs) [[ $val =~ ^[1-9][0-9]*$ ]] ;;
    format) _scan_validate_csv "$val" '^(json|sarif|html|md)$' ;;
    lang) _scan_validate_csv "$val" '^(py|js|go|java)$' ;;
    regions) [[ $val == all ]] || _scan_validate_csv "$val" '^[a-zA-Z0-9-]+$' ;;
    assume-role) [[ $val == arn:*:role/* ]] ;;
    *) [[ -n $val ]] ;;   # every other value-flag: non-empty is the whole contract
  esac
}

# -----------------------------------------------------------------------------
# 4. The parser.  Hand-rolled rather than `getopts`/`getopt`: `getopts` (the
#    bash builtin) has no long-option support at all, and GNU getopt's
#    long-option parsing is not what BSD/macOS getopt implements, so either
#    choice would parse `--format json,sarif` differently - or not at all -
#    depending on the host.  A `case`/`shift` loop over "${1}" uses nothing
#    but bash builtins and string operators, which behave identically on
#    every host bash >= 4.2 runs on (the version gate above is what makes
#    that guarantee true rather than aspirational).
# -----------------------------------------------------------------------------
declare -A SCAN_FLAGS=()
SCAN_COMMAND=''

scan_parse_args() {
  SCAN_FLAGS=()
  SCAN_COMMAND=''

  if (( $# == 0 )); then
    scan_die_usage 'no command given'
  fi
  case $1 in
    -h | --help)
      scan_usage
      exit "$SCOURSH_EXIT_OK"
      ;;
  esac

  SCAN_COMMAND=$1
  shift
  local known=0 c
  for c in "${SCAN_COMMANDS[@]+"${SCAN_COMMANDS[@]}"}"; do
    if [[ $c == "$SCAN_COMMAND" ]]; then
      known=1
      break
    fi
  done
  (( known )) || scan_die_usage "unknown command: '$SCAN_COMMAND' (one of: ${SCAN_COMMANDS[*]})"

  local arg flag val kind
  while (( $# > 0 )); do
    arg=$1
    case $arg in
      -h | --help)
        scan_usage
        exit "$SCOURSH_EXIT_OK"
        ;;
      --)
        shift
        (( $# == 0 )) || scan_die_usage "unexpected argument after '--': '$1'"
        ;;
      --*=*)
        flag=${arg%%=*}
        flag=${flag#--}
        val=${arg#*=}
        kind=$(scan_flag_kind "$SCAN_COMMAND" "$flag") \
          || scan_die_usage "flag '--$flag' is not valid for command '$SCAN_COMMAND'"
        [[ $kind == value ]] \
          || scan_die_usage "flag '--$flag' takes no value (got '--$flag=$val')"
        [[ -n $val ]] || scan_die_usage "flag '--$flag' requires a non-empty value"
        scan_validate_flag_value "$flag" "$val" \
          || scan_die_usage "invalid value for '--$flag': '$val'"
        SCAN_FLAGS[$flag]=$val
        shift
        ;;
      --*)
        flag=${arg#--}
        kind=$(scan_flag_kind "$SCAN_COMMAND" "$flag") \
          || scan_die_usage "flag '--$flag' is not valid for command '$SCAN_COMMAND'"
        if [[ $kind == bool ]]; then
          SCAN_FLAGS[$flag]=true
          shift
        else
          (( $# >= 2 )) || scan_die_usage "flag '--$flag' requires a value"
          val=$2
          [[ $val != --* ]] || scan_die_usage "flag '--$flag' requires a value, got another flag ('$val')"
          scan_validate_flag_value "$flag" "$val" \
            || scan_die_usage "invalid value for '--$flag': '$val'"
          SCAN_FLAGS[$flag]=$val
          shift 2
        fi
        ;;
      *)
        scan_die_usage "unexpected argument: '$arg' (every value is supplied via --flag)"
        ;;
    esac
  done

  # Cross-flag and required-flag checks that need the whole flag set, not
  # just one flag in isolation.
  if [[ ${SCAN_FLAGS[fail-on-new]:-} == true && -z ${SCAN_FLAGS[fail-on]:-} ]]; then
    scan_die_usage '--fail-on-new requires --fail-on (docs/FOUNDATION.md tension 14)'
  fi
  case $SCAN_COMMAND in
    dast)
      [[ -n ${SCAN_FLAGS[target]:-} ]] || scan_die_usage "'dast' requires --target"
      ;;
    diff)
      [[ -n ${SCAN_FLAGS[against]:-} ]] || scan_die_usage "'diff' requires --against"
      ;;
    report)
      [[ -n ${SCAN_FLAGS[from]:-} ]] || scan_die_usage "'report' requires --from"
      ;;
  esac
}

# -----------------------------------------------------------------------------
# 5. Exit-code precedence (docs/FOUNDATION.md tension 14), as a pure function
#    so it is testable on its own without a real module to drive it.
#
#    scan_exit_code USAGE SCOPE INPUT INCOMPLETE GATE - each 0/1 (empty=0).
#    The FIRST true condition wins, in this fixed order - never "worst
#    finding wins" and never "highest code wins":
#      2 usage > 3 scope > 4 input > 5 incomplete > 1 gate > 0 clean
#    Tension 14's own worked example: a run that BOTH tripped the circuit
#    breaker AND found gated findings exits 5, not 1, because "1 asserts a
#    complete assessment that failed its gate, and this run cannot make that
#    assertion" - scan_exit_code 0 0 0 1 1 must be 5, not 1.
# -----------------------------------------------------------------------------
scan_exit_code() {
  local usage=${1:-0} scope=${2:-0} input=${3:-0} incomplete=${4:-0} gate=${5:-0}
  if (( usage )); then
    printf '%s' "$SCOURSH_EXIT_USAGE"
  elif (( scope )); then
    printf '%s' "$SCOURSH_EXIT_SCOPE"
  elif (( input )); then
    printf '%s' "$SCOURSH_EXIT_INPUT"
  elif (( incomplete )); then
    printf '%s' "$SCOURSH_EXIT_INCOMPLETE"
  elif (( gate )); then
    printf '%s' "$SCOURSH_EXIT_GATE"
  else
    printf '%s' "$SCOURSH_EXIT_OK"
  fi
}

# -----------------------------------------------------------------------------
# 6. Required-input gates (docs/FOUNDATION.md tension 14's table), run AFTER
#    config_scanner_load so the config loader has already run, and BEFORE
#    scan_dispatch so nothing is dispatched on unresolved/unauthorized input.
# -----------------------------------------------------------------------------
# Sets _SCAN_RESOLVED_PATH rather than printing it, and MUST be called
# directly, never through $(...).  die()'s `exit` only reliably aborts when
# there is no $(...) subshell boundary between the call and the top-level
# invocation: wrapping a die-capable function in a command substitution turns
# its abort into just another command's exit status, and `set -e`'s "checked
# context" rule (the command is the operand of ||, an if/while condition, or
# inside a subshell whose own exit status is itself being tested - which is
# exactly what happens when scan_main is invoked through this suite's own
# assert_status) can silently SWALLOW that exit rather than propagate it -
# reproduced and measured in tests/suites/scan.sh, not assumed.  Realpath_of
# itself never dies, so capturing THAT via $(...) remains safe.
_scan_require_readable_path() {
  local path=${1:-.}
  _SCAN_RESOLVED_PATH=$(realpath_of "$path")
  [[ -e $_SCAN_RESOLVED_PATH ]] || die "$SCOURSH_EXIT_INPUT" "--path '$path' does not exist"
  [[ -r $_SCAN_RESOLVED_PATH ]] || die "$SCOURSH_EXIT_INPUT" "--path '$path' is not readable"
}

# `_scan_capture VARNAME CMD [ARGS...]` - runs CMD (which may call die(), e.g.
# every lib/config.sh `config_scanner_*` accessor) with its stdout captured
# into VARNAME, WITHOUT ever wrapping the call itself in $(...) - see the
# comment on _scan_require_readable_path above for why that distinction is
# load-bearing rather than stylistic.  A plain output redirection (`>`) does
# not fork a subshell in bash, so CMD runs in the CURRENT shell and a die()
# inside it aborts reliably; only the harmless second step (reading the
# captured file back) uses a bare `read`, never $(...).
_scan_capture() {
  local __var=$1
  shift
  local __tmp=$SCOURSH_SCRATCH/_scan_capture.$$
  "$@" >"$__tmp"
  # config_scanner_value/list print with `printf '%s'` - deliberately no
  # trailing newline (lib/config.sh).  `read` still captures a final line
  # with no trailing newline correctly, but returns status 1 for it (EOF
  # before a newline), which `set -e` would treat as this HELPER failing.
  # Appending one restores the normal read contract without masking a real
  # failure: CMD already ran (and would have died above if it failed).
  printf '\n' >>"$__tmp"
  # SC2229: "$__var" is deliberately the INDIRECT target - read into the
  # variable NAMED by __var's value, the standard idiom for this (bash 4.2
  # has no `local -n` nameref, per tension 24's frozen minimum).
  # shellcheck disable=SC2229
  IFS= read -r "$__var" <"$__tmp"
  rm -f "$__tmp"
}

_scan_require_prior_run() {
  local flag=$1 dir=$2 resolved
  resolved=$(realpath_of "$dir")
  [[ -d $resolved ]] || die "$SCOURSH_EXIT_INPUT" "--$flag '$dir' is not a directory"
  [[ -r $resolved/findings.jsonl || -r $resolved/run.json ]] \
    || die "$SCOURSH_EXIT_INPUT" "--$flag '$dir' does not look like a prior run directory (no findings.jsonl or run.json)"
}

# -----------------------------------------------------------------------------
# 7. Dispatch.  Real modules do not exist yet (nothing under modules/ has
#    landed - AGENTS.md "Build order"), so this is deliberately a thin,
#    logged no-op rather than a guess at module internals that a later
#    ticket will actually own.  A `coverage_reduction` fact is recorded so
#    run.json states the reason honestly (docs/FOUNDATION.md tension 14's
#    "declared reduction" - this run did what it was asked, and said so).
# -----------------------------------------------------------------------------
_scan_module_script() {
  case $1 in
    cloud) printf '%s' "$SCOURSH_INSTALL_ROOT/modules/cloud/aws/run.sh" ;;
    *) printf '%s' "$SCOURSH_INSTALL_ROOT/modules/$1/run.sh" ;;
  esac
}

scan_dispatch() {
  local module=$1 script
  script=$(_scan_module_script "$module")
  if [[ -f $script ]]; then
    # shellcheck disable=SC1090
    source "$script"
    return 0
  fi
  log_warn "module '$module' has no run.sh yet (docs/DESIGN.md §13 build order); nothing to run"
  run_record coverage_reduction "module=$module reason=not_yet_built"
  return 0
}

# `_scan_apply_profile_filter MODULE` - the lib/checks.sh wiring, called once
# per module right before `scan_dispatch`: discover whatever check registry
# already exists on disk for MODULE, apply the tension-15 filter chain
# (--profile-scan / --intensity / --allow-intrusive, each with the defaults
# lib/checks.sh documents), and record the outcome into run.json via
# checks_record_run_selection (checks_selected / skipped_checks) - or, when
# the module has no registry on disk yet (true for every module today), a
# coverage_reduction fact, the same declared-no-op shape scan_dispatch itself
# uses for "no run.sh yet".  Placed ahead of dispatch rather than inside it so
# the SAME filtering step already exists once a module's run.sh lands and
# needs the selected id list - it will read CHECKS_REGISTRY_SETS /
# meta/checks_selected rather than reinventing this.  `checks_selected` is
# deliberately NOT `checks_run`: nothing has executed anything yet at this
# point (scan_dispatch runs AFTER this), so claiming `checks_run` here would
# overclaim - see lib/checks.sh's own comment on
# checks_record_run_selection.
#
# Also grows SCOURSH_SELECTED_CHECKS (declared with SCAN_FLAGS below): the
# LF-joined id list lib/findings.sh's `_derived_record_selected` already
# reads (tension 6 condition (a)), across every module this run dispatches -
# `scan.sh all` must union sast+sca+iac+dast+cloud's selections, not just the
# last module filtered, or a composite whose contributors span modules would
# be judged against only one of them.
_scan_apply_profile_filter() {
  local module=$1
  local profile=${SCAN_FLAGS[profile-scan]:-$CHECKS_PROFILE_DEFAULT}
  local intensity=${SCAN_FLAGS[intensity]:-$CHECKS_INTENSITY_DEFAULT}
  local allow=${SCAN_FLAGS[allow-intrusive]:-false}
  checks_registry_load "$module" "reg_$module"
  if (( ${#CHECKS_REGISTRY_SETS[@]} > 0 )); then
    checks_record_run_selection "$profile" "$intensity" "$allow" "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"
    local id
    for id in "${CHECKS_LAST_SELECTED_IDS[@]+"${CHECKS_LAST_SELECTED_IDS[@]}"}"; do
      SCOURSH_SELECTED_CHECKS="${SCOURSH_SELECTED_CHECKS:+$SCOURSH_SELECTED_CHECKS$'\n'}$id"
    done
  else
    run_record coverage_reduction "module=$module reason=no_check_registry_on_disk_yet"
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 8. main
# -----------------------------------------------------------------------------
scan_main() {
  scan_parse_args "$@"

  core_require_baseline
  [[ ${SCAN_FLAGS[history]:-} != true ]] || require_cmd git

  local out_dir=${SCAN_FLAGS[out]:-"$SCOURSH_INSTALL_ROOT/reports/$(now_iso | tr ':' '-')"}
  run_init "$out_dir"
  run_record notes "command=$SCAN_COMMAND"
  # Reset for THIS invocation - scan_main may run more than once in one
  # process (every test in tests/suites/scan.sh sources scan.sh once and
  # calls scan_main repeatedly), and _scan_apply_profile_filter only ever
  # APPENDS to this variable.
  SCOURSH_SELECTED_CHECKS=''

  # 8a. The config loader runs before any dispatch (this ticket's third
  # acceptance criterion, verbatim): scanner.conf is resolved through the
  # CLI > env > file > default chain lib/config.sh already implements, with
  # this invocation's flags as the CLI layer.  Called with no argument on
  # purpose, to pick up config_scanner_load's own default path
  # ($SCOURSH_INSTALL_ROOT/config/scanner.conf, lib/config.sh) - $1 there is
  # an explicit optional override, not scan_main's own args forwarded, so
  # this is not the "$@" case SC2119 warns about.  Older shellcheck reports
  # it here and 0.11.0 does not (AGENTS.md "Things measured on this
  # codebase"), so it is silenced explicitly rather than left to whichever
  # version a CI image happens to ship.
  # shellcheck disable=SC2119
  config_scanner_load
  _scan_capture SCOURSH_JOBS config_scanner_value jobs "${SCAN_FLAGS[jobs]:-}"
  _scan_capture SCOURSH_FAIL_ON config_scanner_value fail-on "${SCAN_FLAGS[fail-on]:-}"
  _scan_capture SCOURSH_MIN_CONFIDENCE config_scanner_value min-confidence "${SCAN_FLAGS[min-confidence]:-}"
  _scan_capture SCOURSH_REDACT_SECRETS config_scanner_value redact-secrets ''
  export SCOURSH_JOBS SCOURSH_FAIL_ON SCOURSH_MIN_CONFIDENCE SCOURSH_REDACT_SECRETS
  config_scanner_list formats "${SCAN_FLAGS[format]:-}" >/dev/null

  # 8b. --paranoid (docs/FOUNDATION.md tension 20; lib/paranoid.sh): attached
  # AFTER config is loaded (paranoid_allow, the fourth allowlist set, comes
  # from scanner.conf) and BEFORE any module dispatch, so the observer is
  # watching for the very first connection any module could make.  Dies
  # exit 4 on its own (SCOURSH_EXIT_INPUT) when neither `ss` nor a usable
  # `strace` is available - see lib/paranoid.sh's paranoid_attach.
  if [[ ${SCAN_FLAGS[paranoid]:-} == true ]]; then
    paranoid_attach
  fi

  # 8c. --use-engines (docs/ADAPTERS.md; lib/engines.sh) - recorded once per
  # run.json for audit, exactly like every other flag this section already
  # captures, regardless of which command actually reads it.  scan.sh does
  # NOT itself call has_engine or run any adapter: the gate
  # "${SCAN_FLAGS[use-engines]:-} == true) && has_engine MODULE ENGINE" is
  # evaluated at each module's own call site (modules/sast/run.sh), never
  # here - docs/ADAPTERS.md §5's pseudocode keeps "was --use-engines given"
  # and "is it vendored" independent, and lib/engines.sh's own header
  # explains why folding them into one function/one call site would be
  # wrong.  Adapter check ids are also never selected by
  # `_scan_apply_profile_filter` below (rules/RULE-FORMAT.md §9.1.1a /
  # docs/ADAPTERS.md §6: an adapter check id carries no MODULE-FAMILY-NAME
  # shape, so lib/checks.sh's registry-based filter chain has nothing of
  # theirs to select or drop) - lib/checks.sh's own header states this
  # boundary explicitly so a future reader does not wonder why
  # --use-engines never narrows or widens what that filter chain selects.
  run_record use_engines "${SCAN_FLAGS[use-engines]:-false}"

  local incomplete=0 gate=0 path

  case $SCAN_COMMAND in
    sast | sca | iac)
      path=${SCAN_FLAGS[path]:-.}
      _scan_require_readable_path "$path"
      SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$_SCAN_RESOLVED_PATH")
      SCOURSH_PATH_ROOT=$(path_root_cell "$_SCAN_RESOLVED_PATH")
      export SCOURSH_SCAN_ROOT_ID SCOURSH_PATH_ROOT
      _scan_apply_profile_filter "$SCAN_COMMAND"
      scan_dispatch "$SCAN_COMMAND"
      ;;
    dast)
      # config_scope_require is the non-bypassable §7 gate: no matching
      # --target dies 3, a wholly missing scope.conf dies 4.  Called
      # directly, never through $(...) - lib/config.sh's own comment on this
      # function explains why (a subshell would throw the loaded record set
      # away the instant it exits).
      config_scope_require "${SCAN_FLAGS[target]}"
      run_record targets "${SCAN_FLAGS[target]}"
      _scan_apply_profile_filter dast
      scan_dispatch dast
      ;;
    cloud)
      if [[ ${SCAN_FLAGS[live]:-} == true ]]; then
        command -v aws >/dev/null 2>&1 \
          || die "$SCOURSH_EXIT_INPUT" "cloud --live requires the aws CLI to be installed"
      fi
      _scan_apply_profile_filter cloud
      scan_dispatch cloud
      ;;
    all)
      path=${SCAN_FLAGS[path]:-.}
      _scan_require_readable_path "$path"
      SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$_SCAN_RESOLVED_PATH")
      SCOURSH_PATH_ROOT=$(path_root_cell "$_SCAN_RESOLVED_PATH")
      export SCOURSH_SCAN_ROOT_ID SCOURSH_PATH_ROOT
      _scan_apply_profile_filter sast
      scan_dispatch sast
      _scan_apply_profile_filter sca
      scan_dispatch sca
      _scan_apply_profile_filter iac
      scan_dispatch iac
      if [[ -n ${SCAN_FLAGS[target]:-} ]]; then
        config_scope_require "${SCAN_FLAGS[target]}"
        run_record targets "${SCAN_FLAGS[target]}"
        _scan_apply_profile_filter dast
        scan_dispatch dast
      else
        run_record coverage_reduction 'module=dast reason=no --target given (declared, all)'
      fi
      if [[ ${SCAN_FLAGS[live]:-} == true ]]; then
        command -v aws >/dev/null 2>&1 \
          || die "$SCOURSH_EXIT_INPUT" "cloud --live requires the aws CLI to be installed"
        _scan_apply_profile_filter cloud
        scan_dispatch cloud
      else
        run_record coverage_reduction 'module=cloud reason=no --live given (declared, all)'
      fi
      ;;
    diff)
      _scan_require_prior_run against "${SCAN_FLAGS[against]}"
      run_record coverage_reduction 'module=diff reason=not_yet_built'
      log_warn "'diff' has no engine yet (docs/FOUNDATION.md tension 12 lands with state/, step 7)"
      ;;
    report)
      _scan_require_prior_run from "${SCAN_FLAGS[from]}"
      run_record coverage_reduction 'module=report reason=not_yet_built'
      log_warn "'report' regeneration has no engine yet"
      ;;
  esac

  # SCOURSH_SELECTED_CHECKS: LF-joined ids every _scan_apply_profile_filter
  # call above added; export unconditionally (possibly empty) so a findings
  # pipeline downstream never has to distinguish "the filter chain ran and
  # selected nothing" from "the filter chain never ran" - lib/findings.sh's
  # `_derived_record_selected` already treats unset/empty as "no filter
  # chain: all selected" (tension 6 condition (a)'s permissive default),
  # which stays correct either way; this just makes it accurate rather than
  # perpetually falling back to that default now that the filter chain
  # actually exists.
  export SCOURSH_SELECTED_CHECKS
  SCOURSH_GATE_RESULT=${SCOURSH_GATE_RESULT:-not-evaluated}
  export SCOURSH_GATE_RESULT

  # A violation aborts via paranoid_on_violation's own die() (exit 3) and
  # never reaches here; reaching this point means the run's observer, if
  # any, found nothing out of scope for its entire duration.
  if [[ -n $PARANOID_SAMPLER_PID ]]; then
    paranoid_detach
  fi

  report_run_json "$SCOURSH_RUN_DIR"

  local code
  code=$(scan_exit_code 0 0 0 "$incomplete" "$gate")
  # An intentional exit is not an error to be re-reported by the ERR trap -
  # same reasoning and the same guard as lib/core.sh's own `die`.  Without
  # it, a non-zero CODE (gate or incomplete) makes the EXIT trap
  # (core_cleanup, lib/core.sh) end in `return "$status"`, which under
  # `set -E` errtrace re-fires the ERR trap on the trap handler's own
  # non-zero return and prints a spurious "command failed" line naming this
  # exit statement - measured against a real `--fail-on` gate trip, not
  # assumed, once modules/sast/run.sh (docs/DESIGN.md §13 step 3) became the
  # first code path that ever produced a non-zero, non-`die` exit here.
  trap - ERR
  exit "$code"
}

if (( SCOURSH_SCAN_SH_MAIN )); then
  scan_main "$@"
fi
