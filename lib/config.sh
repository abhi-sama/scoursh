#!/usr/bin/env bash
# lib/config.sh - the operator config loader.
#
# Owns:
#   docs/DESIGN.md    §11 (config files) and §13 step 2 (config loading, the
#                      piece of it that does not require scan.sh's CLI parser
#                      or scan-profile filter chain to exist yet)
#   docs/FOUNDATION.md tension 14 (exit-code precedence; the required-inputs
#                      table; "a missing scope.conf is exit 4 only for dast")
#   docs/FOUNDATION.md tension 19 (scope-gate semantics)
#   docs/FOUNDATION.md tension 26 (frozen record format; config files are data)
#   rules/RULE-FORMAT.md §9.4 (scope target) and §9.6.1 (scanner config)
#
# Every value handled here traces to an operator's own config file, CLI flag,
# or environment variable at runtime: no target, environment, or endpoint
# name is ever baked in (docs/DESIGN.md §1, AGENTS.md "What scoursh is").
#
# PRECEDENCE, for every `config/scanner.conf` setting: CLI > env > file >
# documented default (rules/RULE-FORMAT.md §9.6.1's "Default" column).  A
# level that is ABSENT falls through to the next; a level that is PRESENT but
# fails validation dies loudly right there and never falls through - an
# invalid CLI flag can never be silently rescued by a valid file value, and
# an invalid file value can never be silently rescued by the default.  That
# is what "no silent default" means in this file: a default is only ever
# used when every higher level was genuinely unset, never as a fallback for
# a level that was set wrong.
#
# The environment layer uses its OWN namespace, `SCOURSH_CONFIG_<KEY>`
# (hyphens become underscores, uppercased), rather than reusing an
# already-meaningful internal variable such as core.sh's
# `SCOURSH_LOCK_STALE_SECONDS`.  That variable is set unconditionally by
# core.sh (`: "${SCOURSH_LOCK_STALE_SECONDS:=30}"`) before this file is even
# sourced, so by the time config.sh runs it is ALWAYS "set" - whether or not
# an operator actually exported it - and treating that as "the operator gave
# an env override" would make env silently outrank a real
# `config/scanner.conf` value on every run with no operator action at all.
# A dedicated namespace has no such collision, for this key or any other.
# Wiring the resolved values from this file into the long-running process
# state that core.sh already owns (the scratch dir, the mutex timeouts) is
# scan.sh's job, once it exists (docs/DESIGN.md §13 step 2's remaining
# pieces): that dir is created and those defaults are latched at core.sh's
# OWN source time, before any config file can be read, so this loader
# resolves and validates the effective value but does not claim to apply it
# to state that already exists by the time it runs.
#
# shellcheck shell=bash
#
# SC2209: `src=env` / `src=file` assign the plain strings "env" and "file" to
# a source-tracking variable; both happen to also be command names, which is
# what triggers shellcheck's "did you mean $(...)" heuristic here. There is
# no command substitution intended anywhere `src=` is assigned in this file.
# shellcheck disable=SC2209

if [[ -n ${SCOURSH_CONFIG_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CONFIG_SOURCED=1

# ADR: cut lib/config.sh's shellcheck -x edge to lib/records.sh
# Context: lib/http.sh sources BOTH lib/config.sh and lib/findings.sh, and
#   both of those independently `source lib/records.sh` (which itself
#   sources lib/core.sh) with real (non-/dev/null) shellcheck directives -
#   an uncut diamond that inlines records.sh/core.sh TWICE for every one of
#   the ~130+ files that reach lib/http.sh (most of modules/dast/ and its
#   test suites), per the cost model AGENTS.md already records for the
#   sca engine cycle and the dast/passive response-reader diamond.
# Decision: cut THIS edge (lib/config.sh's), not lib/findings.sh's own.
#   lib/http.sh sources config.sh before findings.sh (this file's own
#   header before lib/http.sh's findings.sh source), so findings.sh's real
#   edge still inlines records.sh once for every lib/http.sh consumer.
#   lib/findings.sh is left untouched because it is ALSO sourced directly
#   (not via this file) by lib/report.sh and half a dozen standalone test
#   suites with no other path to records.sh - cutting it there measurably
#   broke one of them (a real SC2034 on tests/suites/findings.sh's
#   SCOURSH_RUN_ID, since records.sh/core.sh use it and shellcheck could no
#   longer see that). Runtime is unaffected either way: the `source` call
#   below still executes, and records.sh's own SCOURSH_RECORDS_SOURCED
#   guard (and config.sh's own SCOURSH_CONFIG_SOURCED above) makes
#   re-sourcing a no-op.
# Alternatives considered: cutting lib/findings.sh's edge instead (the
#   ticket's own first proposal) - rejected: findings.sh is a standalone
#   entry point itself and is reached directly (not via config.sh) by
#   lib/report.sh and 6 test suites, several with no other path to
#   records.sh; fixing all of those by adding a defensive real
#   `source lib/records.sh` to lib/report.sh would in turn create a NEW
#   diamond in modules/sast/engine.sh and modules/sca/engine.sh, which
#   source both lib/report.sh and lib/config.sh directly.
# Consequences: every lib/http.sh consumer inlines records.sh/core.sh once
#   instead of twice (measured: lib/http.sh alone drops from 1.16GB to
#   0.85GB peak shellcheck -x RSS, ~27%). lib/config.sh's own standalone
#   entry point (and tests/suites/config.sh, its only other direct
#   consumer) no longer sees records.sh's declarations statically; verified
#   empirically (see ticket) that this introduces no new finding today. A
#   future edit to lib/config.sh that references an unassigned-looking
#   records.sh/core.sh global could reintroduce a false SC2034 the way the
#   findings.sh path did - if that happens, add a real
#   `source lib/records.sh` ahead of this line rather than reverting it.
# -x back-edge cut: lib/records.sh
# shellcheck source=/dev/null
source "${BASH_SOURCE[0]%/*}/records.sh"

# ---------------------------------------------------------------------------
# 1. Generic load-or-die, shared by every config/*.conf file
# ---------------------------------------------------------------------------
# `config_load_or_die PATH SCHEMA [SET]` - loads and schema-validates PATH,
# dying loudly (exit 4, "missing required input" per tension 14 - the file
# exists but cannot be trusted) on any syntax or schema error.  Every
# diagnostic records_load/records_validate produced was already printed to
# stderr by the time this dies, so the operator sees file:line:col:CODE for
# each problem, not just "failed".
config_load_or_die() {
  local path=$1 schema=$2
  local set=${3:-$schema}
  if [[ ! -e $path ]]; then
    die "$SCOURSH_EXIT_INPUT" "required config file missing: $path"
  fi
  records_load "$path" "$schema" "$set" \
    || die "$SCOURSH_EXIT_INPUT" "$path failed to parse (see diagnostics above)"
  records_validate "$set" \
    || die "$SCOURSH_EXIT_INPUT" "$path failed schema validation (see diagnostics above)"
}

# `config_load_if_present PATH SCHEMA [SET]` - as above, but an ABSENT file is
# not an error: it returns 1 with no diagnostic, so the caller can fall back
# to documented defaults.  A file that EXISTS but is malformed always dies via
# config_load_or_die; it is never treated as if it were absent, because that
# would let an operator's typo silently disable a config file's settings
# (or, for scope.conf, the scope gate itself) instead of refusing to run
# (rules/RULE-FORMAT.md §11).
config_load_if_present() {
  local path=$1 schema=$2
  local set=${3:-$schema}
  [[ -e $path ]] || return 1
  config_load_or_die "$path" "$schema" "$set"
  return 0
}

# ---------------------------------------------------------------------------
# 2. config/scanner.conf (rules/RULE-FORMAT.md §9.6.1)
# ---------------------------------------------------------------------------
# An absent file is equivalent to one containing only `id: scanner` (§9.6.1),
# so it is not an error; every key then resolves through env/default exactly
# as if the file existed and simply omitted that key.
CONFIG_SCANNER_LOADED=0

config_scanner_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scanner.conf}
  CONFIG_SCANNER_LOADED=0
  config_load_if_present "$path" scanner-config scanner || return 0
  CONFIG_SCANNER_LOADED=1
  return 0
}

# `SCOURSH_CONFIG_<KEY>`, e.g. `jobs` -> `SCOURSH_CONFIG_JOBS`.
_scanner_env_name() {
  local key=$1 upper
  upper=${key^^}
  upper=${upper//-/_}
  printf 'SCOURSH_CONFIG_%s' "$upper"
}

# The §9.6.1 "Default" column, for every SINGLE-cardinality key.  `formats`
# and `paranoid-allow` are repeatable and are handled by
# _scanner_default_list instead: a single scalar default cannot represent
# "all four formats".
_scanner_default() {
  case $1 in
    requests-per-second) printf '%s' 4 ;;
    jobs) printf '%s' 4 ;;
    http-timeout) printf '%s' 20 ;;
    max-redirects) printf '%s' 5 ;;
    request-budget) printf '%s' 20000 ;;
    circuit-breaker-failures) printf '%s' 10 ;;
    circuit-breaker-window) printf '%s' 60 ;;
    fail-on) printf '%s' none ;;
    min-confidence) printf '%s' low ;;
    redact-secrets) printf '%s' true ;;
    max-matches-per-file) printf '%s' 200 ;;
    evidence-max-bytes) printf '%s' 512 ;;
    # Resolved here, explicitly, by the loader - never by sourcing or
    # expanding the config file (rules/RULE-FORMAT.md §11, §5.3: "$HOME in a
    # config value is four literal bytes").  This is the loader's own
    # fallback constant, not config data, so resolving it in bash is exactly
    # what tension 26 asks for.
    scratch-dir) printf '%s' "${TMPDIR:-/tmp}" ;;
    # An empty default is a real value here, not a missing one: `contact` is
    # optional and its ABSENCE is what selects the no-contact User-Agent form
    # (docs/STEP5-DAST-PLAN.md, "The identifying User-Agent").  Returning ''
    # with status 0 is therefore correct, and is why this arm exists rather
    # than falling through to the `*) return 1` unknown-key refusal.
    contact) printf '%s' '' ;;
    # docs/STEP5-DAST-PLAN.md DAST-07.  30 days is the notice period the
    # public CA ecosystem itself operates on - ACME clients renew at 30 days
    # remaining - so it is the window at which "expiring soon" first becomes
    # actionable rather than noise, and it is a scanner-wide policy for the
    # reason modules/dast/passive/tls.sh's header gives.
    tls-expiry-warn-days) printf '%s' 30 ;;
    state-retain-runs) printf '%s' 30 ;;
    history-window-days) printf '%s' 365 ;;
    history-max-commits) printf '%s' 5000 ;;
    lock-stale-seconds) printf '%s' 30 ;;
    mutex-timeout-seconds) printf '%s' 120 ;;
    *) return 1 ;;
  esac
}

_scanner_default_list() {
  case $1 in
    formats) printf '%s\n' json sarif html md ;;
    paranoid-allow) printf '' ;;
    # Empty, not the shipped seven-entry list: an empty result here is what
    # tells modules/dast/passive/headers_engine.sh's hdr_load_recommended that
    # the operator did not configure this key at all, so it falls through to
    # its own file/vendored-default layer instead. The shipped list lives in
    # modules/dast/passive/recommended-headers.txt, not here, so there is
    # exactly one place that enumerates it.
    recommended-header) printf '' ;;
    *) return 1 ;;
  esac
}

# Shape validation per the §9.6.1 "Value" column.  Applied to the RESOLVED
# value regardless of which precedence level it came from, because
# `records_validate` checks syntax and cross-field schema rules but does not
# know these keys are meant to be integers, decimals, or booleans - and a CLI
# flag or env var never goes through records_validate at all.
_scanner_validate_value() {
  local key=$1 val=$2
  case $key in
    requests-per-second)
      [[ $val =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] ;;
    jobs | http-timeout | request-budget | circuit-breaker-failures \
      | max-matches-per-file | evidence-max-bytes | state-retain-runs \
      | history-window-days | history-max-commits | lock-stale-seconds \
      | mutex-timeout-seconds)
      [[ $val =~ ^[1-9][0-9]*$ ]] ;;
    # Zero IS valid here, unlike every key above: `tls-expiry-warn-days: 0`
    # means "warn about nothing that has not already expired", which is a
    # legitimate thing for an operator to want and is the only way to turn the
    # expiring-soon check off without turning the expired check off with it.
    tls-expiry-warn-days)
      [[ $val =~ ^(0|[1-9][0-9]*)$ ]] ;;
    max-redirects | circuit-breaker-window)
      [[ $val =~ ^(0|[1-9][0-9]*)$ ]] ;;
    fail-on)
      [[ $val =~ ^(critical|high|medium|low|info|none)$ ]] ;;
    min-confidence)
      [[ $val =~ ^(high|medium|low)$ ]] ;;
    redact-secrets)
      [[ $val == true || $val == false ]] ;;
    scratch-dir)
      [[ $val == /* ]] ;;
    contact)
      config_valid_ua_text "$val" ;;
    *)
      return 1 ;;
  esac
}

# The shape both User-Agent inputs share (docs/STEP5-DAST-PLAN.md DAST-31):
# `contact`, the scanner-config key, and `--user-agent-suffix`, which is a CLI
# flag with no config key of its own.  One predicate rather than two, so the
# two can never disagree about what is safe to put in a request header.
#
# Empty is VALID and means "not configured": `contact`'s documented default is
# empty, and an empty value is what selects the no-contact User-Agent form.
#
# The charset is deliberately narrow rather than "free text": this value is
# concatenated into an HTTP `User-Agent` header, so a CR or LF would be header
# injection, and an unescaped `(`, `)` or `\` would break out of - or corrupt -
# the RFC 7230 comment the contact is placed inside.  A space is excluded too,
# because every value this key is meant to hold (an email address, a URL, a
# product token) has none, and excluding it means the resulting header cannot
# grow a second, unintended product token out of one operator value.
config_valid_ua_text() {
  local v=$1
  if [[ -z $v ]]; then
    return 0
  fi
  [[ $v =~ ^[!-~]+$ ]] || return 1
  [[ $v != *'('* && $v != *')'* && $v != *\\* ]]
}

_scanner_validate_list_item() {
  local key=$1 val=$2
  case $key in
    formats) [[ $val =~ ^(json|sarif|html|md)$ ]] ;;
    paranoid-allow) [[ $val =~ ^[^:[:space:]]+:[0-9]+$ ]] ;;
    # An RFC 7230 field-name token - the identical bracket expression
    # modules/dast/passive/headers_engine.sh's own file-based loader accepts
    # (copied rather than re-derived: a bracket expression has no escape
    # character in POSIX ERE, so re-deriving this by hand is exactly how a
    # stray backslash ends up a literal member of the class instead of
    # protecting the character after it from bash). Case is not constrained
    # here: hdr_load_recommended lowercases on its way in.
    recommended-header) [[ $val =~ ^[A-Za-z0-9!#\$%\&\'*+.^_\`|~-]+$ ]] ;;
    *) return 1 ;;
  esac
}

# `config_scanner_value KEY [CLI_VALUE]` - resolves a single-cardinality
# scanner.conf setting through CLI > env > file > default, validates the
# resolved value's shape, and prints it.  Dies loudly on the first level that
# was present and invalid: exit 2 (usage error) for a bad CLI value or a bad
# env var - both are the operator's own invocation - and exit 4 (missing
# required input, matching the convention `records_load` callers already use
# elsewhere in this repo for an unusable config file) for a bad file value.
# CLI_VALUE is the caller's already-parsed flag value; scan.sh's CLI parser
# (not yet built) is what will eventually supply it.  An empty CLI_VALUE or
# an empty/unset env var both mean "not given at this level" and fall
# through, exactly like an absent flag or an unset variable.
#
# It also PUBLISHES which level won, in `CONFIG_SCANNER_LAST_SOURCE` (one of
# `cli`, `env`, `file`, `default`).  That is not a new mechanism: the `src`
# variable below already decided which exit code an invalid value costs, and
# docs/STEP5-DAST-PLAN.md's DAST-32 clamp needs exactly the same distinction
# for a VALID value that is above a module ceiling - an explicit `cli`/`env`
# value is the operator's own invocation and is refused rather than rewritten,
# while a `file`/`default` value is clamped.  Reading it back requires calling
# this function WITHOUT a `$(...)` wrapper (lib/core.sh's `core_capture`, or
# scan.sh's `_scan_capture`), because a subshell's assignment to a global is
# discarded when the subshell exits - the same property that already makes
# `die` unreliable through `$(...)` here.  A `$(...)` caller that does not read
# the source at all is unaffected, which is why the test suite's own
# `$(config_scanner_value ...)` idiom keeps working.
# SC2034: read by lib/http.sh's DAST-32 clamp, which shellcheck's per-file
# call graph does not follow.  Deliberately NOT exported: an exported variable
# would cross into a subprocess and become another way for a limit decision to
# be influenced from outside this process.
# shellcheck disable=SC2034
CONFIG_SCANNER_LAST_SOURCE=''

config_scanner_value() {
  local key=$1 cli=${2:-}
  local env_name env_val src val
  CONFIG_SCANNER_LAST_SOURCE=''

  if [[ -n $cli ]]; then
    val=$cli
    src=cli
  else
    env_name=$(_scanner_env_name "$key")
    env_val=${!env_name:-}
    if [[ -n $env_val ]]; then
      val=$env_val
      src=env
    elif (( CONFIG_SCANNER_LOADED )) && records_has scanner 0 "$key"; then
      val=$(records_field scanner 0 "$key")
      src=file
    else
      val=$(_scanner_default "$key") \
        || die "$SCOURSH_EXIT_USAGE" "internal: config_scanner_value called with unknown key '$key'"
      src=default
    fi
  fi

  # shellcheck disable=SC2034  # read by lib/http.sh; see the declaration above
  CONFIG_SCANNER_LAST_SOURCE=$src

  if ! _scanner_validate_value "$key" "$val"; then
    case $src in
      cli) die "$SCOURSH_EXIT_USAGE" "invalid value for '$key' on the command line: '$val'" ;;
      env) die "$SCOURSH_EXIT_USAGE" "$env_name has an invalid value: '$val'" ;;
      file) die "$SCOURSH_EXIT_INPUT" "config/scanner.conf: '$key' has an invalid value: '$val'" ;;
      *) die "$SCOURSH_EXIT_INCOMPLETE" "internal: built-in default for '$key' is invalid: '$val'" ;;
    esac
  fi
  printf '%s' "$val"
}

# `config_scanner_list KEY [CLI_CSV]` - as above for the two repeatable keys
# (`formats`, `paranoid-allow`).  CLI_CSV and the matching env var are
# comma-separated, matching the `--format json,sarif,html,md` grammar in
# docs/DESIGN.md §5.  Prints one entry per line, in resolution order.
#
# Publishes which level won in `CONFIG_SCANNER_LIST_LAST_SOURCE`, the identical
# contract `config_scanner_value`'s own `CONFIG_SCANNER_LAST_SOURCE` documents -
# a separate variable rather than the same one, since a caller resolving both a
# scalar and a list key in sequence (docs/STEP-GUIDE-PLAN.md GUIDE-06's own
# run.json `config` object, which records every scanner.conf key's value AND
# source) must be able to read each one back without either call clobbering the
# other's answer.  Deliberately NOT exported, for the identical reason.
# shellcheck disable=SC2034
CONFIG_SCANNER_LIST_LAST_SOURCE=''

config_scanner_list() {
  local key=$1 cli_csv=${2:-}
  local env_name env_val src item list
  local -a items=()
  CONFIG_SCANNER_LIST_LAST_SOURCE=''

  if [[ -n $cli_csv ]]; then
    src=cli
    IFS=',' read -r -a items <<<"$cli_csv"
  else
    env_name=$(_scanner_env_name "$key")
    env_val=${!env_name:-}
    if [[ -n $env_val ]]; then
      src=env
      IFS=',' read -r -a items <<<"$env_val"
    elif (( CONFIG_SCANNER_LOADED )) && records_has scanner 0 "$key"; then
      src=file
      list=$(records_list scanner 0 "$key")
      while IFS= read -r item; do
        [[ -n $item ]] && items+=("$item")
      done <<<"$list"
    else
      src=default
      list=$(_scanner_default_list "$key") \
        || die "$SCOURSH_EXIT_USAGE" "internal: config_scanner_list called with unknown key '$key'"
      while IFS= read -r item; do
        [[ -n $item ]] && items+=("$item")
      done <<<"$list"
    fi
  fi

  for item in "${items[@]+"${items[@]}"}"; do
    if ! _scanner_validate_list_item "$key" "$item"; then
      case $src in
        cli) die "$SCOURSH_EXIT_USAGE" "invalid entry for '$key' on the command line: '$item'" ;;
        env) die "$SCOURSH_EXIT_USAGE" "$env_name has an invalid entry: '$item'" ;;
        file) die "$SCOURSH_EXIT_INPUT" "config/scanner.conf: '$key' has an invalid entry: '$item'" ;;
        *) die "$SCOURSH_EXIT_INCOMPLETE" "internal: built-in default list for '$key' has an invalid entry: '$item'" ;;
      esac
    fi
  done

  # shellcheck disable=SC2034  # read by lib/report.sh's config object (GUIDE-06)
  CONFIG_SCANNER_LIST_LAST_SOURCE=$src
  printf '%s\n' "${items[@]+"${items[@]}"}"
}

# ---------------------------------------------------------------------------
# 3. config/scope.conf (rules/RULE-FORMAT.md §9.4) - the §7 scope gate
# ---------------------------------------------------------------------------
# Unlike scanner.conf, scope.conf is NOT globally required (tension 14's
# required-inputs table: sast/sca/iac need no scope.conf at all).  Loading it
# is therefore split in two: `config_scope_load` is optional-file, same as
# `config_scanner_load`, for callers (such as cloud target attribution) that
# want the targets IF an operator declared any; `config_scope_require` is the
# non-bypassable dast gate, which DOES require the file to exist.
CONFIG_SCOPE_LOADED=0

config_scope_load() {
  local path=${1:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  CONFIG_SCOPE_LOADED=0
  config_load_if_present "$path" scope-target scope || return 1
  CONFIG_SCOPE_LOADED=1
  return 0
}

# `config_scope_require TARGET_ID [PATH]` - docs/DESIGN.md §7: "the --target
# name must resolve to an entry in scope.conf. No entry -> exit 3. This is
# the single most important safety control; do not make it bypassable by raw
# URL."  A wholly missing scope.conf is a DIFFERENT failure from a present
# file with no matching entry: dast cannot even attempt the gate with no
# file at all, which tension 14's required-inputs table makes exit 4 ("a
# missing scope.conf is exit 4 only for dast"); a present file that simply
# does not name TARGET_ID is exit 3, the gate itself refusing.  An empty
# scope.conf (docs/DESIGN.md §11: "make the tool error clearly if it's
# missing/empty") falls into the second case automatically, since it parses
# to zero records and therefore matches no target id either.
#
# Deliberately VOID rather than printing the matched index: it loads
# config/scope.conf as a side effect (populating the "scope" record set), and
# a side-effecting function called as `idx=$(config_scope_require ...)` would
# run that load inside the command-substitution subshell and throw the
# populated record set away the moment the subshell exits, leaving every
# later records_field/records_id call against an empty set - the same class
# of bug `run_init` (lib/core.sh) is deliberately never called through `$()`
# for.  Call it directly, then read the target through
# config_scope_field[_or] or `records_index_of_id scope TARGET_ID`.
config_scope_require() {
  local target=$1 path=${2:-$SCOURSH_INSTALL_ROOT/config/scope.conf}
  [[ -n $target ]] || die "$SCOURSH_EXIT_USAGE" 'config_scope_require called with no target id'
  [[ -e $path ]] || die "$SCOURSH_EXIT_INPUT" "dast requires $path, and it does not exist"
  config_scope_load "$path"
  records_index_of_id scope "$target" >/dev/null \
    || die "$SCOURSH_EXIT_SCOPE" "--target '$target' has no entry in $path"
  return 0
}

# Convenience accessor for a field of an already-loaded/required target.
# Both check CONFIG_SCOPE_LOADED first so a caller that forgot to load or
# require scope.conf gets "scope.conf was never loaded" rather than the
# more confusing "target not found" that an empty record set would also
# produce.
config_scope_field() {
  local target=$1 key=$2 idx
  (( CONFIG_SCOPE_LOADED )) || die "$SCOURSH_EXIT_INCOMPLETE" \
    'internal: config_scope_field called before config_scope_load/config_scope_require'
  idx=$(records_index_of_id scope "$target") \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: config_scope_field called for unknown target '$target'"
  records_field scope "$idx" "$key"
}

config_scope_field_or() {
  local target=$1 key=$2 default=$3 idx
  (( CONFIG_SCOPE_LOADED )) || die "$SCOURSH_EXIT_INCOMPLETE" \
    'internal: config_scope_field_or called before config_scope_load/config_scope_require'
  idx=$(records_index_of_id scope "$target") \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: config_scope_field_or called for unknown target '$target'"
  records_field_or scope "$idx" "$key" "$default"
}
