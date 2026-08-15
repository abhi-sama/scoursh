#!/usr/bin/env bash
# modules/sca/engine.sh - the SCA lockfile/manifest parsers (npm, Python,
# Ruby/RubyGems, and Java) and the shared data/advisories.db exact-match
# lookup (docs/DESIGN.md §6.5, §13 step 4).  PHP/Composer's own parser lives
# in the sibling php_engine.sh (sourced below) instead of inline here - see
# that file's own header; nothing in THIS file parses a composer manifest
# directly.
#
# Owns:
#   docs/DESIGN.md      §6.5 "SCA (dependency vulnerabilities, offline)"
#   docs/FOUNDATION.md  tension 25 - offline version matching: NO version-range
#                       arithmetic, an exact (ecosystem, package, version)
#                       lookup against a pre-expanded data/advisories.db, name
#                       normalisation frozen per ecosystem (npm: verbatim,
#                       scope included; PyPI: PEP 503; RubyGems: verbatim,
#                       lowercased; Maven: `groupId:artifactId`; Composer:
#                       verbatim, lowercased), and the ONE roll-up finding
#                       (per ecosystem-scan entry point) for a package the db
#                       knows but whose exact pinned version it does not.
#
# SCOPE: npm (package-lock.json v1/v2/v3, yarn.lock, pnpm-lock.yaml) - PLUS
# Python (requirements.txt, poetry.lock, Pipfile.lock) - PLUS Ruby/RubyGems
# (Gemfile.lock) - PLUS Java: `pom.xml`'s top-level `<dependencies>`, and
# `build.gradle`'s two literal-string declaration shapes (`implementation
# "g:a:v"` and `implementation group: 'g', name: 'a', version: 'v'`),
# regex/line-based best-effort - PLUS, as of this ticket, PHP/Composer
# (composer.lock/composer.json), parsed by the sibling php_engine.sh instead
# of inline here.  A later ticket adds another ecosystem alongside these
# five; nothing here parses a manifest belonging to one still un-shipped
# (Go, ...).  NOT in scope for Java specifically, stated rather than
# silently missed: Gradle Kotlin DSL (`build.gradle.kts`); Gradle version
# catalogs (`libs.versions.toml`, or any `libs.xxx` accessor reference inside
# a `build.gradle`); and any Gradle or Maven dependency whose
# group/artifact/version is a computed value or a property/variable
# interpolation rather than a literal - `_sca_parse_build_gradle` and
# `_sca_parse_pom_xml` below both document exactly where each of these is
# recognised and silently skipped, precisely so this list stays true and is
# not just aspirational prose.
#
# `sca_scan_tree` below (section 9) is the SHARED per-run orchestrator for
# npm, Ruby and PHP alike (Java's own sca_scan_java_tree and Python's own
# sca_scan_python_tree are deliberately separate - see each function's own
# header for why), because docs/DESIGN.md/this ticket's own acceptance
# criteria require SCA-COV-UNKNOWN_VERSION-01 to be ONE roll-up finding per
# run for the ecosystems it covers, not one per ecosystem - see that
# function's own comment.
#
# A pure function library: sourced once, defines functions, no side effects
# at source time (modules/sca/run.sh is the file that DOES something when
# sourced) - the same split modules/sast/engine.sh and modules/sast/run.sh
# use, deliberately mirrored here per the npm ticket's own instruction to
# reuse the proven per-module registry/dispatch pattern.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SCA_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SCA_ENGINE_SOURCED=1

# See modules/sast/engine.sh's own comment on this exact guard: `scan_dispatch`
# resolves modules relative to $SCOURSH_INSTALL_ROOT, which can be a fixture
# root with no lib/ sibling at all when this file is sourced standalone by a
# test; a real `scan.sh` run has already sourced both from ITS OWN directory
# before scan_dispatch ever runs, so this is a no-op there.
if [[ -z ${SCOURSH_REPORT_SOURCED:-} ]]; then
  # shellcheck source=lib/report.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/report.sh"
fi
if [[ -z ${SCOURSH_CONFIG_SOURCED:-} ]]; then
  # shellcheck source=lib/config.sh
  source "${BASH_SOURCE[0]%/*}/../../lib/config.sh"
fi
# php_engine.sh (PHP/Composer: composer.lock + composer.json, §13 step 4) is
# the sibling "front end" `sca_scan_tree` below calls into for that
# ecosystem, exactly as this file is npm's own front end - see
# php_engine.sh's own header for why it is a separate file and why the two
# source each other (both guarded, so the recursive attempt below is a
# same-line no-op whichever file a caller sources first).
if [[ -z ${SCOURSH_SCA_PHP_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=modules/sca/php_engine.sh
  source "${BASH_SOURCE[0]%/*}/php_engine.sh"
fi

# ---------------------------------------------------------------------------
# 1. Lockfile discovery
# ---------------------------------------------------------------------------
# Directories never worth walking into, for the same reason
# modules/sast/engine.sh's SAST_DEFAULT_EXCLUDE_DIRS exists: a vendored,
# already-installed node_modules tree (or, for Ruby, a `bundle install
# --path` local gem cache under .bundle/) can itself contain lockfiles
# (nested workspace packages, or a vendored dependency that ships its own),
# and walking into it would report someone else's already-installed tree as
# this repository's own dependency graph.  A separate array from SAST's
# rather than a shared one: this module owns its own exclusion policy and a
# future SAST-side change must not silently change what SCA walks.  `vendor`
# is already shared with Go's own vendoring convention, kept as one entry
# rather than duplicated.
SCA_DEFAULT_EXCLUDE_DIRS=(.git node_modules vendor .venv venv __pycache__
  .mypy_cache .pytest_cache .tox dist build reports state .terraform .bundle)

_sca_dir_excluded() {
  local base=$1 d
  for d in "${SCA_DEFAULT_EXCLUDE_DIRS[@]+"${SCA_DEFAULT_EXCLUDE_DIRS[@]}"}"; do
    [[ $base == "$d" ]] && return 0
  done
  return 1
}

# sca_walk_npm_lockfiles ROOT - prints one absolute path per line, in
# LC_ALL=C sorted order, to every package-lock.json, yarn.lock and
# pnpm-lock.yaml under ROOT, skipping SCA_DEFAULT_EXCLUDE_DIRS at any depth.
# ROOT itself may be a single lockfile (a `--path` naming one file directly).
sca_walk_npm_lockfiles() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      package-lock.json | yarn.lock | pnpm-lock.yaml) printf '%s\n' "$root" ;;
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
    \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml \) \
    -print 2>/dev/null | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 2. Name normalisation (docs/FOUNDATION.md tension 25's frozen table)
# ---------------------------------------------------------------------------
# npm: "name verbatim, scope included" - the identity function.  Kept as a
# named call, not inlined at every use site, so the day a second ecosystem
# lands its own (non-identity) normaliser sits right next to this one and the
# per-ecosystem table stays visibly complete rather than half-implemented and
# half-assumed.
sca_npm_normalize_name() {
  printf '%s' "$1"
}

# RubyGems: "name verbatim, lowercase" (docs/FOUNDATION.md tension 25's
# frozen table - the same rule the table states for Composer and Cargo,
# which this ticket does not implement).  `${1,,}` is the bash 4+
# lowercasing expansion; §13/tension 24 already requires bash >= 4.2, so no
# `tr`/capability wrapper is needed the way tension 24's frozen-function
# table reserves for genuinely non-portable operations.
sca_ruby_normalize_name() {
  local n=$1
  printf '%s' "${n,,}"
}

# ---------------------------------------------------------------------------
# 3. A minimal, stated-assumption JSON reader
# ---------------------------------------------------------------------------
# ASSUMPTION (stated, not hidden, per this repository's own convention -
# docs/FOUNDATION.md tension 5's "COST, stated rather than hidden"): every
# JSON file this module reads carries exactly one structural token - an
# opening `{`/`[`, a closing `}`/`]`, or one `"key": value` pair - per
# physical line.  This is true of EVERY package-lock.json on disk without
# exception, because npm's own writer (json-stringify-nice /
# JSON.stringify(x, null, 2)) never emits more than one per line.  For a
# hand-authored package.json it holds for every realistic indent style
# (2-space, 4-space, tabs) that still keeps one key per line, which is what
# every editor and `npm pkg set` produce; only a deliberately minified
# package.json would violate it, and no registry accepts one as a manifest.
# A full recursive-descent JSON parser in bash was rejected for the same
# reason docs/FOUNDATION.md tension 25 rejected bash version-range algebra:
# large, mostly-untested surface for a codebase built to avoid exactly that.
#
# _sca_json_walk FILE - streams one TSV record per input line to stdout:
#   DEPTH <0x1F> KEY <0x1F> KIND <0x1F> VALUE
# (0x1F, the ASCII "unit separator" - not a real tab: MEASURED, bash's
# `read` treats a literal tab as "IFS whitespace" and collapses/strips it
# even when IFS is set to ONLY a tab, silently shifting every field after
# an empty one - see _sca_emit_finding's own comment, where this same fact
# bites for real on data/advisories.db's genuinely tab-delimited rows).
# KIND is `open` (KEY's value opens an object/array; DEPTH is the depth this
# KEY itself lives at, so its children appear at DEPTH+1), `close` (an
# object/array ends; DEPTH is the depth being returned TO, i.e. identical to
# the DEPTH its own `open` line reported), or `scalar` (KEY holds a JSON
# scalar at DEPTH; VALUE is the raw JSON text with a trailing comma
# stripped, otherwise un-decoded).  A bare array element or any other shape
# is silently skipped - no field this module reads is ever an array element
# or spans more than one line (every "packages" / "dependencies" /
# "devDependencies" value this module needs is a flat object of strings, or
# a nested object; never an array, per the npm lockfile schemas themselves).
_sca_json_walk() {
  local file=$1 depth=0 line t key value
  while IFS= read -r line || [[ -n $line ]]; do
    t=$line
    t="${t#"${t%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    [[ -n $t ]] || continue
    case $t in
      '{' | '[' | '{,' | '[,')
        # A BARE open (no `"key":` prefix) is, for every file this module
        # reads, the document root's own opening brace on line 1 - never a
        # bare array element (see the header comment: nothing this module
        # needs is ever an array of objects).  It is intentionally NOT a
        # depth transition: the root object's own keys ("packages", ...)
        # are wanted at depth 0, not depth 1, and the root's matching
        # closing brace at end-of-file is still handled correctly below
        # (it decrements from 0 and is clamped back to 0 - harmless, since
        # nothing reads an event after the last line).
        continue
        ;;
      '}' | '},' | ']' | '],')
        depth=$(( depth - 1 ))
        # `if`, not the equivalent-looking `(( depth < 0 )) && depth=0`: see
        # this file's own "MEASURED" note further down
        # (_sca_parse_npm_lock_v2v3's header) - a bare `(( cond )) && stmt`
        # sharing a `case` with a plain function call in ANOTHER arm
        # spuriously trips the ERR trap on this loop's own natural EOF.
        if (( depth < 0 )); then depth=0; fi
        printf '%d\x1f\x1fclose\x1f\n' "$depth"
        continue
        ;;
    esac
    if [[ $t =~ ^\"((\\.|[^\"\\])*)\"[[:space:]]*:[[:space:]]*(.*)$ ]]; then
      key=$(_sca_json_unescape "${BASH_REMATCH[1]}")
      value=${BASH_REMATCH[3]}
      case $value in
        '{' | '{,' | '[' | '[,')
          printf '%d\x1f%s\x1fopen\x1f\n' "$depth" "$key"
          depth=$(( depth + 1 ))
          ;;
        *)
          value=${value%,}
          printf '%d\x1f%s\x1fscalar\x1f%s\n' "$depth" "$key" "$value"
          ;;
      esac
    fi
    # else: a bare array element or a line this walker does not model - see
    # the header comment on why nothing this module reads takes that shape.
  done <"$file"
}

# Minimal unescaping for the handful of sequences an npm/pnpm package NAME or
# VERSION can plausibly contain when it round-trips through JSON - none of
# them legally contain a literal `"` or control character, so this is not a
# general JSON string decoder (rules/RULE-FORMAT.md's own "values carry no
# escaping at all" design note is a different frozen format, not this one;
# this function exists only because a `dependencies` key IS occasionally a
# scoped name written `@scope/name`, which JSON never needs to escape at all,
# so in practice this is close to a no-op - it is here so a `\\` or `\/` some
# tool's writer chose does not leak into a package name verbatim).
_sca_json_unescape() {
  local s=$1
  s=${s//\\\//\/}
  s=${s//\\\\/\\}
  printf '%s' "$s"
}

# _sca_json_scalar_str VALUE - VALUE is `_sca_json_walk`'s raw scalar text;
# strips a JSON string's surrounding quotes (and unescapes it) when VALUE is
# a string, or returns it unchanged otherwise (a bare `true`/`false`/number is
# never quoted, so this is a safe unconditional check).
_sca_json_scalar_str() {
  local v=$1
  if [[ $v == \"*\" ]]; then
    v=${v#\"}
    v=${v%\"}
    _sca_json_unescape "$v"
  else
    printf '%s' "$v"
  fi
}

# ---------------------------------------------------------------------------
# 4. Shared name/version helpers
# ---------------------------------------------------------------------------

# _sca_split_name_version STRING - splits a `name@version` (or
# `@scope/name@version`) string, setting _SCA_NV_NAME and _SCA_NV_VERSION.
# The split point is the LAST `@` for an unscoped name and the SECOND `@` for
# a scoped one (the first `@` is the scope marker itself, never a version
# separator) - the same rule yarn.lock and pnpm-lock.yaml both use for their
# own package-spec strings.
_sca_split_name_version() {
  local s=$1 rest
  if [[ $s == @* ]]; then
    rest=${s#@}
    _SCA_NV_NAME="@${rest%%@*}"
    _SCA_NV_VERSION=${rest#*@}
  else
    _SCA_NV_NAME=${s%%@*}
    _SCA_NV_VERSION=${s#*@}
  fi
}

# _sca_npm_pkgpath_info PATH - PATH is a package-lock.json v2/v3 `packages`
# map key, e.g. `node_modules/lodash` or
# `node_modules/foo/node_modules/@scope/bar`.  Sets _SCA_PKGNAME (the
# installed package's own name, scope included) and _SCA_PKG_TOPLEVEL (1 when
# PATH has exactly one `node_modules/` segment, i.e. it is installed directly
# under the project root rather than nested inside another package's own
# node_modules - the necessary, but not by itself sufficient, condition for
# "direct": a HOISTED transitive dependency also lands at this same top
# slot, which is why the caller additionally checks the root's own recorded
# dependency names before calling a top-level entry "direct".
_sca_npm_pkgpath_info() {
  local path=$1 tmp=$1 count=0
  while [[ $tmp == *node_modules/* ]]; do
    count=$(( count + 1 ))
    tmp=${tmp#*node_modules/}
  done
  _SCA_PKGNAME=${path##*node_modules/}
  if (( count == 1 )); then _SCA_PKG_TOPLEVEL=1; else _SCA_PKG_TOPLEVEL=0; fi
}

# ---------------------------------------------------------------------------
# 5. package-lock.json (v1, and v2/v3) - docs/DESIGN.md §6.5
# ---------------------------------------------------------------------------

# sca_npm_direct_deps DIR - prints, one per line, the names npm considers
# this project's OWN direct dependencies: the union of a sibling
# package.json's `dependencies`, `devDependencies`, `optionalDependencies`
# and `peerDependencies` keys.  Prints nothing (not an error) when
# DIR/package.json is absent - callers that need a direct/transitive split
# fall back to a lockfile-native heuristic in that case, documented at each
# call site.
sca_npm_direct_deps() {
  local dir=$1
  local file=$dir/package.json
  [[ -r $file ]] || return 0
  local -a stack=()
  local depth key kind value
  while IFS=$'\x1f' read -r depth key kind value; do
    if [[ $kind == open ]]; then
      stack[depth]=$key
    fi
    if [[ $kind == scalar && $depth -eq 1 ]]; then
      case ${stack[0]:-} in
        dependencies | devDependencies | optionalDependencies | peerDependencies)
          printf '%s\n' "$key"
          ;;
      esac
    fi
  done < <(_sca_json_walk "$file")
}

# _sca_npm_lock_format FILE - prints `v2v3` when FILE has a top-level
# `packages` key (npm lockfileVersion 2 or 3), else `v1`.  v1 has no such key
# at all - its top-level dependency tree lives directly under `dependencies`.
#
# Reads the raw file directly rather than through `_sca_json_walk` on
# purpose: this only needs to find ONE line and stop, and breaking out of a
# loop early while a PROCESS-SUBSTITUTION producer is still writing gives
# that producer's next `printf` an EPIPE, which `set -e` (lib/core.sh,
# tension 4) turns into a spurious ERR-trap failure message on stderr even
# though the actual detection already succeeded (measured) - reading a
# plain file descriptor has no such producer to break out from under.
_sca_npm_lock_format() {
  local file=$1 line fmt=v1
  while IFS= read -r line; do
    case $line in
      '  "packages": {'*)
        fmt=v2v3
        break
        ;;
    esac
  done <"$file"
  printf '%s' "$fmt"
}

# _sca_parse_npm_lock_v2v3 FILE - prints one `name<0x1F>version<0x1F>direct|transitive`
# row per line per package.  Direct/transitive comes from the `packages` map
# itself (docs/DESIGN.md §6.5's "packages map" wording): the root entry (key
# `""`) is npm's own record of package.json's dependency lists, so a v2/v3
# lockfile needs no sibling package.json read at all - see the header comment
# on why this is preferred over reading package.json again where the
# lockfile already carries the same fact first-hand.
#
# ASSUMES npm's own, universally-observed convention that the root entry
# (key `""`) is the FIRST key inside `packages`, so its dependency lists are
# fully collected before any installed package entry needs to consult them.
# A hand-edited lockfile that violated this would only under-classify some
# direct dependencies as transitive - both are still matched against
# data/advisories.db identically, so this cannot cause a missed detection,
# only a metadata nicety being wrong (stated, not hidden, per this
# repository's own convention for this class of tradeoff).
_sca_parse_npm_lock_v2v3() {
  local file=$1
  local -a stack=()
  local -A root_direct=()
  local dep_map_key='' depth key kind value
  while IFS=$'\x1f' read -r depth key kind value; do
    case $kind in
      open)
        stack[depth]=$key
        if (( depth == 2 )) && [[ ${stack[0]:-} == packages && ${stack[1]:-} == '' ]]; then
          case $key in
            dependencies | devDependencies | optionalDependencies | peerDependencies)
              dep_map_key=$key
              ;;
            *) dep_map_key='' ;;
          esac
        fi
        ;;
      close)
        # MEASURED (bash 5.3.9, this host): a bare `(( cond )) && stmt`
        # statement, in a `case` arm that shares its enclosing `while read`
        # loop with ANOTHER arm that calls a plain function (the `scalar`
        # arm below calls `_sca_json_scalar_str`/`_sca_npm_pkgpath_info`),
        # spuriously trips the ERR trap (lib/core.sh's `core_on_err`, tension
        # 14) on that loop's own natural EOF - even though the loop condition
        # itself is the well-documented exempt case, and even though this
        # exact statement in isolation (no sibling function call) does not
        # reproduce it.  Isolated by bisection; not reproduced with an
        # equivalent `if (( cond )); then stmt; fi`, which is what every
        # instance of this shape uses in this file instead - never a bare
        # `(( cond )) && stmt`.
        if (( depth == 2 )); then dep_map_key=''; fi
        ;;
      scalar)
        if (( depth == 3 )) && [[ -n $dep_map_key ]]; then
          root_direct[$key]=1
        elif (( depth == 2 )) && [[ ${stack[0]:-} == packages && $key == version ]]; then
          local path=${stack[1]:-}
          if [[ -n $path ]]; then
            local ver
            ver=$(_sca_json_scalar_str "$value")
            _sca_npm_pkgpath_info "$path"
            if (( _SCA_PKG_TOPLEVEL )) && [[ -n ${root_direct[$_SCA_PKGNAME]:-} ]]; then
              printf '%s\x1f%s\x1fdirect\n' "$_SCA_PKGNAME" "$ver"
            else
              printf '%s\x1f%s\x1ftransitive\n' "$_SCA_PKGNAME" "$ver"
            fi
          fi
        fi
        ;;
    esac
  done < <(_sca_json_walk "$file")
}

# _sca_parse_npm_lock_v1 FILE DIR - prints the same `name<0x1F>version<0x1F>
# direct|transitive` shape for a v1 lockfile, whose `dependencies` map
# nests recursively (a package's own un-hoisted transitive dependencies sit
# inside ITS `dependencies`, same shape as the top one) - a nested occurrence
# is always transitive; a TOP occurrence is classified against DIR's own
# package.json when present (sca_npm_direct_deps), because npm's hoisting can
# put a transitive dependency in the same top slot a direct one would
# occupy, and only package.json can tell the two apart.  With no
# package.json available, every top occurrence is reported as direct - the
# same lockfile-only heuristic v2/v3 uses, and the same stated limitation.
_sca_parse_npm_lock_v1() {
  local file=$1 dir=$2
  local -A direct_set=()
  local has_direct_set=0 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
    has_direct_set=1
  done < <(sca_npm_direct_deps "$dir")

  local -a stack=()
  local depth key kind value
  while IFS=$'\x1f' read -r depth key kind value; do
    if [[ $kind == open ]]; then
      stack[depth]=$key
    fi
    if [[ $kind == scalar && $key == version ]]; then
      local p=$(( depth - 1 ))
      if (( p >= 1 )) && [[ ${stack[$(( p - 1 ))]:-} == dependencies ]]; then
        local name=${stack[$p]}
        local ver top=0
        ver=$(_sca_json_scalar_str "$value")
        # `if`, not `(( p == 1 )) && top=1` - see
        # _sca_parse_npm_lock_v2v3's own MEASURED comment on why a bare
        # `(( cond )) && stmt` is avoided everywhere in this file.
        if (( p == 1 )); then top=1; fi
        if (( top == 1 )) && { (( ! has_direct_set )) || [[ -n ${direct_set[$name]:-} ]]; }; then
          printf '%s\x1f%s\x1fdirect\n' "$name" "$ver"
        else
          printf '%s\x1f%s\x1ftransitive\n' "$name" "$ver"
        fi
      fi
    fi
  done < <(_sca_json_walk "$file")
}

# sca_parse_package_lock FILE - dispatches on lockfile shape (v1 vs v2/v3),
# DIR is FILE's own directory (where a sibling package.json, if any, lives).
sca_parse_package_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local fmt
  fmt=$(_sca_npm_lock_format "$file")
  if [[ $fmt == v2v3 ]]; then
    _sca_parse_npm_lock_v2v3 "$file"
  else
    _sca_parse_npm_lock_v1 "$file" "$dir"
  fi
}

# ---------------------------------------------------------------------------
# 6. yarn.lock - a custom, non-JSON, indented format
# ---------------------------------------------------------------------------
# One header line at column 0 (`name@range[, name@range2, ...]:`), followed
# by 2-space-indented properties (`version "x.y.z"`, `dependencies:`), whose
# OWN 4-space-indented children (`name "range"`) are yarn's transitive-
# dependency graph.  This is yarn classic's (v1 lockfile) shape; yarn
# berry's own lockfile is a different (YAML) format and is out of scope for
# this ticket (npm-only, per the ticket's own scope line).

# _sca_yarn_header_name LINE - LINE is a header with the trailing `:`
# already known to be present; returns the FIRST descriptor's package name
# (every descriptor in one header names the same package, by yarn's own
# grouping rule, so one suffices).
_sca_yarn_header_name() {
  local line=$1 first
  line=${line%:}
  first=${line%%,*}
  first="${first#"${first%%[![:space:]]*}"}"
  first="${first%"${first##*[![:space:]]}"}"
  if [[ $first == \"*\" ]]; then
    first=${first#\"}
    first=${first%\"}
  fi
  _sca_split_name_version "$first"
  printf '%s' "$_SCA_NV_NAME"
}

# _sca_yarn_quoted_value LINE - LINE is `  version "x.y.z"` (or, rarely, an
# unquoted value); prints the value with any surrounding quotes stripped.
_sca_yarn_quoted_value() {
  local line=$1 v
  v=${line#*version}
  v="${v#"${v%%[![:space:]]*}"}"
  if [[ $v == \"*\" ]]; then
    v=${v#\"}
    v=${v%\"}
  fi
  printf '%s' "$v"
}

# _sca_yarn_dep_line_name LINE - LINE is one 4-space-indented line inside a
# `dependencies:`/`optionalDependencies:` sub-block (`    name "range"`);
# prints just the name.
_sca_yarn_dep_line_name() {
  local line=$1 t
  t="${line#"${line%%[![:space:]]*}"}"
  t=${t%%[[:space:]]*}
  if [[ $t == \"*\" ]]; then
    t=${t#\"}
    t=${t%\"}
  fi
  printf '%s' "$t"
}

# sca_parse_yarn_lock FILE - same `name<0x1F>version<0x1F>direct|transitive` shape
# shape as the npm lockfile parsers.  DIR (FILE's own directory) is used for
# a sibling package.json when present, exactly as the v1 npm parser above;
# with no package.json, a package is classified `direct` only when NO other
# entry's own `dependencies:`/`optionalDependencies:` sub-block references
# it - yarn.lock's "own graph" (docs/DESIGN.md §6.5's own wording for this
# format).  STATED LIMITATION: a package that is BOTH a genuine direct
# dependency AND separately required by another package would, under this
# graph-only fallback, be reported `transitive` (it IS reachable as someone
# else's dependency, which is the only signal yarn.lock alone carries) -
# the package.json path above does not have this gap, which is why it is
# preferred whenever available.
sca_parse_yarn_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local -A direct_set=()
  local has_direct_set=0 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
    has_direct_set=1
  done < <(sca_npm_direct_deps "$dir")

  local -A referenced=()
  local in_deps=0 name
  while IFS= read -r line; do
    case $line in
      '  dependencies:' | '  optionalDependencies:')
        in_deps=1
        continue
        ;;
    esac
    if (( in_deps )); then
      if [[ $line == '    '* ]]; then
        name=$(_sca_yarn_dep_line_name "$line")
        [[ -n $name ]] && referenced[$name]=1
        continue
      else
        in_deps=0
      fi
    fi
  done <"$file"

  local cur_name='' cur_version=''
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    [[ $line == '#'* ]] && continue
    if [[ $line != ' '* ]]; then
      cur_name=$(_sca_yarn_header_name "$line")
      cur_version=''
      continue
    fi
    if [[ $line == '  version '* ]]; then
      cur_version=$(_sca_yarn_quoted_value "$line")
      [[ -n $cur_name ]] || continue
      if (( has_direct_set )); then
        if [[ -n ${direct_set[$cur_name]:-} ]]; then
          printf '%s\x1f%s\x1fdirect\n' "$cur_name" "$cur_version"
        else
          printf '%s\x1f%s\x1ftransitive\n' "$cur_name" "$cur_version"
        fi
      else
        if [[ -z ${referenced[$cur_name]:-} ]]; then
          printf '%s\x1f%s\x1fdirect\n' "$cur_name" "$cur_version"
        else
          printf '%s\x1f%s\x1ftransitive\n' "$cur_name" "$cur_version"
        fi
      fi
      cur_name=''    # one row per header; a stray second "version" line (never real) does not double-emit
    fi
  done <"$file"
}

# ---------------------------------------------------------------------------
# 7. pnpm-lock.yaml - YAML, indentation IS the structure
# ---------------------------------------------------------------------------
# Targets the modern (lockfileVersion >= 6) `importers:` / `packages:` shape,
# which is what current pnpm ships and what this ticket's fixtures use.
# SCOPE LIMIT, stated rather than hidden: a pre-`importers:` pnpm-lock.yaml
# (lockfileVersion < 6, top-level `dependencies:`/`specifiers:`, no
# `importers:` wrapper at all) falls back to a sibling package.json exactly
# like the v1 npm and yarn.lock paths above, rather than a second bespoke
# YAML shape - out of scope for this ticket's npm-only, "touch ONLY npm
# parsing" discipline to also chase every historical pnpm lockfile revision.

# _sca_pnpm_yaml_key LINE - LINE is `  key:` or `  'key':` (2, 4 or 6-space
# indented, quoting optional); prints just the key with quotes stripped.
_sca_pnpm_yaml_key() {
  local line=$1 t
  t="${line#"${line%%[![:space:]]*}"}"
  t=${t%%:*}
  if [[ $t == \'*\' && ${#t} -ge 2 ]]; then
    t=${t:1:${#t}-2}
  elif [[ $t == \"*\" && ${#t} -ge 2 ]]; then
    t=${t:1:${#t}-2}
  fi
  printf '%s' "$t"
}

# _sca_pnpm_indent LINE - number of leading space characters.
_sca_pnpm_indent() {
  local line=$1 stripped
  stripped="${line#"${line%%[![:space:]]*}"}"
  printf '%d' $(( ${#line} - ${#stripped} ))
}

# _sca_pnpm_importers_direct_deps FILE - prints, one per line, every name
# found under `importers: -> <any workspace> -> {dependencies,
# devDependencies,optionalDependencies}:`, across every workspace (a
# single-project repo has exactly one, `.`; a monorepo's several workspaces
# are unioned, which over-collects slightly across workspaces but never
# under-collects for any one of them - the safe direction for a
# vulnerability scanner, matching the npm/yarn parsers' own stated-limitation
# convention above rather than silently narrowing coverage).
_sca_pnpm_importers_direct_deps() {
  local file=$1 in_importers=0 dep_map=0 indent line key
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    indent=$(_sca_pnpm_indent "$line")
    if (( indent == 0 )); then
      if [[ $line == 'importers:' ]]; then in_importers=1; else in_importers=0; fi
      dep_map=0
      continue
    fi
    if (( ! in_importers )); then continue; fi
    if (( indent == 4 )); then
      key=$(_sca_pnpm_yaml_key "$line")
      case $key in
        dependencies | devDependencies | optionalDependencies) dep_map=1 ;;
        *) dep_map=0 ;;
      esac
      continue
    fi
    if (( indent == 6 )) && (( dep_map )); then
      key=$(_sca_pnpm_yaml_key "$line")
      [[ -n $key ]] && printf '%s\n' "$key"
      continue
    fi
    # `if`, not `(( indent < 4 )) && dep_map=0` - see
    # _sca_parse_npm_lock_v2v3's own MEASURED comment on why a bare
    # `(( cond )) && stmt` is avoided everywhere in this file.
    if (( indent < 4 )); then dep_map=0; fi
  done <"$file"
}

# sca_parse_pnpm_lock FILE - same `name<0x1F>version<0x1F>direct|transitive` shape
# shape.  `packages:` entries are 2-space indented under the top-level key;
# each key is `[/]name@version[(peerinfo)]` (a leading `/` and a trailing
# parenthesised peer-dependency suffix are both optional depending on pnpm
# version and are stripped before the name/version split).
sca_parse_pnpm_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local -A direct_set=()
  local has_direct_set=0 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
    has_direct_set=1
  done < <(_sca_pnpm_importers_direct_deps "$file")
  if (( ! has_direct_set )); then
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      direct_set[$line]=1
      has_direct_set=1
    done < <(sca_npm_direct_deps "$dir")
  fi

  local in_packages=0 indent key spec name version
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    indent=$(_sca_pnpm_indent "$line")
    if (( indent == 0 )); then
      if [[ $line == 'packages:' ]]; then in_packages=1; else in_packages=0; fi
      continue
    fi
    # `if`, not a bare `(( cond )) || continue` - see
    # _sca_parse_npm_lock_v2v3's own MEASURED comment on why a bare
    # `(( cond )) && stmt`/`|| stmt` is avoided everywhere in this file.
    if (( ! in_packages )); then continue; fi
    if (( indent != 2 )); then continue; fi
    key=$(_sca_pnpm_yaml_key "$line")
    [[ -n $key ]] || continue
    spec=$key
    spec=${spec#/}
    spec=${spec%%(*}
    _sca_split_name_version "$spec"
    name=$_SCA_NV_NAME
    version=$_SCA_NV_VERSION
    [[ -n $name && -n $version ]] || continue
    if (( has_direct_set )) && [[ -n ${direct_set[$name]:-} ]]; then
      printf '%s\x1f%s\x1fdirect\n' "$name" "$version"
    else
      printf '%s\x1f%s\x1ftransitive\n' "$name" "$version"
    fi
  done <"$file"
}

# ---------------------------------------------------------------------------
# 7a. Gemfile.lock - Ruby/RubyGems (docs/DESIGN.md §6.5)
# ---------------------------------------------------------------------------
# A blank-line-separated sequence of top-level (column 0) stanzas: `GEM`,
# `GIT`, or `PATH` (one per dependency source; a project with a git-sourced
# gem has more than one), each carrying a 2-space-indented `remote:`/
# `revision:`/etc. and a 2-space-indented `specs:` sub-header whose OWN
# 4-space-indented children are `name (version)` lines - one per RESOLVED
# gem, direct or transitive alike; a spec's own dependency names are listed
# as 6-space(+)-indented annotation lines directly below it, purely for
# documentation (bundler flattens the whole graph into this one list, unlike
# npm v1's genuinely nested node_modules/ tree - see sca_parse_gemfile_lock's
# own header for why that means no recursion is needed here); then a bare
# `PLATFORMS` stanza; then the top-level `DEPENDENCIES` stanza, whose OWN
# 2-space-indented children are the project's Gemfile's own direct
# requirements (bundler's direct analogue of npm's package.json dependency
# lists) - `name`, `name (~> 1.0)`, or `name!` (bundler's own marker for a
# git-/path-/local-sourced dependency); then usually `BUNDLED WITH`.

# _sca_gemfile_indent LINE - number of leading space characters (mirrors
# _sca_pnpm_indent; kept as its own small helper rather than shared with it,
# the same "one helper per format" convention this file already uses for
# yarn vs pnpm - Gemfile.lock's indentation levels mean something different:
# 2-space is a stanza's own property line, 4-space is a specs entry, 6-space+
# is that entry's own dependency annotation).
_sca_gemfile_indent() {
  local line=$1 stripped
  stripped="${line#"${line%%[![:space:]]*}"}"
  printf '%d' $(( ${#line} - ${#stripped} ))
}

# _sca_gemfile_dep_token LINE - LINE is a `DEPENDENCIES` entry (`  name`,
# `  name (~> 1.0)`, or `  name!`) or a `specs:` entry (`    name (1.2.3)`);
# prints just the bare name (the first whitespace-delimited token, with a
# trailing `!` - bundler's git/path/local marker, valid only in
# `DEPENDENCIES` - stripped; a `specs:` entry line never carries one).
_sca_gemfile_dep_token() {
  local line=$1 t
  t="${line#"${line%%[![:space:]]*}"}"
  t=${t%%[[:space:]]*}
  t=${t%!}
  printf '%s' "$t"
}

# _sca_gemfile_dependencies_set FILE - prints, one per line, every gem name
# declared directly under the top-level `DEPENDENCIES` stanza - what
# sca_parse_gemfile_lock classifies direct-vs-transitive against.  Unlike
# the npm/yarn/pnpm parsers above, there is no "package.json absent" fallback
# to reason about: `DEPENDENCIES` is part of Gemfile.lock itself (bundler
# always writes it), never a sibling file that might not exist.
_sca_gemfile_dependencies_set() {
  local file=$1 line indent in_deps=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    indent=$(_sca_gemfile_indent "$line")
    if (( indent == 0 )); then
      if [[ $line == DEPENDENCIES ]]; then in_deps=1; else in_deps=0; fi
      continue
    fi
    if (( in_deps )) && (( indent == 2 )); then
      printf '%s\n' "$(_sca_gemfile_dep_token "$line")"
    fi
  done <"$file"
}

# sca_parse_gemfile_lock FILE - prints one `name<0x1F>version<0x1F>
# direct|transitive` row per line per resolved gem, the same shape every
# other lockfile parser in this file uses.  A `specs:` block (under `GEM`,
# and identically shaped under `GIT`/`PATH` for a git-/path-sourced gem) is
# already FLAT - every resolved gem, direct or transitive, is one
# 4-space-indented `name (version)` line - so, unlike
# _sca_parse_npm_lock_v1, no recursion is needed: every `specs:` entry is
# classified in one pass against the top-level DEPENDENCIES set (this
# file's own header comment explains why the 6-space+ annotation lines
# beneath an entry are skipped rather than walked).
sca_parse_gemfile_lock() {
  local file=$1
  local -A direct_set=()
  local line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
  done < <(_sca_gemfile_dependencies_set "$file")

  local indent in_specs=0 name version rest
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    indent=$(_sca_gemfile_indent "$line")
    if (( indent == 0 )); then
      in_specs=0
      continue
    fi
    if (( indent == 2 )); then
      if [[ $line == '  specs:' ]]; then in_specs=1; else in_specs=0; fi
      continue
    fi
    if (( ! in_specs )); then continue; fi
    if (( indent != 4 )); then continue; fi
    # `    name (version)` - name is everything up to the space before the
    # opening paren; version is the parenthesised content.  STATED
    # LIMITATION, not hidden: a platform-specific gem
    # (`nokogiri (1.13.8-x86_64-linux)`) carries its platform suffix INSIDE
    # the same parens and it is not stripped here - this module's fixtures
    # and data/advisories.db rows are both keyed on the plain version
    # tools/vendor-engines.sh resolves, so a platform-tagged pin would
    # under-match (miss the advisory, reported honestly via the
    # unknown-version roll-up once the package is otherwise known) rather
    # than over-match - the same declared-cost direction tension 25 already
    # accepts elsewhere in this module.
    rest="${line#*"("}"
    name="${line%%(*}"
    name="${name#"${name%%[![:space:]]*}"}"
    name="${name%"${name##*[![:space:]]}"}"
    version="${rest%)}"
    [[ -n $name && -n $version ]] || continue
    if [[ -n ${direct_set[$name]:-} ]]; then
      printf '%s\x1f%s\x1fdirect\n' "$name" "$version"
    else
      printf '%s\x1f%s\x1ftransitive\n' "$name" "$version"
    fi
  done <"$file"
}

# sca_walk_gemfile_locks ROOT - prints one absolute path per line, in
# LC_ALL=C sorted order, to every Gemfile.lock under ROOT, skipping
# SCA_DEFAULT_EXCLUDE_DIRS at any depth - the same walk shape
# sca_walk_npm_lockfiles uses above, kept as its own function (rather than a
# shared "walk for these basenames" helper) so a third ecosystem's own
# lockfile basename stays a one-line diff here, not a shared array two
# ecosystems must agree on growing.  ROOT itself may be a single Gemfile.lock
# (a `--path` naming one file directly).
sca_walk_gemfile_locks() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      Gemfile.lock) printf '%s\n' "$root" ;;
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
    -name Gemfile.lock -print 2>/dev/null | LC_ALL=C sort
}

# sca_relpath ROOT PATH - PATH relative to ROOT, or "." when they are equal
# (mirrors modules/sast/engine.sh's own sast_relpath).
sca_relpath() {
  local root=$1 path=$2
  if [[ $path == "$root" ]]; then
    printf '.'
    return 0
  fi
  local rel=${path#"$root"/}
  printf '%s' "$rel"
}

# ---------------------------------------------------------------------------
# 8. data/advisories.db - the exact-match lookup (docs/FOUNDATION.md tension 25)
# ---------------------------------------------------------------------------

# sca_advisories_db_path - the real db's location, or SCOURSH_SCA_ADVISORIES_DB
# when a caller (a test, or an operator pointing at an alternate snapshot)
# overrides it - the same override-by-env convention lib/config.sh already
# uses elsewhere in this codebase for a path a test needs to redirect.
sca_advisories_db_path() {
  printf '%s' "${SCOURSH_SCA_ADVISORIES_DB:-${SCOURSH_INSTALL_ROOT:-}/data/advisories.db}"
}

# sca_lookup_exact ECOSYSTEM PACKAGE VERSION [DB] - prints every matching
# `data/advisories.db` row (or the first, under the `look`-absent fallback -
# tension 25's own frozen asymmetry) via lib/core.sh's db_lookup_exact.
# Returns db_lookup_exact's own exit status (0 = matched, 1 = not).
sca_lookup_exact() {
  local ecosystem=$1 package=$2 version=$3 db=${4:-$(sca_advisories_db_path)}
  local prefix
  prefix=$(printf '%s\t%s\t%s\t' "$ecosystem" "$package" "$version")
  db_lookup_exact "$prefix" "$db"
}

# sca_package_known ECOSYSTEM PACKAGE [DB] - true when ANY row for this
# (ecosystem, package) exists, at any version - the "is this package tracked
# at all" test the SCA-COV-UNKNOWN_VERSION-01 roll-up needs to tell "unknown
# version of a known package" apart from "this package carries no advisory
# data at all", which is not a coverage gap.
sca_package_known() {
  local ecosystem=$1 package=$2 db=${3:-$(sca_advisories_db_path)}
  local prefix
  prefix=$(printf '%s\t%s\t' "$ecosystem" "$package")
  db_lookup_exact "$prefix" "$db" >/dev/null
}

# sca_ecosystems_all - every ecosystem this module can scan, one per line,
# LC_ALL=C sorted.  It is the ANSWER TO "what could this run not scan", so it
# is deliberately a single list in a single place rather than a fact each walk
# knows about itself: the walks used to each announce their own absence (two
# of them) or none at all (the other two), and no reader could assemble the
# whole from the parts.  Adding a seventh ecosystem means adding it here.
#
# These are `data/advisories.db`'s own ecosystem keys (tension 25's frozen
# normalisation table), not display names, so the record a reader sees names
# exactly what a db row would have to say.
sca_ecosystems_all() {
  printf '%s\n' Go RubyGems composer maven npm pypi | LC_ALL=C sort
}

# sca_advisories_db_readable [DB] - the one place the module asks whether it
# can scan at all.  Every walk's own guard and the module-level announcement
# below both go through it, so "is the db usable" is decided identically
# everywhere and cannot drift between them.
sca_advisories_db_readable() {
  local db=${1:-$(sca_advisories_db_path)}
  [[ -r $db ]]
}

# sca_report_no_advisories_db - the module-level announcement when there is no
# advisory database: ONE warning, ONE coverage_reduction naming EVERY
# ecosystem, and one SCA-COV-NO_ADVISORY_DB-01 finding on the report.
#
# WHY THIS LIVES AT THE MODULE AND NOT IN THE WALKS, which is the whole point
# of the function: `data/advisories.db` does not exist in a fresh checkout
# (tools/vendor-engines.sh populates it on a networked box and is never run
# during a scan), so the shipped behaviour was the DEFAULT one - a `scan.sh
# sca` against a knowingly vulnerable project exited 0 with zero findings and
# an empty `checks_run`, which is "it did not look" rendered exactly like "it
# looked and found nothing".  Two of the four walks announced the absence
# (`sca_scan_tree` bare, `sca_go_scan_tree` with `ecosystem=Go`), so a plain
# `sca` run recorded the same reason twice whatever ecosystems the tree
# actually contained, while `sca_scan_python_tree` and `sca_scan_java_tree`
# returned silently and accounted for nothing.  A single announcement made
# once, by the module, is the only shape in which "announced exactly once"
# and "names every ecosystem" can both be true - a per-walk announcement can
# satisfy neither without knowing what the other walks did.
#
# The finding is `info`, matching SCA-COV-UNKNOWN_VERSION-01, its sibling in
# the same SCA-COV-* coverage family: a blind spot is not a vulnerability,
# and inflating its severity would trip a `--fail-on` gate and report exit 1
# ("a complete assessment that failed its gate", docs/FOUNDATION.md tension
# 14), which is the opposite of what this run can claim.  The honest exit
# code is 4, and modules/sca/run.sh sets it - see that file for why.
sca_report_no_advisories_db() {
  local db
  db=$(sca_advisories_db_path)
  local -a ecos=()
  local eco joined=''
  while IFS= read -r eco; do
    [[ -n $eco ]] && ecos+=("$eco")
  done < <(sca_ecosystems_all)
  for eco in "${ecos[@]+"${ecos[@]}"}"; do
    joined="${joined:+$joined,}$eco"
  done

  log_warn "sca: no advisory database at '$db' - NO dependency was checked in any of: $joined (populate it with 'tools/vendor-engines.sh advisories' on a networked box, docs/FOUNDATION.md tension 25)"
  run_record coverage_reduction "module=sca reason=no_advisories_db_on_disk ecosystems=$joined"
  run_record checks_run SCA-COV-NO_ADVISORY_DB-01

  finding_new
  finding_set check_id SCA-COV-NO_ADVISORY_DB-01
  finding_set module sca
  finding_set title 'SCA: dependency scanning did NOT run - no advisory database on disk, so ZERO dependencies were checked'
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set remediation "Populate the advisory database with 'tools/vendor-engines.sh advisories' on a networked box, then re-run. Until then this run says NOTHING about the dependencies of this project - absence of findings here is absence of evidence, never evidence of absence."
  finding_set_evidence "advisories_db: $db (absent or unreadable)
ecosystems_not_scanned: $joined
dependencies_checked: 0"
  finding_emit
}

# ---------------------------------------------------------------------------
# 8a. The shared unknown-version roll-up (docs/FOUNDATION.md tension 5)
# ---------------------------------------------------------------------------
# SCA-COV-UNKNOWN_VERSION-01 is a PER-RUN roll-up, never a per-package and
# never a per-ecosystem-walk finding, and tension 5's SCA fingerprint profile
# is (ecosystem, package, advisory_id) - all three of which a roll-up leaves
# empty, because it names no single dependency.  Every roll-up in a run
# therefore hashes to the identical fingerprint by construction.
#
# That is correct as long as a run emits exactly ONE.  It did not: each of the
# module's four ecosystem-scan entry points (sca_scan_tree, which itself
# covers npm+RubyGems+composer; sca_scan_python_tree; sca_scan_java_tree;
# sca_go_scan_tree) accumulated into its OWN local table and emitted its own
# roll-up, so a repository with both npm and Python dependencies produced two
# findings with one fingerprint, findings_merge's dedup kept whichever won its
# sort, and the operator was told a SMALLER number of unknown-version
# dependencies than the truth.  Measured on tests/fixtures/sca/
# mixed-four-ecosystems/: run.json recorded four coverage_gap facts and the
# report carried one roll-up reading "1 ... by ecosystem: Go: 1".
#
# The fix is at the EMISSION layer rather than the fingerprint layer, and that
# choice is load-bearing.  Adding the ecosystem to the roll-up's fingerprint
# would also stop the collision, but it changes finding identity for a shipped
# check id (rules/RULE-FORMAT.md §14 item 3), and it would be modelling the
# roll-up as a per-ecosystem fact, which it is not - the check answers "how
# much of this project's dependency surface could this run not resolve", one
# question with one answer per run.  Accumulating into one table and flushing
# once makes a second roll-up impossible to emit rather than merely harmless,
# and leaves the fingerprint byte-for-byte what it already was.
#
# The DEFERRAL FLAG is what keeps each walk independently callable.  A walk
# invoked on its own (every unit test in tests/suites/sca.sh does this) still
# flushes its own roll-up on the way out, exactly as before; modules/sca/run.sh
# wraps its four calls in sca_rollup_begin/sca_rollup_flush, and inside that
# window the walks only accumulate.  A global associative array is the
# portable way to share the table: docs/FOUNDATION.md tension 24 rules out
# `local -n` namerefs (bash >= 4.2 is the frozen minimum; namerefs need 4.3),
# which is the reason each walk kept its own local table in the first place.
declare -gA _SCA_UNKNOWN_COUNT=()
declare -g _SCA_ROLLUP_DEFERRED=0

# sca_rollup_begin - open a deferred window: the walks accumulate, nobody
# flushes until sca_rollup_flush is called.  Resets the table, so a window
# never inherits a count from an earlier run in the same process.
sca_rollup_begin() {
  _SCA_UNKNOWN_COUNT=()
  _SCA_ROLLUP_DEFERRED=1
}

# sca_rollup_add ECOSYSTEM [N] - record N (default 1) unknown-version
# dependencies for ECOSYSTEM.
sca_rollup_add() {
  local eco=$1 n=${2:-1}
  _SCA_UNKNOWN_COUNT[$eco]=$(( ${_SCA_UNKNOWN_COUNT[$eco]:-0} + n ))
}

# sca_rollup_flush - emit the single roll-up finding for everything
# accumulated since the last begin/flush, then reset.  A no-op when nothing
# was accumulated, so a run with no unknown-version case emits no roll-up at
# all, exactly as before.  Also closes any deferred window, so the next
# standalone walk self-flushes again.
sca_rollup_flush() {
  _SCA_ROLLUP_DEFERRED=0
  (( ${#_SCA_UNKNOWN_COUNT[@]} > 0 )) || return 0

  run_record checks_run SCA-COV-UNKNOWN_VERSION-01
  local -a ecos=()
  local eco cnt total=0 breakdown=''
  while IFS= read -r eco; do
    [[ -n $eco ]] && ecos+=("$eco")
  done < <(printf '%s\n' "${!_SCA_UNKNOWN_COUNT[@]}" | LC_ALL=C sort)
  for eco in "${ecos[@]+"${ecos[@]}"}"; do
    cnt=${_SCA_UNKNOWN_COUNT[$eco]}
    total=$(( total + cnt ))
    breakdown="${breakdown:+$breakdown, }$eco: $cnt"
    run_record coverage_gap "module=sca reason=unknown_version ecosystem=$eco count=$cnt"
  done
  _SCA_UNKNOWN_COUNT=()

  finding_new
  finding_set check_id SCA-COV-UNKNOWN_VERSION-01
  finding_set module sca
  finding_set title "SCA: $total pinned dependency version(s) not present in data/advisories.db (package known, exact version unmatched)"
  finding_set base_severity info
  finding_set confidence high
  finding_set cwe none
  finding_set owasp none
  finding_set cell "$SCOURSH_PATH_ROOT"
  finding_set remediation 'Refresh data/advisories.db (tools/vendor-engines.sh, on a networked box) to a snapshot that covers these exact pinned versions - absence here means "unknown", never "not vulnerable".'
  finding_set_evidence "by ecosystem: $breakdown"
  finding_emit
}

# _sca_rollup_autoflush - what every walk calls on its way out: flush only
# when no deferred window is open.  This is the single line that makes "each
# walk is independently callable" and "one roll-up per module run" both true.
_sca_rollup_autoflush() {
  (( _SCA_ROLLUP_DEFERRED )) && return 0
  sca_rollup_flush
}

# ---------------------------------------------------------------------------
# 9. Finding emission and orchestration
# ---------------------------------------------------------------------------

# _sca_emit_finding CHECK_ID DIRECT MANIFEST_LABEL MANIFEST_RELPATH ROW - ROW
# is one `data/advisories.db` TSV line already known to match a pinned
# dependency.  CHECK_ID is the check id to mint the finding under
# (SCA-NPM-VULNERABLE_DEP-01, SCA-RUBY-VULNERABLE_DEP-01, SCA-PHP-VULNERABLE_DEP-01,
# or SCA-JAVA-VULNERABLE_DEP-01 - each ecosystem's own scan entry point passes
# its own, since the id does not derive from the row's `ecosystem` field
# alone: `maven` mints under `SCA-JAVA-*`, per that ticket's own instruction,
# not a hypothetical `SCA-MAVEN-*`, and `RubyGems` mints under `SCA-RUBY-*`
# rather than `SCA-RUBYGEMS-*`).  This function itself otherwise stays
# ecosystem-agnostic (the title/logical_fqn already read the ecosystem label
# from ROW's own first field, not a literal), so a new ecosystem only ever
# needs its own check id and label, never a fork of this function.
# MANIFEST_LABEL is the evidence line's own label word (`lockfile` for npm,
# Ruby and PHP, `manifest` for Java - a lockfile and a build manifest are not
# the same thing, and the evidence should say which one this is).  Mints
# directly via lib/findings.sh's finding API (this check id has no
# `*.rules` pattern record behind it - a table lookup is not a pattern rule,
# per the npm ticket's own instruction, unchanged by later ecosystems
# reusing the same emitter).
_sca_emit_finding() {
  local check_id=$1 direct=$2 manifest_label=$3 lockfile_rel=$4 row=$5
  local eco pkg ver advisory sev fixed summary
  # data/advisories.db is real-TAB TSV (tension 25's frozen on-disk schema,
  # not this file's own choice), and `fixed_versions` is legitimately empty
  # for a no-fixed-version advisory - exactly the middle-empty-field case
  # `read` cannot be trusted with when IFS is a literal tab: MEASURED, tab is
  # always "IFS whitespace" even when IFS is set to ONLY tab, so consecutive
  # tabs collapse and silently shift every field after the empty one (unlike
  # a non-whitespace delimiter such as `,`, which read splits correctly).
  # Translating to \x1f first - a byte that is never IFS whitespace and never
  # appears in an advisories.db field (tension 25 forbids TAB/LF in a field;
  # \x1f is neither) - sidesteps the bug entirely rather than working around
  # it per call site.
  local marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r eco pkg ver advisory sev fixed summary <<<"$marked"

  local accept_risk=false
  [[ -z $fixed ]] && accept_risk=true

  finding_new
  finding_set check_id "$check_id"
  finding_set module sca
  finding_set title "$eco: $pkg@$ver is vulnerable ($advisory)"
  finding_set base_severity "$sev"
  finding_set confidence high
  finding_set cwe none
  finding_set owasp A06:2021
  finding_set loc_ecosystem "$eco"
  finding_set loc_package "$pkg"
  finding_set loc_version "$ver"
  finding_set loc_advisory_id "$advisory"
  finding_set path "$lockfile_rel"
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
  evline+="$manifest_label: $lockfile_rel"$'\n'
  evline+="advisory: $advisory ($sev)"$'\n'
  evline+="fixed_versions: ${fixed:-none published}"$'\n'
  evline+="accept_risk_candidate: $accept_risk"$'\n'
  evline+="summary: $summary"
  finding_set_evidence "$evline"
  finding_emit
}

# sca_scan_tree ROOT - the module's npm+Ruby+PHP slice: walk ROOT for
# package-lock.json/yarn.lock/pnpm-lock.yaml, Gemfile.lock, AND
# composer.lock, parse each, look every pinned dependency up against
# data/advisories.db, emit one finding per vulnerable pinned dependency, and
# one roll-up SCA-COV-UNKNOWN_VERSION-01 finding (never per-package, and -
# this is the reason every ecosystem here is walked in ONE function rather
# than one per ecosystem - never per-ecosystem either) when any package the
# db tracks had its exact pinned version go unmatched.  (Python's own
# sca_scan_python_tree, section 10, is deliberately a separate FUNCTION - see
# that function's header for why it is not folded in here too - but it is no
# longer a separate roll-up: every walk feeds section 8a's shared
# accumulator.)
#
# WHY ONE FUNCTION FOR EVERY ECOSYSTEM IT COVERS: the three walks below share
# one accumulator, so npm, RubyGems and composer contribute to one roll-up
# rather than three.  Splitting this into a per-ecosystem `sca_scan_tree`/
# `sca_ruby_scan_tree`/`sca_composer_scan_tree` set (each with its own roll-up
# emission) was considered and rejected: a repository with an npm lockfile, a
# Gemfile.lock and a composer.lock, each contributing unknown-version
# packages, would then emit THREE SCA-COV-UNKNOWN_VERSION-01 findings in one
# run, which is exactly what this ticket's own acceptance criterion
# ("contributes ... to the SHARED roll-up") and the npm suite's own "fires
# exactly ONCE, not per package" invariant both rule out.
#
# THAT ACCUMULATOR IS NOW MODULE-WIDE rather than local to this function, and
# the sibling walks (Python, Java, Go) share it too - see section 8a's own
# header for why they had to.  The per-ecosystem-walk shape this header used
# to describe was only ever a partial defence: it kept npm/RubyGems/composer
# from colliding with each other while leaving them free to collide with the
# other three walks, which is what shipped and what section 8a fixes.
#
# The db-absent guard here is SILENT by design.  The announcement moved to
# `sca_report_no_advisories_db`, called once by modules/sca/run.sh, because
# this function's warning plus `sca_go_scan_tree`'s meant every `sca` run
# announced the same fact twice while Python and Java announced nothing.
sca_scan_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  sca_advisories_db_readable "$db" || return 0

  local lockfile relpath fmt row name ver direct hits
  hits=$SCOURSH_SCRATCH/sca-hits.$$
  while IFS= read -r lockfile; do
    [[ -n $lockfile ]] || continue
    # SC2100 false positive: `fmt=package-lock.json` below is a plain string
    # assignment (that case arm's own label), not an arithmetic expression -
    # the linter's own hyphen heuristic misreads it.  Same false positive
    # already documented and silenced at tests/suites/records.sh:12
    # (`schema=pattern-rule`).  A lint directive is only valid in front of a
    # complete command (SC1124), so it sits here, above the whole `case`,
    # rather than above the individual branch that trips it.
    # shellcheck disable=SC2100
    case ${lockfile##*/} in
      package-lock.json) fmt=package-lock.json ;;
      yarn.lock) fmt=yarn.lock ;;
      pnpm-lock.yaml) fmt=pnpm-lock.yaml ;;
      *) continue ;;
    esac
    relpath=$(sca_relpath "$root" "$lockfile")
    run_record checks_run SCA-NPM-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name ver direct; do
      [[ -n $name && -n $ver ]] || continue
      name=$(sca_npm_normalize_name "$name")
      if sca_lookup_exact npm "$name" "$ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_emit_finding SCA-NPM-VULNERABLE_DEP-01 "$direct" lockfile "$relpath" "$row"
        done <"$hits"
      elif sca_package_known npm "$name" "$db"; then
        sca_rollup_add npm
      fi
    done < <(
      case $fmt in
        package-lock.json) sca_parse_package_lock "$lockfile" ;;
        yarn.lock) sca_parse_yarn_lock "$lockfile" ;;
        pnpm-lock.yaml) sca_parse_pnpm_lock "$lockfile" ;;
      esac
    )
  done < <(sca_walk_npm_lockfiles "$root")

  # Ruby/RubyGems - Gemfile.lock - same shared `hits` scratch file, and the
  # SAME roll-up accumulator (section 8a) the npm walk above just fed, per
  # this function's own header comment on why the roll-up is computed once,
  # after every ecosystem, rather than per ecosystem.
  while IFS= read -r lockfile; do
    [[ -n $lockfile ]] || continue
    relpath=$(sca_relpath "$root" "$lockfile")
    run_record checks_run SCA-RUBY-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name ver direct; do
      [[ -n $name && -n $ver ]] || continue
      name=$(sca_ruby_normalize_name "$name")
      if sca_lookup_exact RubyGems "$name" "$ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_emit_finding SCA-RUBY-VULNERABLE_DEP-01 "$direct" lockfile "$relpath" "$row"
        done <"$hits"
      elif sca_package_known RubyGems "$name" "$db"; then
        sca_rollup_add RubyGems
      fi
    done < <(sca_parse_gemfile_lock "$lockfile")
  done < <(sca_walk_gemfile_locks "$root")

  # PHP/Composer (php_engine.sh, sourced above) - same shared `hits` scratch
  # file, and the SAME roll-up accumulator (section 8a) the npm walk above
  # just fed, per this function's own header comment on why the roll-up is
  # computed once, after every ecosystem, rather than per ecosystem.
  while IFS= read -r lockfile; do
    [[ -n $lockfile ]] || continue
    relpath=$(sca_relpath "$root" "$lockfile")
    run_record checks_run SCA-PHP-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name ver direct; do
      [[ -n $name && -n $ver ]] || continue
      name=$(sca_composer_normalize_name "$name")
      if sca_lookup_exact composer "$name" "$ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_emit_finding SCA-PHP-VULNERABLE_DEP-01 "$direct" lockfile "$relpath" "$row"
        done <"$hits"
      elif sca_package_known composer "$name" "$db"; then
        sca_rollup_add composer
      fi
    done < <(sca_parse_composer_lock "$lockfile")
  done < <(sca_walk_composer_lockfiles "$root")
  rm -f "$hits"

  # Section 8a: accumulate always, emit only when no deferred window is open.
  # A standalone call still produces its own roll-up here; a module run
  # (modules/sca/run.sh) collects this walk's counts with the other three and
  # flushes one roll-up for the whole run.
  _sca_rollup_autoflush

  # tension 16's parallel workers (rate limiter, request budget, circuit
  # breaker) land at §13 step 5, same as modules/sast/run.sh's identical
  # note; this run is single-worker, honestly declared rather than silently
  # claimed as parallel.
  run_record coverage_reduction 'module=sca reason=single_worker_no_parallel_scan_yet'
}

# ---------------------------------------------------------------------------
# 10. Python: requirements.txt, poetry.lock, Pipfile.lock (docs/DESIGN.md
#     §6.5, docs/FOUNDATION.md tension 25 - the Python slice of §13 step 4)
# ---------------------------------------------------------------------------
# SCOPE (this ticket): parses exactly the three names docs/DESIGN.md §6.5
# names for Python - `requirements.txt`, `poetry.lock`, `Pipfile.lock` - no
# `requirements-*.txt`/`requirements/*.txt` variants, no bare `pyproject.toml`
# PEP 621 projects with no `poetry.lock`, no `setup.py`/`setup.cfg`.  Touches
# nothing under npm/Go/Java/Ruby/PHP - this ticket's own scope line - and
# does not modify section 5-9 above (npm) at all.

# ---- 10.1 PyPI name normalisation (frozen table, tension 25) --------------
# PEP 503: lowercase, with runs of `-`, `_`, `.` collapsed to a single `-`
# (Python's own `re.sub(r"[-_.]+", "-", name).lower()`).  A pure-bash char
# scan, not `sed`/`tr`, mirroring this file's other small per-token scanners
# (_sca_pnpm_indent, _sca_yarn_dep_line_name) rather than spawning a
# subprocess per dependency line.
sca_pypi_normalize_name() {
  local s=${1,,} out='' ch prev='' i n
  n=${#s}
  for (( i = 0; i < n; i++ )); do
    ch=${s:i:1}
    case $ch in
      -|_|.) ch='-' ;;
    esac
    if [[ $ch == '-' && $prev == '-' ]]; then
      continue
    fi
    # SC2324 false positive: `out` is a string accumulator (declared `out=''`
    # above), and `$ch` is a single character, never a bare numeric literal -
    # the linter's own "did you mean ((out+=1))" heuristic misfires on any
    # `+=` whose right-hand side traces back to a one-character case arm.
    # shellcheck disable=SC2324
    out+=$ch
    prev=$ch
  done
  printf '%s' "$out"
}

# ---- 10.2 Manifest/lockfile discovery --------------------------------------
# Reuses SCA_DEFAULT_EXCLUDE_DIRS (section 1) unchanged - it already lists
# .venv/venv/__pycache__/.mypy_cache/.pytest_cache/.tox precisely because it
# was written with this ecosystem in mind, per that array's own comment.
sca_walk_python_manifests() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      requirements.txt | poetry.lock | Pipfile.lock) printf '%s\n' "$root" ;;
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
    \( -name requirements.txt -o -name poetry.lock -o -name Pipfile.lock \) \
    -print 2>/dev/null | LC_ALL=C sort
}

# ---- 10.3 A minimal, stated-assumption TOML reader -------------------------
# poetry.lock, pyproject.toml and Pipfile are all TOML.  Like section 3's
# JSON reader, this is NOT a general TOML parser: it reads only
# `[table]`/`[[table]]` headers and `key = "value"` (or `key = value`) lines,
# one per physical line - true of every poetry.lock (machine-written) and of
# every hand-authored pyproject.toml/Pipfile in the shape this module reads
# (a flat dependency table, one package per line), which is the same
# real-world scope-limit tradeoff section 3 already states for JSON.  Inline
# tables (`{version = "1.0", extras = ["x"]}`) and multi-line arrays inside a
# table this module reads are not modelled - out of scope for this ticket's
# fixture-scale target, stated rather than hidden.

# _sca_toml_table_header LINE - prints the bare table name of a
# `[table]`/`[[table]]` header line, or nothing if LINE is not one.
_sca_toml_table_header() {
  local line=$1 t
  t="${line#"${line%%[![:space:]]*}"}"
  case $t in
    '[['*']]'*)
      t=${t#\[\[}
      t=${t%%\]\]*}
      printf '%s' "$t"
      ;;
    '['*']'*)
      t=${t#\[}
      t=${t%%\]*}
      printf '%s' "$t"
      ;;
  esac
}

# _sca_toml_kv LINE - sets _SCA_TOML_KEY/_SCA_TOML_VALUE from a `key = value`
# line (a bare or quoted key, a quoted-string value with its quotes stripped -
# every key/value this module reads is one of those two shapes).  Returns 1
# with both unset when LINE has no top-level `=` (a table header, a blank
# line, or a shape this reader does not model).
_sca_toml_kv() {
  local line=$1 k v
  if [[ $line != *=* ]]; then
    _SCA_TOML_KEY=''
    _SCA_TOML_VALUE=''
    return 1
  fi
  k=${line%%=*}
  v=${line#*=}
  k="${k#"${k%%[![:space:]]*}"}"
  k="${k%"${k##*[![:space:]]}"}"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  if [[ $k == \"*\" && ${#k} -ge 2 ]]; then
    k=${k:1:${#k}-2}
  fi
  if [[ $v == \"*\" ]]; then
    v=${v#\"}
    v=${v%\"}
  fi
  _SCA_TOML_KEY=$k
  _SCA_TOML_VALUE=$v
  return 0
}

# ---- 10.4 requirements.txt --------------------------------------------------

# _sca_req_strip_extras STRING - drops a `[extra1,extra2]` marker, keeping
# whatever came before AND after it (the version specifier, if any, follows
# the closing `]`) - e.g. `foo[bar]==1.2.3` -> `foo==1.2.3`.
_sca_req_strip_extras() {
  local s=$1 pre post
  if [[ $s == *'['*']'* ]]; then
    pre=${s%%\[*}
    post=${s#*\]}
    printf '%s' "$pre$post"
  else
    printf '%s' "$s"
  fi
}

# sca_parse_requirements_txt FILE - prints one `name<0x1F>version<0x1F>unknown`
# row per requirement line: VERSION is the exact pinned version for a `==`
# requirement, or empty when this format cannot resolve one (a range
# specifier such as `>=1.0`, or a bare unpinned name) - the caller still
# looks an empty-version name up via sca_package_known, which is how a
# requirements.txt entry with no pin at all contributes to the
# SCA-COV-UNKNOWN_VERSION-01 roll-up even though there is no version to
# exact-match: this case cannot arise for a resolved lockfile (every
# poetry.lock/Pipfile.lock entry is already pinned to one exact version) and
# is unique to a hand-authored/`pip freeze`-shaped manifest like this one.
#
# STATED LIMITATION (this ticket's own AC: "documents rather than guesses"):
# direct/transitive is always literal `unknown`, never guessed.
# requirements.txt carries no dependency graph (unlike poetry.lock's own
# `[package.dependencies]` sub-tables) and has no separate manifest/lockfile
# pair to cross-reference the way pyproject.toml/Pipfile give poetry.lock and
# Pipfile.lock (below) - a hand-curated requirements.txt often IS the
# manifest, and `pip freeze` output is byte-indistinguishable from one
# written by hand, so there is no second artifact to read at all, let alone
# one recording which entries were declared by name.
#
# Skips `-r`/`-e`/`--flag` option lines and VCS/URL/local-path requirements
# (no static exact version); drops a trailing environment marker
# (`; python_version >= "3.8"`, discarded rather than evaluated - the
# conservative "never silently narrow coverage" direction this file's other
# stated limitations already take, since evaluating it could make a real
# vulnerable pin disappear from the report on the wrong interpreter).  A
# `--hash=...` continuation line is not modelled (out of scope: fixture-scale,
# no fixture in this suite uses one).
sca_parse_requirements_txt() {
  local file=$1 line t name version rest
  while IFS= read -r line || [[ -n $line ]]; do
    t=$line
    t="${t#"${t%%[![:space:]]*}"}"
    t="${t%"${t##*[![:space:]]}"}"
    [[ -n $t ]] || continue
    [[ $t == \#* ]] && continue
    [[ $t == -* ]] && continue
    t=${t%%;*}
    t="${t%"${t##*[![:space:]]}"}"
    [[ -n $t ]] || continue
    case $t in
      git+* | hg+* | svn+* | bzr+* | http://* | https://* | ./* | ../* | /*) continue ;;
    esac
    t=$(_sca_req_strip_extras "$t")
    if [[ $t == *'=='* ]]; then
      rest=$t
      name=${rest%%==*}
      version=${rest#*==}
      version=${version%%,*}
      version="${version%"${version##*[![:space:]]}"}"
    else
      name=${t%%[\<\>=\!\~\ ]*}
      version=''
    fi
    name="${name%"${name##*[![:space:]]}"}"
    [[ -n $name ]] || continue
    printf '%s\x1f%s\x1funknown\n' "$name" "$version"
  done <"$file"
}

# ---- 10.5 poetry.lock -------------------------------------------------------

# sca_poetry_pyproject_direct_deps FILE - prints, one per line, every key
# under a sibling pyproject.toml's `[tool.poetry.dependencies]`,
# `[tool.poetry.dev-dependencies]` (legacy) or `[tool.poetry.group.<name>.
# dependencies]` (current) tables - poetry's own declared direct-dependency
# sets, across the default group and every named group - excluding the
# `python` key, which poetry lists as the interpreter's own version
# constraint, never a real PyPI package.  Prints nothing (not an error) when
# FILE is absent - sca_parse_poetry_lock below falls back to a lockfile-native
# heuristic in that case, exactly as sca_npm_direct_deps's own callers do for
# a missing package.json.
sca_poetry_pyproject_direct_deps() {
  local file=$1 line cur_table='' hdr key
  [[ -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    hdr=$(_sca_toml_table_header "$line")
    if [[ -n $hdr ]]; then
      cur_table=$hdr
      continue
    fi
    case $cur_table in
      tool.poetry.dependencies | tool.poetry.dev-dependencies | tool.poetry.group.*.dependencies) ;;
      *) continue ;;
    esac
    if _sca_toml_kv "$line"; then
      key=$_SCA_TOML_KEY
      [[ -n $key && $key != python ]] && printf '%s\n' "$key"
    fi
  done <"$file"
}

# sca_parse_poetry_lock FILE - prints one `name<0x1F>version<0x1F>
# direct|transitive` row per `[[package]]` block.
#
# Direct/transitive: primary source is a sibling pyproject.toml (above) - the
# same "read the manifest, not just the lockfile" pattern this file already
# uses for package-lock.json v1/yarn.lock/pnpm-lock.yaml.  With no
# pyproject.toml available, this format - UNLIKE Pipfile.lock below, which
# has no dependency structure at all - carries its OWN graph in each
# package's `[package.dependencies]` sub-table, so it falls back to the same
# "referenced by nobody else" heuristic sca_parse_yarn_lock uses for
# yarn.lock's own package.json-absent path: a package is direct only if no
# OTHER package's own dependencies table names it (stated limitation,
# identical in shape to yarn.lock's own: a package that is BOTH a genuine
# direct dependency AND separately required by another package would be
# reported transitive under this fallback alone).
sca_parse_poetry_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local -A direct_set=()
  local has_direct_set=0 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
    has_direct_set=1
  done < <(sca_poetry_pyproject_direct_deps "$dir/pyproject.toml")

  local -A referenced=()
  local -a names=() versions=()
  local cur_table='' in_pkg_deps=0 pkg_name='' pkg_version='' hdr line2
  while IFS= read -r line2 || [[ -n $line2 ]]; do
    [[ -n $line2 ]] || continue
    [[ $line2 == \#* ]] && continue
    hdr=$(_sca_toml_table_header "$line2")
    if [[ -n $hdr ]]; then
      if [[ -n $pkg_name && $hdr == package ]]; then
        names+=("$pkg_name")
        versions+=("$pkg_version")
        pkg_name=''
        pkg_version=''
      fi
      cur_table=$hdr
      in_pkg_deps=0
      [[ $hdr == package.dependencies ]] && in_pkg_deps=1
      continue
    fi
    if (( in_pkg_deps )); then
      if _sca_toml_kv "$line2"; then
        [[ -n $_SCA_TOML_KEY ]] && referenced[$_SCA_TOML_KEY]=1
      fi
      continue
    fi
    [[ $cur_table == package ]] || continue
    if _sca_toml_kv "$line2"; then
      case $_SCA_TOML_KEY in
        name) pkg_name=$_SCA_TOML_VALUE ;;
        version) pkg_version=$_SCA_TOML_VALUE ;;
      esac
    fi
  done <"$file"
  if [[ -n $pkg_name ]]; then
    names+=("$pkg_name")
    versions+=("$pkg_version")
  fi

  local i name version
  for (( i = 0; i < ${#names[@]}; i++ )); do
    name=${names[i]}
    version=${versions[i]}
    [[ -n $name && -n $version ]] || continue
    if (( has_direct_set )); then
      if [[ -n ${direct_set[$name]:-} ]]; then
        printf '%s\x1f%s\x1fdirect\n' "$name" "$version"
      else
        printf '%s\x1f%s\x1ftransitive\n' "$name" "$version"
      fi
    else
      if [[ -z ${referenced[$name]:-} ]]; then
        printf '%s\x1f%s\x1fdirect\n' "$name" "$version"
      else
        printf '%s\x1f%s\x1ftransitive\n' "$name" "$version"
      fi
    fi
  done
}

# ---- 10.6 Pipfile.lock ------------------------------------------------------

# sca_pipfile_direct_deps FILE - prints, one per line, every key under a
# sibling Pipfile's `[packages]`/`[dev-packages]` tables (pipenv's own
# declared direct-dependency sets).  Prints nothing (not an error) when FILE
# is absent.
sca_pipfile_direct_deps() {
  local file=$1 line cur_table='' hdr key
  [[ -r $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    hdr=$(_sca_toml_table_header "$line")
    if [[ -n $hdr ]]; then
      cur_table=$hdr
      continue
    fi
    case $cur_table in
      packages | dev-packages) ;;
      *) continue ;;
    esac
    if _sca_toml_kv "$line"; then
      key=$_SCA_TOML_KEY
      [[ -n $key ]] && printf '%s\n' "$key"
    fi
  done <"$file"
}

# _sca_pipfile_lock_section FILE SECTION - prints one `name<0x1F>version` row
# per package under Pipfile.lock's top-level SECTION map ("default" or
# "develop"), reusing section 3's _sca_json_walk (Pipfile.lock is
# machine-generated by pipenv with one token per line, same as
# package-lock.json).  VERSION has its pipenv-recorded leading `==` stripped
# (Pipfile.lock always records `"version": "==x.y.z"`, never a bare version).
_sca_pipfile_lock_section() {
  local file=$1 section=$2
  local -a stack=()
  local depth key kind value
  while IFS=$'\x1f' read -r depth key kind value; do
    if [[ $kind == open ]]; then
      stack[depth]=$key
    fi
    if [[ $kind == scalar && $depth -eq 2 && $key == version ]]; then
      if [[ ${stack[0]:-} == "$section" && -n ${stack[1]:-} ]]; then
        local ver
        ver=$(_sca_json_scalar_str "$value")
        ver=${ver#==}
        printf '%s\x1f%s\n' "${stack[1]}" "$ver"
      fi
    fi
  done < <(_sca_json_walk "$file")
}

# sca_parse_pipfile_lock FILE - prints one `name<0x1F>version<0x1F>
# direct|transitive` row per package across BOTH the "default" and "develop"
# sections.
#
# Pipfile.lock's own "default"/"develop" maps are FLAT: pipenv's resolver
# records every resolved package - direct AND transitive alike - at the same
# single level (unlike poetry.lock's per-package `[package.dependencies]`
# sub-tables above), so there is no dependency graph inside Pipfile.lock
# itself to fall back on.  Direct/transitive therefore comes ONLY from a
# sibling Pipfile's own `[packages]`/`[dev-packages]` tables (the same
# "read the manifest" pattern package-lock.json v1/yarn.lock/pnpm-lock.yaml
# already use for THEIR sibling package.json) - when Pipfile is absent, every
# entry is reported `direct`, the same stated, lockfile-only-heuristic
# fallback those three parsers use for a missing package.json.
sca_parse_pipfile_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local -A direct_set=()
  local has_direct_set=0 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    direct_set[$line]=1
    has_direct_set=1
  done < <(sca_pipfile_direct_deps "$dir/Pipfile")

  local name ver
  while IFS=$'\x1f' read -r name ver; do
    [[ -n $name && -n $ver ]] || continue
    if (( ! has_direct_set )) || [[ -n ${direct_set[$name]:-} ]]; then
      printf '%s\x1f%s\x1fdirect\n' "$name" "$ver"
    else
      printf '%s\x1f%s\x1ftransitive\n' "$name" "$ver"
    fi
  done < <(_sca_pipfile_lock_section "$file" default; _sca_pipfile_lock_section "$file" develop)
}

# ---- 10.7 Finding emission and orchestration -------------------------------

# _sca_py_emit_finding DIRECT MANIFEST_RELPATH ROW - the Python-ecosystem
# mirror of section 9's _sca_emit_finding: same fields, same TSV-via-\x1f
# translation and the same reasoning for it (see that function's own
# comment), differing only in check_id/title, which is why this is a
# separate function rather than a parameterised call into npm's own
# (this ticket's scope line: do not modify section 9).
_sca_py_emit_finding() {
  local direct=$1 lockfile_rel=$2 row=$3
  local eco pkg ver advisory sev fixed summary
  local marked=${row//$'\t'/$'\x1f'}
  IFS=$'\x1f' read -r eco pkg ver advisory sev fixed summary <<<"$marked"

  local accept_risk=false
  [[ -z $fixed ]] && accept_risk=true

  finding_new
  finding_set check_id SCA-PY-VULNERABLE_DEP-01
  finding_set module sca
  finding_set title "python: $pkg@$ver is vulnerable ($advisory)"
  finding_set base_severity "$sev"
  finding_set confidence high
  finding_set cwe none
  finding_set owasp A06:2021
  finding_set loc_ecosystem "$eco"
  finding_set loc_package "$pkg"
  finding_set loc_version "$ver"
  finding_set loc_advisory_id "$advisory"
  finding_set path "$lockfile_rel"
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
  evline+="lockfile: $lockfile_rel"$'\n'
  evline+="advisory: $advisory ($sev)"$'\n'
  evline+="fixed_versions: ${fixed:-none published}"$'\n'
  evline+="accept_risk_candidate: $accept_risk"$'\n'
  evline+="summary: $summary"
  finding_set_evidence "$evline"
  finding_emit
}

# sca_scan_python_tree ROOT - the module's whole Python slice: walk ROOT for
# requirements.txt/poetry.lock/Pipfile.lock, parse each, normalise every name
# per PEP 503, look every resolved pinned dependency up against
# data/advisories.db under ecosystem "pypi", emit one SCA-PY-VULNERABLE_DEP-01
# finding per vulnerable pinned dependency, and contribute to the shared
# SCA-COV-UNKNOWN_VERSION-01 roll-up.
#
# "Shared" is now literal.  This header used to say the opposite - that a run
# with both an npm and a Python unknown-version case emitted TWO
# SCA-COV-UNKNOWN_VERSION-01 findings, one per ecosystem-scan call, with a
# true cross-ecosystem merge left as a stated, filed follow-up.  That was not
# a cosmetic gap: both findings hashed to the identical fingerprint (a roll-up
# populates none of tension 5's SCA location components), so findings_merge's
# dedup dropped one and the surviving count understated the truth.  Section 8a
# is the shared accumulator that fixes it; this walk feeds it with
# `sca_rollup_add pypi` and ends with `_sca_rollup_autoflush`, so it still
# emits its own roll-up when called standalone.
#
# A requirements.txt entry the parser could not resolve to an exact version
# (a range specifier, or a bare unpinned name - see sca_parse_requirements_txt
# above) still contributes here when the package is otherwise KNOWN to the db
# - there being no exact version to check at all is itself "unresolved",
# landing in the same roll-up bucket an unmatched pinned version falls into.
#
# Deliberately does NOT record the module-level
# single_worker_no_parallel_scan_yet coverage_reduction fact that section 9's
# sca_scan_tree records: modules/sca/run.sh's _sca_run_module always runs
# _sca_npm_run (and so sca_scan_tree) before _sca_py_run, and that trailing
# fact is UNCONDITIONAL there regardless of whether any npm lockfile actually
# exists in the tree, so it is already recorded exactly once for the whole
# module by the time this function would otherwise duplicate it.  The
# db-absent guard below is silent for a different and stronger reason: that
# announcement is `sca_report_no_advisories_db`'s, made once by the module -
# no walk owns it, precisely so that none can make it twice.
sca_scan_python_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  sca_advisories_db_readable "$db" || return 0

  local manifest relpath fmt name ver direct hits
  hits=$SCOURSH_SCRATCH/sca-py-hits.$$
  while IFS= read -r manifest; do
    [[ -n $manifest ]] || continue
    case ${manifest##*/} in
      requirements.txt) fmt=requirements.txt ;;
      poetry.lock) fmt=poetry.lock ;;
      Pipfile.lock) fmt=Pipfile.lock ;;
      *) continue ;;
    esac
    relpath=$(sca_relpath "$root" "$manifest")
    run_record checks_run SCA-PY-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name ver direct; do
      [[ -n $name ]] || continue
      name=$(sca_pypi_normalize_name "$name")
      if [[ -n $ver ]] && sca_lookup_exact pypi "$name" "$ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_py_emit_finding "$direct" "$relpath" "$row"
        done <"$hits"
      elif sca_package_known pypi "$name" "$db"; then
        sca_rollup_add pypi
      fi
    done < <(
      case $fmt in
        requirements.txt) sca_parse_requirements_txt "$manifest" ;;
        poetry.lock) sca_parse_poetry_lock "$manifest" ;;
        Pipfile.lock) sca_parse_pipfile_lock "$manifest" ;;
      esac
    )
  done < <(sca_walk_python_manifests "$root")
  rm -f "$hits"

  # Section 8a: accumulate always, emit only when no deferred window is open.
  # A standalone call still produces its own roll-up here; a module run
  # (modules/sca/run.sh) collects this walk's counts with the other three and
  # flushes one roll-up for the whole run.
  _sca_rollup_autoflush
}

# ---------------------------------------------------------------------------
# 11. Java: pom.xml and build.gradle (this ticket)
# ---------------------------------------------------------------------------
# Ecosystem string is `maven` (docs/FOUNDATION.md tension 25's frozen
# normalisation table names the ecosystem "Maven", and `data/advisories.db`
# rows use the lower-case form, matching `npm`'s own lower-case row values) -
# for BOTH pom.xml and build.gradle, since Gradle resolves against the same
# Maven-shaped coordinate (`groupId:artifactId:version`) and the same
# artifact repositories; there is no separate "gradle" ecosystem in any
# advisory feed.

# Directories never worth walking into, for Java's own build tooling: `target`
# (Maven's build output - can contain a shaded/copied pom.xml that is not this
# project's own manifest) and `.gradle` (Gradle's cache/daemon state).  Built
# from SCA_DEFAULT_EXCLUDE_DIRS rather than duplicating it, so a future
# addition to the shared list is not silently missed here.
SCA_JAVA_EXCLUDE_DIRS=("${SCA_DEFAULT_EXCLUDE_DIRS[@]+"${SCA_DEFAULT_EXCLUDE_DIRS[@]}"}" target .gradle)

_sca_java_dir_excluded() {
  local base=$1 d
  for d in "${SCA_JAVA_EXCLUDE_DIRS[@]+"${SCA_JAVA_EXCLUDE_DIRS[@]}"}"; do
    [[ $base == "$d" ]] && return 0
  done
  return 1
}

# sca_walk_java_manifests ROOT - prints one absolute path per line, in
# LC_ALL=C sorted order, to every pom.xml and build.gradle under ROOT,
# skipping SCA_JAVA_EXCLUDE_DIRS at any depth.  ROOT itself may be a single
# manifest file directly, exactly like sca_walk_npm_lockfiles.  Deliberately
# does NOT match `build.gradle.kts` (Gradle's Kotlin DSL) - a different
# syntax this ticket's two regex shapes do not parse, stated as an
# unsupported gap in this file's own header rather than silently mis-parsed.
sca_walk_java_manifests() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      pom.xml | build.gradle) printf '%s\n' "$root" ;;
    esac
    return 0
  fi
  local -a prune=()
  local d first=1
  for d in "${SCA_JAVA_EXCLUDE_DIRS[@]+"${SCA_JAVA_EXCLUDE_DIRS[@]}"}"; do
    (( first )) || prune+=(-o)
    prune+=(-path "$root/*/$d" -o -path "$root/$d")
    first=0
  done
  find "$root" \( "${prune[@]+"${prune[@]}"}" \) -prune -o -type f \
    \( -name pom.xml -o -name build.gradle \) \
    -print 2>/dev/null | LC_ALL=C sort
}

# sca_maven_normalize_name GROUPID ARTIFACTID - the Maven key
# (docs/FOUNDATION.md tension 25's frozen table: "Maven | `groupId:artifactId`"),
# a plain `:`-join with no case-folding - Maven coordinates are
# case-sensitive, unlike PyPI's normalisation.  Kept as its own named call for
# the same reason sca_npm_normalize_name is (§2 above): the per-ecosystem
# table stays visibly complete at every call site rather than inlined once
# and forgotten the next time an ecosystem lands.
sca_maven_normalize_name() {
  printf '%s:%s' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 10a. pom.xml - a line-based XML walker
# ---------------------------------------------------------------------------
# ASSUMPTION (stated, not hidden, same convention as _sca_json_walk's own
# header above): every pom.xml this module reads carries at most one
# structural token per physical line - an opening tag, a closing tag, or one
# `<tag>text</tag>` scalar - which is true of every pom.xml produced by an
# IDE, `mvn archetype:generate`, or a human editing Maven's own conventional
# 2-space/4-space pretty-printed style.  A single-line minified pom.xml (all
# elements on one line) would defeat this walker; none is known to exist in
# practice, and Maven's own tooling never emits one.
#
# What is (and is not) captured, spelled out because pom.xml's shape has two
# traps for a naive dependency scan:
#
#   - `<dependencyManagement><dependencies>` only PINS a version for a
#     dependency some *other* module or child POM chooses to declare; it
#     never by itself makes this project depend on anything.  Only a
#     `<dependencies>` that is a DIRECT CHILD OF THE ROOT `<project>` element
#     is scanned - which excludes dependencyManagement's own nested
#     `<dependencies>` (one level deeper), <profiles>/<profile>/<dependencies>
#     (two levels deeper, and conditionally active besides), and any
#     <plugin>'s own <dependencies> (nested under <build>/<plugins>/<plugin>).
#     Stated limitation: a dependency declared only inside an active
#     <profile> is not seen by this walker at all - out of scope for this
#     ticket, which targets the always-active top-level dependency list.
#   - Inside one eligible `<dependency>`, only its IMMEDIATE children
#     (`<groupId>`, `<artifactId>`, `<version>`) are read; a nested
#     `<exclusions><exclusion><groupId>...` sits two levels deeper and is
#     never mistaken for the dependency's own groupId.
#
# Prints one `name<0x1F>version<0x1F>unknown` row per eligible <dependency>
# (name already normalised to `groupId:artifactId`).  The third field is the
# literal string `unknown`, never `direct` or `transitive` - this ticket's
# own instruction: pom.xml's <dependencies> list is Maven's declared
# dependency set, but whether any one of them is ALSO reachable transitively
# through another (the same ambiguity npm's hoisting creates) is a fact only
# a real `mvn dependency:tree` resolution could settle, and this module never
# invokes Maven or touches the network to do that - so it says "unknown"
# rather than guessing "direct" for every entry, which is this ticket's
# explicit "marked ... unknown rather than guessed" requirement.
#
# A `<version>` that is a Maven property placeholder (`${...}`) is passed
# through completely unresolved - property interpolation is a stated,
# documented gap (this file's own header, and the module-level SCOPE note
# above): the literal, un-substituted string is what gets looked up, which
# misses cleanly (data/advisories.db never contains a `${...}` version)
# rather than guessing which concrete version the property resolves to.
_sca_parse_pom_xml() {
  local file=$1
  local -a stack=()
  local depth=0
  local elig_deps_depth=-1 elig_dep_depth=-1
  local cur_group='' cur_artifact='' cur_version=''
  local in_comment=0
  local line trimmed tag value

  while IFS= read -r line || [[ -n $line ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -n $trimmed ]] || continue

    if (( in_comment )); then
      [[ $trimmed == *'-->'* ]] && in_comment=0
      continue
    fi
    if [[ $trimmed == '<!--'* ]]; then
      [[ $trimmed == *'-->'* ]] || in_comment=1
      continue
    fi
    [[ $trimmed == '<?'* ]] && continue

    # self-closing: <tag/> or <tag attr="x"/> - no depth change, no scalar.
    # `<` and `>` are backslash-escaped in every pattern below for the SHELL's
    # own sake, not the regex engine's: written bare in an inline `[[ ... ]]`
    # word, `<`/`>` are shell redirection operators and bash's parser rejects
    # them before `=~` ever runs (MEASURED: `^<[A-Za-z...` here is a syntax
    # error, "unexpected token `<'"). `\<`/`\>` is bash's own quote-removal
    # escape (same mechanism as `\;` in a `find` command) - it is stripped by
    # bash itself while parsing the source line, so the compiled regex the C
    # library actually sees contains a plain, ordinary `<`/`>` byte, never a
    # backslash - there is no GNU-vs-BSD `\<` "word boundary" ambiguity here,
    # because regcomp never receives a backslash for this character at all.
    # (This escape is therefore NOT available via a variable holding the
    # pattern text - MEASURED: storing `\<...\>` in a variable and matching
    # `[[ $x =~ $re ]]` fails, because at that point the backslash is already
    # gone from a NORMAL variable assignment's own quote-removal pass and the
    # variable holds a bare `<`, which is fine, OR - if the assignment itself
    # was singly-quoted - the backslash survives literally into the pattern
    # text and IS then handed to regcomp, which is the one case this parser
    # avoids entirely by never storing a `<`/`>`-bearing pattern in a
    # variable; every regex below that needs one is written inline instead.)
    if [[ $trimmed =~ ^\<[A-Za-z_][A-Za-z0-9_.:-]*([[:space:]][^\>]*)?/\>$ ]]; then
      continue
    fi

    # scalar: <tag>text</tag> entirely on one line.  The open and close tag
    # names are captured SEPARATELY and compared as plain bash strings below,
    # never via a `\1` backreference in the pattern itself - a backreference
    # is a GNU regex extension, not POSIX ERE, and (unlike the `\<`/`\>` case
    # above) IS handed to regcomp as-is, so it would be a real GNU-vs-BSD
    # portability risk if used.
    if [[ $trimmed =~ ^\<([A-Za-z_][A-Za-z0-9_.:-]*)\>(.*)\</([A-Za-z_][A-Za-z0-9_.:-]*)\>$ ]]; then
      tag=${BASH_REMATCH[1]}
      value=${BASH_REMATCH[2]}
      if [[ $tag == "${BASH_REMATCH[3]}" ]] && (( elig_dep_depth >= 0 )) && (( depth == elig_dep_depth + 1 )); then
        case $tag in
          groupId) cur_group=$value ;;
          artifactId) cur_artifact=$value ;;
          version) cur_version=$value ;;
        esac
      fi
      continue
    fi

    # closing tag
    if [[ $trimmed =~ ^\</([A-Za-z_][A-Za-z0-9_.:-]*)\>$ ]]; then
      tag=${BASH_REMATCH[1]}
      if [[ $tag == dependency ]] && (( elig_dep_depth >= 0 )) && (( depth == elig_dep_depth + 1 )); then
        if [[ -n $cur_group && -n $cur_artifact ]]; then
          printf '%s\x1f%s\x1funknown\n' "$(sca_maven_normalize_name "$cur_group" "$cur_artifact")" "$cur_version"
        fi
        cur_group='' cur_artifact='' cur_version=''
        elig_dep_depth=-1
      fi
      if [[ $tag == dependencies ]] && (( elig_deps_depth >= 0 )) && (( depth == elig_deps_depth + 1 )); then
        elig_deps_depth=-1
      fi
      depth=$(( depth - 1 ))
      if (( depth < 0 )); then depth=0; fi
      continue
    fi

    # opening tag: <tag> or <tag attr="x">
    if [[ $trimmed =~ ^\<([A-Za-z_][A-Za-z0-9_.:-]*)([[:space:]][^\>]*)?\>$ ]]; then
      tag=${BASH_REMATCH[1]}
      if [[ $tag == dependencies ]] && (( depth == 1 )) && [[ ${stack[0]:-} == project ]]; then
        elig_deps_depth=$depth
      elif [[ $tag == dependency ]] && (( elig_deps_depth >= 0 )) && (( depth == elig_deps_depth + 1 )); then
        elig_dep_depth=$depth
      fi
      stack[depth]=$tag
      depth=$(( depth + 1 ))
      continue
    fi
    # else: text content on its own line (e.g. a multi-line comment's body) -
    # matches none of the above and is correctly ignored.
  done <"$file"
}

# ---------------------------------------------------------------------------
# 10b. build.gradle - regex-based best effort (Groovy DSL only, this ticket's
# own framing; build.gradle.kts is a different syntax and out of scope)
# ---------------------------------------------------------------------------
# Recognises exactly the two declaration shapes this ticket names, each
# entirely on its own line:
#
#   implementation "group:artifact:version"          (also single-quoted)
#   implementation group: 'g', name: 'a', version: 'v'  (also double-quoted)
#
# across the common single-module dependency configurations (`implementation`,
# `api`, `compile`, `runtimeOnly`, `compileOnly`, `annotationProcessor`, and
# their `test*` equivalents) - a small, closed, named list rather than a bare
# `\w+` match, so an unrelated Groovy method call is never mistaken for a
# dependency declaration.
#
# Everything else is a stated, documented gap, not a silent miss:
#   - a version catalog accessor (`implementation(libs.foo)`, `libs.versions.toml`
#     entirely) matches neither shape's literal-quoted-string requirement and
#     is skipped;
#   - a computed/interpolated value (a Groovy local var, or `"...:$var"`
#     string interpolation) is DETECTED (the quoted string still matches the
#     shape) and then explicitly discarded because it contains a `$` - this
#     module never evaluates Groovy, so a `$`-bearing group/artifact/version
#     is never treated as if it were the literal text after substitution;
#   - a 4-component coordinate (`group:artifact:version:classifier`, or an
#     `@ext` package-type suffix) is likewise discarded rather than guessed
#     at, since a wrong split would silently corrupt the version used for
#     lookup.
#
# Prints the same `name<0x1F>version<0x1F>direct` row shape as the other
# parsers (name already normalised to `groupId:artifactId`).  The
# classification is always the literal `direct`: every configuration keyword
# this function matches is itself Gradle's own declaration of a dependency
# this build script asks for directly - build.gradle carries no transitive
# graph at all (that only exists after Gradle's own dependency resolution,
# which this module never invokes), so unlike pom.xml there is no separate
# "is this really direct" ambiguity to hedge with "unknown": everything this
# function can see is, by construction, a direct declaration.
_SCA_GRADLE_CFG_RE='(implementation|api|compile|runtimeOnly|compileOnly|annotationProcessor|testImplementation|testCompile|testRuntimeOnly|testCompileOnly|testAnnotationProcessor)'

_sca_parse_build_gradle() {
  local file=$1 line trimmed
  local shape1_re="^${_SCA_GRADLE_CFG_RE}[[:space:]]*\\(?[[:space:]]*['\"]([^'\"]+)['\"][[:space:]]*\\)?[[:space:]]*\$"
  local shape2_re="^${_SCA_GRADLE_CFG_RE}[[:space:]]+group:[[:space:]]*['\"]([^'\"]+)['\"][[:space:]]*,[[:space:]]*name:[[:space:]]*['\"]([^'\"]+)['\"][[:space:]]*,[[:space:]]*version:[[:space:]]*['\"]([^'\"]+)['\"][[:space:]]*\$"
  local g a v rest spec

  while IFS= read -r line || [[ -n $line ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [[ -n $trimmed ]] || continue
    [[ $trimmed == //* ]] && continue

    if [[ $trimmed =~ $shape2_re ]]; then
      g=${BASH_REMATCH[2]}
      a=${BASH_REMATCH[3]}
      v=${BASH_REMATCH[4]}
      if [[ $g == *'$'* || $a == *'$'* || $v == *'$'* ]]; then continue; fi
      [[ -n $g && -n $a && -n $v ]] || continue
      printf '%s\x1f%s\x1fdirect\n' "$(sca_maven_normalize_name "$g" "$a")" "$v"
      continue
    fi

    if [[ $trimmed =~ $shape1_re ]]; then
      spec=${BASH_REMATCH[2]}
      [[ $spec == *'$'* ]] && continue
      g=${spec%%:*}
      rest=${spec#*:}
      a=${rest%%:*}
      v=${rest#*:}
      # exactly 3 colon-separated fields: `rest` unchanged from `spec` means
      # there was no second ':' at all (one colon total, or none); `v`
      # containing a further ':' means a 4th component was present.  Either
      # way this is not a plain group:artifact:version triple - skip rather
      # than guess.
      if [[ -z $g || -z $a || -z $v ]]; then continue; fi
      if [[ $rest == "$spec" || $v == *:* ]]; then continue; fi
      printf '%s\x1f%s\x1fdirect\n' "$(sca_maven_normalize_name "$g" "$a")" "$v"
      continue
    fi
  done <"$file"
}

# sca_scan_java_tree ROOT - the module's whole Java slice: walk ROOT for
# pom.xml/build.gradle, parse each, look every pinned dependency up against
# data/advisories.db, emit one SCA-JAVA-VULNERABLE_DEP-01 finding per
# vulnerable pinned dependency, and one roll-up SCA-COV-UNKNOWN_VERSION-01
# finding (never per-package) when any package the db tracks had its exact
# pinned version go unmatched - the same self-contained, independently
# callable contract sca_scan_tree above documents and is tested under
# (tests/suites/sca.sh calls each ecosystem's entry point standalone).
#
# Still NOT merged into one shared "scan every ecosystem" FUNCTION with
# sca_scan_tree - each ecosystem's walk stays self-contained and
# independently callable - but the two now share one ROLL-UP ACCUMULATOR
# (section 8a), which is a different thing and was the missing half.
#
# The cost this header used to state as acceptable was not: a single
# scan_dispatch sca run against a tree with BOTH an npm lockfile and a Java
# manifest emitted two SCA-COV-UNKNOWN_VERSION-01 findings, one per entry
# point, and because a roll-up populates none of tension 5's SCA location
# components the two hashed identically, so findings_merge's dedup kept one
# and the operator was told the smaller number.  "Each is still individually
# correct" was true and irrelevant - only one of them reached the report.
#
# The portability objection that produced the per-walk shape is answered
# rather than overridden: docs/FOUNDATION.md tension 24 does rule out
# `local -n` namerefs (`bash >= 4.2` is the frozen minimum; namerefs need
# 4.3), which is why a shared emitter cannot take the table as an argument -
# so section 8a uses a plain global associative array, the same
# `declare -gA` idiom modules/sast/engine.sh's own _SAST_CHECK_LOC already
# uses, with an explicit begin/flush protocol rather than an eval.
#
# Deliberately does NOT record the module-level
# single_worker_no_parallel_scan_yet coverage_reduction fact that section 9's
# sca_scan_tree records - the same reasoning sca_scan_python_tree's own header
# states, and the same silent db-absent guard, for the same two reasons.
sca_scan_java_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  sca_advisories_db_readable "$db" || return 0

  local manifest relpath fmt row name ver direct hits
  hits=$SCOURSH_SCRATCH/sca-java-hits.$$
  while IFS= read -r manifest; do
    [[ -n $manifest ]] || continue
    case ${manifest##*/} in
      pom.xml) fmt=pom.xml ;;
      build.gradle) fmt=build.gradle ;;
      *) continue ;;
    esac
    relpath=$(sca_relpath "$root" "$manifest")
    run_record checks_run SCA-JAVA-VULNERABLE_DEP-01

    while IFS=$'\x1f' read -r name ver direct; do
      [[ -n $name && -n $ver ]] || continue
      if sca_lookup_exact maven "$name" "$ver" "$db" >"$hits"; then
        while IFS= read -r row; do
          [[ -n $row ]] || continue
          _sca_emit_finding SCA-JAVA-VULNERABLE_DEP-01 "$direct" manifest "$relpath" "$row"
        done <"$hits"
      elif sca_package_known maven "$name" "$db"; then
        sca_rollup_add maven
      fi
    done < <(
      case $fmt in
        pom.xml) _sca_parse_pom_xml "$manifest" ;;
        build.gradle) _sca_parse_build_gradle "$manifest" ;;
      esac
    )
  done < <(sca_walk_java_manifests "$root")
  rm -f "$hits"

  # Section 8a: accumulate always, emit only when no deferred window is open.
  # A standalone call still produces its own roll-up here; a module run
  # (modules/sca/run.sh) collects this walk's counts with the other three and
  # flushes one roll-up for the whole run.
  _sca_rollup_autoflush
}
