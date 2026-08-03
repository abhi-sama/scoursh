#!/usr/bin/env bash
# modules/sca/engine.sh - the SCA npm-lockfile parser and advisories.db
# exact-match lookup (docs/DESIGN.md §6.5, §13 step 4).
#
# Owns:
#   docs/DESIGN.md      §6.5 "SCA (dependency vulnerabilities, offline)"
#   docs/FOUNDATION.md  tension 25 - offline version matching: NO version-range
#                       arithmetic, an exact (ecosystem, package, version)
#                       lookup against a pre-expanded data/advisories.db, name
#                       normalisation frozen per ecosystem (npm: verbatim,
#                       scope included), and the ONE roll-up finding for a
#                       package the db knows but whose exact pinned version it
#                       does not.
#
# SCOPE (this ticket): npm only - package-lock.json (v1/v2/v3), yarn.lock,
# pnpm-lock.yaml.  A later ticket adds another ecosystem alongside this one
# in modules/sca/run.sh, per that file's own header; nothing here parses a
# non-npm manifest.
#
# A pure function library: sourced once, defines functions, no side effects
# at source time (modules/sca/run.sh is the file that DOES something when
# sourced) - the same split modules/sast/engine.sh and modules/sast/run.sh
# use, deliberately mirrored here per this ticket's own instruction to reuse
# the proven per-module registry/dispatch pattern.
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

# ---------------------------------------------------------------------------
# 1. Lockfile discovery
# ---------------------------------------------------------------------------
# Directories never worth walking into, for the same reason
# modules/sast/engine.sh's SAST_DEFAULT_EXCLUDE_DIRS exists: a vendored,
# already-installed node_modules tree can itself contain lockfiles (nested
# workspace packages, or a vendored dependency that ships its own), and
# walking into it would report someone else's already-installed tree as this
# repository's own dependency graph.  A separate array from SAST's rather than
# a shared one: this module owns its own exclusion policy and a future
# SAST-side change must not silently change what SCA walks.
SCA_DEFAULT_EXCLUDE_DIRS=(.git node_modules vendor .venv venv __pycache__
  .mypy_cache .pytest_cache .tox dist build reports state .terraform)

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

# ---------------------------------------------------------------------------
# 9. Finding emission and orchestration
# ---------------------------------------------------------------------------

# _sca_emit_finding DIRECT LOCKFILE_RELPATH ROW - ROW is one
# `data/advisories.db` TSV line already known to match a pinned dependency.
# Mints SCA-NPM-VULNERABLE_DEP-01 directly via lib/findings.sh's finding API
# (this check id has no `*.rules` pattern record behind it - a table lookup
# is not a pattern rule, per this ticket's own instruction).
_sca_emit_finding() {
  local direct=$1 lockfile_rel=$2 row=$3
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
  finding_set check_id SCA-NPM-VULNERABLE_DEP-01
  finding_set module sca
  finding_set title "npm: $pkg@$ver is vulnerable ($advisory)"
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

# sca_scan_tree ROOT - the module's whole npm slice: walk ROOT for
# package-lock.json/yarn.lock/pnpm-lock.yaml, parse each, look every pinned
# dependency up against data/advisories.db, emit one finding per vulnerable
# pinned dependency, and one roll-up SCA-COV-UNKNOWN_VERSION-01 finding (never
# per-package) when any package the db tracks had its exact pinned version
# go unmatched.
sca_scan_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  if [[ ! -r $db ]]; then
    log_warn "sca: data/advisories.db not readable at '$db' - nothing to match against (tools/vendor-engines.sh populates it and is never run in this repo/CI, docs/FOUNDATION.md tension 25)"
    run_record coverage_reduction 'module=sca reason=no_advisories_db_on_disk'
    return 0
  fi

  local -A unknown_count=()
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
          _sca_emit_finding "$direct" "$relpath" "$row"
        done <"$hits"
      elif sca_package_known npm "$name" "$db"; then
        unknown_count[npm]=$(( ${unknown_count[npm]:-0} + 1 ))
      fi
    done < <(
      case $fmt in
        package-lock.json) sca_parse_package_lock "$lockfile" ;;
        yarn.lock) sca_parse_yarn_lock "$lockfile" ;;
        pnpm-lock.yaml) sca_parse_pnpm_lock "$lockfile" ;;
      esac
    )
  done < <(sca_walk_npm_lockfiles "$root")
  rm -f "$hits"

  if (( ${#unknown_count[@]} > 0 )); then
    run_record checks_run SCA-COV-UNKNOWN_VERSION-01
    local -a ecos=()
    local eco cnt total=0 breakdown=''
    while IFS= read -r eco; do
      [[ -n $eco ]] && ecos+=("$eco")
    done < <(printf '%s\n' "${!unknown_count[@]}" | LC_ALL=C sort)
    for eco in "${ecos[@]+"${ecos[@]}"}"; do
      cnt=${unknown_count[$eco]}
      total=$(( total + cnt ))
      breakdown="${breakdown:+$breakdown, }$eco: $cnt"
      run_record coverage_gap "module=sca reason=unknown_version ecosystem=$eco count=$cnt"
    done
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
  fi

  # tension 16's parallel workers (rate limiter, request budget, circuit
  # breaker) land at §13 step 5, same as modules/sast/run.sh's identical
  # note; this run is single-worker, honestly declared rather than silently
  # claimed as parallel.
  run_record coverage_reduction 'module=sca reason=single_worker_no_parallel_scan_yet'
  # `scan.sh sca --fail-on`/`--fail-on-new` do not yet gate the exit code:
  # modules/sast/engine.sh's own sast_evaluate_gate is SAST-specific code,
  # not a shared lib/findings.sh function, so there is nothing generic for
  # this module to call yet - declared here rather than silently left
  # looking gated (SCOURSH_GATE_RESULT stays lib/report.sh's own
  # "not-evaluated" default). Follow-up ticket filed for a shared gate
  # function once a second module needs the identical logic.
  run_record coverage_reduction 'module=sca reason=gate_evaluation_not_yet_wired'
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
# finding per vulnerable pinned dependency, and contribute to the
# SCA-COV-UNKNOWN_VERSION-01 roll-up mechanism section 9 uses for npm -
# "shared" in the sense of reusing the identical check id, finding shape and
# coverage semantics documented in docs/FOUNDATION.md tension 25; NOT
# literally merged into one finding object with npm's own roll-up when both
# ecosystems have unknown-version cases in the SAME run (two
# SCA-COV-UNKNOWN_VERSION-01 findings would be emitted in that case, one per
# ecosystem-scan call) - a true cross-ecosystem merge is a stated, filed
# follow-up rather than attempted here, to avoid touching section 9's own,
# already-tested npm code path.
#
# A requirements.txt entry the parser could not resolve to an exact version
# (a range specifier, or a bare unpinned name - see sca_parse_requirements_txt
# above) still contributes here when the package is otherwise KNOWN to the db
# - there being no exact version to check at all is itself "unresolved",
# landing in the same roll-up bucket an unmatched pinned version falls into.
#
# Deliberately does NOT run the data/advisories.db-absent check nor the two
# module-level coverage_reduction facts (single_worker_no_parallel_scan_yet,
# gate_evaluation_not_yet_wired) that section 9's sca_scan_tree records:
# modules/sca/run.sh's _sca_run_module always runs _sca_npm_run (and so
# sca_scan_tree) before _sca_py_run, and sca_scan_tree's own db-absent check
# and its two trailing facts are UNCONDITIONAL there regardless of whether
# any npm lockfile actually exists in the tree - so they are already recorded
# exactly once for the whole module by the time this function would
# otherwise duplicate them.  Stated, not hidden: calling
# sca_scan_python_tree ALONE with a missing db (as this ticket's own unit
# tests do) therefore returns silently rather than re-declaring a fact only
# the npm pass owns; the real _sca_run_module ordering that makes this safe
# end-to-end is exercised by the e2e `scan.sh sca` case in tests/suites/sca.sh.
sca_scan_python_tree() {
  local root=$1
  local db
  db=$(sca_advisories_db_path)
  if [[ ! -r $db ]]; then
    return 0
  fi

  local -A unknown_count=()
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
        unknown_count[pypi]=$(( ${unknown_count[pypi]:-0} + 1 ))
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

  if (( ${#unknown_count[@]} > 0 )); then
    run_record checks_run SCA-COV-UNKNOWN_VERSION-01
    local cnt=${unknown_count[pypi]}
    run_record coverage_gap "module=sca reason=unknown_version ecosystem=pypi count=$cnt"
    finding_new
    finding_set check_id SCA-COV-UNKNOWN_VERSION-01
    finding_set module sca
    finding_set title "SCA: $cnt pinned dependency version(s) not present in data/advisories.db (package known, exact version unmatched)"
    finding_set base_severity info
    finding_set confidence high
    finding_set cwe none
    finding_set owasp none
    finding_set cell "$SCOURSH_PATH_ROOT"
    finding_set remediation 'Refresh data/advisories.db (tools/vendor-engines.sh, on a networked box) to a snapshot that covers these exact pinned versions - absence here means "unknown", never "not vulnerable".'
    finding_set_evidence "by ecosystem: pypi: $cnt"
    finding_emit
  fi
}
