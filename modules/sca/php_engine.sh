#!/usr/bin/env bash
# modules/sca/php_engine.sh - the SCA PHP/Composer parser: composer.lock
# discovery/parsing, composer.json direct-dependency cross-reference, and
# name normalisation (docs/DESIGN.md §6.5, §13 step 4;
# docs/FOUNDATION.md tension 25's frozen table row "RubyGems, Composer,
# Cargo | name verbatim, lowercase").
#
# SCOPE (this ticket): PHP/Composer only - composer.lock, cross-referenced
# against a sibling composer.json when present.  No other PHP lockfile
# format exists to parse (composer.lock is the only one), and no
# version-range arithmetic (tension 25 forbids it; lookup stays exact-match).
#
# WHY A SEPARATE FILE FROM modules/sca/engine.sh: engine.sh's own header
# scopes itself to "the SCA npm-lockfile parser" - this ticket's own
# instruction is to reuse modules/sca/run.sh and the shared advisories.db
# lookup helper (sca_lookup_exact/sca_package_known/_sca_emit_finding,
# sca_advisories_db_path, sca_relpath, the JSON-walker primitives) that the
# npm ticket already landed there, not to fork or rewrite them.  This file
# supplies ONLY the PHP-specific "front end" (discovery + parsing); the
# shared "back end" (lookup, finding emission, the SCA-COV-UNKNOWN_VERSION-01
# roll-up) stays in engine.sh's own `sca_scan_tree`, which this ticket
# extends to also walk composer.lock - see that function's own comment for
# why the roll-up specifically must not be duplicated per ecosystem.
#
# A pure function library: sourced once, defines functions, no side effects
# at source time - same contract as modules/sca/engine.sh and
# modules/sast/engine.sh.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_SCA_PHP_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_SCA_PHP_ENGINE_SOURCED=1

# Guard set BEFORE this source, exactly like engine.sh's own guard-then-source
# ordering: engine.sh sources this file too (its `sca_scan_tree` calls the
# composer-specific functions below), so the two files source each other -
# safe only because each sets its own "already sourced" flag before
# recursing into the other, which turns the second, recursive attempt into
# an immediate no-op rather than infinite mutual sourcing.
#
# The `source=/dev/null` directive is what stops ShellCheck FOLLOWING this
# particular edge, and it is deliberate rather than lazy: `-x` resolves sources
# statically, where the mutual guard above does not exist, so engine.sh ->
# php_engine.sh -> engine.sh is an unbounded static cycle that ShellCheck
# inlines until it runs out of memory.  Measured on a real run of
# `shellcheck -x -s bash modules/sca/run.sh`: 43.6 GB peak RSS and 236 seconds
# with this edge followed, against 4.6 GB and 16 seconds with it cut - and an
# OOM kill, not a slow pass, on any machine with less RAM than this one, which
# is how it was found (the Linux container leg of tools/daily-suite.sh died
# where the 64 GB macOS leg survived).  Cutting ONE edge of the cycle is enough;
# engine.sh's forward edge to this file is still followed, so nothing is lost
# from the analysis - `run.sh`, the entry point, sources every file in this
# directory itself and remains the graph ShellCheck actually walks.
if [[ -z ${SCOURSH_SCA_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/engine.sh"
fi

# ---------------------------------------------------------------------------
# 1. composer.lock discovery
# ---------------------------------------------------------------------------
# SCA_DEFAULT_EXCLUDE_DIRS (engine.sh) already lists `vendor` - Composer's own
# install directory - so a vendored dependency that ships its own
# composer.lock (rare, but not impossible for a bundled sub-project) is never
# walked into and double-reported as this repository's own dependency graph,
# the same reasoning engine.sh's own header gives for excluding node_modules.

# sca_walk_composer_lockfiles ROOT - prints one absolute path per line, in
# LC_ALL=C sorted order, to every composer.lock under ROOT, skipping
# SCA_DEFAULT_EXCLUDE_DIRS at any depth.  ROOT itself may be a single
# composer.lock (a `--path` naming one file directly) - mirrors
# sca_walk_npm_lockfiles exactly.
sca_walk_composer_lockfiles() {
  local root=$1
  if [[ -f $root ]]; then
    case ${root##*/} in
      composer.lock) printf '%s\n' "$root" ;;
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
    -name composer.lock -print 2>/dev/null | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 2. Name normalisation (docs/FOUNDATION.md tension 25's frozen table)
# ---------------------------------------------------------------------------
# Composer: "name verbatim, lowercase" - unlike npm's identity function, a
# real transform.  `${1,,}` is bash's builtin lowercase expansion (bash >=
# 4.0; this repository's own floor is 4.2, docs/FOUNDATION.md tension 24),
# already the established idiom elsewhere in this codebase (lib/http.sh,
# lib/findings.sh) rather than a `tr`/`awk` subprocess per call.
sca_composer_normalize_name() {
  local n=$1
  printf '%s' "${n,,}"
}

# ---------------------------------------------------------------------------
# 3. composer.json - direct-dependency cross-reference
# ---------------------------------------------------------------------------

# sca_composer_direct_deps DIR - prints, one per line, the names Composer
# considers this project's OWN direct dependencies: the union of a sibling
# composer.json's top-level `require` and `require-dev` keys (this ticket's
# own instruction: "cross-references composer.json's require/require-dev
# keys").  Prints nothing (not an error) when DIR/composer.json is absent -
# `sca_parse_composer_lock` then honestly reports every package `unknown`
# rather than guessing, because (unlike npm's node_modules nesting)
# composer.lock's flat `packages`/`packages-dev` arrays carry no
# direct/transitive signal of their own to fall back to.
#
# Platform entries (`php`, `ext-*`) come through unfiltered - they are never
# present in composer.lock's own `packages`/`packages-dev` arrays (those list
# only real, installable packages), so they simply never match anything and
# cost nothing to leave in.
#
# Reuses engine.sh's `_sca_json_walk`: composer.json's `require`/
# `require-dev` are flat `"name": "constraint"` maps, the exact shape
# `_sca_json_walk`'s own stated assumption already covers (same shape
# `sca_npm_direct_deps` reads from package.json's `dependencies`) - this
# function is that one's direct structural mirror, ecosystem swapped.
sca_composer_direct_deps() {
  local dir=$1
  local file=$dir/composer.json
  [[ -r $file ]] || return 0
  local -a stack=()
  local depth key kind value
  while IFS=$'\x1f' read -r depth key kind value; do
    if [[ $kind == open ]]; then
      stack[depth]=$key
    fi
    if [[ $kind == scalar && $depth -eq 1 ]]; then
      case ${stack[0]:-} in
        require | require-dev)
          printf '%s\n' "$key"
          ;;
      esac
    fi
  done < <(_sca_json_walk "$file")
}

# ---------------------------------------------------------------------------
# 4. composer.lock - a bare JSON ARRAY of flat package objects
# ---------------------------------------------------------------------------
# composer.lock's "packages" (prod: direct + transitive) and "packages-dev"
# (dev: direct + transitive) are each a bare JSON array of package objects -
# NOT a nested map the way npm's package-lock.json "packages" key is.
# engine.sh's `_sca_json_walk` states its own assumption plainly: "nothing
# this module reads is ever an array element" - true for every npm lockfile,
# false for composer.lock, so that walker is not reused here; a bare `{`
# array-element open is exactly the shape it deliberately does not model.
#
# ASSUMPTION (stated, not hidden, same convention engine.sh's own JSON
# reader states for itself): Composer's own JSON writer emits the identical
# one-token-per-line, fixed-indent shape npm's writer does - every
# `composer.lock` on disk, unless hand-minified, keeps this shape.  Under
# that shape: `"packages":`/`"packages-dev":` sit at indent 4 (inside the
# document root object), each package object opens/closes at indent 8, and
# that object's OWN top-level fields ("name", "version", ...) sit at exactly
# indent 12.  A deeper indent belongs to a NESTED object/array within that
# package entry (e.g. "source", "require", or "authors", whose own entries
# are themselves objects with their own "name" field) - restricting to
# indent 12 exactly is what tells the package's own "name" apart from, say,
# an "authors" entry's "name" without a full recursive parser, the same
# indent-discipline convention `_sca_pnpm_importers_direct_deps`
# (engine.sh) already uses for pnpm-lock.yaml's own nested YAML nested
# structure.

# _sca_composer_indent LINE - number of leading space characters.  Mirrors
# engine.sh's `_sca_pnpm_indent` structurally; kept as this file's own copy
# rather than a cross-file call so each lockfile format owns its own small
# helpers, the same convention engine.sh already uses per-format internally
# (yarn's `_sca_yarn_quoted_value` vs pnpm's `_sca_pnpm_yaml_key`, structurally
# similar, deliberately not merged).
_sca_composer_indent() {
  local line=$1 stripped
  stripped="${line#"${line%%[![:space:]]*}"}"
  printf '%d' $(( ${#line} - ${#stripped} ))
}

# _sca_composer_kv LINE - LINE is `            "key": "value",` (or a
# non-string scalar); sets _SCA_COMPOSER_KEY and _SCA_COMPOSER_VALUE (quotes
# stripped and unescaped via engine.sh's own `_sca_json_unescape`/
# `_sca_json_scalar_str`).  Both are set to '' when LINE is not a
# `"key": value` line (e.g. a nested `"source": {` open, or `},`/`]`
# structural punctuation) - the caller only acts on a non-empty key.
_sca_composer_kv() {
  local line=$1 t
  t="${line#"${line%%[![:space:]]*}"}"
  if [[ $t =~ ^\"((\\.|[^\"\\])*)\"[[:space:]]*:[[:space:]]*(.*)$ ]]; then
    local key value
    key=$(_sca_json_unescape "${BASH_REMATCH[1]}")
    value=${BASH_REMATCH[3]}
    value=${value%,}
    _SCA_COMPOSER_KEY=$key
    _SCA_COMPOSER_VALUE=$(_sca_json_scalar_str "$value")
  else
    _SCA_COMPOSER_KEY=''
    _SCA_COMPOSER_VALUE=''
  fi
}

# sca_parse_composer_lock FILE - prints one
# `name<0x1F>version<0x1F>direct|transitive|unknown` row per package found in
# either FILE's "packages" or "packages-dev" array.  DIR (FILE's own
# directory) is checked for a sibling composer.json via
# `sca_composer_direct_deps`: when present, a package whose NORMALISED name
# (lowercase - see section 2) matches a normalised entry from composer.json's
# `require`/`require-dev` is `direct`, every other package composer.lock
# lists is `transitive`.  With no composer.json, every package is `unknown`
# - composer.lock's own prod/dev split is not a direct/transitive signal
# (both arrays list the FULL resolved graph, direct and transitive alike,
# the same as npm's "packages" map), and unlike npm's node_modules path
# nesting, a flat array carries no positional hint to fall back to, so
# guessing here would be dishonest rather than a documented heuristic (this
# ticket's own acceptance criterion: absent composer.json, "unknown").
#
# The emitted `name` is the RAW, verbatim name as composer.lock spells it -
# normalisation is applied here only for the internal direct-set comparison,
# and again by the caller (sca_scan_tree, engine.sh) immediately before the
# advisories.db lookup, exactly mirroring how npm's own parsers emit raw
# names and `sca_scan_tree` normalises once at the lookup call site.
sca_parse_composer_lock() {
  local file=$1 dir
  dir=$(dirname -- "$file")
  local -A direct_set=()
  local has_direct_set=0 line norm
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    norm=$(sca_composer_normalize_name "$line")
    direct_set[$norm]=1
    has_direct_set=1
  done < <(sca_composer_direct_deps "$dir")

  local indent t section='' cur_name='' cur_version='' status cur_norm
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    indent=$(_sca_composer_indent "$line")
    t="${line#"${line%%[![:space:]]*}"}"
    if (( indent == 4 )); then
      case $t in
        '"packages": ['*) section=packages ;;
        '"packages-dev": ['*) section=packages-dev ;;
        *) section='' ;;
      esac
      continue
    fi
    [[ -n $section ]] || continue
    if (( indent == 8 )); then
      case $t in
        '{'*)
          cur_name=''
          cur_version=''
          ;;
        '},' | '}')
          if [[ -n $cur_name && -n $cur_version ]]; then
            if (( ! has_direct_set )); then
              status=unknown
            else
              cur_norm=$(sca_composer_normalize_name "$cur_name")
              if [[ -n ${direct_set[$cur_norm]:-} ]]; then
                status=direct
              else
                status=transitive
              fi
            fi
            printf '%s\x1f%s\x1f%s\n' "$cur_name" "$cur_version" "$status"
          fi
          cur_name=''
          cur_version=''
          ;;
      esac
      continue
    fi
    if (( indent == 12 )); then
      _sca_composer_kv "$line"
      case $_SCA_COMPOSER_KEY in
        name) cur_name=$_SCA_COMPOSER_VALUE ;;
        version) cur_version=$_SCA_COMPOSER_VALUE ;;
      esac
    fi
  done <"$file"
}
