#!/usr/bin/env bash
# tests/lint-rules.sh - the record-format linter.
#
# Implements the rules/RULE-FORMAT.md §13 checks that apply at §13 step 1.
# Error codes are §13's; nothing here invents one.
#
# Per-record checks (§3-§10) live in lib/records.sh, because the parser itself
# needs the schema to classify a line at all.  This script adds the checks that
# need the WHOLE repository: the check-id namespace (E019), contributor
# existence and chaining (E051, E052), correlation-key capability (E053), the
# rubric's (fact, equals) uniqueness (E075), the posture cross-references (E077,
# E078), the target cross-references (E080), and retirement (E028, E062).
#
# Not yet applicable, and stated rather than silently skipped:
#   E060 / W061 - a rule needs a true-positive fixture and must stay quiet on
#                 the clean one.  Scoped to shipped pattern packs under
#                 modules/, of which §13 step 1 ships none; the check runs and
#                 reports zero, and step 3 is where it starts biting.
#   E046        - only meaningful for a declared `pcre` dialect when a PCRE2
#                 engine exists; the ERE half runs here.
#   E072 / E073 - `script:` paths and config/auth.conf permissions, neither of
#                 which exists before §13 steps 5 and 6.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose names subcommands in backticks.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"

cd "$ROOT"

FAILED=0
note() { printf '%s\n' "$*"; }
fail() {
  FAILED=1
  printf '%s\n' "$*" >&2
}

# ---------------------------------------------------------------------------
# 1. Which files are record files
# ---------------------------------------------------------------------------
# Repository record files take their schema from the §9 path table.  Test
# fixtures live outside that table by design and declare their schema
# explicitly, exactly as a caller of records_load does.
repo_record_files() {
  local dirs=()
  local d
  for d in rules data config; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  find "${dirs[@]}" -type f \
    \( -name '*.rules' -o -name '*.conf' -o -name '*.conf.example' \) \
    | LC_ALL=C sort
}

fixture_schema_for() {
  case $1 in
    tests/fixtures/rules/derived.rules) printf '%s' derived ;;
    tests/fixtures/rules/*.rules) printf '%s' pattern-rule ;;
    tests/fixtures/config/scope.conf) printf '%s' scope-target ;;
    tests/fixtures/config/http-scope.conf) printf '%s' scope-target ;;
    *) return 1 ;;
  esac
}

fixture_record_files() {
  [[ -d tests/fixtures ]] || return 0
  find tests/fixtures -type f \( -name '*.rules' -o -name '*.conf' \) | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# 2. Parse and validate every one of them
# ---------------------------------------------------------------------------
declare -A SEEN_CHECK_ID=()       # check id -> file, the §9.1.1a check-id namespace
declare -A DERIVED_IDS=()
DERIVED_FILES=()

lint_one() {
  local f=$1 schema=$2 set=lintset
  records_reset_diagnostics
  if ! records_load "$f" "$schema" "$set"; then
    fail "$f: failed to parse"
    return 1
  fi
  if ! records_validate "$set"; then
    fail "$f: failed schema validation"
  fi
  local n i id
  n=$(records_count "$set")
  schema=$(records_schema "$set")
  for (( i = 0; i < n; i++ )); do
    id=$(records_id "$set" "$i")
    if records_schema_is_check_id "$schema"; then
      # E019 is scoped to the check-id NAMESPACE, not to every record file in
      # the repository: config/discovery.conf and config/auth.conf ids are
      # REQUIRED to name config/scope.conf targets, so a global rule would make
      # every correct config a lint error (§9.1.1a).
      if [[ -n ${SEEN_CHECK_ID[$id]:-} ]]; then
        fail "$f: E019 $id duplicate check id (also in ${SEEN_CHECK_ID[$id]})"
      else
        SEEN_CHECK_ID[$id]=$f
      fi
      if [[ $schema == derived ]]; then
        DERIVED_IDS[$id]=$f
      fi
    fi
  done
  return 0
}

note '== record files =='
while IFS= read -r f; do
  [[ -n $f ]] || continue
  rel=${f#./}
  if ! records_schema_for_path "$rel" >/dev/null; then
    fail "$rel: E070 record file matches no row of the §9 path table"
    continue
  fi
  if lint_one "$rel" ''; then
    note "  ok  $rel"
  fi
done <<<"$(repo_record_files)"

while IFS= read -r f; do
  [[ -n $f ]] || continue
  rel=${f#./}
  if schema=$(fixture_schema_for "$rel"); then
    if lint_one "$rel" "$schema"; then
      note "  ok  $rel (fixture, schema declared explicitly)"
    fi
    [[ $schema == derived ]] && DERIVED_FILES+=("$rel")
  else
    fail "$rel: no schema declared for this fixture; add it to fixture_schema_for"
  fi
done <<<"$(fixture_record_files)"

# ---------------------------------------------------------------------------
# 3. Cross-file checks
# ---------------------------------------------------------------------------
note '== cross-file =='

# E028 / E062: a retired id may never be reused, and RETIRED.txt may not name an
# id that is still defined.
if [[ -f rules/RETIRED.txt ]]; then
  while IFS= read -r rid; do
    rid=${rid%%#*}
    rid=${rid// /}
    [[ -n $rid ]] || continue
    if [[ -n ${SEEN_CHECK_ID[$rid]:-} ]]; then
      fail "rules/RETIRED.txt: E062 $rid is retired but is still defined in ${SEEN_CHECK_ID[$rid]}"
    fi
  done <rules/RETIRED.txt
  note '  ok  rules/RETIRED.txt'
else
  note '  --  rules/RETIRED.txt absent (no check has been retired yet)'
fi

# E051 / E052 / E053 over every derived record.
#
# §9.2.2's capability table is what makes E053 decidable statically: it governs
# `correlate-on` only, and is a different vocabulary from §9.5.1's
# coverage-scope, which is validated against its own table.
module_can_supply() {
  local module=$1 key=$2
  case $key in
    none) return 0 ;;
    file) case $module in SAST | SCA | IAC) return 0 ;; *) return 1 ;; esac ;;
    target) case $module in DAST | CLOUD | POSTURE) return 0 ;; *) return 1 ;; esac ;;
    account | account-region) case $module in CLOUD | POSTURE) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}

lint_derived_file() {
  local f=$1 schema=$2
  records_reset_diagnostics
  records_load "$f" "$schema" dset >/dev/null 2>&1 || return 0
  local n i id corr c
  n=$(records_count dset)
  for (( i = 0; i < n; i++ )); do
    id=$(records_id dset "$i")
    corr=$(records_field dset "$i" correlate-on)
    while IFS= read -r c; do
      [[ -n $c ]] || continue
      if [[ -z ${SEEN_CHECK_ID[$c]:-} ]]; then
        fail "$f: E051 $id names contributor '$c', which no record defines"
      elif [[ -n ${DERIVED_IDS[$c]:-} ]]; then
        fail "$f: E052 $id names derived contributor '$c'; composites may not chain"
      fi
      if ! module_can_supply "${c%%-*}" "$corr"; then
        fail "$f: E053 $id correlate-on '$corr' is a key module ${c%%-*} cannot supply (§9.2.2)"
      fi
    done <<<"$(records_list dset "$i" requires)
$(records_list dset "$i" any-of)"
  done
}

if [[ -f rules/derived.rules ]]; then
  lint_derived_file rules/derived.rules derived
  note '  ok  rules/derived.rules contributors'
else
  # docs/FOUNDATION.md open findings F5 and F20: seeding COMPOSITE-TOKEN-HIJACK
  # at §13 step 1 is a guaranteed E051 failure, because its contributors do not
  # exist until steps 5 and 6.  The seed is therefore deferred, deliberately.
  note '  --  rules/derived.rules is not seeded yet (F5/F20); its contributors arrive at §13 steps 5 and 6'
fi
for f in "${DERIVED_FILES[@]+"${DERIVED_FILES[@]}"}"; do
  # A fixture composite's contributors are fixture check ids, which are in the
  # namespace, so the same rules apply.
  lint_derived_file "$f" derived
  note "  ok  $f contributors"
done

# E075: two data/severity-rubric.conf records sharing a (fact, equals) pair
# would make the sum order-dependent.
if [[ -f data/severity-rubric.conf ]]; then
  records_load data/severity-rubric.conf severity-modifier rub >/dev/null 2>&1
  declare -A PAIR=()
  n=$(records_count rub)
  for (( i = 0; i < n; i++ )); do
    key="$(records_field rub "$i" fact)|$(records_field rub "$i" equals)"
    if [[ -n ${PAIR[$key]:-} ]]; then
      fail "data/severity-rubric.conf: E075 duplicate (fact, equals) pair '$key'"
    fi
    PAIR[$key]=1
    mod=$(records_field rub "$i" modifier)
    if [[ ! $mod =~ ^[+-]?[0-4]$ ]]; then
      fail "data/severity-rubric.conf: E024 modifier '$mod' is outside -4..+4"
    fi
  done
  note '  ok  data/severity-rubric.conf (fact, equals) uniqueness'
fi

# E080: a config/discovery.conf or config/auth.conf id must name a target that
# config/scope.conf defines.  E077 / E078: the posture cross-references.
if [[ -f config/scope.conf ]]; then
  records_load config/scope.conf scope-target sc >/dev/null 2>&1
  declare -A TARGETS=()
  n=$(records_count sc)
  for (( i = 0; i < n; i++ )); do TARGETS[$(records_id sc "$i")]=1; done
  for cf in config/discovery.conf config/auth.conf; do
    [[ -f $cf ]] || continue
    schema=$(records_schema_for_path "$cf")
    records_load "$cf" "$schema" cfset >/dev/null 2>&1
    n=$(records_count cfset)
    for (( i = 0; i < n; i++ )); do
      id=$(records_id cfset "$i")
      t=${id%%.*}
      [[ -n ${TARGETS[$t]:-} ]] \
        || fail "$cf: E080 id '$id' names target '$t', which config/scope.conf does not define"
    done
  done
  note '  ok  config cross-references'
else
  note '  --  config/scope.conf absent (only `dast` requires it, tension 14)'
fi

if [[ -f config/posture.conf ]]; then
  records_load config/posture.conf posture-expectation pex >/dev/null 2>&1
  declare -A PPAIR=()
  n=$(records_count pex)
  for (( i = 0; i < n; i++ )); do
    ck=$(records_field pex "$i" check)
    sk=$(records_field pex "$i" scope-key)
    [[ -n ${SEEN_CHECK_ID[$ck]:-} ]] \
      || fail "config/posture.conf: E077 check '$ck' is defined by no checks.rules"
    if [[ -n ${PPAIR["$ck|$sk"]:-} ]]; then
      fail "config/posture.conf: E078 duplicate (check, scope-key) pair '$ck|$sk'"
    fi
    PPAIR["$ck|$sk"]=1
  done
  note '  ok  config/posture.conf'
fi

# E060 / W061: fixture coverage for shipped pattern packs.
note '== fixture coverage (E060) =='
shipped_patterns=0
if [[ -d modules ]]; then
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    shipped_patterns=$(( shipped_patterns + 1 ))
  done <<<"$(find modules -type f -name '*.rules' | LC_ALL=C sort)"
fi
note "  --  $shipped_patterns shipped pattern packs under modules/ (§13 step 3 seeds the first)"

printf '\n'
if (( FAILED )); then
  printf 'lint-rules: FAILED\n'
  exit 1
fi
printf 'lint-rules: clean\n'
