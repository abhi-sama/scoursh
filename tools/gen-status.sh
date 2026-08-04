#!/usr/bin/env bash
# tools/gen-status.sh - generate the module status inventory that AGENTS.md and
# docs/FOUNDATION.md both carry, from the repository itself.
#
# Owns, in each case the block between the two markers and nothing else:
#   AGENTS.md          "Build order and where we are"
#   README.md          "Current status: what running a scan does today"
#   docs/FOUNDATION.md "Where the build currently stands"
#
# WHY THIS EXISTS.  Both files used to state the module inventory as prose, and
# the prose stated NEGATIVES and DERIVED FACTS: "neither has landed yet",
# "nothing beyond nosql.rules/ldap.rules remains", "modules/ now ships nine
# pattern packs".  A negative claim about N modules has to be rewritten when ANY
# of the N lands, so N concurrent branches all edit the same sentences and
# conflict by construction - one rescue PR needed three rebases, conflicting on
# exactly these two files every time.  Worse, the claims went stale silently:
# three separate tickets landed a module without updating them, and a whole
# ticket existed only to correct text that a generator would never have got
# wrong.  So the inventory is computed here and spliced between markers, and
# `tests/lint-status.sh` fails the suite when the committed block differs from a
# fresh generation.  Staleness is now impossible rather than merely discouraged.
#
#   tools/gen-status.sh            # print the block to stdout
#   tools/gen-status.sh --write    # splice it into all three files
#   tools/gen-status.sh --check    # exit 1 if any committed block is stale
#
# WHAT COUNTS AS LANDED, stated here because deriving from the filesystem alone
# would let a file that no test has ever run read as "landed":
#
#   1. the artifact exists at its path under modules/, AND
#   2. the test tree exercises it -
#        rule pack      : at least one check id the pack itself declares appears
#                         in a tests/**/*.sh suite;
#        script         : its basename appears in a tests/**/*.sh suite;
#        SCA ecosystem  : every manifest filename docs/DESIGN.md §6.5 names for
#                         it appears in modules/sca/*.sh, and a fixture file
#                         named for one of them exists under tests/fixtures/.
#
# Both halves are checked on every run, so the rule is one the repository can
# actually enforce rather than a convention.  An artifact that satisfies (1) but
# not (2) is reported "present, untested" - its own state, never rounded up to
# landed.  An ecosystem whose manifests are only partly implemented is "partial".
#
# WHAT IS PLANNED comes from docs/DESIGN.md's own catalog, parsed here, not from
# a list typed into this script:
#
#   §6.3  the per-language SAST catalog        -> modules/sast/rules/*.rules
#   §6.5  the SCA manifest/lockfile bullet     -> modules/sca/
#   §6.6  the container/orchestration catalog  -> modules/iac/*.rules
#   §8.2  the cloud-IaC bullet (Terraform, CloudFormation) -> modules/iac/*.rules
#
# §8.2 is the one section that names its two formats in prose ("*.tf",
# "(CloudFormation)") rather than as artifact names, so its two entries are
# spelled out below - and asserted against the section's own text on every run,
# so the transcription cannot silently drift from the spec it transcribes.
#
# NO LANDING IS EVER IDENTIFIED BY A COMMIT SHA.  A ticket cannot know its own
# landing sha (the squash merge mints it afterwards) and two invented shas have
# already shipped into these files and had to be corrected.  Artifacts are
# identified by PATH, which is knowable at the time of writing and stays true.
#
# shellcheck shell=bash
#
# SC2016: this script's output is markdown, so single-quoted format strings are
# full of literal backticks that are not meant to expand.
# shellcheck disable=SC2016

set -Eeuo pipefail

GS_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$GS_ROOT/lib/core.sh"
cd "$GS_ROOT"

GS_BEGIN='<!-- BEGIN GENERATED STATUS -->'
GS_END='<!-- END GENERATED STATUS -->'
GS_TARGETS=(AGENTS.md README.md docs/FOUNDATION.md)

GS_HITS=$SCOURSH_SCRATCH/gen-status-hits

# ---------------------------------------------------------------------------
# 1. Reading docs/DESIGN.md
# ---------------------------------------------------------------------------
# `gs_section HEADING-PREFIX` prints the body lines of one `###` section, from
# the line after its heading to the line before the next heading at any level.
gs_section() {
  local want=$1 line inside=0
  while IFS= read -r line; do
    if (( inside )); then
      if [[ $line == '#'* ]]; then break; fi
      printf '%s\n' "$line"
      continue
    fi
    if [[ $line == "$want"* ]]; then inside=1; fi
  done <docs/DESIGN.md
  (( inside )) || die "$SCOURSH_EXIT_INPUT" "docs/DESIGN.md has no section '$want'"
}

# The bolded lead of a catalog bullet: `- **nosql.rules / ldap.rules** - ...`
# yields `nosql.rules / ldap.rules`.  A bullet with no bolded lead is prose
# about the section rather than a catalog entry, and is skipped.
gs_bullet_lead() {
  local line=$1 rest
  [[ $line == '- **'* ]] || return 1
  rest=${line#- \*\*}
  [[ $rest == *'**'* ]] || return 1
  printf '%s\n' "${rest%%\*\**}"
}

# The catalog spells two artifacts in one bullet with a SPACED slash
# (`nosql.rules / ldap.rules`, `docker-compose / Helm values`), and alternative
# spellings of ONE artifact with a bare slash (`javascript/ts`).  Splitting on
# the spaced slash and then taking the part before any bare slash is what keeps
# `javascript/ts` from inventing a second, unplanned `ts.rules`.
gs_lead_to_artifacts() {
  local lead=$1 part token
  while [[ -n $lead ]]; do
    if [[ $lead == *' / '* ]]; then
      part=${lead%% / *}
      lead=${lead#* / }
    else
      part=$lead
      lead=''
    fi
    token=${part%% *}      # "Kubernetes manifests" -> "Kubernetes"
    token=${token%%/*}     # "javascript/ts"        -> "javascript"
    token=${token,,}
    [[ -n $token ]] || continue
    if [[ $token == *.rules || $token == *.sh ]]; then
      printf '%s\n' "$token"
    else
      printf '%s.rules\n' "$token"
    fi
  done
}

gs_catalog_from_section() {
  local heading=$1 line lead
  while IFS= read -r line; do
    lead=$(gs_bullet_lead "$line") || continue
    gs_lead_to_artifacts "$lead"
  done < <(gs_section "$heading")
}

# §6.5 names its ecosystems as comma-separated groups of backticked manifest
# filenames, so the groups ARE the planned ecosystems - no ecosystem-name table
# is needed, and adding one to the spec adds a row here for free.
gs_sca_catalog() {
  local line body group seg tok out
  body=''
  while IFS= read -r line; do
    if [[ $line == '- Parse dependency manifests/lockfiles:'* ]]; then
      body=${line#*: }
      break
    fi
  done < <(gs_section '### 6.5 ')
  [[ -n $body ]] || die "$SCOURSH_EXIT_INPUT" \
    "docs/DESIGN.md §6.5 no longer opens with its manifest/lockfile bullet"
  body=${body%.}
  while [[ -n $body ]]; do
    if [[ $body == *', '* ]]; then
      group=${body%%, *}
      body=${body#*, }
    else
      group=$body
      body=''
    fi
    seg=$group
    out=''
    while [[ $seg == *'`'*'`'* ]]; do
      seg=${seg#*\`}
      tok=${seg%%\`*}
      seg=${seg#*\`}
      out+="${out:+ }$tok"
    done
    if [[ -n $out ]]; then printf '%s\n' "$out"; fi
  done
  return 0
}

# §8.2's two formats, asserted against the section's own wording so this
# transcription cannot outlive the text it transcribes.
gs_iac_spec_extra() {
  local body
  body=$(gs_section '### 8.2 ')
  [[ $body == *'*.tf'* ]] || die "$SCOURSH_EXIT_INPUT" \
    "docs/DESIGN.md §8.2 no longer names Terraform (\`*.tf\`)"
  [[ $body == *'CloudFormation'* ]] || die "$SCOURSH_EXIT_INPUT" \
    "docs/DESIGN.md §8.2 no longer names CloudFormation"
  printf 'terraform.rules\ncloudformation.rules\n'
}

# ---------------------------------------------------------------------------
# 2. Reading the repository
# ---------------------------------------------------------------------------
# The witness search walks these in order and stops at the first hit, so the
# order IS the output: `tests/suites/` first (the named suites, the most useful
# thing to cite), then everything else under tests/, each half in LC_ALL=C order.
GS_TEST_FILES=()
gs_load_test_files() {
  local f
  # `find` over a directory that does not exist fails, and under pipefail takes
  # the whole pipeline with it, so every root is tested before it is walked.
  if [[ -d tests/suites ]]; then
    while IFS= read -r f; do
      if [[ -n $f ]]; then GS_TEST_FILES+=("$f"); fi
    done < <(find tests/suites -type f -name '*.sh' | LC_ALL=C sort)
  fi
  [[ -d tests ]] || die "$SCOURSH_EXIT_INPUT" "no tests/ directory to read coverage from"
  while IFS= read -r f; do
    if [[ -n $f && $f != tests/suites/* ]]; then GS_TEST_FILES+=("$f"); fi
  done < <(find tests -type f -name '*.sh' | LC_ALL=C sort)
  (( ${#GS_TEST_FILES[@]} > 0 )) || die "$SCOURSH_EXIT_INPUT" "no test suites found under tests/"
}

# `gs_first_match PATTERN FILE...` - the first file, in the order GIVEN, whose
# text matches; non-zero and silent when none does.
#
# The engine is asked one file at a time ON PURPOSE.  Handing the whole list to
# `scan_match ... -l` and taking the first line back is what a first draft did,
# and it is NOT deterministic: ripgrep searches in parallel and emits filenames
# in completion order, so the same tree produced `tests/suites/sast.sh` on one
# run and `tests/suites/records.sh` on the next - measured here, and caught by
# tests/lint-status.sh's own diff.  A generated file that differs between two
# runs of the generator is worse than no generator, and this repository's CI
# compares generated bytes across two userlands.  Iterating in a fixed order and
# stopping at the first hit is the fix; the file count is small enough that the
# cost does not matter.
gs_first_match() {
  local pattern=$1 f
  shift
  for f in "$@"; do
    if scan_match "$GS_HITS" -e "$pattern" -- "$f"; then
      printf '%s\n' "${f#./}"
      return 0
    fi
  done
  return 1
}

gs_tests_name() {
  gs_first_match "$1" "${GS_TEST_FILES[@]+"${GS_TEST_FILES[@]}"}"
}

# Every check id a rule pack declares, in file order.
#
# The `if` is not stylistic: `[[ ... ]] && printf` as the loop's last command
# makes the whole loop exit non-zero whenever the file's last line is not an id,
# which under `set -Eeuo pipefail` is an ERR trap and a failed run.
gs_pack_ids() {
  local file=$1 line
  while IFS= read -r line; do
    if [[ $line == 'id: '* ]]; then
      printf '%s\n' "${line#id: }"
    fi
  done <"$file"
  return 0
}

# ---------------------------------------------------------------------------
# 3. Classifying one artifact
# ---------------------------------------------------------------------------
# Sets GS_STATUS, GS_DETAIL (checks column) and GS_WITNESS (the suite that
# exercises it).  A function rather than a printed value because a side-effecting
# function called as $(f) runs in a subshell and its writes are discarded.
GS_STATUS=''
GS_DETAIL=''
GS_WITNESS=''

gs_classify_pack() {
  local path=$1 id count=0 witness='' pattern=''
  GS_STATUS='not landed'
  GS_DETAIL='-'
  GS_WITNESS='-'
  [[ -f $path ]] || return 0
  # One alternation over every id the pack declares, so the witness is the first
  # SUITE that exercises any of them rather than an artefact of which id happens
  # to be listed first.  Check ids are `[A-Z0-9_-]+`, which carries no ERE
  # metacharacter, so they need no escaping.
  while IFS= read -r id; do
    count=$((count + 1))
    pattern+="${pattern:+|}$id"
  done < <(gs_pack_ids "$path")
  if [[ -n $pattern ]]; then
    witness=$(gs_tests_name "$pattern") || witness=''
  fi
  GS_DETAIL=$count
  if [[ -n $witness ]]; then
    GS_STATUS='landed'
    GS_WITNESS=$witness
  else
    GS_STATUS='present, untested'
  fi
}

gs_classify_script() {
  local path=$1 witness
  GS_STATUS='not landed'
  GS_DETAIL='-'
  GS_WITNESS='-'
  [[ -f $path ]] || return 0
  # A basename is a literal here; `.` is the only ERE metacharacter it can
  # carry, and matching one literal dot as "any byte" cannot change a verdict.
  if witness=$(gs_tests_name "${path##*/}"); then
    GS_STATUS='landed'
    GS_WITNESS=$witness
  else
    GS_STATUS='present, untested'
  fi
}

# An SCA ecosystem is a manifest group rather than a file, so both halves of the
# landed rule are asked of the group: is every manifest parsed, and is at least
# one of them exercised by a real fixture file on disk.
gs_classify_ecosystem() {
  local manifests=$1 m present=0 total=0 fixture='' found cand
  GS_STATUS='not landed'
  GS_DETAIL='-'
  GS_WITNESS='-'
  for m in $manifests; do
    total=$((total + 1))
    if gs_module_names_manifest "$m"; then
      present=$((present + 1))
    fi
    if [[ -z $fixture && -d tests/fixtures ]]; then
      # First in LC_ALL=C order, read rather than `head`-ed: `head` closing the
      # pipe early is a SIGPIPE the surrounding pipefail would report as failure.
      found=''
      while IFS= read -r cand; do
        if [[ -n $cand && -z $found ]]; then found=$cand; fi
      done < <(find tests/fixtures -type f -name "$m" | LC_ALL=C sort)
      if [[ -n $found ]]; then fixture=$found; fi
    fi
  done
  GS_DETAIL="$present of $total parsed"
  if (( present == 0 )); then
    return 0
  fi
  if [[ -z $fixture ]]; then
    GS_STATUS='present, untested'
    return 0
  fi
  GS_WITNESS=$fixture
  if (( present == total )); then
    GS_STATUS='landed'
  else
    GS_STATUS='partial'
  fi
}

GS_SCA_FILES=()
gs_module_names_manifest() {
  local m=$1 pattern
  (( ${#GS_SCA_FILES[@]} > 0 )) || return 1
  # A manifest filename is a literal; escaping its dots keeps `go.mod` from
  # also matching a hypothetical `goXmod`.
  pattern=${m//./\\.}
  gs_first_match "$pattern" "${GS_SCA_FILES[@]+"${GS_SCA_FILES[@]}"}" >/dev/null
}

gs_load_sca_files() {
  local f
  [[ -d modules/sca ]] || return 0
  while IFS= read -r f; do
    if [[ -n $f ]]; then GS_SCA_FILES+=("$f"); fi
  done < <(find modules/sca -type f -name '*.sh' | LC_ALL=C sort)
}

# ---------------------------------------------------------------------------
# 4. Rendering
# ---------------------------------------------------------------------------
gs_row() {
  printf '| `%s` | %s | %s | %s |\n' "$1" "$2" "$3" "$(gs_code_or_dash "$4")"
}

# A space-separated list rendered as `a`, `b`, `c`.
gs_code_list() {
  local item out=''
  for item in $1; do out+="${out:+, }\`$item\`"; done
  printf '%s' "${out:--}"
}

gs_code_or_dash() {
  if [[ $1 == - ]]; then printf -- '-'; else printf '`%s`' "$1"; fi
}

# Anything on disk that the parsed catalog does not name is still reported,
# rather than silently dropped: a pack that arrives ahead of the spec must show
# up as an inventory line, not as a gap between two files nobody diffs.
gs_extra_packs() {
  local dir=$1 f base planned
  shift
  planned=" $* "
  [[ -d $dir ]] || return 0
  while IFS= read -r f; do
    base=${f##*/}
    if [[ $planned == *" $base "* ]]; then continue; fi
    printf '%s\n' "$base"
  done < <(find "$dir" -type f -name '*.rules' | LC_ALL=C sort)
  return 0
}

gs_render() {
  local a kind landed total remaining
  local planned=()
  local sast_packs=0 iac_packs=0

  printf '%s\n' "$GS_BEGIN"
  cat <<'EOF'
<!--
  GENERATED by tools/gen-status.sh.  Everything between these two markers is
  machine-written from the repository tree and docs/DESIGN.md's own catalog.

  Do not hand-edit inside the markers: run `tools/gen-status.sh --write`.
  `tests/lint-status.sh` (run by `tests/run-tests.sh`) fails when a committed
  block differs from a fresh generation, so an edit here is a broken build.

  A MERGE CONFLICT INSIDE THIS BLOCK IS NEVER RESOLVED BY HAND.  Take either
  side of the conflict, then re-run `tools/gen-status.sh --write`.
-->

### Module status inventory (generated)

What is PLANNED is parsed from `docs/DESIGN.md`'s own catalog (§6.3 SAST, §6.5
SCA, §6.6 and §8.2 IaC).  What has LANDED is read off the repository tree.  What
REMAINS is the difference, computed rather than typed - which is why no sentence
in here has to be rewritten when a module lands, and why two branches landing
different modules cannot conflict over it.

**Landed** means both halves hold, and both are checked on every run:

1. the artifact exists at its path under `modules/`, and
2. the test tree exercises it - for a rule pack, at least one check id the pack
   itself declares appears in a `tests/**/*.sh` suite; for a script, its
   basename does; for an SCA ecosystem, every manifest `docs/DESIGN.md` §6.5
   names for it is parsed under `modules/sca/` and at least one has a real
   fixture file under `tests/fixtures/`.

A file that is present but that no suite names is **present, untested** - its own
state, never rounded up to landed.  Artifacts are identified by PATH and never by
a commit sha: a ticket cannot know its own landing sha, and invented ones have
shipped here before.

EOF

  # --- SAST -----------------------------------------------------------------
  planned=()
  while IFS= read -r a; do
    if [[ -n $a ]]; then planned+=("$a"); fi
  done < <(gs_catalog_from_section '### 6.3 ' | LC_ALL=C sort -u)
  printf '#### SAST - `docs/DESIGN.md` §6.3 catalog -> `modules/sast/`\n\n'
  printf '| Artifact | Status | Checks | Exercised by |\n'
  printf -- '| --- | --- | --- | --- |\n'
  landed=0
  total=0
  remaining=''
  # Rule packs first, then the scripts §6.3 also lists, so the table reads as an
  # inventory of one kind of thing at a time rather than interleaving them by
  # basename (`history.sh` would otherwise sort between `go` and `injection`).
  for kind in rules sh; do
    for a in "${planned[@]+"${planned[@]}"}"; do
      if [[ $kind == sh && $a != *.sh ]]; then continue; fi
      if [[ $kind == rules && $a == *.sh ]]; then continue; fi
      total=$((total + 1))
      if [[ $a == *.sh ]]; then
        gs_classify_script "modules/sast/$a"
        gs_row "modules/sast/$a" "$GS_STATUS" "$GS_DETAIL" "$GS_WITNESS"
      else
        gs_classify_pack "modules/sast/rules/$a"
        gs_row "modules/sast/rules/$a" "$GS_STATUS" "$GS_DETAIL" "$GS_WITNESS"
      fi
      if [[ $GS_STATUS == landed ]]; then
        landed=$((landed + 1))
      else
        remaining+="${remaining:+, }\`$a\`"
      fi
    done
  done
  while IFS= read -r a; do
    [[ -n $a ]] || continue
    total=$((total + 1))
    gs_classify_pack "modules/sast/rules/$a"
    gs_row "modules/sast/rules/$a" "$GS_STATUS (not in the §6.3 catalog)" "$GS_DETAIL" "$GS_WITNESS"
    if [[ $GS_STATUS == landed ]]; then landed=$((landed + 1)); fi
  done < <(gs_extra_packs modules/sast/rules "${planned[@]+"${planned[@]}"}")
  printf '\nLanded %d of %d.  Outstanding: %s.\n\n' "$landed" "$total" "${remaining:-none}"

  # --- SCA ------------------------------------------------------------------
  printf '#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`\n\n'
  printf '| Manifests | Status | Parsers | Exercised by |\n'
  printf -- '| --- | --- | --- | --- |\n'
  landed=0
  total=0
  remaining=''
  while IFS= read -r a; do
    [[ -n $a ]] || continue
    total=$((total + 1))
    gs_classify_ecosystem "$a"
    printf '| %s | %s | %s | %s |\n' \
      "$(gs_code_list "$a")" "$GS_STATUS" "$GS_DETAIL" "$(gs_code_or_dash "$GS_WITNESS")"
    if [[ $GS_STATUS == landed ]]; then
      landed=$((landed + 1))
    else
      remaining+="${remaining:+, }\`${a%% *}\`"
    fi
  done < <(gs_sca_catalog)
  printf '\nLanded %d of %d.  Outstanding: %s.\n\n' "$landed" "$total" "${remaining:-none}"

  # --- IaC ------------------------------------------------------------------
  planned=()
  while IFS= read -r a; do
    if [[ -n $a ]]; then planned+=("$a"); fi
  done < <( { gs_catalog_from_section '### 6.6 '; gs_iac_spec_extra; } | LC_ALL=C sort -u)
  printf '#### IaC rule packs - `docs/DESIGN.md` §6.6 and §8.2 -> `modules/iac/`\n\n'
  printf '| Artifact | Status | Checks | Exercised by |\n'
  printf -- '| --- | --- | --- | --- |\n'
  landed=0
  total=0
  remaining=''
  for a in "${planned[@]+"${planned[@]}"}"; do
    total=$((total + 1))
    gs_classify_pack "modules/iac/$a"
    gs_row "modules/iac/$a" "$GS_STATUS" "$GS_DETAIL" "$GS_WITNESS"
    if [[ $GS_STATUS == landed ]]; then
      landed=$((landed + 1))
    else
      remaining+="${remaining:+, }\`$a\`"
    fi
  done
  while IFS= read -r a; do
    [[ -n $a ]] || continue
    total=$((total + 1))
    gs_classify_pack "modules/iac/$a"
    gs_row "modules/iac/$a" "$GS_STATUS (not in the §6.6/§8.2 catalog)" "$GS_DETAIL" "$GS_WITNESS"
    if [[ $GS_STATUS == landed ]]; then landed=$((landed + 1)); fi
  done < <(gs_extra_packs modules/iac "${planned[@]+"${planned[@]}"}")
  printf '\nLanded %d of %d.  Outstanding: %s.\n\n' "$landed" "$total" "${remaining:-none}"

  # --- totals ---------------------------------------------------------------
  sast_packs=$(gs_count_packs modules/sast/rules)
  iac_packs=$(gs_count_packs modules/iac)
  printf '#### Totals\n\n'
  printf -- '- Pattern packs on disk: **%d** (`modules/sast/rules/` %d, `modules/iac/` %d).\n' \
    "$((sast_packs + iac_packs))" "$sast_packs" "$iac_packs"
  printf -- '- Module directories present: %s.\n' "$(gs_module_dirs)"
  printf '\n'
  printf '%s\n' "$GS_END"
}

gs_count_packs() {
  local dir=$1 n=0 f
  [[ -d $dir ]] || { printf '0'; return 0; }
  while IFS= read -r f; do
    if [[ -n $f ]]; then n=$((n + 1)); fi
  done < <(find "$dir" -type f -name '*.rules')
  printf '%d' "$n"
}

gs_module_dirs() {
  local d out=''
  [[ -d modules ]] || { printf 'none'; return 0; }
  while IFS= read -r d; do
    [[ -n $d ]] || continue
    out+="${out:+, }\`${d#./}/\`"
  done < <(find modules -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
  printf '%s' "${out:-none}"
}

# ---------------------------------------------------------------------------
# 5. Splicing and checking
# ---------------------------------------------------------------------------
# `gs_extract FILE` - the committed block, markers included.
gs_extract() {
  local file=$1 line inside=0 seen=0
  while IFS= read -r line; do
    if (( inside )); then
      printf '%s\n' "$line"
      [[ $line == "$GS_END" ]] && { inside=0; continue; }
      continue
    fi
    if [[ $line == "$GS_BEGIN" ]]; then
      inside=1
      seen=1
      printf '%s\n' "$line"
    fi
  done <"$file"
  (( seen )) || die "$SCOURSH_EXIT_INPUT" "$file carries no '$GS_BEGIN' marker"
  (( inside == 0 )) || die "$SCOURSH_EXIT_INPUT" "$file has an unterminated generated block"
}

gs_splice() {
  local file=$1 block=$2 line inside=0 seen=0
  local out=$SCOURSH_SCRATCH/gen-status-out
  : >"$out"
  while IFS= read -r line; do
    if (( inside )); then
      [[ $line == "$GS_END" ]] && inside=0
      continue
    fi
    if [[ $line == "$GS_BEGIN" ]]; then
      inside=1
      seen=1
      cat -- "$block" >>"$out"
      continue
    fi
    printf '%s\n' "$line" >>"$out"
  done <"$file"
  (( seen )) || die "$SCOURSH_EXIT_INPUT" "$file carries no '$GS_BEGIN' marker"
  (( inside == 0 )) || die "$SCOURSH_EXIT_INPUT" "$file has an unterminated generated block"
  cat -- "$out" >"$file"
}

# `--write` and `--check` take optional file arguments so a test can point them
# at a COPY of a target and perturb it.  A guard that can only ever be run
# against the two committed files cannot be proved to bite without editing them,
# and a check nobody has watched fail is not known to be a check at all
# (tests/lint-status.sh does exactly that).
gs_main() {
  local mode=${1:-print}
  local block=$SCOURSH_SCRATCH/gen-status-block
  local committed=$SCOURSH_SCRATCH/gen-status-committed
  local file rc=0
  local targets=()

  gs_load_test_files
  gs_load_sca_files
  gs_render >"$block"

  if (( $# > 1 )); then
    shift
    targets=("$@")
  else
    targets=("${GS_TARGETS[@]+"${GS_TARGETS[@]}"}")
  fi

  case $mode in
    print)
      cat -- "$block"
      ;;
    --write)
      for file in "${targets[@]+"${targets[@]}"}"; do
        gs_splice "$file" "$block"
        printf 'gen-status: wrote %s\n' "$file"
      done
      ;;
    --check)
      for file in "${targets[@]+"${targets[@]}"}"; do
        gs_extract "$file" >"$committed"
        if diff -u -- "$committed" "$block" >"$SCOURSH_SCRATCH/gen-status-diff"; then
          printf '  ok  %s\n' "$file"
        else
          rc=1
          printf '%s\n' "gen-status: $file's generated block is stale or hand-edited." >&2
          printf '%s\n' "  --- committed (left) versus freshly generated (right):" >&2
          cat -- "$SCOURSH_SCRATCH/gen-status-diff" >&2
          printf '%s\n' "  Fix it with: tools/gen-status.sh --write" >&2
        fi
      done
      return "$rc"
      ;;
    -h | --help)
      printf '%s\n' \
        'usage: tools/gen-status.sh [--write | --check] [FILE...]' \
        '  (no argument)  print the generated block to stdout' \
        '  --write        splice it into AGENTS.md, README.md and docs/FOUNDATION.md' \
        '  --check        exit 1 if any committed block is stale' \
        '  FILE...        operate on these files instead of the defaults'
      ;;
    *)
      die "$SCOURSH_EXIT_USAGE" "unknown argument: $mode (try --help)"
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
  gs_main "$@"
fi
