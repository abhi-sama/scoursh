#!/usr/bin/env bash
# bench/tools/kics.sh - KICS (Checkmarx), IaC.
#
# GATE: `kics scan -p ROOT -q <the queries the install shipped> --report-formats
# json`, no `--include-queries`, no `--exclude-queries`, no custom query
# directory.  Nothing tuned against the corpus - methodology rule R5.
#
# THE QUERY PATH IS EXPLICIT AND IS NOT A TUNING KNOB.  KICS ships its query
# library as data beside the binary rather than compiled into it, and with no
# `--queries-path` and no `KICS_QUERIES_PATH` it looks in `./assets/queries`
# relative to the CURRENT DIRECTORY and finds nothing - a run that reports zero
# findings and exit 0, which reads as "KICS found nothing wrong with this
# corpus".  `kics_queries_path` resolves the installed library instead, and
# `kics_available` requires it to exist, so the failure mode is a refusal to
# run rather than a silent clean result.
#
# KICS IS THE ONE IaC TOOL HERE THAT PUBLISHES A CWE PER QUERY, and this
# adapter passes it through unchanged.  It has no effect on the B6 IaC leg's
# score - the hand labels carry no CWE, so strict matching is not defined for
# those categories and the scorecard says so in its own cell rather than
# printing zeros - but a normaliser that DISCARDED a field the tool supplies
# would be editing the tool's output, which the raw-output rule exists to
# prevent.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_KICS_SOURCED:-} ]] && return 0
BENCH_TOOL_KICS_SOURCED=1

# kics_queries_path - where this installation keeps its query library.
#
# In precedence order: an operator override, then the two layouts a package
# manager produces (a `libexec`-style prefix beside the binary, and Homebrew's
# `opt/kics/share/kics`).  Printing nothing means "not found", which
# kics_available turns into a refusal.
kics_queries_path() {
  if [[ -n ${BENCH_KICS_QUERIES:-} ]]; then printf '%s' "$BENCH_KICS_QUERIES"; return 0; fi
  local bin tgt dir c
  bin=$(command -v kics 2>/dev/null) || { printf ''; return 0; }
  # A package manager usually installs the binary as a symlink whose target is
  # RELATIVE to the link's own directory (Homebrew writes `../Cellar/...`), so
  # the target has to be resolved against that directory and not against the
  # caller's - which is what turned a working lookup into `cd: ../Cellar/...:
  # No such file or directory` the first time this ran.
  tgt=$(readlink "$bin" 2>/dev/null) || tgt=''
  if [[ -n $tgt ]]; then
    case $tgt in
      /*) bin=$tgt ;;
      *) bin=$(dirname -- "$bin")/$tgt ;;
    esac
  fi
  dir=$(cd -- "$(dirname -- "$bin")" && pwd -P) || { printf ''; return 0; }
  for c in "$dir/../share/kics/assets/queries" "$dir/assets/queries" \
           "$dir/../assets/queries" "$dir/../opt/kics/share/kics/assets/queries"; do
    [[ -d $c ]] && { (cd -- "$c" && pwd -P); return 0; }
  done
  printf ''
}

kics_available() {
  command -v kics >/dev/null 2>&1 || return 1
  local q; q=$(kics_queries_path)
  [[ -n $q && -d $q ]]
}

kics_version() { kics version 2>/dev/null | head -1 | sed 's/.*Secure //' | tr -d '\r'; }

kics_scope() { printf '%s\n' terraform-aws kubernetes; }

kics_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0 q
  q=$(kics_queries_path)
  # KICS uses its exit code to report the highest severity it found - 50 for
  # INFO through 60 for HIGH and above - so a non-zero status here is the
  # normal outcome and only a status outside that band is an error.  Measured
  # on 2.1.21: 60 against the TerraGoat AWS slice.
  kics scan -p "$root" -q "$q" --report-formats json \
    -o "$raw" --output-name kics --no-progress --silent \
    >"$raw/stdout.txt" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 40 | 50 | 60 | 70) ;;
    *) printf 'bench: kics exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2; return 2 ;;
  esac
  [[ -r $raw/kics.json ]] || {
    printf 'bench: kics produced no report under %s\n' "$raw" >&2
    return 2
  }
}

# KICS groups by QUERY: a top-level `queries` array, each entry carrying the
# rule's own metadata once and a `files` array of every place it fired.  So the
# rule id, severity and CWE are on the OUTER object and the file and line on
# the inner one - the mirror image of Trivy's nesting, and the same trap.
kics_normalise() {
  local raw=$1 root=$2
  local f=$raw/kics.json
  [[ -r $f ]] || { printf 'bench: no kics.json under %s\n' "$raw" >&2; return 2; }

  local flat
  flat=$(bench_json_flatten <"$f") || return 2
  bench_flat_read <<<"$flat"

  local i=0 j p rule sev cwe file line
  while :; do
    [[ -n ${BENCH_FLAT_TYPE[queries/$i/query_id]:-} ]] || break
    rule=$(bench_flat_str "queries/$i/query_id")
    sev=$(_kics_severity "$(bench_flat_str "queries/$i/severity")")
    cwe=$(bench_cwe_number "$(bench_flat_str "queries/$i/cwe")")
    j=0
    while :; do
      p="queries/$i/files/$j/file_name"
      [[ -n ${BENCH_FLAT_TYPE[$p]:-} ]] || break
      file=$(bench_flat_str "$p")
      # KICS REPORTS A PATH RELATIVE TO ITS OWN WORKING DIRECTORY, not to the
      # `-p` root it was handed - even when `-p` is absolute.  Measured: every
      # one of 155 findings came back as `bench/corpora/terragoat/...`, which
      # bench_relpath cannot strip because it is not prefixed by the scan root,
      # so every case scored 0 TP AND 0 FP and the tool read as having found
      # nothing at all.  Absolutising against the harness's own cwd - the same
      # cwd the child inherited - is what makes the prefix real.
      case $file in
        /*) ;;
        *) file=$PWD/$file ;;
      esac
      file=$(bench_relpath "$file" "$root")
      line=$(bench_flat_num "queries/$i/files/$j/line")
      # KICS uses -1 for "this query is about the file as a whole".  Passed
      # through it would be a line number no range can contain, which is the
      # right outcome but by accident; emptying it makes the record explicitly
      # line-less, which the scorer counts and reports.
      [[ $line == -1 || $line == 0 ]] && line=''
      bench_record "$file" "$line" "$cwe" "$sev" "$rule"
      j=$(( j + 1 ))
    done
    i=$(( i + 1 ))
  done
}

_kics_severity() {
  case $1 in
    CRITICAL) printf 'critical' ;;
    HIGH) printf 'high' ;;
    MEDIUM) printf 'medium' ;;
    LOW) printf 'low' ;;
    INFO | TRACE | '') printf 'info' ;;
    *) printf 'info' ;;
  esac
}
