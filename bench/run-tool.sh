#!/usr/bin/env bash
# bench/run-tool.sh - run one tool against one corpus, preserving its raw
# output verbatim and emitting the normalised records beside it.
#
#   bench/run-tool.sh --tool scoursh --sample sast-192 --out bench/results/smoke
#   bench/run-tool.sh --tool semgrep --root /abs/path --corpus my-corpus --out …
#   bench/run-tool.sh --list-tools
#
# Writes, under <out>/<tool>/ :
#   raw/            the tool's own output, byte for byte, plus its stderr and
#                   its exit code
#   normalised.jsonl the harness's record shape
#   MANIFEST        tool version, corpus id and pinned commit, gate config,
#                   wall clock, and the scope this tool CLAIMS
#
# THE RAW OUTPUT IS THE POINT, not a debugging convenience.  "The whole thing
# must be re-runnable by a stranger" is what the
# numbers already shipping in docs/COMPARISON.md fail, and raw output is the
# half of it a reader cannot reconstruct.  A normalised record is this
# harness's INTERPRETATION of what a tool said; keeping the tool's own words
# beside it is what lets a reader who distrusts the interpretation check it.
#
# RUNTIME IS RECORDED AS A WALL CLOCK AND A FILE COUNT, never as a rate.
# scoursh's cost is ~38 s of fixed startup plus ~0.3 s/file (measured), so a single total on a small corpus is almost entirely startup and
# every such comparison is wrong in scoursh's disfavour.  Publishing `a + b·n`
# needs both numbers from at least two corpus sizes, which is why this file
# records the inputs to that fit rather than a ratio it cannot honestly
# compute from one run.
#
# shellcheck shell=bash

set -Eeuo pipefail

BENCH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BENCH_LIB_DIR=$BENCH_ROOT/lib
# shellcheck source=bench/lib/normalise.sh
source "$BENCH_LIB_DIR/normalise.sh"
# shellcheck source=bench/lib/corpus.sh
source "$BENCH_LIB_DIR/corpus.sh"

LOCK=${BENCH_CORPUS_LOCK:-$BENCH_ROOT/corpus.lock}
CORPORA=${BENCH_CORPORA_DIR:-$BENCH_ROOT/corpora}

usage() {
  cat <<'EOF'
bench/run-tool.sh --tool NAME (--sample NAME | --root DIR --corpus ID) --out DIR

  --tool NAME     an adapter under bench/tools/ (see --list-tools)
  --sample NAME   a sample built by bench/make-sample.sh; supplies the scan
                  root, the corpus id and the pinned commit together
  --root DIR      scan this directory instead
  --corpus ID     the corpus id to record when using --root
  --out DIR       where to write <tool>/{raw,normalised.jsonl,MANIFEST}
  --portable-paths  rewrite the absolute scan-root prefix to <SCAN_ROOT>
                  everywhere under <out>/<tool>/ once the run is finished.
                  Use it for a result that will be COMMITTED.
  --redact-secret-values  replace the matched CREDENTIAL in a secrets tool's
                  raw output with a <redacted:N-bytes> placeholder.  Required
                  for any secrets-leg result that will be COMMITTED.
  --list-tools    the adapters present
EOF
}

list_tools() {
  local f
  for f in "$BENCH_ROOT"/tools/*.sh; do
    [[ -e $f ]] || continue
    printf '%s\n' "$(basename "$f" .sh)"
  done
}

main() {
  local tool='' sample='' root='' corpus='' out='' portable=0 redact=0
  while (( $# > 0 )); do
    case $1 in
      --tool) tool=$2; shift 2 ;;
      --sample) sample=$2; shift 2 ;;
      --root) root=$2; shift 2 ;;
      --corpus) corpus=$2; shift 2 ;;
      --out) out=$2; shift 2 ;;
      --portable-paths) portable=1; shift ;;
      --redact-secret-values) redact=1; shift ;;
      --list-tools) list_tools; return 0 ;;
      -h | --help) usage; return 0 ;;
      *) printf 'bench: unknown option: %s\n' "$1" >&2; usage >&2; return 2 ;;
    esac
  done
  [[ -n $tool && -n $out ]] || { usage >&2; return 2; }

  local adapter=$BENCH_ROOT/tools/$tool.sh
  [[ -r $adapter ]] || { printf 'bench: no adapter for tool: %s\n' "$tool" >&2; return 2; }
  # shellcheck source=/dev/null
  source "$adapter"

  local commit='' truth=''
  if [[ -n $sample ]]; then
    local sdir=$CORPORA/_samples/$sample
    [[ -d $sdir ]] || {
      printf 'bench: no such sample: %s (run bench/make-sample.sh)\n' "$sample" >&2
      return 2
    }
    root=$sdir/root
    truth=$sdir/truth
    corpus=$sample
    commit=$(sed -n 's/^commit: //p' "$sdir/MANIFEST")
  fi
  [[ -n $root && -d $root ]] || { printf 'bench: --root must be a directory: %s\n' "$root" >&2; return 2; }
  [[ -n $corpus ]] || { printf 'bench: --corpus is required with --root\n' >&2; return 2; }
  root=$(cd -- "$root" && pwd -P)

  if [[ -z $commit ]] && corpus_load "$LOCK" 2>/dev/null && corpus_has "$corpus"; then
    commit=$(corpus_field "$corpus" commit)
  fi

  "${tool}_available" || {
    # An absent tool is REFUSED, never recorded as a run that found nothing.
    # "semgrep is not installed" and "semgrep found nothing" are different
    # facts and only one of them is a benchmark result; emitting an empty
    # normalised.jsonl here would make the second indistinguishable from the
    # first for every reader downstream.
    printf 'bench: tool not available here: %s\n' "$tool" >&2
    return 2
  }

  local version
  version=$("${tool}_version")

  local dest=$out/$tool
  rm -rf "${dest:?}"
  mkdir -p "$dest/raw"

  local nfiles
  nfiles=$(find "$root" -type f | wc -l | tr -d ' ')

  local t0 t1 rc=0
  t0=$(date +%s)
  "${tool}_run" "$dest/raw" "$root" || rc=$?
  t1=$(date +%s)
  if (( rc != 0 )); then
    printf 'bench: %s run failed (rc=%d); raw output kept at %s\n' "$tool" "$rc" "$dest/raw" >&2
    return "$rc"
  fi

  "${tool}_normalise" "$dest/raw" "$root" |
    bench_records_to_jsonl "$tool" "$version" "$corpus" >"$dest/normalised.jsonl"

  {
    printf 'tool: %s\n' "$tool"
    printf 'version: %s\n' "$version"
    printf 'corpus: %s\n' "$corpus"
    printf 'corpus-commit: %s\n' "${commit:-unpinned}"
    printf 'scan-root: %s\n' "$root"
    printf 'files-scanned: %s\n' "$nfiles"
    printf 'wall-clock-seconds: %s\n' "$(( t1 - t0 ))"
    printf 'records: %s\n' "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')"
    printf 'claims-categories: %s\n' "$("${tool}_scope" | tr '\n' ' ' | sed 's/ $//')"
    [[ -n $truth ]] && printf 'ground-truth: %s\n' "$truth"
    printf 'gate: %s\n' "$(_gate_line "$tool")"
    printf 'note: runtime is a WALL CLOCK over %s file(s), not a rate - see the\n' "$nfiles"
    printf '  header of bench/run-tool.sh for why a single total on a small corpus\n'
    printf '  is mostly fixed startup cost.\n'
  } >"$dest/MANIFEST"

  if (( portable )); then _portable_paths "$dest" "$root"; fi
  # AFTER _portable_paths, deliberately: that rewrite matches on a path prefix
  # and this one on a JSON key, so neither can hide the other's target, and
  # running the path rewrite first keeps its measured behaviour unchanged.
  if (( redact )); then _redact_secret_values "$dest"; fi

  printf 'bench: %s @ %s -> %s (%s record(s), %ds)\n' \
    "$tool" "$version" "$dest/normalised.jsonl" \
    "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')" "$(( t1 - t0 ))"
}

# _portable_paths DEST ROOT - rewrite the absolute scan root to <SCAN_ROOT>.
#
# WHY A COMMITTED RESULT IS NOT BYTE-VERBATIM, stated here rather than left for
# a reader to notice.  Every tool echoes back the path it was given, so a raw
# output captured on a real machine embeds that machine's absolute scan root -
# which, for anything committed to a public repository, is an operator's home
# directory.  This rewrite is the ONE transformation applied, it is purely
# mechanical (three prefixes, three tokens), and the MANIFEST records that it
# happened, so a reader is never left to wonder whether anything else was
# edited.  Without `--portable-paths` nothing is touched at all.
#
# It runs AFTER normalisation, deliberately: the normalisers resolve paths
# against the real scan root, and rewriting first would leave them resolving
# against a token that is not a prefix of anything.
_portable_paths() {
  local dest=$1 root=$2 f
  # THREE prefixes, longest first - order matters, because the scan root is
  # itself usually under bench/, which is itself usually under $HOME, so
  # rewriting a shorter prefix first would leave the longer ones only
  # PARTIALLY matching whatever token replaced their own prefix, and every
  # later rule would then match nothing - the tokens would be inconsistent
  # between files rather than absent, which is worse than either alone.  The
  # third rule catches a path a TOOL emits about ITSELF rather than about the
  # scan - Grype's own `descriptor.db.location`, naming wherever its local
  # vulnerability database happens to be cached, is not under the scan root
  # or bench/ at all and was measured leaking here first.
  local home_prefix=${HOME:-}
  local sed_args=(-e "s|${root//|/\\|}|<SCAN_ROOT>|g" -e "s|${BENCH_ROOT//|/\\|}|<BENCH>|g")
  [[ -n $home_prefix ]] && sed_args+=(-e "s|${home_prefix//|/\\|}|<HOME>|g")
  while IFS= read -r f; do
    LC_ALL=C sed -i.bak "${sed_args[@]}" "$f" && rm -f "$f.bak"
  done < <(find "$dest" -type f ! -name '*.bak')
  printf 'portable-paths: the scan-root prefix was replaced by <SCAN_ROOT>, the bench/ prefix by <BENCH>, and any remaining operator-home prefix by <HOME>; no other edit was made\n' \
    >>"$dest/MANIFEST"
}

# _redact_secret_values DEST - blank the matched credential in a raw output.
#
# WHY A SECOND TRANSFORMATION EXISTS AT ALL, since the harness's whole point is
# that raw output is preserved verbatim.  A secrets scanner's raw output
# contains, by construction, the credential it matched: Gitleaks reports it in
# `Secret` and `Match`, TruffleHog in `Raw`, `RawV2`, `Redacted` and
# `SecretParts`.  Committing that puts credential-shaped strings into this
# repository's history permanently, and the values in a corpus like leaky-repo
# are fakes only because its author says so - a future corpus's might not be.
#
# It is not hypothetical.  Committing the unredacted output was tried, and
# GitHub push protection refused the push, naming a Slack API token at
# `gitleaks/raw/gitleaks.json:49`.  That refusal was CORRECT and the right
# response is to stop shipping the value, not to click the bypass link - a
# security tool's own repository is the last place to normalise waving a
# secret past a scanner.
#
# WHAT IS AND IS NOT LOST.  The rule id, the file, the line, the entropy score,
# the detector name, the verification state and every other field survive
# untouched, so a reader can still check every scoring decision this harness
# made against the tool's own words.  What goes is the credential text and its
# surrounding match context, replaced by a placeholder carrying its BYTE
# LENGTH - which is what a reader needs to tell "matched a 40-character token"
# from "matched an empty string" without holding the token.  The MANIFEST
# records that it happened, exactly as _portable_paths does.
#
# THE KEY LIST IS EXPLICIT AND DELIBERATELY OVER-BROAD.  Redacting a key a tool
# does not use costs nothing; missing one ships a credential.  `Redacted` is in
# it despite its name - TruffleHog's own redaction leaves enough of some values
# to matter, and this placeholder does not.
#
# A FAILURE HERE IS FATAL, AND THAT IS THE LOAD-BEARING PART.  The first draft
# wrote `awk ... >"$f.new" && mv "$f.new" "$f"`, whose awk program had a
# escaping bug: awk exited non-zero, `mv` never ran, every credential stayed in
# the file - and the MANIFEST still gained its "the matched credential was
# replaced" line, because the function ran to the end and returned 0.  A
# transformation that ANNOUNCES it happened while not happening is worse than
# no transformation at all, so the awk's status is checked, a non-empty input
# that produces empty output is refused, and the whole run fails rather than
# writing a MANIFEST claim it cannot honour.
_redact_secret_values() {
  local dest=$1 f k prog
  local keys=(Secret Match Raw RawV2 Redacted SecretV2 connection_string password)

  # The program is written out rather than inlined, so its backslashes are the
  # ones awk sees rather than the ones some intermediate quoting left behind.
  prog=$dest/.redact.awk
  cat >"$prog" <<'AWK'
{
  out = ""; rest = $0
  while ((i = index(rest, "\"" key "\":")) > 0) {
    out = out substr(rest, 1, i - 1) "\"" key "\":"
    rest = substr(rest, i + length(key) + 3)
    while (substr(rest, 1, 1) == " ") { out = out " "; rest = substr(rest, 2) }
    if (substr(rest, 1, 1) != "\"") { continue }
    rest = substr(rest, 2)
    v = ""
    while (length(rest) > 0) {
      c = substr(rest, 1, 1)
      if (c == "\\") { v = v substr(rest, 1, 2); rest = substr(rest, 3); continue }
      if (c == "\"") { rest = substr(rest, 2); break }
      v = v c; rest = substr(rest, 2)
    }
    out = out "\"<redacted:" length(v) "-bytes>\""
  }
  print out rest
}
AWK

  while IFS= read -r f; do
    for k in "${keys[@]}"; do
      awk -v key="$k" -f "$prog" "$f" >"$f.redacting" || {
        printf 'bench: redaction failed on %s (key %s) - refusing to write a MANIFEST claim it cannot honour\n' "$f" "$k" >&2
        rm -f "$f.redacting" "$prog"
        return 2
      }
      if [[ -s $f && ! -s $f.redacting ]]; then
        printf 'bench: redaction emptied %s (key %s) - refusing\n' "$f" "$k" >&2
        rm -f "$f.redacting" "$prog"
        return 2
      fi
      mv "$f.redacting" "$f"
    done
  done < <(find "$dest/raw" -type f)
  rm -f "$prog"

  # TruffleHog's `SecretParts` is an OBJECT whose KEY NAMES vary by detector -
  # `key`, `token`, `connection_string`, and whatever a future detector
  # invents - so a fixed key list cannot reach inside it.  Measured: after the
  # keyed pass above, a `SecretParts` object keyed `token` still held two
  # entire PEM private keys and five live-shaped tokens.  This pass
  # keeps the PART NAMES, which are metadata worth reading, and redacts every
  # value inside the object whatever it is called.
  local objkeys=(SecretParts StructuredData ExtraData)
  prog=$dest/.redact-obj.awk
  cat >"$prog" <<'AWK'
{
  out = ""; rest = $0
  while ((i = index(rest, "\"" key "\":{")) > 0) {
    out = out substr(rest, 1, i - 1) "\"" key "\":{"
    rest = substr(rest, i + length(key) + 4)
    first = 1
    while (length(rest) > 0 && substr(rest, 1, 1) != "}") {
      if (substr(rest, 1, 1) == ",") { out = out ","; rest = substr(rest, 2); continue }
      if (substr(rest, 1, 1) != "\"") { break }
      # the part NAME, kept verbatim
      rest = substr(rest, 2); n = ""
      while (length(rest) > 0) {
        c = substr(rest, 1, 1)
        if (c == "\\") { n = n substr(rest, 1, 2); rest = substr(rest, 3); continue }
        if (c == "\"") { rest = substr(rest, 2); break }
        n = n c; rest = substr(rest, 2)
      }
      if (substr(rest, 1, 1) != ":") { out = out "\"" n "\""; break }
      rest = substr(rest, 2)
      while (substr(rest, 1, 1) == " ") { rest = substr(rest, 2) }
      if (substr(rest, 1, 1) != "\"") { out = out "\"" n "\":"; continue }
      rest = substr(rest, 2); v = ""
      while (length(rest) > 0) {
        c = substr(rest, 1, 1)
        if (c == "\\") { v = v substr(rest, 1, 2); rest = substr(rest, 3); continue }
        if (c == "\"") { rest = substr(rest, 2); break }
        v = v c; rest = substr(rest, 2)
      }
      out = out "\"" n "\":\"<redacted:" length(v) "-bytes>\""
      first = 0
    }
  }
  print out rest
}
AWK
  while IFS= read -r f; do
    for k in "${objkeys[@]}"; do
      awk -v key="$k" -f "$prog" "$f" >"$f.redacting" || {
        printf 'bench: object redaction failed on %s (key %s)\n' "$f" "$k" >&2
        rm -f "$f.redacting" "$prog"
        return 2
      }
      if [[ -s $f && ! -s $f.redacting ]]; then
        printf 'bench: object redaction emptied %s (key %s) - refusing\n' "$f" "$k" >&2
        rm -f "$f.redacting" "$prog"
        return 2
      fi
      mv "$f.redacting" "$f"
    done
  done < <(find "$dest/raw" -type f)
  rm -f "$prog"

  # PROVE IT, rather than assert it.  A `"KEY": "value"` still carrying
  # anything but the placeholder means the walk missed a shape, and the whole
  # point of this function is that such a miss must not reach a commit.
  # PROVE IT, rather than assert it.  Three checks, because the first draft's
  # proof was as narrow as its redaction and passed while two private keys sat
  # in the file: a keyed value that is not a placeholder, an object-valued
  # part that is not a placeholder, and a PEM header ANYWHERE - which is the
  # shape-independent backstop, since no field of any tool's own metadata
  # legitimately contains one.
  local leftover=''
  local k2
  for k2 in "${keys[@]}"; do
    leftover+=$(LC_ALL=C grep -oE "\"$k2\": ?\"[^\"<]" -r "$dest/raw" 2>/dev/null || true)
  done
  for k2 in "${objkeys[@]}"; do
    leftover+=$(LC_ALL=C grep -oE "\"$k2\":\{[^}]*\": ?\"[^\"<]" -r "$dest/raw" 2>/dev/null || true)
  done
  leftover+=$(LC_ALL=C grep -l -- '-----BEGIN' -r "$dest/raw" 2>/dev/null || true)
  if [[ -n $leftover ]]; then
    printf 'bench: a secret-bearing field survived redaction:\n%s\n' "$leftover" >&2
    return 2
  fi

  printf 'redact-secret-values: the matched credential in every %s field was replaced by a <redacted:N-bytes> placeholder; every other field is the tool%s own output, and the run fails rather than claiming this if it did not happen\n' \
    "$(printf '%s/' "${keys[@]}" | sed 's|/$||')" "'s" >>"$dest/MANIFEST"
}

# The exact configuration each tool was run at, recorded rather than implied.
# R5 again: "gate configuration must be declared, symmetric, and never tuned
# against the corpus" - a manifest that omits it lets a later reader assume
# whichever configuration flatters the conclusion they already hold.
_gate_line() {
  case $1 in
    scoursh) printf 'scan.sh sast --format json (defaults: --profile-scan full --min-confidence low; NOT --use-engines)' ;;
    scoursh-iac) printf 'scan.sh iac --format json (defaults: --profile-scan full --min-confidence low; NOT --use-engines)' ;;
    scoursh-secrets) printf 'scan.sh sast --format json (defaults; NOT --use-engines, NOT --history; output NOT filtered to the SAST-SEC-* family - see the adapter header)' ;;
    semgrep | semgrep-default) printf 'semgrep --config %s --no-git-ignore --metrics=off' "$BENCH_SEMGREP_CONFIG" ;;
    scoursh-sca) printf 'scan.sh sca --format json, one invocation per case directory (defaults: --profile-scan full --min-confidence low; NOT --use-engines) - requires a populated data/advisories.db, built separately via tools/vendor-engines.sh advisories bulk' ;;
    grype) printf 'grype dir:<root> -o json (default vulnerability DB, whatever local state grype already has)' ;;
    osv-scanner) printf 'osv-scanner scan source --format json --lockfile <each manifest> (queries api.osv.dev live; deps.dev data source default)' ;;
    trivy-fs) printf 'trivy fs --scanners vuln --format json --skip-db-update --skip-java-db-update (cached DB, NOT freshly pulled - see bench/tools/trivy-fs.sh header)' ;;
    checkov) printf 'checkov -d ROOT -o json --compact --quiet (default auto-detected frameworks; no --check/--skip-check)' ;;
    kics) printf 'kics scan -p ROOT -q <installed query library> --report-formats json (no --include-queries/--exclude-queries)' ;;
    trivy-config) printf 'trivy config --format json --skip-check-update ROOT (default compiled-in checks; no --severity filter)' ;;
    gitleaks) printf 'gitleaks dir --no-banner --exit-code 0 --report-format json ROOT (default rule set; WORKING TREE, not history)' ;;
    trufflehog) printf 'trufflehog filesystem ROOT --json --no-verification --results=verified,unknown,unverified --exclude-paths <.git/> (default detectors; verification is egress and is excluded)' ;;
    *) printf 'unrecorded - add a row to _gate_line in bench/run-tool.sh' ;;
  esac
}

main "$@"
