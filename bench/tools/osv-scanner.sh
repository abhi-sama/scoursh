#!/usr/bin/env bash
# bench/tools/osv-scanner.sh - the OSV-Scanner (google/osv-scanner) SCA
# adapter (B5).
#
# LOCKFILES ARE PASSED AS EXPLICIT `--lockfile` ARGUMENTS, NEVER AS A
# RECURSIVE DIRECTORY SCAN - measured, not a style choice.  `osv-scanner scan
# source -r ROOT` was tried first, since it is the tool's own documented
# top-level usage; on this host it consistently logged "Starting filesystem
# walk for root: /" (not ROOT) and "0 Extract calls" regardless of `-r`, an
# absolute path, or `--include-git-root`, and reported "No package sources
# found" over a directory this adapter had just confirmed held 26 real
# lockfiles.  osv-scanner 2.5.1's own `--lockfile PATH` flag bypasses that
# walker entirely and was confirmed working against the identical files - see
# this leg's own results README for the full account.  Do not "fix" this by
# reaching for `-r` again without re-confirming the walker issue is gone on
# whatever host this next runs on.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_OSV_SCANNER_SOURCED:-} ]] && return 0
BENCH_TOOL_OSV_SCANNER_SOURCED=1

osv-scanner_available() { command -v osv-scanner >/dev/null 2>&1; }

osv-scanner_version() {
  local v
  v=$(osv-scanner --version 2>&1 | sed -n 's/^osv-scanner version: *//p' | head -1)
  printf '%s' "${v:-unknown}"
}

osv-scanner_scope() {
  printf '%s\n' sca-npm sca-pypi sca-go
}

# The exact three manifest basenames bench/fetch-sca-corpus.sh's `_write_case`
# ever writes.  A tool-agnostic "every file under root" enumeration would
# also hand osv-scanner the go.sum siblings this corpus ships beside every
# go.mod, double-submitting the same module - `-L` accepts a lockfile
# directly and go.sum lacks the direct/transitive marker go.mod carries
# (bench/fetch-sca-corpus.sh's own go.mod generation is what osv-scanner
# should read, matching every other tool in this directory).
osv-scanner_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local args=() f
  while IFS= read -r f; do
    args+=(--lockfile "$f")
  done < <(find "$root" -maxdepth 2 -type f \
    \( -name 'package-lock.json' -o -name 'requirements.txt' -o -name 'go.mod' \) | LC_ALL=C sort)

  if (( ${#args[@]} == 0 )); then
    printf 'bench: osv-scanner: no manifests found under %s\n' "$root" >&2
    printf '2\n' >"$raw/exit-code"
    return 2
  fi

  local rc=0
  osv-scanner scan source --format json "${args[@]}" >"$raw/osv-scanner.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  # osv-scanner's own documented exit codes: 0 no vulnerabilities, 1
  # vulnerabilities found. Anything else (128 in this adapter's own probing -
  # see the header - was the directory-walker bug, never reached here since
  # every path is now explicit) is a real failure.
  case $rc in
    0 | 1) return 0 ;;
    *)
      printf 'bench: osv-scanner exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
      return "$rc"
      ;;
  esac
}

osv-scanner_normalise() {
  local raw=$1 root=$2
  local jsonfile=$raw/osv-scanner.json
  [[ -r $jsonfile ]] || { printf 'bench: no osv-scanner.json under %s\n' "$raw" >&2; return 2; }

  python3 - "$jsonfile" "$root" <<'PYEOF'
import json, os, sys

with open(sys.argv[1]) as f:
    doc = json.load(f)
root = sys.argv[2]

US = "\x1f"

def strip(s):
    return (s or "").replace(US, "")

# osv-scanner reports a CVSS score as `max_severity`, never a severity word
# (confirmed against real output, not assumed from the schema docs) - this is
# the standard CVSS v3 base-score banding
# (https://nvd.nist.gov/vuln-metrics/cvss), the same bands every SCA/vendor
# advisory feed in this ecosystem uses.
def band(score_str):
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"

for result in doc.get("results", []):
    src_path = strip((result.get("source", {}) or {}).get("path", ""))
    if not src_path:
        continue
    rel = os.path.relpath(src_path, root)
    case = rel.split(os.sep, 1)[0]
    for pkg_entry in result.get("packages", []) or []:
        pkg = strip((pkg_entry.get("package", {}) or {}).get("name", ""))
        for group in pkg_entry.get("groups", []) or []:
            sev = band(group.get("max_severity", ""))
            # Every id in the group, same "one record per identity the
            # ground truth might have pinned" reasoning bench/tools/grype.sh
            # documents - a group's own `ids` is its OSV-canonical members and
            # `aliases` adds the CVE cross-reference OSV itself publishes.
            ids = set(group.get("ids", []) or []) | set(group.get("aliases", []) or [])
            if not ids:
                ids = {""}
            for one_id in sorted(strip(i) for i in ids):
                print(f"{case}{US}{US}{one_id}{US}{sev}{US}{pkg}")
PYEOF
}
