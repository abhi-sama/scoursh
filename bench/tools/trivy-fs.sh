#!/usr/bin/env bash
# bench/tools/trivy-fs.sh - the Trivy filesystem-scan (aquasecurity/trivy fs
# --scanners vuln) SCA adapter (B5).
#
# NAMED `trivy-fs`, NOT `trivy` - a deliberate reservation. `docs/COMPARISON.md`
# names Trivy TWICE, once
# per category: `trivy config` for IaC (a hypothetical future
# `bench/tools/trivy.sh` for that leg) and `trivy fs --scanners vuln` for SCA,
# here. `<tool>_run` takes no category argument (bench/run-tool.sh), so one
# adapter file names one full command line; giving this file the bare name
# `trivy` would let a same-named future IaC adapter either collide with it or
# silently inherit the wrong command.
#
# `--skip-db-update` IS PASSED DELIBERATELY, AND IT IS A REAL,
# ENVIRONMENT-SPECIFIC LIMITATION, NOT A PREFERENCE.  A fresh
# `trivy fs --scanners vuln` (no skip flags) was tried first here and hung
# past several minutes past the point its own debug log printed
# "[vulndb] Downloading artifact... repo=mirror.gcr.io/aquasec/trivy-db:2" -
# reachability to mirror.gcr.io was independently confirmed fast (HTTP 200
# and 401 responses in well under a second) at the same time, so this is not
# a blanket egress failure, and Trivy's `config`-only IaC path (no DB needed) already
# ran sub-second in an earlier pilot on a sibling host - it is
# specific to this host's ability to complete a fresh `fs --scanners vuln` DB
# pull. `--skip-db-update` against the pre-existing cached DB (dated on disk
# to 2026-09-08, two days before this leg's run - see the leg's own results
# README for the exact age and size) worked immediately and reproducibly.
# THIS MEANS TRIVY IS MEASURED HERE AGAINST A DATABASE THAT IS NOT FRESHLY
# PULLED AT RUN TIME, which is the opposite of the egress cost this leg's own
# §4.5/§5.3 columns exist to quantify for every OTHER tool - stated plainly
# in the results README rather than left for a reader to notice from a flag.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_TRIVY_FS_SOURCED:-} ]] && return 0
BENCH_TOOL_TRIVY_FS_SOURCED=1

trivy-fs_available() { command -v trivy >/dev/null 2>&1; }

trivy-fs_version() {
  local v
  v=$(trivy --version 2>/dev/null | sed -n 's/^Version: *//p' | head -1)
  printf '%s' "${v:-unknown}"
}

trivy-fs_scope() {
  printf '%s\n' sca-npm sca-pypi sca-go
}

trivy-fs_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  trivy fs --scanners vuln --format json --skip-db-update --skip-java-db-update --quiet \
    "$root" >"$raw/trivy.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  case $rc in
    0 | 1) return 0 ;;
    *)
      printf 'bench: trivy exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
      return "$rc"
      ;;
  esac
}

trivy-fs_normalise() {
  local raw=$1 root=$2
  local jsonfile=$raw/trivy.json
  [[ -r $jsonfile ]] || { printf 'bench: no trivy.json under %s\n' "$raw" >&2; return 2; }

  python3 - "$jsonfile" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    doc = json.load(f)

US = "\x1f"

def strip(s):
    return (s or "").replace(US, "")

for result in doc.get("Results", []) or []:
    target = strip(result.get("Target", ""))
    if not target:
        continue
    case = target.split("/", 1)[0]
    for vuln in result.get("Vulnerabilities", []) or []:
        pkg = strip(vuln.get("PkgName", ""))
        sev = strip(vuln.get("Severity", "")).lower() or "info"
        if sev not in ("critical", "high", "medium", "low"):
            sev = "info"
        # `VulnerabilityID` (usually a CVE) plus every `VendorIDs` entry
        # (the GHSA/OSV-native id, confirmed present in real output for the
        # npm advisories this corpus targets) - the same "every id this
        # finding could be known by" reasoning bench/tools/grype.sh documents.
        ids = set()
        vid = strip(vuln.get("VulnerabilityID", ""))
        if vid:
            ids.add(vid)
        for vendor_id in vuln.get("VendorIDs", []) or []:
            v = strip(vendor_id)
            if v:
                ids.add(v)
        if not ids:
            ids = {""}
        for one_id in sorted(ids):
            print(f"{case}{US}{US}{one_id}{US}{sev}{US}{pkg}")
PYEOF
}
