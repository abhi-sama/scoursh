#!/usr/bin/env bash
# bench/tools/grype.sh - the Grype (anchore/grype) SCA adapter (B5).
#
# Grype needs no per-ecosystem flag and no manifest enumeration: `grype
# dir:ROOT` walks the whole tree in one pass (via its own embedded syft
# cataloguer) and reports one JSON document, `matches[]`, covering every
# lockfile it found under ROOT - unlike osv-scanner (see that adapter's own
# header for why THAT tool needed a different shape here).
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_GRYPE_SOURCED:-} ]] && return 0
BENCH_TOOL_GRYPE_SOURCED=1

grype_available() { command -v grype >/dev/null 2>&1; }

grype_version() {
  local v
  v=$(grype version 2>/dev/null | sed -n 's/^Version: *//p' | head -1)
  printf '%s' "${v:-unknown}"
}

# Every category bench/fetch-sca-corpus.sh's corpus supplies: Grype has no
# declared per-ecosystem scope of its own (unlike scoursh's rule packs, its
# vulnerability matching is ecosystem-agnostic over whatever syft catalogued),
# so it claims every category this leg measures at all.
grype_scope() {
  printf '%s\n' sca-npm sca-pypi sca-go
}

grype_run() {
  local raw=$1 root=$2
  mkdir -p "$raw"
  local rc=0
  grype "dir:$root" -o json >"$raw/grype.json" 2>"$raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$raw/exit-code"
  # Grype's own convention (like scoursh's): a non-zero exit can mean
  # "findings met the configured fail-on severity", not "the tool broke".
  # No `--fail-on` is passed here (this leg's own gate declaration, recorded
  # in bench/run-tool.sh's `_gate_line`), so in practice this run is always 0,
  # but the tool's documented range is treated identically to the scoursh
  # adapter's rather than assumed always-zero.
  case $rc in
    0 | 1) return 0 ;;
    *)
      printf 'bench: grype exited %d (see %s/stderr.txt)\n' "$rc" "$raw" >&2
      return "$rc"
      ;;
  esac
}

grype_normalise() {
  local raw=$1 root=$2
  local jsonfile=$raw/grype.json
  [[ -r $jsonfile ]] || { printf 'bench: no grype.json under %s\n' "$raw" >&2; return 2; }

  python3 - "$jsonfile" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    doc = json.load(f)

US = "\x1f"

def strip(s):
    return (s or "").replace(US, "")

for m in doc.get("matches", []):
    vuln = m.get("vulnerability", {}) or {}
    vuln_id = strip(vuln.get("id", ""))
    sev = strip(vuln.get("severity", "")).lower() or "info"
    if sev not in ("critical", "high", "medium", "low"):
        sev = "info"
    # Every id this finding could plausibly be known by - Grype's own
    # `vulnerability.id` plus every `relatedVulnerabilities[].id` (the CVE
    # cross-reference for a GHSA-namespaced npm match, or vice versa) - is
    # printed as its OWN record.  bench/lib/normalise.sh's own header already
    # states the reasoning this generalises: "one record per (finding, CWE)"
    # is a question about the SET of identities a finding could satisfy, and
    # the confusion matrix counts CASES, never records - so this cannot
    # inflate a published number, only let a ground truth pinned to WHICHEVER
    # alias OSV happened to canonicalise (bench/sca-advisories.lock's own
    # `osv-id`) actually match a tool that reports the CVE alias instead.
    ids = {vuln_id} if vuln_id else set()
    for rel in m.get("relatedVulnerabilities", []) or []:
        rid = strip(rel.get("id", ""))
        if rid:
            ids.add(rid)
    if not ids:
        ids = {""}

    for artifact_loc in (m.get("artifact", {}) or {}).get("locations", []) or []:
        path = strip(artifact_loc.get("path", ""))
        if not path:
            continue
        case = path.lstrip("/").split("/", 1)[0]
        pkg = strip((m.get("artifact", {}) or {}).get("name", ""))
        for one_id in sorted(ids):
            print(f"{case}{US}{US}{one_id}{US}{sev}{US}{pkg}")
PYEOF
}
