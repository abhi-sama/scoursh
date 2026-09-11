#!/usr/bin/env bash
# bench/tools/scoursh-dast.sh - scoursh's DAST module (B7 leg).
#
# A SEPARATE ADAPTER FROM bench/tools/scoursh.sh and bench/tools/scoursh-iac.sh,
# for the same reason those two are separate from each other: `scan.sh dast` is
# a different subcommand over a different rule set answering a different
# question, and the adapter contract's `<tool>_scope` is a per-adapter claim.
#
# THIS ADAPTER DOES NOT FIT bench/run-tool.sh's `--root DIR` MODEL, AND IS NOT
# DRIVEN THROUGH IT.  Every other adapter scans a directory of files; DAST
# scans a running HTTP target, so there is no "scan root" to `find -type f`
# over and no filesystem path to normalise a finding against.  It is driven
# instead by bench/run-dast-leg.sh, which calls the five functions below
# directly and writes the identical <tool>/{raw,normalised.jsonl,MANIFEST}
# shape bench/score.sh already reads - see that script's own header for why a
# dedicated driver was the right shape here, the same way B5's SCA leg needed
# its own fetch script rather than forcing a lockfile corpus through
# bench/fetch-corpus.sh's git-clone model.
#
# THE NORMALISED `file` FIELD IS A URL PATH, NOT A FILESYSTEM PATH.  scoursh's
# DAST fingerprint location profile (AGENTS.md, "the fingerprint location
# profile") is `target method path_template param_location param_name` - no
# `path`/`line` at all, because a DAST finding is about a request, not a byte
# range in a file.  `path_template` (rules/RULE-FORMAT.md's tension-5
# volatile-segment normalisation, e.g. `/rest/user/123` -> `/rest/user/{id}`)
# is the closest analogue to a normalised finding's `file`, and it is what
# bench/labels/dast-juiceshop.truth's own `file` column is written against -
# see that file's header for why matching is done on the PATH alone (no
# scheme, no host, no query string) and what that costs.
#
# ONE RECORD PER FINDING, straight off findings.jsonl - unlike Grype's
# multi-alias expansion, scoursh's own CWE field is a single string, so no
# analogous per-id fan-out is needed here.
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_SCOURSH_DAST_SOURCED:-} ]] && return 0
BENCH_TOOL_SCOURSH_DAST_SOURCED=1

BENCH_SCOURSH_ROOT=${BENCH_SCOURSH_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)}

scoursh-dast_available() { [[ -r $BENCH_SCOURSH_ROOT/scan.sh ]]; }

scoursh-dast_version() {
  local v='' sha=''
  [[ -r $BENCH_SCOURSH_ROOT/VERSION ]] && IFS= read -r v <"$BENCH_SCOURSH_ROOT/VERSION"
  sha=$(git -C "$BENCH_SCOURSH_ROOT" rev-parse --short=12 HEAD 2>/dev/null) || sha=''
  printf '%s' "${v:-unknown}${sha:++$sha}"
}

# The categories bench/labels/dast-juiceshop.truth actually scores scoursh
# against.  scoursh's DAST engine ships checks well beyond these (auth,
# crawl, safe-active discovery, tier-5 authz/JWT/GraphQL/rate-limit - see
# docs/COMPARISON.md's DAST row for the full 92-check count); this leg's own
# hand-labelled corpus exercises only what a same-request-set, header/CORS/
# injection-focused comparison against ZAP could hand-verify without a tool's
# own output as the source of truth (methodology rule R2) - see that file's
# header for exactly what was and was not verified.
scoursh-dast_scope() { printf '%s\n' cors missing-csp sqli info-disclosure; }

# scoursh-dast_run RAW _ - RAW already holds a completed `scan.sh dast` run
# (bench/run-dast-leg.sh runs it directly, against the real config/scope.conf
# + config/auth.conf an operator would use, because DAST has no scan-root
# directory for run-tool.sh's own model to point at - see this file's header).
# This function's job is narrower than its SAST/IaC siblings': confirm the
# run actually produced output, never re-invoke scan.sh itself, so the
# driver's own exit-code handling (scan.sh's tension-14 dual-purpose exit
# code) is not duplicated in two places.
scoursh-dast_run() {
  local raw=$1
  [[ -r $raw/run/findings.jsonl ]] || {
    printf 'bench: no scoursh findings.jsonl under %s (run bench/run-dast-leg.sh)\n' "$raw" >&2
    return 2
  }
  return 0
}

scoursh-dast_normalise() {
  local raw=$1
  local jsonl=$raw/run/findings.jsonl
  [[ -r $jsonl ]] || { printf 'bench: no scoursh findings.jsonl under %s\n' "$raw" >&2; return 2; }

  python3 - "$jsonl" <<'PYEOF'
import json, sys

US = "\x1f"

def strip(s):
    return (s or "").replace(US, "")

with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        loc = d.get("location", {}) or {}
        path = strip(loc.get("path_template", ""))
        if not path:
            continue
        cwe = strip(d.get("cwe", ""))
        # scoursh writes "CWE-942"; bench_cwe_number (bench/lib/normalise.sh)
        # strips the prefix, but this adapter does the arithmetic itself so
        # the internal record line can be printed directly, matching every
        # sibling adapter's own convention.
        cwe_num = ""
        c = cwe
        for pfx in ("CWE-", "cwe-", "Cwe-"):
            if c.startswith(pfx):
                c = c[len(pfx):]
                break
        if c.isdigit():
            cwe_num = str(int(c))
        sev = strip(d.get("severity", "")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        rule = strip(d.get("check_id", ""))
        print(f"{path}{US}{US}{cwe_num}{US}{sev}{US}{rule}")
PYEOF
}
