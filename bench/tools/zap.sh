#!/usr/bin/env bash
# bench/tools/zap.sh - the OWASP ZAP adapter (B7 leg).
#
# LIKE bench/tools/scoursh-dast.sh, THIS IS NOT DRIVEN THROUGH
# bench/run-tool.sh's `--root DIR` MODEL - a running HTTP target is not a
# directory of files.  bench/run-dast-leg.sh drives ZAP entirely over its own
# HTTP API (never zap-full-scan.py / zap-baseline.py), per the bench report's
# §4.4 fix that made a first attempt at this leg survivable at all:
# `-config start.checkForUpdates=false` so nothing downloads mid-scan, an
# EXPLICIT JVM heap (`-Xmx...`, set at container start) plus an explicit
# Docker container memory ceiling (`--memory`, added in THIS leg after the
# heap flag alone still let the container get OOM-killed - see the driver's
# own header and bench/results/b7-dast-juiceshop/README.md for the measured
# account), and polling `/JSON/.../status/` directly with retries so a
# transient proxy reset never aborts a 20-minute scan.  This function's job is
# narrower: read what the driver already collected via `core/view/alerts` and
# normalise it - it does not itself talk to the ZAP API.
#
# THE NORMALISED `file` FIELD IS A URL PATH, stripped of scheme, host, and
# query string - the identical convention scoursh-dast.sh uses, and the one
# bench/labels/dast-juiceshop.truth's own `file` column is written against.
# A ZAP alert's `url` is the full request URL; this adapter parses it with
# Python's own `urllib.parse` rather than a hand-rolled string split, because
# a URL can legitimately contain '/' inside an encoded segment or a query
# value and a naive split has no way to tell those apart from a path
# separator.
#
# ONE RECORD PER (ALERT, CWE): a ZAP alert carries at most one `cweid`
# (unlike Grype's multi-alias vulnerability ids), so this is a plain 1:1 map
# rather than a fan-out - `cweid` of `-1` or `0` means "ZAP declared none",
# which becomes an empty CWE field here (bench/lib/normalise.sh's own
# `bench_cwe_number`: a CWE-less finding matches loosely and never strictly,
# by design, never mapped to a fabricated class).
#
# shellcheck shell=bash

[[ -n ${BENCH_TOOL_ZAP_SOURCED:-} ]] && return 0
BENCH_TOOL_ZAP_SOURCED=1

zap_available() { [[ -n ${BENCH_ZAP_VERSION:-} ]] || command -v docker >/dev/null 2>&1; }

# The driver records the version ZAP itself reported (`/JSON/core/view/version/`)
# into the raw output; this reads it back rather than re-querying a container
# that may no longer be running by the time normalisation happens.
zap_version() {
  local f=${BENCH_ZAP_RAW_DIR:-}/version.json
  [[ -n $f && -r $f ]] || { printf 'unknown'; return 0; }
  python3 -c "
import json
try:
    print(json.load(open('$f')).get('version', 'unknown'))
except Exception:
    print('unknown')
"
}

# What this leg's corpus can score ZAP against - see bench/tools/scoursh-dast.sh's
# own `_scope` for why this is narrower than ZAP's real, much broader rule set.
zap_scope() { printf '%s\n' cors missing-csp sqli info-disclosure; }

zap_run() {
  local raw=$1
  [[ -r $raw/alerts.json ]] || {
    printf 'bench: no ZAP alerts.json under %s (run bench/run-dast-leg.sh)\n' "$raw" >&2
    return 2
  }
  return 0
}

zap_normalise() {
  local raw=$1
  local alertsfile=$raw/alerts.json
  [[ -r $alertsfile ]] || { printf 'bench: no ZAP alerts.json under %s\n' "$raw" >&2; return 2; }

  python3 - "$alertsfile" <<'PYEOF'
import json, sys
from urllib.parse import urlsplit

US = "\x1f"

def strip(s):
    return (s or "").replace(US, "")

RISK_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}

with open(sys.argv[1]) as f:
    doc = json.load(f)

for a in doc.get("alerts", []) or []:
    url = strip(a.get("url", ""))
    if not url:
        continue
    path = urlsplit(url).path or "/"
    cwe_raw = strip(str(a.get("cweid", "")))
    cwe_num = ""
    if cwe_raw.lstrip("-").isdigit():
        n = int(cwe_raw)
        if n > 0:
            cwe_num = str(n)
    risk = strip(a.get("risk", "")).lower()
    sev = RISK_MAP.get(risk, "info")
    # pluginId is ZAP's stable rule identity across alert instances/languages;
    # `alert`/`name` is the human title and is NOT stable across ZAP versions
    # or locales, so it is not used as rule_id here.
    rule = strip(a.get("pluginId", "")) or strip(a.get("alert", ""))
    print(f"{path}{US}{US}{cwe_num}{US}{sev}{US}{rule}")
PYEOF
}
