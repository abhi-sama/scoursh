#!/usr/bin/env bash
# bench/run-dast-leg.sh - the B7 DAST leg driver: scoursh vs OWASP ZAP against
# the local, operator-owned Juice Shop test target.
#
# NEITHER TOOL HERE GOES THROUGH bench/run-tool.sh.  Every other adapter scans
# a directory of files that bench/run-tool.sh's `--root DIR` model can `find
# -type f` over; DAST scans a running HTTP target, so there is no scan root at
# all - see bench/tools/scoursh-dast.sh's and bench/tools/zap.sh's own headers
# for the full reasoning, the same one that gave the SCA leg (B5) its own
# bench/fetch-sca-corpus.sh rather than forcing a lockfile corpus through the
# git-clone model bench/fetch-corpus.sh uses.
#
#   bench/run-dast-leg.sh setup            # start the target, provision auth
#   bench/run-dast-leg.sh scoursh OUTDIR   # run scoursh dast, write OUTDIR/raw
#   bench/run-dast-leg.sh zap-start        # start a fresh ZAP daemon
#   bench/run-dast-leg.sh zap OUTDIR       # drive it over its API, write OUTDIR/raw
#   bench/run-dast-leg.sh normalise OUTDIR # both tools' raw -> normalised.jsonl + MANIFEST
#   bench/run-dast-leg.sh teardown         # stop the ZAP container (never the target)
#
# WHAT THIS SCRIPT WILL NEVER DO: stop, restart or displace a container it did
# not itself start (the target, if reused, is left running exactly as it found
# it - `setup` only starts it when absent), and it binds ZAP to a fixed LOCAL
# port on 127.0.0.1 that it picks freely rather than reusing one already
# owned.  This mirrors the production-safety discipline tools/dast-test-target.sh
# already documents for the target itself.
#
# shellcheck shell=bash

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
BENCH_ROOT=$ROOT/bench
# shellcheck source=bench/lib/normalise.sh
source "$BENCH_ROOT/lib/normalise.sh"
# shellcheck source=bench/tools/scoursh-dast.sh
source "$BENCH_ROOT/tools/scoursh-dast.sh"
# shellcheck source=bench/tools/zap.sh
source "$BENCH_ROOT/tools/zap.sh"

DTT_TARGET_ID=dast-test-target
ZAP_CONTAINER=${BENCH_ZAP_CONTAINER:-scoursh-bench-zap}
ZAP_PORT=${BENCH_ZAP_PORT:-8090}
ZAP_API=http://127.0.0.1:$ZAP_PORT
ZAP_IMAGE=${BENCH_ZAP_IMAGE:-zaproxy/zap-stable:latest}
# ZAP has no way to reach a HOST port from inside its own container on every
# Docker Desktop platform (`host.docker.internal` is unreliable cross-platform
# and adds a variable this driver does not need); it is instead run with no
# --network flag, which joins Docker's default `bridge` network - the same
# network tools/dast-test-target.sh's container already sits on with no
# extra configuration - and addressed by that network's OWN bridge IP rather
# than the host-published port, so it never touches port 3400 at all.
ZAP_TARGET_HOST=

usage() {
  cat <<'EOF'
bench/run-dast-leg.sh setup|scoursh|zap-start|zap|normalise|teardown [OUTDIR]
EOF
}

_target_container() {
  docker ps --filter 'name=^/scoursh-dast-test-target$' --format '{{.Names}}'
}

_zap_bridge_ip() {
  docker inspect scoursh-dast-test-target --format '{{.NetworkSettings.IPAddress}}'
}

cmd_setup() {
  if [[ -z $(_target_container) ]]; then
    bash "$ROOT/tools/dast-test-target.sh" start
  else
    printf 'bench: reusing already-running %s\n' "$(_target_container)" >&2
  fi
  bash "$ROOT/tools/dast-test-identities.sh" >/dev/null
}

# Runs scan.sh dast DIRECTLY against config/scope.conf + config/auth.conf -
# the identical path an operator uses (tests/e2e/dast-auth-live.sh's own "the
# whole operator path" section) - because a symlinked SCOURSH_INSTALL_ROOT
# fixture (the shape that test builds for itself) fails E081/E018's
# owning-module check here: lib/records.sh's `_records_relpath` strips
# SCOURSH_INSTALL_ROOT as a literal prefix off each loaded file's REALPATH,
# and a `modules` symlink resolves through to this repository's real path,
# which is not under a separate fixture root at all. Measured directly (both
# at default and at --intensity active) before this script was written this
# way; config/scope.conf and config/auth.conf are always removed in a trap,
# on every exit path, so a real credential and a real scope record never sit
# in a tracked path for longer than the scan itself runs.
cmd_scoursh() {
  local out=$1
  mkdir -p "$out/raw"
  restore_trap() { rm -f "$ROOT/config/scope.conf" "$ROOT/config/auth.conf"; }
  trap restore_trap EXIT
  cp "$ROOT/tools/dast-test-target/scope.conf" "$ROOT/config/scope.conf"
  cp "$ROOT/.dast-test-target/auth.conf" "$ROOT/config/auth.conf"
  chmod 600 "$ROOT/config/auth.conf"
  local rc=0
  ( cd "$ROOT" && bash scan.sh dast --target "$DTT_TARGET_ID" --authed \
      --intensity active --i-own-target "$DTT_TARGET_ID" \
      --contact scoursh-bench-dast@scoursh.local \
      --out "$out/raw/run" --format json ) \
    >"$out/raw/stdout.txt" 2>"$out/raw/stderr.txt" || rc=$?
  printf '%s\n' "$rc" >"$out/raw/exit-code"
  restore_trap
  trap - EXIT
  case $rc in
    0 | 1) return 0 ;;
    *) printf 'bench: scoursh dast exited %d (see %s/raw/stderr.txt)\n' "$rc" "$out" >&2; return "$rc" ;;
  esac
}

# Starts a FRESH ZAP daemon: checkForUpdates=false and an explicit JVM heap
# (both fixed at container start, per the bench report's §4.4 fix), plus an
# explicit Docker CONTAINER memory ceiling - the addition this leg made after
# the heap flag alone still let the container get OOM-killed. See
# bench/results/b7-dast-juiceshop/README.md for the full, attempt-by-attempt
# account of why 4g is what is used below (a --memory ceiling of 4g, 8g and a
# heap of 2048m, 3072m were all tried against the AJAX SPIDER specifically and
# all still OOM-killed the container; the eventual fix for the ACTIVE SCAN was
# not more memory but disabling one specific scan rule - see cmd_zap below).
cmd_zap_start() {
  docker rm -f "$ZAP_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$ZAP_CONTAINER" --memory=4g --memory-swap=4g \
    -p "127.0.0.1:$ZAP_PORT:$ZAP_PORT" "$ZAP_IMAGE" \
    zap.sh -daemon -host 0.0.0.0 -port "$ZAP_PORT" \
    -config api.disablekey=true \
    -config "api.addrs.addr.name=.*" \
    -config api.addrs.addr.regex=true \
    -config start.checkForUpdates=false \
    -Xmx2048m >/dev/null
  local tries=0
  until curl -sS --max-time 3 "$ZAP_API/JSON/core/view/version/" >/dev/null 2>&1; do
    tries=$(( tries + 1 ))
    (( tries < 30 )) || { printf 'bench: ZAP API never came up on %s\n' "$ZAP_API" >&2; return 2; }
    sleep 2
  done
}

_zap_api() {
  local path=$1 tries=0 out
  while (( tries < 5 )); do
    if out=$(curl -sS --max-time 30 "$ZAP_API$path"); then printf '%s' "$out"; return 0; fi
    tries=$(( tries + 1 )); sleep 3
  done
  printf 'bench: ZAP API failed after retries: %s\n' "$path" >&2
  return 1
}

_zap_json_get() {
  python3 -c "
import json,sys
print(json.loads(sys.argv[1]).get(sys.argv[2], ''))
" "$1" "$2"
}

# Drives ZAP entirely over its API - never zap-full-scan.py / zap-baseline.py
# - polling `/JSON/.../status/` directly with retries so a transient proxy
# reset never aborts the run, per the bench report's §4.4 fix.
#
# THE AJAX SPIDER IS NOT RUN.  It (and, separately, the DOM-XSS active-scan
# rule, plugin 40026, both of which drive a headless-firefox/Crawljax
# component) OOM-killed this leg's ZAP container on every attempt measured -
# see bench/results/b7-dast-juiceshop/README.md for the full account. Plugin
# 40026 is disabled explicitly below so the rest of the active scan's ~100
# other rules still complete; the ajax spider has no equivalent per-technique
# disable and is skipped outright, which is this leg's one stated,
# non-silent scope reduction against ZAP's own SPA-crawling advantage.
cmd_zap() {
  local out=$1
  mkdir -p "$out/raw"
  ZAP_TARGET_HOST=$(_zap_bridge_ip)
  [[ -n $ZAP_TARGET_HOST ]] || { printf 'bench: could not resolve the target container bridge IP\n' >&2; return 2; }
  local target="http://$ZAP_TARGET_HOST:3000/"

  _zap_api "/JSON/core/action/accessUrl/?url=$target" >/dev/null
  _zap_api "/JSON/ascan/action/disableScanners/?ids=40026" >/dev/null

  local r sid pct
  r=$(_zap_api "/JSON/spider/action/scan/?url=$target&maxChildren=&recurse=true&contextName=&subtreeOnly=")
  sid=$(_zap_json_get "$r" scan)
  local deadline=$(( $(date +%s) + 300 ))
  while :; do
    pct=$(_zap_json_get "$(_zap_api "/JSON/spider/view/status/?scanId=$sid")" status)
    [[ $pct == 100 ]] && break
    (( $(date +%s) < deadline )) || break
    sleep 5
  done
  _zap_api "/JSON/spider/view/results/?scanId=$sid" >"$out/raw/spider-results.json"

  deadline=$(( $(date +%s) + 120 ))
  while :; do
    local left
    left=$(_zap_json_get "$(_zap_api "/JSON/pscan/view/recordsToScan/")" recordsToScan)
    [[ $left == 0 ]] && break
    (( $(date +%s) < deadline )) || break
    sleep 5
  done

  r=$(_zap_api "/JSON/ascan/action/scan/?url=$target&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=")
  sid=$(_zap_json_get "$r" scan)
  deadline=$(( $(date +%s) + 1800 ))
  while :; do
    pct=$(_zap_json_get "$(_zap_api "/JSON/ascan/view/status/?scanId=$sid")" status)
    [[ $pct == 100 ]] && break
    (( $(date +%s) < deadline )) || { _zap_api "/JSON/ascan/action/stop/?scanId=$sid" >/dev/null; break; }
    sleep 15
  done

  _zap_api "/JSON/core/view/alerts/?baseurl=&start=&count=" >"$out/raw/alerts.json"
  _zap_api "/JSON/core/view/numberOfAlerts/?baseurl=" >"$out/raw/alert-count.json"
  _zap_api "/JSON/core/view/urls/?baseurl=" >"$out/raw/urls.json"
  _zap_api "/JSON/core/view/version/" >"$out/raw/version.json"
}

cmd_zap_teardown() {
  docker rm -f "$ZAP_CONTAINER" >/dev/null 2>&1 || true
}

# Normalises BOTH tools' already-collected raw output into
# OUTDIR/<tool>/normalised.jsonl + MANIFEST, matching bench/run-tool.sh's own
# output shape exactly so bench/score.sh reads either leg identically.
cmd_normalise() {
  local out=$1 corpus=dast-juiceshop
  local commit=''
  # shellcheck source=bench/lib/corpus.sh
  source "$BENCH_ROOT/lib/corpus.sh"
  if corpus_load "$BENCH_ROOT/corpus.lock" 2>/dev/null && corpus_has "$corpus"; then
    commit=$(corpus_field "$corpus" image-digest)
  fi

  local tool
  for tool in scoursh-dast zap; do
    local dest=$out/$tool
    [[ -d $dest/raw ]] || { printf 'bench: no raw output at %s/raw - run scoursh/zap first\n' "$dest" >&2; return 2; }
    "${tool}_run" "$dest/raw"
    BENCH_ZAP_RAW_DIR=$dest/raw
    local version
    version=$("${tool}_version")
    "${tool}_normalise" "$dest/raw" |
      bench_records_to_jsonl "$tool" "$version" "$corpus" >"$dest/normalised.jsonl"
    {
      printf 'tool: %s\n' "$tool"
      printf 'version: %s\n' "$version"
      printf 'corpus: %s\n' "$corpus"
      printf 'corpus-commit: %s\n' "${commit:-unpinned}"
      printf 'scan-root: (none - a running HTTP target, not a directory)\n'
      printf 'records: %s\n' "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')"
      printf 'claims-categories: %s\n' "$("${tool}_scope" | tr '\n' ' ' | sed 's/ $//')"
      printf 'ground-truth: bench/labels/dast-juiceshop.truth\n'
      case $tool in
        scoursh-dast)
          printf 'gate: scan.sh dast --target dast-test-target --authed --intensity active --i-own-target dast-test-target --format json (NOT --use-engines; --intensity active + --i-own-target is required to reach scoursh'"'"'s injection/tier-5 checks at all, since the DAST engine default is passive-only)\n'
          ;;
        zap)
          printf 'gate: ZAP %s daemon, -config start.checkForUpdates=false, -Xmx2048m, docker --memory=4g, driven entirely over its own JSON API (never zap-full-scan.py/zap-baseline.py): traditional spider (recurse) -> passive-scan drain -> active scan (all default-policy rules at their default strength/threshold EXCEPT plugin 40026, Cross Site Scripting (DOM Based), disabled - see this leg'"'"'s README for why). The AJAX spider was not run - see the README.\n' "$version"
          ;;
      esac
    } >"$dest/MANIFEST"
    printf 'bench: %s @ %s -> %s (%s record(s))\n' \
      "$tool" "$version" "$dest/normalised.jsonl" "$(wc -l <"$dest/normalised.jsonl" | tr -d ' ')"
  done
}

main() {
  local cmd=${1:-}
  case $cmd in
    setup) cmd_setup ;;
    scoursh) cmd_scoursh "${2:?OUTDIR required}" ;;
    zap-start) cmd_zap_start ;;
    zap) cmd_zap "${2:?OUTDIR required}" ;;
    normalise) cmd_normalise "${2:?OUTDIR required}" ;;
    teardown) cmd_zap_teardown ;;
    *) usage >&2; return 2 ;;
  esac
}

main "$@"
