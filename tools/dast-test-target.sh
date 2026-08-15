#!/usr/bin/env bash
# tools/dast-test-target.sh - start/stop a local, operator-owned DAST test
# target (OWASP Juice Shop, in Docker) that scoursh's DAST layer is
# authorized to scan.
#
# Owns:
#   docs/DAST-TEST-TARGET-AUTHORIZATION.md (the authorization record this
#     tooling exists to satisfy)
#   tools/dast-test-target/scope.conf (the config/scope.conf record that
#     authorizes exactly this target - rules/RULE-FORMAT.md §9.4)
#
# WHY DOCKER, WHY LOCAL.  DAST work was operator-blocked because
# there was no staging environment to point it at, and the operator will not
# scan anything not owned outright. Juice Shop is a deliberately vulnerable
# app built for exactly this purpose (broken access control, injection, and
# every other flaw class this tool's rule catalog targets); running it in
# Docker on the operator's own machine, on a fixed local port, makes it
# unambiguously the operator's own asset with no legal ambiguity - the same
# reasoning docs/DAST-TEST-TARGET-AUTHORIZATION.md records formally.
#
# This is NOT a scan-time script. Nothing under lib/, modules/, or scan.sh
# ever sources or execs this file; an operator (or an agent acting on the
# operator's behalf) runs it by hand before pointing scan.sh --module dast
# at 127.0.0.1, exactly the way tools/vendor-engines.sh is run by hand before
# a scan, never during one.
#
# NO BYPASS, EVEN HERE.  tests/lint-shell.sh's tension-19 "no bypass" check
# forbids curl/wget/nc anywhere outside lib/http.sh and the one documented
# tools/vendor-engines.sh exception. Rather than adding a third exception,
# the one HTTP call this script needs (the readiness poll) runs INSIDE the
# container over `docker exec`, via tools/dast-test-target/http-client.js -
# see that file's own header for the full rationale. The container lifecycle
# itself (docker run/exec/cp/rm) is not a network call lib/http.sh's gate has
# any business mediating: config/scope.conf authorizes scan TARGETS, not how
# the operator's own Docker daemon is driven.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"

DTT_READY_TIMEOUT=${SCOURSH_DAST_TEST_TARGET_READY_TIMEOUT:-90}

dtt_usage() {
  cat <<EOF
tools/dast-test-target.sh [start] | --stop | --status

Starts (or reuses) a local OWASP Juice Shop container for DAST testing,
fixed at $DTT_URL. Idempotent in both directions: starting an already-running
target is a no-op that reprints the URL; stopping an already-stopped target
is a no-op.

Env overrides: SCOURSH_DAST_TEST_TARGET_PORT (default 3400),
SCOURSH_DAST_TEST_TARGET_IMAGE (default $DTT_IMAGE),
SCOURSH_DAST_TEST_TARGET_READY_TIMEOUT seconds (default 90).
EOF
}

dtt_container_state() {
  # Prints "running", "stopped" (exists but not running), or "absent".
  # --filter/--format sidestep engine_files' "no bare grep" lint entirely -
  # docker itself does the matching, not a piped grep.
  local running
  running=$(docker ps --filter "name=^/${DTT_CONTAINER}\$" --format '{{.Names}}')
  if [[ -n $running ]]; then
    printf 'running'
    return 0
  fi
  local any
  any=$(docker ps -a --filter "name=^/${DTT_CONTAINER}\$" --format '{{.Names}}')
  if [[ -n $any ]]; then
    printf 'stopped'
  else
    printf 'absent'
  fi
}

dtt_wait_ready() {
  local waited=0
  while (( waited < DTT_READY_TIMEOUT )); do
    local out status
    if out=$(printf '%s' '{"method":"GET","path":"/rest/admin/application-version"}' \
      | docker exec -i "$DTT_CONTAINER" /nodejs/bin/node "/tmp/scoursh-http-client.js" 2>/dev/null); then
      status=${out%%$'\n'*}
      [[ $status == 200 ]] && return 0
    fi
    sleep 1
    waited=$(( waited + 1 ))
  done
  return 1
}

dtt_start() {
  require_cmd docker

  local state
  state=$(dtt_container_state)
  if [[ $state == running ]]; then
    log_info "dast-test-target: already running at $DTT_URL"
    printf '%s\n' "$DTT_URL"
    return 0
  fi
  if [[ $state == stopped ]]; then
    log_info 'dast-test-target: removing a stale stopped container before recreating it'
    docker rm -f "$DTT_CONTAINER" >/dev/null
  fi

  log_info "dast-test-target: starting $DTT_IMAGE on $DTT_URL"
  docker run -d --name "$DTT_CONTAINER" -p "${DTT_PORT}:3000" "$DTT_IMAGE" >/dev/null

  docker cp "$DTT_CLIENT_JS" "$DTT_CONTAINER:/tmp/scoursh-http-client.js" >/dev/null

  if ! dtt_wait_ready; then
    docker logs "$DTT_CONTAINER" >&2 || true
    die "$SCOURSH_EXIT_INCOMPLETE" \
      "dast-test-target: $DTT_CONTAINER did not become ready within ${DTT_READY_TIMEOUT}s"
  fi

  log_info "dast-test-target: ready at $DTT_URL"
  printf '%s\n' "$DTT_URL"
}

dtt_stop() {
  require_cmd docker
  local state
  state=$(dtt_container_state)
  if [[ $state == absent ]]; then
    log_info 'dast-test-target: nothing to stop'
    return 0
  fi
  docker rm -f "$DTT_CONTAINER" >/dev/null
  log_info 'dast-test-target: stopped and removed'
}

dtt_status() {
  require_cmd docker
  local state
  state=$(dtt_container_state)
  printf '%s %s\n' "$state" "$DTT_URL"
}

case ${1:-start} in
  start) dtt_start ;;
  --stop) dtt_stop ;;
  --status) dtt_status ;;
  -h | --help) dtt_usage ;;
  *)
    dtt_usage >&2
    die "$SCOURSH_EXIT_USAGE" "unknown argument: '$1'"
    ;;
esac
