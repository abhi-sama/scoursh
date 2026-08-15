#!/usr/bin/env bash
# tools/dast-test-identities.sh - provision two distinct test identities in
# the local DAST test target (tools/dast-test-target.sh), for exercising
# broken-access-control / cross-user checks once modules/dast/authz.sh lands
# (docs/STEP5-DAST-PLAN.md, DAST-29).
#
# Credentials convention: this repository's frozen credential convention
# (rules/RULE-FORMAT.md §9.6.2, config/auth.conf's `secret-file` key) is "an
# absolute path to a 600 file holding the credential, preferred over an
# inline value". This script follows that convention rather than inventing a
# new one: each identity's generated password is written to its own 600
# file under .dast-test-target/ (gitignored, local-only, never committed),
# and a companion .dast-test-target/auth.conf is written in the real
# config/auth.conf record format, referencing those secret-files by path.
# Nothing here is a shipped default and no credential is ever printed,
# logged, or passed as a command-line argument (docs/FOUNDATION.md
# tension 9) - registration bodies go over stdin to
# tools/dast-test-target/http-client.js, exactly as that file's own header
# explains.
#
# Idempotent across both a still-running target (the account is already
# there; re-registration is REFUSED and that refusal is the expected,
# successful outcome - see dti_provision) and a stopped-then-restarted one
# (the container's account database does not persist across restarts, so
# re-registering with the same, already-persisted password is what makes the
# old secret-file valid again) - see dti_provision's own comment for why
# skip-if-exists would be wrong here.
#
# Emits two lines on stdout, one per identity, machine-readable:
#   <label> <email> <secret-file-path>
# tests/e2e/dast-target-smoke.sh consumes exactly this.
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tools/dast-test-target/env.sh
source "$ROOT/tools/dast-test-target/env.sh"
# shellcheck source=tools/dast-test-target/http.sh
source "$ROOT/tools/dast-test-target/http.sh"

DTT_TARGET_ID=dast-test-target

dti_require_target_running() {
  local running
  running=$(docker ps --filter "name=^/${DTT_CONTAINER}\$" --format '{{.Names}}')
  [[ -n $running ]] || die "$SCOURSH_EXIT_INPUT" \
    "dast-test-identities: $DTT_CONTAINER is not running - start it first: tools/dast-test-target.sh"
}

# `dti_provision LABEL EMAIL SECRET_FILE` - idempotent, but NOT by skipping
# registration when a secret-file already exists: tools/dast-test-target.sh
# --stop followed by start gives a brand-new container with an EMPTY Juice
# Shop database (the account database is not a volume - it resets with the
# container), while .dast-test-target/'s secret-files are local state that
# outlives any one container. Skipping registration whenever the file
# already existed would silently leave a locally-remembered password with
# no matching account in a freshly (re)started target. Idempotency instead
# comes from re-registering every time (reusing the persisted password when
# one already exists) and, when that registration is REFUSED as a duplicate,
# from proving the account is usable rather than assuming either way.
#
# THIS FUNCTION USED TO CLAIM THE OPPOSITE, AND THE CLAIM WAS WRONG.  Its own
# header stated that this pinned image "accepts a repeat registration rather
# than 400ing on a duplicate email - verified against
# bkimminich/juice-shop:v20.1.1". Re-measured against that same image while
# building DAST-03's live test, it 400s:
#
#   first registration:  201
#   same email again:    400 {"message":"Validation error",
#                             "errors":[{"field":"email",
#                                        "message":"email must be unique"}]}
#   login afterwards:    200
#
# so running this script twice against one still-running container died, and
# every run after the first one failed on a target that was in fact perfectly
# provisioned. A duplicate refusal is therefore treated as the SUCCESS it is -
# but only after a login proves the persisted password still opens the account,
# because "the email is taken" and "the email is taken by an account whose
# password we hold" are different facts and only the second one is idempotency.
dti_provision() {
  local label=$1 email=$2 secret_file=$3 password reused=false

  if [[ -f $secret_file ]]; then
    IFS= read -r password <"$secret_file" || true
    reused=true
  else
    password=$(dtt_gen_password)
    : >"$secret_file"
    chmod 600 "$secret_file"
    printf '%s' "$password" >"$secret_file"
  fi

  local reg_body reg_out reg_status
  reg_body=$(printf '{"email":"%s","password":"%s","passwordRepeat":"%s","securityQuestion":{"id":1},"securityAnswer":"scoursh-local-test-fixture"}' \
    "$email" "$password" "$password")
  reg_out=$(dtt_call POST /api/Users '' "$reg_body")
  reg_status=${reg_out%%$'\n'*}

  if [[ $reg_status == 2* ]]; then
    if [[ $reused == true ]]; then
      log_info "dast-test-identities: $label re-registered against a restarted target, reusing its existing password ($email)"
    else
      log_info "dast-test-identities: provisioned $label ($email)"
    fi
    return 0
  fi

  # Registration refused. The only acceptable reason is that this account is
  # already there from an earlier run of this script against this same still-
  # running container, and the password we hold still opens it.
  local login_out login_status
  login_out=$(dtt_call POST /rest/user/login '' \
    "$(printf '{"email":"%s","password":"%s"}' "$email" "$password")")
  login_status=${login_out%%$'\n'*}
  if [[ $login_status == 200 ]]; then
    log_info "dast-test-identities: $label already exists on the running target and its stored password still works ($email)"
    return 0
  fi

  if [[ $reused == true ]]; then
    die "$SCOURSH_EXIT_INCOMPLETE" \
      "dast-test-identities: $label ($email) could not be registered (status $reg_status) and the stored password in $secret_file does not open the existing account (login status $login_status). Delete $secret_file and restart the target (tools/dast-test-target.sh --stop, then start) to provision it fresh."
  fi
  die "$SCOURSH_EXIT_INCOMPLETE" \
    "dast-test-identities: registration of $label ($email) failed, status $reg_status, and the newly generated password does not open an existing account either (login status $login_status). The target may already hold this account from a run whose secret-file was deleted; restart it (tools/dast-test-target.sh --stop, then start) to reset its account database."
}

dti_main() {
  require_cmd docker
  dti_require_target_running

  mkdir -p "$DTT_STATE_DIR"
  chmod 700 "$DTT_STATE_DIR"

  local email_a=scoursh-dast-test-a@scoursh.local
  local email_b=scoursh-dast-test-b@scoursh.local
  local secret_a="$DTT_STATE_DIR/identity-a.secret"
  local secret_b="$DTT_STATE_DIR/identity-b.secret"

  dti_provision a "$email_a" "$secret_a"
  dti_provision b "$email_b" "$secret_b"

  : >"$DTT_AUTH_CONF"
  chmod 600 "$DTT_AUTH_CONF"
  {
    printf '# %s/auth.conf - local DAST test identities, rules/RULE-FORMAT.md §9.6.2.\n' "$DTT_STATE_DIR"
    printf '# Generated by tools/dast-test-identities.sh. Not committed (see .gitignore).\n\n'
    printf 'id: %s.a\n' "$DTT_TARGET_ID"
    printf 'mode: form\n'
    printf 'username: %s\n' "$email_a"
    printf 'secret-file: %s\n' "$secret_a"
    printf 'login-path: /rest/user/login\n\n'
    printf 'id: %s.b\n' "$DTT_TARGET_ID"
    printf 'mode: form\n'
    printf 'username: %s\n' "$email_b"
    printf 'secret-file: %s\n' "$secret_b"
    printf 'login-path: /rest/user/login\n'
  } >"$DTT_AUTH_CONF"

  printf 'a %s %s\n' "$email_a" "$secret_a"
  printf 'b %s %s\n' "$email_b" "$secret_b"
}

dti_main
