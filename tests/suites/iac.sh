#!/usr/bin/env bash
# tests/suites/iac.sh - modules/iac/{parse.sh,run.sh} and its seed pattern
# packs: terraform.rules (docs/DESIGN.md §13 step 4's cloud half), helm.rules
# (§13 step 4's container half, the "IaC: Helm chart checks via the
# pattern-rule engine" ticket), dockerfile.rules (§13 step 4's container
# half, the "IaC: Dockerfile checks via the pattern-rule engine" ticket),
# and docker-compose.rules (§13 step 4's container half, this ticket).
#
# Modeled on tests/suites/sast.sh's go.rules section (§13 step 3c precedent):
# one true-positive fixture per rule id under tests/fixtures/vuln/, one
# true-negative (safe-equivalent) fixture per rule id under
# tests/fixtures/clean/, both directories scanned wholesale exactly like the
# real end-to-end shape - each pack's own `files:` glob (`*.tf` for
# terraform.rules; `values.yaml` / `templates/*.yaml` for helm.rules;
# `Dockerfile`/`Dockerfile.*`/`*.dockerfile` for dockerfile.rules;
# `docker-compose*.y*ml` / `compose*.y*ml` for docker-compose.rules) is what
# does the filtering out of the fixtures that belong to a different pack (or,
# for dockerfile.rules' docker-compose.yml/helm fixtures below, to no pack at
# all).
#
# Covers the terraform.rules ticket's acceptance criteria:
#   - `scan_dispatch iac` no longer no-ops for a fixture .tf file matching
#     each seed rule (the exit-code-flip section, and the real `scan.sh iac`
#     subprocess calls below)
#   - each IAC-TF-* id fires on its vuln fixture and stays quiet on its
#     clean fixture
#   - findings emitted by the iac module carry module=iac, not module=sast
#     (lib/findings.sh's _fp_profile_for has a dedicated `iac` branch; this
#     is what proves modules/iac/parse.sh's own emission path, not a reused
#     sast one, actually ran)
#
# Covers the Helm ticket's acceptance criteria, in the "helm.rules" and
# "cross-check" sections below:
#   - each IAC-HELM-* id fires on true-positive fixtures covering BOTH
#     values.yaml and templates/*.yaml, and stays quiet on the clean
#     equivalent of each
#   - a cross-check fixture proves helm.rules and the other IaC packs that
#     actually exist on disk (terraform.rules, dockerfile.rules) do not fire
#     on each other's fixtures, and that helm.rules stays silent on a
#     docker-compose fixture (that ticket's own "excluding docker-compose"
#     scope statement) - see that section's own header comment for why this
#     substitutes for a literal "Kubernetes rule pack" cross-check: no such
#     pack exists yet anywhere in this codebase
#
# Covers this (Dockerfile) ticket's acceptance criteria:
#   - each IAC-DOCKER-* id fires on its tests/fixtures/vuln/ Dockerfile
#     fixture and stays quiet across every tests/fixtures/clean/ Dockerfile
#     fixture (no false positives)
#   - a docker-compose.yml and a Helm values.yaml fixture, each containing
#     content that would trip every IAC-DOCKER-* pattern if the file path
#     matched, produce NO iac findings at all - proving the `files:` glob
#     scoping, not the pattern content, is what keeps those formats out
#   - dockerfile.rules lives at modules/iac/dockerfile.rules and passes
#     tests/lint-rules.sh (run separately by tests/run-tests.sh lint-rules)
#
# Covers the docker-compose.rules ticket's acceptance criteria:
#   - each IAC-COMPOSE-* id fires on its vuln fixture and stays quiet on its
#     clean fixture
#   - a Kubernetes-manifest-shaped fixture and a Helm values.yaml-shaped
#     fixture, both containing content that WOULD match every IAC-COMPOSE-*
#     pattern if the engine ever inspected their content, produce zero
#     IAC-COMPOSE-* findings - the "cross-shape scoping" section
#   - a mixed directory holding one file of each IaC shape (Terraform,
#     docker-compose, Kubernetes-shaped, Helm-shaped) never lets an
#     IAC-COMPOSE-* id attach to the non-compose files or an IAC-TF-* id
#     attach to the non-Terraform files - the "double-fire" section
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=modules/iac/parse.sh
source "$ROOT/modules/iac/parse.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/iac-suite
rm -rf "$W"
mkdir -p "$W"

# =============================================================================
printf -- '\n-- terraform.rules: true-positive AND true-negative, per rule id --\n'
# =============================================================================
_scan_one_pack() {
  local pack=$1 fixture=$2 rundir=$3
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=iac-suite
  SCOURSH_PATH_ROOT=$(path_root_cell "$fixture")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$fixture")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_IAC_MAX_MATCHES_PER_FILE=200
  CHECKS_REGISTRY_SETS=(pkset)
  records_load "$ROOT/modules/iac/$pack.rules" pattern-rule pkset >/dev/null
  sast_index_checks
  local -a ids=()
  local n i
  n=$(records_count pkset)
  for (( i = 0; i < n; i++ )); do ids+=("$(records_id pkset "$i")"); done
  # `fixture` is always a DIRECTORY, mirroring tests/suites/sast.sh's own
  # _scan_one_pack - docs/DESIGN.md §5's grammar is `--path DIR`, never a
  # single file.
  iac_scan_tree "$fixture" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
}

_ids_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[check_id]}"
  done <"$rundir/findings.fields"
}

_modules_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[module]}"
  done <"$rundir/findings.fields"
}

# _ids_and_paths_found RUNDIR - one "check_id@loc_path" token per finding,
# used by the cross-check section below to prove WHICH file (not merely
# whether some file) triggered a given check id, and by the cross-shape
# scoping section to pin BOTH which check fired AND which file it was
# attributed to in one substring check.
_ids_and_paths_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s@%s\n' "${_DF[check_id]}" "${_DF[loc_path]}"
  done <"$rundir/findings.fields"
}

# _paths_found RUNDIR - one loc_path per finding, used by the dockerfile.rules
# section below to prove which file (not which check id) triggered.
_paths_found() {
  local rundir=$1 line
  [[ -s $rundir/findings.fields ]] || return 0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[loc_path]}"
  done <"$rundir/findings.fields"
}

# Loads N pattern-rule packs at once into distinct CHECKS_REGISTRY_SETS
# entries (mirrors _scan_one_pack, generalised past a single pack) so a
# cross-pack scoping test can run terraform.rules and docker-compose.rules
# together over one fixture tree, exactly like a real `scan.sh iac` run over
# a repo that has both Terraform and docker-compose files in it.
_scan_multi_pack() {
  local fixture=$1 rundir=$2
  shift 2
  local -a packs=("$@")
  rm -rf "$rundir"
  run_init "$rundir"
  SCOURSH_RUN_ID=iac-suite
  SCOURSH_PATH_ROOT=$(path_root_cell "$fixture")
  SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$fixture")
  export SCOURSH_RUN_ID SCOURSH_PATH_ROOT SCOURSH_SCAN_ROOT_ID
  SCOURSH_IAC_MAX_MATCHES_PER_FILE=200
  local -a sets=()
  local -a ids=()
  local pack setname n i
  for pack in "${packs[@]}"; do
    setname="pkset_${pack//[^A-Za-z0-9_]/_}"
    sets+=("$setname")
    records_load "$ROOT/modules/iac/$pack.rules" pattern-rule "$setname" >/dev/null
  done
  CHECKS_REGISTRY_SETS=("${sets[@]}")
  sast_index_checks
  for setname in "${sets[@]}"; do
    n=$(records_count "$setname")
    for (( i = 0; i < n; i++ )); do ids+=("$(records_id "$setname" "$i")"); done
  done
  iac_scan_tree "$fixture" "${ids[@]+"${ids[@]}"}"
  findings_merge "$rundir"
}

TF_IDS='IAC-TF-OPEN_CIDR-01 IAC-TF-PUBLIC_ACL-01 IAC-TF-UNENCRYPTED-01 IAC-TF-KEY_ROTATION_DISABLED-01 IAC-TF-PUBLIC_IP-01 IAC-TF-HARDCODED_SECRET-01 IAC-TF-RDS_PUBLIC-01'

_scan_one_pack terraform "$ROOT/tests/fixtures/vuln" "$W/run-tf-vuln"
_tf_vuln_found=$(_ids_found "$W/run-tf-vuln")
for _want_id in $TF_IDS; do
  t_case "terraform: $_want_id true-positive detection"
  assert_contains "$_tf_vuln_found" "$_want_id" \
    "$_want_id fires on its tests/fixtures/vuln/*.tf fixture - fails if the pattern, files glob, or context directive silently drops the match"
done

_scan_one_pack terraform "$ROOT/tests/fixtures/clean" "$W/run-tf-clean"
_tf_clean_found=$(_ids_found "$W/run-tf-clean")
for _safe_id in $TF_IDS; do
  t_case "terraform: $_safe_id stays quiet on its safe equivalent"
  assert_not_contains "$_tf_clean_found" "$_safe_id" \
    "$_safe_id does NOT fire on its tests/fixtures/clean/*.tf fixture - fails if the safe rewrite still matches the pattern (a true-negative fixture that isn't actually negative)"
done

t_case 'every finding the iac module emits carries module=iac, not module=sast'
_tf_vuln_modules=$(_modules_found "$W/run-tf-vuln")
assert_not_contains "$_tf_vuln_modules" 'sast' \
  'no finding from this run reports module=sast - fails if iac_scan_tree fell through to sast_scan_file/_sast_emit_finding instead of its own emission path'
assert_contains "$_tf_vuln_modules" 'iac' \
  'at least one finding reports module=iac - sanity check that the assertion above is not vacuously true on an empty run'

unset TF_IDS _tf_vuln_found _tf_clean_found _want_id _safe_id _tf_vuln_modules

# =============================================================================
printf -- '\n-- helm.rules: true-positive AND true-negative, per rule id, across values.yaml AND templates/*.yaml --\n'
# =============================================================================
# Covers this ticket's AC1/AC3: tests/fixtures/vuln/values.yaml and
# tests/fixtures/vuln/templates/deployment.yaml each independently trigger
# every IAC-HELM-* id (exposed/host-published port, sensitive hostPath bind
# mount, plaintext secret); tests/fixtures/clean/ carries the safe rewrite of
# each in both locations.
HELM_IDS='IAC-HELM-HOST_PORT-01 IAC-HELM-HOST_MOUNT-01 IAC-HELM-HARDCODED_SECRET-01'

_scan_one_pack helm "$ROOT/tests/fixtures/vuln" "$W/run-helm-vuln"
_helm_vuln_found=$(_ids_found "$W/run-helm-vuln")
_helm_vuln_paths=$(_ids_and_paths_found "$W/run-helm-vuln")
for _want_id in $HELM_IDS; do
  t_case "helm: $_want_id true-positive detection"
  assert_contains "$_helm_vuln_found" "$_want_id" \
    "$_want_id fires on its tests/fixtures/vuln/{values.yaml,templates/deployment.yaml} fixture - fails if the pattern, files glob, or context directive silently drops the match"
done

t_case 'helm: each IAC-HELM-* id fires from values.yaml specifically (not only from templates/)'
assert_contains "$_helm_vuln_paths" 'values.yaml' \
  'at least one finding has loc_path=values.yaml - fails if the files: glob only ever matched templates/*.yaml, silently leaving values.yaml uncovered'

t_case 'helm: each IAC-HELM-* id fires from templates/deployment.yaml specifically (not only from values.yaml)'
assert_contains "$_helm_vuln_paths" 'templates/deployment.yaml' \
  'at least one finding has loc_path=templates/deployment.yaml - fails if the files: glob only ever matched values.yaml, silently leaving templates/*.yaml uncovered (the Go-template-directive handling this ticket calls out)'

_scan_one_pack helm "$ROOT/tests/fixtures/clean" "$W/run-helm-clean"
_helm_clean_found=$(_ids_found "$W/run-helm-clean")
for _safe_id in $HELM_IDS; do
  t_case "helm: $_safe_id stays quiet on its safe equivalent"
  assert_not_contains "$_helm_clean_found" "$_safe_id" \
    "$_safe_id does NOT fire on tests/fixtures/clean/{values.yaml,templates/deployment.yaml} - fails if the safe rewrite (containerPort not hostPort, configMap not hostPath, secretKeyRef not a literal) still matches the pattern"
done

t_case 'every finding helm.rules emits carries module=iac, not module=sast'
_helm_vuln_modules=$(_modules_found "$W/run-helm-vuln")
assert_not_contains "$_helm_vuln_modules" 'sast' \
  'no finding from this run reports module=sast - fails if iac_scan_tree fell through to the sast emission path'
assert_contains "$_helm_vuln_modules" 'iac' \
  'at least one finding reports module=iac - sanity check that the assertion above is not vacuously true on an empty run'

# =============================================================================
printf -- '\n-- cross-check: helm.rules stays scoped to Helm, and does not overlap the other IaC pack --\n'
# =============================================================================
# This ticket's AC4 asks for a cross-check fixture proving "the existing
# Kubernetes rule pack's checks do not also fire on a Helm template".  As of
# this change there is no modules/iac/kubernetes.rules (or any other
# Kubernetes-manifest pattern pack) anywhere in this codebase - confirmed
# against dev's tip, which carries only terraform.rules under modules/iac/
# before this ticket - so that literal cross-check has nothing to run
# against yet (see modules/iac/helm.rules' own header for the same note).
# The two boundaries below are what IS testable today, and are the closest
# real substitute:
#   1. terraform.rules - the only other IaC pack that exists on disk - does
#      not fire on ANY Helm fixture, and helm.rules does not fire on ANY
#      Terraform fixture, both via the `files:` glob alone (proves pack
#      isolation, the same property AC4 is protecting).
#   2. helm.rules stays silent on a docker-compose fixture that deliberately
#      reuses the exact "password:" vocabulary IAC-HELM-HARDCODED_SECRET-01
#      matches (this ticket's own text: "scoped to Helm only and excluding
#      docker-compose").
t_case 'cross-check: terraform.rules does not fire anywhere under tests/fixtures/vuln (no *.tf files touched by the helm scan already proves this; this asserts it explicitly)'
assert_not_contains "$_helm_vuln_found" 'IAC-TF-' \
  'no IAC-TF-* id appears in a helm.rules-only scan of tests/fixtures/vuln - fails if helm.rules and terraform.rules checks were somehow merged into one registry set'

_scan_one_pack terraform "$ROOT/tests/fixtures/vuln" "$W/run-tf-vs-helm-fixtures"
_tf_vs_helm_found=$(_ids_found "$W/run-tf-vs-helm-fixtures")
t_case 'cross-check: terraform.rules does not fire on the Helm values.yaml/templates fixtures'
assert_not_contains "$_tf_vs_helm_found" 'IAC-HELM-' \
  'no IAC-HELM-* id appears in a terraform.rules-only scan (which walks the same tests/fixtures/vuln tree, values.yaml and templates/deployment.yaml included) - fails if terraform.rules files: *.tf glob were loosened enough to also match Helm sources'

t_case 'cross-check: helm.rules does not fire on any *.tf fixture'
assert_not_contains "$_helm_vuln_found" 'IAC-TF-HARDCODED_SECRET' \
  'sanity check on the inverse direction: a helm.rules-only scan of tests/fixtures/vuln (which also contains tf_hardcoded_secret.tf) reports no Terraform-family id'

_scan_one_pack helm "$ROOT/tests/fixtures/vuln" "$W/run-helm-vs-compose"
_helm_vs_compose_paths=$(_ids_and_paths_found "$W/run-helm-vs-compose")
t_case 'cross-check: helm.rules stays silent on tests/fixtures/vuln/docker-compose.yml (explicitly out of scope)'
assert_not_contains "$_helm_vs_compose_paths" 'docker-compose' \
  'no finding has loc_path=docker-compose.yml - fails if the files: glob (values.yaml / templates/*.yaml) accidentally matched a docker-compose file, or matched by content rather than path'

unset HELM_IDS _helm_vuln_found _helm_vuln_paths _helm_clean_found _want_id _safe_id \
  _helm_vuln_modules _tf_vs_helm_found _helm_vs_compose_paths

# =============================================================================
printf -- '\n-- dockerfile.rules: true-positive AND true-negative, per rule id --\n'
# =============================================================================
DOCKER_IDS='IAC-DOCKER-ROOT_USER-01 IAC-DOCKER-LATEST_TAG-01 IAC-DOCKER-SECRET_ENV-01 IAC-DOCKER-REMOTE_ADD-01 IAC-DOCKER-PIPE_TO_SHELL-01 IAC-DOCKER-UNPINNED_DIGEST-01'

_scan_one_pack dockerfile "$ROOT/tests/fixtures/vuln" "$W/run-docker-vuln"
_docker_vuln_found=$(_ids_found "$W/run-docker-vuln")
for _want_id in $DOCKER_IDS; do
  t_case "dockerfile: $_want_id true-positive detection"
  assert_contains "$_docker_vuln_found" "$_want_id" \
    "$_want_id fires on its tests/fixtures/vuln/ Dockerfile fixture - fails if the pattern, files glob, or context directive silently drops the match"
done

_scan_one_pack dockerfile "$ROOT/tests/fixtures/clean" "$W/run-docker-clean"
_docker_clean_found=$(_ids_found "$W/run-docker-clean")
for _safe_id in $DOCKER_IDS; do
  t_case "dockerfile: $_safe_id stays quiet on its safe equivalent"
  assert_not_contains "$_docker_clean_found" "$_safe_id" \
    "$_safe_id does NOT fire on any tests/fixtures/clean/ Dockerfile fixture - fails if the safe rewrite still matches the pattern (a true-negative fixture that isn't actually negative)"
done

t_case 'every finding the dockerfile pack emits carries module=iac, not module=sast'
_docker_vuln_modules=$(_modules_found "$W/run-docker-vuln")
assert_not_contains "$_docker_vuln_modules" 'sast' \
  'no finding from this run reports module=sast - fails if iac_scan_tree fell through to sast_scan_file/_sast_emit_finding instead of its own emission path'
assert_contains "$_docker_vuln_modules" 'iac' \
  'at least one finding reports module=iac - sanity check that the assertion above is not vacuously true on an empty run'

# Scope: docker-compose.yml and a Helm values.yaml live in tests/fixtures/vuln/
# alongside the Dockerfile fixtures above, and their content is deliberately
# built to trip every IAC-DOCKER-* pattern (an inline `dockerfile_inline:`
# block with FROM node:latest / curl|sh / ADD http:// / ENV API_KEY=...).
# `files:` (Dockerfile, Dockerfile.*, *.dockerfile) must never match
# docker-compose.yml or helm/values.yaml, so no finding in this same
# "$W/run-docker-vuln" run may report either path.
t_case 'docker-compose.yml is never scanned by dockerfile.rules, despite containing every trigger pattern'
_docker_vuln_paths=$(_paths_found "$W/run-docker-vuln")
assert_not_contains "$_docker_vuln_paths" 'docker-compose.yml' \
  "no finding's loc_path is docker-compose.yml - fails if the files glob accidentally admitted a non-Dockerfile path (scope creep this ticket explicitly forbids)"

t_case 'a Helm values.yaml is never scanned by dockerfile.rules'
assert_not_contains "$_docker_vuln_paths" 'helm/values.yaml' \
  "no finding's loc_path is helm/values.yaml - fails on the same scope-creep reading as the docker-compose.yml case above"

unset DOCKER_IDS _docker_vuln_found _docker_clean_found _want_id _safe_id _docker_vuln_modules _docker_vuln_paths

# =============================================================================
printf -- '\n-- docker-compose.rules: true-positive AND true-negative, per rule id --\n'
# =============================================================================
COMPOSE_IDS='IAC-COMPOSE-EXPOSED_PORT-01 IAC-COMPOSE-PRIVILEGED-01 IAC-COMPOSE-SENSITIVE_MOUNT-01 IAC-COMPOSE-PLAINTEXT_SECRET-01'

_scan_one_pack docker-compose "$ROOT/tests/fixtures/vuln" "$W/run-compose-vuln"
_compose_vuln_found=$(_ids_found "$W/run-compose-vuln")
for _want_id in $COMPOSE_IDS; do
  t_case "docker-compose: $_want_id true-positive detection"
  assert_contains "$_compose_vuln_found" "$_want_id" \
    "$_want_id fires on its tests/fixtures/vuln/docker-compose.*.yml fixture - fails if the pattern, files glob, or context directive silently drops the match"
done

_scan_one_pack docker-compose "$ROOT/tests/fixtures/clean" "$W/run-compose-clean"
_compose_clean_found=$(_ids_found "$W/run-compose-clean")
for _safe_id in $COMPOSE_IDS; do
  t_case "docker-compose: $_safe_id stays quiet on its safe equivalent"
  assert_not_contains "$_compose_clean_found" "$_safe_id" \
    "$_safe_id does NOT fire on its tests/fixtures/clean/docker-compose.*.yml fixture - fails if the safe rewrite still matches the pattern (a true-negative fixture that isn't actually negative)"
done

t_case 'every finding docker-compose.rules emits carries module=iac, not module=sast'
_compose_vuln_modules=$(_modules_found "$W/run-compose-vuln")
assert_not_contains "$_compose_vuln_modules" 'sast' \
  'no finding from this run reports module=sast - fails if iac_scan_tree fell through to sast_scan_file/_sast_emit_finding instead of its own emission path'
assert_contains "$_compose_vuln_modules" 'iac' \
  'at least one finding reports module=iac - sanity check that the assertion above is not vacuously true on an empty run'

unset COMPOSE_IDS _compose_vuln_found _compose_clean_found _want_id _safe_id _compose_vuln_modules

# =============================================================================
printf -- '\n-- cross-shape scoping: docker-compose.rules stays silent on Kubernetes/Helm-shaped files --\n'
# =============================================================================
# tests/fixtures/iac-scope/ holds one file of each IaC shape: main.tf
# (Terraform), docker-compose.yml (docker-compose), k8s-deployment.yaml (a
# Kubernetes Deployment manifest), and values.yaml (a Helm chart's
# values.yaml).  The Kubernetes and Helm fixtures deliberately carry the SAME
# hazard-looking content as docker-compose.yml (a privileged flag, a host
# port binding, a docker.sock hostPath, and a plaintext secret value) so this
# section proves the scoping is the `files:` glob (rules/RULE-FORMAT.md
# §9.1.2), never content sniffing: if it were content-based, these two
# fixtures would trip every IAC-COMPOSE-* check exactly like docker-compose.yml
# does.
_scan_one_pack docker-compose "$ROOT/tests/fixtures/iac-scope" "$W/run-compose-scope"
_scope_pairs=$(_ids_and_paths_found "$W/run-compose-scope")

t_case 'docker-compose.rules: every IAC-COMPOSE-* check still fires on the real docker-compose.yml in the mixed directory'
assert_contains "$_scope_pairs" 'IAC-COMPOSE-EXPOSED_PORT-01@tests/fixtures/iac-scope/docker-compose.yml' \
  'the exposed-port check fires on docker-compose.yml - sanity check that the directory scan itself works before trusting the negative assertions below'

t_case 'docker-compose.rules: zero findings on the Kubernetes-manifest-shaped fixture'
assert_not_contains "$_scope_pairs" '@tests/fixtures/iac-scope/k8s-deployment.yaml' \
  'no finding of any IAC-COMPOSE-* check is attributed to k8s-deployment.yaml - fails if a pattern rule matched on file CONTENT rather than the files: glob restricting it to docker-compose*/compose* paths'

t_case 'docker-compose.rules: zero findings on the Helm values.yaml-shaped fixture'
assert_not_contains "$_scope_pairs" '@tests/fixtures/iac-scope/values.yaml' \
  'no finding of any IAC-COMPOSE-* check is attributed to values.yaml - same content-vs-glob distinction as the Kubernetes case above, for the Helm shape named in this ticket'\''s acceptance criteria'

unset _scope_pairs

# =============================================================================
printf -- '\n-- double-fire: terraform.rules and docker-compose.rules together over one mixed directory --\n'
# =============================================================================
_scan_multi_pack "$ROOT/tests/fixtures/iac-scope" "$W/run-mixed" terraform docker-compose
_mixed_pairs=$(_ids_and_paths_found "$W/run-mixed")

t_case 'mixed run: IAC-TF-OPEN_CIDR-01 still fires on main.tf when docker-compose.rules is also loaded'
assert_contains "$_mixed_pairs" 'IAC-TF-OPEN_CIDR-01@tests/fixtures/iac-scope/main.tf' \
  'terraform.rules keeps working when docker-compose.rules shares the registry - sanity check before trusting the no-cross-fire assertions below'

t_case 'mixed run: IAC-COMPOSE-PRIVILEGED-01 still fires on docker-compose.yml when terraform.rules is also loaded'
assert_contains "$_mixed_pairs" 'IAC-COMPOSE-PRIVILEGED-01@tests/fixtures/iac-scope/docker-compose.yml' \
  'docker-compose.rules keeps working when terraform.rules shares the registry - sanity check before trusting the no-cross-fire assertions below'

# Deliberately narrowed to "a compose id landed on main.tf" / "a terraform id
# landed on docker-compose.yml", not "no @main.tf at all" - that would be too
# strong, since IAC-TF-OPEN_CIDR-01@main.tf is expected and asserted above.
# Each loop counts its own bad pairs and ends in a single assert_eq so a
# clean run still records an explicit PASS rather than silently emitting no
# assertion at all.
_bad_compose_on_tf=''
while IFS= read -r _pair; do
  [[ -n $_pair ]] || continue
  case $_pair in
    IAC-COMPOSE-*@tests/fixtures/iac-scope/main.tf) _bad_compose_on_tf+="$_pair "$'\n' ;;
  esac
done <<<"$_mixed_pairs"
t_case 'mixed run: no IAC-COMPOSE-* finding is ever attributed to main.tf'
assert_eq '' "$_bad_compose_on_tf" \
  "expected zero docker-compose checks attributed to main.tf, found: $_bad_compose_on_tf"

_bad_tf_on_compose=''
while IFS= read -r _pair; do
  [[ -n $_pair ]] || continue
  case $_pair in
    IAC-TF-*@tests/fixtures/iac-scope/docker-compose.yml) _bad_tf_on_compose+="$_pair "$'\n' ;;
  esac
done <<<"$_mixed_pairs"
t_case 'mixed run: no IAC-TF-* finding is ever attributed to docker-compose.yml'
assert_eq '' "$_bad_tf_on_compose" \
  "expected zero terraform checks attributed to docker-compose.yml, found: $_bad_tf_on_compose"

t_case 'mixed run: no IAC-COMPOSE-* or IAC-TF-* finding is attributed to the Kubernetes-shaped file'
assert_not_contains "$_mixed_pairs" '@tests/fixtures/iac-scope/k8s-deployment.yaml' \
  'neither pack treats k8s-deployment.yaml as its own - fails if either files: glob matched a path it should not'

t_case 'mixed run: no IAC-COMPOSE-* or IAC-TF-* finding is attributed to the Helm values.yaml-shaped file'
assert_not_contains "$_mixed_pairs" '@tests/fixtures/iac-scope/values.yaml' \
  'neither pack treats values.yaml as its own - fails if either files: glob matched a path it should not'

unset _mixed_pairs _pair _bad_compose_on_tf _bad_tf_on_compose

# =============================================================================
printf -- '\n-- check selection integration: scan_dispatch iac is no longer a no-op --\n'
# =============================================================================
t_case 'scan.sh iac tests/fixtures/vuln records every IAC-TF-*/IAC-HELM-*/IAC-DOCKER-* id as actually run'
rm -rf "$W/run-checks"
bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --out "$W/run-checks" >/dev/null 2>&1
_checks_run=$(cat "$W/run-checks/meta/checks_run" 2>/dev/null || true)
for _id in IAC-TF-OPEN_CIDR-01 IAC-TF-PUBLIC_ACL-01 IAC-TF-UNENCRYPTED-01 \
  IAC-TF-KEY_ROTATION_DISABLED-01 IAC-TF-PUBLIC_IP-01 IAC-TF-HARDCODED_SECRET-01 \
  IAC-TF-RDS_PUBLIC-01 IAC-HELM-HOST_PORT-01 IAC-HELM-HOST_MOUNT-01 \
  IAC-HELM-HARDCODED_SECRET-01 IAC-DOCKER-ROOT_USER-01 IAC-DOCKER-LATEST_TAG-01 \
  IAC-DOCKER-SECRET_ENV-01 IAC-DOCKER-REMOTE_ADD-01 IAC-DOCKER-PIPE_TO_SHELL-01 \
  IAC-DOCKER-UNPINNED_DIGEST-01; do
  t_case "scan.sh iac: $_id is recorded in checks_run - fails if scan_dispatch iac still took the 'no run.sh yet' no-op path, or if the real on-disk registry loader (checks_registry_load) did not pick up modules/iac/helm.rules and modules/iac/dockerfile.rules alongside terraform.rules"
  assert_contains "$_checks_run" "$_id" "$_id present in $W/run-checks/meta/checks_run"
done
unset _checks_run _id

# =============================================================================
printf -- '\n-- exit-code flip (mirrors sast.sh''s own last section) --\n'
# =============================================================================
t_case 'scan.sh iac tests/fixtures/vuln --fail-on high --fail-on-new now exits non-zero'
assert_status "$SCOURSH_EXIT_GATE" \
  'a real subprocess against the vuln fixture, gated on high+, exits the GATE code - fails if scan_dispatch iac were still a no-op (every gate would stay 0)' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --fail-on high --fail-on-new --out "$W/run-gate"

t_case 'the SAME command against the clean fixture still exits 0 - the gate is not a blanket failure'
assert_status 0 \
  'no findings at/above high on the clean fixture, so the gate does not trip' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/clean" --fail-on high --fail-on-new --out "$W/run-gate-clean"

t_case 'without --fail-on, the vuln fixture still exits 0 - the gate is opt-in, never ambient'
assert_status 0 \
  'no --fail-on given means not-evaluated, never a silent gate - fails if the gate fired without being asked' \
  bash "$ROOT/scan.sh" iac --path "$ROOT/tests/fixtures/vuln" --out "$W/run-no-gate"

t_summary 'iac' || FAILED=1
exit "${FAILED:-0}"
