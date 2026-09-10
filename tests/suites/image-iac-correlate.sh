#!/usr/bin/env bash
# tests/suites/image-iac-correlate.sh - IMG-14 (Stage 3, independent peer):
# correlating modules/image/'s built-artifact findings with
# modules/iac/dockerfile.rules' source-text findings via the DERIVED layer
# (rules/RULE-FORMAT.md §9.2/§9.2.2; data/scoursh-image-scan-design/
# report.md §4.4).
#
# What this proves, against the REAL registered check ids and the REAL
# rules/derived.rules file - never a fixture stand-in, because the whole
# point is that the shipped composites correlate the shipped checks:
#
#   A. IMAGE-* checks own no composite id of their own (rules/RULE-FORMAT.md
#      §9.2's first line, "composites live in lib/findings.sh ... not
#      scanner scripts") - modules/image/config.sh and
#      modules/image/distro/{apk,dpkg}.sh only populate a `corr_file`
#      correlation value, directly, the same pattern
#      modules/network/*.sh already uses for `corr_target`.
#   B. IAC-DOCKER-* findings already carry `corr_file` for free, via
#      lib/findings.sh's `path` fingerprint-profile default
#      (`_finding_fill_correlation`) - no code in modules/iac/ changed for
#      this ticket, and this suite proves that by never touching it.
#   C. COMPOSITE-IMAGE-EFFECTIVE_ROOT and the three
#      COMPOSITE-IMAGE-STALE_BASE_* records fire when BOTH sides are
#      present under the SAME corr_file value, and do NOT fire when only
#      one side is present, or when the two sides name different
#      Dockerfiles (proving the join is on the VALUE, not merely on the
#      check ids being present somewhere in the run).
#   D. A fired composite carries its own declared id/severity/remediation
#      (never a contributor's), and round-trips into every report format a
#      real `report_all` call produces: findings.jsonl, findings.json,
#      report.md, report.html, and report.sarif.
#
# Every case that pins a decision names the reading it FAILS under, per
# AGENTS.md's testing rule.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/JSON syntax literally.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SCOURSH_INSTALL_ROOT=$ROOT
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/image-iac-correlate
rm -rf -- "${W:?}"
mkdir -p "$W"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"
attribution_load "$ROOT/tests/fixtures/config/scope.conf"

new_run() {                      # new_run NAME
  rm -rf "${W:?}/run.$1"
  SCOURSH_RUN_DIR=''
  SCOURSH_RUN_ID=''
  occurrence_reset_all
  run_init "$W/run.$1"
}

# emit_iac_root_user DOCKERFILE_PATH - IAC-DOCKER-ROOT_USER-01, the real
# shape modules/iac/parse.sh's `_iac_emit_finding` produces: `module: iac`,
# `loc_path` the Dockerfile's scan-root-relative path. `corr_file` is left
# UNSET here on purpose - it must come from lib/findings.sh's own `path`
# profile default (loc_path), never from this helper, or this suite would
# be proving its own stand-in rather than the shipped mechanism.
emit_iac_root_user() {
  local dockerfile=$1
  finding_new
  finding_set check_id IAC-DOCKER-ROOT_USER-01
  finding_set module iac
  finding_set title 'Dockerfile builds an image with no non-root USER instruction'
  finding_set base_severity high
  finding_set confidence medium
  finding_set cwe CWE-250
  finding_set owasp A02:2025
  finding_set loc_path "$dockerfile"
  finding_set cell .
  finding_set logical_kind file
  finding_set logical_fqn "$dockerfile:FROM"
  finding_set_match 'FROM alpine:3.18'
  finding_set_evidence 'FROM alpine:3.18'
  finding_set remediation 'Add a USER instruction.'
  finding_emit
}

# emit_iac_unpinned DOCKERFILE_PATH CHECK_ID - either
# IAC-DOCKER-LATEST_TAG-01 or IAC-DOCKER-UNPINNED_DIGEST-01, the two
# any-of alternatives every COMPOSITE-IMAGE-STALE_BASE_* record accepts.
emit_iac_unpinned() {
  local dockerfile=$1 check_id=$2
  finding_new
  finding_set check_id "$check_id"
  finding_set module iac
  finding_set title 'Base image not pinned'
  finding_set base_severity medium
  finding_set confidence high
  finding_set cwe CWE-829
  finding_set owasp A08:2025
  finding_set loc_path "$dockerfile"
  finding_set cell .
  finding_set logical_kind file
  finding_set logical_fqn "$dockerfile:FROM"
  finding_set_match 'FROM alpine:latest'
  finding_set_evidence 'FROM alpine:latest'
  finding_set remediation 'Pin the base image.'
  finding_emit
}

# emit_image_runs_as_root IMAGE_ID DOCKERFILE_OR_EMPTY -
# IMAGE-CFG-RUNS_AS_ROOT-01, the real shape modules/image/config.sh's
# `image_check_root_user` produces. `corr_file` is set directly, exactly as
# that emitter does, ONLY when a dockerfile value is given - an empty
# second argument reproduces an image with no `config/images.conf`
# `dockerfile` key declared.
emit_image_runs_as_root() {
  local image_id=$1 dockerfile=${2:-}
  finding_new
  finding_set check_id IMAGE-CFG-RUNS_AS_ROOT-01
  finding_set module image
  finding_set title 'Image config declares no non-root USER - the effective runtime user is root'
  finding_set base_severity medium
  finding_set confidence high
  finding_set cwe CWE-250
  finding_set owasp A04:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set logical_kind image
  finding_set logical_fqn "image $image_id: config.User"
  [[ -n $dockerfile ]] && finding_set corr_file "$dockerfile"
  finding_set remediation 'Add a non-root USER.'
  finding_set_evidence "image: $image_id"
  finding_emit
}

# emit_image_vulnerable_package IMAGE_ID CHECK_ID DOCKERFILE_OR_EMPTY - the
# real shape modules/image/distro/{apk,dpkg}.sh's own
# `_apk_emit_vulnerable_package`/`_dpkg_emit_vulnerable_package` produce.
emit_image_vulnerable_package() {
  local image_id=$1 check_id=$2 dockerfile=${3:-}
  finding_new
  finding_set check_id "$check_id"
  finding_set module image
  finding_set title "vulnerable package ($check_id)"
  finding_set base_severity high
  finding_set confidence high
  finding_set cwe CWE-1104
  finding_set owasp A06:2021
  finding_set cell "$image_id"
  finding_set loc_image_id "$image_id"
  finding_set loc_ecosystem 'Alpine:v3.18'
  finding_set loc_package openssl
  finding_set loc_version '3.1.4-r1'
  finding_set loc_advisory_id SCOURSH-FIXTURE-CVE-1
  finding_set logical_kind package
  finding_set logical_fqn "image $image_id: openssl@3.1.4-r1"
  [[ -n $dockerfile ]] && finding_set corr_file "$dockerfile"
  finding_set fix_fixed_versions '3.1.4-r2'
  finding_set remediation 'Rebuild against an updated base layer.'
  finding_set_evidence "image: $image_id"
  finding_emit
}

composite_fires() {              # composite_fires RUNDIR CHECK_ID
  /usr/bin/grep -c "check_id=$2" "$1/findings.fields" 2>/dev/null || true
}

# =============================================================================
printf -- '\n-- A. COMPOSITE-IMAGE-EFFECTIVE_ROOT: both sides, same Dockerfile --\n'
# =============================================================================

new_run a1
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_root_user services/payments-api/Dockerfile
emit_image_runs_as_root payments-api services/payments-api/Dockerfile
findings_merge "$d"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  'the composite has not been computed yet - derive_findings has not run'

derive_findings "$d" "$ROOT/rules/derived.rules"
t_case 'both IAC-DOCKER-ROOT_USER-01 and IMAGE-CFG-RUNS_AS_ROOT-01 sharing corr_file fire the composite'
assert_eq 1 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  'FAILS if IAC-DOCKER-* corr_file is not populated automatically, or if the IMAGE-* emitter never set one'

line=$(/usr/bin/grep 'check_id=COMPOSITE-IMAGE-EFFECTIVE_ROOT' "$d/findings.fields")
finding_decode "$line"
t_case 'the composite carries its OWN declared id/severity/remediation, never a contributors'"'"''
assert_eq critical "${_DF[severity]}" \
  'declared critical in rules/derived.rules (FAILS if the composite silently inherited a contributor severity of high/medium instead)'
assert_eq CWE-250 "${_DF[cwe]}" 'the declared cwe'
assert_contains "${_DF[remediation]}" 'built image' \
  "the composite's own remediation prose, not IAC-DOCKER-ROOT_USER-01's or IMAGE-CFG-RUNS_AS_ROOT-01's"

t_case 'both contributors are retained in their own right, each carrying derived_into'
assert_eq 2 "$(/usr/bin/grep -c 'derived_into=COMPOSITE-IMAGE-EFFECTIVE_ROOT' "$d/findings.fields" || true)" \
  'contributors are not absorbed into the composite'

# =============================================================================
printf -- '\n-- B. COMPOSITE-IMAGE-EFFECTIVE_ROOT: one side only --\n'
# =============================================================================

t_case 'IAC-DOCKER-ROOT_USER-01 alone (no image scan) does not fire the composite'
new_run b1
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_root_user services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  'requires is ALL - a source-only lint result must not read as a confirmed, built-artifact finding'

t_case 'IMAGE-CFG-RUNS_AS_ROOT-01 alone (no Dockerfile scanned) does not fire the composite'
new_run b2
d=$SCOURSH_RUN_DIR
emit_image_runs_as_root payments-api services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  'requires is ALL - an artifact-only result must not be dressed up as a source+artifact confirmation'

t_case 'IMAGE-CFG-RUNS_AS_ROOT-01 with NO declared dockerfile never correlates, even alongside a real IAC finding'
new_run b3
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_root_user services/payments-api/Dockerfile
emit_image_runs_as_root payments-api ''
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  "FAILS under a resolver that guesses a correlation value for an image with no declared config/images.conf 'dockerfile' key - no value must mean no participation, per rules/RULE-FORMAT.md §9.2.2"

t_case 'the two sides naming DIFFERENT Dockerfiles do not fire the composite'
new_run b4
d=$SCOURSH_RUN_DIR
occurrence_reset_unit u
emit_iac_root_user services/one/Dockerfile
emit_image_runs_as_root other-image services/two/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-EFFECTIVE_ROOT)" \
  'correlate-on: file joins on the VALUE - two different Dockerfiles must not fabricate one chain'

# =============================================================================
printf -- '\n-- C. COMPOSITE-IMAGE-STALE_BASE_APK / _DPKG / _RPM --\n'
# =============================================================================

t_case 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 (apk) + IAC-DOCKER-LATEST_TAG-01, same Dockerfile, fire STALE_BASE_APK'
new_run c1
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_unpinned services/payments-api/Dockerfile IAC-DOCKER-LATEST_TAG-01
emit_image_vulnerable_package payments-api IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 1 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_APK)" 'the apk composite fires'
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_DPKG)" \
  "the mutually-exclusive dpkg sibling must NOT fire - proves the per-distro split does not cross-wire"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_RPM)" 'nor the rpm sibling'

t_case 'IAC-DOCKER-UNPINNED_DIGEST-01 (the OTHER any-of alternative) also satisfies STALE_BASE_APK'
new_run c2
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_unpinned services/payments-api/Dockerfile IAC-DOCKER-UNPINNED_DIGEST-01
emit_image_vulnerable_package payments-api IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 1 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_APK)" \
  'any-of is satisfied by either alternative, not only IAC-DOCKER-LATEST_TAG-01'

t_case 'IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 (dpkg) + IAC-DOCKER-LATEST_TAG-01 fire STALE_BASE_DPKG, not STALE_BASE_APK'
new_run c3
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/web/Dockerfile
emit_iac_unpinned services/web/Dockerfile IAC-DOCKER-LATEST_TAG-01
emit_image_vulnerable_package web-app IMAGE-PKG-VULNERABLE_OS_PACKAGE-02 services/web/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 1 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_DPKG)" 'the dpkg composite fires'
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_APK)" 'and only the dpkg one'

t_case 'a vulnerable apk package with NO unpinned-base signal does not fire STALE_BASE_APK'
new_run c4
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_image_vulnerable_package payments-api IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_APK)" \
  'a pinned, well-maintained base still shipping one stale package is NOT the stronger chain claim this composite makes'

t_case 'an unpinned base with no vulnerable package finding does not fire STALE_BASE_APK'
new_run c5
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_unpinned services/payments-api/Dockerfile IAC-DOCKER-LATEST_TAG-01
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
assert_eq 0 "$(composite_fires "$d" COMPOSITE-IMAGE-STALE_BASE_APK)" \
  'requires is the single package contributor - an unpinned-but-clean image must not read as shipping known-vulnerable packages'

t_case 'the STALE_BASE_APK composite carries its own severity/cwe, clamped to the worse contributor'
line=$(/usr/bin/grep 'check_id=COMPOSITE-IMAGE-STALE_BASE_APK' "$d/findings.fields" || true)
new_run c6
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_unpinned services/payments-api/Dockerfile IAC-DOCKER-LATEST_TAG-01
emit_image_vulnerable_package payments-api IMAGE-PKG-VULNERABLE_OS_PACKAGE-01 services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"
finding_decode "$(/usr/bin/grep 'check_id=COMPOSITE-IMAGE-STALE_BASE_APK' "$d/findings.fields")"
assert_eq high "${_DF[severity]}" 'declared high, and the fixture contributors (medium/high) clamp no higher'
assert_eq CWE-1104 "${_DF[cwe]}" 'the declared cwe (the shipped-vulnerable-component claim)'

# =============================================================================
printf -- '\n-- D. round-trip: findings.jsonl, findings.json, report.md, report.html, report.sarif --\n'
# =============================================================================

new_run d1
d=$SCOURSH_RUN_DIR
occurrence_reset_unit services/payments-api/Dockerfile
emit_iac_root_user services/payments-api/Dockerfile
emit_image_runs_as_root payments-api services/payments-api/Dockerfile
findings_merge "$d"
derive_findings "$d" "$ROOT/rules/derived.rules"

SCOURSH_REDACT_SECRETS=true
SCOURSH_DIFF_GUARD=no_prior_state
SCOURSH_DIFF_USABLE=false
SCOURSH_RUN_TIMESTAMP='2026-01-01T00:00:00Z'
export SCOURSH_REDACT_SECRETS SCOURSH_DIFF_GUARD SCOURSH_DIFF_USABLE SCOURSH_RUN_TIMESTAMP
run_record authorization_affirmed false
run_record authorization_source none
run_record authorization_scope_target none
run_record authorization_intensity passive
run_record authorization_intrusive false
run_record authorization_authed false
run_record use_engines false
# report_all's own SARIF path (_sarif_build_registry) loads every module's
# check registry itself, from lib/report.sh's fixed `_RPT_MODULES` list
# (which already includes `iac` and `image`) - no registry setup is needed
# here.  A derived/composite check id is not in any module's registry at
# all (rules/derived.rules is its own schema, never globbed by
# checks_registry_load), so its SARIF descriptor comes from
# `_sarif_index_findings`'s synthesised-from-the-finding-itself path, the
# same fallback SCA's ungoverned check ids already use.
SCOURSH_FORMATS='json,sarif,html,md'
export SCOURSH_FORMATS
report_all "$d"

t_case 'findings.jsonl carries the composite'
assert_contains "$(cat "$d/findings.jsonl")" '"check_id":"COMPOSITE-IMAGE-EFFECTIVE_ROOT"' \
  'the mandatory per-run jsonl record'

t_case 'findings.json carries the composite'
assert_file_exists "$d/findings.json" 'the --format json output'
assert_contains "$(cat "$d/findings.json")" 'COMPOSITE-IMAGE-EFFECTIVE_ROOT' \
  'FAILS if the derived-finding module="derived" is filtered out of the json report path'

t_case 'report.md carries the composite'
assert_contains "$(cat "$d/report.md")" 'COMPOSITE-IMAGE-EFFECTIVE_ROOT' \
  'the Markdown findings section'

t_case 'report.html carries the composite'
assert_contains "$(cat "$d/report.html")" 'COMPOSITE-IMAGE-EFFECTIVE_ROOT' \
  'the HTML findings section'

t_case 'report.sarif carries the composite as its own ruleId'
assert_contains "$(cat "$d/report.sarif")" '"ruleId":"COMPOSITE-IMAGE-EFFECTIVE_ROOT"' \
  'SARIF-04s per-finding mapping sends check_id to ruleId - FAILS if a derived finding is dropped from _sarif_print_results'

t_summary image-iac-correlate
