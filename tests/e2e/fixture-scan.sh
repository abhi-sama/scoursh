#!/usr/bin/env bash
# tests/e2e/fixture-scan.sh - the end-to-end path for §13 step 1.
#
# Parses a fixture rule pack with lib/records.sh, matches it over a fixture
# tree, emits one finding of every SHAPE the libraries must handle, merges the
# shards, derives the composite, and writes JSON, JSONL, Markdown, a
# self-contained HTML report, and run.json.
#
# This is a TEST HARNESS, not modules/sast/run.sh.  It deliberately implements
# no rule-engine features beyond "find the matches": the context window (§10),
# `files` glob filtering, `max-matches-per-file` overflow, and the two-pass
# design are docs/DESIGN.md §13 step 3 and are not duplicated here.
#
# Usage: tests/e2e/fixture-scan.sh <output-run-dir>
#
# shellcheck shell=bash

set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/report.sh
source "$ROOT/lib/report.sh"

FIXTURES=$ROOT/tests/fixtures
RUNDIR=${1:?usage: fixture-scan.sh <output-run-dir>}

run_init "$RUNDIR"
SCOURSH_RUN_ID=fixture-run
export SCOURSH_RUN_ID

SCOURSH_SCAN_ROOT_ID=$(scan_root_id_of "$FIXTURES/vuln")
SCOURSH_PATH_ROOT=$(path_root_cell "$FIXTURES/vuln")
export SCOURSH_SCAN_ROOT_ID SCOURSH_PATH_ROOT

attribution_load "$FIXTURES/config/scope.conf"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"

records_load "$FIXTURES/rules/fixture.rules" pattern-rule pack \
  || die "$SCOURSH_EXIT_INPUT" "fixture rule pack failed to parse"
records_validate pack || die "$SCOURSH_EXIT_INPUT" "fixture rule pack failed validation"

# ---------------------------------------------------------------------------
# SAST: path / match_digest / occurrence
# ---------------------------------------------------------------------------
scan_tree() {
  local tree=$1 file rel n i pattern hits ln off text
  n=$(records_count pack)
  while IFS= read -r file; do
    [[ -n $file ]] || continue
    rel=${file#"$tree"/}
    # The scanning unit for SAST is the FILE (docs/FOUNDATION.md tension 5).
    occurrence_reset_unit "$rel"
    for (( i = 0; i < n; i++ )); do
      pattern=$(records_field pack "$i" pattern)
      hits=$SCOURSH_SCRATCH/hits.$$
      if ! scan_match_offsets "$hits" "$pattern" "$file"; then
        continue
      fi
      # `-n -b -o` yields one record per MATCH with its byte offset, in
      # ascending line then ascending offset order, which is exactly the order
      # tension 5 freezes for the occurrence ordinal.
      # `off` is read to consume the byte-offset field, which the ordinal is
      # ordered by; the ordinal itself is computed inside finding_emit.
      # shellcheck disable=SC2034
      while IFS=: read -r ln off text; do
        [[ -n $ln ]] || continue
        finding_new
        finding_from_record pack "$i"
        finding_set module sast
        finding_set loc_path "$rel"
        finding_set loc_line "$ln"
        finding_set cell "$SCOURSH_PATH_ROOT"
        finding_set logical_kind file
        finding_set logical_fqn "$rel:$ln"
        finding_set exposure unknown
        finding_set auth user
        if [[ $(records_id pack "$i") == *SECRET* ]]; then
          finding_set sensitive_data true
        fi
        # The RAW matched text feeds the digest and is then discarded; only the
        # hash is retained (tension 9).
        finding_set_match "$text"
        finding_set_evidence "$text"
        finding_emit
      done <"$hits"
    done
  done <<<"$(find "$tree" -type f -name '*.py' | LC_ALL=C sort)"
}

scan_tree "$FIXTURES/vuln"

# ---------------------------------------------------------------------------
# One finding of every other shape, so the report plumbing is exercised for
# each fingerprint profile in tension 5's frozen table.
# ---------------------------------------------------------------------------

# SAST history: blob_sha / match_digest / occurrence (tension 13)
finding_new
finding_set check_id SAST-HIST-AWS_SECRET-01
finding_set module sast
finding_set title 'Hardcoded AWS secret access key in git history'
finding_set base_severity critical
finding_set confidence high
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_blob_sha 0000000000000000000000000000000000000000
finding_set loc_path app.py
finding_set cell "$SCOURSH_PATH_ROOT"
finding_set logical_kind blob
finding_set logical_fqn 'blob 0000000000000000000000000000000000000000'
finding_set sensitive_data true
finding_set oldest_reaching_commit_time '2026-01-01T00:00:00Z'
finding_set remediation 'Rotate the credential FIRST - purging history does not un-disclose it - then purge the blob, force-push, and re-clone.'
finding_set_match 'aws_secret_access_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
finding_set_evidence 'aws_secret_access_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
finding_emit

# SCA: ecosystem / package / advisory_id, deliberately NOT the version
finding_new
finding_set check_id SCA-DEP-VULNERABLE-01
finding_set module sca
finding_set title 'Dependency with a known advisory'
finding_set base_severity high
finding_set confidence high
finding_set cwe CWE-1395
finding_set owasp A06:2021
finding_set loc_ecosystem pypi
finding_set loc_package example-package
finding_set loc_version 1.2.3
finding_set loc_advisory_id FIXTURE-2026-0001
finding_set path requirements.txt
finding_set cell "$SCOURSH_PATH_ROOT"
finding_set logical_kind package
finding_set logical_fqn 'pypi:example-package'
finding_set remediation 'Upgrade to the fixed version named in the advisory.'
finding_set_evidence 'example-package==1.2.3'
finding_emit

# DAST: target / method / path_template / param_location / param_name, with
# HOSTILE evidence - the exact shape tension 10 exists for.
finding_new
finding_set check_id DAST-XSS-REFLECT-01
finding_set module dast
finding_set base_severity medium
finding_set confidence medium
finding_set cwe CWE-79
finding_set owasp A03:2021
finding_set loc_target fixture-target
finding_set loc_method GET
finding_set path '/users/12345/profile'
finding_set loc_param_location query
finding_set loc_param_name q
finding_set cell fixture-target
finding_set exposure internet
finding_set auth none
finding_set logical_kind endpoint
# tension 9 defines redact() as what is written ANYWHERE, not only evidence.
# These four fields are target-derived in the modules that carry credentials - a
# crawled URL's query string is exactly where api_key= lives - so each carries a
# distinct credential-shaped marker that must not survive into any output.
finding_set url 'https://app.fixture.invalid/users/12345/profile?api_key=URLLEAKKEY0123456789abcdef'
finding_set logical_fqn 'fixture-target:GET /users/{id}/profile#q Bearer FQNLEAKTOKEN0123456789abcdef'
finding_set title 'Unescaped reflection, seen with Authorization: TITLELEAKTOKEN0123456789abcdef'
finding_set remediation 'Contextually escape the reflected value; rotate api_key=REMEDIATIONLEAKKEY0123456789abcdef'
finding_set_evidence "$(printf '</script><img src=x onerror=alert(1)> \033[31mANSI\033[0m raw\nnewline \xC3\050 badutf8 ``````fence Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345')"
finding_emit

# Cloud: account_id / region / resource_key / sub_key, plus endpoint_hosts so
# target attribution runs (rules/RULE-FORMAT.md §9.2.2).
finding_new
finding_set check_id CLOUD-APPSYNC-LONG_LIVED_KEY-01
finding_set module cloud
finding_set title 'Managed GraphQL API key with a far-future expiry'
finding_set base_severity medium
finding_set confidence high
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_account_id 123456789012
finding_set loc_region us-east-1
finding_set loc_resource_key 'arn:aws:appsync:us-east-1:123456789012:apis/fixture'
finding_set loc_sub_key none
finding_set cell '123456789012/us-east-1'
finding_set exposure internet
finding_set auth none
finding_add endpoint_hosts api.fixture.invalid
finding_set logical_kind resource
finding_set logical_fqn 'arn:aws:appsync:us-east-1:123456789012:apis/fixture'
finding_set remediation 'Move the API to IAM or identity-provider auth and expire the key.'
finding_set_evidence 'expires: 2099-01-01T00:00:00Z'
finding_emit

# A multi-line PEM private key, so the end-to-end path proves a MULTI-LINE
# secret is redacted in every emitted format, not only a single-line one.
finding_new
finding_set check_id SAST-SEC-PRIVATE_KEY-01
finding_set module sast
finding_set title 'Hardcoded private key'
finding_set base_severity critical
finding_set confidence high
finding_set cwe CWE-798
finding_set owasp A07:2021
finding_set loc_path deploy/id_rsa
finding_set loc_line 1
finding_set cell "$SCOURSH_PATH_ROOT"
finding_set sensitive_data true
finding_set logical_kind file
finding_set logical_fqn 'deploy/id_rsa:1'
finding_set remediation 'Rotate the key pair and remove it from source.'
finding_set_match 'private key'
finding_set_evidence "$(printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvPEMBODYMARKERONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nBBBPEMBODYMARKERTWOBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\nKw==\n-----END RSA PRIVATE KEY-----')"
finding_emit

# Posture: control_id / scope_key
finding_new
finding_set check_id POSTURE-EDGE-WAF_GEO-01
finding_set module posture
finding_set title 'Expected control not observed: edge geo restriction'
finding_set base_severity low
finding_set confidence medium
finding_set cwe none
finding_set owasp none
finding_set loc_control_id POSTURE-EDGE-WAF_GEO-01
finding_set loc_scope_key fixture-target
finding_set cell fixture-target
finding_set logical_kind control
finding_set logical_fqn POSTURE-EDGE-WAF_GEO-01
finding_set remediation 'Attach the geo-match rule the operator declared in config/posture.conf.'
finding_set_evidence 'observed: absent; expected: present'
finding_emit

# ---------------------------------------------------------------------------
# The frozen pipeline (tension 11): merge and dedup, then derive, then report.
# ---------------------------------------------------------------------------
findings_merge "$RUNDIR"
derive_findings "$RUNDIR" "$FIXTURES/rules/derived.rules"

# Suppression is a late ANNOTATION and never a deletion (tension 11 step 6).
# The baseline reader itself is §13 step 7; this is the primitive it will use.
if [[ -n ${SCOURSH_E2E_SUPPRESS_FP:-} ]]; then
  findings_mark_suppressed "$RUNDIR" "$SCOURSH_E2E_SUPPRESS_FP" 'accepted: fixture example'
fi

run_record coverage_reduction 'modules dast, cloud, sca and posture are synthesised by the fixture harness, not scanned'
run_record skipped_checks 'context evaluation (§10) - the rule engine lands at §13 step 3'
report_all "$RUNDIR"

printf '%s\n' "$RUNDIR"
