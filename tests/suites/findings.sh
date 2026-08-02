#!/usr/bin/env bash
# tests/suites/findings.sh - lib/findings.sh.
#
# The load-bearing resolutions: tension 5 (fingerprint identity), tension 6
# (derived findings), tension 8 (the severity rubric), tension 9 (redaction
# versus evidence versus fingerprint), tension 10 (evidence normalisation),
# tension 17 (the deterministic merge).
#
# Every case that pins a decision names the reading it FAILS under, because a
# test that passes under both readings pins nothing.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is the intended reporting shape.
# SC2016: assertion prose mentions shell variables literally.
# shellcheck disable=SC2015,SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/f
mkdir -p "$W"
redaction_load "$ROOT/rules/redaction.rules"
rubric_load "$ROOT/data/severity-rubric.conf"
attribution_load "$ROOT/tests/fixtures/config/scope.conf"

# Sets SCOURSH_RUN_DIR in the CURRENT shell.  Assigning it from a command
# substitution would call run_init inside a subshell and throw the assignment
# away - the same class of bug as calling occurrence_next in one.
new_run() {
  rm -rf "${W:?}/run.$1"
  SCOURSH_RUN_DIR=''
  SCOURSH_RUN_ID=''
  # A real run is one process; this suite simulates many in one, so the ordinal
  # spaces are cleared explicitly or a counter leaks from the previous run into
  # the next one's identities.
  occurrence_reset_all
  run_init "$W/run.$1"
}

fps_of() {                       # every fingerprint in a run's merged output
  local d=$1 line
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    finding_decode "$line"
    printf '%s\n' "${_DF[fingerprint]}"
  done <"$d/findings.fields"
}

emit_match() {                   # emit_match RUNDIR CHECK PATH LINE TEXT
  finding_new
  finding_set check_id "$2"
  finding_set module sast
  finding_set title t
  finding_set base_severity high
  finding_set cwe none
  finding_set owasp none
  finding_set loc_path "$3"
  finding_set loc_line "$4"
  finding_set cell .
  finding_set_match "$5"
  finding_set_evidence "$5"
  finding_emit
}

# ---------------------------------------------------------------------------
printf '\n-- tension 5: no fingerprint input ever contains a line number --\n'
# ---------------------------------------------------------------------------
t_case 'fingerprint stability under reindentation and line shifts'
new_run a
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-X-Y-01 app.py 10 'eval(request.body)'
findings_merge "$d"
before=$(fps_of "$d")

new_run b
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
# The same match, twenty lines lower and reindented by eight spaces.
# `normalise` collapses whitespace RUNS and strips leading and trailing
# whitespace; it does not delete interior spacing, so reindentation is stable
# while an actual edit to the expression is not - which is the intent.
emit_match "$d" SAST-X-Y-01 app.py 30 '        eval(request.body)'
findings_merge "$d"
after=$(fps_of "$d")
assert_eq "$before" "$after" \
  'a line shift plus reindentation leaves the fingerprint byte-identical (fails if line is an input, or if whitespace is not normalised)'

t_case 'a formatter-style respacing does NOT churn the fingerprint'
# Collapsing whitespace RUNS is not the same as being insensitive to whitespace:
# zero spaces versus one space is not a run, and that is exactly what a code
# formatter changes.  Under run-collapsing, `black`/`prettier`/`gofmt` across a
# repository gave every affected finding a new fingerprint, so tension 12 saw the
# old one absent and classified it `fixed` - a wave of remediations that never
# happened, written into state/, with --fail-on-new firing on the whole set.
#
# The existing stability tests cannot see this: they insert blank lines and
# reindent, both of which were already correct.
new_run fmt1
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-X-Y-01 app.py 10 'eval( user_input )'
findings_merge "$d"
spaced=$(fps_of "$d")

new_run fmt2
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-X-Y-01 app.py 10 'eval(user_input)'
findings_merge "$d"
assert_eq "$spaced" "$(fps_of "$d")" \
  'eval( user_input ) and eval(user_input) are one identity (fails under run-collapsing)'

t_case 'and neither does a formatter that changes spacing around an operator'
new_run fmt3
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-SEC-K-01 app.py 5 'key="AAAA"'
findings_merge "$d"
tight=$(fps_of "$d")
new_run fmt4
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-SEC-K-01 app.py 5 'key = "AAAA"'
findings_merge "$d"
assert_eq "$tight" "$(fps_of "$d")" 'key="AAAA" and key = "AAAA" are one identity'

t_case 'the accepted cost: texts differing only in whitespace share a digest'
# Stated rather than hidden.  `a b` and `ab` collide on match_digest under this
# normalisation.  They remain TWO findings, told apart by the occurrence ordinal
# exactly as two byte-identical matches already are, so identity is not lost -
# only the discriminator changes.
assert_eq "$(fingerprint_digest 'a b')" "$(fingerprint_digest 'ab')" \
  'the digests are equal, which is the price of formatter stability'
new_run fmt5
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-X-Y-01 app.py 1 'a b'
emit_match "$d" SAST-X-Y-01 app.py 2 'ab'
findings_merge "$d"
assert_eq 2 "$(fps_of "$d" | LC_ALL=C sort -u | wc -l | tr -d ' ')" \
  'and they are still two distinct findings, separated by the ordinal'

t_case 'two distinct secrets in one file are two distinct findings'
new_run c
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-SEC-K-01 app.py 5 'key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
emit_match "$d" SAST-SEC-K-01 app.py 6 'key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"'
findings_merge "$d"
assert_eq 2 "$(fps_of "$d" | LC_ALL=C sort -u | wc -l | tr -d ' ')" \
  'two different keys hash differently (fails under "fingerprint the redacted text", which collapses them)'

t_case 'five byte-identical matches in one file are FIVE distinct fingerprints'
# The collision the occurrence discriminator exists to eliminate: most rules in
# the §6.3 catalog match a short fixed construct, so every occurrence in a file
# produces byte-identical matched text and therefore an identical digest.
new_run e
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
for ln in 10 11 12 13 14; do emit_match "$d" SAST-X-Y-01 app.py "$ln" 'eval(x)'; done
findings_merge "$d"
five=$(fps_of "$d" | LC_ALL=C sort)
assert_eq 5 "$(printf '%s\n' "$five" | LC_ALL=C sort -u | wc -l | tr -d ' ')" \
  'five distinct fingerprints (fails without the occurrence ordinal, which collapses all five onto one)'

t_case 'and shifting all five down by twenty lines leaves that set byte-identical'
new_run f
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
for ln in 30 31 32 33 34; do emit_match "$d" SAST-X-Y-01 app.py "$ln" 'eval(x)'; done
findings_merge "$d"
assert_eq "$five" "$(fps_of "$d" | LC_ALL=C sort)" 'the ordinal survives line shifts'

t_case 'two matches on ONE line are two findings, ordered by byte offset'
new_run g
d=$SCOURSH_RUN_DIR
occurrence_reset_unit app.py
emit_match "$d" SAST-X-Y-01 app.py 1 'eval(x)'
emit_match "$d" SAST-X-Y-01 app.py 1 'eval(x)'
findings_merge "$d"
assert_eq 2 "$(fps_of "$d" | LC_ALL=C sort -u | wc -l | tr -d ' ')" \
  'the match unit is the MATCH, not the line'

t_case 'the merged findings.jsonl contains no duplicate fingerprint'
dups=$(fps_of "$d" | LC_ALL=C sort | uniq -d | wc -l | tr -d ' ')
assert_eq 0 "$dups" 'the sort key is total, which tensions 12 and 17 both depend on'

t_case 'the occurrence ordinal is scoped to the SCANNING UNIT'
new_run h
d=$SCOURSH_RUN_DIR
occurrence_reset_unit a.py
emit_match "$d" SAST-X-Y-01 a.py 1 'eval(x)'
occurrence_reset_unit b.py
emit_match "$d" SAST-X-Y-01 b.py 1 'eval(x)'
findings_merge "$d"
assert_eq 2 "$(fps_of "$d" | wc -l | tr -d ' ')" 'a new file restarts the ordinal at 0 but the path differs'

# ---------------------------------------------------------------------------
printf '\n-- tension 13: the history occurrence is scoped to the BLOB --\n'
# ---------------------------------------------------------------------------
# "The history `occurrence` is scoped to the blob, not to a path" - stated
# without qualification in tension 13 and repeated in tension 5.  The unit was
# picked by a fallback chain that reached loc_path first, and a SAST-HIST-*
# finding always carries a path (tension 13 requires it in the reported
# location), so loc_blob_sha was never consulted.
emit_hist() {                    # emit_hist RUNDIR BLOB PATH TEXT
  finding_new
  finding_set check_id SAST-HIST-AWS_SECRET-01
  finding_set module sast
  finding_set title t
  finding_set base_severity critical
  finding_set cwe CWE-798
  finding_set owasp A07:2021
  finding_set loc_blob_sha "$2"
  finding_set loc_path "$3"
  finding_set cell .
  finding_set_match "$4"
  finding_emit
}

t_case 'two DIFFERENT blobs at one path both take occurrence 0'
new_run h1
d=$SCOURSH_RUN_DIR
emit_hist "$d" 1111111111111111111111111111111111111111 config/settings.py 'key = "AAAA"'
OCC_A=${_F[loc_occurrence]}
FP_A=${_F[fingerprint]}
emit_hist "$d" 2222222222222222222222222222222222222222 config/settings.py 'key = "AAAA"'
OCC_B=${_F[loc_occurrence]}
assert_eq 0 "$OCC_A" 'the first blob takes ordinal 0'
assert_eq 0 "$OCC_B" \
  'and so does the second (fails under path scoping, which gives it 1 and makes its identity depend on enumeration order)'

t_case 'an untouched blob keeps its identity when another blob is enumerated first'
# The churn tension 13 exists to prevent: adding one older commit to the window
# renumbers an untouched blob, and the diff reports one `fixed` plus one `new`
# for a secret nobody touched.
new_run h2
d=$SCOURSH_RUN_DIR
emit_hist "$d" 2222222222222222222222222222222222222222 config/settings.py 'key = "AAAA"'
emit_hist "$d" 1111111111111111111111111111111111111111 config/settings.py 'key = "AAAA"'
assert_eq "$FP_A" "${_F[fingerprint]}" \
  'the blob enumerated second this run has the same fingerprint it had when enumerated first'

t_case 'a leftover working-tree scan unit does not leak into history ordinals'
# The state the shipped harness actually leaves behind: scan_tree runs first and
# occurrence_reset_unit was last called for a working-tree file.
new_run h3
d=$SCOURSH_RUN_DIR
occurrence_reset_unit some/other/file.py
emit_hist "$d" 3333333333333333333333333333333333333333 config/settings.py 'key = "AAAA"'
assert_eq 0 "${_F[loc_occurrence]}" 'the first history finding takes ordinal 0'
emit_hist "$d" 4444444444444444444444444444444444444444 config/settings.py 'key = "AAAA"'
assert_eq 0 "${_F[loc_occurrence]}" \
  'and so does the next blob (fails when SCOURSH_SCAN_UNIT wins, keying every history finding on the last file scanned)'

t_case 'one blob reachable at two paths yields ONE set of ordinals'
# tension 13: "One blob reachable at three paths across four hundred commits is
# scanned once and yields one set of ordinals."  Under path scoping the two
# emissions land in two ordinal spaces, both take ordinal 0, and the two
# findings collide on ONE fingerprint - breaking tension 5's "fingerprints are
# unique within a run", which tensions 12 and 17 both depend on.
new_run h4
d=$SCOURSH_RUN_DIR
# Cleared deliberately: with a leftover unit still set, BOTH readings key on it
# and the case stops discriminating - which it did on the first run of this test.
SCOURSH_SCAN_UNIT=''
emit_hist "$d" 5555555555555555555555555555555555555555 old/name.py 'key = "AAAA"'
FP_P1=${_F[fingerprint]}
emit_hist "$d" 5555555555555555555555555555555555555555 new/name.py 'key = "AAAA"'
assert_ne "$FP_P1" "${_F[fingerprint]}" \
  'the same blob reported at a second path does not collide onto one fingerprint'
findings_merge "$d"
assert_eq 2 "$(fps_of "$d" | LC_ALL=C sort -u | wc -l | tr -d ' ')" \
  'and the merge keeps both rather than deduping a genuine pair away'

t_case 'each module uses its own frozen location tuple'
assert_eq path "$(_fp_profile_for sast SAST-PY-EVAL-01)" 'sast -> path'
assert_eq history "$(_fp_profile_for sast SAST-HIST-AWSKEY-01)" 'SAST-HIST-* -> blob'
assert_eq path "$(_fp_profile_for iac IAC-TF-X-01)" 'iac -> path'
assert_eq sca "$(_fp_profile_for sca SCA-A-B-01)" 'sca'
assert_eq dast "$(_fp_profile_for dast DAST-A-B-01)" 'dast'
assert_eq cloud "$(_fp_profile_for cloud CLOUD-A-B-01)" 'cloud'
assert_eq posture "$(_fp_profile_for posture POSTURE-A-B-01)" 'posture'
assert_eq derived "$(_fp_profile_for derived COMPOSITE-X)" 'derived'
assert_eq 'blob_sha
match_digest
occurrence' "$(_fp_components_for history)" 'history carries all three components, in that order'

t_case 'SCA excludes the version deliberately'
assert_not_contains "$(_fp_components_for sca)" version \
  'upgrading past an advisory makes the finding disappear, which the diff reports as fixed'

t_case 'path_template replaces volatile segments'
assert_eq '/users/{id}/profile' "$(path_template_of /users/123/profile)" 'digits'
assert_eq '/o/{id}/x' "$(path_template_of /o/f47ac10b-58cc-4372-a567-0e02b2c3d479/x)" 'uuid'
assert_eq '/o/{id}' "$(path_template_of /o/01ARZ3NDEKTSV4RRFFQ69G5FAV)" 'ulid'
assert_eq '/o/{id}' "$(path_template_of /o/deadbeefdeadbeef01)" 'long hex'
assert_eq '/users/me/profile' "$(path_template_of /users/me/profile)" 'everything else is literal'

t_case 'the fingerprint is 64 hex characters over NUL-separated components'
fp=$(fingerprint_compute sast SAST-A-B-01 app.py abcdef 0)
assert_eq 64 "${#fp}" 'full 64 hex characters retained'
assert_ne "$fp" "$(fingerprint_compute sast SAST-A-B-01 'app.py' 'abcdef0')" \
  'NUL separation means concatenated components cannot collide'

# ---------------------------------------------------------------------------
printf '\n-- tension 9: redaction versus evidence versus fingerprint --\n'
# ---------------------------------------------------------------------------
t_case 'redact replaces the secret and keeps a distinguishing digest'
s1='AWS_SECRET_ACCESS_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
s2='AWS_SECRET_ACCESS_KEY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"'
r1=$(redact "$s1")
r2=$(redact "$s2")
assert_not_contains "$r1" 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'the secret is gone'
assert_contains "$r1" '<redacted:AWS_SECRET:' 'the kind token is present'
assert_ne "$r1" "$r2" 'two distinct secrets get two distinct 8-hex digests, so a reader can tell them apart'
assert_eq "$r1" "$(redact "$s1")" 'the same secret is recognisable across findings'
assert_eq 'nothing to see' "$(redact 'nothing to see')" 'ordinary text is untouched'

t_case 'fingerprint_digest consumes the RAW text, not the redacted text'
assert_ne "$(fingerprint_digest "$s1")" "$(fingerprint_digest "$s2")" \
  'fails under "redact then fingerprint", where all secrets of one kind collapse to one string'
dg=$(fingerprint_digest x)
assert_eq 16 "${#dg}" 'the digest is 16 hex characters and only the hash is retained'

t_case 'redaction covers JWT and bearer tokens'
assert_contains "$(redact 'x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123 y')" '<redacted:JWT:' 'JWT'
assert_contains "$(redact 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz')" '<redacted:BEARER:' 'bearer'

t_case 'a REAL multi-line PEM has its body redacted, not just its header'
# The previous assertion here used a single-line pseudo-PEM
# (-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJ), a shape no real key has.  The
# matcher is line-oriented, so the correct and the broken implementation agree
# on that input and the test certified a credential disclosure green.
PEM=$(printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAvSECRETBODYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nBBBSECRETBODYTWOBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\nKw==\n-----END RSA PRIVATE KEY-----')
R=$(redact "$PEM")
assert_contains "$R" '<redacted:PRIVATE_KEY:' 'the header is redacted'
assert_not_contains "$R" 'SECRETBODYAAAA' 'the first body line is redacted'
assert_not_contains "$R" 'SECRETBODYTWOB' 'the second body line is redacted'
assert_not_contains "$R" 'Kw==' 'the short padded tail line is redacted too'
assert_contains "$R" 'END RSA PRIVATE KEY' 'the END marker is left as a readable signal'

t_case 'redact_secrets=false is permitted but must be visible'
out=$(SCOURSH_REDACT_SECRETS=false bash -c "source '$ROOT/lib/findings.sh'; redact '$s1'")
assert_contains "$out" 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'the operator can turn it off'

# ---------------------------------------------------------------------------
printf '\n-- tension 10: evidence normalisation on the way in --\n'
# ---------------------------------------------------------------------------
t_case 'the result is single-line, control-free, valid UTF-8 and bounded'
hostile=$(printf '</script><img src=x onerror=alert(1)>\033[31mANSI\033[0m\nline2\ttab\xC3\050bad')
ev=$(evidence_normalise "$hostile")
nlines=$(printf '%s\n' "$ev" | wc -l | tr -d ' ')
assert_eq 1 "$nlines" 'the result is guaranteed single-line, so findings.jsonl stays one line per finding'
assert_contains "$ev" '\n' 'line structure is preserved as a literal backslash-n'
assert_not_contains "$ev" "$(printf '\033')" 'no ESC survives, so a report cannot rewrite the terminal'
assert_not_contains "$ev" "$(printf '\t')" 'no C0 control survives'
assert_contains "$ev" '\xC3' 'an invalid UTF-8 byte becomes \\xNN'
assert_contains "$ev" '<img src=x onerror=alert(1)>' 'the evidence itself is preserved, not destroyed'

t_case 'truncation happens on a UTF-8 character boundary'
long=$(SCOURSH_EVIDENCE_MAX_BYTES=16 bash -c "
  source '$ROOT/lib/findings.sh'
  evidence_normalise \"\$(printf 'aaaaaaaaaaaaaaa\\xC3\\xA9tail')\"
")
assert_contains "$long" '...[truncated]' 'the marker is appended'
head=${long%% ...\[truncated\]}
assert_true "$(printf '%s' "$head" | { LC_ALL=C od -An -tx1 | { /usr/bin/grep -q ' c3$' && echo 1 || echo 0; }; })" \
  'the cut never leaves a dangling lead byte'

t_case 'md_fence_for cannot be broken out of'
assert_eq '```' "$(md_fence_for 'plain')" 'minimum three'
assert_eq '```````' "$(md_fence_for 'a ``````fence')" 'one longer than the longest run of six'

t_case 'html_escape covers the five characters'
assert_eq '&amp;&lt;&gt;&quot;&#39;' "$(html_escape '&<>"'"'"'')" 'ampersand first, so nothing is double-escaped wrongly'

# ---------------------------------------------------------------------------
printf '\n-- tension 8: the severity rubric --\n'
# ---------------------------------------------------------------------------
t_case 'the rubric always runs and is total'
assert_eq medium "$(severity_final medium)" 'absent facts take their documented defaults'
assert_eq critical "$(severity_final medium internet none false medium)" 'medium +1 internet +1 unauthenticated = critical'
assert_eq critical "$(severity_final high internet none true high)" 'three positives'
assert_eq info "$(severity_final medium internal admin false high)" 'medium -1 internal -1 admin = info'
assert_eq info "$(severity_final low internal admin false low)" 'clamped at 0, never below info'
assert_eq critical "$(severity_final critical internet none true high)" 'clamped at 4, never above critical'

t_case 'a floor keeps the rubric from demoting what it cannot judge'
assert_eq high "$(severity_final critical internal admin false low high)" \
  'the hardcoded private key rule declares severity-floor: high and the rubric cannot go below it'
assert_eq medium "$(severity_final critical internet none true high '' medium)" 'a ceiling caps it'

t_case 'the rubric is deterministic: same inputs, same output, every time'
a=$(severity_final medium internet none true low)
for _ in 1 2 3 4 5; do
  assert_eq "$a" "$(severity_final medium internet none true low)" 'byte-identical on re-run'
done

t_case 'the CVSS vector is an OUTPUT of the same facts, so it cannot disagree'
assert_eq 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' \
  "$(cvss_vector_of internet none true high)" 'internet + unauth + sensitive'
assert_eq 'CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N' \
  "$(cvss_vector_of internal admin false low)" 'internal + admin + low confidence'
assert_eq 8.2 "$(cvss_score_of 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N')" 'frozen score'
assert_eq 3.1 "$(cvss_score_of 'CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N')" 'frozen score'
# Independent check of the generator: this vector's published base score is 9.8.
# It is outside the mapping's own 24-row domain, which is why it is asserted as
# a property of the formula rather than looked up.
assert_eq 0.0 "$(cvss_score_of 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')" \
  'a vector this mapping never produces scores 0.0 rather than guessing'

# ---------------------------------------------------------------------------
printf '\n-- rules/RULE-FORMAT.md §9.2.2: cloud target attribution --\n'
# ---------------------------------------------------------------------------
t_case 'attribution maps endpoint hosts onto scope targets'
assert_eq fixture-target "$(attribute_target api.fixture.invalid || printf NONE)" 'an extra-host matches'
assert_eq fixture-target "$(attribute_target APP.FIXTURE.INVALID. || printf NONE)" \
  'lowercased and trailing-dot-stripped exactly as the scope gate normalises'
assert_eq NONE "$(attribute_target nothing.invalid || printf NONE)" \
  'zero matches means no target value and no participation - not an error'
assert_eq fixture-wide "$(attribute_target deep.sub.wide.fixture.invalid || printf NONE)" \
  'allow-subdomains: true matches a subdomain (fails if the flag is ignored, and the composite would then silently never fire)'

t_case 'scope_split_authority: the shared parser lib/http.sh and attribution both call'
scope_split_authority 'user:pass@good.fixture.invalid:8443'
assert_eq good.fixture.invalid "$_SAH_HOST" 'userinfo is stripped before the host is read'
assert_eq 8443 "$_SAH_PORT" 'port survives userinfo stripping'
assert_eq true "$_SAH_HAD_USERINFO" 'userinfo presence is flagged, same signal lib/http.sh gates on'
scope_split_authority '[2001:db8::1]:8443'
assert_eq '2001:db8::1' "$_SAH_HOST" \
  'a bracketed IPv6 authority is NOT truncated to "[" - FAILS under the old first-colon split (attribution_load extra-host loop, pre-fix)'
assert_eq true "$_SAH_BRACKETED" 'bracket presence is flagged for a numeric-literal check to run on top'
scope_split_authority '%67ood.fixture.invalid'
assert_eq good.fixture.invalid "$_SAH_HOST" \
  'percent-encoding is decoded exactly once - FAILS under the old split, which never decoded at all'
assert_status 1 'an authority with no host (userinfo but nothing after the last "@") is refused, not silently accepted as an empty host' \
  scope_split_authority 'nobody@'

t_case 'attribution now shares the same authority split as the DAST gate (regression: tension 19 "attribution normalises identically")'
assert_eq fixture-authority "$(attribute_target authority.fixture.invalid || printf NONE)" \
  'a userinfo-bearing base-url ("https://user@authority.fixture.invalid/") attributes on the HOST, not on "user@authority.fixture.invalid" - FAILS under the old _host_of_url, which never split userinfo and left it stuck to the host'
assert_eq fixture-authority "$(attribute_target '2001:db8::1' || printf NONE)" \
  'a bracketed-IPv6 extra-host ("[2001:db8::1]:8443") attributes on the address - FAILS under the old extra-host loop, which truncated the host to "[" and could never match anything'

# ---------------------------------------------------------------------------
printf '\n-- tension 17: the deterministic merge --\n'
# ---------------------------------------------------------------------------
t_case 'the merge is byte-reproducible regardless of emission order'
new_run m1
d1=$SCOURSH_RUN_DIR
occurrence_reset_unit u
for c in SAST-C-C-01 SAST-A-A-01 SAST-B-B-01; do emit_match "$d1" "$c" u.py 1 "m-$c"; done
findings_merge "$d1"
new_run m2
d2=$SCOURSH_RUN_DIR
occurrence_reset_unit u
for c in SAST-B-B-01 SAST-C-C-01 SAST-A-A-01; do emit_match "$d2" "$c" u.py 1 "m-$c"; done
findings_merge "$d2"
findings_write_jsonl "$d1"
findings_write_jsonl "$d2"
# One run timestamp is shared by every finding of a run (lib/core.sh run_init),
# so normalising that single value is all that is needed to compare two runs
# byte for byte.  Comparing them raw would pass or fail on whether the two runs
# happened to land in the same second, which is a flaky test and worse than none.
norm() { sed -e 's/"first_seen":"[^"]*"/"first_seen":"T"/g' -e 's/"last_seen":"[^"]*"/"last_seen":"T"/g' "$1"; }
assert_eq "$(norm "$d1/findings.jsonl")" "$(norm "$d2/findings.jsonl")" \
  'sorted by (module, check_id, fingerprint) under LC_ALL=C, so two identical scans produce identical bytes'

t_case 'shards live in the RUN directory, never in the scratch directory (finding F12)'
assert_file_exists "$d1/shards" 'reports/<run>/shards/ exists'
assert_file_absent "$SCOURSH_SCRATCH/findings" 'nothing is written to $SCRATCH/findings/'

# ---------------------------------------------------------------------------
printf '\n-- tension 6: derived / composite findings --\n'
# ---------------------------------------------------------------------------
mk_derived() {                   # mk_derived FILE CORRELATE REQUIRES ANYOF...
  local f=$1 corr=$2 req=$3
  shift 3
  {
    printf 'id: COMPOSITE-TEST-CHAIN\nkind: derived\ntitle: chain\nseverity: low\n'
    printf 'confidence: high\ncwe: none\nowasp: none\n'
    [[ -n $req ]] && printf 'requires: %s\n' "$req"
    local a
    for a in "$@"; do printf 'any-of: %s\n' "$a"; done
    printf 'correlate-on: %s\ntags: derived\nremediation: r\n' "$corr"
  } >"$f"
}

t_case 'case 1: the predicate holds over present findings -> it fires'
new_run d1c
d=$SCOURSH_RUN_DIR
occurrence_reset_unit u
emit_match "$d" SAST-A-A-01 same.py 1 one
emit_match "$d" SAST-B-B-01 same.py 2 two
findings_merge "$d"
mk_derived "$W/d1.rules" file SAST-A-A-01 SAST-B-B-01
derive_findings "$d" "$W/d1.rules"
assert_eq 1 "$(/usr/bin/grep -c 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields" || true)" 'the composite fires once'

t_case 'the composite fingerprint hashes the literal frozen in tension 6'
# tension 6 freezes it as
#   sha256( "fp/1" \0 "composite" \0 check_id \0 correlation_value )
# The reference is computed here from raw bytes, NOT through
# fingerprint_compute, so the assertion cannot agree with the implementation by
# sharing its helper.  A composite fingerprint is written into state/ and
# config/baseline.json, so hashing a different literal means a baseline produced
# by a conformant implementation suppresses nothing.
ref_fp() {
  { printf '%s' 'fp/1'
    local c
    for c in "$@"; do printf '\0%s' "$c"; done
  } | sha256_of
}
finding_decode "$(/usr/bin/grep 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields")"
assert_eq "$(ref_fp composite COMPOSITE-TEST-CHAIN same.py)" "${_DF[fingerprint]}" \
  'the first component is the frozen literal "composite"'
assert_ne "$(ref_fp derived COMPOSITE-TEST-CHAIN same.py)" "${_DF[fingerprint]}" \
  'and NOT the emitted module value "derived", which is a different thing'
assert_eq derived "${_DF[module]}" \
  'while the emitted module field stays "derived", which is what the report groups by'

t_case 'the composite is clamped UPWARD to its worst contributor'
line=$(/usr/bin/grep 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields")
finding_decode "$line"
assert_eq high "${_DF[base_severity]}" 'declared low, clamped to the contributors high (a roll-up is never less severe than its worst part)'

t_case 'contributor fingerprints are recorded as EVIDENCE, never as identity'
ncontrib=$(printf '%s\n' "${_DF[contributors]}" | LC_ALL=C sort -u | wc -l | tr -d ' ')
assert_eq 2 "$ncontrib" 'both contributing fingerprints are recorded in the body'
fp_with=${_DF[fingerprint]}
# The same composite with a different contributor set keeps ONE identity, which
# is what makes the diff say "this chain is still open" instead of churning.
new_run d1d
d=$SCOURSH_RUN_DIR
occurrence_reset_unit u
emit_match "$d" SAST-A-A-01 same.py 1 CHANGED
emit_match "$d" SAST-B-B-01 same.py 9 ALSOCHANGED
findings_merge "$d"
derive_findings "$d" "$W/d1.rules"
finding_decode "$(/usr/bin/grep 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields")"
assert_eq "$fp_with" "${_DF[fingerprint]}" \
  'the composite keeps one stable identity as its contributing evidence shifts (fails if contributor fingerprints are in the hash)'

t_case 'each contributor gains a back-reference and is retained in its own right'
assert_eq 3 "$(wc -l <"$d/findings.fields" | tr -d ' ')" 'contributors are not absorbed'
assert_eq 2 "$(/usr/bin/grep -c 'derived_into=COMPOSITE-TEST-CHAIN' "$d/findings.fields" || true)" \
  'both contributors carry derived_into'

t_case 'case 2: contributors with DIFFERENT correlation values do not fire'
# Fails under a rule that joins on `none`: a key found in account A and
# introspection enabled in account B must not fabricate a composite.
new_run d2
d=$SCOURSH_RUN_DIR
occurrence_reset_unit u
emit_match "$d" SAST-A-A-01 one.py 1 x
emit_match "$d" SAST-B-B-01 two.py 1 y
findings_merge "$d"
derive_findings "$d" "$W/d1.rules"
assert_eq 0 "$(/usr/bin/grep -c 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields" || true)" \
  'correlate-on: file joins per file, so two different files do not correlate'

t_case 'a requires contributor that is absent stops the composite firing'
new_run d3
d=$SCOURSH_RUN_DIR
occurrence_reset_unit u
emit_match "$d" SAST-B-B-01 same.py 1 y
findings_merge "$d"
derive_findings "$d" "$W/d1.rules"
assert_eq 0 "$(/usr/bin/grep -c 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields" || true)" 'requires is ALL'

t_case 'any-of is satisfied by ONE of its alternatives'
new_run d4
d=$SCOURSH_RUN_DIR
mk_derived "$W/d4.rules" file SAST-A-A-01 SAST-B-B-01 SAST-C-C-01
occurrence_reset_unit u
emit_match "$d" SAST-A-A-01 same.py 1 x
emit_match "$d" SAST-C-C-01 same.py 2 z
findings_merge "$d"
derive_findings "$d" "$W/d4.rules"
assert_eq 1 "$(/usr/bin/grep -c 'check_id=COMPOSITE-TEST-CHAIN' "$d/findings.fields" || true)" 'the second alternative satisfies any-of'

t_case 'a derived finding persists cell as JSON null, never the string "none"'
findings_write_jsonl "$d"
comp=$(/usr/bin/grep '"check_id":"COMPOSITE-TEST-CHAIN"' "$d/findings.jsonl")
assert_contains "$comp" '"cell":null' 'null is unambiguous; "none" is a legal path-root AND a legal target id'
assert_not_contains "$comp" '"cell":"none"' 'the withdrawn string sentinel is not used'

# ---------------------------------------------------------------------------
printf '\n-- tension 6: classifying a prior composite that did not fire --\n'
# ---------------------------------------------------------------------------
# Firing and classifying are separate operations with separate rules; conflating
# them is what produces phantom remediation.
records_load "$W/d4.rules" derived derivedset >/dev/null 2>&1
CN=$W/covered_now
CP=$W/covered_prior
PS=$W/prior_state

t_case 'case 3: does not fire, every prior contributor pair covered -> fixed'
printf 'fpA\tSAST-A-A-01\t.\t\nfpC\tSAST-C-C-01\t.\t\n' >"$PS"
printf 'SAST-A-A-01\t.\nSAST-B-B-01\t.\nSAST-C-C-01\t.\n' >"$CN"
printf 'SAST-A-A-01\t.\nSAST-B-B-01\t.\nSAST-C-C-01\t.\n' >"$CP"
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpC' "$PS" "$CN" "$CP" '')
assert_eq fixed "${out%%$'\t'*}" 'the chain is broken and every contributor was reassessed'

t_case 'case 4: one prior contributor cell not visited (--regions narrowed) -> unknown'
# Fails under classification keyed on the bare check id ("ran somewhere").
printf 'fpA\tSAST-A-A-01\tus-east-1\t\nfpC\tSAST-C-C-01\teu-west-1\t\n' >"$PS"
printf 'SAST-A-A-01\tus-east-1\nSAST-B-B-01\tus-east-1\nSAST-C-C-01\tus-east-1\n' >"$CN"
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpC' "$PS" "$CN" "$CP" '')
assert_eq unknown "${out%%$'\t'*}" 'the cell where the contributor could have fired was never revisited'

t_case 'case 5: the composite record itself was dropped by a filter -> unknown'
# Fails when condition (a) is omitted: the round-2 rule returns
# `fixed (chain broken)` with all contributors present and the chain fully open.
# SCOURSH_SELECTED_CHECKS is set directly here rather than through
# lib/checks.sh's real filter chain, so this pins condition (a) independent of
# WHICH filter did the dropping - originally --intensity active (before
# finding F8 exempted `derived` from the intensity ceiling), now realistically
# --profile-scan or --allow-intrusive; docs/FOUNDATION.md tension 6's own case
# 5 note says the same.
printf 'fpA\tSAST-A-A-01\t.\t\nfpC\tSAST-C-C-01\t.\t\n' >"$PS"
printf 'SAST-A-A-01\t.\nSAST-B-B-01\t.\nSAST-C-C-01\t.\n' >"$CN"
out=$(SCOURSH_SELECTED_CHECKS='SAST-A-A-01' classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpC' "$PS" "$CN" "$CP" '')
assert_eq unknown "${out%%$'\t'*}" 'a composite that was not selected is unknown'
assert_contains "$out" composite-not-selected 'and run.json says why'

t_case 'case 6: a listed any-of alternative whose prior cells were not all revisited -> unknown'
# The region-narrowed case.  Fails under (b2) omitted AND under (b2) stated as
# "covered in at least one cell": both return fixed, because C IS covered in
# us-east-1 while eu-west-1 was never revisited.
printf 'fpA\tSAST-A-A-01\tus-east-1\t\nfpB\tSAST-B-B-01\tus-east-1\t\n' >"$PS"
printf 'SAST-A-A-01\tus-east-1\nSAST-B-B-01\tus-east-1\nSAST-C-C-01\tus-east-1\n' >"$CN"
printf 'SAST-C-C-01\tus-east-1\nSAST-C-C-01\teu-west-1\n' >"$CP"
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpB' "$PS" "$CN" "$CP" '')
assert_eq unknown "${out%%$'\t'*}" 'the prior cell set is not a subset of this run cells'

t_case 'case 9: an alternative never covered in EITHER run -> unknown'
# Fails under a bare subset test: the prior cell set for C is empty, empty is a
# subset of anything, so (b2) holds vacuously and the composite is persisted
# `fixed (chain broken)` while the alternative that could keep A AND (B OR C)
# live was never assessed in either run.  This is why the FLOOR is a separate
# explicit conjunct.
printf 'fpA\tSAST-A-A-01\t.\t\nfpB\tSAST-B-B-01\t.\t\n' >"$PS"
printf 'SAST-A-A-01\t.\nSAST-B-B-01\t.\n' >"$CN"      # C has NO entry at all
: >"$CP"
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpB' "$PS" "$CN" "$CP" '')
assert_eq unknown "${out%%$'\t'*}" 'a check with no entry in this run covered_checks is never covered'

t_case 'case 7: a SAST-HIST-* contributor inside a covered cell whose boundary receded -> unknown'
# Fails when (b1)'s fixed-eligibility clause is omitted: a cell-only test returns
# fixed while the history contributor is itself correctly unknown.
records_load "$W/hist.rules" derived derivedset >/dev/null 2>&1 || true
mk_derived "$W/hist.rules" file SAST-HIST-K-01 SAST-B-B-01
records_load "$W/hist.rules" derived derivedset >/dev/null 2>&1
printf 'fpH\tSAST-HIST-K-01\t.\t2025-01-01T00:00:00Z\nfpB\tSAST-B-B-01\t.\t\n' >"$PS"
printf 'SAST-HIST-K-01\t.\nSAST-B-B-01\t.\n' >"$CN"
: >"$CP"
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpH,fpB' "$PS" "$CN" "$CP" '2026-01-01T00:00:00Z')
assert_eq unknown "${out%%$'\t'*}" 'the contributor could not have been seen by this run walk'
out=$(classify_derived COMPOSITE-TEST-CHAIN . false 'fpH,fpB' "$PS" "$CN" "$CP" '2024-01-01T00:00:00Z')
assert_eq fixed "${out%%$'\t'*}" 'and it IS fixed when the boundary still reaches it'

t_case 'case 8: a prior composite with no recorded contributors -> unknown'
# Fails under the "covered in at least one cell" fallback applied to this branch.
out=$(classify_derived COMPOSITE-TEST-CHAIN . false '' "$PS" "$CN" "$CP" '')
assert_eq unknown "${out%%$'\t'*}" 'nothing was learned, so nothing is claimed'
assert_contains "$out" contributors-unavailable 'and the reason is recorded'

t_summary findings
