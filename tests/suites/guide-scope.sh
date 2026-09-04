#!/usr/bin/env bash
# tests/suites/guide-scope.sh - lib/guide_scope.sh (docs/STEP-GUIDE-PLAN.md
# GUIDE-05, step G4): the pure half of the config/scope.conf record writer -
# id derivation, record-text rendering, the reused deny-list check, and the
# validate-in-a-temp-file-then-rename append primitive.  No terminal I/O
# lives in this file (it belongs to lib/guide.sh's `guide_g4_authorize_target`
# instead), so every case here drives a plain function call against a
# scratch directory - no pty, no piped stdin.
#
# The plan's own GUIDE-05 row requires "a suite case must prove the
# post-write gate behaviour is identical to a hand-edited file" - section G
# below is that proof: it writes one target through `guide_scope_append` and
# hand-authors an equivalent record as a literal heredoc in this file, then
# asserts `http_gate_url` makes the identical allow/refuse decision against
# both files for a matched host, an out-of-scope host, and a subdomain (which
# `allow-subdomains: false` must refuse in both).
#
# Every case that pins a reading names the reading it fails under (AGENTS.md's
# testing rule): most of these are marked "FAILS if ..." in their own message.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell/record syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/guide_scope.sh
source "$ROOT/lib/guide_scope.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/guide-scope
mkdir -p "$W"

# ---------------------------------------------------------------------------
# A. guide_scope_id_base - the pure id transform
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_id_base --\n'
t_case 'guide_scope_id_base'

assert_eq 'staging-api-internal-443' "$(guide_scope_id_base 'staging-api.internal' 443)" \
  'a hostname:port with dots and a colon separator all become dashes'

assert_eq 'staging-api-internal-443' "$(guide_scope_id_base 'STAGING-API.INTERNAL' 443)" \
  'lowercased regardless of input case'

assert_eq 't-10-4-7-22-443' "$(guide_scope_id_base '10.4.7.22' 443)" \
  'FAILS if the t- prefix is dropped: an IPv4 literal transforms to a leading digit, which is not a legal id start (rules/RULE-FORMAT.md sec9.4 ^[a-z][a-z0-9-]*$)'

assert_eq 't---1-3400' "$(guide_scope_id_base '::1' 3400)" \
  'an IPv6 literal front-loads dashes from its own colons, which also needs the t- prefix'

assert_eq 'a-b-c-1' "$(guide_scope_id_base 'a.b.c' 1)" \
  'a plain three-label host stays letter-first with no prefix needed'

# ---------------------------------------------------------------------------
# B. guide_scope_unique_id - collision disambiguation
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_unique_id --\n'

t_case 'no existing file: base id is returned unchanged'
assert_eq 'brand-new-id' "$(guide_scope_unique_id 'brand-new-id' "$W/absent.conf")" \
  'an absent scope.conf has zero existing ids to collide with'

cat >"$W/one-target.conf" <<'EOF'
id: taken-id
base-url: https://taken.example
allow-subdomains: false
allow-private-addresses: false
EOF

t_case 'one collision: -2 is appended'
assert_eq 'taken-id-2' "$(guide_scope_unique_id 'taken-id' "$W/one-target.conf")" \
  "FAILS if disambiguation does not fire: 'taken-id' already names a record in one-target.conf"

t_case 'no collision: an unrelated base id is untouched'
assert_eq 'unrelated-id' "$(guide_scope_unique_id 'unrelated-id' "$W/one-target.conf")" \
  'a base id that does not appear in the file needs no suffix'

cat >"$W/two-collisions.conf" <<'EOF'
id: dup
base-url: https://a.example
allow-subdomains: false
allow-private-addresses: false

id: dup-2
base-url: https://b.example
allow-subdomains: false
allow-private-addresses: false
EOF

t_case 'two collisions: -2 is also taken, so -3 is returned'
assert_eq 'dup-3' "$(guide_scope_unique_id 'dup' "$W/two-collisions.conf")" \
  'FAILS if the loop stops after one bump: both dup and dup-2 are already present'

cat >"$W/malformed.conf" <<'EOF'
id: bad id with spaces
base-url: https://a.example
EOF

t_case 'a malformed existing scope.conf dies rather than silently reading as empty'
assert_status "$SCOURSH_EXIT_INPUT" \
  'FAILS if a broken existing file is treated as "no records": that would let a guided write build its preview, and its collision check, against data it cannot trust' \
  guide_scope_unique_id 'anything' "$W/malformed.conf"

# ---------------------------------------------------------------------------
# C. guide_scope_addr_denied - reused from lib/http.sh, never re-derived
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_addr_denied --\n'
t_case 'guide_scope_addr_denied'

assert_true "$(guide_scope_addr_denied '127.0.0.1' && echo 0 || echo 1)" 'loopback IPv4 is denied'
assert_true "$(guide_scope_addr_denied '169.254.169.254' && echo 0 || echo 1)" \
  'link-local IPv4 (cloud metadata) is denied'
assert_true "$(guide_scope_addr_denied '100.64.0.5' && echo 0 || echo 1)" 'CGNAT IPv4 is denied'
assert_true "$(guide_scope_addr_denied '8.8.8.8' && echo 1 || echo 0)" 'an ordinary public IPv4 is not denied'
assert_true "$(guide_scope_addr_denied '::1' && echo 0 || echo 1)" 'IPv6 loopback is denied'
assert_true "$(guide_scope_addr_denied 'fe80::1' && echo 0 || echo 1)" 'IPv6 link-local is denied'
assert_true "$(guide_scope_addr_denied '2001:db8::1' && echo 1 || echo 0)" \
  'the IPv6 documentation range is not in the deny list, so it is not denied'

# ---------------------------------------------------------------------------
# D. guide_scope_notes_text / guide_scope_record_text - preview == what gets
#    written, and the base-url value is carried through VERBATIM (this
#    file's own header, rule 2: never a value the writer invented)
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_record_text --\n'

notes=$(guide_scope_notes_text)
t_case 'guide_scope_notes_text'
assert_contains "$notes" 'Authorised interactively via scan.sh --guided on' \
  'the dated authorisation sentence is present'
assert_contains "$notes" $'\n' 'the notes text is genuinely multi-line'

record=$(guide_scope_record_text 'my-id' 'HTTPS://Weird-Case.Example:443/App' 'true' "$notes")
t_case 'guide_scope_record_text'
assert_eq 'id: my-id' "$(printf '%s\n' "$record" | sed -n 1p)" 'id is the FIRST field, per rules/RULE-FORMAT.md sec9.4'
assert_eq 'base-url: HTTPS://Weird-Case.Example:443/App' "$(printf '%s\n' "$record" | sed -n 2p)" \
  'FAILS if the base-url is normalised before writing: rule 2 requires the operator''s own bytes verbatim, not a lowercased/canonicalised form'
assert_eq 'allow-subdomains: false' "$(printf '%s\n' "$record" | sed -n 3p)" \
  'FAILS if allow-subdomains is ever anything but false: there is no parameter for it in this design'
assert_eq 'allow-private-addresses: true' "$(printf '%s\n' "$record" | sed -n 4p)" \
  'the caller-decided allow-private-addresses value is passed through unchanged'
assert_contains "$(printf '%s\n' "$record" | sed -n 5p)" 'notes: Authorised interactively via scan.sh --guided on' \
  'the notes field opens the multi-line value'
assert_eq '  Confirmed at the prompt after the normalised target and its resolved' \
  "$(printf '%s\n' "$record" | sed -n 6p)" \
  'FAILS if continuation lines are not indented exactly two spaces: rules/RULE-FORMAT.md sec6 requires 0x20 0x20'

# ---------------------------------------------------------------------------
# E. guide_scope_append - the validate-in-a-temp-file-then-rename writer
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_append: fresh file --\n'

fresh=$W/fresh.conf
rec1=$(guide_scope_record_text 'fresh-target' 'https://fresh.example' 'false' "$(guide_scope_notes_text)")
guide_scope_append "$rec1" "$fresh"

t_case 'a fresh file (no prior scope.conf) is written and parses to exactly one record'
assert_file_exists "$fresh" 'the file now exists'
records_clear scope
config_scope_load "$fresh"
assert_eq '1' "$(records_count scope)" 'exactly one record'
assert_eq 'https://fresh.example' "$(records_field scope 0 base-url)" 'base-url round-trips verbatim'

printf '\n-- guide_scope_append: append to an existing file ENDING with a newline --\n'
withnl=$W/withnl.conf
printf 'id: first\nbase-url: https://first.example\nallow-subdomains: false\nallow-private-addresses: false\n' >"$withnl"
rec2=$(guide_scope_record_text 'second' 'https://second.example' 'false' "$(guide_scope_notes_text)")
guide_scope_append "$rec2" "$withnl"

t_case 'append onto a file that already ends with a trailing newline'
records_clear scope
config_scope_load "$withnl"
assert_eq '2' "$(records_count scope)" 'FAILS if the blank-line separator merges the two records into one'
assert_eq 'first' "$(records_id scope 0)" 'the original record is untouched'
assert_eq 'second' "$(records_id scope 1)" 'the new record is appended after it'

printf '\n-- guide_scope_append: append to an existing file NOT ending with a newline --\n'
nonl=$W/nonl.conf
printf 'id: first\nbase-url: https://first.example\nallow-subdomains: false\nallow-private-addresses: false' >"$nonl"
rec3=$(guide_scope_record_text 'second' 'https://second.example' 'false' "$(guide_scope_notes_text)")
guide_scope_append "$rec3" "$nonl"

t_case 'append onto a file with NO trailing newline on its last line'
records_clear scope
config_scope_load "$nonl"
assert_eq '2' "$(records_count scope)" \
  'FAILS if the missing trailing newline lets the new id run into the previous record''s last field'
assert_eq 'first' "$(records_id scope 0)" 'the original record is untouched'
assert_eq 'second' "$(records_id scope 1)" 'the new record is appended after it'

printf '\n-- guide_scope_append: refusals leave the original file untouched --\n'

dupfile=$W/dup.conf
printf 'id: dup-target\nbase-url: https://a.example\nallow-subdomains: false\nallow-private-addresses: false\n' >"$dupfile"
before_sum=$(sha256_of <"$dupfile")

t_case 'append-only: an id that already exists is refused (rules/RULE-FORMAT.md E019), never silently overwritten'
dup_record=$(guide_scope_record_text 'dup-target' 'https://b.example' 'false' "$(guide_scope_notes_text)")
assert_status "$SCOURSH_EXIT_INPUT" \
  'FAILS if the append primitive lets a duplicate id through: this is the structural half of "the writer is append-only", not just the disambiguation layer'\'' convenience' \
  guide_scope_append "$dup_record" "$dupfile"
after_sum=$(sha256_of <"$dupfile")
assert_eq "$before_sum" "$after_sum" 'the original file is byte-identical after the refused write'

badir=$W/does-not-exist/scope.conf
t_case 'a scope.conf whose directory does not exist is refused, not silently mkdir -p'\''d'
assert_status "$SCOURSH_EXIT_INPUT" 'no surprise directory creation' \
  guide_scope_append "$rec1" "$badir"

# ---------------------------------------------------------------------------
# F. guide_scope_append never brick's a pre-existing malformed scope.conf,
#    and never bricks a well-formed one with a bad new record either - both
#    leave the ORIGINAL file exactly as it was.
# ---------------------------------------------------------------------------
printf '\n-- guide_scope_append: malformed composition leaves the original untouched --\n'

good=$W/good.conf
printf 'id: keep-me\nbase-url: https://keep.example\nallow-subdomains: false\nallow-private-addresses: false\n' >"$good"
good_sum=$(sha256_of <"$good")

t_case 'a record with an illegal id shape is refused at write time, not silently written'
bad_record='id: Not A Legal Id
base-url: https://bad.example
allow-subdomains: false
allow-private-addresses: false'
assert_status "$SCOURSH_EXIT_INPUT" 'schema validation refuses an id with spaces/uppercase' \
  guide_scope_append "$bad_record" "$good"
good_sum2=$(sha256_of <"$good")
assert_eq "$good_sum" "$good_sum2" 'the original file is untouched by the refused write'

# ---------------------------------------------------------------------------
# G. THE REQUIRED PROOF (docs/STEP-GUIDE-PLAN.md GUIDE-05): the post-write
#    gate behaviour of a guided write is identical to a hand-edited file.
# ---------------------------------------------------------------------------
printf '\n-- G: guided write vs. a hand-edited file - identical gate behaviour --\n'

# No test here ever resolves a real name: proof.example is a stand-in host,
# stubbed the same way tests/suites/http.sh stubs its own fixture hosts.
_g4_proof_resolve() {
  case $1 in
    proof.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_g4_proof_resolve

guided=$W/guided.conf
guided_rec=$(guide_scope_record_text 'proof-target' 'https://proof.example' 'false' "$(guide_scope_notes_text)")
guide_scope_append "$guided_rec" "$guided"

# A hand-edited file: literal bytes, typed the way an operator hand-editing
# config/scope.conf.example would type them - not produced by any function
# under test in this suite.
handedited=$W/handedited.conf
cat >"$handedited" <<'EOF'
# Hand-edited by a human, per rules/RULE-FORMAT.md sec9.4.
id: proof-target
base-url: https://proof.example
allow-subdomains: false
allow-private-addresses: false
notes: Added by hand while reviewing a PR.
EOF

t_case 'both files parse and schema-validate identically'
for f in "$guided" "$handedited"; do
  records_clear scope
  assert_status 0 "records_load succeeds for $f" config_scope_load "$f"
done

t_case 'both files agree on the fields the gate reads'
for f in "$guided" "$handedited"; do
  records_clear scope
  config_scope_load "$f"
  assert_eq 'https://proof.example' "$(records_field scope 0 base-url)" "base-url in $f"
  assert_eq 'false' "$(records_field_or scope 0 allow-subdomains false)" "allow-subdomains in $f"
  assert_eq 'false' "$(records_field_or scope 0 allow-private-addresses false)" "allow-private-addresses in $f"
done

t_case 'both files make the IDENTICAL scope-gate decision for a matched host'
for f in "$guided" "$handedited"; do
  _HTTP_SCOPE_LOADED=0
  http_scope_load "$f"
  assert_status 0 "http_gate_url allows the exact authorised host for $f" \
    http_gate_url 'https://proof.example/'
done

t_case 'both files make the IDENTICAL scope-gate REFUSAL for an out-of-scope host'
for f in "$guided" "$handedited"; do
  _HTTP_SCOPE_LOADED=0
  http_scope_load "$f"
  rc=0
  http_gate_url 'https://unrelated.example/' >/dev/null 2>&1 || rc=$?
  assert_eq '1' "$rc" "http_gate_url refuses an unrelated host for $f"
done

t_case 'both files make the IDENTICAL scope-gate REFUSAL for a subdomain (allow-subdomains: false in both)'
for f in "$guided" "$handedited"; do
  _HTTP_SCOPE_LOADED=0
  http_scope_load "$f"
  rc=0
  http_gate_url 'https://sub.proof.example/' >/dev/null 2>&1 || rc=$?
  assert_eq '1' "$rc" \
    "FAILS if a guided write is somehow MORE permissive than a hand-edited one for $f"
done

t_summary guide-scope
