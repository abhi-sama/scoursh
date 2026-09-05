#!/usr/bin/env bash
# tests/suites/records.sh - the frozen record format, rules/RULE-FORMAT.md.
#
# Covers §3.2's ordered line classification, §4 records, §5 fields, §6
# continuations, §7's parse algorithm, §9's ten schemas, §12's worked examples
# and §12.6's negative examples, and the §13 error codes the parser owns.
#
# shellcheck shell=bash
#
# SC2015: `cmd && ok || no` is the intended reporting shape here.
# SC2059: the printf format is assembled from a fixture table on purpose.
# SC2100: `schema=pattern-rule` is a string, not arithmetic.
# shellcheck disable=SC2015,SC2059,SC2100

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/records.sh
source "$ROOT/lib/records.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/rec
mkdir -p "$W"

# Parses $1 as $2 and prints the diagnostics; returns the parser's status.
try_parse() {
  local file=$1 schema=$2
  records_reset_diagnostics
  records_load "$file" "$schema" t 2>/dev/null
}

diags() { printf '%s\n' "${RECORDS_DIAGNOSTICS[@]+"${RECORDS_DIAGNOSTICS[@]}"}"; }

# ---------------------------------------------------------------------------
printf '\n-- §12 worked examples parse byte-exactly --\n'
# ---------------------------------------------------------------------------
cat >"$W/w.rules" <<'EOF'
id: SAST-SEC-AWS_AKID-01
title: Hardcoded AWS access key id
severity: critical
confidence: high
cwe: CWE-798
owasp: A07:2021
pattern: \b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b
dialect: ere
context-deny: EXAMPLE|example|AKIAIOSFODNN7EXAMPLE|placeholder|XXXXXXXX
context-window: 0
tags: static
tags: quick
tags: compliance
remediation: Remove the key from source and rotate it immediately; a committed key must be
  treated as compromised even if the commit was reverted.
references: CWE-798
cis: 1.4

id: SAST-GEN-SUPPRESSION-01
title: Security-linter suppression comment in source
severity: low
confidence: high
cwe: none
owasp: none
pattern: (#\s*(nosec|noqa:\s*S[0-9]+|type:\s*ignore\[security)|//\s*eslint-disable.*security)
dialect: ere
tags: static
remediation: A suppression comment hides a finding from every other tool in the pipeline.
references: CWE-1078
EOF
t_case '§12.1 alternation-heavy record'
assert_status 0 'a pack whose regexes are full of | parses' try_parse "$W/w.rules" pattern-rule
try_parse "$W/w.rules" pattern-rule || true
assert_eq '\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b' \
  "$(records_field t 0 pattern)" 'six pipes survive verbatim - no escaping of any kind (§5.3)'
assert_eq 'EXAMPLE|example|AKIAIOSFODNN7EXAMPLE|placeholder|XXXXXXXX' \
  "$(records_field t 0 context-deny)" 'the deny value carries five more pipes'
assert_eq 'static
quick
compliance' "$(records_list t 0 tags)" 'a repeatable key accumulates in file order (§5.4)'
assert_eq 'Remove the key from source and rotate it immediately; a committed key must be
treated as compromised even if the commit was reverted.' "$(records_field t 0 remediation)" \
  'two-space continuations join with one LF, stripped of the two spaces (§6)'
assert_eq '(#\s*(nosec|noqa:\s*S[0-9]+|type:\s*ignore\[security)|//\s*eslint-disable.*security)' \
  "$(records_field t 1 pattern)" 'a value starting with # is data: only column 1 starts a comment (§12.4)'
assert_eq 2 "$(records_count t)" 'a blank line separates records (§4)'

t_case '§5.2 the first ": " separates; later ones are value'
printf 'id: SAST-JS-PROTO-01\ntitle: x\nseverity: high\nconfidence: medium\ncwe: none\nowasp: none\npattern: (__proto__\\s*[:=]|\\[\\s*["'"'"']__proto__["'"'"']\\s*\\])\ntags: static\nremediation: y\n' >"$W/colon.rules"
try_parse "$W/colon.rules" pattern-rule || true
assert_contains "$(records_field t 0 pattern)" '__proto__\s*[:=]' 'a colon inside a value is data (§5.2)'

# ---------------------------------------------------------------------------
printf '\n-- §12.6 negative examples: the right code for the right condition --\n'
# ---------------------------------------------------------------------------
neg() {
  local name=$1 want=$2 wantpos=$3
  shift 3
  printf '%b' "$1" >"$W/$name"
  try_parse "$W/$name" pattern-rule && { _t_no "$name expected $want" 'the parse succeeded'; return; }
  local d
  d=$(diags)
  assert_contains "$d" "$want" "$name -> $want"
  [[ -z $wantpos ]] || assert_contains "$d" "$wantpos" "$name -> reported at $wantpos"
}

# (a) a "blank" line carrying two spaces separates nothing and continues nothing
neg a.rules E011 ':3:1:' 'id: SAST-PY-EVAL-01\nremediation: line one\n  \nfiles: *.py\n'
# (b) one leading space is an error, not a continuation
neg b.rules E010 ':3:1:' 'id: SAST-PY-EVAL-01\nremediation: line one\n line two\n'
# (d) a TAB is content, never indentation
neg d.rules E021 ':2:1:' 'id: SAST-PY-EVAL-01\n\tremediation: x\n'
# (e) an empty value is an error, not an unset field
neg e.rules E013 ':2:1:' 'id: SAST-PY-EVAL-01\ncwe:\n'
neg e2.rules E013 ':2:1:' 'id: SAST-PY-EVAL-01\ncwe: \n'
neg f.rules E012 ':3:1:' 'id: SAST-PY-EVAL-01\n# c\n  cont\n'
neg g.rules E015 ':1:1:' '  cont\nid: SAST-PY-EVAL-01\n'
neg h.rules E016 ':3:1:' 'id: SAST-PY-EVAL-01\npattern: x\n  more\n'
neg i.rules E014 ':3:1:' 'id: SAST-PY-EVAL-01\nseverity: high\nseverity: low\n'
neg j.rules E020 ':1:1:' 'title: x\nid: SAST-PY-EVAL-01\n'
neg k.rules E017 ':2:1:' 'id: SAST-PY-EVAL-01\nbogus-key: x\n'
neg l.rules E002 ':1:20:' 'id: SAST-PY-EVAL-01\r\ntitle: x\n'
neg m.rules E004 '' 'id: SAST-PY-EVAL-01\ntitle: a\x00b\n'
neg n.rules E003 ':1:1:' '\xEF\xBB\xBFid: SAST-PY-EVAL-01\n'
neg dup.rules E019 '' 'id: SAST-PY-EVAL-01\ntitle: a\n\nid: SAST-PY-EVAL-01\ntitle: b\n'

t_case '(c) three or more leading spaces is a valid continuation'
printf 'id: SAST-PY-EVAL-01\nremediation: Do not eval() request data.\n  Prefer:\n    ast.literal_eval()\n' >"$W/c.rules"
try_parse "$W/c.rules" pattern-rule || true
assert_eq 'Do not eval() request data.
Prefer:
  ast.literal_eval()' "$(records_field t 0 remediation)" \
  'only the FIRST two spaces are stripped; the rest is value (§6 rule 1)'

t_case 'a whitespace-only line is E011 even where a Blank would have parsed cleanly'
# This is the case §12.6a exists for: read as a Continuation the record grows a
# trailing empty line, read as a Blank the next record fails E020, and both are
# silent misparses of an invisible byte.  The ordered test makes it loud.
printf 'id: SAST-PY-EVAL-01\ntitle: x\n \nid: SAST-PY-OTHER-01\ntitle: y\n' >"$W/ws.rules"
try_parse "$W/ws.rules" pattern-rule && _t_no 'single-space line' 'parsed clean' || {
  assert_contains "$(diags)" E011 'a single-space line is E011, not a record separator'
}

# ---------------------------------------------------------------------------
printf '\n-- §3.1 UTF-8 --\n'
# ---------------------------------------------------------------------------
t_case 'UTF-8 validation'
printf 'id: SAST-PY-EVAL-01\ntitle: ok \xC3\xA9 \xE2\x82\xAC \xF0\x9F\x94\x92 utf8\n' >"$W/u_ok.rules"
assert_status 0 'well-formed multi-byte sequences are accepted' try_parse "$W/u_ok.rules" pattern-rule
for bad in '\xC3\x28:truncated-2-byte' '\x80:lone-continuation' '\xC0\x80:overlong' \
  '\xED\xA0\x80:utf16-surrogate' '\xF5\x80\x80\x80:above-U+10FFFF' '\xE2\x82:truncated-3-byte'; do
  seq=${bad%%:*}
  why=${bad##*:}
  printf "id: SAST-PY-EVAL-01\ntitle: bad $seq here\n" >"$W/u_bad.rules"
  try_parse "$W/u_bad.rules" pattern-rule \
    && _t_no "E001 $why" 'invalid UTF-8 was accepted' \
    || assert_contains "$(diags)" E001 "E001 rejects $why"
done

# ---------------------------------------------------------------------------
printf '\n-- §9 schemas --\n'
# ---------------------------------------------------------------------------
t_case 'every §9 schema is defined and loads through this one parser'
for s in $(records_schema_names); do
  if records_schema_keys "$s" >/dev/null 2>&1; then
    _t_ok "schema '$s' is defined"
  else
    _t_no "schema '$s' is defined" 'not found'
  fi
done

t_case 'INVARIANT: no key is both repeatable and multi-line'
# The whole line-oriented storage of repeated values depends on this: a
# repeatable value can never contain an LF, so repeated values can be LF-joined.
bad=''
for s in $(records_schema_names); do
  while IFS= read -r k; do
    [[ -n $k ]] || continue
    if records_key_is_repeatable "$s" "$k" && records_key_is_multiline "$s" "$k"; then
      bad="$bad $s.$k"
    fi
  done <<<"$(records_schema_keys "$s")"
done
assert_eq '' "$bad" 'no schema has a repeatable multi-line key'

t_case '§9 path table'
assert_eq script-check "$(records_schema_for_path modules/dast/checks.rules)" \
  'checks.rules is reserved repository-wide and wins over the *.rules globs'
assert_eq script-check "$(records_schema_for_path modules/iac/checks.rules)" \
  'modules/iac/checks.rules is a script check, not a pattern rule'
assert_eq pattern-rule "$(records_schema_for_path modules/iac/cloud.rules)" 'modules/iac/*.rules'
assert_eq pattern-rule "$(records_schema_for_path modules/sast/rules/secrets.rules)" 'sast rules'
assert_eq derived "$(records_schema_for_path rules/derived.rules)" 'derived'
assert_eq redaction "$(records_schema_for_path rules/redaction.rules)" 'redaction'
assert_eq scope-target "$(records_schema_for_path config/scope.conf)" 'scope'
assert_eq scanner-config "$(records_schema_for_path config/scanner.conf)" 'scanner'
assert_eq severity-modifier "$(records_schema_for_path data/severity-rubric.conf)" 'rubric'
assert_status 1 'a file matching no row is E070' records_schema_for_path some/other/file.rules

# --- §9's `checks-<name>.rules` row ----------------------------------------
# The per-owner spelling of the §9.5 script-check registry, added so that peers
# adding phase scripts to one module directory in parallel do not collide on a
# single co-owned file.  Every assertion below names the reading it fails under,
# because the row is only worth having if it legalises EXACTLY one shape: a
# `checks-*` glob that also swallowed arbitrary `*.rules` names would silently
# give the pattern-rule schema's files the script-check schema, and every record
# in them would fail E023 for a missing `pattern`.
t_case '§9 path table: the checks-<name>.rules row'
assert_eq script-check "$(records_schema_for_path modules/dast/passive/checks-cookies.rules)" \
  'checks-<name>.rules at a module path is a script check'
assert_eq script-check "$(records_schema_for_path checks-top.rules)" \
  'the checks- prefix is reserved repository-wide, including at the root'
# Sits ABOVE the pattern-rule rows, exactly as the `checks.rules` row does: under
# the opposite ordering this is captured by `modules/iac/*.rules` and every
# record in it fails E023 for a missing `pattern`.
assert_eq script-check "$(records_schema_for_path modules/iac/checks-terraform.rules)" \
  'checks-<name>.rules beats the modules/iac/*.rules pattern-rule glob'
# The negative direction, which is the half that matters: the row must not open
# the extension up.  Both of these are real names this repository rejected.
assert_status 1 'an arbitrary *.rules at a module path is still E070' \
  records_schema_for_path modules/dast/passive/cookies.rules
assert_status 1 'the SUFFIX spelling headers-checks.rules is still E070' \
  records_schema_for_path modules/dast/passive/headers-checks.rules
# `?*` rather than `*`: a bare `checks-.rules` names no owner.  Under a plain
# `checks-*.rules` glob this assertion fails.
assert_status 1 'checks-.rules names no owner and is E070' \
  records_schema_for_path modules/dast/passive/checks-.rules
# The reservation is on a FILENAME, not on a path segment.  Bash's `*` matches
# `/` too, so a `*/checks-?*.rules` glob would also match this and turn every
# `.rules` file under a directory called `checks-x` into a script-check
# registry.  Matching on the basename is what confines it; this assertion fails
# under the `*/`-prefixed spelling.
assert_status 1 'a DIRECTORY named checks-x does not make its contents script checks' \
  records_schema_for_path modules/dast/checks-x/arbitrary.rules
# The pre-existing rows are unchanged by the addition - the amendment widens the
# table and re-classifies nothing (rules/RULE-FORMAT.md §14's second worked
# example turns on exactly this).
assert_eq script-check "$(records_schema_for_path modules/dast/passive/checks.rules)" \
  'the plain checks.rules row still resolves as it did before'
assert_eq pattern-rule "$(records_schema_for_path modules/iac/terraform.rules)" \
  'a pattern-rule pack is unaffected by the new row'

t_case '§9 single-record config files (E071)'
printf 'id: not-scanner\njobs: 4\n' >"$W/scanner.conf"
try_parse "$W/scanner.conf" scanner-config || true
records_validate t 2>/dev/null || true
assert_contains "$(diags)" E071 'a scanner.conf whose id is not the frozen literal is E071'
printf 'id: scanner\njobs: 4\n\nid: scanner2\njobs: 8\n' >"$W/scanner2.conf"
try_parse "$W/scanner2.conf" scanner-config || true
records_reset_diagnostics
records_validate t 2>/dev/null || true
assert_contains "$(diags)" E071 'more than one record in a single-record file is E071'

t_case '§9.5.1 owning-module map, most specific first'
assert_eq POSTURE "$(records_owning_module modules/cloud/posture/checks.rules)" \
  'posture nests under modules/cloud/ but is its own module'
assert_eq CLOUD "$(records_owning_module modules/cloud/aws/checks.rules)" 'cloud'
assert_eq COMPOSITE "$(records_owning_module rules/derived.rules)" 'derived.rules is COMPOSITE'
assert_eq SAST "$(records_owning_module rules/redaction.rules)" 'redaction ids are SAST-REDACT-*'

# ---------------------------------------------------------------------------
printf '\n-- §9 validation codes --\n'
# ---------------------------------------------------------------------------
val() {
  local name=$1 body=$2
  printf '%b' "$body" >"$W/$name"
  records_reset_diagnostics
  records_load "$W/$name" "$3" t 2>/dev/null || true
  records_validate t 2>/dev/null || true
  diags
}
base='id: SAST-PY-EVAL-01\ntitle: t\nseverity: high\ncwe: CWE-95\nowasp: A03:2021\npattern: x\ntags: static\nremediation: r\n'
assert_contains "$(val v1.rules "${base/severity: high/severity: sever}" pattern-rule)" E024 \
  'E024 an enum value outside its set'
assert_contains "$(val v2.rules "${base/cwe: CWE-95/cwe: CWE95}" pattern-rule)" E025 'E025 cwe form'
assert_contains "$(val v3.rules "${base/owasp: A03:2021/owasp: A3:2021}" pattern-rule)" E026 'E026 owasp form'
assert_contains "$(val v4.rules "${base/id: SAST-PY-EVAL-01/id: SAST-PY-EVAL}" pattern-rule)" E027 \
  'E027 SEQ is required outside the derived schema'
assert_contains "$(val v5.rules 'id: SAST-PY-EVAL-01\ntitle: t\nseverity: high\ncwe: none\nowasp: none\npattern: x\ntags: static\n' pattern-rule)" E023 \
  'E023 a missing required key'
assert_contains "$(val v6.rules "${base}severity-floor: critical\nseverity-ceiling: low\n" pattern-rule)" E029 \
  'E029 floor above ceiling'
assert_contains "$(val v7.rules "${base}context-window: 3\n" pattern-rule)" E031 \
  'E031 context-window with no require and no deny'
assert_contains "$(val v8.rules "${base}context-deny: y\ncontext-window: 99\n" pattern-rule)" E032 \
  'E032 context-window above 50'
assert_contains "$(val v9.rules "${base}files: a{b,c}.py\n" pattern-rule)" E042 \
  'E042 brace expansion in a glob'
assert_contains "$(val v10.rules "${base}tags: intrusive\n" pattern-rule)" E043 \
  'E043 intrusive on a pattern rule'
assert_contains "$(val v11.rules "${base/tags: static/tags: passive}" pattern-rule)" E044 \
  'E044 a type tag illegal for the schema'
assert_contains "$(val v12.rules "${base/tags: static/tags: quik\ntags: static}" pattern-rule)" E044 \
  'E044 a tag outside the §9.1.3 vocabulary (a typo must not silently disable a profile)'
assert_contains "$(val v13.rules "${base}format-version: 2\n" pattern-rule)" E045 'E045 format-version'
assert_contains "$(val v14.rules "${base/pattern: x/pattern: y }" pattern-rule)" E030 \
  'E030 a trailing space on a regex value is invisible and is an error'
assert_contains "$(val v15.rules "${base/pattern: x/pattern: yaml\\\\.load\\\\((?!.*Loader)}" pattern-rule)" E040 \
  'E040 a PCRE lookahead in an ere record'
assert_contains "$(val v16.rules "${base/pattern: x/pattern: (a+)+}" pattern-rule)" E041 \
  'E041 nested unbounded quantification'
assert_not_contains "$(val v17.rules "${base/pattern: x/pattern: [A-Za-z0-9]+}" pattern-rule)" E041 \
  'an unbounded quantifier on one character class is fine'
assert_contains "$(val v18.rules 'id: COMPOSITE-X-01\nkind: derived\ntitle: t\nseverity: low\ncwe: none\nowasp: none\ncorrelate-on: none\nremediation: r\ntags: derived\n' derived)" E050 \
  'E050 a derived record with neither requires nor any-of'
assert_contains "$(val v19.rules 'id: COMPOSITE-X-01\nkind: derived\ntitle: t\nseverity: low\ncwe: none\nowasp: none\nrequires: SAST-A-B-01\ncorrelate-on: none\nremediation: r\ntags: derived\n' derived)" E027 \
  'E027 a derived id MUST omit the SEQ suffix'
assert_contains "$(val v20.rules 'id: SAST-A-B-01\ntitle: t\nscript: x.sh\nseverity: low\ncwe: none\nowasp: none\ntags: passive\ncoverage-scope: target\nremediation: r\n' script-check)" E079 \
  'E079 coverage-scope must be the module-required value'
assert_contains "$(val v21.rules 'id: SAST-A-B-01\ntitle: t\nscript: x.sh\nseverity: low\ncwe: none\nowasp: none\ntags: static\ncoverage-scope: path-root\nremediation: r\n' script-check)" E044 \
  'E044 a script check may not carry the static type tag'
assert_contains "$(val v22.rules "${base}pattern: dup\n" pattern-rule)" E014 'E014 through the validator too'

t_case 'a clean record produces no diagnostics at all'
assert_eq '' "$(val ok.rules "$base" pattern-rule)" 'the seeded shape validates silently'

# ---------------------------------------------------------------------------
printf '\n-- rule_digest --\n'
# ---------------------------------------------------------------------------
t_case 'rule_digest is stable under comment edits and changes with content'
printf '%b' "$base" >"$W/d1.rules"
printf '%b' "# a comment that says nothing\n$base" >"$W/d2.rules"
printf '%b' "${base/severity: high/severity: low}" >"$W/d3.rules"
records_load "$W/d1.rules" pattern-rule d1 >/dev/null 2>&1
records_load "$W/d2.rules" pattern-rule d2 >/dev/null 2>&1
records_load "$W/d3.rules" pattern-rule d3 >/dev/null 2>&1
assert_eq "$(records_digest d1 0)" "$(records_digest d2 0)" \
  'adding a comment does not flag "rule changed" on every finding for that check'
assert_ne "$(records_digest d1 0)" "$(records_digest d3 0)" 'changing a value does change the digest'

# ---------------------------------------------------------------------------
printf '\n-- the shipped record files parse and validate --\n'
# ---------------------------------------------------------------------------
t_case 'repository record files'
for f in rules/redaction.rules data/severity-rubric.conf \
  config/scanner.conf.example config/scope.conf.example config/discovery.conf.example \
  tests/fixtures/rules/fixture.rules tests/fixtures/rules/context.rules \
  tests/fixtures/rules/derived.rules tests/fixtures/config/scope.conf; do
  records_reset_diagnostics
  schema=''
  case $f in
    tests/fixtures/rules/fixture.rules | tests/fixtures/rules/context.rules) schema=pattern-rule ;;
    tests/fixtures/rules/derived.rules) schema=derived ;;
    tests/fixtures/config/scope.conf) schema=scope-target ;;
  esac
  if records_load "$ROOT/$f" "$schema" shipped >/dev/null 2>&1 \
    && records_validate shipped >/dev/null 2>&1; then
    _t_ok "$f parses and validates"
  else
    _t_no "$f parses and validates" "$(diags)"
  fi
done

t_case 'config/discovery.conf.example resolves to the discovery-input schema, by path, not by luck'
assert_eq 'discovery-input' "$(records_schema_for_path config/discovery.conf.example)" \
  'the §9 path table maps the .example file to the same schema as the real config/discovery.conf - FAILS if a future path-table edit stops stripping the .example suffix, which would make the "it parses" case above pass under a different, silently-wrong schema'
records_load "$ROOT/config/discovery.conf.example" '' discovery_ex >/dev/null 2>&1
assert_eq 1 "$(records_count discovery_ex)" 'the shipped example is exactly one worked record, matching every other config/*.example file'
assert_eq 'example-target' "$(records_id discovery_ex 0)" 'its id names the same placeholder target config/scope.conf.example uses'
assert_ne '' "$(records_field_or discovery_ex 0 openapi-path '')" 'openapi-path is set'
assert_ne '' "$(records_field_or discovery_ex 0 graphql-schema-path '')" 'graphql-schema-path is set'
assert_ne '' "$(records_field_or discovery_ex 0 postman-path '')" 'postman-path is set'
assert_ne '' "$(records_field_or discovery_ex 0 har-path '')" 'har-path is set'
assert_eq '3' "$(records_field_or discovery_ex 0 crawl-depth '')" 'crawl-depth is set'
assert_contains "$(records_list discovery_ex 0 include-path)" '/api/**' 'include-path is set (repeatable)'
assert_contains "$(records_list discovery_ex 0 exclude-path)" '/admin/**' 'exclude-path is set (repeatable)'
# A grep for the bare words `base-url`/`extra-host` would also match this
# file's own explanatory prose, which discusses them BY NAME to say they are
# absent; the real question is whether either is a RECORD KEY (line-anchored,
# as rules/RULE-FORMAT.md requires - §8.2), never whether the word appears.
if grep -qE '^(base-url|extra-host):' "$ROOT/config/discovery.conf.example"; then
  _t_no 'no scope-target host anywhere in this file' \
    'found a base-url or extra-host record - FAILS if a future edit adds a base-url/host shortcut here, which would give discovery.conf a second, undocumented way to name a target host outside config/scope.conf'
else
  _t_ok 'no scope-target host anywhere in this file (no base-url/extra-host record key)'
fi

t_case 'the §10 context directive round-trips through the parser'
records_load "$ROOT/tests/fixtures/rules/context.rules" pattern-rule ctx >/dev/null 2>&1
assert_eq '(SafeLoader|CSafeLoader|BaseLoader|yaml\.safe_load)' "$(records_field ctx 0 context-deny)" \
  'context-deny is an ordinary field, never a magic comment (§10, tension 3)'
assert_eq 2 "$(records_field ctx 0 context-window)" 'context-window is read as data'

t_summary records
