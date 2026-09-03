#!/usr/bin/env bash
# tests/suites/gate-mutation-proof.sh - automated regression proof for this
# repository's non-bypassable safety gates and classification predicates.
#
# ROOT CAUSE this suite exists to close (the ticket's AC1): commit 9f96252
# ("fix(security): pin AC4's chokepoint regression proof against a masking
# bug") found that tests/suites/http.sh's fatal-path chokepoint case had
# targeted evil.example, a host the stub resolver cannot resolve. With the
# gate's own `die` deliberately removed, execution fell through to a SECOND,
# unrelated `die` in http_request's DNS-resolution step, which failed for
# evil.example and happened to exit with the SAME code (3,
# SCOURSH_EXIT_SCOPE) the gate itself uses - so the "exits 3" and "transport
# never called" assertions kept passing even with the chokepoint deleted.
# The fixture had stopped discriminating pass from fail; the fix retargeted
# it at a resolvable, merely out-of-scope host.
#
# That fix was real and is verified below to still hold - but the fix
# ITSELF was verified only once, by hand: the commit message records
# copying lib/ to a scratch directory, deleting the gate's `die` call, and
# re-running tests/suites/http.sh to confirm 62/64 rather than 64/64. That
# is a genuine regression proof, but it was never captured as code, so
# nothing re-runs it. A later edit anywhere on this call path that
# reintroduces the same SHAPE of bug - a second `die`/return reachable once
# the gate is gone, that happens to agree with the gate's own exit code or
# classification - would have no coverage at all, which is exactly this
# ticket's "gate fixture that stopped discriminating" failure mode, just
# not yet triggered. This suite turns that one-time manual observation into
# a re-runnable one, for the three places in this codebase where "was this
# actually the control that refused, or did something else coincidentally
# agree with it" matters most:
#
#   1. lib/http.sh's http_request fatal chokepoint (docs/FOUNDATION.md
#      tension 19) - the exact case 9f96252 fixed.
#   2. lib/config.sh's config_scope_require (docs/DESIGN.md §7: "this is
#      the single most important safety control; do not make it
#      bypassable") - the DAST gate's other entry point, never itself
#      mutation-tested.
#   3. lib/findings.sh's classify_derived condition (a) (docs/FOUNDATION.md
#      tension 6) - not an authorization gate, but the same failure shape:
#      docs/FOUNDATION.md records that omitting condition (a) makes a
#      dropped composite read `fixed` instead of `unknown`, which is a
#      false "no longer vulnerable" a downstream --fail-on-new gate would
#      trust.
#
# METHOD, the same for all three: copy the library to a scratch directory,
# apply the EXACT textual mutation (delete one `die`/short-circuit the one
# `if`), and assert TWO things:
#
#   (i)  the mutation target line exists verbatim, exactly once, in the
#        REAL source - fails LOUDLY if a later refactor changes its text,
#        rather than silently mutating nothing and reporting a false pass.
#        This is the vacuity this whole ticket is about, applied to the
#        proof itself: a mutation test that can silently stop mutating
#        anything is the same failure mode one level up.
#   (ii) the ORIGINAL and the MUTATED copy produce DIFFERENT, observable
#        outcomes for the identical input - proving the removed line was
#        load-bearing on its own, not merely redundant with some other
#        check already on the same path.
#
# Every probe runs as a REAL SUBPROCESS (`bash "$W/probe_*.sh" ...`), not a
# sourced function call in this process: lib/http.sh, lib/config.sh and
# lib/findings.sh all guard against being sourced twice
# (SCOURSH_HTTP_SOURCED and friends), so re-sourcing a mutated copy after
# the original was already sourced here would silently no-op and prove
# nothing - the same class of vacuity again.
#
# shellcheck shell=bash
#
# SC2016: OLD/NEW mutation literals and assertion prose quote shell syntax
#   (unexpanded $variables) literally, on purpose.
# SC2329: _run_http_probe / _run_config_probe / _run_findings_probe are only
#   ever invoked indirectly, via assert_status's "$@" forwarding.
# shellcheck disable=SC2016,SC2329

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/gate-mutation-proof
rm -rf "$W"
mkdir -p "$W/mut/lib"
cp "$ROOT"/lib/*.sh "$W/mut/lib/"

FIXTURE_HTTP_SCOPE=$ROOT/tests/fixtures/config/http-scope.conf
FIXTURE_SCOPE=$ROOT/tests/fixtures/config/scope.conf

# `_assert_mutation_landed FILE OLD LABEL` - the guard described in the
# header as property (i). Printed as its own named assertion so a future
# drift in the mutated line's exact text is diagnosed here, at the guard,
# rather than showing up as a confusing pass/fail flip three assertions
# later.
_assert_mutation_landed() {
  local file=$1 old=$2 label=$3 n
  n=$(grep -c -F -- "$old" "$file" 2>/dev/null || true)
  assert_eq 1 "$n" \
    "$label: exactly one occurrence of the exact mutated line in the REAL source - fails loudly if a refactor changed its text instead of silently mutating nothing and certifying a stale proof green"
}

# =============================================================================
printf '\n-- mutation 1: lib/http.sh, http_request'"'"'s fatal scope-gate die (the AC4 case 9f96252 fixed) --\n'
# =============================================================================
HTTP_OLD='    die "$SCOURSH_EXIT_SCOPE" "scope gate refused $method $cur: $_HTTP_GATE_REASON"'
HTTP_NEW='    : # MUTATED by gate-mutation-proof.sh: fatal scope-gate die removed'

t_case 'mutation 1 guard'
_assert_mutation_landed "$ROOT/lib/http.sh" "$HTTP_OLD" 'lib/http.sh fatal chokepoint die'

content=$(cat "$W/mut/lib/http.sh")
content=${content/"$HTTP_OLD"/"$HTTP_NEW"}
printf '%s\n' "$content" >"$W/mut/lib/http.sh"

t_case 'mutation 1 applied'
n=$(grep -c -F -- "$HTTP_OLD" "$W/mut/lib/http.sh" 2>/dev/null || true)
assert_eq 0 "$n" 'the scratch copy no longer contains the fatal die call'

cat >"$W/probe_http.sh" <<'PROBE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LIBDIR=$1 FIXTURE=$2 TLOG=$3
# shellcheck source=/dev/null
source "$LIBDIR/http.sh"
_probe_resolve() {
  case $1 in
    api.good.fixture.example) printf '93.184.216.34' ;;
    good.fixture.example) printf '93.184.216.34' ;;
    *) return 1 ;;
  esac
}
SCOURSH_HTTP_RESOLVE=_probe_resolve
: >"$TLOG"
_probe_transport() {
  printf '%s %s\n' "$1" "$3" >>"$TLOG"
  printf '200\n\n'
}
SCOURSH_HTTP_TRANSPORT=_probe_transport
http_scope_load "$FIXTURE"
# api.good.fixture.example: out-of-scope under fixture-good (no
# allow-subdomains: true) but resolvable in the stub above - the exact host
# 9f96252 retargeted the case at, so a removed gate falls through to a
# successful resolve-and-fetch instead of hiding behind an unrelated,
# same-exit-code DNS failure.
http_request GET 'https://api.good.fixture.example/x'
PROBE_EOF

_run_http_probe() {                # _run_http_probe LIBDIR TLOG
  bash "$W/probe_http.sh" "$1" "$FIXTURE_HTTP_SCOPE" "$2"
}

TLOG_ORIG=$W/http-orig-transport.log
t_case 'the UNMUTATED chokepoint refuses the request before any network call'
assert_status 3 \
  'the real lib/http.sh still exits 3 for api.good.fixture.example - the baseline this mutation test compares against; fails if the fixture host itself has drifted out of sync with tests/suites/http.sh' \
  _run_http_probe "$ROOT/lib" "$TLOG_ORIG"
assert_eq '' "$(cat "$TLOG_ORIG" 2>/dev/null || printf '')" \
  'and the transport was never reached'

TLOG_MUT=$W/http-mut-transport.log
t_case 'the MUTATED copy (fatal die removed) reaches the transport instead'
assert_status 0 \
  'with the gate'"'"'s die removed, the identical request now resolves and fetches successfully - proving the die line itself is what refused it, not some other check reachable on the same path' \
  _run_http_probe "$W/mut/lib" "$TLOG_MUT"
assert_ne '' "$(cat "$TLOG_MUT" 2>/dev/null || printf '')" \
  'and the transport WAS reached this time - the observable signature of a removed gate, which is exactly what tests/suites/http.sh'"'"'s "REGRESSION PROOF" comment claims but (until this suite) never re-verified'

# =============================================================================
printf '\n-- mutation 2: lib/config.sh, config_scope_require'"'"'s exit-3 die (docs/DESIGN.md §7) --\n'
# =============================================================================
CONFIG_OLD=$'    || die "$SCOURSH_EXIT_SCOPE" "--target \'$target\' has no entry in $path"'
CONFIG_NEW=$'    || : # MUTATED by gate-mutation-proof.sh: exit-3 scope-violation die removed'

t_case 'mutation 2 guard'
_assert_mutation_landed "$ROOT/lib/config.sh" "$CONFIG_OLD" 'lib/config.sh config_scope_require exit-3 die'

content=$(cat "$W/mut/lib/config.sh")
content=${content/"$CONFIG_OLD"/"$CONFIG_NEW"}
printf '%s\n' "$content" >"$W/mut/lib/config.sh"

t_case 'mutation 2 applied'
n=$(grep -c -F -- "$CONFIG_OLD" "$W/mut/lib/config.sh" 2>/dev/null || true)
assert_eq 0 "$n" 'the scratch copy no longer contains the exit-3 die call'

cat >"$W/probe_config.sh" <<'PROBE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LIBDIR=$1 TARGET=$2 FIXTURE=$3
# shellcheck source=/dev/null
source "$LIBDIR/config.sh"
config_scope_require "$TARGET" "$FIXTURE"
PROBE_EOF

_run_config_probe() {              # _run_config_probe LIBDIR
  bash "$W/probe_config.sh" "$1" no-such-target "$FIXTURE_SCOPE"
}

t_case 'the UNMUTATED gate refuses an unknown --target with exit 3'
assert_status 3 \
  'config_scope_require no-such-target still dies exit 3 against the real lib/config.sh - the baseline this mutation test compares against' \
  _run_config_probe "$ROOT/lib"

t_case 'the MUTATED copy (exit-3 die removed) lets the same --target through'
assert_status 0 \
  'with the die removed, config_scope_require returns 0 for the same unknown target id - proving that die is what refused it and nothing further down records_index_of_id/config_scope_load coincidentally exits 3 in its place' \
  _run_config_probe "$W/mut/lib"

# =============================================================================
printf '\n-- mutation 3: lib/findings.sh, classify_derived condition (a) (docs/FOUNDATION.md tension 6) --\n'
# =============================================================================
# Not an authorization gate, but the identical failure shape: a false
# `fixed` here is exactly the "the control still applies but the tool says
# it does not" outcome a --fail-on-new gate would trust. FOUNDATION.md
# records this as the round-3 defect condition (a) was added to close:
# without it, a dropped composite (derived checks fall outside every
# --intensity tier, tension 15) reads `fixed (chain broken)` with its whole
# chain still open.
FINDINGS_OLD='  if ! _derived_record_selected "$check_id"; then'
FINDINGS_NEW='  if false && ! _derived_record_selected "$check_id"; then'

t_case 'mutation 3 guard'
_assert_mutation_landed "$ROOT/lib/findings.sh" "$FINDINGS_OLD" \
  'lib/findings.sh classify_derived condition (a) check'

content=$(cat "$W/mut/lib/findings.sh")
content=${content/"$FINDINGS_OLD"/"$FINDINGS_NEW"}
printf '%s\n' "$content" >"$W/mut/lib/findings.sh"

t_case 'mutation 3 applied'
n=$(grep -c -F -- "$FINDINGS_NEW" "$W/mut/lib/findings.sh" 2>/dev/null || true)
assert_eq 1 "$n" 'the scratch copy now short-circuits condition (a) unconditionally false'

DERIVED_RULES=$W/derived-fixture.rules
cat >"$DERIVED_RULES" <<'RULES_EOF'
id: COMPOSITE-TEST-CHAIN
kind: derived
title: chain
severity: low
confidence: high
cwe: none
owasp: none
requires: SAST-A-A-01
any-of: SAST-C-C-01
correlate-on: file
tags: derived
remediation: r
RULES_EOF

cat >"$W/probe_findings.sh" <<'PROBE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LIBDIR=$1 RULEFILE=$2
# shellcheck source=/dev/null
source "$LIBDIR/findings.sh"
records_load "$RULEFILE" derived derivedset >/dev/null 2>&1
PS=$SCOURSH_SCRATCH/ps CN=$SCOURSH_SCRATCH/cn CP=$SCOURSH_SCRATCH/cp
printf 'fpA\tSAST-A-A-01\t.\t\nfpC\tSAST-C-C-01\t.\t\n' >"$PS"
printf 'SAST-A-A-01\t.\nSAST-B-B-01\t.\nSAST-C-C-01\t.\n' >"$CN"
: >"$CP"
# SCOURSH_SELECTED_CHECKS deliberately excludes the composite itself: this
# is docs/FOUNDATION.md's "scan.sh all --intensity active drops every
# composite" case, the one condition (a) exists to catch.
SCOURSH_SELECTED_CHECKS='SAST-A-A-01' \
  classify_derived COMPOSITE-TEST-CHAIN . false 'fpA,fpC' usable "$PS" "$CN" "$CP" ''
PROBE_EOF

t_case 'the UNMUTATED classifier reports a dropped composite as unknown, not fixed'
out=$(bash "$W/probe_findings.sh" "$ROOT/lib" "$DERIVED_RULES")
assert_eq unknown "${out%%$'\t'*}" \
  'the real lib/findings.sh still reports unknown when the composite record itself was not selected this run - the baseline this mutation test compares against'
assert_contains "$out" composite-not-selected 'and names condition (a) as the reason'

t_case 'the MUTATED classifier (condition a short-circuited) reports it fixed instead'
out=$(bash "$W/probe_findings.sh" "$W/mut/lib" "$DERIVED_RULES")
assert_eq fixed "${out%%$'\t'*}" \
  'with condition (a) disabled, the SAME inputs now classify the dropped composite fixed (chain broken) - the exact false remediation FOUNDATION.md tension 6 documents, proving condition (a) alone is what prevented it, not some other filter in the same function'

t_summary 'gate-mutation-proof' || FAILED=1
exit "${FAILED:-0}"
