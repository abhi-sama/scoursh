#!/usr/bin/env bash
# tests/lint-shell.sh - the repository shell lints the register mandates.
#
#   docs/FOUNDATION.md tension  4 rules 1, 2 and 5
#   docs/FOUNDATION.md tension  9 handling rules 1 and 3
#   docs/FOUNDATION.md tension 24 (one capability layer)
#   docs/FOUNDATION.md tension 26 / rules/RULE-FORMAT.md §11 (records are data)
#
# SCOPE, stated rather than assumed.  The engine rules (no bare grep/rg, one
# capability layer) apply to the code that produces findings: lib/, modules/ and
# tools/.  They do not apply to tests/, which is not the rule engine: a test
# grepping its own output cannot produce a silent coverage hole in a scan, which
# is the failure tension 4 rule 2 exists to prevent.  The rules that ARE about
# the process rather than the engine - `set +e`, sourcing a record file - apply
# everywhere, tests included.
#
# shellcheck shell=bash
#
# SC2016: diagnostic prose quotes shell syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"

# The lint always scans a real tree relative to its own cwd; in production
# that is $ROOT.  An optional first argument points it at a different tree
# instead - the same convention tests/lint-aws-readonly.sh already uses, so
# tests/suites/dast35-lint.sh (this file's own meta-test, DAST-35) can prove
# each check fails on a planted fixture and passes once it is removed,
# without ever touching the real lib/modules/config/rules trees.  lib/core.sh
# itself is always sourced from the REAL $ROOT above, never the scan target.
SCAN_ROOT=${1:-$ROOT}
cd "$SCAN_ROOT"

FAILED=0
HITS=$SCOURSH_SCRATCH/lint-hits

report() {
  FAILED=1
  printf '%s\n' "$@" >&2
}

# Files the engine rules apply to.  scan.sh is the entry point, not a
# module, but it is the same class of code (it dispatches to the engine and
# owns the exit-code/scratch-dir contract every engine file relies on), so it
# is held to the same discipline rather than living in an unlint-ed root.
engine_files() {
  local dirs=() d
  for d in lib modules tools aws; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f -name '*.sh'
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

all_files() {
  local dirs=() d
  for d in lib modules tools aws tests; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f -name '*.sh'
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

# scan.sh's actual DISPATCH PATH - deliberately narrower than engine_files:
# no tools/, no aws/.  This is tension 27's (docs/FOUNDATION.md) "no wiring"
# check's file set: tools/vendor-engines.sh is itself under tools/, and
# tools/run-in-netns.sh legitimately mentions scan.sh in its own usage text,
# so scoping to lib/, modules/, and scan.sh alone is what lets that check
# assert "nothing scan.sh can reach references tools/vendor-engines.sh"
# without also having to reason about tools/ referencing itself.
dispatch_path_files() {
  local dirs=() d
  for d in lib modules; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f -name '*.sh'
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

# DAST-35: files that MAY carry a config/scope.conf-format scope-target
# record (rules/RULE-FORMAT.md §9.4: id / base-url / extra-host).  Broader
# than engine_files/all_files on purpose: config/ and rules/ are not part of
# either lister, and DAST-35's own scope is explicitly "script, rule or
# config" - docs/STEP5-DAST-PLAN.md's own wording.  tests/ is included
# deliberately too: "any ticket, comment, fixture or doc example that reaches
# for a hosted instance ... has crossed that line" (same doc), so a fixture
# is exactly the kind of file this check exists to cover, not an exemption
# from it.  docs/ is excluded: docs/DESIGN.md §1's target-agnostic rule binds
# scripts, rules and config, not prose, and docs/STEP5-DAST-PLAN.md itself
# names real hosts on purpose, in the cases where the finding is about that
# host (see its own "Safety defaults and authorisation" section).
dast_scope_files() {
  local dirs=() d
  for d in lib modules tools aws tests config rules; do [[ -d $d ]] && dirs+=("$d"); done
  (( ${#dirs[@]} > 0 )) || return 0
  { find "${dirs[@]}" -type f \( -name '*.sh' -o -name '*.rules' -o -name '*.conf' -o -name '*.example' \)
    [[ -f scan.sh ]] && printf '%s\n' scan.sh
  } | LC_ALL=C sort
}

# `check NAME PATTERN FILE-LIST-FN [EXEMPT...]` - fails when PATTERN matches.
check() {
  local name=$1 pattern=$2 lister=$3
  shift 3
  local f rel exempt skip
  local found=0
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    rel=${f#./}
    skip=0
    for exempt in "$@"; do
      [[ $rel == "$exempt" ]] && skip=1
    done
    (( skip )) && continue
    if scan_match "$HITS" -e "$pattern" -- "$rel"; then
      found=1
      report "$name: $rel"
      while IFS= read -r hit; do
        [[ -n $hit ]] && printf '    %s\n' "$hit" >&2
      done <"$HITS"
    fi
  done <<<"$($lister)"
  (( found )) || printf '  ok  %s\n' "$name"
}

printf '== tension 4: the shell contract ==\n'

# Rule 1.  Matched as a COMMAND, not as a substring: the phrase appears in
# lib/core.sh's own comment explaining that it is forbidden.
check 'rule 1: `set +e` is forbidden repository-wide' \
  '^[[:space:]]*set[[:space:]]+\+[a-zA-Z]*e' all_files

# Rule 2.  A bare grep or rg discards the distinction between "no match" (the
# normal case) and "the engine failed", so a broken rule reports clean.
check 'rule 2: no bare grep/rg outside the wrapper' \
  '^[[:space:]]*(grep|rg|egrep|fgrep)[[:space:]]' engine_files lib/core.sh

# Rule 4.  mapfile discards the producer's exit status, which is the very thing
# rule 2 exists to check.
check 'rule 4: no mapfile in the engine' \
  '^[[:space:]]*mapfile[[:space:]]' engine_files

printf '== tension 24: one capability layer ==\n'
for tool in 'sha256sum' 'shasum' 'shred' 'sort[[:space:]]+-V' 'grep[[:space:]]+-P' \
  'readlink[[:space:]]+-f' 'sed[[:space:]]+-i' 'date[[:space:]]+-d' \
  'date[[:space:]]+-Iseconds' 'stat[[:space:]]+-c' 'stat[[:space:]]+-f' \
  'xargs[[:space:]]+-r[[:space:]]' 'mktemp[[:space:]]+-p'; do
  # Matched at COMMAND position, so a tool NAME appearing inside a string - a
  # run.json key, a diagnostic - is not a false positive.
  check "no direct '$tool' outside lib/core.sh" \
    "(^|[;&|(])[[:space:]]*$tool([[:space:]]|\$)" engine_files lib/core.sh
done

printf '== tension 24: empty-array expansion ==\n'
# bash before 4.4 errors on "${arr[@]}" for an empty array under `set -u`, which
# happens the first time a rule matches no files.  The frozen minimum is 4.2, so
# every array expansion is written "${arr[@]+"${arr[@]}"}".
# ${#arr[@]} and ${!arr[@]} are not expansions of the elements and are exempt.
#
# The guarded form CONTAINS the bare form as a substring, so the guarded ones are
# removed before looking for what is left.  A check that flagged its own fix
# would be worse than no check.
check_array_guard() {
  local f rel stripped=$SCOURSH_SCRATCH/lint-stripped found=0
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    rel=${f#./}
    sed -e 's/\${[A-Za-z_][A-Za-z0-9_]*\[@\]+"\${[A-Za-z_][A-Za-z0-9_]*\[@\]}"}//g' \
      -- "$rel" >"$stripped"
    if scan_match "$HITS" -n -e '\$\{[a-zA-Z_][a-zA-Z0-9_]*\[@\]\}' -- "$stripped"; then
      found=1
      report "array expansion is unguarded for bash 4.2: $rel"
      while IFS= read -r hit; do
        [[ -n $hit ]] && printf '    %s\n' "$hit" >&2
      done <"$HITS"
    fi
  done <<<"$(engine_files)"
  (( found )) || printf '  ok  array expansions are guarded for bash 4.2\n'
}
check_array_guard

printf '== tension 26 / §11: record files are data, never code ==\n'
check 'no source/eval of a record file' \
  '^[[:space:]]*(source|\.|eval)[[:space:]]+.*(config/|rules/|data/)' all_files

printf '== tension 9: secrets never reach argv or disk ==\n'
# sha256_of reads stdin only, so a secret never appears in any process's argv.
check 'sha256_of takes no argument' \
  'sha256_of[[:space:]]+[^|)&;]' engine_files

# Evidence is only ever set through finding_set_evidence, which applies redact,
# truncation and control-character stripping in that order.  The other
# target-derived fields are only ever set through finding_set, which redacts
# them.  A direct assignment to any of them bypasses redact() and writes a
# credential into every emitted format.
check 'no direct assignment to a redacted field' \
  '_F\[(evidence|title|remediation|url|logical_fqn|loc_path_template|loc_param_name)\]=' \
  engine_files lib/findings.sh

printf '\n== tension 19: no bypass - a single chokepoint for the network ==\n'
# docs/FOUNDATION.md tension 19 "No bypass": every request in every module
# goes through lib/http.sh's http_request. A bare curl/wget/nc/openssl
# s_client anywhere else is a second, ungated path to the network - exactly
# the bypass the scope gate exists to make impossible. lib/http.sh is where
# the wrapper itself lives (it is expected to invoke curl); the documented
# `modules/dast/passive/tls.sh` exception (docs/FOUNDATION.md tension 19) has
# NOW LANDED (docs/STEP5-DAST-PLAN.md DAST-07) and is exempted below, together
# with the engine file that holds its single `openssl s_client` invocation.
#
# THAT EXEMPTION IS FROM THE TRANSPORT AND FROM NOTHING ELSE, which is what
# keeps it from being a hole rather than an exception.  A raw TLS handshake is
# the measurement a transport-security check makes - it is not an HTTP request
# and curl does not expose the negotiated protocol, the negotiated cipher, or
# the presented certificate - but that module still takes its authorization, its
# PINNED address and its tension-16 limiter/budget/breaker spend from
# lib/http.sh's `http_authorize_raw_connection`, so the scope gate, the
# resolution-pinning deny list and the request budget all still bind it.  The
# host it connects to comes from that already-resolved, gated tuple, never from
# a raw URL and never from a second DNS lookup.  Exempt BY PATH, exactly as
# tools/dast-test-target/scope.conf is in the DAST-35 checks below - never by
# widening the pattern, which would exempt every future file that happened to
# look similar.
#
# tools/vendor-engines.sh (docs/FOUNDATION.md tension 27) is the SECOND and
# LAST documented exception, added by that ticket: it is the one script
# docs/DESIGN.md §9/§13 step 9 names as permitted to touch the network at
# all, and it necessarily calls curl/wget directly to do it - it is never
# called during a scan and is not gated by lib/http.sh's scope allowlist on
# purpose (config/scope.conf authorizes scan TARGETS; a vendored engine's
# own upstream release URL is not one). The check immediately below is what
# keeps this exemption from becoming a real bypass: it fails the build if
# anything under scan.sh's own dispatch path ever wires this script in.
check 'no bypass: no curl/wget/nc/openssl s_client outside lib/http.sh' \
  '(^|[;&|(])[[:space:]]*(curl|wget|nc|ncat|netcat|openssl[[:space:]]+s_client)([[:space:]]|\$)' \
  engine_files lib/http.sh tools/vendor-engines.sh \
  modules/dast/passive/tls.sh modules/dast/passive/tls_engine.sh

printf '\n== DAST-35: no bundled scan target - docs/STEP5-DAST-PLAN.md ==\n'
# "A convenient example target" is a helpful-looking contribution that would
# silently become the built-in demo host, and a scanner with a built-in host
# it will happily point traffic at is a liability, not a convenience.  Three
# checks, in the one-exemption-with-a-stated-reason shape the tension-19
# "no bypass" check above already uses:
#
#   1. config/ ships scope.conf.example only - never a real config/scope.conf.
#   2. scope.conf.example's own base-url names a reserved (RFC 2606 / 6761)
#      example domain, never a host that could be mistaken for a real one.
#   3. no base-url or extra-host record (rules/RULE-FORMAT.md §9.4) anywhere
#      in a shipped script, rule or config file names anything other than a
#      reserved example domain or a reserved/non-routable IP literal (RFC
#      1918 private, RFC 3927 link-local - which covers the 169.254.169.254
#      cloud metadata sentinel - RFC 6598 CGN, RFC 5737 TEST-NET, and the
#      IPv6 equivalents) - i.e. a host that could resolve to a real third
#      party.  Loopback (127.0.0.0/8, ::1) is deliberately NOT in that safe
#      set - see _dast35_ipv4_is_reserved's own comment below for why.
#
# HEURISTIC, stated plainly rather than implied: host extraction below is a
# bounded regex reading of the frozen base-url/extra-host record shape, not a
# general RFC 3986 URL parser, and "reserved" is an allowlist of documented
# non-resolving names and ranges, never a live DNS lookup - an air-gapped
# lint cannot perform one, and must not pretend to.  A host this lint cannot
# parse, or cannot place on the allowlist, is treated as UNSAFE - it fails
# closed rather than silently skipping a line it does not understand.
#
# tools/dast-test-target/scope.conf is exempt BY PATH, not by pattern: its
# 127.0.0.1 target is the one deliberate exception this repository has
# authorized (docs/DAST-TEST-TARGET-AUTHORIZATION.md), it is never installed
# as config/scope.conf, and it is loaded only by the opt-in
# tests/e2e/dast-target-smoke.sh - exactly as its own header comment and that
# authorization record already state.  A pattern exemption ("always allow
# loopback", say) would silently cover a future file nobody authorised;
# a path exemption covers exactly the one file that was.
DAST35_EXEMPT_PATH='tools/dast-test-target/scope.conf'

# `URL -> lowercased host`, RFC 3986-ish: strip scheme, take the authority up
# to the first /?#, drop userinfo up to the LAST @ (rules/RULE-FORMAT.md's own
# host-vs-userinfo split, lib/http.sh's scope_split_authority does the same),
# then a bracketed IPv6 literal or the part before the first remaining colon.
_dast35_host_of_url() {
  local url=$1 rest authority host
  [[ $url =~ ^[A-Za-z][A-Za-z0-9+.-]*:// ]] || return 1
  rest=${url#*://}
  if [[ $rest =~ ^([^/?#]*) ]]; then authority=${BASH_REMATCH[1]}; else authority=$rest; fi
  [[ -n $authority ]] || return 1
  [[ $authority == *@* ]] && authority=${authority##*@}
  if [[ $authority =~ ^\[([^]]+)\] ]]; then
    host=${BASH_REMATCH[1]}
  else
    host=${authority%%:*}
  fi
  [[ -n $host ]] || return 1
  printf '%s' "${host,,}"
}

# `host[:port] -> lowercased host`, the extra-host value shape (no scheme).
_dast35_host_of_hostport() {
  local v=$1 host
  if [[ $v =~ ^\[([^]]+)\] ]]; then
    host=${BASH_REMATCH[1]}
  else
    host=${v%%:*}
  fi
  [[ -n $host ]] || return 1
  printf '%s' "${host,,}"
}

# RFC 2606 / RFC 6761 reserved documentation names: the .example/.test/
# .invalid/.localhost TLDs (any depth), and the three registered
# example.{com,net,org} second-level domains and their subdomains.
_dast35_host_is_reserved_example_domain() {
  local h=$1
  case $h in
    example | *.example) return 0 ;;
    test | *.test) return 0 ;;
    invalid | *.invalid) return 0 ;;
    localhost | *.localhost) return 0 ;;
    example.com | *.example.com) return 0 ;;
    example.net | *.example.net) return 0 ;;
    example.org | *.example.org) return 0 ;;
  esac
  return 1
}

# RFC 1918 private, RFC 3927 link-local (covers 169.254.169.254), RFC 6598
# CGN, RFC 5737 TEST-NET-1/2/3, and unspecified - the same base/bits-table
# shape as lib/http.sh's own _http_ipv4_denied, extended past its runtime deny
# list (which stops at what the SSRF gate must ALWAYS refuse) to cover the
# ranges an operator's real base-url legitimately can use with
# allow-private-addresses: true, none of which are a real third party either.
#
# 127.0.0.0/8 (loopback) is deliberately NOT in this table, even though the
# runtime deny list above treats it identically to the ranges that are: a
# private/link-local/TEST-NET address means nothing without a specific
# network, but 127.0.0.1 means "whatever this operator's own machine happens
# to be running" for every single installation, which is exactly the
# "convenient built-in demo host" risk this ticket exists to close - it is
# why tools/dast-test-target/scope.conf needed its own authorization record
# in the first place.  It is allowed, but ONLY via that one file's path
# exemption below, never generically.
_dast35_ipv4_is_reserved() {
  local ip=$1 a b c d addr
  [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  local IFS=.
  read -r a b c d <<<"$ip"
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  addr=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  # 0.0.0.0/8  169.254.0.0/16  100.64.0.0/10  10.0.0.0/8  172.16.0.0/12
  # 192.168.0.0/16  192.0.2.0/24  198.51.100.0/24  203.0.113.0/24
  local -a bases=(0 0xA9FE0000 0x64400000 0x0A000000 0xAC100000 \
    0xC0A80000 0xC0000200 0xC6336400 0xCB007100)
  local -a bits=(8 16 10 8 12 16 24 24 24)
  local i base mask
  for i in "${!bases[@]}"; do
    base=${bases[i]}
    mask=$(( (0xFFFFFFFF << (32 - bits[i])) & 0xFFFFFFFF ))
    (( (addr & mask) == (base & mask) )) && return 0
  done
  return 1
}

# fe80::/10 link-local (same leading-hextet pattern as lib/http.sh's own
# _http_ipv6_denied), fd00::/8 unique-local, and 2001:db8::/32 (RFC 3849
# documentation).  ::1 (IPv6 loopback) is excluded for the identical reason
# 127.0.0.0/8 is excluded above.
_dast35_ipv6_is_reserved() {
  local tok=${1,,}
  [[ $tok =~ ^fe[89ab][0-9a-f]: ]] && return 0
  [[ $tok =~ ^fd[0-9a-f]{2}: ]] && return 0
  [[ $tok =~ ^2001:0?db8(:|$) ]] && return 0
  return 1
}

_dast35_host_is_safe() {
  local h=$1
  _dast35_host_is_reserved_example_domain "$h" && return 0
  if [[ $h == *:* ]]; then
    _dast35_ipv6_is_reserved "$h"
    return
  fi
  if [[ $h =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    _dast35_ipv4_is_reserved "$h"
    return
  fi
  return 1
}

# Check 1: config/ ships scope.conf.example only.
dast35_check_no_shipped_scope_conf() {
  if [[ -e config/scope.conf ]]; then
    report "config/scope.conf must never be shipped - only config/scope.conf.example may exist (docs/DESIGN.md §1, DAST-35)"
  else
    printf '  ok  config/scope.conf is not shipped\n'
  fi
  if [[ -f config/scope.conf.example ]]; then
    printf '  ok  config/scope.conf.example exists\n'
  else
    report "config/scope.conf.example is missing"
  fi
}
dast35_check_no_shipped_scope_conf

# Check 2: scope.conf.example's own base-url names a reserved example domain.
dast35_check_example_host_reserved() {
  if [[ ! -f config/scope.conf.example ]]; then
    report "config/scope.conf.example: missing, cannot check its base-url (see check 1 above)"
    return
  fi
  if ! scan_match "$HITS" -n -e '^base-url:[[:space:]]' -- config/scope.conf.example; then
    report "config/scope.conf.example: has no base-url: record to check"
    return
  fi
  local hit line value host
  while IFS= read -r hit; do
    [[ -n $hit ]] || continue
    line=${hit%%:*}
    value=${hit#*: }
    host=$(_dast35_host_of_url "$value") || host=''
    if [[ -z $host ]]; then
      report "config/scope.conf.example:$line: base-url '$value' is not a parseable http(s) URL"
      continue
    fi
    if _dast35_host_is_reserved_example_domain "$host"; then
      printf '  ok  config/scope.conf.example:%s base-url names a reserved example domain (%s)\n' "$line" "$host"
    else
      report "config/scope.conf.example:$line: base-url names '$host', which is not an RFC 2606/6761 reserved example domain (.example/.test/.invalid/.localhost, or example.com/net/org)"
    fi
  done <"$HITS"
  return 0
}
dast35_check_example_host_reserved

# Check 3: no shipped script, rule or config file names a resolvable
# third-party host in a scope-target record.
dast35_check_no_bundled_target() {
  local files f rel found=0
  files=$(dast_scope_files)
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    rel=${f#./}
    [[ $rel == "$DAST35_EXEMPT_PATH" ]] && continue
    local key
    for key in base-url extra-host; do
      if scan_match "$HITS" -n -e "^${key}:[[:space:]]" -- "$rel"; then
        local hit line value host
        while IFS= read -r hit; do
          [[ -n $hit ]] || continue
          line=${hit%%:*}
          value=${hit#*: }
          value=${value%$'\r'}
          if [[ $key == base-url ]]; then
            host=$(_dast35_host_of_url "$value") || host=''
          else
            host=$(_dast35_host_of_hostport "$value") || host=''
          fi
          if [[ -z $host ]]; then
            found=1
            report "$rel:$line: unparseable $key value '$value' - DAST-35 fails closed rather than skip it"
            continue
          fi
          if ! _dast35_host_is_safe "$host"; then
            found=1
            report "$rel:$line: $key names '$host', which is not a reserved example domain or a reserved/non-routable address - no shipped file may name a resolvable third-party scan target (DAST-35)"
          fi
        done <"$HITS"
      fi
    done
  done <<<"$files"
  (( found )) || printf '  ok  no shipped script, rule or config file names a resolvable third-party scan target\n'
}
dast35_check_no_bundled_target

printf '\n== tension 27: tools/vendor-engines.sh is never wired into a scan ==\n'
# docs/FOUNDATION.md tension 27 / docs/ADAPTERS.md §2: tools/vendor-engines.sh
# is the only script permitted to reach the network, and that guarantee is
# only real if nothing scan.sh can reach ever sources, execs, or otherwise
# runs it - a `source tools/vendor-engines.sh` (or `bash`/`sh`/`eval`)
# anywhere under lib/, modules/, or scan.sh would open exactly the second,
# ungated network path the whole quarantine exists to prevent, even though
# the curl/wget calls themselves would still live inside the one exempted
# file.
#
# Matched at COMMAND position with an explicit invocation verb required
# (source/./eval/bash/sh), same discipline as the curl/wget and
# source-a-record-file checks above, and deliberately NOT a bare substring
# match: modules/sca/engine.sh and modules/sca/go_engine.sh already mention
# "tools/vendor-engines.sh" by name in log/remediation prose (tension 25 -
# "refresh data/advisories.db via tools/vendor-engines.sh"), including one
# case where the mention sits right after a literal `(` inside a quoted
# string. A bare substring check fails under its own first real run, on
# code that is correct today; requiring an invocation verb is what tells
# "the file is named in a message" apart from "the file is executed".
check 'no wiring of tools/vendor-engines.sh into the scan-time dispatch path' \
  '(^|[;&|(])[[:space:]]*(source|\.|eval|bash|sh)[[:space:]]+.*vendor-engines\.sh' \
  dispatch_path_files

printf '\n'
if (( FAILED )); then
  printf 'lint-shell: FAILED\n'
  exit 1
fi
printf 'lint-shell: clean\n'
