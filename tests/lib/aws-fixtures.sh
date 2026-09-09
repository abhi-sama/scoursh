#!/usr/bin/env bash
# tests/lib/aws-fixtures.sh - the fixture harness for AWS posture checks
# (docs/DESIGN.md §8.1's read-only check catalog, docs/FOUNDATION.md
# tension 23's chokepoint).
#
# The catalog at §8.1 is large and none of it is built yet - modules/cloud/aws
# lands at §13 step 6, and this credential-less pass is explicitly scoped not
# to add any of it (see AGENTS.md, "AWS module: what exists ahead of step 6").
# What this file gives step 6 instead is the PATTERN every check will test
# against: record a real (or hand-written, CIS-shaped) AWS API response once,
# replay it through a stub `aws` binary, and assert the check's finding
# output - known-bad flags, known-good does not - with no network, no
# account, and no dependency on LocalStack having every service implemented.
#
# tests/suites/aws-fixtures.sh exercises this harness against ONE reference
# check, `_example_check_s3_public_read_acl`, defined in that suite file, not
# here and not under modules/ - it is a template proving the mechanism works,
# not a shipped check, and tests/lint-aws-readonly.sh does not even look at
# it, since it never scans tests/.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_AWS_FIXTURES_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_AWS_FIXTURES_SOURCED=1

# `aws_fixture_stub_install BINDIR` - writes a stub `aws` into BINDIR/aws with
# two modes, checked in this order:
#
#   1. ROUTED - $AWS_FIXTURE_ROUTES names a readable route table (see
#      `aws_fixture_route_reset`/`aws_fixture_route_add`/
#      `aws_fixture_route_add_for` below).  The stub looks up the invoked
#      SERVICE and OPERATION (its own $1 $2) in that table and serves the
#      matched file.  A row may additionally be QUALIFIED by one argument
#      value, written `OPERATION@VALUE`, which matches only when VALUE appears
#      verbatim as one of the call's own argv words - that is what lets one
#      run serve a DIFFERENT response per resource (`--bucket a` versus
#      `--bucket b`) for the same operation.  A qualified row always wins over
#      an unqualified one for the same (service, operation), whatever order
#      they were added in, so a table can carry per-resource overrides on top
#      of one default.  A call with no matching row FAILS LOUDLY - a distinct
#      exit code and a stderr message naming the unmatched pair - rather than
#      silently falling back to some other row's file, which is exactly the
#      defect a multi-call check's own test suite must be able to catch.
#   2. SINGLE-RESPONSE - $AWS_FIXTURE_ROUTES is unset (the default, and the
#      only mode that existed before this stub grew routing).  Every call
#      other than `--version` is served whatever file $AWS_FIXTURE_RESPONSE
#      names.  This is the whole harness a single-call posture check needs,
#      unchanged from before: an existing caller that never sets
#      AWS_FIXTURE_ROUTES sees identical behaviour.
#
# Neither mode inspects the args beyond service/operation: one fixture file is
# one canned response, keeping the harness itself free of any AWS-shaped
# parsing.
aws_fixture_stub_install() {
  local bindir=$1
  mkdir -p "$bindir"
  cat >"$bindir/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  printf 'aws-cli/2.15.0 Python/3.11.6 Linux/6.1.0 exe/x86_64.fixture\n'
  exit 0
fi
if [[ -n ${AWS_FIXTURE_ROUTES:-} ]]; then
  if [[ ! -r $AWS_FIXTURE_ROUTES ]]; then
    printf 'aws-fixture-stub: AWS_FIXTURE_ROUTES is set but unreadable (%s)\n' \
      "$AWS_FIXTURE_ROUTES" >&2
    exit 254
  fi
  svc=${1:-}
  op=${2:-}
  matched=''
  fallback=''
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == '#'* ]] && continue
    rsvc=${line%% *}
    rest=${line#* }
    rop=${rest%% *}
    rpath=${rest#* }
    [[ $rsvc == "$svc" ]] || continue
    if [[ $rop == "$op" ]]; then
      # An unqualified row is remembered but never wins immediately: a
      # qualified row later in the table must be able to override it, and a
      # table is written in whatever order a test finds readable.
      [[ -n $fallback ]] || fallback=$rpath
      continue
    fi
    [[ $rop == "$op"@* ]] || continue
    want=${rop#*@}
    for arg in "$@"; do
      if [[ $arg == "$want" ]]; then
        matched=$rpath
        break
      fi
    done
    [[ -n $matched ]] && break
  done <"$AWS_FIXTURE_ROUTES"
  [[ -n $matched ]] || matched=$fallback
  if [[ -z $matched ]]; then
    printf 'aws-fixture-stub: no route registered for "%s %s" in %s\n' \
      "$svc" "$op" "$AWS_FIXTURE_ROUTES" >&2
    exit 253
  fi
  if [[ ! -r $matched ]]; then
    printf 'aws-fixture-stub: routed fixture for "%s %s" is unreadable (%s)\n' \
      "$svc" "$op" "$matched" >&2
    exit 253
  fi
  # A route whose file is named `*.err` is served as a FAILED call: its
  # contents go to stderr and the stub exits 254, the way the real CLI reports
  # a service error.  That is not a convenience - an AWS check's hardest
  # requirement is that a denied call never renders as a clean resource
  # (lib/awscli.sh section 2), and a stub that can only succeed cannot test
  # that at all.  It also covers the opposite case, which is just as easy to
  # get wrong: `NoSuchBucketPolicy`, `NoSuchPublicAccessBlockConfiguration`
  # and `ServerSideEncryptionConfigurationNotFoundError` are ERRORS that carry
  # a real answer ("there is no policy / no block / no encryption"), so a check
  # that treats every error as a coverage loss silently suppresses its own
  # finding on exactly the resources that have the problem.
  if [[ $matched == *.err ]]; then
    cat -- "$matched" >&2
    exit 254
  fi
  cat -- "$matched"
  exit 0
fi
if [[ -z ${AWS_FIXTURE_RESPONSE:-} || ! -r $AWS_FIXTURE_RESPONSE ]]; then
  printf 'aws-fixture-stub: AWS_FIXTURE_RESPONSE is unset or unreadable (wanted %s)\n' \
    "${AWS_FIXTURE_RESPONSE:-<unset>}" >&2
  exit 254
fi
cat -- "$AWS_FIXTURE_RESPONSE"
STUB
  chmod +x "$bindir/aws"
}

# `aws_fixture_path CHECK_ID KIND [EXT]` -
# tests/fixtures/aws/<check-id>/<kind>.<ext>, EXT defaulting to `json`.
# For a single-call check KIND is `good` or `bad` (see
# tests/fixtures/aws/README.md); for a routed, multi-call check KIND is the
# operation name a route serves (e.g. `list-buckets`), since the layout is
# identical either way - one file per (check, thing-that-varies).  Resolved
# against the install root (tension 26), never the scan root, since fixtures
# ship with scoursh itself.
#
# EXT exists for exactly one value, `err`: the stub serves a `*.err` route as a
# FAILED call (see aws_fixture_stub_install's routed-mode note), so a fixture
# set can express `AccessDenied` and `NoSuchBucketPolicy` alongside the
# successful responses rather than only the happy path.  It is a parameter
# rather than a second function because the on-disk layout is the same one -
# one file per (check, thing-that-varies) - and a second path builder would be
# a second place for that layout to drift.
aws_fixture_path() {
  printf '%s/tests/fixtures/aws/%s/%s.%s' "$SCOURSH_INSTALL_ROOT" "$1" "$2" "${3:-json}"
}

# `aws_fixture_response_set PATH` - point the stub at a single canned
# response for every call, dropping any active route table and any cached
# copy of the previous response.  This is the original, single-call mode: a
# check that makes exactly one aws_ro call per run needs nothing else.
#
# The stub deliberately does not inspect service/operation/args in this mode
# (see its own note above), so the fixture's identity lives entirely in this
# variable - while lib/awscli.sh's response cache keys on
# sha256(service|region|account|op|args), which is BYTE-IDENTICAL across two
# cases that call the same operation with a different fixture behind it.  Set
# the variable alone and the second case is served the first case's body: a
# known-good fixture is then judged against known-bad bytes and the check
# reports a finding the fixture does not contain.  That is not a defect in
# the cache - in a real run two identical calls genuinely do have one answer,
# which is the whole point of tension 16 - it is a property of a harness whose
# response varies under a fixed key, so the harness is where it is closed, in
# the one place every step-6 check's own suite will inherit it from.
#
# Clearing AWS_FIXTURE_ROUTES here (rather than leaving it to the caller) is
# what keeps the two modes from leaking into each other across test cases:
# a suite that used routing for one case and single-response for the next
# must not have the stub silently keep consulting a stale route table.
#
# The `declare -F` guard is permissive: a caller that has not sourced
# lib/awscli.sh has no cache to clear either.  It is not load-bearing for
# correctness of the clear itself - tests/suites/aws-fixtures.sh's known-good
# case is what measures that, and it is the case that fails without it.
aws_fixture_response_set() {
  AWS_FIXTURE_RESPONSE=$1
  export AWS_FIXTURE_RESPONSE
  unset AWS_FIXTURE_ROUTES 2>/dev/null || true
  if declare -F aws_ro_cache_clear >/dev/null 2>&1; then
    aws_ro_cache_clear
  fi
}

# `aws_fixture_route_reset` - start a fresh, empty route table and point the
# stub at it, dropping any single-response fixture and any cached copy of a
# previous response.  Call this once before `aws_fixture_route_add`-ing the
# routes a multi-call check's test needs.
#
# The table is a fresh file per call (mktemp, never a fixed name) so two test
# cases in the same suite - or two suites sharing $SCOURSH_SCRATCH - never
# read or append to each other's routes.
aws_fixture_route_reset() {
  local dir=$SCOURSH_SCRATCH/aws-fixtures
  mkdir -p "$dir"
  AWS_FIXTURE_ROUTES=$(mktemp "$dir/routes.XXXXXX")
  export AWS_FIXTURE_ROUTES
  unset AWS_FIXTURE_RESPONSE 2>/dev/null || true
  if declare -F aws_ro_cache_clear >/dev/null 2>&1; then
    aws_ro_cache_clear
  fi
}

# `aws_fixture_route_add SERVICE OPERATION PATH` - serve PATH's contents for
# exactly `aws_ro SERVICE OPERATION ...`, added to the table
# `aws_fixture_route_reset` started.  SERVICE and OPERATION are the stub's own
# $1/$2 (see aws_fixture_stub_install) - plain, whitespace-free CLI tokens,
# never operator- or target-controlled input - so a whitespace-separated,
# newline-delimited table is a safe on-disk shape for them; PATH is the rest
# of the line and may itself contain spaces.
#
# A call whose (SERVICE, OPERATION) matches no row the test registered fails
# LOUDLY at the stub (see aws_fixture_stub_install's routed-mode note) rather
# than silently falling back to some other row's file - that failure-loudly
# property is the whole point of routing existing at all, and is what
# tests/suites/aws-fixtures.sh's unmatched-pair case asserts.
aws_fixture_route_add() {
  local svc=$1 op=$2 path=$3
  # The `@` is the qualified-row separator the stub parses, so an operation
  # carrying one would silently register a route that can never match.
  # Refusing it here is what keeps `aws_fixture_route_add_for` the only way to
  # write one - that function appends through `_aws_fixture_route_append`
  # rather than through this one, precisely so this guard can stay strict.
  case $op in
    *@*) printf 'aws_fixture_route_add: OPERATION may not contain "@" (use aws_fixture_route_add_for for a per-argument route)\n' >&2; return 1 ;;
  esac
  _aws_fixture_route_append "$svc" "$op" "$path"
}

_aws_fixture_route_append() {
  local svc=$1 op=$2 path=$3
  if [[ -z ${AWS_FIXTURE_ROUTES:-} ]]; then
    printf 'aws_fixture_route_add: call aws_fixture_route_reset first\n' >&2
    return 1
  fi
  printf '%s %s %s\n' "$svc" "$op" "$path" >>"$AWS_FIXTURE_ROUTES"
}

# `aws_fixture_route_add_for SERVICE OPERATION ARGVALUE PATH` - serve PATH for
# `aws_ro SERVICE OPERATION ...` only when ARGVALUE appears verbatim as one of
# the call's own argv words, falling back to the unqualified
# `aws_fixture_route_add SERVICE OPERATION ...` row (if the table has one) for
# every other call to that operation.
#
# WHY A ONE-ARGUMENT QUALIFIER RATHER THAN A FULL ARGV MATCHER.  Essentially
# every §8.1 cloud check is `list-<things>` followed by the same per-thing
# `get-<property>` call once per thing, and the property that varies between
# two things is exactly what a good/bad fixture pair has to express - a
# public bucket and a hardened bucket examined by ONE run, so that "the check
# fires" and "the check stays quiet" are asserted against the same code path
# in the same process rather than against two runs, either of which could
# have gone inert without the other noticing.  Matching one argv WORD is
# enough for that (`--bucket my-bucket`, `--role-name my-role`,
# `--db-instance-identifier my-db`) and stays a whitespace-free token, so the
# route table keeps its plain, newline-delimited on-disk shape.  A general
# argv matcher would need quoting rules and would encode each check's call
# shape into the harness, which is the AWS-shaped parsing this stub
# deliberately has none of.
#
# The value is matched as a WHOLE argv word, never as a substring: a bucket
# named `logs` must not match a route registered for a bucket named
# `logs-archive`, and a substring test would make the FIRST-registered of two
# such routes swallow the second - a wrong-fixture failure that reads as a
# perfectly ordinary passing test.
aws_fixture_route_add_for() {
  local svc=$1 op=$2 val=$3 path=$4
  case $op in
    *@*) printf 'aws_fixture_route_add_for: OPERATION may not contain "@"\n' >&2; return 1 ;;
  esac
  case $val in
    '' | *[[:space:]]* | *@*)
      printf 'aws_fixture_route_add_for: ARGVALUE must be a non-empty, whitespace-free token without "@" (got: %s)\n' "$val" >&2
      return 1
      ;;
  esac
  _aws_fixture_route_append "$svc" "$op@$val" "$path"
}
