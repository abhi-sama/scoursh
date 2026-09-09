# AWS posture-check fixtures

This directory holds recorded/synthetic AWS API responses, so a §8.1 posture
check can be unit-tested against known-good and known-bad inputs offline, in
CI, with no AWS account and no LocalStack.

None of §8.1's catalog is built yet - `modules/cloud/aws` lands at
`docs/DESIGN.md` §13 step 6. This directory, and the harness in
`tests/lib/aws-fixtures.sh`, are the credential-less half of that work,
delivered ahead of it so step 6 has a tested pattern to build against rather
than inventing one under time pressure. See `AGENTS.md`, "AWS module: what
exists ahead of step 6".

## Layout

The stub `aws` (`tests/lib/aws-fixtures.sh`) has two modes, and both use the
same on-disk layout - one JSON file per (check, thing-that-varies):

```
tests/fixtures/aws/<check-id>/good.json        # single-call mode: must NOT be flagged
tests/fixtures/aws/<check-id>/bad.json         # single-call mode: MUST be flagged
tests/fixtures/aws/<check-id>/<operation>.json # routed mode: this operation's own response
```

`<check-id>` is a short, descriptive slug - it does not have to match a real
`check_id` yet, since no check ids are minted until step 6 assigns them from
the `docs/DESIGN.md` §8.1 catalog. Every file is exactly what `aws_ro` would
have printed: the real `--output json` body for the operation the check
calls, hand-written or recorded from a real (throwaway, sanitised) account or
from LocalStack. Never a real account's actual identifiers, ARNs, or resource
names - fixtures are committed to the repository and are not secret.

## Using a fixture in a test: single-call mode

For a check that makes exactly one `aws_ro` call per run:

```bash
source tests/lib/aws-fixtures.sh
aws_fixture_stub_install "$W/bin"
export PATH="$W/bin:$PATH"
export AWS_FIXTURE_RESPONSE
AWS_FIXTURE_RESPONSE=$(aws_fixture_path example-s3-public-read-acl bad)
# ... call the check function; aws_ro now returns bad.json's contents ...
```

In this mode the stub ignores which service/operation/args it was called
with and always returns the file named by `$AWS_FIXTURE_RESPONSE`.

## Using a fixture in a test: routed mode (multi-call checks)

**Essentially every real §8.1 check makes more than one `aws_ro` call per
run** - s3 alone is `list-buckets` then, per bucket, `get-bucket-acl` +
`get-bucket-policy-status` + `get-bucket-encryption` + `get-public-access-block`
+ `get-bucket-versioning` + `get-bucket-logging`. The single-response mode
above cannot test that: it has no way to tell one call apart from another, so
every call in the sequence would be served the same file.

`aws_fixture_route_reset` / `aws_fixture_route_add` build a small routing
table that serves a **distinct fixture per `(service, operation)`** pair:

```bash
source tests/lib/aws-fixtures.sh
aws_fixture_stub_install "$W/bin"
export PATH="$W/bin:$PATH"

aws_fixture_route_reset
aws_fixture_route_add s3api list-buckets   "$(aws_fixture_path example-s3-multi-call list-buckets)"
aws_fixture_route_add s3api get-bucket-acl "$(aws_fixture_path example-s3-multi-call get-bucket-acl)"
# ... call the check function; each aws_ro call now gets its OWN operation's
# fixture, in whatever order the check makes them ...
```

### Per-resource routes

Essentially every §8.1 check is `list-<things>` followed by the same
`get-<property>` call once per thing, so the response that has to vary between
two calls is the one addressed at a *resource* - `--bucket a` versus
`--bucket b`. `aws_fixture_route_add_for` adds a route qualified by one argv
value:

```bash
aws_fixture_route_add_for s3api get-bucket-acl my-public-bucket   "$FIX/get-bucket-acl.public.json"
aws_fixture_route_add_for s3api get-bucket-acl my-hardened-bucket "$FIX/get-bucket-acl.hardened.json"
```

A qualified row wins over an unqualified one for the operation, whatever order
they were added in, so a table can carry per-resource overrides on top of one
default. The value is matched as a **whole argv word**, never as a substring,
so a bucket named `logs` cannot swallow a route registered for `logs-archive`.

This is what lets a known-bad and a known-good resource be examined by **one
run**, which matters more than it looks: a check that has gone inert passes
every "stays quiet" assertion ever written, and two separate runs - one
all-bad, one all-good - cannot tell an inert check from a correct one.

### Failure fixtures

A route whose file is named `*.err` is served as a **failed** call: its
contents go to stderr and the stub exits 254, the way the real CLI reports a
service error.

```bash
aws_fixture_route_add_for s3api get-bucket-policy-status my-bucket \
  "$FIX/get-bucket-policy-status.nopolicy.err"
```

Both directions of the honesty contract need this. An `AccessDenied` must never
render as a correctly-configured resource (`lib/awscli.sh` section 2), and a
stub that can only succeed cannot test that at all. The mirror case is just as
easy to get wrong: `NoSuchBucketPolicy`,
`NoSuchPublicAccessBlockConfiguration` and
`ServerSideEncryptionConfigurationNotFoundError` are *errors that carry a real
answer* ("there is no policy / no block / no encryption"), so a check that
treats every error as a coverage loss silently suppresses its own finding on
exactly the resources that have the problem.

An `aws_ro` call whose `(service, operation)` matches no registered route
**fails loudly** - a distinct stub exit code and a diagnostic naming the
unmatched pair in `SCOURSH_AWS_RO_ERROR` - rather than silently falling back
to some other route's file. That is the property a multi-call check's test
most needs: a check that accidentally reused the wrong fixture for its
second call must show up as a test failure, never as a quiet pass.

`aws_fixture_response_set` and `aws_fixture_route_reset` each start their own
mode fresh and clear the other: calling `aws_fixture_response_set` after
`aws_fixture_route_reset` drops the route table and returns to single-response
mode, and vice versa, so the two never leak into each other across test cases
in the same suite. Both also clear `aws_ro`'s response cache (see
`aws_fixture_response_set`'s own header in `tests/lib/aws-fixtures.sh` for why
that clear is required for correctness, not tidiness).

`tests/suites/aws-fixtures.sh`'s "routed mode" section is the worked example,
including the unmatched-pair failure case, against
`tests/fixtures/aws/example-s3-multi-call/{list-buckets,get-bucket-acl}.json`.

## The one real fixture set

`cloud-s3/` is consumed by `tests/suites/cloud-s3.sh`, which drives the real
`modules/cloud/aws/live/s3.sh` through a real `scan.sh cloud --live`
subprocess. It is the worked example for every later service PR, and it is
shaped the way this file recommends: three buckets in one run - one public in
every way the checks can observe, one hardened in every way, and one whose ACL
call is `AccessDenied` - so "the check fires", "the check stays quiet" and "a
denied call is a recorded coverage reduction rather than a clean result" are
all asserted against one code path in one process.

`example-s3-public-read-acl` and `example-s3-multi-call` are consumed only by
`tests/suites/aws-fixtures.sh`, as reference implementations proving the
harness itself works end to end. Neither is a shipped check and neither is
ever invoked by `scan.sh`; `tests/lint-aws-readonly.sh` never examines any of
these files either, since that lint only scans `lib/`, `modules/`, `aws/`, and
`tools/`.
