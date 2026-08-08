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

```
tests/fixtures/aws/<check-id>/good.json   # the check must NOT flag this
tests/fixtures/aws/<check-id>/bad.json    # the check MUST flag this
```

`<check-id>` is a short, descriptive slug - it does not have to match a real
`check_id` yet, since no check ids are minted until step 6 assigns them from
the `docs/DESIGN.md` §8.1 catalog. `good.json` and `bad.json` are exactly what
`aws_ro` would have printed: the real `--output json` body for the operation
the check calls, hand-written or recorded from a real (throwaway, sanitised)
account or from LocalStack. Never a real account's actual identifiers,
ARNs, or resource names - fixtures are committed to the repository and are
not secret.

## Using a fixture in a test

```bash
source tests/lib/aws-fixtures.sh
aws_fixture_stub_install "$W/bin"
export PATH="$W/bin:$PATH"
export AWS_FIXTURE_RESPONSE
AWS_FIXTURE_RESPONSE=$(aws_fixture_path example-s3-public-read-acl bad)
# ... call the check function; aws_ro now returns bad.json's contents ...
```

The stub `aws` ignores which service/operation/args it was called with and
always returns the file named by `$AWS_FIXTURE_RESPONSE` - correct for a
single-call posture check, and simple enough to carry no AWS-shaped logic of
its own. A check that makes more than one `aws_ro` call per run (for example,
`list-user-pools` then `describe-user-pool` per pool) will need either a
richer stub or one fixture file per call in sequence; neither exists yet
because no such check does either, and extending the stub is a small, isolated
change when the first one is written.

## What is NOT here

No real check reads any fixture in this directory yet. `example-s3-public-read-acl`
is consumed only by `tests/suites/aws-fixtures.sh`, as a reference
implementation proving the harness works end to end - it is not a shipped
check, is never invoked by `scan.sh` (which does not exist yet either), and
`tests/lint-aws-readonly.sh` never examines it, since that lint only scans
`lib/`, `modules/`, `aws/`, and `tools/`.
