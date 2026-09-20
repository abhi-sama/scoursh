# Step 6 (Cloud / AWS) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 6 - `docs/DESIGN.md` §13's "`regions.sh` iteration -> live read-only checks
(§8.1 catalog) + the read-only lint -> `posture/` checks" - can be picked up as a clean sequence of
small, independently reviewable tickets the moment its blockers clear, instead of being re-derived from
`docs/DESIGN.md` §8 from scratch by whoever picks it up first, mirroring `docs/STEP5-DAST-PLAN.md` for
step 5.

## Status: complete for the live-checks half; `posture/` is the one thing still open

**Step 6 is done except for the `posture/` phase.** CLOUD-01 through CLOUD-04 (the `lib/awscli.sh`
hardening, `modules/cloud/aws/regions.sh` account/region iteration including `--assume-role`, the
read-only-verb lint's remaining scope, and `modules/cloud/aws/run.sh`'s `scan_dispatch cloud` entry
point) have landed, and so has every one of CLOUD-05 through CLOUD-34: all 30 `docs/DESIGN.md` §8.1
AWS service scripts (`modules/cloud/aws/live/*.sh`, one per service - iam, ec2, s3, rds, kms, lambda,
ecs, cloudfront, route53, secretsmanager, sns, sqs, cloudtrail, eks, guardduty, inspector, macie,
config, cognito, apigw, appsync, dynamodb, opensearch, redshift, efs, backup, acm, ecr, elb, ssm),
totalling 112 checks, CIS AWS Foundations Benchmark v3.0.0 and OWASP mapped, each with its own
`tests/suites/cloud-*.sh` suite. `scan.sh cloud --live` resolves the account(s) and region(s) and runs
every landed service against them today; it is not a dispatch that finds nothing to run.

Only the `posture/` phase remains: POSTURE-01 (`config/posture.conf`/`.example`, the operator-authored
expected-control baseline schema) has landed, but POSTURE-02 (`modules/cloud/posture/sso.sh`),
POSTURE-03 (`edge.sh`) and POSTURE-04 (`session.sh`) have not - `modules/cloud/posture/` does not exist
on disk - so a posture-phase run today is a declared skip. `ROADMAP.md`'s "Step 6" entry and
`AGENTS.md`'s generated module-status block are the always-current mirrors of this paragraph; if either
ever disagrees with this file, trust them and fix this file's wording rather than the other way round.

**The build order (§13) is strictly sequential, and every step through step 10 is now complete on
`dev`** (`main` is the release branch; work lands on `dev` first and reaches `main` in batches - both
exist on the remote) - see `ROADMAP.md` for the current, terse per-step summary.

Whoever picks up POSTURE-02 through POSTURE-04 should update this "Status" section, and the two
build-order sections named in "Doc-update process" below, in the same change.

## `lib/awscli.sh`'s read-only lint has already shipped as a no-op stub - do not re-plan its matching logic

`tests/lint-aws-readonly.sh` already exists on `dev`, landed at §13 step 1
(commit `b25cd26`), and already implements all four `docs/FOUNDATION.md` tension 23 checks: every bare
`aws` invocation outside `lib/awscli.sh` is a failure; every `aws_ro` call's operation argument is
checked against the frozen read-only prefix regex; a variable operation is permitted only from a
`readonly` array of literals in the same file; and an `tests/aws-readonly-allow.txt` entry that no
longer appears in the code is a failure.
Its header dated from §13 step 1 and used to say that `lib/awscli.sh` and the live scripts both arrived
at the start of §13 step 6, so nothing existed for the lint to examine yet.
Only half of that was still true, and the header has since been corrected in the file itself.
`tests/aws-readonly-allow.txt` itself does not exist yet either; the lint prints a note that it is
"seeded at §13 step 6".

**`lib/awscli.sh` has since landed, ahead of step 6.**
A later credential-less pass (no AWS account was available, so it advanced the part of step 6 that needs
none - see `AGENTS.md`, "AWS module: what exists ahead of step 6") shipped the `aws_ro` chokepoint
itself, with its runtime prefix guard, its refusal of `--cli-input-json`/`--cli-input-yaml`/`--output`,
and finding F17 closed by using `AWS_PAGER=''` rather than the CLI-v2-only `--no-cli-pager`.
It also fixed three real defects in the lint itself, found while proving it fails on a planted mutating
call, and added `tests/suites/aws-lint.sh` as the lint's own meta-test - which is why the lint now takes
an optional scan-root and allow-file override that only that suite uses.
The lint nevertheless still passes over an empty set of call sites, because it skips `lib/awscli.sh` by
name (the one file where a bare `aws` invocation is legitimate) and no `aws/live/*.sh` script exists: it
is the live scripts that are missing, not the chokepoint.
`tests/aws-readonly-allow.txt` really is still absent, and deliberately so - seeding it before any code
calls `sts assume-role` would trip the lint's own check 4.

So the "standalone ticket for the read-only-verb CI lint" this plan's acceptance criteria require
(CLOUD-03 below) is **not** "write the lint" - that already happened - and it is no longer "land the
`aws_ro` chokepoint for the lint to have something real to examine" either, since that has happened too.
What is left of it is: seed `tests/aws-readonly-allow.txt` with the two entries tension 23 names
(`sts assume-role`, `sts get-caller-identity`), add the negative-fixture test tension 23's own
"Consequence for the build" paragraph calls for - a script with a mutating `aws_ro` call, asserted to
fail **both** the lint and `aws_ro`'s runtime guard (exit `3`) - and re-verify checks 1 to 3 against the
first real `aws_ro` call sites once `aws/live/*.sh` scripts start landing.
Whoever picks up CLOUD-03 should read `tests/lint-aws-readonly.sh` itself before writing anything, the
same way `docs/STEP5-DAST-PLAN.md` told DAST-01's implementer to read `lib/http.sh` before touching it.

## `docs/DESIGN.md` §8.2 (AWS IaC) is step 4's, not this plan's

`docs/DESIGN.md` §13 step 4 reads "**SCA** ... and **IaC** (cloud + container rules)", and the IaC work
that has landed (`modules/iac/run.sh` + `parse.sh` + all six of its rule packs, above) is exactly that:
a static, offline, pattern-rule-engine parse of `.tf`/CloudFormation files, with no `aws_ro` call and
no dependency on live credentials at all. §8.2 lives under the "8. Module - Cloud / AWS (live + IaC)" heading only
because that is where `docs/DESIGN.md` groups the AWS-flavored content conceptually; §13's own build
order puts IaC in step 4, alongside SCA, because both "reuse the rule engine" and neither needs
`lib/awscli.sh`. This plan is step 6 only: `regions.sh`, the §8.1 live catalog, and `posture/`. It does
not re-list §8.2 IaC work, and no `CLOUD-*` ticket below touches `modules/iac/`.

## Directory layout this plan targets

Per `docs/DESIGN.md` §3's tree (verbatim paths, not renamed here):

```
lib/awscli.sh                  # the aws_ro chokepoint, tension 23 - NOT under modules/
modules/cloud/
  aws/
    run.sh                     # scan_dispatch cloud entry point
    regions.sh                 # enumerate + iterate enabled regions/accounts
    live/                      # one script per service, §8.1 catalog
      checks.rules             # script-check records, coverage-scope: account-region, module CLOUD
  posture/                     # §8.7 expected-control checks
    checks.rules               # script-check records, coverage-scope: scope-key, module POSTURE (§9.5.1)
config/posture.conf(.example)  # §9.6.4 posture expectation schema (frozen, not yet instantiated on disk)
```

`rules/RULE-FORMAT.md` §9.5.1's owning-module map is authoritative and already frozen: `modules/cloud/
posture/` resolves to module `POSTURE`, and `modules/cloud/` (everything else under it, including
`aws/`) resolves to module `CLOUD` - **two different modules**, both nested under one directory. Every
`CLOUD-*` ticket below writes `CLOUD-*` check ids; every `POSTURE-*` ticket writes `POSTURE-*` check ids.
Their `coverage-scope` differs too (`account-region` vs `scope-key`, same table) - this is not a
naming convenience, it is what `docs/FOUNDATION.md` tension 12's "fixed" predicate reads to know which
runs actually covered a finding.

## A note on ticket count vs. the "~20" estimate

This ticket's own acceptance criteria say "~20 live read-only checks" and "one ticket per AWS service ...
each scoped to a single service." `docs/DESIGN.md` §8.1's catalog table has 19 rows, which is where
"~20" comes from - but several rows name more than one actual AWS service sharing one table cell for
brevity (`rds / dynamodb`, `acm / route53`, `secretsmanager / ssm`, `ecr / ecs / eks`, `opensearch /
redshift / efs`, `sns / sqs`, `cloudtrail / config / guardduty`, `inspector / macie`). Two rows are kept
as one ticket each despite the slash because they are genuinely one AWS service: `ec2 / vpc` (VPC
constructs - security groups, subnets, flow logs - are served by the `ec2` CLI namespace, not a separate
one) and `elb / alb` (Classic ELB and ALB/NLB are one AWS product, "Elastic Load Balancing", across two
API generations). `cognito / identity pools`, `lambda / serverless`, `apigw`, and `appsync` already have
their own `docs/DESIGN.md` subsections (§8.3-§8.6) that explicitly name one script each, so those are
kept as one ticket per subsection regardless of how many CLI namespaces they touch internally. Splitting
the remaining genuinely-multi-service rows to satisfy "each scoped to a single service" yields 31
per-service tickets, not ~20; this is stated plainly here rather than silently under- or over-counting
against the AC's estimate.

## Dependency-ordered sub-ticket list

### Tier 0 - shared infrastructure (blocks every ticket below)

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| CLOUD-01 | `lib/awscli.sh` - the `aws_ro` read-only chokepoint (`docs/FOUNDATION.md` tension 23) - **largely landed already; see the Notes** | `lib/core.sh` (`scan_match`, scratch-dir mutex primitives, shipped step 1); `lib/http.sh` as the sibling chokepoint precedent (shipped) | **The chokepoint itself is on `dev` already**, landed out of sequence by the credential-less pass described above: `aws_ro <service> <operation> [args...]` validates `<operation>` against the frozen prefix allowlist (`^(describe\|list\|get\|search\|lookup\|select\|head\|batch-get\|preview\|estimate\|simulate)(-\|$)`) before executing; a non-matching operation aborts with exit `3` (`SCOURSH_EXIT_SCOPE`), logged as a scope violation - same class as an out-of-scope host; `--cli-input-json`/`--cli-input-yaml`/`--output` are refused outright from a caller; and the pin is `AWS_PAGER='' ... --output json` rather than `--no-cli-pager --output json`, because finding F17 measured that `--no-cli-pager` is CLI-v2-only and fails argument parsing on a v1 host before the call is attempted. It is exercised by `tests/suites/awscli.sh` (stub `aws`, no network) and the opt-in `tests/localstack/run.sh`, and has no shipped caller yet. **What remains of this ticket** is the per-`(service, region, account, operation, args)` response cache (§10, tension 16's note) so multiple checks reading the same `describe-*` do not re-fetch, which is not implemented, and seeding `tests/aws-readonly-allow.txt` with `sts assume-role` (needed by CLOUD-02's `--assume-role`) and `sts get-caller-identity` (already covered by the prefix, listed for clarity), per tension 23 item 4 - the file is still deliberately absent. Read `lib/awscli.sh` before writing anything here. |
| CLOUD-02 | `modules/cloud/aws/regions.sh` - multi-region / multi-account iteration | CLOUD-01 | `account get-regions` / EC2 `describe-regions` to enumerate enabled regions; optional `--assume-role ARN` iterates a read-only role across an Org. Every per-service script below is called once per enabled region unless the ticket says the service is global (`iam`, `route53`, `cloudfront`, `s3`'s bucket-list call). Findings cite region + account per §8.1's own requirement (see the per-ticket Notes column below). |
| CLOUD-03 | Finish the read-only-verb CI lint (tension 23) - **the standalone lint ticket this plan's AC requires** | CLOUD-01 | `tests/lint-aws-readonly.sh` already exists and already implements all four tension-23 checks (see the section above) but currently passes over an empty set. This ticket does not write new matching logic, and it no longer waits on the chokepoint either, since `lib/awscli.sh` has landed - the lint skips that one file by name, so the empty set is the still-absent `aws/live/*.sh` call sites. It (a) verifies the lint's checks 1-3 fire correctly against real `aws_ro` call sites, which arrive once CLOUD-05+ start landing, (b) seeds `tests/aws-readonly-allow.txt` (CLOUD-01 does the actual seeding; this ticket verifies check 4 against it), and (c) adds the negative-fixture test tension 23's "Consequence for the build" paragraph requires: a throwaway script calling `aws_ro ec2 create-security-group` (or similar), asserted to fail **both** the lint and `aws_ro`'s own runtime guard. Kept as its own ticket per this plan's AC, sequenced right after CLOUD-01 so there is something real to lint. |
| CLOUD-04 | `modules/cloud/aws/run.sh` - `scan_dispatch cloud` entry point | CLOUD-01, CLOUD-02, `lib/checks.sh` registry loader (shipped, step 2) | Mirrors `modules/sast/run.sh`/`modules/dast/run.sh`'s split (the latter shipped as `docs/STEP5-DAST-PLAN.md` DAST-02): resolves `--regions`/`--assume-role`, loads `modules/cloud/aws/live/checks.rules` via `checks_registry_load cloud cloud`, calls CLOUD-02 for the region/account list, then invokes each `aws/live/*.sh` script below in any order (they are peers). Owns writing the `account-region` coverage cells `rules/RULE-FORMAT.md` §9.5.1 defines for module `CLOUD`, and tolerates zero live scripts existing yet, the same way SAST's dispatch was a no-op before 3a. |

### Tier 1 - identity, storage & key management (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-05 | `aws/live/s3.sh` | `s3` / `s3api` | Public ACL/policy, no default encryption, block-public-access off, no versioning/logging, `get` open to all principals. Bucket listing is a global call; per-bucket checks still cite the bucket's actual region. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-06 | `aws/live/iam.sh` | `iam` | Root MFA, root access keys, `*:*` policies, wildcard/`*` trust policies, cross-account trust without `ExternalId`, unused/old keys & roles, no password policy, no permission boundaries, IAM Access Analyzer findings, inline-vs-managed sprawl. Global service; findings carry `region: global`. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-07 | `aws/live/kms.sh` | `kms` | Key rotation off, overly-permissive key policies. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-08 | `aws/live/secretsmanager.sh` | `secretsmanager` | Secrets without rotation, over-broad resource policies. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-09 | `aws/live/ssm.sh` | `ssm` | `String` parameters where `SecureString` is expected, over-broad resource policies. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-10 | `aws/live/acm.sh` | `acm` | Certificate nearing expiry. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-11 | `aws/live/route53.sh` | `route53` | Dangling DNS records (subdomain-takeover risk). Global service; `region: global`. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-12 | `aws/live/backup.sh` | `backup` | No backup plan covering a critical resource (cross-references findings from CLOUD-05/13/14). Findings must cite ARN, region, account id, CIS control id. |

Every per-service ticket above and below states the same requirement inline in its own Notes column so a
reviewer never has to chase a cross-reference: **findings must cite the resource ARN, region, account id,
and CIS control id**, per `docs/DESIGN.md` §8.1's closing sentence ("Every finding cites the resource ARN,
region/account, and the CIS control id"). `lib/findings.sh` already ships the `cloud` location schema
(`account_id`, `region`, `resource_key`, `sub_key`, shipped step 1) that `resource_key` is meant to hold
the ARN in; the `cis` field is an existing optional/repeatable field on every finding record
(`rules/RULE-FORMAT.md` §9.2). No schema change is needed - each script just has to populate what already
exists.

### Tier 2 - compute & networking (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-13 | `aws/live/ec2.sh` | `ec2` (covers VPC - see counting note above) | Security groups open `0.0.0.0/0` on 22/3389/db ports, default SG in use, public AMIs, public EBS snapshots, unencrypted EBS, IMDSv2 not enforced, VPC flow logs off. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-14 | `aws/live/elb.sh` | `elb` + `elbv2` (Classic ELB and ALB/NLB, one product - see counting note) | HTTP listener without redirect, weak TLS policy, no access logs. Findings must cite ARN, region, account id, CIS control id. |

### Tier 3 - data stores (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-15 | `aws/live/rds.sh` | `rds` | Public accessibility, no encryption at rest, no backups/PITR, public snapshots. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-16 | `aws/live/dynamodb.sh` | `dynamodb` | Public accessibility (VPC endpoint policy), no encryption at rest, no backups/PITR. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-17 | `aws/live/opensearch.sh` | `opensearch` | Public access, no encryption at rest/in transit. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-18 | `aws/live/redshift.sh` | `redshift` | Public access, no encryption at rest/in transit. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-19 | `aws/live/efs.sh` | `efs` | Public access, no encryption at rest/in transit. Findings must cite ARN, region, account id, CIS control id. |

### Tier 4 - app / serverless / API surface (peers; §8.3-§8.6 already give each its own design subsection)

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| CLOUD-20 | `aws/live/cognito.sh` (§8.3) | CLOUD-01/02/04 | User-pool password policy/MFA/advanced-security/`PreventUserExistenceErrors`/self-registration/account-recovery checks; app-client auth-flow/OAuth/callback-URL/token-lifetime/writable-attribute checks; identity-pool `AllowUnauthenticatedIdentities` (inspect the unauth role for over-permissiveness as its own high-severity finding, not a note), `AllowClassicFlow`, unauth `GetCredentialsForIdentity`. Uses `cognito-idp` + `cognito-identity`, both covered by one script per §8.3's own text. Prefer config-derived detection of user-enumeration/self-signup over live probing, exactly as §8.3's closing paragraph says. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-21 | `aws/live/lambda.sh` (§8.6) | CLOUD-01/02/04 | Over-permissive execution role (wildcard actions/resources or sensitive-service grants), public function URL (`AuthType: NONE`) or `*`-principal resource policy, secrets in plaintext/unencrypted env vars. Generic across "AI/agent/bedrock-style" deployments - no product name in the check. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-22 | `aws/live/apigw.sh` (§8.4) | CLOUD-01/02/04 | `get-rest-apis` + `get-resources` for the route list, `get-api-keys` (existence only, never values), per-method authorizer presence -> flag open-auth routes. Also writes `reports/<run>/inventory/endpoints.json` per §8.4/tension 21's inventory-merge contract - `modules/dast/crawl.sh` (DAST-04) has since landed and reads that same file, the "write it, and let a later consumer show up" pattern DAST-04's own ticket used for the reverse direction, now realized in both directions. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-23 | `aws/live/appsync.sh` (§8.5) | CLOUD-01/02/04 | API-key auth in use and key expiry (`list-graphql-apis` -> `list-api-keys`); flag long/far-future-expiry keys and APIs whose default auth is a plain API key rather than IAM/Cognito. Per §8.5's own text, correlate with DAST's `passive/leakage.sh` (`docs/STEP5-DAST-PLAN.md` DAST-10) and `graphql.sh` (DAST-27) at the derived-finding layer (tension 6) - both have since landed, so only this ticket's own script is the remaining unbuilt contributor - a long-lived key present in served JS plus introspection enabled is the schema/content-exposure chain those tickets flag; this is a soft data correlation, not a build dependency on either. Findings must cite ARN, region, account id, CIS control id. |

### Tier 5 - CDN (peer; depends on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-24 | `aws/live/cloudfront.sh` | `cloudfront` | No TLS / weak min protocol, no WAF association, no OAC/OAI (origin exposed), missing logging. Global service; `region: global`. Findings must cite ARN, region, account id, CIS control id. |

### Tier 6 - containers (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-25 | `aws/live/ecr.sh` | `ecr` | Public repos, scan-on-push off, mutable tags. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-26 | `aws/live/ecs.sh` | `ecs` | Task role over-permissive, public cluster/service. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-27 | `aws/live/eks.sh` | `eks` | Pod role over-permissive, public cluster endpoint. Findings must cite ARN, region, account id, CIS control id. |

### Tier 7 - messaging (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-28 | `aws/live/sns.sh` | `sns` | Topic policy allowing `*` principal, unencrypted topic. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-29 | `aws/live/sqs.sh` | `sqs` | Queue policy allowing `*` principal, unencrypted queue. Findings must cite ARN, region, account id, CIS control id. |

### Tier 8 - governance & detection services (peers; all depend on CLOUD-01/02/04)

| # | Ticket | AWS CLI service | Notes |
|---|---|---|---|
| CLOUD-30 | `aws/live/cloudtrail.sh` | `cloudtrail` | Not enabled, not multi-region, no log-file validation. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-31 | `aws/live/config.sh` | `configservice` (AWS Config) | Config disabled / not recording all resource types. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-32 | `aws/live/guardduty.sh` | `guardduty` | GuardDuty disabled. Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-33 | `aws/live/inspector.sh` | `inspector2` | Not enabled (vuln-coverage gap). Findings must cite ARN, region, account id, CIS control id. |
| CLOUD-34 | `aws/live/macie.sh` | `macie2` | Not enabled (sensitive-data-discovery coverage gap). Findings must cite ARN, region, account id, CIS control id. |

That is 4 infrastructure tickets (CLOUD-01..04) plus 30 per-service tickets (CLOUD-05..34) = 34 `CLOUD-*`
tickets end to end, against this ticket's own "~20" estimate - see "A note on ticket count" above for why
the real, single-service count is higher than the table-row estimate.

## Posture / drift tickets (§8.7) - a distinct module, included for completeness

`docs/DESIGN.md` §13 states step 6 as one step covering both the live catalog above **and**
`posture/` checks, and `rules/RULE-FORMAT.md` §9.5.1 already freezes `modules/cloud/posture/` as its own
owning module (`POSTURE`, `coverage-scope: scope-key`) distinct from `CLOUD`. These are not "AWS
services" and are not counted against the AC's "~20 live read-only checks / one ticket per AWS service"
language above; they are listed here so the plan is a complete breakdown of step 6, matching
`docs/STEP5-DAST-PLAN.md`'s precedent of covering every script in its module, not just the ones an AC
happened to enumerate.

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| POSTURE-01 | `config/posture.conf` + `.example` | none (schema is already frozen, `rules/RULE-FORMAT.md` §9.6.4) | Operator-authored expected-control baselines file does not exist on disk yet. This ticket only ships the file and its example, not any check that reads it. |
| POSTURE-02 | `modules/cloud/posture/sso.sh` | POSTURE-01, CLOUD-01 (reads IdP/app-client config, some of it via `aws_ro`) | Federated-SSO signing & encryption present between IdP and app; SSO-enablement gap (operator-declared expected integration to a downstream analytics/BI tool, reported absent if missing). Findings are `info`/`medium`, framed as "expected control not observed," per §8.7's closing paragraph. |
| POSTURE-03 | `modules/cloud/posture/edge.sh` | POSTURE-01, CLOUD-24 (CloudFront) | Edge/WAF IP allowlisting present; geo/embargoed-country restriction present per the configured list; edge TLS/port policy (only 443 served, 80 redirects, HSTS applied at the edge - cross-checks the DAST `transport.sh` ticket, DAST-30, once that lands). |
| POSTURE-04 | `modules/cloud/posture/session.sh` | POSTURE-01, CLOUD-22 (apigw route inventory) | Session-termination capability: heuristic presence of a logout/session-invalidation route in the route inventory CLOUD-22 writes; otherwise flagged for manual confirmation, per §8.7's own heuristic-not-probe framing. |

## Doc-update process

Per `AGENTS.md`'s "Build order and where we are" process rule ("shipping a §13 step updates this
section, and its mirror in `docs/FOUNDATION.md`'s 'Where the build currently stands,' in the same
change"), whoever lands CLOUD-01 (the first real step-6 code) updates both `AGENTS.md`'s "Current
position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section, in the same
change, exactly as every §13 sub-step landing so far has had to. `docs/DESIGN.md` itself stays verbatim
(per this project's documented rule that its wording is load-bearing and preserved as-is) - it is never
the place build-order status is recorded; `AGENTS.md`/`CLAUDE.md` and this section of `docs/FOUNDATION.md`
are.

## Landed tickets

Appended to, one block per landing, rather than edited into the tables above. Step 6's per-service
tickets are dispatched as PARALLEL PRs against one `dev`, so a shared row edited in place is a conflict
for every peer that lands after it - the same argument `modules/cloud/aws/live/checks-cognito.rules`'s
own header makes for not appending its records to the shared `checks.rules`. A conflict here is
resolved by KEEPING BOTH BLOCKS, never by choosing a side.

### CLOUD-20 - `aws/live/cognito.sh` (§8.3)

Ships `modules/cloud/aws/live/cognito_engine.sh` (the pure classifiers, the ARN builders, the IAM
policy reader and the emitter), `modules/cloud/aws/live/cognito.sh` (the pass `cloud_run_service`
sources), `modules/cloud/aws/live/checks-cognito.rules` (24 `CLOUD-COGNITO-*` records) and
`tests/suites/cloud-cognito.sh` with fixtures under `tests/fixtures/aws/cloud-cognito/`. It needed NO
edit to `modules/cloud/aws/engine.sh`: the `'live/cognito.sh:regional'` row has been in
`_CLOUD_SERVICES` since CLOUD-04, so landing the script alone flips the service from `absent` to `ran`.

Eight things about it a later ticket will otherwise rediscover the expensive way.

- **It is the first `regional` service to land, and its cell is `<account>/<region>` rather than the
  `<account>/global` the `s3` row beside it uses.** Both `cognito-idp` and `cognito-identity` are
  regional namespaces, so the pass is sourced once per enabled region, every resource it sees is in the
  region it is enumerating, and the finding's `loc_region` and its `cell` are the same value.
  `s3.sh`'s long note about the two deliberately DIFFERING is specific to a global namespace and must
  not be copied: a `global` cell here would file every finding in a cell no pass ever covers, so
  tension 12 could never classify one `fixed`.
- **It reaches a THIRD API namespace, `iam`, and only where §8.3 requires it.** That section's
  identity-pool bullet says the unauthenticated role must be inspected "for over-permissiveness ... as
  its own high-severity finding, not a note", so the pass reads that role's inline and managed policies
  through `iam list-role-policies` / `list-attached-role-policies` / `get-role-policy` / `get-policy` /
  `get-policy-version`. All five are admitted by the frozen read-only prefix allowlist and need no
  `tests/aws-readonly-allow.txt` entry. The calls are made ONLY when a pool both allows unauthenticated
  identities and has such a role attached - there is nothing to inspect otherwise, and spending them
  anyway would multiply an estate's IAM API cost by its region count for no finding.
- **The policy classifier answers a NARROW question on purpose, and the narrowing is the honest part.**
  It reports an `Allow` statement with NO `Condition` granting a wildcard action (`*` or `<service>:*`)
  against `Resource: "*"`, plus `NotAction`/`NotResource`, and nothing else. A statement that DOES
  carry a `Condition` is COUNTED and set aside with its own `coverage_reduction`, never judged:
  deciding what a conditioned policy really permits is IAM policy evaluation, which
  `s3_engine.sh`'s own `s3_policy_is_public` header already records as the thing not to reimplement in
  shell - and for an IAM role there is no `get-bucket-policy-status` equivalent to ask instead.
  `Statement` is read in BOTH its array and its single-object forms; the object form is the ordinary
  shape for a hand-written Cognito unauthenticated role, and a walk handling only the array form
  reports the most permissive role in the account as having no statements at all.
- **An app-client finding cites the USER POOL's real ARN with the client id in `loc_sub_key`, and never
  an invented client ARN.** AWS defines no ARN for a Cognito app client - it is addressed by
  `(user pool id, client id)` everywhere in the API - and `loc_resource_key` is a fingerprint component
  (tension 5), so an invented `.../userpool/<pool>/client/<id>` would change every stored baseline the
  day someone noticed and removed it.
- **Nothing is probed.** §8.3's closing paragraph is explicit that config-derived detection of
  user-enumeration and self-signup is preferred, "active probing creates real users and fires
  verification email/SMS", and this pass calls no `SignUp`, no `ForgotPassword`, no `InitiateAuth` and
  no `GetCredentialsForIdentity`. `PreventUserExistenceErrors` is read off the app client (which is
  where the API carries it, despite §8.3 listing it under the user pool as well), and §8.3's fourth
  check group - the unauthenticated API surface - is a single `info` finding derived from
  `AdminCreateUserConfig`, `AccountRecoverySetting` and `AutoVerifiedAttributes`.
- **NOT ONE of the 24 records carries a `cis:` value, and that is an honest absence.** CIS AWS
  Foundations Benchmark v3.0.0 - the version `data/cis-mappings` declares - has NO Cognito section.
  The two tempting neighbours are both misattributions `docs/CIS-MAPPINGS.md` §5 item 5 forbids: 1.8
  governs the IAM ACCOUNT password policy (IAM principals with console access), not an application's
  end-user pool, and 1.10 is MFA for IAM users. This is the same decision this directory's
  `checks.rules` already records from the other side, where three of its seven S3 records cite nothing.
  `tests/suites/cloud-cognito.sh` section G asserts the DURABLE invariant instead: every `cis` value
  authored anywhere under `modules/cloud/` resolves to a row in `data/cis-mappings`.
- **Three id PAIRS exist because severity varies with what was observed** - `MFA_OFF`/`MFA_OPTIONAL`,
  `CLIENT_INSECURE_CALLBACK`/`CLIENT_WILDCARD_CALLBACK`, and
  `IDPOOL_UNAUTH_ROLE_ADMIN`/`IDPOOL_UNAUTH_ROLE_BROAD` - and `severity` is a per-record registry field
  (`rules/RULE-FORMAT.md` §9.5) the suites assert the script and the registry agree on, so a script
  that weighted a finding higher at runtime would put the two into disagreement. The identity-pool
  trio (`UNAUTH_IDENTITIES` medium, `UNAUTH_CREDENTIALS` high, `UNAUTH_ROLE_ADMIN` critical) is the
  same reasoning applied to an escalation ladder rather than a pair.
- **The registry is a per-service `checks-cognito.rules`, not a block appended to the shared
  `checks.rules`.** That file's own header names exactly this condition ("a later service whose peers
  really are in flight simultaneously may add its own `checks-<service>.rules`"), and step 6's
  per-service tickets ARE in flight simultaneously. `rules/RULE-FORMAT.md` §9's path table reserves the
  `checks-` PREFIX repository-wide and at any depth (`docs/FOUNDATION.md` tension 29), so this is a
  §9.5 script-check registry by that row; the SUFFIX spelling `cognito-checks.rules` is still `E070`.

One correction outside its own files: `lib/report.sh`'s cloud coverage-strength note said
`modules/cloud/aws/live/` "ships the S3 service only so far", which this ticket makes false. It now
names both services, and `tests/suites/cloud-s3.sh`'s own E16 assertion moved with it in the same
change - the assertion is on the LIST, so the next service to land finds a failing test rather than a
stale sentence in a shipped report.
