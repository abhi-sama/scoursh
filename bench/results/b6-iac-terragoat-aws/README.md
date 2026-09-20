# B6 IaC leg, part 1 — TerraGoat, AWS slice, hand-labelled

**This is the B6 IaC leg's Terraform half.** Its sibling is
`bench/results/b6-iac-kubernetes-goat/`; the secrets half is
`bench/results/b6-secrets-leaky-repo/`. None of it is published anywhere in
`docs/` — that is ticket B9, deliberately separate, per `bench/README.md`'s
"what must not be published" rules.

## What was run

| | |
|---|---|
| Corpus | `bridgecrewio/terragoat` @ `729f8da62c6a85ce4af5ad3d123de97776d954c4` (Apache-2.0), scoped to `terraform/aws` |
| Ground truth | `bench/labels/terragoat-aws.truth` — **hand-authored for this leg and committed**, with a rationale beside every case |
| Cases | **71**: 33 genuinely misconfigured resources, 38 correctly configured |
| scoursh | `0.1.0-dev+0be15e965f28`, `scan.sh iac --format json`, defaults, **not `--use-engines`** |
| Checkov | `3.3.10`, `checkov -d . -o json --compact --quiet`, default auto-detected frameworks |
| KICS | `2.1.21`, `kics scan -p ROOT -q <installed query library>`, no query filter |
| Trivy | `0.74.0`, `trivy config --skip-check-update`, default compiled-in checks |
| Host | one macOS machine, one run each |

Each run's own `MANIFEST` carries its exact `gate:` line. Raw outputs carry one
mechanical change (`--portable-paths`): the absolute scan-root prefix is
rewritten to `<SCAN_ROOT>` and the `bench/` prefix to `<BENCH>`.

## The ground truth, and why it is the deliverable

TerraGoat ships no machine-readable labels. Its own ground truth is prose plus
Checkov's `CKV_*` check ids, and scoring recall against those would bias the
result toward Checkov — which is why `bench/corpus.lock` carried
`ground-truth: none` for this corpus until this leg, and why an earlier pass
over it could only report a coverage metric rather than real recall/precision.

So the corpus was **labelled by hand**, by reading the Terraform, and the labels
are committed. `bench/labels/terragoat-aws.truth` states the two rules every
call was made under and carries a short rationale for each of the 71 cases.
**No tool's output of any kind was consulted to produce them** (methodology rule
R2) — the one property of that file a reader cannot verify from the file itself,
which is why the rules are written down so every call can be re-derived.

**The unit is the resource**, which is the ticket's own unit: one case per
top-level `resource` / `data` / `provider` / `terraform` block, every block in
the slice, none skipped. A tool flags a case when it reports a finding inside
that block's line range.

**What the unit cannot express, stated because it bounds every number below: a
tool that flags a genuinely-misconfigured resource for the WRONG REASON still
scores a true positive.** Separating "found the missing encryption" from "found
something else in the same block" needs a defect vocabulary shared across
scoursh, Checkov, KICS and Trivy, and no such vocabulary exists — their rule
identifiers do not map onto one another. Inventing a mapping would put an
unauditable dial between the corpus and the result; the resource-level unit has
no dial at all. That is the trade, made deliberately.

## Scope first (§7.2 framing)

**scoursh ships 7 Terraform checks.** Checkov fired 77 distinct rule ids on this
corpus, KICS 67, Trivy 49 — and each of those tools ships several hundred more
that this corpus never triggered. The result below is the gap that ratio
predicts.

| tool | Terraform checks it ships | rule ids that fired here |
|---|---|---|
| scoursh | 7 (`modules/iac/terraform.rules`) | 4 |
| Checkov | several hundred | 77 |
| KICS | several hundred | 67 |
| Trivy | several hundred | 49 |

## The numbers

All findings, loose matching, line granularity, window 0
(`scorecard-all-findings.md` is the full scorecard, `.json` the same data):

| tool | TP | FN | FP | TN | recall | FPR | precision | **Youden J** |
|---|---|---|---|---|---|---|---|---|
| trivy-config | 28 | 5 | 9 | 29 | 0.848 | 0.237 | 0.757 | **+0.611** |
| kics | 32 | 1 | 18 | 20 | 0.970 | 0.474 | 0.640 | **+0.496** |
| checkov | 25 | 8 | 10 | 28 | 0.758 | 0.263 | 0.714 | **+0.495** |
| scoursh-iac | 3 | 30 | 2 | 36 | 0.091 | 0.053 | 0.600 | **+0.038** |

`J = 0.000` is a coin flip. **scoursh detects 3 of the 33 genuinely
misconfigured resources in this slice and sits just above a coin flip.** That is
the largest gap of the three B6 legs and it is not a surprise: 7 checks against
several hundred, on the cloud provider and the file format those several hundred
were built for.

The one number that is not a loss: scoursh's **precision is 0.600 on two false
positives**, against Checkov's 10, Trivy's 9 and KICS's 18. A tool that says
little says it fairly accurately — and both of its false positives are
diagnosable, below.

### Why only the all-findings column

Methodology rule R5 asks for a documented-default column and a maximum-ruleset
column, and for a `--min-severity high` column beside the all-findings one.
**The high+critical column is not produced for this leg, and the reason is a
property of one tool's output rather than a choice.** Checkov Community Edition
ships **no severity at all** — 158 of 158 failed checks on this corpus carry
`"severity": null`, because severity comes from the Prisma Cloud platform and
not from the open-source rule set. `bench/tools/checkov.sh` therefore maps an
absent severity to `medium` as a stated convention, and a high+critical
scorecard built on that would compare Trivy's and KICS's real severities against
a placeholder and report Checkov at zero recall — a fact about Checkov CE's JSON
and not about its detection. Publishing the column would be worse than declaring
why it is absent.

There is likewise one gate configuration per tool rather than two: none of the
four ships an alternate "maximum" rule set the way Semgrep ships `p/default`
versus `p/security-audit`, and `scoursh --use-engines` would make scoursh *wrap*
Trivy (`modules/iac/adapters/trivy/`), which is an integration measurement
wearing a detection table's clothes.

## Two scoursh defects this leg found, both worth filing

**1. `IAC-TF-RDS_PUBLIC-01` fires on a COMMENTED-OUT attribute.** One of
scoursh's two false positives is `neptune.tf:28`, which reads

```
  #publicly_accessible                = true # No longer supported, API returns create error.
```

The pattern engine has no comment awareness anywhere — `AGENTS.md` records that
hazard for rule packs matching their own header comments, and this is the same
defect pointed at a scanned corpus rather than at a rule file. A commented-out
attribute is not configuration, and reporting one as a critical finding is a
false positive an operator cannot act on. Neither Checkov, KICS nor Trivy flags
that block.

**2. `IAC-TF-OPEN_CIDR-01` cannot see a CIDR on a continuation line, so it
misses the corpus's least arguable misconfiguration.** `ec2.tf`'s
`aws_security_group.web-node` opens tcp/22 to the entire internet, written as

```
    cidr_blocks = [
    "0.0.0.0/0"]
```

`rules/RULE-FORMAT.md` §8.2 freezes matching as line-oriented, so no pattern
rule can join those two lines — the same architectural limit
`tests/suites/sast-secrets-forms.sh` pins as its `[[G01]]`-`[[G03]]` controls.
The check's only hit on this corpus is the *egress* rule in `db-app.tf`, where
the CIDR does sit on one line, and that hit is scoursh's other false positive
(see the sensitivity table). So on a corpus containing a textbook
SSH-open-to-the-world security group, this check fires once, on the wrong
resource, and misses the right one.

## Sensitivity of the borderline labels

Six of the 71 calls are genuinely arguable and are marked BORDERLINE in the
label file's own rationale. Re-scoring with all six flipped from clean to
misconfigured:

| tool | recall | FPR | Youden J |
|---|---|---|---|
| checkov | 0.758 → 0.795 | 0.263 → 0.125 | +0.494 → +0.670 |
| kics | 0.970 → 0.974 | 0.474 → 0.375 | +0.496 → +0.599 |
| scoursh-iac | 0.091 → 0.103 | 0.053 → 0.031 | +0.038 → +0.071 |
| trivy-config | 0.848 → 0.846 | 0.237 → 0.125 | +0.612 → +0.721 |

And with only the unrestricted-egress rule flipped — the single call that most
affects scoursh, because it is one of its two false positives:

| tool | recall | FPR | Youden J |
|---|---|---|---|
| checkov | 0.758 → 0.765 | 0.263 → 0.243 | +0.494 → +0.521 |
| kics | 0.970 → 0.971 | 0.474 → 0.459 | +0.496 → +0.511 |
| scoursh-iac | 0.091 → 0.118 | 0.053 → 0.027 | +0.038 → +0.091 |
| trivy-config | 0.848 → 0.853 | 0.237 → 0.216 | +0.612 → +0.637 |

**Every borderline call moves every tool in the same direction and none of them
changes the ranking.** That is the point of publishing the table: a reader who
disagrees with a call can see exactly what it is worth, and it is not worth the
conclusion.

## What this corpus is weak evidence for

**Its false-positive rate rests on a small and unusual denominator.** TerraGoat
is seeded end to end, so 38 of its 71 blocks are "correctly configured" mostly
because they are inert — an alias, a route-table association, a data source.
Genuinely-remediated resources that a tool could plausibly get wrong are rarer:
`aws_s3_bucket.logs` (private, versioned, KMS-encrypted) and
`aws_security_group_rule.ingress` (3306 from the VPC CIDR only) are the two
sharpest, and Trivy and KICS both fail the first.

**Nine of the 33 misconfigured cases are near-identical.** `rds.tf` declares nine
`aws_rds_cluster` blocks that differ only in `backup_retention_period`; all nine
are unencrypted at rest, so all nine are labelled misconfigured, and "detect an
unencrypted RDS cluster" is therefore worth 27% of the recall denominator. The
corpus varied retention on purpose and the resource-level unit cannot express
"fixed for retention, still broken for encryption" — a limitation of the unit,
recorded here rather than worked around.

## How to reproduce

```sh
bench/fetch-corpus.sh terragoat
for t in scoursh-iac checkov kics trivy-config; do
  bench/run-tool.sh --tool "$t" \
    --root bench/corpora/terragoat/terraform/aws --corpus terragoat \
    --out bench/results/b6-iac-terragoat-aws --portable-paths
done
bench/score.sh --truth bench/labels/terragoat-aws.truth \
  --results bench/results/b6-iac-terragoat-aws --match line --format md
```

Only the first line needs the network. Every case's line range can be
re-derived from the corpus by brace-matching each top-level block; the ranges in
the label file were computed that way rather than transcribed.

## Runtime

Recorded as a wall clock over a file count, never as a rate — 17 files is far
too small a corpus for a runtime comparison to mean anything, because scoursh's
cost is ~38 s of fixed startup plus a fraction of a second per file (scout
report §3.3). For the record: scoursh 45 s, KICS 3 s, Checkov 2 s, Trivy 1 s.
**Do not publish that as a ratio** — `bench/README.md`'s rule 4.
