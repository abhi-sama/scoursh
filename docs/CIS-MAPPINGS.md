# `data/cis-mappings` - the CIS control id -> label reference table

This document is normative and self-contained, in the same way `docs/VERSIONS-DB.md` is for
`data/versions.db` and `docs/INVENTORY-FORMAT.md` is for the run inventory.
It defines the file the compliance report's CIS view (`docs/DESIGN.md` §4, COMPLIANCE-04) reads to expand
a finding's `cis` control id into its published short title.

`docs/STEP10-SARIF-PLAN.md`'s COMPLIANCE-03 ticket is what this implements, and the captain's D4 decision
(`docs/STEP10-SARIF-PLAN.md`, that ticket's own row, and the linked plan report) is the binding scope
decision behind every choice recorded here. Read that ticket first if you are changing anything in this
file or in `data/cis-mappings` itself: it is the reason this is a *label* table rather than a source of
ids, and the reason it transcribes titles only, never rationale or audit prose.

## 1. What the file is for, and what it is emphatically not

`rules/RULE-FORMAT.md` §9.1, §9.2 and §9.5 each give a check record an optional, repeatable `cis` field:
"CIS control id, for the compliance report." That field is **authored on the check**, by whoever writes
the `CLOUD-*`/`POSTURE-*` check record - `docs/STEP6-CLOUD-PLAN.md` already relies on this, telling every
per-service ticket that "the `cis` field is an existing optional/repeatable field on every finding
record ... No schema change is needed."

**`data/cis-mappings` is a reference table keyed by control id, mapping to that control's published short
title. It is never consulted to decide what a check's `cis` value should be, and no code path in `lib/`,
`modules/`, or `scan.sh` may treat a lookup against this file as validating, inventing, or supplying a
control id.** A `cis` field with no row in this table is not an error - it degrades visibly (§6) - because
the two facts ("this id is a real CIS control" and "this table has a label for it") are different
questions, and only the second is this file's job.

This mirrors `data/versions.db`'s own precedent exactly: `docs/VERSIONS-DB.md` §3 says "there is
deliberately no CWE, no CVSS vector, and no reference URL in a row" because "a row that carried its own
would be a second, drifting source for the same fact." A `data/cis-mappings` that supplied control ids
would be exactly that failure, applied to the id itself rather than to a secondary fact about it.

## 2. Why the file is a records file, not a TSV

`AGENTS.md`'s frozen-record-format section states the rule this file follows: human-authored files use
the `rules/RULE-FORMAT.md` block-record format; machine-generated files use JSON or the frozen TSV.
`data/cis-mappings` is transcribed by a human from a published benchmark PDF - the same origin
`data/versions.db`'s `banner` namespace has, except that namespace is machine-written by
`tools/vendor-engines.sh advisories banner` once an operator supplies advisory ids, where nothing today
resolves a CIS control id and its title from a machine-readable source (CIS does not publish either as an
API or a bulk export; see §5). So this file takes the schema its authorship demands: `rules/RULE-FORMAT.md`
§9.6.7, a records file at the frozen path `data/cis-mappings` (no extension - see that section for the
schema table).

## 3. The record, field by field

See `rules/RULE-FORMAT.md` §9.6.7 for the authoritative schema (required/optional, cardinality,
multi-line). In summary:

| Field | Value |
|---|---|
| `id` | The CIS control number, verbatim from the benchmark's own dotted-decimal numbering (`1.4`, `2.1.1`, ...). |
| `title` | The control's published short title, verbatim from the cited benchmark and version. |
| `benchmark` | The benchmark's published name. Present only on the first record of the file. |
| `benchmark-version` | The benchmark's published version. Present only on the first record of the file. |
| `format-version` | As `data/owasp-categories.conf`'s own field (§9.6.6): present only on the first record. |

**Why `benchmark`/`benchmark-version` live in the file as data, not only in a header comment**: a `cis`
field value carries no version component of its own, so the only place a reader (human or the report
layer) can learn which benchmark edition a given control number was drawn from is this file. Since CIS
renumbers controls between major benchmark versions (`1.4 control 1.4` under v1.4.0 is a different
requirement from `1.4` under v3.0.0 - the version comparison table in
`https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html` documents
several such renumberings), a table that could not say which version it was transcribed from would
silently misattribute every id in it the day a second version is ever added.

**Why only control ids and short titles are transcribed.** CIS AWS Foundations Benchmark control
identifiers and their short recommendation titles are facts about a published standard. The rationale,
audit procedure, and remediation prose that accompany each control in the benchmark PDF are CIS's
copyrighted text. The schema (§9.6.7) has exactly one value field besides the id - `title` - so a
conformant row cannot carry that prose even by accident.

## 4. What is currently seeded, and what is a stated gap

`data/cis-mappings` ships 34 controls today, drawn from the CIS AWS Foundations Benchmark v3.0.0 numbering
for: Identity and Access Management (section 1), Storage (section 2: S3, EBS, RDS, EFS), Logging
(section 3: CloudTrail, AWS Config, KMS, VPC flow logs), and Networking (section 5: security groups,
network ACLs, the default security group, IMDSv2). That set was chosen because it is exactly what
`docs/STEP10-SARIF-PLAN.md`'s D2 v1 service scope (S3, IAM, EC2/VPC) plus the logging controls those
services' own checks cite will need `cis:` values for as `CLOUD-*` checks are written.

**Section 4 of the benchmark (the CloudWatch metric-filter-and-alarm monitoring controls) is deliberately
NOT transcribed.** AWS Security Hub's own public CIS v3.0.0 control mapping - the source this seed set was
cross-referenced against - marks every one of those controls "Not supported - manual check" for v3.0.0
and does not publish their v3.0.0 control numbers, so this file cannot cite them accurately without the
actual benchmark PDF in hand. This is a real, stated gap: a check that someday wants to cite a Section 4
control needs that number added here first, via §5 below, not guessed.

Beyond Section 4, this is a **seed, not the whole benchmark** - `docs/DESIGN.md` §3 uses the identical
phrase for the AWS service catalog, for the identical reason: a table that will grow as later `CLOUD-*`
and `POSTURE-*` tickets need more `cis:` values is a seed, and "not every control in the benchmark has a
row yet" is not a defect in this ticket, it is the intended shape.

## 5. How the table is refreshed, and by whom

**A list nobody can refresh becomes wrong quietly, so the refresh path is part of the format** - the
identical opening line `docs/VERSIONS-DB.md` §5 uses for `data/versions.db`'s `banner` namespace, and for
the identical reason.

The refresh here is a **human, hand-transcription action**, not a script. Unlike `data/versions.db`'s
`banner` namespace (populated by `tools/vendor-engines.sh advisories banner` from OSV.dev, a machine-
readable source), CIS does not publish its benchmark control ids and titles through any API or bulk
export - the only source is the benchmark PDF itself, which requires (free) registration at
<https://www.cisecurity.org/benchmark/amazon_web_services> to obtain. There is therefore no importer
script for this file, by design, and none should be added that scrapes or reconstructs the PDF's content:
that would risk reproducing more than the id and title, and it would put the network access CIS's
distribution terms require behind a script this project's own no-egress posture (`AGENTS.md`, "the
no-egress rule") would otherwise treat as a scan-time dependency. `tools/vendor-engines.sh` is reserved
for machine-readable sources; this table is not one.

**To add or correct a control:**

1. Obtain the CIS AWS Foundations Benchmark v3.0.0 PDF from CIS (see above). Confirm you are reading
   v3.0.0 specifically - CIS renumbers controls between versions (§3).
2. For each control to add, copy exactly two facts: the control number (verbatim, dotted-decimal) and its
   short recommendation title (the one-line heading, never the "Rationale", "Audit", "Remediation", or
   "References" prose beneath it).
3. Add one record to `data/cis-mappings`, in the shape §3 above documents, keeping the file sorted by
   `id` under `LC_ALL=C` for reviewability (not enforced by the parser, which does not require sorted
   input, but kept as a convention here the way `data/owasp-categories.conf` keeps its ids in benchmark
   order).
4. Do not touch `benchmark`/`benchmark-version`/`format-version` on any record but the first, and do not
   add them to a later record - they are meaningful only there (§3).
5. If you are transcribing a **different** benchmark version, do not edit this file in place: open a new
   ticket. `data/cis-mappings` names one benchmark version project-wide (every `cis:` value in the tree is
   authored against it), and switching versions silently would misattribute every finding that already
   cites a v3.0.0-numbered id.
6. Run `bash tests/run-tests.sh records`, `bash tests/run-tests.sh lint-rules`, and
   `bash tests/run-tests.sh report` (which exercises the lookup functions, §7) to confirm the file still
   parses, every id is still unique, and the loader still resolves the new row.

## 6. What a missing, incomplete, or unrecognised entry does

Never an error, always a recorded reduction (`docs/DESIGN.md` §15), mirroring `data/versions.db`'s own
table in `docs/VERSIONS-DB.md` §6:

| State | Behaviour |
|---|---|
| `data/cis-mappings` absent or unreadable | The lookup functions (`lib/report.sh`) return with an empty table loaded; every `cis` id degrades to the bare-id case below. This ticket lands the file, so the shipped tree never has this file absent; a fixture harness pointing elsewhere can still exercise it. |
| a `cis` id with no row in the table | Degrades visibly: the bare id plus a fixed, recorded reason - never a blank, never an invented title - exactly as an unrecognised `owasp` id does (§9.6.6, `docs/VERSIONS-DB.md`'s "a stale list produces false negatives, not false positives" principle applied to labels rather than versions). |
| a `cis` id that IS in the table | Expands to its published short title, alongside the benchmark name and version this file carries. |

## 7. What this ticket lands, and what it does not

**This ticket (COMPLIANCE-03) landed the format (`rules/RULE-FORMAT.md` §9.6.7), the vendored table
(`data/cis-mappings`), and the id -> label loader/lookup functions (`lib/report.sh`:
`cis_mappings_load`, `cis_control_label`, `cis_control_known`, `cis_benchmark_name`,
`cis_benchmark_version`). It rendered nothing at the time**: no CIS section existed in `report.md` or
`report.html` yet, and nothing in `lib/report.sh`'s `report_all`/`report_md`/`report_html` called any
of these functions. **COMPLIANCE-04 has since landed and closes that gap** - `_md_cis_compliance`/
`_html_cis_compliance` (`lib/report.sh` section 1c) now call every function this ticket lands, wired
into `report_md`/`report_html` right after their OWASP siblings - see `docs/STEP10-SARIF-PLAN.md`'s own
COMPLIANCE-03/COMPLIANCE-04 rows for the full account. Landing the table ahead of that, back when step 6
had not yet shipped a single `cis`-carrying check, meant every `CLOUD-*` and `POSTURE-*` ticket written
from then on had a table to check its own `cis:` values against as it was written, rather than after.
