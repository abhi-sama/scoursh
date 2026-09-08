# Roadmap

`scoursh`'s build order is defined in [`docs/DESIGN.md`](docs/DESIGN.md) §13 as ten sequential
steps. Steps do not always land in strict numeric order - anything with no dependency on a blocked
step is pulled forward when it's ready - so "current position" below is a snapshot of what's
actually landed, not a claim that steps finish in order.
The fullest running account lives in [`AGENTS.md`](AGENTS.md)'s "Build order and where we are"
section, and the generated module status block it carries is the mechanically checked part of it.
This file is a shorter, reader-facing summary of the same information, and is hand-maintained
(see [Maintenance note](#maintenance-note-this-file-is-not-generated) at the end).

## Landed

- **Steps 1-2** - core libraries (`lib/records.sh`, `lib/core.sh`, `lib/findings.sh`,
  `lib/report.sh`), the `scan.sh` CLI grammar, and the check-registry/profile filter chain.
- **Step 3 (SAST)** - complete: all 10 planned step-3 artifacts.
  Those 10 are 9 rule packs plus `modules/sast/history.sh`, the git-history scanner, which is a
  script rather than a rule pack.
  (This entry read "8 of 10, 2 rule packs outstanding" until `ldap.rules` and `nosql.rules` landed
  without it being updated - the silent-staleness this file's own maintenance note warns about.
  The generated block in [`README.md`](README.md) reports 10 of 10, outstanding none, and is the
  authority.)
- **Step 4 (SCA + IaC)** - complete: all 6 SCA ecosystems, all 6 IaC rule packs.
  `modules/sca/run.sh` now calls `sast_evaluate_gate` like its SAST and IaC siblings, so
  `scan.sh sca --fail-on` really gates a run.
  It previously exited 0 whatever the severity, and that defect is fixed and pinned by a regression
  test.
- **Step 8 (`--paranoid` / network namespace isolation)** - complete: the connection-observer
  (`--paranoid`) and the Linux network-namespace guarantee (`tools/run-in-netns.sh`) have both
  shipped.
- **Step 9 (optional engine adapters)** - three adapters shipped ahead of schedule: `semgrep` and
  `gitleaks` for `sast`, `trivy config` for `iac`. The advisory-database expansion tooling
  (`tools/vendor-engines.sh advisories ...`) has also landed.
- **Step 5 (DAST)** - complete: every ticket from DAST-01 through DAST-36 has landed (see
  [`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md)'s own status table).
  `scan.sh dast` runs the full engine described in `docs/DESIGN.md` §7 - session acquisition and
  crawling, every passive check, every safe-active and injection check, and the §7.4 tier-5 checks
  (JWT, GraphQL introspection, rate-limiting, object-level authorization, plaintext/mixed-content
  exposure) - subject to `--intensity`/`--authed`/`--i-own-target` gating the design always called for.
  It is no longer a no-op of any kind.
- `lib/http.sh` (the scope-gate chokepoint, normally part of step 5) and `lib/awscli.sh` (the
  read-only AWS wrapper, normally part of step 6) both landed early since neither depends on the
  steps in front of them.
- **`--format` now actually selects output artifacts, and every subcommand has real `--help`.**
  `scan.sh <cmd> --format <fmt>` writes exactly the artifacts `<fmt>` implies; `findings.jsonl` and
  `run.json` are written on every run regardless, as mandatory per-run records rather than
  `--format`-selectable artifacts.
  The no-`--format` default is unchanged (all four selectable formats, same as before).
  `scan.sh <command> --help` now prints that command's own accepted flags (generated from the
  parser's own flag table, so it cannot list a flag the parser would reject) and a plainly-stated
  build status, derived from the same on-disk check `scan_dispatch` itself uses wherever one exists.
- **`--format audit` - a fifth, opt-in format value.** `report_audit` writes `report-audit.html`
  alongside `report.html`, never replacing it: a per-category (sast/sca/iac/dast/cloud) coverage
  report that lists every registered check in exactly one of four states - found something, ran and
  found nothing, did not run (with the recorded reason), or unaccounted - with full not-covered
  detail rather than a count alone, so a registered-but-silent check can never read as "clean."
- **Step 7 (`state/` - persistent coverage tracking) is complete.** STATE-01 through STATE-08 have
  all landed (see [`docs/STEP7-STATE-PLAN.md`](docs/STEP7-STATE-PLAN.md)'s own status table): every
  normal run persists `state/<run-id>.json` and automatically classifies findings
  `new`/`recurring`/`fixed`/`unknown` against the prior run, `scan.sh diff --against DIR` does real
  classification against a named prior run, `config/baseline.json` (or `--baseline FILE`) suppression
  is live, and `--fail-on-new` now really is a carve-out - it gates on `status == new` only when the
  diff was usable, and falls back to every finding otherwise - rather than a synonym for `--fail-on`.
  `report --from DIR` (regenerating reports from a prior run's own findings, distinct from producing
  them during a scan) has since landed too, independent of `state/` (it needs no classification at
  all, only re-emission) - see AGENTS.md's own entry on it.
- **Guided mode is complete.** GUIDE-01 through GUIDE-07 have all landed (see
  [`docs/STEP-GUIDE-PLAN.md`](docs/STEP-GUIDE-PLAN.md)'s own status section): a bare `scan.sh`, or
  `scan.sh <command> --guided`, walks an operator through composing a real command - including the
  DAST target/intensity/affirmation flow - and `--print-command` prints the exact equivalent
  non-interactive invocation, verified byte-identical to what "Run it" actually executes. `cloud` is
  the one surface guided mode refuses outright, since `modules/cloud/` does not exist.

## Not yet started

Ordered by priority, highest first.
With step 5 (DAST) and step 7 (persistent run state) both complete, the compliance report is the top
priority feature, ahead of live cloud scanning.

1. **Step 10 (SARIF output + compliance report)** - the SARIF half is **done**: `--format sarif`
   writes a complete, schema-validated SARIF 2.1.0 document (`report_sarif`, SARIF-01 through
   SARIF-06) - `tool.driver`/`rules[]`/`artifacts[]`/`invocations[]` and a fully-mapped
   `runs[0].results[]` carrying this run's actual findings. The OWASP half of the compliance report is
   **also done** (COMPLIANCE-01/02): `data/owasp-categories.conf` expands every `owasp` id to its
   published Top 10 2021 label, and `report.md`/`report.html` both group findings by category with an
   honest per-category status (assessed-clean, out-of-scope, or filtered out of this run by
   `--profile-scan`/`--intensity`). What remains of step 10 is the CIS half of the compliance report,
   which still has no emitter anywhere in the tree.
   A complete sub-ticket breakdown exists in
   [`docs/STEP10-SARIF-PLAN.md`](docs/STEP10-SARIF-PLAN.md) (tickets SARIF-01 through SARIF-06 and
   COMPLIANCE-01/02, all landed; COMPLIANCE-03/04 not started).
   That plan's own central finding is that this step is three deliverables with three different
   readiness states, not one: the SARIF emitter **has landed**, unblocked from the start by neither
   step 6 nor step 7; the compliance report's OWASP half **has also landed**, likewise unblocked, while
   only its CIS half waits on step 6; and the `--fail-on` CI gate §13 item 10 also names is **already
   shipped in full** and carries no ticket.
   Its position at number 1 here, for what is left of it (the CIS half alone now), is therefore a
   priority choice, not a technical block.
2. **Step 6 (live cloud / CSPM scanning)** - `scan.sh cloud` is a no-op today, with or without
   `--live`.
   There is no `modules/cloud/`, so the dispatch records a `not_yet_built` coverage reduction
   whichever form is used, and all `--live` adds is a check that the `aws` CLI is installed.
   A complete sub-ticket breakdown exists in
   [`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md) (tickets CLOUD-01 through CLOUD-34 plus
   POSTURE-01 through POSTURE-04).
   `docs/STEP6-CLOUD-PLAN.md`'s own build-order gate is now fully cleared too (step 3's tail and all
   of step 5 have both landed); it is placed last here on priority, not on any remaining technical
   block.

Outside that ordering:

- Two derived/composite findings (`COMPOSITE-TOKEN-HIJACK` and its dependents) are intentionally
  not seeded yet. DAST (step 5) now supplies one contributor, but the composite also needs a step 6
  (cloud) contributor that does not exist yet, so it remains unseeded until cloud lands.
- IPv6 / dual-stack routing support for `tools/run-in-netns.sh` was explicitly scoped out of that
  ticket and filed as a separate follow-up.

## Known defects in shipped features

These are not unbuilt steps.
They are features that ship today and are wrong, incomplete, or inert, and each one has to be
scheduled on its own.

- **Flags that were accepted and then ignored.**
  `--authed` used to be one - it no longer is: DAST's `auth.sh`/`crawl.sh` and every authenticated
  check now read it, and `scan.sh` records it as `run.json`'s `authorization.authed` field.
  `--baseline FILE`, `--fail-on-new` and `--jobs N` were three more; all three are now live - see
  "Recently fixed" below.
  (`--format` used to be a fifth: it was parsed and the resolved format list was then discarded, so
  every run wrote the same five artifacts whatever was asked for.  Fixed - see "Landed" above.
  `findings.jsonl` and `run.json` are mandatory per-run records rather than one of the four
  `--format` values, and are written on every run regardless of what `--format` asked for; `sarif`
  selects `report_sarif` like every other value and, as of SARIF-06, writes a complete document -
  see "Recently fixed" below and [`docs/USAGE.md`'s SARIF output section](docs/USAGE.md#sarif-output).)
- **`--paranoid` has a real macOS backend, but no macOS *guarantee*.**
  Of its three connection-observer backends, `ss` and `strace` are Linux-only; `lsof` was added as a
  third, measured-usable backend specifically so `--paranoid` runs on macOS too, and it is a genuine
  detector there, not a refusal.
  What macOS still lacks is `tools/run-in-netns.sh` (step 8's *guarantee* tier, a Linux network
  namespace): on macOS `--paranoid`'s sampling detector is the only egress control available, with no
  stronger mechanism behind it.
  A host with none of the three backends still exits 4 before any module runs.

## Recently fixed

Entries that used to sit under "Known defects" above, kept for a release or two so a reader who knew the
old behaviour can see what replaced it.

- **`--jobs N` was accepted, validated, exported and read by no module.**
  It is documented with a default of 4 and every `sast`/`sca`/`iac` scan was single-worker
  regardless, each module recording a flat `single_worker_no_parallel_scan_yet` coverage_reduction at
  every value of the flag. It is real now: `lib/parallel.sh` is the shared bounded fan-out, `sast`
  and `iac` split the file list through `_sast_walk_parallel` and `sca` splits the manifest list
  through `_sca_scan_parallel`, each worker writing its own finding shard (tension 17). A run at
  `--jobs 4` produces byte-identical findings to the same run at `--jobs 1`, because the merge sorts
  every shard together under `LC_ALL=C` and each worker's `run_record` appends land in a private
  directory the parent folds back in worker order rather than interleaving in `meta/`. The old flat
  reduction is replaced by one that names the resolved value
  (`reason=single_worker jobs=N ...`) or, on a parallel run, a `notes` line naming the worker count.
  A worker that dies exits `5` with an `incomplete_reason` naming `parallel_worker_failed` and
  records no coverage for the cell, rather than letting a half-scanned tree read as a clean report.
  DAST is unchanged and was never part of this defect: `lib/http.sh` reads the same number as an
  in-flight *connection* ceiling, which is a different meaning of it.
- **`--baseline FILE` was parsed and never read; `--fail-on-new` was a tautology.**
  Both needed the step 7 persistent-state work, which has since landed in full
  (`docs/STEP7-STATE-PLAN.md`, STATE-01 through STATE-08). `--baseline FILE` (or the default
  `config/baseline.json`) now really suppresses a matching finding by fingerprint - `suppressed: true`
  plus its reason, never a deletion, and excluded from every count and from `--fail-on`/
  `--fail-on-new`; an explicit path that does not exist is now a real error (`exit 4`) rather than a
  silent no-op. `--fail-on-new` now gates on `status == new` only when this run's diff against the
  prior one was usable, and falls back to every finding when it was not (a first run, a schema
  mismatch, or a `scan_root_id` mismatch), rather than behaving identically to `--fail-on` in every
  case.
- **`--format sarif` wrote a SARIF document with no findings in it.**
  `report_sarif` used to write the document skeleton only - `tool.driver`/`rules[]`/`artifacts[]`/
  `invocations[]` - with `runs[0].results[]` always empty, because the per-finding mapping (SARIF-04)
  had not landed yet.
  SARIF-04 through SARIF-06 (`docs/STEP10-SARIF-PLAN.md`) landed the mapping, the real schema
  validation (against the vendored OASIS SARIF 2.1.0 schema, plus a filesystem-backed check that every
  result's location resolves to a real file), and the operator documentation.
  `report.sarif` now carries this run's actual findings and is safe to point a code-scanning CI step
  at; see [`docs/USAGE.md`'s SARIF output section](docs/USAGE.md#sarif-output).
- **Dependency scanning skipped the scan entirely without an advisory database, and reported that as clean.**
  `data/advisories.db` still does not exist in this repository - the only advisory database in the tree
  is `tests/fixtures/sca/advisories.db`, a test fixture - and populating it is still the operator's job
  (`tools/vendor-engines.sh advisories`, run on a networked box; it takes either a list of OSV ids the
  operator supplies or, since the bulk importer landed, a whole ecosystem at once).
  What changed is that the tool now says so instead of reporting a clean scan.
  `scan.sh sca` with no database exits **4** (`SCOURSH_EXIT_INPUT`, "missing required input" -
  [`docs/FOUNDATION.md`](docs/FOUNDATION.md) tension 14's frozen precedence, no new code and no change
  to the order), writes its full report, and carries a `SCA-COV-NO_ADVISORY_DB-01` finding stating that
  zero dependencies were checked.
  `run.json` records **one** `module=sca reason=no_advisories_db_on_disk ecosystems=<all six>` reduction
  in place of the previous two-from-some-walks-and-nothing-from-the-others, and `checks_run` is no longer
  empty.
  A `scan.sh all` run is unaffected in its exit code, per the same tension's row for a module skipped
  under `all` for absent inputs; it still reports the blind spot.
- **Two SCA coverage roll-ups collided, and one was dropped silently.**
  The `SCA-COV-UNKNOWN_VERSION-01` roll-up carries no ecosystem component in its fingerprint - it names
  no single dependency, so it never could - and the Python, Java and Go paths each used to emit their
  own roll-up rather than joining npm's.
  A project with dependencies in two of those groups therefore produced two findings with an identical
  fingerprint, deduplication dropped one, and the survivor reported one walk's share as if it were the
  total (on a fixture carrying npm, PyPI, Maven and Go gaps, the report said 1 where the truth was 4;
  which walk's count survived depended on the merge sort, not on anything meaningful).
  The four walks now accumulate into one shared table that the module flushes once, so a run emits
  exactly one roll-up and its count is the true total across every ecosystem.
  The fix is at the emission layer on purpose: the fingerprint is byte-for-byte unchanged, so no
  `format_version` bump and no `state/` migration are owed
  ([`rules/RULE-FORMAT.md`](rules/RULE-FORMAT.md) §14 item 3).
  Adding an ecosystem component was weighed and rejected - see
  [`docs/FOUNDATION.md`](docs/FOUNDATION.md) tension 5 for the argument.

## Not currently on the roadmap

Two categories from the broader "types of security scanner" taxonomy are not part of
`docs/DESIGN.md`'s plan at all, not merely unbuilt:

- **Container image scanning** - scanning the layers and installed packages of a *built* Docker
  image (the way Trivy or Grype do). `scoursh` lints Dockerfile and docker-compose *source* as part
  of `iac`, which is a different, narrower thing.
- **Network / host scanning** - servers, open ports, OS patch levels.

If either of these matters to your use case, it's worth raising as an issue rather than assuming
it's simply "next."

## Maintenance note: this file is not generated

`tools/gen-status.sh` regenerates the module status block carried by `AGENTS.md`, `README.md`
and `docs/FOUNDATION.md`, and `tests/lint-status.sh` fails the build when a committed block
differs from a fresh generation.
`ROADMAP.md` is not one of those three targets, so nothing here is checked against the tree.
That makes this the one status surface in the repository that can go stale silently, and it has done
so before.
Read a count here as a claim to verify against the generated block, and correct it in the same change
as the work that invalidated it.
