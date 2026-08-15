# Roadmap

`scoursh`'s build order is defined in [`docs/DESIGN.md`](docs/DESIGN.md) §13 as ten sequential
steps. Steps do not always land in strict numeric order - anything with no dependency on a blocked
step is pulled forward when it's ready - so "current position" below is a snapshot of what's
actually landed, not a claim that steps finish in order.
The fullest running account lives in [`CLAUDE.md`](CLAUDE.md)'s "Build order and where we are"
section, and the generated module status block it carries is the mechanically checked part of it.
This file is a shorter, reader-facing summary of the same information, and is hand-maintained
(see [Maintenance note](#maintenance-note-this-file-is-not-generated) at the end).

## Landed

- **Steps 1-2** - core libraries (`lib/records.sh`, `lib/core.sh`, `lib/findings.sh`,
  `lib/report.sh`), the `scan.sh` CLI grammar, and the check-registry/profile filter chain.
- **Step 3 (SAST)** - 8 of the 10 planned step-3 artifacts.
  Those 10 are 9 rule packs plus `modules/sast/history.sh`, the git-history scanner, which is a
  script rather than a rule pack.
  So the 8 are 7 rule packs on disk plus that scanner, and 2 rule packs are outstanding; see below.
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
- `lib/http.sh` (the scope-gate chokepoint, normally part of step 5) and `lib/awscli.sh` (the
  read-only AWS wrapper, normally part of step 6) both landed early since neither depends on the
  steps in front of them.
- **`--format` now actually selects output artifacts, and every subcommand has real `--help`.**
  `scan.sh <cmd> --format <fmt>` writes exactly the artifacts `<fmt>` implies; `findings.jsonl` and
  `run.json` are written on every run regardless, as mandatory per-run records rather than
  `--format`-selectable artifacts.
  The no-`--format` default is unchanged (all five artifacts, same as before).
  `scan.sh <command> --help` now prints that command's own accepted flags (generated from the
  parser's own flag table, so it cannot list a flag the parser would reject) and a plainly-stated
  build status, derived from the same on-disk check `scan_dispatch` itself uses wherever one exists.

## Not yet started

Ordered by priority, highest first.
The running-endpoint scanner is now the top priority feature, ahead of persistent run state,
SARIF and the compliance report, and live cloud scanning.

1. **Step 5 (DAST)** - `scan.sh dast` currently parses its full flag grammar and
   enforces the scope gate, but has no scan engine behind it; it is a logged no-op.
   A complete, dependency-ordered sub-ticket breakdown already exists in
   [`docs/STEP5-DAST-PLAN.md`](docs/STEP5-DAST-PLAN.md) (tickets DAST-01 through DAST-30, following
   `docs/DESIGN.md` §13's `lib/http.sh -> auth.sh -> crawl.sh -> passive -> safe-active -> injection`
   sequence).
   Two things gated step 5 when that plan was written, and one of them is now cleared: step 4
   (SCA + IaC) is complete, so only step 3's two remaining rule packs still stand in front of the
   module.
   That remaining gate is a sequencing preference rather than a technical dependency.
   DAST-01 (the rate limiter, the per-run request budget, and the circuit breaker) touches
   `lib/http.sh` only and depends on no SAST rule pack whatsoever.
2. **Step 7 (`state/` - persistent coverage tracking)** - needed before `--baseline` suppression and
   the `diff`/`report` subcommands do real work.
   The two subcommands no-op with a stated reason in `run.json`, while `--baseline` records nothing
   at all (see Known defects below).
3. **Step 10 (SARIF output + compliance report)** - `--format sarif` is accepted today, but no SARIF
   emitter exists anywhere in the tree; same for the CIS/OWASP compliance report.
4. **Step 6 (live cloud / CSPM scanning)** - `scan.sh cloud` is a no-op today, with or without
   `--live`.
   There is no `modules/cloud/`, so the dispatch records a `not_yet_built` coverage reduction
   whichever form is used, and all `--live` adds is a check that the `aws` CLI is installed.
   A complete sub-ticket breakdown exists in
   [`docs/STEP6-CLOUD-PLAN.md`](docs/STEP6-CLOUD-PLAN.md) (tickets CLOUD-01 through CLOUD-34 plus
   POSTURE-01 through POSTURE-04).
   Gated on step 5 (DAST) completing.

Outside that ordering:

- **Step 3, remaining** - two SAST rule packs: `ldap.rules` and `nosql.rules`.
  They are the last sequencing item inherited from the original build order in front of DAST, but
  not a technical dependency of it.
  Both are pattern packs against a rule engine that has already shipped, so neither needs engine
  work, and they are the cheapest outstanding items on this page.
- Two derived/composite findings (`COMPOSITE-TOKEN-HIJACK` and its dependents) are intentionally
  not seeded yet, because their contributing checks don't exist until DAST (step 5) and cloud (step
  6) land.
- IPv6 / dual-stack routing support for `tools/run-in-netns.sh` was explicitly scoped out of that
  ticket and filed as a separate follow-up.

## Known defects in shipped features

These are not unbuilt steps.
They are features that ship today and are wrong, incomplete, or inert, and each one has to be
scheduled on its own.

- **Dependency scanning skips the scan entirely without an advisory database.**
  `data/advisories.db` does not exist in this repository; the only advisory database in the tree is
  `tests/fixtures/sca/advisories.db`, which is a test fixture.
  With no database, every ecosystem walk returns before it discovers or parses a single manifest, so
  `scan.sh sca` exits 0 against a knowingly vulnerable project with zero findings and an empty
  `checks_run` - it did not look, rather than looking and finding nothing.
  It is announced twice on every SCA run whatever ecosystems are present, since both walks that carry
  an announcement run unconditionally: one warning from the shared npm/RubyGems/Composer walk and one
  from the Go walk, recorded in `run.json` as `module=sca reason=no_advisories_db_on_disk` and the
  same reason with `ecosystem=Go`.
  The Python and Java walks return just as silently but record no reason of their own.
  Populating the database means `tools/vendor-engines.sh advisories`, which resolves one advisory at a time
  from an ID the operator must already know - there is no bulk or ecosystem-wide import.
- **Three flags are accepted and do nothing.**
  `--baseline FILE` is parsed and never read, and a path that does not exist is accepted with no
  error, no warning, and no record in `run.json`.
  `--authed` is parsed and appears in the help text, but nothing reads it and it is not recorded in
  `run.json` either.
  `--jobs N` is documented with a default of 4 and changes nothing; every scan is single-worker and
  records `single_worker_no_parallel_scan_yet`.
  (`--format` used to be a fourth: it was parsed and the resolved format list was then discarded, so
  every run wrote the same five artifacts whatever was asked for.  Fixed - see "Landed" above.
  `findings.jsonl` and `run.json` are mandatory per-run records rather than one of the four
  `--format` values, and are written on every run regardless of what `--format` asked for; `sarif` is
  accepted and validated but still selects nothing, because no SARIF emitter exists yet - that part of
  the gap is step 10's, not this one's, and remains listed above.)
- **`--fail-on-new` is currently a tautology.**
  Every finding is created with `status=new`, because the diff classification that would mark
  anything otherwise belongs to step 7, so `--fail-on-new` behaves identically to plain
  `--fail-on`.
- **`--paranoid` is Linux-only in practice.**
  Both of its connection-observer backends, `ss` and `strace`, are Linux-only.
  On macOS it does not degrade to a warning: it refuses the entire scan with exit 4 before any
  module runs.
- **Two SCA coverage warnings can collide, and one is dropped silently.**
  The `SCA-COV-UNKNOWN_VERSION-01` roll-up carries no ecosystem component in its fingerprint, and
  the Python, Java and Go paths each emit their own roll-up rather than joining npm's.
  A project with both npm and Python dependencies therefore produces two roll-ups with an identical
  fingerprint, deduplication drops one, and the survivor reports only npm's count.

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
