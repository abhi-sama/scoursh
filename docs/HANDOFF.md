# Handoff

A cold-start brief, written 2026-08-15.
**Sections 1 and 2 describe a point-in-time snapshot from before DAST (`docs/DESIGN.md` §13 step 5)
existed; DAST has since landed in full (`docs/STEP5-DAST-PLAN.md`'s own status section, mirrored in
`AGENTS.md`'s "Build order and where we are"), so most of both sections is now historical rather than
current. They are corrected in place below rather than deleted, since the traps and lessons around them
still hold; for current build state, read `AGENTS.md`'s "Build order and where we are" instead of this
file.**

This document does not restate the plan.
[`ROADMAP.md`](../ROADMAP.md) owns what is left at the project level, [`docs/STEP5-DAST-PLAN.md`](STEP5-DAST-PLAN.md) owns the running-endpoint scanner's 36-ticket sequence, and [`AGENTS.md`](../AGENTS.md) owns the build order and the sharp edges.
Read those.

What this file carries is the part that is not recoverable from them: what has been PROVEN by running it rather than claimed, what genuinely comes next and in what order, the traps that cost real time this week, and the defects that are known and open.

## 1. Verified ground truth

Everything in this section was confirmed by executing it, not by reading code or documentation.
Where a claim is only supported by code reading, it says so.

**Static scanning works and fires.**
Nine SAST rule packs, 51 checks, and six IaC packs, 36 checks.
Every check id was confirmed appearing in output from a real scan, so nothing is registered-but-dead.

**Dependency scanning now works end to end**, which it did not until this week.
The parsers and matcher were always finished; what was missing was any practical way to get advisory data.
Measured on one project with only the database changing: 0 findings before, 3 after.
On a six-ecosystem project: 0 before, 13 after.

**The severity gate fires for every module.**
It silently did not for dependency scanning until this week, so `scan.sh sca --fail-on critical` exited 0 with critical findings present.

**`scan.sh all` works.**
It was broken for eleven days and aborted on 100% of invocations, silently omitting every module after the first while writing a report that declared the run complete.

**The DAST test target is real and has been watched running.**
`tests/e2e/dast-target-smoke.sh` passes 19 of 19 against a live local OWASP Juice Shop container.
It proves the scope gate admits the authorised target and refuses a different port on the same host, that `http_request` exits 3 on an unauthorised host, and that two provisioned identities have a genuine cross-user access-control bug for DAST-29 to assert against.
Before this week that tooling had been reviewed as code but never observed working.

**The rate limiter holds under concurrency.**
Aggregate request rate measured flat from 1 to 32 concurrent worker processes and never reaching the ceiling.
This matters because the failure mode is invisible in single-process tests: per-process state means `--jobs 8` sends eight times the traffic.

**`scan.sh dast` dispatches for real, and now covers everything the plan named.**
At the time this brief was written no phase script existed yet; every DAST-01 through DAST-36 ticket
has since landed, so a `scan.sh dast` run against an authorized target exercises auth/crawl, every
passive/safe-active/injection check, and the tier-5 application-layer checks (see
`docs/STEP5-DAST-PLAN.md` for the full per-ticket record).

**`--paranoid`'s live sampling path has since been exercised against a real kernel socket table**,
which it had not been at the time this section was written.
`tests/suites/paranoid.sh`'s "REAL lsof" section runs the real sampler, unmocked, against sockets the
test itself opens - including a real `scan_main --paranoid` run whose descendant process holds a real
out-of-allowlist socket, observed by the real `lsof` and aborted with exit 3 end to end.
It stays a no-egress test (connected UDP sockets record a peer without a packet leaving the machine),
and it is what makes the macOS CI leg's green result trustworthy rather than an artifact of every test
routing through stubs.

## 2. What comes next

**All 36 DAST tickets shipped** (this section originally tracked "2 of 36 done" and DAST-04 as the
next thing to build; both are stale - the table below is kept only as a record of the shape of that
work, not as a to-do list):

| Stage | Tickets | Landed |
|---|---|---|
| Session and crawling | DAST-03, DAST-04 | yes |
| Passive checks | DAST-05 to DAST-11 (plus DAST-30) | yes |
| Safe active | DAST-12, DAST-13 | yes |
| Injection probes | DAST-14 to DAST-25 | yes |
| Auth, API, access control | DAST-26 to DAST-29 | yes |
| Safety defaults | DAST-31 to DAST-36 | yes |
| Guided interactive mode | GUIDE-01 to GUIDE-07 | **not built** - genuinely still open, and unclaimed rather than blocked; see `docs/STEP-GUIDE-PLAN.md` |

DAST-04 (the crawler) shipped exactly as scoped: it sends real traffic through the landed rate
limiter/budget/breaker, and it records the JavaScript-rendered-app limitation as a `coverage_gap` in
`run.json` and the report rather than reporting a thin crawl as clean (see `AGENTS.md`'s "DAST-04...
has landed" paragraph for the measured detail: 13 endpoints/0 parameters against the local
Angular-based test target with `spa_shaped=1` recorded).

With DAST complete, three steps are next in the queue rather than gated behind it: persistent run
state (step 7), live cloud scanning (step 6), and SARIF plus the compliance report (step 10). See
`ROADMAP.md` for the current priority ordering among them.

## 3. Traps that cost real time this week

These are not in `AGENTS.md`'s sharp-edges section yet.
Each one shipped, or nearly shipped, before it was caught.

**A `declare -A` at file scope in a module is function-local.**
`scan_dispatch` is a function and it `source`s each module from inside itself, so a file-scope declaration without `-g` creates a local that dies when the first dispatch returns.
The sourced-once guard is a plain assignment and survives, so the guard outlives the thing it guards, and the second consumer in one process writes into an undeclared name.
This is what broke `scan.sh all`, and the fix is `declare -gA`.
The bash floor is 4.2, so `-g` is always available.

**A test that has not been run against the broken code pins nothing.**
This was measured twice this week, not theorised.
A concurrency test asserting "exactly the threshold reached the transport" passed under the deliberately broken reading in 2 runs out of 8.
A start barrier that polled with a sleep caught a missing mutex in only 4 runs out of 6, because each poll forks and workers wake spread over tens of milliseconds.
The working forms are a one-sided observable (a lost update can only leave a count short, and a short count cannot open the breaker) and an absolute-deadline barrier where workers spin on the clock rather than forking.
The strongest available check on a test is to break the code and confirm the test fails.

**The silent-completion pattern has appeared three times in two days.**
Stop early, report clean.
Once when dependency scanning skipped its gate, once when `scan.sh all` aborted mid-run, once when a budget-exhausted run exited before the report writers ran.
On anything that can terminate early, assert the honest record on `run.json` itself, which is what a consumer reads, never on an internal file.
The contract is that whenever the exit code is 5, `incomplete_reason` is non-empty.

**Completing the inventory broke the guard on the inventory.**
`tests/lint-status.sh` proves its staleness check still works by corrupting a "not landed" row.
When the catalog reached completion no such row existed and the guard died with no input.
It now tries that direction first and falls back to the opposite.
Guards that depend on the project being unfinished switch themselves off at the worst moment.

**shellcheck conflates same-named variables across sourced files.**
An indexed array declared `local -a` in one file was reported as needing an associative index because four other files declare a local of the same name with `-A`.
The project's convention is an explicit disable directive with a stated reason rather than restructuring correct code.

**`tail -N` on a live pipe emits nothing until the source closes.**
A test suite piped through `tail` looks hung and produces an empty file.
Redirect to a file and read the file.

**The vulnerable and clean test fixture trees are shared and scanned wholesale.**
A new rule pack changes what every existing pack is tested against, and vice versa.
An inert pack passes every "stays quiet" assertion, so a pack needs an assertion that it still FIRES as well as one that it stays silent, over check-id and path pairs from a single scan.

## 4. Known and open

Ordered by what a user notices first.

**Advisory severity for CVSS-only sources is still not scored, but it's a documented default now, not a silent one.**
The importer reads `database_specific.severity` (the vendor field GHSA-backed sources use) and never
attempts to score OSV's standard top-level CVSS vector, which is the normal shape for PyPI/Go sources -
`tools/vendor-engines.sh`'s own header states this is a "stated, not hidden, limitation" and defaults
an unreadable severity to `medium` deliberately (a conservative floor, not "absent is low risk").
No count of how many rows hit that default is recorded anywhere, which is a real, still-open gap for a
tool whose `--fail-on` gates on severity.

**One malformed record still aborts a whole ecosystem import, but the operator can now find it.**
`tools/vendor-engines.sh` prints the specific archive member name in its failure message before
exiting; the import still stops rather than skipping the one bad record and continuing.

**Four flags are accepted and do nothing**: `--format`, `--baseline`, `--jobs`, and `--fail-on-new`,
which is currently identical to `--fail-on`.
`--authed` is no longer in this list - `modules/dast/authz.sh` and the crawl/injection phases spend
the session it acquires. All four remaining inert flags are documented in README's known-gaps section.

**There is no per-subcommand help**, so nothing warns an operator that a command is unbuilt.

**Two ecosystems' coverage-warning collision is fixed.**
`modules/sca/engine.sh`'s shared roll-up accumulator (its own "section 8a") now merges the
"could not check these versions" roll-up across all ecosystems into one finding whose breakdown names
each of them, rather than emitting one per ecosystem that then collide and dedupe down to one.

**`--paranoid` now has a macOS backend (`lsof`) and no longer refuses the scan there.**
`lib/paranoid.sh` tries `ss`, then `strace -f -e trace=connect`, then `lsof` in order; the first two are
Linux-only and `lsof` is what macOS ships. It still refuses with exit 4 only when none of the three is
usable. `tools/run-in-netns.sh` (the stronger, guarantee-tier mechanism) remains Linux-only with no
macOS equivalent - that gap is real and documented, not the `--paranoid` gap this note originally named.

**Two prose debts from the rate limiter.**
The register question about rate buckets being keyed per scope target rather than per resolved host, and a risk-list entry for the clock-granularity fallback that silently quarters the effective rate.
Both conditions warn at runtime and land in `run.json`; the written record is what is missing.

## 5. Not ours

**CI is dormant rather than failing, and that framing has changed since this brief was written.**
At the time of writing, hosted jobs were created and marked failed within two seconds with zero steps
executed. `.github/workflows/ci.yml`'s `suite` job now carries `if: ${{ !github.event.repository.private }}`,
which the Actions scheduler evaluates before ever requesting a runner - so on this private repository
the job is **skipped**, not attempted, and a push or PR produces no failing status at all, only a
skipped one. `docs/CI-RUNBOOK.md` documents this accurately today (it no longer asserts required
checks run on every push); everything landed continues to be verified by local runs only
(`tools/daily-suite.sh`, on a schedule), and by standing captain instruction CI does not gate merges on
this repository. The condition flips to real, hosted, gating checks automatically the moment the
repository goes public - no workflow edit needed.
