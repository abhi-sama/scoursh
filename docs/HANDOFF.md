# Handoff

A cold-start brief, written 2026-08-15.

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

**`scan.sh dast` dispatches for real** and honestly reports covering nothing, because no phase script exists yet.

**Not verified by execution**, and worth knowing:
`--paranoid`'s live sampling path has never been exercised against a real kernel socket table on any platform.
Its parsers are tested against recorded output and its abort logic against a scripted sampler.
The macOS CI leg passes green because every test routes through stubs.

## 2. What comes next

The running-endpoint scanner is the priority and both of its blockers are discharged.
Two of 36 tickets are done.

The critical path is short and the tail is wide:

| Stage | Tickets | Parallel |
|---|---|---|
| Session and crawling | DAST-03, DAST-04 | mostly |
| Passive checks | DAST-05 to DAST-11 | all seven are peers |
| Safe active | DAST-12, DAST-13 | both |
| Injection probes | DAST-14 to DAST-25 | all twelve are peers |
| Auth, API, access control | DAST-26 to DAST-30 | mostly |
| Safety defaults | DAST-31 to DAST-36 | see the plan |
| Guided interactive mode | GUIDE-01 to GUIDE-07 | see the plan |

**DAST-04, the crawler, is the next thing to build.**
Its output, the endpoint and parameter inventory, is what all 26 remaining checks consume, so its shape matters more than its speed.
Two things it must get right:

- It is the first ticket that sends real traffic.
  The rate limiter, budget and breaker are landed and measured, so use them; do not add a second network path.
- It must ship an honest hole.
  scoursh cannot crawl a JavaScript-rendered application, and the plan accepts that as a stated limitation rather than something to solve.
  A crawl that finds three endpoints in a hundred-endpoint single-page app and reports success is a silent false negative.
  The ticket's own acceptance criteria require that gap to appear in `run.json` and the report, not merely in prose.

Three whole steps are unstarted and are gated behind DAST: persistent run state (step 7), SARIF and the compliance report (step 10), and live cloud scanning (step 6).

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

**Advisory severities are silently misgraded.**
The bulk importer reads only a vendor-specific severity field and never OSV's standard top-level CVSS array, which is the normal shape for several ecosystems.
Everything it cannot read defaults to medium with no count and no warning.
For a tool whose `--fail-on` gates on severity, that quietly misgrades a large slice of the database.
This is the most consequential open defect.

**One malformed record aborts a whole ecosystem import** and the operator is given no way to find the offending advisory.

**Five flags are accepted and do nothing**: `--format`, `--baseline`, `--jobs`, `--authed`, and `--fail-on-new`, which is currently identical to `--fail-on`.
All are documented as inert in README's known-gaps section.

**There is no per-subcommand help**, so nothing warns an operator that a command is unbuilt.

**Two ecosystems' coverage warnings collide.**
When a project has both npm and Python dependencies, both emit a "could not check these versions" roll-up with an identical fingerprint, so deduplication drops one and the survivor reports only npm's count.

**`--paranoid` is Linux-only in practice** and refuses the whole scan with exit 4 elsewhere.
Either it gets a macOS backend or the limitation is stated in the docs; that decision is open.

**Two prose debts from the rate limiter.**
The register question about rate buckets being keyed per scope target rather than per resolved host, and a risk-list entry for the clock-granularity fallback that silently quarters the effective rate.
Both conditions warn at runtime and land in `run.json`; the written record is what is missing.

## 5. Not ours

**CI has been failing on billing since 2026-08-02.**
Jobs are created and marked failed within two seconds with zero steps executed.
Everything landed since then is verified by local runs only, and that is now a substantial amount of code.
The CI runbook still asserts in the present tense that three required checks run on every push.

Clearing that is an account action, not a code change.
It is the single highest-value thing an operator can do for this project right now, because the local suite is thorough but runs on one platform, and the whole point of the dual-runner matrix is catching GNU versus BSD divergence that a single machine cannot see.
