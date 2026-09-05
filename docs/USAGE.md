# Usage reference

The complete CLI, exit-code, and configuration-file reference for `scan.sh`.
For an introduction to what `scoursh` is and why it's built this way, see the main
[`README.md`](../README.md).

## How to read this reference

`scoursh` is still being built, and its argument parser accepts several flags and subcommands whose
implementation does not exist yet.
Every table below therefore carries a **Status** column.
It has two values, sometimes followed by a short qualifier:

- **live** - it does what its description says.
- **inert** - it is parsed, validated, and accepted, and then changes nothing about the run.

An inert flag is not a usage error and does not print a warning.
It is accepted, the run exits normally, and in most cases nothing in `run.json` records that the flag
was ever given.
That is the trap this column exists to close: `--jobs 8` and `--lang py,js,go,java` both
look exactly like they worked.

[Accepted but not yet implemented](#accepted-but-not-yet-implemented) gives the precise behaviour of
every inert entry, and is the section to read before wiring `scoursh` into CI.

The tool's own help does not carry this distinction.
`-h` / `--help` prints the same global usage text for every command, built or not, so
`scan.sh diff --help` is byte-identical to `scan.sh sast --help`.
This document is the only place the difference is written down.

## Commands

`scoursh` is a single entry point, `scan.sh`, with one subcommand per surface it scans.
Every run that gets as far as dispatching its command writes `run.json` into its output directory,
whether or not any findings were produced.
A run that refuses first - a missing required input, a scope violation, a `--paranoid` host with no
usable observer - exits before `run.json` is written, so its exit code and its error line are the only
record of it.

```sh
scan.sh <command> [options]
```

| Command | Flags | Status | Notes |
|---|---|---|---|
| `sast` | `[--path DIR]` `[--lang py,js,go,java]` `[--history]` | live | Source code. `--history` replays secret checks across git history and requires `git` on `PATH`. |
| `sca` | `[--path DIR]` | live, needs an advisory database | Dependency/lockfile CVEs. Lockfile parsing works for every supported ecosystem, but matching needs `data/advisories.db`, which this repository does not ship - without it the run exits `4` rather than reporting a clean project. See ["Dependency data"](#dependency-data-dataadvisoriesdb). |
| `iac` | `[--path DIR]` | live | Cloud IaC plus container/Kubernetes manifests. |
| `dast` | `--target NAME` `[--intensity passive\|safe\|active]` `[--authed]` `[--i-own-target NAME]` | partially live - **it sends real requests** | The scope gate below is enforced before anything else (see "The scope gate"), as are the conservative rate/budget/breaker ceilings and the `--i-own-target` affirmation (see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)). Past those, a run now really does talk to the target: it authenticates if asked (`auth.sh`), crawls to build an endpoint inventory (`crawl.sh`), and runs the security-header checks (`passive/headers.sh`). At `--intensity active` it additionally runs the SQL-injection and JWT probes. Most of `docs/DESIGN.md` §7 is still unbuilt, so every phase script that is missing is recorded in `run.json` as a `coverage_gap`; read those, not this table, for what a given run actually covered. |
| `cloud` | `[--live]` `[--profile NAME]` `[--regions all\|us-east-1,...]` `[--assume-role ARN]` | inert | `--live` requires the `aws` CLI on `PATH` and the run refuses (exit 4) if it is missing, which is a real check. No AWS call follows it: there is no `modules/cloud/`, so the run records `module=cloud reason=not_yet_built`. |
| `all` | union of every module's own flags above | live | Runs sast, sca, iac unconditionally; runs dast only if `--target` is given and cloud only if `--live` is given, and those two do nothing when they run. Every module it skips is recorded in `run.json` as a `coverage_reduction` fact, not silently dropped. |
| `diff` | `--against DIR` | inert | `DIR` must be a prior run's output directory (must contain `findings.jsonl` or `run.json`), and that check is enforced. Nothing is then compared. |
| `report` | `--from DIR` | inert | Regenerating reports from a prior run is not built. Report file generation during a scan is a different thing and works - see the section below. |

`-h` / `--help` at any position before the first unrecognized token prints usage and exits 0.

### Per-command flags

| Flag | Command | Status |
|---|---|---|
| `--path DIR` | sast, sca, iac, all | live |
| `--lang py,js,go,java` | sast, all | inert |
| `--history` | sast, all | live |
| `--target NAME` | dast, all | live as a gate, and the scan it gates now runs |
| `--intensity passive\|safe\|active` | dast, all | live as a ceiling; `passive` reaches the crawl and the security-header checks, `active` additionally reaches the SQLi and JWT probes |
| `--authed` | dast, all | live - `auth.sh` acquires a session, and a failed login is a declared coverage reduction rather than an error |
| `--i-own-target NAME` | dast, all | live |
| `--requests-per-second N` | dast, all | live; raising it above the conservative ceiling needs `--i-own-target` (see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)) |
| `--request-budget N` | dast, all | live; same as above |
| `--live` | cloud, all | live as a precondition check only |
| `--profile NAME` | cloud, all | inert |
| `--regions all\|us-east-1,...` | cloud, all | inert |
| `--assume-role ARN` | cloud, all | inert |

## Global flags (apply to every command)

| Flag | Value | Default | Status |
|---|---|---|---|
| `--profile-scan` | `quick` \| `full` \| `compliance` | `full` | live |
| `--verbose` | boolean | off | live |
| `--paranoid` | boolean | off | live on Linux (`ss`/`strace`) and macOS (`lsof`) |
| `--use-engines` | boolean | off | live, but no engine is vendored here |
| `--allow-intrusive` | boolean | off | live as a gate (needs `--i-own-target`); the checks it would admit do not exist |
| `--contact VALUE` | one printable, space-free token | from `config/scanner.conf` (`contact`), else none | live |
| `--user-agent-suffix TOKEN` | one printable, space-free token | none | live |
| `--jobs N` | positive integer | from `config/scanner.conf` (`4`) | inert |
| `--format` | CSV of `json,sarif,html,md` | all four | live; `sarif` writes a complete, schema-validated document - see [SARIF output](#sarif-output) |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` | from `config/scanner.conf` (`none`) | live |
| `--fail-on-new` | boolean; **requires `--fail-on`**, usage error otherwise | off | inert |
| `--min-confidence` | `high\|medium\|low` | from `config/scanner.conf` (`low`) | live |
| `--baseline FILE` | path | none | live |
| `--out DIR` | path | `reports/<timestamp>` | live |
| `--guided` | boolean | off | live |
| `--print-command` | boolean | off | live |

`--verbose` also prints the rule-authoring lint warnings a normal run keeps out of the way.
`--use-engines` is fully wired, but it only has an effect once an optional engine has been vendored
into `modules/<module>/adapters/<engine>/` by hand on a networked host; no engine binary is committed
to this repository, so on a stock checkout the flag produces a
`coverage_reduction reason=engine_not_vendored` line and nothing else.
`--guided` and `--print-command` are covered in full in ["Guided mode"](#guided-mode---guided) below.

## Guided mode (`--guided`)

Two invocations reach guided mode: a bare `scan.sh` with no arguments at all, and
`scan.sh <command> --guided` (e.g. `scan.sh dast --guided`).
Both launch the interactive questionnaire only when run on an interactive terminal - see "When it
prompts, and when it refuses" below for the exact conditions.
Off a terminal (or in CI), a bare `scan.sh` falls through to the ordinary `no command given` usage
error, and `scan.sh <command> --guided` fails loudly naming the reason - see the table below for both.

**`scan.sh --guided` with no command is not a valid invocation, on a terminal or off one.**
`--guided` is parsed as a flag on whichever command precedes it, so with no command before it,
`--guided` is read as the command itself and the parser fails immediately with
`unknown command: '--guided'` - a plain usage error, not a guided-mode refusal, and it happens even on
a real terminal since it never reaches the eligibility check below.

The questionnaire asks what to scan, then a handful of follow-up questions specific to that surface, and always
ends on a review screen that prints the exact command it would run and offers to run it, print it,
or cancel.
Nothing is scanned before that final confirmation.
Every question maps to a flag - see "Flag equivalence" below - so a guided session and its printed
command are two views of the same input, never two different mechanisms: "Run it" hands the composed
argv to the same `scan_parse_args` / `scan_validate_flag_value` / `_scan_check_affirmation` path a
hand-typed invocation goes through, and nothing downstream can tell a run was configured
interactively.

### When it prompts, and when it refuses

Prompting is gated on five conditions (`lib/guide.sh`'s `guide_may_prompt`), checked in this order,
and **all five** must hold:

1. It was actually asked for - the invocation was a bare `scan.sh` with zero arguments, or `--guided`
   was given as a flag on a command (`scan.sh <command> --guided`). `--guided` with no command in
   front of it never reaches this check at all: the parser reads it as the command itself and dies
   `unknown command: '--guided'` first (see above).
2. Standard input is a terminal.
3. Standard error is a terminal - `select`'s own menu and prompt text go to stderr, not stdout, so a
   run whose stderr is redirected to a logfile is exactly the case a menu must not block on.
4. None of these environment variables is set: `CI`, `CONTINUOUS_INTEGRATION`, `BUILD_NUMBER`,
   `JENKINS_URL`, `TEAMCITY_VERSION`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `TF_BUILD`.
5. `SCOURSH_NO_PROMPT` is unset.

The environment layer can only ever turn prompting **off**; nothing in it can force interactive mode
onto a non-terminal.

What a refusal looks like depends on how prompting was asked for, because only an *explicit* ask
gets a loud refusal:

| Invocation | Any of conditions 2-5 fails | Exit code |
|---|---|---|
| Bare `scan.sh`, no arguments | Silent fall-through to the ordinary `no command given` usage error - a bare `scan.sh` was never an explicit ask the way `--guided` is | `2` |
| `scan.sh <cmd> --guided ...` | Loud refusal naming the first failing condition, e.g. `--guided: 'CI' is set in the environment; nothing was run and nothing is waiting for input` | `2` |

Mid-flow, once a session has actually started, every way out has its own exit code:

| Event | Exit code |
|---|---|
| `Ctrl-C` (SIGINT) or SIGTERM at any prompt - `Cancelled.  Nothing was scanned.` | `0` |
| Picking "Cancel" at the final review screen - the identical message and code as the signal case | `0` |
| Stdin hits EOF (piped from `/dev/null`, or a here-doc runs out) at any menu or free-text prompt - `input ended before the scan was configured; nothing ran` | `2` |
| Ten consecutive unusable menu answers - `too many unusable answers; nothing ran` | `2` |
| An unreadable `--path` typed twice in a row - `--path was asked twice and neither answer resolved to a readable directory; nothing was run and nothing is waiting for input - re-run with a valid --path instead` | `2` |
| `scan.sh dast --guided` with no DAST target ever selected - `no DAST target was chosen; nothing was run and nothing is waiting for input - re-run with a valid --target instead` | `2` |

No prompt in this flow ever times out - `select` cannot, and a `read -t` fallback was deliberately
rejected: it would make identical answers produce a different scan depending on typing speed, which
breaks determinism outright.
A session that is genuinely stuck has to be interrupted (`Ctrl-C`, exit `0`), not waited out.

### What each scan type's guided flow can actually configure

This is the same **Status** discipline this whole document uses, applied to the questionnaire
itself: which surfaces guided mode wires up completely, and which one it refuses outright rather than
walking through questions for a scan that cannot do anything yet.

| Scan type | Guided today | Notes |
|---|---|---|
| Source code (`sast`) | **fully wired end to end** | Asks path, languages, and - only if `git` is on `PATH` - whether to also replay secret checks across git history. |
| Dependencies/lockfiles (`sca`) | **fully wired end to end** | Asks path only. If `data/advisories.db` is missing it says so and explains the run will still proceed as a declared coverage gap - the identical honesty `scan.sh sca` already gives outside guided mode. |
| Infrastructure as code (`iac`) | **fully wired end to end** | Asks path only. |
| A running web application (`dast`) | **fully wired end to end** | Target, then intensity, then - only above `passive` - the own-your-target affirmation and each raised limit. Picking `passive` asks nothing further: no affirmation, no rate/budget menus, no side-effecting-checks question. |
| An AWS account, read-only (`cloud`) | **not reachable at all** | There is no `modules/cloud/run.sh` in this checkout (`docs/DESIGN.md` step 6 has not started). Picking this item explains that cloud scanning is not built yet in this version and returns to the menu; nothing is asked and nothing runs - the same refusal any not-yet-built surface gets here. |
| Everything this checkout can actually do (`all`) | **partially wired** | Asks path/languages/history exactly like `sast` (when not already given), then the CI gate. It does **not** route through the `dast` target/intensity/affirmation questions at all: `scan.sh all` only runs `dast` when `--target` was already given on the command line before `--guided`, and only runs `cloud` when `--live` was already given - otherwise both are recorded as declared `coverage_reduction` facts, exactly as a non-guided `scan.sh all` with neither flag already does. A guided `all` session is therefore never how an operator first authorises a DAST target; that has to happen through `scan.sh dast --guided` (or its own "Authorise a new target" menu item) first. |

**There is no live gap today where guided mode walks through configuring a surface and then runs
something not wired up** - the one unbuilt surface (`cloud`) is refused at the door, before a single
question is asked.
The source does carry a forward-looking status string for a *future*, partial `cloud` guided flow
(asking only the CI gate, once `modules/cloud/run.sh` exists); that path is unreachable on this tree
today and is worth re-checking against this table the day a `cloud` module lands, so it does not
quietly become the trap this table exists to rule out.

### Flag equivalence

Every guided prompt has a command-line flag equivalent, so "Print the command and exit without
running" - and the standalone `--print-command` flag, which renders the fully resolved invocation for
**any** command, guided or not, without ever opening a session - always produces a complete,
pasteable replacement for the questionnaire.

| Prompt | Flag |
|---|---|
| Scan type | the subcommand: `sast` \| `sca` \| `iac` \| `dast` \| `cloud` \| `all` |
| Path | `--path DIR` |
| Languages | `--lang py,js,go,java` |
| Git history | `--history` |
| DAST target | `--target NAME` |
| Authorise a new target | none, deliberately - the non-interactive equivalent is editing `config/scope.conf` directly |
| DAST intensity | `--intensity passive\|safe\|active` |
| Own-your-target affirmation | `--i-own-target NAME` (must equal `--target`; a mismatch is exit `2`) |
| Request rate | `--requests-per-second N` |
| Request budget | `--request-budget N` |
| Side-effecting checks | `--allow-intrusive` |
| CI gate | `--fail-on critical\|high\|medium\|low\|info\|none` |
| Print and exit | `--print-command` |
| (turn the whole thing on) | `--guided` |
| (turn the whole thing off) | `SCOURSH_NO_PROMPT=1` |

**One correction to this table, worth stating because `docs/STEP-GUIDE-PLAN.md`'s own version of it
says otherwise:** the request-rate menu's "No limit" item does **not** map to
`--requests-per-second 0`.
Verified against the shipped limiter rather than assumed: `lib/http.sh` refuses a genuinely-zero rate
outright (exit `4`, "permits no requests at all") rather than treating it as unlimited, because a
limiter waiting forever for a token that can never arrive would look like a hang.
"No limit" instead emits the largest schema-legal rate, `999999999` - for any real target that is
indistinguishable from "send as fast as it answers", and the run's request budget and circuit
breaker still bound it either way.

Two flags the guided flow deliberately never asks about, because they belong to a CI setup written
once rather than to a menu: `--fail-on-new` (which requires `--fail-on`) and `--paranoid`.

Every audited run's `run.json` carries an `authorization` object regardless of how it was configured,
and a guided run's is byte-identical to the same flags typed by hand: nothing marks
`authorization.affirmation_source` as having come from a menu, so it reads `flag` either way.

### Log level and colour (`SCOURSH_LOG_LEVEL`, `SCOURSH_COLOR`, `NO_COLOR`)

`SCOURSH_LOG_LEVEL` (`debug|info|warn|error|silent`, default `info`) sets the minimum level
printed to stderr.

Colour on stderr is resolved from `SCOURSH_COLOR` and `NO_COLOR`, checked in this order:

- `SCOURSH_COLOR=never` - never colour.
- `SCOURSH_COLOR=always` - always colour, even when stderr is not a terminal (piped into
  `less -R`, or a CI log that renders ANSI).
- `SCOURSH_COLOR=auto` or unset (the default) - colour only when stderr is a terminal **and**
  `NO_COLOR` (https://no-color.org) is unset or empty.

`SCOURSH_COLOR=always` wins even when `NO_COLOR` is also set: `NO_COLOR`'s own convention text
allows an explicit user flag to override it, and `SCOURSH_COLOR` set to a specific value is exactly
that - an operator who typed `always` gets `always`, not a value NO_COLOR silently downgraded.

## `--format` and the `formats` config key

The list is validated, resolved through the full CLI-over-environment-over-file-over-default chain,
and then honoured: `lib/report.sh`'s `report_all` gates `findings.json`, `report.md`, `report.html`
and `report.sarif` on it, so `--format md` writes the Markdown report and none of the other three.

`findings.jsonl` and `run.json` are **not** `--format` values.
They are mandatory per-run records - the incremental ledger and the audit record - and are written on
every run whatever `--format` asked for, so they are not evidence that the flag was ignored.

`--format sarif` writes `report.sarif`, documented in full in the next section.

## SARIF output

`--format sarif` (or `sarif` in a multi-value `--format`/`formats` list) writes
`reports/<run>/report.sarif`, a complete SARIF 2.1.0 document carrying this run's actual findings.
It is validated in the test suite against the vendored OASIS `sarif-schema-2.1.0.json` schema, plus
an extra condition a schema alone cannot express: every result's
`locations[0].physicalLocation.artifactLocation.uri` is asserted to resolve to a real, existing file
(`tests/suites/sarif-schema.sh`; the full rationale is `docs/FOUNDATION.md` tension 22).
Point a code-scanning CI step at that file today - there is nothing further to wait for.

### What is in the document

- **`runs[0].tool.driver.rules[]`** - the full loaded check registry, one `reportingDescriptor` per
  check id, whether or not that check produced a finding this run. A check id with no on-disk
  `*.rules` record - an SCA id, an `<engine>:...` optional-engine-adapter id, or a derived/composite
  id - gets a descriptor synthesised from the finding itself instead, marked
  `properties.descriptorSource: "synthesised"` so the distinction is visible rather than hidden.
- **`runs[0].results[]`** - one entry per finding. Every result carries **both** a physical location
  and a logical location (`logicalLocations[0].fullyQualifiedName`), never only one - see "The
  location model" below for what the physical location points at when a finding has no source file
  (a cloud resource, a DAST endpoint, a posture control).
- **`result.partialFingerprints["scourshFingerprint/v1"]`** - scoursh's own stable finding
  fingerprint. It never includes a line number, so it survives reindentation and unrelated edits. Use
  it, not the result's message text or line, to track one finding across runs of your own.
- **`result.properties`** - `module`, `status`, `confidence`, `baseSeverity`, `severity`, `cvss`
  (`vector`/`score`, an audit trail - see "What is deliberately never in it" below), `suppressed`,
  `cell`, `firstSeen`/`lastSeen`.
- **`result.suppressions[]`** - present with `kind: "external"` for a finding suppressed by
  `config/baseline.json`, never a dropped result, so a suppressed-but-still-real finding stays visible
  to a consumer that wants to see accepted risk. Baseline suppression is live (`--baseline FILE` - see
  below), so this array is now populated for real by the same finding data every other emitter reads;
  it was written and tested against a hand-authored fixture ahead of that landing, so nothing about
  the SARIF document itself needed to change once it did.
- **`result.properties.status`** - `new` or `recurring`, the real classification against persistent
  run state ([`docs/STEP7-STATE-PLAN.md`](STEP7-STATE-PLAN.md)) for every finding this run actually
  produced. `fixed`/`unknown` never appear here: those describe a PRIOR finding absent from this run,
  which has no SARIF result of its own to carry a status - see `run.json`'s own `counts.by_status` and
  the Markdown/HTML report's "Since last scan" section for that half of the picture.
  `partialFingerprints` is still what lets a consumer do its own tracking independent of this tool's
  own `state/`.
- **`runs[0].artifacts[]` / `runs[0].invocations[0]`** - the generated location artifacts this run
  actually wrote (see below), and the run-level audit facts `run.json` already records
  (`startTimeUtc`/`endTimeUtc`/`executionSuccessful`).

### What is deliberately never in it

- **`security-severity`.** This is the field a GitHub-code-scanning user looks for first, and
  scoursh deliberately does not emit it. `result.properties.cvss` is a CVSS vector and score, but it
  is computed purely as an audit trail for how the severity rubric adjusted a finding's severity -
  its inputs are exposure/authentication/data-sensitivity/confidence, **never the severity itself** -
  so a `critical` finding and an `info` finding with the same exposure/auth/sensitivity/confidence
  carry the identical CVSS score. Publishing that score as `security-severity` would have GitHub code
  scanning (which reads that field and re-derives its own displayed severity from it, ignoring
  `result.level`) show a severity that contradicts `result.level`, `run.json`, the HTML report, and
  the `--fail-on` gate - all of which agree with each other today. `severity` maps to `result.level`
  instead: `critical`/`high` -> `error`, `medium` -> `warning`, `low`/`info` -> `note` (never `none`,
  which SARIF reserves for "this rule did not evaluate to a problem"). The original five-value
  severity survives in `result.properties.severity` for anything that wants the finer distinction
  `level` alone loses.
- **`codeFlows`/`threadFlows`/`graphs`/`taintFlows`.** scoursh's native checks are pattern-grade and
  carry no data-flow model; emitting an empty or single-step flow would overstate the analysis.
- **`fixes[]`.** `remediation` is prose guidance, not a machine-applicable patch.
- **`result.rank`, `automationDetails`, `runAggregates`, `baselineGuid`,
  `versionControlProvenance`.** Each would mint a second, competing notion of severity or run
  identity ahead of the persistent-state work that owns that story.
- **Multiple `runs[]`.** One scan is one run, even under `scan.sh all`; `result.properties.module`
  distinguishes the findings inside it.

One provenance gap worth knowing if you consume SCA (dependency) findings: `data/advisories.db`
cannot today distinguish a genuinely medium-rated advisory from one an upstream source published with
no severity at all - both land on `medium` - so `result.properties.severityProvenance` is never
emitted for any SCA finding. `run.json` instead carries a `coverage_reduction` fact
(`reason=sarif_severity_provenance_unavailable`) when a `medium`-severity SCA finding is present in
the run, so the gap is recorded rather than silently guessed around.

### The location model

Every result's physical location points at a file that genuinely exists - never a fabricated or
guessed path:

| Case | Findings | Physical location points at |
|---|---|---|
| Real source file | SAST, IaC (native and optional-engine-adapter) | The real file and line in the scanned tree. |
| Real file, outside the fingerprint | SCA (dependency) | The real, committed lockfile. |
| Real file that may no longer exist | Git-history secrets (`SAST-HIST-*`) | The file at its current path, if that path still resolves in the working tree; otherwise the generated artifact below, whose line carries the blob sha and commit so you can `git show` it. |
| No file at all | DAST, cloud, posture | A generated `reports/<run>/locations/<module>.txt` artifact - one line per finding, containing that finding's logical identity, included in the SARIF `artifacts[]` array. Clicking through in a code-scanning UI lands on a line describing the resource (an ARN, a URL and parameter, a control id), never on an unrelated source file. |

`docs/FOUNDATION.md` tension 22 has the full rationale for why a generated artifact was chosen over
either omitting the location or fabricating one.

## Accepted but not yet implemented

Everything in this section parses, validates, and is accepted today.
None of it changes the outcome of a run.

### `diff --against DIR`

`DIR` is validated (a directory that is not a prior run directory is a hard exit 4), then the run
prints `'diff' has no engine yet`, records `module=diff reason=not_yet_built` in `run.json`, and exits
0.
Nothing is compared, because there is no persistent run state to compare against: no findings are
classified as new, fixed, or unchanged, and no output directory of a previous run is read beyond
confirming it exists.

### `report --from DIR`

The same shape as `diff`: `DIR` is validated, the run prints `'report' regeneration has no engine
yet`, records `module=report reason=not_yet_built`, and exits 0.
It creates its own output directory containing `run.json` and empty scaffolding, and no `report.md`,
`report.html`, `findings.json`, or `findings.jsonl`.

**Report file generation itself works, and is not affected by this.**
Every `sast`, `sca`, `iac`, and `all` run writes `findings.json`, `findings.jsonl`, `report.md`,
`report.html`, and `run.json` into its own output directory as part of the scan.
What does not exist is the separate ability to rebuild those files from an earlier run's directory
after the fact.
Until it does, keep the output directory a run produced, or scan again.

### `--baseline FILE`

Suppresses findings whose fingerprint matches an entry in `config/baseline.json`, or in FILE when
`--baseline` is given (which REPLACES the default file rather than adding to it).
An entry is either a bare fingerprint string, or an object
`{"fingerprint": "…", "reason": "…", "added": "YYYY-MM-DD", "expires": "YYYY-MM-DD"}`
(`docs/FOUNDATION.md` tension 11's frozen schema; a bare string is `reason: ""`, `added`/`expires:
null`).
Suppression is an annotation, never a deletion: a matched finding still appears in every output
format, with `suppressed: true` and its reason, in a collapsed "accepted risk" section, and is
excluded from every count and from `--fail-on`/`--fail-on-new`.
An entry whose `expires` date has passed stops suppressing, and the report says so; an entry that
matches no finding this run is reported `stale` in `run.json` and in the report, which is also how a
finding that was baselined and then genuinely fixed is still reported `fixed` rather than silently
staying suppressed forever.
The concrete failure this used to invite, now closed: a `--baseline` path that does not exist is a
real error (`exit 4`), not a clean exit with suppression silently never having run; a default
`config/baseline.json` that is simply absent - the ordinary case for a fresh checkout - is not an
error at all.
A baseline file that exists but cannot be read, or is not well-formed, is also a real error, rather
than being treated as an empty baseline - unlike this tool's own `state/`, which degrades gracefully
on corruption, because `config/baseline.json` is a human-edited accept-risk list and silently
misreading it, in either direction, is the one outcome this mechanism exists to rule out.

### `--jobs N` and the `jobs` config key

Validated as a positive integer, resolved, exported, and read by no module.
Every run is single-worker, and each module says so in `run.json` with a
`coverage_reduction reason=single_worker_no_parallel_scan_yet` fact.
The advertised default is `4`; the actual concurrency is 1, at every value of the flag.

### `--fail-on-new`

Today this is a tautology, not a filter.
Every finding is created with `status: new` and nothing overwrites it, because the diff classification
that would ever mark a finding as anything else needs the not-yet-built `state/` layer.
Gating on "only new findings" therefore gates on all findings, so `--fail-on high --fail-on-new` and
`--fail-on high` return the same exit code on the same tree, always.
The usage error when `--fail-on` is absent is real and is enforced.

### `--lang py,js,go,java`

Validated as a CSV of the four language names, then never read.
Every SAST run applies every rule pack; `--lang go` and no `--lang` at all produce identical findings.

### `--intensity` and `--allow-intrusive`

Both are wired into the check-selection chain, and neither can change what a shipped run *selects*:
`--intensity` filters on a check's type tag and every check shipped here is tagged `static`, which all
three tiers admit, while `--allow-intrusive` filters on the `intrusive` tag, which no shipped check
carries.
They will start to bite on selection when the DAST checks they were designed for land.

**Their GATE is live today, though, and it will refuse an invocation.**
`--intensity safe` or `--intensity active`, and `--allow-intrusive`, each require the own-your-target
affirmation described in the next section, so `scan.sh dast --target NAME --intensity active` is exit 2
without it.  That refusal is real now, not deferred.

### `--authed`

Parsed for `dast` and `all`, and recorded in `run.json`'s `authorization` object, because an
authenticated active scan reaches state-changing endpoints an unauthenticated crawl never sees and an
authorisation record that cannot distinguish the two is not answering its own question.
Nothing else reads it: there is no authentication anywhere in the tool yet.

### Conservative DAST limits and `--i-own-target`

The four network limits - `requests-per-second`, `request-budget`, `circuit-breaker-failures` and
`circuit-breaker-window` - are resolved through the ordinary CLI > env > file > default chain and then
held to a conservative limit for a running-endpoint scan, inside `lib/http.sh`, at the same chokepoint
the scope gate lives at.  The effective unaffirmed values are 4 requests/second and a per-run budget of
5000.

What happens to a value above one of those limits depends on where it came from, and the split is
deliberate:

| Where the value came from | What happens |
|---|---|
| `config/scanner.conf`, or the built-in default | Clamped down, with one warning and a `limits_clamped` delta in `run.json`. An unedited install therefore always runs, and never has to affirm anything. |
| The command line, or a `SCOURSH_CONFIG_*` environment variable | **Exit 2**, naming `--i-own-target`. scoursh does not run at a number other than the one you asked for. |

To actually raise one, affirm that you own the target:

```sh
scan.sh dast --target NAME --i-own-target NAME
```

Four things about that flag are worth knowing before reaching for it.

- **It must equal `--target`.** A mismatch, or `--i-own-target` with no `--target`, is exit 2 - so a
  stale command, a shell alias, or a CI file copied between repositories cannot carry an affirmation to
  a host that changed hands.
- **It is a key, not a switch.** On its own it raises nothing, sends nothing, and enables no check. It
  makes the higher settings *available*; you still have to ask for each one.
- **It is never persisted.** There is no config key, dotfile, cache or environment variable that means
  "always unrestricted", and there will not be one.
- **It authorises nothing.** A host is scannable if and only if it has a record in `config/scope.conf`
  and every URL, including every redirect hop, passes the gate. The affirmation bounds the *limits*; it
  says nothing about *which hosts* a run may reach.

Two bounds no affirmation lifts: `circuit-breaker-window` cannot go below 60 seconds (a shorter window
counts fewer failures towards the same threshold, which is a weaker breaker) or above 86400 (that one
is arithmetic, not safety).  The budget can be raised but never removed, and the breaker can have its
threshold raised but never be disabled.

A run that did relax something says so on stderr at run start, banners it in the HTML and Markdown
reports, and records the from->to deltas in `run.json`'s `authorization` object - because an
unrestricted run's *absence* of availability findings is not evidence about the target.

### The identifying `User-Agent`

Every request carries `scoursh/<version> (+<contact>)`, or
`scoursh/<version> (+<project-url>; no operator contact configured)` when no contact is set, so a target
owner who notices the traffic can identify the tool and reach whoever ran it.
Set the contact with `--contact` or the `contact` key in `config/scanner.conf`; append an extra product
token with `--user-agent-suffix`.

The `scoursh/<version>` prefix is **not removable at any setting**, and no flag will ever be added to
remove it: an authorised scan has no need to be unidentifiable and an unauthorised one has every need.

### Dependency data (`data/advisories.db`)

`sca` parses every lockfile format it supports, then looks each resolved package up in
`data/advisories.db`.
That file is not in this repository - `data/` ships only `severity-rubric.conf` - so on a stock
checkout `sca` examines nothing at all, whatever the lockfiles contain.
It reports that rather than reporting a clean project: `scan.sh sca` **exits `4`** (missing required
input - the advisory database is `sca`'s, exactly as `config/scope.conf` is `dast`'s), records one
`coverage_reduction module=sca reason=no_advisories_db_on_disk ecosystems=<every ecosystem>` fact in
`run.json`, and puts a `SCA-COV-NO_ADVISORY_DB-01` finding on the report stating that zero dependencies
were checked.
Under `scan.sh all` the same reason and finding are recorded but the exit code is left to the modules
that did run, since a module skipped for absent inputs is a declared reduction rather than a failure.
This is by design rather than an oversight: the scanner never fetches advisory data at scan time.
Build the database on a networked host with `tools/vendor-engines.sh advisories`, or point
`SCOURSH_SCA_ADVISORIES_DB` at one you already have.

## Exit codes

Checked in this fixed order - the first true condition wins, never "worst finding wins":

| Code | Meaning |
|---|---|
| `0` | Clean, or findings all below `--fail-on`. |
| `1` | Findings at or above `--fail-on` (the CI gate). |
| `2` | Usage error (bad flag, bad value, missing required flag). |
| `3` | Scope violation (`dast --target` not found in `config/scope.conf`), or a `--paranoid` connection observed outside the allowlist. |
| `4` | Missing required input (unreadable path, missing config file, missing required command, or `sca` with no `data/advisories.db` - see ["Dependency data"](#dependency-data-dataadvisoriesdb)). |
| `5` | Incomplete run (circuit breaker tripped or the run aborted mid-flight). A run that both trips the breaker and has gated findings exits `5`, not `1` - an incomplete run cannot assert a clean gate result either way. |

The rate limiter, request budget, and circuit breaker described in
["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target) are real and live: a `dast`
run whose target stops answering trips the circuit breaker and exits `5` naming the failure count and
window, and one that spends its whole request budget exits `5` naming that too. Both are per scope
target, checked at every request through `lib/http.sh`'s single chokepoint.

## The scope gate (`dast`)

Plain language: **`dast` will not touch a host you have not explicitly listed.**
Before any request goes out, `--target NAME` must match the `id` of an entry in `config/scope.conf`.
If `config/scope.conf` does not exist at all, the run refuses with exit `4` ("missing required input") -
`dast` cannot even attempt the gate.
If the file exists but has no entry with that `id`, the run refuses with exit `3` ("scope violation") -
the gate itself is refusing.
There is no raw-URL flag that bypasses this: `--target` only ever takes a name, never a URL.
`sast`, `sca`, and `iac` do not need `config/scope.conf` at all.

The gate matches on the normalized `(scheme, host, port)` tuple from the target's `base-url`, plus any
`extra-host` entries.
Path is **not** part of the gate - it only bounds what the crawler will fetch, it is not a safety
boundary.

This gate is live and enforced, and it is worth being clear about what passing it now buys you:
**real HTTP requests to the host you listed.**
A `dast` run that satisfies the gate crawls the target and inspects what comes back, so treat the entry
you write as an authorisation you are prepared to stand behind.
What it does NOT buy you is complete coverage: most of `docs/DESIGN.md` §7 is still unbuilt, and every
absent check is recorded in `run.json` as a `coverage_gap` rather than passing silently.
The repository also ships `config/scope.conf.example` rather than `config/scope.conf`, so on a fresh
checkout every `dast` invocation refuses with exit 4 until you write the real file.

## `--paranoid` - the connection observer (a detector, not a guarantee)

`--paranoid` builds a run-scoped allowlist from exactly four sets: every in-scope target address
`lib/http.sh` actually resolves this run, resolved AWS endpoint addresses for regions actually iterated
(empty, with a stated reason, until region iteration lands), the host's own `/etc/resolv.conf`
nameservers on port 53 plus loopback on any port, and `config/scanner.conf`'s `paranoid-allow` entries.
It then samples this run's own connections and aborts with exit `3` on the first destination it
observes outside that allowlist.

**It works on Linux and on macOS**, through three backends tried in this order:

| Backend | Kind | Where |
|---|---|---|
| `ss` | sampler | Linux |
| `strace -f -e trace=connect` | tracer (only used where an attach is measured to work) | Linux |
| `lsof` | sampler | macOS, and any host that ships it |

The order is not alphabetical and is not an accident.
`strace` is a *tracer*: it sees every `connect()`, including one that opens and closes between two
polls, so where it genuinely works it is the strongest of the three.
`ss` and `lsof` are *samplers* and are exactly as good - and exactly as blind - as each other.
Availability is measured rather than assumed: `lsof` exits `1` both when it matched nothing and when it
was not permitted to look, so the probe opens a loopback socket of its own and requires `lsof` to
report that exact socket back before accepting it.

If none of the three is usable, the run refuses with exit `4` before a single module is dispatched, and
no findings and no reports are written.
It does not degrade to scanning without the observer, and that is deliberate - a `--paranoid` run that
quietly stopped watching would be worse than no flag at all.

**Read this plainly: it is a detector, not a guarantee - on every platform.**
Sampling can miss a connection that opens and closes between two polls.
`tools/run-in-netns.sh` is the actual guarantee: a network namespace whose only route is the declared
scope makes an out-of-scope connection categorically impossible rather than merely observable.
**That tool is Linux-only and has no macOS equivalent** (it needs network namespaces, and
root/`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`).
So on Linux you can have a detector and, separately, a guarantee; on macOS you have the detector and
nothing behind it.
Every `--paranoid` run states this same limitation in its own `run.json`, so the report never
overstates what the flag proved.

## Configuration

Both config files use the same on-disk record format: blank-line-separated `key: value` blocks, one
`#`-prefixed comment per line, no escaping in values.
Never hand-edit these with tooling that assumes shell syntax - the loader parses them as data and never
`source`s them.
Neither file is committed to this repository; `config/` ships `scope.conf.example` and
`scanner.conf.example`, which you copy and edit.

### `config/scope.conf` - required only for `dast`

One record per target.

| Key | Required | Repeatable | Default | Value |
|---|---|---|---|---|
| `id` | yes | no | - | Target name used by `--target`. Pattern `^[a-z][a-z0-9-]*$`. Must be the first field. |
| `base-url` | yes | no | - | `https://host[:port][/path]`. Scheme must be `http` or `https`. |
| `extra-host` | no | yes | none | Additional `host[:port]` in scope for this target. |
| `allow-subdomains` | no | no | `false` | `true`/`false`. |
| `allow-private-addresses` | no | no | `false` | `true`/`false`. Gates the link-local/loopback deny list. |
| `notes` | no | no (multi-line) | empty | Free text. |

Every key here that affects behaviour is live: `id`, `base-url`, `extra-host`, `allow-subdomains`, and
`allow-private-addresses` are all consumed by the scope gate, which is enforced today.
`notes` is free text that no code reads, exactly as intended.

### `config/scanner.conf` - optional; an absent file behaves as if it contained only `id: scanner`

Resolution order for every key that is read at all, checked independently per key: **CLI flag >
environment variable > file > built-in default**.
The environment variable for key `foo-bar` is `SCOURSH_CONFIG_FOO_BAR`.
An inert key is either never asked for at all, or asked for and then discarded, so setting its
environment variable is exactly as inert as setting it in the file.

The **Status** column means the same thing it means everywhere else in this document.
An inert key is accepted by the record format and validated on load, and then no code asks for its
value, so editing it changes nothing.
Several of the inert keys name a limit that does exist internally and is simply not wired to this
file yet; those are called out in the Notes column.

| Key | Value | Default | Status | Notes |
|---|---|---|---|---|
| `requests-per-second` | decimal, may be fractional | `4` | live | The token-bucket limiter in `lib/http.sh`, shared across workers. Held to 4/s for a DAST scan without `--i-own-target`; see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target). |
| `jobs` | positive integer | `4` | inert | Every run is single-worker. See [`--jobs N`](#--jobs-n-and-the-jobs-config-key). |
| `http-timeout` | positive integer (seconds) | `20` | inert | The HTTP layer's timeout reads `SCOURSH_HTTP_TIMEOUT`, never this file. |
| `max-redirects` | non-negative integer | `5` | inert | The redirect cap is a caller-supplied argument defaulting to 5, never read from this file. |
| `request-budget` | positive integer, per run | `20000` | live | Per-run, shared across workers; exhausting it stops the run at exit 5. Clamped to 5000 for a DAST scan without `--i-own-target`, so this default is not what a DAST run spends. |
| `circuit-breaker-failures` | positive integer | `10` | live | Failures (transport failure or 5xx) within the window below; reaching it aborts the run at exit 5. Never disableable. |
| `circuit-breaker-window` | non-negative integer (seconds) | `60` | live | Rolling window. Bounded at both ends - never below 60s, never above 86400 - and no affirmation lifts either bound. |
| `fail-on` | severity name or `none` | `none` | live | |
| `min-confidence` | `high\|medium\|low` | `low` | live | |
| `redact-secrets` | `true`/`false` | `true` | live | Governs whether a matched credential is written in the clear. See ["What `redact-secrets` covers"](#what-redact-secrets-covers). |
| `formats` | repeatable, `json\|sarif\|html\|md` | all four | live | Resolved through the same chain as `--format`. See [SARIF output](#sarif-output). |
| `max-matches-per-file` | positive integer | `200` | live | Read by both the SAST and IaC scanners. |
| `evidence-max-bytes` | positive integer | `512` | inert | Truncation is real, but reads `SCOURSH_EVIDENCE_MAX_BYTES`, not this file. |
| `scratch-dir` | absolute path | `${TMPDIR:-/tmp}` | inert | The scratch directory follows `SCOURSH_SCRATCH_BASE`, else `TMPDIR`. |
| `state-retain-runs` | positive integer | `30` | inert | There is no `state/` to retain runs in yet. |
| `history-window-days` | positive integer | `365` | live | Bounds `sast --history`. |
| `history-max-commits` | positive integer | `5000` | live | Bounds `sast --history`. |
| `lock-stale-seconds` | positive integer | `30` | inert | The staleness rule is real, but reads `SCOURSH_LOCK_STALE_SECONDS`. |
| `mutex-timeout-seconds` | positive integer | `120` | inert | The timeout is real, but reads `SCOURSH_MUTEX_TIMEOUT_SECONDS`. |
| `paranoid-allow` | repeatable, `addr:port` | empty | live | The fourth allowlist set for `--paranoid`. |
| `contact` | one printable, space-free token | empty | live | Where a target owner can reach you. Rendered into the `User-Agent` every request carries; see ["The identifying `User-Agent`"](#the-identifying-user-agent). |
| `recommended-header` | repeatable, an RFC 7230 header field-name | the shipped `modules/dast/passive/recommended-headers.txt` list | live | The `passive/headers.sh` `DAST-HDR-RECOMMENDED_MISSING-01` roll-up. Any entry here replaces the shipped list entirely, rather than adding to it; a name a dedicated check already owns is dropped. Falls back to `SCOURSH_DAST_RECOMMENDED_HEADERS_FILE`, then the shipped list, when unset here. |
| `notes` | free text (multi-line) | empty | inert by design | Free text for the operator; no code reads it, and none is meant to. |

### What `redact-secrets` covers

`redact-secrets: true` is the default, and it means the same thing in every output the run produces:
**a check whose job is finding a credential never writes that credential.**

It is enforced in two independent layers, because either one alone leaves a real hole.

The first layer is *provenance*.
A finding produced by a secrets check carries a placeholder rather than its matched bytes, decided at
`lib/findings.sh`'s single emission chokepoint, so it holds for every format downstream of the merge -
`findings.jsonl`, `findings.json`, `report.md`, `report.html`, the per-worker shards, and any emitter
added later.
This layer does not consult a pattern list at all, so a new secrets check is covered on the day it
lands rather than on the day somebody remembers to describe its shape somewhere else.

The second layer is *shape*, and it is `rules/redaction.rules`.
It masks a credential that turns up incidentally, somewhere the first layer cannot see it: inside
another check's evidence, in a crawled URL's query string, in a log line, or in a title or remediation
supplied by a vendored engine.

The two layers divide the modules between them rather than overlapping everywhere.
`sast` and `iac` findings get both, because there the evidence *is* the matched bytes.
A `dast` finding's evidence is a composed sentence built around bytes the target chose, so masking it
whole would delete the finding and hide no credential - the shape layer is what covers `dast`, and it
covers the two forms a URL actually carries a credential in: a userinfo authority
(`https://user:pw@host`, RFC 3986 §3.2.1) and a credential-bearing query or form parameter
(`?password=...`, `&token=...`).

Redaction applies to every byte the run writes, not only to findings.
That includes `run.json` and the `meta/` facts behind it, and the log lines on stderr - a DAST phase
logs the endpoint it took from the crawler's inventory, and a coverage gap names the endpoint it could
not reach, so both can carry whatever the crawl brought back.

A masked value is rendered `<redacted:KIND:DDDDDDDD>`, where the eight hex characters are a prefix of
the SHA-256 of the raw bytes.
That is what keeps a redacted report actionable: the rule, the file, the line, the title and the
remediation are all still there, two different credentials never render identically, and the same
credential renders identically everywhere it appears, so a reader can say "this is the same secret in
three places" without the secret being in front of them.

#### `redact-secrets: false`

Setting it to `false` writes the matched credential into every report in the clear.
That is a deliberate mode, not a leftover of one code path serving both: an operator rotating a
credential sometimes has to see the literal bytes to find it in a secret store, and a control whose
only setting is "on" is not a control.

It is not a quiet one.
`run.json` records `"redact_secrets": false` for the run, and both `report.md` and `report.html` open
with a warning that the report may contain live credentials and must not be circulated.
An unredacted report is therefore never mistakable for a redacted one, whichever artifact a reader is
handed.

Treat a run's output directory as containing live credentials whenever this is set, and do not commit
it, attach it to a ticket, or paste it into a chat.
