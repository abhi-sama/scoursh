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
That is the trap this column exists to close: `--baseline /typo/path.json` and `--format sarif` both
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
| `dast` | `--target NAME` `[--intensity passive\|safe\|active]` `[--authed]` `[--i-own-target NAME]` | inert as a scanner; its safety layer is live | The scope gate below is real and is enforced before anything else (see "The scope gate"), as are the conservative rate/budget/breaker ceilings and the `--i-own-target` affirmation (see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)). Past those, nothing happens: `modules/dast/run.sh` exists but ships no phase script, so the run records `module=dast reason=no_phase_scripts_on_disk_yet` plus a `coverage_gap` saying no request was sent, and exits 0. |
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
| `--target NAME` | dast, all | live as a gate; the scan it gates does not exist |
| `--intensity passive\|safe\|active` | dast, all | live as a ceiling; the checks it would select do not exist |
| `--authed` | dast, all | recorded in `run.json`'s authorization object; no authentication exists |
| `--i-own-target NAME` | dast, all | live |
| `--live` | cloud, all | live as a precondition check only |
| `--profile NAME` | cloud, all | inert |
| `--regions all\|us-east-1,...` | cloud, all | inert |
| `--assume-role ARN` | cloud, all | inert |

## Global flags (apply to every command)

| Flag | Value | Default | Status |
|---|---|---|---|
| `--profile-scan` | `quick` \| `full` \| `compliance` | `full` | live |
| `--verbose` | boolean | off | live |
| `--paranoid` | boolean | off | live on Linux only |
| `--use-engines` | boolean | off | live, but no engine is vendored here |
| `--allow-intrusive` | boolean | off | live as a gate (needs `--i-own-target`); the checks it would admit do not exist |
| `--contact VALUE` | one printable, space-free token | from `config/scanner.conf` (`contact`), else none | live |
| `--user-agent-suffix TOKEN` | one printable, space-free token | none | live |
| `--jobs N` | positive integer | from `config/scanner.conf` (`4`) | inert |
| `--format` | CSV of `json,sarif,html,md` | all four | inert |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` | from `config/scanner.conf` (`none`) | live |
| `--fail-on-new` | boolean; **requires `--fail-on`**, usage error otherwise | off | inert |
| `--min-confidence` | `high\|medium\|low` | from `config/scanner.conf` (`low`) | live |
| `--baseline FILE` | path | none | inert |
| `--out DIR` | path | `reports/<timestamp>` | live |

`--verbose` also prints the rule-authoring lint warnings a normal run keeps out of the way.
`--use-engines` is fully wired, but it only has an effect once an optional engine has been vendored
into `modules/<module>/adapters/<engine>/` by hand on a networked host; no engine binary is committed
to this repository, so on a stock checkout the flag produces a
`coverage_reduction reason=engine_not_vendored` line and nothing else.

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

Accepted as a value flag with no validation beyond being non-empty, and then never read.
A path that does not exist is accepted with no error and no warning, the file is never opened, and
the value is not recorded in `run.json`.
Nothing is suppressed by it.
The concrete failure this invites: a CI pipeline with a typo in the baseline path gets a clean exit
and no trace anywhere that suppression never ran.
Baseline suppression needs the not-yet-built `state/` layer.

### `--format` and the `formats` config key

The list is validated, resolved through the full CLI-over-environment-over-file-over-default chain,
and then discarded.
Every scan - `sast`, `sca`, `iac`, `all` - writes exactly the same five files regardless of what is
passed: `findings.json`, `findings.jsonl`, `report.md`, `report.html`, and `run.json`.

`sarif` is accepted as a value, and no SARIF is produced.
There is no SARIF writer anywhere in the tool; the name is a legal config value and nothing more.
Do not point a SARIF-consuming CI step at a `scoursh` run yet.

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

One caveat on `5`: the rate limiter, request budget, and circuit breaker are not built yet, and no
module records an aborted-mid-flight reason, so no scan trips either half of that description today.
The code is currently produced only by an internal consistency failure, which should never happen and
is a bug if it does.

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

This gate is live and enforced, and it is worth being clear about what passing it currently buys you:
nothing yet runs behind it.
A `dast` run that satisfies the gate makes no requests, because the DAST module is unbuilt.
The repository also ships `config/scope.conf.example` rather than `config/scope.conf`, so on a fresh
checkout every `dast` invocation refuses with exit 4 until you write the real file.

## `--paranoid` - the connection observer (a detector, not a guarantee)

`--paranoid` builds a run-scoped allowlist from exactly four sets: every in-scope target address
`lib/http.sh` actually resolves this run, resolved AWS endpoint addresses for regions actually iterated
(empty, with a stated reason, until region iteration lands), the host's own `/etc/resolv.conf`
nameservers on port 53 plus loopback on any port, and `config/scanner.conf`'s `paranoid-allow` entries.
It then samples this run's own connections (`ss`, or a measured-usable `strace -f -e trace=connect`
fallback) and aborts with exit `3` on the first destination it observes outside that allowlist.
If neither `ss` nor a usable `strace` exists on the host, the run refuses with exit `4` rather than
pretending to be watching.

**In practice this makes `--paranoid` a Linux-only flag.**
Both backends are Linux-only, so on macOS the refusal above is what always happens: the run exits `4`
before a single module has been dispatched, and no findings and no reports are written.
It does not degrade to scanning without the observer, and that is deliberate - a `--paranoid` run that
quietly stopped watching would be worse than no flag at all.
Plan for it in CI: a matrix leg that passes `--paranoid` on macOS fails every time.

**Read this plainly: it is a detector, not a guarantee.**
Sampling can miss a connection that opens and closes between two polls.
`tools/run-in-netns.sh` is the actual guarantee: a network namespace whose only route is the declared
scope makes an out-of-scope connection categorically impossible rather than merely observable
(Linux-only, requires root/`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`).
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
| `redact-secrets` | `true`/`false` | `true` | live | |
| `formats` | repeatable, `json\|sarif\|html\|md` | all four | inert | See [`--format`](#--format-and-the-formats-config-key). |
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
| `notes` | free text (multi-line) | empty | inert by design | Free text for the operator; no code reads it, and none is meant to. |
