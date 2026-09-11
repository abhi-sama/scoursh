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
That is the trap this column exists to close: `--lang py,js,go,java` and `report --from DIR` before
it was built both used to look exactly like they worked.

[Accepted but not yet implemented](#accepted-but-not-yet-implemented) gives the precise behaviour of
every inert entry, and is the section to read before wiring `scoursh` into CI.

`scan.sh <command> --help` (or `-h`) prints that command's own accepted flags plus a plainly-stated
build status line - generated from the same on-disk check `scan_dispatch` itself uses, so it can
never claim a status the code disagrees with. It is a good first check, but it is terser than this
document: read the tables below for the exact per-flag behaviour behind that one status line.

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
| `dast` | `--target NAME` `[--intensity passive\|safe\|active]` `[--authed]` `[--i-own-target NAME]` `[--openapi\|--har\|--postman\|--graphql-schema FILE]` | live - **it sends real requests** | The scope gate below is enforced before anything else (see "The scope gate"), as are the conservative rate/budget/breaker ceilings and the `--i-own-target` affirmation (see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)). Every module `docs/DESIGN.md` §7 describes has landed (`docs/STEP5-DAST-PLAN.md`, DAST-01 through DAST-36): authentication and crawling, every passive check (headers, cookies, TLS, CORS, information leakage, mixed content), safe-active checks (content discovery, method enumeration), the full injection family gated at `--intensity active` (SQLi, XSS, command injection, path traversal, SSTI, NoSQLi, LDAPi, CRLF, XXE/SSRF, prototype pollution, open redirect, host-header injection), and the application-layer tier (GraphQL introspection, rate-limiting, JWT, object-level authorization/IDOR). `--intensity` genuinely gates which phases and checks run (not merely a ceiling that nothing tests, unlike the static modules below); a phase this run's intensity or authorization does not reach is recorded in `run.json` as a `coverage_gap`/`coverage_reduction` with its reason, rather than silently omitted. |
| `network` | `--target NAME` `[--intensity passive\|safe\|active]` `[--i-own-target NAME]` | live - **it opens real TCP connections** | Service-posture scanning over the DECLARED listener set `config/scope.conf`'s `base-url`/`extra-host` entries name for `--target` - never a port sweep or host discovery: a port scoursh was not told about is never probed. Gated by the identical scope chokepoint, ceilings, and `--i-own-target` affirmation `dast` uses - one TCP connect costs exactly what one HTTP request costs against the same limiter/budget/breaker. `--intensity` gates phases exactly as it does for `dast`: `passive` (default) reaches banner reads and TLS identification on non-`base-url` listeners plus transport-posture checks, `safe` additionally reaches the three-state reachability probe and HTTP identification on non-standard ports. All six phases (`inventory.sh`, `reachability.sh`, `banner.sh`, `tlsport.sh`, `httpport.sh`, `transport.sh`) are implemented (`data/scoursh-network-scan-design/report.md` §7, NET-01 through NET-11); a target whose `config/scope.conf` entry declares only `base-url` (no `extra-host` listener) records a `coverage_gap` rather than a clean scan, since there is nothing beyond the web port to test. `--jobs N` is also this module's ceiling on simultaneous connections. Unlike `dast`, it accepts no `--requests-per-second`/`--request-budget`/`--circuit-breaker-failures`/spec-file flags - those are DAST's own rate/discovery knobs and have no equivalent here. An operator-declared `expect-closed` expectation in the optional `config/posture.conf` (`scope-key: target:port`) is what lets `NET-PORT-UNEXPECTED_LISTENER-01` fire on a declared listener that should not be answering; absent that file it is a declared skip, never exit 4. |
| `cloud` | `[--live]` `[--profile NAME]` `[--regions all\|us-east-1,...]` `[--assume-role ARN]` `[--i-own-account ID]` | live - **it makes real read-only AWS API calls** | `--live` requires the `aws` CLI on `PATH` and resolvable credentials, and the run refuses (exit 4) if either is missing. Every one of `docs/DESIGN.md` §8.1's 30 AWS services (`modules/cloud/aws/live/*.sh`) is implemented - 112 checks, CIS AWS Foundations Benchmark v3.0.0 and OWASP mapped. `regions.sh` resolves the account's enabled regions (or the `--regions` list, unvalidated against the account) and every AWS call goes through `lib/awscli.sh`'s `aws_ro`, which refuses anything that is not read-only. `--assume-role ARN` scans a second account; `--profile NAME` selects a named AWS CLI profile. An access-denied, opted-out, or throttled service is recorded as a `coverage_reduction`, never folded into a clean pass. The `posture/` phase (SSO/edge/session drift against an operator-declared baseline, `config/posture.conf`) has a config schema but no checks yet, so it is a declared skip today. |
| `image` | `--image ID` `[--source PATH]` | live, needs an advisory database for OS-package/dependency matching | Offline installed-package enumeration and CVE matching against a **built** container image - `ID` names an `id` record in `config/images.conf` pointing at a `docker save` tarball (`source: docker-archive`) or an OCI image-layout directory (`source: oci-layout`); never a registry pull, and `--image` is the only required flag. `--source PATH` overrides the configured path for this run only (the shape is inferred from the filesystem - a directory is `oci-layout`, a file is `docker-archive`); with no `config/images.conf` record for `ID` at all, `--source` is the only way to run. Enumerates and matches apk, dpkg, and rpm packages (rpm needs `sqlite3` on `PATH` - its package database is a binary format, a declared coverage reduction rather than a silent skip when absent), plus language dependencies found at a bounded set of conventional manifest locations inside the image's own rootfs (reusing `sca`'s tree-walkers). Also reads the image's config blob for its effective runtime user, exposed ports, and whether its recorded base reference is a mutable tag - these three checks need no advisory database and run on every opened image regardless of distro. No advisory data for the image's release is `IMAGE-COV-NO_ADVISORY_DB-01` and exit `4` when `image` is the selected command (a declared skip under `all`, per the identical SCA precedent). `--format agent` works here the same as every other module. See ["Dependency data"](#dependency-data-dataadvisoriesdb) and `docs/CHECKS.md`'s "Container image" section. |
| `all` | union of every module's own flags above | live | Runs sast, sca, iac unconditionally; runs dast and network only if `--target` is given (network under the identical condition dast uses - it never gets a separate authorization record, since the two share one `--target`/`--intensity`/`--i-own-target` triple), image only if `--image` is given, and cloud only if `--live` is given. Every module it skips is recorded in `run.json` as a `coverage_reduction` fact, not silently dropped. |
| `diff` | `--against DIR` | live | `DIR` must name a prior run's output directory (must contain `findings.jsonl` or `run.json`). Classifies `state/latest.json` (the most recently completed run) against the state recorded for the named prior run and renders the delta - `new`/`recurring`/`fixed`/`unknown` - into a fresh output directory (`run.json`, `report.md`). Performs no new scan. See [`docs/STEP7-STATE-PLAN.md`](STEP7-STATE-PLAN.md) (STATE-06). |
| `report` | `--from DIR` | live | `DIR` must be a prior run's own output directory (must contain `findings.jsonl` or `run.json`, plus a non-empty `findings.fields` and `meta/`). Regenerates `report.md`/`report.html`/`report.sarif`/`report-audit.html` (honouring `--format`) from that run's own persisted findings and `run.json` (copied byte-for-byte, never recomputed) - no new scan is performed. See ["`report --from DIR`"](#report---from-dir). |

`-h` / `--help` at any position before the first unrecognized token prints usage and exits 0.

### Per-command flags

| Flag | Command | Status |
|---|---|---|
| `--path DIR` | sast, sca, iac, all | live |
| `--lang py,js,go,java` | sast, all | inert |
| `--history` | sast, all | live |
| `--target NAME` | dast, all | live as a gate, and the scan it gates now runs |
| `--intensity passive\|safe\|active` | dast, all | live; `passive` (default) reaches auth/crawl and every passive check (headers, cookies, TLS, CORS, leakage, mixed content), `safe` additionally reaches content discovery and method enumeration, `active` additionally reaches every injection probe and the application-layer tier (GraphQL, rate-limiting, JWT, authorization/IDOR) |
| `--authed` | dast, all | live - `auth.sh` acquires a session, and a failed login is a declared coverage reduction rather than an error |
| `--i-own-target NAME` | dast, all | live |
| `--requests-per-second N` | dast, all | live; raising it above the conservative ceiling needs `--i-own-target` (see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)) |
| `--request-budget N` | dast, all | live; same as above |
| `--circuit-breaker-failures N` | dast, all | live; same as above - useful for a target that answers an unmatched path with 5xx rather than 404, which can otherwise trip the default 10-failures/60s ceiling during discovery/methods before the injection phase runs |
| `--openapi FILE` | dast, all | live - an ephemeral, this-run-only override of `config/discovery.conf`'s `openapi-path` for `--target`; nothing is written to that file. Requires `--target`, exit 2 otherwise. See ["`config/discovery.conf`"](#configdiscoveryconf---optional-feeds-dasts-crawler-an-applications-real-api-surface) if a run told you the target "looks like a single-page app". |
| `--har FILE` | dast, all | live; same as above, for `har-path` |
| `--postman FILE` | dast, all | live; same as above, for `postman-path` |
| `--graphql-schema FILE` | dast, all | live; same as above, for `graphql-schema-path` |
| `--target NAME` | network, all | live as a gate, and the scan it gates now runs (byte-identical requirement to dast's own `--target`) |
| `--intensity passive\|safe\|active` | network, all | live; `passive` (default) reaches banner disclosure, TLS identification on non-`base-url` listeners, and transport-posture checks, `safe` additionally reaches the three-state reachability probe and HTTP identification on non-standard ports. Sharing dast's own `--intensity` value on `all` is deliberate (report.md §9 D6) - it is one authorization, not one per module. |
| `--i-own-target NAME` | network, all | live |
| `--live` | cloud, all | live - runs all 30 AWS service checks against the resolved account/regions |
| `--profile NAME` | cloud, all | live - selects a named AWS CLI profile |
| `--regions all\|us-east-1,...` | cloud, all | live - narrows the enabled-region list; an explicit list is not validated against the account |
| `--assume-role ARN` | cloud, all | live - scans a second account via STS, recorded in `run.json`'s authorization block |
| `--i-own-account ID` | cloud, all | live - optional affirmation; when given, must match the resolved account id (mismatch is exit 2) |
| `--image ID` | image, all | live as a gate (`scan_die_usage`, exit 2, if missing on `image`), and the scan it gates now runs; `all` skips `image` entirely (a declared coverage reduction) when it is absent |
| `--source PATH` | image, all | live; overrides `config/images.conf`'s configured path for this run only, with the `docker-archive`/`oci-layout` shape inferred from the filesystem when `ID` has no config record at all |

## Global flags (apply to every command)

| Flag | Value | Default | Status |
|---|---|---|---|
| `--profile-scan` | `quick` \| `full` \| `compliance` | `full` | live |
| `--verbose` | boolean | off | live |
| `--paranoid` | boolean | off | live on Linux (`ss`/`strace`) and macOS (`lsof`) |
| `--use-engines` | boolean | off | live, but no engine is vendored here |
| `--allow-intrusive` | boolean | off | live as a gate (needs `--i-own-target` too, for dast/all); no shipped check is tagged `intrusive` today, so it admits nothing yet except turning DAST's live user-enumeration probe on - which is itself not built and records why it did nothing |
| `--contact VALUE` | one printable, space-free token | from `config/scanner.conf` (`contact`), else none | live |
| `--user-agent-suffix TOKEN` | one printable, space-free token | none | live |
| `--jobs N` | positive integer | from `config/scanner.conf` (`4`) | live - real worker parallelism for `sast`/`sca`/`iac`, and DAST's in-flight-connection ceiling - see [`--jobs N`](#--jobs-n-and-the-jobs-config-key) |
| `--format` | CSV of `json,sarif,html,md,audit,agent` | `json,sarif,html,md` | live; `sarif` writes a complete, schema-validated document (see [SARIF output](#sarif-output)); `audit` and `agent` are opt-in values that never replace another format - `audit` writes `report-audit.html` alongside `report.html`, `agent` writes `agent-fix.json` (docs/AGENT-FORMAT.md) - see [`--format` and the `formats` config key](#--format-and-the-formats-config-key) |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` | from `config/scanner.conf` (`none`) | live |
| `--fail-on-new` | boolean; **requires `--fail-on`**, usage error otherwise | off | live - gates on `status == new` only when this run's diff against the prior one is usable (see [Persistent run state, diff, and baseline](#persistent-run-state-diff-and-baseline)) |
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

Prefer a point-and-click alternative to either the interactive questionnaire below or hand-typing
flags? [`docs/build.html`](build.html) is a static, offline command builder covering the same surfaces
and flags - it only composes a command string and offers a copy button, and never runs anything itself.

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
| An AWS account, read-only (`cloud`) | **partially wired** | `modules/cloud/aws/run.sh` exists and is reachable at the scan-type menu, but its guided setup beyond the scan type and the CI gate isn't wired into `--guided` yet - only `--fail-on` is asked. The session prints a note saying so and hands back the direct-command equivalent (`scan.sh cloud --live ...`) once you have a target account. |
| Everything this checkout can actually do (`all`) | **partially wired** | Asks path/languages/history exactly like `sast` (when not already given), then the CI gate. It does **not** route through the `dast` target/intensity/affirmation questions, nor the `cloud` account/region questions, at all: `scan.sh all` only runs `dast` when `--target` was already given on the command line before `--guided`, and only runs `cloud` when `--live` was already given - otherwise both are recorded as declared `coverage_reduction` facts, exactly as a non-guided `scan.sh all` with neither flag already does. A guided `all` session is therefore never how an operator first authorises a DAST target or a cloud account; that has to happen through `scan.sh dast --guided` / `scan.sh cloud --guided` (or their own menu items) first. |

**Guided mode never walks through configuring a surface and then runs something not wired up.**
`cloud` is reachable rather than refused, but its account/region questions genuinely aren't composed
yet - the session says so plainly and falls back to naming the direct command, rather than asking
questions it can't yet turn into flags.

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

## Recipes

Task-flow, copy-paste command sequences. Every command below is exact and runnable as written from a
fresh checkout, except where it names a file or directory you supply yourself. The README's own
[Commands & recipes](../README.md#commands--recipes) section is the short version of this; read here
for the reasoning behind each one.

### Per-surface scans

`sast`, `sca`, and `iac` all take a `--path`; `dast` and `network` both take a `--target`; `image` takes
an `--image`. Write each report to its own directory so consecutive scans don't clobber one another:

```sh
./scan.sh sast    --path DIR --format html,audit --out reports/sast
./scan.sh sca     --path DIR --format html,audit --out reports/sca      # needs data/advisories.db - see above
./scan.sh iac     --path DIR --format html,audit --out reports/iac
./scan.sh dast    --target NAME --format html,audit --out reports/dast     # config/scope.conf must authorize NAME first
./scan.sh network --target NAME --format html,audit --out reports/network  # same authorization; scans NAME's declared listener set
./scan.sh image   --image ID --format html,audit --out reports/image      # config/images.conf must name ID first (or pass --source)
```

### A full active-DAST recipe

A bare passive scan against a target it hasn't crawled much of finds relatively little - most of a
real application's surface is API endpoints a static crawl of an HTML page never sees. The recipe that
actually lands injection findings combines three things: an imported API surface, the
`--i-own-target` authorization `--intensity active` requires, and a rate gentle enough not to trip the
target's own resource limits or scoursh's circuit breaker:

```sh
./scan.sh dast \
  --target NAME --i-own-target NAME \
  --intensity active \
  --openapi ./openapi.json \
  --requests-per-second 2 --jobs 2 --circuit-breaker-failures 40 \
  --format json,sarif,html,md,audit \
  --out reports/dast-full
```

- **`--intensity active`** sends real attack payloads and requires `--i-own-target NAME` naming the
  exact same target - see ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target).
- **Import the API surface** with `--openapi`/`--har`/`--postman`/`--graphql-schema` so the scanner
  reaches real endpoints - a single-page application's own routes are close to invisible to a static
  crawl alone (see
  ["`config/discovery.conf`"](#configdiscoveryconf---optional-feeds-dasts-crawler-an-applications-real-api-surface)
  and `docs/DESIGN.md` §7.5).
- **The circuit breaker is a safety feature, not a bug.** It stops the run if the target stops
  answering - 10 failures within a 60-second window by default. Against a small or single-process
  target, go gentler than the unaffirmed defaults (`--requests-per-second 2 --jobs 2`, both already
  below the 4/s ceiling so they need no affirmation on their own), and raise
  `--circuit-breaker-failures` (which does need `--i-own-target`, since it is a CLI-supplied value
  above the default 10) if an application that answers an unmatched path with a `5xx` rather than a
  `404` trips it during discovery or method enumeration before the injection phase ever runs.
- **Run one scan at a time against a target.** Concurrent scans multiply the effective request rate
  the target sees and make a circuit-breaker trip more likely for reasons that have nothing to do with
  the target's actual health.

### Everything in one run

```sh
./scan.sh all --path DIR --target NAME --i-own-target NAME --intensity active \
  --openapi ./openapi.json --requests-per-second 2 --jobs 2 --circuit-breaker-failures 40 \
  --format json,sarif,html,md,audit --out reports/all
```

`all` runs every module whose inputs are configured: `--path` drives `sast`/`sca`/`iac`, `--target`
drives both `dast` and `network` together (one shared `--target`/`--intensity`/`--i-own-target`
authorization, never a separate one per module), and `--live` drives `cloud` (30 AWS services,
read-only - see the [`cloud` row](#commands) above). A module `all` skips for missing input is recorded
as a `coverage_reduction`, not silently dropped.

**The gotcha**: see ["The gotcha" under Dependency data](#dependency-data-dataadvisoriesdb) above -
don't point `--path` at a tree containing `data/advisories.db` once you've built it.

### Guided (interactive) mode, quickly

```sh
./scan.sh all --guided                     # walk through the choices; composes and runs a real command
./scan.sh dast --guided --print-command    # walk through the choices, then print the command instead of running it
```

At the languages prompt (`Limit to which languages? (py,js,go,java, comma-separated) [all]:`),
pressing **Enter** accepts the bracketed default and scans every language; typing the literal word
`all` is rejected (`scan_validate_flag_value` only accepts `py`, `js`, `go`, `java`, singly or
comma-separated) and re-prompts. See ["Flag equivalence"](#flag-equivalence) above for every other
prompt's non-interactive form.

### Optional specialist engines for extra depth

```sh
tools/vendor-engines.sh <engine>      # semgrep | gitleaks | trivy - you supply and pin version+URL+sha256
./scan.sh sast --path DIR --use-engines    # sast: adds semgrep (broader rules) and gitleaks (secrets)
./scan.sh iac  --path DIR --use-engines    # iac: adds trivy config (broader misconfiguration coverage)
```

`--use-engines` only has an effect once the named engine's vendored binary and ruleset are actually
present on disk; absent, it is a silent no-op - never an error, and never a reason a scan behaves any
differently from one without the flag. Nothing is fetched at scan time, whatever the flag is given.

## `--format` and the `formats` config key

The list is validated, resolved through the full CLI-over-environment-over-file-over-default chain,
and then honoured: `lib/report.sh`'s `report_all` gates `findings.json`, `report.md`, `report.html`
and `report.sarif` on it, so `--format md` writes the Markdown report and none of the other three.

`findings.jsonl` and `run.json` are **not** `--format` values.
They are mandatory per-run records - the incremental ledger and the audit record - and are written on
every run whatever `--format` asked for, so they are not evidence that the flag was ignored.

`--format sarif` writes `report.sarif`, documented in full in the next section.

`--format audit` (or `audit` added to a multi-value `--format`/`formats` list) writes
`report-audit.html`, an opt-in fifth value that is **never** in the default list and never replaces
`report.html` - it is written alongside it. It is a per-category (sast/sca/iac/dast/cloud) coverage
report built for a reader auditing the run itself, not for triage: every registered check lands in
exactly one of four states - it found something, it ran and found nothing, it did not run (with the
run's own recorded reason), or it is unaccounted for (registered, not run, no reason recorded, which
is never folded into "clean") - and every not-run check is listed individually with its reason rather
than only a count. `scan.sh <cmd> --format json,html,audit` writes `report.html` and
`report-audit.html` side by side.

`--format agent` (or `agent` added to a multi-value `--format`/`formats` list) writes
`reports/<run>/agent-fix.json`, a compact JSON findings file built for a downstream AI fixing agent
rather than a human reader. It is an opt-in sixth value, **never** in the default list and never
replacing any other format. Unlike every other emitter it does not carry every field - it drops what a
fixing agent never reads (`fingerprint`, `cvss`, timestamps, `contributors`, ...) and, where scoursh can
derive one, includes a deterministic fix scaffold (an SCA dependency-version bump, an IaC config
one-liner, or a cloud remediation command **labeled as a suggestion the tool never runs itself**).
The full field-by-field contract - what is promoted into the shared per-check catalogue, the four
`fixability` states, and the honesty header that keeps "did not check" from ever reading as "clean" -
is [`docs/AGENT-FORMAT.md`](AGENT-FORMAT.md).

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

## Persistent run state, diff, and baseline

[`docs/STEP7-STATE-PLAN.md`](STEP7-STATE-PLAN.md) (STATE-01 through STATE-08) is complete: every
normal scanning run (`sast`/`sca`/`iac`/`dast`/`cloud`/`all`) persists `state/<run-id>.json` and
`state/latest.json` at the end of the run, and automatically classifies every finding against the
prior run's state before its own gate is evaluated.

- **Automatic classification** - every finding gets a `status` of `new`, `recurring`, `fixed`, or
  `unknown` (a prior finding whose own `(check, cell)` was not covered this run - never assumed fixed
  just because it did not reappear). `run.json`'s `counts.by_status` and the HTML/Markdown report's
  "Since last scan" section both carry the breakdown; a `fixed` history-secret finding, a rule-digest
  change, and a schema/`scan_root_id` mismatch that makes the whole diff unusable are each called out
  in that section's own prose, not only in the raw JSON.
- **`diff --against DIR`** - `DIR` must be a prior run's own output directory. Classifies
  `state/latest.json` (the most recently completed run) against the state recorded for the named
  prior run and renders the delta into a fresh output directory. Performs no new scan of its own.
- **`report --from DIR`** - see ["`report --from DIR`"](#report---from-dir) below; regenerates a
  prior run's report artifacts with no reclassification and no new scan.
- **`--baseline FILE`** - suppresses findings whose fingerprint matches an entry in
  `config/baseline.json`, or in `FILE` when `--baseline` is given (which **replaces** the default file
  rather than adding to it). An entry is either a bare fingerprint string, or an object
  `{"fingerprint": "…", "reason": "…", "added": "YYYY-MM-DD", "expires": "YYYY-MM-DD"}`
  (`docs/FOUNDATION.md` tension 11's frozen schema; a bare string is `reason: ""`, `added`/`expires:
  null`). Suppression is an annotation, never a deletion: a matched finding still appears in every
  output format, with `suppressed: true` and its reason, in a collapsed "accepted risk" section, and
  is excluded from every count and from `--fail-on`/`--fail-on-new`. An entry whose `expires` date has
  passed stops suppressing, and the report says so; an entry that matches no finding this run is
  reported `stale` in `run.json` and in the report - which is also how a finding that was baselined and
  then genuinely fixed is still reported `fixed` rather than silently staying suppressed forever.
  A `--baseline` path that does not exist is a real error (`exit 4`), not a clean exit with suppression
  silently never having run; a default `config/baseline.json` that is simply absent - the ordinary case
  for a fresh checkout - is not an error at all. A baseline file that exists but cannot be read, or is
  not well-formed, is also a real error, rather than being treated as an empty baseline - unlike this
  tool's own `state/`, which degrades gracefully on corruption, because `config/baseline.json` is a
  human-edited accept-risk list and silently misreading it, in either direction, is the one outcome
  this mechanism exists to rule out.
- **`--fail-on-new`** - requires `--fail-on` (a real usage error otherwise). Gates on
  `suppressed == false` and `confidence >= --min-confidence` and, once `--fail-on-new` is given,
  `status == new` **if and only if** this run's diff against the prior one was usable
  (`diff_usable`); when the diff was not usable (no prior state, an `fp_schema` mismatch, or - for a
  run whose findings live in `path-root` cells - a `scan_root_id` mismatch), the gate falls back to
  considering every finding, so a broken or absent baseline never silently passes a run that
  `--fail-on` alone would have failed. `scan.sh <cmd> --fail-on high --fail-on-new` and
  `scan.sh <cmd> --fail-on high` therefore agree exactly on a first run, and can disagree once a
  second run has real prior state to compare against.

### `report --from DIR`

`DIR` is validated the same way `diff --against` is (must contain `findings.jsonl` or `run.json`,
plus a non-empty `findings.fields` and `meta/`). The run regenerates `report.md`, `report.html`,
`report.sarif`, and `report-audit.html` (honouring `--format`) from `DIR`'s own persisted
`findings.fields`/`meta/` facts, with no module dispatched and no rescan.

`run.json` is copied byte-for-byte from `DIR` rather than recomputed - several of its fields
(`scan_root_id`, `path_root`, `gate`, `gated_findings`, `diff_usable`) are facts the original scan set
directly and no `meta/` record carries, so recomputing them here would silently replace the original
run's real values with empty defaults. The one field that cannot be byte-identical is
`report.sarif`'s `invocations[].endTimeUtc`, a live timestamp taken at render time - every other
artifact is byte-identical to what the original run wrote.

`SAST-HIST-*` path resolution (whether a history finding's file still exists in the working tree) is
**not** re-checked: that needs a real `--path` this command does not take, so `findings.fields`'s
already-decided verdict from the original scan is used as-is.

`--out` given the same path as `--from` (in-place regeneration) is supported.

Report file generation *during* a scan is a separate thing that always worked: every `sast`/`sca`/
`iac`/`dast`/`cloud`/`all` run already writes `findings.json`, `findings.jsonl`, `report.md`,
`report.html`, and `run.json` (plus `report.sarif` and `report-audit.html` if asked) as part of the
scan itself. `report --from DIR` is the separate ability to rebuild those files from an earlier run's
own directory after the fact, with no reclassification.

### `--jobs N` and the `jobs` config key

**Live for `sast`, `sca` and `iac`.** The resolved value (default 4) is the number of workers the
tree walk fans out over: `sast` and `iac` split the file list, `sca` splits the manifest/lockfile
list, and each worker writes its own finding shard. Never more workers than there are units of work,
so a two-file scan at `--jobs 8` runs two workers rather than forking six with nothing to do.

**The output does not depend on the width.** A run at `--jobs 4` produces byte-identical
`findings.jsonl`, `findings.json` and rendered findings to the same run at `--jobs 1` - the merge
sorts every shard together under `LC_ALL=C` by (module, check id, fingerprint), so neither the
partition nor the scheduling can reach the bytes. `run.json` and the two reports do differ in one
place, deliberately: they record how wide the fan-out actually was, as
`coverage_reduction module=<m> reason=single_worker jobs=1 ...` on a single-worker run and
`notes module=<m> parallel scan: N workers over ...` on a parallel one. (The flat
`single_worker_no_parallel_scan_yet` reduction those replaced is gone.)

**A worker that dies is reported, not swallowed.** Part of the tree going unscanned would otherwise
look exactly like a clean result, so a lost worker makes the run exit `5`
(`SCOURSH_EXIT_INCOMPLETE`) with an `incomplete_reason` naming `parallel_worker_failed`, and the run
records no coverage for that cell - a cell a worker abandoned must never let a later run infer the
findings it never reached as `fixed`. The report is still written.

For `dast`, the same number means something different and is unchanged by any of the above:
`lib/http.sh`'s tension-16 in-flight-connection ceiling uses the resolved `jobs` value as how many
simultaneous connections a target may see (held to 4 without `--i-own-target`). Since no DAST phase
spawns additional workers, that ceiling still has nothing to bound above 1 concurrent connection
today. Raising `--jobs` above 4 for a DAST scan therefore still needs `--i-own-target`, and still
does not make the scan any more parallel.

## Accepted but not yet implemented

Everything in this section parses, validates, and is accepted today.
None of it changes the outcome of a run.

### `--lang py,js,go,java`

Validated as a CSV of the four language names, then never read.
Every SAST run applies every rule pack; `--lang go` and no `--lang` at all produce identical findings.

### `--intensity` and `--allow-intrusive` outside `dast`/`network`

`--intensity` is only accepted by `dast`, `network`, and `all` (`sast`/`sca`/`iac` on their own reject
it as a usage error); `--allow-intrusive` is a global flag every command accepts.
Both are wired into the same check-selection chain `dast` uses, so under `scan.sh all` they also pass
over sast/sca/iac's own checks - but neither changes what gets selected there: `--intensity` filters on
a check's type tag and every non-DAST/non-network check shipped here is tagged `static`, which all
three tiers admit, while `--allow-intrusive` filters on the `intrusive` tag, which no shipped check
anywhere carries yet. For `dast` and `network`, both are live and do gate real check selection - see
the per-command flags table above and ["Conservative DAST limits"](#conservative-dast-limits-and---i-own-target)
below for the details.

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
threshold raised but never be disabled - `--circuit-breaker-failures N` plus `--i-own-target` is the
flag for that, useful against a target that answers an unmatched path with a 5xx rather than a 404
(the default 10-failures/60s ceiling can otherwise trip during discovery/methods before the injection
phase ever runs, on an application that is healthy but idiosyncratic rather than actually failing).

A run that did relax something says so on stderr at run start, banners it in the HTML and Markdown
reports, and records the from->to deltas in `run.json`'s `authorization` object - because an
unrestricted run's *absence* of availability findings is not evidence about the target.

`network` reaches the identical chokepoint and the identical ceilings - one TCP connect draws down the
same rate/budget/breaker state one HTTP request does - but exposes no `--requests-per-second`/
`--request-budget`/`--circuit-breaker-failures` flags of its own; `--i-own-target NAME` still applies,
since the underlying `lib/http.sh` state is shared rather than duplicated per module.

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
That file is not in this repository - `data/` ships only `severity-rubric.conf` and
`owasp-categories.conf`, neither of which is a dependency database - so on a stock checkout `sca`
examines nothing at all, whatever the lockfiles contain.
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

#### Building it: the one command

```sh
tools/vendor-engines.sh advisories bulk --accept-unverified --all
```

Run this on a **networked box** - it is the one script in the whole tool permitted to touch the
network, and it is never called during a scan. It needs `python3` and `curl` on that box only;
neither is a `scan.sh` runtime dependency.

Measured on a clean checkout: **~2 minutes**, **~290 MB downloaded** (OSV.dev's six per-ecosystem
export archives), **~940 MB written** to `data/advisories.db` and `data/versions.db` combined. The
archives themselves are not kept - they live under `$SCOURSH_SCRATCH` and are erased when the command
exits, successfully or not. It ends by printing a per-ecosystem table (ecosystem, grade, rows
imported, and a `range_only_skipped` percentage) - that table, not silence, is how you know it worked.
A failed ecosystem is marked `FAILED` there and the command exits non-zero, rather than leaving you
with a database that silently covers less than it claims.

There are two ways to build it - bulk, above, which is what you almost certainly want, and one
advisory at a time, below, when you already know the specific IDs you care about.

**Bulk.** `advisories bulk` imports a whole ecosystem's published export in one command, or all six
with `--all`. Because that export is rebuilt upstream continuously, there is no fixed checksum to pin,
so an import whose content was not verified refuses until you pass `--accept-unverified`. Every import
prints the integrity grade it achieved and records the digest of exactly what it fetched into the
database header, so you can pin that digest with `--sha256` next time.

```sh
# All six ecosystems in one shot.
tools/vendor-engines.sh advisories bulk --accept-unverified --all
# ...or just the one ecosystem you care about right now.
tools/vendor-engines.sh advisories bulk --accept-unverified npm
# ...or pin the exact bytes, once you know the digest you want.
tools/vendor-engines.sh advisories bulk --sha256 <hex> npm
```

**One advisory at a time**, when you already know the specific IDs you care about. You supply them
per ecosystem and `advisories <ecosystem>` resolves just those. Here `--all` means "every ecosystem
you have supplied an ID list for", not "every known advisory".

```sh
export SCOURSH_ADVISORY_NPM_IDS="GHSA-xxxx-xxxx-xxxx,GHSA-yyyy-yyyy-yyyy"
tools/vendor-engines.sh advisories npm
# or, once an ID list is set for each ecosystem you care about:
tools/vendor-engines.sh advisories --all
```

See [`tools/vendor-engines.sh advisories --help`](../tools/vendor-engines.sh) for the full list of
per-ecosystem environment variables.

**`scan.sh image` reads the same two files, through four more ecosystems that are deliberately NOT
part of `--list`/`--all`/`bulk --all` above: `alpine`, `debian`, `ubuntu`, and `redhat`.** Each is
its own named subcommand, one-advisory-at-a-time only (no bulk import exists for these yet - a stated
gap, not an oversight):

```sh
export SCOURSH_ADVISORY_ALPINE_IDS="CVE-2023-xxxxx,CVE-2023-yyyyy"
tools/vendor-engines.sh advisories alpine
# debian/ubuntu/redhat take SCOURSH_ADVISORY_DEBIAN_IDS / _UBUNTU_IDS / _REDHAT_IDS the same way
```

Without a row for the image's own distro release (Alpine and Debian/Ubuntu are keyed per release,
e.g. `Alpine:v3.18`; Red Hat's OSV.dev namespace is one flat `Red Hat` key with no per-release
suffix), `scan.sh image` reports `IMAGE-COV-NO_ADVISORY_DB-01` and exits `4` rather than a clean
scan - the identical `sca` precedent above, one module over. The three `IMAGE-CFG-*` config-blob
checks (effective runtime user, exposed ports, mutable base reference) need none of this and always
run once an image opens. Matching an installed **rpm** package additionally needs `sqlite3` on
`PATH` - its package database is a binary format no text tool can read - and its absence is its own
declared coverage reduction (`rpm_db_binary_format`), never folded into a silent clean pass.

**Read the `range_only_skipped` percentage in that table - it is coverage, not a progress bar.**
OSV.dev's own advisory records do not all carry an explicit list of affected versions. Where one lists
only a semver *range* instead, `docs/FOUNDATION.md` tension 25's design refuses to guess a concrete
version from it, so that advisory is not represented in the database at all. The percentage is exactly
how much of that ecosystem was left out for this reason - it is not an import problem. Measured on a
full `--all` import: **npm ~89%** and **Go ~98%** of the affected-package entries OSV.dev publishes for
those two ecosystems are range-only and absent from the database, versus **RubyGems ~0%**, **Composer
~9%**, **Maven ~13%**, and **PyPI ~23%**. Concretely, a fresh npm import is dominated by
single-version malicious-package listings (OSV's `MAL-*` ids), not classic CVEs in popular packages: of
npm's own rows, over 99% are `MAL-*` and under 1% are `GHSA-*`/`CVE-*`, covering a few hundred distinct
legitimate packages. An npm-only scan against a real project is very unlikely to flag an outdated
dependency with a well-known CVE, even immediately after a fresh, successful import - that is a
limitation of npm's own OSV.dev export today, not a broken build.

**The gotcha: do not scan `data/` itself with `sast` or `all --path .` after building the database.**
`data/advisories.db` and `data/versions.db` together land at roughly 940 MB. If your `--path` includes
this repository's own `data/` directory (for example, `./scan.sh all --path .` run from a checkout
where you just built the database), `sast` will walk that multi-hundred-megabyte binary file like any
other source file, producing noise and a very slow run for no security value. Point `--path` at real
source you intend to scan, not at this repository's own checkout with the database inside it; if you
must scan a tree that legitimately contains `data/`, exclude it.

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
target, checked at every request through `lib/http.sh`'s single chokepoint - `network` draws from the
identical per-target state, one TCP connect at a time, and can trip the same two exits.

## The scope gate (`dast`, `network`)

Plain language: **`dast` and `network` will not touch a host you have not explicitly listed.**
Before any request or connection goes out, `--target NAME` must match the `id` of an entry in
`config/scope.conf`.
If `config/scope.conf` does not exist at all, the run refuses with exit `4` ("missing required input") -
neither `dast` nor `network` can even attempt the gate.
If the file exists but has no entry with that `id`, the run refuses with exit `3` ("scope violation") -
the gate itself is refusing.
There is no raw-URL flag that bypasses this: `--target` only ever takes a name, never a URL or a bare
`host:port`.
`sast`, `sca`, and `iac` do not need `config/scope.conf` at all.
`network` additionally only ever probes a `(host, port)` tuple the target's own `base-url`/`extra-host`
entries name - it never sweeps a port range or discovers a listener the operator did not declare.

The gate matches on the normalized `(scheme, host, port)` tuple from the target's `base-url`, plus any
`extra-host` entries.
Path is **not** part of the gate - it only bounds what the crawler will fetch, it is not a safety
boundary.

This gate is live and enforced, and it is worth being clear about what passing it now buys you:
**real HTTP requests to the host you listed.**
A `dast` run that satisfies the gate crawls the target, authenticates if asked, and runs every phase
`--intensity` and `--authed` admit - `docs/DESIGN.md` §7's full engine has landed
(`docs/STEP5-DAST-PLAN.md`, DAST-01 through DAST-36) - so treat the entry you write as an
authorisation you are prepared to stand behind. What it does NOT buy you is complete coverage on
every run regardless: a phase your run's own `--intensity`/`--authed`/`--allow-intrusive` did not
reach, or one that had nothing to work with (no inventory, no configured identity), is recorded in
`run.json` as a `coverage_gap`/`coverage_reduction` with its reason, rather than passing silently.
A `network` run that satisfies the gate opens real TCP connections to the declared listener set and
runs every phase `--intensity` admits (`data/scoursh-network-scan-design/report.md` §7, NET-01 through
NET-11 - all six phases are implemented) - treat the entry you write the same way you would for `dast`.
A target whose `config/scope.conf` entry names only `base-url`, with no `extra-host` listener, gives
`network` nothing beyond the web port to test and records a `coverage_gap` rather than a clean scan.
The repository also ships `config/scope.conf.example` rather than `config/scope.conf`, so on a fresh
checkout every `dast` or `network` invocation refuses with exit 4 until you write the real file.

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
**That tool is Linux-only** (it needs network namespaces, and root/`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`); on
macOS its native peers are `tools/run-sandboxed.sh`, Tiers A and B below, which enforce narrower but
still kernel-backed claims, and its full-parity equivalent is Tier C, running the netns tool unmodified
inside a Linux container.
Every `--paranoid` run states its own detector/guarantee limitation in `run.json`, so the report never
overstates what the flag alone proved.

## Enforcement tiers beyond `--paranoid` - `tools/run-sandboxed.sh` and `tools/run-in-netns.sh`

`--paranoid` samples; these two tools make an out-of-scope connection categorically impossible instead
of merely observed. Neither is invoked by `scan.sh` - both are run deliberately, by an operator who
wants a stronger guarantee than sampling can provide.

### Tier A (macOS) - `tools/run-sandboxed.sh`, kernel-enforced deny-all-network

```
tools/run-sandboxed.sh -- scan.sh sast --path .
```

Runs `<command>` under the macOS Seatbelt profile `(version 1)(allow default)(deny network*)` via
`sandbox-exec`: `<command>` and every descendant process it spawns is refused from opening any network
socket at all, by the kernel, before a single packet is sent. This makes the claim above this
section - `sast`/`sca`/`iac` make zero network calls - **kernel-enforced instead of merely asserted**,
for exactly those three modules.

Needs macOS and `sandbox-exec` on PATH; no root, no capabilities - that is this tier's whole advantage
over the netns tool. It fails loud and never degrades: a non-Darwin host, an absent `sandbox-exec`, or a
profile `sandbox-exec` itself rejects each refuse with exit `4` before `<command>` ever runs, rather than
falling through to an unsandboxed run. There is no teardown surface at all - no namespace, no host state
of any kind - so a crashed run leaves nothing behind.

**This is a narrower guarantee than the netns tool's, on purpose.** Seatbelt's network filter accepts
only `*` or `localhost` as a rule's host part, so this profile cannot name the authorised target the way
the netns route table does - only "no network access at all". That is exactly what `sast`/`sca`/`iac`
need and nothing more. Wrapping a `dast`/`cloud`/`network` command in Tier A gets it zero network access
and, most likely, an honest, loud failure on its own first request - use Tier B below for those.

### Tier B (macOS) - `tools/run-sandboxed.sh --scope-conf`, off-host egress kernel-denied plus a loopback relay

```
tools/run-sandboxed.sh --scope-conf config/scope.conf -- scan.sh dast --target my-target
```

This is the mode for `dast`/`cloud`/`network`, which need real traffic to their declared target. It
resolves that scope through `lib/http.sh`'s own scope loader and pinned resolver (the same two functions
the netns tool uses - never a second resolver), starts one loopback forwarder per authorised
`(address, port)` **outside** the sandbox, and emits a profile admitting exactly those relay ports.
`lib/http.sh` then sends every request through them with `curl --connect-to`, which redirects the TCP
connection while keeping the original host for SNI, the `Host:` header and certificate validation.

**What is guaranteed, and by whom - this is a distinct third label, not a full "guarantee".**

- **The kernel** guarantees off-host egress is categorically impossible. Every process in the tree,
  every `xargs -P` worker included, can open only the relay ports and only to an address of this host.
- **scoursh's own relay**, not the kernel, guarantees the bytes on those ports reach the authorised
  target. The relay is a few lines with its destination fixed at process start and no path that takes a
  destination from the wire - auditable, but scoursh's code. Under Tier C the kernel enforces both
  halves; that difference is why this is named "containment guarantee, target restriction by relay"
  rather than folded into either of the words `--paranoid`'s framing already uses.

Needs, in addition to Tier A's requirements, a working `python3` (the relay - bash's `/dev/tcp` can dial
but cannot listen, so there is no bash-only forwarder) and a `curl` that accepts `--connect-to` (7.49+).
Both are probed before `<command>` runs and refuse with exit `4` rather than degrade. Relays are
children of the wrapper and an `EXIT` trap tears them down on success and failure alike; everything is
per-process, bound to `127.0.0.1`, with no host state of any kind.

**The relay is unauthenticated on loopback.** Any process on the host that can reach `127.0.0.1` can
use a live relay to reach the authorised target for as long as the run lasts. Its destination is fixed
and its port ephemeral and unpublished, so it is a path to a target you already authorised and nothing
else - but on a multi-user host where reaching the target is itself meant to be a privilege, prefer
Tier C.

**Two gaps it states rather than hides.** A scope row with `allow-subdomains: true` and an IPv6 scope
host cannot be turned into relays ahead of time, so the wrapper warns and a request for one is refused
with exit `3` naming the reason. And the raw TLS handshake `dast`'s transport check opens for itself is
not redirected, so it is kernel-refused inside the sandbox - it fails closed, which is the safe
direction.

**Guarantee mode is off by default.** Without `--scope-conf` nothing about the ordinary egress path
changes; `lib/http.sh` only redirects when the wrapper has set `SCOURSH_HTTP_RELAY_MAP`.

### Tier C (macOS) - full netns parity via a Linux container, zero code

`tools/run-in-netns.sh` runs **unmodified** inside a Linux container on a macOS host, given an image
carrying `iproute2`, `iptables`, and `ip6tables`: Docker Desktop grants an unprivileged container
`CAP_NET_ADMIN`+`CAP_SYS_ADMIN` and network-namespace creation, so the SAME kernel-level guarantee the
Linux tier provides natively is available on macOS today, with no code change. This project's own GNU
userland test image (`tools/daily-suite/gnu.dockerfile`) does not currently install those three
packages, so it cannot run the netns tool as shipped - an image-build detail specific to that one
Dockerfile's own package list, not a limit of this route itself.

**Which tier to reach for.** Tier A for `sast`/`sca`/`iac`, where zero network is the correct claim and
nothing weaker is needed. Tier B for `dast`/`cloud`/`network` on macOS, where off-host egress becomes
kernel-impossible and the target restriction is supplied by scoursh's own relay. Tier C when you want
the kernel enforcing both halves and can run a Linux container. See `docs/FOUNDATION.md` tension 20 for
the full account, including the measurement of what a Seatbelt `localhost:PORT` rule actually admits
(any address of *this host* on that port - not port-only, and not `127.0.0.1`-only) and why the obvious
"connect to the LAN address and watch it fail" test does not discriminate.

## Configuration

These config files use the same on-disk record format: blank-line-separated `key: value` blocks, one
`#`-prefixed comment per line, no escaping in values.
Never hand-edit these with tooling that assumes shell syntax - the loader parses them as data and never
`source`s them.
None of them is committed to this repository; `config/` ships `scope.conf.example`,
`scanner.conf.example`, `auth.conf.example`, `discovery.conf.example`, and `images.conf.example`,
which you copy and edit.

### `config/scope.conf` - required only for `dast`, `network`

One record per target. `extra-host` entries are what give `network` a listener set to scan: a target
with only `base-url` gives it nothing beyond the web port to test (see ["The scope gate"](#the-scope-gate-dast-network)).

| Key | Required | Repeatable | Default | Value |
|---|---|---|---|---|
| `id` | yes | no | - | Target name used by `--target`. Pattern `^[a-z][a-z0-9-]*$`. Must be the first field. |
| `base-url` | yes | no | - | `https://host[:port][/path]`. Scheme must be `http` or `https`. |
| `extra-host` | no | yes | none | Additional `host[:port]` in scope for this target. Every `extra-host` entry is a listener `network`'s `reachability.sh`/`banner.sh`/`tlsport.sh`/`httpport.sh`/`transport.sh` phases probe; `network` never probes a `base-url`'s own port beyond what `dast`'s TLS/banner checks already assess. |
| `allow-subdomains` | no | no | `false` | `true`/`false`. |
| `allow-private-addresses` | no | no | `false` | `true`/`false`. Gates the link-local/loopback deny list. |
| `tls-expect-wildcard` | no | no | `false` | `true`/`false`. Read by both `passive/tls.sh` (DAST-07) and `network`'s `tlsport.sh` (`NET-TLS-WILDCARD_CERT-01`): declares that a wildcard certificate is this target's intended design, so a wildcard SAN does not produce a finding. Per-target, not scanner-wide, since one estate can legitimately have both shapes. |
| `notes` | no | no (multi-line) | empty | Free text. |

Every key here that affects behaviour is live: `id`, `base-url`, `extra-host`, `allow-subdomains`,
`allow-private-addresses`, and `tls-expect-wildcard` are all consumed somewhere in the scope gate or
a check that reads it, and each is enforced today.
`notes` is free text that no code reads, exactly as intended.

### `config/auth.conf` - required only for `--authed`

One record per (target, identity), `rules/RULE-FORMAT.md` §9.6.2. Copy
`config/auth.conf.example` (which documents every mode - `bearer`, `api-key`, `form`,
`oauth2-password`, `oauth2-client`, `srp`, `external` - with a worked record each) to
`config/auth.conf` and `chmod 600` it; scoursh refuses to read it at any other mode, since every
value in it is a credential (`docs/FOUNDATION.md` tension 9). An `id` of `<target-id>.<label>`
requires `<target-id>` to already exist in `config/scope.conf`. Two labelled identities on one
target is what `authz.sh`'s object-level authorization / IDOR checks need - they work by asking for
identity B's object as identity A, so with only one identity configured they cannot run at all. A
credential belongs in `secret-file` (an absolute path to a mode-600 file, read as its first line)
rather than inline where practical, so it never ends up pasted into this file directly.

### `config/discovery.conf` - optional; feeds `dast`'s crawler an application's real API surface

A DAST scan crawls whatever it can reach by following links, which is enough for a server-rendered
site but blind to a client-rendered (SPA) application's routes and its XHR/fetch endpoints - they
are simply never linked from any HTML the crawler can see.
`config/discovery.conf` closes that gap by importing a document you already have, so the checks that
need a real parameter to test - the whole `active/*.sh` injection family - have one.
An absent file is the ordinary case, not an error: it means "crawl with the documented defaults", and
a run without one records why in `run.json` (`reason=no_specification_supplied`) rather than silently
reporting a thin surface as complete.

**Ran a `dast` scan and its report or terminal output said the target "looks like a single-page app"?**
That is this gap, and scoursh has already told you the fix rather than silently reporting a thin
endpoint list as complete (docs/DESIGN.md §7.5). See "How to obtain one" a few paragraphs down for the
30-second HAR-capture recipe, then re-run with `--har FILE` (or `--openapi FILE`, if you have a spec
instead - see ["Per-command flags"](#per-command-flags)), or set `har-path`/`openapi-path` below to
keep re-running the same way.

One record per target, `id` matching a `config/scope.conf` target you have already authorised.

| Key | Required | Repeatable | Default | Value |
|---|---|---|---|---|
| `id` | yes | no | - | Must name a `config/scope.conf` target. Must be the first field. |
| `openapi-path` | no | no | none | Path to an OpenAPI or Swagger document (JSON or YAML; 2.0, 3.0, 3.1). |
| `graphql-schema-path` | no | no | none | Path to a GraphQL schema. |
| `postman-path` | no | no | none | Path to a Postman collection. |
| `har-path` | no | no | none | Path to a HAR capture of real browser traffic. |
| `crawl-depth` | no | no | `3` | Non-negative integer; how many link-hops the static crawl follows. |
| `include-path` | no | yes | none (all reachable paths) | Glob, matched against the target-relative request path, of paths the crawl is allowed to request. |
| `exclude-path` | no | yes | none | Same glob syntax; a match here is never requested, even if `include-path` would also match it. |
| `notes` | no | no (multi-line) | empty | Free text. |

All four document keys are independent - supply only the ones you have - and every one of them adds
to the *same* inventory (`reports/<run>/inventory/endpoints.json` and `parameters.json`) a plain crawl
already writes, so a supplied spec and a crawl of the same target are additive, not either/or.
Every path is resolved relative to scoursh's own install root, not the scan target and not your
current working directory, when it is not already absolute.

**How to obtain one.** An OpenAPI/Swagger document is usually served by the application itself (a
common path is `/openapi.json`, `/swagger.json`, or embedded in a Swagger UI page's own JavaScript);
export a GraphQL schema with any GraphQL introspection tool pointed at your own authorised instance;
export a Postman collection from Postman itself; and a HAR capture comes from your browser's own
DevTools Network panel ("Save all as HAR") while you exercise the application by hand, or from
"Copy as HAR" on Chrome's Network tab.
Whichever you use, capture it against a system you are authorised to scan - this file supplies
*content* scoursh reads from local disk, never a live fetch of your own.

**Only paths, never hosts.** This schema has no `base-url`, `host`, or `extra-host` key - the host a
target is scanned on is decided exclusively by `config/scope.conf` (above), and this file cannot
override it. A URL that appears *inside* a supplied document - an OpenAPI `servers[].url`, a Postman
request's absolute URL, a HAR entry's `request.url` - is read for its **path only**; its host is
discarded and every request scoursh actually sends is rebuilt on the target's own authorised
`base-url`. A spec that names a production host, or a HAR capturing a call to a CDN or a third-party
analytics endpoint, therefore contributes at most a path to test on the host you already
authorised - it can never become a way to scan a host you did not (docs/FOUNDATION.md tension 19).

**A one-off run without editing this file.** `--openapi`/`--har`/`--postman`/`--graphql-schema` (see
["Per-command flags"](#per-command-flags)) override the matching key above for a single invocation,
ephemerally - nothing is written to `config/discovery.conf`. Each requires `--target` naming the
target the override applies to (exit 2 otherwise, the same rule `--i-own-target` enforces), and a
relative path is resolved against the install root exactly as this file's own paths are. Prefer the
file for anything you want to keep re-running the same way; reach for a flag when you are trying one
spec or capture once.

### `config/images.conf` - required only for `image` (unless `--source` is given)

One record per built container image `--image` can name, `rules/RULE-FORMAT.md` §9.6.8. Copy
`config/images.conf.example` to `config/images.conf` and edit it - or skip this file entirely for a
one-off scan and pass `--source PATH` instead (see ["Per-command flags"](#per-command-flags)).

| Key | Required | Repeatable | Value |
|---|---|---|---|
| `id` | yes | no | The name used by `--image`. Pattern `^[a-z][a-z0-9-]*$`. Must be the first field. Deliberately never derived from the image's own digest or tag, which both change on every rebuild/retag - `id` is the stable coverage-cell key a rebuild must keep, the same reasoning `config/scope.conf`'s own `id` uses one module over. |
| `source` | yes | no | `docker-archive` (a `docker save` tarball) or `oci-layout` (an OCI image-layout directory). Anything else is a lint error. |
| `path` | yes | no | Path to that tarball or directory. A relative path resolves against the process's working directory, never the install root. |
| `reference` | no | no | Which image to read out of a multi-image source - a `RepoTags` entry (`docker-archive`) or the `org.opencontainers.image.ref.name` annotation (`oci-layout`). Required when the source holds more than one image; omitting it there is a declared refusal, never an arbitrary pick. |
| `dockerfile` | no | no | The scan-root-relative path of the Dockerfile that built this image, when you also scan it with `iac`. Populating it is what lets `rules/derived.rules` join this image's `IMAGE-*` findings to that Dockerfile's `IAC-DOCKER-*` findings (`COMPOSITE-IMAGE-EFFECTIVE_ROOT`, `COMPOSITE-IMAGE-STALE_BASE_*` - see `docs/CHECKS.md`). Never validated against the image's own content (it cannot be); omitting it just means this image's findings carry no correlation value and cannot join. |
| `notes` | no | no (multi-line) | Free text. |

`--source PATH` overrides `path` for a single run; when `ID` has no record in this file at all, the
`source` value is inferred from the filesystem instead (a directory is `oci-layout`, a file is
`docker-archive`). Where a record for `ID` does exist, its own `source` and `reference` still apply -
`--source` there just points at a different copy of the same image (a rebuild, say) - and its
`dockerfile` correlation value carries over unchanged. There is deliberately no registry URL or
daemon-socket key: a registry pull is not designed for at all (`docs/FOUNDATION.md` tension 19 - no
third egress channel), so an image is supplied as a file, the same way `data/advisories.db` is.

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
| `jobs` | positive integer | `4` | live | Real worker parallelism for `sast`/`sca`/`iac`, and DAST's in-flight-connection ceiling. See [`--jobs N`](#--jobs-n-and-the-jobs-config-key). |
| `http-timeout` | positive integer (seconds) | `20` | inert | The HTTP layer's timeout reads `SCOURSH_HTTP_TIMEOUT`, never this file. |
| `max-redirects` | non-negative integer | `5` | inert | The redirect cap is a caller-supplied argument defaulting to 5, never read from this file. |
| `request-budget` | positive integer, per run | `20000` | live | Per-run, shared across workers; exhausting it stops the run at exit 5. Clamped to 5000 for a DAST scan without `--i-own-target`, so this default is not what a DAST run spends. |
| `circuit-breaker-failures` | positive integer | `10` | live | Failures (transport failure or 5xx) within the window below; reaching it aborts the run at exit 5. Never disableable, but raisable under `--i-own-target` - `--circuit-breaker-failures N` is the dedicated CLI flag for `dast`/`all` (same shape as `--requests-per-second`/`--request-budget`, exported as `SCOURSH_CONFIG_CIRCUIT_BREAKER_FAILURES`). |
| `circuit-breaker-window` | non-negative integer (seconds) | `60` | live | Rolling window. Bounded at both ends - never below 60s, never above 86400 - and no affirmation lifts either bound. |
| `fail-on` | severity name or `none` | `none` | live | |
| `min-confidence` | `high\|medium\|low` | `low` | live | |
| `redact-secrets` | `true`/`false` | `true` | live | Governs whether a matched credential is written in the clear. See ["What `redact-secrets` covers"](#what-redact-secrets-covers). |
| `formats` | repeatable, `json\|sarif\|html\|md\|audit\|agent` | `json,sarif,html,md` | live | Resolved through the same chain as `--format`; `audit` and `agent` are opt-in and never in the default. See [`--format`](#--format-and-the-formats-config-key). |
| `max-matches-per-file` | positive integer | `200` | live | Read by both the SAST and IaC scanners. |
| `evidence-max-bytes` | positive integer | `512` | inert | Truncation is real, but reads `SCOURSH_EVIDENCE_MAX_BYTES`, not this file. |
| `scratch-dir` | absolute path | `${TMPDIR:-/tmp}` | inert | The scratch directory follows `SCOURSH_SCRATCH_BASE`, else `TMPDIR`. |
| `state-retain-runs` | positive integer | `30` | live | Every scanning run prunes `state/` to this many most-recent runs plus `state/latest.json`. See [Persistent run state, diff, and baseline](#persistent-run-state-diff-and-baseline). |
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
