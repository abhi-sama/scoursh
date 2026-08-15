# Runbook: how this project's tests are actually run

Audience: engineers contributing to scoursh (PR authors), and whoever administers the machine the suite runs on.

## There is no hosted CI, and no pull-request check

**GitHub Actions is switched off for this repository.**
`.github/workflows/ci.yml` is deleted; there is no workflow, no self-hosted runner, and no status check of any kind attached to a commit or a pull request.

Read that literally, because it changes what merging means:

- **A pull request carries no automatic pass/fail.**
  There is no red tick, no green tick, and no "checks pending".
  A PR that breaks every suite in the repository looks, on GitHub, exactly like one that breaks nothing.
- **Nothing runs when you push.**
  The only thing that runs the suite is the daily local run described below, and whatever you run yourself.
- **Anyone merging is the check.**
  Before merging, either run `tests/run-tests.sh` against the merge result yourself, or confirm that a daily run *newer than the change* passed.
  An older green result says nothing about the commit in front of you - see "Reading a result" for why the runner reports staleness rather than letting an old PASS stand in for a current one.

That is a real loss of a real control, stated here rather than papered over.
What replaced it covers the *repository over time*; it does not cover *this pull request before it lands*.

### Why

GitHub Actions stopped assigning machines to this repository on 2026-08-02: every run since then failed within seconds with no machine allocated and zero steps recorded, reproduced identically on a second private repository.
That is an account-level compute-billing condition, not a fault in any workflow file.
A self-hosted runner was registered as a way around that, and then abandoned: the operator's decision is that this repository runs no GitHub Actions at all, hosted or self-hosted, and the runner is being deregistered.
If a runner is still listed under Settings > Actions > Runners, removing it is the remaining cleanup - it has nothing to run.

## What runs instead

`tools/daily-suite.sh` - a local runner, on the operator's own machine, once a day.

```
tools/daily-suite.sh                       # the daily run, on demand
tools/daily-suite.sh --status              # what the last run said
tools/daily-suite.sh --check-userland      # just the BSD-userland assertion
tools/daily-suite.sh --print-launchd       # the LaunchAgent for the schedule
tools/daily-suite.sh --help
```

A run does five things, in order:

1. **Pins the system userland and proves it is BSD.** See "The BSD-userland requirement" below.
   It aborts here rather than producing a result, if the userland is wrong.
2. **Resolves a bash at or above the frozen 4.2 minimum**, and refuses to run the suite at all otherwise.
   macOS's own `/bin/bash` is 3.2.57 and has no associative arrays.
3. **Runs `tests/run-tests.sh` in full, serially,** on the macOS/BSD userland - every suite and every linter, one process each.
   Nothing is fanned out: parallel batches starve each other on a single workstation, which is measured rather than assumed.
4. **Runs the same suite again inside a Linux container** for the GNU userland (`tools/daily-suite/gnu.dockerfile`, `tools/daily-suite/gnu-leg.sh`), which asserts *its* userland is genuinely GNU on the way in.
5. **Diffs the two legs' findings byte for byte.**
   This is `docs/FOUNDATION.md` tension 24's actual requirement: not that the suite passes on both userlands, but that they produce the same findings, the same fingerprints and the same bytes.
   It is the job the retired `compare` CI job used to do.

`tests/run-tests.sh` remains the single entry point, and `tests/run-tests.sh --list` remains the source of truth for which suites and linters exist.
A new suite or linter is picked up by the daily run automatically once it is registered there; nothing else needs editing.

### The GNU leg, and when it does not run

The GNU leg needs a working `docker`.
By default (`--gnu auto`) an absent docker, a stopped daemon, or a failed image build is **recorded as a skipped leg**, and the run's verdict becomes `PASS-PARTIAL` with exit status 5 - never `PASS`.
A run that did not check tension 24 does not get to claim it did.

- `--gnu require` turns those conditions into a hard failure instead.
- `--gnu off` skips the leg deliberately; the verdict is still `PASS-PARTIAL`, because the guarantee still was not checked.

The image is tagged with `gnu.dockerfile`'s own sha256, so it is built once per version of that file and never rebuilt - and never reaches the network again - until the file changes.
The first build needs the network.

Two things the container needs, both found by running it rather than by reasoning about it:

- **git has to resolve inside it.**
  The checkout and the result directory are mounted at their own absolute host paths, and a `git worktree` checkout's git directory (whose `.git` is a *file* holding an absolute path into the main repository) is mounted read-only as well.
  Without that, `git rev-parse --show-toplevel` fails in the container, `lib/core.sh` falls back to the resolved `--path` as the scan root, and every finding's repository-relative `loc_path` is computed from a different root than the BSD leg used - 15 `sast` and `iac` assertions failed that way, with nothing wrong in either rule pack.
  Note for anyone touching that mount: on Docker Desktop for macOS a bind whose source and destination are the *same* absolute path is silently not mounted when the `-v ...:ro` suffix form is used, and works when written as `--mount type=bind,...,readonly`.
- **Enough memory for ShellCheck.**
  About 5 GB, which the default Docker VM has.
  It used to need far more: `shellcheck -x` follows `source` directives statically, where the runtime "already sourced" guards do not exist, so `modules/sca/engine.sh` and `modules/sca/php_engine.sh` sourcing *each other* was an unbounded static cycle - 43.6 GB peak and 236 seconds on one file, which the 64 GB macOS leg survived and the container did not.
  One `# shellcheck source=/dev/null` on the back-edge (see `modules/sca/php_engine.sh`) cuts it to 4.6 GB and 16 seconds with no loss of analysis.

The container is ARM Linux on an Apple Silicon host, rather than the x86-64 Linux the retired hosted CI provided.
For a GNU-versus-BSD *userland* comparison that is faithful: what tension 24 checks is coreutils/grep/sed/bash behaviour, none of which is architecture-dependent.
Do not add `--platform` to force emulation.

## The BSD-userland requirement

This is the sharpest edge in the whole arrangement, and the reason the runner asserts rather than assumes.

On a developer's interactive PATH on this class of machine, `grep` can resolve to **ugrep** and `find` to **bfs**.
Neither is BSD; neither exists on any real macOS target.
A suite run under those goes **green while testing the wrong tools**, which is strictly worse than not running it: it manufactures confidence in a property nobody checked.

`docs/FOUNDATION.md` tension 24 is a register of shell facts that genuinely differ between GNU and BSD, every one of them found by *running* the command rather than reasoning about it, and `AGENTS.md` records measured behaviour of **BSD grep 2.6.0-FreeBSD** specifically - the grep at `/usr/bin/grep`.

So `tools/daily-suite.sh`:

- **Pins `SCOURSH_SYSTEM_PATH`** (default `/usr/bin:/bin:/usr/sbin:/sbin`) ahead of the inherited `PATH`, before it even sources `lib/core.sh` - which binds its pattern engine at source time and would otherwise bind the shadow.
- **Requires each of `grep`, `find`, `sed` and `awk` to resolve inside that pinned path**, so a tool that escaped the pin is a failure rather than a silent substitution.
- **Requires `grep --version` to report BSD grep**, and rejects it if it reports GNU grep - which catches a shadow that sits in the right directory but is the wrong tool.
- **Rejects a `find` or `sed` that answers `--version` at all**, since the BSD ones do not; that is how bfs and GNU findutils announce themselves.

Any of those failing aborts the run with exit 4 and a message naming what it found.
Nothing is written that could be mistaken for a result.

`tests/suites/daily-suite.sh` section B proves each of those guards *bites*, by shadowing the system grep and requiring the abort - including the case that only the version check can catch (a shadow that forwards `--version` to the real binary is caught by the resolved-path check, and one that lies about its version while sitting in the right place is caught by the version check).
It also pins the mechanism working in the other direction: a ugrep-shaped shadow that is merely early on `PATH` must be *overridden* by the pin and the run must proceed, so the suite can tell "the pin works" from "the pin is missing".

## Reading a result

Results live under `$SCOURSH_DAILY_DIR`, defaulting to `~/Library/Logs/scoursh` on macOS (`~/.local/state/scoursh` elsewhere).

```
~/Library/Logs/scoursh/
├── STATUS                       one line, overwritten each run - what --status reads
└── runs/<UTC timestamp>/
    ├── summary.txt              verdict, both legs, which checks ran, failure detail
    ├── userland.txt             exactly which grep/find/sed/awk/bash produced this result
    ├── bsd-suite.log            full output of the BSD leg
    ├── gnu-suite.log            full output of the GNU leg
    ├── checks.txt               every suite and linter that ran, and its result
    ├── bsd-findings.jsonl       normalised fixture-scan findings, per leg
    ├── gnu-findings.jsonl
    └── compare.diff             present only when the two legs disagreed
```

`tools/daily-suite.sh --status` is the thing to run.
Its exit status is the answer:

| Reported | Exit | Means |
|---|---|---|
| `PASS` | 0 | Both legs ran, both passed, and their findings are byte-identical. |
| `FAIL` | 1 | A suite, a linter, or the cross-userland comparison failed. |
| `PASS-PARTIAL` | 5 | Everything that ran passed, but a leg was skipped, so tension 24 was not checked. |
| `DID NOT FINISH` | 5 | A run started and never reached a verdict - killed, timed out, or the machine slept. |
| `STALE` | 5 | The newest result is older than the threshold (default 36h, `--max-age-hours`). |
| `NEVER RUN` | 5 | There is no result at all; most likely the schedule was never installed. |
| `UNREADABLE RESULT` | 5 | The status file is not in a format this version understands. |

**A silent absence must never read as success**, and the last four rows are how that is enforced.
A cron job that quietly stopped firing three weeks ago leaves a genuine `PASS` behind; reporting that as a pass is exactly the failure this arrangement would otherwise have, given that nothing else is watching.
So an old `PASS` is `STALE` and non-zero, and a run that started but never finished leaves `verdict=INCOMPLETE` on disk from the moment it begins - the previous run's `PASS` is overwritten *before* any work happens, not after it succeeds.

On failure the runner also raises a macOS notification (best effort; `--no-notify` suppresses it, and it can never change the exit status or the recorded result).

## Installing the daily schedule

A user LaunchAgent.
The plist is **generated, not committed**: it has to carry this checkout's path and this machine's bash, and `docs/DESIGN.md` §1 forbids a shipped file carrying either.

```sh
# from the repository root
# The results directory must exist before the agent first runs: launchd does not
# create the parent of StandardOutPath, and the plist points both of its log
# paths in there.
mkdir -p ~/Library/Logs/scoursh ~/Library/LaunchAgents
./tools/daily-suite.sh --print-launchd --hour 3 --minute 30 \
  > ~/Library/LaunchAgents/sh.scoursh.daily-suite.plist

launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/sh.scoursh.daily-suite.plist
launchctl print "gui/$(id -u)/sh.scoursh.daily-suite" | head -20   # confirm it loaded
```

`RunAtLoad` is deliberately `false`, so loading the agent does not kick off a full suite run on the spot.
To prove the wiring end to end without waiting for the slot:

```sh
launchctl kickstart -p "gui/$(id -u)/sh.scoursh.daily-suite"
./tools/daily-suite.sh --status      # a few minutes later
```

Uninstall:

```sh
launchctl bootout "gui/$(id -u)/sh.scoursh.daily-suite"
rm ~/Library/LaunchAgents/sh.scoursh.daily-suite.plist
```

Regenerate and reload the plist whenever the checkout moves, or the bash it resolved moves.
Nothing detects that for you; `--status` reporting `STALE` is the symptom.

### Prerequisites on the machine

None of these is a scoursh *runtime* dependency; they are what running its test suite needs.

| Needed | For | If missing |
|---|---|---|
| bash >= 4.2 (`brew install bash`) | the suite itself | run aborts, exit 4, message naming 4.2 |
| a genuine BSD userland at `/usr/bin` | the BSD leg meaning anything | run aborts, exit 4, message naming what it found |
| `shellcheck` (`brew install shellcheck`) | `tests/run-tests.sh`'s final linter | the suite skips it and says so; the run still passes |
| `docker` | the GNU leg | leg skipped, verdict `PASS-PARTIAL`, exit 5 |
| network, once per `gnu.dockerfile` version | building the GNU image | leg skipped, verdict `PASS-PARTIAL`, exit 5 |

`SCOURSH_BASH` overrides bash selection and is **authoritative**: if it points at something below 4.2 the run fails rather than quietly picking a different interpreter, because a result produced by an interpreter nobody asked for is not the result that was asked for.

## Switching back to hosted CI, if billing is restored

Nothing in the repository has to change for the daily runner to keep working alongside a hosted pipeline - it has no GitHub dependency at all.
Restoring hosted CI is a matter of adding a workflow back, and the shape of the one that was deleted is worth knowing before writing a new one:

1. A matrix `suite` job over `ubuntu-latest` (GNU) and `macos-latest` (BSD), each installing a bash >= 4.2 and `shellcheck`, then running `tests/run-tests.sh` and uploading the suite log plus a normalised `findings.jsonl`.
2. A `compare` job that downloads both legs' normalised findings and `diff -u`s them - the same assertion `tools/daily-suite.sh` now makes locally.
3. The check names GitHub displays are the jobs' `name:` fields, not the workflow name; read them off a real run before configuring them as required status checks.

Two things to decide at that point rather than inherit:

- **Whether the daily local run stays.**
  It is not redundant: it is the only thing that would keep running if Actions stopped again, and it is what caught that the retired pipeline had no equivalent of the BSD-userland assertion.
- **Branch protection.**
  It has never been enabled on this repository, and not for want of trying: both the classic branch-protection API and the rulesets API return `403 "Upgrade to GitHub Pro or make this repository public to enable this feature."` on a Free-plan private repository.
  Admin permission and token scope were both confirmed and are not the problem.
  Unblocking it needs a paid plan (or a GitHub Team org), or making the repository public - a product decision, not an infrastructure one.
  Until then, "changes land via PR only" is process discipline, not a server-side gate.

## Checklist: adding a new suite or linter

1. **Write it as its own script.**
   Suites live at `tests/suites/<name>.sh`; linters live at `tests/<name>.sh`.
   Each runs in its own process (`lib/core.sh` installs traps and owns a scratch directory per process; sharing a shell with another suite would not test what the tool actually does).
2. **Name the reading each pinned test fails under**, in a comment on the assertion.
   This is a standing repository rule (see `AGENTS.md`'s Tests section): a test written after the rule, with no stated failing reading, can pass under both the correct and the rejected implementation and certify a defect green.
3. **Register it** in `tests/run-tests.sh`'s `SUITES` or `LINTERS` array.
   Do not invoke it from anywhere else; `run-tests.sh` is the single entry point `pnpm test` and `tools/daily-suite.sh` both use, and `--list` must show the new name.
4. **Nothing else needs editing to make it run daily.**
   Both legs of `tools/daily-suite.sh` run `tests/run-tests.sh` in full.
5. **If it writes to `findings.jsonl` or affects fingerprints**, check it survives the cross-userland comparison: a GNU-only assumption fails on the BSD leg, not locally, and the comparison is byte-for-byte.
6. **If it needs a tool outside scoursh's dependency set**, add a capability probe (`lib/core.sh`'s pattern for `rg`, `openssl`, `aws`, GNU `parallel`) rather than assuming it exists, and add it to `tools/daily-suite/gnu.dockerfile` so the GNU leg has it too - an image missing a tool turns real coverage into a silently skipped check.
7. **Update `AGENTS.md`'s Tests section** so it does not drift from `tests/run-tests.sh --list`.

## What the suite covers

Per `docs/DESIGN.md` §12 and the resolutions in `docs/FOUNDATION.md`.
`tests/run-tests.sh --list` is authoritative for the current set of names; this is what they are for.

**Suites** (`tests/suites/*.sh`), a representative selection rather than the full list:

| Suite | Purpose |
|---|---|
| `records` | The frozen block-record parser: `rules/RULE-FORMAT.md` §3-§10, all ten schemas, the §12 worked and negative examples, the §13 error codes. |
| `core` | `lib/core.sh`: scratch-dir ownership and the `EXIT` trap guard, `msleep`, exit-code validation, `erase_dir`. |
| `config` | `lib/config.sh`: the CLI > env > file > default precedence chain, fail-loud validation at every level. |
| `findings` | `lib/findings.sh`: fingerprint identity, derived/composite findings, the severity rubric, redaction vs. evidence vs. fingerprint. |
| `report` | `lib/report.sh`: hostile-evidence escaping, the no-egress properties of the HTML report, `run.json` content. |
| `http` | `lib/http.sh`: the scope-gate chokepoint end to end - tuple match, normalization, redirect handling, deny-list. |
| `e2e` | Runs `tests/e2e/fixture-scan.sh` for real: valid JSON, a self-contained HTML report, byte-reproducible output. |
| `scan` | `scan.sh`: the CLI grammar, the exit-code precedence contract, "config loads before dispatch." |
| `exit-code-matrix` | Table-driven matrix over `scan.sh`'s six documented exit codes (0-5). |
| `gate-mutation-proof` | Mutation-tests the non-bypassable safety gates by deleting the guarding line in a scratch copy and asserting the outcome actually changes - so a fixture that stopped discriminating pass from fail fails loudly instead of certifying a broken gate green. |
| `daily-suite` | `tools/daily-suite.sh` itself: that the BSD-userland assertion aborts when the system grep is shadowed, and that a missing, stale or unfinished result never reports as a pass. |

**Linters** (`tests/*.sh`):

| Linter | Purpose |
|---|---|
| `lint-rules` | Record-format linter: whole-repository checks the per-record parser can't do alone - check-id namespace, contributor existence/chaining, correlation-key capability, rubric uniqueness, cross-references. |
| `lint-shell` | Enforces: no bare `grep`/`rg` outside `scan_match`, no `source`/`eval` on config/rules/data, the network chokepoint (`lib/http.sh`, plus `tools/vendor-engines.sh` as the one documented quarantined exception - tension 27), that nothing under `lib/`/`modules/`/`scan.sh` wires `tools/vendor-engines.sh` into a scan, one capability layer. |
| `lint-aws-readonly` | Enforces every AWS call goes through `aws_ro` with an operation on the frozen read-only prefix allowlist. |
| `lint-status` | The generated build-status blocks in `AGENTS.md` and `docs/FOUNDATION.md` equal a fresh `tools/gen-status.sh` run, and a hand-edited block is caught. Fix a failure with `tools/gen-status.sh --write`, never by hand-editing the block. |
| `lint-no-ai` | No AI/LLM provider hostname, SDK name, or API-key environment variable anywhere in the shipped tool. |

**`shellcheck`** runs last, over `lib/`, `tests/`, `tools/`, `modules/`, `aws/`, `scan.sh`, if the binary is present.
It is optional locally (an air-gapped host may not have it) and skipped with a notice if absent - so on a machine without it, the daily run still reports `PASS` while having linted nothing. Install it.
CI always installs it, so it is effectively required in CI even though `tests/run-tests.sh` itself treats it as best-effort.
`-x` (follow `source`) always runs, on every file, on every path below - it is what makes the check thorough, and nothing here narrows or drops it.

In CI (`GITHUB_ACTIONS=true`), the stage is unchanged from the original design: a fixed 2-way `xargs -P` batch, no memory cap, no watchdog, because a CI runner is ephemeral and a failed job costs nothing there.

Locally, concurrency is sized by **memory, not core count**, and each `shellcheck` invocation checks exactly one file - never a batch - so a kill or a plain finding is always attributable to exactly one file.
This exists because `-x`'s cost is dominated by how deep a file's own `source` graph goes, not by file size: a file that sources nothing can cost under 100MB, while a file that sources several `lib/*.sh` files that source further routinely measures several GB resident, and macOS offers no per-process memory ceiling to fall back on (`ulimit -v`/`-d`/`-m`/`-s` are all rejected, and shellcheck's own GHC runtime ignores `+RTS -M` in the shipped binary).
An earlier version of this stage parallelised purely by core count and kernel-panicked a 64GB/18-core host twice, at which point concurrent `shellcheck -x` processes had reached far more memory in aggregate than any one of them would need alone.

The local design has two independent safety layers, both watched every 0.4s against the currently-running processes, in addition to the concurrency itself already being sized from available memory (`(available-or-total GB / 2) / budget_gb`, clamped to `[1, detected core count]`):

1. **Per-process budget** (`SCOURSH_SHELLCHECK_MEM_BUDGET_GB`, default 12GB): a single process exceeding its own budget is killed (`SIGTERM` then `SIGKILL`) and named in the failure output.
2. **Free-memory floor** (`SCOURSH_SHELLCHECK_FREE_FLOOR_GB`, default 4GB): even when every process is individually within budget, several of them together can still starve the host if something *else* on the machine grows after the job count was sized from a one-time snapshot - so free memory is watched directly, and if it drops below the floor, the single largest active process is killed to relieve pressure, without failing every file that happened to be running alongside it.

A failure is always attributable: the per-process kill and the free-floor kill each name the file directly, and a process that dies from **any** signal - including one this script did not send, such as a host-level OOM killer - is still detected (by exit status, not by output parsing) and reported with the file name and the signal number, never as a bare non-zero exit.
The branch on success/failure is on real exit status throughout, not on parsed output, so a failure in any file - the first one launched or the last - still fails the stage.

## GNU/BSD: why the suite runs twice at all

`docs/FOUNDATION.md` tension 24 is the source of this design; the summary an operator needs:

scoursh is a shell tool that must run identically on an air-gapped Linux host (GNU coreutils) and on macOS (BSD userland), and the two disagree on facts the codebase depends on - measured on this codebase, not assumed:

- macOS ships bash 3.2, which has no associative arrays; the tool's frozen minimum is bash 4.2.
- `shred` is GNU-only and absent on macOS; the `EXIT` cleanup trap never calls it directly (that failed loudly at exit 127 on macOS during development), and `erase_dir` treats overwrite-based erasure as best effort instead.
- `sort -V` is GNU-only; the tool avoids needing it at all rather than working around it (tension 25 moves SCA version-range arithmetic off the scanning host entirely).
- `xargs -P` is used without `-r`, which BSD lacks, by checking the unit count before ever invoking `xargs` on a possibly-empty input.
- Bash's `=~` uses the system `regcomp`, which on macOS/BSD supports none of `\b \w \s \d`; `redact()` routes through `grep -E`/`rg` instead of matching in-process, because both support all four on both userlands.

Running the suite on only one of these platforms would let any of the above regress silently.
The failure mode is not "the tool crashes" - it is "the tool produces a different, wrong answer on one platform and nobody notices until an operator hits it in the field."
Running the full suite on both, then diffing byte-for-byte, turns "one capability layer, behaving identically everywhere" from a design intention into a property that is actually checked.
Which is precisely why the userland assertion exists: a BSD leg that silently ran GNU tools would leave that property unchecked *while reporting that it had been checked*.
