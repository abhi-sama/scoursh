# Runbook: how this project's tests are actually run

Audience: engineers contributing to scoursh (PR authors), and whoever administers the machine the local suite runs on.

## Two paths, and which one actually runs right now

There are two ways this project's suite gets run: a local daily runner on the maintainer's own machine, and a GitHub Actions workflow (`.github/workflows/ci.yml`) that is committed to the repository but does not currently execute.

- **`tools/daily-suite.sh` is the maintainer's real path, and it runs today.**
  It is described in full below: the BSD-userland assertion, the GNU leg via a container, the byte-for-byte cross-userland diff, and how to install its daily schedule.
- **`.github/workflows/ci.yml` exists for contributors and forks, and is dormant until the repository is public.**
  Hosted Actions currently cannot start a run on this repository at all (see "Why" below) - a self-hosted runner does not help either, there is simply no machine assigned. The workflow is kept in the repository rather than deleted so that publishing scoursh is a one-step act: a fork or an external contributor's PR gets a real check the moment Actions can run, with nothing to reconstruct from history.
  Dormant means genuinely inert, not "fires and fails": the `suite` job carries `if: ${{ !github.event.repository.private }}`, so on a private repository it is **skipped**, not attempted - the Actions scheduler evaluates that condition itself, before it ever asks for a runner, so the run never reaches the point where the missing-machine billing error would fire. Pushing or opening a PR produces no failing status of any kind, on GitHub or anywhere else - only a skipped one, which does not read as red. That condition flips to `false` (making the job real) automatically the moment the repository goes public; nothing here needs editing when that happens.

Read that literally, because it changes what merging means **today**, regardless of which path this file describes:

- **A pull request carries no automatic pass/fail.**
  There is no red tick and no "checks pending" - only a skipped one, from the `if:` guard above. A PR that breaks every suite in the repository looks, on GitHub, exactly like one that breaks nothing.
- **Nothing runs when you push**, except the daily local run described below, and whatever you run yourself.
- **Anyone merging is the check.**
  Before merging, either run `tests/run-tests.sh` against the merge result yourself, or confirm that a daily run *newer than the change* passed.
  An older green result says nothing about the commit in front of you - see "Reading a result" for why the runner reports staleness rather than letting an old PASS stand in for a current one.

That is a real loss of a real control, stated here rather than papered over.
The local runner covers the *repository over time*; it does not cover *this pull request before it lands* - and the workflow does not either, while it cannot start.

### Why

GitHub Actions stopped assigning machines to this repository on 2026-08-02: every run since then failed within seconds with no machine allocated and zero steps recorded, reproduced identically on a second private repository.
That is an account-level compute-billing condition on *private* repositories, not a fault in any workflow file - a self-hosted runner was registered as a way around it and then deregistered, since it had nothing to run against either; a self-hosted runner still needs Actions itself to dispatch a job to it.

Making the repository public removes that condition: hosted Actions is free for public repositories, and does not draw on the same private-repository minutes quota that is currently exhausted.
That is the plan - the maintainer intends to make this repository public, and at that point `.github/workflows/ci.yml` starts running for real, giving forks and contributors, who do not have the maintainer's own machine, a real check with nothing to set up.
The workflow's trigger was also part of why this account's Actions minutes were exhausted before that: it used to fire on both `push: ['**']` and `pull_request`, so every push to a branch with an open PR ran the whole matrix twice.
It is now `push: [main]` plus `pull_request`, so a push to a branch with an open PR runs the matrix once, not twice, and a push to a branch with no PR runs it only if that branch is `main`.

Two things decided rather than inherited once Actions can run again:

- **The daily local runner stays.**
  It is not redundant with a public-repository Actions run: it is the only thing that keeps working if Actions billing changes again, and it is what caught the missing BSD-userland assertion in the first place (see below) - a guarantee the retired hosted-CI matrix never checked for.
- **Branch protection is still not enabled, and can't be yet.**
  Both the classic branch-protection API and the rulesets API return `403 "Upgrade to GitHub Pro or make this repository public to enable this feature."` on a Free-plan private repository.
  Admin permission and token scope were both confirmed and are not the problem.
  Making the repository public removes that blocker too, at which point turning the workflow's job names into required status checks is the natural next step.
  Until then, "changes land via PR only" is process discipline, not a server-side gate.

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

  **A cycle is not the only shape that does this, and the second shape is the one this tree actually has.**
  `shellcheck -x` does not memoise: it re-expands a file EVERY time it is reached, so a *diamond* in an acyclic graph multiplies just as a cycle does.
  Measured on this tree: `lib/http.sh` sources both `lib/config.sh` and `lib/findings.sh`, and both reach `lib/records.sh` -> `lib/core.sh`; `modules/dast/passive/cookies.sh` reaches `lib/http.sh` through `inject_engine.sh` *and* through `auth_engine.sh`; and `tests/suites/dast-cookies.sh` sourced `cookies.sh` six separate times on top of that.
  The compounded result was **156,852 inlined lines for that one entry point, 91% of them duplicates** - `lib/core.sh` inlined 29 times - which measured 23.42 GB and had not finished after 29 minutes, so the stage's own 12 GB watchdog killed it and `tests/run-tests.sh` could not exit 0 on any branch.
  The fix is the same one line, applied to every edge whose target the entry point already reaches another way: **47 `# shellcheck source=/dev/null` directives across 25 files**, each one *lossless* (the file is still inlined once, via the kept edge), taking that entry point to **34,881 lines**.
  Cut a duplicate edge, never a file's only edge: the second is a real loss of analysis and shows up as new SC2154/SC2034 noise in the parent.

  Count them from the tree rather than from this sentence, and count the ADDED set rather than the total - six files carried such a directive before this work:

  ```sh
  git grep -c '# -x back-edge cut:' -- '*.sh' | awk -F: '{s+=$2} END {print s}'   # 47
  git grep -l '# -x back-edge cut:' -- '*.sh' | wc -l                             # 25
  ```

  **Peak RSS varies with the host and with how much the tree has grown since, and the honest figure is the larger one.**  `tests/suites/dast-cookies.sh` measured **8.42 GB / 173 s** on one machine and **9.87 GB / 217 s** on another when those cuts landed; **re-measured later on the tree as it then stood it reached 12.99 GB**, with `tests/suites/dast-jwt.sh` at 12.96 GB (same method throughout: `/usr/bin/time -l`, one file at a time).  **`dast-cookies.sh` is the file closest to the ceiling** - it is where a regression will surface first, followed by `dast-jwt.sh`.
  Two lessons from that drift, both of which cost a ticket: these figures **go stale as the tree grows**, so re-measure rather than trusting the number written here; and the per-process budget was for a while set *below* the real worst case, which killed those two files as false failures.  The budget is now 20 GB against a 12.99 GB worst case (see "The memory model" below) rather than 12 GB against a stale 9.87 GB one.
  These directives are load-bearing.  Deleting one because it "looks unnecessary" puts the stage back over budget.

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

## When the repository goes public

`.github/workflows/ci.yml` needs no rewriting to be ready for that: it is already the shape a public repository's CI should be.

1. A matrix `suite` job over `ubuntu-latest` (GNU) and `macos-latest` (BSD), each installing a bash >= 4.2 and `shellcheck`, then running `tests/run-tests.sh` and uploading the suite log plus a normalised `findings.jsonl`.
2. A `compare` job that downloads both legs' normalised findings and `diff -u`s them - the same assertion `tools/daily-suite.sh` already makes locally, today.
3. The check names GitHub displays are the jobs' `name:` fields, not the workflow name; read them off a real run before configuring them as required status checks.

What actually changes at that point:

1. **`github.event.repository.private` flips to `false`**, so the `suite` job's `if:` guard stops skipping it and hosted Actions starts assigning machines again (public repositories are free) - `pull_request` and pushes to `main` start producing real checks, with no workflow edit needed at all.
2. **Branch protection becomes available**, per the 403 described above. Turning the `suite` and `compare` job names into required status checks is the natural next step once a few real runs exist to read the check names off.
3. **This runbook's "no automatic pass/fail" warning stops being universally true.**
   It becomes true only for pushes to non-default branches with no open PR, same as any other repository's Actions setup - reword the top of this file at that point rather than leave it describing a dormant workflow.

Nothing about the daily local runner changes when this happens: it keeps running, alongside hosted Actions, as the maintainer's own fast path and as the only check that keeps working if Actions billing changes again.

## Checklist: adding a new suite or linter

1. **Write it as its own script.**
   Suites live at `tests/suites/<name>.sh`; linters live at `tests/<name>.sh`.
   Each runs in its own process (`lib/core.sh` installs traps and owns a scratch directory per process; sharing a shell with another suite would not test what the tool actually does).
2. **Name the reading each pinned test fails under**, in a comment on the assertion.
   This is a standing repository rule (see `AGENTS.md`'s Tests section): a test written after the rule, with no stated failing reading, can pass under both the correct and the rejected implementation and certify a defect green.
3. **Register it** in `tests/run-tests.sh`'s `SUITES` or `LINTERS` array (`STAGES` is for the one thing that is neither - the whole-tree `shellcheck` run, which has no script of its own).
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
| `run-tests-stage` | `tests/run-tests.sh`'s own whole-tree `shellcheck` stage: that it prints a verdict line on every exit path (including a SIGTERM mid-run) and that a file it could not check is reported distinctly from one it checked and found clean. Drives the real stage as a subprocess against a stub `shellcheck` and a two-file fixture list, so it runs in seconds. |

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

### The memory model

An earlier version of this model could not reach a verdict on **any** host - an 8GB machine, a 27GB machine and a 64GB machine all failed it, which is what showed the arithmetic rather than any host was wrong.
It had one `budget_gb` (default 12) doing two incompatible jobs at once, and it was wrong three independent, compounding ways:

1. It read macOS `Pages free` as "available memory". That is the **free list**, which Darwin holds near a low-water mark and refills lazily by reclaiming inactive pages; it does not grow with the size of the machine. Measured on a 64GB host: **6GB reported where 36GB was available**, pinned near 6GB regardless. Every number downstream inherited that 6x understatement, and the 4GB free floor built on it fired on essentially every poll - killing a healthy **1.09GB** process on a machine with 36GB free.
2. `jobs = (avail / 2) / budget` yields 0 on any host with under 24GB of headroom, clamped up to 1 - so the "memory-derived" job count was the constant 1 everywhere. And when headroom fell *below* the budget it clamped the job count and left the budget alone, promising one process 12GB on a host with 3GB to give.
3. 12GB was **below** the real worst case, so even with (1) and (2) fixed the two heaviest files would still have been killed as false failures.

**A fourth cause was not a memory bug at all, and it is the one that produced "no output whatsoever".**
The watchdog sampled each live process with `rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null)`.
Written as a bare assignment, the exit status of a simple assignment *is* the command substitution's, so when a process exited in the microseconds between the `kill -0` liveness check and the `ps` call, `ps` exited 1, the assignment exited 1, and `set -e` tore the whole stage down - past the watchdog roll-up, past the verdict line, leaving a log that ended at the header.
It is a **race**, which is why no test caught it: two stub files that both sleep never lose it, and 130 real files lose it almost every run.
Measured on this tree before the fix: **9 of 130 files unmeasured, each annotated "see the message below", with no message below** - the stage had already died.
The fix is `|| rss_kb=` on that one line, and it is load-bearing rather than defensive; `tests/suites/run-tests-stage.sh` section K drives it with a stub `ps` that always fails, which is the same status the race produces without needing timing luck.

The same run showed a second, independent way to lose the explanation: those kill messages were printed inline once both passes had finished, so **any** abort before that point discarded the reason for every kill already made.
They are emitted from `_sc_verdict` instead - the one function the `EXIT`/`INT`/`TERM` traps all call - so no exit path can lose them.
Section L pins that.

Peak RSS, measured with `/usr/bin/time -l`, one file per invocation, watchdog out of the way:

| file | peak RSS | when measured |
|---|---|---|
| `tests/suites/dast-hosthdr.sh` | did not converge - sampled between 9GB and **>25GB** repeatedly over 40+ minutes, killed unfinished rather than left to run indefinitely | this ticket |
| `tests/suites/dast-cors.sh` | **23.79 GB** (25,536,643,072 bytes, kernel-reported `maximum resident set size`) | this ticket |
| `tests/suites/dast-methods.sh` | **~22-41 GB**, non-reproducible run to run (see below) | sibling ticket, "cut shellcheck -x back-edges in dast-methods.sh" |
| `tests/suites/dast-cookies.sh` | 12.99 GB | earlier ticket - now known **stale**, see below |
| `tests/suites/dast-jwt.sh` | 12.96 GB | earlier ticket - now known **stale**, see below |
| `scan.sh` | 4.74 GB | earlier ticket |
| `modules/sca/run.sh` | 3.46 GB | earlier ticket |
| `lib/engines.sh` | 0.11 GB | earlier ticket |

**The 12.99GB/20GB pair above is stale, not just old.** `dast-cors.sh` and `dast-hosthdr.sh` were confirmed (by the sibling back-edge-cutting ticket, then re-confirmed by this one, reading every `source` line in each by hand) to carry **zero repeated source targets** - there is no redundant edge left to cut in either file. Their cost is the irreducible floor of sourcing `lib/http.sh` once plus `modules/dast/engine.sh` once (which itself pulls in `modules/sast/engine.sh` -> `lib/report.sh`/`lib/config.sh` -> `lib/findings.sh`/`lib/records.sh`/`lib/core.sh`) - the same two chains every DAST phase test needs - and that floor alone now measures **23.79 GB** on `dast-cors.sh`, almost double the old 12.99GB reference and already above the old 20GB pass-2 ceiling. A real full-stage run during this ticket (165 files today, not 130) skipped `dast-methods.sh`, `dast-hosthdr.sh` and `dast-cors.sh` at the 20GB budget for exactly this reason: the shared `lib/` dependency chain has grown since the 12.99GB figure was taken, independent of any individual file's own source-graph hygiene.

**Peak RSS is not a fixed property of a file, and this ticket measured why.** `shellcheck`'s GHC runtime ignores `+RTS -M` in the shipped binary and sizes its heap off *ambient available memory at measurement time*, not off a fixed multiple of what the check actually needs. Watched directly on this host (64GB total, ~52GB available, otherwise idle): `dast-cors.sh`'s RSS did not climb monotonically - it oscillated (6.1, 8.7, 6.5, 7.8 GB, ...) for 18 minutes of a mostly-idle host before spiking to its 23.79GB peak in the run's final seconds, and `dast-hosthdr.sh` oscillated between roughly 3GB and >25GB repeatedly over 40+ minutes without ever settling, its RSS visibly jumping upward the moment `dast-cors.sh`'s process exited and freed memory back to the host. This is the same non-reproducibility the sibling ticket reported for `dast-methods.sh` (22-41GB across runs), now independently reproduced rather than only claimed. The practical consequence: a worst-case figure measured on a memory-rich host is not a reliable ceiling for a memory-constrained one, and vice versa - **the `jobs * budget <= headroom` clamp below, not the absolute budget number, is what actually keeps this model safe across host sizes.** Re-measuring and hand-tuning the constant is a stopgap; see "Known follow-up" below for the structural fix.

The model separates two jobs that a single number cannot do at once, and keeps one invariant in every pass - **`jobs * budget <= headroom`** - so the stage can never commit more memory than it has established the host can give:

```
total     physical RAM
avail     obtainable now without swapping
          Linux: MemAvailable;  macOS: free + inactive + purgeable + speculative
reserve   left for the OS and everything else = max(2, total/8)
headroom  = max(avail - reserve, 1)
```

**Pass 1** plans against a *typical* footprint (`SCOURSH_SHELLCHECK_STEP_GB`, default 5GB - above `scan.sh`'s 4.74GB, so the body of the tree clears it) and runs wide.
A file that exceeds it is **not** a failure, it is **deferred**.
**Pass 2** re-runs only the deferred files against the *runaway* trip point (`SCOURSH_SHELLCHECK_MEM_BUDGET_GB`, default **50GB** as of this ticket, raised from 20GB) - roughly 2x the confirmed 23.79GB floor and within reach of the sibling ticket's observed 41GB upper end for `dast-methods.sh`, necessarily narrow.
Both budgets are clamped down to `headroom`, which is what makes (2) above (from the earlier, since-fixed model) impossible to reproduce, and which also means raising the default costs nothing on a small host: it is clamped down to whatever that host can actually give, and a file too heavy for the host is **skipped**, not killed.

| host | avail | reserve | headroom | pass 1 | pass 2 | outcome |
|---|---|---|---|---|---|---|
| 8GB | 6 | 2 | 4 | 1 x 4GB | *(no gain, skipped)* | every file above ~4GB is **reported as skipped by name**, `dast-cors.sh`/`dast-hosthdr.sh` included |
| 27GB | 20 | 3 | 17 | 3 x 5GB | 1 x 17GB | `dast-cors.sh` (23.79GB) still does **not** fit in 17GB headroom on this size host and is skipped by name; lighter files are measured |
| 64GB | 36 | 8 | 28 | 5 x 5GB | 1 x min(50,28)=28GB | `dast-cors.sh` (23.79GB) now fits with real but not generous margin; `dast-hosthdr.sh` and `dast-methods.sh`'s upper range (up to 41GB) may still skip on this documented reference size - that is an accepted "skipped, not failed" outcome, not a regression |

The 27GB and 64GB rows are a deliberate, honest change from the previous version of this table: raising the ceiling constant helps only on hosts with enough real headroom to use it, and on the documented reference hosts above, the two hardest files may still be skipped even now. A host with more available memory than these examples (this ticket was run on a 64GB host with ~52GB available, i.e. ~44GB headroom) comfortably measures all three.

`tests/suites/run-tests-stage.sh` section J drives multiple host shapes from one machine via the `SCOURSH_SHELLCHECK_FORCE_{TOTAL,AVAIL}_GB` test seams and checks the invariant by **parsing the numbers the stage prints**, so it cannot be satisfied by a stage that prints a plausible plan and runs something else.

**Known follow-up, filed separately rather than attempted here:** `lib/http.sh` sources both `lib/config.sh` and `lib/findings.sh`, and both of those independently source `lib/records.sh` (which itself sources `lib/core.sh`) - a real, uncut diamond, confirmed by reading every `source`/`# shellcheck source=` line in `lib/http.sh`, `lib/config.sh`, `lib/findings.sh` and `lib/records.sh` during this ticket. Every one of the ~130+ files that reaches `lib/http.sh` - which is most of `modules/dast/` and its tests - pays for `lib/records.sh` and `lib/core.sh` being inlined twice by `shellcheck -x`. Cutting the second edge (`lib/findings.sh`'s own `source lib/records.sh` line) to `# shellcheck source=/dev/null` is lossless for every consumer that reaches `lib/findings.sh` via `lib/http.sh`, because `lib/config.sh` is sourced first in that file and already inlines `lib/records.sh`. It is **not** obviously lossless for every consumer of `lib/findings.sh` directly (`lib/report.sh` and several `tests/suites/*.sh` files source it without going through `lib/config.sh` first), so verifying the cut is safe everywhere it applies needs its own pass through every consumer chain - real, scoped, structural work, not a documentation change, and is why this ticket raises the budget rather than attempting the cut. This would reduce the actual measured cost (not just move the ceiling to tolerate it), which the ambient-memory finding above argues is the more durable fix.

### The two safety layers, and telling them apart

Both are watched every 0.4s against the currently-running processes:

1. **Per-process budget**: a process exceeding the current pass's budget is killed (`SIGTERM` then `SIGKILL`) and reported as **`OVER BUDGET`**, naming the file, its actual RSS, and stating that host pressure was *not* the cause.
2. **Available-memory floor** (`SCOURSH_SHELLCHECK_FREE_FLOOR_GB`, default: `reserve`): even when every process is within budget, something *else* on the machine can grow after the plan was made. The single largest active process is killed to relieve pressure and reported as **`HOST MEMORY PRESSURE`**, stating that its own RSS was within budget and this is the host's doing, not the file's. It is derived from host size rather than being the absolute 4GB constant it was - 4GB is half of an 8GB machine and 6% of a 64GB one, so as a constant it could only ever be right on one size of host.

**These two must never share a message.** An unattributable kill is the defect, not merely a symptom of it: a reader cannot act on "watchdog killed pid 19523" without knowing whether the file needs more memory than it was given or something unrelated on the machine grew.
Sections C2 and H pin the two arms and each asserts the *other's* wording is absent, so neither can be satisfied by one generic line.

A pressure kill is **not the file's fault, so it is retried** in pass 2 rather than counted against it. That retry is what turns "19 of 128 files went unmeasured" into zero unmeasured files.
A file killed for pressure in *both* passes has had its retry and fails - that is a real failure to measure, not a host size limit.

A failure is always attributable: every kill names the file directly, and a process that dies from **any** signal - including one this script did not send, such as a host-level OOM killer - is still detected (by exit status, not by output parsing) and reported with the file name and the signal number, never as a bare non-zero exit.
The branch on success/failure is on real exit status throughout, not on parsed output, so a failure in any file - the first one launched or the last - still fails the stage.

### Skipped is a third outcome, and it is not a failure

A file that demonstrably needs more memory than this host can give is **skipped**: named, counted, and carried into the run's own last line, which reads `all green (NOT a full pass: the shellcheck stage skipped N file(s) ...)` rather than a bare `all green`.
It does **not** fail the stage, because "this machine is too small for this file" is a fact about the machine - the same class as `shellcheck` not being installed at all - and a stage that can never exit 0 is what made `tests/run-tests.sh` unable to pass for anyone.
Both directions matter and each is the other's bug: report it as a failure and nobody can ever get a green run; report it as nothing and unmeasured files read as clean ones.
It is kept out of the *unmeasured* roll-up, which is for results the stage should have got and did not.

**An unmeasurable file never rounds up to a pass, and is reported separately from a real finding.**
`shellcheck`'s exit 1 is the only status meaning "I checked this file and I have something to say".
Exit 2 is "I could not process this file", 126/127 are "the linter could not be run at all", and 128+n is "died from signal n" (the watchdog, an OOM killer, an operator's `kill`).
The stage keeps those apart, prints them as two separate roll-ups, and fails on either - because "shellcheck said nothing about this file" and "shellcheck found nothing wrong with this file" are different facts and only the second one is evidence.
Collapsing them is the expensive mistake: it sends someone hunting for a defect in a file that was never analysed, or worse, lets an unanalysed file read as clean.

**The verdict line is printed on every exit path, from a trap.**
`--- shellcheck passed` / `--- shellcheck FAILED` used to sit only on the straight-line path, so a `set -E` abort, a `^C`, or a SIGTERM ended the stage after nothing but its `=== linter: shellcheck ===` header - which reads in a log exactly like a stage that ran and was happy.
bash does not run an EXIT trap for an untrapped SIGINT/SIGTERM, so INT and TERM are trapped explicitly rather than left to EXIT.
(One hypothesis about that missing verdict - that `[[ $sc_biggest_pid == "$pid" ]] && sc_biggest_pid=` aborted the script under `set -e` when the test was false - was **measured and refuted**: bash exempts a whole `A && B` list from `set -e` when `A` itself fails, at top level and inside a loop or `if` body alike.)

**The `set -E` arm of that trap is only reachable because of how `sc_stage` is CALLED, and that is the fragile part of this design.**
The stage body was top-level code before it became a function.
bash disables `errexit` for the **entire body** of a function invoked in an `A || B` list, not merely for the call, so `sc_stage || failed+=(shellcheck)` would silently strip that strictness and leave the `EXIT` trap documenting a protection that can never fire.
`sc_stage; sc_rc=$?` is not the alternative either - a function returning non-zero as a plain command *is* an errexit abort, so the runner would die on any run where shellcheck reports anything.
The shipped shape is therefore: **`sc_stage` always returns 0 and reports through the global `SC_STAGE_STATUS`**, and the caller branches on that.
Measured under the `||` spelling with a stub `mktemp` that fails: the stage continued with an empty `$sc_shard_dir`, reported two files as "checked and reported findings" when shellcheck had never run on either, and the runner then printed `all green` and exited **0**.
`tests/suites/run-tests-stage.sh` section F pins this, and goes red under exactly that spelling.

**Running the stage on its own:** `tests/run-tests.sh shellcheck`.
It is a *stage*, not a suite or a linter file - it has no `tests/*.sh` of its own - so it is listed under `stages:` in `--list` and named in `STAGES`, not `SUITES`/`LINTERS`.
`SCOURSH_SHELLCHECK_FILE_LIST` overrides the file list; it is a **test seam** used only by `tests/suites/run-tests-stage.sh` (which drives the real stage over a two-file fixture with a stub `shellcheck`, so the watchdog and the signal paths are exercised in seconds), and it is not a way to exclude files - a real run has it unset and still checks every `*.sh` in the tree.

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
