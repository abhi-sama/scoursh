# Runbook: CI pipeline and required checks

Audience: engineers contributing to scoursh (PR authors) and whoever administers this repository's branch protection.

## What CI runs

The pipeline is a single GitHub Actions workflow, `.github/workflows/ci.yml`, named `tests`.
It triggers on every push to any branch and on every pull request.
It has two jobs.

### Job `suite` (matrix: `ubuntu-latest` / GNU coreutils, `macos-latest` / BSD)

Each matrix leg checks out the repo, installs a bash that meets the frozen 4.2 minimum (macOS ships bash 3.2, which lacks associative arrays), installs `shellcheck`, prints the userland's tool versions for debugging, then runs `tests/run-tests.sh`, which executes:

**Suites** (`tests/suites/*.sh`, one process each):

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
| `gate-mutation-proof` | Mutation-tests the non-bypassable safety gates (`http_request`'s chokepoint, `config_scope_require`, `classify_derived` condition (a)) by deleting the guarding line in a scratch copy and asserting the outcome actually changes - so a fixture that stopped discriminating pass from fail (as happened once, see the suite's own header) fails loudly instead of certifying a broken gate green. |

**Linters** (`tests/*.sh`):

| Linter | Purpose |
|---|---|
| `lint-rules` | Record-format linter: whole-repository checks the per-record parser can't do alone - check-id namespace, contributor existence/chaining, correlation-key capability, rubric uniqueness, cross-references. |
| `lint-shell` | Enforces: no bare `grep`/`rg` outside `scan_match`, no `source`/`eval` on config/rules/data, the network chokepoint (`lib/http.sh`, plus `tools/vendor-engines.sh` as the one documented quarantined exception - tension 27), that nothing under `lib/`/`modules/`/`scan.sh` wires `tools/vendor-engines.sh` into a scan, one capability layer. |
| `lint-aws-readonly` | Enforces every AWS call goes through `aws_ro` with an operation on the frozen read-only prefix allowlist. Passes over an empty set today; `lib/awscli.sh` and `aws/live/` land at step 6. |
| `lint-status` | The generated build-status blocks in `AGENTS.md` and `docs/FOUNDATION.md` equal a fresh `tools/gen-status.sh` run, the two blocks are byte-identical, a hand-edited block is caught, and an edit *outside* the markers is not. Fix a failure with `tools/gen-status.sh --write`, never by hand-editing the block. |

**`shellcheck`** runs last, over `lib/`, `tests/`, `tools/`, `modules/`, `aws/`, `scan.sh`, if the binary is present.
It is optional locally (an air-gapped host may not have it) but CI always installs it, so it is effectively required in CI even though `tests/run-tests.sh` itself treats it as best-effort.
It runs in parallel batches sized to the host's own core count (`nproc`, then `getconf _NPROCESSORS_ONLN`, then `sysctl -n hw.ncpu`, falling back to 4), one batch per core via `xargs -P`, each batch writing to its own shard file rather than shared stdout so parallel writers cannot interleave a finding across two files.
`-x` (follow `source`) still runs on every batch; only the process count changed.
A failure in any batch, first or last, still fails the stage: the branch is on `xargs -P`'s own aggregate exit status (123 if any invocation exited 1-125), not on parsed output.

Each matrix leg finishes by running the fixture scan again, normalizing out the one field that legitimately differs between runs (`first_seen`/`last_seen` timestamps), and uploading `findings.normalised.jsonl` plus the full suite log as artifacts.

### Job `compare` (`ubuntu-latest`, `needs: suite`)

Downloads both userlands' normalized `findings.jsonl` artifacts and runs `diff -u` between them.
This is tension 24's actual requirement: the build fails if a single finding, fingerprint, or byte differs between the GNU run and the BSD run.
Everything else in the `suite` job establishes that the tool behaves correctly on each platform; `compare` establishes that it behaves *identically* across them.

## Required checks today

**Status: branch protection is NOT currently enforced on `main`.**
This is a known gap, not a completed control - do not read anything below as meaning `main` is protected.
GitHub pushes to `main` are not currently blocked by CI status or by review; the only thing preventing an unreviewed or red-CI change from landing on `main` is that every change today arrives via a PR an agent opens and a human or reviewing agent merges deliberately, and CI already runs the three required contexts (below) on every push and PR.
That is process discipline, not a server-side gate: it is the last line of defence that is missing, not the only one.
See "Operator decision, 2026-08-02" below for why this is being left as-is for now, and the JSON payload and `gh api` command further down are ready to apply verbatim the moment that changes.

CI produces three check runs per push/PR: the two `suite` matrix legs and `compare`.
All three should be configured as required status checks on protected branches, since `compare` only means something once both `suite` legs have reported, and `suite` failing on either userland is exactly the class of defect this pipeline exists to catch.

There is no separate "egress-lint" or "smoke-test" workflow: `tests/run-tests.sh` runs `lint-shell` (the egress-chokepoint/no-bypass linter) and the `ci-smoke` suite (`tests/suites/ci-smoke.sh`, added for the step-2 exit-code/profile smoke matrix) as part of the same `suite` job on both matrix legs. So "step-2 tests, egress-lint, smoke test" (the ticket's phrasing) map onto exactly the three check names below - there is nothing further to add to `ci.yml` for this ticket; see the checklist below for why a new suite/linter never needs a workflow edit.

The three GitHub check names to require (read off the Checks tab of a real run; GitHub displays the job's `name:` field, not the workflow name `tests`):

- `ubuntu-latest (GNU coreutils)`
- `macos-latest (BSD)`
- `compare`

### Target branch-protection configuration for `main`

```json
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "ubuntu-latest (GNU coreutils)" },
      { "context": "macos-latest (BSD)" },
      { "context": "compare" }
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
```

Apply with (requires an admin token on a plan that supports this - see the blocker below):

```
gh api --method PUT repos/abhi-sama/scoursh/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{ ...the object above... }
JSON
```

`required_pull_request_reviews` being non-null is what disables direct pushes to `main` (GitHub always routes protected-branch changes through a PR once any review requirement or status check is required) and satisfies the "changes land via PR only" acceptance criterion.
`enforce_admins` is deliberately `false` at rollout: `abhi-sama` is currently the sole admin and the only person who can unblock a red `main` if the required checks themselves regress.
Flip it to `true` once there has been at least one real PR merged under the new rule with no incident, per the checklist below.

**Blocker (confirmed, not a token/scope problem):** both the classic branch-protection API and the newer rulesets API refuse to configure anything on this repo:

```
$ gh api repos/abhi-sama/scoursh/branches/main/protection
{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature.","status":"403"}
$ gh api repos/abhi-sama/scoursh/rulesets
{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature.","status":"403"}
```

Confirmed this is a plan limitation, not a permissions gap: `gh api repos/abhi-sama/scoursh/collaborators/abhi-sama/permission` reports `admin`, and the token has the `repo` scope.
GitHub disables both branch protection and rulesets for private repositories on the Free plan for personal accounts; public repositories and paid plans (Pro/Team/Enterprise) are unaffected.
This repo is private (`scoursh` is a security tool with vendored rule content; making it public is a product decision, not an infra one).

Unblocking requires a human decision between:

1. Upgrade the `abhi-sama` account to GitHub Pro (or move the repo under a GitHub Team org), then run the `gh api` command above, or
2. Make the repository public, which lifts the restriction on the Free plan at the cost of exposing the rule/check catalog and scan logic, or
3. Defer enforcement and rely on the documented convention (PR-only, three required checks) without a server-side gate until (1) or (2) happens.

### Operator decision, 2026-08-02

Option 3, for now: leave `main` un-enforced and rely on the documented PR-only convention, rather than force (1) or (2) tonight.
Rationale recorded here so it isn't re-litigated: (1) and (2) both cost something only the product owner should decide to spend - money for a paid plan, or exposing a security scanner's rule/check catalog by going public - and neither was urgent enough to force immediately.
The practical exposure of option 3 is narrower than "no protection at all" suggests, because the PR-only convention is already enforced by the delivery process (every change to `main` currently arrives via an agent-opened PR that a human or reviewing agent merges deliberately, and CI already runs all three required contexts on every push and PR); what is actually missing is GitHub refusing a direct push if someone bypasses that process.
That is a real gap in the last line of defence, not the only line, and not yet closed.

The configuration above is ready to apply verbatim, unchanged, the moment (1) or (2) is chosen - it is a single `gh api` call once the plan/visibility allows it, no further engineering work needed.

## GNU/BSD dual-runner rationale

`docs/FOUNDATION.md` tension 24 is the source of this design; the summary an operator needs:

scoursh is a shell tool that must run identically on an air-gapped Linux host (GNU coreutils) and on macOS (BSD userland), and the two disagree on facts the codebase depends on - measured on this codebase, not assumed:

- macOS ships bash 3.2, which has no associative arrays; the tool's frozen minimum is bash 4.2, so the macOS leg installs a newer bash via Homebrew before running anything.
- `shred` is GNU-only and absent on macOS; the `EXIT` cleanup trap never calls it directly (that failed loudly at exit 127 on macOS during development), and `erase_dir` treats overwrite-based erasure as best effort instead.
- `sort -V` is GNU-only; the tool avoids needing it at all rather than working around it (tension 25 moves SCA version-range arithmetic off the scanning host entirely).
- `xargs -P` is used without `-r`, which BSD lacks, by checking the unit count before ever invoking `xargs` on a possibly-empty input.
- Bash's `=~` uses the system `regcomp`, which on macOS/BSD supports none of `\b \w \s \d`; `redact()` routes through `grep -E`/`rg` instead of matching in-process, because both of those support all four on both userlands.

A design that only runs one of these platforms in CI would let any of the above regress silently - the failure mode is not "the tool crashes," it's "the tool produces a different, wrong answer on one platform and nobody notices until an operator hits it in the field."
Running the full suite on both, then diffing byte-for-byte in `compare`, turns "one capability layer, behaving identically everywhere" from a design intention into a property CI actually checks.

## Checklist: adding a new required check for a future step

Use this when a future `docs/DESIGN.md` §13 step (DAST, the AWS read-only lint's real content, SARIF, etc.) needs a new suite or linter to gate merges.

1. **Write the suite or linter as its own script.**
   Suites live at `tests/suites/<name>.sh`; linters live at `tests/<name>.sh`.
   Each runs in its own process (`lib/core.sh` installs traps and owns a scratch directory per process; sharing a shell with another suite would not test what the tool actually does).
2. **Name the reading each pinned test fails under**, in a comment on the assertion.
   This is an existing repository rule (see AGENTS.md's Tests section): a test written after the rule, without a stated failing reading, can pass under both the correct and the rejected implementation and certify a defect green.
3. **Register it** in `tests/run-tests.sh`: add the name to the `SUITES` or `LINTERS` array at the top of the file.
   Do not hand-write a new invocation elsewhere; `run-tests.sh` is the single entry point both `pnpm test` and CI use, and `--list` must show the new name.
4. **No `.github/workflows/ci.yml` edit is needed for the check itself.**
   Both matrix legs already run `tests/run-tests.sh` in full, so a new suite or linter is picked up automatically on the next push, on both userlands, with no workflow change.
5. **If the new check writes to `findings.jsonl` or affects fingerprints**, verify it survives the `compare` job: run it under both a GNU and a BSD userland (or at minimum `shellcheck` it and reason through the "Things measured on this codebase, not assumed" list in AGENTS.md) before merging, since a GNU-only assumption here fails on `macos-latest`, not locally.
6. **If the new check needs a tool that isn't in scoursh's required dependency set**, add a capability probe (`lib/core.sh`'s pattern for `rg`, `openssl`, `aws`, GNU `parallel`, etc.) rather than assuming the tool exists; record what the probe found in `run.json`.
7. **If the new check is meant to block merges**, add its check name to the branch-protection required-status-check list in Settings > Branches once a real CI run has produced it (see "Required checks today" above for why the exact displayed name matters).
8. **Update `AGENTS.md`'s Tests section** (the suite/linter counts and the command list) so it doesn't drift from `tests/run-tests.sh --list`.
