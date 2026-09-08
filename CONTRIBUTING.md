# Contributing to scoursh

Thanks for considering a contribution. This file covers process; it does not restate what the tool
is or how it works - read [`README.md`](README.md) and [`docs/USAGE.md`](docs/USAGE.md) for that
first, and [`AGENTS.md`](AGENTS.md) for the project's working conventions, module status, and its
sharp-edges register (most of it applies to agents and humans alike).

## Before you start

- **Prerequisites and setup**: see [README.md § Install](README.md#install) - bash >= 4.2 plus a
  standard Unix toolchain, no build step. If you're touching SCA, you'll also want the one-time
  `data/advisories.db` setup in
  [`docs/USAGE.md`](docs/USAGE.md#dependency-data-dataadvisoriesdb).
- **Read `docs/DESIGN.md` and `docs/FOUNDATION.md` before a structural change.** `docs/DESIGN.md` is
  the preserved handoff spec; `docs/FOUNDATION.md` is the design-tension register, and where the two
  disagree, `docs/FOUNDATION.md` wins and says so explicitly at each point. Both are normative, not
  historical color - `AGENTS.md` explains why and links the sharp edges that follow from them.
- **`docs/DESIGN.md` §15 is a hard rule, not a suggestion: never overstate coverage.** A scan that
  skips something must say so - as a `coverage_reduction` or `coverage_gap` in the run's own output -
  rather than silently reporting clean. If your change makes a check skip, degrade, or not run under
  some condition, it needs to record that honestly, the same way every existing module does.
- **The egress model is load-bearing.** scoursh is egress-restricted by destination: SAST, SCA, and
  IaC make zero network calls; DAST and live AWS scanning talk only to what the operator explicitly
  authorized in `config/scope.conf`, and only through the two chokepoints (`lib/http.sh`'s `curl`
  wrapper, `lib/awscli.sh`'s `aws_ro`). See `docs/DESIGN.md` §2 and `AGENTS.md`'s "The no-egress rule"
  section. A change that adds a new way to reach the network outside those two wrappers will not be
  accepted; `tests/lint-shell.sh` also enforces this mechanically.
- **No target-specific names, ever.** scoursh is target-agnostic by design (`docs/DESIGN.md` §1): no
  application, company, product, environment, or endpoint name is baked into a script, rule, or doc.
  Rules describe classes of issue, never a specific system.

## Branch model and how a PR flows

- `dev` is the integration branch; `main` is the release branch. Work lands on `dev` first (as a
  squashed commit) and reaches `main` later in batches. Open your PR against `dev`, not `main`.
- **CI runs but does not gate merges.** `.github/workflows/ci.yml` runs the suite on GitHub Actions
  for pull requests and pushes (see [`docs/CI-RUNBOOK.md`](docs/CI-RUNBOOK.md) for exactly what runs
  and when), but by standing project instruction it is not a required check. The real gate is a green
  local run of the test suite before you open the PR - see the next section. A red CI check is real
  information and should not be ignored, but a green PR is defined by your own local run, not by it.
- There is no CLA or DCO in force in this repository. Don't assume one.

## Running the tests and lints locally

`tests/run-tests.sh` is the real entry point (`pnpm test` / `npm test` are thin aliases with no
Node dependency behind them - see `AGENTS.md`'s Tests section for why `package.json` exists at all).

```sh
tests/run-tests.sh              # everything: every suite, every linter, then the shellcheck stage
tests/run-tests.sh --list       # the current, authoritative list of suite/linter/stage names
tests/run-tests.sh <name>       # one suite or linter by name, e.g. tests/run-tests.sh sca
tests/run-tests.sh shellcheck   # the whole-tree shellcheck stage on its own (the slowest part)
```

Run the full suite (or at minimum, every suite and linter your change could plausibly touch) before
opening a PR, and confirm it's green. `docs/CI-RUNBOOK.md` is the full runbook, including the
BSD/GNU dual-userland rationale and the memory model behind the shellcheck stage, if you need it.

If you're adding a new test suite or linter file, follow the checklist in
`docs/CI-RUNBOOK.md § Checklist: adding a new suite or linter` - it covers where the file goes, how
it's registered, and the project's rule that every pinned test names the reading it fails under (a
test that passes under both the correct and the rejected implementation pins nothing).

## Adding a new check or rule

This is the most common contribution to a scanner. **[`rules/RULE-FORMAT.md`](rules/RULE-FORMAT.md)
is the normative, self-contained spec for the on-disk record format** every `.rules` pack and
`config/*.conf` file uses - read it before writing one; it's frozen (§14 spells out why and what
changing it costs) but adding a *new* rule pack or record within the existing format is the ordinary
case and does not touch that.

A few things worth knowing going in, all covered in more depth in `AGENTS.md`'s "Sharp edges" section:

- A new SAST/IaC rule pack needs both a "stays quiet on the clean fixtures" test and a "still fires"
  test - an inert pack (over-narrowed to kill false positives) passes every silence assertion and is
  caught only by the second kind.
- `tests/fixtures/{vuln,clean}/` are shared trees scanned by every pack, so a new pack's `files:` glob
  can cross-fire against a sibling pack's fixtures; check what else matches your glob.
- The pattern engine has no comment awareness - a rule pack's own header prose must not spell out the
  hazardous string it's warning about, or it will match itself.
- After landing a new module or rule pack, run `tools/gen-status.sh --write` and commit the result -
  it regenerates the module-status inventory blocks in `AGENTS.md`, `README.md`, and
  `docs/FOUNDATION.md` from the repository tree. **Never hand-edit inside a
  `<!-- BEGIN GENERATED STATUS -->` / `<!-- END GENERATED STATUS -->` block** -
  `tests/lint-status.sh` checks the committed blocks against a fresh generation and will fail on any
  drift or hand edit. The same applies to a merge conflict that lands inside one: take either side of
  the conflict, then re-run `tools/gen-status.sh --write` rather than hand-merging the table.

## Code style

- Shell (bash), targeting the project's frozen minimum of bash 4.2 - don't use a 4.3+ feature (see
  `AGENTS.md`'s "Things measured on this codebase" section for concrete traps, e.g. `&` in
  `${var//pat/repl}` behaving differently across bash versions).
- Changes should be shellcheck-clean. Run `tests/run-tests.sh shellcheck` (or `shellcheck` directly
  on files you touched) before opening a PR; a warranted `# shellcheck disable=` needs a reason
  attached, per the project's own convention.
- Never call `grep`/`rg` bare - use `lib/core.sh`'s `scan_match` family, which distinguishes "no
  match" from "engine failure" under `set -Eeuo pipefail`.
- Follow the file-header convention already in `lib/`/`modules/` files (a short "Owns:" pointer to
  the design/foundation sections a file implements) rather than inventing a new one.

## Commit and PR conventions

- Commit and PR titles in this repository favor a short module/area prefix (`dast:`, `sca:`, `iac:`,
  `docs:`, `ci:`, ...) followed by a concise, specific summary - look at `git log --oneline` for the
  current style rather than following a fixed spec; there's no enforced Conventional Commits format.
- Keep a PR scoped to one change. If you're touching `AGENTS.md`, follow its own
  "Maintaining this file" section: prefer rewriting or pruning existing entries over appending, and
  don't restate what the codebase already shows - point to the authoritative file or command instead.
- Describe *why* in the PR body, not just *what* - this project's own docs (`AGENTS.md`,
  `docs/FOUNDATION.md`) are written that way throughout, and reviewers will expect it.

## License

By contributing, you agree your contribution is licensed under this repository's
[Apache License 2.0](LICENSE).
