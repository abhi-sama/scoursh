# scoursh
scoursh - scan exhaustively

## Usage

`scoursh` is a single entry point, `scan.sh`, with one subcommand per surface it scans.
Every run writes `run.json` into its output directory, whether or not any findings were produced.

```
scan.sh <command> [options]
```

### Commands

| Command | Flags | Notes |
|---|---|---|
| `sast` | `[--path DIR]` `[--lang py,js,go,java]` `[--history]` | Source code. `--history` replays secret checks across git history and requires `git` on `PATH`. |
| `sca` | `[--path DIR]` | Dependency/lockfile CVEs. |
| `iac` | `[--path DIR]` | Cloud IaC plus container/Kubernetes manifests. |
| `dast` | `--target NAME` `[--intensity passive\|safe\|active]` `[--authed]` | `--target` is required and must name an entry in `config/scope.conf` (see "The scope gate" below). `--intensity` defaults to `passive`. |
| `cloud` | `[--live]` `[--profile NAME]` `[--regions all\|us-east-1,...]` `[--assume-role ARN]` | `--live` requires the `aws` CLI on `PATH`; the run refuses (exit 4) if it is missing. |
| `all` | union of every module's own flags above | Runs sast, sca, iac unconditionally; runs dast only if `--target` is given and cloud only if `--live` is given. Every module it skips is recorded in `run.json` as a `coverage_reduction` fact, not silently dropped. |
| `diff` | `--against DIR` | `DIR` must be a prior run's output directory (must contain `findings.jsonl` or `run.json`). |
| `report` | `--from DIR` | Regenerate reports from a prior run's directory (same shape requirement as `diff --against`). |

`-h` / `--help` at any position before the first unrecognized token prints usage and exits 0.

### Global flags (apply to every command)

| Flag | Value | Default |
|---|---|---|
| `--profile-scan` | `quick` \| `full` \| `compliance` | `full` |
| `--paranoid` | boolean | off |
| `--allow-intrusive` | boolean | off |
| `--jobs N` | positive integer | from `config/scanner.conf` (`4`) |
| `--format` | CSV of `json,sarif,html,md` | all four |
| `--fail-on` | `critical\|high\|medium\|low\|info\|none` | from `config/scanner.conf` (`none`) |
| `--fail-on-new` | boolean; **requires `--fail-on`**, usage error otherwise | off |
| `--min-confidence` | `high\|medium\|low` | from `config/scanner.conf` (`low`) |
| `--baseline FILE` | path | none |
| `--out DIR` | path | `reports/<timestamp>` |

### Exit codes

Checked in this fixed order - the first true condition wins, never "worst finding wins":

| Code | Meaning |
|---|---|
| `0` | Clean, or findings all below `--fail-on`. |
| `1` | Findings at or above `--fail-on` (the CI gate). |
| `2` | Usage error (bad flag, bad value, missing required flag). |
| `3` | Scope violation (`dast --target` not found in `config/scope.conf`). |
| `4` | Missing required input (unreadable path, missing config file, missing required command). |
| `5` | Incomplete run (circuit breaker tripped or the run aborted mid-flight). A run that both trips the breaker and has gated findings exits `5`, not `1` - an incomplete run cannot assert a clean gate result either way. |

### The scope gate (dast)

Plain language: **`dast` will not touch a host you have not explicitly listed.**
Before any request goes out, `--target NAME` must match the `id` of an entry in `config/scope.conf`.
If `config/scope.conf` does not exist at all, the run refuses with exit `4` ("missing required input") - `dast` cannot even attempt the gate.
If the file exists but has no entry with that `id`, the run refuses with exit `3` ("scope violation") - the gate itself is refusing.
There is no raw-URL flag that bypasses this: `--target` only ever takes a name, never a URL.
`sast`, `sca`, and `iac` do not need `config/scope.conf` at all.

The gate matches on the normalized `(scheme, host, port)` tuple from the target's `base-url`, plus any `extra-host` entries.
Path is **not** part of the gate - it only bounds what the crawler will fetch, it is not a safety boundary.

### `--paranoid` - the connection observer (a detector, not a guarantee)

`--paranoid` builds a run-scoped allowlist from exactly four sets (`docs/FOUNDATION.md` tension 20): every in-scope target address `lib/http.sh` actually resolves this run, resolved AWS endpoint addresses for regions actually iterated (empty, with a stated reason, until `modules/cloud/aws/regions.sh` lands), the host's own `/etc/resolv.conf` nameservers on port 53 plus loopback on any port, and `config/scanner.conf`'s `paranoid_allow` entries.
It then samples this run's own connections (`ss`, or a measured-usable `strace -f -e trace=connect` fallback) and aborts with exit `3` on the first destination it observes outside that allowlist.
If neither `ss` nor a usable `strace` exists on the host, the run refuses with exit `4` rather than pretending to be watching.

**Read this plainly: it is a detector, not a guarantee.**
Sampling can miss a connection that opens and closes between two polls.
`tools/run-in-netns.sh` (not yet built - see `docs/STEP8-PARANOID-PLAN.md`) is the actual guarantee: a network namespace whose only route is the declared scope makes an out-of-scope connection categorically impossible rather than merely observable.
Every `--paranoid` run states this same limitation in its own `run.json` (`coverage_gap`), so the report never overstates what the flag proved.

## Configuration

Both config files use the same on-disk record format: blank-line-separated `key: value` blocks, one `#`-prefixed comment per line, no escaping in values.
Never hand-edit these with tooling that assumes shell syntax - the loader parses them as data and never `source`s them.

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

### `config/scanner.conf` - optional; an absent file behaves as if it contained only `id: scanner`

Resolution order for every key, checked independently per key: **CLI flag > environment variable > file > built-in default**.
A level that is present but invalid dies immediately (CLI/env: exit `2`; file: exit `4`) - it never silently falls through to the next level.
The environment variable for key `foo-bar` is `SCOURSH_CONFIG_FOO_BAR`.

| Key | Value | Default |
|---|---|---|
| `requests-per-second` | decimal, may be fractional | `4` |
| `jobs` | positive integer | `4` |
| `http-timeout` | positive integer (seconds) | `20` |
| `max-redirects` | non-negative integer | `5` |
| `request-budget` | positive integer, per run | `20000` |
| `circuit-breaker-failures` | positive integer | `10` |
| `circuit-breaker-window` | non-negative integer (seconds) | `60` |
| `fail-on` | severity name or `none` | `none` |
| `min-confidence` | `high\|medium\|low` | `low` |
| `redact-secrets` | `true`/`false` | `true` |
| `formats` | repeatable, `json\|sarif\|html\|md` | all four |
| `max-matches-per-file` | positive integer | `200` |
| `evidence-max-bytes` | positive integer | `512` |
| `scratch-dir` | absolute path | `${TMPDIR:-/tmp}` |
| `state-retain-runs` | positive integer | `30` |
| `history-window-days` | positive integer | `365` |
| `history-max-commits` | positive integer | `5000` |
| `lock-stale-seconds` | positive integer | `30` |
| `mutex-timeout-seconds` | positive integer | `120` |
| `paranoid-allow` | repeatable, `addr:port` | empty |
| `notes` | free text (multi-line) | empty |

**Implementation note:** as of this build (`docs/DESIGN.md` §13 step 2), `scan.sh` only actually reads and exports four of these keys at run time - `jobs`, `fail-on`, `min-confidence`, and `redact-secrets`.
`formats` is parsed and validated but its resolved value is currently discarded (no format-specific writer is wired in yet).
`paranoid-allow` is now read and enforced by `--paranoid` (`lib/paranoid.sh`, `docs/DESIGN.md` §13 step 8) - see "`--paranoid` - the connection observer" above.
The remaining keys (`requests-per-second`, `http-timeout`, `max-redirects`, `request-budget`, the circuit-breaker pair, `max-matches-per-file`, `evidence-max-bytes`, `scratch-dir`, the state/history/lock/mutex settings) are schema-checked structurally when the file loads (unknown keys and cardinality errors are caught) but their *value* shape (e.g. "must be a positive integer") is only enforced once a future module actually calls for that key - they take effect as `lib/http.sh`'s rate limiter and circuit breaker land (`docs/DESIGN.md` §13 step 5).
Setting them today is safe but has no observable effect yet.

## Scan profiles and intensity

Three independent filters narrow which checks run; they compose as an **intersection** - the most restrictive one always wins, and none of them can re-enable a check another one dropped.

**`--profile-scan`** (default `full`):
- `quick` - only checks tagged `quick` (passive/config-read checks, no active probes; seconds to minutes).
- `full` - every check in the loaded set. A check with no profile tag only ever runs under `full`.
- `compliance` - only checks tagged `compliance` (checks that map to a CIS/OWASP control, for the audit report).

**`--intensity`** (default `passive`, applies to checks with a type tag - `dast` is the module this matters most for):
- `passive` - passive/config-read/posture/static checks only.
- `safe` - adds safe-active checks.
- `active` - adds active (injection-class) checks.

Composite ("derived") checks are exempt from the `--intensity` ceiling: they consume other checks' findings rather than issuing requests of their own, so no intensity tier is a meaningful ceiling for one.
They are still subject to `--profile-scan` and `--allow-intrusive`.

**`--allow-intrusive`** (default off): drops any check tagged `intrusive` (side-effecting checks such as live user-enum) unless given.

If a filter drops one or more checks, `scan.sh` logs one warning per dropping flag naming the flag and how many checks it dropped.

**Implementation note:** `docs/DESIGN.md` originally described `compliance` as "checks with a non-empty `cis` or `owasp` field," but `owasp` is a *required* field on every check (value `none` when not applicable), so that reading would select the entire catalog.
The shipped behavior - and the one documented above - is the tag reading (`tags: compliance`), settled in `lib/checks.sh`.

## Current status: what running a scan does today

Three modules have landed and produce real findings: `sast`, `iac`, and `sca`.
Everything else `docs/DESIGN.md` §13 schedules - `dast`, `cloud` (including `lib/awscli.sh`), SARIF
output, the compliance report, and `state/` - has not landed yet.
Exactly which rule packs and ecosystems those three modules cover is GENERATED below by
`tools/gen-status.sh` from `modules/` itself, so it cannot drift from the tree the way this section
twice did; `tests/lint-status.sh` fails the build if it does.
`AGENTS.md`'s "Build order and where we are" section remains the fuller account - the design reasoning,
the out-of-order landings, the sub-scopes - and carries the same generated block verbatim.

<!-- BEGIN GENERATED STATUS -->
<!--
  GENERATED by tools/gen-status.sh.  Everything between these two markers is
  machine-written from the repository tree and docs/DESIGN.md's own catalog.

  Do not hand-edit inside the markers: run `tools/gen-status.sh --write`.
  `tests/lint-status.sh` (run by `tests/run-tests.sh`) fails when a committed
  block differs from a fresh generation, so an edit here is a broken build.

  A MERGE CONFLICT INSIDE THIS BLOCK IS NEVER RESOLVED BY HAND.  Take either
  side of the conflict, then re-run `tools/gen-status.sh --write`.
-->

### Module status inventory (generated)

What is PLANNED is parsed from `docs/DESIGN.md`'s own catalog (§6.3 SAST, §6.5
SCA, §6.6 and §8.2 IaC).  What has LANDED is read off the repository tree.  What
REMAINS is the difference, computed rather than typed - which is why no sentence
in here has to be rewritten when a module lands, and why two branches landing
different modules cannot conflict over it.

**Landed** means both halves hold, and both are checked on every run:

1. the artifact exists at its path under `modules/`, and
2. the test tree exercises it - for a rule pack, at least one check id the pack
   itself declares appears in a `tests/**/*.sh` suite; for a script, its
   basename does; for an SCA ecosystem, every manifest `docs/DESIGN.md` §6.5
   names for it is parsed under `modules/sca/` and at least one has a real
   fixture file under `tests/fixtures/`.

A file that is present but that no suite names is **present, untested** - its own
state, never rounded up to landed.  Artifacts are identified by PATH and never by
a commit sha: a ticket cannot know its own landing sha, and invented ones have
shipped here before.

#### SAST - `docs/DESIGN.md` §6.3 catalog -> `modules/sast/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/sast/rules/crypto.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/go.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/injection.rules` | landed | 8 | `tests/suites/sast.sh` |
| `modules/sast/rules/java.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/javascript.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/ldap.rules` | not landed | - | - |
| `modules/sast/rules/nosql.rules` | not landed | - | - |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/secrets.rules` | landed | 5 | `tests/suites/records.sh` |
| `modules/sast/history.sh` | landed | - | `tests/suites/sast-history.sh` |

Landed 8 of 10.  Outstanding: `ldap.rules`, `nosql.rules`.

#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`

| Manifests | Status | Parsers | Exercised by |
| --- | --- | --- | --- |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-ecosystems-php/package-lock.json` |
| `requirements.txt`, `poetry.lock`, `Pipfile.lock` | landed | 3 of 3 parsed | `tests/fixtures/sca/python-requirements/requirements.txt` |
| `go.mod`, `go.sum` | landed | 2 of 2 parsed | `tests/fixtures/sca/go-mod/go.mod` |
| `pom.xml`, `build.gradle` | landed | 2 of 2 parsed | `tests/fixtures/sca/maven/pom.xml` |
| `Gemfile.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/mixed-ecosystems/Gemfile.lock` |
| `composer.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/composer-no-manifest/composer.lock` |

Landed 6 of 6.  Outstanding: none.

#### IaC rule packs - `docs/DESIGN.md` §6.6 and §8.2 -> `modules/iac/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/iac/cloudformation.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/docker-compose.rules` | landed | 4 | `tests/suites/iac.sh` |
| `modules/iac/dockerfile.rules` | landed | 6 | `tests/suites/iac.sh` |
| `modules/iac/helm.rules` | landed | 3 | `tests/suites/iac.sh` |
| `modules/iac/kubernetes.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/terraform.rules` | landed | 7 | `tests/suites/iac-trivy.sh` |

Landed 6 of 6.  Outstanding: none.

#### Totals

- Pattern packs on disk: **13** (`modules/sast/rules/` 7, `modules/iac/` 6).
- Module directories present: `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

- **`scan.sh sast`** (`modules/sast/engine.sh` + `run.sh` + `history.sh` + rule packs) runs the native
  pattern engine over the scan root against whatever `modules/sast/rules/*.rules` packs are on disk
  today (see the generated table above) and additionally replays `secrets.rules` across git history via
  `modules/sast/history.sh`, populating the `SAST-HIST-*` check family.
- **`scan.sh iac`** (`modules/iac/run.sh` + `parse.sh` + one rule pack per file format) runs the same
  pattern engine over infrastructure-as-code, one pack per shape - Terraform HCL, Helm chart sources,
  Dockerfiles, and so on. Which formats are covered, and which are still out of scope, is in the
  generated table above rather than in this sentence.
- **`scan.sh sca`** (`modules/sca/engine.sh` + `run.sh`, plus a per-ecosystem engine file where one
  landed separately) parses dependency manifests under the scan root and matches every pinned
  dependency's exact ecosystem/name/version against the vendored, pre-expanded `data/advisories.db`,
  emitting one finding per matched advisory. Which of `docs/DESIGN.md` §6.5's ecosystems it covers is in
  the generated table above.

`dast` and `cloud` have not landed yet: their subcommands are still a logged no-op, recording a
`coverage_reduction` fact in `run.json` (`reason=not_yet_built`) instead of scanning anything, and the
profile/intensity filter chain likewise records `reason=no_check_registry_on_disk_yet` for them since
they have no check registry on disk.
`diff` and `report` behave the same way (`reason=not_yet_built`) once their own required-input checks pass.
`lib/awscli.sh` (the read-only AWS API wrapper step 6 needs before any `cloud` check can run), `state/`
(the per-(check, scope-cell) coverage tracking step 7 needs for diffing and baseline suppression), SARIF
output, and the compliance report also do not exist on disk yet; they land with steps 6, 7, and 10
respectively.
This means a scan run today validates flags, config, and (for `dast`) the scope gate correctly for every
subcommand, and always produces a `run.json`; for `sast`, `iac`, and `sca` it also produces real
findings in `findings.jsonl`, while `dast` and `cloud` still produce none.
`--paranoid` is now fully enforced (`lib/paranoid.sh`, `docs/DESIGN.md` §13 step 8 - see "`--paranoid` - the connection observer" above); `--baseline` is accepted but not yet consulted (suppression logic lands with `state/` at step 7).

### Known gaps

- `report`'s `--from` flag name is not specified in `docs/DESIGN.md`'s grammar block (it only says "regenerate reports from a prior run's findings.json" with no flag shown); `--from` is the engineer's own judgment call, noted as such in `scan.sh`'s own comments for a human to confirm or override.
- No SARIF or compliance-mapping report exists yet (`docs/DESIGN.md` §13 step 10), so `--format sarif` is accepted but there is nothing yet that emits SARIF.

### Keeping this section honest

This section has gone stale before: for a stretch after `sast`, `iac`, and `sca` had already landed and
were passing tests, it still opened with "no module has landed yet," so a reader trusted stale,
contradictory documentation over the accurate `AGENTS.md` "Build order and where we are" section.
`AGENTS.md` already imposes an "update on landing" discipline on itself - a ticket that lands a
`docs/DESIGN.md` §13 sub-step is not considered done until that section, and its `docs/FOUNDATION.md`
mirror, are updated in the same change.
That recommendation - "enforce it mechanically rather than leaving it to reviewer memory" - is now
implemented. The inventory in this section is generated by `tools/gen-status.sh` from `modules/` and
`docs/DESIGN.md`, and `tests/lint-status.sh` (part of `tests/run-tests.sh`, so part of CI) fails when
the committed block differs from a fresh generation. A ticket that adds a pack or an ecosystem runs
`tools/gen-status.sh --write` and commits the result; it does not hand-write a status sentence here.
A merge conflict inside the generated block is never resolved by hand - take either side and re-run the
generator.
