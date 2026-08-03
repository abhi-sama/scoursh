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
The remaining keys (`requests-per-second`, `http-timeout`, `max-redirects`, `request-budget`, the circuit-breaker pair, `max-matches-per-file`, `evidence-max-bytes`, `scratch-dir`, the state/history/lock/mutex settings, `paranoid-allow`) are schema-checked structurally when the file loads (unknown keys and cardinality errors are caught) but their *value* shape (e.g. "must be a positive integer") is only enforced once a future module actually calls for that key - they take effect as `lib/http.sh`'s rate limiter, circuit breaker, and `--paranoid` enforcement land (`docs/DESIGN.md` §13 steps 5 and 8).
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

- **`scan.sh sast`** runs `modules/sast/engine.sh`'s native pattern engine over the scan root against
  whatever `modules/sast/rules/*.rules` packs are on disk today - `secrets`, `crypto`, `injection`, and
  per-language packs for Python, JavaScript/TypeScript, Go, and Java - and additionally replays
  `secrets.rules` across git history via `modules/sast/history.sh`, populating the `SAST-HIST-*` check
  family.
- **`scan.sh iac`** runs the same pattern engine over infrastructure-as-code via `modules/iac/parse.sh`:
  Terraform HCL (`modules/iac/terraform.rules`, seven checks covering open CIDRs, public ACLs,
  unencrypted resources, disabled key rotation, public IPs, hardcoded secrets, and publicly-reachable
  RDS instances) and Helm charts (`modules/iac/helm.rules`). CloudFormation is still out of scope.
- **`scan.sh sca`** (`modules/sca/engine.sh`) parses npm/yarn/pnpm lockfiles under the scan root and
  matches every pinned dependency's exact ecosystem/name/version against the vendored,
  pre-expanded `data/advisories.db`, emitting one finding per matched advisory.

`dast` and `cloud` have not landed yet: their subcommands are still a logged no-op, recording a
`coverage_reduction` fact in `run.json` (`reason=not_yet_built`) instead of scanning anything, and the
profile/intensity filter chain likewise records `reason=no_check_registry_on_disk_yet` for them since
they have no check registry on disk.
`diff` and `report` behave the same way (`reason=not_yet_built`) once their own required-input checks pass.
This means a scan run today validates flags, config, and (for `dast`) the scope gate correctly for every
subcommand, and always produces a `run.json`; for `sast`, `iac`, and `sca` it also produces real
findings in `findings.jsonl`, while `dast` and `cloud` still produce none.
`--paranoid` is accepted and validated but has no enforcement yet (`docs/DESIGN.md` §13 step 8); `--baseline` is accepted but not yet consulted (suppression logic lands with `state/` at step 7).

### Known gaps

- `report`'s `--from` flag name is not specified in `docs/DESIGN.md`'s grammar block (it only says "regenerate reports from a prior run's findings.json" with no flag shown); `--from` is the engineer's own judgment call, noted as such in `scan.sh`'s own comments for a human to confirm or override.
- No SARIF or compliance-mapping report exists yet (`docs/DESIGN.md` §13 step 10), so `--format sarif` is accepted but there is nothing yet that emits SARIF.
