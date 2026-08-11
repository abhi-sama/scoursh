# Usage reference

The complete CLI, exit-code, and configuration-file reference for `scan.sh`.
For an introduction to what `scoursh` is and why it's built this way, see the main
[`README.md`](../README.md).

## Commands

`scoursh` is a single entry point, `scan.sh`, with one subcommand per surface it scans.
Every run writes `run.json` into its output directory, whether or not any findings were produced.

```sh
scan.sh <command> [options]
```

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

## Global flags (apply to every command)

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

## Exit codes

Checked in this fixed order - the first true condition wins, never "worst finding wins":

| Code | Meaning |
|---|---|
| `0` | Clean, or findings all below `--fail-on`. |
| `1` | Findings at or above `--fail-on` (the CI gate). |
| `2` | Usage error (bad flag, bad value, missing required flag). |
| `3` | Scope violation (`dast --target` not found in `config/scope.conf`). |
| `4` | Missing required input (unreadable path, missing config file, missing required command). |
| `5` | Incomplete run (circuit breaker tripped or the run aborted mid-flight). A run that both trips the breaker and has gated findings exits `5`, not `1` - an incomplete run cannot assert a clean gate result either way. |

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

## `--paranoid` - the connection observer (a detector, not a guarantee)

`--paranoid` builds a run-scoped allowlist from exactly four sets: every in-scope target address
`lib/http.sh` actually resolves this run, resolved AWS endpoint addresses for regions actually iterated
(empty, with a stated reason, until region iteration lands), the host's own `/etc/resolv.conf`
nameservers on port 53 plus loopback on any port, and `config/scanner.conf`'s `paranoid_allow` entries.
It then samples this run's own connections (`ss`, or a measured-usable `strace -f -e trace=connect`
fallback) and aborts with exit `3` on the first destination it observes outside that allowlist.
If neither `ss` nor a usable `strace` exists on the host, the run refuses with exit `4` rather than
pretending to be watching.

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

Resolution order for every key, checked independently per key: **CLI flag > environment variable >
file > built-in default**.
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
