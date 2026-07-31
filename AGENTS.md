# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

## What scoursh is

`scoursh` ("scan exhaustively") is a shell-based, air-gapped security scanner.
One tool audits three surfaces: source code (SAST plus SCA plus IaC), a running endpoint (DAST), and AWS configuration (live read-only plus IaC).

It is **target-agnostic**.
No application, company, product, environment, or endpoint name is ever baked into a script, a rule, or a document.
Every site-specific value comes from the operator's config at runtime.
Rules describe *classes* of issue, never a specific system.
This is `docs/DESIGN.md` §1 and it is a hard rule for every change.

## The no-egress rule, and why it drives everything

Exactly two kinds of outbound traffic are permitted:

1. `curl` to a host the operator authorised in `config/scope.conf`.
2. Read-only AWS API calls to the operator's own account.

Everything else is forbidden: no telemetry, no SaaS backend, no fetching rules or advisories at scan time.
The tool must run on an air-gapped host.

This single constraint explains most of the architecture, so do not "improve" a design decision without checking it against this first:

- Rules, payloads, wordlists, and advisory data are **vendored in the repo** and read from disk.
- `tools/vendor-engines.sh` is the only script that touches the internet, is never called during a scan, and is quarantined and documented as such.
- Every network call goes through the single wrapper `lib/http.sh`, which refuses any host absent from the resolved allowlist.
- Every AWS call goes through `lib/awscli.sh`, which refuses any operation that is not read-only (`docs/FOUNDATION.md` tension 23).
- The HTML report is self-contained with no external assets and a strict inline CSP, because a report that fetches a font is egress.
- Version-range arithmetic for SCA is done on the networked box and shipped pre-expanded, so the scanner only does table lookups (`docs/FOUNDATION.md` tension 25).

## Documents, and which one wins

| Document | Role |
|---|---|
| `docs/DESIGN.md` | The handoff spec. **Preserved verbatim**; its wording is load-bearing. Do not rewrite, re-order, summarise, or "improve" it. |
| `docs/FOUNDATION.md` | The design-tension register. 26 tensions, each with a committed RESOLUTION. **Where it contradicts the letter of `docs/DESIGN.md`, it wins**, and it says so explicitly at each point. |
| `rules/RULE-FORMAT.md` | The **FROZEN** on-disk record format. Normative and self-contained. |

Read all three before changing anything structural.
`docs/FOUNDATION.md` exists so that decisions are not re-litigated; if you disagree with a resolution, change the register deliberately and cost the change, do not quietly diverge in code.

## The frozen record format

`rules/RULE-FORMAT.md` defines blank-line-separated `key: value` block records.
It replaces the pipe-delimited rule format sketched in `docs/DESIGN.md` §6.2, because any regex containing `|` silently corrupts a pipe-delimited field split, and the §6.3 rule catalog is full of such regexes.
The rule **catalog** in §6.3 is unchanged; only the on-disk encoding is.

It is used by **every human-authored file**: all `*.rules` packs, `rules/derived.rules`, `rules/redaction.rules`, `modules/<m>/checks.rules`, and every `config/*.conf` including `config/scope.conf`.
Machine-generated files use JSON or the frozen TSV instead (`findings.jsonl`, `run.json`, `state/*.json`, `config/baseline.json`, `data/advisories.db`).

Key properties, so you do not have to re-read the spec to avoid breaking it:

- Values carry **no escaping at all**; the bytes after the first `": "` to end of line are the value.
- Comments are whole-line only (first byte `#`), so `#` is free inside values.
- A blank line separates records; a whitespace-only line is an **error**, not a separator.
- CRLF and BOM are errors, because a stray `\r` would silently end up inside every regex.
- Prose fields get multiple lines via two-space continuation lines; `pattern` is always single-line.
- Regexes declare a `dialect`, defaulting to a frozen portable ERE subset that behaves identically under `rg` and `grep -E`.

**The format is FROZEN.**
Every later module depends on it, and check ids feed the finding fingerprint, so a change invalidates `state/` and `config/baseline.json` and breaks the "fail only on new findings" CI mode.
The full cost is enumerated in `rules/RULE-FORMAT.md` §14, and a change requires a `format_version` bump and a `state/` migration.

## Sharp edges that are easy to get wrong

These are resolved decisions, not open questions.
Each has a full entry in `docs/FOUNDATION.md`.

- **Never put a line number in a fingerprint** (tension 5). It would make every finding `new` after any unrelated edit, destroying the diff, the baseline, and the CI gate.
- **Never call `grep` or `rg` bare** (tension 4). `set -Eeuo pipefail` is mandatory and grep exits 1 on no-match, which is the normal case. Use `scan_match`, which distinguishes no-match from engine failure.
- **Guard the `EXIT` cleanup trap with `[[ $BASHPID == $$ ]]`** (tension 4). Traps are inherited by subshells, so an unguarded one shreds the scratch dir mid-run.
- **Shared state across `xargs -P` workers goes in files under an atomic-`mkdir` mutex** (tension 16). The rate limiter, request budget, circuit breaker, and AWS cache are all per-process otherwise, so `--jobs 8` means 8x the request rate and a breaker that never trips.
- **Workers write to their own shard file, never a shared `findings.jsonl`** (tension 17). Appends above `PIPE_BUF` interleave.
- **Never `source` a config file** (tension 26). It is a code-execution vector that would run before the scope gate is consulted.
- **A partial run must never report `fixed`** (tension 12). `state/` tracks `covered_checks`; an uncovered check's prior findings are `unknown`.
- **A secret is never a command-line argument and never touches disk raw** (tension 9). `sha256_of` reads stdin only.
- **Evidence is untrusted target output** (tension 10). It goes through `finding_set_evidence` and is escaped per emitter; the HTML report contains no `<script>` at all.

## Build order and where we are

`docs/DESIGN.md` §13 gives the build order, in ten steps, starting with `lib/core.sh` / `lib/findings.sh` / `lib/report.sh` and ending with SARIF plus the compliance report plus docs.

**Current position: nothing in §13 has been implemented.**
This repository currently contains documentation and the frozen format only.
The next task is §13 step 1.

Two amendments to §13 come from `docs/FOUNDATION.md` and apply from the start:

- `lib/records.sh` (the record parser) is built **before** step 1's stated contents, since tensions 1, 6, 9, 15, and 26 all depend on it.
- `lib/awscli.sh` is added to the layout and lands at the start of step 6, before any `aws/live/*.sh` script exists, so no script is ever written against a bare `aws`.

## Tests

`tests/run-tests.sh` does not exist yet; it arrives with §13 step 1.
When it does, the entry point is:

```
tests/run-tests.sh                 # full suite
tests/run-tests.sh <name>          # one suite
tests/lint-rules.sh                # record-format linter, error codes in rules/RULE-FORMAT.md §13
tests/lint-aws-readonly.sh         # read-only AWS lint, docs/FOUNDATION.md tension 23
```

What the suite must cover, per `docs/DESIGN.md` §12 and the resolutions above:

- Every seeded rule fires on its fixture and stays quiet on the clean fixture.
- JSON and SARIF schema validation, with every SARIF result carrying a physical location that exists.
- The read-only lint over `aws/live/`.
- A no-egress run under `--paranoid` against fixtures and mocks, asserting zero connections outside loopback.
- Fingerprint stability under reindentation and line shifts.
- Byte-identical findings between GNU and BSD userlands; CI runs both.
