# The `--format agent` contract

`reports/<run>/agent-fix.json`, written by `report_agent` (`lib/report.sh`) when `agent` appears in
`--format`/the `formats` config key. It is a first-class deliverable and is in the default format
list (`json,sarif,html,md,agent`), so an ordinary run with no `--format` flag at all writes it with no
flag required; naming `--format` explicitly still replaces that default list rather than adding to it,
so `--format json` alone omits it. Writing it never drops or replaces any other format -
`findings.jsonl` and `run.json` are still written unconditionally, and `json`/`sarif`/`html`/`md` are
still written whenever also requested; `audit` remains the one opt-in value never in the default list.

It exists for one reason: a downstream AI fixing agent reading `findings.json` pays for a lot of bytes
it never uses (`fingerprint`, `cvss`, `first_seen`/`last_seen`, `rule_digest`, `contributors`, ...) and
gets no fix scaffold at all. This format is the schema those fields were dropped from, not a new
encoding - it is compact JSON, using the same `json_string`/`json_number`/`json_bool` writers every
other emitter in this codebase does.

## 1. Document shape

```json
{ "scoursh_agent": 1,
  "_note":  "each finding inherits checks[<check>]; per-finding keys override",
  "run":      { ... the honesty header, §4 ... },
  "checks":   { "<check_id>": { ... fields byte-identical across every LIVE finding of this check ... } },
  "findings": [ { ... per-finding fields; anything absent here inherits from checks[check] ... } ] }
```

A field is promoted into `checks{}` **only when it is byte-identical across every non-suppressed
finding of that check in this run** - computed by `report_agent`'s own two-pass read of
`findings.fields`, never assumed from the check's rule record (SCA and adapter checks have no rule
record at all). A check with exactly one finding trivially satisfies this for every field.

Empty values are **omitted**, not emitted as `""`/`[]`, on every catalogue and per-finding field. The
`run` header is the one exception: every one of its fields is always present, because an absent header
field is exactly the "did not check read as clean" ambiguity §4 exists to prevent.

A check that ran and produced no finding is **excluded** from `checks{}` - there is nothing to
catalogue, and nothing in `findings[]` to point at it either. `run.checks_run` (§4) already carries
its id, so "assessed and clean" is still recoverable from the header; it is not repeated per-check to
avoid paying tokens for a large registry (`--format agent` on a `scan.sh all` run typically has ~100
distinct checks execute).

## 2. Per-finding fields

| field | meaning | notes |
|---|---|---|
| `id` | the finding's fingerprint, truncated to 12 hex chars | collision-free in every corpus measured; the full 64-char fingerprint is in `findings.jsonl` alongside if a caller needs it |
| `check` | the check id | joins into `checks{}` |
| `mod` | the module (`sast`/`sca`/`iac`/`dast`/`cloud`/`posture`) | |
| `sev` | severity, post-rubric | omitted from a finding when the check's is constant (promoted to `checks{}` instead) |
| `conf` | confidence | always per-finding |
| `status` | `new` / `recurring` / `unknown` | never `fixed` - a `fixed` finding is absent this run and has no result to carry it, exactly as `report.sarif` |
| `loc` | the finding's own `logical_fqn` | `file:line` for SAST/IaC, `npm:pkg@ver` for SCA, `target METHOD /path#param` for DAST, a resource ARN/key for CLOUD - the identical string every other emitter already computes, reused rather than re-derived |
| `advisory` | the matched advisory id | SCA only |
| `dep_type` | `direct` / `transitive` / `unknown` | SCA only; decides `auto` vs `assisted` below |
| `cwe`, `owasp`, `refs`, `cis` | rule record / emitter | usually promoted to `checks{}` |
| `title` | rule record / emitter | usually promoted to `checks{}` |
| `evidence` | the finding's `evidence` | already redacted and normalised - no special handling needed here |
| `remediation` | rule record / emitter | usually promoted to `checks{}` |
| `fixability` | derived, §3 | `auto` / `assisted` / `manual` / `blocked` |
| `fix_*` | derived, §3 | **absent entirely** when `fixability` is `manual` or `blocked` |

Dropped deliberately (present in `findings.jsonl`, of no use to a fixer): `fingerprint` (the full 64
chars), `cvss`, `base_severity`, `first_seen`/`last_seen`, `rule_digest`, `contributors`/
`derived_into`/`related`, `endpoint_hosts`, `cell`, `logical.kind`, `exposure`/`auth`/`sensitive_data`,
`suppressed_by`. A suppressed finding is excluded from `findings[]` entirely and is reflected only in
`run.status_counts` (via `findings.fields`' own accounting, the same source `report.md`/`report.html`
read).

## 3. The fix scaffold

Four `fixability` states. `manual` and `blocked` both mean "no automated edit is offered", and they are
kept distinct on purpose:

| state | meaning | `fix_*` present |
|---|---|---|
| `auto` | a complete, self-contained edit scoursh is confident in | yes |
| `assisted` | the edit shape is known, but a value scoursh cannot know offline needs a human (a placeholder, an anchor to insert near, or - for cloud - any write at all) | yes |
| `manual` | no deterministic patch exists; act on `remediation` prose | **no** |
| `blocked` | known to be unfixable *right now* - no upstream fix is published (SCA only) | **no** |

### SCA - `fix_kind: dep-upgrade`

Entirely derived offline from two fields `modules/sca/{engine,go_engine}.sh` set on the finding at
emit time from the exact `data/advisories.db` row it already matched - `fix_fixed_versions` (the
row's own comma-separated fixed-version list) and `dep_type`:

- `fix_fixed_versions` empty -> **`blocked`**, no `fix_*` at all.
- otherwise, `dep_type == direct` -> **`auto`**; `transitive`/`unknown` -> **`assisted`** (a
  transitive pin needs `overrides`/`resolutions` or a parent bump scoursh cannot identify).
- `fix_to` - the smallest published fixed version **>= the installed version** (same branch,
  minimal upgrade: `django@1.11` + `2.1.10,2.2.3,1.11.22` -> `1.11.22`, never `2.1.10`) - computed
  with `semver_cmp_v` (`modules/sca/semver.sh`) **for npm only**, the one ecosystem that comparator is
  verified against (`docs/FOUNDATION.md` tension 25: a 1.66% divergence was measured between it and
  real PEP 440, which is exactly the invented-precision tension 25 forbids). Every other ecosystem
  falls back to the advisory's own **first-listed** fixed version - a real published fact, never a
  guessed ordering - and `fix_all` always carries the complete list so the fixer can choose
  differently.
- `fix_all` - the full published list.
- `fix_cmd` - a frozen per-ecosystem template: npm `npm install <pkg>@<to>`, pypi
  `pip install '<pkg>==<to>'`, RubyGems `bundle update <pkg> --conservative`, composer
  `composer require <pkg>:<to>`, maven `<version><to></version>`, Go
  `go get <pkg>@<to> && go mod tidy`.

`fix_find`/`fix_find`-shaped derivation from `evidence` is never used for SCA either: the version list
comes from the finding's own first-class field, never re-parsed from free text.

### SAST / IaC - `rules/RULE-FORMAT.md` §9.1.4's rule-authored `fix-*` keys

scoursh has no AST, so a deterministic patch can only come from the rule author. Four optional keys on
a pattern-rule record (§9.1.4), read once by the shared `finding_from_record` (`lib/findings.sh`) and
carried onto the finding as `fix_kind`/`fix_find`/`fix_replace`/`fix_snippet` - absent on a check means
`manual`, which is most checks; this is deliberately not populated broadly in v1 (a handful of
representative checks per class, listed below), the same "ship the mechanism, populate incrementally"
shape this codebase already uses for engine adapters and `rules/derived.rules`.

- **`fix-kind: replace`** - `fix-find` names the exact literal text matched; `fix-replace` is the
  exact literal text to put there instead. `fixability: auto`. Worked example:
  `IAC-K8S-PRIVILEGED-01` - `fix-find: privileged: true` / `fix-replace: privileged: false`.
- **`fix-kind: replace-tpl`** - same mechanics as `replace`, but `fix-replace` contains a
  `<PLACEHOLDER>` a human must fill in (a value scoursh cannot know offline, e.g. a trusted CIDR).
  `fixability: assisted`. Worked example: `IAC-TF-OPEN_CIDR-01` -
  `fix-find: "0.0.0.0/0"` / `fix-replace: "<TRUSTED_CIDR>"` (the literal quote characters are part of
  both values - they are Terraform's own quoted-string syntax, matching what the check's `pattern:`
  actually captures).
- **`fix-kind: insert-near`** - `fix-find` matches an **ANCHOR** line, not the offending line (a
  fixer handed only "file:line + replacement" would edit the wrong thing); `fix-snippet` is text to
  insert into the enclosing block near that anchor, indentation and exact placement left to the
  fixer. `fixability: assisted`. Worked example: `IAC-DOCKER-ROOT_USER-01` - the match is `FROM ...`
  (an anchor, not the offender), `fix-snippet` adds the `RUN addgroup ... && adduser ...` / `USER app`
  lines.

**`fix_find` is never derived from `evidence`.** Evidence is the raw regex match, which can be a
truncated fragment, and is **redacted** for every secret-family check. `fix_find` comes from the rule
record only.

**A secret-family check id (`finding_check_is_secret_family`, `lib/findings.sh`) can never carry a
`fix-*` key at all** - `finding_from_record` `die()`s if a rule author adds one. An automated edit that
deletes a matched credential literal leaves a live, unrotated compromised credential the agent cannot
even see (its evidence is `<redacted:SECRET:...>`); `manual` is correct there on purpose, not a gap.

Everything else - all of SAST's 60-odd checks bar the handful opted in, DAST (there is no file to
patch - the subject is a running endpoint), and POSTURE - ships as `manual` in v1. The rule keys exist
so any individual check can opt in later with no format change (`rules/RULE-FORMAT.md` §14: an
additive optional key trips item 2 only).

### CLOUD - `fix_kind: cloud-cli`, always a labeled suggestion

scoursh knows the account, region and resource key, so a remediating AWS CLI command is derivable -
but it is a **write**, and scoursh is read-only end to end. The captain's decision for v1: emit it
anyway, under a distinct `fix_kind` and an explicit marker, rather than withholding it:

- An optional `fix-cli` key on the §9.5 script-check schema (cloud checks are script checks, not
  pattern rules) carries a command TEMPLATE, with the literal placeholder `%RESOURCE%` standing in for
  the resource. `report_agent` fills it in from the finding's own `loc_resource_key` at render time -
  today that means stripping an S3 bucket ARN (`arn:aws:s3:::name`, no embedded `/`) down to its
  trailing colon-segment; a future `fix-cli` on a resource type whose bare name is not simply that
  segment (an IAM role `role/name`, for example) needs its own substitution, not this one reused
  blind.
- `fixability` is **always `assisted`, never `auto`**, whatever the check - a write is never offered
  as unattended.
- The finding also carries `"fix_writes": true` and a fixed `fix_note` string:
  `"suggested, human-review, do NOT auto-run - scoursh is read-only and never executes this"`.
  scoursh never runs this command itself, at any point in its pipeline; it is a suggestion for the
  fixer to review, exactly as its own note says.
- v1 populates three representative S3 checks
  (`CLOUD-S3-BLOCK_PUBLIC_ACCESS_OFF-01`/`CLOUD-S3-NO_DEFAULT_ENCRYPTION-01`/
  `CLOUD-S3-NO_VERSIONING-01`) to prove the mechanism end to end; broader population across the ~112
  CLOUD checks is a stated, deliberate follow-up, not an oversight.

## 4. The `run` header - honesty (`docs/DESIGN.md` §15)

Emitted **first**, before `checks`/`findings`, and every field always present (never omitted for
emptiness - `[]` for an empty array is still a fact, not silence):

```json
"run": {
  "run_id":            "...",
  "modules_reported":  ["iac", "sast", "sca"],
  "modules_not_run":   ["dast", "cloud", "posture", "net", "image"],
  "checks_run":        ["IAC-CFN-ECS_PRIVILEGED-01", "... every id that actually executed"],
  "skipped_checks":     [],
  "coverage_gap":       ["module=sca reason=unknown_version ecosystem=Go count=1"],
  "coverage_reduction": ["module=dast reason=no --target given (declared, all)",
                          "module=cloud reason=no --live given (declared, all)"],
  "incomplete_reason":  [],
  "abort_reason":       [],
  "status_counts":     {"new": 109, "recurring": 0, "fixed": 0, "unknown": 105},
  "gate": "not-evaluated", "diff_usable": false, "redact_secrets": true
}
```

- **`modules_reported` / `modules_not_run`** are *computed*, never hand-listed: every check id in
  `run.json`'s own `checks_run` meta record is mapped to a module by its `rules/RULE-FORMAT.md`
  §9.1.1 id-namespace prefix, via the single `_AGENT_MODULE_PREFIXES` table (`lib/report.sh`) that
  both this mapping and the not-run universe read - `SAST-`/`SCA-`/`IAC-`/`DAST-`/`CLOUD-`/`POSTURE-`
  to their same-named module, plus `NET-` to `net` and `IMAGE-` to `image`, and `modules_not_run` is
  that eight-module universe minus whatever the mapping found. `net` (not `network`) is deliberate:
  it matches the `module` field a `NET-*` finding sets on itself, not `_RPT_MODULES`'s/
  `SCAN_COMMANDS`'s own `network` token for the CLI subcommand and report-audit.html category - a
  different axis that has used a different spelling since NET-01 shipped. A module that ran but
  produced zero findings still shows up in `modules_reported` this way, because it is read from what
  actually EXECUTED, never from which modules happen to have a live finding.
- **`checks_run`** is the full executed set (deduped, `LC_ALL=C` sorted), so "this check ran and found
  nothing" and "this check was never loaded" stay distinguishable - never collapsed into a count.
- **`coverage_gap` / `coverage_reduction` / `skipped_checks` / `incomplete_reason` / `abort_reason`**
  are carried **verbatim**, byte for byte, from the same `meta/*` records `run.json` itself renders -
  never summarised, counted, or reworded.
- **`abort_reason`** is non-empty only when `lib/core.sh`'s `die()` terminated the process on a usage,
  scope, or input exit code (2/3/4) - never on the exit-5 incomplete code, which keeps writing only
  `incomplete_reason` (that field's emptiness is `docs/FOUNDATION.md` tension 14's own exit-5
  predicate, and folding an abort into it would silently relabel a scope refusal as an incomplete
  run). A module named in `modules_not_run` alongside a non-empty `abort_reason` did not run because
  the run terminated early for the stated reason, not because a filter excluded it; a module in
  `modules_not_run` with an empty `abort_reason` was simply never selected.
- **`redact_secrets`** tells the fixer that an `<redacted:...>` evidence value is a masked REAL
  credential, not an absent one.
- **`diff_usable: false`** (with a non-trivial `status_counts.unknown`) means `status` on the findings
  below is not classification the fixer can trust as "new since last time" - a first run, or one whose
  prior state was unusable, reports every live finding `new` regardless.

## 4a. Aborted runs

`report_agent` is not gated on the run having actually reached `report_all`. `die()` (`lib/core.sh`,
exit codes 2/3/4/5) terminates the process directly, and its own abort-refresh path
(`run_json_refresh_incomplete`) re-renders `run.json`, `report.md`, `report.html` **and**
`agent-fix.json` in that order before the process exits - the identical four-writer list, so an
aborted run's `agent-fix.json` is never stale or absent. This closes what would otherwise be the
worst case for a consumer that reads only this one file by default: no file at all on an abort reads
as "never fetched", not as "clean", but it is still strictly worse than an explicit aborted state,
because it gives a downstream fixing agent nothing to branch on.

No new field exists for this - the `run` header (§4) already carries everything needed, because it is
built entirely from the same `meta/*` records `run.json` itself renders, whether or not the run ever
reached `report_all` normally:

- **(a) ran and found nothing**: `run.abort_reason` and `run.incomplete_reason` are both `[]`,
  `run.checks_run` is non-empty. `findings` is `[]`; every check that ran is a real, clean assessment.
- **(b) ran partially, then aborted**: `run.abort_reason` (2/3/4) or `run.incomplete_reason` (5) is
  non-empty, and `run.checks_run` is ALSO non-empty - the modules that completed before the abort left
  real coverage behind, and their findings (if any) are still in `findings[]`. `run.modules_not_run`
  names what never got to run because of the abort, not because a filter excluded it (§4's own bullet
  on `abort_reason` states this precisely).
- **(c) refused before anything ran**: `run.abort_reason` or `run.incomplete_reason` is non-empty and
  `run.checks_run` is `[]` - no module ever dispatched a check, so `findings` is unconditionally `[]`
  too (there is nothing in `findings.fields` for `report_agent` to have read). This is the shape a
  scope/usage/input refusal (`scan.sh all --target <unauthorized>`, exit 3) produces.

A consumer that reads `run.abort_reason`/`run.incomplete_reason` before trusting `findings: []` as
"clean" can never confuse (c) with (a); checking `run.checks_run` alongside it separates (b) from (c).
Nothing here is computed as a "clean" result from an empty finding set - the same honesty precedent
`report.md`/`report.html`'s own `_RPT_COMPLIANCE_SKIPPED` path (`lib/report.sh`) already established
for the compliance tables: an aborted run's absence of findings is stated as an abort, never rendered
indistinguishably from a real, completed, clean scan.

## 5. Wiring, for anyone tracing the implementation

Six changes, all reuse of existing machinery - no new escaping surface, no new dependency:

1. `lib/report.sh`: `report_agent RUNDIR` (§5b region, beside `report_sarif`).
2. `lib/report.sh`: one line in `_report_render_formats` gating it on `agent` in `SCOURSH_FORMATS`,
   the identical shape `audit` already has.
3. `scan.sh`: the `--format` CSV validator's regex gained `agent`.
4. `lib/config.sh`: the `formats` config-key validator's regex gained `agent` too (the two layers
   validate independently, by design).
5. `lib/findings.sh`: `_finding_known_field` gained `fix_kind`/`fix_find`/`fix_replace`/
   `fix_snippet`/`fix_fixed_versions`/`dep_type`/`fix_cli`; `finding_from_record` reads the four
   optional §9.1.4/§9.5 keys and the secret-family guard.
6. `modules/sca/{engine,go_engine}.sh`: `finding_set dep_type`/`finding_set fix_fixed_versions` at
   each of the four emit sites.
7. `lib/core.sh`: `report_agent` added to `run_json_refresh_incomplete`'s writer list (§4a) - the
   abort path, reached from `die()`, otherwise never calls into `report_all`/`_report_render_formats`
   at all, so `agent-fix.json` used to be silently absent on every aborted run (exit 2/3/4/5) even
   though `meta/abort_reason`/`meta/incomplete_reason` were correctly recorded.

At landing, `agent` was opt-in and not in the default list, exactly as `audit`. A later captain
decision made `agent` a first-class deliverable: `lib/config.sh`'s `_scanner_default_list formats` now
returns `json sarif html md agent`, so a plain run with no `--format` flag writes `agent-fix.json`
too - `audit` alone stays opt-in. See §1 above for the current contract. Adding the six
`fix_*`/`dep_type` fields to
`_finding_known_field` does **not** change `findings.jsonl` or `report.sarif` (`_finding_json` emits a
fixed key list, never an iteration over the finding's own field set) and does **not** move any
fingerprint (`finding_fingerprint` reads only `loc_<component>` keys) - both are pinned by
`tests/suites/agent-format.sh`'s A16.

## 6. Stability promise

`scoursh_agent: 1` is additive-only for its lifetime: a future field may be added, but no existing key
is renamed, retyped, or removed while the document still declares `"scoursh_agent": 1`. A
backwards-incompatible change bumps that number, exactly as `fp_schema`/`uk_schema` are versioned
elsewhere in this codebase.
