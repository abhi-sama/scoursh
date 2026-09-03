# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

## What scoursh is

`scoursh` ("scan exhaustively") is a shell-based, egress-restricted security scanner.
One tool audits three surfaces: source code (SAST plus SCA plus IaC), a running endpoint (DAST), and AWS configuration (live read-only plus IaC).

It is **target-agnostic**.
No application, company, product, environment, or endpoint name is ever baked into a script, a rule, or a document.
Every site-specific value comes from the operator's config at runtime.
Rules describe *classes* of issue, never a specific system.
This is `docs/DESIGN.md` §1 and it is a hard rule for every change.

## The no-egress rule, and why it drives everything

`scoursh` is **egress-restricted, enforced by destination** - not air-gapped; see `docs/FOUNDATION.md`
tension 28 and `docs/adr/0001-egress-model-correction.md` for the full correction and why "air-gapped"
overstates the guarantee. Exactly two kinds of outbound traffic are permitted:

1. `curl` to a host the operator authorised in `config/scope.conf`.
2. Read-only AWS API calls to the operator's own account.

Everything else is forbidden: no telemetry, no SaaS backend, no fetching rules or advisories at scan time.
DAST and live cloud scanning need real network access to do their job - the guarantee is not that the
tool never touches a network, but that it never decides on its own who to contact, and refuses anything
outside those two categories at a runtime chokepoint. SAST, SCA, and IaC need no external target at all,
so those three modules alone genuinely make zero network calls and genuinely run unmodified on an
air-gapped host.

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
| `docs/FOUNDATION.md` | The design-tension register. 29 tensions, each with a committed RESOLUTION. **Where it contradicts the letter of `docs/DESIGN.md`, it wins**, and it says so explicitly at each point. |
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

- **The composite fingerprint's first component is the literal `composite`, not the finding's `module` field** (tension 6). The module field is `derived`; the two are different strings for different jobs. Passing the module through hashed `derived` and produced an identity no conformant implementation agrees with - invisible, because a composite fingerprint is only ever compared with itself. Assert it against a digest computed from raw bytes, never through `fingerprint_compute`.
- **Never put a line number in a fingerprint** (tension 5). It would make every finding `new` after any unrelated edit, destroying the diff, the baseline, and the CI gate. Repeated byte-identical matches in one file are told apart by an `occurrence` ordinal, not a line.
- **`fixed` is inferred only inside a covered (check, scope-cell) pair** (tension 12). Check-id-alone coverage lets a `--regions` or `--target` run report every unvisited region's or target's findings as remediated.
- **Never call `grep` or `rg` bare** (tension 4). `set -Eeuo pipefail` is mandatory and grep exits 1 on no-match, which is the normal case. Use `scan_match`, which distinguishes no-match from engine failure.
- **The `EXIT` cleanup trap is guarded on scratch-dir OWNERSHIP, never on subshell-ness** (tension 4 rule 5, finding F13, closed). The guard is `scratch_is_owned_here`: the creating process records its pid in a non-exported variable AND in an on-disk marker, and cleanup no-ops unless both say this process. Do not reach for `[[ $BASHPID == $$ ]]`: bash resets trapped `EXIT` actions in subshells, so that guard defends a case bash never produces, and it PASSES in an `xargs -P` worker - which is a fresh process - so the first worker to finish erases the shared scratch dir. Both halves are measured in `tests/suites/core.sh`.
- **The scratch dir holds only genuinely transient data** (finding F12): `scan_match` line files, the mutexes, and the rate, budget and breaker state. Finding shards and the unit journal live under `reports/<run>/` unconditionally, because the EXIT trap erases the scratch dir on the SIGTERM that resume itself is tested with. `--keep-shards` means "do not delete after a successful merge".
- **`msleep` reads a FIFO the process holds open read-write, and is chosen by MEASUREMENT** (tension 24, finding F14). `read -t </dev/null` returns at EOF instantly and does not sleep, and `read` returns non-zero for EOF and timeout alike, so an exit-status probe cannot tell them apart.
- **The mutex reclaim is single-winner and identity-bound** (tension 16, finding F15). A bare `rm -rf` of a stale lock can delete a *live* one and put two processes in the critical section. `lock_is_stale` needs BOTH age and non-liveness; requiring both is what bounds pid reuse.
- **The RATE limiter does not bound CONCURRENCY, and the two are separate mechanisms in `lib/http.sh`** (tension 16's in-flight-semaphore amendment; section 11b). A token bucket spaces requests over time and says nothing about how many are open at once, so against a target where each request takes seconds a high `--jobs` value opened exactly that many connections while the average rate stayed inside the 4/s ceiling - `docs/STEP5-DAST-PLAN.md`'s enforcement table had to be corrected once to say the row was enforced by nothing. Section 11b is the fix: a `PID NONCE EPOCH` line per held slot in `$SCRATCH/http-limits/inflight.state`, under the same mutex the rate, budget and breaker take, acquired immediately before the transport call and released immediately after it. Four things are easy to get backwards. The ceiling is the resolved `jobs` value rather than a new key - `rules/RULE-FORMAT.md` §9.6.1 is frozen and two numbers to keep in step is worse than one - so DAST-32's asymmetric clamp reaches it unchanged (file/default clamps with a warning, explicit CLI/env is exit 2, the affirmation raises and never removes). The slot is taken AFTER the token, never around the wait, because `_http_throttle` sleeps outside its critical section and `jobs` workers parked for a token would otherwise hold every slot with zero connections open. The reclaim needs BOTH age and non-liveness for the identical reason `lock_is_stale` does, and each half is the other's bug - measured by mutation, age-alone steals a live worker's slot (rc 0 where the real code refuses with 5) and liveness-alone frees a slot the recording worker has not yet been observed holding. And the release matches on the NONCE, never the pid: a pid-keyed release hands back a slot the call never took, which is measurable and was. `http_authorize_raw_connection` deliberately holds NO slot - the socket is opened by `modules/dast/passive/tls.sh`, tension 19's transport exception, and a control the exempted caller must remember to release is a leaked slot rather than a control - so raw TLS handshakes are a stated gap, not an oversight. Test it on the OBSERVED simultaneous-connection count (`tests/suites/http.sh` section 11b plants a marker inside the stub transport and samples on every tick), never on a return value: "it refused" must not be satisfiable by a path that opened the connections and then returned 0.
- **Nothing exits outside 0-5** (tension 14, finding F16). `die` validates its code. `shred` is GNU-only and absent on macOS; it sits behind `erase_dir`, and overwrite-based erasure is best effort - `scratch-dir` on a tmpfs is the real control.
- **Shared state across `xargs -P` workers goes in files under an atomic-`mkdir` mutex** (tension 16). The rate limiter, request budget, circuit breaker, and AWS cache are all per-process otherwise, so `--jobs 8` means 8x the request rate and a breaker that never trips.
- **Workers write to their own shard file, never a shared `findings.jsonl`** (tension 17). Appends above `PIPE_BUF` interleave.
- **Never `source` a config file** (tension 26). It is a code-execution vector that would run before the scope gate is consulted.
- **A partial run must never report `fixed`** (tension 12). `state/` tracks coverage as **(check, scope-cell)** pairs; a prior finding whose own cell was not visited is `unknown`. `path-root` cells are comparable only between runs with the same `scan_root_id` (other cell kinds carry no path and are not gated by it). Two families refine this and can only narrow it: `SAST-HIST-*` adds a per-finding history-boundary test (tension 13), and a composite is `fixed` only when **(a)** its own record was selected this run, **(b)** every check in `requires`/`any-of` is covered - contributors that fired under the test that would let *their own* finding be `fixed`, listed checks that did not fire by being covered **this run** at all (a check with no entry in this run's `covered_checks` is never covered, whatever the prior run recorded) **and** having every cell the prior run covered them over revisited - and **(c)** the predicate no longer holds (tension 6). Reading contributor cells alone is not enough: it misses an unselected composite and a history contributor whose boundary has receded.
- **The scan root is a defined term** (tension 12): the git toplevel of the resolved `--path`, else the resolved `--path`. Every "repository-relative path" means scan-root-relative. scoursh's own install root is a different thing (tension 26).
- **An unusable diff is fail-closed at the gate** (tension 11 step 7). No prior state, an `fp_schema` mismatch, or a `scan_root_id` mismatch **on a run whose findings live in `path-root` cells** all set `diff_usable = false` (a `cloud`/`dast`/`posture`-only run is unaffected by `scan_root_id`, since those cells carry no path), and `--fail-on-new` then gates on **all** findings. `diff_usable` governs the **gate only** and never overrides a `status`: a first run's findings are `new` per tension 12's table, not `unknown`.
- **`data/advisories.db` is `sca`'s REQUIRED INPUT, and its absence is exit 4 - never a clean run** (tension 14's per-module required-inputs table, amended for this). It is absent by default in every checkout (`tools/vendor-engines.sh advisories` populates it on a networked box and never runs during a scan), so the misleading path is the ordinary one, not an edge case: with no db, `scan.sh sca` used to exit 0 with zero findings and an empty `checks_run`, which renders "it did not look" identically to "it looked and found nothing". The gate is decided ONCE, in `modules/sca/run.sh`, before any walk - never per walk, which is a shape in which it cannot be right (two of the four walks announced it, so every run said it twice; the other two said nothing). It records one `coverage_reduction ... ecosystems=<all six, LC_ALL=C sorted>` and a `SCA-COV-NO_ADVISORY_DB-01` finding, and the module sets `scan_main`'s `input` local so `scan_exit_code` applies the frozen precedence and the report is still written. **Under `all` it is a declared skip with no exit-code effect** - the same tension's own row - and both directions are pinned, because the naive fix for each is the other's bug.
- **An `SCA-COV-*` roll-up must be emitted EXACTLY ONCE PER RUN, because its fingerprint has nothing to tell two of them apart** (tension 5). The SCA location profile is `ecosystem`/`package`/`advisory_id`; a roll-up names no dependency and populates none of them, so every instance hashes identically **by design**, and `findings_merge`'s dedup silently keeps one. Each of the module's four ecosystem-scan entry points used to accumulate locally and emit its own, so a repo with npm and Python gaps was told about one of them - measured 1-reported against 4-real on `tests/fixtures/sca/mixed-four-ecosystems/`. `modules/sca/engine.sh` section 8a is the shared accumulator: walks call `sca_rollup_add ECO` and end with `_sca_rollup_autoflush`, which flushes only when no deferred window is open, so a standalone walk still self-flushes while `_sca_run_module` brackets its four calls with `sca_rollup_begin`/`sca_rollup_flush`. **Do not "fix" a future collision here by adding a component to the fingerprint**: that changes identity for a shipped check id (`rules/RULE-FORMAT.md` §14 item 3) and models the roll-up as per-ecosystem, which it is not.
- **A secret is never a command-line argument and never touches disk raw** (tension 9). `sha256_of` reads stdin only.
- **`redact-secrets` is enforced by PROVENANCE at `finding_emit`, not by pattern shape alone** (tension 9).
  `redact()` masks by shape, from `rules/redaction.rules`, which is a list maintained independently of the secrets checks in `modules/*/rules/*.rules` - and the two drifted.
  With `redact-secrets: true` in force, a matched `password = "..."` literal and an uppercase `API_KEY = "..."` were written in the clear into `findings.jsonl`, `findings.json`, `findings.fields`, `report.md`, `report.html` and the per-worker shards, because `secrets.rules` matches both shapes and `redaction.rules` carried neither; a bare `AKIA...` id and a lowercase `api_key = "..."` were masked only INCIDENTALLY, by the PEM-body and Bearer rules, under a `kind` that does not describe them - which is the same defect wearing a passing test.
  Do not close a hole here by adding one more pattern: that is what leaves the mechanism intact.
  An emitter whose match IS a credential calls `finding_set_secret_match` (`lib/findings.sh` section 8a), which keeps `finding_set_match`'s digest **byte-identical** - `modules/sast/adapters/gitleaks/adapter.sh` dedups against native `SAST-SEC-*` findings by comparing `loc_match_digest`, so digesting the masked text instead would silently defeat that dedup - and puts a `<redacted:SECRET:DDDDDDDD>` placeholder in evidence.
  `finding_check_is_secret_family` (also `lib/findings.sh`) is the ONE list; `modules/sast/engine.sh`'s `_sast_check_is_sensitive` delegates to it rather than starting a second one.
  `_finding_secret_backstop` re-checks at `finding_emit` - the single point every finding passes through on its way to a shard, and therefore to every format downstream of the merge including a SARIF emitter that does not exist yet - so a future emitter that reaches for the plain `finding_set_evidence` is masked anyway.
  Three things about the backstop are easy to get backwards: it is scoped to modules `sast` and `iac`, where evidence is BY CONSTRUCTION the raw bytes matched in a file (in `dast` it is composed prose - `lib/paranoid.sh`'s egress finding puts the observed destination there, and `modules/dast/jwt_engine.sh` puts its one actionable sentence there under ids like `DAST-JWT-ALG_NONE`, which match the `*JWT*` arm); it deliberately does **not** gate on `sensitive_data`, because `lib/http.sh` and `lib/paranoid.sh` set that on findings whose evidence is a destination address, and an emitter that forgot the secret setter would most likely forget the flag in the same breath, switching the net off in exactly the case it exists for; and `modules/sast/engine.sh`'s match-count truncation notice therefore sets **no evidence at all**, because it is a meta-finding wearing the truncated check's own id and the string it used to set was already its title, verbatim.
  `rules/redaction.rules` is still wanted and still applies - it is what masks a credential that turns up INCIDENTALLY, in another check's evidence, a crawled URL, a log line, or an adapter-supplied title - so the two layers answer different questions and neither subsumes the other.
  `redact-secrets: false` writes the match in the clear DELIBERATELY (an operator rotating a credential has to be able to see the literal bytes); `run.json` records `redact_secrets`, and `report.md` and `report.html` each open with their own warning banner, whose exact wording differs between the two formats.
  `tests/suites/secret-redaction.sh` pins all of it against committed fake canaries under `tests/fixtures/secret-redaction/`, asserting the PROPERTY ("this value is absent from every byte the run wrote", over a recursive walk of the run directory) rather than any particular pattern being present - a pattern assertion goes green again the next time the two lists drift.
  **`finding_emit` is the single chokepoint for FINDINGS and is not the only OUTPUT PATH, and conflating the two is what a first enumeration got wrong.**
  It really is the sole chokepoint for a finding, and that is checkable rather than assumed: it is the only writer of a shard (`lib/findings.sh` section 12), `findings.fields` is written from exactly one place - a byte copy of the shards - and every downstream reader (`findings_write_jsonl`, `findings_write_json`, all of `lib/report.sh`) `finding_decode`s that file, so no cache or replay path reaches unredacted bytes; the one direct shard reader outside that file, `modules/sast/adapters/gitleaks/adapter.sh`'s dedup pass, only READS.
  But `run_record` (`lib/core.sh`) writes a run-level fact straight into `meta/<key>`, which `lib/report.sh` renders into `run.json`, `report.md` and `report.html`, and it is not a finding - so a canary planted through `finding_emit` cannot reach it, and the recursive walk that would have caught it never had one to find.
  Measured: one `run_record` carrying a userinfo URL put the credential in the clear into all four.
  Both `lib/core.sh` writers - `run_record` and `_log` - now go through `_redact_out`, whose two guards are each load-bearing: `redact()` lives in `lib/findings.sh`, which reaches `lib/core.sh` through `lib/records.sh`, so the `declare -F` guard is forced and is exactly the shape that fails SILENTLY on a rename (section I pins the name by asserting real masked output, not a return value); and `redact()` matches through `scan_match_stdin`, which calls `die` on an engine failure, and `die` logs - so without the reentrancy flag `_log` recursed until the stack gave out on precisely the error path a scanner most needs to report.
  **The `dast` exclusion in `_finding_secret_backstop` is correct and is NOT self-sufficient.**
  Masking a composed sentence whole would destroy the finding, so `dast` is right to be out of the provenance arm - which leaves `rules/redaction.rules` as the only layer over the twelve dast emitters, and it carried no rule for the shapes a URL actually uses: `SAST-REDACT-PASSWORD-01` and `SAST-REDACT-API_KEY-01` both REQUIRE the value to be QUOTED, which a query string never is, and nothing parsed an authority at all.
  A crawled `https://user:pw@host` and a `?password=...` were measured leaking into seven files, every report format among them.
  `SAST-REDACT-URL_USERINFO-01` and `SAST-REDACT-URL_PARAM_CREDENTIAL-01` close that; the userinfo rule is anchored on a real scheme rather than a bare `//` so it cannot fire on a `// user:host` comment.
  Do not read "dast evidence is composed prose" as "dast evidence is safe": the prose is composed AROUND bytes the target chose, and the `url`, `logical_fqn`, `loc_path_template` and `loc_param_name` fields beside it are raw - which is why `_finding_redacted_field` exists and why `tests/lint-shell.sh` enforces that all seven are only ever written through their setter.
  `loc_target` is deliberately NOT in that list and does not need to be: it is the `config/scope.conf` target ID, an operator-chosen short name, never a URL.
- **Evidence is untrusted target output** (tension 10). It goes through `finding_set_evidence` and is escaped per emitter; the HTML report contains no `<script>` at all.
- **The same pre-check applies to a URL lifted out of the INVENTORY, it is SHARED rather than
  per-phase, and it is applied where the row is READ rather than where the request is SENT.**
  `modules/dast/engine.sh` section 3b owns it: `dast_endpoint_in_scope` (the non-fatal predicate,
  built on `http_gate_url`'s return rather than a second URL parser), `dast_endpoint_keep` (the same
  with the refusal counted) and `dast_scope_record_skips PHASE` (one `coverage_reduction`, reason
  `inventory_endpoint_out_of_scope`, carrying the count and the gate's own distinct reasons).
  `reports/<run>/inventory/endpoints.json` is a tension-21 cross-module artifact `crawl.sh`, SAST
  route extraction and `aws/live/apigw.sh` may each write and an operator may write by hand, so one
  out-of-scope row used to abort an ordinary `scan.sh dast` run at exit 3 - fail-CLOSED and never a
  bypass, and still the whole run killed over one row of a file the scanner did not author.
  Three things about the shape are worth knowing before changing it.
  **It is applied at `inject_inventory_load`** (`modules/dast/active/inject_engine.sh`, in both
  `_inject_flush_endpoint` and `_inject_flush_param`'s parameter-`url` FALLBACK, which is the one
  other path a URL reaches a request by), because that function is the single door a dozen phase
  scripts share - every §7.3 probe plus `passive/cookies.sh` and `active/methods.sh` - and tension
  19's own argument applies one level down: a control each of twelve callers must remember is not a
  control. The five consumers that do NOT go through it (`passive/banner.sh`, `passive/cors.sh`,
  `active/hosthdr.sh`, `graphql.sh`, `jwt.sh`) each apply it at their own candidate-build step, and
  `cors.sh`/`hosthdr.sh` do it BEFORE their dedupe and route cap so an out-of-scope row cannot spend
  a bounded slot an in-scope route would have had. `jwt.sh` filters the LIST rather than the loop,
  because its loop is nested inside the per-identity loop and a per-request check would report a
  count that is a fact about the identity list.
  **Every `declare -F` guard around these is PERMISSIVE when absent and inverting it is the trap** -
  the identical reading `dast_check_selected` already ships: a fail-closed default (or an unguarded
  call, which is exit 127, hence "refused") makes every direct-engine suite inert while every "stays
  quiet" assertion in them still passes green. Nothing is unsafe about it, because with no
  `lib/http.sh` loaded there is no `http_request` to send the URL either.
  **The gate reason is captured AT REFUSAL TIME**: `http_gate_url` clears `_HTTP_GATE_REASON` at
  entry on every call, so a roll-up reading it after the loop degrades to a generic fallback on
  exactly the ordinary case where the last row was fine (`passive/transport.sh` found this first).
  `tests/suites/dast-scope-precheck.sh` pins both halves, and its section C is the pre-fix code
  reproduced - the pre-check shadowed away in a real subprocess, asserted to exit 3 - so "seen
  failing before, passing after" is measured rather than claimed. One existing case had to change
  with it: `tests/suites/dast-graphql.sh` asserted the exit-3 abort as if it were the contract, which
  it was not.
- **`modules/sast/rules/secrets.rules` ships NO `files:` glob, so it reads EVERY file in whatever tree it is pointed at - it is the pack most exposed to the cross-fire above, and the only defence is its own clean-tree assertion.** Widening it is therefore never a local change. What it catches is settled by MEASUREMENT against planted controls in `tests/fixtures/sast-secret-forms/`, never by reading a regex: the pack was measured at **7 of 47** assignment forms before the widening ticket and **47 of 47** after, with 0 of 32 negative controls flagged, and `docs/SECRETS-FORM-MATRIX.md` records that table plus which forms are deliberately out of scope. `tests/suites/sast-secrets-forms.sh` re-derives both halves on every run - it scans the same tree with the pack as it stood at `a656663` and asserts each newly-covered form was MISSED then - which is what keeps "seen failing before, passing after" true rather than a claim in a commit message, and which catches the opposite defect a "stays quiet" assertion cannot: a pack gone inert passes every silence check ever written. Four things about it that a later change will otherwise rediscover the expensive way:
  - **The four assignment records share ONE byte-identical `context-deny` block, duplicated on purpose.** `rules/RULE-FORMAT.md` has no include mechanism, so one policy about what a credential assignment is *not* has to exist as four copies. The realistic failure is not a typo but a later ticket adding a deny line to the record it was debugging and not its three siblings, leaving the same benign shape quiet under `password` and noisy under `token`; nothing in the control tree would catch that unless it happened to carry that exact shape under all four keywords. Section F of the suite compares the blocks directly.
  - **A rule file that SPELLS a credential-shaped example in its own header comment matches itself.** The engine has no comment awareness anywhere (the same lesson `cloudformation.rules` recorded), so `secrets.rules` reporting `secrets.rules` is a real, shipped outcome - it happened here twice. Describe the hazard, do not spell it; the suite asserts zero findings across `modules/sast/rules/`.
  - **Identifier case is matched with explicit `[Pp][Aa]...` bracket classes, never a case-insensitive flag.** The frozen dialect is a portable ERE subset with no inline `(?i)`, and this is what keeps the pack behaving identically under BSD `grep -E` and GNU `rg`.
  - **A value on a different line from its keyword is unreachable by ANY pattern rule**, because `rules/RULE-FORMAT.md` §8.2 freezes matching as line-oriented. It is an architectural limit, not a rule defect, and closing it is a register change. It is pinned as the `[[G01]]`-`[[G03]]` controls, tagged `G` rather than `P` so the gap stays visible instead of being silently assumed covered - and so the suite fails if it ever stops being documented.
- **`tests/fixtures/{vuln,clean}/` are SHARED trees scanned wholesale, so landing a new `*.rules` pack changes what every existing pack is tested against - and what every existing pack's fixtures test the new one against.** Each pack asserts "stays quiet across the whole clean tree", so an overlapping `files:` glob is a cross-fire, not a local concern. `kubernetes.rules` (`bb75c9b`) landed **after** `docker-compose.rules` (`57d1cd1`) and its `tests/fixtures/clean/docker-compose.*.yml` fixtures, carried no compose guard, and so merged red: `tests/suites/iac.sh` reports `110 passed, 2 failed` at `bb75c9b` itself, and `dev` carried those two failures onward into every branch cut from it until they were fixed. `image:` and `privileged: true` are byte-identical vocabulary in the two schemas. A pack whose `files:` glob overlaps another's must state the boundary explicitly - `exclude-files` mirroring the owning pack's `files:` list where the shape has a conventional filename (docker-compose, Dockerfile), a content `context-deny` only where it does not (CloudFormation, Helm templates). Reach for `exclude-files` first: it cannot interact with a `context-window`, whereas a content deny on a check like `IAC-K8S-MUTABLE_TAG-01` forces widening a same-line-intent window that `rules/RULE-FORMAT.md` §10.2 requires to stay at `0`, trading a visible false positive for a silent false negative (finding F4).
- **A cross-fire fix needs a test in BOTH directions, because the naive fix for each is the other's bug.** Narrow too little and the false positives return; narrow too much and the pack goes inert - and an inert pack passes every "stays quiet" assertion in the suite, so the only thing that catches it is an assertion that the rules still FIRE. The kubernetes/docker-compose section of `tests/suites/iac.sh` pins both halves, and asserts them over `check_id@loc_path` pairs from a single scan of `tests/fixtures/iac-scope/` so neither half can be satisfied by breaking the other. That failure mode had already cost two tickets before it was tested.
- **`findings.jsonl` and `run.json` are mandatory per-run records, never one of `--format`'s four values** (`json`/`sarif`/`html`/`md` is the whole enum both `scan.sh` and `lib/config.sh` validate against). `lib/report.sh`'s `report_all` writes both unconditionally and gates only `findings.json`/`report.md`/`report.html` behind `SCOURSH_FORMATS` (a CSV `scan.sh` resolves via `config_scanner_list` and exports before dispatch). `--format sarif` alone therefore writes only the two mandatory files today: there is still no SARIF emitter (step 10), so it selects nothing, exactly as before this was wired up - that gap is unchanged and tracked in `ROADMAP.md`, not silently hidden by the fix. A `report_all` caller that never sets `SCOURSH_FORMATS` (every direct call in this test suite) gets all four formats, matching `lib/config.sh`'s own documented default for no `--format` given - keep that fallback in step with that default rather than letting the two drift.
- **A `Set-Cookie` header value is split on `;` OUTSIDE double quotes and NEVER on `,`** (`modules/dast/passive/cookie_engine.sh`, DAST-06). Both naive readings are shipped bugs, and both fail in the direction that reads as a pass. The generic RFC 7230 "a comma separates list members" rule is right for `Accept` and specifically wrong here (RFC 6265 §3): `Expires=Wed, 09 Jun 2021 10:18:14 GMT` carries a comma inside ONE attribute, so splitting on it strands every later attribute on a phantom cookie invented from the date, and reports three findings against a correctly-flagged cookie. A quote-blind `;` split is worse: `pref="light; Secure; dark"` makes it see a `Secure` attribute the server never sent, so a cookie that IS missing `Secure` passes. Attribute names are case-insensitive and unordered, and `Secure`/`HttpOnly` are set by the attribute's PRESENCE - RFC 6265 §5.2.5/§5.2.6 discard the value, so `HttpOnly=false` is an HttpOnly cookie. Every one of these was measured by writing the naive version and watching `tests/suites/dast-cookies.sh` go red, not reasoned about.
- **A record stream between two processes is separated by 0x1f, NEVER by a tab, whenever a field can
  legitimately be EMPTY** (`modules/dast/passive/markup_engine.sh`, DAST-11). A tab is an
  IFS-*whitespace* character, so `read` folds a RUN of tabs into ONE delimiter and drops leading and
  trailing ones (POSIX XCU 2.6.5) - which means a six-column record whose middle two columns are
  empty arrives as four columns and every later value is silently shifted left. Measured here: a
  `<link>` with neither `integrity` nor `crossorigin` put its `rel` into the `integrity` variable, so
  the Subresource-Integrity check read an attribute the server never sent and every unhashed
  cross-origin stylesheet passed. It reads as a clean result, which is the direction that costs the
  most. `crawl_json_flatten` already uses 0x1f for the same reason; the emitter strips 0x1f out of
  every value so target-derived text cannot forge a column. Note this does NOT make the existing
  tab-separated readers in this tree wrong - `crawl_html_extract` and the inventory readers emit no
  empty middle field - it makes the tab a hazard for any NEW stream that does.
- **A DELIBERATE unquoted expansion of target-derived text still needs `set -f`, because word
  splitting and PATHNAME EXPANSION are one switch and only the first one is ever wanted**
  (`markup_tokens_have`, `modules/dast/passive/markup_engine.sh`, DAST-11; CWE-807). `rel` and
  `crossorigin` are HTML token lists, so `local -a toks=($list)` is right - but `$list` is bytes
  lifted verbatim out of a scanned response (tension 10), so a target serving `rel="*"` had that `*`
  expanded against the SCANNER's cwd, and on a host with a file named `noopener` sitting there the
  target switched off its own `DAST-MARKUP-TABNABBING-01` finding. Reproduced both ways before and
  after. Two separate defects in one line: attacker-authorable text steering a security decision, and
  a verdict that depends on where the scanner was started rather than on the response. `set -f` is
  saved and restored BY HAND rather than with `local -`, which is bash 4.4 while `lib/core.sh`
  enforces a 4.2 minimum - there `local -` scopes nothing and the `set -f` escapes into the rest of
  the run. Any future function that word-splits a header, a `Location`, a `rel`, or any other
  response-derived value wants the same three lines.
- **`parsed`, `covered`, `checks_run` and every other honesty counter must count what SUCCEEDED, and
  a run-level accumulator must not be declared inside a per-item function** (`markup.sh`, DAST-11;
  CWE-390 and CWE-778). Both halves shipped here and both read as a CLEAN SCAN. `markup_html_extract`
  was called as `... 2>/dev/null || true`, which is genuinely required under `set -Eeuo pipefail` but
  discarded the status with it, so `parsed` counted documents ATTEMPTED: a page whose markup was
  never tokenized produced zero findings, zero gaps and zero reductions while still putting four
  check ids in `checks_run`. Capture the status into a variable instead of throwing it away, keep
  stderr, and exclude the item from the success counter. Separately, `_MK_FORMS_CROSS_ORIGIN` was
  `declare -g`'d inside the once-per-page analyse function and read after the page loop, so only the
  LAST page's value survived and every earlier page's declared exclusion vanished. Run-level state
  is initialised exactly once, in the phase; only per-item state belongs in the per-item reset.
- **A severity that varies with context is a SECOND CHECK ID, never a `base_severity` a script raises
  at runtime** (DAST-11's two `DAST-MARKUP-TABNABBING*` ids). `severity` is a per-record property of
  the registry (`rules/RULE-FORMAT.md` §9.5) and every DAST suite asserts the emitting script and the
  registry agree on it, so a phase that "weighted a finding higher" in place would put the two into
  disagreement. Two ids is also the right identity: `check_id` is a fingerprint component (tension
  5), so the ordinary and the elevated case stay two findings rather than one whose meaning flips
  between runs - the same argument `cookies.rules` already records for absent-vs-weak `SameSite`.
- **A URL a target hands back is judged by its AUTHORITY, parsed the way a browser parses it - never by a substring, a prefix, or exact host equality alone** (`modules/dast/active/openredirect.sh`'s `_or_url_host`/`_or_host_is_sentinel`, DAST-19). Every naive reading fails in a direction that reads as a clean result, which is why all three are pinned in both directions. A SUBSTRING test flags the commonest SAFE behaviour on the surface - an on-origin redirect that reflects the value into its own query string (`Location: https://site/login?next=https://<probe-host>/`). Ignoring USERINFO misses `https://<site>@<probe-host>/`, and matching the probe host by EXACT EQUALITY alone misses `https://<site>.<probe-host>/`: those two are the shapes that defeat a real `startsWith(ourHost)` allow-list, so a parser that cannot see them cannot see the filters worth testing, while the mirror image `<probe-host>.<site>` is the TARGET's own name and must not match. The split is on the LAST `@`, and `//host/`, `https:/host/` and `/\host/` all carry an authority - a parser STRICTER than the client that will follow the redirect reports safe on a live one. Any peer probe that reads a `Location`, an `Origin` or a `Host` back off a target (DAST-20's SSRF sentinel, DAST-23's CRLF, DAST-24's host header) wants this function rather than its own.
- **The DAST-28 burst probe is the ONE check that cannot run without `--i-own-target`, and the
  affirmation is checked in FOUR places rather than one** (`modules/dast/ratelimit.sh`). The
  amendment `docs/STEP5-DAST-PLAN.md` records is that an unaffirmed run must not execute at all,
  because under the conservative 4/s ceiling a burst "proves" only that the SCANNER was slow - a
  clean result that is really the absence of a test. The non-obvious half is that the affirmation
  LIFTS that ceiling and does not RAISE the rate, so an affirmed run left at the default 4/s has
  exactly the same defect one step further in; that is a second gate, on the EFFECTIVE rate, and
  refusing it is what stops the probe reporting a negative it did not earn. The affirmation is also
  compared against the TARGET (it is a key, not a switch), so owning target A never licenses a burst
  against target B. Every gate is asserted on a REQUEST LOG, never on a return value: "it refused"
  must not be satisfiable by a phase that sent traffic and then returned 0.
- **A burst probe draws down `lib/http.sh`'s OWN budget counter and spends at most HALF of what is
  left; it never carries a budget of its own.** `http_budget_remaining_set` (lib/http.sh section 11)
  is the only reader, placed beside the counter for the same reason tension 19 puts the gate at
  `http_request` - a module-local copy would be a second definition of where the counter lives and of
  what an absent one means. The draw-down itself is automatic (every request goes through the
  chokepoint); the HALF is the deliberate part, because the budget refusal is fatal (exit 5), so a
  probe sized to the whole remainder ends the run for every phase and target after it. The number it
  reports is a READ, never a reservation: nothing is taken out of circulation until
  `_http_throttle` charges it inside its own critical section.
- **A 503 is not throttling, and a `RateLimit-*` header without a 429 is not a finding.** Both fail in
  the direction that reads as a pass. Counting a 503 as a throttle turns "this endpoint collapses when
  you ask for it fifty times" - the worse outcome - into a clean bill of health for the control being
  tested; `lib/http.sh`'s own breaker draws the same line from the other side (a 5xx is a failure it
  counts, a 429 is not). And a target publishing `RateLimit-*`/`X-RateLimit-*` on every response HAS a
  limiter this bounded burst did not reach - fold that into the finding and the check fires against
  every correctly-configured API in the world; fold it the other way and the check goes inert. Both
  directions are pinned in one section of `tests/suites/dast-ratelimit.sh` so neither half can be
  satisfied by breaking the other.
- **A finding's `evidence` is HARD-CAPPED at `SCOURSH_EVIDENCE_MAX_BYTES` (512 by default, `lib/findings.sh`), and `_evidence_truncate` cuts the TAIL off silently.** Whatever a finding most needs the reader to see goes FIRST. Measured on `modules/dast/active/methods.sh`: a first draft wrote a paragraph per finding, and the two sentences that ticket existed to put in front of an operator - how acceptance was determined, and that the write method was never sent - were exactly the two the emitter dropped, because they sat at the end. Background prose belongs in `remediation`, which carries no cap.
- **`modules/dast/active/methods.sh` (DAST-13) establishes method acceptance WITHOUT exercising it, and the only two methods that ever leave it are `OPTIONS` and `TRACE`** (both defined as having no effect on the resource, RFC 7231 §4.3.7/§4.3.8). `PUT`/`DELETE`/`PATCH`/`CONNECT` are read off the server's own `Allow` header - which a `405` is *required* to carry, RFC 7231 §6.5.5, so the rejection is a source and not only the 2xx - and are never sent, which is why those checks are `confidence: medium` and the measured TRACE check is `high`. Three things there are easy to get backwards and each is pinned by a mutation that was watched failing: the `Allow` match is anchored `^allow:`, because an unanchored one reads `Access-Control-Allow-Methods` (a CORS *browser* policy) as an endpoint acceptance claim; a bare `200` is not a TRACE echo, because a single-page app answers every unrouted request with its shell; and the measurement beats the advertisement in BOTH directions - a confirmed echo the server never named is still a finding, a named `TRACE` that answers `405` is not.
- **A GraphQL introspection response is PARSED, never grepped, and the naive reading fails in the
  direction that reads as a FINDING** (`modules/dast/graphql_engine.sh`, DAST-27).
  A server with introspection correctly DISABLED answers `{"errors":[{"message":"GraphQL introspection
  is not allowed, but the query contained __schema"}]}` - the literal string `__schema` appears,
  quoted inside the very error message saying introspection is off, so `case $body in *__schema*)`
  reports a critical misconfiguration against a correctly-configured server on the exact response that
  proves the opposite.
  Hardening the substring to also demand `types` or `queryType` does not help: an error message
  routinely quotes back every field the document asked for.
  The classifier goes through `crawl_json_flatten` and asks for a leaf at the STRUCTURAL path
  `data.__schema.types.<n>.name`, which a JSON string's contents can never become.
  Two smaller siblings in the same file, each measured the same way: the mount-path signal is a
  LAST-SEGMENT match (a substring makes `/graphql-docs` an endpoint and spends a real request on it),
  and the type count is over DISTINCT ARRAY INDICES (counting flattened leaves doubles it, because
  each type carries both a `name` and a `kind`).
  One more that is a real trap: `"mutationType": null` is decided by the PATH (it flattens to
  `data/__schema/mutationType`, a different leaf entirely), so the `[[ $type == s ]]` guard is NOT
  what handles it - what the guard defends is `"mutationType": {"name": null}`, which lands on the
  same path a real name does.
  A test written from the wrong belief about which case the guard covers passes under both readings
  and pins nothing.
- **Whether a DAST check has anything to do is decided from the INVENTORY, never by probing to find
  out** (`modules/dast/graphql.sh`, DAST-27).
  Sending an introspection query at every endpoint to see which one answers is unsolicited traffic
  against an application that may have no GraphQL at all.
  With no GraphQL endpoint in `endpoints.json` the phase sends ZERO requests and records a declared
  `reason=no_graphql_endpoint` reduction plus a `coverage_gap`, because "this application has no
  GraphQL" and "scoursh did not look" are different facts and a silent clean result cannot tell them
  apart.
- **§7.4's "correlated finding" belongs to the DERIVED layer, and a phase script that mints its own
  composite check id is reimplementing it** (DAST-27).
  `rules/RULE-FORMAT.md` §9.2's first line puts composites in `lib/findings.sh` and says "not scanner
  scripts"; a phase could not do it correctly anyway, since it runs before the other module's
  contributors are merged.
  All a contributor owes is a populated `corr_target`, which `loc_target` supplies and which §9.2.2's
  frozen table confirms is the only correlation key DAST can offer.
  `rules/derived.rules` stays unseeded until DAST-10's leakage id exists (F5/F20, `E051`); prove the
  input end with `derive_findings RUNDIR FIXTURE_FILE` - its second argument is the rule file -
  against a composite written to SCRATCH, never under `tests/fixtures/`, which `tests/lint-rules.sh`
  lints and which needs every fixture path registered in its own `fixture_schema_for`.
- **`SCOURSH_DAST_ENDPOINTS` is resolved BEFORE `crawl.sh` runs, so it is empty on the ordinary run** (`modules/dast/run.sh` calls `dast_inventory_read` once, ahead of the phase loop). `crawl.sh` is itself a phase and writes `reports/<run>/inventory/endpoints.json` several phases later; nothing re-reads it. A consumer trusting the exported variable alone therefore sees an empty surface on precisely the run that has one - `active/sqli.sh` does exactly this today. Read `$SCOURSH_RUN_DIR/inventory/endpoints.json` as a fallback (the same artifact by the same path, read after the producer wrote it), as `passive/cookies.sh` does; the general fix in `run.sh` is filed as its own ticket.
- **A DAST phase gates every outbound probe on `dast_check_selected` (`modules/dast/engine.sh` section 3a), and the `declare -F` guard around each call is KEPT deliberately** (tension 15). Unset or empty `SCOURSH_SELECTED_CHECKS` means ALL SELECTED, exactly as `lib/findings.sh`'s `_derived_record_selected` already reads it, and inverting that is the trap: `tests/suites/dast-{sqli,headers,discovery}.sh` each source a phase script with no `engine.sh` in the process, so a fail-closed default - or an UNguarded call, which is `command not found`, exit 127, non-zero, hence "deselected" - makes every phase inert while every "stays quiet" assertion in those suites still passes green. Membership is WHOLE-LINE, never a `*"$id"*` substring, because an id that is merely a suffix of another selected line would deliver a payload the operator filtered out. This mattering at all is why it is worth stating: four call sites called this function across three tickets before anything defined it, so `--profile-scan`/`--intensity` narrowed the DAST check REGISTRY and narrowed nothing a run actually SENT. One consequence is accepted rather than fixed: "the filter chain ran and kept nothing" is indistinguishable from "there is no filter chain", since both leave the variable empty.
- **A phase attaches a session with `dast_auth_apply TARGET LABEL` - `auth_engine.sh`'s own public
  entry point - immediately before EVERY request, and the `declare -F` guard around it is the reason
  a typo there is silent.** That guard is right for `dast_check_selected` (the bullet above) and it
  is what let `modules/dast/passive/cookies.sh` ship a dead authenticated pass: it guarded on and
  called `dast_auth_cookie_header_set`, which does not exist - the real one is
  `_dast_auth_cookie_header_set`, private - so the branch was skipped in silence, every request went
  out with NO credential, and the run still recorded `authenticated_pass=1`. An operator read the
  logged-out cookie surface as the logged-in one, with no error, no log line and no coverage record.
  Two further halves of the same shape, each pinned in both directions by
  `tests/suites/dast-cookies.sh` section E and `tests/suites/dast-methods.sh` section E: a
  COOKIE-ONLY attachment sends nothing at all for a `bearer` or `api-key` identity, the majority
  shape for an API, whereas `dast_auth_apply` attaches the token in the identity's own configured
  header and scheme AND the cookie jar; and `lib/http.sh` section 9a consumes its per-request context
  at ENTRY and resets it, so an attachment made ONCE above the endpoint loop rides only the first
  request and every one after it is anonymous. Assert it on the OUTBOUND HEADER CONTEXT
  (`_HTTP_TX_HEADERS`) at the transport boundary, never on a note the phase wrote about itself - a
  phase that believes it authenticated is exactly what all three defects produce. Do NOT reach for
  `dast_auth_request` here: its transparent 401 re-auth is right for an ordinary authenticated
  request and wrong wherever a 401 is itself the measurement (see the DAST-29 bullet above).
- **A `.rules` file whose basename begins `checks` is a §9.5 script-check registry, wherever it lives - and a co-owner writes its OWN `checks-<name>.rules` rather than appending to a peer's file** (`docs/FOUNDATION.md` tension 29). `rules/RULE-FORMAT.md` §9's path table reserves BOTH `checks.rules` and `checks-<name>.rules` repository-wide for that schema, at any depth; a record file matching no row is still `E070`, so `modules/dast/passive/cookies.rules` and the SUFFIX spelling `headers-checks.rules` (DAST-05's rejected attempt) both remain illegal. The second row is additive: `checks.rules` is unchanged and still legal, both spellings may sit in one directory, and per §14 it trips item 2 alone, so there is no `format_version` bump and no `state/` migration. It needs no engine change either - `checks_registry_load` already globs every `*.rules` under a module directory with no per-file allowlist, exactly as `modules/iac/`'s six packs already rely on - and that is asserted on a real run's `checks_run` set, never on the glob alone. **A split is a byte-identical MOVE of records and never an edit of them**: §9.5.1's owning-module map keys on the DIRECTORY, so `E018`/`E081` still hold a moved id to the same module prefix, `E019` uniqueness stays repository-wide, and renaming an id would change a fingerprint (tension 5). `modules/dast/passive/` is split five ways accordingly. `modules/dast/active/checks.rules` and `modules/dast/checks.rules` are NOT split and stay append-only, resolved by keeping both sides - do not split one opportunistically under peers who are mid-flight, which recreates the conflict in a worse place.
- **The shared response reader is `modules/dast/passive/response_engine.sh`, it is a LEAF in the source graph, and that is the property to preserve rather than the file's contents.** `hdr_parse_capture`/`hdr_present`/`hdr_value`/`hdr_first`/`hdr_is_document`/`hdr_safe_text`/`hdr_path_of`/`hdr_url_is_https` were DAST-05's, lived in `headers_engine.sh`, and six landed files came to need them - `passive/headers.sh`, `passive/leakage_engine.sh`, `passive/transport_engine.sh`, `active/crlf.sh`, `active/hosthdr_engine.sh` and `ratelimit_engine.sh` - so four of them dragged in that ticket's CSP/HSTS/Referrer parsers, its recommended-header loader, its endpoint chooser, `lib/http.sh` and `crawl_engine.sh` merely to read a header block. **A check that needs the READER ALONE sources `response_engine.sh`; one that also needs the parsers or `hdr_endpoints_load` sources `headers_engine.sh`, which sources the reader itself** - `ratelimit_engine.sh` is the single file in the second category today, and its own header says why. **That file sources NOTHING, deliberately**: `shellcheck -x` re-expands every source edge it follows and does not memoise (docs/CI-RUNBOOK.md, "the memory model"), so one edge added back to it is paid for once per consumer - measured on this tree, repointing the four reader-only consumers took `leakage_engine.sh` from 1.641 GB/5.8 s to 0.096 GB/0.3 s and `transport_engine.sh` from 1.689 GB/5.7 s to 0.057 GB/0.1 s under `shellcheck -x`. `tests/suites/dast-response-engine.sh` section A asserts the leaf property directly (`http_request`, `crawl_json_flatten` and `config_scanner_list` are all UNDEFINED after sourcing it), so restoring an edge goes red immediately instead of surfacing a year later as a slow linter. **Two things about the lift itself are worth knowing.** The `hdr_` prefix was KEPT rather than renamed to `resp_`: the published contract is not only the eight functions but the globals `_HDR_STATUS`/`_HDR_NAMES`/`_HDR_VALUE`/`_HDR_COUNT`/`_HDR_V` that consumers read directly, so a function-only rename half-renames the contract and a full one doubles the blast radius across eleven landed files for no behaviour. And `_HDR_MAX_EVIDENCE_FIELD` had to travel WITH `hdr_safe_text`, which reads it as a parameter default - leaving it behind is unbound under `set -u` for anyone sourcing the reader alone, it is the shape a lift most easily misses because the owning file's own tests never notice, and it is pinned by mutation. **The endpoint CHOOSER - `hdr_endpoints_load`, named above as staying behind in `headers_engine.sh` - has since lifted too, in full, as `resp_endpoints_load` in this same file.** It landed in two steps: first for `headers_engine.sh` and `markup_engine.sh` (`markup_endpoints_load` was a confirmed byte-identical second copy), then for `passive/leakage_engine.sh` (`leak_endpoints_load`, a third byte-identical copy) and `passive/transport_engine.sh` (`tr_endpoints_load`, whose one real difference - a dedup key of `(scheme, path template)`, because the plaintext and HTTPS twin of one path is that check's own finding rather than a duplicate to collapse - is `resp_endpoints_load`'s one optional `DEDUP_KEY` parameter, `template` by default). `resp_endpoints_load` calls `crawl_json_flatten`/`crawl_json_unescape` and `path_template_of` BY NAME rather than by sourcing them, exactly as the reader lift's own note above says a naive move would not: a caller that has not itself sourced `crawl_engine.sh` and `lib/http.sh` gets a plain `command not found`. All four of `hdr_endpoints_load`/`markup_endpoints_load`/`leak_endpoints_load`/`tr_endpoints_load` are now thin wrappers over it, under their historic names, so no call site anywhere moved; see `response_engine.sh`'s own third ADR block for the full account, including why a parameter was chosen over a fifth `passive/passive_engine.sh`.
- **A per-subcommand `--help`'s "built" line is generated, never hand-typed, wherever a real check exists to generate it from** (`scan.sh`'s `scan_usage_for`). `_scan_module_built` reuses the exact file-existence check `scan_dispatch` itself makes (`modules/<cmd>/run.sh` on disk) for `sast`/`sca`/`iac`/`dast`/`cloud`; `dast`'s phase count walks `modules/dast/engine.sh`'s own `_DAST_PHASES` table against the same file paths `dast_run_phase` checks. `diff`/`report` are not modules and have no file to check, so `_scan_stateful_command_built` is the one function both scan_main's dispatch arm and `scan_usage_for` read - flip it in the same change that gives them a real engine (step 7's `state/`), never in one place alone. The accepted-flags list per command is generated from `_SCAN_FLAG_KIND`, the same map `scan_flag_kind` validates against, for the identical reason.

## Build order and where we are

`docs/DESIGN.md` §13 gives the build order, in ten steps, starting with `lib/core.sh` / `lib/findings.sh` / `lib/report.sh` and ending with SARIF plus the compliance report plus docs.

**Process rule: shipping a §13 step updates this section, and its mirror in `docs/FOUNDATION.md`'s
"Where the build currently stands," in the same change.**
Step 3e (`modules/sast/history.sh`, commit `18c4c3f`) landed without either doc being updated, so its
existence was rediscovered a ticket downstream by an agent working on unrelated doc staleness, which is
exactly the failure mode this file exists to prevent (see "`main` can lag `dev`" below for the earlier,
sibling instance of the same pattern). Do not repeat it: a ticket that lands a `docs/DESIGN.md` §13
sub-step is not done until this paragraph's "Current position" and the FOUNDATION.md section it mirrors
both say so.
This paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" are part of the deliverable
for every step ticket, not follow-up work: filing a separate documentation ticket to update them later
is not an acceptable substitute, however small the wording change looks. A step landed without this
paragraph and its FOUNDATION.md mirror updated in the same commit range is not done, full stop - close
the gap in the step ticket itself.

**The inventory half of that rule is now mechanical; the prose half is what is left of it.**
`tools/gen-status.sh` regenerates the status block below - and its byte-identical copies in
`README.md` and `docs/FOUNDATION.md` - from the repository tree and `docs/DESIGN.md`'s own catalog, and
`tests/lint-status.sh` (run by `tests/run-tests.sh`, so by the daily local run) fails when any committed block differs
from a fresh generation.
A ticket that lands a module therefore runs `tools/gen-status.sh --write` and commits the result; it
never types a pack count, a "still open" list, or a "the next task is" sentence about a module, because
those are the sentences that went stale three times and that made every branch alive for more than a
few minutes conflict on these files.
**A merge conflict inside a generated block is never resolved by hand.**
Take either side of the conflict and re-run `tools/gen-status.sh --write`: both sides are machine
output, neither is more authoritative than a fresh generation, and hand-merging two generated tables is
exactly how a wrong count gets committed with a straight face.

**Current position: §13 steps 1, 2, 3 and 4 are done - step 4 landed out of step order and in slices,
and step 3's §6.3 rule-pack catalog is complete now that `nosql.rules` and `ldap.rules` have landed -
step 5 (DAST) has its whole TIER 0 complete: DAST-01 (the tension-16 rate limiter, per-run request
budget and circuit breaker), DAST-02 (`modules/dast/run.sh`, the `scan_dispatch dast` entry point), and
the safety half DAST-31/32/33/34 (the identifying `User-Agent`, the conservative ceilings plus the
`--i-own-target` affirmation, the `run.json` authorisation record, and an unrestricted run stated on
stderr and in the report); and **TIER 1 IS NOW COMPLETE** - DAST-03 (`auth.sh`, §7.0 authentication and
session acquisition) and DAST-04 (`modules/dast/crawl.sh`) have both landed, so the endpoint and
parameter inventory that all twenty-seven tickets in tiers 2-5 consume exists, and it can be built
against an authenticated session.
Tiers 2-5 are now COMPLETE - every DAST ticket from DAST-01 through DAST-36 has landed, and nothing in
this step remains outstanding. tier 4's
DAST-14 (`active/sqli.sh`), DAST-15 (`active/xss.sh`), DAST-16 (`active/cmdi.sh`),
DAST-17 (`active/pathtraversal.sh`), DAST-18 (`active/ssti.sh`),
DAST-19 (`active/openredirect.sh`), DAST-20 (`active/xxe_ssrf.sh`),
DAST-21 (`active/nosqli.sh`, the §7.3 NoSQL-injection error/boolean differential), DAST-22
(`active/ldapi.sh`, the §7.3 LDAP-injection error/boolean differential - it landed earlier without a
note in this section or its own landing paragraph; both are corrected here in the same change that adds
DAST-21), DAST-23 (`active/crlf.sh`, the §7.3 encoded CR/LF header-split detection), DAST-24
(`active/hosthdr.sh`, the §7.3 Host-header injection family - see its own paragraph below), and DAST-25
(`active/protopollution.sh`, the §7.3 `__proto__`/`constructor.prototype`-shaped JSON parameter
probe), tier
5's DAST-26 (`jwt.sh`), DAST-27 (`graphql.sh`, the §7.4 GraphQL introspection & key-exposure check),
DAST-28 (`ratelimit.sh`, the §7.4 missing-throttling burst probe),
DAST-29 (`authz.sh`, the §7.4 object-level authorization and
data-exposure family) and DAST-30 (`passive/transport.sh`, the §7.4 plaintext-exposure and
mixed-content family - a tier-5 ticket that RUNS at tier `passive` and lives under
`modules/dast/passive/`, see its own section below), tier 2's
DAST-06 (`passive/cookies.sh`), DAST-05 (`passive/headers.sh`, the §7.1 security-header family),
DAST-07 (`passive/tls.sh`, the §7.1 transport-security family - the ticket that made tension 19's
single documented exception real, see its own section below),
DAST-08 (`passive/cors.sh`, the §7.1 CORS origin-reflection family),
DAST-09 (`passive/banner.sh`, the §7.1 server/framework/version-disclosure family),
DAST-10 (`passive/leakage.sh`, the §7.1 information-disclosure family) and
DAST-11 (`passive/markup.sh`, the §7.1 HTML-markup family),
and tier 3's DAST-12 (`active/discovery.sh`, §7.2 content discovery - the first safe-active phase; no
wordlist ships in this repository by design, see `modules/dast/wordlists/README.md`) and DAST-13
(`active/methods.sh`, §7.2 HTTP method enumeration - the second safe-active phase, which completes
tier 3)
have landed, out of tier order, since the tiers are peers rather than a sequence once tier 1 is in.
DAST-06, DAST-05, DAST-09, DAST-10, DAST-11 and DAST-30 each originally appended their own block to a
shared `modules/dast/passive/checks.rules`; that file is now SPLIT six ways, one
`checks-<name>.rules` per owner, per `docs/FOUNDATION.md` tension 29 - DAST-08 landed after that split
and so was seeded directly into its own `modules/dast/passive/checks-cors.rules` rather than ever
touching a shared file, and DAST-09's own ids sit in `modules/dast/passive/checks-banner.rules` for the
same reason.
**DAST-07 landed carrying the PRE-split shape, and that has since been corrected.** It was written and
reviewed before tension 29, so its six `DAST-TLS-*` ids originally shipped in a generic
`modules/dast/passive/checks.rules` - legal rather than a defect (`rules/RULE-FORMAT.md` §9's path
table still admits the `checks.rules` basename and tension 29's own RESOLUTION leaves it, "nothing is
required to move"), but the one file in that directory a future passive peer could still collide on.
A later fix (filed while resolving a DAST-07 merge conflict, alongside the `tls.sh` exit-3 correction
below) renamed it to `modules/dast/passive/checks-tls.rules`, matching every other per-owner file in
the directory; `tests/suites/dast.sh`'s "modules/dast/passive/ ships FIVE per-owner registries" case is
what had been asserting the shared file's absence all along and is what caught it still present.
`modules/dast/active/checks.rules` is the tier-3/tier-4 equivalent and is under the identical
append-only rule - DAST-15, DAST-16, DAST-19, DAST-20 and tier 3's DAST-13 all appended to DAST-14's
file rather than adding a sibling, because `rules/RULE-FORMAT.md` §9's path table reserves the
`checks.rules` BASENAME
repository-wide and makes a per-ticket `openredirect-checks.rules` an `E070`.
**DAST-15 is the first ticket to consume `modules/dast/active/inject_engine.sh` WITHOUT extending
it**, which is what makes DAST-14's shared half demonstrably shared rather than sqli-shaped - it
added no line to that file, and appended its three `DAST-INJ-XSS_REFLECTED_*` checks to the shared
`modules/dast/active/checks.rules` the same append-only way the passive peers share theirs.
**DAST-16 (`active/cmdi.sh`) has also landed**, tier 4's second injection probe: bounded time-based
blind command injection (CWE-78), reusing DAST-14's shared `inject_engine.sh` and time-based mechanism
verbatim - the injected sleep is clamped into 1..10s BEFORE substitution so the probe can never become
a DoS (see `docs/STEP5-DAST-PLAN.md`'s DAST-16 landing note).
**DAST-17 (`active/pathtraversal.sh`) has also landed**, tier 4's third injection probe: it reuses
DAST-14's shared `inject_engine.sh` unchanged and is the first probe to fall back to reading
`$SCOURSH_RUN_DIR/inventory/{endpoints,parameters}.json` directly when the
`SCOURSH_DAST_ENDPOINTS`/`SCOURSH_DAST_PARAMETERS` exports are empty (the documented first-run state -
see `docs/STEP5-DAST-PLAN.md`'s DAST-17 landing note).
**DAST-18 (`active/ssti.sh`) has also landed**, tier 4's fourth injection probe: arithmetic-only
server-side template injection (CWE-1336), reusing DAST-14's shared `inject_engine.sh` with no line
added to it and DAST-17's run-directory inventory fallback verbatim.
**DAST-20 (`active/xxe_ssrf.sh`) has also landed**, tier 4's fifth injection probe and the §7.3
XXE/SSRF family: three check ids (`DAST-INJ-XXE_ENTITY-01`, an internal-entity reflection with no
network component at all; `DAST-INJ-XXE_SSRF-01`, an external entity naming the in-scope sentinel,
confirmed by a content signature this run independently fetched from that exact URL; and
`DAST-INJ-SSRF_PARAM-01`, the identical sentinel sent as a plain parameter value via DAST-14's
`inject_send`, method-agnostic unlike the two XML techniques). **The sentinel is never invented**: it
is read directly out of `lib/http.sh`'s own already-loaded scope-tuple set
(`_HTTP_SCOPE_ID`/`_HTTP_SCOPE_HOST`/...) for the current target - an `extra-host` when the operator
declared one (the "operator-declared sentinel" docs/DESIGN.md §7.3 calls for), else the target's own
`base-url` (a safe, self-referential fallback so the probe still runs on the ordinary scope.conf that
declares no extra-host). No flag or config key ever substitutes a different host; the two techniques
that fetch the sentinel do so through the ordinary `http_request` chokepoint like every other probe's
traffic, and the ACTUAL SSRF/XXE connection remains something only the target itself makes. The two
XML-body techniques run only against POST/PUT/PATCH endpoints (a full body override, not a parameter
substitution - RFC 7231 leaves GET/HEAD/DELETE body semantics undefined); the per-parameter technique
has no such restriction, which is why its own fixture deliberately probes a GET endpoint.
`tests/suites/dast-xxe-ssrf.sh` (34 assertions, registered) is the proof.
**DAST-21 (`active/nosqli.sh`) has also landed**, tier 4's sixth injection probe and the §7.3
NoSQL-injection family, matching that section's own wording ("operator/object injection ... and
syntax-error differentials; boolean/response-diff detection") with the same two-technique shape
`active/ldapi.sh` (DAST-22) already established: `DAST-INJ-NOSQLI_ERROR-01` (a syntax-breaking value -
an unbalanced quote/brace, a bare `$`-operator key - provokes a MongoDB driver/ODM or `$where`-JS
parse/runtime error the baseline did not) and `DAST-INJ-NOSQLI_BOOLEAN-01` (an always-matching
condition behaves like the baseline while an otherwise-impossible one does not, confirmed on retest).
CWE-943 (not CWE-89/CWE-90) is the correct mapping - MITRE's dedicated "Improper Neutralization of
Special Elements used in a Data Query Logic" id for NoSQL/OQL injection, distinct from SQLi's CWE-89
and LDAP's CWE-90.
There is deliberately NO time-based technique, for the same reason `active/ldapi.sh` gives: claiming a
third technique the probe cannot actually exercise across its full surface would be the overstated
coverage `docs/DESIGN.md` §15 forbids (MongoDB's `$where` COULD sleep via arbitrary JS, but the
comparison-operator-object shape - the more common real-world NoSQL API surface - has no such
primitive, so a time-based check would test a narrower slice than the other two while claiming parity
with them).
**The boolean-pair payload file carries two genuinely different row shapes, and that split is the part
most worth knowing before touching it.** Rows 1-2 of `modules/dast/payloads/nosqli-boolean-pairs.txt`
are `%B`-anchored, AND-based `$where` JS string-context tautologies - the identical safety discipline
`sqli-boolean-pairs.txt` documents (narrows nothing, never an OR-true that widens the result set),
applied to MongoDB's server-side JS evaluation instead of SQL. Rows 3-4 carry **no** `%B` at all: each
column is a whole, standalone comparison-operator object literal (`{"$gte":""}` vs
`{"$eq":"scoursh-no-such-value-zq"}`) that **replaces** the parameter's value outright, for an
application that deserialises the raw parameter string as a query/filter fragment - the "object
injection" half of §7.3's own wording, and a shape `inject_engine.sh` already supported (DAST-18's
`ssti-expressions.txt` established the precedent of a payload file with no `%B` placeholder at all).
Both shapes are tried by the same `_nosqli_try_boolean` loop, in the same order the file lists them, so
the safer AND-based rows are attempted before the broader operator-object rows.
**A parameter-NAME injection technique (`param[$ne]=1`, the bracket-notation object injection several
real NoSQL scanners lead with) is NOT implemented, and cannot be with the shared engine as it stands**:
`inject_send` composes a request from a FIXED parameter name plus a substituted VALUE
(`modules/dast/active/inject_engine.sh` section 3), so nothing in this probe can rename a key to
`name[$ne]`. Widening `inject_send` to vary the NAME is a shared-engine change every sibling probe
would need to tolerate, not a one-file fix, and is left as a stated gap rather than worked around
locally.
`tests/suites/dast-nosqli.sh` (29 assertions, registered) is the proof, including a case that
specifically confirms the boolean technique fires from BOTH payload shapes on two different parameters
- proving the probe is not `$where`-only.
**DAST-23 (`active/crlf.sh`) has also landed**, tier 4's seventh injection probe and the §7.3 encoded
CR/LF header-split family. It reuses DAST-14's shared `inject_engine.sh` unchanged and additionally
sources `modules/dast/passive/headers_engine.sh` for its response-header reader
(`hdr_parse_capture`/`hdr_present`) rather than growing a second one - that file's own header invites
exactly this lift.
**The signal needs no baseline, for the identical per-run-random reason `active/openredirect.sh`'s own
sentinel needs none**: the probe generates a fresh header-name marker and a fresh body sentinel once per
run (`_crlf_marker_set`) and asks only whether that EXACT string reached the response, so a single
confirmed response is sufficient evidence.
**Two check ids, not two independent sinks - this is one root cause observed at two possible
strengths, and they are MUTUALLY EXCLUSIVE per parameter, unlike `openredirect.sh`'s two genuinely
independent sinks that both fire together.** `DAST-INJ-CRLF_HEADER_INJECTION-01` (high) fires when the
marker header alone survives into the response's header block; `DAST-INJ-CRLF_RESPONSE_SPLITTING-01`
(critical) fires when it ADDITIONALLY forges a full second status line and a body sentinel lands at the
true front of the response body - proof the header/body boundary itself moved, which is the escalated,
cache-poisoning-capable case. The probe always tries the bare payload first and escalates to the
full-split payload only after the bare one already confirmed a signal, so a parameter that is not even
bare-vulnerable never receives the second, stronger payload.
**A `header`-location parameter is the one candidate location this probe must never inject into, and
that is a correctness requirement, not a style choice**: `inject_send` routes a `header`-location value
straight to `http_request_header`, which `die`s the WHOLE PROCESS the instant a value carries a CR or
LF (refused there as request smuggling against this scanner's OWN outbound request - a different,
unrelated protection from the one this probe tests for on the target). Every other §7.3 probe can send
that location fine because its payloads never contain a raw CR/LF byte; this one specifically excludes
it before ever calling `inject_send`, and `tests/suites/dast-crlf.sh` proves the exclusion by mutating
it away and observing the whole suite process abort with exit `4` (`SCOURSH_EXIT_INPUT`) rather than
merely failing one assertion.
`modules/dast/payloads/crlf-payloads.txt` ships exactly two templates and carries no raw CR or LF byte
on disk - see that file's own header for its `%NL`/`%H`/`%K` placeholders and why the marker is
generated rather than vendored. `tests/suites/dast-crlf.sh` (51 assertions, registered) is the proof,
including a mock transport that locates the header/body boundary the same way a real HTTP client does
(the first CRLFCRLF), so an injected blank line really does move it in the fixture exactly as it would
against a real server.
**DAST-25 (`active/protopollution.sh`) has also landed**, tier 4's eighth injection probe and the
§7.3 prototype-pollution family. It reuses DAST-14's shared `inject_engine.sh` unchanged and DAST-17's
run-directory inventory fallback verbatim. Two techniques, matching the ticket's own "detection via
differential; no destructive payload" wording, and each its own check id for the same reason every
sibling probe's techniques are (the DAST location profile carries no component naming which technique
fired):

- **`DAST-INJ-PROTOPOLLUTION_ERROR-01` (error-based, high/high)** sends a `__proto__`- or
  `constructor.prototype`-shaped JSON value that replaces the parameter's value outright (the same
  whole-value "object injection" shape `nosqli-boolean-pairs.txt` rows 3-4 already use) and looks for a
  JS-runtime/merge-library error signature (a write onto a frozen `Object.prototype` property, a
  recursive-merge stack overflow, ...). **The signal is a DIFFERENTIAL against a SHAPE-MATCHED CONTROL,
  never a bare 500**: `modules/dast/payloads/protopollution-error-pairs.txt` pairs each pollute template
  with a control of the IDENTICAL nesting depth and an ordinary key in place of the special one, so a
  response difference between the two isolates the special key as the cause rather than "this endpoint
  errors on any nested object" - the control alone is what a bare-500 check could never distinguish. A
  benign baseline that already matches one of `protopollution-error-signatures.txt`'s signatures marks
  the endpoint noisy and skips it for this technique, the identical discipline
  `modules/dast/active/nosqli.sh`'s own `_nosqli_try_error` already applies.
- **`DAST-INJ-PROTOPOLLUTION_MARKER_REFLECTED-01` (marker-reflection, critical/high)** is the stronger,
  directly-confirmed signal: a poisoning value carries a unique, per-run-random property name and value
  (`_pp_marker_set`, the identical `$RANDOM`/`$$` idiom `modules/dast/active/crlf.sh`'s own
  `_crlf_marker_set` uses), and a SEPARATE, entirely benign follow-up request to the SAME parameter -
  one that never itself sends the marker - is asked whether that exact marker now appears in ITS OWN
  response. **The check reads the FOLLOW-UP's response, never the poisoning request's own response** -
  reading the immediate response would flag any endpoint that merely echoes its input, which proves
  nothing about cross-request state. Confirmed with a SECOND, independent marker before being reported,
  the identical retest discipline `modules/dast/active/nosqli.sh`'s own boolean technique already
  applies, so a one-off coincidence (an echo endpoint, request-id logging) cannot fire it alone.

CWE-1321 ("Improper Filtering of Special Elements") is MITRE's dedicated id for this class, distinct
from the generic injection CWEs sibling probes use; OWASP mapping stays A03:2021, the same uniform
choice every §7.3 injection check in this catalog makes. `tests/suites/dast-protopollution.sh` (50
assertions, registered) is the proof, including a mutation-tested case that isolates the baseline-noise
skip specifically (an endpoint whose benign baseline already matches ONE signature while the pollute
value 500s with a DIFFERENT one and the control is clean - a shape that would look like a real
differential if the baseline check alone were removed, even though the redundant control comparison
also guards it) and a case proving a same-request-only echo is not mistaken for cross-request
contamination.
**DAST-24 (`active/hosthdr.sh`) has also landed**, docs/DESIGN.md §7.3's "Host-header injection"
bullet - spoof `Host`/`X-Forwarded-Host` and flag reflection into the response body or into a
redirect's `Location` authority.  It is the first tier-4 probe that does NOT build on
`active/inject_engine.sh`: the check varies a request HEADER on an endpoint the crawler already
inventoried, not a discovered parameter, so it reuses `passive/cors.sh`'s own
candidate-list/dedupe/one-request-per-route shape instead.  It ships
`modules/dast/active/hosthdr_engine.sh` (the sentinel, a duplicate - not a shared call, since
`openredirect.sh` is a phase script with no engine-only file to source - of `openredirect.sh`'s own
proven URL-authority parser for the `Location` sink, a plain-substring body-reflection sink, and
finding emission) and `modules/dast/active/hosthdr.sh` (the phase script).  Two check ids,
`DAST-HOSTHDR-REFLECTED_BODY-01` and `DAST-HOSTHDR-REFLECTED_LOCATION-01`, one per SINK rather than per
header technique - the DAST location profile's `loc_param_name` already carries `Host` or
`X-Forwarded-Host`, exactly as `cors.sh` carries `Origin`, so the technique needs no id of its own,
while the sink does (the same argument `openredirect.sh`'s header/meta split makes).  Only GET/HEAD
endpoints are probed and no form is ever submitted; confirming §7.3's own "reset-poisoning" sink would
need a POST to a real password-reset endpoint and, live, a real outbound email, so that is a stated,
deliberate gap (the same boundary DAST-03's declined "live" enumeration probe draws) and the
body-reflection check is its documented substitute, since a poisoned reset link built from the Host
header shares the identical root cause.  `tests/suites/dast-hosthdr.sh` (49 assertions, registered) is
the proof, including a mutation-pinned case for the authority-vs-substring distinction on the
`Location` sink.
The one thing worth carrying up here from DAST-15's landing note: **that probe measures ESCAPING, not
reflection.**  Almost every parameter on a real application reflects something, so a probe that
flagged reflection alone is a false-positive generator - and the escaped case is the half that fails
in the direction that reads as a pass, which is why every context case in `tests/suites/dast-xss.sh`
is a PAIR (the same marker into the same template, once escaped and once raw) rather than a single
positive.
DAST-16 is bounded time-based OS command injection (`DAST-INJ-CMDI_TIME-01`, CWE-78): it reuses
DAST-14's `inject_engine.sh` and time-based mechanism, adds
`modules/dast/payloads/cmdi-time-payloads.txt`, and clamps the injected sleep into 1..10s BEFORE
substitution so a probe can never become a DoS - the bound is load-bearing and applied, not advisory.
`tests/suites/dast-cmdi.sh` (registered) proves it.
**DAST-18 measures EVALUATION, not reflection, and the payload set is built so the two cannot be
confused by accident.**
Each of its four payloads (`modules/dast/payloads/ssti-expressions.txt`, one per engine family:
`{{...}}` Jinja2/Twig/Nunjucks, `${...}` FreeMarker/JSP-EL/SpEL/Mako, `<%= ... %>` ERB/EJS/ASP,
`{...}` Smarty) is a single multiplication flanked by the literal sentinel `sstiqzx`, and the
signature is that sentinel wrapped around the PRODUCT.
**The invariant the whole check rests on is that the digit `8` occurs in every signature and in no
payload**, so no delete, reorder, re-encode or partial strip of the bytes that were sent can
manufacture the result - only arithmetic can; `tests/suites/dast-ssti.sh` re-derives that from the
shipped file row by row rather than trusting the comment.
Two further things there are easy to get backwards, both measured by mutation: **the product is
deliberately kept under 1000**, because FreeMarker and every other locale-formatting engine groups
from four digits up, so a plain-digit signature for `9007*8117` would MISS the family it was aimed at
and a miss reads as a clean result; and **the first confirmed family wins per parameter**, asserted by
COMPARING request counts (a confirming endpoint costs 2 requests, a non-confirming one costs 5), which
is what distinguishes "stopped early on a hit" from both "sent everything anyway" and the opposite
defect of stopping early on a MISS.
Its four check ids exist for the same reason SQLi's three do - the DAST location profile names no
engine, so one id would collide a Jinja2 and a FreeMarker hit on one parameter onto a single
fingerprint.
It needed NO edit to `modules/dast/engine.sh`: the `'active/ssti.sh:active'` row has been in
`_DAST_PHASES` since DAST-02, so landing the script alone flips the phase from `absent` to `ran`.

DAST-29 created a THIRD such shared registry, `modules/dast/checks.rules`, for the tier-5 phases
whose scripts sit at the top level of `modules/dast/`; DAST-28 has already appended its two
`DAST-RATE-*` records to it, and DAST-27 has appended its own `DAST-GQL-INTROSPECTION-01` record the
same way - a conflict in it is resolved by keeping both blocks, never by choosing a side.
DAST-30 is NOT one of them despite being a tier-5 ticket: its script sits under
`modules/dast/passive/`, so its checks are registered in that directory - today in its own
`modules/dast/passive/checks-transport.rules`, per tension 29's split.
`docs/STEP5-DAST-PLAN.md`'s own per-ticket status table records every one of DAST-01 through DAST-36 as
landed; that table, not this sentence, is the authority if this is ever in doubt.
**Step 5 is therefore complete.**
Steps 8 (`--paranoid` / `tools/run-in-netns.sh`) and 9 (optional engine adapters) have also landed, out
of sequence - see their own sections below.
Steps 6 (Cloud), 7 (persistent state) and 10 (SARIF plus the compliance report) have each now started -
see below - per `docs/STEP6-CLOUD-PLAN.md` and `docs/STEP7-STATE-PLAN.md`'s stated priority order among
the three, now that step 5 has cleared: step 7 first, then step 10, then step 6 last.
All three now have a written sub-ticket plan, step 10's being `docs/STEP10-SARIF-PLAN.md`
(SARIF-01..06 plus COMPLIANCE-01..04).
**Read that one before treating step 10's queue position as a dependency**: it establishes, against
the tree, that step 10 is three deliverables rather than one - the SARIF emitter is unblocked today
and needs neither step 6 nor step 7, the compliance report's OWASP half is unblocked too while only
its CIS half waits on step 6, and the `--fail-on` CI gate that `docs/DESIGN.md` §13 item 10 bundles
with them shipped back at step 3 and carries no ticket at all.**

**Step 7 (persistent run state) has now started**, ahead of step 6 (Cloud) and matching
`docs/STEP7-STATE-PLAN.md`'s stated priority order: **STATE-01 (`lib/state.sh`) has landed** - the
frozen `state/<run-id>.json` schema (tension 12: `fp_schema`, `tool_version`, `run_id`, `completed_at`,
`scan_root_id`, `covered_checks`, `findings`), a writer
(`state_set_run`/`state_add_covered`/`state_add_history_boundary`/`state_add_finding`, then
`state_write`) that persists write-then-rename and prunes to a retain count (default 30, mirroring
`rules/RULE-FORMAT.md` §9.6.1's `state-retain-runs`), and a loader (`state_load_file`/
`state_load_latest`) that treats a missing or unparsable state file as "no prior state" while
REJECTING a structurally malformed record outright - a duplicate fingerprint, a finding missing a
required field, an invalid `scope` value, a non-boolean `suppressed`, an empty `cells` array - rather
than half-loading it, two of those rejections proven by mutation.
It implements the schema and the persistence primitives ONLY: no coverage recording (STATE-02), no
classification (STATE-03 through STATE-05), and no `diff` command wiring (STATE-06) - `scan.sh`, every
module's coverage behaviour, and the `diff` subcommand stub are all byte-for-byte unchanged by this
ticket.
**One coverage-scope kind, `account-region`, has no real producer yet**: cloud (step 6) has not landed,
so `tests/suites/state.sh`'s `account-region` coverage is schema-only, against a hand-authored fixture,
proving the writer and loader treat that scope kind correctly in isolation - not that it round-trips a
real cloud finding, which needs step 6 to exist first (`lib/state.sh`'s own header and
`docs/STEP7-STATE-PLAN.md`'s "Status" section both record this as a known, tracked gap rather than
silently-assumed coverage).

**Step 10's first ticket, SARIF-01, has also landed**: `lib/findings.sh` gained
`_finding_default_logical`, called from `finding_emit` immediately before the fingerprint is computed,
which populates `logical_kind`/`logical_fqn` from the profile's own `loc_*` fields for `path`/`history`
(`kind=file`, `fqn=<loc_path>:<loc_line>`), `dast` (`kind=endpoint`,
`fqn=<loc_target>:<loc_method> <loc_path_template>#<loc_param_name>`, tension 22's shape verbatim),
`cloud` (`kind=resource`, `fqn=<loc_resource_key>`) and `posture` (`kind=control`,
`fqn=<loc_control_id>`) - the two emitter groups (SAST, DAST) and the two not-yet-built modules
(cloud, posture) tension 22's own "empty on every module" finding named.
`sca` and `derived` are untouched, since `modules/sca/` and the composite path already set their own
identity before `finding_emit` runs, and the function is a no-op wherever `logical_kind` is already
non-empty.
`logical_kind`/`logical_fqn` are absent from `_fp_components_for` for every profile, so no fingerprint
moves; `tests/suites/findings.sh` proves it by recomputing `finding_fingerprint` after the default
runs and asserting it against the value `finding_emit` already wrote, for every profile, plus a
single run emitting five profiles at once asserting none is left with an empty `logical_kind` - the
reading a per-module setter (rather than this one control point in `finding_emit`) fails under.
SARIF-02 (the generated location artifact writer) is now unblocked.

**SARIF-02 has also landed**: `report_locations` (`lib/report.sh`) writes
`reports/<run>/locations/<module>.txt` - one line per finding whose profile carries no usable real
file, keyed on the finding's own `logical_fqn` - called unconditionally from `report_all` (never
gated on `--format sarif`) before `findings_write_jsonl`/`findings_write_json`/`report_md`/
`report_html`, so every one of those emitters sees the write-back it makes. It rewrites
`findings.fields` in place, the `findings_mark_suppressed` read-decode-mutate-reencode-rewrite
shape: case 4 (`dast`, `cloud`, `posture`, `derived`) always gets a line; case 3 (`SAST-HIST-*`)
gets one only when a real filesystem test against the scan root shows `loc_path` no longer
resolves, and that fallback line carries `loc_blob_sha` and `commit` so a reader can `git show` it;
case 1 (a real working-tree file) and case 2 (`sca`, whose own `path` field already names a real
lockfile) are untouched. The assigned line number is written back onto `loc_line` - the field
SARIF-04's own mapping table already sends to `region.startLine` - so that ticket needs no
per-case location logic of its own. Ordering is exactly `findings.fields`'s own
`(module, check_id, fingerprint)` order under `LC_ALL=C`, undisturbed by `derive_findings`' later
re-sort, so two runs over one fixture assign the same line to the same finding and produce
byte-identical location files. `SCOURSH_SCAN_ROOT_PATH` is a new variable `scan.sh` exports
alongside `SCOURSH_SCAN_ROOT_ID`/`SCOURSH_PATH_ROOT` for `sast`/`sca`/`iac`/`all` - the one absolute
path the case-3 filesystem test needs; unset is treated as "cannot resolve", never as "resolves",
the fabrication-avoiding default tension 22 requires. `tests/suites/sarif-locations.sh` (33
assertions) is the proof, including a real git-repo fixture for case 3 (one committed-and-deleted
blob, one committed-and-still-present blob) and two independent runs over one fixture proving
byte-identical output.
**`report_all` runs more than once per run directory** - `scan.sh all` calls `sast`/`sca`/`iac`
(and `dast`, with `--target`)'s own `run.sh` in sequence, and each independently calls
`findings_merge` (rebuilding `findings.fields` from every shard emitted so far) then `report_all`
- so `report_locations` sees an earlier pass's findings again on every later call.  Reproduced with
a real `scan.sh all --history` subprocess (three `report_all` calls landed 4 lines in
`locations/sast.txt` for 2 real history findings) before the fix: it now truncates a module's
artifact file the first time a given CALL touches it, making every call a full, idempotent
regeneration from the current snapshot - `findings_write_jsonl`/`report_md`/`report_html`'s own
truncate-then-rebuild discipline - rather than an unbounded append, and the same real subprocess
now lands exactly 2. SARIF-03 is now unblocked.

**STATE-02 (per-(check, cell) coverage recording, and persist-on-every-run wiring) has also landed**,
for the same "its own scope does not need the `account-region` producer" reason STATE-01 was authorised
ahead of step 6.
A (check, cell) pair enters `covered_checks` **only on completion**, never at selection: every module
that already emits findings (SAST, `SAST-HIST-*`, IaC, SCA, DAST) records its coverage on the line
immediately after its own scan-tree/walk call RETURNS, which under `set -Eeuo pipefail` is reached only
on success - so a check merely enumerated/selected but never completed (a profile/intensity filter drop,
a missing dependency such as SCA's `data/advisories.db`, an engine failure, a circuit-breaker trip) is
never marked covered.
`modules/sast/engine.sh` gained `sast_record_coverage`, reused unchanged by `modules/iac/run.sh` exactly
as `sast_index_checks`/`sast_evaluate_gate` already are; `modules/sast/history.sh` records every
`SAST-HIST-*` check plus its `history_boundary` block once the whole bounded blob walk finishes;
`modules/sca/run.sh` records its six fixed check ids with a stable hash of the check id itself as
`rule_digest` (SCA ships no `*.rules` record to hash, and `lib/state.sh`'s own loader rejects an empty
`rule_digest` as malformed - measured while building this ticket); `modules/dast/run.sh` derives its own
coverage from the run-wide `checks_run` fact (already this repository's "the check finished" signal),
filtered to `DAST-*` ids and sliced to the lines appended since the current target's own phase loop
started, so an earlier module's ids in a `scan.sh all` run can never be misattributed to a DAST target
cell.
`scan.sh` wires `state_reset`/`state_set_run` right after `run_init` and `state_write` at the very end
alongside `report_run_json`; `lib/core.sh`'s existing exit-5 recovery path (`run_json_refresh_incomplete`,
which already re-runs the three report writers on a `die 5`) now also persists `state/<run-id>.json` when
`state_set_run` had already run for this process (`state_run_pending`, the one small, purely additive
accessor added to `lib/state.sh` - nothing in STATE-01's own schema, builder, or loader changed) - so a
run that dies mid-flight still leaves real coverage behind for whatever completed before the abort.
`tests/suites/state-coverage.sh` proves all six of tension 12's non-completion cases (module not
selected, profile/intensity filter dropped, missing dependency, breaker-style abort, a resumed run never
reaching a unit, a run never visiting a cell) as well as the positive completed-pair case for two module
kinds, each naming the reading it fails under - several are built specifically to catch a coverage
recorder that copied `modules/sast/run.sh`'s/`modules/iac/run.sh`'s own `run_record checks_run "$id"`
placement (which runs BEFORE the scan-tree call, since `checks_run` answers "loaded and executed", not
"ran to completion") instead of gating on completion the way this ticket actually does.

**STATE-03 (the classification engine: `new`/`recurring`/`fixed`/`unknown` + `diff_usable`) has also
landed**, for the identical "its own scope does not need the `account-region` producer" reason STATE-01
and STATE-02 were authorised ahead of step 6 - tension 12's frozen JSON shape is one shape regardless of
which module produced a given entry, so a hand-authored `account-region` fixture proves the engine's
guard and coverage logic correctly for that scope kind without a real cloud emitter existing.
It is five pure functions added to `lib/findings.sh`'s own new section 17, immediately after
`classify_derived`'s section 16: `findings_classify_guard` (the two guards - an `fp_schema` mismatch or a
`scan_root_id` mismatch, printing `usable`/`no_prior_state`/`fp_schema_mismatch`/`scan_root_id_mismatch`),
`findings_diff_usable` (that guard reduced to the boolean the gate reads), `findings_classify_present`
(new/recurring for a finding THIS run found), `findings_classify_absent` (fixed/unknown for a PRIOR
finding this run did not, reusing `_pair_covered` - the identical coverage test `classify_derived`'s own
(b2) branch already uses, rather than a second copy), and `findings_rule_digest_changed` (the "rule
changed" report flag, which never itself alters a status).
Like `classify_derived`, none of it sources `lib/state.sh` or touches its arrays - every input is a
plain scalar or a line-oriented file, the same shapes `classify_derived`'s own `COVERED_THIS_RUN` already
established - so there is no new `shellcheck -x` source edge, and this ticket wires into nothing:
`scan_main`, `scan.sh diff`, and the report are byte-for-byte unchanged.
Converting a REAL loaded `state/latest.json` and a real run's findings into these shapes is STATE-06's
job, mirroring the division of labour STATE-05 inherits for `classify_derived`.
A derived finding (JSON `null` cell) is out of scope here; `classify_derived` is unchanged.
`tests/suites/state-classify.sh` proves the plain four-row table with no guard active, both guards and
`findings_diff_usable` in isolation - including that a `scan_root_id` mismatch excludes only
`path-root`-scoped prior findings (leaving `target`/`account-region`/`scope-key` findings classified
normally) and that a run with no path-root coverage at all cannot be invalidated by an unrelated
`scan_root_id` difference - and tension 12's own eight-row fixture matrix in full: the three
module/check/region/target-scoped rows via hand-authored coverage files, and the five scan-root-identity
rows (non-git path collision, nested git repo collision, cwd-independence, two-checkout portability, and
full/shallow/single-branch-clone-of-an-orphan-branch-carrying-repo identity) against REAL directories and
REAL `git` repositories, feeding `scan_root_id_of`/`path_root_cell`'s own live output into the
classification functions.
Several cases deliberately plant a coverage entry a naive/rejected reading would accept, so the guard -
not a coincidental absence - is what is proven to block a false `fixed`; two guard mutations were run
against the suite and watched fail before being reverted, per this project's testing rule.

Step 6 (Cloud) remains unstarted.

**DAST-07 made `docs/FOUNDATION.md` tension 19's single documented exception real, and the shape it
landed in is what a future non-HTTP probe must copy.**
`modules/dast/passive/tls.sh` needs a raw TLS handshake - not an HTTP request, and curl exposes neither
the negotiated protocol, the negotiated cipher, nor the presented certificate - so it is exempted from
the chokepoint's TRANSPORT and from nothing else.
`lib/http.sh` gained `http_authorize_raw_connection` (section 9b): everything `http_request` does except
send a request - normalization, the scope tuple compare, the userinfo refusal, the private/loopback deny
list, the pinned resolution, and the tension-16 limiter, per-run budget and circuit breaker spend - and
it hands back a resolved address the module connects to without ever re-resolving the name.
A TLS handshake therefore spends a budget token exactly as a request does.
Letting the module call `http_gate_url` and `_http_throttle` itself was the rejected alternative, on
tension 19's own argument: a control each caller must remember to apply is not a control, and the next
exempted caller would then be free to assemble its own subset.
`tests/lint-shell.sh` exempts the two files **by path**, never by widening the pattern.
Three userland facts it measured, each of which ships green on one userland and is silently wrong on the
other: LibreSSL's `New, TLSv1/SSLv3, Cipher is ...` is a FAMILY LABEL and not the negotiated version (a
parser reading it reports every LibreSSL-probed target as TLSv1); a FAILED handshake still prints a
filled-in `Protocol  :` with `Cipher    : 0000`, so a parser that accepts a protocol alone reports the
*offered* version as negotiated; and `openssl x509 -ext subjectAltName` does not exist on LibreSSL, so
the SAN list is read out of `-text`.
Distinguished names come in two spellings (`CN = h, O = o` versus `/O=o/CN=h`), so every comparison is
made on a normalized form - a raw subject-versus-issuer compare makes the self-signed check
userland-dependent.
Expiry takes `now` as an ARGUMENT rather than calling `openssl x509 -checkend`, which hardcodes the
system clock: injectable time is what lets one committed, long-lived fixture certificate reach
`expired`, `expiring` and `ok` deterministically.
"Wildcard where a host-specific certificate is expected" is an EXPECTATION, so it is the per-target
`tls-expect-wildcard` in `config/scope.conf`, not a scanner-wide verdict - an estate legitimately has
both shapes.
The suite was run under real **OpenSSL 3.6.3** and real **LibreSSL 3.3.6** on one macOS host, 131
passed 0 failed under each; a GNU/Linux host is NOT covered by that and is left to
`tools/daily-suite.sh`'s container leg.
Which rule packs, SCA ecosystems and IaC packs have landed, and what remains of each, is in the
generated block below - read it there rather than restating it here.
The design notes the inventory cannot carry stay hand-written:

- Ecosystems do **not** map one-to-one onto entry points, so never infer coverage from the number of
  tree-walk functions, in either direction. The mapping is:

  | entry point | file | ecosystems |
  |---|---|---|
  | `sca_scan_tree` | `engine.sh` | npm, RubyGems, Composer |
  | `sca_scan_python_tree` | `engine.sh` | pypi |
  | `sca_scan_java_tree` | `engine.sh` | maven |
  | `sca_go_scan_tree` | `go_engine.sh` | Go |

  Ruby and PHP have no entry point of their own: `sca_scan_tree` walks npm, `Gemfile.lock` **and**
  `composer.lock` in one call. That grouping was originally the whole defence against
  `SCA-COV-UNKNOWN_VERSION-01`'s fingerprint carrying no ecosystem component, and it was only ever half
  of one - it kept those three from colliding with each other while leaving them free to collide with
  the other three entry points, which is what shipped. All four now feed ONE module-wide accumulator
  (`modules/sca/engine.sh` section 8a); see the roll-up bullet under "Sharp edges" above. Composer's
  parser lives in `php_engine.sh` and Go's in `go_engine.sh`, but a separate *file* is not a separate
  entry point - and note Go's is spelled `sca_go_scan_tree`, which a `sca_scan_*_tree` glob does not
  even match.
- `history.sh` (the `SAST-HIST-*` mechanism, tension 13) is step 3's sub-step 3e, not a rule pack; it
  appears in the generated SAST table as a script row for that reason.
- Step 3's sub-step letters come from the ticket titles, not from landing order: 3c landed before 3b,
  and 3d after 3e.
- Step 4 groups SCA and IaC into one step (`docs/DESIGN.md` §13, "both reuse the rule engine"), so
  neither half being complete makes step 4 done.

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
| `modules/sast/rules/ldap.rules` | landed | 3 | `tests/suites/sast.sh` |
| `modules/sast/rules/nosql.rules` | landed | 4 | `tests/suites/sast.sh` |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/secrets.rules` | landed | 7 | `tests/suites/records.sh` |
| `modules/sast/history.sh` | landed | - | `tests/suites/sast-history.sh` |

Landed 10 of 10.  Outstanding: none.

#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`

| Manifests | Status | Parsers | Exercised by |
| --- | --- | --- | --- |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-ecosystems-php/package-lock.json` |
| `requirements.txt`, `poetry.lock`, `Pipfile.lock` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-four-ecosystems/requirements.txt` |
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

- Pattern packs on disk: **15** (`modules/sast/rules/` 9, `modules/iac/` 6).
- Module directories present: `modules/dast/`, `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

Because `checks_registry_load` (`lib/checks.sh`) globs every `*.rules` file under `modules/iac/` with
no per-pack allowlist, EVERY IaC pack on disk loads together on any `scan.sh iac` run, whichever packs
those currently are - `tests/suites/iac.sh` scans each landed pack's ids in its `checks_run` integration
section, so a new pack that forgets that section shows up as a gap rather than as silence.

**Step 4's IaC half landed out of the strict step order, one ticket per file format.**
Which formats are in and which are outstanding is in the generated block above; what is worth keeping
in prose is the scoping reasoning behind two of them, because it is not recoverable from the file
list:

- The Terraform ticket (commit `5de4460`, "IaC: Terraform checks via the pattern-rule engine") shipped
  the shared IaC scaffolding - `modules/iac/run.sh` (the `scan_dispatch iac` entry point, reusing
  `modules/sast/engine.sh`'s `sast_evaluate_gate` and `sast_index_checks` unchanged rather than forking
  an IaC-specific copy) and `modules/iac/parse.sh` (`iac_scan_file`/`iac_scan_tree`, the same two-pass
  design as `sast_scan_file` with only the finding-emission path forked so `module` reads `iac`) - plus
  `modules/iac/terraform.rules` (seven `IAC-TF-*` checks: open CIDR, public ACL, unencrypted-at-rest,
  KMS key rotation disabled, public IP, hardcoded secret, RDS publicly accessible), scoped to `*.tf`
  only.
  This ticket landed without this section (or `docs/FOUNDATION.md`'s mirror) being updated - the same
  process-note failure §13 step 3e's own paragraph below already documents for `history.sh` - so
  `modules/iac/` existing was rediscovered by the next ticket reading the tree rather than the docs;
  this section and its mirror are corrected here to close that gap, which is what this paragraph and the
  process note above exist to keep from recurring.
- This ticket ("IaC: Kubernetes manifest checks via the pattern-rule engine") shipped
  `modules/iac/kubernetes.rules`: eight `IAC-K8S-*` checks (privileged containers, host
  network/PID namespace sharing, missing resource limits/requests, `runAsNonRoot` unset, plaintext
  secrets in env vars, the mutable `:latest` image tag, wildcard RBAC verbs/resources, and
  `automountServiceAccountToken` left at its default), scoped to plain Kubernetes YAML/JSON manifests
  and reusing `modules/iac/run.sh`/`parse.sh` unchanged (they were already technology-agnostic).
  Helm chart templates and CloudFormation templates are explicitly excluded by design - see the pack's
  own header comment for the case-sensitivity (Kubernetes' lowerCamelCase field names versus
  CloudFormation's PascalCase) and `context-deny` (`\{\{` for Helm, `AWSTemplateFormatVersion|AWS::` for
  CloudFormation, on the three absence-style checks) mechanisms that keep it out of scope for those two
  shapes even though the file glob overlaps.
- The CloudFormation ticket ("IaC: CloudFormation checks via the pattern-rule engine") shipped
  `modules/iac/cloudformation.rules`: eight `IAC-CFN-*` checks, the seven `IAC-TF-*` siblings
  restated in CloudFormation's PascalCase property shape plus `IAC-CFN-ECS_PRIVILEGED-01`, which
  has no Terraform sibling and is the CloudFormation spelling of `IAC-K8S-PRIVILEGED-01`.
  Its scoping is the **inverse** of every other pack in this directory, and that is the part worth
  keeping in prose: a genuine CloudFormation template has no reserved filename or path convention at
  all, so `files:` is deliberately as broad as the format allows (`*.yaml`, `*.yml`, `*.json`,
  `*.template`) and ALL the narrowing is a `context-require` on `Type: AWS::<Service>::<Resource>`,
  the one string a Kubernetes manifest, a Helm chart or a docker-compose file cannot carry while
  still being that thing.  That anchor is strictly stronger than a filename glob, which is why this
  pack ships **no `exclude-files`** where `kubernetes.rules` needs eight - and why the absence is
  asserted against the same `tests/fixtures/iac/docker-compose/` fixture rather than left as a
  comment.  Do not "harden" this pack by adding compose globs to it: they would be a guard no fixture
  can distinguish from its absence.

Three things this pack measured that are easy to get wrong again, and are not specific to it:

- **Write a `files:` glob as `*.yaml`, never `**/*.yaml`.**  Per `rules/RULE-FORMAT.md` §9.1.2 an
  unanchored glob already matches at any depth (`sast_glob_match` tries every path-segment-aligned
  suffix), so `*.yaml` covers `infra/main.yaml`.  `**/*.yaml` translates to
  `^(.*/)?.*/[^/]*\.yaml$`, whose `.*/` requires at least one directory component, so it silently
  MISSES a file at the scan root - the likeliest place for a template.  The bug is invisible in a
  fixture tree, where every path is nested by construction.
- **The pattern engine has no comment awareness anywhere.**  A `#` line in a *clean* fixture that
  quotes the hazardous `Key: value` pair it is documenting IS a match, and turns that fixture into a
  false positive against itself.  `tests/fixtures/clean/cfn_ecs_privileged.yaml` was exactly that
  before it was reworded; the suite caught it, but the failure reads as a rule defect rather than a
  prose defect, so it costs a debugging cycle.  Describe the hazard, do not spell it.
- **A "not landed" row in the generated status block is not proof the work was never done.**  This
  pack existed as a finished commit in a merger ticket's workspace for a day: mergers resolve on the
  *source* ticket's branch, so they have no branch of their own, the landing sweep skips them by
  design, and nothing then records an outcome - a merger that had something to land looks identical
  to one that did not.  When an artifact is outstanding, search the workspaces for a commit naming
  it before writing it from scratch.

Step 4's IaC scope is drawn from two separate places - `docs/DESIGN.md` §6.6's
container/orchestration catalog and §8.2's CloudFormation checks - and the generated block above tracks
both against what is on disk.  §6.6's Helm bullet means Helm **values and chart sources**; the
**rendered**-chart case is a distinct sub-scope that no pack claims.

**Step 5 (DAST) is the TOP priority - ahead of live cloud scanning (step 6), persistent run state
(step 7), and SARIF plus the compliance report (step 10) - it has a written, dependency-ordered
sub-ticket plan, and its TIER 0 is now complete.**
`docs/STEP5-DAST-PLAN.md` breaks the ~30-script step 5 scope into tickets DAST-01 through DAST-30 plus
DAST-31 through DAST-36, ordered per `docs/DESIGN.md` §13's own `lib/http.sh -> auth.sh -> crawl.sh ->
passive -> safe-active -> injection -> §7.4` sequence, and states plainly that `lib/http.sh`'s
scope-gate chokepoint (tension 19) already shipped (see below) and is not re-planned.
That plan, not this paragraph, is the authority for the sub-ticket sequence and for what each ticket
depends on; its own "Status" section carries the per-ticket landed table.

**What tier 0's safety half (DAST-31 through DAST-34) shipped, and the three things about it that are
easy to get backwards.**

- **The ceilings are enforced where the scope gate is enforced, and nowhere else.**  They are applied
  to the RESOLVED value inside `lib/http.sh`, never in `modules/dast/`, for the identical reason
  tension 19 puts the gate in `http_request`: `tests/e2e/dast-target-smoke.sh` already sends real HTTP
  by calling `http_request` directly, with no module and no `scan.sh` parser anywhere in the path, so a
  ceiling living in a module would bind exactly the callers that had already come through it.
- **The clamp policy is ASYMMETRIC, and each half is the other half's bug.**  A **file or default**
  value above a ceiling is CLAMPED with one `log_warn` and a durable recorded delta; an explicit **CLI
  or env** value above one is **exit 2** naming `--i-own-target`.  Clamping the first is what stops an
  operator affirming reflexively just to make an unedited install run at all - `request-budget`'s own
  §9.6.1 default of `20000` is above the 5000 DAST ceiling, so a uniformly-fatal policy means a fresh
  clone cannot send one request.  Refusing the second is what stops the tool running at a number other
  than the one the operator typed.  `tests/suites/http.sh` pins both directions, each with a case that
  fails under the other reading.
- **`--i-own-target` is a KEY, not a switch, and the affirmation lives in a per-run RECORD.**  It must
  equal `--target` (mismatch, or no `--target` at all, is exit 2), it is valid on `dast` and `all`
  only, and on its own it changes no limit - `--intensity` above `passive` and `--allow-intrusive` each
  need it PLUS themselves.  It is deliberately not an environment variable: an env var is settable by
  anything that can start the process, and binding callers whose command line nobody parsed is the
  ceiling's entire job.  It is never persisted, and there is no `scanner.conf` key meaning "always
  unrestricted".
- One refinement the plan's own "Relaxable" table did not state, now recorded in `docs/FOUNDATION.md`
  tension 16 as well: the affirmation lifts the three UPPER bounds (rate, budget, breaker threshold)
  and lifts NEITHER of `circuit-breaker-window`'s bounds - the 60s floor because a shorter window is a
  weaker breaker, and the 86400s maximum because it is arithmetic rather than safety.

**DAST-03 (`auth.sh`) has landed - the first ticket of tier 1, and the first DAST phase script that
exists at all.**
`modules/dast/auth_engine.sh` is the pure library (config load, the session store, every §7.0 login
mode, re-auth, and the config-derived enumeration check) and `modules/dast/auth.sh` is the phase script
`dast_run_phase` sources - the `engine.sh`/`run.sh` split `modules/sast/` established, one level down.
`tests/suites/dast-auth.sh` is the mocked suite (no network, no Docker, so it runs everywhere) and
`tests/e2e/dast-auth-live.sh` is the opt-in proof against the authorized local Juice Shop target, in
the same shape and for the same reason as `tests/e2e/dast-target-smoke.sh`.
`docs/STEP5-DAST-PLAN.md`'s own DAST-03 landing note is the authority for the detail; six things about
it are worth carrying here because a later ticket will otherwise rediscover them the expensive way.

- **`lib/http.sh` gained a per-request context, and the module deliberately did not.**  `http_request`
  could previously send neither a header nor a request body and discarded the response body, which is
  everything §7.0 needs.  `http_request_header` / `http_request_body` / `http_request_capture` (that
  file's new section 9a) are consumed by `http_request` at ENTRY and the globals reset immediately, so
  a credential attached for one request can never ride along on the next one however the first one
  ended.  Putting any of this in `modules/dast/` would have been the second path to the network
  tension 19 exists to prevent, and would have skipped the limiter, the budget, the breaker and the
  DAST-32 ceilings that all hang off the chokepoint.
- **A credential reaches curl over STDIN, as a `curl -K -` config, never through `argv` and never
  through a file.**  curl has no `-H @file` and no stdin-header option, so the real alternatives were
  argv (visible in `ps` to every user on the host) or a scratch file - and tension 9's handling rules 1
  and 2 forbid both.  `tests/suites/http.sh` proves it with a stub `curl` that dumps its own `argv`.
  There is still **exactly one curl invocation** in that file, and the empty config is passed anyway
  rather than branching, because "every request carries the identifying User-Agent" is only structural
  while there is one command line to notice.
- **A redirect drops the caller's headers and body when it crosses ORIGIN, and downgrades the method on
  a 301/302 after a non-GET.**  Both origins being in `config/scope.conf` does not make them the same
  principal: the gate answers "may this tool talk to that host", never "does this credential belong to
  it".  And re-POSTing a login body to a path the SCANNED TARGET chose is exactly what a login flow
  must not do (RFC 7231 §6.4.3; 307/308 are left alone, since preserving the method is what they are
  for).
- **The `form` mode probes at most three body shapes because the FROZEN schema names none.**
  `rules/RULE-FORMAT.md` §9.6.2 gives `form` a `login-path`, a `username` and a credential and no body
  encoding and no field names, so an implementation must choose - and choosing one would work against
  classic HTML form logins or against JSON login APIs but never both.  Order: urlencoded, then JSON
  `{"email":..}`, then JSON `{"username":..}`; first to yield a session wins; the winner is PERSISTED
  so a re-auth replays it and never probes again.  Three attempts is a real cost against an account
  lockout policy, which is why it is bounded and never repeated.  Do not "improve" this by adding a
  fourth shape: a `login-body-shape` key is the better answer and is a register change, since §9.6.2 is
  frozen.
- **`srp` accepts a pre-obtained token and does not compute the handshake**, which `docs/DESIGN.md`
  §7.0 explicitly permits ("compute the SRP handshake in shell, **or** accept a pre-obtained token to
  avoid re-implementing crypto").  A pure-shell SRP-6a is modular exponentiation over a 3072-bit group
  in bash arithmetic - unverifiable crypto in a language with no way to test it.  E074 says so at
  config-load time and the run records `srp_handshake_not_computed`, so `mode: srp` never reads as
  evidence the provider's SRP exchange was exercised.
- **A failed authentication is a DECLARED coverage reduction, not exit 5.**  §7.0's own wording is
  "mark the authenticated checks `skipped` with a clear reason", which is the vocabulary of
  `docs/FOUNDATION.md` tension 14's declared rows ("a check skipped for an absent `requires-cmd` or
  `requires-config`"), not of its unplanned ones - a session that could not be obtained makes the
  authenticated checks' required input absent, exactly as a missing `config/auth.conf` does.  The run
  continues; `dast_auth_state` returns `failed` for the rest of it and `dast_auth_skip_reason` is the
  sentence every dependent check states.  What is forbidden, and is the whole point, is running those
  checks unauthenticated and reporting their silence as clean.

**The live proof, and one pre-existing bug it turned up.**  `tests/e2e/dast-auth-live.sh` passes 31 of
31 against a real, local Juice Shop container: both identities log in over real HTTP, the form-shape
probe picks the JSON shape (this target's urlencoded attempt is rejected, so a single hardcoded body
would never have logged in at all), each session reaches its OWN object server-side, identity A reading
identity B's object is the broken-access-control case DAST-29 will assert on, a deliberately corrupted
token produces a real 401 that is re-authenticated and retried once, and a real
`scan.sh dast --target ... --authed` run - the whole CLI -> dispatch -> phase chain an operator
actually invokes, which none of the direct-engine cases exercise - acquires both sessions, records them
in its own `run.json`, and leaves no credential anywhere in the run directory.
Two facts measured there are worth keeping:

- **This pinned Juice Shop image 400s on a duplicate registration**, and
  `tools/dast-test-identities.sh`'s header claimed the opposite as a measured fact ("accepting a repeat
  registration rather than 400ing on a duplicate email - verified against
  bkimminich/juice-shop:v20.1.1").  Re-measured: first registration 201, same email again 400
  `email must be unique`, login afterwards 200.  So running that script twice against one still-running container died, and every run after the
  first failed on a target that was in fact correctly provisioned.  `dti_provision` now treats a
  duplicate refusal as the success it is, but only after a login proves the persisted password still
  opens the account - "the email is taken" and "the email is taken by an account whose password we
  hold" are different facts and only the second is idempotency.
- **This target's login sets NO cookie**: it returns the JWT in the JSON body and leaves the SPA to
  install it, so its own `/rest/user/whoami` - which reads a session cookie - answers `{"user":{}}` to a
  perfectly valid bearer token.  A shell scanner authenticating against a client-rendered app therefore
  holds a token some of that app's own endpoints will not accept, which is the same blind spot
  `docs/DESIGN.md` §7.5's SPA limitation names for crawling.  Do not read a 200-with-empty-body from
  such an endpoint as a failed session.

Two things landed with it because the first phase script is what made them true.
**E073 and E074 now have implementations** - both codes were reserved in `rules/RULE-FORMAT.md` §13
with none.  E074's mode-to-required-keys table lives in `lib/records.sh` in ONE copy, which
`modules/dast/auth_engine.sh` consumes rather than restating, and E073 is enforced at runtime as well
as by the linter (the file whose permissions matter is the operator's own; a lint that ran in this
repository has said nothing about it), and a `secret-file` is held to the same 600 requirement.
**`modules/dast/run.sh`'s honesty roll-up now keys on COVERAGE rather than on execution**: DAST-02 could
ask "did any phase run" because none existed and the two questions had one answer, but `auth.sh` runs on
every passive run and covers nothing without `--authed`, so that reading would have started reporting
coverage on exactly the run that has none.  It counts `run_record checks_run` instead - the mechanism
`modules/sast/`, `modules/iac/` and every `modules/sca/` engine already use - and gained a third reason,
`no_check_covered_by_any_phase`, alongside DAST-02's two.
**What DAST-03 deliberately did not build**: the LIVE user-enumeration probe.  §7.4's closing paragraph
splits that check in two and only the config-derived half is here - it reads the authentication
responses the run already received and sends nothing.  The live half submits an identifier the operator
never configured, which on a real identity provider creates accounts and sends messages, so it needs
`--allow-intrusive`; a run given that flag today records `live_enumeration_probe_not_implemented`
rather than letting an absent finding read as a clean result.

**DAST-04 (`modules/dast/crawl.sh`) has landed, and it is the file the rest of step 5 is built on:
it writes `reports/<run>/inventory/endpoints.json` and `parameters.json`, which every one of the
twenty-seven tickets in tiers 2-5 reads.**
`docs/INVENTORY-FORMAT.md` is their normative shape and is a CONTRACT - read it before consuming
either file, and do not widen it casually.
The work splits the way `modules/sast/` already does: `crawl.sh` is the phase script `dast_run_phase`
sources (it orchestrates the four inputs, in the deliberate order inventory -> specification ->
static crawl -> nothing, and records every gap), and `crawl_engine.sh` is the pure, testable half
(HTML link/form extraction, the JSON and YAML front-ends, the four specification parsers, the
inventory reader/writer).
Per the precedent `modules/sca/engine.sh` and the engine adapters set, the JSON parsing is a
purpose-built depth- and string-aware splitter rather than a general JSON library, and the YAML
front-end **refuses what it cannot represent instead of skipping it** - the wrong reading, "parse
the lines you understand and skip the rest", yields a SHORT endpoint list indistinguishable from a
complete one, which is exactly the overstated coverage `docs/DESIGN.md` §15 forbids.

Five decisions here are easy to get backwards; each is pinned by a test naming the reading it fails
under, and each was confirmed by deliberately breaking the implementation and watching the suite go
red:

- **The scope pre-check on a discovered link is NOT the gate, and both are required.** `http_request`
  gates fatally (out-of-scope is a caller bug, exit 3), which is right for an operator-configured URL
  and exactly wrong for one lifted off a scanned page: hand a crawled link straight to `http_request`
  and any site can abort the operator's whole run by linking to a search engine. `_crawl_in_scope`
  decides only whether a URL is worth ENQUEUEING; everything that survives is still requested through
  `http_request`, which re-gates on the way out and on every redirect hop. Deleting the pre-check
  makes the crawler fragile; deleting the `http_request` call makes it unsafe. Asserted on a REQUEST
  LOG, never on a return value - and proven live in `tests/e2e/dast-crawl-target.sh`, where the real
  target's own root document links to a third-party font CDN and the log shows no request to it.
- **A specification contributes its PATHS, never its HOST.** An OpenAPI `servers[].url`, a Postman
  URL and a HAR entry all name a host, routinely a production one; adopting it would make
  `config/discovery.conf` a way past the scope gate. The server URL's own PATH PREFIX *is* kept
  (`basePath` is the Swagger 2 spelling), because that is a fact about where the API is mounted, not
  about who to talk to.
- **The client-rendered (SPA) gap is recorded only when no specification closed it.** Printing it
  unconditionally would make asserting its presence prove nothing, so it is asserted present without
  a spec AND absent with one. It reaches `run.json`, `report.md` and `report.html`, which is the
  ticket's own acceptance criterion - "it is true in `docs/DESIGN.md` §7.5" was explicitly rejected
  as sufficient.
- **A form is inventoried, never submitted** - its `action`, method and input names become an
  endpoint and parameters, and no POST is sent. Submitting one is a state change, forbidden at the
  passive tier §7.1 defines.
- **A query string is stripped off the endpoint URL and its keys recorded as parameters.** Keeping it
  turns a paginated listing into fifty endpoints and makes every later check re-test one handler
  fifty times.

**The SPA limitation ships as a stated gap and is not a ticket awaiting an owner.** scoursh executes
no JavaScript and gets no browser; a client-rendered application's routes and its XHR endpoints are
invisible to a static crawl, so every later check reports clean for them because it never saw them -
the absence of a test, not the absence of a problem. Measured rather than asserted: a crawl of the
real local Juice Shop container (an Angular application) found **13 endpoints and 0 parameters**, all
static assets plus the root, and the run recorded `spa_shaped=1` off the target's own root document.
A thin result there is the PASS condition; a later change that inflates it by guessing at routes is
the defect. Supplying an OpenAPI spec to that same target took it to 16 and removed the gap.

**What DAST-04 deliberately did not build**, so the boundary is not rediscovered: the authenticated
crawl pass. The crawl runs unauthenticated and records a `coverage_gap` saying so; DAST-03
(`auth.sh`) owns the session and was built in parallel with this ticket, so the authenticated pass
plugs into that session when it exists rather than being stubbed here.
One correction this ticket made outside its own files: `modules/dast/run.sh`'s inventory
`coverage_gap` said "no crawler has run", which `crawl.sh` landing makes FALSE - it is emitted before
the crawl phase runs in the same run, so `run.json` contradicted itself, naming an empty surface in
one record and 13 endpoints in another. It now says what is true (no inventory was available as
INPUT) and points the reader at the file rather than the sentence.

**DAST-05 (`modules/dast/passive/headers.sh`) has landed - a TIER 2 check, built in parallel with its
peer DAST-06 (`passive/cookies.sh`), which reached `dev` first and is what actually created
`modules/dast/passive/`.**
It ships `headers_engine.sh` (the pure half: the response-header reader, the CSP/HSTS/Referrer-Policy
parsers, the endpoint chooser), `headers.sh` (the phase script `dast_run_phase` sources),
`checks.rules` (eleven `DAST-HDR-*` script checks, all tagged `passive`) and `recommended-headers.txt`
(the vendored, operator-editable roll-up list).  `tests/suites/dast-headers.sh` is the proof - 153
assertions, no network and no Docker, driven from recorded response heads replayed into
`lib/http.sh`'s own capture sink.  `docs/STEP5-DAST-PLAN.md`'s own DAST-05 landing note is the
authority for the detail; five things about it are worth carrying here because a peer ticket
(DAST-07..DAST-11 are all building against the same surface) will otherwise rediscover them the
expensive way.

- **`http_request_capture`'s header sink ACCUMULATES every redirect hop, so a whole-file match reads
  the WRONG response.**  A `grep '^strict-transport-security:'` over the capture finds the header the
  302 set and reports it as the delivered page's - backwards for the one header whose absence on the
  final response is the finding.  `hdr_parse_capture` resets on every `HTTP/x.y NNN` status line, so
  only the last block survives; removing that reset turns two assertions red, which is how it is
  known to be load-bearing rather than assumed.
- **This directory's script-check registry USED to be a single shared `checks.rules` and is now one
  `checks-<name>.rules` per owner** (`docs/FOUNDATION.md` tension 29; DAST-05's records live in
  `modules/dast/passive/checks-headers.rules`).  When DAST-05 landed, §9's path table gave the §9.5
  schema to "any file named `checks.rules`, at any depth" and made every other path `E070`, so this
  ticket's own attempt at a per-ticket `headers-checks.rules` was refused - note that SUFFIX spelling
  is *still* `E070` today; the row that was added legalises the `checks-` PREFIX only.  The
  append-only "resolve a conflict by keeping BOTH blocks" rule that followed from the shared file is
  retired for this directory, and still stands for `modules/dast/active/checks.rules` and
  `modules/dast/checks.rules`, which were not split.  The engine file is named
  `headers_engine.sh` for the opposite reason - a `passive_engine.sh` would be shared scaffolding
  three parallel tickets each believed they owned, so a peer that needs the same response reader
  should LIFT it deliberately rather than fork it.
  **That lift has since happened, and the reader now lives in
  `modules/dast/passive/response_engine.sh`** - see its own ADR block, and the "the shared response
  reader" bullet below.  `headers_engine.sh` keeps the CSP/HSTS/Referrer parsers and the
  recommended-header loader, and sources the reader like everyone else.  `hdr_endpoints_load` stayed
  behind under its own name too, but only as a thin wrapper - the endpoint CHOOSER it names has since
  lifted into `response_engine.sh` as well, alongside its three siblings; see the "the shared response
  reader" bullet's own correction below.
- **One finding per check per target, located deterministically.**  A header is configured once per
  application, so a per-endpoint emit reports one misconfiguration ten times.  Each check accumulates
  across the (capped, path-template-deduped) endpoint set and emits ONCE, at the first endpoint in a
  fixed order - the operator's own `base-url` first, then the inventory `LC_ALL=C`-sorted - with
  "observed on N of M responses" in the evidence.  The determinism is what stops the fingerprint
  churning when the crawl reorders.  Eleven check ids rather than one because the DAST location
  profile carries no component naming the DEFECT, so a missing CSP and a weak HSTS on one page would
  otherwise collide and dedupe to one finding.
- **Applicability is tracked per check and an INAPPLICABLE check is never in `checks_run`.**  HSTS is
  not evaluated at all on a plaintext response (RFC 6797 §7.2 has the browser ignore the header);
  CSP-absence and framing are document-only, while `nosniff` is not.  A run that saw only plaintext
  records `headers_check_not_applicable` naming the uncovered ids instead of reporting them tested.
- **A "configurable" knob did not have to be a `config/scanner.conf` key at landing time, and a
  follow-up ticket has since given it one anyway.**  DAST-05 shipped a vendored, auditable data file
  plus a documented environment seam (`SCOURSH_DAST_RECOMMENDED_HEADERS_FILE`), exactly as
  `SCOURSH_DAST_SQLI_PAYLOAD_DIR` does for payloads, because §9.6.1's key set was frozen and adding a
  key then would have widened a tier-2 ticket into a format change six peers then building in parallel
  would have had to rebase onto.  Once those peers had landed, "Give the DAST recommended-header
  roll-up a config/scanner.conf key" added the `recommended-header` key (repeatable, §9.6.1) as the
  now-primary source, with the vendored file and its environment seam kept as the fallback
  `hdr_load_recommended` (`modules/dast/passive/headers_engine.sh`) reaches for when the key is unset -
  see that function's own header for the exact precedence.

**DAST-10 (`modules/dast/passive/leakage.sh`) has landed - the third tier-2 check, and the first whose
whole design problem is FALSE POSITIVES rather than detection.**
It ships `leakage_engine.sh` (the pure half), `leakage.sh` (the phase script `dast_run_phase` sources),
five `DAST-LEAK-*` records in `modules/dast/passive/checks-leakage.rules` (appended to the
directory's then-shared `checks.rules`; tension 29 has since split that file), and
`tests/suites/dast-leakage.sh` (154 assertions, no network and no Docker, driven from recorded
head/body pairs replayed into `lib/http.sh`'s own two capture sinks).
Five families, five check ids - a stack trace or debugger page (CWE-209), an infrastructure-disclosing
response header (CWE-200), an email address outside a published contact link (CWE-200), a credential or
internal URL in served JavaScript (CWE-540), and the third-party origin inventory (CWE-829,
**informational**).
Five ids rather than one because `check_id` is a fingerprint component and the DAST location profile
carries no component naming the DEFECT, so two families firing on one path would collide on one
fingerprint and `findings_merge` would keep whichever won the sort.
Six things are worth carrying here.

- **Every one of the five families is defined by what it REFUSES to report, and each refusal is pinned
  by a negative fixture the naive reading flags.**  A stack trace needs a STRUCTURED FRAME - a source
  file plus a line number - never a framework name or the word "error", because otherwise every branded
  404 on the internet is a finding.  An infrastructure header needs its VALUE to name an unroutable
  address or a reserved-internal DNS suffix; the header NAME alone only selects a candidate, so
  `Via: 1.1 varnish` and a Fastly POP code `X-Served-By: cache-lhr7364-LHR` are NOT flagged - a dotless
  token is genuinely ambiguous between a product name, a POP code and an internal hostname, and
  flagging the shape would flag every CDN customer.  An email published as a `mailto:` link is
  deliberate and is subtracted wherever else it appears; so are RFC 2142 role aliases and a "domain"
  whose last label is a file extension (`logo@2x.png` in an `srcset` matches every naive email regex
  ever written).  A JS-config finding subtracts a public-by-design ALLOW-LIST first - a Stripe
  publishable key, a Google browser API key, an analytics id - because those are what a credential is
  designed to look like.  A third-party origin subtracts the response's own host and its registrable
  domain.
- **The suite asserts the DIFFERENCE, not the absence.**  For each family it runs the naive reading
  inline, asserts the naive reading DOES fire on the fixture, then asserts the shipped one does not,
  then asserts the shipped one still fires on a real positive.  A test that only said "no finding"
  would pass equally well against a check broken into silence.  Confirmed by measurement rather than
  by reasoning: eight deliberate mutations - the naive keyword trace match, the dotless-token internal
  host, the dropped `mailto:` subtraction, the dropped file-extension rejection, the dropped
  public-key allow-list, the dropped same-site subtraction, a truncating body reader, and a header
  reader that stops resetting per hop - each took the suite red (1 to 7 failures apiece).
- **A candidate secret's VALUE never reaches the finding.**  Family 4 reports the key name, a
  description of the matched shape and the value's LENGTH.  A finding that quotes the credential has
  copied it into the report, into the run's shard file and into the operator's scrollback -
  `rules/redaction.rules` would catch many of these on the way out, and not carrying the value is the
  control that does not depend on that list being complete.
- **A minified bundle is CHUNKED, never truncated at the line cap.**  A webpack bundle arrives as one
  900 KiB line; a line-cap read inspects its first 4 KiB and silently declares the other 99% clean,
  which is exactly the overstated coverage `docs/DESIGN.md` §15 forbids.  A token straddling a chunk
  boundary is the accepted cost, and it can only cause a MISS, which is this family's stated bias.
- **`leakage_engine.sh` SOURCES the shared response reader rather than copying it.**
  `hdr_parse_capture` resets on every status line because the capture sink accumulates every
  redirect hop, and a second implementation here would be re-earning that lesson and putting two copies
  of it in one directory.  It used to source `headers_engine.sh` for it, and the "lift into a shared
  `passive/response_engine.sh`" that file's own header asked for was filed as its own ticket rather
  than performed under parallel peers; **that ticket has since landed** - see "the shared response
  reader" bullet below.
- **Two emission grains, deliberately.**  A stack trace and a bundled credential are properties of ONE
  HANDLER, so they emit once per path and two leaking paths are two findings.  An internal proxy
  header, the address set and the third-party origin set are properties of the APPLICATION, so they
  accumulate and emit once with the affected/tested count - the same reasoning `passive/headers.sh`
  applies to all of its checks.  Every family no fetched response was applicable to is recorded as a
  `leakage_family_not_applicable` coverage_reduction and is kept OUT of `checks_run`, so a run that
  only ever fetched images never reads as having tested served JavaScript.
- **What DAST-10 deliberately did not build**: provoking an error to harvest its trace.  That raises
  this family's recall and it is active probing, out of scope for §7.1 and for this ticket.

**A pre-existing defect this ticket found and did NOT fix: `SCOURSH_DAST_ENDPOINTS` is EMPTY on every
first run.**
`modules/dast/run.sh` calls `dast_inventory_read` and exports the two inventory paths BEFORE the phase
loop starts, while `crawl.sh` writes `reports/<run>/inventory/{endpoints,parameters}.json` several
phases later in that same loop.  Any consumer that trusts the export alone therefore sees no surface on
exactly the run that has just discovered one - and
`modules/dast/active/inject_engine.sh`'s `inject_inventory_load` does trust it, which means
`active/sqli.sh` tests nothing on a standalone `scan.sh dast` run today.  `headers.sh` falls back to
`$SCOURSH_RUN_DIR/inventory/endpoints.json` for itself and pins the fallback with a test; the export is
`modules/dast/run.sh`'s to fix and is filed as its own ticket rather than changed under six peers.

**DAST-29 (`modules/dast/authz.sh`) has landed - the §7.4 object-level authorization (IDOR) and
excessive-data-exposure checks, and the first tier-5 phase whose script sits at the TOP LEVEL of
`modules/dast/`.**
It ships `authz_engine.sh` (the pure half: candidate extraction from DAST-04's frozen inventory, the
oracle, the field scan), `authz.sh` (the phase `dast_run_phase` sources), the new shared
`modules/dast/checks.rules` (four `DAST-AUTHZ-*` script checks, all `tags: active` and all
`requires-identities: 2`), and the vendored, operator-editable `modules/dast/sensitive-fields.txt`.
`tests/suites/dast-authz.sh` is the proof - 189 assertions, no network and no Docker, driven from a
scripted SERVER keyed on (path, identity) rather than a canned-status queue, because the correctness
of this check IS which identity is served which object and a queue lets a probe pass by asking for the
wrong thing in the right order.
Its section H is the six defects a QA pass found on the first landing; every one of them was observed
red against the shipped code and green after the fix, and five of the six were false or missing
COVERAGE records rather than wrong findings - which is this module's own most expensive failure class
and is where to look first when changing it.
Nine things about it will otherwise be rediscovered the expensive way; each was measured by writing
the wrong version and watching a named case go red, not reasoned about.

- **"Public" is DIGEST EQUALITY with an identity's own response, never the anonymous status code.**
  The anonymous control is required at all - without it every public object on the target is reported
  as a cross-user read - but reading a 2xx as "public" silences every real finding on any application
  that answers a logged-out request with a 200 login page, which is the overwhelmingly common shape.
  That failure reads as a CLEAN REPORT, which is the direction that ships. Case C4 goes red under it.
- **A shared object is TWO different check ids, and which one is decided by a refusal observed
  ELSEWHERE under the same path template.** `DAST-AUTHZ-IDOR-01` (high confidence) needs a witness
  that this endpoint enforces per-object ownership at all - one identity served a reference the other
  was refused; without one it is `DAST-AUTHZ-CROSS_IDENTITY_READ-01` (medium), an observation about a
  possibly-shared resource. One id is not an option: the DAST location profile carries nothing naming
  the defect, so the two would hash to one fingerprint and `findings_merge` would keep whichever
  sorted first. The whole group is therefore probed BEFORE anything is emitted, since the witness can
  arrive on the last reference. Cases C1 and C2 fail under the opposite readings.
- **Read-only is enforced at CANDIDATE SELECTION (`_authz_method_ok`), not at the call site.** A
  POST/PUT/PATCH/DELETE inventory entry never becomes a candidate, so no code path can reach a
  mutation even if a later edit forgets to check - and the guarantee is asserted over a REQUEST LOG,
  the only form of the claim a test can falsify.
- **HEAD is READ-ONLY AND STILL REFUSED, under its own counter, and folding it into the
  mutating-method count is the mistake.** RFC 7231 §4.3.2 gives a HEAD response no body, and every
  oracle here compares response BYTES, so a HEAD candidate spends two requests to reach a verdict that
  cannot exist. Worse, it reached one: an empty digest on both sides landed in the "bytes differed"
  arm, which the phase reports as "readable by BOTH identities but returned different bytes to each" -
  false for a HEAD - while the exposure pass's `-s` test reported the same zero-byte body as
  `response_too_large_to_field_scan cap=524288`. TWO factually wrong coverage records from one
  admission. `authz_body_is_empty` now exists precisely so "no body" and "too big" are never the same
  question; a 204 or an empty 200 on a GET hits the identical trap. Cases H2a-H2d.
- **A 401 is an AUTHORIZATION REFUSAL here, and `dast_auth_request` must not be used for the probes.**
  §7.0's transparent re-auth is right everywhere else - a 401 there means the session expired - and
  exactly inverted in a check that deliberately asks one identity for another's object. Routed
  through it, the first foreign reference answered 401 triggered a full re-login, the retry's 401
  marked that identity `failed` for the WHOLE RUN, and the probe returned 1 - so the enforcement
  witness was discarded, a real IDOR was downgraded to the medium-confidence observation, and every
  later DAST check needing that identity skipped. On any token API that refuses with 401 rather than
  403 that is a false clean result bought with a login storm, and it left the `401` arm of
  `authz_status_refused` documented but unreachable. `authz_probe_as` discriminates instead: an
  identity that has ALREADY received a 2xx this pass has a demonstrably live session, so its later 401
  is a refusal and costs no login; otherwise §7.0's refresh applies ONCE per identity per pass, and a
  retry that is 401 too is reported as a refusal WITHOUT marking the identity failed. Both halves are
  pinned (H6, H6b) because the naive fix for each is the other's bug - treating every 401 as a refusal
  makes an expired session read as an application enforcing authorization on every reference.
- **`loc_method` is the method that was requested, never a constant.** The DAST location profile is
  `target method path_template param_location param_name` and `authz_group_key` discriminates on the
  method too, so a hardcoded `GET` collapses two groups this pass deliberately kept apart onto ONE
  fingerprint and `findings_merge` drops whichever sorts second - the exact collision
  `modules/dast/checks.rules` says the four ids exist to prevent. It also made the field contradict
  the finding's own evidence prose, which interpolates the real method. H1 asserts it on the
  FINGERPRINTS, not on the field alone.
- **`checks_run` is written from the ids that EXECUTED, not from the passes that were entered.**
  `lib/records.sh` defines it expressly so a reader can tell "this check ran and found nothing" from
  "this check was never loaded", and `DAST-AUTHZ-OTHER_IDENTITY_DATA-01` defeated that: it was
  recorded as run on every authenticated run with an inventory, including the ones where it could not
  possibly run. `rules/RULE-FORMAT.md` §9.6.2 makes `username` optional and applicable only to
  `form`/`oauth2-password`/`srp`, so a `bearer`, `api-key`, `oauth2-client` or `external` identity -
  the dominant shape for the API targets this check is aimed at - supplies no identifier at all. The
  passes now append to `_AUTHZ_CHECKS_EXECUTED` and `_dast_authz_record_checks_run` writes a
  `check_not_executed` reduction for every id missing from it. H3.
- **A count in a coverage record must describe what was EXAMINED, not what exists.** An inventory
  entry is dropped for its method or its scope BEFORE its path is inspected, so on an inventory of
  forty POST endpoints "no entry carried an object-reference-shaped value" is simply false - they were
  never looked at. The `ncand == 0` reason now carries `skipped_method` / `skipped_head` /
  `skipped_scope` and says so, and `_dast_authz_record_skips` runs on BOTH branches, because the
  deliberate "object-level authorization on write endpoints was NOT assessed" gap used to be dropped
  on exactly the inventory where it was the only true thing to say. H4. In the same family: the
  exposure-endpoint cap used to `break` with no counter, the one bound in a file whose header promises
  "reaching one is never silent" (H5), and `_AUTHZ_REFS_TESTED` was incremented before the probes, so
  references that produced no usable request were reported as probed (H7).
- **What an object reference IS comes from `lib/findings.sh`'s `path_template_of`, and the suite
  asserts the two AGAINST EACH OTHER rather than restating the four shapes.** Disagreement in either
  direction is a real defect: probing a segment the fingerprint treats as a literal splits one
  endpoint's findings, and skipping one it collapses leaves the check with no candidates on an
  endpoint whose findings it would happily merge. A slug (`/users/jane`) is deliberately NOT a
  reference - admitting path words spends the request budget on `/about` - and that narrowing is a
  recorded gap, not a claim slug-keyed IDOR does not exist.
- **The exposure pass reads FIELD NAMES and never field VALUES, and the "other identity" needle is a
  pure-bash substring test rather than a `scan_match`.** The needle is an identifier out of
  `config/auth.conf`, a mode-600 credential file, and every engine this repository wraps takes its
  pattern on argv (tension 9 handling rule 1); bash function arguments are not argv. The needle is
  never echoed into a finding either - the evidence names the identity LABEL. Both are pinned by
  asserting the planted value appears NOWHERE in the shard, which is meaningful because the shard
  escapes only backslash, tab, CR and LF, so a copied plain value really would be visible.
- **Every skip path returns 0 with a RECORDED reason - the ticket's own "skip cleanly and say why, not
  fail".** No `--authed`, one authenticated identity where two are configured, no inventory, an
  unreadable field list: each records a `coverage_reduction` plus a human-readable `coverage_gap`, and
  the suite asserts the exit status AND the reason for each, because silence here reads as "this
  application enforces object-level authorization", the single most expensive way for this check to be
  wrong.

**One testing lesson from this ticket that is not specific to it: never assert a check id against raw
shard text.**
A finding carries its own remediation prose, and `DAST-AUTHZ-CROSS_IDENTITY_READ-01`'s deliberately
NAMES `DAST-AUTHZ-IDOR-01` in it ("unlike DAST-AUTHZ-IDOR-01, it saw no evidence ...") so a reader
knows which of the two they are holding.
A substring test over the shard therefore finds the confirmed id on a run that emitted only the
observation: `assert_not_contains` fails on correct behaviour, and - the expensive half -
`assert_contains ... IDOR` would PASS on the rejected "always emit the confirmed id" implementation.
`tests/suites/dast-authz.sh`'s `_shard_check_ids` decodes through `lib/findings.sh`'s own
`finding_decode` for that reason; any suite asserting on ids should do the same.

**DAST-30 (`modules/dast/passive/transport.sh`) has landed - a §7.4 TIER-5 check that RUNS AT TIER
`passive` and lives in `modules/dast/passive/`, which is the one thing about it most worth knowing.**
It ships `transport_engine.sh` (the pure half: the sub-resource extractor, reference resolution, the
endpoint chooser, the sensitivity scan and the redirect verdict), `transport.sh` (the phase script),
and five `DAST-TRANSPORT-*` checks in `modules/dast/passive/checks-transport.rules` (appended to the
directory's then-shared `checks.rules`; tension 29 has since split that file),
alongside the blocks DAST-06, DAST-05, DAST-10 and DAST-11 each appended to the same file.
`tests/suites/dast-transport.sh` is the proof
(109 assertions, no network, no Docker, driven from recorded response heads AND bodies).
`docs/STEP5-DAST-PLAN.md`'s own DAST-30 landing note is the authority for the detail; five things are
worth carrying here.

- **The phase table row MOVED, from `transport.sh:active` to `passive/transport.sh:passive`, and this
  is the first exercise of the mechanism `modules/dast/engine.sh`'s phase table always specified for
  it** ("a later ticket whose checks legitimately carry a LOWER type tag than the tier its row
  declares here must change that row in the same change and say why").  DAST-02 transcribed every
  tier-5 row from `docs/DESIGN.md` §7.4's section HEADING, which is right for its other four scripts
  and wrong for this one: nothing here mutates target state, §7.4's own wording for this bullet calls
  it a complement to "the TLS **passive** check", and at `active` it would never run at all, because
  `--intensity` defaults to `passive` and anything above it additionally requires `--i-own-target`.
  A row left at `active` is not a conservative choice - it is a check that is dead code on every
  ordinary run.  `tests/suites/dast.sh`'s phase-table coverage list names `passive/transport.sh` and
  moved in the same change.
- **A plaintext `<a href>` is NOT mixed content, and the naive reading is a flood rather than a
  miss.**  A hyperlink loads nothing into the secure document.  Matching `http://` anywhere in the
  body fires on every external link on every page, so a plaintext footer link outranks a login bundle
  fetched over port 80.  The extractor emits `nav` references ANYWAY, so the suite can assert their
  absence from the findings - a class that is never emitted cannot be tested for - and the run
  records a `notes` count so an operator who sees the link in their own markup knows the phase
  decided rather than missed.
- **The plaintext URL is requested with `max_redirects` 0, and without that the redirect check cannot
  exist.**  `http_request` follows redirects internally and reports the FINAL status, so a correct
  301-to-HTTPS and a page served on port 80 both come back `200`.  Two neighbours fail the same way
  under the obvious "is it a 3xx" test: a 301 to another `http://` URL does not leave plaintext, and a
  scheme-relative `Location` is resolved by the browser against the CURRENT scheme.
- **`crawl_html_extract` is deliberately NOT reused, and `hdr_endpoints_load`'s dedup key deliberately
  IS NOT borrowed.**  The former skips `<script>`/`<style>` wholesale and emits nothing for `<img>`,
  because it inventories NAVIGABLE endpoints - the archetypal mixed-content references are invisible
  to it by design, and widening it would change a frozen inventory contract six tickets read.  The
  latter dedupes by path template alone, which collapses `http://h/login` and `https://h/login` into
  one candidate and so drops the plaintext twin that IS the finding; this phase keys on
  (scheme, path template).  Everything else about the chooser is kept in step with it rather than
  re-argued.  The response READER is reused unforked (`hdr_parse_capture` and friends), because its
  reset-on-every-status-line is the most dangerous parse in the tier and two copies is two chances to
  lose it; the shared-file lift `headers_engine.sh` asked for was DAST-05's follow-up and **has since
  landed** as `modules/dast/passive/response_engine.sh`, which this file now names directly.
- **A test that passes under both the correct and the rejected reading was found here by MUTATION,
  not by review, and it is worth knowing which one.**  "A protocol-relative reference produces no
  finding" pins nothing: it passes both when the reference is properly resolved AND when anything
  without its own scheme is simply skipped, because only an absolute `http://` reference can be mixed
  content on an https page at all.  What discriminates is the ACCOUNTING - `_TR_REF_TOTAL`,
  "references this check could judge" - which under the skip silently becomes "references that
  happened to be written absolutely".  Every decision in this family was re-checked by breaking the
  implementation and watching the suite go red; three of the five needed no change and one assertion
  had to be reworded because it claimed a discrimination it did not have.

**What DAST-30 deliberately did not build**: any TLS inspection (DAST-07 owns the connection, the
certificate and the cipher suite; this family opens no connection of its own), any HSTS check
(`DAST-HDR-HSTS_*` is DAST-05's, and `NO_HTTPS_REDIRECT`'s remediation names it as the companion
control rather than restating it), and any cookie-attribute check (`DAST-COOKIE-NO_SECURE-01` is
DAST-06's; this family records only that a cookie was ALREADY sent in the clear).  It also REQUESTS no
sub-resource: a discovered `http://` script URL is classified from the markup and never fetched, so an
out-of-scope reference is still reported - a third-party CDN over plaintext is the commonest real
mixed-content case and is out of scope by definition, so dropping it would be a false negative on
exactly the case that matters most.
**DAST-08 (`modules/dast/passive/cors.sh` plus `cors_engine.sh`) is tier 2's fifth check.**  Its own
commit message describes creating `modules/dast/passive/` and a shared, appended-to `checks.rules` -
true when the ticket was originally written, but DAST-06 reached `dev` first and already created the
directory (see DAST-05's paragraph above), and tension 29's split (also above) already replaced the
shared file by the time this ticket actually landed, so its three CORS check ids were seeded directly
into `modules/dast/passive/checks-cors.rules` rather than into a shared file that no longer exists.
`docs/STEP5-DAST-PLAN.md`'s DAST-08 landing note is the authority for the detail; three things about it
bind every OTHER tier-2 ticket and so belong here rather than only there.

- **`dast_check_selected` DOES NOT EXIST, in any file.**  `modules/dast/active/sqli.sh` calls it behind
  a `declare -F dast_check_selected >/dev/null` guard and `modules/dast/passive/cors.sh` now does the
  same, so both are inert: tension 15's per-check selection has never bound a DAST check, and
  `--profile-scan`/`--intensity` narrowing does not reach the module's script checks today (the
  PHASE-level intensity gate in `dast_run_phase` is a separate, working mechanism and is not affected).
  Keep the guard rather than writing a local copy; the function belongs in `modules/dast/engine.sh`,
  which is exactly the file a parallel tier-2 ticket is most likely to be editing.  It is filed as its
  own ticket.
- **A §7.1 check that sends a request is still passive, and the contract is "no mutation of state", not
  "no traffic".**  `cors.sh` is the worked example: only GET/HEAD endpoints from the inventory are
  requested, one request per distinct route, no request body, no response-body capture sink, no
  redirect followed, and everything through `http_request`.  Assert those against a REQUEST LOG rather
  than a return value - `tests/suites/dast-cors.sh` section D is the pattern, and it is what catches a
  probe that quietly starts requesting a POST route.
- **A response-header read is case-INSENSITIVE on the field name, and that is a coverage control
  rather than a nicety - it binds DAST-05 and DAST-06 as much as this ticket.**  RFC 7230 §3.2 makes
  field names case-insensitive and HTTP/2 (RFC 7540 §8.1.2) REQUIRES them lowercase on the wire, so a
  target behind any HTTP/2 edge answers `access-control-allow-origin:` and a matcher spelling the RFC
  6454 form byte-for-byte reports every one of them clean - a silent false negative on the most common
  production deployment shape, indistinguishable from a genuinely absent header.  `cors_header_last`
  passes `-i` through `scan_match` (never a bare grep, tension 4); both bound engines accept it
  identically (`grep -E -i`, `rg -i`), the same way `scan_match_offsets` already passes `-b -o`.
  DAST-08's first draft documented the property in a comment and omitted the flag from the pattern,
  and only `tests/suites/dast-cors.sh`'s lowercase fixtures - one at the reader level, one end to end -
  caught it; a suite that recorded only RFC-spelled fixtures would have certified it green.
- **A scratch file in a DAST phase is created with `mktemp`, never with a name built from `$BASHPID`.**
  Every one of these paths is spelled `${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/...`, and that fallback is
  reached by every standalone-engine caller - including this repository's own suites - so a pid-derived
  name is one a local user can predict and pre-create as a symlink that the process then writes
  *through*: `scan_match` truncates whatever it points at, and a response-header capture sink deposits
  the target's own headers wherever someone else chose (CWE-377 via CWE-59). `lib/http.sh`'s
  `_http_transport_default` already had the right idiom (`mktemp ... XXXXXX` plus `chmod 600`); DAST-08
  shipped the wrong one in both of `cors_engine.sh`'s scratch paths and corrected it in the same
  ticket. `tests/suites/dast-cors.sh` section A2 pins it by PLANTING the pre-fix name as a symlink over
  a canary and asserting the canary survives - and note that its `_plant_symlink` helper **sets** a
  variable rather than printing one, because a `VICTIM=$(_plant_symlink ...)` runs in a subshell with
  its own `$BASHPID` and so plants a name the code under test never computes; that first draft passed
  against the vulnerable spelling, which is the failure mode this file's own testing rule exists to
  catch.

**DAST-09 (`modules/dast/passive/banner.sh`) has also landed - a §7.1 passive check, and the ticket
that creates `docs/VERSIONS-DB.md`.**
`modules/dast/passive/` already existed by the time it landed (DAST-06 created it first, per above),
and it lands after the tension-29 split above is already in effect for its peers, so its three check
ids are seeded directly into their own `modules/dast/passive/checks-banner.rules` rather than a shared
`checks.rules` - the same convention DAST-08's `checks-cors.rules` already follows, never the retired
shared file `tests/suites/dast.sh` asserts is gone.
The split is `modules/sast/`'s, one level down and identical to `auth.sh`/`crawl.sh`:
`passive/banner_engine.sh` is the pure half (header/meta/bundle extraction, product-key normalisation,
the `data/versions.db` lookup - no socket, no host named anywhere in it) and `passive/banner.sh` is the
phase script `dast_run_phase` sources.
Five things about it are worth carrying here, because a later ticket will otherwise rediscover them the
expensive way:

- **`docs/VERSIONS-DB.md` is the normative format for `data/versions.db`, and the file carries TWO
  namespaces in one table.** Field 1 is an SCA ecosystem (`npm`, `pypi`, ...) for the rows
  `tools/vendor-engines.sh advisories` writes, and the literal `banner` for the rows this check reads.
  They coexist by construction rather than by luck: that writer replaces only the rows whose first field
  equals the ecosystem it is writing, and `banner` sorts before every ecosystem name under `LC_ALL=C`,
  so neither namespace can disturb the other's rows or the sort `db_lookup_exact` depends on. There is
  no importer for the `banner` namespace yet; §5 of that document is the hand procedure, and it exists
  because a list nobody can refresh becomes wrong quietly.
- **The scanner does an exact table lookup and NOTHING else.** There is deliberately no "1.18.0 looks
  older than 1.27.0" heuristic: that is version-range arithmetic, which tension 25 moved off the scanner
  onto the networked box that has each ecosystem's real tooling. Do not add one here.
- **A missing or `banner`-less list degrades ONE sub-check, never the phase.** `versions_db_absent` and
  `versions_db_no_banner_rows` are distinct recorded reasons (a fresh clone is the second), the two
  disclosure checks still run, and a discovered product with no row of any version is counted into one
  `versions_db_product_unknown` roll-up - so "the list has never heard of this component" can never
  render as "this component is fine". The out-of-date finding also carries the list's own `# generated:`
  stamp, because a stale list produces false NEGATIVES, which is the failure mode that hides.
- **Identity: the version is part of the finding's key for `OUTDATED_COMPONENT` and NOT for the two
  disclosure checks**, and the asymmetry is the point. "This endpoint discloses its jQuery version"
  survives an upgrade and must keep one identity; "this endpoint runs jQuery 3.4.1, which the list
  names" is a claim about 3.4.1 and must go `fixed` when it changes. Three check ids rather than one for
  the same reason the three SQLi techniques have three: the DAST location profile carries no "kind"
  component, so one id would collide a name-only disclosure with a known-vulnerable-version hit on the
  same endpoint and `findings_merge` would silently keep one.
- **Passive means passive.** One plain GET per endpoint the DAST-04 inventory already recorded, GET/HEAD
  only (a POST endpoint is counted and skipped, and the skip is reported), no crawling, no invented URL,
  and every request through `http_request` - so the limiter, budget, breaker and DAST-32 ceilings all
  bind it. `tests/suites/dast-banner.sh` (69 assertions) drives the whole thing from recorded responses
  with a stubbed transport and asserts on the REQUEST LOG, so "it did not dial the POST endpoint" is
  measured rather than asserted.

**This block used to read "no DAST-0x ticket is picked up until step 3's outstanding rule packs and
step 4's SCA half are both complete on `dev`"; BOTH halves of that gate are now discharged, so it is
gone rather than narrowed.**
The generated block above reports SCA at 6 of 6 ecosystems and SAST at 10 of 10 artifacts, each with
none outstanding, and it remains the live answer if this paragraph is ever in doubt: `nosql.rules`
(4 checks) and `ldap.rules` (3 checks) - the last item the gate was waiting on - are landed and
exercised by `tests/suites/sast.sh`, which reports 130 passed, 0 failed.
**The gate is recorded here rather than deleted because its reasoning held rather than evaporated: it
was a SEQUENCING preference inherited from `docs/DESIGN.md` §13's build order, never a technical
dependency, and it was discharged by the work landing rather than by being argued away.**
No DAST ticket consumes a SAST rule pack, and DAST-01 - the tension-16 rate limiter with its per-run
request budget and circuit breaker - touches `lib/http.sh` only, on top of `lib/core.sh`'s mkdir-mutex
and scratch-dir primitives that shipped at step 1, so step 5 is startable now with nothing in front of
it.
**One ordering constraint was internal to step 5 rather than a gate on starting it - DAST-01 must land
before anything issues real HTTP traffic - and it has been satisfied.**
Until the limiter and the budget are hooked into `http_request`, `--jobs` multiplies the request rate
against a live endpoint with no throttle at all - tension 16's own per-process-state failure, the same
one that leaves the breaker unable to trip - which is why DAST-01 heads the plan's tier 0, and that
tier blocks all of tiers 1 to 5.
DAST-01 landed first and the rest of tier 0 landed on top of it, so no ticket has yet issued a request
before the controls that bound it existed.
**A local, authorized DAST test target has already landed, ahead of DAST-01.**
`tools/dast-test-target.sh` and `tools/dast-test-identities.sh` start a pinned, self-hosted OWASP Juice
Shop container and provision two distinct throwaway identities in it, authorized by
`tools/dast-test-target/scope.conf` and `docs/DAST-TEST-TARGET-AUTHORIZATION.md`'s written record, with
`tests/e2e/dast-target-smoke.sh` as an opt-in (Docker- and network-requiring, so not in
`tests/run-tests.sh`'s default list) end-to-end proof that the target is reachable, that `lib/http.sh`'s
scope gate really does refuse everything else, and that the two identities' basket-IDOR case is real.
**That smoke test has now been observed passing end to end for the first time: 19 of 19 assertions, 0
failures, against a live local Juice Shop container.**
The target served; the scope gate admitted the authorized target and refused both a different port on
the same host (`DTT_PORT + 1`) and an unrelated host; `http_request` exited 3 (`SCOURSH_EXIT_SCOPE`)
against an unauthorized host; and the two provisioned identities produced a real cross-user
broken-access-control case for DAST-29 (`authz.sh`) to assert against once it exists.
Until that run this tooling had been reviewed as code but never watched working, which is a weaker
grade of evidence - do not write it back down to one.
Target *acquisition* was the blocker that ticket closed, not step 3 or step 4 completion - but it means
DAST-01 onward already has something to build and test against, and does not need to plan or authorize
a target of its own.
See `docs/STEP5-DAST-PLAN.md`'s own section on this for the two conventions worth knowing before
building against it.

**DAST-35 (the "no bundled scan target" lint) has also landed, ahead of DAST-01 - it has no dependency
on anything in this plan and its own row says "can land immediately".**
Three checks now live in `tests/lint-shell.sh`, in the same one-exemption-with-a-stated-reason shape
the file's own tension-19 "no bypass" check already uses: `config/` ships `scope.conf.example` only,
never a real `scope.conf`; `scope.conf.example`'s own `base-url` names an RFC 2606/6761 reserved
example domain; and no shipped script, rule or config file anywhere in the tree carries a
`base-url`/`extra-host` record naming anything other than a reserved example domain or a
reserved/non-routable IP literal - `tools/dast-test-target/scope.conf` is exempt **by path**, not by
pattern, exactly as `docs/DAST-TEST-TARGET-AUTHORIZATION.md` already authorizes.  Landing this needed
one small, additive change to `tests/lint-shell.sh` itself, which every other check in the file now
also benefits from: an optional first argument, `SCAN_ROOT` (default `$ROOT`), the same convention
`tests/lint-aws-readonly.sh` already established, so the lint can run against a disposable fixture tree
instead of the real repository.  `tests/suites/dast35-lint.sh` is the meta-test - both directions for
each of the three checks, plus the path exemption proven both ways (the authorized file passes at its
real path; a byte-identical copy at any other path fails) - and `tests/run-tests.sh`'s `SUITES` array
now names it.  See `docs/STEP5-DAST-PLAN.md`'s DAST-35 row and the landing note just below it for the
full detail, including the one deliberate asymmetry worth knowing: loopback (`127.0.0.0/8`, `::1`) is
NOT in the generic "safe" IP set that private/link-local/CGN/TEST-NET literals sit in, because unlike
those, a bare loopback address means "whatever this operator's own machine happens to be running" for
every installation - it is allowed only via the one authorized file's path exemption.

**Step 8 (`--paranoid` / `tools/run-in-netns.sh`) is half landed: NETNS-01 has shipped; PARANOID-01 has
not.**
`docs/STEP8-PARANOID-PLAN.md` splits `docs/DESIGN.md` §13 step 8 into **PARANOID-01** (the `--paranoid`
connection-observer and abort-on-out-of-scope enforcement, per `docs/FOUNDATION.md` tension 20's
RESOLUTION) and **NETNS-01** (`tools/run-in-netns.sh`, the network-namespace runner - optional and
root-requiring, stated directly in that ticket's own filed description, not only in the plan doc).
**NETNS-01 has now landed**: `tools/run-in-netns.sh` (a Linux-only, root/CAP_NET_ADMIN
+CAP_SYS_ADMIN-requiring wrapper) builds a network namespace whose route table admits only two sets of
IPv4 addresses - the resolved addresses of scoursh's in-scope targets, via `lib/http.sh`'s own
`http_scope_load`/`http_resolve_host` (tension 19's pinned resolution cache, never a re-implementation),
and the nameservers parsed from `/etc/resolv.conf` (tension 20's "set 3") - installs NO default route
inside the namespace, and execs the wrapped command inside it via `ip netns exec`. Teardown (namespace,
veth, NAT/iptables rules, `ip_forward` restoration) runs from the tool's own EXIT trap on every exit
path, success or failure, staying inside the project's 0-5 exit-code contract throughout. It is never
invoked by `scan.sh` and has no dependency on PARANOID-01 - the two are independent, peer mechanisms per
tension 20's "guarantee vs detector" distinction. `tests/suites/netns.sh` tests it: argument parsing,
the CapEff bitmask arithmetic, the target-IP/nameserver collectors, and the build/teardown command
sequence are unit-tested against stubbed `ip`/`iptables`/`sysctl` on any host; the "fails immediately, no
isolation action, `<command>` never runs" non-Linux/no-privilege paths (this ticket's ACs 3-4) are
exercised as real subprocess invocations on whichever host the suite runs on; and a real, kernel-level
out-of-scope-connection-fails test (this ticket's AC2) is gated behind a genuine Linux+root/capability+
tooling probe and is honestly marked SKIPPED (not a silent pass) on a host that does not meet it.
IPv6 routing is out of scope for this tool (an in-scope host that only resolves to IPv6 is logged and
skipped, never routed) - a follow-up ticket for dual-stack support was filed separately, per this
ticket's own out-of-scope list.
**PARANOID-01 (the `--paranoid` observer/abort mechanism) remains unimplemented.**
Unlike the DAST plan above, step 8 was never gated on any unlanded step: this planning ticket's own
acceptance criteria named `lib/http.sh` (the tension-19 chokepoint) as step 8's blocker, and it was
confirmed present on `dev` before either sub-ticket started - it shipped early, out of its normal step-5
sequence, exactly as noted below. PARANOID-01 may still be picked up independently at any time; it does
not depend on NETNS-01 having landed, or vice versa.

**Step 6 (Cloud/AWS) now also has a written, dependency-ordered sub-ticket plan, but is not started.**
`docs/STEP6-CLOUD-PLAN.md` breaks the `docs/DESIGN.md` §13 step 6 scope (`regions.sh` iteration -> the
§8.1 live read-only catalog -> the read-only-verb CI lint -> `posture/` checks) into tickets CLOUD-01
through CLOUD-34 plus POSTURE-01 through POSTURE-04, and states plainly that `tests/lint-aws-readonly.sh`
(tension 23's read-only lint) already shipped at step 1 as a no-op stub that passes over an empty set -
it is not re-planned as new matching logic, only the still-missing `lib/awscli.sh` chokepoint it lints
against, the exception-file seeding, and the negative-fixture test are (CLOUD-03). It also records that
the one IaC ticket already landed on `origin/dev` (`modules/iac/`, "IaC: Terraform checks via the
pattern-rule engine") is step 4's `docs/DESIGN.md` §8.2 work, not step 6's, and is out of this plan's
scope for that reason. Step 6 was gated on step 5 (DAST) completing - `dev` is the live integration
branch and `main` lags it (see "`main` lags `dev`" below), so gating on `main`'s own tip would read
work that has already landed as still outstanding - and step 5 has since landed in full (see "Current
position" above), so that gate is discharged; step 6 remains not started only because no CLOUD-0x or
POSTURE-0x ticket has been picked up yet, not because it is still blocked.

**PARANOID-01 has now landed - `lib/paranoid.sh` implements `--paranoid` for real.**
It builds the four-set allowlist tension 20's RESOLUTION specifies (`paranoid_allowlist_build`).
It attaches a connection sampler (`paranoid_probe_backend`), aborts the run with exit `3`
(`SCOURSH_EXIT_SCOPE`) on the first observed destination outside that allowlist, and exits `4`
(`SCOURSH_EXIT_INPUT`) when no backend is available or permitted.
It is wired into `scan.sh`'s `scan_main` right after config loads and before any module dispatch.
`tests/suites/paranoid.sh` is the deterministic no-egress fixture tension 20 calls for.
`SCOURSH_PARANOID_FORCE_BACKEND`/`SCOURSH_PARANOID_SAMPLE` stand in for the backend probe and the
sampler itself (the same swappable-hook idiom `lib/http.sh`'s `SCOURSH_HTTP_RESOLVE`/
`SCOURSH_HTTP_TRANSPORT` already use), so the suite never depends on a backend actually being
installed.

**There are THREE backends, not two, and `lsof` is the one that makes `--paranoid` work on macOS.**
`paranoid_probe_backend` tries `ss`, then a measured-usable `strace -f -e trace=connect`, then a
measured-usable `lsof`, and only then gives up with exit 4.
Do not reorder that list casually: `strace` is a TRACER (it sees a `connect()` that opens and closes
between two polls) while `ss` and `lsof` are SAMPLERS, so `lsof` is APPENDED rather than inserted -
which also means no host that resolved to a backend before resolves to a different one now.
`lsof` was chosen over macOS's other candidates for measured reasons - `netstat` has no per-process
filter there, `nettop`'s per-connection rows carry no pid, and `dtruss` needs SIP disabled, which a
security tool must never ask for - and the full reasoning is in `docs/FOUNDATION.md` tension 20's
"Backend roster" paragraph, which records the extension deliberately rather than diverging from the
RESOLUTION in silence.
**None of this changes the framing**: `lsof` is a sampler with exactly `ss`'s blind spot, and
`tools/run-in-netns.sh` - the actual guarantee - is Linux-only with **no macOS equivalent**, so a
macOS run has the detector and nothing behind it.

**Two things measured while building that backend, both easy to hit again:**

- **`exec` with redirections and no command makes those redirections PERMANENT.**
  `exec {pfd}<>/dev/udp/127.0.0.1/9 2>/dev/null` - the natural spelling of the probe's positive
  control - silenced the whole run's stderr, so every log line including the violation message
  vanished while the exit code stayed correct: a detector that looked like it worked and had gone
  mute.  Wrap it: `if ! { exec {pfd}<>...; } 2>/dev/null`.  Pinned by a test that fails under the
  original spelling.
- **A `--paranoid` end-to-end test must fork its connection holder in the same shell that runs
  `scan_main`**, because `paranoid_attach` takes `$BASHPID` of that process as the family root.  A
  holder forked inside a nested subshell is not a descendant of it, and the test then passes for the
  wrong reason - nothing observed, so no abort.  `tests/suites/paranoid.sh`'s "REAL lsof" section is
  the worked example, and it stays a no-egress test by using *connected UDP* sockets: `connect(2)` on
  a UDP socket only records a default peer, so an RFC 5737 destination is observable without a packet
  leaving the machine.
One correction surfaced while building this ticket, recorded in full in `docs/FOUNDATION.md` tension
20's own "Implementation" paragraph: the observer and the abort's kill action are scoped to the
DESCENDANT-PROCESS FAMILY rooted at the main `scan.sh` pid, not the raw OS process group tension 20's
prose names.
A plain `cmd &` never changes pgid, so scoping to the real process group would have let a violation's
`kill -TERM` reach unrelated processes sharing that group by accident - measured directly: it took out
this project's own test harness before the fix.
`tools/run-in-netns.sh` (NETNS-01) is **not** implemented by this ticket, exactly as
`docs/STEP8-PARANOID-PLAN.md` scoped it - it remains a separate, independently-schedulable,
root-requiring ticket.

**Step 9 (optional engine adapters) now has a real scaffold, out of its normal sequence and ahead of
step 3's then-remaining `nosql`/`ldap` packs, step 5 (DAST), and step 6 (Cloud) - it shipped no
per-engine logic and cost nothing those blocked steps.**
`docs/ADAPTERS.md` is the new normative, self-contained convention document (the same role
`rules/RULE-FORMAT.md` plays for records): it defines the `modules/<module>/adapters/<engine>/`
directory shape and the three-function `adapter.sh` contract (`<engine>_detect`/`<engine>_run`/
`<engine>_normalize`), generalizing `docs/DESIGN.md` §3/§6.4's SAST-only `adapters/` diagram to any
module - `docs/FOUNDATION.md` Tension 27 records that generalization as a deliberate extension, not a
correction, since DESIGN.md is preserved verbatim and is never edited to match it. It points at
`rules/RULE-FORMAT.md` §9.1.1a for the check-id convention (`<engine>:<engine's own rule id>`) rather
than inventing a second one.
`tools/vendor-engines.sh` now exists as a real, runnable script - `docs/DESIGN.md` §9/§13 step 9's "only
script permitted to reach the network" - with a genuinely empty engine registry (`VENG_REGISTRY`):
`--help`, `--list`, `--all`, and vendoring a named engine all work today, and every one of those paths
is exercised as a real subprocess in `tests/suites/vendor-engines.sh`, run with `curl`/`wget` absent
from `PATH` so an accidental fetch attempt fails loudly rather than silently reaching the network. It is
never called during a scan; `tests/lint-shell.sh` gained two checks enforcing that in both directions -
`tools/vendor-engines.sh` is now exempted (alongside `lib/http.sh`) from the tension-19 "no bare
curl/wget" check, and a new tension-27 check fails the build if anything under `lib/`, `modules/`, or
`scan.sh` sources, execs, or evals `tools/vendor-engines.sh` by name.
**What this ticket deliberately did not build**, so the boundary is not rediscovered: `lib/engines.sh`
and `has_engine()` (named in `docs/DESIGN.md`'s directory layout but not step 9's - the first concrete
adapter ticket builds them together with its own adapter, mirroring how `--paranoid`'s flag landed with
its first real enforcement), the `--use-engines` flag, and `tools/vendor-engines.sh`'s *second*,
unrelated responsibility that `docs/FOUNDATION.md` tension 25 already committed it to - regenerating
`data/advisories.db`/`data/versions.db` from each SCA ecosystem's real tooling. That responsibility is
real and already designed, but it is SCA work, not an engine adapter, and this ticket's own acceptance
criteria scoped it out ("adds no per-engine logic itself, only the scaffold"). Zero adapter directories
exist anywhere in the tree; the full suite (`tests/run-tests.sh`) passes with none present, which is
the concrete proof that no adapter is required for `scoursh` to run, not merely an assertion.

**This ticket is the first concrete adapter ticket the scaffold above anticipated, and it closes every
gap that paragraph named as deliberately unbuilt.**
It ships `lib/engines.sh` (`has_engine MODULE ENGINE`, memoised per pair, a pure filesystem question -
"would this engine's own `<engine>_detect` return 0 right now" - that deliberately never reads
`--use-engines` itself; docs/ADAPTERS.md §5's own pseudocode keeps "is it vendored" and "was
`--use-engines` given" independent, ANDed together only at the calling module's own call site) and wires
the `--use-engines` global flag through `scan.sh` (`_SCAN_FLAG_KIND`, usage text, and one
`run_record use_engines <bool>` per run for audit) - `lib/checks.sh` itself gained no new filtering logic,
only a header paragraph stating explicitly why not: an adapter check id (`<engine>:<engine's own rule
id>`) is minted at runtime, never declared in a `*.rules` file, so `checks_registry_load` has nothing of
its own to select or drop, exactly as `docs/ADAPTERS.md` §6 already froze.
It ships `modules/sast/adapters/semgrep/adapter.sh` (the three-function contract: `semgrep_detect` is a
pure filesystem check for an executable `bin/semgrep` plus a non-empty `rules/`; `semgrep_run` invokes it
with `--offline --metrics=off` - and `SEMGREP_SEND_METRICS=off` as a belt-and-suspenders second control,
since an egress-restricted scanner cannot rely on a vendored third-party binary's own default being safe;
`semgrep_normalize` parses semgrep's own JSON with a purpose-built, depth- and string-aware `awk`
splitter plus bash-native field extractors - never a general JSON parser, the same pragmatic,
stated-scope choice `modules/sca/engine.sh`'s `_sca_json_walk` already makes for lockfiles) and
`modules/sast/adapters/semgrep/vendor.sh` (the sole file, besides `tools/vendor-engines.sh` itself,
permitted to touch the network - and it does not either: it calls only `veng_fetch`, the new function
`tools/vendor-engines.sh` now exports, which downloads and then verifies a caller-supplied sha256, never
a hardcoded or guessed one - hardcoding an unverified checksum here would be the exact `AGENTS.md`
"invented fact" mistake this file's own history section already warns about, applied to integrity
verification instead of a commit sha). `tools/vendor-engines.sh`'s `VENG_REGISTRY` now carries exactly
one entry, `[semgrep]=veng_vendor_semgrep`, which requires five operator-supplied
`SCOURSH_SEMGREP_*` environment values (version, binary URL + sha256, ruleset URL + sha256) and refuses
- never guesses - when any are missing.
A normalised finding is validated against the scan root before it is ever trusted (`path` traversal
outside the scan root is rejected with its own `coverage_reduction` reason, never silently accepted) and
its match text is re-derived from the real file at the reported line when that still resolves, falling
back to semgrep's own reported snippet only when it does not - `docs/FOUNDATION.md` tension 5/11's
"re-derive match_digest ... from the file at the adapter's reported path and line" requirement, made
concrete.
Absent or un-vendored is a clean, logged `coverage_reduction reason=engine_not_vendored engine=semgrep`
with the run otherwise unaffected; without `--use-engines` at all, a run behaves byte-for-byte as it did
before this ticket - not even a `coverage_reduction` mentions the engine.
`tests/suites/engines.sh` (fake, purpose-built adapters, independent of semgrep specifically) and
`tests/suites/sast-semgrep.sh` (the three-function contract, the path-traversal guard, graceful
degradation as a real `scan.sh sast` subprocess, and a full round-trip through every report format
against a FAKE vendored "semgrep" - a tiny stand-in script, since zero real engines are vendored anywhere
in this repository per `docs/ADAPTERS.md` §1) both exist and pass; `tests/suites/vendor-engines.sh`
gained a fetch/verify section (stubbed `curl`, never a real network call) proving `veng_fetch`'s
checksum-match, checksum-mismatch, and download-failure paths, plus `semgrep_vendor`'s own
required-env-var gate and full success path against a scratch copy of the adapter directory - never the
real one, so no test ever writes a fake "binary" into this repository's own working tree.
`docs/ADAPTERS.md` §9's roster table now names this one row; every other module/engine cell remains
"none shipped" exactly as before (the gitleaks ticket, immediately below, adds the second row).

**A second concrete adapter has now landed on top of the first: `modules/sast/adapters/gitleaks/`
(§13 step 9), built entirely on the plumbing the semgrep ticket shipped above - `lib/engines.sh`'s
`has_engine`, the `--use-engines` flag - rather than duplicating any of it.**
It ships `modules/sast/adapters/gitleaks/adapter.sh` (the three-function contract: `gitleaks_detect` is
a pure filesystem check for an executable `bin/gitleaks` plus a `rules/gitleaks.toml` file;
`gitleaks_run` invokes it with `detect --no-banner --no-git --exit-code 0 --source <target> --config
<vendored gitleaks.toml> --report-format json --report-path <file>` per `docs/DESIGN.md` §6.4's own
"gitleaks --no-banner" - `--no-git` because this adapter scans the WORKING TREE, leaving git-history
secret scanning to `modules/sast/history.sh`'s own, already-shipped `SAST-HIST-*` mechanism (§13 step
3e), and `--exit-code 0` because gitleaks' own default exit code (1 when leaks are found) is a normal,
successful outcome for a secrets scanner, not an engine failure; `gitleaks_normalize` parses gitleaks'
own BARE top-level JSON array - unlike semgrep's `{"results":[...]}` envelope - with the same
purpose-built, depth/string-aware `awk` splitter shape `_semgrep_split_results` established, adapted to
start directly at the first `[` rather than locating a `"results"` key first) and
`modules/sast/adapters/gitleaks/vendor.sh` (the only other file permitted to touch the network, calling
only `veng_fetch`, mirroring `semgrep/vendor.sh` exactly - never a hardcoded or guessed checksum).
`tools/vendor-engines.sh`'s `VENG_REGISTRY` now carries two entries, `[semgrep]=veng_vendor_semgrep` and
`[gitleaks]=veng_vendor_gitleaks`; the gitleaks entry requires the same five-operator-supplied-value
shape (`SCOURSH_GITLEAKS_VERSION`/`URL`/`SHA256`/`RULES_URL`/`RULES_SHA256`) and refuses - never
guesses - when any are missing, identically to semgrep.  `modules/sast/run.sh`'s `_sast_run_module` now
gates semgrep and gitleaks INDEPENDENTLY in the same `--use-engines` block, in two separate
`has_engine`/adapter-call pairs - one adapter's presence, absence, or failure never affects the other's
own gate or its own `coverage_reduction` line.

**This ticket's own, additional scope item - deduplicating gitleaks findings against the native
`modules/sast/rules/secrets.rules` pack - exists because both target the same class of issue (a
hardcoded credential), so the same secret at the same location is a routine, expected overlap that the
ordinary per-run fingerprint dedup (`lib/findings.sh`'s `findings_merge`) cannot catch on its own:
`check_id` is itself one of the fingerprint's own hashed components, so `gitleaks:aws-access-token` and
`SAST-SEC-AWS_AKID-01` always hash to two different fingerprints even when they report the identical
file, line, and matched bytes.**
`_gitleaks_dup_of_native_secret` (in `adapter.sh`) is the narrower, second dedup pass this ticket adds:
it reads this run's own not-yet-merged shard file(s) under `$SCOURSH_RUN_DIR/shards/*.fields` (via
`lib/findings.sh`'s public `finding_decode` reader - never a hand-rolled parse of that format) for an
already-emitted `module=sast`, `check_id=SAST-SEC-*` finding at the same `loc_path` AND the same
`loc_match_digest`, and skips emitting the gitleaks finding when one is found, counting it in a
`reason=dedup_native_secret engine=gitleaks count=N` `coverage_reduction` rather than dropping it
invisibly.  This works reliably because `modules/sast/run.sh` calls the native pattern scan, then
`history.sh`, then the engine adapters, strictly in that order, single-worker (its own
`single_worker_no_parallel_scan_yet` `coverage_reduction` already states there is exactly one shard per
run) - so by the time `gitleaks_normalize` runs, this run's own native secrets findings are already
sitting in that one shard file, unmerged.
**One correction surfaced while building this: `loc_match_digest` is NOT comparable across a
whole-line read and a matched-substring read.**
`modules/sast/engine.sh`'s own `_sast_emit_finding` hashes ONLY the exact regex-match substring
`scan_match_offsets` captured (`rules/RULE-FORMAT.md` §10.3's pass 1 - the `text` field of `while
IFS=: read -r ln off text`), never a `sed -n "${ln}p"`-read whole line.  The semgrep adapter's own
`_semgrep_match_text` DOES prefer a re-derived whole-line read, because semgrep's JSON carries no
distinct "just the matched substring" field - only a line-level `extra.lines` snippet - so a first draft
of `_gitleaks_match_text` that copied that same whole-line-read preference produced a digest that never
matched a native secrets.rules finding's own digest even at the identical file+line, silently defeating
the dedup entirely (caught by this ticket's own end-to-end fixture, section D of
`tests/suites/sast-gitleaks.sh`, before it ever reached review).  The fix, and the shipped behaviour:
`_gitleaks_match_text` prefers gitleaks' OWN reported `Secret` field (falling back to `Match`, then a
re-derived line, then `Description`) BECAUSE gitleaks, unlike semgrep, already reports the exact matched
secret substring directly - that is the "raw matched text" this codebase's fingerprint convention wants,
with no re-derivation needed, and re-deriving a whole line here would only pull in surrounding-line noise
the underlying match never had.
Absent or un-vendored is a clean, logged `coverage_reduction reason=engine_not_vendored engine=gitleaks`,
independent of semgrep's own; without `--use-engines` at all, behaviour is unchanged, exactly as semgrep
established.
`tests/suites/sast-gitleaks.sh` (35 assertions: the three-function contract including the bare-array
JSON shape, the path-traversal guard, the dedup helper in isolation, graceful degradation as a real
`scan.sh sast` subprocess, a full round-trip through every report format against a FAKE vendored
"gitleaks", and an end-to-end section proving the dedup itself - one gitleaks finding at the same
file+line as a native AWS-key finding is dropped, while a second, non-overlapping gitleaks finding at a
different line survives) and an expanded `tests/suites/vendor-engines.sh` (the registry now names two
engines sorted under `LC_ALL=C`, so `gitleaks` reaches its own refusal path before `semgrep` in `--all`,
plus `gitleaks_vendor`'s own fetch/verify section mirroring `semgrep_vendor`'s) both exist and pass.
`docs/ADAPTERS.md` §9's roster table now names this second row.

**This ticket is the SECOND concrete adapter, and the first for a module other than sast - it proves
`docs/ADAPTERS.md`'s directory-convention generalization (§4) for real rather than leaving it a claim
about a hypothetical future module.**
It ships `modules/iac/adapters/trivy/adapter.sh` (the same three-function contract as semgrep's, applied
to `trivy config`, trivy's offline IaC misconfiguration scanner): `trivy_detect` is a pure filesystem
check for an executable `bin/trivy` ONLY - unlike `semgrep_detect`, it needs no `rules/` at all, because
trivy's misconfiguration checks (OPA/Rego policies) are compiled into the binary itself, the
"self-contained binary" case `docs/ADAPTERS.md` §4 already anticipated; `trivy_run` invokes it with
`--offline-scan --skip-check-update --skip-db-update --scanners misconfig`, the same
belt-and-suspenders "two independent ways of saying offline" precedent `semgrep_run` set;
`trivy_normalize` walks trivy's own JSON, which nests findings TWO levels deep (a top-level `Results`
array, one entry per scanned target file, each with its own `Misconfigurations` array) rather than
semgrep's single flat array, via a generalized depth- and string-aware `awk` splitter
(`_trivy_split_objects_from_marker`) reused for both levels.
Which of `docs/DESIGN.md` §6.6's three named candidates (`checkov`, `tfsec`, `trivy config`) to build was
this ticket's own decision to make, not the operator's: only `trivy config` natively scans every IaC
shape the ticket's own scope names (Terraform, CloudFormation, Kubernetes, Helm, docker-compose) in one
binary - `tfsec` is Terraform-only, and `checkov` is a Python application rather than the single
vendorable static binary `semgrep`'s own adapter already established as this project's shape - see
`modules/iac/adapters/trivy/adapter.sh`'s own header for the full reasoning.
`tools/vendor-engines.sh`'s `VENG_REGISTRY` now carries a SECOND entry,
`[trivy]=veng_vendor_trivy`, requiring three operator-supplied `SCOURSH_TRIVY_*` values (version, binary
URL, sha256 - one artifact, not two, since there is no ruleset to vendor separately) and refusing - never
guessing - when any are missing; `modules/iac/adapters/trivy/vendor.sh` states explicitly why it never
extracts trivy's real `.tar.gz` release archive (the operator supplies a URL to the already-extracted
binary, the same "operator supplies the exact right platform artifact" contract semgrep's own vendor.sh
already uses).
Merge/dedup against native `modules/iac/*.rules` findings (this ticket's own scope item 3) needed no new
code: `docs/FOUNDATION.md`'s frozen pipeline (tension 11 stage 3) already merges and dedups every
finding, native and adapter alike, purely by fingerprint equality after every module's findings are
collected, and a trivy finding's `trivy:<AVD-ID>` check id never collides with a native `IAC-TF-*`/
`IAC-K8S-*`/... id - `tests/suites/iac-trivy.sh`'s section C fixture proves this concretely by engineering
a native `IAC-TF-OPEN_CIDR-01` finding and a `trivy:AVD-AWS-0107` finding to land on the exact same file
and line (so their `match_digest` is identical too) and asserting both still appear as two distinct
findings.
`tests/suites/iac-trivy.sh` (the three-function contract including the nested-array split, the
path-traversal guard, the `_trivy_severity_map` widening to `critical` - unlike `_semgrep_severity_map`,
because native `modules/iac/*.rules` packs already author `severity: critical` directly, so capping this
adapter at `high` would be an inconsistency invented for it alone - graceful degradation as a real
`scan.sh iac` subprocess, and the full round-trip/merge proof above against a FAKE vendored "trivy") is
new and passes; `tests/suites/vendor-engines.sh` gained the equivalent `trivy_vendor` fetch/verify
section, against its own scratch copy of the adapter directory.
`docs/ADAPTERS.md` §9's roster table now names this second row too.

**`tools/vendor-engines.sh`'s OTHER, unrelated responsibility - tension 25's `data/advisories.db`/
`data/versions.db` expansion, named as deliberately unbuilt by the step-9 scaffold paragraph above - has
now landed too, as its own ticket ("Implement tools/vendor-engines.sh's advisories.db/versions.db
expansion (tension 25)"), independent of and structurally separate from the semgrep/trivy/gitleaks
adapter work above.**
It adds the `advisories` command namespace to `tools/vendor-engines.sh` §3: a SEPARATE associative array
(`VENG_ADVISORY_REGISTRY`, never `VENG_REGISTRY`), separate functions (`veng_advisories_list`/
`veng_advisories_one`/`veng_advisories_all`, never `veng_vendor_*`), and its own `advisories` branch in
`veng_main`, exactly as the scaffold paragraph's own instruction required - an `<engine>` name and an
ecosystem name can never be mistaken for each other.
It covers all six `docs/DESIGN.md` §6.5 ecosystems (npm, PyPI, Maven, Go, RubyGems, Composer), one
`veng_advisories_<ecosystem>` function each, resolving real advisory data from OSV.dev
(`https://api.osv.dev/v1/vulns/<id>`) - the same cross-ecosystem vulnerability database
`govulncheck`/`pip-audit`/`osv-scanner` are themselves built on, chosen because OSV's schema already
carries a per-advisory `affected[].versions` array (the exact, ecosystem-tool-computed exact-version
enumeration tension 25 asks for), so this script still performs no range arithmetic of its own.
Every advisory id is operator-supplied via `SCOURSH_ADVISORY_<ECOSYSTEM>_IDS`, never guessed or
hardcoded, mirroring `semgrep_vendor`'s own "operator supplies the fact, this script only
fetches/transforms it" discipline.
JSON parsing uses `python3`'s stdlib `json` module (this script runs on a networked, operator-controlled
box with real tooling, never in the egress-restricted scan-time path); per-ecosystem name normalisation reuses
`modules/sca/engine.sh`'s, `php_engine.sh`'s and `go_engine.sh`'s own `sca_*_normalize_name`/
`sca_go_normalize_version` functions verbatim (lazily sourced), so the writer and the reader of
`data/advisories.db` can never drift apart on the frozen normalisation table.
`data/versions.db` is written by the identical `_veng_advisories_write_db` call, mirroring tension 25's
own "the same shape and the same rule" - its own, separate banner-matching product catalog (a bare web
server or TLS library with no SCA-ecosystem manifest at all) had been a stated, filed gap; a later
ticket (below) closed it.
`tests/suites/vendor-engines-advisories.sh` (85 assertions) is the fixture-driven proof, against
hand-authored, OSV.dev-*shaped* (never live-fetched) fixtures under
`tests/fixtures/vendor-engines/osv/` - the identical "no live network calls in CI" posture
`tests/fixtures/sca/advisories.db` already established for that data's READER side.
`docs/ADAPTERS.md` §10 and this script's own header are both updated in the same change to stop calling
this responsibility unimplemented; `docs/FOUNDATION.md` tension 27's own section carries the mirror of
this paragraph.

**The banner-matching product catalog gap named just above has since been closed.**
`veng_advisories_banner` (`tools/vendor-engines.sh`'s own §3) resolves an operator-supplied
`SCOURSH_ADVISORY_BANNER_IDS` into `data/versions.db`'s `banner` namespace
(`docs/VERSIONS-DB.md` §3-§5) - the known-vulnerable-version catalogue
`modules/dast/passive/banner.sh` reads for a product with no SCA-ecosystem manifest at all.
It is reached from its own `advisories banner` command, deliberately **not** a seventh
`VENG_ADVISORY_REGISTRY` entry: `advisories --list`/`--all` and `advisories bulk --all` must not sweep
it in, since OSV.dev publishes no per-ecosystem bulk-export archive for a synthetic "banner" ecosystem.
Two things depart from the six-ecosystem shape: the OSV ecosystem argument passed to the shared
extractor is the wildcard sentinel `*` (`_veng_advisories_osv_ecosystem`'s "banner" case), read as
"take every `affected[]` entry that names a package, regardless of its own `ecosystem` field" - a
banner-matched product has no single OSV ecosystem string to filter on the way an npm/PyPI/... advisory
does; and a missing severity defaults to `high`, not the SCA rows' `medium` default
(`docs/VERSIONS-DB.md` §3's own frozen text), via an optional second `DEFAULT` argument added to
`_veng_advisories_normalize_severity` rather than a second function, so every SCA call site is
unaffected.
The product key is normalised through `banner_normalize_product`
(`modules/dast/passive/banner_engine.sh`), sourced lazily, never re-implemented - the identical
writer/reader-drift discipline the six SCA importers already apply to `sca_*_normalize_name`.
Rows land in `data/versions.db` only, never `data/advisories.db`.
`tests/suites/vendor-engines-advisories.sh` section D2 is the fixture-driven proof (against
`tests/fixtures/vendor-engines/osv/SCOURSH-FIXTURE-OSV-BANNER-*.json`), including that the wildcard
admits two different non-SCA ecosystem strings for one product and the writer still dedupes them into a
single row, and that re-running `advisories banner` replaces the whole namespace - the same
per-ecosystem replace semantics every SCA ecosystem already has - without touching any SCA ecosystem's
rows or `data/advisories.db`.
`docs/VERSIONS-DB.md` §5, `docs/ADAPTERS.md` §10 and `docs/FOUNDATION.md` tension 25's own section are
all updated in the same change to carry the real command instead of the "no importer today" gap.

**Step 3a-3d shipped the SAST module's rule packs and engine.**
Four tickets landed, in this order:

- **3a** (`6f25a67`, "SAST: native pattern engine + seed secrets/crypto/injection/python rules")
  shipped `modules/sast/engine.sh` (the native pattern engine: walks the repo, applies per-language
  rule packs, matches only through `lib/core.sh`'s `scan_match` family per tension 4 rule 2, and
  implements the `context` directive - the first ticket to evaluate it at all), `modules/sast/run.sh`
  (the `scan_dispatch sast` entry point, sourced rather than subprocessed per its own header), and
  four rule packs: `modules/sast/rules/secrets.rules`, `crypto.rules`, `injection.rules`, and
  `python.rules`.
  It also closed finding F4 (the `context-deny` window contradiction between `rules/RULE-FORMAT.md`
  §12.1 and §12.2); see `docs/FOUNDATION.md` "Known follow-ups" for the closure detail.
- **3c** (`754a994`, "SAST: seed Go rule pack") shipped `modules/sast/rules/go.rules`.
  It landed before 3b in commit order even though it is lettered after it; the letter is a step-3
  sub-label from the ticket titles, not a landing-order guarantee.
- **3b** (`446f642`, "SAST: seed JS/TS rule pack") shipped `modules/sast/rules/javascript.rules`.
- **3d** (`910d2c7`, "SAST: seed Java rule pack") shipped `modules/sast/rules/java.rules`: `Runtime.exec`
  is deliberately *not* re-declared under a new `SAST-JAVA-*` id, since `injection.rules`' existing
  `SAST-INJ-OS_COMMAND-01` already carries `Runtime.getRuntime().exec(` as one of its alternatives; the
  pack instead adds JDBC statement concatenation, XML parsers missing `disallow-doctype` (an absence
  check, `context-deny` with a non-zero window), unsafe `readObject` deserialization, a trust-all
  `X509TrustManager`/`HostnameVerifier` pair (two ids, one per code shape), and SpEL/OGNL injection (two
  ids, one per library). It landed after 3e in commit order, out of letter order, same as 3c did for 3b.

What `modules/sast/rules/` holds is in the generated block above, counted from the directory.
Do not take a pack count from an individual ticket's own description - a ticket written before a
sibling pack landed will list fewer, which is how this paragraph itself used to be wrong; the directory
is the source, and the generator reads it.

**Step 3e shipped `history.sh`, landing after 3a-3c and out of letter order (§13 lists it last in the
step-3 sentence, but it is not "3d").**
`18c4c3f` ("SAST: history.sh - replay secrets.rules across git history (§13 step 3e)") shipped
`modules/sast/history.sh` (429 lines): it replays `modules/sast/rules/secrets.rules` against git
history rather than the working tree, bounded by a commit/time window per `docs/DESIGN.md` §6.3, and
populates the `SAST-HIST-*` check family - including the `history` fingerprint profile (`blob_sha`,
`match_digest`, `occurrence`) and the per-finding `oldest_reaching_commit_time` that tension 13's
boundary test and tension 6 condition (b1) read once `state/` exists at step 7.
`tests/suites/sast-history.sh` (295 lines) tests it.
`modules/sast/` now has all three files `docs/DESIGN.md` §13 step 3 names for it: `engine.sh`, `run.sh`,
and `history.sh`; step 3's §6.3 rule-pack catalog is complete as of the `nosql.rules`/`ldap.rules`
landing, per the generated block above.

**Findings still open after 3a-3d and 3e, and the step each is inherited by:**

- **F5 and F20** - `rules/derived.rules` still does not seed `COMPOSITE-TOKEN-HIJACK`.
  Step 5 (DAST) has since landed in full and supplies one contributor, but the composite also needs a
  step 6 (cloud) contributor that does not exist yet, so it remains unseeded until step 6.
  Seeding it now is a guaranteed `E051`/`E060` lint failure.

F3, F4, F8, F17, and F16's `look` half are closed (F3 and F8 as of step 2's `lib/checks.sh`; F4 as of 3a
above; F17 as of `lib/awscli.sh` landing - `aws_ro` sets `AWS_PAGER=''` rather than `--no-cli-pager`, see
"AWS module: what exists ahead of step 6" below; F16's `look` half as of `lib/core.sh`'s
`db_lookup_exact` and its new `tests/suites/core.sh` test - see `docs/FOUNDATION.md`'s "Known follow-ups"
for the full closure detail); do not re-flag any of them.

**`dev` is the integration branch; `main` is the release branch.** Work lands on `dev` first (squash
commits) and reaches `main` later in batches. Both branches exist on the remote; `main` is the default
branch (`origin/HEAD -> origin/main`). Historical narrative that says a ticket "landed on `dev`" remains
accurate. Do not assume `main` carries all the work that `dev` does.

**`main` lags `dev` - check the actual branch tip, not a stale local checkout, before declaring a
dependency unlanded.** This project develops on `dev` and merges to `main` in batches, so a checkout of
`main` can be several merged tickets behind what `dev` already has. A stale local checkout of either
branch makes that problem worse.
An earlier agent run on the 3b ticket read a `main` checkout where `modules/` was genuinely still
absent, concluded the 3a dependency (and this stale memory) meant the work hadn't landed, and moved the
ticket to `blocked` - when 3a had in fact already merged to `dev`.
Before concluding a dependency is missing, check the actual workspace branch and, if it is behind, fetch
and check the remote tip rather than trusting a stale checkout or this file's prose alone.

**A ticket can never cite its own landing sha, because the squash merge mints that sha afterwards.**
Landings reach `dev` as squash commits, so the sha a ticket's own branch carries is not the sha its work
ends up with, and a ticket writing "`<sha>` (this ticket)" into these docs is guessing at a commit that
does not exist yet and generally never will.
This has already happened three times and shipped every time: `ae03175` (the Dockerfile slice, really
`25abfa3`), `11e7c97` (the Ruby SCA slice, really `a2d37aa`) and `d7a746f` (the Kubernetes IaC slice,
really `bb75c9b`) - eight references between them across `AGENTS.md` and `docs/FOUNDATION.md`, none of
which `git cat-file -e` could resolve until this change corrected them.
The third one landed while this very change was in review, which is the argument for the rule.
Write the landing in prose without a sha ("this ticket adds ..."), and let the next ticket that touches
the paragraph fill in the real one.
Before trusting any sha in these two files, resolve it:

```sh
grep -ohE '`[0-9a-f]{7,40}`' AGENTS.md docs/FOUNDATION.md | tr -d '`' | sort -u |
  while read -r s; do
    git cat-file -e "$s^{commit}" 2>/dev/null || echo "MISSING $s"
  done
```

It has exactly five known false positives, all in prose rather than in a citation: the two decimal/octal
IPv4 literals in `docs/FOUNDATION.md` tension 19's SSRF text (`2851995906`, `025154325002`), which are
not shas at all, and `ae03175`/`11e7c97`/`d7a746f` in the paragraph immediately above, which this note
quotes on purpose as the bad values to recognise.
Anything else it reports is a real reference to a commit that does not exist, and is a bug.

**A branch marked done with no recorded landing commit is usually a bookkeeping gap, not stranded
work - prove the work is really unlanded before rescuing it by hand.**
(This project's default branch is `main`, but work lands on `dev` first. Check whether the work reached
`dev` before concluding it is unlanded. The commands below show how to test against `dev`; adapt them as
needed for the workflow.)
Because every landing squashes, `git log origin/main..<branch>` reports "1 commit ahead" for a branch
whose content is *already fully merged*, so commits-ahead is not evidence of anything.
The test that actually discriminates is `git cherry origin/main origin/<branch>`: a leading `-` means the
patch is already upstream, `+` means it is not.
Confirm a `-` by comparing trees (`git rev-parse <branch>^{tree}` against the `main` commit that landed
it); identical trees mean there is nothing to rescue and the correct outcome is to say so, not to open
an empty PR.
Two shapes cause a missing landing record: a landing recorded against a sibling branch that shared the
work, and merge-conflict-resolution branches, which resolve the conflict in the source branch's own
workspace and so frequently own no branch of their own.
Unpushed work, if any exists, can also live outside this repository entirely, in whatever per-task
workspace the driving automation used - sweep those clones and any local stashes
(`git rev-list HEAD --not --remotes=origin` plus `git stash list`) before concluding a branch missing
from `origin` means the work is lost; a commit found that way still has to be compared against `main`
artifact by artifact, since it is usually a superseded draft of what already landed.

**One piece of step 5 landed out of sequence: `lib/http.sh` (the scope-gate chokepoint,
docs/FOUNDATION.md tension 19) now exists**, built and reviewed as its own ticket once tension 19's
contract itself was signed off, rather than waiting for steps 2-4.  It has no dependency on `scan.sh`,
SAST, or SCA/IaC - it is a self-contained URL-normalization/tuple-match/deny-list/redirect-loop library
over `config/scope.conf` - so pulling it forward cost nothing those steps would otherwise have blocked.
`modules/dast/`, the rate limiter/request budget/circuit breaker (tension 16), and IDN/general-IPv6-CIDR
support (both explicitly out of scope for this ticket) still arrive at step 5 proper.  Do not read this
paragraph as "step 5 is done" - see "Current position" above for what is actually next.
`docs/STEP5-DAST-PLAN.md` is the sub-ticket breakdown for that remaining step-5 work and already excludes
`lib/http.sh` from its "still to plan" list, since this paragraph is where that fact is recorded.

**A second piece of a later step also landed out of sequence: `modules/iac/` (step 4's IaC half) now
exists - in three separate landings, and still only partial.**
`5de4460` ("IaC: Terraform checks via the pattern-rule engine (§13 step 4)") shipped `modules/iac/run.sh`
(the `scan_dispatch iac` entry point), `modules/iac/parse.sh` (the Terraform HCL parser), and
`modules/iac/terraform.rules`, run through the same native pattern engine `modules/sast/engine.sh` built
at step 3a.
`terraform.rules` seeds seven checks: `IAC-TF-OPEN_CIDR-01`, `IAC-TF-PUBLIC_ACL-01`,
`IAC-TF-UNENCRYPTED-01`, `IAC-TF-KEY_ROTATION_DISABLED-01`, `IAC-TF-PUBLIC_IP-01`,
`IAC-TF-HARDCODED_SECRET-01`, and `IAC-TF-RDS_PUBLIC-01`.
`tests/suites/iac.sh` tests it.
A second landing, `add2b21` ("IaC: Helm chart checks via the pattern-rule engine (§13 step 4)"),
added `modules/iac/helm.rules`: three checks (`IAC-HELM-HOST_PORT-01`, `IAC-HELM-HOST_MOUNT-01`,
`IAC-HELM-HARDCODED_SECRET-01`) against Helm chart sources only (`values.yaml` and
`templates/*.yaml`) - its own header states that scope discipline explicitly (never a docker-compose
file, never a bare non-Helm Kubernetes manifest) and its own "KNOWN GAP" note confirms no
`modules/iac/kubernetes.rules` (or any other Kubernetes-manifest pattern pack) exists on `dev` as of
that landing.
A third landing, `25abfa3` ("IaC: Dockerfile checks via the pattern-rule engine (§13 step 4)") added
`modules/iac/dockerfile.rules`: six checks (`IAC-DOCKER-ROOT_USER-01`,
`IAC-DOCKER-LATEST_TAG-01`, `IAC-DOCKER-SECRET_ENV-01`, `IAC-DOCKER-REMOTE_ADD-01`,
`IAC-DOCKER-PIPE_TO_SHELL-01`, `IAC-DOCKER-UNPINNED_DIGEST-01`) scoped strictly to `Dockerfile`,
`Dockerfile.*`, and `*.dockerfile` - `docker-compose*.yml` and Helm `values.yaml` are deliberately NOT
in this pack's `files:` list, per `docs/DESIGN.md` §3's original combined `containers.rules` sketch
being deliberately split one-format-per-file.
Which §6.6 slices have landed, and the on-disk pattern-pack count that `tests/lint-rules.sh`'s E060
fixture-coverage note reports, are both in the generated block above.
These packs landed ahead of step 3's then-remaining rule packs and ahead of step 4's own SCA half, the
same "land what's ready, out of strict step order" pattern as `lib/http.sh` above; step 4's SCA half
has its own paragraph below.

**A third piece of step 4 has now landed, in five sub-tickets: `modules/sca/` (the SCA module's npm,
Python, Ruby, Java, and PHP slices).**
`ed8c283` ("SCA: parse npm lockfiles and match against data/advisories.db") shipped `modules/sca/run.sh`
(the `scan_dispatch sca` entry point - no check-registry gate, unlike SAST/IaC, since SCA is a table
lookup rather than a pattern-rule engine) and `modules/sca/engine.sh`: lockfile discovery,
`package-lock.json` (v1 and v2/v3), `yarn.lock`, and `pnpm-lock.yaml` parsing, npm's own (identity)
name normalisation, and the `data/advisories.db` exact-match lookup (`sca_lookup_exact`/
`sca_package_known`, both routed through `lib/core.sh`'s `db_lookup_exact` per tension 25), emitting
`SCA-NPM-VULNERABLE_DEP-01` and the `SCA-COV-UNKNOWN_VERSION-01` roll-up.
A follow-on ticket ("SCA: parse Python lockfiles and match against data/advisories.db") then added the
module's Python slice on top of that same `run.sh`/`engine.sh` split, exactly as `run.sh`'s own header
comment anticipated for a sibling ecosystem: `requirements.txt`, `poetry.lock`, and `Pipfile.lock`
parsing, PEP 503 name normalisation (`sca_pypi_normalize_name`), and `SCA-PY-VULNERABLE_DEP-01`
findings under ecosystem `pypi`, plus its own `SCA-COV-UNKNOWN_VERSION-01` roll-up - a separate finding
from npm's own when both ecosystems have unknown-version cases in the same run, a stated scope limit
rather than a true cross-ecosystem merge (see `modules/sca/engine.sh`'s `sca_scan_python_tree` header
comment).

`a2d37aa` ("SCA: parse Ruby Gemfile.lock and match against data/advisories.db (§13 step 4)") then added
Ruby/RubyGems, in `modules/sca/engine.sh` alongside the npm parser rather than a forked file:
`sca_parse_gemfile_lock` (Gemfile.lock's `GEM`/`GIT`/`PATH` `specs:` blocks - already flat, one resolved
gem per 4-space-indented line, so unlike npm v1 no recursion is needed), `sca_ruby_normalize_name`
(lowercase, tension 25's RubyGems rule - unlike npm's identity function), and direct-vs-transitive
classified from the lockfile's own top-level `DEPENDENCIES` stanza versus a specs-only entry.  It mints
`SCA-RUBY-VULNERABLE_DEP-01` via the same `_sca_emit_finding` the npm path uses, now dispatched by
ecosystem (`_sca_check_id_for_ecosystem`) rather than hardcoded to npm's own check id.
UNLIKE Python, Ruby joined npm's OWN shared `sca_scan_tree` call rather than getting a sibling function:
`sca_scan_tree` (`modules/sca/engine.sh`) now walks BOTH npm's and RubyGems' lockfiles in one call and
shares one `unknown_count` table across them, because two separate `sca_scan_tree` calls would emit two
`SCA-COV-UNKNOWN_VERSION-01` findings that collide on one fingerprint (it carries no
ecosystem/package/advisory_id component) - `findings_merge`'s dedup would then silently drop whichever
ecosystem lost the sort instead of merging their counts.  `sca_scan_python_tree` (the Python slice, see
above) still runs as its own separate call for the same reason it always did - to avoid touching
`sca_scan_tree`'s already-tested npm code path.
`tests/suites/sca.sh` proves the npm+Ruby merge concretely with a `mixed-ecosystems` fixture carrying
both an npm lockfile and a Gemfile.lock, asserting exactly one roll-up finding whose breakdown names
both ecosystems, and separately tests the Python slice and the real `scan.sh sca` end-to-end path for
all three ecosystems.
`tests/fixtures/sca/advisories.db` now carries `npm`, `pypi`, and `RubyGems` fixture rows, with the npm
and RubyGems rows sorted together under `LC_ALL=C` (tension 25's own `look`-compatible sort
requirement).

Java (`pom.xml`/`build.gradle`, `a1b3c43`) and PHP/Composer (`composer.lock`, `7e7b186`) landed after
that paragraph was written, each without updating this section; `ab23b79` went back and corrected the
"still open" sentences for both.

**The Go slice (`go.mod`/`go.sum`) landed last, and is the first SCA ecosystem to ship as its own
engine file: `modules/sca/go_engine.sh`.**
PHP had already broken `engine.sh`'s monopoly with `modules/sca/php_engine.sh`, but PHP's parser is
still driven from inside `sca_scan_tree`; Go is fully standalone - `sca_go_scan_tree` is its own entry
point, called from its own `_sca_go_run` in `modules/sca/run.sh`, exactly as that file's own header
invited a further ecosystem to land ("do not fork this file per ecosystem").
It parses `go.mod`'s `require` lines (single-line and block form), reading a trailing `// indirect`
comment as the direct-vs-transitive signal, and falls back to `go.sum` when no `go.mod` sits beside it -
in which case `dependency_type` is reported **`unknown`**, never guessed.
`go.mod` wins when both are present in one directory.
Normalisation follows tension 25's frozen Go row: the `/vN` major-version suffix is **retained** and a
`+incompatible` version suffix is **stripped** before the `data/advisories.db` lookup, and both halves
are pinned by a test that fails under the naive opposite reading.
`replace`/`exclude` directives are **not** resolved - a stated limitation recorded in
`go_engine.sh`'s own header and surfaced at runtime as a
`reason=go_replace_exclude_directives_not_resolved` coverage_reduction, not hidden.
`sca_go_scan_tree` does its own `data/advisories.db`-readable check (unlike `sca_scan_python_tree` and
`sca_scan_java_tree`, which rely on `_sca_npm_run` having gone first), so `_sca_go_run` carries no
ordering requirement; it is still called last for a stable emission order.
Like Python and Java, Go emits its **own** `SCA-COV-UNKNOWN_VERSION-01` roll-up rather than joining
npm/Ruby/PHP's shared one - the same stated, filed cross-ecosystem-merge gap, not a new one.
With Go landed, step 4's SCA half covers every §6.5 manifest format; `tests/fixtures/sca/advisories.db`
now carries `Go` rows alongside `npm`, `pypi`, `RubyGems`, `composer`, and `maven`, all sorted together
under `LC_ALL=C` (tension 25's `look`-compatible sort requirement).

**A third piece of step 4's IaC half has since landed on top of the Terraform one above:
`modules/iac/docker-compose.rules` (the "IaC: docker-compose checks via the pattern-rule engine"
ticket).**
docs/DESIGN.md §6.6 bundles docker-compose in with Dockerfile/Kubernetes/Helm under one prose
"containers.rules" bullet, but none of the decomposed IaC tickets had claimed the docker-compose slice
itself; this ticket closes exactly that one gap, reusing `modules/iac/run.sh`/`parse.sh` unchanged (they
already existed from the Terraform landing above) and adding only the new flat pack file plus its
fixtures.
`docker-compose.rules` seeds four checks: `IAC-COMPOSE-EXPOSED_PORT-01` (a host port bound without
restricting the interface), `IAC-COMPOSE-PRIVILEGED-01` (`privileged: true`),
`IAC-COMPOSE-SENSITIVE_MOUNT-01` (a host bind mount of `/var/run/docker.sock`, `/etc`, `/root`, `/home`,
`/proc`, `/sys`, or `/` itself), and `IAC-COMPOSE-PLAINTEXT_SECRET-01` (a literal credential value in an
`environment:` entry, rather than a `${VAR}`/`env_file:` reference).
Its `files:` globs match `docker-compose.yml`/`compose.yml` (and their `.yaml`/override-variant forms)
only - `tests/suites/iac.sh` has a dedicated cross-shape section proving a Kubernetes-manifest-shaped and
a Helm `values.yaml`-shaped fixture, each deliberately carrying content that would trip every
`IAC-COMPOSE-*` check if the engine ever inspected file content, still produce zero findings, and that a
mixed directory holding one file of each IaC shape never lets a check cross-attribute to the wrong file.
This paragraph describes one slice of §6.6's container-rules bullet, not the bullet; the generated
block above is what says which of its slices are in.

Step 1 delivered `lib/records.sh`, `lib/core.sh`, `lib/findings.sh` and `lib/report.sh`, plus
`rules/redaction.rules`, `data/severity-rubric.conf`, the `config/*.example` files, a fixture
end-to-end path under `tests/e2e/`, and the test suite.
The six findings that blocked it (F13, F14, F12, F15, F16, and F18 by consequence) are **closed**, each
in the tension that owns it; see `docs/FOUNDATION.md` "Known follow-ups".

Step 2 delivered `scan.sh` (the §5 CLI grammar, tension 14's exit-code precedence, and wiring
`lib/config.sh` ahead of dispatch) and, in a later ticket, `lib/checks.sh` (tension 15's check-set
filter chain and registry loader, wired into `scan.sh` via `_scan_apply_profile_filter` ahead of every
`scan_dispatch`).
Findings F3 (which of two incompatible readings decides the `compliance` profile - settled on the TAG
reading) and F8 (`derived` checks are exempt from the `--intensity` ceiling) are **closed** as part of
that; see their entries in `docs/FOUNDATION.md` "Known follow-ups", and tension 15's own RESOLUTION,
both amended in the same change.
`lib/checks.sh` also wires `SCOURSH_SELECTED_CHECKS`, the env var `lib/findings.sh`'s
`_derived_record_selected` was already reading at step 1 in anticipation of this filter chain landing.

**What steps 1 and 2 deliberately did not build**, so the boundary is not rediscovered: anything under
`modules/`, `lib/http.sh`, `lib/engines.sh`, `lib/awscli.sh`, SARIF, the compliance report, any shipped
rule pack, and `state/`.
`lib/http.sh` landed anyway, out of sequence - see above.
**Step 3 then filled in most of that gap**: `modules/sast/` (with `engine.sh`, `run.sh`, AND
`history.sh` - see above) and its rule packs exist, so `scan_dispatch sast` no longer no-ops and
`_scan_apply_profile_filter` finds a non-empty registry for SAST checks.
**The IaC tickets (see the step 4 paragraph above) then did the same for `modules/iac/`**: it holds
`run.sh` and `parse.sh` plus the packs the generated block above lists, so `scan_dispatch iac` no longer
no-ops either and `_scan_apply_profile_filter` finds a non-empty registry for IaC checks too -
`modules/iac/` is off the "do not exist yet" list accordingly.
`modules/sca/` also landed out of sequence - see above.
`lib/engines.sh` also landed out of sequence, ahead of step 5/6/step-3's then-remaining packs - see
the paragraph above.
Of the original list, `lib/awscli.sh`, SARIF, the compliance report, and `state/` are
still unbuilt; which module directories exist is in the generated block above.
Every `scan_dispatch` call for a module other than `sast`, `iac`, or `sca` remains a logged
`coverage_reduction` no-op (`reason=not_yet_built`); `scan_dispatch sca` is no longer one of them, since
`modules/sca/run.sh` now does real work for npm/yarn/pnpm, Python, RubyGems, Maven, Composer, and Go.
`sca` is DIFFERENT from that group in a way worth stating precisely, since it is easy to conflate the
two separate coverage_reduction mechanisms `scan.sh` has: `scan_dispatch sca` itself no longer no-ops
(its `reason=not_yet_built` no longer fires - `modules/sca/run.sh` is real), but
`_scan_apply_profile_filter sca` still records `reason=no_check_registry_on_disk_yet` on every run, and
always will - by design, not because the module is unbuilt.
`_scan_apply_profile_filter`'s check-registry side loads check ids from on-disk `*.rules` files
(`checks_registry_load`), and `modules/sca/` ships none: SCA is a table lookup against
`data/advisories.db`, not a pattern-rule engine, so it has no `modules/sca/checks.rules` registry to
ever populate (`modules/sca/run.sh`'s own header states this explicitly) and its findings are emitted
directly by the engine files instead.
Both mechanisms are real and tested against fixtures.
Diff classification (tension 12) and baseline suppression (tension 11 steps 5 and 6) belong to step 7;
step 1 ships the primitives they call - the merge, the fingerprint, `findings_mark_suppressed`, and
`classify_derived`, which is pure and already tested against tension 6's whole case table.

**Two run.json fields are deliberately empty at step 1**, rather than absent, so a
consumer never has to handle a missing key and the gap is visible in the output:

- `regions` is `[]`. Region iteration is `modules/cloud/aws/regions.sh` at step 6;
  nothing before it visits a region, and inferring regions from a finding's cell
  would report where findings happened to land rather than where the run looked.
- `run_identity` is absent. `docs/FOUNDATION.md` tension 18 records it in
  run.json, but its inputs include the normalised CLI flags, which arrive with
  `scan.sh` at step 2.

`checks_run` is the set of checks the run LOADED AND EXECUTED. It is not
tension 12's `covered_checks`, which is per-(check, cell) coverage persisted in
`state/` and owned by step 7: a check can be in `checks_run` and still be
uncovered for a cell the run never visited.

`rules/derived.rules` is **not** seeded, and that is deliberate: findings F5 and F20 record that
`COMPOSITE-TOKEN-HIJACK`'s contributors do not exist until steps 5 and 6, so seeding it now is a
guaranteed `E051` lint failure.  The derived *mechanism* is delivered and is tested against a fixture
composite under `tests/fixtures/rules/derived.rules`.

**Read `docs/FOUNDATION.md` "Known follow-ups" before starting step 2.**
Six findings remain open (F4, F3, F5, F20, F8, F17, plus F16's `look` half); all are cheap corrections
that cost nothing to defer, and each names the step it must land before.
This is a snapshot from before step 2 landed and is kept for history; it is stale on its own.
F3, F4, and F8 have since closed, and F17 has since closed too (see "Findings still open after 3a-3d and 3e"
above for the current list: only F5, F20, and F16's `look` half remain).

Two amendments to §13 come from `docs/FOUNDATION.md` and applied from the start:

- `lib/records.sh` (the record parser) is built **before** step 1's stated contents, since tensions 1, 6, 9, 15, and 26 all depend on it.
- `lib/awscli.sh` is added to the layout and lands at the start of step 6, before any `aws/live/*.sh` script exists, so no script is ever written against a bare `aws`. **Update:** `lib/awscli.sh` itself now exists (see "AWS module: what exists ahead of step 6" below) - built out of sequence, deliberately, without the `aws/live/*.sh` scripts it was meant to land alongside.

## AWS module: what exists ahead of step 6, and why

A credential-less pass (no AWS account was available, and none of §13 step 2's other work was
blocked on it) advanced the part of step 6 that needs no account: the chokepoint, its runtime
guard, and the test infrastructure around both.
**Nothing in `docs/DESIGN.md` §8.1's check catalog was built** - no `modules/cloud/aws/live/*.sh`
script exists, `scan.sh` still does not exist, and this work does not change "current position:
step 2 is next" above.

**What exists now:**

- `lib/awscli.sh` - `aws_ro`, tension 23's chokepoint, exactly as specified: the prefix allowlist
  enforced at runtime (exit 3, not just a lint), `--cli-input-json`/`--cli-input-yaml`/`--output`
  refused outright, and **finding F17 closed**: `AWS_PAGER=''` rather than `--no-cli-pager`, which
  is CLI-v2-only and fails argument parsing on a v1 host before the call is even attempted.
  `tests/suites/awscli.sh` reproduces F17's failure mode against a real AWS CLI v1 install
  (`aws-cli/1.44.x`, measured) in `tests/localstack/run.sh`, not just a stub - the flag really does
  reject at parsing, and `AWS_PAGER` really does not.
- `tests/lint-aws-readonly.sh` gained an optional scan-root and allow-file override (used only by
  its own meta-test) and three real fixes, found while proving it fails on a planted mutating call:
  check 3 used to accept ANY `readonly`-declared variable regardless of what its literals were,
  so `readonly OPS=(list-users delete-user); aws_ro iam "${OPS[1]}"` passed clean; checks 2 and 3's
  allow-file lookup required the operation to be the last byte on the line, so the file's own
  documented style (`service operation # reason`) could never match; check 4's stale-entry
  detector had the same trailing-space-before-comment bug, which silently marked every entry for a
  service "used" the moment any call to that service existed anywhere. All three are fixed with a
  test that fails under the original reading, in `tests/suites/aws-lint.sh`.
- `tests/lib/aws-fixtures.sh` + `tests/fixtures/aws/` - the fixture harness for §8.1: a stub `aws`
  serves a recorded/synthetic JSON response, so a check's own logic can be unit-tested against
  known-good and known-bad inputs offline. Proven against one reference check
  (`tests/suites/aws-fixtures.sh`), explicitly labelled as a template, not a shipped check -
  `tests/fixtures/aws/README.md` says why.
- `tests/localstack/run.sh` - brings up LocalStack (docker), seeds a bucket via the real `aws` CLI
  directly (creation is mutating, so it deliberately does not go through `aws_ro`), then proves
  `aws_ro` against a real API shape: two read calls return the seeded bucket, and a mutating call
  is refused with exit 3 before it ever reaches the endpoint - verified independently by listing
  buckets again afterward. **Opt-in only**, not part of `tests/run-tests.sh`, requires docker and a
  real `aws` CLI (neither is a scoursh runtime dependency); confirmed by running the full suite
  with `docker` removed from `PATH`.
- `tests/aws-readonly-allow.txt` is **deliberately still absent**. No code calls `sts assume-role`
  until an `aws/live/*.sh` script exists at step 6, and seeding the file now would trip the lint's
  own check 4 (confirmed empirically before deciding this).

**What is NOT proven, and should not be read into any of the above:** none of this has run against
a real AWS account. LocalStack's S3 implementation is close to real but not identical - it does not
reproduce IAM policy evaluation, real service quotas or throttling, cross-account behaviour, or
every service's edge cases, and only S3 was exercised. `aws_ro`'s multi-account `sts assume-role`
path is unused and untested beyond being allow-listable. The read-only guarantee is proven against
a stub and against one emulated service, not against the full breadth of read operations §8.1's
catalog will eventually call. Do not describe any of this as "verified against AWS."

**A naming lesson worth keeping:** for `list-buckets`, `get-bucket-acl`, and the rest of the
low-level S3 API, the AWS CLI service name is `s3api`, not `s3` - `aws s3 <verb>` is a distinct
high-level command set (`ls`, `cp`, `mb`, `sync`, ...) with different verbs entirely. A first draft
of the fixture/stub examples got this wrong; it only surfaced once `tests/localstack/run.sh` ran
against a real CLI, since a stub that ignores the service name never would have caught it.

## Tests

```
tests/run-tests.sh                 # everything: every suite, every linter, then the shellcheck stage
tests/run-tests.sh --list          # the source of truth for exactly which suites, linters and stages exist today
tests/run-tests.sh <suite-name>    # one suite, e.g. tests/run-tests.sh sca
tests/run-tests.sh lint-rules      # or one linter by name
tests/run-tests.sh shellcheck      # or the whole-tree shellcheck STAGE alone (the slowest thing in a
                                    # full run; it is neither a suite nor a linter file, so it lives in
                                    # STAGES and is listed separately by --list)
tests/lint-rules.sh                # record-format linter, error codes in rules/RULE-FORMAT.md §13
tests/lint-shell.sh                # the tension 4, 9, 24 and 26 shell lints
tests/lint-aws-readonly.sh         # read-only AWS lint, docs/FOUNDATION.md tension 23
tests/lint-status.sh               # the generated build-status blocks are current, and the guard bites
tests/lint-no-ai.sh                # no AI/LLM provider hostname, SDK name, or API-key env var
                                    # anywhere in the shipped tool (excludes docs and its own two files)
tests/lint-source-graph.sh         # caps the shellcheck -x hub fan-out per entry point at 20 (see
                                    # "Sharp edges" above); catches the shape in milliseconds, before
                                    # the shellcheck stage would spend minutes and 30+ GB finding it
tools/gen-status.sh --write        # regenerate those blocks after landing a module
tests/e2e/fixture-scan.sh <dir>    # the end-to-end path on its own, for eyeballing a report
tests/localstack/run.sh [up|verify|down|all]   # OPT-IN: real API shapes via a local emulator.
                                    # Needs docker and a real `aws` CLI (neither is a scoursh
                                    # runtime dependency). NOT part of the suite above - see the
                                    # "AWS module" section below.
tools/daily-suite.sh               # the scheduled local runner: the whole suite on BSD, again on
                                    # GNU in a container, and a byte-for-byte diff of the two
tools/daily-suite.sh --status      # what the last scheduled run said (and whether one happened)
```

**`tests/run-tests.sh --list` is the source of truth for the current suite and linter names, not this
paragraph.**
This file used to hand-copy that list (as "eight suites: records | core | config | checks | findings |
report | http | e2e | scan"), and it silently went stale the moment `sast`, `sast-history`, `sca`, `iac`,
`exit-code-matrix`, `gate-mutation-proof`, and `ci-smoke` were registered - each addition is a one-line
edit to `SUITES=(...)` in `tests/run-tests.sh` itself (`docs/CI-RUNBOOK.md` checklist item 8) that this
doc has no way of tracking automatically. Run `tests/run-tests.sh --list` to see what actually exists;
do not hand-maintain a duplicate enumeration here or trust one written before your current checkout.

See `docs/CI-RUNBOOK.md` for how the suite is actually run while the hosted workflow is dormant: the daily local runner, how to install and remove its schedule, how to read a result, the GNU/BSD dual-userland rationale, and the checklist for adding a new suite or linter.

`package.json` at the repository root exists **only** so the conventional `pnpm test` / `npm test`
entry point runs the real suite above.
`pnpm test` is a thin alias for `bash tests/run-tests.sh`: no dependencies, no lockfile, no
`node_modules`, no build step.
scoursh has no Node runtime dependency and is not becoming a Node project; the shell entry point,
`tests/run-tests.sh`, remains the real one and the one to run directly when Node/npm/pnpm are not on
the box.
Anyone tempted to add a dependency, a devDependency, or tooling config to `package.json` has
misunderstood why it exists - don't.

`build` is a no-op (`echo` plus `true`) for the same reason `test` is a thin alias: the agent
platform's hand-off gate runs `pnpm run build --if-present`, and measured behavior on pnpm 10.29.3 is
that `--if-present` does NOT suppress `ERR_PNPM_NO_SCRIPT` when the `build` key is absent from
`scripts` entirely - it only no-ops when the key exists. scoursh has no build step; the script exists
solely so the gate's `--if-present` check has a script to find.

Each suite runs in its own process, because `lib/core.sh` installs traps, sets shell options and owns a
scratch directory: a suite sharing a shell with another would not be testing what the tool does.
`shellcheck` runs over everything if it is installed and is skipped with a notice if it is not, since an
air-gapped host may not have it.

**Every test that pins a decision names the reading it fails under.**
That is not a style preference: review round 5 found that four rounds had all written the test after the
rule, so every suite agreed with its author's reading and certified the defect green.
A test that passes under both the correct and the rejected reading pins nothing and is worse than no
test, because it buys false confidence.

What the suite covers now, per `docs/DESIGN.md` §12 and the resolutions above:

- Every worked example in `rules/RULE-FORMAT.md` §12 and every negative example in §12.6, with the right error code at the right line and column.
- Fingerprint stability under reindentation and line shifts; five byte-identical matches in one file yielding five fingerprints; no duplicate fingerprint in the merged output.
- Tension 6's derived-finding case table, including cases 5, 6, 7, 8 and 9, each of which the round-2 rule returned `fixed` for.
- Redaction across all four output formats, with two distinct secrets yielding two distinct digests.
- Hostile evidence: a script tag, an ANSI sequence, a raw newline, invalid UTF-8 and a backtick run, asserted escaped in every emitter, with the CSP present and no `<script>` in the HTML.
- Byte-reproducible `findings.jsonl` across two runs.
- The five closed findings, each with a test that fails under the original implementation.

Still to come with their steps: SARIF schema validation (step 10), the read-only lint over a non-empty
`aws/live/` (step 6), and a no-egress run under `--paranoid` (step 8).
Byte-identical findings between GNU and BSD userlands is checked by `tools/daily-suite.sh`, not by
CI - see "The hosted workflow is dormant, and a PR carries no automatic pass/fail" below.

## The hosted workflow is dormant, and a PR carries no automatic pass/fail

**`.github/workflows/ci.yml` exists, but hosted GitHub Actions cannot start a run on this account at
all right now - a billing condition, not a workflow defect - so it produces no status check today.**
It is kept, not deleted: the maintainer intends to make this repository public, which is what lifts that
condition, and at that point the workflow starts running for real with nothing to reconstruct.
**Restoring the file alone is not enough to make that true**: without a guard, GitHub still schedules
the `suite` job on every push and PR, and it fails within seconds with zero steps recorded - a real red
X, not "no check at all" - because the account has no machine to assign. The `suite` job therefore
carries `if: ${{ !github.event.repository.private }}`, which the Actions scheduler evaluates itself
before ever requesting a runner, so it reports `skipped` instead. That flips to `false` and the job
becomes real automatically the moment the repository goes public - no edit needed. Do not remove this
guard when troubleshooting a "why didn't CI run" question; it is working as intended.
Until then, do not assume a check will run on a push, and do not read a green-looking PR as a tested
one: there is no *failing* status of any kind on a commit or a pull request (only a skipped one), so a
PR that breaks every suite looks exactly like one that breaks nothing.
Anyone merging is the check - run `tests/run-tests.sh` against the merge result, or confirm a
`tools/daily-suite.sh` run *newer than the change* passed.
See `docs/CI-RUNBOOK.md` for the full account, including what changes once the repository is public.

What actually runs today is `tools/daily-suite.sh`, a local runner on a `launchd` daily schedule.
`docs/CI-RUNBOOK.md` is the authority for how it is installed, what it records, and how to read a
result; three things are worth knowing before touching it:

- **A missing or stale result is never a pass.**  `--status` reports `NEVER RUN`, `DID NOT FINISH` and
  `STALE` as distinct non-zero outcomes, and a run writes `verdict=INCOMPLETE` to `STATUS` *before* it
  starts work rather than writing a verdict after it succeeds.  With no PR check watching, a cron job
  that quietly stopped firing would otherwise leave a genuine old `PASS` behind and read as green.
- **A skipped leg is not a pass either.**  If docker is unusable the GNU leg is recorded as skipped and
  the verdict is `PASS-PARTIAL`, exit 5 - because tension 24's cross-userland guarantee genuinely was
  not checked that run.
- **The runner pins `/usr/bin:/bin:/usr/sbin:/sbin` ahead of `PATH` and then PROVES the userland is
  BSD, aborting if it is not.**  On this class of machine an interactive `PATH` resolves `grep` to
  ugrep and `find` to bfs; a suite run under those goes green while testing tools scoursh does not ship
  on, which is worse than not running it at all.  `tests/suites/daily-suite.sh` section B pins that the
  guard bites, in both directions - a shadow reachable only through `PATH` must be *overridden* by the
  pin and the run must proceed, so the suite can tell the pin working from the pin missing.

**Pinning the system path also pins `/bin/bash` 3.2.57, and `tests/run-tests.sh` spawns every suite as
a bare `bash "$path"`.**
That is measured, on the first real end-to-end run: all 35 checks died with "bash >= 4.2 required"
while the runner itself was healthy.  The fix is a one-entry shim directory holding only a `bash`
symlink, placed ahead of the pinned path - prepending the modern bash's own directory instead would put
Homebrew or a Nix profile back in front of `/usr/bin` and hand the grep shadow its win back.

**`SCOURSH_SCRATCH` is EXPORTED, so a nested `tools/*.sh` invocation shares its parent's scratch
directory** (`lib/core.sh`: that is deliberate, so `xargs -P` workers use the parent's; only
`SCOURSH_SCRATCH_OWNER` is non-exported, which is what keeps a worker from erasing it).
The consequence bit on the second real end-to-end run: `tests/suites/daily-suite.sh` runs
`tools/daily-suite.sh` as a subprocess, so the nested run got the same scratch directory AND its own
`$BASH` was the outer run's bash shim - one fixed shim path plus an underefenced `ln -sf` pointed that
shim at itself, and every check spawned after that suite died with "Too many levels of symbolic links",
from a run that had been green until then.
Anything writing a fixed-name file into `$SCOURSH_SCRATCH` from a `tools/` script has the same problem:
name it per-PID, and dereference `$BASH` before treating it as a real interpreter path.

## Things measured on this codebase, not assumed

Recorded because the review rounds found several confidently-stated shell facts that were simply wrong.

- `local a=$1 b=${#a}` gives `b=0`. Assignments in one `local` do not see each other; use two lines.
- **The exit status of `var=$(cmd)` IS `cmd`'s, so under `set -e` a bare assignment from a command substitution is an abort waiting for its first failure** - and where the command is a *probe* of something transient, that failure is a race rather than an error, so it shows up in production and never in a test. Measured in `tests/run-tests.sh`'s shellcheck watchdog: `rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null)` sampled a process the loop had just confirmed alive with `kill -0`, but a `shellcheck` finishing in that window made `ps` exit 1, which took the whole stage down past its own roll-up and verdict - so 9 of 130 files came back unmeasured with the messages explaining them never printed. Two stub files never lose that race; 130 real ones lose it almost every run. Write `|| var=` (or `|| true`) on any assignment whose command is allowed to fail, and be aware `2>/dev/null` silences the *message*, not the *status* - it is what makes this shape look safe. The same applies to `local var=$(cmd)`, in the opposite direction and worse: `local` is itself a command, so its own status wins and the failure is swallowed silently instead.
- Bash resets trapped `EXIT` actions in subshells. `xargs -P` workers are fresh processes and DO run them.
- A side-effecting function called as `$(f)` runs in a subshell and its writes are discarded. `occurrence_next` and `worker_id_set` therefore SET a variable rather than printing one; getting this wrong silently collapses every repeated match onto one fingerprint.
- BSD awk evaluates the source constant `0x80` as `0`, so hex literals are a GNU extension. The UTF-8 validator is pure bash for that reason.
- Bash's `=~` uses the system regcomp, which on macOS/BSD supports none of `\b`, `\w`, `\s`, `\d`. `grep -E` and `rg` support all four on both userlands. `redact()` therefore routes through the engine wrapper rather than matching in-process.
- `-n -b -o` produces byte-identical output under ripgrep 15.1.0 and BSD grep 2.6.0-FreeBSD, which is what `rules/RULE-FORMAT.md` §10.3's per-match ordinal needs.
- **`&` in the REPLACEMENT half of `${var//pattern/replacement}` expands to the MATCHED TEXT on bash 5.2 and later**, sed-style, where bash 4.2 - this project's frozen minimum - treats it as an ordinary character. So `${v//%3C/&lt;}` yields `%3Clt;` on a current macOS bash and `&lt;` on the oldest bash we support: the same line means two different things across the two userlands `tools/daily-suite.sh` deliberately runs. Write `\&` whenever the ampersand must stay literal. Measured in `tests/suites/dast-xss.sh`, where the unescaped spelling silently filled every "correctly HTML-escaped" control fixture with gibberish; because gibberish contains no raw `<` either, three of the four controls stayed GREEN and the mistake was caught only by the one case whose `&` sat mid-string rather than at the front. This is the failure shape to fear - a fixture that is wrong in the direction that still passes.
- `printf '--- ...'` is parsed as options by bash's builtin printf; use `printf -- '--- ...'`.
- `find` over a directory that does not exist fails, and under `pipefail` takes the whole pipeline with it.
- ShellCheck versions disagree: Debian's reports `SC2119`/`SC2120` where 0.11.0 does not. The BSD leg runs whatever Homebrew installed and the GNU leg whatever the container image ships, so a finding is silenced with an explicit `# shellcheck disable=` and a reason rather than left to the version.
- A comment line beginning `# shellcheck ` is parsed as a DIRECTIVE, so prose about shellcheck must not start a line with that word.
- **`shellcheck -x` follows `source` STATICALLY, where a runtime "already sourced" guard does not exist, so two files that source each other are an unbounded cycle it inlines until it dies.** `modules/sca/engine.sh` and `modules/sca/php_engine.sh` do exactly that on purpose (each sets its flag before recursing, so at runtime the second attempt is a no-op). Measured on `shellcheck -x -s bash modules/sca/run.sh`: **43.6 GB peak RSS and 236 seconds** with the cycle followed, **4.6 GB and 16 seconds** with one `# shellcheck source=/dev/null` on the back-edge, and an OOM kill rather than a slow pass on any machine with less RAM - which is how it was found, when the Linux container leg of `tools/daily-suite.sh` died where the 64 GB macOS leg survived. Cut ONE edge; the entry point (`run.sh`) sources every file in the directory itself and stays the graph shellcheck walks, so nothing is lost.
- **A CYCLE is not the only shape that blows `shellcheck -x` up, and the second shape - a DIAMOND in a perfectly acyclic graph - is the one this tree actually has.**
  `-x` does not memoise: it re-expands a file EVERY time it is reached, so two paths to the same file cost twice, and the multipliers compound.
  Measured here: `lib/http.sh` reaches `lib/records.sh` -> `lib/core.sh` through BOTH `lib/config.sh` and `lib/findings.sh`; `modules/dast/passive/cookies.sh` reaches `lib/http.sh` through both `inject_engine.sh` and `auth_engine.sh`; and `tests/suites/dast-cookies.sh` sourced `cookies.sh` six separate times on top of that - **156,852 inlined lines for one entry point, 91% duplicates, `lib/core.sh` inlined 29 times, 23.42 GB, unfinished after 29 minutes**, which the stage's own 12 GB watchdog killed.
  While that stood `bash tests/run-tests.sh` could not exit 0 on `dev` or on any branch cut from it, so "merge when the suite is green" was unachievable.
  The fix is the same one line applied to every edge whose target the entry point ALREADY reaches another way: **47 `# shellcheck source=/dev/null` directives across 25 files**, each *lossless* (the file is still inlined once, via the kept edge), taking that entry point to **34,881 lines**.
  Count them from the tree rather than from this sentence - `git grep -c '# -x back-edge cut:' -- '*.sh'` - because six files carried an unrelated such directive before this work, so the TOTAL (71 across 31) is not the added set.
  Peak RSS for it measured **8.42 GB / 173 s** on one host and **9.87 GB / 217 s** on another, same commit; **re-measured later on the grown tree it reached 12.99 GB**, with `dast-jwt.sh` at 12.96 GB - so `dast-cookies.sh` is the file closest to the ceiling, and **these figures go stale as the tree grows: re-measure rather than trusting the number written here.** That drift is not academic - the stage's per-process budget sat at 12 GB, *below* the real worst case, and killed both files as false failures until it was raised to 20 GB.
  **That 20 GB figure has since gone stale too, tree-wide rather than for one file, and the budget is now 50 GB.** `tests/suites/dast-cors.sh` and `tests/suites/dast-hosthdr.sh` carry zero repeated source targets - there is nothing left to back-edge-cut in either - yet `dast-cors.sh` alone re-measured at **23.79 GB**, and a real full-stage run skipped all three of `dast-methods.sh`/`dast-hosthdr.sh`/`dast-cors.sh` at the old 20 GB ceiling. That run also confirmed peak RSS here is itself ambient-memory-dependent (shellcheck's GHC runtime sizes its heap off available memory at measurement time, not a fixed multiple of the work done - `dast-hosthdr.sh`'s RSS visibly jumped the moment `dast-cors.sh`'s process exited and freed memory back to the host), so the `jobs * budget <= headroom` clamp, not the absolute number, is what actually keeps the model safe across host sizes - see `docs/CI-RUNBOOK.md`, "The memory model", for the full evidence. The still-open structural fix is flattening the `lib/http.sh` -> `lib/config.sh` + `lib/findings.sh` -> `lib/records.sh` diamond documented two paragraphs above: it was never cut by the 47-directive pass this paragraph describes, and is filed as its own follow-up ticket rather than attempted opportunistically.
  Those directives are LOAD-BEARING - deleting one because it "looks unnecessary" puts the stage back over budget, and those two files are where that regression surfaces first.
  Two traps when adding one: a comment line starting `# shellcheck ` is parsed as a directive, so the prose above a cut must not begin with that word (the first draft of these 47 blocks wrote `` `-x` `` in backticks inside a HEREDOC and minted `SC2006`/`SC2215` findings out of a comment); and a `source` line inside a heredoc or a quoted string is NOT an edge shellcheck follows, so a tool that counts it will call a cut "lossless" when it is not (that is exactly how a first pass wrongly cut `tests/suites/core.sh`'s only real edge and turned `SCOURSH_ENGINE` into a fresh `SC2034`).
  **The `lib/http.sh` -> `lib/records.sh` diamond this paragraph names was left UNCUT by the 47-directive pass above** - it names the shape as measured, not as closed, and a later ticket confirmed by re-reading every `source`/`# shellcheck source=` line in `lib/http.sh`, `lib/config.sh`, `lib/findings.sh` and `lib/records.sh` that it was still real. It is now cut, and the cut landed on `lib/config.sh`'s edge, not `lib/findings.sh`'s: `lib/http.sh` sources `config.sh` before `findings.sh`, so `findings.sh`'s own (kept, real) edge to `records.sh` still supplies it once for every `lib/http.sh` consumer. `lib/findings.sh`'s edge was the ticket's own first proposal and was rejected after measurement: `findings.sh` is also a standalone shellcheck entry point in its own right, and is reached directly - not via `config.sh` - by `lib/report.sh` and half a dozen test suites (`tests/suites/{findings,dast-response-engine,secret-redaction,aws-fixtures,dast-banner,gate-mutation-proof}.sh`), several with no other path to `records.sh`. Cutting there measurably broke one of them: `tests/suites/findings.sh` picked up a real `SC2034` on `SCOURSH_RUN_ID`, because `records.sh`/`core.sh` are what use that variable and shellcheck could no longer see it. Patching that by giving `lib/report.sh` its own defensive real edge to `records.sh` would in turn have opened a NEW diamond in `modules/sast/engine.sh` and `modules/sca/engine.sh`, which source both `lib/report.sh` and `lib/config.sh` directly - so the smaller, cleaner cut is the one on the side with only two direct consumers (`lib/config.sh` itself and `tests/suites/config.sh`, both confirmed clean by direct measurement) rather than the side with eight. Measured: `lib/http.sh` alone drops from 1.16 GB to 0.85 GB peak `shellcheck -x` RSS (-27%); `tests/suites/dast-inject-engine.sh`, a real entry point, drops from 2.22 GB to 1.49 GB (-33%).
- **After the diamond flattening above, `dast-methods.sh` and `dast-hosthdr.sh` still would not fit, because the multiplier lives at the ENTRY POINT, not at the leaves, and cutting inlined *lines* there does nothing - only cutting *copies* of the `lib/` hub chain (`core.sh`/`records.sh`/`findings.sh`/`http.sh`/`config.sh`) does.** Peak RSS is not a function of inlined size: `tests/suites/dast-ratelimit.sh` inlines MORE lines than `dast-hosthdr.sh` and costs 5.1x less memory, and a synthetic `lib/core.sh` x8 probe costs 36.75 GB where x6 costs 0.79 GB - roughly 7x per additional copy past 6, an exponential cliff, not a linear one. The real predictor is the **hub sum**: total expansions of those five files across the whole followed graph. Two independent, unrelated causes hid behind the one symptom in this tree, and fixing only one leaves the wall exactly where it was:
  1. Several suites `source` the same phase script ONCE PER TEST CASE, each with its own real directive, so the whole subtree re-expands every time - `tests/suites/dast-methods.sh` sourced `modules/dast/active/methods.sh` 9 times, `dast-graphql.sh` sourced `modules/dast/graphql.sh` 13 times. Keeping the FIRST real and cutting the other N-1 (the target is already inlined once, and the runtime `source` still executes since the `SCOURSH_*_SOURCED` guards make repeats no-ops) is lossless by construction - but on its own this cut `dast-methods.sh` from 211,313 to 50,641 inlined lines (-76%) for **zero** RSS improvement (33.46 GB, unchanged), because its hub sum only fell from 116 to 28, still past the cliff.
  2. `dast-methods.sh` ALSO sourced `method_engine.sh`/`inject_engine.sh`/`auth_engine.sh` at its own top level, duplicating what `modules/dast/active/methods.sh` (which the suite also sources) already supplies internally; `dast-hosthdr.sh` had a direct `source lib/http.sh` duplicating what `hosthdr_engine.sh` already supplies. Cutting THESE (real edges, not repeats of an identical directive) took `dast-methods.sh` to 31,000 lines / hub sum 17 / **5.70 GB**, and `dast-hosthdr.sh` to 34,735 lines / **5.90 GB** (from 30.39 GB) - proven lossless by diffing `shellcheck -x`'s own findings before and after each cut, not by argument.
  A cap of 20 on the hub sum flags exactly these two files at baseline and nothing else (`dast-ratelimit.sh` at 21 passes at 5.92 GB, the nearest neighbour), which is why `tests/lint-source-graph.sh` - registered in `tests/run-tests.sh`'s `LINTERS`, with its own self-test at `tests/suites/lint-source-graph-selftest.sh` - gates on that number rather than on inlined lines: it would have failed the ticket that grew either file past the cliff on the day it landed, in milliseconds, rather than after minutes and 30+ GB of the shellcheck stage discovering it the expensive way.
- **On Docker Desktop for macOS, a bind mount whose source and destination are the SAME absolute path is silently not mounted when written as `-v <path>:<path>:ro`** - the destination simply does not exist inside the container and `docker run` reports nothing. The identical read-only bind written as `--mount type=bind,src=<path>,dst=<path>,readonly` works. `-v <path>:<path>` (read-write) also works, so the `:ro` suffix is the trigger.
- **A `git worktree` checkout's `.git` is a FILE holding an absolute path into the main repository**, so git does not work inside a container that mounts only the checkout. `tools/daily-suite.sh` mounts `git rev-parse --git-common-dir` as well, at its own path. Without it `git rev-parse --show-toplevel` fails, `lib/core.sh` falls back to the resolved `--path` as the scan root, and every finding's repository-relative `loc_path` changes - a whole class of "the rule pack broke" failures whose real cause is the scan root.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
