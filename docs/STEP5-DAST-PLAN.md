# Step 5 (DAST) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 5 - `docs/DESIGN.md` §13's dependency-ordered "`lib/http.sh` -> `auth.sh` (§7.0)
-> `crawl.sh` (§7.5) -> DAST passive -> safe-active -> injection probes one file at a time, each with a
mock-response test -> §7.4 auth/API/authz checks" - can be picked up as a clean sequence of small,
independently reviewable tickets, instead of being re-derived from `docs/DESIGN.md` §7 from scratch by
whoever picks it up first.

## Status: top priority - tiers 0 and 1 are both complete

**Every gate this section used to record is now discharged, and the whole of tier 0 has landed.**
`docs/DESIGN.md` §13 step 3 finished (`nosql.rules` and `ldap.rules` landed), step 4 finished (SCA at
6 of 6 ecosystems, IaC at 6 of 6 packs), and step 5's own tier-0 tickets are in:

| Ticket | State |
|---|---|
| DAST-01 - the tension-16 rate limiter, request budget and circuit breaker in `http_request` | landed |
| DAST-02 - `modules/dast/run.sh`, the `scan_dispatch dast` entry point | landed |
| DAST-31 - the identifying `User-Agent` and operator contact | landed |
| DAST-32 - the conservative ceilings and the `--i-own-target` affirmation | landed |
| DAST-33 - the authorisation record in `run.json` (and `use_engines`, the same gap) | landed |
| DAST-34 - an unrestricted run stated on stderr and in the report | landed |
| DAST-35 - the lint forbidding a bundled scan target | separate ticket; no ticket below is gated on it |
| DAST-36 - folding this posture into DAST-01..30's own acceptance criteria | doc-only; **landed** |
| DAST-04 - `crawl.sh`, the endpoint/parameter inventory every later ticket reads | **landed** (tier 1) |

**Tier 1 is now complete.**

| Ticket | State |
|---|---|
| DAST-03 - `auth.sh`, authentication and session acquisition (§7.0) | landed |
| DAST-04 - `crawl.sh`, crawling, parameter and spec discovery (§7.5) | landed |

**Tier 2 has started: DAST-06 (`passive/cookies.sh`), DAST-05 (`passive/headers.sh`) and DAST-11
(`passive/markup.sh`) have all landed**, built in parallel - DAST-06 reached `dev` first and created
`modules/dast/passive/` and the shared `checks.rules`, DAST-05 appended the `DAST-HDR-*` block to it,
and DAST-11 appended the `DAST-MARKUP-*` block.  Their four remaining peers (DAST-07..DAST-10) are
open and unordered among themselves.  See each ticket's landing note under the tier-2 table for what
it shipped, and DAST-05's and DAST-06's for the one pre-existing `modules/dast/run.sh` defect they
found and deliberately did not fix in place.

**DAST-30 (`passive/transport.sh`) now also lives in this directory and runs at this tier**, carrying
its own `DAST-TRANSPORT-*` block in `modules/dast/passive/checks-transport.rules` (it appended to the
directory's then-shared `checks.rules`; tension 29 has since split that file), even though it
is a tier-5 §7.4 ticket - its landing note below states the reasoning, and `modules/dast/engine.sh`'s
phase table carries the same note at the row itself.  It is not an additional tier-2 ticket and the
tier-2 peer list above is unchanged by it; what moved is one intensity floor, not the ticket.

**Tier 5 has started too: DAST-26 (`jwt.sh`) and DAST-29 (`authz.sh`) have both landed.**
DAST-29 created `modules/dast/checks.rules`, the shared, append-only script-check registry for the
tier-5 phases whose scripts sit at the top level of `modules/dast/`; DAST-27 and DAST-28
append their own blocks to it and resolve a conflict in it by keeping both sides.
That file is deliberately NOT split - `docs/FOUNDATION.md` tension 29 makes the per-owner
`checks-<name>.rules` spelling legal everywhere but keeps splitting optional and per-directory, and
doing one under peers who are mid-flight recreates the conflict it exists to prevent.
`modules/dast/passive/` IS split, so it is no longer the precedent this paragraph used to cite.
DAST-30 is NOT one of the top-level tier-5 phases: its script sits under `modules/dast/passive/`
rather than at the top level, so its checks are registered in that directory with the rest of it -
today in its own `modules/dast/passive/checks-transport.rules`, per the paragraph above.
DAST-29 is also the first consumer of DAST-03's labelled multi-identity plumbing, so the
`requires-identities: 2` path in `rules/RULE-FORMAT.md` §9.5 now has a real implementation behind it.
See its landing note under the tier-5 table.

**Tier 5 has started too: DAST-28 (`ratelimit.sh`, the §7.4 missing-throttling burst probe) has
landed**, alongside DAST-26 (`jwt.sh`).  It is the ticket carrying this plan's one behavioural
amendment (see "Conservative-posture criteria, restated per ticket" below), and it created
`modules/dast/checks.rules` - the shared, APPEND-ONLY registry for every tier-5 phase that sits at the
top of `modules/dast/` rather than under `passive/` or `active/`.  Its landing note is under the tier-5
table.

**Tiers 2-5 are unblocked and nothing remains in front of them**: every check below needs the endpoint
and parameter inventory DAST-04 writes, and the authenticated ones need the session DAST-03 acquires.
Both are in.
**Tier 2 has started** (DAST-07, `passive/tls.sh`), **tier 3 has started** (DAST-12,
`active/discovery.sh`), and **tier 4 has started too**: DAST-14 (`active/sqli.sh`, which also shipped the
shared `inject_engine.sh` every §7.3 probe reuses) and DAST-22 (`active/ldapi.sh`) have both landed - see
their landing notes under the tier-4 table.  Tier 5's DAST-26 (`jwt.sh`) is in as well.  These tiers are
peers once tier 1 is in, so they land out of tier order.
Each ticket's own row in the tier tables below is the authority for whether it is in; this paragraph
names only the tiers that have opened, so it does not become the second enumeration that went stale
three times in `AGENTS.md`.
DAST-07 is the one worth flagging outside its own row, because it is the ticket that made tension 19's
single documented exception real: `lib/http.sh` gained `http_authorize_raw_connection`, and any future
non-HTTP probe calls **that** rather than assembling its own subset of the gate.
What each shipped, and the things about them that are easy to get backwards, are stated in their own
landing notes below the ticket table.
The one ordering constraint tier 0 existed to impose has been met: no ticket may issue real HTTP
traffic until the limiter, the budget, the breaker, the identified `User-Agent` and the conservative
ceilings are all in `lib/http.sh`, and they are.

What DAST-31 through DAST-34 actually shipped, stated once here rather than left to be read out of
the diff:

- Every request carries `scoursh/<version> (+<contact>)`, composed in `_http_transport_default` and
  nowhere else, with the no-contact form naming the project URL instead.  `contact` is a
  `config/scanner.conf` key (`rules/RULE-FORMAT.md` §9.6.1) plus a `--contact` flag;
  `--user-agent-suffix` appends a product token and cannot displace the prefix.
  **The `format_version` question was checked rather than assumed** and the answer is the expected
  one: an additive optional key trips §14 item 2 only, and `rules/RULE-FORMAT.md` §14 now carries the
  worked item-by-item reasoning so the next additive key does not have to re-derive it.
- The ceilings are applied to the **resolved** value at the `lib/http.sh` chokepoint, and the clamp
  policy is asymmetric exactly as specified below: a **file or default** value above a ceiling is
  clamped with one `log_warn` and a recorded delta, an explicit **CLI or env** value above one is
  exit 2 naming `--i-own-target`.  Both directions are pinned by tests that fail under the other
  reading.
- `--i-own-target <id>` must equal `--target <id>`; it is valid on `dast` and `all` only, it is a key
  rather than a switch, and it is carried as a per-run record under the run directory, never an
  environment variable.  `--intensity` above `passive` and `--allow-intrusive` both require it.
- The affirmation lifts the three upper bounds (rate, budget, breaker threshold) and **neither** of
  `circuit-breaker-window`'s bounds: the 60s floor because a shorter window is a weaker breaker, and
  the 86400s maximum because it is arithmetic rather than safety.  This is a refinement of the
  "Relaxable" table below, which did not say which way the window moves.
- `run.json` carries an `authorization` object on **every** run, affirmed or not, and now also renders
  `use_engines`, which had been recorded and never rendered since the semgrep adapter landed.

## Status (historical): top priority - one gate cleared, one sequencing item left

The section below is the state this plan recorded BEFORE tier 0 landed.  It is kept because its
reasoning held rather than evaporated, in the same way the step-3/step-4 gate was; the table above is
the live answer.

**Step 5 is now this project's top-priority feature**, ahead of live cloud scanning (step 6), persistent
run state (step 7), and SARIF plus the compliance report (step 10).
That is a change of priority, not a rewrite of the build order.
What follows records exactly what is, and is not, still in front of DAST-01.

Two things gated step 5 when this plan was written.

1. **`docs/DESIGN.md` §13 step 3 finishes**: the `nosql` and `ldap` SAST rule packs
   (`modules/sast/rules/nosql.rules`, `modules/sast/rules/ldap.rules`) land.
   **Still outstanding.**
   `modules/sast/rules/` holds seven packs - `secrets`, `crypto`, `injection`, `python`, `go`,
   `javascript`, `java` - plus `history.sh` (sub-steps 3a-3e); neither `nosql.rules` nor `ldap.rules`
   exists.
2. **`docs/DESIGN.md` §13 step 4 (SCA + IaC) completes.**
   **Cleared.**
   This section used to read "as of this writing step 4 has not started", and that has been wrong for
   some time.
   Both halves are complete and exercised by the test tree: the generated status block reports SCA at
   6 of 6 ecosystems and IaC at 6 of 6 packs.
   The SCA half finished with the Go slice (`1c4a28f`), and the IaC half with the CloudFormation pack
   (`62cbf0e`) - the last step-4 artifact to land.
   The generated block, not this paragraph, is the live answer if it is ever in doubt again.

**The one remaining item is a sequencing preference from the original build order, not a technical
dependency.**
No ticket below consumes a SAST rule pack.
`docs/DESIGN.md` §13 puts step 3 first because it is a sequential build plan, not because `nosql.rules`
or `ldap.rules` produce anything a DAST script reads.
The single point of contact between step 5 and SAST is DAST-04's optional merge of
`reports/<run>/inventory/endpoints.json` (tension 21's route extraction), which that ticket must already
tolerate being absent.

**DAST-01 in particular can begin immediately.**
It touches `lib/http.sh` only: it hooks the tension-16 rate limiter, per-run request budget, and circuit
breaker into `http_request`, on top of `lib/core.sh`'s mkdir-mutex and scratch-dir primitives that
shipped at step 1.
Both of its dependencies are shipped, neither is a rule pack, and `lib/http.sh`'s own header already
names these three pieces as the step-5 work it deliberately left for later.
DAST-01 also blocks all of tiers 1-5 below, so starting it is what shortens step 5 rather than merely
reordering it.

DAST-01 has since landed, and the loose end this paragraph used to record is discharged:
`docs/FOUNDATION.md` no longer states the old gate and no longer cites this section by its former
name, "Status: blocked".
Verified rather than assumed - that string does not appear in `docs/FOUNDATION.md` at all today.

## `lib/http.sh` has already shipped - do not re-plan it

`docs/FOUNDATION.md` tension 19 and `AGENTS.md`'s "Build order and where we are" both already record
this: `lib/http.sh` (the scope-gate chokepoint - `http_url_normalize`, `http_scope_load`/
`http_scope_match`, `http_resolve_host`, the IPv4/IPv6 deny list, `http_gate_url`, and `http_request`)
landed early, out of its normal step-5 sequence, once its tension-19 contract was signed off.
It is **not** in the "still to plan" list below.

One piece of tension 16 (the shared rate limiter, per-run request budget, and circuit breaker that
`http_request` is supposed to enforce "regardless of `--jobs`", per `docs/DESIGN.md` §4/§5) is still
genuinely unbuilt - `docs/FOUNDATION.md` tension 19's own "Implementation" note says so explicitly.
That gap is real remaining step-5 work and is planned below as DAST-01, distinct from the chokepoint
itself, which is done.

## A local, authorized DAST test target now exists - do not re-plan it either

This target was needed because no staging environment was available, and the operator would not scan
anything not owned outright: `tools/dast-test-target.sh` starts (idempotently) a
pinned, self-hosted OWASP Juice Shop container on a fixed local port for exactly this purpose, and
`tools/dast-test-identities.sh` provisions two distinct throwaway identities in it, following the same
`secret-file`-in-a-600-file convention `config/auth.conf` (`rules/RULE-FORMAT.md` §9.6.2) already
defines for a real operator's credentials.
`tools/dast-test-target/scope.conf` is the `config/scope.conf`-format record authorizing exactly that
target; `docs/DAST-TEST-TARGET-AUTHORIZATION.md` is the written authorization record itself, dated.
None of DAST-01 through DAST-30 below need to plan target acquisition, authorization, or multi-identity
setup - DAST-29 (`authz.sh`) in particular can point straight at this fixture's two identities and the
basket-IDOR case `tests/e2e/dast-target-smoke.sh` asserts against them, rather than standing up its own.

Three things worth knowing before building against it:

- **This tooling has been reviewed as code, not observed running.**
  `tests/e2e/dast-target-smoke.sh` needs Docker and real network access to pull the pinned image, so it
  is deliberately outside `tests/run-tests.sh`'s suite list and is never run by the default suite or by
  CI.
  The machinery is real and complete, and nothing here is a stub - but no record of an actual end-to-end
  run exists, so its reachability, identity-provisioning and IDOR assertions are unproven in practice.
  The first ticket that actually talks to the target runs that smoke test by hand before building on it,
  and records the outcome.
- **This tooling never calls a host-side `curl`/`wget`/etc.**, on purpose: `tests/lint-shell.sh`'s
  tension-19 "no bypass" check only exempts `lib/http.sh` and `tools/vendor-engines.sh`, and adding a
  third exemption for one-time local setup tooling was judged not worth diverging from that frozen
  invariant. Instead, the one HTTP call this tooling needs (registration, login, the readiness poll)
  runs *inside* the container over `docker exec`, via the small vendored
  `tools/dast-test-target/http-client.js`. A future DAST-0x script that legitimately needs to talk to
  this fixture from the host should go through `lib/http.sh`'s `http_request` like everything else -
  `tests/e2e/dast-target-smoke.sh` already does exactly that for its own reachability/gate checks.
- **The container's account database does not survive a stop/start cycle** (it is not a volume), while
  `.dast-test-target/`'s generated secret-files are local state that does. `tools/dast-test-identities.sh`
  handles this by always re-registering (harmless against this pinned image, which does not reject a
  duplicate email) rather than skipping registration whenever a secret-file already exists - see that
  script's own comment on `dti_provision` if this ever needs revisiting against a different pinned
  version.

## Safety defaults and authorisation - the posture every ticket below inherits

This section was written after DAST-01 through DAST-30 and it constrains all of them.
Nothing in it is a style preference.
It is the set of defaults that decides whether a downstream operator who misjudged a host ends up with
a coverage gap or with a legal problem, and the tool's own defaults are the only part of that outcome
this repository controls.

### What was verified about publicly authorised scan targets

Each of these was read from the target owner's own published statement, not from a summary of one.

- **Every permission statement that addresses the question at all asks scanners not to hammer the
  target.**
  Rate limiting is therefore a *condition of the authorisation*, not politeness, and a scan that
  ignores it has stepped outside the permission it was relying on.
  This is a second, independent reason DAST-01 comes first, alongside the tension-16 `--jobs` argument
  already recorded above: until the limiter, the budget and the breaker exist, no DAST traffic this
  tool sends can honour the one condition that every authorisation attaches.
- **The Nmap project's `scanme.nmap.org` grants permission for port scanners only**, and explicitly
  excludes exploit testing and brute forcing.
  Permission to point one class of tool at a host is not permission to point another class at it, and
  a scanner that treats "we are allowed to touch this host" as "we are allowed to do this to this
  host" has substituted its own reading for the owner's.
- **The OWASP-hosted public Juice Shop demo explicitly prohibits being used as a scan target**: "You
  are not supposed to use this instance for your own hacking endeavours!"
  That finding lands directly on this repository, because `tools/dast-test-target.sh` runs Juice Shop.
  The *local, operator-started container* is authorised by `docs/DAST-TEST-TARGET-AUTHORIZATION.md`
  and by `tools/dast-test-target/scope.conf`; the *public hosted instance of the same application* is
  not, and never becomes authorised by being the same software.
  Any ticket, comment, fixture or doc example that reaches for a hosted instance because "Juice Shop
  is the thing we test against" has crossed that line.
- **The one target whose published permission does cover injection testing, and does explicitly invite
  third-party tools, is currently offline.**
  So there is no live host that a shipped example could point at even if shipping one were acceptable.
- **There is no general convention that grants standing permission to scan.**
  Neither `robots.txt` nor `security.txt` is authorisation: the first is a crawler-exclusion hint and
  the second is a contact address.
  A bug-bounty page is not authorisation either, unless it names this host and this kind of testing.

Hostnames appear in the bullets above and must not be copied out of them into a shipped file.
`docs/DESIGN.md` §1's exact words are "No application, company, environment, product, or endpoint name
is ever baked into a **script or rule**", so it binds `scan.sh`, `lib/`, `modules/`, `rules/` and
`config/`, and it says nothing about documents.
An earlier draft of this section cited §1 as covering documents as well; it does not, and inventing a
rule under a frozen document's authority is worse than proposing the same rule on its own merits.
What this plan actually adopts, as a new and deliberate rule: **no shipped file names a third-party
host as a scannable target**, DAST-35 lints that mechanically, and this planning document may name a
host in the cases above precisely because the finding *is about that host*.

### Why the defaults must be conservative, stated as a cost rather than a value

The operator running this tool is frequently not the person who wrote it, and the host they point it
at is one this repository's authors cannot vet.
The failure costs are asymmetric and only one direction is recoverable.
A default that is too strict costs one config edit and one flag.
A default that is too loose sends attack-shaped traffic to somebody else's host from an attributable
IP address, which is not undoable, and it does so on behalf of an operator who reasonably assumed the
tool's own defaults were safe to run.
So the defaults are set for the host the authors cannot see, and the operator who genuinely owns their
target lifts them deliberately, per run, per target.

This is affordable *now* and only now.
`modules/dast/` does not exist, so there is no existing DAST behaviour to break by setting these
defaults, and no operator can yet depend on a looser one.
That window closes the moment DAST-02 lands.

### The conservative defaults, and the one place they are enforced

| Default | Value when not affirmed | Enforced by |
|---|---|---|
| `--intensity` ceiling | `passive` (read what the target already sends back; nothing injected) | `scan.sh`, ahead of `lib/checks.sh`'s existing type-tag ceiling filter |
| requests per second | `4` (the `rules/RULE-FORMAT.md` §9.6.1 default, unchanged) | DAST-01's limiter, reading an already-clamped effective value |
| concurrent DAST requests | **not enforced by DAST-01** | nothing; see the row note below |
| per-run request budget | `5000`, clamped down from the §9.6.1 default of `20000` | DAST-01's budget counter, reading an already-clamped effective value |
| circuit breaker | 10 failures in a 60s window aborts the module | DAST-01's breaker |
| side-effecting checks | off (`--allow-intrusive` absent) | `lib/checks.sh`'s existing `checks_intrusive_keeps` filter |
| destructive payloads | none exist at any setting (`docs/DESIGN.md` §7.3) | the payload set itself |
| credential brute forcing | none exists at any setting (§7.4's "weak-key detection, not a cracking rig") | the vendored, capped list itself |
| bundled scan target | none, anywhere in a shipped file | DAST-35's lint |

**The concurrency row is a correction, and it is the row most worth reading twice.**
It previously read "`4`, enforced by DAST-01's limiter, same shared bucket that already defeats
`--jobs` multiplication", and that is not true of a token bucket.
A shared bucket bounds the request RATE; it does not bound how many requests are IN FLIGHT at once.
Against a slow target where each request takes seconds, a high `jobs` value yields exactly that many
simultaneous connections while the average rate stays under the ceiling, and nothing in DAST-01 clamps
`jobs` at all - `scan.sh` resolves it into `SCOURSH_JOBS` and no ceiling is applied anywhere.
Stating an unenforced number in an enforcement table is the failure mode this whole section exists to
avoid, so the row now says what is actually true.
**A real concurrency ceiling is a separate, unassigned piece of work**, not a line that can be added to
DAST-01's clamp: bounding simultaneous requests needs an in-flight counter taken before the transport
and released after it, at the same `lib/http.sh` chokepoint, plus a reclaim path for the slot a killed
worker never releases - which is a mutex-and-liveness design of the same weight as
`docs/FOUNDATION.md` tension 16's own lock reclaim, and it should be its own ticket rather than a
retrofit.
Until that ticket exists, the honest statement is the one in the table: rate is bounded, concurrency
is not, and the operator's `jobs` value is what decides how many connections a target sees at once.

The rate ceiling deliberately **equals the shipped default**, so an operator who never
edited `config/scanner.conf` sees no clamp at all and no warning; the clamp exists only to stop a
*raised* value applying to a host nobody vetted.
The budget's clamp is silent for the same reason, even though its ceiling and its schema default
differ: the value it refuses on an unedited install is the one the schema itself supplies, so warning
about it would be blaming the operator for a config they never wrote.
DAST-01 states the effective rate, budget and breaker numbers on one informational line per run
instead, and warns only when a value was actually raised past a limit.
The budget ceiling is the one number that diverges from the frozen schema default, and the arithmetic
is the argument: 20000 requests at 4/s is 83 minutes of sustained traffic, while 5000 is about 21
minutes and is still enough for a real passive assessment of a mid-size site.
That last clause matters, because the unaffirmed path has to stay genuinely useful.
A conservative default that makes the tool useless without an affirmation converts the affirmation
into something people click through to get any scan at all, which destroys the only thing it is worth.
This is a module-scoped ceiling on a *resolved* value, not a change to the schema default, so
`rules/RULE-FORMAT.md` §9.6.1 is untouched and `config/scanner.conf.example` changes only in a comment.

**The ceilings are enforced where the scope gate is enforced, and nowhere else.**
This is the single most important implementation fact in this section, and it was got wrong in review:
a ceiling that lives in `modules/dast/run.sh` binds only callers that came through `modules/dast/run.sh`.
`tests/e2e/dast-target-smoke.sh` already sends real HTTP to a live container without going near
`scan.sh` or any module, and says so in its own header (line 19: "runs instead is `lib/http.sh`'s
`http_request`/`http_gate_url` directly - the piece of it that does not require `scan.sh`'s CLI
parser"), calling `http_request GET "${DTT_URL}/rest/admin/application-version"`.
`docs/FOUNDATION.md` tension 19 puts the gate at `http_request` precisely because callers must not be
trusted to apply it, and a throughput ceiling has exactly the same property.
So the resolved rate and budget values that DAST-01's limiter reads are already clamped
before it sees them, and the clamp lives with the limiter in `lib/http.sh`, not in the module.
(`jobs` is not among them, per the concurrency row's note above: it is resolved and never clamped.)
Only the `--intensity` ceiling stays in `scan.sh`, because intensity is check *selection* and never
reaches the transport at all.

**How the affirmation reaches the limiter, and why it is not an environment variable.**
`scan.sh` writes the affirmation as a per-run record under the run directory at parse time, and the
clamp reads it from there.
An absent record means the conservative ceiling, which is what makes a caller that never went through
`scan.sh`'s parser - the smoke test, a future tool, an interactive `source lib/http.sh` - inherit the
safe value rather than an unbounded one.
It is deliberately **not** an environment variable: an env var is settable by anything that can start
the process, and the ceiling's entire job here is to bind callers whose command line nobody parsed.
One consequence worth stating rather than discovering: `tests/e2e/dast-target-smoke.sh` will run at 4
requests per second against its own loopback container, which is fine for what it asserts, and
DAST-28's burst probe cannot run there at all without an affirmation (see the DAST-28 amendment below).

### The identifying User-Agent

`lib/http.sh` today sends curl's default `User-Agent`, and the string `User-Agent` does not appear
anywhere in the repository.
A target owner who notices unusual traffic therefore has no way to identify the tool or reach the
operator, which is the practical difference between an owner who can send one email and an owner whose
only available response is to escalate.
DAST-31 makes every request carry `scoursh/<version> (+<contact>)`, composed in
`_http_transport_default` and nowhere else.
The `scoursh/<version>` product token is **never removable at any setting**.
An authorised scan has no need to be unidentifiable and an unauthorised one has every need, so a flag
whose only function is hiding the tool's identity is a flag for scanning something you do not own.
Expect it to be requested as WAF evasion; the refusal and its reason belong in the flag's own help
text, not in a review comment a year later.
The contact half is operator-configurable and an extra product token may be appended.

### The scope gate line, and why it is drawn exactly there

**No prompt, no affirmation, no flag, and no environment variable ever authorises a target.**
A host is scannable if and only if it has a record in `config/scope.conf` and every URL, including
every redirect hop, passes `http_gate_url`.
The guided mode of the next section may *offer to write a record*; it never answers the gate, and the
gate then re-reads the file and can still refuse.

Four reasons, each of which survives contact with the code, and each of which alone is sufficient.

1. **The gate is asked a different question, at a different time, about things the operator never
   named.**
   `config_scope_require` runs once at invocation against a target id; `http_gate_url` runs per URL at
   request time, including on every redirect `Location` - a string the *scanned site* chose, not the
   operator.
   DAST discovers URLs nobody typed: crawled links, spec-derived endpoints, redirect targets.
   An assertion made at invocation time about the operator's intent has no answer for a host the
   operator has never seen, so there is nothing for it to be an affirmation of.
2. **The gate's answer has to outlive the process.**
   A `config/scope.conf` record is diffable, greppable, reviewable and auditable a year later, and can
   be required by policy.
   "The operator pressed y at 03:14" is not that artifact.
3. **Every other control is defined relative to the in-scope host set.**
   The limiter's buckets, the breaker, `paranoid_allowlist_build`, the resolution deny list and curl's
   `--resolve` pinning all derive from it.
   Two controls derived from the same keystroke are one control.
4. **In this codebase specifically, a prompt-derived scope means `lib/http.sh` loading tuples from
   something other than a records file.**
   That is a second scope source, which is the raw-URL bypass `docs/DESIGN.md` §7 forbids by name,
   wearing a friendlier hat.

One argument that reads well and is **false**, so it is recorded here rather than repeated: it is not
true that "no process-startable state can reach the gate".
Two such variables already exist and neither is introduced by any ticket in this plan.
`lib/core.sh` sets `SCOURSH_INSTALL_ROOT` only when unset and exports it, and every `scope.conf` path
in the tree resolves through it, so `SCOURSH_INSTALL_ROOT=/tmp/mine ./scan.sh dast --target x` reads
`/tmp/mine/config/scope.conf`.
`SCOURSH_HTTP_RESOLVE` names a resolver function, and an exported bash function propagates into the
re-exec'd child.
Neither is a reason to change the gate and neither is in scope here, but a plan that oversells an
argument a reviewer can falsify in one command damages the three arguments that are sound.

**The gate is file-wide, not `--target`-scoped, and neither design noticed this.**
`http_scope_load` loads every record in `config/scope.conf` into one flat tuple array and
`http_scope_match` walks all of them with no reference to the run's `--target`; `config_scope_require`
only checks that the named id exists and does not narrow what the gate subsequently permits (verified
by reading `lib/http.sh`: `http_gate_url`'s `target` argument is used solely for the audit finding in
`_http_gate_audit`, never for matching).
Two consequences follow, and both belong in the plan rather than in a surprise later.
Writing a target authorises that host for **every future scoursh run on this machine**, not just the
run being configured, so the guided writer's confirmation screen has to say so.
And the affirmation is per-target while the gate is per-file, so an affirmation bounds the *limits* and
bounds nothing about *which hosts a run may reach*.
Whether `http_scope_match` should be narrowed to the run's own `--target` plus its `extra-host` entries
is a real design question this work surfaced; it is filed here deliberately and is **not** silently
decided by any ticket below.

### What the own-your-target affirmation actually accomplishes

Plainly, so no reader over-trusts a run that carries one:

**An affirmation is not a technical control.**
It is answered by the same person who typed the command, it stands between them and the result they
want, and it adds no independent knowledge to the system.
It stops nobody who is willing to lie, and this plan does not pretend otherwise.

What it does buy is three things, and the design spends its whole value on them:

- **An audit trail.** A specific, timestamped, host-named, operator-named self-assertion recorded in
  the run, alongside the exact numeric limits it raised.
- **A shift of responsibility.** After the affirmation, "I did not realise it would do that" is no
  longer available, because the prompt named the host, the resolved address, and the traffic.
- **Friction in the accidental case.** `--i-own-target` must equal `--target`, so a stale command, a
  shell alias or a copied CI config carrying an affirmation to a *different* host fails at exit 2
  rather than proceeding.

There is also a signposted bypass, and it must be stated rather than left to be inferred: an operator
who wants to scan something they do not own can hand-edit `config/scope.conf`, which needs no
affirmation at all.
The affirmation is a speed bump on a road with a marked detour.
What the design can do, and does, is decline to make the unauthorised case *convenient*: no bundled
demo host, no persisted affirmation, no `--user-agent` spoofing, no bulk target list, no free-text URL
box anywhere in the guided flow.

Three consequences of that honest valuation are load-bearing and easy to get backwards.

- **The affirmation is a key, not a switch.**
  It makes the higher settings *available*; it never itself selects one.
  Passing `--i-own-target` alone changes no limit.
  A single flag that raised intensity, removed the rate limit and enabled side-effecting checks
  together would hand the maximum blast radius to one token and undo the whole design.
- **It is never persisted.**
  No `scanner.conf` key meaning "always unrestricted", no dotfile, no cache, no environment variable,
  no "remember this target".
  A prompt answered once and remembered forever is not friction, it is a settings change with extra
  steps, and remembering it destroys all three of the things above.
  "Stop asking me every time" is the most predictable feature request this design will attract and the
  answer is no; that belongs in the plan as an explicit non-goal.
- **It appears in exactly one place.**
  A second affirmation - a cloud one, an intrusive-check one, a per-target reconfirm - devalues all of
  them and degrades the flow into the click-through it exists to prevent.
  Treat "add another confirmation" as a design smell requiring justification, not as a free safety
  improvement.

### What may be relaxed by the affirmation, and what may never be

| Default | Relaxable | Why |
|---|---|---|
| The scope gate (`config/scope.conf` + `http_gate_url` on every hop) | **no** | The four reasons above. The guided mode may offer to write a record; the gate then re-reads the file and can still refuse. |
| `--intensity` ceiling of `passive` | yes | This is the clean line: anything beyond reading what the target volunteers needs the affirmation. `safe` puts hundreds of 404s in someone's logs; `active` sends injection payloads. Neither is covered by permission to browse, and the Nmap finding is exactly a permission that covers one technique and excludes another. Costs nothing today, since `CHECKS_INTENSITY_DEFAULT` is already `passive`. |
| `circuit-breaker-window` (either bound) | **no** | Added by DAST-32's implementation, because this table did not say which way the window moves and both directions turn out to be refusals. The 60s FLOOR is not relaxable because a shorter window counts fewer failures towards the same threshold, so relaxing it reaches "the breaker never trips" by a different route than the disable switch the row above declines to offer. The 86400s MAXIMUM is not relaxable because it is not a safety limit at all - it is what keeps `now - window` inside 64-bit arithmetic, and no statement about who owns a host can make a wrapped integer mean what it says. |
| requests per second, DAST concurrency | yes | Rate limiting is a condition of authorisation against a host the authors cannot vet. Against a host that genuinely is the operator's, a 4/s cap has no safety content and the worst case is that they degrade their own lab. (Concurrency has no ceiling to relax yet: DAST-01 bounds rate only, per the concurrency row's note in "The conservative defaults" above. This row describes what an affirmation would relax once one exists.) |
| per-run request budget | **partially** | The number is raisable; the existence of a finite budget is not. The budget is what bounds the worst case of every *other* mistake in the tool - a crawler loop, a redirect cycle, a parameter-list bug. A control whose whole job is bounding unknown failures cannot be surrendered to an assertion about a known one. |
| circuit breaker | **partially** | Threshold raisable, disabling never offered, and the argument is that disabling has no upside even on your own host: a target returning sustained 5xx produces no useful findings, so continuing to hammer it buys nothing. There is no honest case for a prompt that removes it. |
| `--allow-intrusive` (live user enumeration, signup/reset probing, the burst probe) | **partially** | Requires the affirmation **and** its own separate opt-in, and must never be folded into the affirmation. Its blast radius escapes the target: §7.4 says these "create users and send messages", so the harmed parties are the target's *users*, and owning a host does not confer permission to do that to its users. |
| destructive payloads (`DROP`/`DELETE`, stacked writes, exfiltration) | **no** | Nothing to relax. `docs/DESIGN.md` §7.3's "prove a vuln exists via a signal, don't exploit it" is a frozen product invariant, not a default with a dial. The affirmation is unverified and the blast radius of a wrong answer is unbounded and irreversible, so no self-assertion can be worth it. Stating it as an invariant is what stops a future ticket adding `--allow-destructive` as a natural-looking extension of `--allow-intrusive`. |
| credential brute forcing | **no** | The feature does not exist and the affirmation does not create it. DAST-26's weak-HMAC list and DAST-12's wordlist are bounded vendored files; the affirmation may raise the rate those bounded passes run at, never their size. |
| SSRF/XXE sentinels (§7.3: in-scope hosts only, operator-declared sentinel) | **no** | The whole point of an SSRF probe is that the request is issued by the *target*, to a host of the payload's choosing. The operator's affirmation covers the target; it cannot cover `169.254.169.254` or an internal host the target can reach and the operator cannot see. The host that actually gets hit is not the one the affirmation named. |
| one-hop redirect handling with a full gate re-run on every `Location` | **no** | This is the SSRF control, not a courtesy, and the operator cannot affirm ownership of a host the scanned site named and they have never seen. |
| the `scoursh/<version>` User-Agent prefix | **partially** | The contact portion is configurable and an extra token may be appended. Replacing the prefix is never offered, for the reason in the User-Agent section above. |
| any bundled scan target or demo host | **no** | The research is unambiguous that no such convention exists, and any shipped list would be wrong the moment a host changed hands, went offline, or - as one prominent public demo instance already does - prohibited being used as a scan target. |
| the affirmation itself being remembered | **no** | Explicit non-goal, per the reasoning above. |

### New tickets

These are tier-0 work: DAST-31 and DAST-32 block every ticket that issues a request, exactly as
DAST-01 does, despite their numbers.

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| DAST-31 | Identifying `User-Agent` and operator contact on every request | `lib/http.sh` (shipped). Sequence after DAST-01 for merge order only: both edit the curl invocation in `_http_transport_default` and will conflict textually, not functionally. | Adds a `contact` key to the scanner-config schema (one row in `rules/RULE-FORMAT.md` §9.6.1, one arm in `lib/records.sh`'s schema table, one arm in `_scanner_default`/`_scanner_validate_value`) plus a `--contact` global flag resolved through `config_scanner_value`'s existing CLI > env > file > default chain. UA is `scoursh/<version> (+<contact>)`, or `scoursh/<version> (+<repo-url>; no operator contact configured)` when unset, passed via `curl -A` from `_http_transport_default` only. `--user-agent-suffix` appends an extra product token; the prefix is never replaceable, and the flag's help text says why. **Schema cost, checked rather than asserted:** an additive optional key trips `rules/RULE-FORMAT.md` §14 item 2 (`lib/records.sh` and `tests/lint-rules.sh` move together, both in this ticket) and none of items 1, 3 or 4 - no pack is rewritten, no check id changes, no fingerprint input changes, no SARIF `ruleId` changes - so the expectation is **no `format_version` bump**, confirmed against §14 in the ticket rather than assumed. Also prints one line at DAST run start when `contact` is unset, naming the config key; this is deliberately *not* a guided-mode question, because flow length is a budget. |
| DAST-32 | Conservative DAST ceilings at the chokepoint, and the `--i-own-target` affirmation | DAST-01 (the limiter, budget and breaker are what a ceiling clamps), `lib/checks.sh` (shipped), `lib/config.sh` (shipped) | The core safety ticket. Ceilings per the table above, applied to the **resolved** value at the `lib/http.sh` chokepoint (not in `modules/dast/`), with the affirmation carried as a per-run record rather than an environment variable - see "the one place they are enforced" above for both arguments. **Clamp policy, matching `lib/config.sh`'s own precedent** (`config_scanner_value` dies exit 2 for a bad CLI *or env* value and exit 4 for a bad file value, because the first two are the operator's own invocation): a **file or default** value above the ceiling is clamped down with one `log_warn` and a recorded delta, while an **explicit CLI or env** value above the ceiling is exit 2 naming `--i-own-target`. Clamping rather than refusing the file/default case is deliberate, so an operator is never pushed to affirm reflexively just to get any scan; refusing the explicit case is deliberate too, because quietly honouring a different number than the operator typed contradicts this codebase's own rule that the invocation is authoritative or fatal, never rewritten. `--i-own-target <id>` **must equal** `--target <id>` or the run is exit 2; valid on `dast` and `all`; a **key, not a switch** - it changes no limit by itself. `--allow-intrusive` is brought under it: on `dast`, and on `all` with a `--target`, `--allow-intrusive` without a matching `--i-own-target` is exit 2. The flag stays global in `_SCAN_FLAG_KIND` so `docs/DESIGN.md` §5's grammar block is not diverged from, and zero `intrusive`-tagged checks ship today (verified: the tag appears nowhere under `modules/` or `rules/`), so the first ticket that introduces an intrusive check *outside* DAST extends the affirmation vocabulary to cover it rather than inheriting a gap. Explicit non-goals to write into the plan: no persisted affirmation, no `--allow-destructive`, no removable budget, no disableable breaker. Also updates `config/scanner.conf.example`'s **comment** (never its values) so the `20000` budget does not read as the effective DAST value. |
| DAST-33 | Render the authorisation record into `run.json`, and close the same gap for `use_engines` | DAST-32 | A safety prompt that leaves no trace is theatre, and there is an already-shipped instance of exactly that gap: `scan.sh` calls `run_record use_engines ...`, which writes `reports/<run>/meta/use_engines`, but `report_run_json`'s `_meta_array`/`_meta_array_unique` block in `lib/report.sh` never renders it (verified: no `use_engines` key exists in that block, and both suites that cover it - `tests/suites/sast-semgrep.sh` and `tests/suites/iac-trivy.sh` - assert against the meta **file**, not `run.json`). The tool's only shipped audit flag is half-recorded today. Fix both in one change, since the ticket is already inside `report.sh`. Full field list and the reasoning for each is in "What is recorded, and where" below. |
| DAST-34 | State an unrestricted run in the report and on stderr | DAST-33 | One stderr line at run start when limits were relaxed, naming target, affirming operator, timestamp and the relaxations. Loud, once, not a wall. Plus a banner in the HTML and markdown reports and an entry in the limitations section `docs/DESIGN.md` §15 already requires. The reason is specific rather than decorative: an unrestricted run's **absence** of availability findings is not evidence, because a reader cannot tell whether "no throttling findings" means the target handles load or means the scanner was told to ignore its own limits - and DAST-28 makes that ambiguity concrete. §15's own framing applies: a scan that overstates coverage is worse than one that names its blind spots. The banner is plain text through the existing escaping path, since evidence is untrusted and the HTML report contains no `<script>` at all (tension 10). |
| DAST-35 (**landed**) | Lint: no shipped scope target, no bundled scan host | none; can land immediately | Landed in `tests/lint-shell.sh` (not `tests/lint-rules.sh` - see the landing note below for why), in the same one-exemption-with-a-stated-reason shape the tension-19 no-bypass check already uses: `config/` contains no `scope.conf`, only `scope.conf.example`; `scope.conf.example`'s `base-url` uses a reserved example domain; and no shipped script, rule or config file carries a scope-target record naming a resolvable third-party host. `tools/dast-test-target/scope.conf` is exempt **by path**, with its reason named - it is never installed as `config/scope.conf` and is loaded only by the opt-in smoke test, exactly as its own header and `docs/DAST-TEST-TARGET-AUTHORIZATION.md` already record. This exists because "a convenient example target" is a helpful-looking contribution that would silently become the built-in demo host the research findings rule out. |
| DAST-36 (**landed**) | Fold this posture into DAST-01 through DAST-30's own acceptance criteria | DAST-31, DAST-32 | Doc-only, no shell code. Restating the constraints inside each affected ticket rather than leaving them inherited by reference, because a ticket is implemented from its own acceptance criteria. Landed as "Conservative-posture criteria, restated per ticket" below: seven numbered clauses plus a per-ticket table that assigns clauses to every ticket in DAST-01..30, replacing a five-bullet form that covered only seven of them. The `docs/FOUNDATION.md` obligation this row used to carry - the stale step-5 gate sentence and the dangling "Status: blocked" cross-reference - was checked and found already discharged; see the "Doc-update process" note for the verification. |

**DAST-35 has landed, as its own three checks inside `tests/lint-shell.sh` rather than a new file or
`tests/lint-rules.sh`.**
`tests/lint-rules.sh` lints the RULE-FORMAT `*.rules`/record **syntax** itself (the frozen key/cardinality/
escaping grammar, `rules/RULE-FORMAT.md` §13's `E0xx` codes); DAST-35's three checks are a repository-wide
content-safety policy over what a `base-url`/`extra-host` **value** is allowed to name, which is the same
shape tension-19's own "no bypass" check already has, so it lands beside it rather than inventing a second
home. It needed one small, additive change to `tests/lint-shell.sh` itself: an optional first argument,
`SCAN_ROOT` (defaulting to `$ROOT`, exactly the convention `tests/lint-aws-readonly.sh` already
established), so its own meta-test can point the whole lint at a disposable fixture tree without ever
writing into the real `config`/`lib`/`modules`/`rules` trees - every existing check in the file inherits
this for free, since they all resolve their file lists relative to the now-overridable cwd.
Host extraction (`_dast35_host_of_url`/`_dast35_host_of_hostport`) and the reserved-range classifiers
(`_dast35_host_is_reserved_example_domain`/`_dast35_ipv4_is_reserved`/`_dast35_ipv6_is_reserved`) are a
bounded, self-contained regex reading of the record shape, not a general RFC 3986 parser and not a live
DNS lookup - an air-gapped lint cannot perform one, and the lint says so in its own header comment.
**One deliberate asymmetry, worth recording because it is not obvious from the RFC citations alone:**
loopback (`127.0.0.0/8`, `::1`) is excluded from the generic "safe" IP set that RFC 1918 private, RFC 3927
link-local (the `169.254.169.254` metadata sentinel), RFC 6598 CGN and RFC 5737 TEST-NET addresses sit in.
A private/link-local/TEST-NET literal means nothing without a specific network and is only ever exercised
as an SSRF-deny-list unit-test fixture in this repository; `127.0.0.1` means "whatever this operator's own
machine happens to be running" for every single installation, which is exactly the built-in-demo-host risk
this ticket exists to close - it is why `tools/dast-test-target/scope.conf` needed its own written
authorization record in the first place. A loopback target is therefore allowed **only** via that one
file's path exemption, never generically; `tests/suites/dast35-lint.sh` proves this both ways, including
a copy of the authorized file's exact byte content planted at a different path.
`tests/suites/dast35-lint.sh` is the meta-test (20 assertions): the clean tree, all three checks failing
on a planted violation and passing once it is fixed, an `extra-host` violation alongside a `base-url` one,
a reserved/non-routable literal (`169.254.169.254`) NOT tripping check 3, and the path exemption proven in
both directions. `tests/run-tests.sh`'s `SUITES` array now names it.

### Conservative-posture criteria, restated per ticket (owned by DAST-36)

DAST-31 through DAST-34 own the safety posture as *mechanism*.
This section folds that posture into DAST-01 through DAST-30 as *acceptance criteria*, because a
ticket is implemented from its own criteria and an inherited constraint is one nobody reads.
Nothing here is new policy.
Every clause restates a decision already made in "The conservative defaults, and the one place they
are enforced", in "What may be relaxed by the affirmation, and what may never be", or in
`docs/FOUNDATION.md` tension 19.

This section replaces an earlier five-bullet form that named only DAST-01, DAST-12, DAST-13,
DAST-14..25, DAST-26, DAST-28 and DAST-29.
A reader picking up DAST-02..11, DAST-27 or DAST-30 found no posture line for their own ticket and
had to reconstruct one from the central plan, which is exactly the failure this section exists to
close.

#### The seven clauses

Every DAST ticket restates the clauses marked for it in the per-ticket table below.
Restate them in the ticket's own acceptance criteria, by clause text, not by citing this section.

**P1 - one path to the network.**
Every request goes through `lib/http.sh`'s `http_request`.
No module opens a socket, invokes `curl`, or composes a request line of its own.
The single exception is a raw TLS handshake (`modules/dast/passive/tls.sh`), which goes through
`http_authorize_raw_connection` and spends a budget token exactly as a request does.

**P2 - the scope gate is the only authorisation.**
A host is reachable if and only if `config/scope.conf` carries a record for it and every URL,
including every redirect `Location`, passes `http_gate_url`.
No flag, prompt, affirmation or environment variable authorises a target.
A URL lifted off a scanned page is pre-checked before it is enqueued **and** still gated on the way
out; the pre-check is not the gate.

**P3 - the tool identifies itself.**
Every request carries `scoursh/<version> (+<contact>)`, composed in `_http_transport_default` and
nowhere else.
The `scoursh/<version>` product token is never removable at any setting.
A phase never composes, overrides or suppresses a `User-Agent`.

**P4 - limits are clamped before a phase sees them.**
The effective rate (4 req/s), per-run request budget (5000) and circuit breaker (10 failures in a
60s window) are resolved and clamped at the `lib/http.sh` chokepoint.
A phase reads the effective value.
A phase never reads `config_scanner_value` directly, never carries a budget of its own, and never
re-implements a limiter.
`--i-own-target` is a key, not a switch: it must equal `--target`, it is never persisted, and on its
own it changes no limit.
**Concurrency is not bounded today.**
Rate is capped; simultaneous connections are whatever `--jobs` produces.
Do not write a concurrency ceiling into any ticket's criteria until the in-flight-counter ticket
named in the gaps below exists.

**P5 - intensity is declared at the lowest tier that is true.**
`--intensity` defaults to `passive`, and anything above it additionally requires `--i-own-target`.
A phase's row in `modules/dast/engine.sh`'s `_DAST_PHASES` table carries the lowest tier its checks
actually need.
A row left at `active` for a phase that mutates nothing is dead code on every ordinary run - see the
DAST-30 landing note, where exactly that row had to move.

**P6 - detection, never exploitation.**
Prove a defect with a signal; do not exploit it.
No `DROP`/`DELETE`, no stacked writes, no data modification, and no exfiltration beyond the minimal
evidence that confirms the finding.
No credential brute forcing at any setting.
Any bounded vendored input - a wordlist, a weak-key list, a payload set - has a size no flag
changes; the affirmation may raise the rate a bounded pass runs at, never its size.

**P7 - a check that could not run says so.**
A skipped, inapplicable or ceiling-blocked check records a `coverage_gap`/`coverage_reduction`
naming the reason, and stays out of `checks_run`.
Silence is never allowed to render as a clean result.

#### Per-ticket restatement

| Ticket | Clauses to restate | Ticket-specific wording it must add |
|---|---|---|
| DAST-01 (limiter/budget/breaker) | P4 | The limiter, budget and breaker read an **effective** value DAST-32's clamp has already applied, and the clamp lives beside them in `lib/http.sh`, not in any module. If DAST-01 and DAST-32 stay separate tickets, DAST-01 must not ship a limiter reading `config_scanner_value` directly, or DAST-32 becomes a retrofit. |
| DAST-02 (`run.sh` dispatch) | P4, P5, P7 | Owns resolving `--target` against `scope.conf` and applying the `--intensity` gate before any phase is sourced. Its honesty roll-up keys on coverage (`checks_run`), never on "did a phase execute". |
| DAST-03 (`auth.sh`) | P1, P2, P3, P6, P7 | A credential never reaches `argv` and never touches disk raw. A redirect crossing origin drops the caller's headers and body. A failed authentication is a declared coverage reduction, not a non-zero exit. The live user-enumeration probe requires `--allow-intrusive` on top of the affirmation and is not implemented. |
| DAST-04 (`crawl.sh`) | P1, P2, P5, P7 | A specification contributes its paths, never its host. A form is inventoried, never submitted. The client-rendered (SPA) gap reaches `run.json`, `report.md` and `report.html`, not only prose. |
| DAST-05..DAST-11 and DAST-30 (passive) | P1, P2, P3, P5, P7 | Passive means no mutation of target state, not no traffic. GET/HEAD only, one request per distinct route, no request body, no submitted form, no invented URL. A discovered sub-resource is classified from markup, never fetched. Every family no fetched response was applicable to is recorded and kept out of `checks_run`. |
| DAST-12 (content discovery), DAST-13 (method enumeration) | P2, P4, P5, P6, P7 | Both are `safe`-intensity and therefore unreachable without an affirmation. The wordlist is a bounded vendored file whose size no flag changes, and no wordlist ships in this repository. DAST-13 establishes method acceptance without exercising it: only `OPTIONS` and `TRACE` are ever sent. |
| DAST-14..DAST-25 and DAST-27 (injection and API probes) | P1, P2, P4, P5, P6, P7 | Detection-only. No data modification. No exfiltration beyond minimal confirming evidence. A time-based payload's sleep is clamped before substitution, so a probe can never become a denial of service. Whether a probe has anything to do is decided from the inventory, never by probing to find out. **DAST-20 additionally**: SSRF/XXE sentinels are in-scope-only and no affirmation widens them, because the host that gets hit is chosen by the target rather than named by the operator. |
| DAST-26 (`jwt.sh`) | P4, P6 | The weak-secret list is bounded and vendored. No flag expands it. This is weak-key detection, not a cracking rig. |
| DAST-28 (`ratelimit.sh`) | P2, P4, P5, P6, P7 | The one behavioural amendment in this section, and it closes a silent false negative neither design resolved. Under the conservative ceilings a burst probe establishes neither a positive nor a true negative: it would report "no missing-throttling finding" from a scanner that was itself throttled below any plausible threshold. **On an unaffirmed run DAST-28 does not execute**, and emits a `coverage_gap` naming the scanner's own rate ceiling as the reason, using the mechanism `lib/report.sh` already ships. The affirmation is additionally gated on the *effective* rate, because an affirmed run left at 4/s has the same defect one step further in. The probe draws down `lib/http.sh`'s own budget counter and spends at most half of what remains; it never carries a budget of its own. |
| DAST-29 (`authz.sh`) | P1, P4, P6, P7 | Read-only object references only. Read-only is enforced at candidate selection, so no code path can reach a mutating method. Every skip path returns 0 with a recorded reason, because silence here reads as "this application enforces object-level authorization". |

#### How this applies to the tickets that have already landed

Most of DAST-01 through DAST-30 landed before this section existed.
For those, the table is a **review checklist**, not a change order.
Where a landed module already satisfies a clause, nothing happens.
Where a landed module contradicts one, file it as its own ticket and cite the clause; do not amend
the module under a doc-only ticket.

#### Gaps this section does not close

Named rather than guessed, per `docs/DESIGN.md` §15.

1. **Concurrency has no ceiling.**
   The concurrency row in "The conservative defaults" says so, and the paragraph beneath it calls the
   fix a separate, unassigned piece of work.
   P4 states the gap instead of promising a limit; do not let a ticket's criteria imply otherwise.
2. **The affirmation is not a technical control.**
   It bounds *limits*, never *which hosts a run may reach* - the gate is file-wide, not
   `--target`-scoped.
   Whether `http_scope_match` should be narrowed to the run's own target is a real open design
   question and is deliberately not decided here.
3. **`SCOURSH_DAST_ENDPOINTS` is empty on a first run.**
   Any ticket whose criteria assume the export is populated is wrong; the fallback is
   `$SCOURSH_RUN_DIR/inventory/endpoints.json`.
   The fix in `modules/dast/run.sh` is filed separately.
4. **DAST-18 and DAST-20 through DAST-25 are unlanded.**
   Their criteria are the ones this section can still shape prospectively rather than
   retrospectively.

## Dependency-ordered sub-ticket list

Ordering follows `docs/DESIGN.md` §13 step 5's own sequence (`lib/http.sh` -> `auth.sh` -> `crawl.sh` ->
passive -> safe-active -> injection, one file at a time -> §7.4 auth/API/authz), refined to script
granularity using §7's own script list. Every ticket also authors its own `modules/dast/**/checks.rules`
script-check record (`rules/RULE-FORMAT.md` §9.5, `coverage-scope: target`) alongside its script, since
that is what `lib/checks.sh`'s registry loader and tension 12's coverage tracking need to see it at all.

### Tier 0 - shared infrastructure (blocks all of tiers 1-5)

DAST-31 (the identifying `User-Agent`) and DAST-32 (the conservative ceilings and the
`--i-own-target` affirmation) are also tier 0 and block the same set, despite their numbers.
They are specified in "Safety defaults and authorisation" above rather than restated here.

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| DAST-01 | Wire the tension-16 rate limiter, request budget, and circuit breaker into `http_request` | `lib/http.sh` (shipped), `lib/core.sh` mkdir-mutex + scratch-dir primitives (shipped, step 1) | Token-bucket limiter, per-run request budget, and breaker state live under the run scratch dir per tension 16's already-frozen design; this ticket implements the hook, not the mutex mechanism (that part is already built). Nothing below issues real HTTP traffic until this lands - `--jobs` must not multiply the request rate. |
| DAST-02 | `modules/dast/run.sh` - `scan_dispatch dast` entry point + target/intensity orchestration skeleton | DAST-01, `lib/checks.sh` registry loader (shipped, step 2), `lib/config.sh`/`config/scope.conf` gate (shipped) | Mirrors `modules/sast/run.sh`/`engine.sh`'s split: resolves `--target`(s) against `scope.conf`, applies `--intensity` (`passive`/`safe`/`active`), loads `modules/dast/**/checks.rules` via `checks_registry_load dast dast`, and calls each phase below in order once that phase's script exists. Owns writing DAST's `coverage-scope: target` cells (§9.5.1) and reading `reports/<run>/inventory/{endpoints,parameters}.json` (tension 21) - tolerating both files being absent, exactly like SAST's dispatch was a no-op before 3a. |

### Tier 1 - session and surface discovery (blocks tiers 2-5)

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| DAST-03 **(landed)** | `auth.sh` (§7.0) - authentication & session acquisition | DAST-01, DAST-02, `config/auth.conf` schema (already frozen, `rules/RULE-FORMAT.md` §9.6.2) | Static bearer/API key, form login, OAuth2/OIDC password/client-credentials grant, Cognito-style SRP. Session store (cookie jar + token cache) in the run scratch dir, perms `600`. Transparent re-auth on `401`, else the authenticated checks are marked `skipped` with a reason. Multi-identity (labelled A/B) for DAST-29 (`authz.sh`). The config-derived half of the §7.4 closing paragraph's user-enumeration checks (detection via config, not a live probe) belongs here too; the live `--allow-intrusive` opt-in variant is a small follow-up once this ticket's session modes exist, not counted separately below. |
| DAST-04 (**landed**) | `crawl.sh` (§7.5) - crawling, parameter & spec discovery | DAST-01, DAST-02; optionally DAST-03 for an authenticated crawl pass (unauthenticated static crawl does not need it) | Static crawl (links/forms/`action`s/input names, depth-limited, scope-gated); spec ingestion (OpenAPI/Swagger, GraphQL schema, Postman, HAR) as the preferred, most-complete input; merges any `reports/<run>/inventory/endpoints.json` another module already wrote (tension 21 - SAST route extraction, `apigw.sh`), tolerating its absence with a `coverage_gap` record via the mechanism `lib/report.sh` already ships (step 1). Writes `endpoints.json` + `parameters.json`, which every ticket below consumes. **Must implement the SPA/client-rendered-app limitation as a stated `coverage_gap`, not a fix**: see "SPA/client-rendered limitation" below - this ticket's acceptance criteria should require that gap to actually appear in `run.json`/the report when no spec/HAR is supplied, not just be true in prose. |

**DAST-04 has landed.**  It ships `modules/dast/crawl.sh` (the phase script `dast_run_phase`
sources, which orchestrates the four inputs and writes the two artifacts) and
`modules/dast/crawl_engine.sh` (the pure, testable half: the HTML link/form extractors, the JSON and
YAML front-ends, the four specification parsers, and the inventory reader/writer), plus
`docs/INVENTORY-FORMAT.md`, which is the **normative shape of the two files every ticket in tiers 2
through 5 reads** - treat it as a contract and read it before consuming either file.

Five things about it are easy to get backwards, and each is pinned by a test naming the reading it
fails under (`tests/suites/dast-crawl.sh`, 146 assertions, no network and no Docker):

- **A discovered link is pre-checked against the scope gate BEFORE it is enqueued, and that
  pre-check is not the gate.**  `http_request` gates fatally - an out-of-scope URL is a caller bug
  and exits 3 - which is right for a URL the operator configured and exactly wrong for one lifted off
  a scanned page: handing a crawled link straight to `http_request` lets any site stop the operator's
  whole run by linking to a search engine.  `_crawl_in_scope` therefore decides only whether a URL is
  worth ENQUEUEING; every URL that survives is still requested through `http_request`, which applies
  the real gate again on the way out and on every redirect hop.  Deleting the pre-check would make the
  crawler fragile; deleting the `http_request` call would make it unsafe, and only one of those two
  is a gate.  Both halves are asserted on a REQUEST LOG rather than on a return value.
- **A specification contributes its PATHS, never its HOST.**  An OpenAPI `servers[].url`, a Postman
  URL and a HAR entry each name a host, routinely a production one.  Taking it would turn
  `config/discovery.conf` into a way past the scope gate, so only the path is used and the host is
  always the operator's own `--target`.  The server URL's own PATH PREFIX *is* honoured (and
  `basePath` is the Swagger 2 spelling of it), because that is a fact about where the API is mounted
  rather than about who to talk to.
- **The client-rendered gap is recorded only when no specification closed it.**  Printing it
  unconditionally would make asserting its presence prove nothing, so the suite asserts it present
  without a spec AND absent with one.  It reaches `run.json`, `report.md` and `report.html` - not
  just prose - which is this ticket's own acceptance criterion.
- **A form is inventoried, never submitted.**  Its `action`, its method and its input names become an
  endpoint and parameters; no POST is sent.  Submitting one is a state change, forbidden at the
  passive tier `docs/DESIGN.md` §7.1 defines.
- **A query string is stripped from the endpoint URL and its keys recorded as parameters instead.**
  Keeping the query would turn a paginated listing into fifty endpoints and make every later check
  re-test one handler fifty times.

Everything the crawl cannot see is recorded rather than absorbed: an unusable specification, an
unreachable URL, a depth or page ceiling that bit, a truncated inventory, and the anonymous-crawl
case all emit their own `coverage_gap`/`coverage_reduction`.  `tests/e2e/dast-crawl-target.sh` is the
opt-in (Docker-requiring) proof against the real local Juice Shop container, and it is worth reading
for what it asserts: a crawl of a real Angular application found **13 endpoints and 0 parameters**,
all static assets plus the root, and the run SAID SO - `spa_shaped=1` was measured off the target's
own root document.  A thin result there is the pass condition, not a defect; supplying a
specification to the same target took it to 16.  That file is also where the scope gate is proven
live: the target's own root document links to a third-party font CDN, and the request log shows no
request was ever made to it.

**What DAST-04 deliberately did NOT build**, so the boundary is not rediscovered: the authenticated
crawl pass.  `crawl.sh` runs unauthenticated and records a `coverage_gap` saying so.  DAST-03 owns
the session and was built in parallel with this ticket, so nothing here was stubbed against it; both
have now landed, which means **the authenticated crawl pass is a real, available follow-up rather
than a blocked one** - `crawl.sh` still does not take a session, and until something wires
`dast_auth_state`'s session into `_crawl_fetch`, a crawl of an authenticated application sees only
its public surface and says exactly that.  There is also no JavaScript execution and no headless
browser, now or later - that is the stated limitation above, not a gap awaiting a ticket.

#### What DAST-03 actually shipped, and the five things about it that are easy to get backwards

`modules/dast/auth_engine.sh` (the pure library: config load, the session store, every mode, re-auth,
and the config-derived enumeration check) plus `modules/dast/auth.sh` (the phase script
`dast_run_phase` sources), in the `engine.sh`/`run.sh` split `modules/sast/` established.
`tests/suites/dast-auth.sh` is the mocked suite; `tests/e2e/dast-auth-live.sh` is the opt-in
Docker-requiring proof against the authorized local target, in the same shape and for the same reason
as `tests/e2e/dast-target-smoke.sh`.
The public surface later tickets consume is `dast_auth_load`, `dast_auth_labels_set`,
`dast_auth_acquire`, `dast_auth_apply`, `dast_auth_request`, `dast_auth_state`,
`dast_auth_skip_reason` and `dast_auth_authenticated_labels_set`.

- **`lib/http.sh` grew a per-request context, and that is where it had to go.**  Before this ticket
  `http_request` could send neither a header nor a body and discarded the response - which is
  everything §7.0 needs and nothing a reachability probe does.  Sections 9a and 12 of that file now
  carry `http_request_header` / `http_request_body` / `http_request_capture`.  Putting it in the module
  instead would have been the second path to the network tension 19 exists to make impossible, and it
  would have skipped the limiter, the budget, the breaker and the ceilings that all hang off the
  chokepoint.  **A credential reaches curl over STDIN, as a `curl -K -` config**: there is no `-H
  @file` and no stdin-header option, so the alternatives really were argv (visible in `ps`) or a
  scratch file, and neither satisfies tension 9.  `tests/suites/http.sh` proves it against a stub
  `curl` that dumps its own `argv`.
- **The context is CONSUMED at entry, not cleared at exit, and a redirect drops it.**  A credential
  left attached after a gate refusal or an opened breaker would ride along on the next request.  A
  redirect crossing ORIGIN drops the caller's headers and body even when both origins are in
  `config/scope.conf`: the gate answers "may this tool talk to that host", never "does this credential
  belong to it".  A 301/302 after a non-GET is re-issued as GET with the body dropped (RFC 7231
  §6.4.3), because re-POSTing a credential to a path the *scanned target* chose is exactly what a
  login flow must not do; 307/308 are left alone.
- **The `form` mode probes at most three body shapes, and the frozen schema is what forced it.**
  §9.6.2 gives `form` a `login-path`, a `username` and a credential, and names no body encoding and no
  field names, so an implementation must pick - and picking one would work against classic HTML form
  logins or against JSON login APIs but never both.  Order: urlencoded `username=/password=`, then
  JSON `{"email":..}`, then JSON `{"username":..}`; first to yield a session wins; the winner is
  persisted so a re-auth replays it and never probes again.  Three attempts is a real cost against an
  account lockout policy, which is why it is bounded and never repeated.  A `login-body-shape` key
  would be the better answer and is a REGISTER change, not something to add here.
- **`srp` accepts a pre-obtained token; it does not compute the handshake.**  `docs/DESIGN.md` §7.0
  offers the implementer both, and a pure-shell SRP-6a is modular exponentiation over a 3072-bit group
  written in bash arithmetic - unverifiable crypto in a language with no way to test it.  E074 says so
  at config-load time, and the run records `srp_handshake_not_computed`, so nobody reads `mode: srp` as
  evidence the provider's SRP exchange was exercised.
- **A failed authentication is a DECLARED coverage reduction, not exit 5.**  `docs/DESIGN.md` §7.0's
  own wording is "mark the authenticated checks `skipped` with a clear reason", which is the vocabulary
  of `docs/FOUNDATION.md` tension 14's declared rows ("a check skipped for an absent `requires-cmd` or
  `requires-config`") rather than its unplanned ones: a session that could not be obtained makes the
  authenticated checks' required input absent, exactly as a missing `config/auth.conf` does.  The run
  is not abandoned; `dast_auth_state` returns `failed` for the rest of it and `dast_auth_skip_reason`
  is the sentence every dependent check must state.

Two smaller things this ticket had to land with it, because the first phase script is what made them
true:

- **E073 and E074 are now enforced.**  Both error codes were reserved in `rules/RULE-FORMAT.md` §13 and
  neither had an implementation.  E074's mode-to-required-keys table lives in `lib/records.sh` (one
  copy, which `modules/dast/auth_engine.sh` consumes rather than restating), and E073 is checked at
  runtime as well as by the linter - the file whose permissions matter is the operator's own, and a
  lint that ran in this repository has said nothing about it.  A `secret-file` is held to the same
  600 requirement as `config/auth.conf` itself.
- **`modules/dast/run.sh`'s honesty roll-up now keys on COVERAGE, not on execution.**  DAST-02 could
  ask "did any phase run", because none existed and the two questions had one answer.  `auth.sh` runs
  on every passive run and, without `--authed`, covers nothing - so "a phase ran" would have started
  reading as coverage on exactly the run that has none.  The roll-up counts `checks_run` instead, which
  is the mechanism `modules/sast/`, `modules/iac/` and every `modules/sca/` engine already use, and it
  gained a third reason (`no_check_covered_by_any_phase`) alongside the two DAST-02 shipped.

**What DAST-03 deliberately did NOT build**, so the boundary is not rediscovered: the LIVE
user-enumeration probe.  §7.4's closing paragraph splits that check in two, and only the config-derived
half - which reads the authentication responses the run already received and sends nothing - is here.
The live half submits an identifier the operator did not configure, which on a real identity provider
creates accounts and sends messages, so it needs `--allow-intrusive`; a run given that flag today
records `live_enumeration_probe_not_implemented` rather than letting an absent finding read as a clean
result.  Also not built, and belonging to their own tickets: an authenticated crawl pass (DAST-04) and
any consumer of the two-identity plumbing (DAST-29).

### Tier 2 - passive checks (§7.1, 7 scripts, `modules/dast/passive/*.sh`)

Each is independently testable against one recorded HTTP response (`docs/DESIGN.md` §7.1's own "one file
per family" framing) and each is a peer of the other six - no ordering constraint among DAST-05..DAST-11,
only that all of them come after DAST-04 (they need the endpoint list) and DAST-01/02.

| # | Ticket | Extra notes beyond DAST-01/02/04 |
|---|---|---|
| DAST-05 **(landed)** | `passive/headers.sh` | CSP, HSTS, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, "recommended headers not set" roll-up. See the landing note below the tier-2 table. |
| DAST-06 **(landed)** | `passive/cookies.sh` | `Secure`/`HttpOnly`/`SameSite` per cookie. See the landing note below the tier-2 table. |
| DAST-07 **(landed)** | `passive/tls.sh` | Shells out to `openssl s_client`; the one documented exception to "every network call goes through `lib/http.sh`" (`docs/FOUNDATION.md` tension 19's neighbourhood notes this). Sequence close to DAST-30 (`transport.sh`), which complements it - not a hard code dependency, just worth landing in the same review window for a coherent report section. See the landing note below the tier-2 table. |
| DAST-08 **(landed)** | `passive/cors.sh` | Origin-reflection probe. Landing note below. It created `modules/dast/passive/` and `modules/dast/passive/checks.rules`, the shared tier-2 script-check registry every other ticket in this table appends its own records to. |
| DAST-09 **(landed)** | `passive/banner.sh` | Framework/version disclosure matched against **`data/versions.db`**, seeded into its own `modules/dast/passive/checks-banner.rules` (tension 29's per-owner split was already in effect for its peers by the time it landed). The writer side is no longer a forward dependency: `tools/vendor-engines.sh advisories` landed ahead of step 5 and writes `data/versions.db` by the same call that writes `data/advisories.db` (tension 25). `data/versions.db` is gitignored and absent by default in every checkout (an earlier accidental commit of it was reverted); populating one is an operator action on a networked box, never part of a scan. This ticket ships the matching logic, `docs/VERSIONS-DB.md`'s format and refresh procedure, and degrades gracefully (that sub-check alone becomes a recorded reason, never an error) when the list is missing or carries no `banner` row - the state of a fresh clone. See the landing note below the tier-2 table. |
| DAST-10 **(landed)** | `passive/leakage.sh` | Verbose-error/stack-trace disclosure, upstream proxy header leakage, email disclosure, client-config leakage in served JS, CDN/third-party origin detection. Its "API key found in served JS" output is a later correlation input for DAST-27 (`graphql.sh`) at the derived-finding layer (tension 6), not a code dependency. See the landing note below the tier-2 table. |
| DAST-11 **(landed)** | `passive/markup.sh` | Missing SRI, reverse tabnabbing, insecure external frame, CSRF-token absence in state-changing forms. See the landing note below the tier-2 table. |

#### What DAST-05 (`passive/headers.sh`) shipped, and the five things about it that are easy to get backwards

**DAST-05 (`passive/headers.sh`) has landed - a tier-2 check, built in parallel with its peer
DAST-06, which reached `dev` first and is what actually created `modules/dast/passive/`.**
It ships four files: `modules/dast/passive/headers_engine.sh` (the pure half - the response-header
reader, the CSP/HSTS/Referrer-Policy parsers, the endpoint chooser),
`modules/dast/passive/headers.sh` (the phase script `dast_run_phase` sources),
`modules/dast/passive/checks.rules` (eleven `DAST-HDR-*` script checks, all tagged `passive`), and
`modules/dast/passive/recommended-headers.txt` (the vendored, operator-editable roll-up list).
`tests/suites/dast-headers.sh` is the proof: 153 assertions, no network, no Docker, driven entirely
from recorded response heads replayed into `lib/http.sh`'s own capture sink.

Eight decisions in it are easy to get backwards; each is pinned by a test naming the reading it fails
under, and four of them were confirmed by deliberately breaking the implementation and watching the
suite go red.

- **Only the FINAL hop's headers count, which is why the reader is not a `grep`.**
  `http_request_capture`'s header sink ACCUMULATES every redirect hop by design (DAST-03 needed that
  for a login's `Set-Cookie`), so a whole-file match for `^strict-transport-security:` happily reads
  the REDIRECT's header and reports it as the delivered page's - exactly backwards for the one header
  whose absence on the final response is the finding.  `hdr_parse_capture` resets on every
  `HTTP/x.y NNN` status line.  Measured: with the reset removed, two assertions go red.
- **The file is named `headers_engine.sh`, not `passive_engine.sh`.**  DAST-06..DAST-11 are peers
  being built in parallel, and a tier-wide engine is shared scaffolding three tickets each believe
  they own.  A later ticket that needs the same response-header reader should LIFT it into a shared
  `passive/response_engine.sh` deliberately, with this suite moving with it.
  **That lift has since landed**, once six files depended on the reader: it lives in
  `modules/dast/passive/response_engine.sh` (a leaf that sources nothing) and its unit cases moved
  to `tests/suites/dast-response-engine.sh`.  `headers_engine.sh` keeps the CSP/HSTS/Referrer
  parsers, the recommended-header loader and `hdr_endpoints_load`, and sources the reader like every
  other consumer.  The **endpoint chooser** was deliberately NOT part of it and its own lift is
  still open - see the DAST-11 note below.
- **`modules/dast/passive/checks.rules` IS shared ground, and that is forced rather than chosen.**
  `rules/RULE-FORMAT.md` §9's path table gives the §9.5 schema to "any file named `checks.rules`, at
  any depth" and makes every other path `E070`, so a per-ticket `headers-checks.rules` is not a legal
  record file.  The file is append-only between peers; a conflict in it is resolved by keeping BOTH
  blocks, never by choosing a side.
- **One finding per check per target, not one per endpoint.**  A header is configured once for an
  application, so the per-endpoint shape reports one misconfiguration ten times.  Each check
  accumulates and emits once, located at the first endpoint in a DETERMINISTIC order (the operator's
  own `base-url` first, then the inventory's paths `LC_ALL=C`-sorted), with "observed on N of M
  responses" in the evidence.  The determinism is what keeps the fingerprint from churning when the
  crawl reorders.
- **The eleven ids exist because the DAST fingerprint has no component naming the defect.**
  (target, method, path_template, param_location, param_name) is the whole location profile, so a
  single `DAST-HDR-MISCONFIG-01` would make a missing CSP and a weak HSTS on one page collide and
  dedupe to one finding.  HSTS is three ids for the reason §7.1 asks for them separately: missing,
  weak and malformed are three different conversations, and only the third means "you configured it
  and got nothing for it".
- **Four false-positive guards that a naive implementation gets wrong**, each with a control fixture:
  `'unsafe-inline'` beside a nonce or hash is IGNORED by every CSP2+ browser and is not flagged;
  `data:` in `img-src` is ordinary and only script/object/default context is flagged; a wildcard in a
  source's PATH is not a domain wildcard; and `Referrer-Policy` is the LAST RECOGNISED token, so
  `unsafe-url, strict-origin-when-cross-origin` is not a finding.  Conversely `frame-ancestors *` is
  flagged even though the directive is present, because it permits every origin AND overrides an
  `X-Frame-Options: DENY` sent beside it.
- **Applicability is tracked per check, and an inapplicable check is NOT in `checks_run`.**  HSTS is
  not evaluated on a plaintext response at all (RFC 6797 §7.2 has the browser ignore it); CSP-absence
  and framing are document-only, while nosniff is not.  A run that only ever saw plaintext records
  `headers_check_not_applicable` naming the uncovered ids rather than reporting them as tested.
- **The roll-up is configurable through a vendored data file plus an environment seam
  (`SCOURSH_DAST_RECOMMENDED_HEADERS_FILE`), not a `config/scanner.conf` key.**  §9.6.1's key set is
  frozen, so a key moves `lib/records.sh` and `tests/lint-rules.sh` together (§14 item 2) and would
  widen this ticket into a format change six peers then rebase onto.  A `config/scanner.conf` key
  remains the better long-term home and is filed separately.  A name that already has its own check id
  is dropped from the operator's list, with a `notes` record saying which - reporting one absence
  twice helps nobody.

**One pre-existing defect this ticket found and did NOT fix here.**
`modules/dast/run.sh` calls `dast_inventory_read` and exports `SCOURSH_DAST_ENDPOINTS` /
`SCOURSH_DAST_PARAMETERS` BEFORE the phase loop starts, but `crawl.sh` writes
`reports/<run>/inventory/{endpoints,parameters}.json` several phases later in that same loop.  On a
first run - the ordinary case - every consumer that trusts the export alone therefore sees an EMPTY
inventory on exactly the run that has just discovered the surface, and
`modules/dast/active/inject_engine.sh`'s `inject_inventory_load` does trust it.  `headers.sh` falls
back to `$SCOURSH_RUN_DIR/inventory/endpoints.json` for itself and pins that fallback with a test; the
export itself belongs to `modules/dast/run.sh`, which six peer tickets are editing around, so it is
filed as its own ticket rather than changed here.

#### What DAST-06 (`passive/cookies.sh`) shipped, and the six things about it that are easy to get backwards

**DAST-06 has landed, and it is the first tier-2 passive check.**
It ships `modules/dast/passive/cookie_engine.sh` (the pure `Set-Cookie` parser and attribute
analyser), `modules/dast/passive/cookies.sh` (the phase script `dast_run_phase` sources),
`modules/dast/passive/checks.rules` (the §7.1 script-check registry, four records), and
`tests/suites/dast-cookies.sh` (107 assertions, registered in `tests/run-tests.sh`, driven entirely
from recorded responses through a stubbed transport - no network, no Docker).
The engine/phase split is `modules/sast/`'s, reused verbatim, exactly as `auth_engine.sh` + `auth.sh`
and `inject_engine.sh` + `sqli.sh` already do.

- **A `Set-Cookie` header value is NEVER split on a comma, and that is the hazard with the highest
  cost.** The generic RFC 7230 "a comma separates list members" rule is correct for `Accept` and
  specifically wrong here (RFC 6265 §3), because `Expires=Wed, 09 Jun 2021 10:18:14 GMT` carries a
  comma *inside one attribute*. Under the split, one correctly-flagged cookie becomes two: the real
  one loses every attribute after the date and is reported with three findings it does not deserve,
  and a phantom cookie is invented out of the expiry date. Measured, not asserted: a comma-splitting
  extractor was written and the suite went red in five places, at the extraction layer and end to end.
- **A `;` inside a quoted cookie-value does not split it either, and the naive reading here fails in
  the direction that reads as a pass.** RFC 6265 §4.1.1 allows `DQUOTE *cookie-octet DQUOTE`, so
  `pref="light; Secure; dark"; HttpOnly` is one cookie with no `Secure` attribute - but a naive `;`
  split sees the quoted word `Secure` as an attribute and reports a cookie that IS missing `Secure`
  as having it. A false negative, not a false positive. Also measured: the naive splitter turns two
  assertions red, one unit and one end to end.
- **`SameSite` ABSENT and `SameSite` EXPLICITLY WEAK are two check ids, not one check with two
  messages.** Browsers do not agree on what an absent attribute means (Chromium applies `Lax`; other
  engines have shipped both `Lax` and no restriction), so absence is a policy the *site did not
  choose*; an explicit `SameSite=None` is one it did. `check_id` is a fingerprint component, so a
  single id would make those two states one finding whose meaning flips between runs. An
  unrecognised value (`SameSite=Bogus`, or an empty `SameSite=`) is a third parser state that maps
  to the WEAK id and quotes the value verbatim - folding it into `absent` would tell the operator
  the server stated no policy when it stated an unusable one, and so recommend the wrong fix.
- **`Secure` and `HttpOnly` are set by the attribute's PRESENCE, never its value** (RFC 6265 §5.2.5
  and §5.2.6 both discard the attribute-value), so `HttpOnly=false` is an HttpOnly cookie in every
  browser. Reading the value reports a flag as missing on a cookie that has it.
- **Only `GET` endpoints are requested.** §7.1's own first sentence is "No mutation of state", so a
  `POST`/`PUT`/`PATCH`/`DELETE` endpoint in the inventory is not dialled - which costs real coverage,
  because a login POST is exactly where the session cookie is usually set. That omission is a
  recorded `coverage_reduction` (`cookies_non_get_endpoints_not_dialled`), never a silent skip; so is
  an unauthenticated-only pass (`cookies_unauthenticated_only`), for the same reason.
- **The endpoint walk is SORTED under `LC_ALL=C`, and that is not cosmetic.** `inject_inventory_load`
  returns the endpoints in a bash *associative* array, whose iteration order is hash order. With a
  per-phase cap (`SCOURSH_DAST_COOKIE_MAX_ENDPOINTS`, default 25) an unsorted walk would make *which*
  endpoints a capped run inspects depend on hash order, so two runs over one surface could produce
  different findings - the opposite of this repository's byte-reproducible-output property. Pinned by
  a case that runs the capped phase twice and compares the request logs.

**What DAST-06 deliberately did not build.** It writes no header reader, no inventory reader and no
request composer: DAST-05..DAST-11 are peers being built in parallel, so this ticket added nothing
another passive ticket also needs. The endpoint inventory is read through `inject_inventory_load`
(`modules/dast/active/inject_engine.sh`), the shipped reader for that frozen artifact, rather than a
second one - which is that file's own stated reason for existing. The live user-enumeration probe,
`Domain`-scope analysis, cookie-prefix (`__Host-`/`__Secure-`) conformance and cookie-value entropy
are all out of scope and unclaimed by any ticket.

**One correction it surfaced but did not make, filed instead.** `modules/dast/run.sh` calls
`dast_inventory_read` ONCE, before the phase loop, and exports `SCOURSH_DAST_ENDPOINTS` from what it
found *then* - which on a fresh run is nothing, because `crawl.sh` is itself a phase and has not run
yet. It writes `reports/<run>/inventory/endpoints.json` a few phases later in the same loop and
nothing re-reads it, so any consumer trusting the exported variable alone sees an empty surface on
precisely the ordinary run. `passive/cookies.sh` works around it locally (it falls back to
`$SCOURSH_RUN_DIR/inventory/endpoints.json`, the same artifact by the same path, read after the
producer wrote it) and says so in its own header. The general fix belongs to `modules/dast/run.sh`
and affects every inventory consumer - `active/sqli.sh` reads the exported variable alone today - so
it is filed as its own ticket rather than widened into this one.

#### What DAST-10 (`passive/leakage.sh`) shipped, and why every family is defined by what it refuses

**DAST-10 has landed - the third tier-2 check, and the first whose whole design problem is FALSE
POSITIVES rather than detection.**
It ships `modules/dast/passive/leakage_engine.sh` (the pure half: the body reader, the five family
decisions, the endpoint chooser), `modules/dast/passive/leakage.sh` (the phase script `dast_run_phase`
sources), five `DAST-LEAK-*` records now in `modules/dast/passive/checks-leakage.rules` (APPENDED to
the directory's then-shared `checks.rules`; tension 29 has since split that file), and
`tests/suites/dast-leakage.sh` - 154 assertions, no network and no Docker, driven entirely from
recorded head/body pairs replayed into `lib/http.sh`'s own two capture sinks.

The five families and their ids:

| Check id | Severity | CWE | OWASP |
|---|---|---|---|
| `DAST-LEAK-STACK_TRACE-01` | medium | CWE-209 | A05:2021 |
| `DAST-LEAK-PROXY_HEADER-01` | low | CWE-200 | A05:2021 |
| `DAST-LEAK-EMAIL-01` | low | CWE-200 | A01:2021 |
| `DAST-LEAK-JS_CONFIG-01` | high | CWE-540 | A05:2021 |
| `DAST-LEAK-THIRD_PARTY_ORIGIN-01` | **info** | CWE-829 | A08:2021 |

Five ids rather than one because `check_id` is itself a fingerprint component (`docs/FOUNDATION.md`
tension 5) and the DAST location profile carries no component naming the DEFECT - so a trace and a
leaked address on one path would collide on one fingerprint under a single id and `findings_merge`
would silently keep whichever won the sort.

Six things about it are worth knowing before a peer ticket touches this directory.

- **Each family is defined by its REFUSAL, and each refusal has a negative fixture the naive reading
  flags.**  A stack trace needs a STRUCTURED FRAME (a source file plus a line number) or an
  interactive-debugger banner - never a framework name or the word "error", which is what a branded 404
  carries.  An infrastructure header needs its VALUE to name an unroutable address or a
  reserved-internal DNS suffix; the header NAME only selects a candidate, so `Via: 1.1 varnish` (a
  product name) and `X-Served-By: cache-lhr7364-LHR` (a public CDN edge POP code) are not flagged,
  because a dotless token is genuinely ambiguous and flagging the shape would flag every CDN customer.
  An address published as a `mailto:` link is deliberate publication and is subtracted wherever else in
  the target it appears, as are RFC 2142 role aliases and a "domain" whose last label is a file
  extension (`logo@2x.png` in an `srcset` matches every naive email regex).  A JS-config finding
  subtracts a public-by-design ALLOW-LIST first - a Stripe publishable key, a Google browser API key,
  an analytics id - because those are precisely what a credential is designed to look like.  A
  third-party origin subtracts the response's own host and everything sharing its registrable domain.
- **The suite asserts the DIFFERENCE rather than the absence.**  For every family it runs the naive
  reading INLINE, asserts that the naive reading DOES fire on the fixture, then asserts the shipped one
  does not, then asserts the shipped one still fires on a real positive.  A case that only asserted "no
  finding" would pass equally well against a check broken into silence.  Measured, not reasoned: eight
  deliberate mutations - the naive keyword trace match, a dotless token read as an internal host, the
  dropped `mailto:` subtraction, the dropped file-extension rejection, the dropped public-key
  allow-list, the dropped same-site subtraction, a truncating body reader, and a header reader that
  stops resetting per hop - each took the suite red, by 1 to 7 assertions apiece.
- **A candidate secret's VALUE never reaches the finding.**  Family 4 carries the key name, a
  description of the matched shape and the value's LENGTH.  A finding that quotes the credential has
  copied it into the report, the run's shard file and the operator's scrollback; `rules/redaction.rules`
  would catch many of these on the way out, and not carrying the value is the control that does not
  depend on that list being complete.
- **A minified bundle is CHUNKED, never truncated at the per-line cap.**  A webpack bundle arrives as
  one 900 KiB line, and a line-cap read inspects its first 4 KiB and declares the other 99% clean -
  exactly the overstated coverage `docs/DESIGN.md` §15 forbids.  A token straddling a chunk boundary is
  the accepted cost and can only cause a MISS, which is this family's stated bias.
- **`leakage_engine.sh` SOURCES `headers_engine.sh` for its response-header reader rather than copying
  it.**  `hdr_parse_capture` resets on every status line because `http_request_capture`'s header sink
  accumulates every redirect hop; a second implementation here would be re-earning DAST-05's own
  measured lesson and would put two copies of it in one directory.  This is deliberately NOT the "lift
  into a shared `passive/response_engine.sh`" that `headers_engine.sh`'s header asks a later ticket to
  do - that lift moves a peer's file AND its tests, so it is filed as its own ticket rather than
  performed under parallel peers.  **That ticket has since landed**, and this file now sources
  `passive/response_engine.sh` directly rather than a peer ticket's engine; no call site changed,
  because the lift kept every function and global name.
- **Two emission grains, deliberately.**  A stack trace and a bundled credential are properties of ONE
  HANDLER and emit once per path, so two leaking paths are two findings the operator fixes in two
  places.  An internal proxy header, the disclosed address set and the third-party origin set are
  properties of the APPLICATION and emit once with the affected/tested count, the same reasoning
  `passive/headers.sh` applies to all of its checks.  A family that no fetched response was applicable
  to is recorded as a `leakage_family_not_applicable` coverage_reduction naming the ids, and is kept
  OUT of `checks_run` - so a run that only fetched images never reads as having tested served
  JavaScript.

**What DAST-10 deliberately did not build**, so the boundary is not rediscovered: provoking an error to
harvest its trace.  That is the obvious way to raise this family's recall and it is active probing,
which §7.1 excludes; it belongs behind `--intensity` and a ticket that owns it.  TLS inspection
(DAST-07), banner/version matching (DAST-09) and the derived correlated-key finding DAST-27 relates to
are likewise out of scope and unchanged by this landing.  SQL driver error strings (`SQLSTATE[`,
`ORA-`, "You have an error in your SQL syntax") are deliberately NOT matched here either: they are the
error-based oracle `active/sqli.sh` (DAST-14) already owns, and matching them in both places would
report one defect under two check ids that the fingerprint cannot dedup.


**One note on the frozen record format - AMENDED SINCE, so read the whole note before copying either
half of it.**
This ticket first shipped its registry as `modules/dast/passive/cookies.rules`, one pack per owning
script, so that DAST-05..DAST-11 would not all edit one file. That was not available at the time:
`rules/RULE-FORMAT.md` §9's path table reserved the basename `checks.rules` repository-wide for the
§9.5 schema, and a record file matching no row of that table is `E070` - which `tests/lint-rules.sh`
duly reported. The tier therefore shared `modules/dast/passive/checks.rules`, and a parallel passive
ticket met an append-only merge conflict there that was resolved by taking both sides.

**That shared file no longer exists.** `docs/FOUNDATION.md` tension 29 added one additive row to §9's
path table legalising `checks-<name>.rules` at any depth, and this directory is now split five ways -
this ticket's four `DAST-COOKIE-*` records live in `modules/dast/passive/checks-cookies.rules`. A
passive ticket from now on **creates its own `modules/dast/passive/checks-<name>.rules` and appends to
nobody's file**, so there is no conflict to resolve. Note the shape precisely: the legal spelling is
the `checks-` PREFIX, so this ticket's original `cookies.rules` and DAST-05's `headers-checks.rules`
SUFFIX attempt are both still `E070`.


#### What DAST-11 (`passive/markup.sh`) shipped, and the six things about it that are easy to get backwards

**DAST-11 (`passive/markup.sh`) has landed - a tier-2 check, built after its peers DAST-06 and
DAST-05 and appending to the `modules/dast/passive/checks.rules` they already share.**
It ships `markup_engine.sh` (the pure half: the tag tokenizer, the origin comparison, the token-list
and anti-CSRF-name predicates, the sensitive-page classifier, the endpoint chooser), `markup.sh` (the
phase script `dast_run_phase` sources), and six `DAST-MARKUP-*` script checks, all tagged `passive`.
`tests/suites/dast-markup.sh` is the proof - 189 assertions at landing and 211 after the corrective
pass recorded below, no network and no Docker, driven from recorded response bodies replayed into
`lib/http.sh`'s own body sink.

- **The record separator between the tokenizer and the phase is 0x1f, and a tab is a MEASURED bug
  rather than a taste question.**  A tab is an IFS-*whitespace* character, so `read` folds a RUN of
  them into ONE delimiter (POSIX XCU 2.6.5).  A `<link>` with neither `integrity` nor `crossorigin`
  emits six fields of which two are empty, and a tab-separated reader collapses that to four - so
  `rel` arrives in the `integrity` variable, the SRI check reads an attribute that was never sent,
  and every unhashed cross-origin stylesheet on the internet passes.  That is what the first draft
  did; the suite caught it, and it now pins the reading in both directions.  0x1f is what
  `crawl_json_flatten` already uses, for the same reason.
- **`rel` is a TOKEN LIST and both naive readings are wrong in opposite directions.**  A
  whole-attribute comparison misses `rel="external noopener"`, which IS protection; a substring test
  accepts `rel="noopenerx"`, which is not.  Same for `markup_link_takes_sri`: `rel="stylesheet
  alternate"` takes SRI and `rel="icon"` does not, and flagging every `<link href>` puts a finding on
  every favicon on the internet.
- **`sandbox` is a BOOLEAN attribute, so presence is not the same question as a non-empty value.**
  `sandbox` and `sandbox=""` are both the maximally restrictive sandbox; reading presence off the
  value reports a fully sandboxed frame as unsandboxed.  The tokenizer has a separate
  `attr_present()` for exactly this and the suite fails under the merged reading.
- **The "weighted higher on login and redirect pages" requirement is expressed as a SECOND CHECK ID,
  not as a severity a script raises at runtime.**  `severity` is a per-record property of the
  registry (`rules/RULE-FORMAT.md` §9.5), and a phase that emitted a `base_severity` above what its
  own record declares would put the report and the registry into disagreement -
  `tests/suites/dast-markup.sh` asserts they always match.  `DAST-MARKUP-TABNABBING-01` is `low`,
  `DAST-MARKUP-TABNABBING_SENSITIVE-01` is `medium`, and the page is classified sensitive by its path
  OR by carrying an `<input type="password">`; the content signal is the stronger one and is what
  catches a page that is not called `/login`.  The same argument splits insecure framing into a
  transport defect and a missing-control defect, because `docs/DESIGN.md` §7.1 names two and one id
  could only carry one remediation.
- **The finding grain is per PAGE, which is deliberately NOT `headers.sh`'s per-target grain, and the
  contrast is the argument.**  A security header is a server-configuration property that is the same
  on every response, so collapsing it is right.  Markup is a TEMPLATE property: collapsing it would
  tell an operator that "a page" on this target has a form with no CSRF token without saying which.
  The location profile already carries `path_template` and the endpoint chooser has already deduped
  by it, so the report is bounded by construction.  The offending elements go in the EVIDENCE and
  never in the location - a CDN URL routinely carries a content hash, and putting one in the identity
  would mint a new finding on every deploy and destroy the tension-12 diff `--fail-on-new` gates on.
- **The parser's limits are stated in `markup_engine.sh`'s header, in both directions, and the
  SPA one changes what a clean result means.**  Handled: multi-line attributes, all three quoting
  styles, a `>` inside a quoted value, comments and `<script>`/`<style>`/`<textarea>`/`<template>`
  bodies, mixed case, the five named character references.  Not handled: markup a script builds at
  runtime, numeric references other than `&`, an unterminated quoted value (the tag AND the rest of
  the document are abandoned rather than guessed at), nested forms, `<svg>` self-closing syntax,
  XHTML CDATA, and anything past the 1 MiB cap.  Every one of those that bites on a real run is
  emitted as a `coverage_gap` or `coverage_reduction`, and the client-rendered case gets both,
  because for an SPA a clean markup result is the absence of a test rather than evidence of anything.

**What DAST-11 deliberately did not build, and what it filed instead.**  It writes no shared
`passive/response_engine.sh`.  `headers_engine.sh`'s own header invites a peer that needs the same
endpoint chooser to LIFT it "with this file's tests moving with it ... a refactor with an owner, not
a side effect of a peer landing", and doing that lift here would have moved `headers.sh`, its
156-assertion suite and `cookies.sh` under a markup ticket.  So `markup_endpoints_load` is a second,
STATED copy and the lift is filed as its own ticket.
**Read that precisely now that `passive/response_engine.sh` EXISTS: it holds the READER and only the
reader, and the ENDPOINT CHOOSER lift this paragraph is about is still open.**  `hdr_endpoints_load`
stays in `headers_engine.sh` deliberately - it has two callers rather than a shared need, and it
depends on `crawl_engine.sh` and `path_template_of`, which would put source edges back into a file
whose whole purpose is to have none.  `markup_endpoints_load` is therefore still a stated second
copy, as are `transport_engine.sh`'s and `leakage_engine.sh`'s own choosers, each of which differs
from `hdr_endpoints_load` in its dedup key for reasons its own header records.  A future chooser lift
is a separate ticket with a separate argument to make; the reader's landing does not settle it.  It also does not re-use `crawl_html_extract`:
that function's output stream carries no attribute detail, and every check here is about an
attribute, so widening it would change a contract `docs/INVENTORY-FORMAT.md`'s consumers read - the
scanner core is reused, the emitter is not.  A second, smaller gap was found and filed rather than
worked around at landing time: `http_request` published `_HTTP_LAST_STATUS` and
`_HTTP_LAST_CONTENT_TYPE` but not the final URL after a redirect, so a relative reference on a page
that redirected was resolved against the REQUESTED URL rather than the delivered one - **this has
since been closed**.  `http_request` (lib/http.sh §12) now also publishes `_HTTP_LAST_URL`, the
canonical URL of the hop that actually produced the returned response, set on every path that
publishes a response including the "redirect not followed, gate declined" early return; `markup.sh`
now seeds `_MK_BASE` (and the finding's own `url` field) from it instead of from the URL this phase
first asked for, so a same-origin/cross-origin judgement on a page reached via redirect is made
against the document that was actually served.  `<base href>`, when present, still overrides it and
always made the case moot; a redirect with none of its own is what was silently wrong before and is
correct now.  Out of scope here and unclaimed: `<meta http-equiv>`
refresh redirects, `formaction` overrides on a submit button, `autocomplete="off"` on credential
fields, and the `crossorigin`-missing-beside-`integrity` case (which breaks the resource rather than
weakening it, so it is named in the remediation instead of flagged).

#### DAST-11 corrective pass - seven defects the 189-assertion suite could not reach

**DAST-11 was approved, then the approval was reversed by an adversarial review; the corrective
ticket landed the fixes and took the suite to 211 assertions.**
Every one of the seven was silent in the direction that reads as a CLEAN SCAN RESULT, and none was
reachable by the original suite - not because the assertions were weak, but because no case
exercised the path at all.
The security defect and the two honesty defects are recorded as sharp edges in `AGENTS.md`; what is
worth keeping here is the pattern and the four smaller adjudications.

- **`markup_tokens_have` glob-expanded a `rel` attribute against the scanner's cwd** (CWE-807), so a
  target serving `rel="*"` suppressed its own `DAST-MARKUP-TABNABBING-01` finding on any host with a
  file named `noopener` in the working directory, and `markup_link_takes_sri` inherited it.
- **The tokenizer's exit status was discarded** (`... 2>/dev/null || true`) and `parsed` counted
  documents ATTEMPTED, so a page nothing had read contributed four ids to `checks_run` (CWE-390).
- **`_MK_FORMS_CROSS_ORIGIN` was a run-level counter declared in the per-page function**, so a
  cross-origin POST form on any page but the last was excluded from the CSRF check and the exclusion
  was never declared (CWE-778).
- **A `<input type="password">` outside any `<form>` never became a `field` record**, because the
  tokenizer gated those on an open form - which is exactly the single-page login shape, so those
  pages were classified ordinary and downgraded from `TABNABBING_SENSITIVE-01` to `TABNABBING-01`.
  The record contract is unchanged: a field belongs to the most recent unclosed `<form>`, and one
  with no open form belongs to none.  `markup.sh` pass two still guards on the association itself;
  pass one reads the same records for the document-wide signal.
- **`<a href="..."target="_blank">` did not parse**, because `attr()` required `[ \t\r\n/]` before an
  attribute name.  Browsers accept it and the check could not fire.  A quote is now a separator, in
  `attr()` and `attr_present()` alike - the pair is pinned in both directions, since widening only
  the first would invent a finding about a frame that IS sandboxed.
- **`_mk_selected FRAME_INSECURE_SCHEME-01 || continue` skipped the whole record** rather than
  falling through to the untrusted-frame arm, so deselecting one check silenced another the operator
  had left selected.  Dormant when DAST-11 landed and no longer: `dast_check_selected` now exists.
- **The two tabnabbing ids left `checks_run` whenever they found nothing**, alone among the six, so a
  clean page and an untested page looked alike for them and tension 12 could never infer `fixed` -
  the run that would prove the fix is the run that drops the coverage.  The condition is now "was a
  page classified under this id", counted per page in `_MK_TAB_SEEN`, which still declines to claim
  the sensitive id on a run that saw no authentication page.

Two cosmetic items went with them: the scope-refusal reason is captured AT the refusal (`_HTTP_GATE_REASON`
read after the loop holds the last gate call's value, routinely an ADMITTED URL), and
`markup_html_extract` runs under `LC_ALL=C` so awk's `length()` counts bytes and `_MARKUP_MAX_BYTES`
means what its name says - in a UTF-8 locale the "1 MiB" cap read up to 4 MiB of a hostile response.
The `crossorigin`-parsed-and-never-read case (item 8 of the corrective ticket) is real and NOT fixed
there: closing it means minting a new check id, which is a registry and fingerprint-identity change,
so it is filed as its own ticket.


**DAST-08 (`passive/cors.sh`) has landed - the first tier-2 passive check, and the ticket that
created `modules/dast/passive/`.**
It ships `modules/dast/passive/cors_engine.sh` (the pure half: the response-header reader, the
`Access-Control-Allow-Origin` classifier, the credentials predicate, the probe and the finding
emission) and `modules/dast/passive/cors.sh` (the phase script `dast_run_phase` sources at tier
`passive`), in the `engine.sh`/`run.sh` split `modules/sast/` established and every DAST phase since has
reused.  Three check ids in the new `modules/dast/passive/checks.rules` -
`DAST-CORS-ORIGIN_REFLECTED-01` (medium, CWE-346), `DAST-CORS-REFLECTED_WITH_CREDENTIALS-01` (high,
CWE-346) and `DAST-CORS-WILDCARD-01` (low, CWE-942), all `owasp: A05:2021`, type tag `passive`, profile
tag `quick`, `coverage-scope: target`.  `tests/suites/dast-cors.sh` (91 assertions, no network, no
Docker) drives the whole check from RECORDED response-header blocks under
`tests/fixtures/dast/cors/`.

`modules/dast/passive/checks.rules` is SHARED tier-2 scaffolding this ticket created and owns until a
sibling appends to it.  `rules/RULE-FORMAT.md` §9 reserves the basename `checks.rules`
repository-wide for the §9.5 schema, so a passive check's registry cannot be given a per-check
filename; DAST-05, DAST-06, DAST-07, DAST-09, DAST-10 and DAST-11 each append their own records to this
one file.  The records are blank-line-separated and order-independent, so two of those tickets landing
in parallel conflict only on adjacent text.

Five decisions here are easy to get backwards; each is pinned by a test naming the reading it fails
under, and each was confirmed by deliberately breaking the implementation and watching the suite go red
(nine such mutations were run; two assertions that survived their mutation were replaced with ones that
do not).

- **THIS CHECK SENDS A REQUEST AND IS STILL PASSIVE, AND THE TWO ARE NOT IN TENSION.**  §7.1's
  contract is "No mutation of state", not "no traffic", and its own `cors.sh` bullet spells the probe
  out as "`Origin: <sentinel>` -> check `Access-Control-Allow-Origin` + credentials".  Six properties
  keep it inside that contract and each is asserted against a REQUEST LOG rather than a return value:
  only GET/HEAD endpoints from the inventory are requested (a POST or DELETE route the crawler found is
  never touched, and is never "downgraded" to a GET, which would be content discovery at the
  safe-active tier); exactly one request per distinct route, with no retry and no `OPTIONS` preflight;
  no request body; no response-body capture sink, so target content never enters the process or an
  artifact; no redirect followed; and the request goes through `http_request`, so tension 19's gate,
  DAST-01's limiter, the budget, the breaker and DAST-32's ceilings all bind it.
- **A WILDCARD IS NOT A REFLECTION, AND THEY ARE THREE CHECK IDS RATHER THAN ONE.**  `*` says "any
  origin may read this UNAUTHENTICATED" - the Fetch standard forbids a browser from honouring `*`
  together with credentials at all - whereas reflection says "whatever origin asked is trusted", which
  composes with cookies into a full cross-origin read of an authenticated response.  A check keying on
  "an ACAO header came back" grades a public CSS asset the same as a reflecting API.  They must also be
  separate ids mechanically: the DAST location profile (target, method, path_template, param_location,
  param_name) carries no verdict component, so one shared id would make a wildcard and a reflection on
  the same route collide and dedupe to a single finding.
- **THE CREDENTIALED FINDING SUBSUMES THE PLAIN ONE; EXACTLY ONE FIRES PER ROUTE.**  Emitting
  `ORIGIN_REFLECTED` and then separately noting credentials would report one root cause twice and make
  the CORS finding count meaningless - the same discipline `jwt_engine.sh` applies when
  `SIG_NOT_VERIFIED` subsumes its per-variant probes.
- **A STATIC ALLOWLIST IS NOT A FINDING, AND REFLECTION IS EXACT EQUALITY.**  A server that answers its
  own configured origin to our sentinel validated the Origin and refused it, which is correct
  configuration; reporting it is a false positive on the thing we are asking operators to do.  And a
  value that merely CONTAINS the sentinel (`<sentinel>.attacker.invalid`) is a different, suffix-match
  bug and not a reflection of ours - a substring test calls it one.
- **HEADER FIELD NAMES ARE MATCHED CASE-INSENSITIVELY, AND THE TRAILING CR IS STRIPPED.**  HTTP/2
  (RFC 7540 §8.1.2) REQUIRES lowercase field names, so a check matching the RFC 6454 spelling
  byte-for-byte reports every target behind an HTTP/2 edge clean; and every recorded fixture is
  CRLF-terminated because that is what HTTP is, so a reader that keeps the `\r` compares
  `"<origin>\r"` against the sentinel and calls a reflecting server clean.  These are the two ways this
  check goes quietly blind in production while every "emits nothing" assertion stays green, which is
  why the fixtures are recorded rather than composed inline.

**The sentinel origin.**  It is `https://scoursh-cors-probe.example`, an RFC 2606 reserved name that
can never be delegated, and it is a header VALUE only - no request is ever addressed to it, which the
suite asserts against the request log.  It names no application, company, product or environment
(AGENTS.md §1).  `SCOURSH_DAST_CORS_ORIGIN` overrides it for testing, the same swappable-seam idiom
`lib/http.sh`'s transport and resolver hooks use; it is deliberately not a documented operator knob and
has no config key.

**Coverage is recorded for all three ids whenever a probe got a response, including the ids that fired
nothing.**  One response answers all three verdicts at once, so recording only the ids that happened to
fire would make coverage a function of the result and leave a genuinely clean target indistinguishable
from an unscanned one.  The converse is pinned too: a run whose every probe failed at the transport
level records NO `checks_run` and states that nothing was tested, because a breaker-opened run must
never read as a clean target.

**What DAST-08 deliberately did not build**, so the boundary is not rediscovered:

- **An AUTHENTICATED probe pass.**  A CORS policy is frequently set only on the authenticated API
  surface, so an unauthenticated probe can miss one.  That is a real bound and it is RECORDED
  (`reason=cors_probe_is_unauthenticated`) on exactly the runs where a reader could expect otherwise -
  `--authed` given and a session actually acquired.
  **This has since been decided, not merely deferred** (the "DAST-08 follow-up: authenticated CORS
  probe pass, or a decision that we will not send credentials cross-origin" ticket): scoursh will
  NOT attach a session to this probe.  `cors.sh` runs at tier `passive`, which every `--intensity`
  reaches with no `--i-own-target` affirmation gate, and sending a live credential on a request that
  also carries an attacker-shaped `Origin` is the specific combination a WAF or fraud stack treats as
  a credential-riding attack signature - a risk the passive contract never asks the operator to
  accept.  `active/sqli.sh` and `jwt.sh`'s own authenticated passes are not a counter-example, since
  neither ever forges `Origin` alongside the credential.  The failure mode is not even contained to
  this check: a resulting account lockout would make DAST-03's transparent re-auth mark that identity
  `failed` for the rest of the run, silently degrading every OTHER authenticated check (DAST-29,
  DAST-26, the authenticated crawl pass, ...) that a passive check nobody opted into never should have
  been able to touch.  The `cors_probe_is_unauthenticated` coverage_reduction stays as the permanent,
  honest statement of the resulting gap - the same shape as DAST-04's SPA limitation.  See
  `modules/dast/passive/cors.sh`'s own header for the same reasoning kept beside the code it binds.
- **An `OPTIONS` preflight probe.**  The actual-request response already carries the two headers §7.1
  names; a preflight would double this check's request count to also read
  `Access-Control-Allow-Methods`/`-Headers`, and HTTP method enumeration is DAST-13
  (`active/methods.sh`) at the safe-active tier.
- **`Access-Control-Allow-Origin: null` as a finding of its own.**  Reflecting the `null` origin is
  separately exploitable from a sandboxed iframe, but detecting it needs a SECOND request carrying
  `Origin: null`, which is a second probe per endpoint.  A `null` value classifies as `allowlisted`
  today and produces no finding; that is a stated gap, filed as its own backlog ticket.
- **`dast_check_selected`.**  `modules/dast/active/sqli.sh` (DAST-14) already calls this function
  behind a `declare -F` guard, and it EXISTS NOWHERE IN THIS REPOSITORY - so tension 15's per-check
  selection has never bound a DAST check, and `--profile-scan`/`--intensity` narrowing is inert for the
  module today.  `cors.sh` uses the identical guard so it behaves exactly as its peer, and the gap is
  filed as its own ticket rather than closed inside a check: the function belongs in
  `modules/dast/engine.sh`, which every tier-2 peer is editing in parallel.

#### What DAST-09 (`passive/banner.sh`) shipped

**DAST-09 (`passive/banner.sh`) has landed - a tier-2 check.**
`modules/dast/passive/` and its shared script-check registry already existed by the time it landed
(DAST-08's landing note above), so its three check ids are seeded into their own
`modules/dast/passive/checks-banner.rules` following the tension-29 per-owner split, and it did not
create `modules/dast/passive/` itself - only `docs/VERSIONS-DB.md`.

It ships four artifacts plus one doc:

- `modules/dast/passive/banner_engine.sh` - the pure, testable half. Header iteration over the capture
  file `lib/http.sh` writes, `<meta name="generator">` extraction, versioned-bundle-filename extraction,
  the frozen product-key normalisation (`banner_normalize_product`), and the `data/versions.db` lookup.
  It opens no socket and names no host; every function is a pure function over bytes the caller already
  has, which is what makes the whole detection surface testable from a recorded response.
- `modules/dast/passive/banner.sh` - the phase script `dast_run_phase` sources, at tier `passive`, so it
  runs on the default intensity. It reads `reports/<run>/inventory/endpoints.json` (DAST-04) and never
  crawls; it dials GET/HEAD endpoints only and counts-and-reports the rest; every request goes through
  `http_request`.
- `modules/dast/passive/checks-banner.rules` - its own check registry, with three ids
  (`DAST-BANNER-SERVER_DISCLOSURE-01` info/CWE-200/A05, `DAST-BANNER-VERSION_DISCLOSURE-01`
  low/CWE-200/A05, `DAST-BANNER-OUTDATED_COMPONENT-01` high/CWE-1104/A06), each with remediation text.
  It lands after tension 29's per-owner split was already in effect for its tier-2 peers, so it was
  seeded directly into its own file rather than into a shared `checks.rules` - `checks_registry_load`
  globs `*.rules` at any depth under `modules/dast/`, so which shape a given owner picked makes no
  difference to what loads.
- `tests/suites/dast-banner.sh` (69 assertions, registered in `tests/run-tests.sh`) plus
  `tests/fixtures/dast/banner/` - recorded header/body pairs and a fixture `versions.db`. No network, no
  Docker. Assertions are made on the REQUEST LOG where the claim is about traffic, so "the POST endpoint
  was not dialled" is measured rather than asserted.
- `docs/VERSIONS-DB.md` - the normative, self-contained format for `data/versions.db`, in the role
  `docs/INVENTORY-FORMAT.md` plays for the crawl inventory.

Five decisions worth stating here rather than leaving to the diff, each pinned by a test naming the
reading it fails under:

1. **Two namespaces, one table.** Field 1 is an SCA ecosystem for the rows `tools/vendor-engines.sh
   advisories` writes and the literal `banner` for the rows this check reads. That writer replaces only
   the rows whose first field equals the ecosystem it is writing, and `banner` sorts before every
   ecosystem name under `LC_ALL=C`, so refreshing npm cannot delete the banner catalogue and adding a
   banner row cannot disturb the sort `db_lookup_exact` needs.
2. **Exact lookup only - no version comparison anywhere.** Deciding that 1.18.0 is behind 1.27.0 is range
   arithmetic, which tension 25 moved off the scanner deliberately. "Out of date" means "this exact
   version is named in the vendored list", never a guess.
3. **Degradation is per-sub-check and named.** `versions_db_absent` and `versions_db_no_banner_rows` are
   distinct reasons, the two disclosure checks keep running under both, and a discovered product with no
   row of any version lands in one `versions_db_product_unknown` roll-up rather than one record per
   product. The out-of-date finding carries the list's own `# generated:` stamp, because a stale list
   produces false negatives and those are the ones that hide.
4. **The version is in the finding's identity for `OUTDATED_COMPONENT` and out of it for the two
   disclosure checks.** A disclosure survives an upgrade and must keep one identity; a
   known-vulnerable-version claim is about that version and must go `fixed` when it changes.
5. **Three ids, not one**, for the reason `modules/dast/active/checks.rules` already records for the
   three SQLi techniques: the DAST location profile carries no "kind" component, so one id would collide
   a name-only disclosure with a version hit on the same endpoint and `findings_merge` would keep one.

**What DAST-09 deliberately did not build**, so the boundary is not rediscovered: any shared
`passive/passive_engine.sh`. Six peer tickets are in flight and `banner_engine.sh`'s two header helpers
are scoped to this file's own needs; a later passive ticket that wants them should LIFT them into a
shared file in its own change and say so. Also not built: an importer for the `banner` namespace -
`tools/vendor-engines.sh advisories` covers the SCA ecosystems only, and extending it is filed
separately. `docs/VERSIONS-DB.md` §5 is the hand procedure until it lands.

**DAST-07 (`passive/tls.sh`) has landed - a tier-2 check, and the ticket that turns tension 19's single
documented exception from a sentence in a register into code.**
It was written when it would have been the first script under `modules/dast/passive/`; its peers
DAST-05, DAST-06 and DAST-08 through DAST-11 reached `dev` while it was in review, so DAST-08 is what
actually created that directory, and this note is corrected here rather than left claiming a
first-ness the landing order did not give it.
It ships `modules/dast/passive/tls_engine.sh` (the pure library: the ASN.1-date-to-epoch converter, the
`SSL-Session:` transcript parser, the DN normalizer, the SAN/CN reader, the expiry, self-signed and
wildcard predicates, and the one `openssl s_client` invocation in the whole tool),
`modules/dast/passive/tls.sh` (the phase script `dast_run_phase` sources at tier `passive`), and
`modules/dast/passive/checks.rules` - this phase's own check records, carrying six ids:
`DAST-TLS-WEAK_PROTOCOL-01`, `DAST-TLS-WEAK_CIPHER-01`, `DAST-TLS-CERT_EXPIRED-01`,
`DAST-TLS-CERT_EXPIRING-01`, `DAST-TLS-SELF_SIGNED-01` and `DAST-TLS-WILDCARD_CERT-01`.
`tests/suites/dast-tls.sh` (131 assertions, no network, no Docker) drives every case from recorded
transcripts and committed fixture certificates under `tests/fixtures/dast/tls/`, whose own README states
the provenance of each.

Six decisions here are easy to get backwards, and each is pinned by a test naming the reading it fails
under:

- **The exemption is from the TRANSPORT and from nothing else, and `http_authorize_raw_connection`
  (`lib/http.sh` section 9b) is what keeps it that narrow.**  That function does everything
  `http_request` does except send a request - normalization, the scope tuple compare, the userinfo
  refusal, the deny list, the pinned resolution, and the tension-16 limiter, budget and breaker spend -
  and returns an address.  The phase connects to that address and never re-resolves the name.  The
  alternative, letting the module call `http_gate_url` and `_http_throttle` for itself, was rejected on
  tension 19's own argument: a control each caller must remember to apply is not a control.  Pinned by a
  case asserting that a target the gate refuses is exit 3 **and** that no handshake was opened - the
  gate is consulted before the probe, never after.
- **`New, TLSv1/SSLv3, Cipher is ...` is a FAMILY LABEL, not the negotiated version.**  LibreSSL prints
  it for a TLS 1.2 session, so a parser reading that line reports every LibreSSL-probed target as
  speaking TLSv1 and fires the weak-protocol finding on all of them.  `Protocol  :` inside the
  `SSL-Session:` block is authoritative on both userlands.  Pinned against a LibreSSL transcript that
  carries both lines.
- **A failed handshake still prints a filled-in `Protocol  :`, with `Cipher    : 0000`.**  A parser that
  accepted a protocol alone would report the *offered* version as negotiated for a connection that
  agreed on nothing.  `tls_parse_session` requires the cipher, and the fixture set carries that exact
  transcript for it.
- **Distinguished names come in two spellings and every comparison is made on the normalized form.**
  OpenSSL 1.1/3.x prints `subject=CN = host, O = Org`; LibreSSL and OpenSSL 1.0 print
  `subject=/O=Org/CN=host`.  A raw subject-versus-issuer comparison makes the self-signed check
  userland-dependent, and a `CN=` prefix match finds nothing on the slash form.  The self-signed case is
  deliberately tested from the LibreSSL transcript for that reason.
- **`openssl x509 -ext subjectAltName` does not exist on LibreSSL** (it is an OpenSSL 1.1.1+ flag), so
  the SAN list is read out of `-text`, which exists on both.
- **"Wildcard certificate where a host-specific one is expected" is an EXPECTATION, not a verdict**, so
  it is per target: `tls-expect-wildcard` in `config/scope.conf` (`rules/RULE-FORMAT.md` §9.4, default
  `false`).  An estate legitimately has both shapes, and a scanner-wide answer would make a false
  positive indistinguishable from a real finding.  Pinned in both directions on ONE certificate - the
  same wildcard is a finding on a target that does not declare the expectation and is not on one that
  does, and the satisfied expectation is RECORDED so a reader can see the check ran rather than
  inferring it from an absent finding.

**Expiry is decided by arithmetic this module owns, with `now` injectable, and `openssl x509 -checkend`
was rejected for that.**  `checkend` hardcodes the system clock, so "expiring inside the window" could
only be tested by minting a certificate at test time and "expired" only by committing one and waiting.
Taking `now` as an argument makes `expired`, `expiring` and `ok` all reachable from one long-lived
committed certificate, deterministically, forever.  The window is `tls-expiry-warn-days` in
`config/scanner.conf` (§9.6.1, default 30 - the notice period the public CA ecosystem itself operates
on); `0` is valid and disables the expiring-soon window without disabling the expired check.

**Both userlands were verified for real, not only through transcripts.**  The transcripts pin the
*parsing* of each userland's output; the `openssl x509` calls that read a certificate run against
whatever `openssl` is on `PATH`, so the suite was run twice on one macOS host - once under **OpenSSL
3.6.3** and once under the system **LibreSSL 3.3.6** - and reports 131 passed, 0 failed under each.
What has **not** been verified is a GNU/Linux host: the OpenSSL 3.x leg here is a Homebrew build on
macOS, so it exercises the OpenSSL output shape rather than the GNU userland around it.
`tools/daily-suite.sh`'s container leg covers that gap on its next run; stating it is better than
implying a coverage this ticket did not buy.

**What DAST-07 deliberately did not build**, so the boundary is not rediscovered: it does not report
plaintext exposure or mixed content - that is DAST-30 (`transport.sh`), and a target whose base URL is
plain HTTP is recorded here as a declared gap NAMING DAST-30 rather than this check minting a second id
for the same fact.  It does not validate the chain against a trust store beyond reading `openssl`'s own
verify return code, does not check revocation (OCSP/CRL), does not check key size or signature
algorithm, and does not enumerate the protocols and ciphers a listener *offers* - it reports the one
session that was negotiated, because enumerating the offer surface means a handshake per candidate,
which is not a passive check at §7.1's tier.

### Tier 3 - safe active (§7.2, 2 scripts)

| # | Ticket | Depends on |
|---|---|---|
| DAST-12 (**landed**) | `active/discovery.sh` - content discovery | DAST-01/02/04. **No wordlist is committed to this repository** - this ticket vendors its own, in-repo and read from disk under §12's `tests/fixtures/`-style vendoring rule, so unlike DAST-09 it carries no `vendor-engines.sh` dependency and no missing-data degradation path. |
| DAST-13 **(landed)** | `active/methods.sh` - HTTP method enumeration | DAST-01/02/04. See the landing note below. |

#### What DAST-13 (`active/methods.sh`) shipped, and the four things about it that are easy to get backwards

**DAST-13 has landed - the second tier-3 safe-active phase, after DAST-12 (`active/discovery.sh`),
whose own landing note follows this one; with both in, tier 3 is complete.**
It ships `modules/dast/active/method_engine.sh` (the pure parsing half: `Allow`-header extraction,
comma-list splitting, method classification and TRACE confirmation) and
`modules/dast/active/methods.sh` (the phase `dast_run_phase` sources at tier `safe`), registering
`DAST-METHOD-TRACE_ENABLED-01`, `DAST-METHOD-WRITE_ADVERTISED-01` and
`DAST-METHOD-CONNECT_ADVERTISED-01` in `modules/dast/active/checks.rules` - the same shared,
append-only file `active/sqli.sh`'s records already live in, for the reason the tier-2 note above gives
for its own directory.  `tests/suites/dast-methods.sh` (104 assertions, no network, no Docker) is the
proof, and is named in `tests/run-tests.sh`.

- **THE ONLY TWO METHODS THAT EVER LEAVE THIS PHASE ARE `OPTIONS` AND `TRACE`.**  `PUT`, `DELETE`,
  `PATCH` and `CONNECT` are never sent, on any endpoint, under any flag: acceptance is established
  from the server's own `Allow` header, which a `405` is *required* to carry (RFC 7231 §6.5.5), and
  never by exercising the method - completing one would create, overwrite or delete a resource on a
  target under audit.  That is why those two checks are `confidence: medium` and say so in their
  evidence, while the measured TRACE check is `high`.  The suite asserts the absence of every write
  method **on the request log**, over a fixture surface that advertises all of them.
- **`Access-Control-Allow-Methods` IS NOT `Allow`, AND THE ANCHOR IS THE WHOLE DEFENCE.**  The
  header-name match is `^allow:`; an unanchored, case-insensitive match for `allow` reads a CORS
  preflight policy - what a BROWSER may send cross-origin - as what the ENDPOINT accepts, so every
  API permitting a cross-origin `PUT` from its own front end is reported as accepting `PUT` from
  anyone.  Measured: that mutation fails 7 assertions.  CORS analysis is a separate check family and
  is out of this ticket's scope; the point is not doing a bad version of it by accident.
- **THE MEASUREMENT BEATS THE ADVERTISEMENT, IN BOTH DIRECTIONS, AND ONE READING GETS EACH HALF
  WRONG.**  A confirmed TRACE echo that the server names in NO `Allow` header is still a finding
  (Apache's historical `TraceEnable` default is exactly that shape); a `TRACE` named in `Allow` that
  the actual `TRACE` request answers `405` is NOT a finding, only a recorded contradiction.  And a
  bare `200` is not an echo: a single-page app answers every unrouted request with its shell, so
  "TRACE returned 200" fires on a great many servers with no TRACE handler - confirmation requires
  `Content-Type: message/http` or a body echoing the request line (RFC 7231 §4.3.8).
- **THIS PHASE DOES NOT FILTER THE INVENTORY TO ITS `GET` ROWS, UNLIKE `passive/cookies.sh`, AND THAT
  IS NOT AN INCONSISTENCY.**  That phase dials each endpoint *with the method the crawler recorded*,
  so a recorded `POST /login` had to be skipped.  This one never uses the recorded method as the
  method to send, so a `POST` row is a safe thing to ask `OPTIONS` about - and skipping it would drop
  exactly the write-shaped endpoints whose method surface is most worth knowing.

- **THE AUTHENTICATED PASS ATTACHES ITS CREDENTIAL THROUGH `dast_auth_apply`, IMMEDIATELY BEFORE EVERY
  REQUEST.**  Two readings of that sentence are wrong and both were measured failing here.  Reaching
  into the session store for a cookie header - `dast_auth_cookie_header_set`, which does not exist;
  the real helper is `_dast_auth_cookie_header_set` and it is private - means a `declare -F` guard
  quietly skips it, so the run reports `authenticated_pass=1` while sending nothing, and a
  cookie-only attachment would still send nothing for a `bearer`/`api-key` identity, which is the
  majority shape for an API.  And attaching ONCE per endpoint is not enough: `http_request` consumes
  lib/http.sh section 9a's per-request context at entry, so the `TRACE` that follows the `OPTIONS`
  would go out anonymous.
  Section E of the suite pins both, on the outbound header context at the transport boundary rather
  than on anything the phase says about itself.
  **`modules/dast/passive/cookies.sh` (DAST-06) carries the first of those two bugs verbatim** and is
  filed as its own ticket rather than fixed here.

One standing bound is recorded on every run that enumerated anything
(`reason=methods_write_not_exercised`), because the absence of a write finding means "none was
advertised", not "none is enabled": an endpoint that accepts `PUT` without saying so is outside what a
non-destructive check can see, permanently and by design.

**DAST-12 (`active/discovery.sh`) has landed - the first tier-3 (§7.2 safe-active) phase.**
It ships `modules/dast/active/discovery.sh` (the phase script `dast_run_phase` sources at tier `safe`)
and the four §7.2 checks in `modules/dast/active/checks.rules` (tag `safe-active`, coverage-scope
`target`): `DAST-DISC-SENSITIVE-01` (CWE-538), `DAST-DISC-BACKUP-01` (CWE-530), `DAST-DISC-CONTENT-01`
(CWE-200) and `DAST-DISC-DIRLIST-01` (CWE-548), all OWASP A05:2021.  Three candidate sources feed one
soft-404-baseline + status/length heuristic: a small fixed in-code well-known-sensitive-path set
(`.git/HEAD`, `.env`, `.htaccess`, ... - the two §7.2 names it explicitly), backup/temp variants
DERIVED from the crawl inventory's endpoint paths by a fixed in-code suffix set (`.bak`, `~`, `.old`,
...), and the VENDORED wordlist; any 200 hit whose body matches an autoindex signature also emits
`DAST-DISC-DIRLIST-01`.

**The wordlist vendoring is the part worth keeping in prose.**  No content-discovery wordlist ships in
this repository (the no-egress rule; an online or unbounded list breaks both that premise and the
request budget).  The probe reads its list from `modules/dast/wordlists/content-discovery.txt` by
default (absent in a fresh clone - only a README lives there), overridable to any vendored file with
`SCOURSH_DAST_DISCOVERY_WORDLIST`, and BOUNDED by `_DISCOVERY_MAX_WORDS` (500) plus an absolute
`_DISCOVERY_MAX_REQUESTS` (600) request ceiling; each entry is validated as a safe relative path (a
`..`, a scheme/absolute URL, or a control character is rejected, so a malicious vendored list cannot
escape the authorised surface).  **That safe-relative-path rule is ONE function
(`_discovery_safe_rel`) and it is applied to the CRAWL INVENTORY as well as to the wordlist**, because
an inventory `path` is untrusted target output (tension 10) and so is strictly LESS trusted than a file
an operator vendored deliberately - validating only the vendored list draws the trust boundary
backwards, and measurably did: an endpoint recorded as `/a/../../../../etc/passwd` produced real probe
requests off the crawled surface until the guard was shared.  `http_request`'s gate is authority-scoped
and would still refuse another HOST, so this is not the last line of defence; it is what keeps a target
from choosing which paths on its own authority the scanner walks, and from spending the DAST-01 request
budget on paths nobody discovered.  An ABSENT or EMPTY wordlist degrades ONLY the wordlist technique to a
recorded `coverage_reduction`/`coverage_gap` and never errors (docs/DESIGN.md §15); the sensitive-path
and backup techniques still run, since neither needs an external list.  Every request is a read-only
GET through `lib/http.sh` (tension 19), non-destructive per §7.2's posture.  `tests/suites/dast-discovery.sh`
(29 assertions, recorded responses, no network) pins the heuristic (including a soft-404 app that 200s
every path yielding no false hits), the three source->family mapping, directory-listing detection,
graceful degradation for an absent wordlist and an unreachable base-url, the read-only-GET posture, and
the wordlist reader's rejection of unsafe entries.  `docs/STEP5-DAST-PLAN.md`'s own DAST-12 row above is
the authority for the dependency; DAST-13 (`active/methods.sh`), the other tier-3 script, has since
landed too - see its own note above.

**A follow-up ticket then corrected technique B's coverage claim, and the correction is the general
lesson, not a detail of this phase: `DAST-DISC-BACKUP-01` is recorded in `checks_run` on the number of
candidates DERIVED, never on the inventory file being readable.**
The two are different facts, and the gap between them is reachable on an ordinary run rather than
theoretical: `modules/dast/crawl.sh` calls `crawl_inv_write_endpoints` UNCONDITIONALLY and
`crawl_engine.sh` emits the full envelope with `"endpoints": []`, so a crawl that found nothing (a
client-rendered application is the ordinary case, per DAST-04's own measured 13-endpoints/0-parameters
result against Juice Shop) still leaves a readable, non-empty `reports/<run>/inventory/endpoints.json`.
The same shape arises when the inventory has endpoints but every one is rejected by `_discovery_safe_rel`
or names a bare directory with no filename component.
In both, the technique sent zero probes while the phase reported the check as covered, which is exactly
the (check, cell) coverage pair that lets step 7's `state/` infer a prior real finding `fixed`
(`docs/FOUNDATION.md` tension 12).
`_discovery_collect_backups` now reports a count (`_DISC_BACKUP_ADDED`, incremented where the candidate
is appended so the count and the array cannot drift apart), and `inventory_state` carries THREE values
rather than two: `absent`, `empty` and `present`.
Keeping `empty` distinct from `absent` is the half that is easy to drop, and it is not cosmetic: the
absent-inventory message tells an operator to run a crawl, which on the `empty` shape is advice to
re-run something that already ran and succeeded, so the two shapes get their own
`reason=discovery_no_endpoint_inventory` and `reason=discovery_inventory_yielded_no_candidate` lines.
Per the cross-fire rule, the suite pins BOTH directions, because an over-broad gate makes technique B
inert and every "stays quiet" assertion in this suite passes against an inert technique: a
zero-endpoint inventory and an all-rejected inventory each yield no coverage plus both records, AND a
well-formed inventory still derives, still probes `/config.php.bak`, still emits its finding and still
claims its check.
`tests/suites/dast-discovery.sh` is at 57 assertions with that section (the "29 assertions" above
counts the original landing only).

### Tier 4 - active injection probes (§7.3, 11 scripts, "one file at a time, each with a mock-response test" per §13's own build-order text)

All are peers of each other; all depend on DAST-04's parameter inventory (query/body/JSON/header/path
segments) plus DAST-01/02, and land after tier 2/3 per §13's stated ordering.

| # | Ticket |
|---|---|
| DAST-14 | `active/sqli.sh` - error-based, boolean, and time-based SQL injection |
| DAST-15 **(landed)** | `active/xss.sh` - marker-token unescaped-reflection detection. See the landing note below. |
| DAST-16 **(landed)** | `active/cmdi.sh` - bounded time-based command injection. See the landing note below. |
| DAST-17 **(landed)** | `active/pathtraversal.sh` - benign read-only marker traversal. See the landing note below. |
| DAST-18 **(landed)** | `active/ssti.sh` - arithmetic-expression template injection. See the landing note below. |
| DAST-19 | `active/openredirect.sh` - attacker-controlled `Location` host |
| DAST-20 | `active/xxe_ssrf.sh` - safe-sentinel-only XXE/SSRF detection, in-scope hosts only |
| DAST-21 | `active/nosqli.sh` - operator/object injection, boolean/error differential |
| DAST-22 | `active/ldapi.sh` - filter-breaking payloads, response/error differential |
| DAST-23 **(landed)** | `active/crlf.sh` - encoded CR/LF header-split detection. See the landing note below. |
| DAST-24 **(landed)** | `active/hosthdr.sh` - spoofed `Host`/`X-Forwarded-Host` reflection. See the landing note below. |
| DAST-25 **(landed)** | `active/protopollution.sh` - `__proto__`-style JSON param probing (JS backends). See AGENTS.md's own DAST-25 landing note. |

**DAST-14 (`active/sqli.sh`) has landed - the first tier-4 injection probe, and the first DAST check
that emits a finding at all.**
It ships `modules/dast/active/inject_engine.sh` (the SHARED, pure library every §7.3 probe reuses: the
tension-21 parameter-inventory reader, the per-location request composer, the request+timing helper,
and the response-signal helpers) and `modules/dast/active/sqli.sh` (the phase script `dast_run_phase`
sources at tier `active`), in the `engine.sh`/`run.sh` split `modules/sast/` established.  The three
techniques `docs/DESIGN.md` §7.3 names are all implemented and each is its own check id -
`DAST-INJ-SQLI_ERROR-01`, `DAST-INJ-SQLI_BOOLEAN-01`, `DAST-INJ-SQLI_TIME-01` in
`modules/dast/active/checks.rules` (the module's first `checks.rules`; `coverage-scope: target`, type
tag `active`).  Payloads are vendored and read from disk under `modules/dast/payloads/` (auditable, per
§7.3), degrading a technique to a recorded `coverage_reduction` when its file is absent.
`tests/suites/dast-sqli.sh` (35 assertions, no network, no Docker) is the mock-response proof.

Six decisions here are easy to get backwards, and each is pinned by a test naming the reading it fails
under; the first four are properties of the shared engine that every peer probe (DAST-15..DAST-25)
inherits:

- **Three techniques are three check ids, not one, because the technique is NOT part of the DAST
  fingerprint** (target, method, path_template, param_location, param_name).  A single id would make an
  error-based and a time-based finding on one parameter collide and dedupe to one - a parameter that is
  vulnerable to all three produces three findings, and the suite pins exactly that.
- **The probe injects where each parameter's `location` says** (query, body/formData, path, header,
  cookie), not just top-level query strings (§7.3's own requirement).  A `graphql` location and a path
  parameter with no template slot are honest "cannot inject", recorded as a coverage reduction, never
  reported clean.  Body injection is proven end to end.
- **Every request still goes through `http_request`.**  The engine composes the request off the
  untrusted inventory and hands the whole thing to the chokepoint, which re-gates the URL on the way
  out - a discovered endpoint is a candidate, never an authorisation, the same rule DAST-04's crawler
  follows.  Nothing in `modules/dast/active/` touches the network directly.
- **Time-based flags on a latency DELTA over the baseline floor, not on absolute time.**  The floor is
  the MINIMUM of benign samples (the DAST-01 throttle inside `http_request` only ever ADDS delay, so the
  minimum is the closest estimate of real server time), the injected time is likewise a minimum, and
  the probe re-tests before flagging (§7.3: "time-based checks re-test to reduce false positives from
  jitter").  A uniformly slow endpoint is NOT flagged; a sub-threshold delay is NOT flagged - both are
  pinned, each failing under the naive absolute-time reading.  The suite drives this with a swappable
  clock hook (`SCOURSH_INJECT_NOW_NS`), the same idiom `lib/http.sh`'s transport/resolver stubs use, so
  the timing is deterministic with no real sleep.
- **Boolean needs the tautology to behave like the baseline AND the contradiction to differ from it**,
  confirmed on retest - a page that changes for both, or neither, is not a differential.  The injected
  value is stripped from each body before the size comparison, so a reflected payload is not itself read
  as the change.
- **Non-destructive is a property of the vendored payloads, restated in the check records and the
  ticket per the DAST-36 amendment**: every payload is read-only (a broken quote, an always-true/false
  `AND`, a bounded `SLEEP`/`WAITFOR`), with no `DROP`/`DELETE`/`UPDATE`/`INSERT`, no stacked write, and
  no exfiltration.  A suite assertion fails the moment a write verb is added to any payload file.

**What DAST-14 deliberately did not build**, so the boundary is not rediscovered: it reuses DAST-03's
session when `--authed` is given and a session exists (attaching the first authenticated identity), but
like DAST-04's crawl it runs against the surface it has; the authenticated-crawl pass that would widen
that surface is DAST-04's own stated follow-up, not this ticket's.  UNION-based and out-of-band SQLi are
out of §7.3's error/boolean/time scope and are not built.

**DAST-15 (`active/xss.sh`) has landed - the second tier-4 injection probe, and the first ticket to
consume `active/inject_engine.sh` without extending it.**
That is the useful fact about it beyond XSS itself: DAST-14 shipped the shared engine while building
the first probe on top of it, so nothing until now had tested whether the inventory reader, the
per-location request composer and the send helper were genuinely reusable or merely sqli-shaped.  They
were reusable - this ticket added no line to `inject_engine.sh`.
It ships `modules/dast/active/xss.sh` (the phase script `dast_run_phase` sources at tier `active`),
`modules/dast/payloads/xss-marker-chars.txt` (the vendored, operator-editable character ledger) and
three `DAST-INJ-XSS_REFLECTED_{HTML,ATTR,JS}-01` checks appended to the shared
`modules/dast/active/checks.rules`.  `tests/suites/dast-xss.sh` (115 assertions, no network, no
Docker, driven entirely from recorded responses) is the mock-response proof.

Five things about it are easy to get backwards, and each is pinned by a test naming the reading it
fails under:

- **The probe measures ESCAPING, not reflection, and that distinction is the whole ticket.**  Almost
  every parameter on a real application reflects something, so a probe that flagged reflection alone
  would be a false-positive generator.  Every context case in the suite is therefore a PAIR - the same
  marker into the same template, once escaped and once raw - and the escaped half is the one that
  fails in the direction that reads as a pass.
- **The window walk is POSITIONAL, and a fixed-offset reading is the bug it prevents.**  An escaped
  character shifts everything after it (the window reads `&lt;&gt;` where a raw one reads `<>`), so a
  probe that looked at a fixed byte offset for the second character would read the `l` of `&lt;`.
  `_xss_scan_window` consumes exactly what it matched - one byte for a raw character, the encoding's
  own length for an escaped one, and NOTHING for a character a filter dropped - which keeps the cursor
  aligned through any mixture of the three.  A dropped character is not raw, either.
- **Three check ids, not one, for the reason sqli already has three.**  The DAST location profile
  carries no component naming the CONTEXT, so an HTML-text and an attribute-value reflection on one
  parameter would collide on a single shared id and dedupe to one finding.  The context is also what
  the remediation differs on, so it is the thing a reader needs.
- **Context decides which raw character is dangerous, and the rules are narrow on purpose.**  HTML
  text needs BOTH `<` and `>` - a raw `<` whose `>` is escaped opens nothing.  A quoted attribute
  needs the quote that DELIMITS THAT value, so a raw `"` inside a single-quoted value is just a
  character; an unquoted value needs `>` instead, and is reported at medium confidence.  A script
  block with both angle brackets raw is high confidence (the element can be closed outright); one with
  only a raw quote is medium, because it depends on the marker actually sitting inside a string
  literal, which this probe does not verify - and the evidence says so rather than hiding it.
- **A raw reflection into a non-rendering Content-Type is NOT a finding, but IS counted.**  A `<`
  echoed into `application/json` executes nowhere, so reporting it is a false positive - but skipping
  it silently would be the overstated coverage §15 forbids, so the run records
  `xss_non_rendering_content_type` with a count.  An EMPTY content type is treated as rendering, since
  that is precisely the response a browser may content-sniff.

**Two defects this ticket found and fixed in its own module, both worth recording because neither is
XSS-specific.**  First, `_XSS_PROBE_SUFFIX` was referenced when composing the probe value and assigned
nowhere, so under the mandatory `set -Eeuo pipefail` the phase aborted with "unbound variable" the
first time it reached a parameter - the module had never been executed end to end.  It is now DERIVED
from the ledger rather than written as a literal, so trimming a line from
`xss-marker-chars.txt` narrows what is sent instead of leaving the probe sending a character its own
context rules can no longer reason about.  Second, and the one with reach beyond this file: **bash 5.2
made `&` in the REPLACEMENT half of `${var//pat/repl}` expand to the matched text**, sed-style, where
bash 4.2 - this project's frozen minimum - treats it as a literal.  The suite's own entity-encoding
helper was written unescaped and silently produced `%3Clt;` instead of `&lt;` on a modern macOS bash,
which left every "correctly escaped" control fixture full of gibberish that contained no raw `<` and
so still passed.  Three of the four cases stayed green; only the one whose `&` sat mid-string rather
than at the front failed loudly, which is what exposed it.  Escape it as `\&` in any replacement that
must stay literal.

**What DAST-15 deliberately did not build**, so the boundary is not rediscovered: STORED XSS and
DOM-based XSS.  Stored XSS needs a write followed by a read of a different page, which is a state
change §7.3's non-destructive posture forbids at this tier; DOM XSS needs a JavaScript engine, which
`scoursh` does not have and does not intend to (the same stated SPA limitation §7.5 already records
for crawling).  Neither is silently assumed covered - the probe reports on reflection into the
response it actually received, and nothing else.

**DAST-16 (`active/cmdi.sh`) has landed - the second tier-4 injection probe, built on the shared
`inject_engine.sh` DAST-14 shipped.**
It ships `modules/dast/active/cmdi.sh` (the phase script `dast_run_phase` sources at tier `active`),
`modules/dast/payloads/cmdi-time-payloads.txt` (the vendored, read-from-disk payloads), and one check
id `DAST-INJ-CMDI_TIME-01` (CWE-78, OWASP A03:2021, `severity: critical`, `confidence: medium`) in
`modules/dast/active/checks.rules`.  `tests/suites/dast-cmdi.sh` (23 assertions, no network, no Docker,
driven by the same fake-clock idiom as `dast-sqli.sh`) is the mock-response proof, and is registered in
`tests/run-tests.sh`.

Scope and the decisions worth keeping:

- **Time-based ONLY, by design.**  A blind command injection has no reliable in-band signal (command
  output is rarely reflected; an error page is indistinguishable from ordinary input rejection), so a
  bounded injected DELAY - universal across shells, unambiguous against the benign baseline - is the one
  signal this probe uses.  It reuses DAST-14's time-based mechanism verbatim: the baseline floor is the
  MINIMUM of benign samples (the throttle only ever ADDS delay), the injected time is likewise a
  minimum, the threshold is HALF the injected sleep, and the parameter is retested once before flagging.
  The `/slow` control (uniformly 2s on every request) pins that it flags on the DELTA over the floor,
  not absolute time.
- **BOUNDED is load-bearing, and the bound is applied, not advisory.**  `_CMDI_SLEEP_N` is clamped into
  1..10 seconds (default 3) BEFORE it is ever substituted into a payload, and every vendored payload is
  a single fixed `sleep`/`timeout`/`Start-Sleep` of exactly `%N` seconds - no loop, no amplifier, no
  hardcoded duration that could bypass the clamp.  So a probe delays an authorised target by at most a
  few seconds per parameter and can never become a denial-of-service.  `SCOURSH_DAST_CMDI_SLEEP=999`
  clamps to 10 and the sent surface never carries `999`; the suite pins both, and each fails under an
  unbounded reading.
- **Non-destructive, enforced by the payloads.**  A sleep reads nothing, writes nothing, exfiltrates
  nothing.  The suite scans the payload lines (not the prose comments) and fails the moment a
  destructive verb (`rm`/`curl`/`nc`/...) or an unbounded construct (`while`/`for`/`yes`/`fork`/...) is
  added.
- **Everything else is inherited from the shared engine**: injection where each parameter's `location`
  says (query AND body proven), every request through `http_request`, graceful degradation to a recorded
  `coverage_reduction`/`coverage_gap` on a missing payload file or an empty parameter surface, honest
  `checks_run`, and the optional `--authed` pass.
- **`active/cmdi.sh:active` was already in `modules/dast/engine.sh`'s `_DAST_PHASES` table**, so it runs
  under `scan_dispatch dast` at `--intensity active` with no engine change.

**DAST-17 (`active/pathtraversal.sh`) has landed - the third tier-4 injection probe, and it reuses
`inject_engine.sh` unchanged, exactly as DAST-14 anticipated.**
Unlike SQLi's three differential techniques it is a single check,
`DAST-INJ-PATH_TRAVERSAL-01`, because §7.3's own path-traversal design is one technique - "request
known-safe read-only markers ... and detect its signature; report access, don't harvest contents" -
not a family of them.
Two new vendored, tab/placeholder-format data files back it:
`modules/dast/payloads/pathtraversal-sequences.txt` (bounded `../`-depth-2-through-8 climb templates,
placeholder `%M`) and `modules/dast/payloads/pathtraversal-markers.txt` (`<marker's relative
path><TAB><ERE content signature>`, two rows: `etc/passwd` and `windows/win.ini`, the single most
universally-present read-only file on the two major server platforms).  Both degrade independently to
a recorded `coverage_reduction` when absent, mirroring `active/sqli.sh`'s own per-payload-file
degradation.
`tests/suites/dast-pathtraversal.sh` (22 assertions, no network, no Docker) is the mock-response proof.

Three decisions here are easy to get backwards, each pinned by a test naming the reading it fails
under (confirmed by deliberately breaking the implementation and watching the suite go red before
this ticket shipped):

- **The signal is a match against the marker's own CONTENT signature, never the presence of the
  traversal string in the response.**  A control endpoint that echoes the raw payload text back
  (`/echo` in the suite) must NOT flag - only a body that actually contains passwd-shaped or
  win.ini-shaped content does.  This is also why the finding's evidence names the signature that
  matched rather than reproducing the response body: §7.3's own "report access, don't harvest
  contents" is a property of what the evidence carries, not only of what the probe requests.
- **A parameter whose BASELINE already carries a marker's signature is skipped, not flagged.**  The
  signal has to appear only after injection to mean anything; a baseline check identical in spirit to
  `active/sqli.sh`'s own error-technique baseline check, applied here to every vendored marker before
  any traversal payload is sent.
- **This is the first probe to read the parameter inventory from
  `$SCOURSH_RUN_DIR/inventory/{endpoints,parameters}.json` directly, rather than trusting
  `SCOURSH_DAST_ENDPOINTS`/`SCOURSH_DAST_PARAMETERS` alone.**  AGENTS.md and this plan's own DAST-14 row
  already record that those two exports are resolved by `modules/dast/run.sh` BEFORE `crawl.sh` writes
  the inventory, so they are empty on the ordinary first run; `active/sqli.sh` inherited that gap
  un-worked-around.  `active/pathtraversal.sh` does not repeat it - it falls back to the run
  directory's own artifacts, the identical pattern `passive/headers.sh` already established for its
  endpoint file, extended here to the parameters file too.  The general fix still belongs to
  `modules/dast/run.sh` and is unchanged by this ticket.

**What DAST-17 deliberately did not build**: WAF-evasion encodings (double-encoding, null-byte, case
mangling) - §7.3's own framing is "prove a vuln exists via a signal, don't exploit it", and this probe
detects, it does not evade; a third or fourth marker file (e.g. `/etc/hosts`, `boot.ini`) beyond the two
`docs/DESIGN.md` §7.3 example calls for; and an authenticated-session-aware crawl of new surface (it
reuses whatever session `auth.sh` already obtained under `--authed`, the same DAST-14 pattern, but does
not widen the crawl itself).

**DAST-18 (`active/ssti.sh`) has landed - server-side template injection, and it added no line to
DAST-14's shared `active/inject_engine.sh`.**
It ships `modules/dast/active/ssti.sh` (the phase script `dast_run_phase` sources at tier `active`),
one vendored data file (`modules/dast/payloads/ssti-expressions.txt`), four `DAST-INJ-SSTI_*` records
appended to the shared `modules/dast/active/checks.rules`, and `tests/suites/dast-ssti.sh`
(91 assertions, no network and no Docker, every response composed by a recorded mock).
The phase table needed no edit: `modules/dast/engine.sh` has carried `'active/ssti.sh:active'` since
DAST-02, so landing the script alone flips `_DAST_PHASE_PRESENT` from `absent` to `ran`.
Six decisions in it are easy to get backwards; each is pinned by a case naming the reading it fails
under, and each was confirmed by MUTATING the implementation into that reading and watching the suite
go red - six mutations, six reds (5, 2, 11, 9, 2 and 1 failing assertions), one green baseline.

- **The signal is the EVALUATED result and never the reflection, and the payload is built so the two
  cannot be confused by accident.** Almost every parameter on almost every application reflects
  something, so a probe that flagged reflection is a false-positive generator - and the
  reflected-but-not-evaluated case is the half that fails in the direction that reads as a pass, the
  same lesson DAST-15 records for escaping. Each payload is flanked by the literal sentinel
  `sstiqzx` and the signature is that sentinel wrapped around the PRODUCT (`sstiqzx899sstiqzx`).
  **The invariant that makes it airtight is that the digit `8` occurs in every signature and in no
  payload**, so no delete, reorder, re-encode or partial strip of the bytes that were sent can
  manufacture the result - only arithmetic can. The suite re-derives that from the shipped file row
  by row rather than trusting the comment, and pins it with a control endpoint that runs a naive
  sanitiser (delete every template delimiter, echo the rest) and must stay silent.
- **The product is deliberately under 1000, and the reason is a false NEGATIVE.** FreeMarker - and
  any engine that formats numbers for a locale - renders `${9007*8117}` as `73,109,819`, with
  grouping separators, from four digits up. A plain-digit signature would then MISS the very family
  it was aimed at, and a miss reads as a clean result. Three digits are never grouped; the sentinel,
  not the number, is what carries the specificity.
- **Four check ids, one per engine family**, for the identical reason the three SQLi techniques have
  three: the DAST location profile (target, method, path_template, param_location, param_name)
  carries no component naming the engine, so one shared id would collide a Jinja2 hit and a
  FreeMarker hit on the same parameter onto one fingerprint and `findings_merge` would keep whichever
  sorted first. The suite asserts a `${...}`-evaluating endpoint yields the DOLLAR id and NOT the
  BRACES id; collapsing the map took 11 assertions red.
- **First confirmed family wins per parameter; the remaining families are not sent - and that is
  asserted on the REQUEST LOG, not on the finding count.** An application renders through one engine,
  so continuing spends requests against an authorised target to learn nothing. The discriminating
  assertion is a COMPARISON: a confirming endpoint costs 2 requests (baseline + first family) while a
  non-confirming one costs 5 (baseline + all four), so "stopped early on a hit" is distinguishable
  from both "sent everything anyway" and the opposite defect, "stopped early on a MISS", which would
  leave three engine families untested while still reading clean.
- **`checks_run` carries only the family ids whose payload really went out**, and every shipped family
  missing from that set gets its own `ssti_family_not_applicable` reduction naming it - DAST-29's H3
  defect (the field written from the passes ENTERED rather than the ids that RAN) applied here before
  it could ship. A run with one family selected records one id, not four.
- **The per-family `dast_check_selected` gate is pinned in BOTH directions, because the naive fix for
  each is the other's bug.** With the filter chain live, a deselected family sends zero requests
  (asserted on the log, since a probe that dialled the target and then declined to report is exactly
  what selection exists to prevent). With `dast_check_selected` ABSENT from the process - every
  direct-engine suite in this tree - the `declare -F` guard must fall through to PERMISSIVE, or the
  whole phase goes inert while every "stays quiet" assertion still passes green. This suite sources
  the REAL `modules/dast/engine.sh` rather than stubbing the function, so the whole-line membership
  test and the unset/empty fallback are the shipped ones.

**What DAST-18 deliberately did not build**, so the boundary is not rediscovered: any non-arithmetic
payload - no file read, no command execution, no sandbox escape, no object-traversal or class-loader
gadget chain - so the probe confirms "the server did the sum" and never escalates that into the code
execution it usually implies; Apache Velocity, whose VTL references are not expressions (`${29*31}`
renders literally and arithmetic needs a `#set(...)` DIRECTIVE, which assigns template-context state
and so sits outside the arithmetic-only contract); Thymeleaf's `__${...}__` preprocessing form; blind
or time-based SSTI, which has no reflection channel at all; and client-side template injection. Each
is a named gap in the module header rather than a silent absence.

**DAST-19 (`active/openredirect.sh`) has landed - the fourth tier-4 injection probe, built on
DAST-14's shared `active/inject_engine.sh` rather than beside it.**
It ships `modules/dast/active/openredirect.sh` (the phase script `dast_run_phase` sources at tier
`active`), two vendored data files under `modules/dast/payloads/`
(`openredirect-payloads.txt`, `openredirect-params.txt`), two `DAST-INJ-OPENREDIR_*` records appended
to the shared `modules/dast/active/checks.rules`, and `tests/suites/dast-openredirect.sh`
(62 assertions, no network and no Docker, every response composed by a recorded mock).
Six decisions in it are easy to get backwards; each is pinned by a case naming the reading it fails
under, and each was confirmed by MUTATING the implementation into that reading and watching the suite
go red - ten mutations, ten reds, one green baseline.

- **The signal is the AUTHORITY of the `Location` URL, never a substring of it.** The commonest safe
  behaviour of a redirect parameter is to reflect it while redirecting ON-ORIGIN
  (`Location: https://site/login?next=https://<sentinel>/`), so a substring test flags the single
  most common non-defect on the surface. `_or_url_host` is the parser and everything rests on it.
- **Userinfo is stripped at the LAST `@`, and a subdomain OF the sentinel is the sentinel's.** Both
  are FALSE-NEGATIVE directions, which is the worse kind because they read as a pass:
  `https://<site>@<sentinel>/` and `https://<site>.<sentinel>/` are exactly the two shapes that
  defeat a `startsWith(ourHost)` allow-list, so a probe that cannot see them cannot see the filters
  worth testing. The mirror image - `<sentinel>.<site>` - is the TARGET's own name and correctly does
  not match; a substring test gets that one wrong in the other direction.
- **The parser is never STRICTER than the browser that will follow the redirect.** `//host/`,
  `https:/host/` and `/\host/` are all off-origin redirects in a real client (WHATWG URL folds `\` to
  `/` and normalises one slash to two for a special scheme), so a parser that rejects them reports
  safe on a live open redirect.
- **The sentinel is a per-run RANDOM label under `.invalid` (RFC 6761 §6.4), and is deliberately not
  configurable.** Random is what removes the baseline: a `Location` naming it can only have come from
  this run's own request, so one response is sufficient evidence and no retest is needed. `.invalid`
  is what keeps the tool target-agnostic (§1, DAST-35) and means an accidentally-followed redirect
  reaches a name the DNS root is required never to answer for. A knob here would be a way to aim a
  scan's redirects at a host somebody chose, which is the same argument DAST-31 makes for the
  User-Agent product token being unremovable.
- **The redirect is detected and NEVER followed**, via a new opt-in `_INJ_MAX_REDIRECTS=0`. The scope
  gate would refuse the hop anyway, but relying on a control to FIRE is testing it rather than using
  it - and the suite pins the difference on the gate's own "redirect not followed" warning, which is
  the only observable the request log cannot see (no packet moves either way).
- **Two check ids, and both sinks are evaluated on the SAME response before either breaks.** The DAST
  fingerprint carries nothing naming the sink, so one id would make a `Location` finding and a
  meta-refresh finding on one parameter collide and dedupe to one - and breaking out after the header
  check reintroduces exactly that loss in control flow instead of in the fingerprint.

**Two additive changes outside this ticket's own files, both opt-in and both defaulting to the
pre-existing behaviour** (pinned by an assertion that fails if `active/sqli.sh`'s behaviour moved):
`inject_engine.sh` gained `_INJ_WANT_HEADERS` (capture the response headers into `_INJ_HEADERS` -
`http_request` publishes the `Location` to NO global, so the header capture is the only channel that
carries it out) and `_INJ_MAX_REDIRECTS` (a per-probe hop count).

**What DAST-19 deliberately did not build**: it probes a FILTERED SUBSET of the discovered parameters
- those named like a redirect destination, or whose observed example is already an absolute URL - and
records the count it declined as a `coverage_reduction`. Probing all of them would be six requests per
discovered parameter. A JavaScript `location =` sink is out of scope: this probe reads the `Location`
field and meta-refresh, which is the ticket's own wording, and a script-sink probe belongs with
DAST-15's own reflection machinery.

**DAST-20 (`active/xxe_ssrf.sh`) has landed - the fifth tier-4 injection probe, and the §7.3 XXE/SSRF
family.**
It ships `modules/dast/active/xxe_ssrf.sh` (the phase script `dast_run_phase` sources at tier `active`;
the `'active/xxe_ssrf.sh:active'` row was already in `_DAST_PHASES`, so no engine.sh edit was needed)
and three check records appended to the shared `modules/dast/active/checks.rules`:
`DAST-INJ-XXE_ENTITY-01` (medium/medium, CWE-611, A05:2021), `DAST-INJ-XXE_SSRF-01` (critical/high,
CWE-918, A10:2021) and `DAST-INJ-SSRF_PARAM-01` (critical/high, CWE-918, A10:2021).
`tests/suites/dast-xxe-ssrf.sh` (34 assertions, no network, no Docker, driven from recorded responses)
is the proof.
Unlike every other tier-4 probe, this one composes its OWN request for two of its three techniques
rather than calling `inject_send`: `_xs_send_xml` is a full BODY OVERRIDE (Content-Type forced to
`application/xml`, the body replaced wholesale) built the same way `inject_send` assembles a
request's siblings, because the injection point for an XXE probe is the whole document, not one field
of it. The third technique (`DAST-INJ-SSRF_PARAM-01`) reuses `inject_send` unmodified.

**The sentinel, and how scope is enforced at probe time - the ticket's central constraint.**
docs/DESIGN.md §7.3 requires "detection via safe internal sentinels only, and only against in-scope
hosts," and the two things that make that concrete here are: (1) the value this probe ever puts into a
payload - an entity's `SYSTEM` identifier, or a parameter's value - is drawn EXCLUSIVELY from
`lib/http.sh`'s own already-loaded scope-tuple set (`_HTTP_SCOPE_ID`/`_HTTP_SCOPE_HOST`/...), never
invented and never operator-suppliable through any flag; and (2) the two calls this script itself
makes to the network - the ordinary request to the endpoint under test, and the one-shot "oracle"
fetch of the sentinel's own content - both go through `http_request`, the same chokepoint every other
probe's traffic uses. `_xs_sentinel_set` is the one function that chooses the host: an `extra-host`
declared for the current target in `config/scope.conf` when the operator added one (the stronger,
cross-host "operator-declared sentinel" case), else the target's own `base-url` (a self-referential
fallback, still fully in scope, that keeps the probe usable on the ordinary scope.conf that declares no
extra-host at all). The ACTUAL SSRF/XXE connection - the one that matters - is made by the TARGET, not
by scoursh, and is never observed directly; the whole safety property rests on the payload never naming
anything the operator has not already authorised this run to reach itself.

**Confirmation is by CONTENT SIGNATURE, never by byte-length or status code alone.** `_xs_oracle_fetch`
fetches the sentinel once per run and keeps a short (<=96 byte) slice of its body; a technique-2/3 hit
requires that exact slice to appear in the endpoint's response AND be absent from that same endpoint's
own baseline (the "noisy" check every other §7.3 probe already applies to its own signatures). The
slice is taken from the MIDDLE of the body rather than the start, because a response's opening bytes
are the most likely to be boilerplate shared site-wide - relevant precisely because the self-referential
sentinel case makes "the sentinel's content" and "this endpoint's own ordinary content" the same
application. Three ids rather than one because the DAST location profile names no defect class, and an
internal-entity reflection, an XML-driven SSRF confirmation, and a plain-parameter SSRF confirmation are
three different code paths with three different remediations.

**A noisy baseline SKIPS the external-entity/parameter probe entirely, rather than sending it anyway
and discarding the result.** Once the baseline already carries the oracle's signature, no response to
the follow-up request could ever be attributed to it, so sending it would only spend a request (and the
tension-16 budget) to learn nothing - `tests/suites/dast-xxe-ssrf.sh`'s `/formnoisy` fixture pins the
exact request count this saves.

**What DAST-20 deliberately did not build**: any attempt to reach a cloud metadata endpoint or any host
the operator did not declare - docs/DESIGN.md §7.3 forbids it outright, and DAST-36's amendment for this
ticket states plainly that no `--allow-intrusive`/`--i-own-target` affirmation widens what a payload may
name; and any BLIND SSRF confirmation via timing (an unreachable-but-attempted destination would need an
address outside scope to produce a measurable delay, which is exactly the boundary this ticket exists to
hold). A blind SSRF that content-reflection cannot confirm is left as a named coverage_reduction, not
reported as either a finding or a clean result.

**DAST-22 (`active/ldapi.sh`) has landed - a tier-4 injection probe built entirely on DAST-14's shared
`inject_engine.sh`.**
It ships `modules/dast/active/ldapi.sh` (the phase script `dast_run_phase` sources at tier `active`),
two vendored payload files plus one signature file under `modules/dast/payloads/`
(`ldapi-error-payloads.txt`, `ldapi-error-signatures.txt`, `ldapi-boolean-pairs.txt`), and two check
records in `modules/dast/active/checks.rules` (`DAST-INJ-LDAP_ERROR-01` high/high,
`DAST-INJ-LDAP_BOOLEAN-01` critical/medium; `CWE-90`, `A03:2021`, type tag `active`,
`coverage-scope: target`).  `tests/suites/dast-ldapi.sh` (28 assertions, no network, no Docker, driven
from recorded responses; registered in `tests/run-tests.sh`) is the mock-response proof.  The phase was
already in `modules/dast/engine.sh`'s `_DAST_PHASES` table (`active/ldapi.sh:active`), so no
registration edit was needed.

Three decisions here are easy to get backwards, each pinned by a test naming the reading it fails under:

- **TWO techniques, not three, and it is stated rather than silently short.**  §7.3 names LDAP
  injection as "filter-breaking payloads, response/error differential" - an error signal and a boolean
  differential.  There is deliberately no time-based technique: an LDAP search filter has no portable
  sleep primitive (unlike SQL's `SLEEP`/`WAITFOR`/`pg_sleep`), so a time-based LDAP probe would invent a
  signal the protocol does not offer.  A run records exactly the two checks it can perform and the suite
  asserts `checks_run` names no `LDAP_TIME` check - claiming a third would be the overstated coverage
  §15 forbids.
- **The boolean pairs are well-formed filter clauses, not filter breaks.**  The "true" side closes the
  value and appends a matching clause (`)(|(cn=*)`, a wildcard/`objectClass=*` that reproduces the
  baseline result set rather than broadening past it); the "false" side is otherwise identical but
  appends a never-matching sentinel (`scoursh-no-such-entry-zq`).  The probe reuses DAST-14's
  `inject_body_sig` to strip the injected value before comparing lengths, so a page that merely reflects
  the payload is not read as a differential - the suite's reflecting-endpoint control pins that.  Same
  SQLi boolean model (true ~ baseline, false ≠ baseline, true ≠ false), confirmed on retest.
- **Non-destructive by construction.**  Every payload is a SEARCH filter (a broken paren, a wildcard, an
  always/never-matching clause); LDAP writes are `add`/`modify`/`delete`/`modrdn` LDIF operations and no
  search filter can carry them, so the contract holds by shape.  A suite assertion fails the moment a
  mutating LDIF verb appears in any `ldapi-*.txt` file.

**DAST-23 (`active/crlf.sh`) has landed - a tier-4 injection probe built on DAST-14's shared
`inject_engine.sh`, plus one lift from tier 2.**
It ships `modules/dast/active/crlf.sh` (the phase script `dast_run_phase` sources at tier `active`),
one vendored payload file with exactly two templates (`modules/dast/payloads/crlf-payloads.txt`), and
two check records in `modules/dast/active/checks.rules` (`DAST-INJ-CRLF_HEADER_INJECTION-01` high/high,
`DAST-INJ-CRLF_RESPONSE_SPLITTING-01` critical/high; both `CWE-113`, `A03:2021`, type tag `active`,
`coverage-scope: target`). Unlike every sibling probe, it also sources
`modules/dast/passive/headers_engine.sh` for its response-header reader
(`hdr_parse_capture`/`hdr_present`) rather than growing a second one - that file's own header invites
exactly this lift for a later ticket that needs the same reader. `tests/suites/dast-crlf.sh` (51
assertions, no network, no Docker, driven from a mock transport that locates the header/body boundary
the same way a real HTTP client does - the first CRLFCRLF - so an injected blank line really does move
it in the fixture; registered in `tests/run-tests.sh`) is the proof. The phase was already in
`modules/dast/engine.sh`'s `_DAST_PHASES` table (`active/crlf.sh:active`), so no registration edit was
needed.

Four decisions here are easy to get backwards, each pinned by a test naming the reading it fails under:

- **The marker is generated per run, never vendored, for the identical reason
  `active/openredirect.sh`'s own sentinel is generated.** A header-name marker and a body sentinel are
  drawn fresh from `$RANDOM`/`$$` every run; nothing but this run's own request could have put that
  exact string in the response, so a single confirmed response is sufficient evidence with no benign
  baseline to compare against.
- **Two check ids for ONE root cause observed at two possible strengths, and they are mutually
  exclusive per parameter - the opposite shape from `openredirect.sh`'s two genuinely independent
  sinks, which both fire together.** The escalated payload (a forged status line plus a body sentinel
  landing at the true front of the response body) is sent only after the bare payload already confirmed
  the marker header, and whichever signal the escalation attempt actually produces is the one and only
  finding reported for that parameter - never both, never the weaker one suppressed silently.
- **A `header`-location parameter is never a candidate, and that is a correctness requirement rather
  than a scope choice.** `inject_send` routes a `header`-location value straight to
  `http_request_header`, which `die`s the WHOLE SCAN PROCESS the instant a value carries a CR or LF -
  refused there as request smuggling against this scanner's OWN outbound request, a different and
  unrelated protection from the one this probe tests for on the target. The suite proves the exclusion
  by mutating it away and observing the whole test process abort with exit `4`
  (`SCOURSH_EXIT_INPUT`), not merely one assertion going red.
- **The payload file carries no raw CR or LF byte on disk.** A raw CR/LF cannot survive a line-oriented
  `read -r` as DATA - an embedded LF is indistinguishable from the line ending - so the file uses its
  own placeholders (`%NL` for "insert one CRLF here", `%H`/`%K` for the per-run marker) and the probe
  expands them after reading, exactly as `ssti-expressions.txt` and `nosqli-boolean-pairs.txt` each
  established their own placeholder vocabulary for their own shape of payload.

**DAST-24 (`active/hosthdr.sh`) has landed - docs/DESIGN.md §7.3's "Host-header injection" bullet, and
the first tier-4 probe that is NOT built on DAST-14's shared `active/inject_engine.sh`.**
It is endpoint-shaped rather than parameter-shaped (it varies a request HEADER, not a discovered
parameter), so it reuses `passive/cors.sh`'s own candidate-list/dedupe pattern instead: it ships
`modules/dast/active/hosthdr_engine.sh` (the pure half - the sentinel, URL-authority parsing for the
`Location` sink, the body-substring sink, the probe, and finding emission) and
`modules/dast/active/hosthdr.sh` (the phase script, which resolves the endpoint inventory and drives
it), plus two `DAST-HOSTHDR-*` records appended to the shared `modules/dast/active/checks.rules`.
`tests/suites/dast-hosthdr.sh` (49 assertions, no network, no Docker) is the mock-response proof.  The
phase table needed no edit: `modules/dast/engine.sh` has carried `'active/hosthdr.sh:active'` since
DAST-02.

- **Two check ids, one per SINK (body vs. `Location`-authority), not one per HEADER TECHNIQUE.**  The
  DAST location profile (target, method, path_template, param_location, param_name) already has a slot
  for "which request field" - `loc_param_name` carries `Host` or `X-Forwarded-Host`, exactly as
  `cors.sh` carries its own probe in `loc_param_name=Origin` - so the technique needs no id of its own.
  The sink DOES need one: it is not part of the profile, so a body hit and a `Location` hit on one
  endpoint would otherwise collide onto one fingerprint and `findings_merge` would keep whichever
  sorted first, the same argument `openredirect.sh`'s own header/meta split makes.
- **The body sink is a plain substring test; the `Location` sink is authority-only, and that asymmetry
  is deliberate, not an oversight.**  The sentinel is injected ONLY as a header value never echoed
  elsewhere in the request, so wherever it surfaces in the body it can only have been read off that
  header - there is no realistic false-positive shape to guard against there, unlike
  `openredirect.sh`'s own parameter-reflected payloads.  `Location` is different in kind: it has
  exactly one authority, and the finding's own claim ("this redirects to a host we control") needs the
  authority-only parser `openredirect.sh` already proved correct, reused as a duplicate (not a shared
  call - `openredirect.sh` is a phase script that runs its own probe at source time, so there is no
  engine-only file to source it from) rather than re-derived.  Pinned by mutation: replacing the
  authority parse with a substring test breaks exactly the two assertions built for it.
- **Non-destructive by construction, and the ticket's own posture ("report the reflection; do not
  attempt cache poisoning") is read literally.**  Only GET/HEAD endpoints the crawler already
  inventoried are probed - the identical restriction `cors.sh` applies to itself - no form is
  submitted, and confirming the "reset-poisoning" sink §7.3's own bullet names would need a POST to a
  real reset endpoint and, against a real target, a real outbound email; that is out of scope for a
  detection-only probe (the same boundary DAST-03's own declined "live" enumeration probe draws), and
  the body-reflection check is documented as the right-sized substitute, since a poisoned reset link
  built from the Host header shares the identical root cause.

### Tier 5 - §7.4 auth, API, and access-control checks (5 scripts)

| # | Ticket | Depends on |
|---|---|---|
| DAST-26 **(landed)** | `jwt.sh` - `alg:none`, empty-secret HS256, weak-secret list, RS->HS confusion | DAST-01/02, DAST-03 (needs a sample/test-account token and a protected endpoint to replay against) |
| DAST-27 **(landed)** | `graphql.sh` - introspection + correlated key-exposure | DAST-01/02, DAST-04 (needs the GraphQL endpoint in the inventory); the soft data dependency on DAST-10's leakage finding for the correlated-key case was never a build blocker and is discharged as a *contract* rather than as code: this ticket ships the DAST-side correlation input and DAST-10 supplies the other contributor. See the landing note under this table. |
| DAST-28 | `ratelimit.sh` - missing-throttling burst probe | DAST-01 (must draw down the *same* per-run request budget DAST-01 owns, since this is the one check §7.4 flags as intentionally multi-request) |
| DAST-29 **(landed)** | `authz.sh` - IDOR / excessive data exposure | DAST-03 with `requires-identities: 2` (two labelled identities), DAST-04 (object-reference endpoints from the parameter inventory) |
| DAST-30 **(landed)** | `passive/transport.sh` - plaintext-exposure / mixed-content | DAST-04; sequence close to DAST-07 (`tls.sh`), which it complements, per the note under DAST-07 |

**DAST-30 moved OUT of this tier's own intensity floor**: the script is
`modules/dast/passive/transport.sh` at phase-table tier `passive`, not `transport.sh:active`.  See the
landing note immediately below for why, and `modules/dast/engine.sh`'s own note at the row.  It is
still §7.4 work and is still listed in this table; only its tier changed.

#### What DAST-30 (`passive/transport.sh`) shipped, and the six things about it that are easy to get backwards

**DAST-30 has landed.**  It ships `modules/dast/passive/transport_engine.sh` (the pure half: the
sub-resource extractor, RFC 3986 reference resolution through `crawl_url_resolve`, the
(scheme, path-template) endpoint chooser, the sensitivity scan and the redirect verdict),
`modules/dast/passive/transport.sh` (the phase script `dast_run_phase` sources), and five
`DAST-TRANSPORT-*` script checks appended to the shared
`modules/dast/passive/checks.rules`.  `tests/suites/dast-transport.sh` is the proof - 109
assertions, no network and no Docker, driven from recorded response heads AND bodies replayed
into `lib/http.sh`'s own capture sinks.

- **THE PHASE TABLE ROW MOVED, DELIBERATELY, FROM `transport.sh:active` TO
  `passive/transport.sh:passive`.**  DAST-02 transcribed every tier-5 row from `docs/DESIGN.md`
  §7.4's section HEADING ("Active - auth, API, and access-control checks"), which is right for
  this section's other four scripts and wrong for this one.  `modules/dast/engine.sh`'s own phase
  table already specified the remedy - "a later ticket whose checks legitimately carry a LOWER type
  tag than the tier its row declares here must change that row in the same change and say why" - and
  this is that change.  Three reasons, in the file's own note and in the script header: nothing here
  mutates target state (every request is a plain GET to the operator's `base-url` or an endpoint an
  earlier phase already fetched), §7.4's own wording for this bullet calls it a complement to "the
  TLS **passive** check", and at `active` it would never run at all, since `--intensity` defaults to
  `passive` and anything above it additionally requires `--i-own-target`.  The records carry the
  matching `passive` type tag so tension 15's two gates agree.  `tests/suites/dast.sh`'s phase-table
  coverage list moved with it, in the same change.
- **A PLAINTEXT `<a href>` IS NOT MIXED CONTENT, AND THIS IS THE FALSE POSITIVE MOST WORTH
  KNOWING ABOUT.**  A hyperlink loads nothing into the secure document; the user navigates away and
  the address bar says so.  The naive reading - match `http://` anywhere in the body - fires on every
  external link on every page, so a site with a plaintext footer link outranks one whose login bundle
  is fetched over port 80.  The extractor emits `nav` references anyway, precisely so the suite can
  assert their ABSENCE from the findings: a class that is never emitted cannot be tested for.  The
  run records a `notes` line counting them, so an operator who can see the link in their own markup
  knows the phase looked and decided rather than missed it.
- **THE PLAINTEXT URL IS REQUESTED WITH `max_redirects` 0, AND THAT IS THE WHOLE MECHANISM OF THE
  REDIRECT CHECK.**  `http_request` follows redirects internally and reports the FINAL status, so a
  target that correctly 301s port 80 to HTTPS and one that serves the page on port 80 both come back
  `200` - the two facts the check exists to separate become one string.  Two further readings are
  pinned in the same section and each fails under the obvious "is it a 3xx" implementation: a 301 to
  another `http://` URL (a host-canonicalising redirect) does not leave plaintext, and a
  scheme-relative `Location` is resolved by the browser against the CURRENT scheme, so it redirects
  http to http.
- **THE ENDPOINT DEDUP KEY IS (SCHEME, PATH TEMPLATE), NOT `hdr_endpoints_load`'S PATH TEMPLATE
  ALONE.**  `passive/headers.sh` is right to collapse `http://h/login` and `https://h/login` into one
  candidate - it asks about a header the application sets once.  Here the two URLs are the entire
  question, and borrowing that key drops whichever twin sorts second, so the check reports clean on
  exactly the target that has the defect.  Everything else about the chooser is deliberately kept in
  step with `hdr_endpoints_load` rather than re-argued.
- **PLAINTEXT EXPOSURE AND A MISSING TLS REDIRECT ARE TWO CHECKS, NOT ONE AT TWO SEVERITIES.**
  `NO_HTTPS_REDIRECT` is about the transport and is true of a plain marketing page;
  `PLAINTEXT_SENSITIVE` requires an observed credential control, `Set-Cookie`, or authenticated
  session, and its evidence names which.  Collapsing them makes every plaintext site a
  high-severity data-exposure finding and drowns the ones that really are.  The active/passive
  mixed-content split is the same kind of distinction rather than a severity opinion: browsers BLOCK
  blockable mixed content and merely downgrade the padlock for the optionally-blockable kind.
- **RESOLUTION IS PINNED ON THE ACCOUNTING, NOT ON THE FINDINGS, AND A MUTATION RUN IS WHAT FOUND
  THAT.**  The obvious assertion - "a protocol-relative reference produces no finding" - passes under
  BOTH resolving the reference and simply skipping anything with no scheme of its own, because only
  an absolute `http://` reference can ever be mixed content on an https page.  It therefore pinned
  nothing.  What discriminates is `_TR_REF_TOTAL`, "references this check could actually judge":
  under the skip it silently becomes "references that happened to be written absolutely", so a page
  whose sub-resources are all relative reports zero examined while looking exactly like a fully
  inspected one.  The suite asserts the count, and the first draft's overclaiming wording was
  corrected rather than left in.

**What DAST-30 deliberately did not build**, so the boundary is not rediscovered:

- **No TLS inspection of any kind.**  The handshake, the certificate and its dates and hostname
  binding, the protocol version and the cipher suite are DAST-07 (`passive/tls.sh`) and this family
  opens no connection of its own.  The two are complements, which is what §7.4's own sentence for
  this bullet says.
- **No HSTS check.**  `Strict-Transport-Security` is DAST-05's `DAST-HDR-HSTS_*` family.
  `NO_HTTPS_REDIRECT`'s remediation names it as the companion control rather than restating it, and
  the suite asserts no `DAST-TRANSPORT-HSTS*` id exists.
- **No cookie-attribute check.**  The `Secure` attribute is DAST-06's `DAST-COOKIE-NO_SECURE-01`;
  this family records only that a cookie was ALREADY sent in the clear, and says so in the evidence.
- **No sub-resource is ever REQUESTED.**  A discovered `http://` script URL is classified from the
  markup and never fetched, so the scope pre-check on it governs reportability of an off-target
  reference rather than gating a request that is never made.  This is deliberate and is the honest
  reading: a third-party CDN loaded over plaintext is the COMMONEST real mixed-content case and is
  out of scope by definition, so dropping out-of-scope references would produce a false negative on
  the case that matters most.  The document URLs the phase does request all go through
  `http_gate_url` first and then `http_request`, which re-gates them.
- **The client-rendered (SPA) gap applies here too and is inherited, not restated.**  A route or a
  sub-resource injected by JavaScript is invisible to this check exactly as it is to `crawl.sh`, and
  `crawl.sh`'s own recorded gap is the one that says so.

**DAST-29 (`authz.sh`) has landed.**
It ships `modules/dast/authz_engine.sh` (the pure half: candidate extraction from DAST-04's frozen
inventory, the oracle, the sensitive-field scan), `modules/dast/authz.sh` (the phase script
`dast_run_phase` sources), `modules/dast/checks.rules` (four `DAST-AUTHZ-*` script checks, all
`tags: active` matching the phase table's own `authz.sh:active` floor, and all
`requires-identities: 2`), and `modules/dast/sensitive-fields.txt` (the vendored, operator-editable
field list, overridable through `SCOURSH_DAST_SENSITIVE_FIELDS_FILE`).
`tests/suites/dast-authz.sh` is the proof: 189 assertions, no network and no Docker, driven from a
scripted SERVER keyed on (path, identity) rather than a canned-status queue - the correctness of this
check IS which identity is served which object, and a queue lets a probe pass by asking for the wrong
thing in the right order.

**A QA pass on the first landing found six defects, all now fixed and each pinned by a case in the
suite's section H that was observed red against the shipped code and green after the fix.**
Five of the six were false or missing COVERAGE records rather than wrong findings, which is this
module's most expensive failure class, and the full account of each is in `AGENTS.md`'s DAST-29
bullets rather than restated here. In short: `loc_method` was a hardcoded `GET` and collided two
fingerprints (H1); `HEAD` was admitted as a candidate although the oracle compares response bytes,
and produced two factually wrong coverage records including a zero-byte body reported as over the
512 KiB parse bound (H2a-H2d); `DAST-AUTHZ-OTHER_IDENTITY_DATA-01` was written to `checks_run` on
runs where it could not execute at all, which is every `bearer`/`api-key` identity (H3); the
`no object reference` reason claimed entries carried none when they were never examined, and the
by-design write-endpoint gap was lost on exactly that path (H4); the exposure-endpoint cap truncated
silently (H5); and the `401` arm of `authz_status_refused` was unreachable because the probe went
through `dast_auth_request`, whose 401 handling marked the identity `failed` for the whole run (H6,
H6b).

Seven decisions here are easy to get backwards.
Each is pinned by a case naming the reading it fails under, and each was confirmed by writing the
wrong version and watching the suite go red rather than by reasoning about it.

- **The unauthenticated control is required, and "public" is DIGEST EQUALITY with an identity's own
  response rather than the anonymous status code.** Without the control every public object on the
  target is reported as a cross-user read. With a status-only reading, an application that answers a
  logged-out request with a 200 login page - the overwhelmingly common shape - suppresses every real
  finding on itself, and that failure reads as a clean report. Case C4 is red under it.
- **A shared object is TWO check ids, separated by a refusal observed ELSEWHERE under the same path
  template, and the whole group is probed before either is emitted.** The refusal is the witness that
  the endpoint enforces per-object ownership at all; with one, the shared object is
  `DAST-AUTHZ-IDOR-01` at high confidence, without one it is `DAST-AUTHZ-CROSS_IDENTITY_READ-01` at
  medium and the finding says so. One id is not available: the DAST location profile
  (target, method, path_template, param_location, param_name) names nothing that distinguishes them,
  so the two would share a fingerprint and `findings_merge` would keep whichever sorted first. Under
  "always emit the confirmed id" case C2 goes red; under "always emit the observation" case C1 does.
- **Read-only is enforced at CANDIDATE SELECTION, never at the call site.** A POST/PUT/PATCH/DELETE
  inventory entry never becomes a candidate, so no later edit can reach a mutation by forgetting a
  check, and the guarantee is asserted over a REQUEST LOG rather than a return value - the only form
  of the claim a test can falsify.
- **What counts as an object reference is `lib/findings.sh`'s `path_template_of`'s own four shapes,
  and the suite asserts the two against each other rather than restating them.** Disagreement is a
  real defect in both directions: probe a segment the fingerprint treats as a literal and one
  endpoint's findings split; skip one it collapses and the check has no candidates on an endpoint
  whose findings it would merge. A slug (`/users/jane`) is deliberately excluded, because admitting
  arbitrary path words spends the request budget on `/about` and `/pricing` - a stated narrowing the
  phase records, not a claim that slug-keyed IDOR does not exist.
- **The exposure pass reads FIELD NAMES and never field values, and the "other identity" needle never
  becomes a pattern argument.** The needle is an identifier out of `config/auth.conf`, a mode-600
  credential file, so the test is a pure-bash substring comparison over a bounded read rather than a
  `scan_match` (tension 9 handling rule 1: every engine takes its pattern on argv). It is never
  echoed into the evidence either - the finding names the identity LABEL. An identifier that is a
  substring of the other identity's own is refused with a recorded reason rather than reported.
- **The digest comparison's cost is stated rather than assumed away.** A response embedding a
  per-request nonce, CSRF token or timestamp never compares equal, so its IDOR goes unreported. That
  is a false NEGATIVE, which is the direction to fail in for a check that accuses an application of
  leaking one user's data to another, and the phase records a `coverage_gap` naming the count
  whenever both identities read an object and the bytes differed.
- **Every skip returns 0 with a recorded reason, per this ticket's own wording.** No `--authed`, one
  authenticated identity where two are configured, no inventory, an unreadable field list: each
  records a `coverage_reduction` and a human-readable `coverage_gap`, and the suite asserts the exit
  status AND the reason for each. Silence would read as "this application enforces object-level
  authorization", which is the most expensive way for this check to be wrong.

**One testing lesson worth carrying beyond this ticket: never assert a check id against raw shard
text.**
`DAST-AUTHZ-CROSS_IDENTITY_READ-01`'s remediation deliberately NAMES `DAST-AUTHZ-IDOR-01`, so a
substring test over the shard finds the confirmed id on a run that emitted only the observation -
`assert_not_contains` then fails on correct behaviour, and `assert_contains` would PASS on the
rejected implementation. `tests/suites/dast-authz.sh`'s `_shard_check_ids` decodes through
`lib/findings.sh`'s own `finding_decode` for that reason.

**What DAST-29 deliberately did not build**, so the boundary is not rediscovered: object-level
authorization on WRITE endpoints (§7.4 restricts this check to read-only references, and the phase
records how many inventory entries it passed over for that reason), slug-keyed references, a
live user-enumeration probe (still DAST-03's stated `--allow-intrusive` follow-up), and any fix to
`modules/dast/run.sh`'s inventory-export ordering - it falls back to
`$SCOURSH_RUN_DIR/inventory/endpoints.json` for itself, exactly as `passive/headers.sh` does, and
leaves the export to the ticket that owns it.

**`modules/dast/checks.rules` is the tier-5 shared registry, and DAST-27 through DAST-30 append to it
rather than creating one of their own.**
DAST-26 landed with `jwt.sh` but registered none of the five `DAST-JWT-*` ids it emits, so tension 12
could compute no coverage for them and tension 15's filter chain could neither select nor drop them - a
run that genuinely tested a target's JWT verification was indistinguishable, in `state/`, from one that
never looked.
A follow-up ticket closed that: `modules/dast/checks.rules` now carries all five records, and `jwt.sh`
and `jwt_engine.sh` consult `dast_check_selected` so the records GATE the probes rather than only
describing them.
Three things about that file a tier-5 peer needs before touching it:

- **It sits at `modules/dast/`, one level above `passive/` and `active/`, and it has to.**
  `rules/RULE-FORMAT.md` §9's path table reserves the basename `checks.rules` repository-wide for the
  §9.5 schema and makes every other path `E070`, so a per-ticket `jwt-checks.rules` is not a legal
  record file; §9.5's `script` value is MODULE-relative, so `script: jwt.sh` resolves only from a
  registry at this level, exactly as `script: passive/cookies.sh` resolves only from `modules/dast/`
  as its root.
  `graphql.sh`, `ratelimit.sh`, `authz.sh` and `transport.sh` are all tier-5 phases at that same
  level, so all four belong here.
- **It is APPEND-ONLY between peers.**  A merge conflict in it is resolved by keeping BOTH blocks,
  never by choosing a side - the same rule `modules/dast/passive/checks.rules` already carries after
  DAST-05 and DAST-06 landed in parallel and each appended its own block.
- **The gate is `dast_check_selected`, which does not exist in the tree yet.**  Every call site guards
  it with `declare -F dast_check_selected >/dev/null` and runs everything when it is absent, which is
  the "empty means all selected" fallback every direct-engine test relies on; a fail-closed default
  would make every DAST phase inert while every "stays quiet" assertion still passed green.
  Defining it in `modules/dast/engine.sh` is filed as its own ticket.

**DAST-28 (`ratelimit.sh`) has landed, and it is the ticket that carries this plan's one behavioural
amendment.**
It ships `modules/dast/ratelimit_engine.sh` (the pure half: the vendored rate-limit header family, the
`Retry-After` usability test, the burst arithmetic and the verdict), `modules/dast/ratelimit.sh` (the
phase script `dast_run_phase` sources) and `modules/dast/checks.rules` (two `DAST-RATE-*` script
checks, both tagged `active`, both `coverage-scope: target`).
`tests/suites/dast-ratelimit.sh` is the proof - 70 assertions, no network and no Docker, driven from
recorded response heads replayed into `lib/http.sh`'s own capture sink, and registered in
`tests/run-tests.sh`'s `SUITES` array.
Seven things about it are worth carrying here, because a peer tier-5 ticket will otherwise rediscover
them the expensive way.

- **The amendment is enforced as FOUR gates, and the second is a strengthening this plan did not
  state.**  The amendment says an unaffirmed run must not execute and must record a `coverage_gap`
  naming the scanner's own rate ceiling; that is gate 1.  But the affirmation LIFTS the 4/s ceiling and
  does not RAISE the rate, so an operator who affirms and leaves `requests-per-second` at its default
  gets a fifty-request "burst" trickled out over twelve seconds - the identical silent false negative,
  one step further in.  Gate 2 therefore refuses a run whose EFFECTIVE rate is still at or below 4/s
  and names the config key to change.  Gate 3 is the budget, gate 4 an idempotent endpoint.  Every one
  of them is asserted on a REQUEST LOG rather than on a return value, so "it refused" cannot be
  satisfied by a phase that sent traffic and then returned 0.
- **`--i-own-target` is compared against the target, not merely read.**  It is a key rather than a
  switch (DAST-32's own wording), so an affirmation naming target A does not license a burst against
  target B; a run that scoped both would otherwise burst the one the operator never affirmed.
- **The budget is READ from `lib/http.sh`, never re-implemented, and the reader lives there.**
  `http_budget_remaining_set` is new in that file's section 11, beside the counter it reads, for the
  same reason tension 19 puts the gate at `http_request`.  Because every burst request goes through
  `http_request`, the draw-down is not something the module has to remember to do - it is what the
  chokepoint does with any request - so the amendment's "must draw down the *same* per-run request
  budget DAST-01 owns" is structural rather than a convention.  What the module adds is spending at
  most HALF of what is left: `lib/http.sh`'s budget refusal is fatal (exit 5), so a probe sized to the
  whole remainder would end the run for every phase and every target after it.
- **The read is not a reservation, and saying so is the point.**  Nothing takes budget out of
  circulation; the only charge happens inside `_http_throttle`'s critical section.  Promoting it to a
  reservation would leak budget for the rest of the run whenever a caller died mid-burst.
- **A 503 is NOT throttling, and a rate-limit HEADER without a 429 is not a finding.**  A target that
  collapses under the burst is the worse outcome, and counting its 503 as a throttle would turn that
  into a clean bill of health for the very control being tested - `lib/http.sh`'s own breaker draws the
  same line from the other side (a 5xx is a failure it counts; a 429 is not).  And a target that
  publishes `RateLimit-*`/`X-RateLimit-*` on every response HAS a limiter this bounded burst simply did
  not reach; folding that into the finding would fire this check against every correctly-configured API
  in the world, while folding it the other way makes the check inert.  Both directions are pinned in
  the same suite section, so neither half can be satisfied by breaking the other.
- **The burst stops at the first 429 and at nothing else.**  Once the target has said "too many",
  further requests can only confirm what is known, against a host that has just asked for less.  The
  NEGATIVE case has no such exit: "no 429 in N requests" is only true of N, so it earns the full burst.
- **Two check ids, not one.**  `DAST-RATE-NO_THROTTLE-01` (no throttle at all) and
  `DAST-RATE-NO_RETRY_AFTER-01` (throttles, but the 429 carries no usable back-off) are different
  defects with different severities and remediations; the DAST fingerprint carries no component naming
  the defect, so one shared id would make them collide and `findings_merge` would silently keep one -
  the identical argument `active/checks.rules` already records for the SQLi family.  A `Retry-After` a
  client cannot parse counts as absent, and is in fact worse than absent, because a client that parses
  it gets zero and retries immediately.

#### What DAST-27 (`graphql.sh`) shipped, and the four things about it that are easy to get backwards

**DAST-27 has landed, and it is the second tier-5 check** (after DAST-26's `jwt.sh`).
It ships `modules/dast/graphql_engine.sh` (the pure half: endpoint classification, the introspection
document, the response classifier and the finding), `modules/dast/graphql.sh` (the phase script
`dast_run_phase` sources), `modules/dast/checks.rules` (a NEW file - the §9.5 registry for the phase
scripts that sit at `modules/dast/` top level, one record so far) and `tests/suites/dast-graphql.sh`
(117 assertions, registered in `tests/run-tests.sh`, driven entirely from recorded responses through a
stubbed transport - no network, no Docker).
`modules/dast/engine.sh`'s phase table already carried `graphql.sh:active` from DAST-02, so **nothing in
`engine.sh` needed editing**: the file landing IS the registration.

- **Whether an endpoint is GraphQL is decided from the INVENTORY, never by probing.** The obvious
  alternative - POST an introspection document at every endpoint and see which one answers - sends
  unsolicited GraphQL traffic to every URL the crawler found, on a run whose application has no GraphQL
  at all. The four signals are `source: graphql`, a GraphQL media type, the managed-GraphQL DNS shape
  (§8.5), and the conventional mount path, strongest first. With none of them the phase sends **zero**
  requests and records a declared `reason=no_graphql_endpoint` reduction plus a `coverage_gap` - because
  "this application has no GraphQL" and "scoursh did not look" are different facts.
- **The response is PARSED, never grepped, and the naive reading fails in the direction that reads as a
  FINDING.** A server with introspection correctly DISABLED answers with
  `{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema"}]}` -
  the literal string `__schema` appears, quoted inside the very error message saying introspection is
  off. `case $body in *__schema*)` therefore reports a misconfiguration against a correctly-configured
  server, on the exact response that proves the opposite. The classifier goes through
  `crawl_json_flatten` and asks for a leaf at the STRUCTURAL path `data.__schema.types.<n>.name`, which
  an error message cannot fabricate. Measured, not reasoned about: the substring reading was written and
  four assertions went red, including one where the error message quotes back every field the document
  asked for, which defeats a substring reading hardened to also look for `types` or `queryType`.
- **The mount-path signal is a SEGMENT match, and the type count is over DISTINCT ARRAY INDICES.** A
  substring path match makes `/graphql-docs` and `/blog/a-graphql-primer` endpoints and spends a real
  request on each; counting flattened leaves instead of indices doubles every type count, because each
  type carries both a `name` and a `kind`. Both were written wrong on purpose and watched go red (3 and
  1 assertions respectively).
- **§7.4's "correlated finding" is the DERIVED layer's job and is deliberately NOT a second check id
  here.** §9.2's own first line puts composites in `lib/findings.sh` and says "not scanner scripts", and
  a second implementation could not work anyway: this phase runs before §7.1's leakage findings are
  merged, and §8.5's AppSync key-expiry contributor comes from a different module. What a contributor
  owes is ONE thing - a populated `corr_target`, which `loc_target` supplies and which §9.2.2's frozen
  table confirms is the only correlation key DAST can offer. `rules/derived.rules` is still NOT seeded
  (findings F5/F20: `E051` requires every contributor id to exist, and DAST-10's does not yet), so the
  suite proves the input end by running the shipped finding through `derive_findings RUNDIR FIXTURE`
  against a composite written to scratch, naming two REAL registered DAST ids rather than an invented
  one - and asserts it does NOT fire on one contributor alone, nor when the two sit on different
  targets.

**What DAST-27 deliberately did not build**, so the boundary is not rediscovered: DAST-10's own key and
secret leakage detection (this ticket supplies only the correlation input); mutation execution,
batching/aliasing DoS probes and field-level authorization testing (every document it constructs is a
`query`, which GraphQL specifies as side-effect free, which is what makes the POST verb read-only here);
schema recovery by field-suggestion brute-forcing when introspection is off (a `disabled` classification
is reported as the real negative it is and the phase stops); and any authenticated GraphQL pass beyond
the session DAST-03 already provides, which it attaches through `dast_auth_apply`.

**One pre-existing gap this ticket found and filed rather than absorbed:** `modules/dast/jwt_engine.sh`
emits five `DAST-JWT-*` check ids that NO `checks.rules` registers, so tension 12 computes no coverage
over them and tension 15's filter chain can neither select nor drop them. `modules/dast/checks.rules`
now exists and is the right home for them, but their base severities and remediations are DAST-26's
author's call, not this ticket's.

That is 30 tickets end to end (DAST-01 through DAST-30), matching this ticket's "~30-script scope"
estimate for step 5.
Two later sections add work on top of those 30: DAST-31 through DAST-36 ("Safety defaults and
authorisation", above) and GUIDE-01 through GUIDE-07 ("The guided interactive mode", below).
Neither renumbers anything here, and GUIDE-01 through GUIDE-03 are not DAST-gated at all, since the
guided mode covers `sast`, `sca`, `iac` and `cloud` too.

## SPA / client-rendered-app limitation - documented, not solved

`docs/DESIGN.md` §7.5 already states this as an "Honest limitation" and §15 repeats it as one of the
things the report must state plainly: a pure-shell crawler fetches HTML but cannot execute JavaScript,
so a client-rendered app (React/Next.js-style SPA) will have its client-side routes and XHR/fetch
endpoints missed unless a spec/HAR/SAST-route input closes the gap.

This ticket does not solve that gap - closing it for real needs a headless browser, which
`docs/DESIGN.md` §7.5 itself says is "outside the pure-shell/no-egress envelope and should be a
documented, separate opt-in tool - not smuggled into the core," and this ticket's own out-of-scope list
excludes designing that tool.

What this plan requires instead, so the limitation is a report fact rather than a doc-only claim:

- **DAST-04 (`crawl.sh`)** is the ticket that owns surfacing it: when no OpenAPI/GraphQL/Postman/HAR
  spec is supplied and the crawler cannot otherwise establish full route coverage for a target, it must
  emit a `coverage_gap` record (the mechanism tension 21 defines and `lib/report.sh` already ships from
  step 1) naming the SPA limitation, not just log it internally.
- **`lib/report.sh`'s existing limitations-section rendering** (already built, step 1) is the consumer;
  no new report-layer ticket is needed, only DAST-04 actually calling `run_record coverage_gap` with a
  reason a human reads in the output.
- The three mitigations §7.5 already lists, in preference order, stay the operator-facing guidance:
  (1) supply an OpenAPI/GraphQL schema or a HAR capture - this fully closes the gap; (2) rely on SAST
  route extraction for server endpoints (tension 21's inventory merge); (3) if deeper dynamic coverage
  is required, that needs a headless browser, which §7.5 says explicitly should be "a documented,
  separate opt-in tool - not smuggled into the core" - i.e. a future, separately-scoped tool, not
  something any DAST-0x ticket in this plan builds.

## The guided interactive mode (GUIDE-01 through GUIDE-07)

A guided mode that asks the operator what to scan, asks follow-up questions determined by that answer,
and - for DAST - asks whether they own the target and want the conservative limits lifted.
It covers `sast`, `sca`, `iac` and `cloud` as well as `dast`, so GUIDE-01 through GUIDE-03 are not
gated on any DAST ticket and can land in parallel with all of the above.

### The one architectural decision everything else follows from

**The guided mode never runs a scan.**
It asks questions, composes an exact `scan.sh` argv, prints it, and hands that argv to the ordinary
`scan_parse_args` path.
One execution path runs scans, always.

That single constraint is what makes four of this design's requirements structural rather than a
checklist somebody has to keep honouring.

- **Every prompt has a flag equivalent**, because flags are the guided mode's *only* output: a prompt
  that could not be expressed as a flag could not be emitted at all.
- **Every existing validation still runs, unmoved.**
  `scan_parse_args` resets `SCAN_FLAGS` and `SCAN_COMMAND` at its top, so re-entry is clean, and the
  per-command flag-legality check (`scan_flag_kind`), the value-shape check
  (`scan_validate_flag_value`) and the cross-flag checks all execute on the composed argv exactly as
  they do on a hand-typed one.
  The rejected alternative - having the guided layer write `SCAN_FLAGS` entries directly - bypasses
  `scan_flag_kind` entirely, which is the *only* thing enforcing that a flag is legal for the command,
  and would let the guided layer set `SCAN_FLAGS[target]` under `sast`.
  It would also put an unset `SCAN_FLAGS[target]` in front of `scan_main`'s
  `config_scope_require "${SCAN_FLAGS[target]}"` (no `:-` default), which under `set -u` aborts with
  "unbound variable" through the ERR trap instead of a clean exit 2.
- **The printed command cannot drift from what ran**, because it *is* what ran: the same array is
  printed and executed, with no second renderer to keep in sync and no exclusion list to maintain.
- **Nothing downstream can tell the run was configured interactively**, which is what keeps the
  guided mode out of every safety-relevant code path.

### When it prompts, and every case where it must not

`scan.sh` is a CI tool.
A wrong answer here does not degrade an experience, it hangs somebody's build until a human notices.
Prompting is gated **conjunctively**, and the environment layer can only ever turn it *off*.

Guided mode is ON if and only if **all five** hold, evaluated in `scan_main` before any other work:

1. **Asked for.** Either `--guided` was given, or `$#` is `0` (the operator typed bare `scan.sh`).
2. **stdin is a terminal**: `[[ -t 0 ]]`.
3. **stderr is a terminal**: `[[ -t 2 ]]`.
   Both ends are checked because `select` writes its menu and `PS3` to **stderr**, not stdout
   (measured, below).
   Gating on `-t 1` would be checking the wrong stream, and gating on stdin alone lets a run whose
   stderr goes to a logfile block on a menu nobody can see.
4. **No non-interactive environment marker is set**, where the probe is any of `CI`,
   `CONTINUOUS_INTEGRATION`, `BUILD_NUMBER`, `JENKINS_URL`, `TEAMCITY_VERSION`, `GITHUB_ACTIONS`,
   `GITLAB_CI`, `BUILDKITE` or `TF_BUILD`.
   `CI` alone is not enough: Jenkins does not set it by default, and a runner that allocates a pty
   (`docker run -t`, an `expect` or `script` wrapper) satisfies conditions 2 and 3.
   The probe list is documented in `docs/USAGE.md` so it is an inspectable contract rather than a
   heuristic, and when any marker is present the operator's own explicit `--guided` is still required
   - a zero-argument invocation never auto-prompts there.
5. **`SCOURSH_NO_PROMPT` is unset or empty.**
   This variable can only ever *disable* prompting.
   There is deliberately no environment value that *enables* it, because an inherited variable that
   makes a tool block is the hang vector itself.

Otherwise guided mode is OFF and behaviour is byte-identical to today.

**Must not prompt, ever, in any of these:**

- Any of conditions 2 through 5 fails.
- Zero arguments with no terminal: byte-identical to today, `scan_usage` to stderr and `die` exit 2,
  "no command given".
  This is the strict non-regression, and it is the case `tests/suites/scan.sh`'s `'no command at all'`
  assertion already pins.
- A command that already carries every flag it needs, with no `--guided`: silent even on a terminal.
  `--guided` only ever fills flags that were **not** supplied on the command line, which is also how
  it degrades to a no-op.
- Inside `scan_dispatch`, any module, any check script, any `xargs -P` worker.
- After `run_init`.
  Once a run directory exists the run is under way, and a mid-run question leaves a half-written run
  directory waiting on a human.

**When prompting was explicitly requested but is ineligible, fail loudly and immediately.**
`--guided` with any of conditions 2 through 5 unmet is a usage error, exit 2, with a message naming the
concrete reason ("standard input is not a terminal", "`JENKINS_URL` is set in the environment"), the
sentence "nothing was run and nothing is waiting for input", and a worked flag example.
It is never a silent fallback to a default scan - a script that asked for guided setup and silently got
a passive scan is a worse outcome than a clear refusal - and it is never a block.

**`scan.sh dast --guided` must work**, and this is the reason the parser is split.
`scan_parse_args` today ends with the required-flag block, so `scan.sh dast` dies at
`'dast' requires --target` before anything else can run.
GUIDE-02 moves the required-flag and cross-flag block out of `scan_parse_args` into
`_scan_check_required`, called by `scan_main` **after** the guided pass, with the rules and the exit-2
message text unchanged.
`scan_parse_args` stays a pure function: it populates and shape-validates, and it never reads a
terminal.
That matters beyond tidiness.
`tests/suites/scan.sh` calls `scan_parse_args` directly, `tests/run-tests.sh` runs each suite as
`bash <path>` with no stdin or stderr redirection, and at a developer's terminal a suite file therefore
has stdin **and** stderr on a tty.
Putting the zero-argument guided branch inside `scan_parse_args` would make the project's own parser
tty-sensitive, surviving today only because `assert_status` happens to be written
`( "$@" ) >/dev/null 2>&1`.
A guard that depends on an incidental redirection in a generic test helper is not a guard.

**Four landed assertions move with the block**, and GUIDE-02 names them rather than discovering them
red.
They are identified by their `t_case` labels rather than by line number, because line numbers move and
this repository already has a rule about citing positions that go stale:
`'--fail-on-new requires --fail-on in the SAME invocation'`, `"'dast' requires --target"`, and the two
assertions under `"'diff' requires --against, 'report' requires --from"`.
Each is retargeted at `_scan_check_required` (or at a `scan_main`-level subprocess), keeping the exit
code and the message text asserted byte-identically, so the move is provably behaviour-preserving at
the CLI boundary.
`'no command at all'` does **not** move: zero-argument handling stays where it is, and the guided
branch sits in `scan_main` in front of it.

**No timeout, anywhere.**
`select` cannot time out, and a `read -t` fallback was considered and rejected: it would make the same
answers produce a different scan depending on typing speed, which breaks determinism outright.
The terminal gate plus "guided mode never runs unattended" is the control instead.
Somebody will propose a timeout as unattended safety; the reason it is absent belongs in
`lib/guide.sh`'s own header where the proposer will read it, not only here.

**Ctrl-C at a prompt must exit 0, and today it would exit 5.**
This is a real defect neither design caught, and it was measured rather than reasoned about.
`lib/core.sh` calls `core_install_traps` at source time, so `trap 'core_on_signal INT' INT` is armed
before any prompting can happen, and `core_on_signal` unconditionally does
`run_record incomplete_reason "run interrupted by SIG$sig"` then `exit "$SCOURSH_EXIT_INCOMPLETE"`.
Measured with a replica of that exact trap shape: SIGINT delivered while `select` is waiting produces
exit **5**, which in this project's frozen 0-5 table means "incomplete run (circuit breaker / aborted
mid-flight)" - the code that asserts a run started and could not complete an assessment.
Nothing ran.
A wrapper doing `scan.sh --guided || alert` would report a failed scan for an abandoned questionnaire.
GUIDE-01 therefore installs a guided-scope `INT`/`TERM` trap for the duration of prompting that prints
`Cancelled.  Nothing was scanned.` and exits 0, and **restores `core_on_signal` before `run_init`**, so
a real run's interrupt semantics are unchanged.
Its test sends SIGINT to a forced-terminal guided run and asserts both the exit code and that no run
directory was created.

**EOF at any prompt is exit 2**, with "input ended before the scan was configured; nothing ran".
This is not decoration either; see the measured `select` and `read` behaviour below for why an
unguarded version of each is a silent abort under this project's mandatory `set -Eeuo pipefail`.

### The menu flow

Menu items on **fixed** menus are fixed in number and order and are never reordered or removed by
availability.
An item whose module is not built is labelled and refused with one line if picked, rather than dropped:
renumbering would mean "answer 4" meant different things on different checkouts, which breaks both
reproducibility and anyone who wrote down what they ran.
New commands append at the end.
The availability labels are **derived from the filesystem at menu-build time**, through the same
capability probe `scan_dispatch` uses, so the menu can never claim a capability dispatch will not
deliver.
The conservative option is item 1 on every fixed menu.

**G1 - scan type.**

```
scoursh 0.1.0-dev - guided setup
--------------------------------

  This asks a few questions and then shows you the exact command it would
  run, so you can paste it into CI next time.  Nothing is scanned until you
  confirm at the end, and every answer here has a command-line flag.

  Press Enter at any menu to see the list again.
  To skip this and use flags directly:  scan.sh --help
  To turn it off permanently:           export SCOURSH_NO_PROMPT=1

What do you want to scan?

 1) Source code                              scan.sh sast    ready
 2) Dependencies and lockfiles               scan.sh sca     no advisory database installed
 3) Infrastructure as code                   scan.sh iac     ready
 4) A running web application over HTTP      scan.sh dast    not built yet in this version
 5) An AWS account, read-only                scan.sh cloud   not built yet in this version
 6) Everything this checkout can actually do scan.sh all     runs every ready surface
 7) Quit without scanning

pick a number>
```

Picking 4 or 5 today prints the honest explanation and returns here, rather than walking a whole
configuration flow and then running something inert:

```
  A running web application (DAST) is planned but not built yet in this
  version of scoursh.

  `scan.sh dast --target NAME` is accepted today: it checks the target
  against config/scope.conf, refuses if it is not authorised there, and then
  exits 0 without sending a single request.  It would report no findings, and
  that would not mean the target is clean.
```

Picking 2 with no `data/advisories.db` prints the same shape of explanation, ending with the sentence
that is the whole point of these screens: **a run that finds nothing because its data is missing is not
a run that found nothing wrong.**
Absence there means unknown, never safe, and the remedy (`tools/vendor-engines.sh advisories --all`, on
a networked machine) is named.
The operator may still proceed; the module already emits its own `coverage_reduction`.

**G2 - the local-surface follow-ups** (`sast`, `sca`, `iac`, and the local half of `all`): path, then
languages, then whether to replay the secret checks across git history.
Free text with the default shown in brackets, because `select` is single-choice only and `--lang` is
multi-value.
A path that does not exist re-asks once and then returns to G1; it never dies, because
`_scan_require_readable_path`'s exit 4 is the real gate and the guided mode must not duplicate it.
The `--history` option is labelled unavailable, and refuses with that reason, when `git` is not on
`PATH`.

**G3 - the DAST target**, read straight out of `config/scope.conf` through `config_scope_load`, so the
menu and the gate can never disagree about which targets exist:

```
  DAST only ever talks to a host you have authorised in config/scope.conf.
  That file is the tool's authorisation record.  This menu cannot override
  it: answering a question here never grants permission to scan anything.

Which target?

 1) staging-api    https://staging-api.internal:443
 2) staging-web    https://staging-web.internal:443
 3) Authorise a new target - writes a record into config/scope.conf
 4) Back

pick a number>
```

Each listed line shows the **normalised** `scheme://host:port` tuple the gate will actually match,
produced by `http_url_normalize`, not the raw `base-url` string.
There is deliberately **no free-text URL box on this screen**: a typed URL here would be a second scope
source, which is exactly the raw-URL bypass `docs/DESIGN.md` §7 forbids.
This is the one data-driven menu in the flow, so its numbering follows the operator's own file; the
answer is recorded by target id, never by position, so reproducibility is unaffected.
When `config/scope.conf` does not exist the menu collapses to "Authorise a target now / Back / Quit"
and states plainly that scoursh ships with no target of any kind and there is no demo host to point it
at, with the reason from the safety section above.

**G4 - authorising a new target.**
This is the most dangerous screen in the whole design, because it structurally resembles "the gate
refused, shall I remove the refusal?", which is the click-through everything else here avoids.
Four things keep it honest, and all four were corrections made in review.

```
  This will be appended to /path/to/config/scope.conf:

  ------------------------------------------------------------------
  id: staging-api
  base-url: https://staging-api.internal
  allow-subdomains: false
  allow-private-addresses: false
  notes: Authorised interactively via scan.sh --guided on 2026-08-14T10:22:31Z.
    Confirmed at the prompt after the normalised target and its resolved
    address were shown.
  ------------------------------------------------------------------

  The gate will match exactly:  https://staging-api.internal:443
  which resolves right now to:  10.4.7.22

  This authorises that host for EVERY scoursh run on this machine, not just
  this one, until you remove the record.

  This is plain data in scoursh's record format.  scoursh never executes a
  config file, so nothing written here can run.

  Type the host name  staging-api.internal  to write this, or anything else
  to cancel.
>
```

1. **It shows the normalised tuple and the currently-resolved address, not only the bytes.**
   `http_url_normalize` does real work between the typed string and the matched tuple: it
   percent-decodes the authority once, strips userinfo up to the **last** `@` (so
   `http://allowed@evil/` names host `evil`, as `lib/http.sh`'s own comment records), and canonicalises
   numeric IPv4 literals including octal and hex forms.
   It does **not** do IDN A-label conversion, which `lib/http.sh`'s header already records as "a real,
   known gap for a homograph-style bypass".
   An operator asked to type back a hostname the tool derived from their input is confirming the
   tool's parse, not the gate's match; showing both the tuple and the address is the only mitigation
   available for that gap, at the only moment it can be applied.
2. **It says the authorisation is file-wide.**
   Per the safety section above, `http_scope_match` walks every record in the file with no reference
   to the run's `--target`, so this is not "authorise a host for this run".
3. **`allow-subdomains` is always written `false`, and the menu does not offer otherwise.**
   `http_scope_match` implements subdomains as a bare suffix test (`$host == *".$s_host"`), so
   authorising a registrable or delegated zone with subdomains authorises an unbounded set of hosts
   the operator never enumerated, including any host somebody else can create in that zone.
   If you need it, open the gate's own file - widening the gate should mean editing the gate.
4. **`allow-private-addresses: true` may only ever be written alongside an IP-literal `base-url`,
   never a hostname.**
   This is the correction of a genuinely fatal defect in the design this section replaces, which
   proposed deriving that flag automatically from a DNS answer at write time.
   The flag is not range-scoped: `lib/http.sh`'s check is
   `if (( denied == 0 )) && [[ $_HTTP_MATCH_ALLOW_PRIVATE != true ]]`, a single boolean that disables
   the **entire** resolution-pinning deny list for that target - `127/8`, `169.254/16` where cloud
   metadata lives, `100.64/10` and `0/8` alike.
   Worse, the decision would be made once at write time against one DNS answer while the effect
   applies to every future resolution of that name, so a host that resolves to loopback today and to
   `169.254.169.254` tomorrow reaches cloud metadata through a record the guided mode wrote without
   ever asking.
   The repository already demonstrates the correct pattern: `tools/dast-test-target/scope.conf`
   authorises loopback as `base-url: http://127.0.0.1:3400/`, an **IP literal**, which sets
   `_HN_IS_LITERAL=true` so `addr=$host` and no resolution is ever consulted, closing the rebinding
   window entirely.
   If the operator types a name that resolves private, the guided mode offers to write the literal
   instead and says why.

The write itself copies the existing file to a temp file, appends a blank-line separator and the
record, runs `records_load` plus `records_validate` against the `scope-target` schema **on the temp
file**, and only then replaces the original by rename.
A malformed `config/scope.conf` makes `config_load_or_die` exit 4 on every future DAST run, so the
guided mode must not be able to brick the operator's config; a validation failure leaves the original
untouched, prints the `file:line:col` diagnostics and exits 4.
The writer is **append-only**: an id that already exists is refused, and no existing record is ever
edited, reordered or weakened.
There is deliberately **no flag equivalent**, and that is the point: writing an authorisation is a
config edit, not a per-run scan option, and the non-interactive equivalent is editing
`config/scope.conf` - the same act with the same reviewability.
An `--add-target` flag would turn "the gate refused" into a one-liner that removes the refusal, inside
CI, unreviewed.

**G5 - DAST intensity**, with the conservative option first and the standing invariant stated under
the list:

```
How hard should the scan push 'staging-api'?

 1) passive - read only: headers, cookies, TLS, markup, served JavaScript.
              Nothing is injected.                              (default)
 2) safe    - passive, plus content discovery and HTTP method enumeration.
              This puts hundreds of 404s into the target's logs.
 3) active  - safe, plus injection probes (SQLi, XSS, SSTI, traversal, ...)
              into every parameter found.  A target owner will read this as
              an attack.

  Detection only at every level: scoursh sends no destructive payload and
  does no credential brute forcing at any intensity, and cannot be told to.

  2 and 3 require you to affirm you are authorised for this host.  Permission
  to browse a host, or to port-scan it, is not permission to send it
  injection payloads.

pick a number>
```

**G6 - the limits router, then the affirmation, then each limit separately.**
The router states the *effective resolved* numbers, not literals, so an operator whose
`config/scanner.conf` sets a higher budget learns about the ceiling here rather than being confused by
it mid-run.
Choosing "keep these limits" after choosing `safe` or `active` at G5 forces the intensity back to
`passive`, and item 1's text says so explicitly when that applies.

The affirmation screen is the one place in the flow where an affirmation is asked:

```
-------------------------------------------------------------------
 Raising the limits for target 'staging-api'

 Base URL     https://staging-api.internal/
 Resolves to  10.4.7.22
 From         this machine, as user abhi

 Above the conservative limits, scoursh sends traffic a target owner will
 read as an attack: injection payloads in every parameter it found, and
 hundreds of requests for paths that probably do not exist.

 That traffic is attributable to you.  It leaves this machine's IP address,
 it carries a User-Agent naming this tool, and it lands in the target's logs
 next to your source address.

 It can also take the target down.  A host that is small, slow or shared can
 stop serving real users while this runs.

 Only continue if you own this host, or you hold written permission from
 whoever does that covers active security testing.

 Being able to reach a host is not permission.  A robots.txt or a
 security.txt file is not permission.  A bug bounty page is not permission
 unless it names this host and this kind of testing.

 Type the target name  staging-api  to continue, or anything else to keep
 the conservative limits.

>
```

Typing the target id rather than "yes" is deliberate: it cannot be answered by muscle memory or by a
stray digit in a keyboard buffer, and it makes the operator re-read which host this is about.
The resolved address is shown because "staging-api" feeling familiar and "staging-api" resolving to a
colleague's box are different facts.
There is **no retry loop**: a second attempt turns a deliberate act back into a click-through, and the
failure direction (keep the conservative limits) is safe.

**After a matched affirmation, each limit is its own menu, with the conservative value still at item 1.**
This is the second correction that a review round forced, and it is not cosmetic.
A flow that jumps from the affirmation straight into three prompts pre-filled with the *raised* values
gives an operator who presses Enter three times a 5x request rate, 4x concurrency and 10x budget
without a single further decision - which is precisely the click-through the affirmation exists to
prevent, sitting one keystroke after it.
The affirmation unlocked the door; it does not walk through it.
The acceptance criterion is written as a test: **a scripted answer sequence that picks item 1 at every
fixed menu must produce an argv containing no `--i-own-target`, no `--allow-intrusive` and no raised
limit.**
That is "the path of least resistance is the safe one", as an assertion rather than an aspiration.

```
Requests per second against 'staging-api'

 1) 4        - the conservative default                        (default)
 2) 20
 3) 50
 4) No limit - send as fast as the target answers

'No limit' can take a small or shared host offline.  The total request
budget and the failure breaker still apply either way.

pick a number>
```

```
Total request budget for 'staging-api'

scoursh stops the run once it has sent this many requests, whatever is still
queued.  There is always a budget.  It cannot be removed - it is what bounds
a crawler loop or a mistake in a parameter list.

 1) 5000    - the conservative default                         (default)
 2) 20000   - the value in your config/scanner.conf
 3) 100000

pick a number>
```

Item 2 on the budget menu appears only when `config/scanner.conf` actually sets a different value, and
showing it there is what explains the clamp the operator was told about one screen earlier.

`--allow-intrusive` is asked **separately, last, and only when intensity is `active` and the
affirmation matched**, with the most specific warning text in the flow, because its worst case reaches
the target's *users* rather than its owner:

```
Side-effecting checks against 'staging-api'?

These are off by default because their effects leave the target:

  - user enumeration through login, signup and password-reset responses,
    which on a real identity provider CREATES ACCOUNTS and SENDS EMAIL OR SMS
    to real people
  - a deliberate burst to test whether rate limiting exists at all

Owning a host does not always mean you may do this to its users.

 1) No - skip them                                             (default)
 2) Yes - run them

pick a number>
```

A defensible stricter position is that this should be flag-only and never reachable from a prompt at
all.
This plan offers it, gated behind `active` plus a matched affirmation and asked separately, but the
stricter alternative is genuinely arguable and is named here rather than settled silently.

**G7 - cloud**, when that module lands: read the live account read-only, or only the IaC on disk.
Both paths are read-only and enforced by `lib/awscli.sh` plus the build lint; the menu says so.

**G8 - the CI gate**: whether the run should exit non-zero on findings, and at what severity.

**G9 - review, and the exit.**

```
Ready.

  scan.sh dast --target staging-api --intensity active \
    --i-own-target staging-api --requests-per-second 50 \
    --request-budget 20000 --allow-intrusive --fail-on high

This will:
  - send injection payloads to https://staging-api.internal/
  - at up to 50 requests/second, stopping after 20000 requests
  - including checks that may email or create real users
  - and exit 1 if it finds anything high or critical

Authorisation affirmed for 'staging-api' by abhi at 2026-08-14T12:03:11Z.
That affirmation, and every limit it raised, is recorded in this run's
run.json.

 1) Run it
 2) Print the command and exit without running
 3) Cancel

pick a number>
```

Item ordering here differs from every other screen on purpose: this is an action menu rather than a
settings menu, so "Run it" stays at 1 for stable muscle memory, and all of the safety work already
happened upstream.
Option 2 writes to **stdout** (so it pipes and copies) and exits 0 with no run directory created.
It is load-bearing rather than a nicety - it is what converts an interactive operator into a scripting
one - and it therefore also exists as a real flag, `--print-command`, which renders the fully resolved
invocation for **any** invocation, guided or not, and exits 0 without running.
An interactive-only escape hatch from interactive-only capture would be self-defeating.
Cancel exits **0** with "Cancelled.  Nothing was scanned.", because a cancelled setup is a legitimate
outcome rather than an error, consistent with `--help` exiting 0.

### Flag equivalence

Every prompt maps to a flag.
`--print-command` and the two new global flags are the only additions to `_SCAN_FLAG_KIND` that the
guided mode itself needs; the rest already exist or arrive with DAST-32.

| Prompt | Flag |
|---|---|
| G1 scan type | the subcommand: `sast` \| `sca` \| `iac` \| `dast` \| `cloud` \| `all` |
| G2 path | `--path DIR` |
| G2 languages | `--lang py,js,go,java` |
| G2 git history | `--history` |
| G3 target | `--target NAME` |
| G4 authorise a new target | **none, deliberately** - the non-interactive equivalent is editing `config/scope.conf` |
| G5 intensity | `--intensity passive\|safe\|active` |
| G6 affirmation | `--i-own-target NAME` (must equal `--target`; mismatch is exit 2) |
| G6 rate | `--requests-per-second N`, or `0` for no limit (the same key name `config/scanner.conf` already uses, so no second vocabulary is invented) |
| G6 budget | `--request-budget N` |
| G6 side-effecting checks | `--allow-intrusive` |
| G7 cloud live | `--live` (with `--profile`, `--regions`, `--assume-role` left at their defaults) |
| G8 CI gate | `--fail-on none\|high\|medium\|info` |
| G9 print and exit | `--print-command` |
| (turn the whole thing on) | `--guided` |
| (turn the whole thing off) | `SCOURSH_NO_PROMPT=1` |

Two flags the guided flow deliberately does **not** ask about, and names in its closing text instead,
because they belong to a CI setup written once rather than to a menu: `--fail-on-new` (which requires
`--fail-on`) and `--paranoid`.

### What is recorded for audit, and where

Four places, each answering a different question, and one of them survives the run directory being
deleted.

**1. `run.json`, a new top-level `authorization` object**, written on **every** DAST run, affirmed or
not.
Recording it unconditionally is deliberate: an absent key would be ambiguous between "nothing was
affirmed" and "this version does not record it", and the clamp that actually bit is exactly the fact a
reviewer needs in order to judge whether a run was gentle or heavy without reconstructing it.

```
"authorization": {
  "scope_target":        "staging-api",
  "scope_base_url":      "https://staging-api.internal/",
  "scope_conf_sha256":   "3f9a...",
  "affirmed":            true,
  "affirmation_source":  "interactive-guided",
  "affirmation_target":  "staging-api",
  "affirmed_at":         "2026-08-14T12:03:11Z",
  "intensity":           "active",
  "intrusive":           true,
  "authed":              false,
  "limits_relaxed":  ["intensity-ceiling:passive->active",
                      "requests-per-second:4->50",
                      "request-budget:5000->20000",
                      "allow-intrusive:false->true"],
  "limits_enforced": ["request-budget:20000 (finite, never removable)",
                      "circuit-breaker:10-failures/60s",
                      "scope-gate:config/scope.conf",
                      "payloads:detection-only",
                      "ssrf:in-scope-sentinels-only",
                      "user-agent:scoursh-identified"]
}
```

Why each of the load-bearing fields earns its place:

- `limits_relaxed` records the **delta**, from-value to to-value, not a boolean.
  "unrestricted: true" is not an audit record; it tells a later reader nothing about what traffic was
  actually authorised, whereas the delta reconstructs the traffic profile.
  An unaffirmed run records the clamps that bit in the same shape
  (`requests-per-second:200->4 reason=no_owner_affirmation source=file`), including the resolution
  layer the clamped value came from.
- `limits_enforced` records what was **not** relaxed, so the record is a complete statement rather
  than a partial one.
  The usual question after an incident is what the tool could not have done, and a list of what stayed
  on is the answer; without it a reader has to reason from the tool's version number.
- `intensity`, `intrusive` and `authed` are recorded on every run.
  `--authed` already exists as `[dast:authed]=bool` and DAST-03 gives it real teeth, and an
  authenticated active scan reaches state-changing endpoints an unauthenticated crawl never sees, so
  an authorisation record that cannot distinguish the two is not answering its own question.
- `scope_conf_sha256` ties the run to the exact authorisation-file state, so "was this host authorised
  at the time" is answerable from the run plus that file's git history.
- `affirmation_source` is one of `interactive-guided`, `flag`, or `none`, so a reviewer can tell a
  human answering a question at a terminal from a flag pasted into a CI file.
  Both are legitimate; they are different evidence, and collapsing them loses the distinction that
  matters most in review.

**2. `run.json`'s `invocation` and `config` facts**, which is where the determinism claim gets an
honest statement rather than an overstated one.
`invocation` is the fully rendered, shell-quoted command - the same array the guided mode printed and
executed.
That is safe to record verbatim only because `docs/FOUNDATION.md` tension 9 already forbids a secret
ever being a command-line argument; the frozen rule that keeps credentials off argv is what makes
recording argv a non-issue.
But **the argv is not the run's only input**, and saying otherwise would be wrong: `config_scanner_value`
resolves every scanner setting through CLI > env > file > default, and the guided flow sets only a
subset of those keys as flags, leaving `http-timeout`, `max-redirects`, `circuit-breaker-failures`,
`circuit-breaker-window`, `max-matches-per-file`, `evidence-max-bytes` and `redact-secrets` to resolve
from the environment or from `config/scanner.conf`.
The same printed command therefore produces a materially different scan on a different machine,
including different breaker and redirect behaviour.
So `config` records `scanner_conf_sha256` alongside `scope_conf_sha256`, and for every scanner key the
effective value plus its resolution source (`cli`, `env`, `file`, `default`).
That is a recording change rather than a new mechanism: `config_scanner_value` already computes exactly
that in its own `src` variable.
**Reproducibility is therefore stated as "this argv against these two digests", never as "this argv".**

**3. `reports/<run>/meta/<key>`** - the raw `run_record` fact files, free, already the mechanism, and
surviving as evidence independent of the JSON rendering.
This is **not** sufficient on its own, which is the point of DAST-33's second half: `run_record
use_engines` already writes `meta/use_engines` and `report_run_json` never renders it, so the tool's
only shipped audit flag is half-recorded today.

**4. `config/scope.conf` itself**, for a guided-written record only: a `notes:` line naming who added
it and when.
`reports/` is gitignored and run directories are deleted, so the authorisation decision has to outlive
them.
This is the one piece of the record that belongs with the authorisation rather than with a run, and it
is plain data in the frozen block-record format, written into a field the `scope-target` schema already
has, so no key is added to a safety-critical schema.

**What is deliberately not recorded.**
The affirmation is never persisted outside the run it was made for: no `scanner.conf` key, no dotfile,
no cache, no environment variable, no "remember this target", and `--i-own-target` must equal
`--target` so even the command line cannot carry it to another host.
Operator identity is recorded **only when `SCOURSH_OPERATOR` is set**, and is otherwise omitted rather
than harvested from `id -un` and the hostname.
`run.json` is frequently the artifact handed to a third party alongside a report, and quietly attaching
a username and machine name to every run is a privacy cost the audit requirement does not need: that it
happened, when, for which named target, by which route, and what numbers it changed is the complete set
of facts an auditor asks for.

**The test that pins the record**, and the reading it fails under: a suite case runs the guided flow
with the terminal check forced and a scripted answer stream, then runs the rendered command
non-interactively, and asserts the two `run.json` `authorization` objects are byte-identical.
It fails under the reading "the affirmation is a UI concept that the flag path need not reproduce",
which is exactly the drift that would turn the record back into decoration.

### `select`, measured rather than assumed

`select` is a bash builtin, so it adds **no dependency at all** and - unusually for this codebase - it
carries no GNU/BSD divergence risk, because the behaviour lives inside bash rather than in a userland
tool.
Every item below was measured on this machine on **bash 5.3.9** and cross-checked on **bash 3.2.57**
(macOS's own `/bin/bash`), and the two agreed on every one of them.
Two of these were stated *wrongly* in a design draft, in the direction that would have shipped a bug,
which is why they are recorded with their measurement rather than as folklore.

1. **The menu and the `PS3` prompt go to stderr; the loop body's output goes to stdout.**
   Measured: `printf '1\n' | bash -c 'select x in aa bb; do echo "BODY:$x"; break; done'` with the two
   streams captured separately puts `BODY:aa` on stdout and the numbered list plus `#?` on stderr.
   Good, because it keeps stdout clean for `--print-command`, but it is why the terminal gate must
   check `-t 2` and not `-t 1`.
2. **`select` reads stdin and prints its menu even when stdin is not a terminal.**
   Measured: `printf '2\n' | bash -c 'select x in a b; do echo $x; break; done'` prints `b`, with no
   terminal involved anywhere.
   A pipeline that happened to be feeding data in would have its menu answered by that data.
   This is why the terminal gate must be reached before any `select` is, and why a lint asserting that
   nothing outside `lib/guide.sh` uses `select` is worth having.
   (`read -p` differs: measured, it suppresses its prompt entirely when stdin is not a terminal.
   `select` does not.  The gate has to be ours, not the builtin's.)
3. **An empty line redisplays the list without entering the loop body.**
   So there is no press-Enter-for-default anywhere: Enter is inert, every advance costs a specific
   digit, and the flow cannot be held-Enter-ed through.
   Turn it into the feature it is, and say so in the header text.
4. **Invalid or out-of-range input *does* enter the loop body**, with the choice variable set to the
   empty string and `REPLY` holding the raw token.
   Measured: `zz` gives `CHOSE:[] REPLY:[zz]`, and `9` of 3 items gives `CHOSE:[] REPLY:[9]`.
   Every body must therefore test for an empty choice and re-prompt, or a typo becomes a silent wrong
   answer.
5. **At EOF, `select` ends the loop with status 1 - and as the last command of a function under
   `set -Eeuo pipefail` that aborts the caller.**
   Measured with this project's real trap shape: the ERR trap fires
   (`status=1 ... cmd=select x in a b`), the EXIT trap runs, and the process exits **1**.
   It does not "fall through silently", and the consequence is worse than a wrong prediction: exit 1
   is this project's "findings at or above `--fail-on`" code, so an EOF in a menu would be
   indistinguishable in CI from a failing security gate.
   **The fix is an explicit, unconditional `return 0` after every `select`**, measured to restore
   clean behaviour, and the idiom is already established here: `lib/checks.sh`'s `checks_select`
   carries the identical "explicit, unconditional success" comment for the same class of bug.
   A lint asserts it.
6. **The choice variable is UNSET after EOF, but set-to-empty after an invalid choice**, and `REPLY`
   is empty in both cases.
   Measured: reading the variable unguarded after an EOF-terminated `select` dies
   `y: unbound variable` under `set -u`, with the ERR trap firing.
   So a post-`select` predicate written naively as `[[ -z $var && -n $REPLY ]]` is *itself* the abort.
   Every post-`select` read uses `${var-}` and `${REPLY-}` defaulting, and a suite case runs each menu
   with `</dev/null` and asserts a clean classified exit rather than an unbound-variable abort.
7. **Layout is column-major and reflowed to `COLUMNS`, and an item-count cap does not control it.**
   Measured: 9 short items at `COLUMNS=80` *do* columnise into two rows of five, reading down the
   columns; and the seven-item scan-type menu above, with its long labels, splits into two column-major
   columns at `COLUMNS=200` and four at `COLUMNS=400`.
   Layout is a joint function of item width, item count and `COLUMNS` and it is not monotonic, so a
   "cap the menu at nine items" rule is not a rendering guarantee.
   **Setting `COLUMNS=1` for the menu's duration forces exactly one item per line regardless of width**
   (measured, 12 items, both bash versions), which is deterministic and removes a reading-order hazard
   at the exact moment one of the items says "No limit".
   Also measured: `COLUMNS` is **unset** in a non-interactive bash script even when attached to a pty,
   and bash defaults to 80, so this only bites operators whose environment exports it (some tmux and
   CI images) - which makes the hazard intermittent, and intermittent is worse than deterministic.
   Keep an item cap if you like, as a UI-length judgement, but never as the rendering control.
8. **A zero-item `select` exits status 0 with the body never running and the variable unset**, and
   prints no menu at all.
   Measured.
   `guide_menu` therefore dies on an empty item list rather than silently continuing.
9. **`REPLY` holds the raw input**, which is what the two typed-string confirmations (the affirmation
   and the scope write) use - through `read -r`, not `select`.
10. **A bare `read` at EOF aborts immediately under `set -e`**, unlike `select`, which at least reaches
    the next statement's status check.
    Measured: `read -r -p "FIRST> " a` on exhausted stdin returns 1, the ERR trap fires and the script
    dies on the spot, so the intended "EOF means cancel" semantics are unreachable from a bare read.
    Every prompt read is written `if ! IFS= read -r ...; then <cancel path>; fi`, and a lint on
    `lib/guide.sh` asserts it.

Menu text is plain ASCII, with no box-drawing characters, for the same portability reason this
repository already applies elsewhere.

### New tickets

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| GUIDE-01 | `lib/guide.sh` - the prompt gate, the signal trap, and the menu primitives | none; can land in parallel with all DAST work | New file, sourced only by `scan.sh`. Ships `guide_may_prompt` (the exact five-condition rule, including the full non-interactive environment probe list), `guide_menu`, `guide_ask`, `guide_confirm`, and `_guide_shquote`. `guide_menu` absorbs every measured `select` edge above: `COLUMNS=1` for the menu's duration, an unconditional `return 0` after the loop, `${var-}`/`${REPLY-}` defaulting, dies on an empty item list, treats an empty choice with a non-empty `REPLY` as unusable and re-prompts, converts EOF into exit 2 with "input ended before the scan was configured; nothing ran", and caps consecutive unusable answers at 10. Installs the guided-scope `INT`/`TERM` trap and restores `core_on_signal` before returning. `_guide_shquote` is hand-rolled (single-quote wrap with `'\''` escaping when the value is not `[A-Za-z0-9_./:,=@%+-]+`) rather than `printf %q`, which diverges into `$'...'` forms for control characters. `SCOURSH_GUIDE_FORCE_TTY` is a **test-only** hook in the same swappable-hook idiom as `SCOURSH_HTTP_TRANSPORT` and `SCOURSH_PARANOID_FORCE_BACKEND`; it forces only the terminal check, never the environment-marker or `SCOURSH_NO_PROMPT` checks, and it is documented as test-only in the same breath as those two or it will end up in somebody's CI file. New `tests/suites/guide.sh`, and it must prove the **refusals** rather than only the happy path: piped stdin, each environment marker set, `SCOURSH_NO_PROMPT` set, EOF mid-flow, and SIGINT mid-flow each exit non-zero (or 0 for the cancel path) without blocking, and none of them creates a run directory. |
| GUIDE-02 | `--guided`, the `scan_main` routing, and the `_scan_check_required` split | GUIDE-01 | Adds `[global:guided]=bool` and `[global:print-command]=bool` to `_SCAN_FLAG_KIND`. Routes the zero-argument and `--guided` branches in **`scan_main`**, keeping `scan_parse_args` a pure function that never reads a terminal. Moves the required-flag and cross-flag block into `_scan_check_required`, called after the guided pass, with rules and exit-2 messages unchanged, and retargets the four named assertions in `tests/suites/scan.sh`. Adds the two lints that make flag parity structural rather than a convention: one in `tests/lint-shell.sh`, in the same shape as the tension-19 no-bypass check, failing the build if anything under `lib/` other than `guide.sh`, or anything under `modules/`, calls a `guide_*` function or uses `select` or `read -p`; and a suite case walking every key the guided flow can set against `_SCAN_FLAG_KIND` and failing on any key with no flag. Direct non-regression test: bare `scan.sh` with no terminal keeps today's exit-2 usage text byte-identically. |
| GUIDE-03 | The scan-type menu, the local-surface follow-ups, and prerequisite honesty | GUIDE-02 | Steps G1, G2, G8. Menu items fixed in number and order; availability labels derived at menu-build time from the same probe `scan_dispatch` uses, through **one shared function** so the menu can never advertise what dispatch will not deliver - with a suite case asserting the menu's ready set equals the set of modules with a `run.sh` on disk, because a shared-function convention is a thing a future edit can break. Five probes, each reusing the check the real code path already makes rather than inventing a second one: `data/advisories.db` for SCA, `git` on `PATH` for `--history`, `modules/dast/run.sh` and `modules/cloud/aws/run.sh` presence, the `aws` CLI for `cloud --live`, and `config/scope.conf` plus its target list via `config_scope_load` for DAST. Absence is never an error here, only a labelled menu state with an explanation. |
| GUIDE-04 | The DAST branch and the affirmation | GUIDE-02, DAST-32 | Steps G3, G5, G6. The hard dependency on DAST-32 is structural rather than a convenience: the flags must exist before a prompt can emit them, because prompts emit nothing else. Every number in the prompt text is **interpolated from the same named constants DAST-32's clamp reads**, never typed as prose, and a suite case asserts the rendered prompt contains the constant's current value - otherwise the text drifts into promising a limit the code does not enforce, which is the most likely way this whole design quietly becomes theatre. The target menu offers only ids from `config/scope.conf` and has no free-text URL box. The affirmation requires typing the target id exactly, once, with no retry loop. After a matched affirmation each limit is its own menu with the conservative value at item 1, and the acceptance test named in the flow section above is part of the deliverable. `--allow-intrusive` is asked separately, last, only when intensity is `active`. The trailing lines that state what the affirmation does **not** do are part of the deliverable, not decoration: they are what stops "a full scan without the conservative limitations" being read as "a destructive scan". |
| GUIDE-05 | The `config/scope.conf` record writer | GUIDE-02, GUIDE-03, `lib/records.sh` (shipped) | Step G4, and the most dangerous thing in this design - it deserves the most adversarial review of anything here. Ships the offer, the preview showing raw bytes **plus** the normalised `http_url_normalize` tuple **plus** the currently-resolved address **plus** the file-wide-authorisation sentence, the typed-hostname confirmation, `allow-subdomains: false` always, `allow-private-addresses: true` only alongside an IP-literal `base-url`, append-only with an existing-id refusal, the deterministic id derivation (lowercase, dots and colons to dashes, `t-` prefix when it would not start with a letter, `-2` on collision) so the same URL always yields the same id, the dated `notes:` line, and validate-in-a-temp-file-then-rename. Frozen record format only, never sourced (tension 26), and the writer must never emit a value it did not receive verbatim from the operator - `rules/RULE-FORMAT.md` §5.3 already fixes that `$HOME` is five literal bytes, and the likeliest future way to break "no config file is ever sourced" is a well-meant convenience like a variable expansion or an `include` directive written into a file the loader would then have to evaluate. A suite case must prove the post-write gate behaviour is identical to a hand-edited file. **This ticket also owns an explicit decision, not a default:** `config/scope.conf` is not in `.gitignore` today (verified: it lists `reports/`, `state/`, `suite.log`, `findings-*/`, `.DS_Store` and `.dast-test-target/`), so a guided write makes an untracked file, possibly containing internal hostnames, appear in every clone. Either ignore it and lose the "commit this so the authorisation outlives the machine" story, or leave it tracked and document the consequence - but decide it here. |
| GUIDE-06 | The review screen, `--print-command`, and the argv round-trip | GUIDE-03, GUIDE-04, GUIDE-05 | Step G9. Prints the exact composed command, a plain-language statement of what it will actually do, and the affirmation restatement when one was made. `--print-command` is the non-interactive twin and works for any invocation. The load-bearing test: run the guided flow with a scripted answer stream, then run the rendered command non-interactively, and assert the two runs' `run.json` flag facts, `authorization` object and `config` object are byte-identical. It must fail under the reading "the printed command is a best-effort summary". |
| GUIDE-07 | Documentation: the guided quickstart, the flag table, and the honest status column | GUIDE-06 | `docs/USAGE.md` gains a guided-mode section stating the five prompt conditions verbatim, the full non-interactive environment probe list, the exit code for each refusal path, and the flag-equivalence table above; its existing Status column gains rows for `--guided`, `--print-command`, `--i-own-target`, `--requests-per-second`, `--request-budget` and `--contact`. That column applies directly here: **guided mode is live even while DAST is inert**, and the doc must say that picking DAST walks the whole flow and then runs something that does nothing yet, because that column exists precisely to close this class of trap. `config/scanner.conf.example` gains commented entries for the new keys. Nothing here restates a count or a build-order sentence that `tools/gen-status.sh` owns; per `AGENTS.md`, run `tools/gen-status.sh --write` and commit the result rather than typing any inventory figure. |

### Open decisions and residual risks

- **Bare `scan.sh` on a terminal changes behaviour**, from usage plus exit 2 to a menu.
  The terminal gate plus the environment probe makes this impossible in any pipeline, cron job or
  tty-less container, and `SCOURSH_NO_PROMPT=1` is the documented off switch, but this is the single
  decision in the design worth the project owner's explicit sign-off.
  The conservative alternative is to require `--guided` explicitly and leave bare invocation exactly as
  it is today; it costs only the "useful result inside sixty seconds from a fresh clone" premise.
  This plan ships the zero-argument behaviour and flags the decision rather than burying it.
- **The scope-writing offer is the piece most likely to be regretted.**
  Every mitigation above is real, and the residual risk is irreducible by tooling: a mistyped but
  valid base URL authorises a host the operator did not mean, and only the operator's own reading of
  the preview catches it.
- **`--i-own-target prod-api` can become CI boilerplate**, pasted once and still there after the target
  changes hands.
  The must-equal-`--target` rule and the recorded numeric deltas blunt this, but nothing prevents a
  stale affirmation living in a CI file for a year.
  A periodic re-affirmation is the obvious fix and is deliberately not designed here, because a
  time-based expiry that fires mid-pipeline is its own outage.
- **Prompt text can drift from enforced behaviour**, and a menu that promises a limit the code does not
  keep is worse than no menu.
  The interpolate-from-the-constants rule plus GUIDE-04's suite case are the guard, and every future
  edit to that text has to respect it.
- **"No limit" at the rate prompt is the option most likely to be chosen casually**, because its
  consequence lands on a host that may be shared or smaller than the operator believes.
  It carries the loudest single consequence line in the flow, and removing it is a reasonable response
  if it turns out to be picked without thought.
- **Interactive flows are hard to test without a pty**, and the honest limit of the proposed suite is
  that it exercises the guided run with the terminal check forced and stdin from a here-doc.
  It proves the state machine and the flag output, not the terminal rendering.
  Assertions are therefore written over choices made, never over line counts or column layout, and no
  test should be read as evidence that the menu looks right on a real terminal.
- **None of this has been built or run.**
  The `select` and `read` behaviours above are measured on this machine on bash 5.3.9 and 3.2.57, and
  the code facts cited from `scan.sh`, `lib/http.sh`, `lib/config.sh`, `lib/core.sh`, `lib/report.sh`,
  `lib/checks.sh` and the test tree were read out of the tree rather than recalled - but the flow, the
  clamping, the argv round-trip and the scope-write path are unimplemented, and the first ticket that
  builds any of them should expect to find at least one stated behaviour slightly different in context.

## Doc-update process

Per `AGENTS.md`'s "Build order and where we are" process rule ("shipping a §13 step updates this
section, and its mirror in `docs/FOUNDATION.md`'s 'Where the build currently stands,' in the same
change"), whoever lands DAST-01 (the first real step-5 code) updates both `AGENTS.md`'s "Current
position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section, in the same
change, exactly as every §13 sub-step landing so far has had to. `docs/DESIGN.md` itself stays verbatim
(per this project's documented rule that its wording is load-bearing and preserved as-is) - it is never
the place build-order status is recorded; `AGENTS.md`/`CLAUDE.md` and this section of `docs/FOUNDATION.md`
are.

**The step-5 gate was written into two other documents, and both are now corrected.**
`AGENTS.md` (which `CLAUDE.md` is a symlink to) carried the sentence "No DAST-0x ticket is picked up
until step 3's outstanding rule packs and step 4's SCA half are both complete on `dev`", and the change
that retitled this section corrected it there in the same commit range.
`docs/FOUNDATION.md` carried the same sentence verbatim in its "Where the build currently stands"
section, plus two lines citing this plan's own section by its old name, "Status: blocked".
Both are gone: that section now records the gate as discharged, and the string "Status: blocked" does
not appear in `docs/FOUNDATION.md` at all.
DAST-36 verified this rather than assuming it, because the obligation had been carried in this
document for long enough to outlive the work that satisfied it.
The paragraph is kept rather than deleted for the reason it was written: leave the two documents
disagreeing and they contradict each other on whether step 5 may be started at all, which is the
failure this note exists to prevent recurring.
`docs/STEP6-CLOUD-PLAN.md` and `docs/STEP7-STATE-PLAN.md` still carry their own "Status: blocked"
headings and are correct as written; nothing here asks either to change.
