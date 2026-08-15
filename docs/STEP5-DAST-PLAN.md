# Step 5 (DAST) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 5 - `docs/DESIGN.md` §13's dependency-ordered "`lib/http.sh` -> `auth.sh` (§7.0)
-> `crawl.sh` (§7.5) -> DAST passive -> safe-active -> injection probes one file at a time, each with a
mock-response test -> §7.4 auth/API/authz checks" - can be picked up as a clean sequence of small,
independently reviewable tickets, instead of being re-derived from `docs/DESIGN.md` §7 from scratch by
whoever picks it up first.

## Status: top priority - one gate cleared, one sequencing item left

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

Whoever picks up DAST-01 updates this section, and every build-order section named in "Doc-update
process" below, in the same change.
One known loose end until then: `docs/FOUNDATION.md` still states the old gate and still cites this
section by its former name, "Status: blocked" - see "Doc-update process" for exactly what has to
change there.

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

Crewban-22 (operator-blocked - no staging environment, and the operator would not scan anything not
owned outright) landed while this block held: `tools/dast-test-target.sh` starts (idempotently) a
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
| DAST-35 | Lint: no shipped scope target, no bundled scan host | none; can land immediately | A check in `tests/lint-shell.sh` (or `tests/lint-rules.sh`, wherever the maintainer prefers config-shape rules), in the same one-exemption-with-a-stated-reason shape the tension-19 no-bypass check already uses: `config/` contains no `scope.conf`, only `scope.conf.example`; `scope.conf.example`'s `base-url` uses a reserved example domain; and no shipped script, rule or config file carries a scope-target record naming a resolvable third-party host. `tools/dast-test-target/scope.conf` is exempt **by path**, with its reason named - it is never installed as `config/scope.conf` and is loaded only by the opt-in smoke test, exactly as its own header and `docs/DAST-TEST-TARGET-AUTHORIZATION.md` already record. This exists because "a convenient example target" is a helpful-looking contribution that would silently become the built-in demo host the research findings rule out. |
| DAST-36 | Fold this posture into DAST-01 through DAST-30's own acceptance criteria | DAST-31, DAST-32 | Doc-only, no shell code. Restating the constraints inside each affected ticket rather than leaving them inherited by reference, because a ticket is implemented from its own acceptance criteria. The amendments are enumerated in the next subsection. Per this document's own "Doc-update process", whoever lands this also fixes `docs/FOUNDATION.md`'s stale step-5 gate sentence and its dangling "Status: blocked" cross-reference in the same change. |

### Amendments to DAST-01 through DAST-30 (owned by DAST-36)

- **DAST-01** gains the ceiling hook: the limiter, budget and breaker read an **effective** value that
  DAST-32's clamp has already applied, and the clamp lives beside them in `lib/http.sh` rather than in
  any module. DAST-01 and DAST-32 are arguably one thing and merging them is the implementer's call to
  make; if they stay separate, DAST-01 must not ship a limiter that reads `config_scanner_value`
  directly, or DAST-32 becomes a retrofit.
- **DAST-12 (content discovery)** and **DAST-13 (method enumeration)** restate in their own criteria
  that they are `safe`-intensity and therefore unreachable without an affirmation, and that the
  wordlist is a bounded vendored file whose size no flag changes.
- **DAST-14 through DAST-25 (the injection probes)** each restate the non-destructive constraint in
  their own acceptance criteria: detection-only, no data modification, no exfiltration beyond minimal
  confirming evidence. **DAST-20** additionally restates that SSRF/XXE sentinels are in-scope-only and
  that no affirmation widens them.
- **DAST-26 (`jwt.sh`)** restates that the weak-secret list is bounded and vendored and that no flag
  expands it.
- **DAST-28 (`ratelimit.sh`)** gets the one behavioural amendment in this list, and it closes a silent
  false negative that neither design resolved. Under the conservative ceilings a burst probe cannot
  establish either a positive or a true negative: it would report "no missing-throttling finding" from
  a scanner that was itself throttled below any plausible threshold. **On an unaffirmed run DAST-28
  does not execute, and emits a `coverage_gap` naming the scanner's own rate ceiling as the reason**,
  using the mechanism `lib/report.sh` already ships. That makes the ceiling visible as a coverage fact
  rather than as a clean bill of health.
- **DAST-29 (`authz.sh`)** restates read-only object references only, no writes.

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
| DAST-03 | `auth.sh` (§7.0) - authentication & session acquisition | DAST-01, DAST-02, `config/auth.conf` schema (already frozen, `rules/RULE-FORMAT.md` §9.6.2) | Static bearer/API key, form login, OAuth2/OIDC password/client-credentials grant, Cognito-style SRP. Session store (cookie jar + token cache) in the run scratch dir, perms `600`. Transparent re-auth on `401`, else the authenticated checks are marked `skipped` with a reason. Multi-identity (labelled A/B) for DAST-29 (`authz.sh`). The config-derived half of the §7.4 closing paragraph's user-enumeration checks (detection via config, not a live probe) belongs here too; the live `--allow-intrusive` opt-in variant is a small follow-up once this ticket's session modes exist, not counted separately below. |
| DAST-04 | `crawl.sh` (§7.5) - crawling, parameter & spec discovery | DAST-01, DAST-02; optionally DAST-03 for an authenticated crawl pass (unauthenticated static crawl does not need it) | Static crawl (links/forms/`action`s/input names, depth-limited, scope-gated); spec ingestion (OpenAPI/Swagger, GraphQL schema, Postman, HAR) as the preferred, most-complete input; merges any `reports/<run>/inventory/endpoints.json` another module already wrote (tension 21 - SAST route extraction, `apigw.sh`), tolerating its absence with a `coverage_gap` record via the mechanism `lib/report.sh` already ships (step 1). Writes `endpoints.json` + `parameters.json`, which every ticket below consumes. **Must implement the SPA/client-rendered-app limitation as a stated `coverage_gap`, not a fix**: see "SPA/client-rendered limitation" below - this ticket's acceptance criteria should require that gap to actually appear in `run.json`/the report when no spec/HAR is supplied, not just be true in prose. |

### Tier 2 - passive checks (§7.1, 7 scripts, `modules/dast/passive/*.sh`)

Each is independently testable against one recorded HTTP response (`docs/DESIGN.md` §7.1's own "one file
per family" framing) and each is a peer of the other six - no ordering constraint among DAST-05..DAST-11,
only that all of them come after DAST-04 (they need the endpoint list) and DAST-01/02.

| # | Ticket | Extra notes beyond DAST-01/02/04 |
|---|---|---|
| DAST-05 | `passive/headers.sh` | CSP, HSTS, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, "recommended headers not set" roll-up. |
| DAST-06 | `passive/cookies.sh` | `Secure`/`HttpOnly`/`SameSite` per cookie. |
| DAST-07 | `passive/tls.sh` | Shells out to `openssl s_client`; the one documented exception to "every network call goes through `lib/http.sh`" (`docs/FOUNDATION.md` tension 19's neighbourhood notes this). Sequence close to DAST-30 (`transport.sh`), which complements it - not a hard code dependency, just worth landing in the same review window for a coherent report section. |
| DAST-08 | `passive/cors.sh` | Origin-reflection probe. |
| DAST-09 | `passive/banner.sh` | Framework/version disclosure matched against **`data/versions.db`**. The writer side is no longer a forward dependency: `tools/vendor-engines.sh advisories` landed ahead of step 5 and writes `data/versions.db` by the same call that writes `data/advisories.db` (tension 25). What is still missing is the data - no `data/versions.db` is committed to this repository, and populating one is an operator action on a networked box, never part of a scan. This ticket ships the matching logic and must degrade gracefully (skip that sub-check with a reason, not an error) when `data/versions.db` is missing or empty, which is the state of a fresh clone. |
| DAST-10 | `passive/leakage.sh` | Verbose-error/stack-trace disclosure, upstream proxy header leakage, email disclosure, client-config leakage in served JS, CDN/third-party origin detection. Its "API key found in served JS" output is a later correlation input for DAST-27 (`graphql.sh`) at the derived-finding layer (tension 6), not a code dependency. |
| DAST-11 | `passive/markup.sh` | Missing SRI, reverse tabnabbing, insecure external frame, CSRF-token absence in state-changing forms. |

### Tier 3 - safe active (§7.2, 2 scripts)

| # | Ticket | Depends on |
|---|---|---|
| DAST-12 | `active/discovery.sh` - content discovery | DAST-01/02/04. **No wordlist is committed to this repository** - this ticket vendors its own, in-repo and read from disk under §12's `tests/fixtures/`-style vendoring rule, so unlike DAST-09 it carries no `vendor-engines.sh` dependency and no missing-data degradation path. |
| DAST-13 | `active/methods.sh` - HTTP method enumeration | DAST-01/02/04 |

### Tier 4 - active injection probes (§7.3, 11 scripts, "one file at a time, each with a mock-response test" per §13's own build-order text)

All are peers of each other; all depend on DAST-04's parameter inventory (query/body/JSON/header/path
segments) plus DAST-01/02, and land after tier 2/3 per §13's stated ordering.

| # | Ticket |
|---|---|
| DAST-14 | `active/sqli.sh` - error-based, boolean, and time-based SQL injection |
| DAST-15 | `active/xss.sh` - marker-token unescaped-reflection detection |
| DAST-16 | `active/cmdi.sh` - bounded time-based command injection |
| DAST-17 | `active/pathtraversal.sh` - benign read-only marker traversal |
| DAST-18 | `active/ssti.sh` - arithmetic-expression template injection |
| DAST-19 | `active/openredirect.sh` - attacker-controlled `Location` host |
| DAST-20 | `active/xxe_ssrf.sh` - safe-sentinel-only XXE/SSRF detection, in-scope hosts only |
| DAST-21 | `active/nosqli.sh` - operator/object injection, boolean/error differential |
| DAST-22 | `active/ldapi.sh` - filter-breaking payloads, response/error differential |
| DAST-23 | `active/crlf.sh` - encoded CR/LF header-split detection |
| DAST-24 | `active/hosthdr.sh` - spoofed `Host`/`X-Forwarded-Host` reflection |
| DAST-25 | `active/protopollution.sh` - `__proto__`-style JSON param probing (JS backends) |

### Tier 5 - §7.4 auth, API, and access-control checks (5 scripts)

| # | Ticket | Depends on |
|---|---|---|
| DAST-26 | `jwt.sh` - `alg:none`, empty-secret HS256, weak-secret list, RS->HS confusion | DAST-01/02, DAST-03 (needs a sample/test-account token and a protected endpoint to replay against) |
| DAST-27 | `graphql.sh` - introspection + correlated key-exposure | DAST-01/02, DAST-04 (needs the GraphQL endpoint in the inventory); soft data dependency on DAST-10's leakage finding for the correlated-key case, not a build blocker |
| DAST-28 | `ratelimit.sh` - missing-throttling burst probe | DAST-01 (must draw down the *same* per-run request budget DAST-01 owns, since this is the one check §7.4 flags as intentionally multi-request) |
| DAST-29 | `authz.sh` - IDOR / excessive data exposure | DAST-03 with `requires-identities: 2` (two labelled identities), DAST-04 (object-reference endpoints from the parameter inventory) |
| DAST-30 | `transport.sh` - plaintext-exposure / mixed-content | DAST-04; sequence close to DAST-07 (`tls.sh`), which it complements, per the note under DAST-07 |

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

**The step-5 gate was written into two other documents; one is corrected, and `docs/FOUNDATION.md` is
not.**
`AGENTS.md` (which `CLAUDE.md` is a symlink to) carried the sentence "No DAST-0x ticket is picked up
until step 3's outstanding rule packs and step 4's SCA half are both complete on `dev`", and the change
that retitled this section corrected it there in the same commit range.
`docs/FOUNDATION.md` still carries that sentence verbatim in its "Where the build currently stands"
section (line 4273 at the time of writing), and it is stale in exactly the way this document's "Status"
section was: step 4's SCA half is complete, so the gate as that file states it no longer holds.
The two lines immediately after it additionally cite this plan's own section by its old name, "Status:
blocked", which this change has retitled, so that cross-reference is knowingly dangling until it is
fixed.
Whoever lands DAST-01 corrects that sentence and that cross-reference in `docs/FOUNDATION.md`, in the
same change as the "Where the build currently stands" update named above.
This is not cosmetic tidying: leave it and the two documents contradict each other on whether step 5
may be started at all.
One nearby citation is deliberately NOT part of this: `docs/FOUNDATION.md`'s other "Status: blocked"
reference, in its step 6 paragraph, points at `docs/STEP6-CLOUD-PLAN.md`, which still carries that
heading and is correct as written.
