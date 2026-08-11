# Step 5 (DAST) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 5 - `docs/DESIGN.md` §13's dependency-ordered "`lib/http.sh` -> `auth.sh` (§7.0)
-> `crawl.sh` (§7.5) -> DAST passive -> safe-active -> injection probes one file at a time, each with a
mock-response test -> §7.4 auth/API/authz checks" - can be picked up as a clean sequence of small,
independently reviewable tickets the moment its blockers clear, instead of being re-derived from
`docs/DESIGN.md` §7 from scratch by whoever picks it up first.

## Status: blocked

**No step 5 implementation ticket (any of DAST-01 through DAST-30 below) is picked up until both of the
following are complete on `dev`:**

1. **`docs/DESIGN.md` §13 step 3 finishes**: the `nosql` and `ldap` SAST rule packs
   (`modules/sast/rules/nosql.rules`, `modules/sast/rules/ldap.rules`) land.
   As of this writing `dev`'s step 3 has shipped `secrets`, `crypto`, `injection`, `python`, `go`,
   `javascript`, `java`, and `history.sh` (sub-steps 3a-3e); only `nosql`/`ldap` remain.
2. **`docs/DESIGN.md` §13 step 4 (SCA + IaC)** completes. As of this writing step 4 has not started.

This applies to the whole module, not just the scripts under `modules/dast/`.
DAST-01 below touches `lib/http.sh` rather than `modules/dast/`, but it is still running-endpoint-layer
work in scope of this same block, per this ticket's own description ("no engineer should begin coding
the running-endpoint module yet"), so it waits with everything else.
Whoever lifts this block should update the "Status" line above, and the two build-order sections named
in "Doc-update process" below, in the same change that starts DAST-01.

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
setup - DAST-29 (`authz.sh`) in particular can point straight at this fixture's two identities and their
already-confirmed basket-IDOR case (see `tests/e2e/dast-target-smoke.sh`) rather than standing up its
own.

Two things worth knowing before building against it:

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

## Dependency-ordered sub-ticket list

Ordering follows `docs/DESIGN.md` §13 step 5's own sequence (`lib/http.sh` -> `auth.sh` -> `crawl.sh` ->
passive -> safe-active -> injection, one file at a time -> §7.4 auth/API/authz), refined to script
granularity using §7's own script list. Every ticket also authors its own `modules/dast/**/checks.rules`
script-check record (`rules/RULE-FORMAT.md` §9.5, `coverage-scope: target`) alongside its script, since
that is what `lib/checks.sh`'s registry loader and tension 12's coverage tracking need to see it at all.

### Tier 0 - shared infrastructure (blocks all of tiers 1-5)

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
| DAST-09 | `passive/banner.sh` | Framework/version disclosure matched against **`data/versions.db`**, which `tools/vendor-engines.sh` populates at §13 step 9 - a forward dependency. This ticket ships the matching logic and must degrade gracefully (skip that sub-check with a reason, not an error) when `data/versions.db` is missing/empty, since step 9 lands long after step 5. |
| DAST-10 | `passive/leakage.sh` | Verbose-error/stack-trace disclosure, upstream proxy header leakage, email disclosure, client-config leakage in served JS, CDN/third-party origin detection. Its "API key found in served JS" output is a later correlation input for DAST-27 (`graphql.sh`) at the derived-finding layer (tension 6), not a code dependency. |
| DAST-11 | `passive/markup.sh` | Missing SRI, reverse tabnabbing, insecure external frame, CSRF-token absence in state-changing forms. |

### Tier 3 - safe active (§7.2, 2 scripts)

| # | Ticket | Depends on |
|---|---|---|
| DAST-12 | `active/discovery.sh` - content discovery | DAST-01/02/04; vendored wordlist (already committed under §12's `tests/fixtures/`-style vendoring rule, no `vendor-engines.sh` dependency the way DAST-09 has) |
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

## Doc-update process

Per `AGENTS.md`'s "Build order and where we are" process rule ("shipping a §13 step updates this
section, and its mirror in `docs/FOUNDATION.md`'s 'Where the build currently stands,' in the same
change"), whoever lands DAST-01 (the first real step-5 code) updates both `AGENTS.md`'s "Current
position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section, in the same
change, exactly as every §13 sub-step landing so far has had to. `docs/DESIGN.md` itself stays verbatim
(per this project's documented rule that its wording is load-bearing and preserved as-is) - it is never
the place build-order status is recorded; `AGENTS.md`/`CLAUDE.md` and this section of `docs/FOUNDATION.md`
are.
