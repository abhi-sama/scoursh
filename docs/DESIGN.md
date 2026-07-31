# Air-Gapped Shell Security Scanner - Design & Implementation Plan

> Handoff spec. Build in the order given in §13. Each module is
> independent and testable in isolation. Nothing in the core makes third-party
> network calls. The only outbound traffic permitted is (a) `curl` to targets the
> operator has explicitly authorized in `config/scope.conf`, and (b) read-only AWS
> API calls to the operator's own account. Everything else - rules, payloads,
> wordlists, signature data - is vendored in the repo and used from disk.

---

## 1. Goals

- One shell-based tool that audits three surfaces: **source code (SAST)**, a **running endpoint (DAST)**, and **AWS configuration (live + IaC)**.
- **Exhaustive** across the surfaces it can reach - code, dependencies, running endpoint, and cloud/IaC config - with coverage and blind spots stated explicitly (§15) rather than implied. Depth on SAST scales with the engine tier (§9).
- **Modular** - each surface is a self-contained module under `modules/`, invokable alone or together.
- **No third-party egress.** No telemetry, no SaaS backend, no fetching rules at scan time. Runs on an air-gapped host.
- **Pure bash by default.** External engines are optional, adapter-gated power-ups - never required for the tool to run.
- **Target-agnostic - no hardcoded names.** No application, company, environment, product, or endpoint name is ever baked into a script or rule. Every site-specific value (hosts, endpoint paths, an org's password-policy baseline, which downstream SSO integrations are expected) is supplied at runtime through the config files in §11. Rules and checks describe *classes* of issue ("authenticated profile endpoint returns excess user data"), never a specific system. This keeps the tool reusable across projects and keeps internal names out of the codebase.

## 2. The egress model (read this first - it drives the whole design)

Three things people forget are technically "network traffic" but are legitimately in-scope here:

| Traffic | Verdict | Why |
|---|---|---|
| `curl` to a host listed in `scope.conf` | **Allowed** | It's the operator's own app; DAST requires it |
| `aws` read-only calls to the operator's account | **Allowed** | It's the operator's own infra |
| Any connection to a host *not* in scope / not the AWS API | **Forbidden** | Exfiltration / telemetry - abort |

Enforcement, layered:

1. **No hidden calls in code.** Core libs never `curl`/`wget`/`nc` except through the single wrapper in `lib/http.sh`, which refuses any host absent from the resolved allowlist (scope hosts + AWS endpoints).
2. **Paranoid mode (`--paranoid`).** Wrap the whole run in a check that logs every destination host any child process opens (via `ss`/`conntrack` sampling or an `strace -f -e connect` shim where available) and **aborts on the first host not in the allowlist**. Document the limitations honestly (sampling can miss short-lived connections).
3. **Optional netns isolation.** Provide `tools/run-in-netns.sh` that runs a module inside a network namespace whose only route is to the declared scope - belt-and-suspenders for high-assurance environments. Optional because it needs root.

## 3. Directory layout

```
scanner/
  scan.sh                     # entrypoint / CLI orchestrator
  VERSION
  config/
    scope.conf                # REQUIRED authorized targets (safety gate)
    scanner.conf              # global defaults (concurrency, timeouts, severity gate)
    baseline.json             # accepted/suppressed findings (fingerprint list)
  lib/
    core.sh                   # logging, colors, tmpdir, traps, arg parsing helpers
    http.sh                   # the ONLY curl wrapper; enforces scope allowlist + rate limit
    findings.sh               # finding data model, severity, dedup, fingerprinting
    report.sh                 # emit JSON / SARIF / HTML / Markdown
    engines.sh                # detect optional vendored engines; expose has_engine()
  modules/
    sast/
      run.sh
      rules/                  # vendored pattern packs (see §6.2 format)
        secrets.rules  crypto.rules  python.rules  javascript.rules
        go.rules  java.rules  injection.rules  nosql.rules  ldap.rules
      history.sh              # scan git history for secrets, not just the working tree
      adapters/               # optional: semgrep.sh, gitleaks.sh
    sca/                      # software composition analysis (dependency CVEs, offline)
      run.sh                  # parse lockfiles -> match against data/advisories.db
    iac/
      run.sh
      cloud.rules             # terraform.rules cloudformation.rules
      containers.rules        # Dockerfile, Kubernetes, docker-compose, Helm
      parse.sh
    dast/
      run.sh
      auth.sh                 # §7.0 session acquisition: login, token store, re-auth
      crawl.sh                # §7.5 spider + parameter/spec/HAR discovery
      passive/                # headers.sh tls.sh cookies.sh cors.sh banner.sh
                              # leakage.sh markup.sh
      active/                 # discovery.sh methods.sh sqli.sh xss.sh cmdi.sh
                              # traversal.sh ssti.sh redirect.sh xxe.sh ssrf.sh
                              # nosqli.sh ldapi.sh crlf.sh hosthdr.sh protopollution.sh
                              # jwt.sh graphql.sh ratelimit.sh authz.sh transport.sh
      payloads/               # vendored, non-destructive probe strings
      wordlists/              # vendored dir/file discovery lists
    cloud/
      aws/
        run.sh
        regions.sh            # enumerate + iterate enabled regions (per-region checks)
        live/                 # one script per service (see §8.1 catalog)
      posture/                # §8.7 expected-control checks (SAML, WAF, SSO, logout)
  data/                       # vendored, offline: versions.db  advisories.db  cis-mappings
  reports/                    # timestamped output dirs (findings.jsonl per run)
  state/                      # prior-run fingerprints for run-to-run diff (§9a)
  tests/
    fixtures/                 # deliberately-vulnerable sample code, IaC, mock responses
    run-tests.sh
  tools/
    run-in-netns.sh
    vendor-engines.sh         # one-time, on a networked box, to populate adapters + data/ offline
```

## 4. Shared libraries

### `lib/core.sh`
- Logging with levels (`log_debug/info/warn/error`), timestamped, colorized when TTY, plain when piped.
- `mktemp -d` scratch dir with an `EXIT` trap that shreds it.
- `set -Eeuo pipefail`; a global `ERR` trap that reports the failing command + line.
- Small helpers: `require_cmd`, `is_tty`, `now_iso`, `sha256_of`.

### `lib/http.sh` (the enforcement chokepoint)
- Single function `http_request METHOD URL [opts...]`. **Every** network call in DAST goes through it.
- On entry: resolve URL host, check against the allowlist built from `scope.conf`. Not listed -> hard fail, logged as a scope violation.
- Global token-bucket **rate limiter** (`requests_per_second` from config) so scans stay polite and don't DoS the target.
- Sane curl defaults: `--max-time`, `-s`, no redirects unless asked, custom UA string identifying the scanner, connection reuse.
- Never follows a redirect to an out-of-scope host.

### `lib/findings.sh` - data model
Every finding is one JSON object:
```json
{
  "id": "SAST-PY-EVAL-0007",
  "module": "sast|dast|cloud|sca|iac",
  "title": "Use of eval() on request-derived data",
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "cwe": "CWE-95",
  "owasp": "A03:2021-Injection",
  "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/...", "score": 9.8},
  "location": {"file":"app/x.py","line":42,"endpoint":null},
  "evidence": "...redacted, truncated...",
  "remediation": "...short fix guidance...",
  "references": ["CWE-95", "OWASP-A03"],
  "first_seen": "2026-07-30T...", "status": "new|recurring|fixed",
  "fingerprint": "sha256(stable fields)"
}
```
- `fingerprint` = hash of stable identity fields (module+rule+location, not evidence) so the same issue dedups across runs and can be suppressed via `baseline.json`.
- **Severity rubric (documented, deterministic).** Each check declares a base severity; `findings.sh` may adjust it from a small CVSS-style rubric (exposure: internet vs internal; auth required; data sensitivity; exploit complexity) so severity is reproducible and defensible rather than per-author guesswork. Store the CVSS vector for auditability.
- Severity ordering + a `--fail-on <severity>` gate for CI.

### `lib/report.sh`
- Emit **JSON** (full), **SARIF 2.1.0** (CI / code-scanning ingestion), **Markdown** (summary), self-contained **HTML** (human report, no external assets - inline CSS, no CDN, honors no-egress).
- HTML: executive summary (counts by severity + module + OWASP category), then per-finding cards with evidence, remediation, CWE/OWASP references.
- **Run-to-run diff (§9a).** Compare this run's fingerprints against `state/` to tag every finding `new` / `recurring` / `fixed`, and render a delta section ("since last scan: +N new, -M fixed"). This is the primary output for remediation-verification and regression gating.
- **Compliance mapping report.** Group findings by OWASP Top 10 (Appendix B) and CIS AWS Benchmark control id (from `data/cis-mappings`), so the same scan produces both an engineering view and a compliance view.
- **Scan metadata / audit record.** Every run writes `run.json`: tool version, timestamp, targets, regions, which checks ran/skipped and why, counts, and duration - so scans are reproducible and defensible for an audit.

## 5. CLI / orchestrator (`scan.sh`)

```
scan.sh <command> [options]

Commands:
  sast     [--path DIR] [--lang py,js,go,java] [--history]   # +git-history secrets
  sca      [--path DIR]                                      # dependency CVEs (lockfiles)
  iac      [--path DIR]                                      # cloud IaC + container/K8s
  dast     --target <name-from-scope> [--intensity passive|safe|active] [--authed]
  cloud    [--live] [--profile <p>] [--regions all|us-east-1,...] [--assume-role ARN]
  all      run every module for which inputs are configured
  diff     --against <prior-run-dir>       # new/fixed/recurring delta report
  report   regenerate reports from a prior run's findings.json

Global:
  --profile-scan quick|full|compliance   # curated check sets (see below)
  --paranoid            abort on any out-of-scope connection (§2)
  --allow-intrusive     enable side-effecting checks (live user-enum, etc.) - off by default
  --jobs N              parallelism (default from scanner.conf)
  --format json,sarif,html,md   (default: all)
  --fail-on SEVERITY    exit non-zero if >= this severity found (CI gate)
  --baseline FILE       suppress known findings
  --out DIR             report dir (default reports/<timestamp>)
```

**Scan profiles** keep "exhaustive" usable: `quick` (passive + config-read, no active probes, seconds-to-minutes), `full` (everything the config allows), `compliance` (only checks that map to a CIS/OWASP control, for the audit report). Profiles are just named check-set filters in `scanner.conf`.

**Circuit breaker (active scans).** The orchestrator watches target health: if the target returns sustained 5xx / connection failures above a threshold, it pauses then aborts that module with a clear reason rather than hammering a downed service. Complements the rate limiter and the per-run request budget.

Exit codes: `0` clean / below gate · `1` findings at/above `--fail-on` · `2` usage error · `3` scope violation · `4` missing required input · `5` target-health abort (circuit breaker).

## 6. Module - SAST (source code)

### 6.1 Approach
Native tier: a bash pattern engine over the tree using `ripgrep` if present else `grep -R`. Walks the repo, applies per-language rule packs, emits findings. Fast, zero deps, fully offline.

### 6.2 Rule file format (simple, greppable, extensible)
Pipe-delimited, one rule per line; `#` comments:
```
# id | severity | cwe | owasp | regex | message
PY-EVAL-01 | critical | CWE-95 | A03 | \beval\s*\( | eval() on untrusted input
PY-PICKLE  | high     | CWE-502| A08 | \bpickle\.load | insecure deserialization
PY-YAMLLD  | high     | CWE-502| A08 | yaml\.load\((?!.*Loader) | yaml.load without SafeLoader
```
Loader in `run.sh` parses these; each match becomes a finding with file+line. Keep a `# context:` directive option to require/deny a neighboring pattern (cheap way to cut false positives, e.g. only flag `eval(` when `request`/`input`/`argv` appears within N lines).

> NOTE (firstmate correction, see `docs/FOUNDATION.md` tension 1): the pipe-delimited format above is REPLACED
> by a blank-line-separated `key: value` block-record format, because any regex containing `|` silently
> corrupts the field split. The rule *catalog* below (which rules to seed) stands; only the on-disk
> format changes. See `rules/RULE-FORMAT.md` (frozen in the foundation).

### 6.3 Rule catalog to seed (per language)
- **secrets.rules** - AWS keys (`AKIA...`), private-key headers, high-entropy assignment heuristics, JWT, generic `api_key=`/`password=` literals, cloud-credential file patterns.
- **crypto.rules** - MD5/SHA1 for security, DES/ECB, hardcoded IV/salt, `verify=False`/disabled TLS verification, `Math.random()` for tokens.
- **injection.rules** (language-agnostic sinks) - OS-command concatenation, SQL string concatenation, **CRLF / header injection** (user input into headers/`Location`), **host-header trust**, **template injection** sinks, unsafe redirect from user input, **mass-assignment** (binding whole request bodies to models), **XXE** (parsers with external entities enabled).
- **nosql.rules / ldap.rules** - NoSQL query operators built from user input (e.g. `$where`, object injection), LDAP filters from unescaped input.
- **python** - `eval/exec`, `pickle`, `yaml.load`, `subprocess ... shell=True`, `os.system`, Flask `debug=True`, Jinja `autoescape=False`, raw SQL f-strings.
- **javascript/ts** - `eval`, `child_process.exec`, `dangerouslySetInnerHTML`, `document.write`, template-literal SQL, `require` on user input, disabled TLS (`rejectUnauthorized:false`), **prototype pollution** patterns (recursive merge / `__proto__` assignment).
- **go** - `exec.Command` with concatenation, `text/template` for HTML, `math/rand` for secrets, SQL string concat, `InsecureSkipVerify:true`.
- **java** - `Runtime.exec`, JDBC statement concatenation, XML parsers without `disallow-doctype`, deserialization (`readObject`), `TrustAllCerts`, SpEL/OGNL injection.
- **history.sh** - replays the same secret rules across **git history** (`git log -p` / `git rev-list`), since secrets are frequently committed then "removed" but remain in history. Bounded by a commit/time window; skipped if not a git repo.

### 6.4 Optional adapters (`adapters/`)
`engines.sh` detects a vendored `semgrep`/`gitleaks` binary + local ruleset. If present and `--use-engines` given, run them **offline** (`semgrep --offline --config <local rules>`, `gitleaks --no-banner`), normalize their JSON into the finding model, merge + dedup with native results. If absent, silently continue native-only.

### 6.5 Module - SCA (dependency vulnerabilities, offline) - `modules/sca/run.sh`
This is the *proper* answer to OWASP A06, stronger than version-in-response detection:
- Parse dependency manifests/lockfiles: `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`, `requirements.txt`/`poetry.lock`/`Pipfile.lock`, `go.mod`/`go.sum`, `pom.xml`/`build.gradle`, `Gemfile.lock`, `composer.lock`.
- Match each pinned `name@version` against a **vendored offline advisory database** (`data/advisories.db`, e.g. an OSV export refreshed by `vendor-engines.sh` on a networked box) -> emit a finding per vulnerable dependency with the advisory id, affected range, and fixed version.
- Flag **direct vs transitive**, and dependencies with no fixed version (accept-risk candidates). Pure text/JSON parsing - no package manager needs to run, so it stays air-gapped.

### 6.6 Module - Container & orchestration IaC - `modules/iac/` (`containers.rules`)
Extends IaC beyond Terraform/CloudFormation (§8.2) to the container stack:
- **Dockerfile** - runs as root / no `USER`, `:latest` base tag, secrets in `ENV`/`ARG`, `ADD` from a URL, `curl | sh` build steps, no pinned base digest.
- **Kubernetes manifests** - `privileged: true`, `hostNetwork`/`hostPID`, missing resource limits, `runAsNonRoot` unset, secrets in env, `imagePullPolicy` + `:latest`, overly-broad RBAC (`*` verbs/resources), `automountServiceAccountToken` on by default.
- **docker-compose / Helm values** - exposed ports, host bind mounts of sensitive paths, plaintext secrets.
Same `.rules` engine as SAST, so adding checks is a data change.

## 7. Module - DAST (running endpoint)

**Scope gate first:** the `--target` name must resolve to an entry in `scope.conf`. No entry -> exit 3. This is the single most important safety control; do not make it bypassable by raw URL.

Intensity tiers stack:

### 7.0 Authentication & session acquisition (`auth.sh`) - prerequisite for authenticated checks
Everything in §7.4 (IDOR, excessive-data, JWT replay) and any authenticated crawl needs a logged-in session; this module obtains and maintains it. Credentials come **only from operator config** (`config/auth.conf` or a referenced secrets file with `600` perms), never hardcoded, never logged, redacted in all evidence.
- **Supported login modes (pluggable):** static bearer token / API key; form login (POST creds, capture Set-Cookie); OAuth2/OIDC password or client-credentials grant; and identity-provider SRP for Cognito-style pools (compute the SRP handshake in shell, or accept a pre-obtained token to avoid re-implementing crypto).
- **Session store:** cookie jar + token cache in the run's scratch dir (`600`), injected into every `http_request` for authenticated checks.
- **Re-auth on expiry:** on `401`/token-expiry, transparently refresh once and retry; if refresh fails, mark the authenticated checks `skipped` with a clear reason rather than emitting false negatives.
- **Multi-identity:** accept two or more labelled identities (A, B) so `authz.sh` can do cross-user IDOR checks. Test accounts are the operator's responsibility and declared in config.

### 7.1 Passive (`passive/`)
No mutation of state. One file per family so each is independently testable against a recorded response:
- **headers.sh** - security-header set: CSP present + not `unsafe-inline`/`unsafe-eval`, no `data:` source, no wildcard in the domain portion; HSTS present + adequate `max-age` (flag missing/weak/errors); `X-Frame-Options`/`frame-ancestors`; `X-Content-Type-Options`; `Referrer-Policy` (flag leaky values that send the full URL cross-origin); and a configurable "recommended headers not set" roll-up.
- **cookies.sh** - `Secure`, `HttpOnly`, `SameSite` flags per cookie.
- **tls.sh** - `openssl s_client`: protocol/cipher, cert expiry, self-signed, **wildcard certificate in use where a SAN/host-specific cert is expected** (configurable expectation).
- **cors.sh** - origin-reflection (`Origin: <sentinel>` -> check `Access-Control-Allow-Origin` + credentials).
- **banner.sh** - server/framework disclosure and **framework version disclosure** (e.g. framework/library name + version in headers, meta tags, or bundle filenames). Version strings are matched against a **vendored** known-vulnerable-version list (`data/versions.db`, offline) to flag **out-of-date components** without any internet lookup.
- **leakage.sh** - verbose error / stack-trace disclosure; **upstream proxy header leakage** (e.g. `x-envoy-*`/`via`/internal routing headers surfaced to clients); email-address disclosure (regex); client-config leakage in served JS (identity/client/pool identifiers, backend endpoints, embedded API keys); **CDN/third-party origin detected** (informational).
- **markup.sh** - parse returned HTML: **missing Subresource Integrity** on `<script>`/`<link>` with a cross-origin `src`; **reverse tabnabbing** (`target="_blank"` without `rel="noopener"`/`noreferrer"`), weighted higher on login/redirect pages; **insecure external frame** (framing untrusted/`http://` origins); **CSRF-token absence** in state-changing forms (login/other POST forms lacking an anti-CSRF token, combined with cookie `SameSite` state -> "[possible] CSRF").

### 7.2 Safe active (`active/discovery.sh`, `methods.sh`)
Content discovery from the **vendored** wordlist (status-code + length heuristics), HTTP method enumeration (`OPTIONS`, dangerous `PUT`/`DELETE`/`TRACE`), directory-listing detection, backup/temp file patterns (`.bak`, `~`, `.git/`, `.env`).

### 7.3 Active injection - **detection-oriented, non-destructive**
Design principle for every probe: **prove a vuln exists via a signal, don't exploit it.** No data modification, no destructive payloads (no `DROP`/`DELETE`/stacked writes), no data exfiltration beyond the minimal evidence needed to confirm. Payloads live in `payloads/` so they're auditable.

- **SQLi** - (a) error-based: inject `'` / `"` and diff for DB error signatures; (b) boolean: send a tautology vs a contradiction that are otherwise identical, flag if responses differ meaningfully; (c) time-based: inject a bounded `sleep`/`WAITFOR` and flag on a latency delta above threshold. Report the parameter + technique; do not dump data.
- **XSS** - inject a unique marker token, check for **unescaped reflection** of that exact token in HTML/JS/attribute context. Reflection = finding; no payload execution needed.
- **Command injection** - bounded time-based only (`; sleep N` style) measuring latency delta. Never a payload that reads/writes files or opens connections.
- **Path traversal** - request known-safe read-only markers (e.g. traversal to a benign, universally-present read-only file) and detect its signature; report access, don't harvest contents.
- **SSTI** - inject a simple arithmetic expression per templating syntax; flag if the response contains the evaluated result.
- **Open redirect** - set redirect param to an in-scope sentinel; flag if a 3xx `Location` honors attacker-controlled host.
- **XXE / SSRF** - **detection via safe internal sentinels only**, and **only against in-scope hosts**; SSRF probes must target an operator-declared sentinel, never arbitrary metadata endpoints unless the operator explicitly opts in for their own audit. Default: report the *reachable sink*, flag for manual review, don't chase the exploit.
- **NoSQL injection** (`nosqli.sh`) - operator/object injection (e.g. always-true operators) and syntax-error differentials; boolean/response-diff detection, no data extraction.
- **LDAP injection** (`ldapi.sh`) - filter-breaking payloads; detect via response/error differential.
- **CRLF / header injection & response splitting** (`crlf.sh`) - inject encoded CR/LF into params reflected in headers/`Location`; flag if a header split is honored.
- **Host-header injection** (`hosthdr.sh`) - send a spoofed `Host`/`X-Forwarded-Host`; flag if it's reflected into links, redirects, or password-reset URLs (cache-poisoning / reset-poisoning risk).
- **Prototype pollution** (`protopollution.sh`, for JS backends) - send `__proto__`-style params to JSON endpoints; flag behavioral change indicating pollution. Detection only.

Each probe records request/response evidence (truncated, secrets redacted) and a confidence level; time-based checks re-test to reduce false positives from jitter. Every injection probe iterates the **parameter inventory** built by the crawler (§7.5): query params, body/JSON fields, headers, and path segments - not just top-level query strings.

### 7.4 Active - auth, API, and access-control checks (detection-oriented)
Same contract as §7.3: prove the weakness with a signal against an **operator-authorized, in-scope** target, non-destructive, evidence-only. Endpoint paths that vary per app come from config (§11), never hardcoded.

- **jwt.sh - token-verification weaknesses.** Given a sample token (or one minted for a test account the operator supplies), derive variants and replay each against a protected endpoint, flagging any that is **accepted**:
  - **`alg:none` / unsigned** - re-encode header with `alg:none`, strip the signature.
  - **empty-secret HS256** - re-sign with an empty key.
  - **weak/guessable secret** - attempt signing with a small **vendored** list of common/weak HMAC secrets (bounded, offline; this is weak-key *detection*, not a cracking rig - cap attempts, no wordlist expansion).
  - **algorithm confusion** - RS->HS downgrade where a public key is known/derivable.
  Detection = "protected resource returned success with a forged/weakened token." Report the accepted variant; never persist or reuse the forged token beyond the single probe.
- **graphql.sh - introspection & key exposure.** If a GraphQL/AppSync endpoint is in scope: send a standard introspection query and flag if the **schema is returned** (introspection enabled in prod). If a long-lived API key was found in the served JS (§7.1 `leakage.sh`), report that the key grants schema/content access - as a correlated finding, without exfiltrating data.
- **ratelimit.sh - missing throttling.** Send a bounded burst (respecting a hard cap) to an idempotent endpoint and flag the **absence of `429`/rate-limit headers / back-off**. Strictly capped and skippable; this is the one check that intentionally sends several requests, so it honors an explicit per-run budget.
- **authz.sh - object-level & data-exposure checks** (needs two operator-supplied test identities to be meaningful):
  - **IDOR / missing object authorization** - request an object-reference endpoint as identity A using identity B's reference; flag if A receives B's object. Read-only references only; no writes.
  - **excessive data exposure** - call an authenticated profile/bootstrap endpoint and flag when the response body contains far more fields than the view needs (configurable sensitive-field list: tokens, internal IDs, other users' data).
- **transport.sh - plaintext exposure.** Flag a service answering on `http`/port 80 that does not redirect to TLS, and mixed-content resources; complements the TLS passive check.

**Enumeration-via-response checks** (user-existence through login / password-reset / signup responses) stay **config-derived by default** and only run live as an explicit opt-in (`--allow-intrusive`), single-request, never bulk, never mass-triggering email/SMS - because on a real identity provider these create users and send messages.

### 7.5 Crawling, parameter & spec discovery (`crawl.sh`)
Injection and access-control checks are only as good as the surface they know about. This module builds the target inventory (URLs, endpoints, forms, parameters) that the active checks iterate:
- **Static crawl** - fetch in-scope pages, extract links/forms/`action`s/input names, follow within scope up to a configurable depth, honoring the rate limiter and scope gate.
- **Spec ingestion (preferred, most complete)** - if an **OpenAPI/Swagger** doc, **GraphQL schema**, **Postman collection**, or **HAR capture** is provided in config, parse it to enumerate endpoints, methods, and parameters directly. This is the highest-signal input and the recommended way to feed the scanner.
- **Route import from SAST (§8.4)** - merge the statically-extracted server routes so server-side endpoints with no inbound link are still tested.
- **Output** - a deduped `endpoints.json` + `parameters.json` consumed by §7.3/§7.4. Still scope-gated: nothing is requested that isn't an in-scope host.

> **Honest limitation - SPA / client-rendered apps.** A pure-shell crawler fetches HTML but **cannot execute JavaScript**, so for a client-rendered app (e.g. a React/Next.js SPA) it will miss client-side routes and XHR/fetch endpoints that only exist after JS runs. Mitigations, in order of preference: (1) feed an **OpenAPI/GraphQL schema or a HAR capture** of real usage - this fully closes the gap; (2) rely on **SAST route extraction** for server endpoints; (3) if deeper dynamic coverage is required, that needs a headless browser, which is outside the pure-shell/no-egress envelope and should be a documented, separate opt-in tool - not smuggled into the core. The scanner states this limitation in its report so coverage is never overstated.

## 8. Module - Cloud / AWS (live + IaC)

### 8.1 Live (`aws/live/*.sh`) - read-only only
- Enforce read-only by construction: scripts use **only** `describe-*`, `list-*`, `get-*`. Add a lint in `tests/` that greps the live scripts and fails CI if any mutating verb (`create/put/delete/update/modify/attach/authorize`) appears.
- Recommend (in docs) running under an IAM role with an explicit read-only policy - the tool audits, it never changes state.
- **Multi-region & multi-account (`regions.sh`).** Most services are regional, so a truthful audit **iterates every enabled region** (`account get-regions` / EC2 `describe-regions`), not just the default. Optionally iterate accounts via `--assume-role` across an Org (read-only role in each). Findings cite region + account so results are unambiguous.
- Checks mapped to the **CIS AWS Foundations Benchmark** and common misconfigs, one script per service. Seed catalog (extend freely - each service is one script):

| Service | Representative read-only checks |
|---|---|
| **s3** | public ACL/policy, no default encryption, block-public-access off, no versioning/logging, `get` for all principals |
| **iam** | root MFA, root access keys, `*:*` policies, wildcard/`*` trust policies, **cross-account trust without ExternalId**, unused/old keys & roles, no password policy, no permission boundaries, **Access Analyzer** findings, inline vs managed sprawl |
| **ec2 / vpc** | SGs open `0.0.0.0/0` on 22/3389/db ports, default SG in use, public AMIs, **public EBS snapshots**, unencrypted EBS, IMDSv2 not enforced, VPC flow logs off |
| **rds / dynamodb** | public accessibility, no encryption at rest, no backups/PITR, public snapshots |
| **cognito / identity pools** | see §8.3 |
| **lambda / serverless** | see §8.6 |
| **apigw** | see §8.4 |
| **appsync** | see §8.5 |
| **cloudfront** | no TLS / weak min protocol, no WAF association, no OAC/OAI (origin exposed), missing logging |
| **elb / alb** | HTTP listener without redirect, weak TLS policy, no access logs |
| **acm / route53** | cert nearing expiry, dangling DNS records (subdomain-takeover risk) |
| **secretsmanager / ssm** | secrets without rotation, SSM `String` where `SecureString` expected, over-broad resource policies |
| **kms** | key rotation off, overly-permissive key policies |
| **ecr / ecs / eks** | public repos, scan-on-push off, mutable tags, task/pod roles over-permissive, public clusters |
| **opensearch / redshift / efs** | public access, no encryption at rest/in transit |
| **sns / sqs** | topic/queue policies allowing `*` principal, unencrypted |
| **cloudtrail / config / guardduty** | not enabled / not multi-region / no log-file validation; Config & GuardDuty disabled |
| **inspector / macie** | not enabled (vuln + sensitive-data discovery coverage gap) |
| **backup** | no backup plan for critical resources |

- Every finding cites the resource ARN, region/account, and the CIS control id. The table is a **seed, not a ceiling** - the `.rules`/per-service-script pattern makes adding a service a contained change.

### 8.2 IaC (`aws/iac/`)
- `parse.sh` walks for `*.tf`, `*.yaml/yml/json` (CloudFormation) and applies pattern rules in the same `.rules` format as SAST.
- Seed rules: `cidr_blocks = ["0.0.0.0/0"]`, `acl = "public-read"`, `encrypted = false`, missing `enable_key_rotation`, `associate_public_ip_address = true`, hardcoded secrets in `.tf`, `publicly_accessible = true` (RDS).
- Optional adapter for a vendored `checkov`/`tfsec`/`trivy config` run offline, normalized into the model (same pattern as §6.4).

### 8.3 Cognito (live, read-only - `aws/live/cognito.sh`)
Uses `cognito-idp` + `cognito-identity`, `describe-*`/`list-*`/`get-*` only (covered by the read-only lint). Group into three check sets:

**User pool** (`list-user-pools` -> `describe-user-pool`):
- Password policy: min length `< 8`, missing complexity requirements, over-long temporary-password validity.
- MFA configuration is `OFF` or `OPTIONAL` (flag; `ON` expected for sensitive pools).
- Advanced security mode not `ENFORCED` (`OFF`/`AUDIT`) -> no compromised-credential detection / adaptive auth.
- `PreventUserExistenceErrors` not `ENABLED` -> username enumeration.
- Self-registration open: `AdminCreateUserConfig.AllowAdminCreateUserOnly = false` -> flag for review.
- Account recovery via SMS/phone only (SIM-swap exposure); deletion protection disabled.

**App clients** (`list-user-pool-clients` -> `describe-user-pool-client` for each):
- `ExplicitAuthFlows` includes `ALLOW_USER_PASSWORD_AUTH` / `ADMIN_USER_PASSWORD_AUTH` (plaintext, non-SRP) or legacy `USER_PASSWORD_AUTH`.
- Implicit OAuth flow enabled (`AllowedOAuthFlows` contains `implicit`) -> token exposed in URL fragment.
- Callback / logout URLs that are `http://` (non-TLS), wildcarded, or overly broad -> token theft / open redirect.
- Excessive token lifetimes (access/ID/refresh); `EnableTokenRevocation` off.
- **Client-writable sensitive attributes** (`WriteAttributes` includes `email_verified`, `phone_number_verified`, or custom privilege attrs) -> privilege escalation.
- `PreventUserExistenceErrors` disabled at client level; public client (no secret) using flows that assume confidentiality.

**Identity pool** (`list-identity-pools` -> `describe-identity-pool` + `get-identity-pool-roles`):
- `AllowUnauthenticatedIdentities = true` -> then **inspect the unauthenticated IAM role policy for over-permissiveness**. Anonymous callers assuming a broad role is high-impact; emit as its own high-severity finding, not a note.
- **`AllowClassicFlow` enabled** -> the identity pool permits the legacy/basic auth flow (should be off).
- **Unauthenticated `GetCredentialsForIdentity` reachable** -> anonymous callers can obtain AWS credentials via the pool; report together with the unauth-role scope.
- Token-based role-mapping misconfigurations.

**Unauthenticated user-pool API surface** (config-derived; report which self-service operations are exposed):
- **`SignUp` enabled** -> external self-registration possible without admin. Derive from `AdminCreateUserConfig.AllowAdminCreateUserOnly` and client settings rather than actually signing up.
- **`ForgotPassword` reachable** -> self-service password reset exposed where policy expects it disabled.
- Combined with the app-side check (§7.4) that a **password reset succeeds even for a non-registered user** (user-enumeration via the reset flow) - config-derived detection preferred, live only under `--allow-intrusive`.

Each finding cites the pool/client/identity-pool ID and, where applicable, the CIS control. **Prefer config-derived detection** of user-enumeration and self-signup over live endpoint probing (see §7.x note) - active probing creates real users and fires verification email/SMS.

### 8.4 Endpoint inventory (`aws/live/apigw.sh` + SAST route extraction)
Answers "what are all my endpoints," fed to DAST as candidate targets (still scope-gated):
- **API Gateway** (read-only): `get-rest-apis` + `get-resources` for the route list; `get-api-keys` (existence only, never values); per-method authorizer presence -> flag routes with **no authorizer / open auth**.
- **SAST route extraction**: grep framework route definitions - Flask `@app.route`, Express `app.<verb>(`, Spring `@RequestMapping`/`@GetMapping`, Go mux/`http.HandleFunc` - and emit `endpoints.json`. DAST consumes this list but still refuses any host absent from `scope.conf`.

### 8.5 AppSync / managed GraphQL (live, read-only - `aws/live/appsync.sh`)
- **API-key auth in use** and **key expiry** - `list-graphql-apis` -> `list-api-keys`; flag keys with a **long/far-future expiry** (long-lived keys are the root of the "key in bundle -> content exposed" chain) and APIs whose default auth is a plain API key rather than IAM/Cognito.
- Correlate with §7.1 (`leakage.sh`) and §7.4 (`graphql.sh`): a long-lived key present in served JS + introspection enabled = schema and content exposure.

### 8.6 Serverless functions & AI/agent deployments (live, read-only - `aws/live/lambda.sh`)
Covers the "function backing a deployment has too much access / is publicly reachable" class:
- **Over-permissive execution role** - resolve each function's IAM role and flag wildcard actions/resources or sensitive-service grants beyond what the function needs.
- **Public function URL** (`get-function-url-config` with `AuthType: NONE`) or a resource policy allowing `*` principal invoke.
- **Secrets in environment variables** (pattern-match env keys/values), and unencrypted env.
- Generic across "AI/agent/bedrock-style" deployments - the check is about the function's access and exposure, named nowhere in code.

### 8.7 Configuration-state / posture checks (read-only, not probeable - `posture/`)
Facts the scanner **reads and reports as present/absent/misconfigured**; there is nothing to actively trigger. Each has an expected value supplied in config so the tool reports *drift*, not opinion:
- **Federated-SSO signing & encryption** - SAML/OIDC assertions signed and encrypted between IdP and app (read from the identity-provider/app-client config).
- **SSO enablement gaps** - expected SSO integration to a downstream analytics/BI tool is present (operator declares the expectation; tool reports if absent).
- **Edge/WAF IP allowlisting** - access restricted to trusted networks (WAF IP sets / hosting-firewall rules present).
- **Geo / embargoed-country restriction** - WAF geo-match / country block present per the configured list.
- **Edge TLS/port policy** - only `443` served, `80` redirects, HSTS applied at the edge (cross-checks §7.4 `transport.sh`).
- **Session-termination capability** - a logout/session-invalidation route exists (heuristic: presence of a logout endpoint in the route inventory from §8.4; otherwise flagged for manual confirmation).
These live under `modules/cloud/posture/` and read from live APIs, IaC, or an operator-provided config export. They produce `info`/`medium` findings framed as "expected control not observed."

### Cross-module rule additions (fold into existing modules)
- **DAST passive (§7.1):** Cognito/Amplify config leakage - parse returned JS for `userPoolId`, `userPoolWebClientId`, `identityPoolId`, `region`; flag loudly when an identity pool with unauth access is exposed. Broaden version disclosure - `Server`, `X-Powered-By`, `X-AspNet-Version`, framework fingerprints, JS library versions, optionally matched against a **vendored** known-vuln version list (stays offline). Reverse tabnabbing - anchors with `target="_blank"` lacking `rel="noopener"`/`noreferrer"`, weighted higher on login/OAuth-redirect pages.
- **DAST active (opt-in, side-effecting):** live user-enumeration via Cognito auth-endpoint responses - single crafted request, no bulk enumeration, never mass-trigger email/SMS. Default off; config-derived detection (§8.3) preferred.
- **SAST (§6.3):** new `secrets`/`config` rules for hardcoded `userPoolId`/`clientId`/`identityPoolId`/app-client secret; reverse-tabnabbing rule (`target="_blank"` without `rel=noopener`) for `.html`/`.jsx`/`.tsx`/`.vue`.

## 9. Exhaustiveness strategy (native vs engines)

Two tiers, operator chooses:

1. **Native (default):** pure bash + pattern rules. Zero deps, fully air-gapped, "linter-grade" depth. Great signal on secrets, dangerous sinks, weak crypto, IaC misconfig, header/TLS/injection *detection*. Blind spot: cross-function data-flow.
2. **Engine-boosted (opt-in):** drop vendored offline engines into `adapters/` via `tools/vendor-engines.sh` (run **once on a networked box**, commit the binaries + local rule DBs, then the scanner uses them offline forever). Adds taint/data-flow depth without breaking no-egress.

`tools/vendor-engines.sh` is the *only* script that touches the internet, is never called during a scan, and is clearly quarantined + documented as such.

## 9a. Run-to-run diff & baselining (`diff` command + `state/`)
For a remediation-verification tool this is a first-class feature, not an add-on:
- After each run, persist the set of finding fingerprints (+ severity, first-seen) to `state/`.
- `scan.sh diff --against <prior-run>` (and every normal run, automatically) classifies each finding: **new** (not in prior), **recurring** (in both), **fixed** (in prior, gone now). The report leads with this delta.
- CI usage: `--fail-on high` **combined with** "fail only on *new* high+ findings" lets teams gate on regressions without being blocked by a known backlog - the single most useful mode for continuous scanning.
- `baseline.json` remains the explicit accept-risk list; `state/` is the automatic history. The two are distinct: baseline = "we accept this," state = "we've seen this."

## 10. Concurrency, performance, resumability
- Parallelize file/host/check fan-out with `xargs -P "$JOBS"` (fallback) or GNU `parallel` if present; bound by `--jobs`.
- DAST honors the global rate limiter **and** the circuit breaker (§5) regardless of `--jobs`; active checks also share a per-run request budget.
- Write findings incrementally to `reports/<run>/findings.jsonl`; a resumable run skips already-completed work units keyed by fingerprint, so long AWS/DAST scans survive interruption.
- AWS calls are cached per (service, region, account) within a run so multiple checks reading the same `describe-*` don't re-fetch.

## 11. Config files

- **`config/scope.conf`** - required. Named targets: `name | base_url | notes`. DAST refuses anything not here. Ship a `.example` and make the tool error clearly if it's missing/empty.
- **`config/scanner.conf`** - `requests_per_second`, `jobs`, `http_timeout`, `fail_on`, `redact_secrets=true`, default formats, circuit-breaker thresholds, per-run request budget, and the named **scan-profile** check-sets (`quick`/`full`/`compliance`).
- **`config/auth.conf`** (perms `600`, or a reference to an external secrets file) - per-target login mode + credentials for authenticated DAST; supports multiple labelled identities (A/B) for IDOR checks. Never logged; redacted everywhere.
- **`config/discovery.conf`** - optional paths to an OpenAPI/Swagger spec, GraphQL schema, Postman collection, or HAR capture to feed the crawler (§7.5); crawl depth; endpoint/param allow-and-deny lists.
- **`config/posture.conf`** - expected-control baselines for §8.7 (which SSO integrations should exist, WAF IP/geo expectations, org password-policy thresholds) so posture checks report *drift* rather than opinion.
- **`config/baseline.json`** - array of accepted fingerprints to suppress.

## 12. Testing

- `tests/fixtures/` - a deliberately-vulnerable sample repo (per language), sample vulnerable Terraform/CFN, and **recorded mock HTTP responses** so DAST logic is testable with no live target.
- `tests/run-tests.sh` - asserts each seeded rule fires on its fixture (true positives) and stays quiet on a clean fixture (false-positive guard), validates JSON/SARIF schema, and runs the **read-only lint** over `aws/live/`.
- Add a **no-egress test**: run the full suite under `--paranoid` against fixtures/mocks and assert zero out-of-scope connection attempts.

## 13. Build order

1. `lib/core.sh`, `lib/findings.sh` (incl. severity rubric), `lib/report.sh` (JSON/HTML + `run.json` metadata) + the finding schema and a trivial fixture -> report plumbing working end to end.
2. `scan.sh` skeleton + config loading + `scope.conf` gate + exit codes + scan profiles.
3. **SAST** native engine + rule format + seed `secrets`/`crypto`/`injection`/`python` rules + fixtures/tests. Then the other languages; then `history.sh`.
4. **SCA** (lockfile parse -> `advisories.db`) and **IaC** (cloud + container rules) - both reuse the rule engine.
5. `lib/http.sh` (scope allowlist + rate limit + circuit breaker) -> **`auth.sh`** (§7.0) -> **`crawl.sh`** (§7.5) -> **DAST passive** -> safe-active -> injection probes one file at a time, each with a mock-response test -> §7.4 auth/API/authz checks.
6. **Cloud**: `regions.sh` iteration -> live read-only checks (§8.1 catalog) + the read-only lint -> `posture/` checks.
7. **Diff/state** (§9a): fingerprint history + `diff` command + "fail on new only" mode.
8. `--paranoid` enforcement + `tools/run-in-netns.sh`.
9. Optional `adapters/` + `tools/vendor-engines.sh` (also populates `data/` DBs), clearly quarantined.
10. SARIF + compliance-mapping report + `--fail-on` CI gate + docs/README.

## 14. Guardrails to bake in from day one

- DAST cannot run against a host absent from `scope.conf` - no raw-URL bypass; the crawler and every probe are scope-gated.
- Injection probes are detection/evidence only: no destructive payloads, no data exfiltration, re-test to kill jitter false positives.
- Side-effecting checks (live user-enum, signup/reset probing) are off unless `--allow-intrusive`.
- Live AWS is read-only by construction and enforced by a CI lint; multi-account only via read-only assumed roles.
- Credentials (DAST auth, AWS) are never logged; `redact_secrets` scrubs secret-matching patterns from all evidence and reports; scratch/session/config files use `600` perms.
- The only internet-touching script (`vendor-engines.sh`) is never invoked by a scan and is documented as the sole exception.

## 15. Known limitations & honest scope (state these in the report)

Being explicit here is what keeps the output trustworthy - a scan that overstates coverage is worse than one that names its blind spots:
- **Client-rendered SPAs** - the pure-shell crawler can't execute JavaScript; client routes/XHR endpoints are only covered if a spec/HAR is supplied or routes come from SAST (§7.5).
- **Data-flow SAST** - native tier is pattern/linter-grade; true taint/cross-function analysis needs the optional vendored engines (§9).
- **CVE/advisory freshness** - SCA and outdated-component verdicts are only as current as the last `vendor-engines.sh` refresh of `data/`; on an air-gapped host that's a deliberate, dated snapshot, not real-time.
- **Business logic & full authorization** - IDOR/excessive-data checks are detection-oriented; complete access-control correctness (A01) and design flaws (A04) still require human review.
- **Not a pentest / not ASVS** - this is automated regression + posture scanning that complements, and does not replace, a manual assessment.

## 16. Extension points

- New language SAST or IaC target = a new `.rules` file, no code change.
- New cloud provider = a new `modules/cloud/<provider>/` mirroring the AWS layout.
- New injection class = a new `active/<name>.sh` following the detection-only contract, auto-iterated over the parameter inventory.
- New dependency ecosystem = a new lockfile parser feeding the same advisory match.
- New output format = a new emitter in `report.sh`.

---

## Appendix A - Detection coverage catalog (traceability matrix)

The full generic finding-class catalog (no target names) from the original handoff is preserved. Every
finding class is described generically, with a check id, module, and type
(`passive`/`active`/`safe-active`/`config-read`/`posture`/`static`). `COMPOSITE-TOKEN-HIJACK` is a derived
roll-up computed in `lib/findings.sh` from contributing findings, not a scanner script. See §4 and
`docs/FOUNDATION.md` tension 6 for the derived-finding mechanism.

## Appendix B - OWASP coverage mapping (and honest limits)

This tool targets the **testable portion of the OWASP Top 10 (2021)**; it does **not** attempt full ASVS.
Each finding carries an `owasp` tag so the report can group by category. Coverage: A01 partial
(detection-oriented), A02 strong, A03 strong, A04 not covered (inherent - design category), A05 strong,
A06 strong (needs vendored DB), A07 strong, A08 partial, A09 partial (cloud-side only), A10 covered
(detection-oriented). The OWASP API Security Top 10 overlaps and is largely covered by the same checks.
Honest one-line summary: **strong automated coverage of the testable Top 10, explicit and labeled gaps on
A04/A08/A09 and the manual-review portion of A01 - not a substitute for a human pentest or an ASVS audit.**
