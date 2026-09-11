# What scoursh detects

*Also available as a standalone page: [`checks.html`](checks.html).*

The full built-in check catalogue on the `dev` branch, grouped by scan surface and by what each check
needs to run. 319 checks ship in the box (53 SAST + 36 IaC + 92 DAST + 15 network + 11 container-image +
112 Cloud/AWS; SCA is a table lookup across 6 ecosystems, not counted as checks).

> **Almost everything runs with no external data.** Point scoursh at source code (`--path`), a live
> app (`--target`), or an authorized listener set (`--target`, network) and every SAST, IaC, DAST, and
> network check below works immediately - no database, no downloads, no network of scoursh's own
> choosing. **Dependency-CVE scanning (SCA)**, most of **container-image scanning** (the three
> `IMAGE-CFG-*` config-blob checks need only a supplied image, no database), and three banner-version
> checks (one DAST, two network) need the vendored advisory database; **Cloud/AWS (CSPM)** needs
> resolvable AWS credentials.

| | |
|---|---|
| **53** | SAST checks |
| **36** | IaC checks |
| **46** | DAST passive |
| **34** | DAST active |
| **12** | DAST authorization/JWT/rate-limit/GraphQL |
| **15** | Network/host checks |
| **6** | SCA ecosystems |
| **11** | Container-image checks |
| **112** | Cloud/AWS checks (30 services) |

## Legend

- 🟢 **No external data** - works on just `--path` (code) or `--target` (a running app). Active DAST
  needs a reachable target + `--i-own-target`.
- 🔵 **Needs the advisory DB** - requires `data/advisories.db` (built with `tools/vendor-engines.sh
  advisories`).
- 🟣 **Optional engine depth** - `--use-engines` adds vendored Semgrep/Trivy/Gitleaks. Boosts depth,
  not new categories.
- 🟠 **Needs AWS credentials** - resolvable via profile, environment, or instance role
  (`aws sts get-caller-identity`); read-only only, enforced by `lib/awscli.sh`'s `aws_ro` chokepoint.
  Optional `--i-own-account ID` affirmation and `--assume-role` for multi-account.

## SAST 🟢 no external data

Static analysis of source code. Runs on `./scan.sh sast --path DIR` with nothing else.

### Secrets — hardcoded credentials in code

| Check | Catches | CWE |
|---|---|---|
| `SAST-SEC-AWS_AKID-01` | Hardcoded AWS access key id | CWE-798 |
| `SAST-SEC-PRIVATE_KEY-01` | Hardcoded private key | CWE-798 |
| `SAST-SEC-GENERIC_API_KEY-01` | Hardcoded API key literal | CWE-798 |
| `SAST-SEC-GENERIC_PASSWORD-01` | Hardcoded password literal | CWE-798 |
| `SAST-SEC-GENERIC_SECRET-01` | Hardcoded secret, token or credential literal | CWE-798 |
| `SAST-SEC-ENV_ASSIGNMENT-01` | Hardcoded credential in an unquoted assignment | CWE-798 |
| `SAST-SEC-JWT-01` | Hardcoded JSON Web Token | CWE-798 |

### Crypto — weak cryptography

| Check | Catches | CWE |
|---|---|---|
| `SAST-CRY-WEAK_HASH-01` | MD5 or SHA1 used where a security-relevant hash is expected | CWE-327 |
| `SAST-CRY-DES_ECB-01` | DES or ECB-mode cipher in use | CWE-327 |
| `SAST-CRY-HARDCODED_IV-01` | Hardcoded initialization vector or salt | CWE-329 |
| `SAST-CRY-TLS_VERIFY_DISABLED-01` | TLS certificate verification disabled | CWE-295 |
| `SAST-CRY-WEAK_RANDOM_TOKEN-01` | Math.random() used to generate a token, session id, or secret | CWE-338 |

### Injection — language-agnostic sinks

| Check | Catches | CWE |
|---|---|---|
| `SAST-INJ-OS_COMMAND-01` | OS command built from a shell that trusts its own arguments | CWE-78 |
| `SAST-INJ-SQL_CONCAT-01` | SQL statement built by string concatenation | CWE-89 |
| `SAST-INJ-CRLF_HEADER-01` | Response header value built from request-derived data | CWE-113 |
| `SAST-INJ-HOST_HEADER_TRUST-01` | Host header trusted to build a URL or redirect target | CWE-441 |
| `SAST-INJ-SSTI-01` | Server-side template built from request-derived data | CWE-1336 |
| `SAST-INJ-OPEN_REDIRECT-01` | Redirect target taken directly from request-derived data | CWE-601 |
| `SAST-INJ-MASS_ASSIGNMENT-01` | Whole request body bound directly to a model | CWE-915 |
| `SAST-INJ-XXE-01` | XML parser configured to resolve external entities | CWE-611 |

### Python · JavaScript · Go · Java — language-specific sinks

| Check | Catches | CWE |
|---|---|---|
| `SAST-PY-EVAL_EXEC-01` | eval()/exec() on request-derived data | CWE-95 |
| `SAST-PY-PICKLE_LOAD-01` | pickle.load()/loads() on untrusted data | CWE-502 |
| `SAST-PY-YAML_UNSAFE_LOAD-01` | yaml.load() without a safe loader | CWE-502 |
| `SAST-PY-SUBPROCESS_SHELL-01` | subprocess call with shell=True | CWE-78 |
| `SAST-PY-OS_SYSTEM-01` | os.system() invocation | CWE-78 |
| `SAST-PY-FLASK_DEBUG-01` | Flask run/configured with debug enabled | CWE-489 |
| `SAST-PY-JINJA_AUTOESCAPE_FALSE-01` | Jinja2 environment with autoescape disabled | CWE-79 |
| `SAST-JS-EVAL-01` | eval() to execute dynamic code | CWE-95 |
| `SAST-JS-DANGEROUSLY_SET_INNER_HTML-01` | React dangerouslySetInnerHTML rendering markup | CWE-79 |
| `SAST-JS-DOCUMENT_WRITE-01` | document.write() injecting markup | CWE-79 |
| `SAST-JS-TEMPLATE_LITERAL_SQL-01` | SQL built from a JS template literal | CWE-89 |
| `SAST-JS-DYNAMIC_REQUIRE-01` | require() with a non-literal specifier | CWE-829 |
| `SAST-JS-PROTO_ASSIGN-01` | Direct assignment to __proto__ | CWE-1321 |
| `SAST-JS-UNSAFE_MERGE-01` | Recursive merge without a prototype guard | CWE-1321 |
| `SAST-GO-EXEC_CONCAT-01` | exec.Command from a concatenated string | CWE-78 |
| `SAST-GO-TEMPLATE_HTML-01` | text/template where html/template is required | CWE-79 |
| `SAST-GO-WEAK_RANDOM-01` | math/rand for a token/session id/secret | CWE-338 |
| `SAST-GO-SQL_CONCAT-01` | SQL built by concatenation or Sprintf | CWE-89 |
| `SAST-GO-TLS_SKIP_VERIFY-01` | TLS verification disabled via InsecureSkipVerify | CWE-295 |
| `SAST-JAVA-JDBC_SQL_CONCAT-01` | JDBC statement with a concatenated SQL string | CWE-89 |
| `SAST-JAVA-XXE_DISALLOW_DOCTYPE-01` | XML factory without DOCTYPE/entity hardening | CWE-611 |
| `SAST-JAVA-UNSAFE_DESERIALIZATION-01` | ObjectInputStream.readObject() on untrusted data | CWE-502 |
| `SAST-JAVA-TRUST_ALL_MANAGER-01` | X509TrustManager that accepts any certificate | CWE-295 |
| `SAST-JAVA-TRUST_ALL_HOSTNAME-01` | HostnameVerifier that always returns true | CWE-295 |
| `SAST-JAVA-SPEL_INJECTION-01` | SpEL expression from request-derived data | CWE-94 |
| `SAST-JAVA-OGNL_INJECTION-01` | OGNL expression from request-derived data | CWE-94 |

### NoSQL · LDAP — query injection

| Check | Catches | CWE |
|---|---|---|
| `SAST-NOSQL-WHERE_JS-01` | MongoDB $where from concatenated/interpolated input | CWE-95 |
| `SAST-NOSQL-SERVER_JS-01` | Server-side JavaScript evaluation in the database | CWE-94 |
| `SAST-NOSQL-OPERATOR_INJECTION-01` | Request value used directly in a NoSQL query document | CWE-943 |
| `SAST-NOSQL-QUERY_CONCAT-01` | NoSQL query document parsed from a concatenated string | CWE-943 |
| `SAST-LDAP-FILTER_CONCAT-01` | LDAP search filter from an unescaped value | CWE-90 |
| `SAST-LDAP-DN_CONCAT-01` | LDAP distinguished name from an unescaped value | CWE-90 |
| `SAST-LDAP-UNESCAPED_FILTER_INPUT-01` | LDAP filter taken directly from request-derived data | CWE-90 |

## IaC 🟢 no external data

Infrastructure-as-code misconfigurations. Runs on `./scan.sh iac --path DIR`. Covers Terraform,
CloudFormation, Kubernetes, Helm, Dockerfile, and docker-compose.

| Check | Catches |
|---|---|
| `IAC-TF-OPEN_CIDR-01` | Terraform security group open to 0.0.0.0/0 |
| `IAC-TF-PUBLIC_ACL-01` | S3 bucket ACL set public |
| `IAC-TF-UNENCRYPTED-01` | Resource without encryption at rest |
| `IAC-TF-KEY_ROTATION_DISABLED-01` | KMS key without automatic rotation |
| `IAC-TF-PUBLIC_IP-01` | Instance auto-assigns a public IP |
| `IAC-TF-HARDCODED_SECRET-01` | Hardcoded credential in Terraform |
| `IAC-TF-RDS_PUBLIC-01` | RDS instance publicly accessible |
| `IAC-CFN-*` (8 checks) | CloudFormation: open CIDR, public S3, unencrypted, no key rotation, public IP, hardcoded secret, public RDS, privileged ECS |
| `IAC-K8S-*` (8 checks) | Kubernetes: privileged, host namespace, no resource limits, runs-as-root, secret env, mutable :latest tag, RBAC wildcard, default SA token mount |
| `IAC-HELM-*` (3 checks) | Helm: hostPort, sensitive hostPath mount, hardcoded secret |
| `IAC-DOCKER-*` (6 checks) | Dockerfile: root user, :latest tag, secret in ENV/ARG, remote ADD, pipe-to-shell, unpinned digest |
| `IAC-COMPOSE-*` (4 checks) | docker-compose: exposed port, privileged mode, sensitive mount, plaintext secret |

## DAST — passive 🟢 no external data

Observations from responses to a running app (`./scan.sh dast --target NAME`) - no attacks, no
database. (One exception is marked 🔵 below.)

| Family | Catches |
|---|---|
| Headers (11) | Missing/unsafe CSP, HSTS missing/weak/malformed, clickjacking, nosniff missing, leaky referrer, recommended headers |
| Cookies (4) | Missing Secure, HttpOnly, SameSite absent/weak |
| CORS (5) | Null-origin trust, origin reflection, wildcard - each with/without credentials |
| Leakage (5) | Stack traces, internal-infra headers, email disclosure, secrets in served JS, third-party origins |
| Markup (7) | Missing SRI, tabnabbing, insecure/untrusted frames, absent anti-CSRF token |
| TLS (6) | Weak protocol/cipher, expired/expiring/self-signed/wildcard certificate |
| Transport (5) | Plaintext sensitive content, no HTTPS redirect, mixed active/passive/form content |
| Banner (2) | Server/framework disclosed, version disclosed |
| `DAST-BANNER-OUTDATED_COMPONENT-01` 🔵 advisory DB | Component version matched against the vendored known-vulnerable list (needs versions.db) |

## DAST — active 🟢 no external data

Sends real attack payloads to a running app. Needs a reachable target plus `--intensity active` and
`--i-own-target` (your authorization). No database.

| Check | Catches |
|---|---|
| `DAST-INJ-SQLI_ERROR/BOOLEAN/TIME-01` | SQL injection - error-based, boolean-based, time-based blind |
| `DAST-INJ-NOSQLI_ERROR/BOOLEAN-01` | NoSQL injection - error and operator/object injection |
| `DAST-INJ-LDAP_ERROR/BOOLEAN-01` | LDAP injection - error and boolean-based |
| `DAST-INJ-XSS_REFLECTED_HTML/ATTR/JS-01` | Reflected XSS in HTML text, attribute, and script contexts |
| `DAST-INJ-SSTI_BRACES/DOLLAR/ERB/SMARTY-01` | Server-side template injection (four engine dialects) |
| `DAST-INJ-CMDI_TIME-01` | OS command injection (time-based blind) |
| `DAST-INJ-PATH_TRAVERSAL-01` | Path traversal via a request parameter |
| `DAST-INJ-OPENREDIR_HEADER/META-01` | Open redirect via Location header or meta-refresh |
| `DAST-INJ-XXE_ENTITY / XXE_SSRF-01` | XXE entity processing and XXE-driven SSRF |
| `DAST-INJ-SSRF_PARAM-01` | Server-side request forgery via a parameter |
| `DAST-INJ-CRLF_HEADER_INJECTION / RESPONSE_SPLITTING-01` | CRLF header injection and full response splitting |
| `DAST-INJ-PROTOPOLLUTION_ERROR / MARKER_REFLECTED-01` | Prototype pollution (error-based and confirmed-reflected) |
| `DAST-HOSTHDR-REFLECTED_BODY / LOCATION-01` | Host-header reflection into body or redirect authority |
| `DAST-DISC-SENSITIVE / BACKUP / CONTENT / DIRLIST-01` | Exposed sensitive/backup files, content discovery, directory listing |
| `DAST-METHOD-TRACE / WRITE / CONNECT-01` | Dangerous HTTP methods advertised (TRACE, PUT/DELETE/PATCH, CONNECT) |

## DAST — authorization, tokens, rate limits & GraphQL 🟢 no external data

The tier-5 `modules/dast/checks.rules` registry: object-level authorization, JWT verification
weaknesses, missing rate limiting, and GraphQL introspection. Reachable only at `--intensity active`
(same target/authorization requirements as DAST active, above). The `DAST-AUTHZ-*` checks additionally
need two authenticated identities (`requires-identities: 2`, `config/auth.conf`); `DAST-RATE-*`
additionally needs the `--i-own-target` burst-probe affirmation (DAST-28).

### Authorization — object-level access control

| Check | Catches | CWE |
|---|---|---|
| `DAST-AUTHZ-IDOR-01` | Object reference is readable by an identity that does not own it | CWE-639 |
| `DAST-AUTHZ-CROSS_IDENTITY_READ-01` | Two separate identities receive the identical non-public object | CWE-639 |
| `DAST-AUTHZ-EXCESSIVE_DATA-01` | Authenticated response carries fields beyond what the view needs | CWE-213 |
| `DAST-AUTHZ-OTHER_IDENTITY_DATA-01` | Authenticated response contains another identity's identifier | CWE-200 |

### JWT — signature and algorithm verification

| Check | Catches | CWE |
|---|---|---|
| `DAST-JWT-SIG_NOT_VERIFIED-01` | JWT signature is not verified | CWE-347 |
| `DAST-JWT-ALG_NONE-01` | JWT accepted with alg:none (unsigned token) | CWE-347 |
| `DAST-JWT-EMPTY_HMAC-01` | JWT accepted when re-signed HS256 with an empty secret | CWE-1391 |
| `DAST-JWT-WEAK_HMAC-01` | JWT accepted when re-signed HS256 with a common weak secret | CWE-1391 |
| `DAST-JWT-ALG_CONFUSION-01` | JWT RS to HS algorithm confusion accepted | CWE-347 |

### Rate limiting

| Check | Catches | CWE |
|---|---|---|
| `DAST-RATE-NO_THROTTLE-01` | No request throttling on an idempotent endpoint | CWE-770 |
| `DAST-RATE-NO_RETRY_AFTER-01` | Rate limit signalled without a usable back-off (429 with no Retry-After) | CWE-770 |

### GraphQL

| Check | Catches | CWE |
|---|---|---|
| `DAST-GQL-INTROSPECTION-01` | GraphQL introspection is enabled and returns the full schema | CWE-200 |

## Network / host 🟢 no external data

Service-posture scanning over an operator-declared listener set. Runs on
`./scan.sh network --target NAME`, where `NAME` names a `config/scope.conf` target whose `base-url`
and `extra-host` entries declare the host:port tuples authorized for this scan. This is deliberately
**not** a port scanner or host-discovery tool: a port the operator did not declare is never probed,
gated by the identical `lib/http.sh` scope chokepoint and ceilings `dast` uses. OS patch-level
inference and UDP are stated v1 exclusions, not oversights - see `AGENTS.md`'s "Network module (NET)"
section for why.

| Check | Catches |
|---|---|
| `NET-PORT-DECLARED_NOT_ANSWERING-01` | A declared listener did not accept a TCP connection during this run |
| `NET-PORT-UNEXPECTED_LISTENER-01` | A declared listener answers on a port an operator-supplied `config/posture.conf` expectation names as should-be-closed |
| `NET-SVC-BANNER_DISCLOSURE-01` | Service greeting discloses a product name and/or version unprompted on connect (zero bytes sent) |
| `NET-SVC-OUTDATED_COMPONENT-01` 🔵 advisory DB | Banner-disclosed version matched exactly against the vendored known-vulnerable list |
| `NET-TLS-*` (6 checks) | TLS on a non-`base-url` listener: weak protocol/cipher, expired/expiring/self-signed certificate, unexpected wildcard cert |
| `NET-SVC-HTTP_SERVER_DISCLOSURE-01` / `HTTP_VERSION_DISCLOSURE-01` | Server/framework or component version disclosed by an HTTP response on a non-standard port |
| `NET-SVC-HTTP_OUTDATED_COMPONENT-01` 🔵 advisory DB | HTTP-disclosed component version on a non-standard port matched exactly against the vendored known-vulnerable list |
| `NET-TRANSPORT-PLAINTEXT_SERVICE-01` | Service answers in the clear on a port whose protocol has a standard encrypted variant |
| `NET-TRANSPORT-STARTTLS_NOT_REQUIRED-01` | Listener advertises STARTTLS but does not appear to require it |

Both `*OUTDATED_COMPONENT*` checks are `confidence: medium`, never `high`: the version came from what
the service volunteered on connect, and a distribution that backports a security fix keeps the
upstream version string unchanged, so an exact-match lookup can name an already-patched host as
vulnerable. This is a table lookup against `data/versions.db`'s `banner` namespace, never range
arithmetic - the identical `DAST-BANNER-OUTDATED_COMPONENT-01` convention above, one port over.

## SCA — dependency CVEs 🔵 advisory DB

Known-vulnerable dependencies from your lockfiles. This is the one surface that needs the vendored
`data/advisories.db` (built with `tools/vendor-engines.sh advisories bulk --all`); without it, SCA
reports that no advisory data was available rather than a false all-clear.

| Check | Ecosystem |
|---|---|
| `SCA-NPM-VULNERABLE_DEP-01` | npm (semver-range matching) |
| `SCA-PY-VULNERABLE_DEP-01` | PyPI |
| `SCA-JAVA-VULNERABLE_DEP-01` | Maven |
| `SCA-RUBY-VULNERABLE_DEP-01` | RubyGems |
| `SCA-PHP-VULNERABLE_DEP-01` | Composer |
| `SCA-GO-VULNERABLE_DEP-01` | Go modules |
| `SCA-COV-NO_ADVISORY_DB-01` / `UNKNOWN_VERSION-01` | Honest coverage notes when data is missing |

## Container image 🔵 advisory DB

Offline installed-package enumeration and CVE matching against a **built** container image - never a
registry pull. Runs on `./scan.sh image --image ID` (optionally `--source PATH` to override the path
`config/images.conf` records for that id), where `ID` names an `id` record in `config/images.conf`
pointing at a `docker save` tarball (`source: docker-archive`) or an OCI image-layout directory
(`source: oci-layout`) the operator has already exported. `tar` is the only new binary this needs;
rpm additionally needs `sqlite3` on `PATH` (its package database is a binary format text tools can't
read - `requires-cmd: sqlite3`, a declared coverage reduction rather than a silent skip when absent).
This is the **built-artifact** counterpart to `modules/iac/dockerfile.rules`: the Dockerfile check
reads what was *written*, this reads what actually *shipped* - the base image's own packages, drift
between a digest-pinned Dockerfile and a months-old build, and the effective runtime user across every
merged layer, none of which source linting can see. See `docs/DESIGN.md` §15 for the boundary between
the two and this module's own stated gaps.

| Check | Catches |
|---|---|
| `IMAGE-PKG-VULNERABLE_OS_PACKAGE-01` | Installed apk package matches a known advisory for the image's Alpine release |
| `IMAGE-PKG-VULNERABLE_OS_PACKAGE-02` | Installed dpkg package matches a known advisory for the image's Debian/Ubuntu release (resolved against the `Source:` package where one is declared) |
| `IMAGE-PKG-VULNERABLE_OS_PACKAGE-03` (needs `sqlite3` on `PATH`) | Installed rpm package matches a known advisory for the image's RHEL/Fedora release |
| `IMAGE-LANGDEP-VULNERABLE_DEP-01` | A language dependency (npm/RubyGems/Composer/PyPI/Maven/Go) found at a bounded set of conventional manifest locations inside the image's own rootfs matches a known advisory - reuses `sca`'s own tree-walkers, re-emitted under this id and the image's own `image-id` cell rather than `module=sca` |
| `IMAGE-CFG-RUNS_AS_ROOT-01` | Image config declares no non-root `User` - the *effective* runtime user across every merged base layer, not one Dockerfile's own `USER` line |
| `IMAGE-CFG-EXPOSED_PORTS-01` | Image config declares one or more exposed ports (informational) |
| `IMAGE-CFG-MUTABLE_BASE_REF-01` | Image's own recorded base-image reference is a mutable tag rather than a content digest |
| `IMAGE-COV-NO_ADVISORY_DB-01` | No advisory rows for this image's distro release - nothing was matched (exit 4 when `image` is the selected command) |
| `IMAGE-COV-UNKNOWN_DISTRO-01` | No recognised package database (apk/dpkg/rpm) found in any layer - e.g. a distroless/scratch image |
| `IMAGE-COV-LAYER_UNREADABLE-01` | One or more layers or archive members could not be read |
| `IMAGE-COV-LANGDEPS_NOT_SCANNED-01` | Language-dependency scanning found no manifest at any declared candidate location, or no advisory data |

Every `VULNERABLE_OS_PACKAGE`/`VULNERABLE_DEP` finding needs a real, differential-tested version
comparator per package manager (`modules/sca/semver.sh` is npm-only by measured decision - it mismatches
7 of 12 real OS version pairs, including a false negative - so apk/dpkg/rpm each ship their own).
`distro_release_unknown` (no `/etc/os-release`)
is its own declared reduction, never a silent guess at "latest": Alpine advisories are keyed per
release, and guessing produces false negatives on older images.

Also seeded: `COMPOSITE-IMAGE-EFFECTIVE_ROOT` and three `COMPOSITE-IMAGE-STALE_BASE_*` ids
(`rules/derived.rules`), correlating an `IMAGE-*` built-artifact finding with the `IAC-DOCKER-*`
Dockerfile-source finding for the same image when `config/images.conf`'s optional `dockerfile` key
names the Dockerfile that built it - never guessed, and never minted by a scanner script (composites
live in the derived layer per `rules/RULE-FORMAT.md` §9.2).

## Cloud / AWS (CSPM) 🟠 needs AWS credentials

Live AWS configuration, read-only. Runs on `./scan.sh cloud --live` against 30 services across your
enabled regions (`--assume-role` for a second account); every call goes through `lib/awscli.sh`'s
`aws_ro` chokepoint, which refuses anything that is not a read-only API call. Findings carry both a
CIS AWS Foundations Benchmark v3.0.0 control and an OWASP Top 10 category, feeding the compliance
report (`report.md`/`report.html`). An access-denied, opted-out, or throttled service is recorded as
a coverage reduction, never folded into a clean pass. The `posture/` phase (SSO/edge/session drift
against an operator-declared baseline) has a config schema (`config/posture.conf.example`) but no
checks yet.

| Check | Catches |
|---|---|
| `CLOUD-IAM-*` (12 checks) | Root user MFA/access-key hygiene, missing/weak account password policy, no IAM Access Analyzer, full-admin policy, wildcard role trust, cross-account trust with no ExternalId, stale credentials/keys/roles, full-admin identity with no permission boundary, mixed inline+managed policies |
| `CLOUD-COGNITO-*` (24 checks) | User pool: weak password policy, long-lived temp passwords, MFA off/optional, advanced security off, open self-registration, SMS-only recovery, deletion protection off; app client: non-SRP auth, implicit OAuth grant, plaintext/wildcard callback URL, excessive token lifetime, token revocation off, writable sensitive attribute, username enumeration; identity pool: unauthenticated identities/credentials, over-permissioned unauth role, classic auth flow, permissive role mapping |
| `CLOUD-S3-*` (7 checks) | Public ACL (read/write), public bucket policy, Block Public Access off, no default encryption, versioning off, access logging off |
| `CLOUD-RDS-*` (4 checks) | Publicly accessible instance, unencrypted storage, backups/point-in-time recovery off, snapshot shared publicly |
| `CLOUD-DYNAMODB-*` (3 checks) | VPC endpoint left at the default full-access policy, no encryption at rest, point-in-time recovery off |
| `CLOUD-EFS-*` (3 checks) | Wildcard file-system policy, no encryption at rest, transit encryption not enforced |
| `CLOUD-BACKUP-*` (1 check) | EBS volume with no AWS Backup recovery point |
| `CLOUD-EC2-*` (8 checks) | Security group open to 0.0.0.0/0 on an admin or database port, default security group attached to a resource, public AMI/snapshot, unencrypted EBS volume, IMDSv2 not enforced, VPC with no flow log |
| `CLOUD-LAMBDA-*` (6 checks) | Execution role with unrestricted or wildcard-sensitive actions, function URL open to unauthenticated invocation, wildcard resource policy, plaintext-looking env var, env vars not encrypted with a customer-managed key |
| `CLOUD-ECR-*` (3 checks) | Wildcard repository policy, scan-on-push off, mutable image tags |
| `CLOUD-ECS-*` (2 checks) | Task assigns a public IP, task role over-permissioned |
| `CLOUD-EKS-*` (2 checks) | API endpoint reachable from outside the VPC, node-group role over-permissioned |
| `CLOUD-CLOUDFRONT-*` (5 checks) | Plain-HTTP viewer protocol, weak minimum TLS version, no WAF web ACL, S3 origin with no Origin Access Control/Identity, logging off |
| `CLOUD-ELB-*` (3 checks) | Plain-HTTP listener with no HTTPS redirect, TLS policy below a TLS 1.2 floor, access logging off |
| `CLOUD-APIGW-*` (2 checks) | Method with no authorizer and no API key, method relying on an API key alone |
| `CLOUD-APPSYNC-*` (2 checks) | GraphQL API defaults to a plain API key, API key with a far-future expiration |
| `CLOUD-ROUTE53-*` (1 check) | DNS record pointing at a nonexistent S3 static-website bucket (subdomain takeover) |
| `CLOUD-KMS-*` (2 checks) | Automatic key rotation off, key policy grants an unqualified wildcard principal |
| `CLOUD-SECRETSMANAGER-*` (2 checks) | Automatic rotation off, resource policy grants an unqualified wildcard principal |
| `CLOUD-SSM-*` (2 checks) | Sensitive-looking parameter not stored as SecureString, resource policy grants an unqualified wildcard principal |
| `CLOUD-ACM-*` (1 check) | Certificate nearing or past expiry |
| `CLOUD-SNS-*` (2 checks) | Wildcard topic policy, no server-side encryption |
| `CLOUD-SQS-*` (2 checks) | Wildcard queue policy, no server-side encryption |
| `CLOUD-CLOUDTRAIL-*` (3 checks) | Not logging in this account/region, not multi-region, log-file validation off |
| `CLOUD-CONFIG-*` (1 check) | Configuration recorder absent or not recording |
| `CLOUD-GUARDDUTY-*` (1 check) | Not enabled in this region |
| `CLOUD-INSPECTOR-*` (1 check) | Automated vulnerability scanning not fully enabled |
| `CLOUD-MACIE-*` (1 check) | Sensitive-data discovery not enabled in this region |
| `CLOUD-OPENSEARCH-*` (3 checks) | Public endpoint with a wide-open access policy, no encryption at rest, node-to-node transport encryption off |
| `CLOUD-REDSHIFT-*` (3 checks) | Publicly accessible cluster, no encryption at rest, parameter group does not require SSL |

Also seeded: `COMPOSITE-TOKEN-HIJACK` (`rules/derived.rules`), a cross-module derived finding that
correlates a DAST contributor with a cloud contributor rather than firing off either surface alone.

## Optional engine depth 🟣 --use-engines

Vendor a specialist engine (you pin its version + checksum) and `--use-engines` runs it as an adapter
for extra depth, keeping scoursh's honest coverage accounting. These add depth to existing surfaces,
not new categories.

| Engine | Boosts |
|---|---|
| Semgrep | SAST rule breadth |
| Trivy | IaC coverage |
| Gitleaks | Secret detection |

---

Generated from scoursh's shipped check registry on `dev`. Counts are approximate family totals; the
audit report (`--format audit`) renders the exact per-run coverage. Every "no external data" check
needs only the target you give it - code path or a running app.
