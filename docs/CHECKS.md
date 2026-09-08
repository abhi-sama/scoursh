# What scoursh detects

*Also available as a standalone page: [`checks.html`](checks.html).*

The full built-in check catalogue on the `dev` branch, grouped by scan surface and by what each check
needs to run. Roughly 180 checks ship in the box.

> **Almost everything runs with no external data.** Point scoursh at source code (`--path`) or a live
> app (`--target`) and every SAST, IaC, and DAST check below works immediately - no database, no
> downloads, no network. Only **dependency-CVE scanning (SCA)** and one banner check need the
> vendored advisory database.

| | |
|---|---|
| **53** | SAST checks |
| **36** | IaC checks |
| **46** | DAST passive |
| **34** | DAST active |
| **6** | SCA ecosystems |

## Legend

- 🟢 **No external data** - works on just `--path` (code) or `--target` (a running app). Active DAST
  needs a reachable target + `--i-own-target`.
- 🔵 **Needs the advisory DB** - requires `data/advisories.db` (built with `tools/vendor-engines.sh
  advisories`).
- 🟣 **Optional engine depth** - `--use-engines` adds vendored Semgrep/Trivy/Gitleaks. Boosts depth,
  not new categories.
- ⚪ **Planned, not built** - designed but no code ships yet.

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
| `SCA-GO` | Go modules |
| `SCA-COV-NO_ADVISORY_DB-01` / `UNKNOWN_VERSION-01` | Honest coverage notes when data is missing |

## Optional engine depth 🟣 --use-engines

Vendor a specialist engine (you pin its version + checksum) and `--use-engines` runs it as an adapter
for extra depth, keeping scoursh's honest coverage accounting. These add depth to existing surfaces,
not new categories.

| Engine | Boosts |
|---|---|
| Semgrep | SAST rule breadth |
| Trivy | IaC coverage |
| Gitleaks | Secret detection |

## Planned — not built ⚪ no code yet

Designed in the roadmap but not shipping detections yet.

| Surface | Status |
|---|---|
| Cloud / AWS (CSPM) | Fully designed (CIS Benchmark checks per service); the read-only harness ships, the live checks do not. `scan.sh cloud` is an accepted, logged no-op today. |
| SARIF compliance report | SARIF output ships; the OWASP/CIS-grouped compliance view is planned. |

---

Generated from scoursh's shipped check registry on `dev`. Counts are approximate family totals; the
audit report (`--format audit`) renders the exact per-run coverage. Every "no external data" check
needs only the target you give it - code path or a running app.
