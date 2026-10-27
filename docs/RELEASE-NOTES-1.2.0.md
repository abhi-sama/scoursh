# scoursh 1.2.0

1.2.0 is a precision release. It cuts false positives across the SAST, SCA, IaC, DAST and AWS
checks, adds two secrets check ids, and adds one optional rule key. It also automates the
Homebrew formula bump at release time. Nothing that 1.1.2 did is removed.

321 checks ship in this release (55 SAST + 36 IaC + 92 DAST + 15 network + 11 container-image +
112 Cloud/AWS). 1.1.2 shipped 319; the two new ids are both SAST secrets checks.

## Why this is a minor release

Under semantic versioning a minor version adds functionality without breaking compatibility. This
release adds two check ids and an additive, optional rule key (`match-deny`). It needs no
`format_version` bump and no `state/` migration (`rules/RULE-FORMAT.md` §14, item 2 only). That is
new functionality, so the version is 1.2.0 rather than 1.1.3.

## New checks

| Check | Catches | Severity | CWE |
|---|---|---|---|
| `SAST-SEC-DEFAULT_PASSWORD-01` | A well-known default password literal (`postgres`, `changeit`, ...) | medium | CWE-1392 |
| `SAST-SEC-NONPROD_CREDENTIAL-01` | A credential-shaped literal in a test, documentation, example or CI file | low | CWE-798 |

## Secrets: fewer false positives

- **Test, docs, example and CI paths** (`tests/**`, `*.test.*`, `docs/**`, `*.md`, `examples/**`,
  `*.example`, `.github/workflows/**`, ...) and localisation catalogues no longer raise the keyword
  secrets checks. The same shapes on those paths report under `SAST-SEC-NONPROD_CREDENTIAL-01` at
  low, so a fixture password stays visible without being reported as critical.
- **Value guards now look at the matched value**, through the new optional `match-deny` rule key
  (`rules/RULE-FORMAT.md` §10.1a). Before, an unrelated URL, arrow function or boolean elsewhere on
  the line could drop a real credential, and nothing checked that a quoted "secret" was an issued
  value rather than a name. Semver ranges, `env()`/`{name}`/`%VAR%` references, module paths,
  `mock-`/`fake-` prefixes, validator tags, rate specs and Helm Secret key names are now denied.
- **Severity:** keyword matches and JWTs are capped at high. Well-known default passwords move to
  `SAST-SEC-DEFAULT_PASSWORD-01` at medium.
- **`SAST-SEC-ENV_ASSIGNMENT-01`** no longer fires on JavaScript/TypeScript source (including TSX),
  and its unquoted value must end at whitespace or end of line.
- **`SAST-SEC-PRIVATE_KEY-01`** needs key material within 4 lines. **`SAST-SEC-JWT-01`** needs a
  real-length signature and skips the jwt.io sample and Supabase anon/demo keys.
  **`SAST-SEC-AWS_AKID-01`** matches credential prefixes, not IAM unique-id prefixes.
- **IaC secrets:** Dockerfile `ENV X=$X`, empty defaults, paths and URLs without userinfo are no
  longer flagged; compose `*_FILE` names, Kubernetes `valueFrom`, and Helm template variables and
  comment prose are no longer read as plaintext secrets. Under `scan.sh all`, an IaC secret on a
  line a `SAST-SEC-*` check already reports is dropped and counted in `run.json`.
- **DAST and AWS:** `DAST-LEAK-JS_CONFIG-01` skips UI labels and prose, and
  `CLOUD-LAMBDA-ENV_SECRET-01` skips metadata names (ARNs, SSM paths, TTLs) and references.
- Build output directories (`.next`, `.nuxt`, `.svelte-kit`, `.output`, `.vercel`, `.turbo`,
  `.angular`, `storybook-static`) are skipped like `dist/` and `build/`.

## SAST, SCA and IaC: fewer false positives

- Native SAST and IaC candidates now pass through an offline local-syntax reader before they are
  reported (`modules/sast/precision.awk`, `modules/iac/precision.awk`). The reader tells comments
  from code and constant arguments from dynamic ones. For IaC it checks which YAML/JSON map, HCL
  block or Docker stage owns a field. [`docs/NATIVE-PRECISION.md`](NATIVE-PRECISION.md) has the
  details and the limits.
- A candidate the reader cannot settle is reported as an informational `Review required:` entry
  with no asserted impact, plus a coverage reduction. It is not reported as a vulnerability.
- SCA resolves dependency identity (for example npm aliases) and applicability before the advisory
  lookup.

## Other fixes

- A scanning command now clears an earlier run left in `--out`, so old shards are no longer merged
  into the new report.
- `die()` keeps its exit code when the abort-path report-registry dump does not parse.

## Release and packaging

- `release.yml` now renders `packaging/homebrew/scoursh.rb` at the tagged commit and opens the
  formula-bump PR on `abhi-sama/homebrew-scoursh`.

## Upgrading

Your configuration, state and reports carry over. Two things change between a 1.1.2 run and a
1.2.0 run, and neither means your code changed:

- Findings that are no longer reported, or that moved to a new check id or severity, read as
  `fixed` or `new` in the first 1.2.0 diff.
- When an earlier false candidate is dropped, a later identical token's `occurrence` ordinal can
  change, which changes its fingerprint. Review baseline and `--fail-on-new` results after the
  upgrade.
