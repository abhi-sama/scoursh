# scoursh 1.0.0

scoursh is a security scanner written in bash. One command line and one report cover seven
surfaces: source code, dependencies, infrastructure-as-code, a running web application, a declared
set of network listeners, a container image, and a live AWS account.

Two rules shape everything it does:

- **It only talks to hosts you have authorised.** A web or network scan only reaches hosts listed
  in `config/scope.conf`. An AWS scan only makes read-only API calls to your own account. Anything
  else is refused when the scan runs, not just by a lint. The source-code, dependency and IaC
  scanners make no network calls at all, so they run unchanged on an air-gapped host.
- **It says what it did not check.** When a check cannot run (a missing database, a denied AWS
  permission, a file type that is not in the tree), the report records that as a declared coverage
  reduction with its reason. A skipped check never shows up as a clean result.

## What it scans

319 checks ship in this release. The counts come from the `id:` records under `modules/`:

| Surface | Command | Checks | Notes |
|---|---|---|---|
| Source code (SAST) | `scoursh sast --path DIR` | 53 | Injection, crypto misuse, secrets, Go/Java/JavaScript/Python rules, and a replay of the secrets rules over git history (`--history`) |
| Infrastructure-as-code | `scoursh iac --path DIR` | 36 | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, docker-compose |
| Running application (DAST) | `scoursh dast --target NAME` | 92 | 46 passive, 34 active (injection family), 12 authorization/JWT/rate-limit/GraphQL |
| Network listeners | `scoursh network --target NAME` | 15 | Reachability, banner/version disclosure, TLS and plaintext/STARTTLS posture on ports you declared |
| Container image | `scoursh image --image ID` | 11 | Offline OS-package matching for apk and dpkg images, language dependencies inside the image, runtime-user/port/base-tag config checks |
| AWS (Cloud/CSPM) | `scoursh cloud --live` | 112 | 30 AWS services, read-only, mapped to CIS AWS Foundations Benchmark v3.0.0 and OWASP |
| Dependencies (SCA) | `scoursh sca --path DIR` | - | Lockfile lookups for npm, PyPI, Maven, Go, RubyGems and Composer. SCA is a table lookup, so it is not counted as checks |

`rules/derived.rules` adds 5 composite findings that fire only when findings from different
surfaces line up. For example: a long-lived AppSync API key (from the AWS scan) that is also served
in the app's JavaScript and whose GraphQL schema is open to introspection (both from the DAST scan).

The full catalogue, with every check id and what it needs to run, is in
[`docs/CHECKS.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/CHECKS.md).

Every run writes `findings.jsonl` and `run.json`. You choose the other formats with `--format`:
`json`, `sarif` (SARIF 2.1.0), `html`, `md`, `agent` (a compact file meant for an automated fixer),
and `audit`. `audit` is off by default. It writes `report-audit.html`, a coverage matrix that puts
every registered check in one of four groups: found, clean, not run (with its reason), or
unaccounted.

Exit codes are fixed, so CI can act on them: `0` ok, `1` the `--fail-on` gate tripped, `2` usage
error, `3` a scope refusal, `4` a required input is missing, `5` the run was incomplete.

## Install and verify

Every release is one architecture-independent tarball, `scoursh-1.0.0.tar.gz`, plus a `SHA256SUMS`
file. It is built by `.github/workflows/release.yml`, attested, and published as an immutable GitHub
Release.

**Verify the download before you run it:**

```sh
V=1.0.0
gh release download "v$V" --repo abhi-sama/scoursh --pattern "scoursh-$V.tar.gz" --pattern SHA256SUMS
sha256sum -c SHA256SUMS                  # macOS: shasum -a 256 -c SHA256SUMS
gh attestation verify "scoursh-$V.tar.gz" --repo abhi-sama/scoursh \
  --signer-workflow abhi-sama/scoursh/.github/workflows/release.yml
gh release verify "v$V" --repo abhi-sama/scoursh
```

- `sha256sum -c` checks integrity only. Anyone who could swap the tarball could also swap the
  checksum file next to it.
- `gh attestation verify` checks where the file came from: a Sigstore-signed build-provenance
  attestation says this exact file was built by this repository's release workflow from the tagged
  commit.
- `gh release verify` checks that the release is immutable, so its tag and assets cannot have been
  replaced after publishing.

For an air-gapped host, or to rebuild the tarball yourself and compare it byte for byte (the build
is reproducible), see ["Installing from a release" in `docs/USAGE.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/USAGE.md#installing-from-a-release).

**Install the tarball:**

```sh
mkdir -p ~/.local/share/scoursh ~/.local/bin
tar -xzf "scoursh-$V.tar.gz" -C ~/.local/share/scoursh
ln -sfn ~/.local/share/scoursh/scoursh-$V/bin/scoursh        ~/.local/bin/scoursh
ln -sfn ~/.local/share/scoursh/scoursh-$V/bin/scoursh-vendor ~/.local/bin/scoursh-vendor
scoursh --version
scoursh paths
```

**Homebrew.** The Homebrew formula lands with this release, in the `abhi-sama/homebrew-scoursh`
tap:

```sh
brew install abhi-sama/scoursh/scoursh
```

If the tap is not visible yet when you read this, use the tarball above. Both give the same
installed layout.

**Requirements:** bash 4.2 or newer (macOS ships 3.2, so run `brew install bash`), plus `grep` or
`rg`, `awk`, and coreutils. Some surfaces need more:

- `dast` and the network HTTP phase need `curl`.
- TLS and JWT checks need `openssl`. Without it they record a declared skip.
- `image` needs `tar`.
- `cloud --live` needs the `aws` CLI and credentials.
- `sast --history` needs `git`.

On Windows, use WSL. Git Bash is not supported.

## Where an installed copy keeps your files

The extracted install directory is never written to. Your files live outside it, so an upgrade
(extract the new version, re-point the two links) keeps your configuration, state and reports.

| What | Default location | Override |
|---|---|---|
| Configuration (`scope.conf`, `scanner.conf`, ...) | `~/.config/scoursh` | `XDG_CONFIG_HOME` |
| Generated advisory data (`advisories.db`, ...) | `~/.local/share/scoursh` | `XDG_DATA_HOME` |
| Diff state between runs | `~/.local/state/scoursh/state` | `XDG_STATE_HOME` |
| Reports | `~/.local/state/scoursh/reports` | `XDG_STATE_HOME` |

Set `SCOURSH_HOME=/some/dir` to put all four under one root as `{config,data,state,reports}`. That
is useful in a container. `scoursh paths` prints the exact locations this copy uses.

## What it deliberately does not do

- **No port discovery or host discovery.** `network` checks only the listeners you declared in
  `config/scope.conf` (`base-url` and `extra-host`). A port you did not name is never probed. It is
  not a port scanner.
- **No scanning of a host that is not in `config/scope.conf`.** Every outbound request goes through
  one gate (`lib/http.sh`). A `--target` with no record in `config/scope.conf` is refused with exit
  `3` (exit `4` if there is no `scope.conf` at all). If the scanned site redirects to a host
  outside the scope, the redirect is not followed and the refusal is recorded. At an interactive
  terminal scoursh offers to write the scope record for you. There is no flag that skips the gate.
- **No mutating AWS calls.** Every AWS call goes through `lib/awscli.sh`, which refuses anything that
  is not read-only (also exit `3`).
- **No fetching at scan time.** Rules, payloads and advisory data are read from disk. There is no
  telemetry and no SaaS backend. `scoursh-vendor` (`tools/vendor-engines.sh`) is the only command
  that reaches the internet, and a scan never calls it.
- **No silent clean scans.** A check that could not run is recorded in `run.json` as a
  `coverage_reduction` with its reason, and shown in the report. An AWS `AccessDenied` is recorded as
  "could not look", not as "nothing found". `sca` with no advisory database exits `4` and names every
  ecosystem it did not check.

## Known gaps

These are real limits of 1.0.0, not fine print:

- **No OCI container image of scoursh yet.** Install from the tarball (or Homebrew).
- **No one-line installer yet.** There is no `install.sh`. Use the verify-then-extract steps above.
- **rpm-based container images report a coverage gap, not package findings.** Real rpm databases
  store binary RPM headers, and scoursh cannot decode them yet. A RHEL, CentOS, Rocky, AlmaLinux or
  Fedora image reports `IMAGE-COV-UNKNOWN_DISTRO-01` (`rpm_db_binary_format`) instead of vulnerable
  packages. The image's config checks and its language-dependency checks still run. Alpine (apk) and
  Debian/Ubuntu (dpkg) images get full package matching.
- **The AWS posture phase is not built.** The SSO/edge/session drift checks (POSTURE-02 to
  POSTURE-04) are not written yet. Only their config schema, `config/posture.conf.example`, ships,
  so a posture run is a declared skip. The 112 live service checks are not affected.
- **You build the advisory database yourself.** It is not in the tarball, and a scan never
  downloads it. Build it once on a networked machine, then refresh it weekly:

  ```sh
  scoursh-vendor advisories bulk --all --accept-unverified
  ```

  On a clean checkout this took about 2 minutes and downloaded about 290 MB (OSV.dev's
  per-ecosystem exports). Until it exists, `sca` exits `4` and image package matching is a declared
  gap. When the database's `# generated:` stamp is older than `advisory-max-age-days` (default
  **30**), SCA, image and banner-version checks record
  `coverage_reduction reason=advisory_data_stale` in the report. The findings and exit code do not
  change. Set the limit in `scanner.conf` or with `SCOURSH_CONFIG_ADVISORY_MAX_AGE_DAYS`.

Also not included: optional engines (Semgrep, Gitleaks, Trivy) are vendored by hand with
`scoursh-vendor`. There is no setup-time installer and no committed version lock for them yet. The
full list of open work is in [`ROADMAP.md`](https://github.com/abhi-sama/scoursh/blob/main/ROADMAP.md).

## How it compares

scoursh is not a deeper Semgrep, ZAP or Trivy, and a specialist wins inside its own category. The
measured, reproducible comparison is in [`docs/COMPARISON.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/COMPARISON.md). It shows where
specialists win and by how much, where scoursh wins, and what was not measured. Every number there
traces to raw tool output committed under `bench/results/`.

## Help close the gaps

If you want to work on any of the gaps above, start with
[`docs/CONTRIBUTING-ROADMAP.md`](https://github.com/abhi-sama/scoursh/blob/main/docs/CONTRIBUTING-ROADMAP.md). For each gap it gives where the code would
go, how the tool reports the gap today, and how to check a fix.
