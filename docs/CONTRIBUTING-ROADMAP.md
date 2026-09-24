# What to build next: a contributor's guide to scoursh's open work

This file lists the work that is still open in scoursh, written so that someone outside the project can
pick one up without asking anyone first.
Each entry says what is missing, why it matters, where the code would go, how scoursh reports the gap
to users today, roughly how big the job is, how to check a fix, and which decisions are already made.

How it relates to the other contributor documents:

- [`ROADMAP.md`](../ROADMAP.md) is the project's status record: what has landed and what has not.
  This file is where a contributor starts. It does not repeat the status history.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) covers process: branch model, running tests, code style.
  Read it before you open a PR.
- [`AGENTS.md`](../AGENTS.md) is the full working guide and the register of sharp edges.
  Search it for the file you are about to touch before you change it.

All file paths, function names, and reason strings below were checked against the `dev` branch on
2026-09-24. Size estimates are rough guesses, not measurements.
If an entry here disagrees with the code, trust the code and fix this file in the same PR.

## Contents

- [Non-negotiables](#non-negotiables)
- [Good first issues](#good-first-issues)
- [1. Decode real rpm package databases](#1-decode-real-rpm-package-databases)
- [2. A published OCI/Docker image of scoursh](#2-a-published-ocidocker-image-of-scoursh)
- [3. `install.sh`, a one-line installer for Linux and WSL](#3-installsh-a-one-line-installer-for-linux-and-wsl)
- [4. Setup-time engine install and `engines.lock`](#4-setup-time-engine-install-and-engineslock)
- [5. The AWS posture phase (POSTURE-02 to POSTURE-04)](#5-the-aws-posture-phase-posture-02-to-posture-04)
- [6. Smaller open items](#6-smaller-open-items)

## Non-negotiables

A PR that breaks one of these will not be merged, however useful it is otherwise.

1. **The egress model.** scoursh limits network traffic by destination. It is not air-gapped (see
   [`docs/adr/0001-egress-model-correction.md`](adr/0001-egress-model-correction.md)).
   A scan may reach only two kinds of destination:
   - a target the operator authorised in `config/scope.conf`, through `lib/http.sh`;
   - read-only AWS calls to the operator's own account, through `lib/awscli.sh`'s `aws_ro`.

   Never add a raw-URL bypass, a new `curl`/`wget`/`/dev/tcp` call site, or a flag that skips the
   scope gate. `tests/lint-shell.sh` enforces this by exact file path.
   Setup-time downloads (`tools/vendor-engines.sh`) are allowed only because nothing on the scan path
   can reach them, and the same lint enforces that too.
2. **Declared coverage gaps, never a silent clean scan.** If your code cannot check something, it must
   say so with `run_record coverage_reduction` or `coverage_gap`, or with a declared `*-COV-*`
   finding, and name the reason. A scan that looked at nothing must never read the same as a scan that
   found nothing. This is `docs/DESIGN.md` §15. Every entry below follows it.
3. **The frozen rule format.** [`rules/RULE-FORMAT.md`](../rules/RULE-FORMAT.md) is frozen.
   Adding a new rule pack, a new `checks-<name>.rules` file, or a new optional key is fine; §14 lists
   what counts as additive. Renaming a shipped check id, or changing what goes into a fingerprint,
   needs a `format_version` bump and a `state/` migration, and will be refused without a strong case.
4. **No AI-agent attribution in commits or PRs.** Do not add `Co-Authored-By:` lines, "Generated with"
   footers, or any other AI-tool credit. Authorship belongs to the human who submits the change.
5. **Target-agnostic.** Never put an application, company, product, environment, or endpoint name in
   a script, rule, config example, or fixture (`docs/DESIGN.md` §1).
6. **It must work from an installed copy.** A release tarball is read-only and contains only the paths
   in `tools/build-release.sh`'s `BR_RELEASE_PATHS`. Read and write operator data through
   `SCOURSH_CONF_DIR`, `SCOURSH_DATA_DIR`, `SCOURSH_STATE_DIR` and `SCOURSH_REPORTS_DIR`
   (`lib/layout.sh`), never through a path under the install root.

## Good first issues

Ranked from most to least approachable. None of these needs design approval first.

1. **Stop the timing-sensitive test assertions from flaking.** One test file per assertion, with a
   known pattern for the fix. See [6.1](#61-two-timing-sensitive-test-assertions-flake-on-ci).
2. **Make `tests/suites/build-release.sh` section E check the right file.** A one-line change plus a
   test showing it now fails when it should. See [6.2](#62-build-release-suite-checks-the-wrong-file).
3. **Silence the stderr noise in image OS-package matching.** Three one-line changes with an existing
   fix to copy (`modules/sca/engine.sh`). See [6.3](#63-image-os-package-matching-prints-false-errors).
4. **Let the AppSync finding correlate with DAST (finding F21).** One cloud service script. See
   [6.4](#64-appsync-findings-cannot-correlate-with-dast-f21).
5. **`install.sh`.** The biggest of the five, but self-contained, with a tested install layout to
   build on. See [section 3](#3-installsh-a-one-line-installer-for-linux-and-wsl).

## 1. Decode real rpm package databases

**This is the biggest capability gap today: RHEL, CentOS, Rocky, AlmaLinux and Fedora images produce
no package findings.**

**What is missing.** `modules/image/distro/rpm.sh` can already:

- find the rpm database in an image;
- compare rpm versions correctly (`modules/image/distro/rpm_version.sh`);
- match packages against the Red Hat advisories in `data/advisories.db`;
- emit `IMAGE-PKG-VULNERABLE_OS_PACKAGE-03` findings.

The missing piece is reading the list of installed packages out of a real rpm database.
Real rpm databases come in three formats:

- `var/lib/rpm/rpmdb.sqlite`: sqlite, used by Fedora 33 and later;
- `var/lib/rpm/Packages`: Berkeley DB;
- `var/lib/rpm/Packages.db`: ndb.

All three store each package as a binary RPM header blob.
Even the sqlite format's `Packages` table has only two columns, `(hnum, blob)`.
The name, epoch, version, release and architecture are inside the blob.
`_rpm_sqlite_enumerate` runs `SELECT name, epoch, version, release, arch FROM Packages`, which
works only against a database that already has those columns. On a real image it fails, and the code
treats that the same as the two binary formats.

**Why it matters.** Container scanning covers apk (Alpine) and dpkg (Debian, Ubuntu) end to end.
rpm-based images are the third large family, and today scoursh cannot report a single vulnerable OS
package in them.

**How the gap is reported today.** Honestly: `rpm_installed_enumerate` sets
`_RPM_INSTALLED_REASON=rpm_db_binary_format`. `modules/image/run.sh` then emits
`IMAGE-COV-UNKNOWN_DISTRO-01` (registered in `modules/image/checks-coverage.rules`) with detail
`rpm_db_binary_format`, and `image_report_unknown_distro` (`modules/image/engine.sh`) gives that detail
its own wording. Nothing is reported as clean.

**Where it would live.**

- The decoder itself: a vendored engine adapter, following [`docs/ADAPTERS.md`](ADAPTERS.md). For
  example, `modules/image/adapters/<engine>/{adapter.sh,vendor.sh}` wrapping a real tool that can read
  rpm headers.
- The adapter's output: a sqlite database with `name, epoch, version, release, arch` columns in a
  `Packages` table. The existing query in `_rpm_sqlite_enumerate` already reads that shape, so the
  matching code needs no change.
- The dispatch: `modules/image/run.sh`, near its existing `rpm_scan_installed` call. Run the adapter
  when it is vendored; otherwise keep today's declared gap.
- The tests: `tests/suites/image-rpm.sh` (enumeration, including section F, which builds the real
  two-column native schema) and `tests/suites/image-rpm-e2e.sh` (end-to-end with a sqlite fixture).

**Decisions already made. Do not reopen them.**

- **No hand-written RPM header parser in bash.** `rpm.sh`'s header explains why: there is no reference
  implementation in the tree to test it against. This is the same reasoning `docs/FOUNDATION.md`
  tension 25 uses for OS version comparison. Wrap a real tool behind an adapter instead.
- **The adapter is optional and never required.** When the engine is absent, the run must still report
  `rpm_db_binary_format`, exactly as it does today (`docs/ADAPTERS.md` §7).
- **No network during a scan.** The engine is fetched only at setup time, by the adapter's `vendor.sh`
  through `tools/vendor-engines.sh`, and must be pinned by checksum.
- **Do not use `modules/sca/semver.sh` for rpm versions.** It is npm-only and gets OS package versions
  wrong. `rpm_version.sh` is the rpm comparator.

**Size.** Large: a new adapter, its vendoring entry, and tests on both userlands. Roughly two to four
days, most of it choosing and pinning a decoder that runs offline on Linux and macOS.

**How to verify.**

1. Build a fixture image whose rpm database uses the real native format (the way
   `tests/suites/image-rpm.sh` section F does).
2. With a fake vendored adapter, following the pattern in `tests/suites/sast-gitleaks.sh`, check that
   `scan.sh image` emits `IMAGE-PKG-VULNERABLE_OS_PACKAGE-03` for a vulnerable package.
3. With the adapter absent, check the run still emits `IMAGE-COV-UNKNOWN_DISTRO-01` with
   `rpm_db_binary_format`.
4. Run `tests/run-tests.sh image-rpm`, `tests/run-tests.sh image-rpm-e2e`, and
   `tests/run-tests.sh lint-shell`.

## 2. A published OCI/Docker image of scoursh

**What is missing.** scoursh is released as an attested tarball (`.github/workflows/release.yml`,
`tools/build-release.sh`), with a Homebrew formula template in `packaging/homebrew/`.
There is no container image, no Dockerfile for one, and no workflow job that builds or publishes one.

**Why it matters.**

- **Pinned dependencies.** An image fixes bash, the GNU userland, `openssl`, `sqlite3`, `git`,
  `python3` and the rest at known versions, so every user runs the same tools.
- **Windows.** scoursh's Windows answer is WSL (`docs/USAGE.md`). A container is the only way a
  Windows user can get a kernel-enforced no-egress guarantee: `docker run --network none` for
  `sast`, `sca` and `iac`.
- **A strong guarantee from one command.** Today that guarantee needs `tools/run-in-netns.sh` (Linux,
  root) or `tools/run-sandboxed.sh` (macOS). Tier C in `docs/USAGE.md` already runs
  `tools/run-in-netns.sh` inside a Linux container.

**How the gap is reported today.** It is listed under "Not yet started" in `ROADMAP.md`. No code
path refers to it.

**Where it would live.**

- `packaging/docker/Dockerfile`, next to `packaging/homebrew/`. The directory does not exist yet.
- Base it on the precedent in `tools/daily-suite/gnu.dockerfile`: `debian:bookworm-slim`, with every
  download pinned and checked against a checksum.
- Unlike that file, the image must also install `iproute2`, `iptables` and `ip6tables`, so it can run
  `tools/run-in-netns.sh` (Tier C, `docs/USAGE.md`).
- Build it from the tarball `tools/build-release.sh` produces, not from a git checkout, so the image
  contains exactly the bytes that were attested.
- A new job in `.github/workflows/release.yml`, after the existing build and publish jobs: build a
  multi-arch image (amd64 and arm64), push it, and attest it the same way the tarball is attested.

**Decisions already made. Do not reopen them.**

- **The image is built from the attested release tarball.** It adds no second build path.
- **Do not describe it as "air-gapped".** The claim is exactly this: `sast`, `sca` and `iac` make no
  network calls, and running them with `--network none` means the kernel enforces that.
  `dast`, `cloud` and `network` need egress by design and cannot run under `--network none`.
- **Do not bake advisory data into the image.** `data/advisories.db` goes stale quickly. Mount it or
  generate it into a volume; never ship an old copy that looks like current coverage.
- **Operator config and state live in a volume.** Point `SCOURSH_HOME` at the volume so the
  installed-layout rules in [`docs/adr/0002-installed-layout.md`](adr/0002-installed-layout.md)
  apply unchanged.
- **Release publishing is the maintainer's job.** A contributor PR adds the Dockerfile, a local check,
  and a workflow job that does not run until the maintainer turns it on. It must not push to any
  registry itself.

**Size.** Medium, roughly a day: a Dockerfile, a smoke-test script, and one workflow job.

**How to verify.**

1. `tools/build-release.sh "$(cat VERSION)" /tmp/rel`, then build the image from that tarball.
2. `docker run --rm IMAGE --version` prints the contents of `VERSION`.
3. `docker run --rm --network none -v "$PWD:/src:ro" IMAGE sast --path /src` completes, and
   `scoursh paths` inside the container puts state and reports in the volume, not the install root.
4. Run `tools/run-in-netns.sh` inside the image and check that an unauthorised destination is
   refused.
5. Put the same checks in a script, following the shape of `tools/smoke-installed.sh`.

## 3. `install.sh`, a one-line installer for Linux and WSL

**What is missing.** A user without Homebrew installs by hand: download the tarball, check it,
extract it, and link `bin/scoursh` onto `PATH` (`docs/USAGE.md`, "Installing from a release").
There is no script that does this.

**Why it matters.** It is the missing install path for WSL and for Linux without Homebrew. Neither
of those users can use the Homebrew formula.

**How the gap is reported today.** Listed in `ROADMAP.md` under "Not yet started". No code refers to
it.

**Where it would live.**

- A new `install.sh`, published as a release asset next to the tarball and `SHA256SUMS`, by
  extending `.github/workflows/release.yml`.
- It installs the tarball into a user prefix, for example `~/.local/share/scoursh/<version>`, and
  links the four entry points `tools/build-release.sh` creates (`bin/scoursh`, `bin/scoursh-vendor`,
  `bin/scoursh-sandbox`, `bin/scoursh-netns`) into `~/.local/bin`.
  The entry points already work through a symlink, and `tools/smoke-installed.sh` tests exactly that.
- **Lint trap.** If you put the script under `tools/`, `tests/lint-shell.sh`'s "no bypass" check will
  fail on its `curl`, because it scans every `*.sh` under `tools/`. Either add an exact-path exemption
  with a written reason (the same way `tools/vendor-engines.sh` is exempted) or put it outside the
  scanned directories, for example `packaging/install.sh`. Say which you chose and why in the PR.

**Decisions already made. Do not reopen them.**

- **It must verify before it installs.** Check the tarball against `SHA256SUMS` every time. When `gh`
  is available, also run `gh attestation verify` against this repository, with the same
  `--signer-workflow` argument `docs/USAGE.md` ("Verify a download") uses. Offer a setting that makes
  a missing attestation check an error instead of a warning.
- **Download from the immutable release, never from a branch.** The script and the tarball must both
  come from the same tagged release.
- **Document download-then-run, not `curl ... | sh`.** A tool whose whole point is naming every
  destination in advance cannot ask users to pipe an unread script into a shell.
- **It installs scoursh and nothing else.** It checks for bash 4.2 or later and prints how to get it.
  It does not install bash, engines, or advisory data.
- **Exit codes stay within 0-5** (`docs/FOUNDATION.md` tension 14): 4 for a missing prerequisite,
  2 for bad arguments.

**Size.** Small to medium, roughly half a day to a day, most of it testing.

**How to verify.**

1. Point the script at a local tarball and `SHA256SUMS` built by `tools/build-release.sh`.
2. Check that it installs, and that `scoursh paths` then shows state outside the install root.
3. Corrupt one byte of the tarball. The script must refuse and leave nothing behind.
4. Run `tools/smoke-installed.sh` on the installed tarball.
5. Run `tests/run-tests.sh lint-shell` to check the exemption.

## 4. Setup-time engine install and `engines.lock`

**What is missing.** scoursh can use three optional engines: semgrep and gitleaks for `sast`, and
trivy for `iac`. Today the operator installs each one by hand, passing a URL and a sha256 through
environment variables (`SCOURSH_SEMGREP_*`, `SCOURSH_GITLEAKS_*`, `SCOURSH_TRIVY_*`, read by
`modules/*/adapters/*/vendor.sh` through `tools/vendor-engines.sh`).
Two things are missing:

- a committed `engines.lock` that pins each engine's version, upstream URL and publisher sha256 for
  each supported platform;
- a setup command that installs engines from that file.

semgrep has no working install route at all (`README.md`, "Vendor the engines, for extra depth").

**Why it matters.** Without a lock file, every operator looks up URLs and checksums alone, and
nothing records which engine bytes produced a given result. Without a setup step for semgrep, one of
the three adapters cannot be used from a clean install.

**How the gap is reported today.** At scan time, an engine that is missing is recorded as
`coverage_reduction ... reason=engine_not_vendored engine=<name>`, and one that crashes as
`reason=engine_run_failed` (`modules/sast/run.sh`, `modules/iac/run.sh`). `README.md` and
`docs/USAGE.md` both say plainly that semgrep has no recipe.

**Where it would live.**

- `engines.lock`: a new committed file, one row per (engine, OS, architecture), holding the version,
  upstream URL and publisher sha256. It must be added to `BR_RELEASE_PATHS` in
  `tools/build-release.sh`, or it will not ship.
- The installer: `tools/vendor-engines.sh`, the one script allowed to reach the network, or a new
  `tools/` script next to it. It writes to `scoursh_engine_dir_for_write` (`lib/layout.sh`), so an
  installed copy puts engines under `SCOURSH_DATA_DIR/engines/<module>/<engine>`.
- Detection: `semgrep_detect`, `gitleaks_detect` and `trivy_detect` in
  `modules/*/adapters/*/adapter.sh` currently only check that the file is executable. Once a lock
  file exists, they should also compare the file's sha256 against it, so a wrong or wrong-platform
  binary is refused by name instead of failing when it runs.

**Decisions already made by the maintainer. Do not reopen them.**

- **gitleaks and trivy are pinned to upstream, never re-hosted.** `engines.lock` records the
  publisher's own URL and sha256. The project never mirrors or commits engine binaries. trivy is
  larger than GitHub's 100 MB file limit anyway, and `.gitignore` already excludes
  `modules/*/adapters/*/bin/` and `.../rules/`.
- **semgrep is installed at setup time into a pinned pipx or venv environment**, for example
  `pip install semgrep==<pinned version>` into a directory the adapter finds as `bin/semgrep`.
  semgrep publishes no binary release, so there is nothing to pin by URL.
- **semgrep's registry rules are never redistributed.** Semgrep's rules licence forbids
  redistribution (`README.md` and `.gitignore` both say so). Setup may fetch rules onto the user's own disk if the user
  asks, but they must never be committed, put in a release tarball, or baked into an image.
- **The setup command must not be reachable from the scan path.** `tests/lint-shell.sh`'s tension-27
  check fails if anything under `lib/`, `modules/` or `scan.sh` sources or runs
  `tools/vendor-engines.sh`. Keep setup as a separate `tools/` entry point.
- **No platform guessing.** If `engines.lock` has no row for the host's `uname -s`/`uname -m`, refuse
  with exit 4 and name the platform. Never download a binary for a different platform.
- **Keep engines offline at scan time.** The adapters' offline flags (`docs/ADAPTERS.md` §7a) stay as
  they are. Re-check them against the pinned version's real `--help` output every time you bump a pin.

**Size.** Medium to large, roughly two to three days: the lock format, a setup path for the two binary
engines, the semgrep venv path, checksum-based detection, and tests.

**How to verify.**

1. Stub `curl`, as `tests/suites/vendor-engines.sh` does, so tests never touch the network.
2. Check that setup installs each engine from `engines.lock` and refuses on a checksum mismatch.
3. Check that setup refuses an unknown platform with exit 4.
4. Check that `has_engine` (`lib/engines.sh`) reports a binary with the wrong checksum as not
   vendored, and the run records `engine_not_vendored`.
5. Run `tests/run-tests.sh vendor-engines`, `tests/run-tests.sh engines`, and
   `tests/run-tests.sh lint-shell`.

## 5. The AWS posture phase (POSTURE-02 to POSTURE-04)

**What is missing.** `scan.sh cloud --live` runs 112 read-only checks across 30 AWS services
(`modules/cloud/aws/live/`). The posture phase from `docs/DESIGN.md` §8.7 has not been built. It is
meant to compare the account against the operator's own expected-control baseline and report drift.
Only its config schema exists: `config/posture.conf.example`, defined in `rules/RULE-FORMAT.md`
§9.6.4. The directory `modules/cloud/posture/` does not exist.

The three tickets, from `docs/STEP6-CLOUD-PLAN.md`:

| Ticket | File | What it checks |
|---|---|---|
| POSTURE-02 | `modules/cloud/posture/sso.sh` | Federated SSO is configured with signing and encryption; an expected SSO integration is present. |
| POSTURE-03 | `modules/cloud/posture/edge.sh` | Edge/WAF IP allowlisting and geo restriction are present; the edge serves only 443, redirects 80, and applies HSTS. |
| POSTURE-04 | `modules/cloud/posture/session.sh` | A logout or session-invalidation route exists in the API route inventory written by `modules/cloud/aws/live/apigw.sh`. |

**Why it matters.** Some controls cannot be probed from outside; they can only be read from
configuration. Posture checks report drift from a baseline the operator wrote, rather than the
scanner's opinion, so they fill a gap the live checks cannot.

**How the gap is reported today.** `_cloud_run_posture_phase` (`modules/cloud/aws/run.sh`) records
one of two declared reductions: `reason=no_posture_conf` when `config/posture.conf` is absent, or
`reason=no_posture_checks_on_disk_yet` when it exists but no check has shipped. `tests/suites/cloud.sh`
pins both. The exit code is not affected.

**Where it would live.**

- Scripts: `modules/cloud/posture/{sso,edge,session}.sh`. `lib/records.sh` already maps
  `modules/cloud/posture/*` to the `POSTURE` module.
- Check registries: one `checks-<name>.rules` file per script, in the same directory.
  `config/posture.conf.example` uses the ids `POSTURE-SSO-FEDERATION_ENABLED-01`,
  `POSTURE-EDGE-WAF_IP_ALLOWLIST-01` and `POSTURE-SESSION-LOGOUT_ROUTE-01` as examples. Register
  these, or change the example to match what you register.
- The phase runner: `_cloud_run_posture_phase` in `modules/cloud/aws/run.sh`. Replace the
  `no_posture_checks_on_disk_yet` placeholder with real dispatch, and keep the `no_posture_conf` path.
- Tests: a new suite per script, built with `tests/lib/aws-fixtures.sh`'s routed mode
  (`aws_fixture_route_add`) so each AWS call gets its own recorded response.

**Decisions already made. Do not reopen them.**

- **Posture is a phase of `scan.sh cloud`, not a new command.**
- **Its coverage cell is `scope-key`, not `account-region`.** That is why posture has no row in the
  `_CLOUD_SERVICES` table and why `_cloud_record_coverage` skips `POSTURE-*` ids. Do not add a
  `posture` row to that table (`AGENTS.md` explains why).
- **Every AWS call goes through `aws_ro`.** Read the outcome with `aws_ro_into` or a redirect, never
  `$(aws_ro ...)`, and treat an `AccessDenied` as lost coverage, not an empty account
  (`aws_ro_outcome_is_coverage_loss`).
- **Findings are framed as "expected control not observed"**, at `info` or `medium` severity, as
  `docs/DESIGN.md` §8.7 says. POSTURE-04 is a heuristic: when no logout route is found, flag it for
  manual confirmation rather than claiming there is none.
- **`config/posture.conf` is shared with the network module.** `NET-PORT-UNEXPECTED_LISTENER-01`
  already reads `expect: absent` records from it. Do not change the schema.
- **Cite a `cis` control only where CIS AWS Foundations Benchmark v3.0.0 has one**
  (`docs/CIS-MAPPINGS.md`). Leaving it out is correct when there is none.

**Size.** Medium per ticket, roughly one to two days each. The three are independent once you have
read `run.sh`; start with POSTURE-04, which needs no new AWS calls.

**How to verify.**

1. With a fixture `config/posture.conf` and routed AWS fixtures, check that a missing expected control
   produces a finding and a present one does not.
2. Check that an `AccessDenied` produces a coverage reduction, not a clean result.
3. Check that removing `config/posture.conf` still produces `no_posture_conf`.
4. Run `tests/run-tests.sh cloud`, your new suites, and `tests/run-tests.sh lint-aws-readonly`.
5. Update the "Status" section of `docs/STEP6-CLOUD-PLAN.md` and the posture line in `ROADMAP.md` in
   the same PR.

## 6. Smaller open items

### 6.1 Two timing-sensitive test assertions flake on CI

Each of these failed once on GitHub Actions and passed when the job was re-run, on unchanged code.

| Assertion | File | What went wrong | CI run |
|---|---|---|---|
| `preflight should refuse in a couple of seconds, never run a real module first` | `tests/suites/scan.sh`, around line 1313 | The check requires `all --target no-such-target` to return within 10 seconds. On `macos-latest` it took 11 seconds, although the functional assertions beside it (exit 3, no `meta/checks_run`) passed. | 35730475261, attempt 1 |
| `and the same fixture DOES observe three at once with the slot removed` | `tests/suites/http.sh`, section 11b, around line 1476 | This is the mutation proof for the in-flight limiter. With the slot removed it expects all three workers to overlap (`_INFLIGHT_MAX` = 3). On a loaded `ubuntu-latest` runner only two overlapped. | 35951198842, attempt 1 |

**Fix direction.** Both assertions depend on timing. The project's approach is to assert on structure,
not the clock; see `tests/lib/bounded-read.sh` and the "BOUNDED at read time" entry in `AGENTS.md`.

- For `scan.sh`, the check that no module ran (`meta/checks_run` absent) already proves the bug is
  fixed. Remove the wall-clock ceiling, or loosen it a lot and keep it as a backstop.
- For `http.sh`, make the three workers wait at a shared rendezvous inside the stub transport
  (for example a FIFO or a marker file) before they return, so overlap is forced rather than hoped
  for.

Keep the rule the project applies to every test: the assertion must still fail under the reading it
names. Show that by breaking the code once and watching the test go red.

**Size.** Small, a few hours each.

### 6.2 Build-release suite checks the wrong file

`tests/suites/build-release.sh` section E decides whether the installed-layout resolver has landed by
looking for `SCOURSH_STATE_DIR` in `lib/core.sh`. That variable now lives in `lib/layout.sh`, and
`lib/core.sh` does not mention it.
So if the release gate (`tools/smoke-installed.sh`) ever started refusing a tarball again, section E
would take its older "refusal expected" branch and pass.

**Fix.** Look for the variable in `lib/layout.sh`, or remove the branch now that the resolver has
landed. Then show that the suite fails when the gate refuses.

**Size.** Small.

### 6.3 Image OS-package matching prints false errors

`modules/image/distro/apk.sh`, `dpkg.sh` and `rpm.sh` each read advisories with
`done < <(db_lookup_prefix "$prefix" "$db")`.
When a package has no advisories, `db_lookup_prefix` returns 1. That is the normal case, but it still
trips `set -Eeuo pipefail` error handling, which prints a spurious `command failed` line to stderr.

`modules/sca/engine.sh` already fixed the same thing with `|| true` inside the process substitution.
That is safe because `db_lookup_prefix` exits the process (`die`) on a real failure, before `|| true`
is reached. `AGENTS.md` has the full explanation; search it for "third instance".

**Fix.** Apply the same `|| true` in all three files. Add a test that captures stderr from a scan of a
package with no advisories and asserts it is empty. Keep a test showing a real lookup failure still
aborts.

**Size.** Small.

### 6.4 AppSync findings cannot correlate with DAST (F21)

`CLOUD-APPSYNC-API_KEY_LONG_EXPIRY-01` never sets `endpoint_hosts`, so it cannot be matched to a DAST
target. That means the composite `COMPOSITE-TOKEN-HIJACK` in `rules/derived.rules` can fire in tests
but never in a real `scan.sh cloud` plus `scan.sh dast` run.

**Fix.** In `modules/cloud/aws/live/appsync_engine.sh`, read the API's `uris` from the
`list-graphql-apis` response the script already has, and add them to the finding with
`finding_add endpoint_hosts`. `docs/FOUNDATION.md` has the full account under "F21".

**Size.** Small to medium.

### 6.5 Network Tier 4 (NET-13 to NET-15)

These are optional follow-ups to the network module, described in `docs/FOUNDATION.md`:

- NET-13: an optional `nmap` adapter;
- NET-14: a `rules/derived.rules` composite linking `NET-*` findings with a cloud or IaC open-CIDR
  finding;
- NET-15: a local, authorised network test target.

NET-13 follows `docs/ADAPTERS.md`. The adapter must keep the module's rule that only ports declared in
`config/scope.conf` are probed; it must not become a port scanner.

### 6.6 DAST live user-enumeration probe

`docs/DESIGN.md` §7.4 has two halves. The half that reads responses scoursh already received has
landed. The live probe, which submits an identifier the operator never configured, has not.
With `--allow-intrusive`, `modules/dast/auth.sh` records
`reason=live_enumeration_probe_not_implemented` today.
On a real identity provider this probe can create accounts or send messages, so it must stay behind
`--allow-intrusive` and `--i-own-target`.

### 6.7 Open GitHub issues

- [#104](https://github.com/abhi-sama/scoursh/issues/104): a whole-tree `scan.sh sast` makes
  `tests/suites/sast.sh` and `tests/suites/scan.sh` take 40-90+ minutes.
- [#326](https://github.com/abhi-sama/scoursh/issues/326): in `tools/daily-suite.sh`'s GNU leg,
  `shellcheck -x` appears broken under the pinned linux/aarch64 build on Apple Silicon Docker
  Desktop.

## Keeping this file honest

When a PR closes an entry here, delete the entry in the same PR and update `ROADMAP.md`.
If an entry is part of a `docs/DESIGN.md` §13 step, also update the "Build order and where we are"
section of `AGENTS.md` and its mirror in `docs/FOUNDATION.md`, as `AGENTS.md` requires.
