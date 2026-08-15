# tools/daily-suite/gnu.dockerfile - the GNU-userland leg of the local daily
# suite run (tools/daily-suite.sh).
#
# WHY AN IMAGE AND NOT A PACKAGE INSTALL PER RUN.  tools/daily-suite.sh tags the
# built image with this file's own sha256, so "the image is absent" means
# exactly "this dockerfile has never been built on this machine": an edit here
# rebuilds, and an unchanged file never touches the network again.  A daily job
# that apt-installed shellcheck every morning would need the network every
# morning and would be slower for nothing.
#
# THE NETWORK BOUNDARY.  `docker build` reaches the network by construction - it
# pulls a base image - so this file is not where docs/FOUNDATION.md tension 19's
# no-egress rule applies.  That rule is about what a SCAN does; nothing under
# lib/, modules/ or scan.sh builds or runs this image, and tools/daily-suite.sh
# only builds it when it is absent.  Every artifact fetched here is pinned by
# version and verified by a sha256 taken from the publisher's own release
# metadata, never guessed - the same discipline tools/vendor-engines.sh applies
# to a vendored engine.
#
# WHY DEBIAN AND NOT ALPINE.  Alpine is busybox, which is neither GNU nor BSD.
# docs/FOUNDATION.md tension 24 is about exactly two userlands scoursh ships on;
# testing a third would answer a question nobody asked while leaving the GNU one
# unanswered.
#
# WHY ARM.  This runs on whatever the operator's machine is, which for Apple
# Silicon means ARM Linux rather than the x86-64 Linux the retired hosted CI
# provided.  For a GNU-versus-BSD USERLAND comparison that is faithful - what
# tension 24 checks is coreutils/grep/sed/bash behaviour, none of which is
# architecture-dependent - and forcing x86-64 through emulation would be far
# slower for no relevant gain.  Do not add --platform here to "fix" it.
#
# The package list is exactly what tests/run-tests.sh reaches for on Linux:
#   bash >= 4.2               the frozen minimum (bookworm ships 5.2)
#   coreutils/grep/sed/gawk/findutils/diffutils   the GNU userland under test
#   git                       tests/suites/sast-history.sh builds real repos
#   python3                   tests/suites/vendor-engines-advisories.sh
#   openssl                   lib/core.sh's SHA-256 fallback provider
#   ca-certificates, curl     tests/suites/http.sh's transport stubs
#   bsdextrautils             provides `look`, which lib/core.sh's
#                             db_lookup_exact uses for the advisory table
#   procps                    provides `ps`, which lib/paranoid.sh samples
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed gawk diffutils \
      git curl ca-certificates openssl python3 \
      bsdextrautils procps xz-utils \
 && rm -rf /var/lib/apt/lists/*

# shellcheck is deliberately NOT the distribution package.
#
# tests/run-tests.sh runs it with `-x`, which follows `source` directives.  On
# this repository's source graph, both Debian bookworm's 0.9.0 and trixie's
# 0.10.0 consume every byte of available memory on `modules/sca/run.sh` and are
# killed by the OOM killer - measured, twice, with ~7 GB free; dropping `-x`
# avoids it but would lint less than the BSD leg does, and the two legs linting
# different things is exactly the divergence this run exists to catch.  0.11.0,
# which is what the BSD leg's Homebrew build is, handles it.
#
# The sha256s are the publisher's own, read from the GitHub release metadata for
# this tag.  Bump the version and BOTH checksums together, from the same source;
# never carry an unverified one.
ARG TARGETARCH
ARG SHELLCHECK_VERSION=v0.11.0
ARG SHELLCHECK_SHA256_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
ARG SHELLCHECK_SHA256_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
RUN set -eux; \
    case "${TARGETARCH:-}" in \
      arm64) sc_arch=aarch64; sc_sha="$SHELLCHECK_SHA256_ARM64" ;; \
      amd64) sc_arch=x86_64;  sc_sha="$SHELLCHECK_SHA256_AMD64" ;; \
      *) echo "no pinned shellcheck for TARGETARCH='${TARGETARCH:-}'" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.${sc_arch}.tar.xz"; \
    curl -fsSL "$url" -o /tmp/shellcheck.tar.xz; \
    printf '%s  /tmp/shellcheck.tar.xz\n' "$sc_sha" | sha256sum -c -; \
    tar -xJf /tmp/shellcheck.tar.xz -C /tmp; \
    install -m 0755 "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" /usr/local/bin/shellcheck; \
    rm -rf /tmp/shellcheck.tar.xz "/tmp/shellcheck-${SHELLCHECK_VERSION}"; \
    shellcheck --version
