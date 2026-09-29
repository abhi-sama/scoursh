# Homebrew tap release handoff

This directory is the source repository's formula template and release check. It
does not create or publish a tap.

**Current status:** the public tap is `abhi-sama/homebrew-scoursh`.  A release
job renders this template and opens a formula-bump pull request after each
published release; `brew install` resolves the new version after that tap PR
has been merged.

## Captain publication steps

1. Configure the source repository's `HOMEBREW_TAP_TOKEN` Actions secret as a
   fine-grained token limited to `abhi-sama/homebrew-scoursh`, with only
   Contents and Pull requests read/write permissions. The release job fails
   loudly rather than silently skipping a bump when the secret is absent.
2. The release job renders `Formula/scoursh.rb` from
   `packaging/homebrew/scoursh.rb` after it replaces:
   - every `@VERSION@` with the release version (the first release is `1.0.0`);
   - `@SHA256@` with the SHA-256 emitted by the release build for the exact
     `scoursh-<version>.tar.gz` asset.
3. After GitHub Release publication, the job commits the rendered formula on a
   deterministic branch in `abhi-sama/homebrew-scoursh` and opens (or reuses)
   its pull request. It uses the build job's checksum and never downloads the
   release again to calculate one.
4. Have the tap PR run, on macOS and Linux, `brew audit --strict --new`,
   `brew install --build-from-source`, and `brew test`, then merge the tap PR.

Users install the published formula with:

```sh
brew install abhi-sama/scoursh/scoursh
```

## Formula/release contract

The formula installs the release archive into `libexec` and exposes
`bin/scoursh` as a symlink to a small wrapper under `libexec/bin`. The wrapper
executes Homebrew's Bash, rather than relying on macOS's Bash 3.2.

The release archive must extract to one top-level directory and place these
paths directly below it:

- `scan.sh`, `VERSION`, `LICENSE`, `README.md`, `lib/`, `modules/`, `rules/`,
  `data/`, `config/`, and `tools/`;
- `.scoursh-packaged`, the installed-copy marker required for the XDG/
  `SCOURSH_HOME` state layout;
- `bin/` (the formula replaces the release entrypoint links with wrappers).

Do not omit the marker: Ruby's normal `Dir["*"]` glob excludes dotfiles, so
the formula installs `.scoursh-packaged` explicitly. The formula intentionally
does not depend on OpenSSL, SQLite, or Git: they enable optional scanner
capabilities and their absence is reported by scoursh as a declared coverage
reduction.

## Local release validation

After building a release-shaped archive, run:

```sh
packaging/homebrew/self-check.sh /absolute/path/scoursh-$(cat VERSION).tar.gz
```

The check exits successfully with a clear skip message when Homebrew is absent.
With Homebrew present, it verifies the archive has `VERSION` and
`.scoursh-packaged`, renders a temporary formula pointing at that local archive,
then runs `brew audit --strict --new`, `brew install --build-from-source`, and
`brew test`. It refuses to run if `scoursh` is already installed and removes
only the formula instance it installed.
