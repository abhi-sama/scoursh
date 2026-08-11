# Spike: GNU/BSD portability of `scan.sh` arg parsing and exit codes

Status: **complete, non-blocking**.
This is a research spike.
It ships no production code.
Its findings and recommendation feed the `scan.sh` skeleton ticket (`docs/DESIGN.md` §13 build-order step 2), which owns the actual decision and implementation.

```
// ADR: candidate approach for scan.sh's long-option CLI parsing
// Context: scan.sh's CLI surface (docs/DESIGN.md §5) is long-option-only
//   (--path, --profile-scan, --fail-on, ...) with no short forms, must run
//   unmodified on macOS (BSD userland, ships bash 3.2) and Linux (GNU
//   userland), and per the sharp-edge register must never fail silently.
// Decision: recommend a hand-rolled `while (( $# )); case "$1" in ...`
//   shift-loop (candidate B below), supporting both `--flag value` and
//   `--flag=value`, with no external getopt(1) dependency. Verified
//   byte-identical behavior, including error paths and exit codes, on
//   macOS system bash 3.2 and Linux (Debian 12) bash 5.2 with util-linux
//   getopt installed.
// Alternatives considered: external getopt(1) in "enhanced"/--long mode
//   (candidate A) -> measured NOT portable, see Finding 1; bash builtin
//   getopts with the `-:` long-option hack -> rejected on inspection,
//   no runtime test needed (Finding 3).
// Consequences: scan.sh's parser is more verbose (one case arm per flag,
//   times two for the `=value` form) than a getopt one-liner, but it has
//   zero external dependencies and cannot silently misparse. It does not
//   get short-option clustering (-abc) for free, which the CLI spec never
//   asked for.
```

## 1. What was tested

Two candidate implementations of the same slice of the real CLI surface
(`--path`, `--lang`, `--history`, `--jobs`, `--fail-on`, `--format`, `--out`,
`--paranoid`, plus `--` and trailing positionals), using the project's frozen
exit-code contract (`lib/core.sh`: 0 ok, 1 gate, 2 usage, 3 scope, 4 input,
5 incomplete):

- **Candidate A** - `docs/spikes/fixtures/candidate-a-getopt.sh`.
  Delegates to the external `getopt(1)` binary in GNU/util-linux "enhanced"
  mode (`getopt -o '' --long path:,lang:,... -- "$@"`), then `eval set --`
  on the result.
  This is the idiom most shell arg-parsing writeups recommend for long
  options.
- **Candidate B** - `docs/spikes/fixtures/candidate-b-handrolled.sh`.
  A `while (( $# > 0 )); do case "$1" in ...` loop that shifts its own
  arguments, with an explicit `--flag=value` arm and a `--flag) ... shift 2`
  arm per option, and an explicit "requires a value" check before
  dereferencing `$2`.

Both fixtures are throwaway: they are not sourced by any real module, not
referenced by `tests/run-tests.sh`, and exist only as evidence for this
ticket.

## 2. Where it was run

- **BSD**: this host, natively.
  `Darwin 25.5.0 arm64`, system `/bin/bash` (Apple-shipped, GNU bash
  3.2.57, kept at 3.2 for GPLv2/v3 licensing reasons - this is the bash
  every macOS operator actually has on `$PATH` unless they installed
  their own), system `/usr/bin/getopt`.
- **GNU**: `debian:12-slim` under Docker (`docker run --rm -v
  .../fixtures:/fixtures:ro -w /fixtures debian:12-slim bash -c '...'`),
  with `util-linux` installed for its `getopt`.
  Linux 6.12 aarch64, GNU bash 5.2.15, `getopt from util-linux 2.38.1`.

Full transcripts, uncut, are checked in at
`docs/spikes/fixtures/transcript-macos-bsd.txt` and
`docs/spikes/fixtures/transcript-linux-gnu.txt`.
The exact commands are reproduced in §5 below.

## 3. Findings

### Finding 1 (disqualifying) - `getopt(1)` is not the same program on macOS and Linux, and macOS's fails silently

On Linux, `getopt -o '' --long path:,lang:,history,... -n candidate-a --
--path src --history extra1` behaves exactly as documented: it reorders,
validates, and rewrites argv, and exits non-zero with a message on an
unknown flag or a missing value.
Candidate A's output on Linux is fully correct across all four test cases
(normal parse, `--bogus`, missing `--path` value).

On macOS, `/usr/bin/getopt` is not util-linux getopt at all.
`man getopt` on this host describes a single-string, short-option-only
`getopt optstring $*` from the original getopt(3) era, with **no concept of
`--long`, `-o`, or `-n`**.
Measured directly:

```
$ /usr/bin/getopt -o '' --long path:,lang:,history -n test -- --path src --history extra1
 --  --long path:,lang:,history -n test -- --path src --history extra1
$ echo $?
0
```

It does not error.
It does not recognize any of `-o`, `--long`, or `-n` as options, it takes
`''` as the (empty) optstring, and it echoes essentially everything else
back as literal, unprocessed text - with exit code **0**.
Fed through candidate A's `eval set -- "$PARSED"`, this becomes 15+ bogus
positional arguments and every flag variable stays empty.
Run through the full candidate-A fixture, the "happy path" invocation on
macOS silently produces `path=[] lang=[] history=0 ... positional=[--long
path:,lang:,history -n candidate-a -- --path src ...]` and **exits 0** -
indistinguishable from a successful run with no flags given.
The unknown-flag and missing-value cases are just as silent: no error, exit
0, garbage positionals.

This is worse than a portability gap that merely needs `#ifdef`-style
branching.
It is a **silent-corruption** failure mode on the platform this project
explicitly must support (`docs/DESIGN.md` targets an operator's own
workstation, which is routinely macOS), and it is exactly the class of bug
the project's own sharp-edge register already treats as disqualifying
elsewhere - e.g. the pipe-delimited rule format was replaced because it
"silently corrupts" on `|` in a regex, and `tests/e2e` un-usable-diff
handling is fail-closed by design.
An arg parser that returns exit 0 on `--bogus-flag-that-does-not-exist`
is not an acceptable foundation for `scan.sh`, which per `docs/DESIGN.md`
§5 must map "usage error" to exit code 2, not 0.

Installing GNU getopt via Homebrew (`brew install gnu-getopt`) fixes this,
but that means the tool cannot run on a stock macOS install - which
directly conflicts with the air-gapped, zero-install-step posture this
project already holds for everything else (vendored rules, no runtime
fetches, `require_cmd` in `lib/core.sh` only demanding POSIX-standard
tools).
Depending on a non-stock binary for the CLI's own entry point was rejected
on that basis alone; the silent-failure behavior above is the sharper
reason.

### Finding 2 - the hand-rolled loop is byte-identical on both platforms

Candidate B, run with the same four cases (happy path with `--flag value`
form, happy path with `--flag=value` form, unknown flag, missing value),
produced **identical stdout, stderr, and exit codes** on macOS bash 3.2 and
Linux bash 5.2:

| case | macOS bash 3.2 | Linux bash 5.2 |
|---|---|---|
| full happy path | `path=[src] lang=[py,js] history=1 jobs=[4] fail_on=[high] format=[json,html] out=[/tmp/o] paranoid=1 positional=[extra1 extra2]`, rc=0 | identical |
| `--path=src --fail-on=high extra1` | `path=[src] lang=[] history=0 jobs=[] fail_on=[high] format=[] out=[] paranoid=0 positional=[extra1]`, rc=0 | identical |
| `--bogus foo` | `die(2): unknown option: --bogus`, rc=2 | identical |
| `--path` (no value) | `die(2): --path requires a value`, rc=2 | identical |

No external binary is invoked; the loop uses only bash builtins
(`case`, `shift`, `${1#*=}`, `(( ))`) that are present in bash 3.2 as
shipped by Apple, so there is no minimum-bash-version tax on macOS beyond
what the project already assumes elsewhere.
It also composes cleanly with `set -Eeuo pipefail` and the project's `die`
convention (`lib/core.sh` tension 14): the `(( $# >= 2 )) || die ...` guard
is short-circuited by `||` before `set -e` would otherwise trip on the
arithmetic-false return, exactly as `lib/core.sh`'s existing guards do
elsewhere.

### Finding 3 - bash builtin `getopts` was considered, not executed

`getopts` is a portable bash/POSIX builtin (no external binary, so it does
not share Finding 1's platform-identity problem), but it has no native
long-option support in either userland; the common workaround is an
`OPTSTRING` of `-:` plus manual `$OPTARG` splitting on `=`, which is a
well-known fragile pattern (silently swallows a flag typo as "argument
required" rather than "unknown option" on some `getopts` builds).
Since `docs/DESIGN.md` §5's entire CLI surface is long-options only - there
is not a single short flag to support - `getopts` would buy nothing over
candidate B while adding an indirection layer that has to be re-explained
to every reader.
This was a design-level disqualification, not a portability question, so
no runtime evidence was needed and none was collected.

## 4. Recommendation for the entry-point ticket

Adopt candidate B's shape for `scan.sh`'s argument loop: no external
`getopt`, a `case` arm per flag supporting both `--flag value` and
`--flag=value`, an explicit "requires a value" check before shifting the
value out, `--` as an explicit end-of-options marker, and unknown
`--*` mapped to `die "$SCOURSH_EXIT_USAGE" ...` (exit 2, matching
`docs/DESIGN.md` §5's documented contract).
Given `docs/DESIGN.md` line 48 already earmarks "arg parsing helpers" as
part of `lib/core.sh`, the step-2 ticket should decide whether the loop
lives directly in `scan.sh` or is factored into a small `lib/core.sh`
helper (e.g. a `parse_flag_value` used by every `--flag) ... ;;` arm to
collapse the current one-arm-per-form duplication) - that factoring choice
is left to that ticket, since it depends on the final flag list and is not
something this spike should pre-empt.

## 5. Reproduction

```
# BSD (run natively on macOS):
/bin/bash docs/spikes/fixtures/candidate-a-getopt.sh --path src --lang py,js --history \
  --jobs 4 --fail-on high --format json,html --out /tmp/o --paranoid -- extra1 extra2
/bin/bash docs/spikes/fixtures/candidate-b-handrolled.sh --path src --lang py,js --history \
  --jobs 4 --fail-on high --format json,html --out /tmp/o --paranoid -- extra1 extra2

# GNU (Linux via Docker):
docker run --rm -v "$PWD/docs/spikes/fixtures:/fixtures:ro" -w /fixtures debian:12-slim bash -c '
  apt-get update -qq && apt-get install -y -qq util-linux
  bash ./candidate-a-getopt.sh --path src --lang py,js --history --jobs 4 --fail-on high \
    --format json,html --out /tmp/o --paranoid -- extra1 extra2
  bash ./candidate-b-handrolled.sh --path src --lang py,js --history --jobs 4 --fail-on high \
    --format json,html --out /tmp/o --paranoid -- extra1 extra2
'
```

Full transcripts (all four cases, both platforms) are in
`docs/spikes/fixtures/transcript-macos-bsd.txt` and
`docs/spikes/fixtures/transcript-linux-gnu.txt`.

## 6. Scope note

Nothing under `lib/`, `modules/`, or `scan.sh` was touched.
`docs/spikes/` and its `fixtures/` subdirectory are new, are not referenced
by `tests/run-tests.sh` or any lint suite, and are not part of the build.
This satisfies the ticket's "no production code merged" constraint; the
entry-point ticket for `scan.sh` §13 step 2 is expected to implement the
recommendation above as real, tested, production code and may delete or
keep these fixtures at its discretion.
