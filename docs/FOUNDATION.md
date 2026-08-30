# scoursh foundation - design-tension register

> This is the register of design tensions found by reading `docs/DESIGN.md` adversarially, as an
> implementer who has to write the thing in bash.
> Each entry states the tension, why it bites, the options that were considered, the **RESOLUTION**, and
> the consequence for the build.
>
> Every resolution is a decision, not a menu.
> An implementer must be able to act on any entry here without asking a follow-up question.
> Where a resolution contradicts the letter of `docs/DESIGN.md`, this document wins and says so
> explicitly; `docs/DESIGN.md` is preserved verbatim as the handoff artifact it is, and is not edited to
> match.
>
> Companion documents: `docs/DESIGN.md` (what scoursh is) and `rules/RULE-FORMAT.md` (the frozen
> on-disk record format, which tension 1 produces and which several later tensions reuse).

## Index

| # | Tension | Bites at |
|---|---|---|
| 1 | Rule-record encoding | §6.2, §6.3 |
| 2 | Regex dialect and engine parity | §6.1, §6.2 |
| 3 | The `context` directive | §6.2 |
| 4 | `set -Eeuo pipefail` versus a rule engine | §4 |
| 5 | Fingerprint identity: what "location" means | §4, §9a |
| 6 | Derived / composite findings | §4, Appendix A |
| 7 | Identifier namespaces | §4, §6.2, Appendix A |
| 8 | Base severity versus rubric adjustment | §4 |
| 9 | Redaction versus evidence versus fingerprint | §4, §14 |
| 10 | Untrusted evidence rendered into reports | §4 |
| 11 | Baseline versus diff versus the CI gate | §9a, §11 |
| 12 | Diff soundness under partial runs | §9a |
| 13 | Git-history findings | §6.3 |
| 14 | Exit-code precedence and required inputs | §5, §9a, §11 |
| 15 | Check-set selection precedence | §5, §7 |
| 16 | Shared limiter, budget, breaker, cache across processes | §4, §5, §10 |
| 17 | Concurrent writes to `findings.jsonl` | §10 |
| 18 | Resumability keyed by a fingerprint that does not exist yet | §10 |
| 19 | Scope-gate semantics | §2, §7, §11 |
| 20 | Paranoid mode versus infrastructure traffic | §2, §12 |
| 21 | Module independence versus cross-module inventory | header, §7.5, §8.4 |
| 22 | SARIF locations for findings with no file | §4 |
| 23 | A read-only AWS lint that survives contact with reality | §8.1, §12 |
| 24 | Runtime freeze: bash and coreutils portability | §4, §10 |
| 25 | Offline version matching for SCA | §6.5 |
| 26 | One record format for human-authored config | §11 |

---

## Tension 1 - rule-record encoding

**The tension.**
`docs/DESIGN.md` §6.2 specifies a pipe-delimited rule record whose fifth field is a regular expression.
The §6.3 catalog that the same section asks us to seed is full of regexes containing `|`.

**Why it bites.**
`|` is both the field separator and the single most common regex metacharacter in this catalog.
AWS key prefixes, weak-hash algorithm names, dangerous sink names, framework fingerprints, and template
delimiters are all naturally written as alternations.
A record like `SEC-AKID | critical | CWE-798 | A07 | \b(AKIA|ASIA|AROA)[0-9A-Z]{16}\b | hardcoded key`
splits into eight fields instead of six.
The failure is silent in the worst way: the loader either drops the rule (a check that reports zero
findings because it never ran) or truncates the regex to `\b(AKIA` (which does not compile, or worse,
compiles and matches something else).
A security scanner that quietly stops running a check is worse than one that crashes.
There is no escaping scheme that survives, because the escape character would itself need escaping
inside a regex, and regexes are already saturated with backslashes.

**Options considered.**

1. *Keep pipes, escape `|` as `\|` inside the regex field.*
   Rejected: `\|` is already a meaningful ERE escape (a literal pipe), so the record format and the
   regex language collide on the same two bytes with different meanings.
   Authors cannot be expected to track two levels of backslash.
2. *Keep pipes, quote fields CSV-style.*
   Rejected: it moves the collision to `"` and `,`, both of which appear in the §6.3 catalog
   (`rejectUnauthorized:false`, `cidr_blocks = ["0.0.0.0/0"]`), and CSV quoting in pure bash is a
   character-at-a-time loop.
3. *Use TAB as the delimiter.*
   Rejected: a TAB is invisible, editors convert it to spaces, and a single silent conversion breaks the
   pack the same way pipes do.
   It also makes multi-line remediation impossible.
4. *Use JSON or YAML for rule packs.*
   Rejected: JSON requires escaping every backslash in every regex, doubling them
   (`\\b(AKIA|ASIA)[0-9A-Z]{16}\\b`), which is exactly the authoring hazard we are trying to remove, and
   there is no JSON parser in bash.
   YAML needs a real parser and its block scalars pivot on `|`, the one character this catalog is full
   of.
   §6.2 also asks for the format to be "simple, greppable" and §16 asks that a new language be "a new
   `.rules` file, no code change"; both point away from a format needing a parser dependency.
5. *Blank-line-separated `key: value` block records.* **Chosen.**

**RESOLUTION.**
Rule records are **blank-line-separated `key: value` block records**, specified normatively and
completely in `rules/RULE-FORMAT.md`.
Fields are delimited by line boundaries, not by any character a regex can contain.
The key/value separator is the *first* `": "` on the line, so `:` is free inside values.
Values carry **no escaping of any kind**: the byte sequence after the separator to end of line is the
value, verbatim.
The only bytes a value cannot contain are LF and NUL, and prose fields get LF back through
two-space continuation lines.
Comments are whole-line only (first byte `#`), so `#` is free inside values.

The **rule catalog of `docs/DESIGN.md` §6.3 stands unchanged**.
Which rules to seed, per language, is unaffected; only the on-disk encoding of a rule changes.

**Consequence for the build.**
`lib/records.sh` is the single parser and is written first, before any module that consumes rules
(this reorders nothing in §13, since §13 step 3 is where the rule format lands).
`tests/lint-rules.sh` implements the error codes in `rules/RULE-FORMAT.md` §13 and runs as part of
`tests/run-tests.sh`.
The format is frozen: it is reused for derived findings (tension 6), redaction rules (tension 9), and
every human-authored config file (tension 26), so a change to it is a repository-wide breaking change,
costed in `rules/RULE-FORMAT.md` §14.

## Tension 2 - regex dialect and engine parity

**The tension.**
§6.1 says the engine uses "`ripgrep` if present else `grep -R`".
§6.2's own worked example is `yaml\.load\((?!.*Loader)`, a PCRE negative lookahead.
These three facts cannot all hold: `rg` and `grep -E` and `grep -P` are three different regular
expression languages, and the example rule works in none of the portable ones.

**Why it bites.**
The same rule pack silently produces different findings on different hosts.
`grep -E` has no lookahead at all and will either error or, on some implementations, treat `(?!` as a
literal group and match nothing.
`grep -P` is GNU-only and absent on macOS and BSD.
`rg` supports lookahead only with `-P`, which requires a PCRE2-enabled build that many distributions do
not ship.
`rg` and `grep` also disagree on smaller things that matter here: `rg` treats the pattern as Rust regex
syntax (where `{` is a repetition operator in more contexts), searches UTF-8 by default, and skips files
listed in `.gitignore` unless told otherwise, which would make the scanner silently skip exactly the
generated or vendored files most likely to contain secrets.
A security tool whose coverage depends on which grep the host happens to ship is not a security tool.

**Options considered.**

1. *Require PCRE everywhere.*
   Rejected: it forces a build-time dependency onto air-gapped hosts, which §1 rules out ("pure bash by
   default", "zero deps").
2. *Write every rule twice, once per dialect.*
   Rejected: doubles the catalog and doubles the ways a pack can drift out of sync.
3. *Normalise at load time by translating PCRE to ERE.*
   Rejected: the translation is not total (lookahead has no ERE equivalent), so it would fail on exactly
   the rules that motivate it.
4. *Freeze a portable subset, declared per rule, with explicit opt-in to PCRE.* **Chosen.**

**RESOLUTION.**
Every regex-bearing record declares a `dialect`, one of exactly two values, defaulting to `ere`.

- `ere` is a **frozen portable subset** enumerated construct by construct in `rules/RULE-FORMAT.md`
  §8.2: POSIX ERE plus the `\b \w \s \d` shorthands that both engines share, and nothing else.
  Lookaround, non-capturing groups, backreferences, lazy quantifiers, and inline flags are forbidden and
  the linter rejects them by construct (E040).
  Matching is line-oriented and case-sensitive; case-insensitivity is written into the pattern
  (`[Mm][Dd]5`) rather than passed as a flag, so identical bytes mean identical things in both engines.
- `pcre` is opt-in, and a `pcre` record is **skipped** when no PCRE2-capable engine is present.
  A skipped check is recorded in `run.json` under `skipped_checks` with reason `pcre-unavailable`, and
  is excluded from `covered_checks` in `state/` so it cannot manufacture `fixed` findings
  (tension 12).

The `rg` invocation is pinned to remove its defaults:
`rg --no-config --no-ignore --hidden --no-binary --engine default -n --no-heading --color never`,
with `--engine pcre2` added only for `pcre` records.

> **`--binary=false` was corrected to `--no-binary` in §13 step 1.**
> ripgrep rejects the former outright - "invalid CLI arguments: unexpected argument for option
> '--binary'", measured on ripgrep 15.1.0 - so `scan_match` aborted the run on its first call.
> It failed loudly rather than silently, which is what tension 4 rule 2 is for.
The `grep` fallback is `grep -E -n`.

> **`-r` and the exclude list were removed from the pinned invocation in §13
> step 1, and the removal was measured rather than reasoned.**
> `-r` is `--recursive` to `grep` and `--replace` to `ripgrep`:
> `rg <pinned flags> -r 'eval' tree` consumes `eval` as a replacement string and
> returns rc=1 having searched nothing, while `grep -E -n -r 'eval' tree`
> recurses and matches (measured; commit `a28cba8`).
> A flag that means two different things to the two engines cannot live in a
> shared wrapper whose whole purpose is that the two produce byte-identical
> findings, so **file enumeration is the caller's job** and the wrapper is handed
> one path at a time.
>
> That moves the **exclude list** to the caller too.  It is not lost: it belongs
> with the walker that §13 step 3 builds, alongside `files` / `exclude-files`
> (`rules/RULE-FORMAT.md` §9.1.2), which are per-rule and which the wrapper could
> never have applied anyway.  Recorded here as a step-3 obligation so it is not
> silently dropped.
>
> This paragraph is now checked rather than asserted: `tests/suites/core.sh`
> reads what `lib/core.sh` binds for each engine and requires this document to
> contain that exact string, so the two cannot drift again without a test
> failing.
Both are wrapped in one function so the invocation exists in exactly one place.

§6.2's `yaml\.load\((?!.*Loader)` is **rewritten** as an `ere` pattern plus a `context-deny`; the
worked record is `rules/RULE-FORMAT.md` §12.2.
The rewrite is strictly better than the original, because a two-line context window also catches the
common shape where the loader argument sits on the following line.

**Consequence for the build.**
`lib/engines.sh` gains a capability probe (`rg` present, `rg` PCRE2 present, `grep -P` present) run once
at startup and recorded in `run.json`.
The linter compiles every pattern against its declared engine (E046) so a pack cannot ship a pattern
that does not compile.
A parity test in `tests/` runs the whole catalog under `rg` and under `grep -E` against the same fixture
tree and asserts byte-identical findings; a pack that diverges fails CI.
`-n -b -o` - the invocation `rules/RULE-FORMAT.md` §10.3 requires so that one line yielding two matches
yields two findings - was measured to produce byte-identical output under ripgrep 15.1.0 and BSD grep
2.6.0-FreeBSD, and `\b`, `\w` and `\s` were measured to behave identically under both, so §8.2's
portable subset holds on a BSD userland as stated.
Reaching for `pcre` is a documented last resort, and the linter warns (W047) when a `pcre` record uses
no PCRE-only construct.

## Tension 3 - the `context` directive

**The tension.**
§6.2 asks for "a `# context:` directive option to require/deny a neighboring pattern (cheap way to cut
false positives, e.g. only flag `eval(` when `request`/`input`/`argv` appears within N lines)".
That sentence contains a slash where a decision has to be, and three unstated parameters.

**Why it bites.**
An implementer cannot write this.
"Require/deny" does not say whether the directive is one thing with a polarity or two separate things.
"Within N lines" does not say whether the window is symmetric or forward-only, whether the matching line
itself counts, or what N defaults to.
With multiple directives on one rule it does not say whether they conjoin or disjoin.
Every one of these choices changes which findings fire, and getting them wrong produces either a flood
of false positives or a silent false negative.
Additionally, the directive is written as a `# context:` **comment**, which under any sane comment rule
is exactly the thing the parser throws away, and which the linter therefore cannot check.

**Options considered.**

1. *One `context` key with an inline mini-language, `context: require /RE/ within 3`.*
   Rejected: it needs a second parser with its own delimiters, and the delimiter would collide with
   regex content again, which is the mistake of tension 1 repeated one level down.
2. *Keep it as a `# context:` magic comment, per the letter of §6.2.*
   Rejected: a directive that lives in a comment is invisible to the linter, is stripped by
   comment-aware tooling, and gives `#` two meanings.
3. *Forward-only window (lines `m` to `m+N`).*
   Rejected: the motivating case is `eval(user_input)` where the request object was bound *above* the
   call, which is the overwhelmingly common shape.
4. *Separate `context-require` and `context-deny` keys with fixed, opposite quantifiers.* **Chosen.**

**RESOLUTION.**
The directive is expressed as ordinary record fields, never as a comment.
Normative statement in `rules/RULE-FORMAT.md` §10; the decisions are:

- **It is both require and deny**, as two independent repeatable keys: `context-require` and
  `context-deny`.
- **The window is symmetric and inclusive of the match line.**
  For a match on line `m` with `context-window: W` in a file of `L` lines, the window is
  `[max(1, m-W), min(L, m+W)]`.
- **`context-window` defaults to 2.**
  `0` means the match line only, which is the correct setting for a same-line guard.
  The linter caps it at 50 (E032) and errors if it appears with no require or deny (E031).
- **Quantifiers are fixed and opposite.**
  *All* `context-require` entries must be satisfied (AND); *any* satisfied `context-deny` entry
  suppresses (OR).
  Deny is evaluated after require and wins.
  This is chosen for monotonicity: adding an entry of either kind always makes the rule stricter about
  firing, so an author tuning a noisy rule never has to re-reason about the whole predicate.
- Context patterns use the record's `dialect` and the same line-oriented case-sensitive matching as
  `pattern`, so tension 2's portability guarantee covers them too.

**Consequence for the build.**
The engine is a two-pass-per-file design, not a per-match re-read: pass one collects candidate line
numbers for every rule from a single `rg -n` / `grep -n`; pass two walks the file once and evaluates all
windows.
Per-file matches are capped by `max_matches_per_file` (default 200) and an overflow emits an `info`
finding plus a `run.json` record, because §15 forbids silently overstating coverage and a silent
truncation does exactly that.
Every false-positive complaint against a rule is now fixable as a data change (add a `context-deny`),
which is what §16 promises.

## Tension 4 - `set -Eeuo pipefail` versus a rule engine

**The tension.**
§4 mandates `set -Eeuo pipefail` and "a global `ERR` trap that reports the failing command + line", and
a `mktemp -d` scratch dir "with an `EXIT` trap that shreds it".
The core loop of this entire tool is `grep`, which exits **1** when it finds nothing.
Finding nothing is the normal, expected, overwhelmingly common outcome of a rule engine.

**Why it bites.**
Four separate ways, all of which produce a tool that appears to work and does not.

1. `set -e` terminates the script on the first rule that does not match, which is usually the first rule.
2. The `ERR` trap fires and reports a "failure" for every non-matching rule, burying real errors in
   thousands of lines of noise.
3. `pipefail` makes it worse: in `rg ... | sort | head`, a no-match `rg` makes the *whole pipeline*
   return 1 even though `head` succeeded, so a pipeline cannot be used to post-process matches at all.
4. Least obvious and most damaging: `trap cleanup EXIT` installed in the parent is **inherited by every
   `xargs -P` worker**, because a worker is a fresh `bash` process that sources `lib/core.sh` and
   therefore installs the trap itself.
   The first worker to finish then erases the scratch directory while the run is still using it.

   > **Corrected in §13 step 1 (finding F13).**
   > This item previously said the hazard was *subshell* inheritance - that a `( ... )` or a `$( ... )`
   > that exits runs the cleanup handler.
   > That is false for bash, which resets trapped `EXIT` actions to their default in every subshell, and
   > it was measured: `trap 'echo FIRED' EXIT; ( true ); x=$(exit 3); ( exit 5 ) & wait` prints `FIRED`
   > exactly once, at parent exit, on bash 3.2.57 and on bash 5.3.9.
   > `$$` is also the parent pid inside a subshell, so the guard rule 5 used to prescribe was a no-op
   > belt for a case that cannot occur - while passing in the case that does.
   > `tests/suites/core.sh` reproduces both halves.

Also, `set -u` plus `"${arr[@]}"` on an empty array is an unbound-variable error in bash before 4.4,
which is guaranteed to happen the first time a rule matches no files (see tension 24).

**Options considered.**

1. *Drop `set -e`.*
   Rejected: it is the property that makes a 5000-line shell program survivable, and §4 mandates it.
2. *Append `|| true` to every grep.*
   Rejected: it discards the distinction between "no match" (exit 1) and "the engine failed" (exit 2 or
   above, for example a bad pattern or an unreadable file), so a broken rule reports clean.
   That is precisely the silent-coverage-hole failure mode.
3. *`set +e` around the engine.*
   Rejected: it disables the guarantee exactly where the code is densest, and it is impossible to keep
   the exception scoped as the code grows.
4. *A frozen calling convention plus one wrapper.* **Chosen.**

**RESOLUTION.**
`set -Eeuo pipefail` stays, is never disabled anywhere, and the following five rules are frozen.
A lint in `tests/` enforces rules 1, 2, and 5 by grep.

1. **`set +e` is forbidden repository-wide.**
   The lint fails on any occurrence.
2. **Bare `grep` / `rg` is forbidden.**
   All pattern matching goes through `scan_match` in `lib/core.sh`, which distinguishes the three
   outcomes explicitly:

   ```
   scan_match() {                       # writes hits to $1; 0 = matched, 1 = no match
     local rc=0 out=$1; shift
     "${SCOURSH_GREP[@]+"${SCOURSH_GREP[@]}"}" "$@" >"$out" || rc=$?
     (( rc <= 1 )) || die 5 "pattern engine failed (rc=$rc): $*"
     return $rc
   }
   ```

   Three corrections to this sample landed with §13 step 1.
   The comment said "writes hits to `$2`" while the body takes the output path as `$1` (open finding
   F18's second half).
   `die 6` is outside the frozen 0-5 exit contract of tension 14 and would reach CI unclassifiable; a
   pattern-engine failure is what tension 14 already calls an **incomplete run**, so it is `die 5` and it
   writes `incomplete_reason`.
   `die` itself now validates its argument against 0-5, so `die 6` cannot exist - which closes the rest
   of F18 by mechanism rather than by editing each sample.
   The array expansion takes tension 24's guarded form, and `scan_match` additionally aborts when the
   engine array is unbound, because an empty expansion would leave a bare redirect that succeeds and
   writes an empty file - "no match" for every rule, which is the silent coverage hole this wrapper
   exists to prevent.

   `rc >= 2` is a hard error and aborts, so a malformed pattern or an I/O failure can never be mistaken
   for a clean result.
3. **No-match commands are invoked in a condition context or with explicit `|| rc=$?`.**
   Bash does not apply `set -e` to a command in an `if` condition, in a `while` condition, or on the
   left of `&&` / `||`, and the `ERR` trap does not fire there either.
   `if scan_match "$hits" -E "$pat" -- "$f"; then ... fi` is therefore both safe and idiomatic.
4. **No pipelines whose non-final stage may legitimately exit non-zero.**
   The engine writes producer output to a file in the scratch dir and checks the producer's status
   directly, as in `scan_match` above.
   `mapfile -t x < <(producer)` is forbidden in the engine because it discards the producer's exit
   status, which is the very thing rule 2 exists to check.
5. **The `EXIT` cleanup trap is guarded on scratch-dir OWNERSHIP, so that only the process that created
   the scratch dir removes it.**

   ```
   scratch_init() {
     [[ -n ${SCOURSH_SCRATCH:-} && -d ${SCOURSH_SCRATCH:-} ]] && return 0   # inherited: never our own
     SCOURSH_SCRATCH=$(tmpdir_make); chmod 700 "$SCOURSH_SCRATCH"
     printf '%s\n' "$$" >"$SCOURSH_SCRATCH/.owner"
     export SCOURSH_SCRATCH          # the PATH is inherited ...
     SCOURSH_SCRATCH_OWNER=$$        # ... but ownership is NOT exported
   }
   scratch_is_owned_here() {         # in-memory marker AND the on-disk one
     [[ ${SCOURSH_SCRATCH_OWNER:-} == "$$" ]] || return 1
     IFS= read -r recorded <"$SCOURSH_SCRATCH/.owner" || true
     [[ $recorded == "$$" ]]
   }
   cleanup() { scratch_is_owned_here && erase_dir "$SCOURSH_SCRATCH"; return 0; }
   trap cleanup EXIT
   ```

   > **This replaces the guard `[[ $BASHPID == $$ ]]`, which was wrong in both directions (finding
   > F13, closed in §13 step 1).**
   > It defended subshell inheritance, which bash does not produce, and it PASSED in an `xargs -P`
   > worker, which is a fresh process where `$BASHPID == $$` is true - so the first worker to finish
   > erased the shared scratch dir holding the rate limiter, the budget counter, the breaker state and
   > the AWS cache.
   > Ownership is deliberately not exported and is confirmed against an on-disk marker, so a worker
   > cannot become the owner by inheriting or re-exporting a variable.

   The scratch dir now holds **only genuinely transient data**: the matching lines `scan_match` writes,
   the mutex directories, and the rate, budget and breaker state.
   Finding shards and the unit journal live in the run directory instead (finding F12, tensions 17 and
   18), because this trap erases the scratch dir on the very signal tension 18's resume test uses.

   The `ERR` trap reports `${BASH_SOURCE[0]}:${LINENO}` and `$BASH_COMMAND`, must contain no command
   that can itself fail, and re-raises the original status.
   `die` removes the `ERR` trap before exiting, so an intentional exit is not re-reported as an error.

**Consequence for the build.**
This lands in §13 step 1, because every later module depends on it.
`tests/run-tests.sh` includes a negative test that a deliberately broken pattern makes the run abort
with a non-zero status rather than reporting zero findings.

**The prescribed cleanup test is replaced (finding F13).**
It used to be "a subshell exit leaves the scratch dir intact", which is vacuous: a subshell never runs
the trap in the first place, so the assertion holds under the correct implementation and under the
broken one alike.
The replacement runs **N workers under `xargs -P`**, each sourcing `lib/core.sh` for real, and asserts
that the scratch dir, a parent-owned sentinel, and every worker's shard all survive until the parent
exits.
That test fails under the old guard.
A second test asserts the converse directly - that `[[ $BASHPID == $$ ]]` passes in every one of four
`xargs -P` workers - so the register's claim about why the old rule was wrong is itself checked rather
than asserted.
The scratch dir is created once by `lib/core.sh` and its path is exported, so workers never create their
own.

## Tension 5 - fingerprint identity: what "location" means

**The tension.**
§4 defines `fingerprint` as a hash of "module+rule+location", and §9a builds run-to-run diffing,
`baseline.json` suppression, and the "fail only on new findings" CI gate on top of it.
The `location` object in the same section is `{"file":"app/x.py","line":42,"endpoint":null}`.
If the line number is in the fingerprint, adding an import at the top of a file makes every finding in
that file `new`.

**Why it bites.**
This is the single most load-bearing identity decision in the tool and the failure is total rather than
partial.
An unrelated edit twenty lines above a finding shifts its line number, which changes its fingerprint,
which makes the diff report it as one `fixed` plus one `new`, which makes every `baseline.json` entry
stop suppressing, which makes the "fail only on new" gate that §9a calls "the single most useful mode
for continuous scanning" fail every build after any refactor.
Worse, it is not obviously broken: it works perfectly in testing on a static fixture tree and falls
apart on the first real commit.
The `location` shape is also a union that does not fit every module: cloud findings have no file, DAST
findings have no line, posture findings have neither.

**Options considered.**

1. *`file` + `line`.*
   Rejected, as above.
2. *`file` only.*
   Rejected: two hardcoded keys in one file collapse into one finding, so fixing one reports the other
   as fixed too.
3. *`file` + enclosing function or class name.*
   Rejected: extracting the enclosing symbol needs a parser per language, which the native tier
   explicitly does not have (§9, "pattern/linter-grade").
4. *`file` + a digest of the matched text.* **Chosen**, with a per-module definition of location.

**RESOLUTION.**
**No fingerprint input ever contains a line number.**
Line numbers are still recorded in `location.line` and used for reports, SARIF regions, and human
navigation; they are simply not part of identity.

The fingerprint is:

```
fingerprint = lowercase_hex_sha256( FP_SCHEMA \0 module \0 check_id \0 loc_1 \0 loc_2 \0 ... )
FP_SCHEMA   = "fp/1"
```

with NUL as the separator (no location component can contain NUL, per `rules/RULE-FORMAT.md` §3.1), the
full 64 hex characters retained, and the components in the fixed order below.

| Module | Location components |
|---|---|
| SAST, IaC, containers | **scan-root-relative** path (tension 12; `/` separators, no `./`), `match_digest`, `occurrence` |
| SAST history | `blob_sha`, `match_digest`, `occurrence` (see tension 13) |
| SCA | `ecosystem`, `package` (normalised per tension 25), `advisory_id`. **Not the version.** |
| DAST | `target_name` (the `config/scope.conf` id, not the URL), `method`, `path_template`, `param_location` (`query`/`body`/`header`/`path`/`cookie`), `param_name` |
| Cloud live | `account_id`, `region` (or `global`), `resource_key` (the ARN when one exists), `sub_key` (or `none`) |
| Posture | `control_id` (= the `POSTURE-*` **check** id, never the expectation id), `scope_key` (target name, or account, or `account/region`) |
| Derived | correlation value only (see tension 6). The **module component of the hash is the literal `composite`**, not this row's label and not the finding's `module` field, which is `derived` |

Four of these need their normalisation frozen:

- **`match_digest`** = first 16 hex characters of `sha256(normalise(raw_matched_text))`, where
  `normalise` **strips every whitespace byte** (space, TAB, LF, CR, FF, VT).
  Reindenting or reformatting therefore does not churn identity; changing the code does, which is
  correct, because the matched text *is* the finding.
  The raw text is hashed, not the redacted text; see tension 9 for why, and for the rule that it never
  touches disk.

  **This was "collapse every run of whitespace to a single space", and that was not enough.**
  Collapsing runs is not insensitivity to whitespace: zero spaces versus one space is not a run, and
  intra-token respacing is exactly what a code formatter changes.
  Measured: `eval( user_input )` and `eval(user_input)` hashed differently, so a `black`, `prettier`
  or `gofmt` pass over a repository gave every affected finding a new fingerprint.
  The old fingerprint is then absent from the run, tension 12's table classifies it **`fixed`**, and a
  formatting-only commit writes a wave of remediations that never happened into `state/` while
  `--fail-on-new` fires on the whole affected set.
  That is this tension's own phantom-remediation failure, reached by a mechanism none of its tests
  exercised - the stability test inserts blank lines and reindents, both of which were already
  correct, and neither of which is what a formatter does.

  **The cost is stated rather than hidden.**
  `a b` and `ab` now share a `match_digest`.
  They remain **two findings**, told apart by the `occurrence` ordinal exactly as two byte-identical
  matches already are, and by the path component, so identity is not lost - only the discriminator
  changes.
  This widens slightly the bounded ordinal churn described below (deleting one of several matches that
  share a digest renumbers the ones after it), and buys immunity to the far more common formatter case.
  The normalisation can only ever **merge** digests, never split them, so it cannot manufacture a `new`
  finding.

  The alternative considered and rejected was to narrow the claim instead - say "reindentation" rather
  than "reformatting" and accept the churn.
  It was rejected because this register exists to stop a scanner claiming a fix that did not happen,
  and that option knowingly leaves one such path open for a routine, repository-wide operation.
  The change is a **fingerprint input**, so it was made while nothing had been persisted: no scan had
  run, and no `state/` or `config/baseline.json` existed anywhere.
- **`occurrence`** = the 0-based ordinal of this match among the matches **in the same scanning unit,
  for the same `check_id`, with an identical `match_digest`**, ordered by ascending line number and
  then by ascending byte offset within the line.
  The **scanning unit** is the file for SAST, IaC, and containers, and the **blob** for SAST history
  (tension 13), which is what that module actually scans and keys identity on.
  The byte-offset tie-break is required because the line ordering alone is not total: `a = eval(x); b =
  eval(y)` puts two byte-identical matches of one check on one line, and without a tie-break two
  conformant implementations would disagree on which gets ordinal 0, producing different fingerprints
  for the same source and breaking tension 17's byte-reproducibility across implementations.
  It also settles, normatively, that the match unit is the **match** and not the line: one line yielding
  two matches yields two findings.
  This exists because `match_digest` alone collides on the common case.
  Most rules in the §6.3 catalog match a short fixed construct (`\byaml\.load\s*\(`, `\beval\s*\(`,
  `# nosec`), so every occurrence in a file produces byte-identical matched text and therefore an
  identical digest.
  `max_matches_per_file` defaults to 200, so many matches per file is the expected shape, not an edge
  case.
  Without a discriminator, five `yaml.load(` calls in one file would be five findings sharing one
  fingerprint, and nothing would decide whether they collapse or coexist: collapsing hides four of
  five and lets one `baseline.json` entry silently suppress every future occurrence in that file, while
  coexisting puts duplicate keys in `state/` and breaks tension 17's byte-reproducible merge.
  The ordinal is scoped to identical digests, so it is unaffected by unrelated matches of the same rule
  elsewhere in the file, and it survives line shifts and reindentation, which is what tension 5 is
  for.
  **Its cost, stated plainly:** deleting or inserting one of several byte-identical matches in a file
  renumbers the ones after it, so those report as one `fixed` plus one `new`.
  That churn is bounded to files containing repeated byte-identical matches of the same check, and it
  is the price of not collapsing distinct call sites into one finding.
  There is no discriminator that is both stable under sibling edits and distinct per occurrence without
  a language parser, which §9 rules out.
- **`path_template`** replaces volatile path segments with `{id}` so `/users/123` and `/users/456` are
  one finding.
  A segment is replaced when it is entirely digits, or matches a UUID, or matches a ULID, or is
  hexadecimal and at least 16 characters long.
  Everything else is kept literally.
- **SCA excludes the version deliberately.**
  Upgrading past an advisory makes the finding disappear, which the diff reports as `fixed`.
  Including the version would instead report `fixed` plus `new` on every patch bump.

**An SCA coverage roll-up populates none of those three components, and that obliges the module to emit
exactly one of it per run.**
`SCA-COV-UNKNOWN_VERSION-01` and `SCA-COV-NO_ADVISORY_DB-01` answer a question about the run, not about
a dependency: they name no ecosystem, no package and no advisory, so every instance of one hashes to
the identical fingerprint, by construction and correctly.
The uniqueness that the "fingerprints are unique within a run" property below asserts therefore rests, for
these two check ids alone, on the module emitting each at most once - not on the components telling two
instances apart, because there are no components.
That obligation was breached and cost real coverage: the module's four ecosystem-scan entry points each
accumulated unknown-version counts locally and each emitted its own roll-up, so a repository with npm and
Python dependencies produced two findings with one fingerprint, the merge's dedup kept whichever won its
sort, and the operator was told a smaller number than the truth - measured at four-to-one on a fixture
carrying npm, PyPI, Maven and Go gaps together.
The repair is at the emission layer: the walks accumulate into one table that the module flushes once.
**Adding `ecosystem` to the roll-up's fingerprint was the obvious alternative and is rejected**, on two
grounds worth keeping so it is not re-proposed.
It changes finding identity for a shipped check id, which `rules/RULE-FORMAT.md` §14 item 3 prices as
invalidating `state/` and every `config/baseline.json` entry for it; and it is a false model, since the
roll-up is one answer to one per-run question and splitting it per ecosystem makes the check mean
something it does not.
Emitting once is also the stronger repair: a second roll-up becomes impossible to produce rather than
merely harmless.

**`control_id` is the `POSTURE-*` check id**, not the `config/posture.conf` expectation id.
Those became two different things when `rules/RULE-FORMAT.md` §9.6.4 split the namespaces, and a
fingerprint input may not have two candidate referents.
Because `check_id` is already a separate input to the same hash, `control_id` is redundant with it and
the posture location's discriminating component is `scope_key` alone; it is retained so every module's
location tuple has the same shape, and its value is pinned so two implementations cannot hash different
bytes.

Only the SAST, history, IaC, and container modules need `occurrence`.
Every other module's component tuple is already unique per issue, and each for its own reason:
a DAST finding is keyed down to the parameter, a cloud finding down to the sub-resource, an SCA finding
down to the advisory, a posture finding down to (control, scope key) which
`rules/RULE-FORMAT.md` §9.6.4 makes unique by construction, and a derived finding down to its
correlation value, of which it produces at most one.

**Fingerprints are therefore unique within a run**, which two other resolutions depend on and which was
not true before the discriminator existed.
The dedup at step 3 of tension 11's pipeline is consequently a genuine merge of *one* finding seen by
two engines, not a collapse of distinct occurrences: an adapter result (§6.4) is normalised onto the
native location model first, re-deriving `match_digest` and `occurrence` from the file at the adapter's
reported path and line, and only then compared.

An adapter finding that does **not** normalise onto a native location (no file, or a line that no longer
matches) is kept as its own finding rather than being merged or dropped, and it takes its `occurrence`
from a separate ordinal space: the rank among **that adapter's own** findings in the same file with the
same `check_id` and `match_digest`, ordered as above.
Without that, its ordinal would be undefined, since the native ordinal is defined by enumerating matches
of a native check.
Its `check_id` carries the adapter's own id namespace - `<ADAPTER>:<engine rule id>`, frozen as a row of
`rules/RULE-FORMAT.md` §9.1.1a - so the two ordinal spaces cannot collide in a fingerprint.
That form contains a `:` and is therefore outside the §9.1.1 check-id regex by construction, which is
what keeps an adapter id from ever being mistaken for an authored one.

**Consequence for the build.**
`lib/findings.sh` exposes exactly one fingerprint function, and no module computes a fingerprint itself.
`FP_SCHEMA` is written into every `state/` file and every `config/baseline.json`.
On a mismatch tension 12 treats the **prior set as empty** for classification: nothing `fixed`, nothing
`recurring`, this run's findings `new`, prior findings persisted `unknown` with the mismatch as the
reason, and the gate fail-closed.
A test asserts fingerprint stability directly: it inserts blank lines and reindents a fixture, re-runs,
and requires the fingerprint set to be byte-identical.
A further test uses a **formatter-style respacing** (`eval( x )` becoming `eval(x)`, and
`key = "AAAA"` becoming `key="AAAA"`) and requires the same, because the reindentation cases pass
under run-collapsing and therefore cannot distinguish the two normalisations - which is how the
overclaim survived to review round 2.
A companion test pins the accepted cost, asserting that `a b` and `ab` share a digest and are still
two distinct findings.
A second test asserts that two distinct secrets in one file produce two distinct fingerprints.
A third test asserts that a fixture with five byte-identical matches of one check in one file produces
**five** distinct fingerprints, and that shifting them all down by twenty lines leaves that set
byte-identical.
A fourth asserts the merged `findings.jsonl` contains no duplicate fingerprint, which is the invariant
tension 17's sort key and tension 12's `state/` keying both rely on.

## Tension 6 - derived / composite findings

**The tension.**
Appendix A states that `COMPOSITE-TOKEN-HIJACK` "is a derived roll-up computed in `lib/findings.sh` from
contributing findings, not a scanner script", and points here for the mechanism.
No mechanism exists.
Nothing says how a derived finding declares its contributors, when it is evaluated, what its fingerprint
is, or what the §9a diff does when only some contributors are present.

**Why it bites.**
The chain Appendix A is describing is real and is exactly the kind of thing that makes a scan worth
reading: §8.5 finds a long-lived AppSync API key, §7.1 `leakage.sh` finds that same class of key served
in the JavaScript bundle, §7.4 `graphql.sh` finds introspection enabled.
Each on its own is a medium.
Together they are a critical, and the roll-up is the finding a reader acts on.
But a roll-up has no file, no line, and no scanner script, so it fits none of the existing plumbing.
The diff question is the sharp one: if the composite's identity depends on its contributors, then losing
one contributor changes its fingerprint, and instead of reporting "the chain is partially remediated"
the diff reports "one finding fixed, one different finding new", which is noise that trains readers to
ignore the delta.

**Options considered.**

1. *Compute composites in a scanner script.*
   Rejected by Appendix A itself, and it would be wrong: contributors come from different modules that
   may run in any order and in separate processes.
2. *Hardcode the composites in `lib/findings.sh`.*
   Rejected: §16 says a new check is a data change, and a hardcoded roll-up cannot be reviewed, linted,
   or tested like a rule.
3. *Include contributor fingerprints in the composite's fingerprint.*
   Rejected: this is the churn described above.
4. *Data-declared composites, evaluated once, with an identity that does not depend on the contributor
   set.* **Chosen.**

**RESOLUTION.**

**Declaration.**
Derived findings are records in `rules/derived.rules`, in the same frozen format as every other record
(`rules/RULE-FORMAT.md` §9.2).
A record declares `kind: derived` and its contributors as two repeatable keys:

- `requires: <check-id>` - **all** listed checks must have produced at least one finding this run.
- `any-of: <check-id>` - **at least one** listed check must have produced a finding this run.

At least one of the two must be present.
A contributor id must name a real, **non-derived** check; composites may not chain.
That restriction is what makes evaluation a single pass with no fixed point to converge to, and the
linter enforces it (E051, E052).

**Correlation.**
`correlate-on` declares the join key: `none`, `target`, `account`, `account-region`, or `file`.
Contributors count toward one composite instance only when their correlation values are equal, so a
key found in account A and introspection enabled in account B do not fabricate a composite.
`correlate-on: none` means the composite fires at most once per run.

Which module can supply which key is **not** a per-finding judgement, and must not be, because `E053`
has to be decidable statically at lint time.
The frozen capability table is `rules/RULE-FORMAT.md` §9.2.2, and `E053` fires when a record's
`correlate-on` is a key that any of its contributors' modules cannot supply.

`COMPOSITE-TOKEN-HIJACK` uses `correlate-on: target`, since the chain is a property of one deployed
front end.
That requires the cloud-live module to supply `target`, and a cloud finding's identity (tension 5) has
no scope-target name in it - only account, region, and ARN.
The gap is closed by **cloud target attribution**, frozen in `rules/RULE-FORMAT.md` §9.2.2: a cloud
check that reads a resource with a public endpoint records the resource's domain names on the finding
as `endpoint_hosts`, and `lib/findings.sh` maps those against the host set of every
`config/scope.conf` target to derive the finding's `target` correlation value.
So the composite's three contributors - the §8.5 long-lived key finding from cloud live, the §7.1
key-in-bundle finding from DAST passive, and the §7.4 introspection finding from DAST active - all
share one correlation domain, and the chain is only asserted when the key actually belongs to the front
end that was scanned.

Attribution is a **correlation attribute only and never a fingerprint input**.
Putting it into a cloud finding's identity would make every cloud finding churn to `new` the moment an
operator edited `config/scope.conf`, which is exactly the instability tension 5 exists to prevent.
A cloud finding whose `endpoint_hosts` match no target simply has no `target` value and does not
participate, which is the correct outcome: a key on an API that is not behind the scanned front end is
not evidence of that front end's hijack chain.

**When it is evaluated.**
Exactly once, in `lib/findings.sh`, at a fixed point in the frozen pipeline (tension 11):
after all modules have completed, after native and adapter results are merged and deduped, and
**before** baseline suppression, diff classification, and state persistence.

Two ordering consequences follow, both deliberate:

- Because evaluation is **before** suppression, baselining a contributor does not silently destroy the
  composite.
  The composite is independently suppressible by its own fingerprint, which is the honest behaviour:
  accepting the risk of a leaked key is not the same decision as accepting the risk of the full hijack
  chain.
- Because evaluation is **before** diff classification, the composite participates in new / recurring /
  fixed like any other finding.

**Fingerprint.**

```
fingerprint = sha256( "fp/1" \0 "composite" \0 check_id \0 correlation_value )
```

with `correlation_value` being the literal string `none` when `correlate-on: none`.

**The first component is the literal `composite`, and it is NOT the finding's
`module` field.**
That field is `derived` - which is how tension 5's table labels the row, and what
`lib/report.sh` groups by - so the two are different strings for two different
jobs, and `lib/findings.sh` maps one to the other explicitly rather than passing
the module through.
This is called out because the implementation originally passed the module field
into the frozen slot and hashed `derived`: no test noticed, because the only
assertions on a composite fingerprint were self-consistency ones that agreed with
whatever the emitter produced.
A composite fingerprint is persisted into `state/` and `config/baseline.json`, so
hashing the wrong literal means a baseline written by a conformant implementation
suppresses nothing, and correcting it after release costs an `fp_schema` bump and
a full-backlog churn - which is the whole reason this byte string is pinned here
rather than left to the module name.
`tests/suites/findings.sh` now computes the reference digest from raw bytes
rather than through `fingerprint_compute`, so the assertion cannot agree with the
implementation by sharing its helper.

**Contributor fingerprints are deliberately not in the identity.**
They are recorded in the finding body as `contributors: [<fingerprint>, ...]`, which is evidence, not
identity.
This is the decision that makes the diff behave: the composite keeps one stable identity across runs
even as the contributing evidence shifts, so a reader sees "this chain is still open" rather than a
churn of new and fixed.
Each contributing finding gains a back-reference `derived_into: [<composite check_id>, ...]`, and
contributors are retained as findings in their own right rather than being absorbed.

**Severity.**
The record's declared `severity` is the base, then it is **clamped upward** to the highest final
severity among its contributors, then the standard rubric (tension 8) runs on it.
A roll-up can never be less severe than its worst part.

**Diff behaviour when only some contributors are present.**
This is the case Appendix A's mechanism has to answer.
**Firing and classifying are separate operations with separate rules**, and conflating them is what
produces phantom remediation.

**Firing** needs no coverage test at all.
A composite fires, this run, for every correlation value where its `requires` and `any-of` predicate
holds over the findings actually present.
If the contributors are there, the chain is real, whatever else the run did or did not visit.

**Classifying a prior composite that did not fire this run** is where coverage matters.
A prior composite is **`fixed`** only if **all three** of the following hold; if any fails it is
**`unknown`**:

> **(a) The composite's own record was selected and evaluated this run.**
> **(b) Every check named in the record's `requires` and `any-of` is covered this run**, where "covered"
> is judged per §(b1)/(b2) below.
> **(c) The predicate no longer holds** over this run's findings.

Each of the three exists because leaving it out produces a false `fixed`, and each is stated as its own
condition rather than folded into a single "contributors are covered" test, because that single test was
the round-2 formulation and it was wrong on two of the three counts.

**(a) Own selection.**
A composite has no coverage cell, so tension 12's `(check, cell)` test cannot protect it, and nothing
else asked whether the composite record itself survived tension 15's filter chain.
It still can not: `--profile-scan quick` drops any composite without a `quick` profile tag, and
`--allow-intrusive` off drops one tagged `intrusive`, exactly as either would for an ordinary check.
(`--intensity` used to be a THIRD way this happened - `derived` was a type tag in no `--intensity`
tier, open finding F8, so `scan.sh all --intensity active` dropped every composite regardless of intent
- but F8 is closed: `lib/checks.sh` exempts `derived` from the intensity ceiling specifically, so
`--intensity` alone no longer drops a composite.  `--profile-scan` and `--allow-intrusive` still can.)
Without (a), `scan.sh all` followed by `scan.sh all --profile-scan quick` would classify the flagship
`COMPOSITE-TOKEN-HIJACK` **`fixed (chain broken)`** with all three contributors still present and the
chain fully open.
A composite that was not selected is `unknown`, exactly as an unselected ordinary check's findings are.

**(b) Contributor coverage**, which has two branches because contributors divide into two kinds:

- **(b1) A check that produced a prior contributor finding.**
  Its `(check_id, cell)` pair is read from `state/` and must be covered this run.
  Additionally, that contributor must itself be **`fixed`-eligible**, not merely cell-covered: for a
  `SAST-HIST-*` contributor its `oldest_reaching_commit_time` must be at or after this run's
  `oldest_commit_time` (tension 13).
  A covered cell is necessary but not sufficient for that family, and reading only the cell would let a
  composite be `fixed` while the history contributor it depends on is itself correctly `unknown`.
  The rule is general, not a `SAST-HIST-*` special case: **a contributor counts as covered only under
  the same test that would let its own finding be classified `fixed`.**
- **(b2) A listed check that produced no prior contributor finding.**
  `contributors` records only the checks that actually *fired*, so a listed `any-of` alternative that did
  not fire leaves no pair to look up and would otherwise be invisible.
  Such a check counts as covered only when **both** of the following hold, and the composite is
  `unknown` if either fails:

  1. **A floor.** The check has an entry in **this run's** `covered_checks` with at least one cell.
     A check with no entry at all is **not covered, whatever the prior run recorded.**
  2. **A subset.** The prior `state/`'s `covered_checks[<check>].cells` set is a subset of this run's for
     that check, so every cell the prior run covered it over was revisited.

  **Neither half is sufficient alone**, and this tension has now been wrong in each direction once, so
  both failures are recorded rather than just the second.

  *Without the subset test*, the region-narrowed case slips through.
  `requires: DAST-A-01`, `any-of: DAST-B-01`, `any-of: CLOUD-C-01`, `correlate-on: target`.
  Run 1 `--regions all`: A and B fire at `staging`, C never fires anywhere, so `contributors = [A, B]`
  while `covered_checks[CLOUD-C-01].cells` records both regions.
  Run 2 `--regions us-east-1`: (a) holds, (b1) holds for A and B, and under a floor-only test (b2) holds
  because C was covered in `us-east-1` - so the composite is reported **`fixed (chain broken)`** and
  persisted, even though `eu-west-1`, the only region where C could have fired, was never visited.

  *Without the floor*, the never-covered case slips through, and this one needs no exotic flags at all.
  Same record, run 1 `scan.sh all` on a runner with no cloud credentials, so `CLOUD-C-01` is kept out of
  `covered_checks` entirely by the exclusion list below.
  A and B fire, the composite fires, `contributors = [A, B]`.
  Run 2 is the **identical invocation** with B remediated.
  The prior cell set for `CLOUD-C-01` is empty, empty is a subset of anything, "if any of those cells was
  not revisited" ranges over nothing, so a bare subset test holds **vacuously** and the composite is
  persisted **`fixed (chain broken)`** naming B as the link that went away - while C, the alternative
  that could keep `A ∧ (B ∨ C)` live, was never assessed in either run.
  That is prescribed test 9.

  An earlier draft carried the floor as part of a weaker rule, and replacing that rule with the subset
  test dropped it silently.
  It is restored here as an explicit conjunct so it cannot be dropped again by rewriting the other half.

  This is the case where "the one that would have fired never ran" has to be distinguished from "none of
  them fired", and it is why (b) is stated over the record's `requires` and `any-of` lists rather than
  over the recorded contributor set alone.

Both branches read only data the frozen `state/` shape already carries: (b1) takes its pairs from
`contributors` plus each contributor's recorded `cell`, and (b2) takes its cell set from
`covered_checks[<check>].cells`.
Nothing is inferred, and no mapping from a correlation value to a contributor's coverage cell has to be
invented.

**(c)** is the ordinary predicate re-evaluation.

When all three hold, the composite is **`fixed`**, and this is correct and desirable: the chain is broken
even though individual links may remain open.
The report renders it `fixed (chain broken)` and names which contributor went away, from the prior run's
`contributors` list, so a reader can see *why* it closed.
When (a) or (b) fails, the composite is **`unknown`**, recorded in `run.json` under `skipped_checks` with
reason `composite-not-selected` or `contributor-not-covered`, the latter naming the check ids and cells
that were missed.
Nothing was learned, so nothing is claimed.

**Why the earlier check-id-only test was wrong.**
It read "a composite is evaluated if and only if every check id named in its `requires` and `any-of`
appears in this run's `covered_checks`".
Once `covered_checks` became a map whose key is present when a check ran in *at least one* cell,
"appears" stopped meaning "ran everywhere" and started meaning "ran somewhere".
Concretely: run 1 is `scan.sh all --regions all` and `COMPOSITE-TOKEN-HIJACK` fires for target
`staging` off an AppSync key in `eu-west-1`.
Run 2 is `scan.sh all --regions us-east-1`.
The cloud contributor's id still appears in `covered_checks`, so the composite was evaluated, the cloud
contributor produced nothing because `eu-west-1` was never visited, and the flagship composite was
reported **`fixed (chain broken)`** and persisted.
That is phantom remediation on exactly the invocation tension 12 exists to defeat, reaching the register
through the one path tension 12's own cell test does not cover, because a composite has no cell.
Under the rule above, the prior cloud contributor's cell is `123.../eu-west-1`, that pair is not covered
this run, and the composite is `unknown`.

**A composite has no coverage cell of its own** and does not appear in `covered_checks`.
Its `cell` is persisted as JSON `null` (tension 12).
Its coverage is **not** simply the conjunction of its contributors': condition (a) above is a property of
the composite record itself and has no contributor to read it from, which is exactly why the round-2
formulation - "the conjunction of its contributors'" - was wrong and is withdrawn here.

**No prior contributors recorded.**
Two situations produce this and they are decided differently, because the justification that made one of
them harmless does not hold for the other:

- **The composite is new** (no prior composite finding at all).
  There is nothing to classify as `fixed`, so any coverage test can only affect `unknown` versus absent.
  Require every check id in `requires` and `any-of` to be covered in at least one cell, and flag it in
  `run.json`.
- **A prior composite finding exists but the state predates `contributors`.**
  Here the weak "covered in at least one cell" test is exactly the round-2 formulation this tension
  replaced, and a region-narrowed run would report the flagship composite `fixed` through it.
  So it is **not** used: such a prior finding is classified **`unknown`** and `run.json` records
  `contributors-unavailable`.
  Nothing gates this branch on `tool_version`, and `fp_schema` does not change when `contributors` is
  added, so the branch has to fail safe on its own rather than be detected.

Condition (b2) above is what the old sentence "`any-of` requires all of its listed checks to have been
*covered*, not just one" was reaching for, and it now has a defined scope and a defined meaning of
"covered".
That sentence used the pre-cell vocabulary and, left standing beside a cell-keyed rule, gave two
conformant implementations opposite classifications for the same `any-of` composite; it is withdrawn and
replaced by (b2).

**Consequence for the build.**
`lib/findings.sh` gains `derive_findings`, called once by `scan.sh` after module completion, and
`classify_derived`, called during tension 11's step 5.
Both are pure: their inputs are the merged findings list, the derived records, `covered_checks`, and the
prior state's contributor records.
A fixture test feeds a synthetic findings set and asserts each outcome.
**Every case below is chosen to fail under a specific rejected reading**, named alongside it, because a
test that passes under both readings pins nothing:

| # | Fixture | Must be | Fails under |
|---|---|---|---|
| 1 | Predicate holds over present findings | fires | - |
| 2 | Correlation values differ across contributors | does not fire | joining on `none` |
| 3 | Does not fire; every prior contributor pair covered; composite selected | `fixed` | a rule that never reports `fixed` |
| 4 | Does not fire; one prior contributor's cell not visited (`--regions` narrowed) | **`unknown`** | classification keyed on bare check id ("ran somewhere") |
| 5 | **Composite record dropped by a filter (e.g. `--profile-scan quick`); all contributors present and firing** | **`unknown`** | condition (a) omitted - the round-2 rule returns `fixed (chain broken)` |
| 6 | **`any-of: DAST-B-01, CLOUD-C-01`; run 1 `--regions all`, only B fires; run 2 `--regions us-east-1`, same modules selected, B now absent** | **`unknown`** | condition (b2) omitted **and** (b2) stated as "covered in at least one cell" - both return `fixed`, because C *is* covered in `us-east-1` while `eu-west-1` was never revisited |
| 7 | **`SAST-HIST-*` contributor whose cell is covered but whose `oldest_reaching_commit_time` precedes this run's `oldest_commit_time`** | **`unknown`** | condition (b1)'s `fixed`-eligibility clause omitted - cell-only returns `fixed` |
| 8 | Prior composite finding with no `contributors` recorded | **`unknown`** | the "covered in at least one cell" fallback applied to this branch |
| 9 | **`requires: DAST-A-01`, `any-of: DAST-B-01`, `any-of: CLOUD-C-01`. Run 1 `scan.sh all` on a runner with no cloud credentials, so `CLOUD-C-01` is never covered; A and B fire; composite fires with `contributors = [A, B]`. Run 2 identical invocation, B remediated** | **`unknown`** | **a bare subset test: the prior cell set for `CLOUD-C-01` is empty, empty is a subset of anything, so (b2) holds vacuously and the composite is reported `fixed (chain broken)` while the alternative that could keep `A ∧ (B ∨ C)` live was never assessed in either run** |

Cases 5, 6, 7, and 8 are new, and each is the only case in the set that discriminates its condition:
under the round-2 rule every one of them returns `fixed (chain broken)` while cases 1 to 4 still pass, so
the previous suite certified the defect green.
Case 5 additionally pins that `--profile-scan quick` reaches the same hole independently of `--intensity`
(originally "independently of open finding F8"; F8 - `derived` falling outside every `--intensity`
tier - is now closed, so `--intensity` alone no longer drops a composite at all, and `--profile-scan`/
`--allow-intrusive` are the two filters condition (a) still has to guard against).
Case 6 **varies the region rather than the module**, deliberately: an earlier draft of it dropped the
module owning the never-fired alternative, which is the one condition under which the weak
"covered in at least one cell" test and the strict subset test agree, so it would have certified the weak
test green.
Keeping every module selected and narrowing only the region is what makes it discriminate.
`COMPOSITE-TOKEN-HIJACK` is seeded in `rules/derived.rules` as part of §13 step 1, since `findings.sh`
lands there, but its contributors do not exist until steps 5 and 6, so until then the composite is
correctly and visibly `unknown` in every run.
Appendix A's remaining composite classes are added as data.

## Tension 7 - identifier namespaces

**The tension.**
§4's finding example carries `"id": "SAST-PY-EVAL-0007"`.
§6.2's rule records carry ids of the shape `PY-EVAL-01`.
Appendix A calls the same thing a "check id".
The `-0007` suffix in the §4 example reads as a per-occurrence counter.

**Why it bites.**
If `id` is per-occurrence, it is unstable: it depends on how many matches came before it, so inserting
an unrelated finding renumbers everything after it.
That would make `id` useless for SARIF (whose `ruleId` must be stable and must appear in `driver.rules`)
and it would collide conceptually with `fingerprint`, which already exists to be the per-occurrence
identity.
If `id` is per-check, then a field named `id` is not unique per record, which is a trap every downstream
consumer walks into exactly once.
The mismatch between `SAST-PY-EVAL` and `PY-EVAL` also leaves it undecided whether the module prefix is
authored or derived, and `covered_checks` in `state/` needs one canonical answer.

**Options considered.**

1. *Keep `id` as the per-check id and document that it is not unique.*
   Rejected: the name actively misleads, and the failure shows up as a silent dedup bug in a consumer,
   not as an error here.
2. *Keep `id` per-occurrence and add `rule_id`.*
   Rejected: a per-occurrence id is unstable by construction and duplicates `fingerprint`.
3. *Rename to `check_id` and drop `id` entirely.* **Chosen.**

**RESOLUTION.**
Exactly two identifiers exist, and there is no third.

- **`check_id`** identifies the *check*.
  It is the rule record's `id`, authored in full including the module prefix
  (`SAST-PY-EVAL-01`), with the linter enforcing that the prefix matches the owning module (E018) and
  that the id is unique **within the check-id namespace** (E019) - that is, across every record file
  that carries check ids, and *not* across every record file in the repository.
  The distinction is load-bearing: `config/discovery.conf` and `config/auth.conf` ids are *required* to
  name `config/scope.conf` targets, so a global rule would make every correct config a lint error.
  `rules/RULE-FORMAT.md` §9.1.1a is the normative namespace table.
  Format is frozen in `rules/RULE-FORMAT.md` §9.1.1.
  It is the SARIF `ruleId`, the Appendix A check id, the key of `covered_checks` in `state/`, and an
  input to the fingerprint.
- **`fingerprint`** identifies the *occurrence* (tension 5).

The finding schema field is named **`check_id`**, and emitters MUST NOT emit a field named `id`.
This supersedes the field name in the §4 example of `docs/DESIGN.md`, and the `-0007` occurrence suffix
in that example is dropped: **there is no per-occurrence sequence number anywhere in the system.**
The `-01` suffix in a check id distinguishes sibling rules within a family, not occurrences of a match.

Check ids are stable forever.
Renaming one makes every historical finding for it `fixed` and every current one `new`.
Retirement is: delete the record, add the id to `rules/RETIRED.txt`, and the linter fails if a retired
id is ever reused (E028, E062).

**Consequence for the build.**
`lib/findings.sh` and the JSON/SARIF emitters use `check_id` from §13 step 1, so nothing is ever written
with the old name.
`lib/report.sh` emits the full loaded rule catalog as SARIF `driver.rules`, which is only possible
because ids are stable and authored, not generated.

## Tension 8 - base severity versus rubric adjustment

**The tension.**
§4 says each check declares a base severity and that "`findings.sh` **may** adjust it from a small
CVSS-style rubric ... so severity is reproducible and defensible".
"May adjust" does not say which wins, when the adjustment applies, or what makes it deterministic.
§5 then gates CI on severity with `--fail-on`, so this is not cosmetic.

**Why it bites.**
Three concrete failure modes.
If the rubric's inputs include anything outside the finding record - the time of day, a DNS lookup, the
order results arrived in - then the same scan of the same code produces different gate outcomes on
different runs, and a flaky security gate gets disabled within a week.
If "may" means the rubric sometimes runs, an author cannot predict the severity their rule produces, so
severity becomes exactly the "per-author guesswork" the sentence says it is replacing.
And a rubric with no bounds can silently demote a hardcoded private key to `low` because it happens to
sit in an internal-only service, which is not a judgement the rubric is entitled to make.
Separately, the model carries `confidence` and nothing in the spec ever consumes it, so it is unclear
whether a `low`-confidence `critical` should fail a build.

**Options considered.**

1. *Base severity always wins; the rubric is advisory.*
   Rejected: then it is decoration, and §4's "reproducible and defensible" claim is unearned.
2. *The rubric always wins; the base is a hint.*
   Rejected: it discards the check author's knowledge, which is the only source of truth for things the
   rubric cannot see.
3. *Rubric as a bounded, total, pure function over recorded facts.* **Chosen.**

**RESOLUTION.**
The rubric **always** runs.
It is a pure, total function whose only inputs are fields already recorded on the finding, over an
ordinal scale `info`=0, `low`=1, `medium`=2, `high`=3, `critical`=4:

```
final = clamp( base + Σ modifiers , floor , ceiling )
```

The modifier table is frozen data in `data/severity-rubric.conf` (in the frozen record format,
tension 26), so it is reviewable and diffable rather than buried in code:

| Fact recorded on the finding | Modifier |
|---|---|
| `exposure: internet` | +1 |
| `exposure: internal` | -1 |
| `exposure: unknown` | 0 |
| `auth: none` (reachable unauthenticated) | +1 |
| `auth: user` | 0 |
| `auth: admin` | -1 |
| `sensitive_data: true` (match or response touches a configured sensitive field or a secret) | +1 |
| `confidence: low` | -1 |
| `confidence: medium` or `high` | 0 |

The sum is clamped to `[0, 4]`, then to the rule's optional `severity-floor` and `severity-ceiling`.
Floors are how a check author keeps the rubric from demoting something it cannot judge: the hardcoded
private key rule declares `severity-floor: high` and the rubric cannot go below it.

Determinism is a hard guarantee, not an aspiration:

- The rubric may read **nothing** outside the finding record.
  No wall clock, no random, no host state, no network, no ordering.
- Facts absent from a finding take their documented default (`exposure: unknown`, `auth: user`,
  `sensitive_data: false`), so the function is total and never depends on whether a module bothered to
  set a field.
- A test re-runs the rubric over a recorded `findings.jsonl` fixture and requires byte-identical output.

**The CVSS vector is an output, not an input.**
It is generated from the same facts by a frozen mapping and stored for auditability, so it can never
disagree with the severity it accompanies.

**Confidence** is not folded into severity beyond the single `-1` modifier above; it stays a separate
reported field.
The CLI gains `--min-confidence <level>` (default `low`, meaning everything gates) so a team can tune
the gate without hiding findings from the report.

The severity used for the `--fail-on` gate, for `state/`, and for the report is always the **final**
severity.
A severity change between runs does **not** change the fingerprint (tension 5), so such a finding stays
`recurring` and the report annotates it `recurring (severity high -> critical)`.

**Consequence for the build.**
§13 step 1 delivers `severity_of()` in `lib/findings.sh` plus `data/severity-rubric.conf`, and every
module records `exposure`, `auth`, and `sensitive_data` on the findings it emits.
`--min-confidence` joins the frozen CLI surface (tension 14).

## Tension 9 - redaction versus evidence versus fingerprint

**The tension.**
§14 requires that `redact_secrets` "scrubs secret-matching patterns from all evidence and reports".
§6.3's `secrets.rules` exists specifically to match secrets, so its evidence is entirely secret.
Tension 5 then puts a digest of the matched text into the fingerprint.
These three pull in opposite directions: evidence must be useful, secrets must not be disclosed, and
identity must distinguish two different secrets in the same file.

**Why it bites.**
Naive redaction makes secrets findings useless: every one reports `<redacted>` at some file, so a reader
cannot tell whether two findings are the same key twice or two different keys, and cannot tell which of
their credentials to rotate.
Naive non-redaction is worse: the scanner writes the customer's live AWS secret key into
`findings.jsonl`, into the HTML report, into `run.json`, into the terminal log, and then someone
attaches the report to a ticket.
The scanner becomes the exfiltration path it was built to prevent.
And there are two shell-specific traps that a careful design still walks into: passing a secret as a
command-line argument makes it visible in `ps` to every user on the host, and writing it to a scratch
file leaves it on disk even after the `EXIT` trap shreds the directory, if the run is killed with
`SIGKILL`.

**Options considered.**

1. *Redact, then fingerprint the redacted text.*
   Rejected: all secrets of one kind redact to the same string, so every hardcoded key in a file
   collapses into one finding.
2. *Do not redact secrets findings, on the grounds that the operator already has the secret.*
   Rejected: the report is a document that travels, and §14 is unconditional.
3. *Two distinct transforms with different domains.* **Chosen.**

**RESOLUTION.**
Two functions, clearly separated, both in `lib/findings.sh`.

- **`redact(text)`** produces what is written anywhere: evidence, logs, `run.json`, JSON, SARIF,
  Markdown, HTML.
  Each match of a rule in `rules/redaction.rules` (frozen record format,
  `rules/RULE-FORMAT.md` §9.3) is replaced with `<redacted:KIND:DDDDDDDD>`, where `KIND` is the
  redaction rule's kind token (`AWS_SECRET`, `JWT`, `PRIVATE_KEY`, `BEARER`) and `DDDDDDDD` is the first
  8 hex characters of the SHA-256 of the raw matched bytes.
  The short digest is what makes the redacted report usable: a reader can tell two distinct secrets
  apart and can recognise the same secret appearing in three places, without the secret being present.
  8 hex characters is 32 bits, which is far too little to invert a high-entropy secret and ample to
  distinguish the handful of secrets in one report.
- **`fingerprint_digest(text)`** consumes the **raw** matched text, hashes it, and returns 16 hex
  characters.
  Only the hash is retained.
  Because it hashes the raw text, two different keys in one file are two different findings, which is
  what tension 5 needs.

Three handling rules make this safe in shell, and are enforced by lint:

1. **A secret is never a command-line argument.**
   `sha256_of` reads **stdin only** (`printf '%s' "$x" | sha256_of`), and `printf` is a builtin so the
   value never appears in any process's `argv`.
   The lint fails on any call passing a variable holding matched text to an external command as an
   argument.
2. **Raw matched text never touches disk.**
   It is hashed and redacted in-process; only the redacted form is written to the shard files.
   `scan_match` writes matching *lines* to the scratch dir, so the scratch dir is created mode `700`
   inside a `umask 077` and is erased on exit by `erase_dir` (tension 24), and `config/scanner.conf`
   gains `scratch-dir` so an operator can point it at a tmpfs.
   **The tmpfs is the real control, and the erasure is best effort**: overwriting achieves nothing on
   APFS, journalled ext4, tmpfs, or an SSD with wear levelling, and `shred` does not exist on macOS at
   all (finding F16).
   Saying "shredded" without that qualification claimed a guarantee the primitive cannot deliver, on a
   platform where the primitive is absent.
3. **Evidence is only ever set through `finding_set_evidence`,** which applies `redact`, truncation
   (tension 10), and control-character stripping in that order.
   The lint fails on any direct assignment to an evidence field.

Redaction rules are data, so adding a new secret shape is a data change, matching §16.
`redact_secrets=false` is permitted but is recorded prominently in `run.json` and printed as a banner in
every report, because a report generated without redaction must be visibly identifiable as one that must
not be circulated.

**Consequence for the build.**
§13 step 1 delivers `redact`, `fingerprint_digest`, `finding_set_evidence`, and
`rules/redaction.rules`.
A test asserts that a fixture containing a known key produces a report containing zero occurrences of
that key across all four output formats, and that two different keys in one fixture file yield two
distinct fingerprints and two distinct redaction digests.

**AMENDMENT - `redact()` alone does not deliver this RESOLUTION, and a second layer was added.**
The RESOLUTION above makes `redact()` the thing that "produces what is written anywhere", and derives
its behaviour from `rules/redaction.rules`.
That is a *shape* test, and the shape list is maintained independently of the secrets checks in
`modules/*/rules/*.rules` - so the two could drift, and did.
`secrets.rules` matches a generic quoted `password = "..."` literal and an uppercase
`API_KEY = "..."`; `redaction.rules` carried a pattern for neither; so with `redact-secrets: true` in
force the raw credential was written in the clear into `findings.jsonl`, `findings.json`,
`findings.fields`, `report.md`, `report.html` and the per-worker shards.
Two further shapes - a bare `AKIA...` access key id and a lowercase `api_key = "..."` - were masked
only *incidentally*, by the PEM-body and Bearer rules, under a `kind` that does not describe them,
which is the same defect wearing a passing test.

The "Consequence for the build" paragraph above is where this hid.
Its test was written, and passes, over a fixture key whose shape `redaction.rules` already knew
(`aws_secret_access_key = ...`), so it certified the property for the one case that could not fail it -
the failure mode this register elsewhere insists on avoiding, a test that agrees with its author's
reading rather than pinning it.

**The correction is a second, independent layer, not another pattern.**
Adding the two missing patterns would have closed those two holes and left the mechanism that produced
them exactly as it was.
A finding produced by a check whose whole purpose is finding a credential now never carries that
credential as evidence, whatever `redaction.rules` contains: `finding_set_secret_match`
(`lib/findings.sh`) is the setter such an emitter calls, and `_finding_secret_backstop`, called from
`finding_emit` - the one point every finding passes through on its way to a shard - re-checks it, so
the guarantee covers every format downstream of the merge including a SARIF emitter that does not
exist yet.
This is *provenance*, and it needs no list of shapes: a secrets check landing tomorrow is covered on
the day it lands.

`redact()` and `rules/redaction.rules` are unchanged in role and are still required.
They are what mask a credential appearing *incidentally* - in another check's evidence, in a crawled
URL's query string, in a log line, in an adapter-supplied title - which the provenance layer cannot
see.
The two layers answer different questions and neither subsumes the other.

**Second amendment: the incidental layer had two holes of its own, and both were measured.**
The provenance arm is scoped to modules `sast` and `iac`, correctly - a `dast` finding's evidence is a
composed sentence, so masking the field whole would destroy the finding and hide no credential.
That leaves `rules/redaction.rules` as the **only** layer over the twelve `dast` emitters, and its
shape list did not cover a URL: `SAST-REDACT-PASSWORD-01` and `SAST-REDACT-API_KEY-01` both REQUIRE the
value to be quoted, which a query string never is, and no rule parsed an authority at all.
A finding carrying a crawled `https://user:pw@host` and one carrying `?password=...` wrote both values
in the clear into `findings.jsonl`, `findings.json`, `findings.fields`, `report.md`, `report.html` and
both per-worker shards - seven files, every report format.
`SAST-REDACT-URL_USERINFO-01` and `SAST-REDACT-URL_PARAM_CREDENTIAL-01` close it.
This also makes true, for the first time, a promise tension 19's own **Auditability** paragraph
already made in this document: that "a userinfo credential embedded in the rejected URL is redacted
(tension 9) rather than landing in the report in the clear."
It was not - nothing matched userinfo - so that sentence described an intended property rather than an
implemented one, and a scope-violation finding would have reported the credential it rejected.

Separately, `finding_emit` is the single chokepoint for **findings** and is not the only **output
path**.
`run_record` (`lib/core.sh`) appends a run-level fact straight into `meta/<key>`, which `lib/report.sh`
renders into `run.json`, `report.md` and `report.html`, and it is not a finding - so a canary planted
through `finding_emit` can never reach it.
Measured: one `run_record` carrying a userinfo URL put the credential in the clear into all four.
Both `lib/core.sh` writers, `run_record` and `_log`, now route through `_redact_out`.
Its two guards are each load-bearing rather than defensive: `redact()` lives in `lib/findings.sh`,
which reaches `lib/core.sh` through `lib/records.sh`, so the `declare -F` guard is forced and is
exactly the shape that fails SILENTLY on a rename - `tests/suites/secret-redaction.sh` section I
therefore pins the name by asserting real masked output rather than a return value; and `redact()`
matches through `scan_match_stdin`, which calls `die` on an engine failure, and `die` logs, so without
the reentrancy flag `_log` recursed until the stack gave out on precisely the error path a scanner most
needs to be able to report.

**Nothing in the RESOLUTION above is reversed by this**, which is why it is an amendment rather than a
new resolution.
In particular, rejected option 1 stays rejected: `fingerprint_digest` still consumes the **raw**
matched text, so two different keys in one file remain two findings, and `finding_set_secret_match`
computes `loc_match_digest` byte-identically to `finding_set_match` - load-bearing, because
`modules/sast/adapters/gitleaks/adapter.sh` dedups against native `SAST-SEC-*` findings by comparing
that digest.
Two distinct secrets still render as two distinct `<redacted:KIND:DDDDDDDD>` placeholders, for the
reason the RESOLUTION gives.
The `KIND` on a provenance-masked value reads `SECRET` rather than the shape name, and that costs a
reader nothing here: `check_id` already says which kind of secret it is, which is precisely what is not
true of the incidental matches `redact()` exists for.

**Cost of the amendment.**
One new setter and one backstop in `lib/findings.sh`; six emitters updated to call the setter
(`modules/sast/engine.sh`, `modules/sast/history.sh`, `modules/iac/parse.sh`, and the gitleaks,
semgrep and trivy adapters); `_sast_check_is_sensitive` reduced to a delegation so the family list
exists once; and `modules/sast/engine.sh`'s match-count truncation notice no longer sets evidence,
because it is a meta-finding wearing the truncated check's own id and the string it set was already
its title verbatim.
`tests/suites/secret-redaction.sh` is the register's own missing test, rewritten to assert the
*property* - the planted value is absent from every byte the run wrote, over a recursive walk of the
run directory - rather than any pattern being present, because a pattern assertion goes green again
the next time the two lists drift.

## Tension 10 - untrusted evidence rendered into reports

**The tension.**
§4 requires a "self-contained **HTML** (human report, no external assets - inline CSS, no CDN, honors
no-egress)" with "per-finding cards with evidence".
That evidence is, for every DAST finding, bytes the scanned target chose to send.

**Why it bites.**
A security scanner that renders attacker-influenced bytes into HTML without escaping is a stored XSS
delivery mechanism, and the payload lands in the browser of the security engineer reading the report,
usually on an internal host, usually authenticated to things.
The §7.3 XSS check makes this concrete and unavoidable: it injects a marker and records the reflected
response as evidence, so evidence containing HTML markup is not an edge case, it is the expected content
of that check's findings.
The same applies at three more boundaries: a response body containing a raw newline corrupts
`findings.jsonl` (one finding per line), a response containing ANSI escape sequences can rewrite the
operator's terminal when logged (including hiding subsequent output), and a Markdown report is broken
out of by a backtick run inside the evidence.
The "no external assets" requirement helps but does not solve it, because inline script is not external.

**Options considered.**

1. *Escape at each emitter.*
   Rejected on its own: four emitters times every field is four places to forget, and the one that gets
   forgotten is the one that matters.
2. *Strip all non-alphanumeric characters from evidence.*
   Rejected: it destroys the evidence, which is the whole point of the field.
3. *Escape at a chokepoint, plus defence in depth in the HTML itself.* **Chosen.**

**RESOLUTION.**
Evidence is normalised once, on the way in, and escaped once per emitter, on the way out.

**On the way in**, `finding_set_evidence` is the only path to the field and applies, in order:

1. `redact` (tension 9).
2. Strip all C0 control characters except none (that is, all of `0x00`-`0x1F` and `0x7F` are removed),
   which kills ANSI escape sequences, embedded NULs, and stray CR and LF.
   Line structure that matters is preserved by replacing each stripped LF with a literal `\n` two-byte
   sequence before stripping.
3. Replace invalid UTF-8 bytes with `\xNN`, so every downstream format receives valid UTF-8.
4. Truncate to `evidence_max_bytes` (default 512), on a UTF-8 character boundary, appending
   ` ...[truncated]`.

The result is guaranteed single-line, valid UTF-8, control-character-free, and bounded, which makes
`findings.jsonl` structurally safe by construction rather than by the JSON writer's care.

**On the way out**, per emitter:

- **JSON / JSONL / SARIF**: standard JSON string escaping, applied by one writer function.
  No string is ever interpolated into JSON by `printf` at a call site; the lint fails on it.
- **HTML**: escape `& < > " '` to entities.
  Evidence is placed **only in text nodes**, never in an attribute, never inside `<script>` or
  `<style>`.
  The report contains **no `<script>` element at all**; interactivity is `<details>`/`<summary>`, which
  needs none.
  The document carries
  `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`,
  so even a defect in the escaping cannot execute script or make a network request.
  That last clause is also what makes the HTML report genuinely honour the no-egress model of §2 rather
  than merely not shipping a CDN link.
- **Markdown**: evidence is emitted inside a fenced code block whose fence is one backtick longer than
  the longest backtick run in the content, with a minimum of three.

**Consequence for the build.**
§13 step 1 delivers `finding_set_evidence` and the escaping functions, before any emitter is written.
`tests/` includes a hostile-evidence fixture: a recorded mock response containing
`</script><img src=x onerror=alert(1)>`, a raw ANSI sequence, a raw newline, invalid UTF-8, and a run of
five backticks.
The test asserts the JSON parses, the JSONL has one line per finding, the SARIF validates, the HTML
contains no unescaped `<`, and the Markdown fence is not broken.
The CSP meta tag is asserted present.

## Tension 11 - baseline versus diff versus the CI gate

**The tension.**
§9a defines `state/` for run-to-run diffing and `baseline.json` as the accept-risk list, and says "the
two are distinct".
§5 defines `--fail-on` and §9a defines a "fail only on new findings" mode.
Nothing states the order in which suppression, classification, gating, and persistence happen, and every
ordering produces different and mostly wrong behaviour.

**Why it bites.**
Suppress before diffing, and a baselined finding is invisible to `state/`, so the day someone removes
the baseline entry the finding reappears as `new` even though it has been there for a year, and a
`--fail-on-new` gate fires on a year-old issue.
Suppress before diffing and a baselined finding that is genuinely fixed is never reported fixed, so the
baseline accumulates entries for issues that no longer exist and nobody ever prunes it.
Persist state after suppression, and the same thing happens one layer down.
Separately, §11 specifies `baseline.json` as "array of accepted fingerprints", a bare string array,
which records no reason and no expiry, so a baseline is a list of 400 opaque hashes that no reviewer can
evaluate and that never shrinks.

**Options considered.**

1. *Suppress as early as possible, to keep later stages cheap.*
   Rejected for all the reasons above.
2. *Treat baseline as a diff input, so baselined findings are "prior".*
   Rejected: it conflates "we accept this" with "we have seen this", which §9a explicitly separates.
3. *A single frozen pipeline where suppression is a late annotation, never a deletion.* **Chosen.**

**RESOLUTION.**
The pipeline is frozen in this order, and every stage is a named function in `lib/findings.sh`:

1. **Collect** raw findings from modules.
2. **Normalise and fingerprint** (tension 5).
3. **Merge and dedup** native results with adapter results (§6.4) on fingerprint.
   This is a merge of one finding seen by two engines, **not** a collapse of distinct occurrences:
   fingerprints are unique per occurrence (tension 5), and adapter results are normalised onto the
   native location model before comparison.
4. **Derive** composite findings (tension 6).
5. **Classify** against `state/` into `new` / `recurring` / `fixed` / `unknown` (tension 12).
   This step also sets one run-level boolean, **`diff_usable`**, which step 7 reads.
   It is false when there is no prior state, when `state/latest.json`'s `fp_schema` does not match this
   build's, and when its `scan_root_id` does not match this run's for the `path-root` cells this run
   scanned (tension 12).

   **`diff_usable` governs the gate only. It never overrides a `status`.**
   Statuses are assigned by tension 12's classification table and by nothing else, and that table already
   answers all three cases without help:

   - **No prior state.** Every finding is absent-then-present, which is the table's `new` row.
     A first run's findings are `new`, they are persisted `new`, and the first report a team ever sees
     counts them as `new` - which is what makes the "baseline after the first red build" workflow
     (tension 14) mean anything.
   - **`fp_schema` mismatch.** Tension 12 treats the prior set as empty, so the table has no prior
     finding to match and every finding this run produced is again `new`, with the prior findings
     persisted `unknown` and the report saying the schema changed and a baseline rebuild is required.
     Note it is the emptied prior set, not the raw table, that gives this answer: run against the prior
     set intact, the table's `present, covered | absent | fixed` row would report the whole backlog
     remediated.
   - **`scan_root_id` mismatch.** As above, for `path-root` cells only.

   An earlier draft of this step said `status` was `unknown` for every finding in these cases.
   That contradicted the table, which is the owner of classification, and the two would have persisted
   different `status` bytes for every finding of every first run.
   It is withdrawn: `unknown` means "this run did not assess it", and a first run assessed everything it
   found.
   The gate still fails closed in all three cases, because step 7 keys on `diff_usable` rather than on
   `status`.
6. **Suppress**: for each finding matching a baseline entry, set `suppressed: true` and
   `suppressed_by: <entry id>`.
   **Never delete.**
7. **Gate**: `--fail-on` considers only findings where `suppressed == false` and `confidence >=
   --min-confidence`.
   When `--fail-on-new` is given, it additionally requires `status == new` **if and only if
   `diff_usable` is true**; when `diff_usable` is false, `--fail-on-new` gates on **all** findings this
   run regardless of status.
   The carve-out is not optional wording.
   It is what makes the gate fail closed without touching classification: an `fp_schema` bump makes every
   finding `new` and a bare `status == new` predicate would then happen to gate correctly, but a run
   whose prior state is present and merely *stale in part* would not, and relying on that coincidence is
   how the fail-open shipped in the first place.
   Unusable prior state and absent prior state are the same situation at the gate and get the same
   answer.
8. **Persist** `state/`: **all** findings, including suppressed ones, with their `first_seen` preserved.
9. **Report**: suppressed findings render in a separate collapsed "accepted risk" section with their
   reason, and are counted separately in every summary.

Because suppression is step 6 and persistence is step 8, removing a baseline entry never manufactures a
`new` finding, and a baselined finding that gets fixed is still reported `fixed` with a note to prune
the entry.

`baseline.json` is redefined as an array of **objects**:

```json
{ "fingerprint": "…", "reason": "accepted: internal-only, tracked in <ticket>",
  "added": "2026-07-30", "expires": "2026-10-30" }
```

A bare string is accepted and treated as `{fingerprint, reason: "", added: null, expires: null}`, so the
§11 shape still loads.
`expires` is the mechanism that stops a baseline from becoming permanent: after that date the entry
stops suppressing and the report says so.
An entry that matched nothing this run is reported as `stale` in `run.json` and in the report, so the
list shrinks under normal use.
`--baseline FILE` replaces `config/baseline.json` rather than adding to it.

**Consequence for the build.**
§13 step 7 (diff/state) implements steps 5, 6, and 8; step 1 implements 2, 3, 8's writer, and 9's
counting.
Tests cover each ordering hazard directly: unsuppress-does-not-create-new, suppressed-can-still-be-fixed,
expired-entry-stops-suppressing, stale-entry-is-reported.

## Tension 12 - diff soundness under partial runs

**The tension.**
§9a says every normal run automatically classifies findings against `state/` as new / recurring /
**fixed**.
§5 lets a run be a single module (`scan.sh sast`), a single profile (`--profile-scan quick`), a single
region set, or an aborted run (circuit breaker, exit 5).

**Why it bites.**
`fixed` is an inference from absence, and absence has two causes that a naive diff cannot tell apart:
the issue was remediated, or the check never ran.
So `scan.sh sast` after a full run reports every DAST, cloud, IaC, and SCA finding as **fixed**.
That is not a cosmetic bug.
§9a positions the delta as "the primary output for remediation-verification and regression gating", so
this makes the tool confidently report that the entire cloud posture was remediated because someone ran
a source-only scan.
It also poisons the persisted state, so the next full run reports all of them as `new`, and a
`--fail-on-new` gate fires on a backlog that was never fixed and never regressed.
`--profile-scan quick` and a circuit-breaker abort produce the same effect at finer granularity.

**Options considered.**

1. *Only diff full runs.*
   Rejected: §9a's CI mode is most valuable on the fast partial runs, and it would make `quick`
   diff-less.
2. *Diff per module, comparing only findings whose module ran.*
   Rejected: too coarse.
   Inside one module, `quick` runs a subset of checks, and a breaker abort stops a module partway, so
   module granularity still manufactures `fixed`.
3. *Track coverage at check granularity alone.*
   Rejected: a check id cannot represent a region set or a DAST target, so
   `scan.sh cloud --live --regions us-east-1` after an all-regions run would mark every cloud check
   covered and report every prior finding in every other region as `fixed`.
   The same holds for `scan.sh dast --target a` after a run that covered `a` and `b`.
   That is the identical phantom-remediation failure surviving one level below the granularity chosen to
   fix it, and §8.1 makes multi-region iteration a correctness requirement, so this is the ordinary
   deployment shape rather than an edge case.
4. *Track coverage at (check, scope) granularity and only infer `fixed` inside a covered cell.*
   **Chosen.**

**RESOLUTION.**
`state/` records **coverage**, not just findings, and coverage is **scoped**.
Each run writes `state/<run-id>.json` plus a `state/latest.json` pointer:

```json
{ "fp_schema": "fp/1", "tool_version": "…", "run_id": "…", "completed_at": "…",
  "scan_root_id": "git-remote:https://example.invalid/org/proj",
  "covered_checks": {
    "SAST-PY-EVAL-01":     {"rule_digest": "…", "scope": "path-root",     "cells": ["src"]},
    "SAST-HIST-AWSKEY-01": {"rule_digest": "…", "scope": "path-root",     "cells": ["."],
                            "history_boundary": {"oldest_commit": "<sha>",
                                                 "oldest_commit_time": "2025-08-01T00:00:00Z",
                                                 "objects_scanned": 12345,
                                                 "bound_by": "window-days"}},
    "CLOUD-EC2-SG_OPEN-01":{"rule_digest": "…", "scope": "account-region",
                            "cells": ["123456789012/us-east-1", "123456789012/eu-west-1"]},
    "DAST-XSS-REFLECT-01": {"rule_digest": "…", "scope": "target",        "cells": ["staging"]} },
  "findings": [ {"fingerprint": "…", "check_id": "…", "cell": "…", "severity": "…",
                 "first_seen": "…", "last_seen": "…", "suppressed": false,
                 "oldest_reaching_commit_time": "…",
                 "contributors": ["…"]}, … ] }
```

Four of those fields are conditional or need their value pinning, and are listed here rather than only in
the tension that consumes them so that the persisted shape and its consumers agree in one place:

- `covered_checks[].history_boundary` is present for `SAST-HIST-*` checks only, and
  `findings[].oldest_reaching_commit_time` for their findings only.
  Both are what tension 13's per-finding rule reads.
- `findings[].contributors` is present for derived findings only, and is what tension 6's
  contributor-coverage classification reads.
  Each contributor fingerprint resolves to another entry in the same `findings` array, from which its
  `check_id` and `cell` are read - so the pairs that rule tests are looked up, never inferred.
- **`findings[].cell` is present on every finding, and for a derived finding its value is JSON `null`.**
  The key is never omitted and is never the string `"none"`.
  A derived finding has no coverage cell (its classification replaces the cell test entirely), and the
  earlier `none` sentinel was withdrawn because a string sentinel can collide with a real cell value -
  `none` is a legal `path-root` and a legal scope target id.
  `null` is unambiguous, and it makes "this finding is classified by contributor coverage" checkable in
  one comparison.
- `scan_root_id` is present on every run and gates whether any `path-root` cell is comparable at all.
  Its `<kind>:` prefix is part of the value, so two kinds can never collide on one string.

A **coverage cell** is the value of the scope dimension that partitions a check's findings.
The dimension is declared per check (`coverage-scope` in `rules/RULE-FORMAT.md` §9.5 for script checks;
implied by the module for pattern rules) and is frozen as:

| Module | `coverage-scope` | Cell value |
|---|---|---|
| SAST, IaC, containers, SCA | `path-root` | the `--path` root relative to the scan root |
| SAST history | `path-root` | the `--path` root relative to the scan root |
| DAST | `target` | the `config/scope.conf` target id |
| Cloud live | `account-region` | `<account_id>/<region>`, or `<account_id>/global` |
| Posture | `scope-key` | the expectation's `scope-key` |
| Derived | (none; `cell` is JSON `null`) | classified by tension 6's three-condition rule, not by a cell |

**The history cell does not carry the boundary.**
An earlier draft put the resolved history boundary inside the cell, which would have been a second,
incompatible coverage mechanism for one check family: cells are matched by exact value, so under a
rolling window the boundary moves every run, no prior cell would ever be a member of this run's cells,
and every history finding would be `unknown` forever.
That is the precise outcome tension 13 rejects and replaces with a per-finding ordering test.
**Tension 13 owns `SAST-HIST-*` classification**, and it composes with this section in two layers rather
than competing with it:

1. This section's cell test runs first, on `path-root` like any other SAST check.
   An uncovered path root gives `unknown` and tension 13 is not consulted.
2. Inside a covered cell, tension 13's boundary comparison decides between `fixed` and `unknown`.

So there is one owner per layer and no case in which both mechanisms answer the same question.

**How a cell is obtained.**
Every finding **records its `cell` explicitly when it is emitted**; that recorded value is what
`state/` persists and what classification compares.
It is not always re-derivable from the location, and the earlier blanket claim that it was is withdrawn:

- Cloud, DAST, and posture findings: the cell *is* a projection of the location components (tension 5),
  so the two cannot drift.
  `account-region` is a cloud finding's first two components, `target` is a DAST finding's first, and
  `scope-key` is a posture finding's second.
- SAST, history, IaC, and SCA findings: the cell is the run's `--path` root, which is a **run
  parameter**, not part of the finding's identity.
  It is not recoverable from the location and is not meant to be: `src/sub/x.py` is consistent with a
  root of `.`, `src`, or `src/sub`, and an SCA finding's location carries no path at all.

A cell is never a fingerprint input, in either case.
Recording it rather than deriving it is what keeps identity stable while coverage varies per run.

**The scan root.**
Everything below, and every "repository-relative path" elsewhere in these documents, is relative to the
**scan root**, which is frozen here because nothing else defined it and it decides a fingerprint input, a
`unit_key` input, a glob base, and a persisted cell string.

```
--path              defaults to "." when omitted
resolved_path    =  realpath_of("$--path")            # absolute, symlinks followed (tension 24)
scan_root        =  git -C "$resolved_path" rev-parse --show-toplevel   # if it succeeds and is non-empty
                    else resolved_path                                  # not a git repo, or git absent

# scan_root_id is "<kind>:<value>" - the kind prefix is part of the id, so
# two different kinds can never collide on one string.
if scan_root came from git:
    url = git -C "$scan_root" config --local --get remote.origin.url   # --local: see (5)
    url = url with one trailing "/" then one trailing ".git" stripped  # normalise FIRST
    url = url with any userinfo removed:                               # see (4)
              "<scheme>://<user>[:<pass>]@<rest>"  ->  "<scheme>://<rest>"
              "<user>@<host>:<path>"               ->  "<host>:<path>"
    if url is non-empty:  kind = "git-remote"; value = url             # test AFTER normalise
    else:                 kind = "git-local";  value = scan_root       # absolute path
else:                     kind = "path";       value = resolved_path   # absolute path
```

**`scan_root_id` MUST NOT contain credentials.**
It is written to `state/<run-id>.json`, to `run.json`, and into the `run_identity` hash (tension 18), so
a credential in it is a secret on disk, which tension 9 forbids without qualification.
The userinfo strip is not a tidiness step; it is that rule applied here.

**This recipe was chosen by running it, not by reasoning about it.**
The obvious identity - the repository's root commit - reads correctly and fails three ways in practice,
including on the *default* CI checkout.
All output below is real, from `git version 2.54.0`, with the probe directory rewritten to `/tmp/probe`
for width:

```
# (1) commit-less repository: the git branch is taken, and the root-commit recipe returns nothing
$ git init -q A && cd A
$ git rev-parse --show-toplevel; echo "exit=$?"
/tmp/probe/A
exit=0
$ git rev-list --max-parents=0 --all; echo "exit=$? lines=..."
exit=0 lines=0

# (2) shallow clone (--depth 1, what actions/checkout does by default):
#     grafted commits are reported parentless, so the recipe returns the TIP, not the root
$ git -C shallow rev-list --max-parents=0 --all
d386ff1dec3434c3f30689a7d392828bd1b99de9
$ git -C shallow rev-parse HEAD
d386ff1dec3434c3f30689a7d392828bd1b99de9
$ git -C B rev-list --max-parents=0 main      # the TRUE root
09e3153106d25eda557e3f48ca8a53925ef77c16

# (3) ref-set dependence: one repository with an orphan branch, two clone shapes, two ids
$ git -C full2   rev-list --max-parents=0 --all | sort | head -1
01c4cff55fdcc60cb98efe59f02bf9c91c597cda
$ git -C single2 rev-list --max-parents=0 --all | sort | head -1
09e3153106d25eda557e3f48ca8a53925ef77c16
```

Setup note for (2), because the transcript is not re-executable without it: `git clone --depth 1`
against a **local path** silently ignores the flag, so the shallow limb must be cloned over `file://`.
Git says so itself:

```
$ git clone -q --depth 1 "$SP/src" bypath
warning: --depth is ignored in local clones; use file:// instead.
$ git -C bypath rev-parse --is-shallow-repository ; git -C bypath rev-list --count HEAD
false
3
$ git clone -q --depth 1 "file://$SP/src" byfile
$ git -C byfile rev-parse --is-shallow-repository ; git -C byfile rev-list --count HEAD
true
1
```

Each failure is fatal in a different way.
(1) leaves `scan_root_id` **undefined**, so two unrelated commit-less trees scanned from one install
share the empty id and cell `.`, and the second run reports the first's findings `fixed` - the exact
collision this gate exists to forbid, reached through the one input the gate did not cover.
(2) makes the id **equal to `HEAD`**, so it changes on every commit, so `diff_usable` is false on every
run, so `--fail-on-new` gates on the entire backlog and the build fails forever with no operator action
able to converge it - the register's own remedy, "baseline after the first red build", never converges
because every run is a first run.
(3) falsifies the portability claim outright.

The replacement was then run against the same three constructions plus the collision cases it must keep
apart:

```
# read with THE FROZEN COMMAND. `git remote get-url` is NOT equivalent and must not be
# substituted: it applies url.<base>.insteadOf rewriting and returns the FIRST url of a
# multi-url remote, while `config --local --get` returns the raw LAST value. Measured:
$ git -C io config url.'git@host.example:'.insteadOf 'https://host.example/'
$ git -C io config --local --get remote.origin.url   ->  https://host.example/org/proj.git
$ git -C io remote get-url origin                    ->  git@host.example:org/proj.git
$ git -C io remote set-url --add origin https://host.example/org/mirror.git
$ git -C io config --local --get remote.origin.url   ->  https://host.example/org/mirror.git
$ git -C io remote get-url origin                    ->  git@host.example:org/proj.git

$ git -C B config --local --get remote.origin.url ; git -C shallow3 ... ; git -C single3 ...
https://example.invalid/org/proj.git
https://example.invalid/org/proj.git/
https://example.invalid/org/proj

# scan_root_id under the replacement recipe
A          git-local:/tmp/probe/A                        <- commit-less: defined
B          git-remote:https://example.invalid/org/proj
full3      git-remote:https://example.invalid/org/proj
shallow3   git-remote:https://example.invalid/org/proj    <- shallow == full == single-branch
single3    git-remote:https://example.invalid/org/proj

# after adding a commit to the shallow clone
shallow3   git-remote:https://example.invalid/org/proj    <- unchanged

# distinctness cases
B (superproject)       git-remote:https://example.invalid/org/proj
B/vendor/libfoo        git-remote:https://example.invalid/org/libfoo
C1 (commit-less)       git-local:/tmp/probe/C1
C2 (commit-less)       git-local:/tmp/probe/C2
tarball                path:/tmp/probe/tarball
tarball/frontend       path:/tmp/probe/tarball/frontend
```

The three URL spellings in that run differ by a trailing `/` and a trailing `.git`; the two-step
normalisation collapses them, which is why the three clones agree.

**The `--local` and userinfo clauses each close a defect that was measured, not imagined.**

```
# (4) credential leak. This is the standard GitLab Runner clone shape.
$ git -C gl config --local --get remote.origin.url
https://gitlab-ci-token:JOBTOKEN123@gitlab.example/org/proj.git
     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ a live job token, bound for state/, run.json and run_identity

#     and because the job token rotates per job, the id moved on every run, so path-root
#     cells were permanently incomparable and the gate could never converge:
     token=JOBTOKEN123 -> git-remote:https://gitlab.example/org/proj   # after the strip
     token=JOBTOKEN456 -> git-remote:https://gitlab.example/org/proj   # unchanged

# (5) --get reads global config too, so a stray global remote.origin.url collides
#     two unrelated remote-less repositories onto one id and one cell "."
$ printf '[remote "origin"]\n\turl = https://host.example/org/LEAK.git\n' > "$GIT_CONFIG_GLOBAL"
$ git -C R1 config --get remote.origin.url         ->  https://host.example/org/LEAK.git
$ git -C R2 config --get remote.origin.url         ->  https://host.example/org/LEAK.git
$ git -C R1 config --local --get remote.origin.url ->  (unset, exit 1)
     R1 -> git-local:/tmp/probe2/R1     # with --local: distinct again
     R2 -> git-local:/tmp/probe2/R2

# (6) normalise-then-test: a degenerate url of exactly ".git" normalises to empty and
#     must fall through to git-local rather than yielding a bare "git-remote:"
     origin=".git"  ->  git-local:/tmp/probe2/degen

# scp-like userinfo is stripped by the second form of the rule
     origin="git@host.example:org/proj.git"  ->  git-remote:host.example:org/proj
```

`git config --local --get` exits 1 when the key is unset, which under tension 4's mandatory
`set -Eeuo pipefail` aborts the run unless the call is written in a condition context (tension 4 rule 3).
That is a fail-loud error rather than a wrong id, and it is noted here so the implementer does not meet
it by surprise.

**What the replacement does and does not promise**, stated so nobody has to re-derive it:

- It is **defined for every input**, including a commit-less repository and a directory that is not a
  repository at all.
- It is **independent of clone depth and of which refs were fetched**, because it reads a config value
  rather than the object graph.
- It **distinguishes** a superproject from a nested repository, two unrelated commit-less repositories,
  and two nested non-git roots - the cases that would otherwise collide onto cell `.`.
- It is **portable across CI workspaces** for the ordinary case of a repository with an `origin` remote
  whose URL is not a local path, since the id then contains no checkout path.
  A remote named something other than `origin` falls to `git-local:`, and a local-path remote yields
  `git-remote:/abs/path`; both are workspace-bound.
- It **never contains a credential**, by the userinfo strip above.
- It reads **local config only**, so nothing outside the repository can supply or collide it.
- It does **not** unify different spellings of one remote beyond the trailing `/` and `.git`: an `ssh://`
  and an `https://` URL for one repository are different ids.
  That direction is safe - a differing id makes `path-root` cells incomparable, so nothing is reported
  `fixed` there and the gate goes fail-closed (tension 11 step 7).
  It is recorded in `run.json` so an operator who sees a permanently-unusable diff can see why.
- A repository with **no remote** falls back to its absolute path and is therefore not portable across
  workspaces.
  Same fail-safe direction.

"The repository root" is **not** scoursh's own install root.
That other sense survives in exactly one place, tension 26's config loader, and is called the *install
root* there so the two can never be confused.

**`path_root`, the cell string**, is then:

1. `resolved_path` expressed relative to `scan_root`, with `/` separators, no trailing `/`, no leading
   `./`.
2. The literal `.` when `resolved_path` equals `scan_root`, never the empty string.

Deriving `scan_root` from the git toplevel rather than from `--path` is what makes the cell
**cwd-independent**: `cd /repo && scan --path .` and `cd /repo/src && scan --path /repo` both yield
`scan_root = /repo` and cell `.`.
It is also what makes `state/` **portable across CI workspaces** for a git target, since neither the cell
nor `scan_root_id` contains the checkout path.

**Two distinct scan roots may never map to the same cell string.**
Exact-equality comparison alone does not deliver this: it only helps when two scopes produce *different*
strings, and the dangerous case is two scopes colliding onto the same one.
So **`path-root` cells** are comparable only between runs whose `scan_root_id` is equal; when it differs,
every prior finding *in a `path-root` cell* is `unknown` and no `fixed` is inferred there.

**The gate is scoped to `path-root` cells and to nothing else.**
`target`, `account-region`, and `scope-key` cells contain no filesystem path and are not derived from
`--path`, and `dast`, `cloud` and `posture` have no `--path` flag at all (`docs/DESIGN.md` §5).
A global gate would therefore let `scan.sh cloud --live` invoked from two different working directories
silently invalidate the entire cloud diff, for cells that a change of directory cannot affect.
That is fail-safe rather than dangerous, but it is a permanent, unfixable `unknown` on a module whose
diff has nothing to do with the scan root, so it is scoped out.

The scoped gate closes the two constructions this rule exists for, both of which are `path-root`:

- **Non-git target** (an unpacked tarball, ordinary usage since only `history.sh` needs git).
  `--path /srv/app` and `--path /srv/app/frontend` each become their own `scan_root`, so both would
  otherwise carry cell `.` and the narrower run would report every backend finding `fixed`.
  Their `scan_root_id` values are the two different absolute paths, so the cells are not comparable and
  the result is `unknown`.
- **Nested repository or submodule.**
  `--path /repo` and `--path /repo/vendor/libfoo` both resolve to a git toplevel, so both would otherwise
  carry cell `.`.
  Their remote URLs differ (or, with no remote, their absolute toplevels do), so again the cells are
  not comparable.

Within one `scan_root_id`, comparison is **exact string equality with no subsumption rule**.
`--path .` after `--path src` therefore leaves the earlier findings `unknown` rather than `fixed`, and
so does the reverse, even though one root contains the other.
That is deliberate: a subsumption rule would have to decide whether a wider root's coverage entitles it
to declare a narrower root's findings fixed, and getting that wrong is phantom remediation.
Failing to `unknown` in both directions is the conservative reading, and it is the one frozen here.

`scan_root_id` is recorded in `state/` alongside `fp_schema`.
A mismatch makes every `path-root` cell incomparable, so every prior finding in one is `unknown`.
Unlike an `fp_schema` mismatch it does **not** make the whole diff unusable, because it tells us nothing
about `target`, `account-region` or `scope-key` cells; `diff_usable` is set false only when the
*selected modules* are ones whose findings live in `path-root` cells.
For a run that scans both kinds, the `path-root` findings are `unknown` and the rest are classified
normally.

**One consequence, stated so it is not discovered later.**
Because `location.path` is scan-root-relative and is a fingerprint input (tension 5), a **git** target's
fingerprints are stable no matter which `--path` subtree a run scans, since `scan_root` is the toplevel
either way.
A **non-git** target's are not: there `scan_root` is the resolved `--path`, so `--path /srv/app` and
`--path /srv/app/frontend` record different relative paths for the same file and therefore different
fingerprints.
That is correct rather than a defect, and it is safe: those two runs also have different `scan_root_id`
values, so their `path-root` cells are not comparable and nothing is reported `fixed`.
The churn is confined to non-git trees, where there is no repository identity to anchor to, and it fails
in the conservative direction.

A (check, cell) pair enters `covered_checks` **only if that check ran to completion over that cell**.
It does not if the module was not selected, if a profile or intensity filter dropped the check
(tension 15), if the check was skipped for a missing dependency or an unavailable engine (tension 2),
if the circuit breaker aborted its module (tension 16), if a resumed run never reached it (tension 18),
or if the run simply never visited that region, target, or path root.

Classification is then, for a prior finding with `check_id` C and cell K:

| Prior finding | This run | Status |
|---|---|---|
| present, (C, K) covered | present | `recurring` |
| present, (C, K) covered | absent | **`fixed`** |
| present, (C, K) **not** covered | absent | **`unknown`**, carried forward with its original `first_seen` |
| absent | present | `new` |

The middle row is the whole point: `fixed` is inferred only inside a cell this run actually visited.
A region-scoped or target-scoped run therefore leaves every other region's and target's prior findings
`unknown`, exactly as a module-scoped run leaves other modules' findings `unknown`.

**Two families take a refinement of the `fixed` row, and nothing else in the table changes.**

- `SAST-HIST-*`: a covered cell is necessary but not sufficient.
  Tension 13's per-finding boundary comparison then decides `fixed` versus `unknown` within it.
- Derived findings: they have no cell of their own, and the whole `(C, K)` test is replaced by
  tension 6's three-condition rule.
  A composite is `fixed` only when **(a)** its own record was selected this run, **(b)** every check
  named in its `requires` and `any-of` is covered - contributors that fired by their recorded
  `(check_id, cell)` pair *and* by the same test that would let their own finding be `fixed`, listed
  checks that did not fire by being covered **this run** at all **and** having every cell the prior run
  covered them over revisited - and **(c)** the predicate no longer holds.
  Reading only the recorded pairs is not sufficient, for two reasons this section has to state because
  they are properties of the cell mechanism: a composite has no cell, so nothing else asks whether it was
  selected; and for a `SAST-HIST-*` contributor "cell covered" is precisely the signal the bullet above
  says is *not* sufficient, so a composite over a history contributor would otherwise be `fixed` while
  that contributor is itself correctly `unknown`.

Both refinements can only turn a `fixed` into an `unknown`, never the reverse, so the table remains the
upper bound on what may be claimed as remediated.

`unknown` findings are carried into the persisted state unchanged so that coverage gaps never erode
history, are excluded from the gate, and are shown in the report as "not assessed this run" with the
reason from `run.json`.

Two guards sit alongside it:

- **`fp_schema` or `scan_root_id` mismatch** between `state/latest.json` and this run makes the prior set
  **incomparable**, and the mechanism for that is stated here because the table above is the only owner
  of classification and would otherwise answer it wrongly.

  **The prior set is treated as empty for classification**, with one addition:

  - Nothing is reported `fixed`.
  - Nothing is carried forward as `recurring`.
  - Every finding *this run* produced takes the table's `absent | present` row and is therefore `new`.
  - Every *prior* finding is persisted `unknown`, with the mismatch recorded as the reason, so history is
    not erased.

  Saying only "nothing is reported `fixed`" would not have been enough, and the earlier wording that did
  say only that was wrong in a way worth recording.
  Follow the table literally after an `fp/1` to `fp/2` bump: the prior findings are present in `state/`,
  their `(C, K)` cells *are* covered because the run ran normally, and no prior fingerprint matches any of
  this run's - which is exactly the `present, (C, K) covered | absent | fixed` row.
  The table would have persisted the **entire backlog as `fixed`** and headlined it as remediated.
  Treating the prior set as empty is what stops the table reaching that row at all, and it is a
  mechanism rather than an assertion.

  The report says which of the two changed and that a baseline rebuild is required.
  Both set **`diff_usable = false`** (tension 11 step 5), and that flag - **not** any finding's `status` -
  is what the gate reads.
  Statuses come from the classification table above and from nothing else; `diff_usable` never overrides
  one.
  **The condition is fail-closed at the gate**: `--fail-on-new` gates on **all** findings, exactly as
  with no prior state, so a tool upgrade that bumps `fp/1` to `fp/2` cannot turn fifty criticals into a
  green build.
  This is stated identically in tension 11 step 7 (which owns the gate predicate) and tension 14 (which
  owns exit codes); a rule that lived only here would be contradicted by both.
  A `scan_root_id` mismatch is narrower than an `fp_schema` one: it makes only `path-root` cells
  incomparable, and sets `diff_usable = false` only when this run's selected modules put their findings
  in those cells.
- **`rule_digest`** is the SHA-256 of the rule record that defines a check.
  When it changes, findings for that check are still classified normally, but the report flags
  `rule changed - new/fixed for this check may reflect the rule edit, not a code change`.
  The gate still applies (fail closed), because a rule edit is not a reason to stop gating.

An automatic run diffs against `state/latest.json`; `scan.sh diff --against <dir>` overrides the source.
`state/` is pruned to `state_retain_runs` (default 30) newest runs plus `latest.json`.

**Consequence for the build.**
Every check must be registered with an id and a `coverage-scope` before it runs, and must report
completion **per cell**, which means `scan.sh` owns a check registry rather than each module tracking
its own, and a module must know which cells it is about to visit before it visits them.
That last requirement is the same one tension 18 imposes for `unit_key`, and it is satisfied by the same
enumerate-then-execute structure.
This is why check ids are authored and stable (tension 7), and why script checks are registered as
records (`rules/RULE-FORMAT.md` §9.5).
§13 step 7 implements it.
Each test below names the reading it fails under:

| # | Fixture | Must be | Fails under |
|---|---|---|---|
| 1 | Full scan, then `sast`-only | zero non-SAST findings `fixed` | module-blind coverage |
| 2 | All-region cloud scan, then `--regions us-east-1` | zero `eu-west-1` findings `fixed` | check-id-only coverage |
| 3 | Two-target DAST scan, then one `--target` | zero other-target findings `fixed` | check-id-only coverage |
| 4 | **Non-git tree: `--path /srv/app`, then `--path /srv/app/frontend`** | **zero backend findings `fixed`** | **a `path-root` cell that collapses each scan root to `.` without comparing `scan_root_id`** |
| 5 | **`--path /repo`, then `--path /repo/vendor/libfoo` where that is a nested repo or submodule** | **zero superproject findings `fixed`** | the same; both would otherwise carry cell `.` |
| 6 | **`cd /repo && scan --path .` versus `cd /repo/src && scan --path /repo`** | **identical cell, all findings `recurring`** | a cwd-derived or `--path`-derived root instead of the git toplevel |
| 7 | **Same git repo cloned to two different absolute paths** | **identical cells, all findings `recurring`** | embedding the checkout path in the cell or in `scan_root_id` |
| 8 | **Same repo as a full clone, a `--depth 1` clone, and a `--single-branch` clone of a repo carrying an orphan branch** | **one `scan_root_id` across all three; findings `recurring`** | **any object-graph identity: the root-commit recipe returns nothing, the tip, and two different shas respectively** |

Tests 1 to 3 pin the coverage granularity; only test 1 would have passed under check-id-only coverage.
Tests 4 to 7 pin the scan-root definition, and none of them existed while "the repository root" was
undefined: 4 and 5 are the two constructions that produce a false `fixed` by colliding two scopes onto
one cell string, and 6 and 7 are the cwd-independence and CI-portability properties that deriving the
root from the git toplevel is what buys.

## Tension 13 - git-history findings

**The tension.**
§6.3's `history.sh` "replays the same secret rules across **git history**", "bounded by a commit/time
window".
Findings from history have no working-tree line, are duplicated across every commit that touched the
file, and cannot be fixed by editing the working tree.

**Why it bites.**
Three failures compound.
First, the same secret in one blob touched by 400 commits produces 400 findings if identity is
commit-based, which buries the report.
Second, a history finding can never be `fixed` by any normal remediation, so under tension 12's rules it
recurs forever, and a team that has correctly rotated the credential still sees a permanent `critical`,
which trains them to ignore the whole category.
Third, the window is a coverage boundary that the diff does not know about: narrowing
`--history-since` from 365 days to 90 makes every finding outside the new window vanish and be reported
`fixed`, which is exactly the phantom-remediation failure of tension 12 wearing a different hat.
And the naive implementation, `git log -p`, rescans unchanged context once per commit, so it is both
quadratic and a source of duplicate matches.

**Options considered.**

1. *Fold history findings into the working-tree secret rules.*
   Rejected: they need different remediation (rotate plus purge, not delete the line) and different
   fixed-semantics.
2. *Identify by commit SHA plus path plus line.*
   Rejected: the 400-findings problem, plus renames change the path.
3. *Scan blobs, identify by blob.* **Chosen.**

**RESOLUTION.**

**Scan blobs, not diffs.**
`history.sh` enumerates reachable objects with `git rev-list --objects` bounded by the window, filters
to blobs, and reads them with `git cat-file --batch`.
Every distinct blob is scanned exactly once regardless of how many commits reference it.
This is simultaneously the correctness fix and the performance fix.

**Identity.**
History checks live in their own id family (`SAST-HIST-*`), so they are never confused with working-tree
checks.
The fingerprint location components are `blob_sha`, `match_digest`, then `occurrence` (tension 5).
All three, in that order.
`occurrence` is not optional here: a blob containing five byte-identical hardcoded secrets would
otherwise collapse into one fingerprint, which is exactly the collision tension 5 introduced the
discriminator to eliminate, and both tension 5's "unique within a run" guarantee and tension 17's
byte-reproducible merge depend on it holding for this module too.

**The history `occurrence` is scoped to the blob, not to a path.**
Tension 5 defines the ordinal as a rank "in the same file"; for history the unit is the blob, because
that is what this module scans and what its identity is keyed on.
One blob reachable at three paths across four hundred commits is scanned once and yields one set of
ordinals.
Scoping the ordinal to a path instead would reintroduce per-commit duplication through the back door,
since the same content is reachable under a renamed path.

Because a blob is content-addressed, the same secret in the same file content is one finding no matter
how many commits, branches, or tags reach it.
The finding's reported `location` carries the path, the earliest reaching commit, the line within the
blob, and the blob sha, for navigation.

**Relation to the working tree.**
A history finding is separate from a working-tree finding even when the secret is the same, but carries
`related: [<working-tree fingerprint>]` when their `match_digest` values match, and the report groups
them so a reader sees "this key is in the tree and in history" as one story with two remediations.

**Fixed semantics.**
A history finding is `fixed` when its blob is no longer reachable, which is what actually happens after
a history purge.
It is **never** `fixed` merely because the working tree changed.
Its `remediation` states the real fix explicitly: **rotate the credential first**, because purging
history does not un-disclose it, then purge the blob, then force-push and re-clone.

**The window is coverage, and coverage is measured on the commits actually reached, not on the config.**

The obvious rule - "compare `history_window_days` and `history_max_commits` against the prior run's, and
treat a narrower setting as reduced coverage" - is wrong, and wrong in the dangerous direction.
Both defaults describe a **rolling** window, so with no config change whatever, coverage shrinks at the
trailing edge on every single run: a blob reachable only from commits that have since aged past a
constant 365-day cutoff is simply absent from this run's enumeration.
The settings compare equal, the check looks fully covered, and a leaked credential still sitting in git
history is reported **`fixed`**.
`history_max_commits` does the same thing continuously on any active repository, from the moment the cap
starts binding.
That is a false all-clear on the one finding class this design explicitly says cannot be verified from
the working tree, and a settings comparison cannot see it.

So coverage is recorded as the **resolved boundary of the enumeration**, and it is compared per finding
rather than per check.
Each run records, for the `SAST-HIST-*` family in `state/`:

```json
"history_boundary": { "oldest_commit": "<sha>", "oldest_commit_time": "<iso8601>",
                      "objects_scanned": 12345, "bound_by": "window-days|max-commits|repo-root" }
```

and every history finding records `oldest_reaching_commit_time`, the committer timestamp of the earliest
commit that reaches its blob **within this run's bounded walk**.
It is not the globally earliest reaching commit: the value must describe what this run could see, and a
global minimum would push nearly every old finding to `unknown` permanently, which is the outcome this
resolution exists to avoid.
Both fields are part of tension 12's frozen `state/` shape, listed there so the two sections cannot
drift.

**This is the second of two layers, not a replacement for the first.**
Tension 12's `(check, cell)` test runs first, on `path-root` like every other SAST check, and an
uncovered path root gives `unknown` without ever consulting this rule.
The history cell carries **only** the path root; it deliberately does not carry the boundary, because
cells are compared by exact value and a boundary in the cell would make every prior history finding
`unknown` forever under a rolling window - the very outcome this rule is written to avoid.

Inside a covered cell, classification for a prior `SAST-HIST-*` finding absent from this run:

- If its `oldest_reaching_commit_time` is **at or after** this run's `oldest_commit_time`, the blob was
  inside the range this run actually walked, so its absence is real: **`fixed`**.
- If it is **before** this run's `oldest_commit_time`, this run could not have seen it whatever the
  config said: **`unknown`**.

Because this layer can only turn a `fixed` into an `unknown`, tension 12's table stays the upper bound
on what may be claimed as remediated, and the two layers cannot disagree.

One rule catches all three ways coverage shrinks - a rolling cutoff, a `max_commits` cap that has
started binding, and a manual narrowing - and it does not permanently blind the check the way a
whole-family exclusion would.
That matters: under a rolling window every run's boundary is more recent than the last, so excluding the
family whenever the boundary moves would make history findings `unknown` forever and a genuinely purged
secret would never be reported `fixed`.
Per-finding comparison keeps `fixed` reachable for everything still inside the walked range while
protecting everything outside it.
`bound_by` is recorded so the report can say *why* coverage ended where it did.

`history.sh` is skipped entirely, with a `run.json` reason, when the path is not a git repository or the
clone is shallow, since a shallow clone silently truncates history and would otherwise look like
remediation.

**Consequence for the build.**
`history.sh` lands at the end of §13 step 3 and needs `git rev-list`, `git cat-file`, and
`git rev-parse --is-shallow-repository`, which join the required-command probe (tension 24).
A fixture repository with a secret committed and then removed is part of `tests/fixtures/`.
**Each test below names the reading it fails under**, since the earlier suite consisted entirely of cases
where the correct and the rejected readings agree, and therefore certified the defect green:

| # | Fixture | Must be | Fails under |
|---|---|---|---|
| 1 | Secret in one blob reached by many commits | one finding, not one per commit | commit-keyed identity |
| 2 | Secret committed then removed from the working tree, blob still reachable | not `fixed` | working-tree-driven `fixed` |
| 3 | `history_window_days` narrowed | `unknown` | settings-blind coverage |
| 4 | `history_window_days` **constant**, fixture commit dates advanced past the cutoff | `unknown` | comparing settings instead of the resolved boundary |
| 5 | Blob purged; boundary did **not** move | `fixed` | a rule that simply disables `fixed` for the family |
| 6 | **Blob purged; boundary HAS moved; the finding's `oldest_reaching_commit_time` is still at or after the new boundary** | **`fixed`** | **boundary-in-the-cell** - cell equality fails, giving `unknown` |
| 7 | **Five byte-identical secrets in one blob** | **five distinct fingerprints** | a two-component history fingerprint without `occurrence` |
| 8 | **The same blob reachable at three paths across many commits** | **one set of ordinals** | an `occurrence` scoped to the path rather than the blob |

Case 6 is the one that matters most and was missing: case 5 stipulates an unmoved boundary, which is the
single condition under which the rejected boundary-in-cell reading still produces `fixed`, while case 6
is the **ordinary** shape on any active repository, since a rolling boundary moves on essentially every
run.
An implementation that folds the boundary back into the cell string passes 1 to 5 and fails 6.
Cases 7 and 8 pin the two `occurrence` decisions this module carries (tension 5), neither of which any
earlier test exercised.

## Tension 14 - exit-code precedence and required inputs

**The tension.**
§5 defines six exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error, `3` scope
violation, `4` missing required input, `5` circuit-breaker abort.
They are described as if mutually exclusive.
They are not: a run can trip the circuit breaker after already having collected findings above the gate,
and §9a's "fail only on new findings" mode - which §9a calls the single most useful mode - has no flag
in the §5 grammar at all.
§11 separately says `scope.conf` is "required", though `sast`, `sca`, and `iac` make no network calls.

**Why it bites.**
CI reads exactly one integer.
If a breaker-aborted run that also found a critical returns `1`, the pipeline reports "security gate
failed", the team fixes the finding, and nobody notices that two thirds of the checks never ran.
If it returns `5`, a pipeline that treats non-zero as failure still fails, but a pipeline that
distinguishes them can retry.
Getting this wrong silently converts an incomplete scan into a trusted verdict, which is the failure
mode §15 exists to prevent.
The missing flag is a plain blocker: an implementer cannot build §9a's headline mode from §5.
And requiring `scope.conf` for a pure SAST run is worse than friction: it teaches operators to write a
dummy scope entry, which weakens the one control §7 calls "the single most important safety control".

**Options considered.**

1. *Highest-numbered code wins.*
   Rejected: it is arbitrary, and it would let `5` mask a `2` usage error.
2. *Worst finding wins, so `1` beats `5`.*
   Rejected: it makes an incomplete run indistinguishable from a complete one, which is the exact
   failure above.
3. *Rank by "how much should the reader distrust this run", with everything recorded in `run.json`.*
   **Chosen.**

**RESOLUTION.**

**Exit-code precedence, highest priority first:**

```
2  usage error          (the invocation was invalid; nothing ran)
3  scope violation      (the tool was asked to leave its authorised scope)
4  missing required input
5  incomplete run       (the run did not finish what it was asked to do)
1  gate failed          (the run finished what it was asked to do, and found findings at or above --fail-on)
0  clean
```

The first condition that holds, in that order, determines the exit code.
**A run that both tripped the circuit breaker and found gated findings exits `5`.**
The rationale is that `1` asserts a complete assessment that failed its gate, and this run cannot make
that assertion.
Nothing is lost: `run.json` always records every condition that held, including
`"gate": "failed"`, `"gated_findings": N`, and `"incomplete_reason"`, and the report leads with both.
The documented CI contract is: `1` means fix the findings, `5` means investigate the target or the run
and re-scan, `2`/`3`/`4` mean fix the invocation or the config.
Codes `2`, `3`, and `4` sit above `5` because they mean the run was never valid, and `3` in particular
must never be masked, since it is the signal that the tool was pointed somewhere it was not authorised
to go.

**Exit 5 means unplanned incompleteness, never declared scope reduction.**
This distinction is load-bearing and the two must never be conflated, because tension 12 produces
`unknown` findings for both.

| Cause of reduced coverage | Class | Effect on exit code |
|---|---|---|
| Subcommand selected one module (`scan.sh sast`) | declared | none |
| `--profile-scan quick` / `compliance` dropped checks | declared | none |
| `--intensity` ceiling dropped checks | declared | none |
| `--allow-intrusive` absent dropped checks | declared | none |
| `--regions` / `--target` / `--path` narrowed the cells visited | declared | none |
| A module skipped under `all` for absent inputs | declared | none |
| A `pcre` record skipped for an unavailable engine (tension 2) | declared | none |
| A check skipped for an absent `requires-cmd` or `requires-config` | declared | none |
| A retired check id (tension 7) | declared | none |
| A `SAST-HIST-*` finding older than this run's history boundary (tension 13) | declared | none |
| A composite not selected this run, or with incomplete contributor coverage (tension 6) | inherits its cause's class | inherits |
| An unusable diff: `fp_schema` mismatch, or a `scan_root_id` mismatch **for a run whose findings live in `path-root` cells** (tension 12) | neither; see below | none, **but the gate goes fail-closed** |
| Circuit breaker opened | **unplanned** | **5** |
| Per-run request budget exhausted | **unplanned** | **5** |
| A module or check aborted with an error mid-flight | **unplanned** | **5** |
| A resumed run was itself interrupted | **unplanned** | **5** |

This table is exhaustive over the causes tension 12, 13, and 6 can produce.
Two entries need a word of explanation.
The history-boundary row is neither chosen by the invocation nor a failure: under a rolling window,
coverage recedes because **time passed**, which is a third thing, and it is classed declared because the
run did exactly what it was asked.
The composite row has no class of its own because a composite is never independently incomplete; it is
`unknown` only because some contributor is, so it takes that contributor's class and cannot upgrade a
declared reduction into an unplanned one.

`--paranoid` requested with no observer available is deliberately **not** in this table.
That run never starts, so it produces no reduced coverage to classify, and tension 20 assigns it exit
`4` (missing required input), which outranks `5` in the precedence list above.

A run whose reduced check set follows from its own invocation or from the host it is running on **did**
do what it was asked, so it exits `0` or `1` normally.
Only a run that failed to do what it was asked exits `5`.
That is what "declared" means here: not "named on the command line" - three of the declared rows follow
from the environment rather than the invocation - but "this run's scope was settled before it began, and
it honoured it".
`run.json` carries `coverage_reduction` (the declared entries, with the cause of each) and
`incomplete_reason` (the unplanned ones), and `incomplete_reason` being non-empty is exactly the exit-5
predicate.

Without this split, exit 5 swallows the product.
Tension 12 emits `unknown` for every prior finding of any uncovered check, so on any repository with
prior state and a non-empty backlog, `scan.sh sast` and `--profile-scan quick` would *always* exit 5 and
`0` and `1` would be unreachable.
That would kill the fast partial run - the mode tension 12 explicitly refused to sacrifice when it
rejected "only diff full runs", and the mode §9a calls the single most useful one - by making it
indistinguishable, to CI, from a target that fell over.
A `--profile-scan quick --fail-on-new` pipeline that catches a genuine new critical must report "fix the
findings", not "investigate the run".

**The missing gate flags** are added to the frozen CLI surface:

- `--fail-on-new` - restricts the `--fail-on` gate to findings whose status is `new`.
  Using it without `--fail-on` is a usage error (exit `2`).
- `--min-confidence <level>` - default `low` (tension 8).

Three edge cases are decided rather than left open, all three **fail closed**:

- **An unusable diff** - `diff_usable == false` per tension 11 step 5, which covers no prior state (first
  ever run or `state/` cleared), an `fp_schema` mismatch, and a `scan_root_id` mismatch **when this run's
  selected modules put their findings in `path-root` cells**.
  The `path-root` qualifier is not decoration: `dast`, `cloud` and `posture` have no `--path`, so without
  it `scan.sh cloud --live` from a new working directory would set `diff_usable = false`, gate on the
  whole backlog, and exit `1` forever - the precise symptom tension 12 scoped the gate to prevent.
  In every one of these `--fail-on-new` gates on **all** findings, and the report says so.
  Failing open would let the very first CI run pass silently with a full backlog, and teams calibrate on
  that first green build; the `fp_schema` case is worse still, because a tool upgrade would turn fifty
  criticals into a green build with no operator action at all.
  The intended workflow after a first red build is to baseline (tension 11), which is explicit and
  reviewable, rather than to inherit an invisible amnesty.
  Unusable prior state and absent prior state are the same situation and get the same answer.
- **Findings classified `unknown` while the diff is usable** (tension 12): excluded from the gate, since
  nothing was learned about them.
  The qualifier matters, but not because an unusable diff produces `unknown` findings - it does not.
  `diff_usable` governs the gate and never a `status`, so a first run's findings are `new` (tension 11
  step 5), and `unknown` keeps its single meaning of "this run did not assess it".
  The qualifier is there so that this exclusion is never read as licence to gate on nothing: when
  `diff_usable` is false the bullet above governs and the gate examines everything.
  Their presence **does not** by itself affect the exit code.
- **Exit code versus gate outcome.**
  Whether the run exits `5` is decided solely by `incomplete_reason` per the declared-versus-unplanned
  table above, so a deliberately scoped run still returns `0` or `1`, and an unusable diff sets no
  `incomplete_reason` and so cannot produce `5` either - it changes what the gate examines, not the
  precedence.
  The `unknown` findings and the reason each was not assessed are recorded in `run.json` and led with in
  the report, which is what tension 12 already specifies and is the right place for that signal.

**Required inputs are per module,** and exit `4` is scoped accordingly:

| Command | Requires |
|---|---|
| `sast`, `iac` | a readable `--path`, which is optional and **defaults to `.`** (tension 12), so exit `4` means the resolved path is absent or unreadable, not that the flag was omitted. **No `scope.conf`.** |
| `sca` | the same readable `--path`, **and a readable `data/advisories.db`** - see the paragraph below |
| `dast` | `config/scope.conf` with a matching `--target`; `config/auth.conf` additionally when `--authed` |
| `cloud --live` | resolvable AWS credentials; `config/scope.conf` is not required, since AWS endpoints are allowed by §2 independently |
| `posture` | `config/posture.conf` |
| `all` | whatever each selected module requires; a module whose inputs are absent is **skipped with a `run.json` reason**, not an error, which is what §5's "run every module for which inputs are configured" already says |

A missing `scope.conf` is exit `4` only for `dast`.
This preserves the §7 gate exactly (a `dast` run still cannot proceed without it, and there is still no
raw-URL bypass) while removing the incentive to write a dummy entry.

**`data/advisories.db` is `sca`'s required input, and this row was added rather than assumed.**
It is a later amendment to this table, not part of the original resolution, so it is marked as one.
The register already answers what a missing module input costs; what it had never been asked is whether
the advisory database *is* one.
It is: `sca` is a table lookup (tension 25), every ecosystem is matched against that one table, and
without it not a single dependency in any ecosystem is examined.
The behaviour before this row existed was that a `scan.sh sca` against a knowingly vulnerable project
exited `0` with zero findings and an empty `checks_run`, which renders "it did not look" and "it looked
and found nothing" identically - the precise failure §15 and this whole register exist to prevent, and
worse here than elsewhere because `data/advisories.db` is absent by default (`tools/vendor-engines.sh`
populates it on a networked box and never runs during a scan), so the misleading run was the ordinary
one rather than an edge case.
Nothing new is minted for it: no exit code outside `0`-`5`, and the precedence order above is untouched.
Exit `5` was considered and rejected - it is reserved for **unplanned** incompleteness, its predicate is
`incomplete_reason` being non-empty, and this run did not fail part-way through; it never had the input
it needed, which is what `4` means.
The documented CI contract settles it independently: `5` says "investigate the target or the run and
re-scan", `4` says "fix the invocation or the config", and the remedy here is to populate the database.
The closest existing precedent is tension 20's, where `--paranoid` with no connection observer available
on the host is exit `4` before the run starts, for the same reason: a requested capability whose
prerequisite is absent, discovered from the environment rather than the command line.
The `all` row above governs unchanged - a `scan.sh all` with no advisory database **skips `sca` with a
`run.json` reason and does not change the exit code**, because the other modules did do what they were
asked.
Both directions are pinned by tests, because the naive fix for each is the other's bug: exit `4`
unconditionally makes every `all` run non-zero on a fresh checkout, and exit `0` unconditionally is the
defect itself.

**Implementation.**
`modules/sca/run.sh` decides the gate once, for the module, before any ecosystem walk, and records one
`coverage_reduction module=sca reason=no_advisories_db_on_disk ecosystems=<every ecosystem, LC_ALL=C
sorted>` plus a `SCA-COV-NO_ADVISORY_DB-01` finding so the report says so in the findings list rather
than only in its limitations section.
That announcement had previously been each walk's own business, which is a shape in which it cannot be
correct: two of the four walks announced it (so a plain `sca` run recorded the same fact twice whatever
the tree contained) and the other two returned silently (so half the ecosystems were accounted for by
nothing at all).
The finding is `info`, matching its sibling `SCA-COV-UNKNOWN_VERSION-01`: a blind spot is not a
vulnerability, and giving it a gating severity would make the run report exit `1`, which asserts "a
complete assessment that failed its gate" - exactly the claim this run cannot make.
The module sets the `input` condition and `scan_exit_code` applies the precedence, so the run still
writes its full report before returning `4`; a `die` would have exited with nothing on disk, which
trades one kind of silence for another.

**Consequence for the build.**
§13 step 2 delivers the exit-code precedence function and the complete flag table; the gate itself lands
in step 10 but its inputs exist from step 2.
`run.json` gains `incomplete_reason`, `coverage_reduction`, `gate`, and `gated_findings`.
A test matrix asserts one exit code per combination of (breaker tripped, findings above gate, scope
violation, missing input), plus two cases each chosen to fail under a rejected reading:

| Fixture | Must exit | Fails under |
|---|---|---|
| `--profile-scan quick --fail-on high --fail-on-new`, prior state and a backlog, no new high | `0` | "any `unknown` forces 5" |
| the same, with one new high | `1` | the same |
| **`--fail-on critical --fail-on-new` after an `fp_schema` bump, 50 criticals present** | **`1`** | **`unknown` excluded from the gate unconditionally, or a bare `status == new` predicate - both give `0`** |
| **`scan.sh sast --fail-on critical --fail-on-new` after a `scan_root_id` change, no `fp_schema` change, 50 criticals** | **`1`** | treating only `fp_schema` as making a diff unusable. The module mix is named deliberately: `sast` findings live in `path-root` cells, which is the only kind `scan_root_id` gates |
| **`scan.sh cloud --live --fail-on critical --fail-on-new` run from `/repoA`, then the identical scan from `/repoB`, with a prior cloud backlog and no new criticals** | **`0`, with cloud findings classified normally** | **the comparability gate stated flat rather than scoped to `path-root`: a change of working directory invalidates the entire cloud diff, every prior finding goes `unknown`, `--fail-on-new` falls back to gating everything, and the run exits `1` forever. Fails under each of the unscoped consumer sentences independently** |
| **First-ever run, no `state/` at all, `--fail-on critical --fail-on-new`, 50 criticals** | **`1`, and all 50 persisted with `status: new`** | **`diff_usable` overriding `status` to `unknown` - the gate still gives `1`, but `state/` and the first report a team ever sees carry the wrong status for every finding** |

The `fp_schema` row is one no earlier test touched: tension 14's matrix had no `fp_schema` axis, and
tensions 5, 11 and 12's tests are about fingerprints, baseline ordering, and coverage respectively, so
the fail-open shipped green under every prescribed test in the register.
The two rows after it name their **module mix**, which the earlier drafts did not: a `sast` fixture and a
`cloud` fixture answer differently once the gate is scoped, so a row that does not say which module ran
cannot discriminate the scoping at all.

## Tension 15 - check-set selection precedence

**The tension.**
Three independent controls select which checks run: `--profile-scan quick|full|compliance` (global),
`--intensity passive|safe|active` (on `dast`), and `--allow-intrusive` (global, default off).
§5 defines `quick` as "passive + config-read, no active probes".
`scan.sh dast --profile-scan quick --intensity active` therefore says two opposite things.

**Why it bites.**
An implementer must pick a precedence and cannot guess it, and the two possible answers have very
different safety properties.
If the more permissive control wins, then a flag intended to make a scan *faster and safer* can be
silently overridden into sending active injection probes at a production target, which is the one
outcome §14's guardrails exist to prevent.
There is also no definition of what `compliance` selects that an implementer can compute; "only checks
that map to a CIS/OWASP control" is a property of a check, but nothing says where that property lives.

**Options considered.**

1. *Last flag on the command line wins.*
   Rejected: order-dependent CLI semantics are a footgun, and the dangerous direction is reachable by
   accident.
2. *Error on any conflict.*
   Rejected: `all --profile-scan quick` would then have to reject the `dast` default intensity, making
   the common invocation fail.
3. *The controls are filters and compose as intersection; the most restrictive always wins.* **Chosen.**

**RESOLUTION.**
The three controls are **filters**, applied in sequence to the registered check set, and the result is
their **intersection**.
The most restrictive control always wins; no control can ever re-enable a check another has removed.

1. **Module selection** (the subcommand) picks the candidate set.
2. **`--profile-scan`** filters by profile TAG: `quick` keeps checks tagged `quick`; `full` keeps
   everything; `compliance` keeps checks tagged `compliance`.
   (Finding F3, closed: the line originally here read "keeps checks with a non-empty `cis` **or**
   `owasp` field... computable from the record, with no separate list to drift".
   That reading is unusable as written - `owasp` is a REQUIRED key on every pattern rule and script
   check (`rules/RULE-FORMAT.md` §9.1, §9.5), present as a real category or the literal `none` but
   never absent, so "non-empty owasp field" is true for the entire catalog and selects nothing
   `compliance`-specific.
   `lib/checks.sh` settles F3 on the TAG reading: it is the only one of the two that is actually
   computable as a strict subset, `lib/records.sh`'s closed tag vocabulary already treats `compliance`
   as a legal profile-tag value (`_records_check_tags`, E044), and `rules/RULE-FORMAT.md` §12's own
   worked examples assume it - 12.1 and 12.5 carry an explicit `tags: compliance` line, while 12.2 has a
   real, non-`none` `owasp` value and NO compliance tag.)
3. **`--intensity`** applies a type-tag ceiling: `passive` keeps `passive`, `config-read`, `posture`,
   and `static`; `safe` additionally keeps `safe-active`; `active` additionally keeps `active`.
   `derived` is exempt from this filter entirely (finding F8, closed: see its own entry in "Known
   follow-ups" - a composite consumes other checks' findings rather than issuing requests of its own,
   so no intensity tier is a meaningful ceiling for one).  A `derived` check remains fully subject to
   `--profile-scan` and `--allow-intrusive`; only the intensity ceiling is waived.
4. **`--allow-intrusive`** (default off) removes every check tagged `intrusive`, regardless of anything
   above.
   It can only ever remove checks; it never adds one that a prior filter dropped.

Therefore `--profile-scan quick --intensity active` runs passive checks only.
When a filter drops checks that a later, more permissive flag would have kept, `scan.sh` prints a
warning naming the flag that won and the count of checks dropped, and `run.json` records
`skipped_by: "profile-scan=quick"` per check.
That is what makes §4's "which checks ran/skipped and why" real rather than aspirational, and it means a
surprised operator gets an explanation instead of a mystery.

Every check carries its tags in its record: pattern rules in their `.rules` pack, script checks in a
`modules/<module>/checks.rules` registry in the same frozen format (`rules/RULE-FORMAT.md` §9.5, whose
`tags` key follows §9.1.3).
Exactly one type tag per check (`passive`, `safe-active`, `active`, `config-read`, `posture`, `static`,
`derived`), zero or more profile tags, and the `intrusive` marker where it applies.
Registering script checks as records is also what gives tension 12 a check registry to compute
`covered_checks` from, and gives tension 7 stable ids for scripts and not just for patterns.

**Consequence for the build.**
§13 step 2 delivers the filter chain and the registry loader: `lib/checks.sh`, plus the
`_scan_apply_profile_filter` wiring in `scan.sh` that calls it ahead of every `scan_dispatch`.
The §7.4 enumeration-via-response checks and the §8.3 live user-enumeration probe are the seed
`intrusive` checks, which makes §14's "side-effecting checks are off unless `--allow-intrusive`"
enforced by the selection chain rather than by each script remembering to check a variable.
A test asserts that `--profile-scan quick --intensity active` selects zero `active` checks
(`tests/suites/checks.sh`).

Two defaults this tension left unstated are pinned in `lib/checks.sh` rather than in this document,
because they are ordinary engineering judgement calls, not open design tensions: `--profile-scan`
defaults to `full` when not given (an absent flag must not silently narrow "scan exhaustively"), and
`--intensity` defaults to `passive` when not given, including for `dast` itself (every other guardrail
in this tool defaults to the safest behaviour, and "no flag given" must not be the one exception).

`lib/checks.sh` also delivers the registry loader's other half: `checks_registry_load` discovers every
`*.rules` file that exists on disk under a module's directory right now (none do, before §13 step 3),
and `SCOURSH_SELECTED_CHECKS` - the LF-joined selected-id env var `lib/findings.sh`'s
`_derived_record_selected` already read from step 1, in anticipation of this filter chain - is wired
from `scan.sh`, union'd across every module one invocation dispatches.

**A module that emits SCRIPT checks needs its own READER of that variable, and DAST's is
`dast_check_selected` (`modules/dast/engine.sh` section 3a).**
A pattern module needs no reader: `checks_registry_load` gives `modules/sast/engine.sh` and
`modules/iac/parse.sh` a filtered id set to iterate, so a deselected check is simply never evaluated.
A DAST phase script has no such loop - it hardcodes the ids it implements - so the filter chain binds
it only if the script asks.
That gap shipped: four call sites across three tickets called `dast_check_selected` behind a
`declare -F` guard before anything defined it, so `--profile-scan`/`--intensity` narrowed the DAST
check REGISTRY and narrowed nothing a run actually SENT - a forged JWT, a SQLi payload or a
content-discovery sweep still went to the operator's live target for a check they had excluded, which
is a request the operator did not authorise by check set.
Three properties of the reader are load-bearing, and each is pinned by a case in `tests/suites/dast.sh`
that fails under the reading it rejects:

1. **Unset OR empty means ALL SELECTED**, verbatim as `lib/findings.sh`'s `_derived_record_selected`
   already reads it.
   `scan.sh` exports the variable unconditionally and possibly empty, so both cases must answer
   "selected", and every direct-engine DAST suite sources a phase script with no filter chain in the
   process at all.
   A fail-closed default would therefore make every DAST phase inert while every "stays quiet"
   assertion in those suites still passed green - invisible from the test output, and it reads as
   coverage.
2. **Membership is WHOLE-LINE, never a `*"$id"*` substring.**
   An id that is merely a prefix or suffix of another selected line would otherwise deliver a payload
   the operator filtered out.
3. **The `declare -F` guard at each call site is KEPT.**
   An unguarded call in a process without `engine.sh` is `command not found`, exit 127, non-zero -
   which reads as "deselected" and reproduces failure mode 1 by another route.

One consequence is accepted rather than fixed: "the filter chain ran and kept nothing" is
indistinguishable from "there is no filter chain", since both leave the variable empty.
Distinguishing them needs a second variable in `scan.sh`, a change to a contract three other readers
already agree on, and the surviving reading is the permissive one `lib/findings.sh` has shipped since
step 1 - so nothing diverges.
A corollary for whoever registers a new DAST check family: gate a probe on `dast_check_selected` only
once its ids are in a `checks.rules` registry.
An id no registry declares can never survive the filter chain, so gating it ahead of registration makes
it inert on precisely the runs that pass a `--profile-scan`.

## Tension 16 - shared limiter, budget, breaker, and cache across processes

**The tension.**
§4 puts a "global token-bucket rate limiter" and §5 a circuit breaker and a per-run request budget in
`lib/http.sh`.
§10 fans work out with `xargs -P "$JOBS"`, and §10 also caches AWS responses per
`(service, region, account)` within a run.
`xargs -P` creates N independent processes.
Shell variables are per-process.

**Why it bites.**
Every one of these controls silently becomes per-worker.

- The rate limiter admits `jobs × requests_per_second`.
  With the default `--jobs 8` that is an 8x overshoot against a production target by a tool whose stated
  purpose in §4 is that "scans stay polite and don't DoS the target".
- The per-run request budget is multiplied by 8, so §7.4's `ratelimit.sh` burst cap - the one check that
  deliberately sends many requests - is 8x its declared bound.
- The circuit breaker never trips: each worker sees only its own share of the 5xx responses, so eight
  workers each below threshold keep hammering a target that is comprehensively down, which is the exact
  scenario §5 introduces the breaker to prevent.
- The AWS cache never hits across workers, so eight workers issue the same `describe-*` call, which
  wastes the API rate limit that §8.1's multi-region iteration is already pressing against.

**Options considered.**

1. *Single-threaded HTTP.*
   Rejected: it makes `--jobs` meaningless for the module where scan time is dominated by latency.
2. *A broker coprocess handing out tokens over a FIFO.*
   Rejected: a FIFO with N concurrent writers needs its own framing to avoid interleaving (tension 17
   again), and a dead broker deadlocks every worker with no clean recovery.
3. *`flock(1)` on state files.*
   Rejected as the single mechanism: `flock(1)` is util-linux and is absent on macOS and BSD, which
   would make the concurrency correctness of the tool depend on the host (tension 24).
4. *An atomic-`mkdir` mutex over files in the run scratch directory.* **Chosen.**

**RESOLUTION.**
Shared state lives in files in the run scratch directory, guarded by a mutex built on `mkdir`, which is
atomic on every POSIX filesystem and needs no external binary.

```
mutex_acquire() {           # $1 = mutex name
  local d="$SCOURSH_SCRATCH/mx/$1.lock" waited=0 token
  while ! mkdir "$d" 2>/dev/null; do
    token=$(_lock_token "$d")                  # the instance we are judging
    if lock_is_stale "$d"; then
      if _lock_reclaim "$d" "$token"; then continue; fi
    fi
    msleep "$MUTEX_TICK_MS"; waited=$((waited+1))
    (( waited < MUTEX_TIMEOUT_TICKS )) || die 5 "mutex timeout: $1"
  done
  printf '%s %s\n' "$BASHPID" "$(now_epoch)" > "$d/owner"
}
```

Two corrections to this sample landed with §13 step 1.
It called `sleep 0.05` literally, contradicting its own "Consequence for the build" paragraph and the
capability layer of tension 24; it now calls `msleep`, which is the point of finding F14.
And `die 6` is outside the frozen 0-5 exit contract; a mutex timeout is an **incomplete run**, so it is
`die 5` (see tension 4's `scan_match` note).

**`lock_is_stale` is specified rather than asserted (finding F15).**
A lock is reclaimable only when **both** of these hold:

1. it has been held for at least `lock_stale_seconds` (default 30), measured from the timestamp the
   owner **recorded**, never from filesystem mtime, so a `touch` cannot extend a lock; and
2. the process that published it is no longer alive (`proc_alive`, over `kill -0`).

Requiring both is what bounds **pid reuse** over a long DAST run: a recycled pid belonging to some
unrelated live process makes the lock look held, so the run waits and then fails loud on the mutex
timeout rather than entering a critical section another process may be in.

The window between `mkdir` returning and the owner file being written is **decided rather than left
undefined**: a published lock with no owner file is NOT stale until it is older than
`lock_stale_seconds` by its directory mtime (`stat_mtime`).
Treating it as stale would let a waiter delete a lock acquired microseconds earlier by a live holder;
treating it as never stale would wedge the run if a holder died inside that window.

**Reclaim is single-winner and identity-bound.**
The frozen path was `if lock_is_stale "$d"; then rm -rf "$d"; continue; fi`, which can delete a **live**
lock: waiters W1 and W2 both judge one lock stale, W1 removes it and acquires, and W2 - already past its
check - removes W1's freshly acquired lock and acquires too, putting two processes in the critical
section.
`mkdir` is atomic; the reclaim was not.
So reclaim now takes a **claim marker whose name embeds the token of the instance being reclaimed**:

```
_lock_reclaim() {                       # $1 = lock dir, $2 = the token we judged stale
  local claim="$1.rcl.$(slug "$2")"
  [[ -d $claim ]] && lock_is_stale "$claim" && rm -rf "$claim"   # an abandoned claim
  mkdir "$claim" 2>/dev/null || return 1                         # lost the race; just retry
  printf '%s %s\n' "$$" "$(now_epoch)" > "$claim/owner"
  [[ $(_lock_token "$1") == "$2" ]] && rm -rf "$1"               # re-verify, THEN delete
  rm -rf "$claim"
}
```

Only one process can create a given claim name, so only one can reclaim a given lock instance; a process
that judged an **older** instance stale re-verifies the token inside the claim and declines when it has
changed.
An abandoned claim - a reclaimer killed inside the microseconds it takes to remove a small directory -
is itself reclaimed by the same staleness test, so the recovery path terminates, and it cannot produce
double occupancy, because deleting the lock still requires winning the claim `mkdir` **and** the token
re-check.

Prescribed tests, each naming the reading it fails under:

| Fixture | Must be | Fails under |
|---|---|---|
| Fresh lock, live owner | not stale | age-only |
| **Old lock, owner still alive** | **not stale** | **liveness-only: this is the pid-reuse bound** |
| Dead owner, no age | not stale | liveness-only |
| Old lock, dead owner | stale | - |
| **Published lock with no owner file yet** | **not stale** | an undefined window: a waiter deletes a live holder's lock |
| **Reclaim a stale lock, let a live holder take it, then reclaim again with the OLD token** | **the live lock survives** | **a bare `rm -rf` reclaim, which deletes it** |
| 8 concurrent workers each entering the critical section | no overlap | any of the above |

Four pieces of state, with their protocols:

- **Rate limiter.** One bucket per scope target (rate is a politeness property of the target), at
  `$SCRATCH/rate/<target>.state` holding `last_refill_ns tokens`.
  `http_request` takes the mutex, refills by elapsed time, and either consumes a token and releases, or
  computes the wait, **releases the mutex, sleeps outside it**, and retries.
  Sleeping while holding the mutex would serialise every worker behind the slowest wait and destroy the
  point of `--jobs`.
- **Request budget.** A counter at `$SCRATCH/budget.state`, decremented inside the **same critical
  section** as the token grant, so one mutex acquisition covers both and the two can never disagree.
  Exhaustion aborts the module with the same path as the breaker.
- **Circuit breaker.** Per target, at `$SCRATCH/breaker/<target>.state`, holding the rolling window
  counters and the state (`closed` / `open` / `half-open`), updated under the mutex after every
  response.
  When it opens, the worker writes `$SCRATCH/abort/<target>`; **every worker checks for that file before
  every request** and exits `5` if present.
  That flag file is the fan-out abort signal, and it is a plain existence check with no mutex, since
  creation is atomic and the value never changes.
- **AWS response cache.** `$SCRATCH/awscache/<sha256(service|region|account|op|args)>.json`, written by
  `mktemp` in the same directory then `mv`, which is atomic within a filesystem, so a reader never sees
  a partial file.
  On a miss the reader takes a per-key mutex, re-checks (another worker may have filled it while it
  waited), then fetches, which prevents eight workers issuing the same call.

`--jobs` therefore has no effect on politeness: the shared bucket enforces the configured rate no matter
how many workers exist.
The interaction with resumability is decided in tension 18: a resumed run carries the remaining budget
forward rather than resetting it.

**Consequence for the build.**
The mutex, the scratch layout, and `now_epoch_ns` land in `lib/core.sh` at §13 step 1, ahead of
`lib/http.sh` at step 5, because `lib/http.sh` cannot be written without them.
`sleep 0.05` needs fractional sleep, which is not POSIX, so `lib/core.sh` probes for it once and falls
back to a busy-wait bounded by `read -t` (tension 24).
Two tests matter: a concurrency test runs 16 workers against a local mock and asserts the observed
request rate does not exceed `requests_per_second`, and a breaker test asserts all workers stop within
one request of the breaker opening.

## Tension 17 - concurrent writes to `findings.jsonl`

**The tension.**
§10 says "write findings incrementally to `reports/<run>/findings.jsonl`" while fanning out with
`xargs -P`.
Multiple processes appending to one file is only atomic for writes up to `PIPE_BUF`.

**Why it bites.**
A finding line carries evidence, remediation, a CVSS vector, and references, and readily exceeds 4096
bytes.
`O_APPEND` guarantees the offset is taken atomically, but a write larger than the pipe buffer can be
split, and two workers' lines interleave mid-record.
The result is a `findings.jsonl` with corrupt lines that appears fine at low `--jobs` and on small
fixture runs, and corrupts on a long production scan under load, which is the worst possible
distribution of failures.
The corruption then flows into `state/`, `baseline.json` matching, and the SARIF upload.
There is a second, quieter problem: with workers racing, the order of lines is nondeterministic, so two
identical scans produce different `findings.jsonl` bytes, which undermines §4's "so scans are
reproducible and defensible for an audit".

**Options considered.**

1. *Take the mutex for every write.*
   Rejected: it serialises the hot path for a problem that does not need locking at all, and the mutex
   from tension 16 is already on the request path.
2. *A single writer process fed by a FIFO.*
   Rejected: it moves the interleaving problem into the FIFO and adds a process whose death is a silent
   data-loss mode.
3. *Per-worker shard files, merged deterministically.* **Chosen.**

**RESOLUTION.**
Each worker writes only to `reports/<run>/shards/<worker-id>.jsonl`, which it owns exclusively.
No locking is needed, because there is no sharing.
The worker id is `$BASHPID` plus the work-unit index, so it is unique even if a pid is recycled.

> **The shard location moved out of the scratch dir in §13 step 1 (finding F12).**
> It was `$SCRATCH/findings/<worker-id>.jsonl`, retained under `reports/<run>/shards/` only when
> `--keep-shards` was given, while tension 4 rule 5's `EXIT` trap erases `$SCRATCH` - including on the
> `SIGTERM` that tension 18's own resume test uses.
> So on a normal interrupted run both of tension 18's inputs were destroyed, and an operator would have
> had to pass `--keep-shards` on the run they did not know would be interrupted.
> Shards are now written into the run directory **unconditionally**, and `--keep-shards` is redefined
> below.
>
> The worker id must be taken in the CURRENT shell, not from a command substitution: `$BASHPID` inside
> `$( ... )` is the subshell's pid and differs on every call, which silently gives every finding a shard
> of its own.

`--keep-shards` is redefined accordingly: it means **do not delete the shard and unit directories after
a successful merge**.  Without it they are removed once the merge has completed, which is the only point
at which they are genuinely redundant.

At end of run, `scan.sh` merges every shard into `reports/<run>/findings.jsonl`, sorted by
`(module, check_id, fingerprint)` under `LC_ALL=C`.
Sorting is not cosmetic: it makes the output **byte-reproducible** across runs regardless of scheduling,
which is what §4's audit-record claim needs and what makes a diff of two `findings.jsonl` files readable
by a human.
The sort key is total, because the fingerprint is unique within a run.
That uniqueness is not free: it holds only because tension 5's location components carry an `occurrence`
discriminator for the SAST, history, IaC, and container modules, whose `match_digest` would otherwise be
identical across every repeated byte-identical match in a file.
Without it this sort would be non-deterministic between ties and the merged file would not be
byte-reproducible.

"Incrementally" is preserved in the sense §10 actually needs: findings are durable on disk as they are
produced, so an interrupted run loses nothing and a resumed run (tension 18) reads the prior shards.
What is deferred to the merge is only the *ordering*, not the *persistence*.
That claim is now true rather than contradicted two paragraphs earlier, which is what finding F12 was.

**The merge sorts a sidecar, not the JSONL.** Each worker writes its finding twice: as JSON to
`shards/<worker-id>.jsonl`, which is the durable artifact this section names and what a resume reads,
and as one line to `shards/<worker-id>.fields` in an internal escaped `key=value` encoding, which the
merge sorts and the report renders from.
Both are written by one process in lockstep, so they cannot drift.
The sidecar exists so that nothing in this repository has to parse JSON in bash, which would be a second
parser with its own quoting bugs sitting in the path of every report - the mistake tension 1 spent a
whole section avoiding one level up.

Every finding line is guaranteed to be a single line by construction: `finding_set_evidence`
(tension 10) removes control characters including LF from the only field that could carry one.

**Consequence for the build.**
§13 step 1 delivers the shard writer and the merge, so every later module simply calls `emit_finding`.
A test runs 32 concurrent emitters producing findings with 4 KB evidence and asserts that the merged
file has exactly the expected line count, that every line parses as JSON, and that two runs with
different `--jobs` produce byte-identical output.

## Tension 18 - resumability keyed by a fingerprint that does not exist yet

**The tension.**
§10: "a resumable run skips already-completed work units keyed by fingerprint".
A fingerprint is a property of a **finding**.
A work unit that has not run has produced no findings, so it has no fingerprint.
Worse, a work unit that runs and finds nothing produces no fingerprint at all, yet it is precisely the
unit a resume must know to skip.

**Why it bites.**
As written the feature cannot be built: the key is circular for the units that need skipping, and
undefined for the clean ones, which are the majority.
Keying on findings would also produce a resume that re-runs every check that was clean, which for a
multi-region AWS scan or a long DAST run is most of the work, so the feature would deliver almost none
of its value.
And a naive resume has a second hazard that is worse than not resuming: if the config, rule packs, or
scope changed between the interrupted run and the resume, the resumed run silently produces a findings
set that corresponds to no single configuration, and then persists it to `state/` as though it did.

**Options considered.**

1. *Key on the findings produced so far and re-run everything else.*
   Rejected: it cannot distinguish "not run" from "run and clean", so it re-runs nearly everything.
2. *Checkpoint by module and region.*
   Rejected: too coarse for DAST, where one module is tens of thousands of probes.
3. *A distinct work-unit key derived from the unit's inputs.* **Chosen.**

**RESOLUTION.**
§10's word "fingerprint" is a spec-wording error; its intent is preserved with a distinct, frozen
concept.

A **`unit_key`** is derived from a work unit's **inputs**, so it exists before the unit runs:

```
unit_key = lowercase_hex_sha256( "uk/1" \0 module \0 check_id \0 scope_1 \0 scope_2 \0 ... )
```

| Module | Unit scope |
|---|---|
| SAST, IaC | scan-root-relative file path (tension 12) |
| SAST history | blob sha |
| SCA | lockfile path |
| DAST | `target_name`, `method`, `path_template`, `param_location`, `param_name` |
| Cloud live | `account_id`, `region`, `service` |
| Posture | `control_id` (the `POSTURE-*` check id), `scope_key` |

Each worker appends `{"unit_key":…, "state":"started"|"done"|"failed", "ts":…}` to
`reports/<run>/units/<worker-id>.jsonl`, using the same per-worker shard mechanism as tension 17, so the
journal needs no locking either.

> **The path was ambiguous and is now single (finding F12).**
> It read `reports/<run>/units.jsonl`, a single durable path, while "the same per-worker shard
> mechanism" pointed at `$SCRATCH` - which the `EXIT` trap erases on the very signal this section's own
> resume test uses.
> Both the finding shards and this journal are now written into the run directory unconditionally, and
> the scratch dir holds only genuinely transient data (tension 4 rule 5).
A resume skips exactly the units whose latest record is `done`.
A unit recorded `started` but never `done` is re-run, which is correct: partial work is discarded rather
than trusted.
Findings are recovered by reading the prior run's finding shards, so a clean unit is skipped and
contributes nothing, and a unit that had found something contributes its already-recorded findings.

**A resume requires an identical run identity.**
`run.json` records:

```
run_identity = sha256( tool_version \0 fp_schema \0 uk_schema \0 scan_root_id \0 sorted(check_ids selected)
                       \0 digest(config/*.conf) \0 digest(all record files) \0 normalised CLI flags )
```

`--resume <run-dir>` recomputes it and **refuses with exit `2`** on any mismatch, naming what changed.
Silently resuming across a config change is how a scan comes to report a state that never existed.

Three interactions are decided here rather than left to discovery:

- **Coverage.** A (check, cell) pair counts toward `covered_checks` (tension 12) only when **all** of
  that check's units **within that cell** are `done`.
  Unit scope is finer than cell scope in every module, so this is a refinement of tension 12's rule and
  not a competing one: a check can be covered for `us-east-1` while its `eu-west-1` units are still
  outstanding.
  A resumed run that still has not finished a check leaves it uncovered, so its prior findings stay
  `unknown` rather than becoming `fixed`.
- **Budget.** The per-run request budget and the breaker state are **carried forward** from the
  interrupted run, not reset.
  Resetting would let a run exceed its declared budget by resuming repeatedly, which turns a safety
  bound into a suggestion.
- **Exit code.** A resumed run that completes exits normally; one that is itself interrupted exits `5`
  (tension 14).

**Consequence for the build.**
`unit_key` and the journal land in §13 step 1 alongside the shard writer, and `--resume` joins the frozen
CLI surface at step 2, even though the long-running modules that benefit arrive at steps 5 and 6.
Every module must enumerate its work units before executing them, which is a real structural
requirement: a module cannot stream units out of a discovery loop that also executes them.
The test interrupts a scan with `SIGTERM` mid-module, resumes, and asserts the union of findings equals
an uninterrupted run's, that no unit ran twice, and that a modified rule pack makes the resume refuse.

## Tension 19 - scope-gate semantics

**The tension.**
§2 says `lib/http.sh` "resolves URL host, check against the allowlist built from `scope.conf`".
§11 says a scope entry is `name | base_url | notes`, so the authored value is a **URL with a scheme, an
optional port, and often a path**, while the gate is described as matching a **host**.
§7 calls the gate "the single most important safety control; do not make it bypassable by raw URL".

**Why it bites.**
The gap between "a base URL was authorised" and "a host is allowed" is where every bypass lives, and
none of the questions have obvious answers.
Does authorising `https://host/api` authorise `https://host/admin`?
Does authorising `https://host` authorise `http://host` on port 80, which §7.4's `transport.sh` must
probe deliberately?
Does it authorise `host:8443`?
Does it authorise `sub.host`?
Beyond parsing, there are two live security problems the spec does not address at all.
First, TOCTOU: the gate resolves the host, then `curl` resolves it again, and a DNS answer that changes
between the two (or a short-TTL record under someone else's control) sends the request somewhere the
gate never approved.
Second, §7.3's SSRF check explicitly worries about "arbitrary metadata endpoints", but nothing stops an
in-scope hostname from resolving to `169.254.169.254`, at which point the scanner obligingly fetches
cloud credentials and puts them in the report as evidence.

**Options considered.**

1. *Match the full base URL prefix including path.*
   Rejected: unenforceable the moment the crawler follows a link, and it would make `transport.sh`
   impossible to write.
2. *Match hostname only, ignoring scheme and port.*
   Rejected: it silently authorises every port on the host, including an admin interface the operator
   never named.
3. *Match a normalised `(scheme, host, port)` tuple set, with path as a crawler bound rather than a
   gate.* **Chosen.**

**RESOLUTION.**

**Entry point.**
`http_request` is the single chokepoint every network call in scoursh routes through.
No module, check script, or crawler calls `curl`, a language HTTP client, or any other transport
primitive directly; every one of them calls `http_request`, and `http_request` is the only place the
gate logic below runs.
This is enforced, not just documented: the "No bypass" lint below fails the build the moment a second
path to the network exists, so the contract cannot silently rot as modules are added in later steps.

**What the gate matches.**
Each `config/scope.conf` target (block-record format, `rules/RULE-FORMAT.md` §9.4) contributes a set of
`(scheme, host, port)` tuples, with the port defaulted from the scheme when absent.
The gate lowercases the host, strips a trailing dot, converts IDNs to A-labels, and compares tuples
exactly.

- **Path is not part of the gate.**
  It seeds and bounds the **crawler's** frontier (`crawl.sh` will not queue outside the base path unless
  `discovery.conf` widens it), which is a coverage control, not a safety control.
  This distinction is stated because conflating them is what makes people think a path-scoped gate is
  protecting them.
- **Scheme and port are part of the gate.**
  `https://host` does not authorise `https://host:8443`.
  It **does** authorise `http://host:80` for the same host, because §7.4's `transport.sh` must be able
  to check whether port 80 redirects to TLS, and requiring operators to author both lines would push
  them toward authorising more than they mean to.
  This one relaxation is explicit, is limited to port 80 on a host already authorised over `https`, and
  is recorded in `run.json`.
- **Subdomains are never implicitly in scope.**
  `allow-subdomains: true` opts in per target; the default is `false`.
  Additional hosts are authored one per `extra-host` line.
- **IP literals must be authored literally.**

**Resolution pinning.**
`http_request` resolves each in-scope host **once per run** and caches the result.
Every resolved address is checked against a deny list: `127.0.0.0/8`, `::1`, `169.254.0.0/16` (which
covers `169.254.169.254`), `fe80::/10`, `fd00::/8`, `100.64.0.0/10`, and `0.0.0.0/8`.
A hit aborts with exit `3` and a scope-violation record naming the host and the address, unless the
target declares `allow-private-addresses: true`, which is the honest opt-in for scanning something on a
private network.
The pinned address is then passed to `curl` as `--resolve host:port:addr`, so `curl` performs no
resolution of its own and the address the gate approved is the address that is connected to.
That closes the TOCTOU window and the rebinding vector in one move.

**Redirects.**
`curl` is invoked with `--max-redirs 0` and never `-L`.
When a check needs to follow a redirect it does so **manually, one hop at a time**, re-running the full
gate on each `Location`, with a hop cap of `max_redirects` (default 5).
An out-of-scope `Location` is not followed and is recorded, which is itself useful signal for §7.3's
open-redirect check.

**No bypass.**
There is no raw-URL flag.
`--target` names a `scope.conf` id and nothing else, and every request in every module goes through
`http_request`.
A lint fails on any `curl`, `wget`, `nc`, or `openssl s_client` invocation outside `lib/http.sh` and
`modules/dast/passive/tls.sh`, the latter being the one documented exception, which takes its host from
the same resolved, gated tuple set.

**Normalization order.**
Every URL `http_request` is given, whether authored in `scope.conf`, discovered by the crawler, or
returned in a `Location` header, is put through the same pipeline **before** any gate comparison runs,
and the pipeline runs exactly once per URL, not once per bypass class:

1. Percent-decode the authority component only (scheme, userinfo, host, port), one pass.
   A second decode pass is never performed, because decoding twice is itself the bypass: a host authored
   or matched as `evil` and presented as `%65vil` survives one decode as `evil`, but a value that must
   stay `%2565vil` (a literal, encoded `%65vil` string some application-layer consumer might re-decode)
   would be corrupted into `evil` by a second pass.
   One pass, applied uniformly, is the only rule that is unambiguous to re-implement.
2. Split the authority into userinfo, host, and port per RFC 3986; **discard userinfo**.
   `http://allowed@evil/` names host `evil`, not `allowed`; the gate has never looked at userinfo and
   must not start now, so this step exists to stop userinfo from ever reaching the comparison as if it
   were the host.
   `http_request` also refuses to place a non-empty userinfo on the wire at all (`curl -u` is not used
   from a parsed URL), because a credential embedded in an authored or discovered URL is exactly the
   shape of value tension 9 requires never touch disk raw or appear in a log; if the check needs
   authentication it comes from `config/auth.conf`, not from the URL.
3. Canonicalize a numeric host.
   A host that parses as an IPv4 or IPv6 literal is normalised to its canonical dotted-quad or
   compressed-colon form before either the scope-tuple compare or the deny-list compare, which closes
   every non-canonical numeric spelling as a distinct bypass:
   - Decimal (`2851995906`), octal (`0251.0.0.1` / `025154325002`), and hex (`0xA9FEA9FE`) IPv4 forms all
     canonicalize to the same dotted-quad `169.254.169.254` before comparison.
   - IPv4-mapped and IPv4-compatible IPv6 (`::ffff:169.254.169.254`, `::a9fe:a9fe`) canonicalize to the
     same address family used by the deny list, so the `169.254.0.0/16` entry catches the IPv6 spelling
     too.
   - A host that is a numeric literal in **any** of these forms skips DNS resolution entirely (there is
     nothing to resolve), so step 4 below applies the deny list to the canonicalized literal directly,
     not just to the outcome of a lookup; the "IP literals must be authored literally" rule above governs
     which literals a target may *author*, this step governs what every literal *means* once one appears,
     authored or discovered.
4. Lowercase the host, strip one trailing dot, convert IDNs to A-labels (already stated above; repeated
   here because it is step 4 of one pipeline, not a separate check that could run out of order or be
   skipped for one call site).

Steps 1-4 are one function, not four call sites a check script could invoke a subset of; a module cannot
"skip encoding normalization because this call is only ever hit with a literal IP" any more than it can
skip the deny list, because both live inside `http_request` and neither is reachable independently.

**Redirect-recheck parity.**
The manual, one-hop-at-a-time redirect loop re-runs the **entire** gate above on each `Location` header,
including the normalization pipeline, not a lighter host-only comparison.
A `Location` is untrusted target output (tension 10) before it is anything else, so it goes through the
identical percent-decode / userinfo-strip / numeric-canonicalize / lowercase-and-dot-strip sequence the
initial URL does, then the same `(scheme, host, port)` tuple compare and the same resolution-pinning and
deny-list steps, including a fresh per-hop resolution (each hop is a new host, so the once-per-run
resolution cache is keyed per resolved host, not per run-start).
An implementation that fast-paths the redirect check to "just compare the new host string" reintroduces
every bypass class above one hop later, which is why this is stated as parity with the initial check
rather than assumed to follow from it.

**Auditability.**
A caught bypass attempt is not a silent abort.
Whichever step rejects the URL - deny-list hit, out-of-scope tuple after normalization, a decode that
changed the host, a non-empty userinfo - produces a scope-violation finding record (same record path the
existing deny-list-hit abort already uses) carrying the check id, the raw input as given to `http_request`,
the canonicalized value the gate actually compared, and which pipeline step rejected it.
The raw and canonicalized values go through `finding_set_evidence` like any other evidence field, so a
userinfo credential embedded in the rejected URL is redacted (tension 9) rather than landing in the report
in the clear.
This is what makes a bypass *attempt* - as opposed to a successful bypass, which by construction cannot
reach the network - visible to the operator instead of only visible as a process exit code in a log no one
reads; it is also what lets a future review confirm the gate is actually being exercised by a run rather
than trivially satisfied because nothing ever tried to violate it.

**Consequence for the build.**
`lib/http.sh` at §13 step 5 owns the tuple set, the resolution cache, the deny list, and the manual
redirect loop.
`config/scope.conf` moves to the block-record format (tension 26), which is what lets `notes` be free
text and `extra-host` be repeatable.
Tests cover each bypass in turn: a different port, a subdomain, a redirect to an out-of-scope host, a
hostname resolving to `169.254.169.254`, an `http://` probe of an `https://` target, a percent-encoded
host that decodes to an in-scope or deny-listed name, a URL carrying userinfo naming an in-scope host
while the real authority host is out of scope (`http://allowed@evil/`), a decimal/octal/hex IPv4 literal
for `169.254.169.254`, an IPv4-mapped IPv6 literal for the same address, and a redirect `Location` that
itself carries one of the encoding bypasses above, to prove the redirect recheck applies the full
pipeline rather than a host-string compare.
Each rejected case also asserts a scope-violation finding record was produced (the auditability
subsection above), not just a non-zero exit, so the audit trail is pinned by the same tests as the
rejection itself.

**Verification.**
This resolution is a contract, not yet code (`lib/http.sh` lands at §13 step 5); a reviewer signing off
before that implementation starts can check the contract itself rather than an implementation:

- `grep -n "Entry point\." docs/FOUNDATION.md` finds the callout naming `http_request` as the single
  chokepoint (AC1).
- `grep -n "Normalization order\.\|Redirect-recheck parity\.\|Auditability\." docs/FOUNDATION.md` finds
  the three subsections covering encoding/authority-confusion, redirect-recheck parity, and audit
  logging added by this ticket, alongside the pre-existing IP-literal-vs-hostname, redirect, and
  case/trailing-dot coverage in the same tension, so all four AC2 bypass classes (encoding, IP-literal
  vs hostname, redirects, case/trailing-dot) are enumerated in one place.
- `grep -n "percent-encoded\|userinfo\|IPv4-mapped\|decimal.*octal.*hex" docs/FOUNDATION.md` confirms the
  specific encoding sub-cases (percent-encoding, userinfo/authority confusion, numeric IP-literal
  obfuscation) the round-1 tech-lead review flagged as missing are now present.
- `docs/FOUNDATION.md` still has exactly one `## Tension 19` heading and this document remains the sole
  owner of scope-gate semantics; `grep -rn "scope-gate\|scope gate" docs/` finding no second document
  making competing claims rules out the doc-fork the tech-lead review also flagged.
- Sign-off itself is a tracker action, not a grep: this ticket is handed to `in_review` with this diff
  attached so a human or the tech-lead role can record an explicit approve/request-changes verdict in the
  ticket tracker, per AC3. No `lib/http.sh` or other network-call code is added by this change, so
  the gate implementation gate ("§13 step 5 does not start until sign-off") is preserved by construction:
  there is nothing here to have jumped ahead of the sign-off.

**Implementation.**
The paragraph above is the record of the contract-definition ticket, before any code existed; it is left
as written rather than rewritten, because it is the sign-off record this tension's own "Verification"
section describes.  The follow-on ticket (`e3c8f1e`, "Implement the scope.conf authorization gate for
DAST targets") landed the code this paragraph is a status update for: `lib/http.sh` now implements every
mechanism this tension describes - `http_url_normalize` (steps 1-4), `http_scope_load`/`http_scope_match`
(the tuple compare, the port-80 relaxation, `allow-subdomains`), `http_resolve_host` (resolution pinning,
cached per host), the IPv4/IPv6 deny list, `http_gate_url` (the pure predicate), and `http_request` (the
chokepoint: fatal on the initial URL, non-fatal per redirect hop, `--resolve`-pinned, `--max-redirs 0`)
- plus the auditability finding (`DAST-SCOPE-GATE-VIOLATION`) and the `tests/lint-shell.sh` "no bypass"
check.  `tests/suites/http.sh` is the regression suite.  Two things this ticket deliberately left open
rather than silently narrowing the contract: IDN/A-label conversion (hosts are compared as lowercased
bytes, not punycode-normalised - a real homograph-bypass gap, tracked separately) and a general IPv6 CIDR
matcher (the deny list currently matches `::1` exactly, `fe80::/10` and `fd00::/8` by leading-hextet
pattern, and the two documented embedded-IPv4 forms, rather than an arbitrary compressed address). The
rate limiter, request budget, and circuit breaker (tension 16) are still not built; `http_request` is the
place they hook in when they are.

## Tension 20 - paranoid mode versus infrastructure traffic

**The tension.**
§2's `--paranoid` "logs every destination host any child process opens ... and **aborts on the first
host not in the allowlist**", where the allowlist is "scope hosts + AWS endpoints".
§12 requires a no-egress test that runs the full suite under `--paranoid` and asserts zero out-of-scope
connection attempts.

**Why it bites.**
Resolving `scope.conf`'s hostnames requires talking to a DNS resolver, and the resolver is a host that
is not in the allowlist.
So `--paranoid` aborts on scoursh's own first name lookup, before it has sent a single request to the
target.
The same is true of anything else the host does incidentally.
The result is that `--paranoid` is unusable, so it gets left off, so the §12 no-egress test never runs,
so the tool's central claim is untested.
A safety feature that always fires is a safety feature that is always disabled.
There is also an honesty problem: §2 already admits sampling can miss short-lived connections, but the
text still reads as though `--paranoid` is a guarantee, and the §12 test asserting "zero out-of-scope
connection attempts" would then be asserting something the mechanism cannot deliver.

**Options considered.**

1. *Allowlist anything on port 53.*
   Rejected: it authorises an arbitrary host as long as the exfiltration is dressed as DNS, which is the
   most common covert channel there is.
2. *Warn instead of abort on unknown hosts.*
   Rejected: §2 says abort, and a warning in a long log is not a control.
3. *An explicit, narrow infrastructure allowlist, plus honest framing of what the mechanism proves.*
   **Chosen.**

**RESOLUTION.**

The `--paranoid` allowlist is the union of exactly four sets, and nothing else:

1. Resolved addresses of in-scope targets, from `lib/http.sh`'s pinned resolution cache (tension 19),
   on their authorised ports only.
2. Resolved addresses of AWS API endpoints for the regions actually iterated.
3. **Infrastructure**: the nameserver addresses parsed from `/etc/resolv.conf`, **port 53 only**, plus
   loopback.
   This is derived from the host's own configuration rather than authored, so it cannot be widened by
   accident, and it is written into `run.json` so a reader can see exactly what was permitted.
4. Anything in `scanner.conf`'s `paranoid_allow` list, which is empty by default and whose entries are
   `addr:port` pairs.

Any other destination aborts the run with exit `3`.
Because `lib/http.sh` pins resolution per run (tension 19), the number of legitimate DNS lookups is
small and bounded, which keeps set 3 narrow.

**What the mechanism proves is stated plainly** in the report and in the docs: `--paranoid` observes
connections by sampling, so it is a **detector**, not a guarantee, and a sufficiently short-lived
connection can evade it.
`tools/run-in-netns.sh` is the guarantee, because a network namespace whose only route is to the
declared scope makes an out-of-scope connection impossible rather than merely observable.
§15 carries this limitation, since §15 is where coverage claims are kept honest.

**The §12 no-egress test is made deterministic** by removing DNS from it entirely: the fixture suite runs
against recorded mock responses and `file://` inputs with `--resolve` entries pre-seeded for the mock
listener on loopback, so a passing test means zero connections outside loopback rather than "zero
connections we did not expect".
An assertion about a sampled observation would otherwise be flaky, and a flaky security test gets
deleted.

**Consequence for the build.**
§13 step 8 implements `--paranoid` and the netns tool; the allowlist construction depends on
`lib/http.sh`'s resolution cache from step 5, so the ordering already works.
The observer covers child processes, which matters because §10 fans out with `xargs -P`; it attaches at
the process-group level (`ss` sampling filtered by the run's cgroup or process group, or
`strace -f -e trace=connect` where available and permitted) rather than to a single pid.
Where neither is available, `--paranoid` fails with exit `4` rather than pretending to be active.
(See "Backend roster" below: the roster this paragraph names is **extended**, not replaced - `lsof`
was added as a third backend so the mechanism exists at all on macOS.
The exit-`4` rule is unchanged and now means "none of the three is usable".)

**Implementation.**
`lib/paranoid.sh` (PARANOID-01) now implements every mechanism this tension describes.
`paranoid_allowlist_build` assembles the four sets in one call.
`_paranoid_allowlist_in_scope` proactively resolves (not merely reads) every `config/scope.conf`
tuple through `lib/http.sh`'s `http_resolve_host` *before* the observer starts.
That ordering is how this implementation closes the bootstrapping problem this tension opens with
("`--paranoid` aborts on scoursh's own first name lookup") - by sequencing (resolve everything the
run could need, unobserved, then attach), not by a DNS-specific carve-out, since option 1 above
("allowlist anything on port 53") stays rejected.
`_paranoid_allowlist_aws` degrades set 2 to empty with a stated reason (`run.json`'s
`paranoid_allowlist_note`), because `modules/cloud/aws/regions.sh` (§13 step 6) has not landed yet.
That is the same forward-dependency shape `docs/STEP5-DAST-PLAN.md`'s DAST-09 used for
`data/versions.db`.
`_paranoid_allowlist_infra` parses the host's own `/etc/resolv.conf` for `nameserver` lines (port 53
only) and adds loopback (`127.0.0.0/8`, `::1`) unconditionally on any port.
The two are not the same rule, precisely because option 1 above is rejected for the resolver case but
loopback never leaves the host.
`_paranoid_allowlist_operator` reads `scanner.conf`'s `paranoid_allow`.

**Family, not process group, for the kill action.**
The RESOLUTION text above says "ss sampling filtered by the run's cgroup OR process group".
This implementation instead attributes both the sampler's readings AND the abort's kill action to the
DESCENDANT-PROCESS FAMILY rooted at the main `scan.sh` pid (`_paranoid_family_pids`, a fixed-point
walk over `ps -Ao pid=,ppid=`), not the raw OS process group.
This is a correction found empirically while building this ticket, not a stylistic choice: a plain
`cmd &`/`( ... )` never changes pgid, so `scan.sh`'s own process group is whatever group its OWN
invoker happens to be in.
Reproduced directly against this project's own test harness, a pgid-wide `kill -TERM` on a violation
took out the test runner driving the suite itself, because sourcing `scan.sh` and calling `scan_main`
inside nested subshells shares one process group with the whole harness, none of it under `setsid`.
Every `xargs -P` worker is a descendant of the invoking `scan.sh` process regardless of pgid, so the
family walk gets the same coverage this tension's "not per-pid" requirement (§13 step 8's AC3) asks
for, without that blast radius.

The abort path is a dedicated `SIGUSR2` trap (`paranoid_on_violation`), installed by `paranoid_attach`
and never overloaded onto the existing `SIGTERM`/`SIGINT`/`SIGHUP` handlers `lib/core.sh` already
installs.
Those exit `5` ("incomplete run"); a paranoid violation must exit `3`, a different point on tension
14's precedence table, so it cannot share their signal or their exit path.
The background sampler writes a violation marker and signals the main process rather than aborting
the run itself, because only the main process can produce the exit-3 `die()` tension 14 requires.
Measured directly (20/20 runs): a `wait` on the sampler's own pid reliably lets a pending trapped
signal interrupt it and run before the waiter's own next statement, which is what makes the handoff
deterministic rather than a race against how much work the dispatched module still has left to do.
`_paranoid_audit_violation` mirrors `lib/http.sh`'s `_http_gate_audit` - the same finding pipeline,
reusing the `dast` fingerprint profile rather than adding a new module to the closed enum
`lib/findings.sh`'s `_fp_profile_for` owns, for one check id (`PARANOID-EGRESS-VIOLATION`).

The "detector, not guarantee" framing is written into `run.json`'s `coverage_gap` array (via
`run_record coverage_gap ...` in `paranoid_attach`, read by both `lib/report.sh` limitations
emitters) on every `--paranoid` run.
That is how the framing reaches the actual report output this tension's own RESOLUTION requires, not
only this document.

`tests/suites/paranoid.sh` is the regression suite, and it is fully deterministic on every host.
`SCOURSH_PARANOID_FORCE_BACKEND` overrides the backend probe (mirroring
`SCOURSH_FORCE_MSLEEP_IMPL`, `lib/core.sh`) and `SCOURSH_PARANOID_SAMPLE` overrides the sampler
itself with a scripted, recorded sequence of "observed" connections (mirroring `lib/http.sh`'s own
`SCOURSH_HTTP_RESOLVE`/`SCOURSH_HTTP_TRANSPORT`).
So the no-egress fixture this tension asks for never depends on any backend actually being installed -
`ss` and `strace` are Linux-only, `lsof` is not universal either, and this project's suite runs on both
userlands.
`tools/run-in-netns.sh` (NETNS-01) is not implemented by this ticket, per
`docs/STEP8-PARANOID-PLAN.md`'s own split.

**Backend roster: `ss`, `strace`, and now `lsof` - a deliberate EXTENSION of this RESOLUTION.**
The "Consequence for the build" paragraph above names `ss` and `strace -f -e trace=connect`
specifically, and both are Linux-only.
macOS ships neither, so on macOS the mechanism this tension exists to provide did not exist at all:
`--paranoid` refused every run with exit `4` before dispatching a single module.
That was recorded as a documented limitation while Linux was the assumed platform.
It is no longer acceptable, because macOS is now the platform this tool is primarily run on, and a
flagship safety control that is unavailable on the primary platform is a control nobody has.

`lsof` is therefore added to the roster as a third backend, and this register records the addition the
way Tension 27 records the `adapters/` generalisation: as an extension made deliberately, not a quiet
divergence in code.

**This changes nothing about what the tension MEANS**, which is why it is an extension rather than a
re-resolution, and each half of that claim is worth stating rather than asserting:

- The four-set allowlist is untouched.
  A backend only answers "what destinations did this run's own processes connect to"; it has no say in
  which of them are permitted.
- The abort contract is untouched: exit `3` on the first out-of-allowlist destination, exit `4` when no
  backend is usable.
  Exit `4` now means "none of `ss`, a usable `strace`, or a usable `lsof`", which is strictly narrower
  than before - a host that used to refuse may now run, and no host that used to run now refuses.
- **The honesty framing is untouched, and this is the half most at risk of quiet inflation.**
  `lsof` is a **sampler**, exactly like `ss`, with exactly the same blind spot: a connection that opens
  and closes between two polls is never observed.
  It is emphatically not a tracer, so it buys nothing `ss` did not already buy, and nothing about
  "detector, not guarantee" softens because a third platform now has a detector.
- The order is `ss` -> `strace` -> `lsof`, and `lsof` is APPENDED rather than inserted.
  `strace` is a tracer and therefore the strictly stronger detector where it is genuinely usable, and
  appending means no host that resolved to a backend before this change resolves to a different one
  after it.
  Only a host that previously resolved to `none` is affected at all.

**`lsof` and not `netstat`, `nettop`, or `dtruss`**, all of which macOS also ships, each rejected for a
measured reason rather than a stylistic one (measured on macOS 26.5.2, arm64, as an ordinary
unprivileged user):

- `netstat` has no per-process filter on macOS, so a connection cannot be attributed to the run's own
  process family - which is the entire mechanism `_paranoid_family_pids` implements.
- `nettop`'s per-connection rows carry no pid of their own; they are emitted under a preceding process
  row, so attribution needs stateful parsing of an interactive tool's batch dump, and its per-process
  (`-P`) mode drops the remote address entirely.
- `dtruss` would be the macOS analogue of `strace`, and it is deliberately NOT a candidate: DTrace
  generally requires System Integrity Protection to be disabled, and a security tool must not ask an
  operator to weaken their operating system in order to be observed.
- `lsof` runs unprivileged, and `lsof -F` is a purpose-built machine-readable mode emitting one
  `p<pid>` line followed by that process's own `n<local>-><peer>` lines, so a command name containing a
  space cannot shift a column.

**What macOS still does NOT get, stated plainly so no reader infers parity.**
`tools/run-in-netns.sh` - the guarantee this tension names, and the only mechanism here that makes an
out-of-scope connection impossible rather than merely observable - is built on Linux network
namespaces and **has no macOS equivalent**.
Nothing in this extension provides one.
So on Linux the two tiers are "detector, plus a guarantee available separately"; on macOS there is the
detector and nothing behind it.

**Usability is MEASURED, with a positive control, not inferred from `command -v`.**
`lsof` exits `1` both when it matched nothing and, on a restricted host, when it was not permitted to
look, so an exit-status probe cannot tell those apart.
`_paranoid_probe_lsof` therefore opens a socket of its own - a connected loopback UDP socket, which
needs no listener and transmits nothing, since `connect(2)` on a UDP socket only records a default
peer - and requires `lsof` to report that exact socket back.
The control socket is loopback (allowlist set 3) and is opened before the observer attaches in any
case, so the probe cannot trip the mechanism it is probing.

**One defect found while building this, recorded because it is invisible and expensive.**
The natural spelling of that probe, `exec {pfd}<>/dev/udp/127.0.0.1/9 2>/dev/null`, is wrong: `exec`
with redirections and no command makes those redirections **permanent for the shell**, so the
`2>/dev/null` silenced the main process's stderr for the rest of the run.
Every log line a `--paranoid` run would have printed disappeared - including the violation message
itself - while the exit code stayed correct, so the detector looked like it was working and had merely
gone mute.
The fix is a brace group (`if ! { exec {pfd}<>...; } 2>/dev/null`), which scopes the redirection while
leaving the fd assignment in place, and `tests/suites/paranoid.sh` pins it with a case that fails under
the original spelling.

`tests/suites/paranoid.sh` covers the new backend at three levels, all of which run on every host: the
`lsof -F pn` parser against canned output (including a foreign pid, a `LISTEN` row and an unbound
socket, each of which must be dropped), the probe against a stubbed present-but-blind `lsof`, and the
`ss` -> `strace` -> `lsof` order against stubbed availability.
A further host-conditional section runs the real `lsof` binary against real sockets - up to and
including a full `scan_main --paranoid` run that aborts with exit `3` on a real socket held by a real
descendant - and is honestly marked SKIPPED, never silently passed, where `lsof` is absent.
That section is still a **no-egress** test: its sockets are connected UDP sockets, so an RFC 5737
TEST-NET-3 destination is observable without a single packet leaving the machine, which is exactly what
this tension's §12 fixture requires.

## Tension 21 - module independence versus cross-module inventory

**The tension.**
The handoff header states "Each module is independent and testable in isolation."
§7.5 says the crawler performs "**Route import from SAST (§8.4)** - merge the statically-extracted server
routes", and §8.4 says API Gateway's route list is "fed to DAST as candidate targets".
So DAST consumes artifacts produced by SAST and by the cloud module.

**Why it bites.**
Both claims are load-bearing and they contradict.
If modules genuinely call each other, then `scan.sh dast` alone either fails or silently runs with a
fraction of its intended surface, and §12's promise that each module is testable in isolation against
mock responses stops holding.
If modules never exchange anything, then §7.5's own honest-limitation note is unsatisfiable: it lists
"rely on **SAST route extraction** for server endpoints" as mitigation number two for the SPA blind
spot, so the import is the answer to a stated coverage gap, not a nicety.
And whichever way it is resolved, a standalone `dast` run that quietly tests fewer endpoints while
reporting the same clean verdict is precisely the overstated coverage §15 forbids.

**Options considered.**

1. *Let `dast` invoke `sast`'s route extractor.*
   Rejected: it makes DAST depend on SAST's code and on a source tree being present, and it breaks
   isolated testing.
2. *Merge the modules.*
   Rejected: §3's layout and §16's extension model are built on module separation.
3. *Exchange data only through run-directory artifacts with a frozen schema.* **Chosen.**

**RESOLUTION.**
**Modules never invoke each other and never import each other's code.**
They communicate only through **artifacts in the run directory**, with a frozen schema:

```
reports/<run>/inventory/endpoints.json
reports/<run>/inventory/parameters.json
```

Any module that can produce inventory writes into it, and `crawl.sh` merges and dedupes:

- SAST route extraction (§8.4) writes server routes it finds statically.
- `aws/live/apigw.sh` writes API Gateway routes.
- `crawl.sh` writes what it crawls and what it parses from an OpenAPI, GraphQL, Postman, or HAR input.

Every consumer treats the inventory as **optional input**.
When it is absent or thin, the consumer records a `coverage_gap` entry in `run.json` naming what was
missing, and `lib/report.sh` renders those entries in the report's limitations section, which is the
§15 section that exists for exactly this.
So a standalone `dast` run still works, still tests everything it can discover itself, and **says in its
own report** that it had no SAST routes and no API Gateway inventory.
It never reports the same coverage as a full run.

`scan.sh all` runs modules in a frozen order so the inventory is as complete as possible before it is
consumed:

```
sast -> sca -> iac -> cloud -> dast
```

DAST last, deliberately.
For the standalone case, `--from-run <dir>` imports a previous run's inventory, which lets a fast DAST
loop reuse a nightly full run's route extraction without re-running SAST.
Imported inventory is recorded in `run.json` with its source run id, because inventory from a stale
source is a coverage claim that needs an audit trail.

The scope gate is unaffected and is applied after the merge: an endpoint in the inventory whose host is
not in `scope.conf` is dropped with a `run.json` record, exactly as §7.5 already requires.
An `apigw`-sourced endpoint is a candidate, never an authorisation.

**Consequence for the build.**
The inventory schema is frozen at §13 step 1 with the rest of the data model, even though its first
producer arrives at step 3 and its first consumer at step 5.
`tests/` can then feed a fixed `endpoints.json` to `crawl.sh` and to the active checks with no SAST run
at all, which is what keeps the header's isolation claim true.
A test asserts that a standalone `dast` run emits the `coverage_gap` entries and that they appear in the
report.

## Tension 22 - SARIF locations for findings with no file

**The tension.**
§4 requires SARIF 2.1.0 output "for CI / code-scanning ingestion".
A SARIF `result` is expected to carry a `physicalLocation` with an `artifactLocation.uri`.
Cloud findings identify an ARN, DAST findings identify a URL and a parameter, and §8.7 posture findings
identify an expected control that is absent.
None of them has a file, and most have no line.

**Why it bites.**
There are only bad naive answers.
Omitting `locations` produces SARIF that a schema validator may accept but that real code-scanning
ingesters reject or file at an arbitrary location, so §12's "validates JSON/SARIF schema" passes while
the actual ingestion goal fails.
Synthesising a plausible-looking source path is worse: a cloud misconfiguration reported at
`main.tf:1` sends an engineer to a file that has nothing to do with the finding, and if that file
happens to exist the annotation lands on someone's unrelated pull request diff.
Since the cloud, DAST, and posture modules are three of the five, this is the majority of findings for
many runs, not an edge case.

**Options considered.**

1. *Emit SARIF only for SAST and IaC.*
   Rejected: §4 asks for SARIF as an output of the tool, and the compliance and CI story needs cloud
   findings in the same feed.
2. *Use `logicalLocations` alone.*
   Rejected: it is the semantically correct field and it is exactly what real ingesters ignore, so the
   findings would validate and then be invisible.
3. *Emit a real generated artifact and point at it, alongside the logical location.* **Chosen.**

**RESOLUTION.**
Every SARIF `result` carries **both** a logical and a physical location, and the physical location always
points at a file that genuinely exists.

- **`logicalLocations[0]`** carries the semantic identity: `fullyQualifiedName` is the ARN, or
  `<target>:<method> <path_template>#<param>`, or the posture control id, with `kind` set to `resource`,
  `endpoint`, or `control`.
- **`physicalLocation`** for SAST, IaC, and container findings is the real source file and line, exactly
  as expected.
- **`physicalLocation`** for cloud, DAST, and posture findings points into a **generated location
  artifact** written by `lib/report.sh` into the run directory:

  ```
  reports/<run>/locations/<module>.txt
  ```

  one line per finding, containing that finding's logical identity, with `region.startLine` set to the
  finding's line in that file.
  The file is a real artifact of the run, it is committed to nothing, it is included in the SARIF
  `artifacts` array, and clicking through in a code-scanning UI lands the reader on a line that
  describes precisely the resource in question.
  Nothing is fabricated, and no source file is implicated in a finding that is not about it.

Two further requirements make the SARIF actually useful rather than merely valid:

- **`partialFingerprints`** carries `scourshFingerprint/v1: <fingerprint>` (tension 5).
  This is SARIF's own mechanism for stable result identity, so the consumer's new/fixed tracking aligns
  with scoursh's §9a diff instead of contradicting it.
  It is also the reason tension 5's line-number exclusion matters here: a line-based fingerprint would
  make the consumer's history churn identically.
- **`tool.driver.rules[]`** carries the full loaded check registry, keyed by `check_id` (tension 7), with
  each result's `ruleId` referencing it.
  `properties` on the result carry `module`, `status`, `confidence`, `cvss`, and `suppressed`.
  A finding suppressed by `baseline.json` (tension 11) is emitted with SARIF's own
  `suppressions[].kind: "external"` rather than being dropped, so the consumer sees the accepted risk
  instead of a gap.

**Consequence for the build.**
§13 step 1 fixes the location model in the finding schema so every module records a logical identity from
the start; §13 step 10 writes the SARIF emitter and the location-artifact writer together.
The §12 SARIF validation test is strengthened: it validates against the 2.1.0 schema **and** asserts
that every result has a non-empty `locations[0].physicalLocation.artifactLocation.uri` pointing at a path
that exists in the run directory or the scanned tree.

## Tension 23 - a read-only AWS lint that survives contact with reality

**The tension.**
§8.1 requires a CI lint that "greps the live scripts and fails CI if any mutating verb
(`create/put/delete/update/modify/attach/authorize`) appears".
§12 requires that lint to run in the test suite.

**Why it bites.**
Those substrings appear constantly in genuinely read-only code.
`aws organizations describe-create-account-status` is read-only and contains `create`.
`aws iam list-attached-role-policies` contains `attach`.
`aws iam get-account-authorization-details` contains `authoriz`.
`aws eks describe-update` contains `update`.
So do the parts of the file that are not API calls at all: a `remediation` string saying "delete the
public snapshot", a comment explaining that the check does not modify anything, a variable named
`update_available`.
The lint therefore fails on nearly every correct script, and the entirely predictable outcome is that
someone adds enough exclusions to make it pass, or comments it out, and the guarantee §14 calls
"read-only by construction and enforced by a CI lint" quietly evaporates.
A control that cries wolf is removed, and its removal looks like a cleanup commit.
There is also a real gap the grep cannot close in either direction: §8.1's multi-account support needs
`sts assume-role`, which is not a read verb and is nonetheless required.

**Options considered.**

1. *Refine the denylist regex with word boundaries and an exclusion list.*
   Rejected: it is an arms race against the AWS API's naming, the exclusion list grows monotonically,
   and one missed case is a false negative in a control that only matters for its false negatives.
2. *Lint the AWS CLI's own metadata for whether an operation mutates.*
   Rejected: it requires the CLI's service model on an air-gapped host and a JSON parse of it, and §1
   rules out that dependency.
3. *Route every call through a wrapper, allowlist by operation prefix, enforce at runtime and with a
   linter in the test suite.*
   **Chosen.**

**RESOLUTION.**
Stop linting prose and start linting invocations, and back the lint with a runtime check so the property
holds even if the lint is wrong.

1. **A single chokepoint.**
   Every AWS call goes through `aws_ro <service> <operation> [args...]` in `lib/awscli.sh`, mirroring
   what `lib/http.sh` is for HTTP.
   A bare `aws` invocation anywhere is a lint failure.
2. **Runtime enforcement.**
   `aws_ro` validates the operation before executing, against a frozen allowlist of read-only prefixes:

   ```
   ^(describe|list|get|search|lookup|select|head|batch-get|preview|estimate|simulate)(-|$)
   ```

   A non-matching operation aborts with exit `3` and is logged as a scope violation, the same class as
   an out-of-scope host, because it is the same kind of breach: the tool attempting something it is not
   authorised to do.
   This is the guarantee that actually holds, because it survives a typo, a dynamically-constructed
   operation name, and a broken lint.
3. **A precise CI lint,** which can now be exact rather than heuristic, because it inspects arguments
   rather than text:
   - every `aws` invocation is via `aws_ro`;
   - the literal `<operation>` argument of each `aws_ro` call matches the prefix allowlist;
   - an `aws_ro` call whose operation is a variable is only permitted when that variable is assigned
     from a `readonly` array of literals declared in the same file, and the lint checks every literal in
     that array.

   Comments, remediation strings, and variable names are never examined, so the lint has no false
   positives by construction.
4. **A small, reviewed exception file** for operations that are legitimately needed and are not read
   verbs.
   `tests/aws-readonly-allow.txt` holds exact `service operation` pairs with a justification comment,
   seeded with `sts assume-role` (required by §8.1 multi-account) and `sts get-caller-identity` (which
   the prefix allows anyway, listed for clarity).
   The lint fails on any call not covered by the prefix allowlist **or** this file, **and** fails on any
   file entry that no longer appears in the code, so the exception list cannot rot into a blanket
   permission.
   An allowlisted exception is still refused at runtime unless the same pair is present, so the file is
   the single source of truth for both.
5. `aws_ro` additionally pins `--no-cli-pager` and `--output json`, and never accepts `--cli-input-json`
   or `--cli-input-yaml` from a caller, since either would let an operation's real shape come from
   somewhere the lint never sees.

**Consequence for the build.**
`lib/awscli.sh` is a new library, not in §3's layout, and it lands at the start of §13 step 6 before any
`aws/live/*.sh` script exists, so no script is ever written against a bare `aws`.
It is also the natural home for the per-`(service, region, account, operation, args)` response cache from
§10 and tension 16.
`tests/lint-aws-readonly.sh` implements the four checks above, and a negative test asserts that a script
calling a mutating operation fails both the lint and the runtime guard.

## Tension 24 - runtime freeze: bash and coreutils portability

**The tension.**
§4 depends on `sha256_of`, `now_iso`, and `mktemp -d`; §10 depends on `xargs -P` and a per-key cache
that wants an associative array; tension 16 needs sub-second sleep; tension 25 needs version-aware
sorting.
None of these is portable, and §1 promises "pure bash by default" running on "an air-gapped host",
which says nothing about which bash.

**Why it bites.**
The specific breakages are not exotic, they are the first things any implementer hits.
macOS ships bash **3.2**, which has no associative arrays, no `mapfile`, and no `${var@Q}`; under
`set -u` it also errors on `"${arr[@]}"` for an empty array, which happens the first time a rule matches
no files (tension 4).
`sha256sum` is GNU; macOS has `shasum -a 256`; some minimal images have only `openssl dgst -sha256`; and
all three print a trailing filename that must be stripped, so a naive `sha256_of` silently includes the
filename in the hash and every fingerprint in the tool becomes path-dependent in a way tension 5 did not
intend.
`sort -V` is GNU-only.
`date -Iseconds`, `date -d`, `stat -c`, `readlink -f`, `sed -i` without an argument, and `xargs -r` are
all GNU-only with different or absent BSD equivalents.
`sleep 0.05` is not POSIX.
Each of these fails differently on different hosts, and several fail *silently*, which for a tool whose
output is a security verdict is the worst category.

**Options considered.**

1. *Target POSIX `sh` for maximum portability.*
   Rejected: no arrays, no `local`, no `pipefail`, and §4 mandates bash-specific `set -E` and `ERR`
   traps.
2. *Target GNU only and document it.*
   Rejected: it excludes macOS, which is where a large share of the SAST and IaC use will happen, and
   §1's air-gapped host is not guaranteed to be Linux.
3. *Freeze a minimum bash and put every non-portable call behind one detected wrapper.* **Chosen.**

**RESOLUTION.**

**Interpreter.**
`bash >= 4.2` is required.
`scan.sh` starts with `#!/usr/bin/env bash`, and if `BASH_VERSINFO` is below 4.2 it searches
`$SCOURSH_BASH`, then `/opt/homebrew/bin/bash`, `/usr/local/bin/bash`, and `PATH` for a newer bash and
**re-execs itself** under it.
Finding none, it exits `4` with a message naming the requirement and the remedy.
4.2 buys associative arrays, `mapfile`, and `printf -v`; 4.4's empty-array-under-`set -u` fix is not
assumed, so every array expansion is written `"${arr[@]+"${arr[@]}"}"`, and the lint enforces it.

**One capability layer.**
`lib/core.sh` probes once at startup and binds exactly one function per capability.
Nothing else in the repository may call the underlying tools directly, and a lint enforces that by
failing on `sha256sum`, `shasum`, `sort -V`, `grep -P`, `readlink -f`, `sed -i`, `date -d`,
`date -Iseconds`, `stat -c`, `stat -f`, `xargs -r`, and `mktemp -p` outside `lib/core.sh`.

| Function | Implemented over |
|---|---|
| `sha256_of` | `sha256sum`, else `shasum -a 256`, else `openssl dgst -sha256`; **reads stdin only** (tension 9), output normalised to bare lowercase hex with any trailing filename stripped, and **rejected if it is not 64 hex characters**, since a provider that leaves the filename in would make every fingerprint path-dependent |
| `now_iso` | `date -u +%Y-%m-%dT%H:%M:%SZ`, which is portable, rather than `-Iseconds` |
| `now_epoch` | `$EPOCHSECONDS` where the shell has it, else `date -u +%s`. Added by finding F15: tension 16's mutex sample called it while it was not among the frozen functions |
| `now_epoch_ns` | `$EPOCHREALTIME` (a builtin, so no fork) where the shell has it, else `date -u +%s%N` where it yields real nanoseconds, else `%s` scaled - with `SCOURSH_CLOCK_NS` recording whether the source is genuinely sub-second, so the rate limiter's arithmetic and the `msleep` probe both know what they are working with |
| `msleep` | **See below (finding F14).** `sleep 0.05` when a MEASUREMENT shows it really sleeps, else a `read -t` on a FIFO this process holds open read-write, else a 1-second floor with a startup warning |
| `stat_mode` | `stat -c %a`, else `stat -f %Lp` |
| `stat_mtime` | `stat -c %Y`, else `stat -f %m`. Added by finding F15: `lock_is_stale` needs an mtime accessor and the frozen table provided only `stat_mode`, while linting `stat` out of every file but `lib/core.sh` |
| `proc_alive` | `kill -0`. Added by finding F15, which named a liveness primitive without providing one |
| `erase_dir` | `shred -u -n 1` over the regular files where `shred` exists, then `rm -rf` either way. Added by finding F16 |
| `realpath_of` | `readlink -f`, else `cd`-and-`pwd -P` in a subshell. Resolves a path that does not exist yet by resolving the deepest existing ancestor and appending the remainder, because a run directory is named before it is created and `readlink -f` does not accept a missing component on every BSD |
| `sed_inplace` | `sed -i.bak` plus removal, which is the one form both accept |
| `tmpdir_make` | `mktemp -d "${TMPDIR:-/tmp}/scoursh.XXXXXXXX"`, which is the portable form |

**`msleep` is selected by measurement, never by exit status (finding F14).**
The frozen fallback was `read -t 0.05 </dev/null`, described as "a bash builtin, so no process".
Reading from `/dev/null` returns at EOF **immediately**; the timeout never elapses.
Measured: 2000 iterations complete in 0 seconds, where a real 0.05 s sleep would take 100.
Tension 16's `mutex_acquire` retry loop therefore became a spin that burned a core and consumed its
whole timeout in under a millisecond, so every worker contending for a lock held longer than that -
the AWS cache path holds one across a full API call - aborted with "mutex timeout".

The defect is also **undetectable by a naive probe**, because `read` returns non-zero for EOF exactly as
it does for a timeout, so a probe asking "did `read -t` return non-zero" concludes the fallback works.
Two changes close it:

- **Read from a descriptor that never yields data** rather than one already at EOF: a FIFO under the
  scratch dir, opened read-write (`exec {fd}<>"$fifo"`), so this process is itself a writer, no EOF ever
  arrives, and `read -t` times out as intended.
  `mkfifo` joins the probed-optional list; where it is absent the 1-second floor applies.
- **Probe by measuring elapsed time**, with a discarded warm-up round first.
  A candidate asked for 200 ms must block for at least 100 ms.
  The margin is wide on purpose: what separates a working implementation from a broken one is the
  REQUESTED interval, not a fixed threshold, since a broken one returns after a fork and an exec that
  cost single-digit milliseconds.
  A tighter threshold would make the probe a race against process-startup cost on a loaded machine, and
  a probe that flakes gets deleted - which is how the defect it guards comes back.
  Being wrong in the remaining direction is safe, because the fallback is the one-second floor: slow,
  but correct.
  The warm-up is not decoration: the first exec of an external `sleep` measured 175 ms cold against 7 ms
  warm, and a cold-start artifact would make a broken `sleep` look like a working one - the single
  failure the probe exists to catch.
  Where there is no sub-second clock at all, nothing can be verified, so the 1-second floor applies and
  is recorded; refusing to certify what cannot be measured is the point.

`tests/suites/core.sh` reproduces the defect, asserts that an exit-status probe cannot see it, asserts
that the selected implementation really sleeps, and asserts that a fake `sleep` which returns instantly
is **rejected** by the probe - which is the case that discriminates the two probe designs.

`require_cmd` runs once at startup and reports **every** missing command at once rather than failing on
the first, since discovering four missing dependencies one run at a time is a bad first experience for an
air-gapped install.
Required: `bash`, `grep`, `sed`, `awk`, `sort`, `tr`, `cut`, `find`, `xargs`, `mktemp`, `date`, `curl`,
one of the SHA-256 providers, and `git` for `history.sh` only.
Optional and probed: `rg`, `rg` with PCRE2 (tension 2), `openssl` (for `tls.sh`), `aws`, GNU `parallel`,
`ss`, `strace` or `lsof` (tension 20 - `lsof` is the one of the three macOS ships), **`mkfifo`** (the
`msleep` fallback, finding F14), **`shred`** and
**`look`** (finding F16).
Everything probed is recorded in `run.json`, so a report always states what the host could and could not
do.

**`shred` is probed, never assumed (finding F16).**
It is GNU coreutils and does not exist on macOS - measured, `command -v shred` returns nothing - yet the
cleanup was specified as shredding, inside the one trap tension 4 rule 5 says must contain no command
that can itself fail.
On a host without it the trap ran a missing command and, under the mandated `set -Eeuo pipefail`, the
process exited **127** on every single run: outside the frozen 0-5 exit contract of tension 14, and with
the scratch dir left behind on exactly the platform this section's CI matrix mandates.
`erase_dir` above replaces it, and `lint-shell.sh` fails on any direct `shred` call outside
`lib/core.sh`.

**Overwrite-based erasure is best effort, and this is stated in the docs rather than implied.**
It achieves nothing on APFS, on journalled ext4, on tmpfs, or on any SSD with wear levelling, so the
security claim of tension 9 handling rule 2 does not rest on it.
The real control is `scratch-dir` pointed at a tmpfs, which `config/scanner.conf` exposes and its
shipped example documents.

`xargs -P` is used without `-r`, which BSD lacks, by never invoking `xargs` on a possibly-empty input:
the caller checks the unit count first.
**Version-aware sorting is not needed at all**, because tension 25 removes range arithmetic from the
scanner entirely.

**Consequence for the build.**
This is the first thing built in §13 step 1, ahead of everything else, since every later line depends on
it.
The full suite runs on Linux with GNU coreutils **and** on macOS with BSD userland, and fails if a
finding, a fingerprint, or a `findings.jsonl` byte differs between them, which is what turns this from
a list of good intentions into a checked property.
That pair of runs used to be a hosted-CI matrix; GitHub Actions is switched off for this repository
now, and `tools/daily-suite.sh` performs both legs and the byte-for-byte diff on the maintainer's own
machine, on a daily schedule (`docs/CI-RUNBOOK.md`).
It refuses to produce a result at all unless the userland it measured is genuinely BSD, because a leg
that silently ran a shadowing ugrep would leave this property unchecked *while reporting that it had
been checked*.

## Tension 25 - offline version matching for SCA

**The tension.**
§6.5 requires matching each pinned `name@version` from a lockfile against `data/advisories.db` and
emitting a finding "with the advisory id, **affected range**, and fixed version", all in pure bash on an
air-gapped host.

**Why it bites.**
"Affected range" means implementing version-range comparison, and there is no such thing as *the*
version ordering: semver has a prerelease precedence rule where `1.0.0-alpha < 1.0.0`, PEP 440 has
epochs, post-releases, and local versions, Maven has its own qualifier ordering where `1.0-SNAPSHOT` is
before `1.0`, and Go has `+incompatible` and `/v2` module paths.
Lexical comparison, the thing bash actually offers, gets `1.2.10 < 1.2.9` wrong, which is not a rare edge
case but the ordinary situation for any package past its ninth patch.
`sort -V` is GNU-only (tension 24) and implements none of these four rulesets correctly.
Getting it wrong in the permissive direction means a vulnerable dependency reported clean, which is
silent and is the failure this module exists to prevent; getting it wrong the other way floods the report
and the module gets ignored.
Implementing four correct version algebras in bash is a large amount of code whose bugs are invisible.

**Options considered.**

1. *Implement semver comparison in bash and approximate the rest.*
   Rejected: approximation here means silent false negatives in a vulnerability scanner.
2. *Require Python or a helper binary at scan time.*
   Rejected: §1 and §9 make the native tier zero-dependency and pure bash.
3. *Move the range arithmetic to the networked box and ship exact versions.* **Chosen.**

**RESOLUTION.**
**The scanner performs no range arithmetic and no version comparison.**
`data/advisories.db` is shipped **pre-expanded**: `tools/vendor-engines.sh`, which already is "the *only*
script that touches the internet" (§9), resolves every advisory's affected range against the ecosystem's
actual published version list, using that ecosystem's real tooling on a machine that has it, and writes
**one record per exact affected version**.

The scanner's entire SCA matching step becomes an exact string lookup.
This is the resolution that survives contact with shell: the hard, easy-to-get-silently-wrong part is
done once, on the machine equipped to do it, and the air-gapped host does something it cannot get wrong.
It also strengthens the air-gap story rather than weakening it, since the scan-time behaviour is now a
table lookup with no logic to diverge.

**Format.**
`data/advisories.db` is TSV, not the frozen record format, and this exemption is explicit: it is
machine-generated, has millions of rows, and needs O(log n) lookup, none of which the block-record format
is for (`rules/RULE-FORMAT.md` covers human-authored records only, tension 26).
Its schema is frozen here:

```
ecosystem \t package \t version \t advisory_id \t severity \t fixed_versions \t summary
```

sorted by the first three fields under `LC_ALL=C`, with a `#` header line.
No field may contain a TAB or an LF, which holds for every ecosystem's package names and versions.
`fixed_versions` is a comma-separated list, carried as opaque display text and never compared.
Lookup is `LC_ALL=C look` on the `ecosystem\tpackage\tversion\t` prefix, falling back to
`grep -F -m 1` where `look` is absent.
`data/versions.db` (§7.1's known-vulnerable-version list for banner-based detection) uses the same shape
and the same rule.

**Both databases are ABSENT by default in every checkout, and absence is their committed state - not a
gap waiting to be filled in-tree.**
`tools/vendor-engines.sh advisories` generates them on a networked box and never runs during a scan, so
neither file is a source and neither is committed here; `.gitignore` names both, so a generated database
cannot land by accident.
The distinction this buys is the whole point: a consumer can tell **"nobody has run the vendoring
pipeline"** (the file is absent) apart from **"it ran and this is what it knows"** (the file exists with
rows).
A committed database collapses those two facts into one, and does it in the direction that reads as a
pass - anyone inspecting the tree to judge whether the pipeline has been run gets a false yes.

This is recorded as a RESOLUTION rather than a convention because the tree already violated it once.
`data/versions.db` was committed in `9b580c1` carrying four rows that were verification-run output, not
advisory data - packages `goodpkg`, `uspkg`, `critpkg` and `lowpkg`, under `# bulk:` provenance headers
that said so outright (`grade=unpinned-local-archive`, `source=local archive /tmp/adv-verify/bad/...`).
That shipped fake vulnerability data in the release artifact, alongside machine-local scratch paths in a
repository deliberately tidied of them.
It was removed rather than reduced to its `#` headers: a header-only file still carries a `generated:`
timestamp and per-ecosystem provenance lines, so it still reads as a database somebody produced, and
stripping those to fix the machine-local paths leaves headers asserting nothing.
**Absence is the only state that is unambiguous**, and it is the state `data/advisories.db` has always
had, so the two files now behave identically rather than differently for no stated reason.

**Name normalisation is frozen**, since an exact lookup is only as good as its key:

| Ecosystem | Key |
|---|---|
| npm | name verbatim, scope included (`@scope/name`) |
| PyPI | PEP 503 normalised: lowercase, runs of `-`, `_`, `.` collapsed to a single `-` |
| Maven | `groupId:artifactId` |
| Go | full module path, `/vN` suffix retained, version without a `+incompatible` suffix |
| RubyGems, Composer, Cargo | name verbatim, lowercase |

**Coverage is reported, not assumed.**
A pinned `name@version` whose package appears in the database but whose exact version does not means the
snapshot does not know that version, which is not the same as "not vulnerable".
Those are counted and emitted as **one** roll-up `info` finding, `SCA-COV-UNKNOWN_VERSION-01`, listing
counts by ecosystem, plus a `run.json` counter.
One roll-up rather than one finding per package, because per-package noise would drown the real
findings.
`data/advisories.db` carries its generation timestamp and source snapshot id, which the report prints,
making §15's "only as current as the last `vendor-engines.sh` refresh" a dated fact in the output rather
than a caveat in a document nobody reads.

**Consequence for the build.**
§13 step 4's SCA module is reduced to lockfile parsing, name normalisation, and a table lookup, which is
a much smaller and more testable module than the original framing.
The expansion logic moves into `tools/vendor-engines.sh` at §13 step 9, and is the reason that script's
output is a build artifact with its own tests rather than a download.
Tests cover normalisation per ecosystem, the exact-lookup path, and the unknown-version roll-up, all
against a small committed fixture database.

## Tension 26 - one record format for human-authored config

**The tension.**
§11 specifies `config/scope.conf` as `name | base_url | notes`.
Tension 1 has just established that a pipe-delimited record cannot safely carry free text, and `notes`
is free text by definition.
The remaining config files in §11 (`scanner.conf`, `auth.conf`, `discovery.conf`, `posture.conf`) have
no stated format at all, and no stated key set.

**Why it bites.**
The same delimiter bug, in the file that gates every outbound request.
An operator writes `notes: prod api | do not scan on fridays` and the parser sees four fields and either
drops the target (so a scan silently covers nothing) or mis-assigns `base_url` (so the gate authorises
the wrong thing).
Leaving the other four files unspecified is worse in a different way: the obvious bash implementation is
`source config/scanner.conf`, and that makes every config file executable code.
A config file is exactly the artifact a team copies from a colleague or a wiki, and a `source`d
`scope.conf` could run arbitrary commands *before the scope gate is ever consulted*, defeating the
tool's central safety property from inside its own loader.
Left unspecified, each config file also acquires its own ad-hoc parser and its own subtly different
quoting rules.

**Options considered.**

1. *A different format per file, chosen to suit each.*
   Rejected: five parsers, five sets of quoting bugs, and no shared linter.
2. *`key=value` shell files, `source`d.*
   Rejected on the security ground above, which is disqualifying and not a matter of taste.
3. *JSON for config.*
   Rejected: no JSON parser in bash, and it is hostile to hand-editing, which is what these files are
   for.
4. *Reuse the frozen record format for everything human-authored.* **Chosen.**

**RESOLUTION.**
A clean split by authorship, with exactly one format on each side.

**Human-authored files use the frozen block-record format** from `rules/RULE-FORMAT.md`:
`config/scope.conf`, `config/scanner.conf`, `config/auth.conf`, `config/discovery.conf`,
`config/posture.conf`, `data/severity-rubric.conf`, every `*.rules` pack,
`modules/<m>/checks.rules`, `rules/derived.rules`, and `rules/redaction.rules`.
The **syntax** is identical for all of them; only the **key set** differs, and each key set is a schema
listed in `rules/RULE-FORMAT.md` §9.

Every one of those schemas is defined **in that document**, not alongside its consumer.
That is not tidiness: §7's parser consults *single* versus *repeatable* to raise `E014` and *multi-line*
to raise `E016`, so a file whose key cardinality lives elsewhere cannot be parsed at all, and
`rules/RULE-FORMAT.md`'s claim to be self-contained would be false.
The operator-config schemas are §9.6.1 to §9.6.5, and the script-check registry is §9.5.

A file containing exactly one record is legal, which is what `scanner.conf` is.
Its `id` is the frozen literal `scanner`, so §4's "first field is `id`" rule stays total with no special
case in the parser (`rules/RULE-FORMAT.md` §9).
`config/scope.conf`'s schema is `rules/RULE-FORMAT.md` §9.4, which replaces §11's pipe-delimited line and
gives `notes` a genuinely free-text field and `extra-host` a repeatable one.

**Machine-generated files use JSON or the frozen TSV**: `findings.jsonl`, `run.json`, `state/*.json`,
`config/baseline.json`, `reports/<run>/inventory/*.json`, `data/advisories.db`, `data/versions.db`.
`baseline.json` stays JSON despite living in `config/`, because it is machine-appended far more often
than hand-edited and because §11 already specifies it as JSON.

**Config files are data and are never executed.**
`source`, `.`, and `eval` applied to anything under `config/`, `rules/`, or `data/` are lint failures.
Values undergo no expansion: `$HOME` in a config value is five literal bytes.
Where a path genuinely needs to be relative to something, it is resolved by the loader, explicitly,
rather than by the shell implicitly, against scoursh's own **install root** - the directory containing
`scan.sh`.
That is a different root from the **scan root** of tension 12, which is a property of the tree being
scanned; the two are never interchangeable and are named differently for that reason.

One parser, `lib/records.sh`, serves all of it.
One linter covers all of it, so a typo in `scanner.conf` fails the same way a typo in a rule pack does,
with a file, line, column, and error code.
Adding a config file becomes a schema declaration rather than new parsing code, which is the same
property §16 promises for rules.

**Consequence for the build.**
`lib/records.sh` is built at §13 step 1 and `scan.sh`'s config loading at step 2 uses it immediately, so
no ad-hoc parser is ever written.
`config/*.example` files ship in the frozen format, and the linter runs over them as part of
`tests/run-tests.sh` so the examples cannot drift from the schema.
`auth.conf` keeps its `600` permission requirement from §7.0, checked via `stat_mode` (tension 24), and
its values are marked secret at the schema level so `redact` (tension 9) covers them everywhere.

---

## Tension 27 - optional engine adapters: quarantine and convention

**The tension.**
`docs/DESIGN.md` §9 offers a second, opt-in tier on top of the native pattern engine: drop a vendored
`semgrep`/`gitleaks` binary plus a local ruleset into `adapters/`, run it fully offline, and merge its
findings with the native ones. §3's tree diagram and §6.4 describe this only under `modules/sast/`; §6.6
separately invites "the same pattern" for IaC engines (`checkov`/`tfsec`/`trivy config`); §13 step 9
names `tools/vendor-engines.sh` as the mechanism that populates `adapters/` in the first place, "the
*only* script that touches the internet... never called during a scan... clearly quarantined." None of
that is a directory convention, an interface contract, or an enforcement mechanism yet - it is prose
describing a shape, not a shape a second engine's ticket could implement without guessing, and "clearly
quarantined" is not, on its own, something CI can fail a build over.

**Why it bites.**
Three separate failure modes, all avoidable only by deciding the shape before the first adapter, not
after:

1. Without a frozen interface contract, the first two adapter tickets (say, `semgrep` for SAST and
   `checkov` for IaC) would each invent their own function names, their own detect/run/normalize split,
   and their own error-handling convention, and nothing would catch the divergence until a third ticket
   tried to write code that treats adapters uniformly and discovered there were two incompatible shapes
   to support.
2. Without a single, actually-enforced "only script that touches the internet," the guarantee is a
   sentence in a document rather than a property of the repository. A future adapter ticket, under
   deadline pressure, could plausibly have its `adapter.sh` reach out and fetch its own ruleset "just
   this once" - `docs/FOUNDATION.md` tension 19's own "no bypass" check does not know `adapters/` exists
   yet, so nothing would stop it.
3. Without an explicit "adapters are optional" proof, an operator or a future maintainer reading the
   code cannot tell whether `scoursh` still runs, unmodified, with zero engines vendored - which is the
   entire point of "native (default): zero deps, fully air-gapped" in §9's own two-tier framing.

**Options considered.**

1. *Defer the whole scaffold until the first concrete adapter ticket, and let it define the convention
   ad hoc.*
   Rejected: this is exactly failure mode 1 above, and it is the same mistake `docs/FOUNDATION.md`
   already paid for once, in a different shape - `rules/RULE-FORMAT.md` exists precisely because
   deferring "what does a record look like" to the first rule pack produced a pipe-delimited format that
   broke on its own catalog's regexes (tension 1).
2. *Fold the adapter convention into `rules/RULE-FORMAT.md` itself, as a new schema.*
   Rejected: `rules/RULE-FORMAT.md` §9.1.1a already draws the correct line - an adapter check id is
   "not a record file; produced at runtime by a vendored engine... never linted, since no record
   declares it." Adapters are executable bash, not data; putting them in the frozen record format would
   contradict the format's own reason to exist (tension 26: "record files are data, never code").
3. *One convention document (this scaffold), plus a lint that makes the quarantine a checked property
   rather than a comment.* **Chosen.**

**RESOLUTION.**

`docs/ADAPTERS.md` is a new, normative, self-contained document - the same role `rules/RULE-FORMAT.md`
plays for records - defining:

- **Directory convention**: `modules/<module>/adapters/<engine>/adapter.sh` (plus conventional `bin/`
  and `rules/` subdirectories for the vendored binary and local ruleset). This **generalizes** §3's
  SAST-only diagram to any module, which is a deliberate extension of DESIGN.md's literal text, not a
  correction of it: DESIGN.md is preserved verbatim per this project's own rule and is never edited to
  match a later decision, and §9/§13 step 9's own prose already speaks of `adapters/` without confining
  it to SAST, while §6.6 explicitly invites the same shape for IaC. A future reader comparing §3's
  diagram against a `modules/iac/adapters/checkov/` directory is seeing this deliberate generalization,
  not drift.
- **The three-function interface contract**: `<engine>_detect` (pure filesystem check, never touches the
  network), `<engine>_run OUTPUT_FILE TARGET...` (runs the vendored engine fully offline, writes its
  native JSON), `<engine>_normalize INPUT_FILE` (reads that JSON and calls `lib/findings.sh`'s existing
  public API - `finding_new`/`finding_set`/`finding_set_evidence`/`finding_set_match`/`finding_emit` -
  never the internal `_F` array directly, which `tests/lint-shell.sh`'s existing redacted-field check
  already forbids repository-wide). Namespacing the three functions by engine name is what lets more
  than one adapter be sourced into the same process without collision, the same reason `sca_go_scan_tree`
  is named for its ecosystem rather than reusing `sca_scan_tree`'s name.
- **Check ids reuse `rules/RULE-FORMAT.md` §9.1.1a's already-frozen "adapter check id" namespace**
  (`<engine>:<engine's own rule id>`) rather than inventing a second convention that could drift from
  it. This is the one place this tension deliberately adds nothing new: the frozen format already
  drew the correct line (option 2, rejected above, would have redrawn it).
- **Graceful degradation is mandatory**: an absent or failing adapter records a `coverage_reduction`
  (`reason=engine_not_vendored`, mirroring the `not_yet_built`/`no_advisories_db_on_disk` convention
  every other module-gap case already uses) and the run continues native-only. It is never an error, per
  §9's own "if absent, silently continue native-only."
- **Runtime gating is explicitly deferred, not built here.** `docs/DESIGN.md`'s directory layout names
  `lib/engines.sh` and `has_engine()`; §6.4 names the `--use-engines` flag. Neither exists as of this
  ticket. The first concrete adapter ticket builds both, together with its own adapter - mirroring how
  `--paranoid`'s flag landed together with its first real enforcement (tension 20) rather than as a
  separate ticket - so that `lib/engines.sh` is designed against one real adapter's actual needs instead
  of a guess. Until it lands, a fully-populated `adapters/` directory would still be inert: nothing
  calls `<engine>_detect`.

**`tools/vendor-engines.sh` is established as the network chokepoint, and it is now an enforced property,
not a comment.**
The script itself is real and runnable - usage/help, `--list`, `--all`, and vendoring a named engine all
work - with a genuinely empty registry (`VENG_REGISTRY`), since zero adapters exist. Two additions to
`tests/lint-shell.sh` make "the only script permitted to reach the network" checked in both directions:

1. The existing tension-19 "no bare curl/wget/nc/openssl s_client" check now exempts
   `tools/vendor-engines.sh` alongside `lib/http.sh` - it is expected to call `curl`/`wget` directly, and
   is deliberately **not** routed through `lib/http.sh`'s scope gate, because that gate authorizes scan
   *targets* (`config/scope.conf`) and a vendored engine's own upstream release URL is not one; routing
   it through the gate would be a category error, not an extra safety layer.
2. A new check fails the build if anything under `lib/`, `modules/`, or `scan.sh` - `scan.sh`'s own
   dispatch path, narrower than tension 19's `engine_files` (which also covers `tools/` and a future
   `aws/`) - sources, execs, or evals `tools/vendor-engines.sh` by name. It is matched at command
   position with an explicit invocation verb required (`source`/`.`/`eval`/`bash`/`sh`), not a bare
   substring match: `modules/sca/engine.sh` and `modules/sca/go_engine.sh` already name
   `tools/vendor-engines.sh` in log and remediation prose (tension 25), including one case immediately
   after a literal `(` inside a quoted string, and a bare substring check fails under its own first real
   run - on code that is correct today - which is exactly the "a test that passes under both readings
   pins nothing" failure `AGENTS.md`'s Tests section warns against, applied to a lint instead of a suite.

**`tools/vendor-engines.sh` carries a second, unrelated, already-committed responsibility that this
ticket does not implement.**
Tension 25's RESOLUTION already assigns this same script the job of resolving `data/advisories.db`'s and
`data/versions.db`'s advisory ranges against each SCA ecosystem's real published version list ("the
expansion logic moves into `tools/vendor-engines.sh` at §13 step 9"). That is real, SCA-scoped work, not
an engine adapter, and it needs genuine per-ecosystem tooling this scaffold has no offline, fixture-testable
way to exercise - it is explicitly out of this ticket's scope ("adds no per-engine logic itself, only the
scaffold") and is recorded here, in the script's own header, and in `docs/ADAPTERS.md` §10, so it is not
mistaken for an oversight or silently re-invented as a second network-touching script later. The two
responsibilities share this one file for the same reason they share the no-egress rule, not because they
are the same kind of work.

**Consequence for the build.**
Zero adapter directories exist anywhere in the tree as of this ticket. `tests/suites/vendor-engines.sh`
proves the empty-registry script's own behavior end-to-end as real subprocess invocations, with
`curl`/`wget` stripped from `PATH` so an accidental fetch attempt fails loudly rather than silently
reaching the network - and the full suite (`tests/run-tests.sh`) passing with no `modules/*/adapters/`
directory anywhere is the concrete proof, not merely an assertion, that `docs/DESIGN.md` §9's "if absent,
silently continue native-only" already holds for the only case that exists today: every adapter, for
every module.

**The second, unrelated responsibility the paragraph above names as unimplemented has since landed** -
a later ticket ("Implement tools/vendor-engines.sh's advisories.db/versions.db expansion") added the
`advisories` command namespace `tools/vendor-engines.sh`'s own §3 now documents: `VENG_ADVISORY_REGISTRY`,
`veng_advisories_list`/`veng_advisories_one`/`veng_advisories_all`, and one `veng_advisories_<ecosystem>`
function per `docs/DESIGN.md` §6.5 ecosystem (npm, PyPI, Maven, Go, RubyGems, Composer) - kept
structurally separate from `VENG_REGISTRY`/`veng_vendor_one`/`veng_vendor_all`/`veng_list` exactly as
this section's own header note required, with its own `advisories` branch in `veng_main` rather than a
name collision with a registered `<engine>`.
Each ecosystem resolves real advisory data via OSV.dev (`https://api.osv.dev/v1/vulns/<id>`), the same
cross-ecosystem, open-source vulnerability database `govulncheck`/`pip-audit`/`osv-scanner` are
themselves built on - chosen because OSV's own schema already carries a per-advisory
`affected[].versions` array, the exact ecosystem-tool-computed version enumeration tension 25 asks for,
so this script still performs no range arithmetic of its own.
Every advisory id is operator-supplied via `SCOURSH_ADVISORY_<ECOSYSTEM>_IDS`, never guessed or
hardcoded - the identical discipline this file's own `semgrep_vendor` narrative already established for
a release URL/checksum.
JSON parsing uses `python3`'s stdlib `json` module rather than a hand-rolled bash/grep parser (this
script runs on a networked, operator-controlled box with real tooling, never in the egress-restricted
scan-time path), and per-ecosystem name normalisation reuses `modules/sca/engine.sh`'s, `php_engine.sh`'s and
`go_engine.sh`'s own `sca_*_normalize_name`/`sca_go_normalize_version` functions verbatim, lazily
sourced, so the writer and the reader of `data/advisories.db` can never drift apart.
`data/versions.db` is written by the identical `_veng_advisories_write_db` call, mirroring tension 25's
own "the same shape and the same rule" - its own, separate banner-matching product catalog (a bare web
server or TLS library with no SCA-ecosystem manifest at all) is a stated gap this ticket does not close,
not silently assumed covered.
`tests/suites/vendor-engines-advisories.sh` is the fixture-driven proof, against hand-authored,
OSV.dev-*shaped* (never live-fetched) fixtures under `tests/fixtures/vendor-engines/osv/` - the identical
"no live network calls in CI" posture `tests/fixtures/sca/advisories.db` already established for that
data's READER side.
`docs/ADAPTERS.md` §10 and this script's own header are both updated in the same change to stop calling
this responsibility unimplemented.

---

## Tension 28 - the egress claim: air-gapped versus egress-restricted-by-destination

**The tension.**
`docs/DESIGN.md`'s title and §1 describe scoursh as an "air-gapped" scanner, and that word is repeated
throughout `README.md` and `AGENTS.md`. Taken at face value, "air-gapped" means the host has no network
path to reach at all - but scoursh's own design, from `docs/DESIGN.md` §7 (DAST) and §8 (cloud/AWS live)
onward, requires exactly two categories of scan-time network access: a `curl` to an operator-authorized
target in `config/scope.conf`, and read-only AWS API calls to the operator's own account. Both are real
HTTP/API calls over a real network connection made *at scan time*, not vendored data resolved in advance.
A tool that has to reach a live target to do its job is not air-gapped by any ordinary reading of the
word, and describing it that way overstates the guarantee to a reader deciding whether it is safe to run
inside a genuinely isolated network.

**Why it bites.**
1. It is the sentence an operator uses to decide whether the tool is safe to run inside a network with no
   egress at all. Taken at face value and then followed by `scan.sh dast` or `scan.sh cloud --live`, the
   claim is falsified by the tool's own next command - or, worse, an operator who trusts the label punches
   an undocumented exception through a boundary they believed the tool never needed crossed.
2. It is self-contradictory on its own terms already. `AGENTS.md`'s "no-egress rule" section states
   plainly that "exactly two kinds of outbound traffic are permitted," then two sentences later says "the
   tool must run on an air-gapped host" - a host that can reach a `curl` target and the AWS API is not
   air-gapped by definition, so the same paragraph asserts and denies the same property.
3. It undersells what the design actually guarantees, which is stronger and more checkable than "no
   network access": every outbound call, without exception, is enforced at a single runtime chokepoint
   (`lib/http.sh`'s scope gate, `lib/awscli.sh`'s read-only guard) against an allowlist the operator
   supplies, refused by default with `SCOURSH_EXIT_SCOPE`. That is a *destination-restricted* guarantee,
   provable by reading two files and their tests, not an *absence* claim that a single un-audited `curl`
   call anywhere in the tree would silently falsify.

Not every occurrence of "air-gapped" in the tree makes this same claim, and this tension does not correct
the ones that don't. "An air-gapped host may not have `shellcheck` installed" and "must run identically on
an air-gapped Linux host and macOS" describe the class of restricted-network host the tool is expected to
run on - a true and useful thing to say, unaffected by this tension, since SAST/SCA/IaC genuinely make zero
network calls and so genuinely run unmodified on such a host. What is corrected here is narrower: the claim
that scoursh *itself*, as a whole, is air-gapped, unconditionally.

**Options considered.**
1. *Keep "air-gapped" but add a caveat every time it appears near DAST or cloud.*
   Rejected: the caveat would have to be repeated at every one of dozens of sites, drifts the moment one is
   missed, and still leaves the headline word wrong - a reader who reads only the title or the first
   sentence gets the false claim with no caveat in sight.
2. *Rewrite `docs/DESIGN.md` to drop the word, including its title.*
   Rejected outright: `docs/DESIGN.md` is preserved verbatim by this project's own rule (`AGENTS.md`, "the
   handoff spec... preserved verbatim; its wording is load-bearing"). An earlier attempt at this exact
   correction (PR #66) rewrote `docs/DESIGN.md`'s title and closed unmerged, among other reasons - that
   document's wording is not this project's to edit after the fact, whatever it later turns out to have
   been wrong about.
3. *Say nothing in this register and let `README.md`/`AGENTS.md`'s wording changes speak for themselves.*
   Rejected: this project's own convention is that a decision correcting or superseding `docs/DESIGN.md`'s
   letter is recorded here, with an explicit statement that the register wins where the two conflict - see
   this file's own preface and every prior tension. Skipping that step for the one claim this register
   exists to correct would defeat the reason it exists.
4. *Record the correction as a tension here, with a dated ADR alongside it, and correct every reader-facing
   document except `docs/DESIGN.md` directly.* **Chosen.**

**RESOLUTION.**
scoursh is **egress-restricted, enforced by destination** - not air-gapped. Exactly two categories of
scan-time outbound traffic are ever permitted, each requiring the operator to have named the exact
destination in advance:

1. `curl` (via `lib/http.sh`'s `http_request`) to a host authorized in `config/scope.conf`.
2. Read-only AWS API calls (via `lib/awscli.sh`'s `aws_ro`) to the operator's own account.

Everything else is refused by default at those two chokepoints - not merely undocumented, but rejected at
runtime with `SCOURSH_EXIT_SCOPE` (`lib/http.sh`'s scope gate; `lib/awscli.sh`'s read-only-prefix and
disallowed-flag checks) - and the three modules that exist today (SAST, SCA, IaC) make zero network calls
at all, since nothing about reading source, lockfiles, or config needs an external target to begin with.
**Where `docs/DESIGN.md`'s title and its §1, §6.5, and §9 text call the tool "air-gapped," that wording is
superseded by this resolution, and this resolution wins** - exactly as this register's own preface reserves
for every tension that contradicts the letter of `docs/DESIGN.md`. `docs/DESIGN.md`'s text is not edited to
match: it is preserved verbatim as the historical handoff spec, and this paragraph is where the correction
lives instead. `docs/adr/0001-egress-model-correction.md` records the dated decision in full; `README.md`
and `AGENTS.md` are corrected directly, since neither is a preserved-verbatim document.

This is a documentation correction only. `lib/http.sh` and `lib/awscli.sh` already implement exactly this
model - both were built, reviewed, and tested (tensions 19 and 23) against a destination-restricted
contract, never an absence-of-network one - so nothing changes in the enforcement chokepoints themselves.
What changes is the label attached to a guarantee that was already real.

---

## Tension 29 - the co-owned module check registry: one shared `checks.rules` versus one file per owner

**The tension.**
`rules/RULE-FORMAT.md` §9's path table reserved the basename `checks.rules` repository-wide for the §9.5
script-check schema, and made a record file matching no row an `E070`.
That reservation is what stops `modules/iac/*.rules` from capturing `modules/iac/checks.rules` and
failing `E023` on every record in it for a missing `pattern`, so it is load-bearing and not incidental.
But it also made the shared file the **only** legal name for a module directory's script-check registry,
and a module directory's registry is co-owned: every ticket that adds a phase script to
`modules/dast/passive/` must add its own records to the one file every peer is also adding to.
`docs/STEP5-DAST-PLAN.md` leaves DAST-07..DAST-11 explicitly unordered among themselves, so any two of
them dispatched in parallel produce an add/add or append/append conflict on that single file - not
because either ticket is wrong, but because the file has one name and several simultaneous authors.

**Why it bites.**
1. It is a *scheduling* hazard wearing the costume of a code defect. Nothing about the records is in
   conflict - the correct resolution is always "keep both blocks" - so every one of these conflicts is
   pure overhead paid by an agent or a reviewer who has to recognise the shape first.
2. "Resolve it by taking both sides" is a convention, and a convention is re-taught to every agent and
   every reviewer that touches the directory. It is silently wrong exactly once before anyone notices,
   and the failure mode is a **dropped block** - a check id that no longer loads, which reads as a check
   that ran and found nothing rather than as a check that was never registered. That is `docs/DESIGN.md`
   §15's overstated-coverage failure reached through a merge, and `checks_run` is the only place it
   would show.
3. It is already measured, three times over in `modules/dast/` alone: `passive/checks.rules`,
   `active/checks.rules` and the top-level tier-5 `checks.rules` are each co-owned by several tickets,
   and each carries its own hand-written "append-only, keep both sides" warning in `AGENTS.md` because
   of it. DAST-05 and DAST-06 avoided a live collision only by happening to land sequentially.
4. The prohibition had already been enforced against a real attempt: DAST-05's
   `modules/dast/passive/headers-checks.rules` was refused on exactly these grounds, so the constraint
   was known to bind rather than being theoretical.

**Options considered.**
1. *Keep the single shared file and add a foundational ticket every peer lists in `dependsOn`, so the
   file exists before anyone appends to it.*
   Rejected. It solves add/add and leaves append/append untouched: once the file exists, two peers
   appending to its end still conflict, which is the commoner shape and the whole of what remains for
   DAST-07..DAST-11. It also buys a permanent serialisation cost - every future co-owner of every future
   module registry inherits a dependency edge - to work around a filename.
2. *Keep the single shared file and rely on the convention, unchanged.*
   Rejected as the status quo whose cost is item 2 above. The convention is correct and it is also
   unenforceable: no linter can tell a deliberate deletion from a badly-resolved conflict, because both
   arrive as a well-formed file with fewer records than one side had.
3. *Retire `checks.rules` and require the per-owner spelling everywhere.*
   Rejected. It forces every module directory to move in lockstep, and `rules/RULE-FORMAT.md` §14 item 1
   makes a rewrite of every existing pack a versioned migration with a `state/` migration behind it -
   a large, invalidating change bought for a scheduling convenience.
4. *Add one additive row to §9's path table legalising `checks-<name>.rules` at any depth, leaving
   `checks.rules` legal and unchanged, and split only where a directory wants to.* **Chosen.**

**RESOLUTION.**
§9's path table gains **one additive row**: any file named `checks-<name>.rules`, at any depth, takes the
§9.5 script-check schema, sitting immediately below the `checks.rules` row and above the pattern-rule
row. The rule a reader carries away is one sentence - **a `.rules` file whose basename begins `checks` is
a §9.5 script-check registry, wherever it lives.**

Five properties are what make this cheap, and each is asserted rather than assumed:

- **It is additive, so it is not a versioned migration.** Every path that resolved to a schema before the
  row resolves to the same schema after it; no existing file has a basename beginning `checks-`, and
  `checks.rules` keeps its own row, first. Per §14's four-item test it trips item **2** (the parser and
  the linter move) and nothing else, so there is **no `format_version` bump** and `state/` and
  `config/baseline.json` stay valid. §14 now carries this as its second worked example, and generalises
  the pair: an amendment that *adds* a legal spelling trips item 2 alone, while one that *retires,
  renames or re-schemas* an existing spelling trips item 1 - which is precisely why option 3 was rejected.
- **It needs no engine change.** `checks_registry_load` (`lib/checks.sh`) already globs every `*.rules`
  file under a module directory with no per-file allowlist - which is how `modules/iac/`'s six packs
  already load together - so a split registry requires no registration step. That claim is verified on a
  real run's `checks_run` set (`tests/suites/dast.sh`), never on the glob in isolation, because the glob
  being right and the registry actually loading are two different facts.
- **Identity does not move with a record.** §9.5.1's owning-module map keys on the file's **directory**,
  not its basename, so every id in `modules/dast/passive/checks-cookies.rules` is held to the same
  `DAST-` prefix (`E018`, `E081`) it was held to in `checks.rules`; and a check id is unchanged by the
  file it lives in, so `E019` namespace uniqueness stays repository-wide rather than becoming per file.
  This is what makes a split a **byte-identical move of records and never an edit of them** - a move that
  renamed an id would trip §14 item 3, since `check_id` is a fingerprint component (tension 5).
- **It legalises one shape and does not open the extension up.** The glob is `checks-?*.rules`, so the
  bare `checks-.rules` names no owner and stays `E070`; an arbitrary `*.rules` basename at a module path
  is still `E070`, keeping `modules/dast/passive/cookies.rules` and the DAST-05 **suffix** spelling
  `headers-checks.rules` both illegal. The match is on the **basename**, never a `*/`-prefixed glob:
  bash's `*` matches `/` too, so `*/checks-?*.rules` would also match `a/checks-x/y.rules` and let a
  *directory* named `checks-x` silently re-schema every `.rules` file beneath it.
- **Splitting is optional and per-directory.** Both spellings are legal simultaneously and a directory
  may hold `checks.rules` and `checks-<name>.rules` side by side. Nothing is required to move, which is
  exactly the property option 3 lacked.

**What this obliges of a co-owner from now on, and what it retires.** A ticket adding a phase script to a
module directory creates **its own** `checks-<name>.rules` and does not append to a peer's file. The
"append-only, resolve a conflict by keeping both sides" instruction in `AGENTS.md` is retired for
`modules/dast/passive/`, whose five owners are split by this change; it still stands for
`modules/dast/active/checks.rules` and `modules/dast/checks.rules`, which are **not** touched here and
whose records must not be moved opportunistically - a split is a deliberate, tested change, and doing one
under peers who are mid-flight recreates the conflict it exists to prevent, in a worse place.

This resolution constrains every future module registry and not only this one directory, which is why it
is recorded here rather than only in `rules/RULE-FORMAT.md`.

---

## Cross-cutting consequences

Eight decisions here reach beyond their own tension and are collected so they are not missed.

1. **`lib/records.sh` is the first thing built**, ahead of §13 step 1's stated contents, because
   tensions 1, 6, 9, 15, and 26 all depend on it.
2. **Two libraries are added to §3's layout**: `lib/awscli.sh` (tension 23) and the capability layer
   inside `lib/core.sh` (tension 24).
3. **A check registry exists in `scan.sh`**, because tensions 7, 12, 15, and 18 all need every check to
   have a stable id, a set of tags, a `coverage-scope`, and a per-cell completion signal.
4. **Coverage is `(check, cell)` everywhere, with exactly two exceptions**, both of which can only
   narrow what may be claimed as `fixed`, never widen it.
   `SAST-HIST-*` keeps the cell test and adds tension 13's per-finding boundary comparison **inside** a
   covered cell.
   Derived findings have no cell at all and replace the cell test outright with tension 6's
   three-condition rule.
   There is no third mechanism.
   A composite whose contributor is a `SAST-HIST-*` check is subject to **both** exceptions, which is
   exactly why tension 6 condition (b1) requires a contributor to pass the same test that would let its
   own finding be `fixed` rather than merely to have a covered cell.
   The earlier claim that no check is subject to both was true per check and false for that composition,
   and it is withdrawn.
5. **The scan root is a defined term** (tension 12): the git toplevel of the resolved `--path`, else the
   resolved `--path` itself.
   Every "repository-relative path" in these documents means scan-root-relative, and scoursh's own
   install root (tension 26) is a different thing that is never called the repository root.
   `path-root` cells are comparable only between runs with equal `scan_root_id`; the other cell kinds
   carry no filesystem path and are not gated by it.
6. **`run.json` is load-bearing, not decorative.**
   It carries `skipped_checks` with reasons, `coverage_gap` entries, `coverage_reduction`,
   `incomplete_reason`, the capability probe results, the paranoid allowlist, and the advisory snapshot
   date.
   Tensions 2, 12, 14, 15, 20, 21, 24, and 25 all write to it, and §15's honesty requirement is
   implemented through it.
   `incomplete_reason` being non-empty is exactly the exit-5 predicate (tension 14).
7. **`fp/1` and `uk/1` are versioned schemas** (tensions 5 and 18) whose change invalidates `state/` and
   `config/baseline.json`.
   They are printed in every report, and a mismatch makes the diff unusable and the gate fail-closed
   (tension 11 step 7).
8. **The suite runs on both GNU and BSD userlands** (tension 24) and asserts byte-identical findings,
   which is the check that keeps most of the resolutions above honest.
   `tools/daily-suite.sh` is what runs it, on a daily local schedule; the hosted-CI workflow is
   dormant until the repository is public, so there is no pull-request status check today
   (`docs/CI-RUNBOOK.md`).

---

## Known follow-ups

Two adversarial review rounds have run over this register and `rules/RULE-FORMAT.md`.

**Round 1** raised twenty surviving defects.
Eight were fixed then, because they determine what gets persisted into `state/` and
`config/baseline.json`, or the bytes a parser produces, and changing those after the freeze is a data
migration rather than a document edit: **F1, F2, F6/F10, F7, F9, F11, F19**.

**Round 2** verified those eight independently, confirmed seven, and found that F7 was closed on the
ordinary-finding path but still open on the derived-finding path, plus four defects introduced by the
round-1 edits themselves.
Five contract-determining items were fixed in round 2 and are resolved in the tensions above:

- The tension 13 **Identity** line, which still gave the history fingerprint two components after
  tension 5 had given it three - F9's own defect surviving in the one module tension 5 cross-referenced.
- **One owner for `SAST-HIST-*` coverage.** The round-1 cell table had put the history boundary inside
  the coverage cell while tension 13 rejected boundary-in-coverage by name, so two incompatible
  mechanisms governed one check family. The cell now carries only the path root, and tension 13's
  per-finding test applies as a second layer inside a covered cell.
- The **composite coverage predicate**, which still read "appears in `covered_checks`" after that map
  became cell-scoped, so a region-narrowed run still reported the flagship composite `fixed`.
  Classification then required every prior contributor's `(check_id, cell)` pair to be covered - which
  round 3 found insufficient on two further counts and replaced with the three-condition rule below.
- The **posture id collision**, where a `POSTURE-*` id was required in both `checks.rules` and
  `config/posture.conf` and fired `E019` on every control.
  Expectations now carry their own id namespace plus a `check` reference, which also makes
  `coverage-scope: scope-key` a real partition instead of a degenerate one.
- A **frozen `--path` root normalisation**, since cells are string-compared across runs and persisted,
  with comparison stated as exact equality and no subsumption rule.

The doc-only items round 2 raised were folded in at the same time: the §9.2.2 / §9.5.1 contradiction
over `coverage-scope` validation, the false "every cell is derivable from the location" claim, the
withdrawn ambiguous-attribution error code (it had two incompatible predicates, one static and one
runtime, and its static reading outlawed two path-scoped targets on one host, which tension 19
supports), the `--paranoid` row asserting
exit 5 where tension 20 says 4, the `fp_schema`-mismatch fail-open, the missing declared/unplanned rows,
tension 15's stale §9.1.3 citation, the `AGENTS.md` check-keyed summary, the `occurrence` tie-break for
two matches on one line, the history `occurrence` scoping, the adapter-finding ordinal, `allow-subdomains`
hosts missing from the attribution set, tension 18's all-units rule, `E018` for posture placement, and
the §3.2 and §9.6.1 wording slips.

**Round 3** confirmed the tension 13 Identity line, the `SAST-HIST-*` coverage owner and the posture id
split as closed by mechanism, and found that rounds 1 and 2 shared one procedural failure: a mechanism
was fixed in the section that owns it while the sections that **consume** it kept the pre-fix sentence,
and no prescribed test was ever changed, so every test landed where the correct and the rejected readings
agree.
Two of the surviving contradictions were byte-identical to the original commit.
Eight items were fixed in round 3, each with its consumers swept and its test rewritten to **fail** under
the reading that was rejected:

- **Tension 6 condition (a)**: a composite whose own record was not selected this run is `unknown`.
  Round 2 removed the composite's `covered_checks` entry and nothing then asked whether the composite
  survived tension 15's filters, so `scan.sh all --intensity active` reported the flagship composite
  `fixed` with its chain fully open.
  F8's rationale is corrected to match.
- **Tension 6 condition (b2)**: the orphaned `any-of` sentence is withdrawn and replaced.
  `contributors` records only checks that fired, so a listed alternative that never fired was invisible
  to the contributor-pair test.
- **Tension 6 condition (b1)**: a contributor counts as covered only under the test that would let its
  own finding be `fixed`, which for `SAST-HIST-*` includes the boundary comparison.
  This is where the round-2 fixes for items 2 and 3 failed to compose.
- **Tension 12: the scan root**, previously undefined for the scanned tree while deciding a fingerprint
  input, a `unit_key` input, a glob base and a persisted cell.
  Frozen as the git toplevel of the resolved `--path`, else the resolved `--path`, with `scan_root_id`
  gating cell comparability so two distinct roots can never collide onto one cell string.
  The `--path` default is frozen at `.`, and scoursh's own **install root** is renamed so it can never be
  confused with the scan root.
- **Tension 12: the derived `cell` value**, frozen as JSON `null` rather than a string sentinel.
- **Tension 5: `control_id`** bound to the `POSTURE-*` check id, which gained a second candidate referent
  when the posture namespaces split.
- **The `fp_schema` fail-closed rule**, which existed only in tension 12 while tension 11 step 7 (the
  frozen gate predicate) and tension 14 (the owner of exit codes) both still contradicted it.
  `diff_usable` is now a named flag set in step 5 and read in step 7, and it covers `scan_root_id`
  mismatch too.
- **Discriminating tests** for all of the above, plus the history boundary-has-moved case, replacing
  suites that certified the defects green.

Also swept as consumers while their mechanisms were open: tension 7's global `E019` scope, the adapter
`check_id` namespace row, §10.3's line-based match sketch against the byte-offset ordinal, the
owning-module map's totality, and the cross-cutting numbering.

**Round 4** confirmed round 3 broke the procedure failure - both sentences that had survived two rounds
byte-identical to the original are gone, and nothing from rounds 1 or 2 regressed - and found three
blockers, two of them fresh instances of the same pattern inside round 3's own new machinery.
All three are fixed here:

- **`scan_root_id` was not a repository identity.**
  The frozen recipe (lexicographically smallest of `git rev-list --max-parents=0 --all`) reads correctly
  and fails three ways in practice, including on the *default* CI checkout.
  This was found by a verifier who ran the commands rather than reasoning about them, so the replacement
  was chosen the same way: tension 12 now carries the real terminal output for a commit-less repository,
  a `--depth 1` clone, and a single-branch-versus-full clone, for both the rejected recipe and the
  replacement.
  The replacement keys on the normalised `remote.origin.url` with a kind prefix, falling back to the
  absolute toplevel.
- **`diff_usable` overrode `status`.**
  Round 3's step 5 said every finding was `unknown` when the diff was unusable, while tension 12's
  classification table - the owner of classification, byte-identical to the original commit - says a
  finding absent from prior state and present now is `new`.
  `diff_usable` now governs the gate only and never a `status`; a first run's findings are `new`.
- **Condition (b2) used "covered in at least one cell",** which produced a false `fixed` on a
  region-narrowed run.
  It gained a subset test - but replacing the old rule wholesale also **dropped its floor clause**, which
  made the new rule vacuous whenever the prior cell set was empty, and that was a safety regression
  against round 3 on the never-covered case.
  Round 5 restores the floor alongside the subset test, as two explicit conjuncts, with prescribed test 9
  pinning the case the floor exists for.

Also scoped in the same section: the cell-comparability gate applies to `path-root` cells only, since
`dast`, `cloud` and `posture` have no `--path` and a global gate would invalidate their diffs from a
change of working directory.

**Round 5** confirmed round 4 closed all three of its named blockers, and closed the first-run `status`
one in the right way - consumer sentence deleted rather than patched, ownership handed to tension 12 by
name, and a test asserting the persisted byte.
It also found that four rounds had shared one ordering habit: **write the rule, then write a test that
agrees with it.**
A test written after the rule, by whoever wrote the rule, tests the reading its author already had, which
is why every round passed its own suite while carrying a defect.
Round 4 made that concrete by *deleting* the fixture covering a never-covered `any-of` alternative in the
same edit that removed the rule the fixture guarded, and arguing for the deletion.

**Round 5 therefore inverted the order: the two fixtures were written into the test tables first, then
the rules were changed, then each fixture was re-checked against the rule that resulted.**
The fixtures are tension 6 case 9 and the cloud-only row of tension 14's gate matrix.

Fixed here:

- **A live credential in `scan_root_id`.** On GitLab's standard runner
  `git config --get remote.origin.url` returns
  `https://gitlab-ci-token:<TOKEN>@gitlab.example/org/proj.git`, measured, so the frozen recipe wrote a
  job token into `state/`, into `run.json`, and into the `run_identity` hash - a direct violation of
  tension 9.
  The token also rotates per job, so the id moved every run and the gate could never converge, which is
  the failure the root-commit recipe was replaced to escape.
  The recipe now strips any `userinfo@` component and states normatively that the id must never contain
  credentials.
- **`git config --get` reads global config**, so a stray global `remote.origin.url` collided two
  unrelated remote-less repositories onto one id and one cell `.` - the same collision class, through a
  different channel. Now `--local`.
- **(b2) was vacuous on an empty prior cell set.** Round 4's subset test dropped round 3's floor clause,
  and empty is a subset of anything, so an alternative never covered in either run satisfied it and the
  composite was persisted `fixed`. This was a safety regression against round 3. The floor is restored
  as an explicit second conjunct.
- **The `fp_schema` mismatch had no mechanism.** Round 4 kept the assertion "nothing is reported `fixed`"
  and deleted the mechanism, while naming tension 12's table the sole owner of classification - and that
  table, followed literally, puts the entire backlog on its `present, covered | absent | fixed` row.
  The prior set is now treated as **empty** for classification, which is a mechanism the table cannot
  route around.

Consumers swept with them: the three unscoped `diff_usable` / `scan_root_id` statements, tension 5's
`FP_SCHEMA` sentence, step 5's `fp_schema` bullet, tension 12's mirror of (b2), `AGENTS.md`, and round
4's own change-log entry, which had described the (b2) edit as strictly strengthening.
The evidence block was re-run with the **frozen** command: round 4's proof executed
`git remote get-url origin`, which applies `insteadOf` rewriting and returns a different value, so it
could not have caught the defect in the thing it was proving.

Twelve findings were recorded here with their numbers so the next task would inherit them rather than
rediscover them.
**Six are now closed** - the five that had to land before `lib/core.sh`, plus F18, which closed with
them by mechanism.
The remaining six are still open, deliberately deferred; each names the tension it lands in and the
build step it must land before, and none is a matter of taste.

### Closed in §13 step 1

These five had to land before `lib/core.sh` and the parallel path were written, and they did.
Each is fixed **in the tension that owns it**, its consumers are swept, and each carries a test that
**fails under the original** - since round 5's finding was that a test written to agree with its own
rule pins nothing.

- **F13 [high] - CLOSED. The EXIT-trap guard is on scratch-dir ownership** (tension 4 rule 5, and its
  "Why it bites" item 4, both rewritten).
  Both halves of the original claim were measured and are recorded there: bash resets trapped `EXIT`
  actions in subshells, so the hazard the guard defended cannot occur, and `[[ $BASHPID == $$ ]]` passes
  in every `xargs -P` worker, so the guard let through exactly the case that destroys the run.
  The vacuous prescribed test is replaced by one that runs eight workers under `xargs -P` and asserts
  the scratch dir, a parent-owned sentinel and every shard survive; a second test asserts the old guard
  would have passed in all four of its workers, so the register's reasoning is itself checked.
  The matching claim in `AGENTS.md` is corrected in the same change.
- **F14 [high] - CLOSED. `msleep` reads a FIFO that never yields data, and is selected by measurement**
  (tension 24 capability table).
  The 200 ms / 100 ms margin, the discarded warm-up round, and why an exit-status probe cannot see the
  defect are stated there.
  Tension 16's sample now calls `msleep` rather than `sleep 0.05`.
- **F12 [high] - CLOSED. Shards and the unit journal live in the run directory unconditionally**
  (tensions 17 and 18, with tension 4 rule 5 stating that the scratch dir now holds only transient
  data).
  `--keep-shards` is redefined as "do not delete after a successful merge".
  The test interrupts a run with `SIGTERM` and asserts the shard and the journal survive while the
  scratch dir is erased - which is precisely the run the original could not survive.
- **F15 [medium] - CLOSED. Reclaim is single-winner and identity-bound, and `lock_is_stale` is
  specified** (tension 16), with `stat_mtime`, `now_epoch` and `proc_alive` added to the capability
  table.
  The discriminating test reclaims a stale lock, lets a live holder take it, and reclaims again with the
  stale token: the live lock must survive, where a bare `rm -rf` deletes it.
- **F16 [medium] - CLOSED. `shred` is a probed capability behind `erase_dir`** (tension 24), the
  cleanup cannot fail, and `look` joined the probed-optional list.
  `die` validates its code against the frozen 0-5 contract, so no path can leave the process with an
  unclassifiable status.
  Overwrite-based erasure is documented as best effort, with `scratch-dir` on a tmpfs as the real
  control.
  **The SCA half - `look`'s O(n) `grep -F` fallback cost - is CLOSED too.**
  `lib/core.sh`'s `db_lookup_exact` is the one implementation of the `LC_ALL=C look`-on-PREFIX,
  `LC_ALL=C grep -F -m 1`-fallback mechanism tension 25's lookup names, and `modules/sca/engine.sh`'s
  two call sites (`sca_lookup_exact`, `sca_package_known`) route every npm, Python, Ruby, Maven,
  Composer AND Go exact-match lookup through it - `modules/sca/go_engine.sh`, the one SCA engine that
  lives outside `engine.sh`, deliberately calls those same two shared helpers rather than reaching for
  `look`/`grep` itself, so no second, ad hoc parser exists alongside it (tension 24's "one capability
  layer").
  `tests/suites/core.sh` now pins both branches directly, against a fixture with two rows sharing one
  exact prefix: the fallback returns only the first row (FAILS under a bare `grep -F` missing `-m 1`,
  which would return both), `look` returns every row sharing the prefix (FAILS under an implementation
  that routed the `look` branch through the fallback instead of a real `look` call), and both the
  no-match and missing-file cases return status 1 with no output under either branch.
  This entry previously read "remains open; it lands with §13 step 4", reasoning that the mechanism was
  unexercised until a real caller existed; six real callers (npm, Python, Ruby, Java, PHP, Go) now exist
  and are tested end to end (`tests/suites/sca.sh`), so that condition is met.
  The O(n) cost on a `look`-less host is tension 25's own accepted, frozen tradeoff, not an open
  defect - which ecosystems have joined the same call site is step 4 SCA-completeness bookkeeping,
  tracked separately in "Where the build currently stands", not this finding.

**F18 is closed as a consequence rather than deferred.**
Once `die` refuses any code outside 0-5, a `die 6` cannot exist: both normative samples now read
`die 5` and write `incomplete_reason`, and the `scan_match` comment that said "writes hits to `$2`"
while the body took `$1` is corrected.

Two further corrections were found while building, and are recorded because a document that asserts
what the code disproves is the failure mode round 3 diagnosed:

- **Tension 2's pinned `rg` invocation** used `--binary=false`, which ripgrep rejects outright
  ("unexpected argument for option '--binary'", measured on ripgrep 15.1.0), so `scan_match` aborted on
  its first call.  It is `--no-binary`.
- **Tension 26 requires the linter to run over `config/*.example`**, but `rules/RULE-FORMAT.md` §9's
  path table has no row for them.  The loader strips a trailing `.example` before resolving the schema,
  so an example takes the schema of the file it is an example of.  That is a loader rule rather than a
  format change, and the frozen document is untouched.

**Still open, and inherited by §13 step 2 and beyond.**
F5 and F20 are why `rules/derived.rules` is **not** seeded at step 1: `COMPOSITE-TOKEN-HIJACK`'s
contributors do not exist until steps 5 and 6, so seeding it now is a guaranteed `E051` failure and a
red CI on the first build task.  The derived MECHANISM is delivered and tested against a fixture
composite under `tests/fixtures/rules/derived.rules`; only the shipped seed waits.


### Cheap corrections, safe to defer

- **F4 [medium] - CLOSED.**
  Originally: "§12.2's `context-deny` rewrite suppresses true positives" (`rules/RULE-FORMAT.md` §12.2,
  blessed as the general recipe by §8.3 and tension 2) - with `context-window: 2`, a correct safe-loader
  call within two lines of a genuine vulnerable call suppressed the finding, and tension 12 then
  classified the suppressed finding `fixed`.
  §12.1 already stated the correct discipline (`context-window: 0` for a same-line guard) and §12.2
  abandoned it, so the two frozen examples gave contradictory precedents for the identical hazard.
  Closed by the "SAST: native pattern engine + seed secrets/crypto/injection/python rules" ticket
  (`docs/DESIGN.md` §13 step 3a), the first ticket to evaluate the `context` directive at all and
  therefore its correct owner: `rules/RULE-FORMAT.md` §12.2's worked example now carries
  `context-window: 0` with an inline note explaining the correction; §10.2 states the general rule
  (widening a `context-deny` window trades a detectable false positive for an undetectable false
  negative, while widening a `context-require` window only ever risks the detectable direction); and
  `lib/records.sh`'s `_records_validate_record` gained `W033`, a warning (not an error - a wider deny
  window is sometimes a deliberate, reviewed trade-off) that fires whenever a `context-deny` is present
  with an EFFECTIVE window above 0, including an absent `context-window` (which defaults to 2).  The
  shipped `modules/sast/rules/python.rules` `SAST-PY-YAML_LOAD-01` (the real-world equivalent of the
  worked example) ships with `context-window: 0` from day one, and `tests/suites/sast.sh` carries a
  regression test that fails under the pre-fix (window-2) reading.
- **F3 [medium] - CLOSED.**
  Originally: "the `tags` vocabulary is not closed, so `E044` is unimplementable and a typo silently
  disables" (`rules/RULE-FORMAT.md` §9.1.3 and §13 against tension 15) - `tags: quik` lints clean and
  silently removes a rule from the `quick` profile, which is the exact failure mode `E017` exists to
  prevent for keys; and "`compliance` has two incompatible definitions - tag-based in §9.1.3, derived
  from a non-empty `cis` or `owasp` in tension 15 - and since `owasp` is required on every pattern rule
  the derived form selects the entire catalog."
  Both halves are closed, the first one retroactively: `lib/records.sh`'s `_records_check_tags`
  (`rules/RULE-FORMAT.md` §13 step 1, `b25cd26`) already enumerates the closed vocabulary - every type
  tag, `quick`, `compliance`, `intrusive` - and fires `E044` for anything outside it; this entry was
  simply never updated to say so.
  The second half is closed by the "Wire scan profiles: quick, full, compliance" ticket:
  `lib/checks.sh` picks the TAG reading of `compliance` (tension 15 step 2, amended in the same change)
  for the reasons recorded there - the field-derived reading is not computable as written (`owasp` is
  required, so "non-empty" selects the whole catalog), the closed vocabulary above already treats
  `compliance` as a legal tag, and `rules/RULE-FORMAT.md` §12's own worked examples (12.1, 12.5) already
  assume the tag reading.
- **F5 and F20 [medium] - seeding the composite at §13 step 1 is a guaranteed lint failure**
  (tension 6's "Consequence for the build" against `E051`, and `E060`).
  Tension 6 instructs seeding `COMPOSITE-TOKEN-HIJACK` at step 1 while its contributors do not exist
  until steps 5 and 6, and `E051` makes a dangling contributor id an error, so the first build task
  ships a red CI.
  `E060` is a second, independent failure for the same record, since a composite's fixture is a
  synthetic findings set rather than a source fixture.
  Direction: either defer the seed to step 6, or add a narrow, explicit forward-reference allowance that
  downgrades `E051` and forces the check into `skipped_checks`, and state `E060`'s applicability to the
  derived schema.
- **F18 [medium] - CLOSED in §13 step 1**, as a consequence of F16's exit-code work rather than as a
  deferred edit.
  `die` validates its argument against the frozen 0-5 contract, so a `die 6` cannot exist; both
  normative samples read `die 5` and write `incomplete_reason`, and the `scan_match` comment that said
  "writes hits to `$2`" while the body took `$1` is corrected.
- **F8 [low] - CLOSED.**
  Originally: "the `derived` type tag falls outside every `--intensity` tier" (tension 15 step 3, and
  `rules/RULE-FORMAT.md` §9.1.3 against §9.2) - under an intersection filter where nothing can be
  re-enabled, any run carrying `--intensity` drops every composite.
  The consequence was that composites are silently absent from those runs, not that they are wrongly
  classified: a composite has no `covered_checks` entry to lose, and tension 6 condition (a) makes an
  unselected composite `unknown`.
  (The earlier rationale here said "a dropped check never enters `covered_checks`, so its prior findings
  are `unknown` forever", which was the *ordinary*-check mechanism and stopped applying to composites
  once they lost their cell; the outcome is the same but it now comes from condition (a), and this entry
  no longer contradicts tension 6.)
  Closed by the "Wire scan profiles: quick, full, compliance" ticket exactly per this entry's own
  direction: `lib/checks.sh`'s `checks_intensity_keeps` exempts a `derived`-type record from the
  `--intensity` ceiling unconditionally (tension 15 step 3, amended in the same change), while leaving
  it fully subject to `--profile-scan` and `--allow-intrusive` - only the intensity filter is waived.
  `rules/RULE-FORMAT.md` §9.1.3's own enumeration is untouched (the frozen document; see §11's rule
  against editing it for a decision settled elsewhere), so `derived` remains absent from its type-tag
  list there - that list was never wrong, since a composite is never itself tagged with an
  `--intensity` tier; it is tension 15's FILTER that needed the exemption, not the tag vocabulary.
- **F17 [low] - CLOSED. `aws_ro` sets `AWS_PAGER=''` rather than pinning `--no-cli-pager`**
  (tension 23, item 5), which is exactly the prescribed direction.
  The flag is v2-only; tension 24 probes for `aws` by presence rather than by major version, so on a
  v1 host every AWS call would have failed at argument parsing and the entire cloud module would have
  produced zero findings while reporting a tool error.
  Measured against a real `aws-cli/1.44.x` install (`tests/localstack/run.sh`, not just a stub):
  `--no-cli-pager` is rejected at parsing exactly as described, and `AWS_PAGER=''` is not.
  `_awscli_probe` in `lib/awscli.sh` records the detected major version via `run_record
  aws_cli_major` whenever a run directory exists, satisfying the second half of the direction; it is
  a no-op outside a run (`tests/suites/awscli.sh`), same as every other `run_record` call.
  `lib/awscli.sh` itself lands ahead of `docs/DESIGN.md` §13 step 6 as part of a credential-less pass
  advancing what needed no AWS account; see `AGENTS.md`, "AWS module: what exists ahead of step 6".

## Where the build currently stands

**`docs/DESIGN.md` §13 step 1 is implemented.**
`lib/records.sh`, `lib/core.sh`, `lib/findings.sh` and `lib/report.sh` exist, with
`rules/redaction.rules`, `data/severity-rubric.conf`, the shipped `config/*.example` files, a fixture
end-to-end path, and a test suite that runs from `tests/run-tests.sh`.
The five follow-ups that had to be settled first - F13, F14, F12, F15, F16 - are closed above, each in
the tension that owns it and each with a test that fails under the original.
F18 closed with them by mechanism.

`scan.sh` (the §5 CLI grammar, tension 14's exit-code precedence, and wiring `lib/config.sh` ahead of
dispatch) and `lib/checks.sh` (tension 15's filter chain and registry loader, plus the
`_scan_apply_profile_filter` wiring into `scan.sh`) are both now built, closing out §13 step 2 except
for real module execution, which waits on step 3+ as `scan.sh`'s own header says.
F3 and F8 are closed as part of `lib/checks.sh` landing (see their own entries above); F5 and F20
remain open for the same reason they always were - `rules/derived.rules` is still not seeded, since its
contributors do not exist until steps 5 and 6.

**§13 step 3 is complete: every rule pack `docs/DESIGN.md` §6.3's catalog names is now on disk and
exercised.**
3a shipped the native pattern engine `modules/sast/engine.sh` and the `scan_dispatch sast` entry point
`modules/sast/run.sh` plus the first rule packs; 3b, 3c and 3d added further per-language packs; and 3e
shipped `modules/sast/history.sh`, which replays `secrets.rules` against git history (bounded by a
commit/time window, per §6.3) and populates the `SAST-HIST-*` check family - the fingerprint profile
(`blob_sha`, `match_digest`, `occurrence`) and `oldest_reaching_commit_time` that tension 13's boundary
test and tension 6 condition (b1) read once `state/` exists at step 7.
WHICH packs have landed, and that §6.3 now owes nothing, is in the generated block below, not in this
paragraph: it previously undercounted step 3 and left an already-landed pack in its still-missing list,
which is the failure the generator exists to make impossible.
The last two packs, `nosql.rules` (4 checks) and `ldap.rules` (3 checks), landed together and took
`tests/suites/sast.sh` from 90 to 130 passing assertions with none failing.
Step 4 is complete: both its IaC and its SCA halves landed, out of step order and in slices - see the
two paragraphs below.
Step 5 (DAST) is under way, its whole **tier 0 is complete**, and **tier 1 is now complete too**.
Tier 0: DAST-01 (the tension-16 limiter, budget and breaker), DAST-02 (`modules/dast/run.sh`, the
dispatch entry point), DAST-31 (the identifying `User-Agent`), DAST-32 (the conservative ceilings and
the `--i-own-target` affirmation), DAST-33 (the authorisation record in `run.json`) and DAST-34 (an
unrestricted run stated on stderr and in the report).
Tier 1: **DAST-03 (`auth.sh`, §7.0 authentication and session acquisition) has landed** -
`modules/dast/auth_engine.sh` and `modules/dast/auth.sh`, with every §7.0 login mode (static bearer and
API key, form login, the OAuth2 password and client-credentials grants, and Cognito-style SRP from a
pre-obtained token), a mode-600 cookie-jar-plus-token session store in the run scratch directory,
transparent re-auth on a `401` exactly once, two labelled identities for DAST-29, and the
config-derived half of §7.4's user-enumeration checks.
It also enforces `rules/RULE-FORMAT.md`'s E073 and E074 for the first time, and it extended
`lib/http.sh` with the per-request context (headers, a request body, and response capture) that §7.0
cannot be expressed without - inside the chokepoint, for tension 19's own reason, with the credential
reaching curl over stdin rather than through `argv` or a file (tension 9).
`docs/STEP5-DAST-PLAN.md`'s DAST-03 landing note carries the full detail, including why a failed
authentication is a DECLARED coverage reduction under tension 14's table rather than an exit 5.
**Tier 1's DAST-04 (`modules/dast/crawl.sh` plus `crawl_engine.sh`) has landed alongside it**, so the
endpoint and parameter inventory that all twenty-seven tickets in tiers 2-5 consume exists and has a
normative, frozen-in-intent shape in `docs/INVENTORY-FORMAT.md`.
With both tier-1 tickets in, **tiers 2-5 are unblocked and nothing remains in front of them**; the
authenticated crawl pass plugs into DAST-03's session rather than being stubbed.
Work in those tiers has started, and out of tier order, since they are peers rather than a sequence:
tier 4's DAST-14 (`active/sqli.sh`), DAST-15 (`active/xss.sh`), DAST-17
(`active/pathtraversal.sh`) and DAST-19 (`active/openredirect.sh`), tier 5's DAST-26 (`jwt.sh`),
DAST-27 (`graphql.sh`, the §7.4 GraphQL introspection & key-exposure check), DAST-29 (`authz.sh`) and
DAST-30 (`passive/transport.sh`) and
tier 2's DAST-06 (`passive/cookies.sh`), DAST-05 (`passive/headers.sh`) and DAST-11
(`passive/markup.sh`) have landed.
DAST-17 reuses DAST-14's shared `inject_engine.sh` unchanged; see `docs/STEP5-DAST-PLAN.md`'s DAST-17
landing note for its one new decision - reading the parameter inventory from
`$SCOURSH_RUN_DIR/inventory/*.json` directly rather than trusting the exported paths alone, since
`modules/dast/run.sh` resolves those exports before `crawl.sh` writes the inventory they name.
DAST-15 is the second tier-4 injection probe and the first to consume `active/inject_engine.sh`
without extending it, which is the evidence that DAST-14's shared half really is shared rather than
sqli-shaped.
One decision in it is a tension matter rather than implementation detail: it tells a reflection that
came back RAW from one that came back ESCAPED, and reports only the former.
Almost every parameter on a real application reflects something, so a probe that flagged reflection
alone would be a false-positive generator, and the escaped case is the one that reads as a pass -
which is why every context case in `tests/suites/dast-xss.sh` is a PAIR, the same marker escaped and
raw, rather than a single positive.
DAST-19 is the third tier-4 probe and likewise reused DAST-14's shared `active/inject_engine.sh`
rather than forking it, adding two OPT-IN knobs there (`_INJ_WANT_HEADERS`, `_INJ_MAX_REDIRECTS`) that
default to exactly the behaviour every probe written before them already had.
Its one tension-relevant decision: an open-redirect signal is the AUTHORITY of the returned `Location`
URL, parsed the way a browser parses it, and never a substring of the URL.
Both naive readings fail in a direction that reads as a clean result - a substring test flags the
commonest SAFE behaviour on the surface (an on-origin redirect that reflects the payload into its own
query string), while ignoring userinfo or matching the sentinel host by exact equality alone misses
`https://<site>@<sentinel>/` and `https://<site>.<sentinel>/`, which are precisely the two shapes that
defeat a real allow-list and so the two worth probing for.
Every one of those was measured by mutating the implementation into the rejected reading and watching
`tests/suites/dast-openredirect.sh` go red, not reasoned about: ten mutations, ten reds, one green
baseline.
DAST-27's GraphQL introspection check (`modules/dast/graphql.sh`/`graphql_engine.sh`) parses the
introspection response structurally via `crawl_json_flatten` rather than grepping for `__schema`: a
server with introspection correctly DISABLED echoes that literal string back inside its own refusal
error message, so a substring test reports a critical misconfiguration on the exact response proving
the opposite. It also decides whether to probe at all from the crawled inventory rather than sending an
introspection query at every endpoint to find out, and it contributes a `loc_target`-bearing finding for
the DERIVED layer's `COMPOSITE-TOKEN-HIJACK` correlation rather than minting its own composite id.
DAST-06 is the first §7.1 passive check and the first `modules/dast/passive/` file; two things about
it are tension decisions rather than implementation detail.
First, its `Set-Cookie` parser splits on `;` only OUTSIDE double quotes and never on `,` - both naive
readings fail in the direction that reads as a pass (a comma split invents a phantom cookie out of an
`Expires` date and strands the real one's attributes on it; a quote-blind `;` split reads a quoted
word `Secure` as the attribute and passes a cookie that is missing it), and both were measured by
writing the naive version and watching `tests/suites/dast-cookies.sh` go red rather than reasoned
about.
Second, an ABSENT `SameSite` and an explicitly weak one are two check ids rather than one check with
two messages, because `check_id` is a fingerprint component (tension 5) and a single id would make
two states with different remediations one finding whose meaning flips between runs.
`docs/STEP5-DAST-PLAN.md`'s DAST-06 landing note carries the full detail, including the
`SCOURSH_DAST_ENDPOINTS`-is-resolved-before-`crawl.sh`-runs defect it surfaced in
`modules/dast/run.sh` and filed rather than widened into itself.
**DAST-05 (`modules/dast/passive/headers.sh`) landed alongside it**, appending eleven
`DAST-HDR-*` script checks to the shared `checks.rules` (CSP presence and content, HSTS
missing/weak/malformed as three separate ids, framing protection, MIME sniffing, a leaky
`Referrer-Policy`, and a configurable "recommended headers not set" roll-up), with
`tests/suites/dast-headers.sh` proving them from recorded responses and no network.
**DAST-11 (`modules/dast/passive/markup.sh`) landed after both**, appending six `DAST-MARKUP-*`
script checks to the same shared `checks.rules` (missing Subresource Integrity, reverse tabnabbing as
two ids, insecure framing as two ids, and an absent anti-CSRF token in a state-changing form), with
`tests/suites/dast-markup.sh` proving them from recorded response bodies and no network.
Two things about it are tension decisions rather than implementation detail.
First, tension 5 again, in a shape the register had not previously recorded: a severity that varies
with CONTEXT is expressed as a second check id, never as a `base_severity` the emitting script raises
at run time.  This ticket's own requirement was that reverse tabnabbing be "weighted higher on login
and redirect pages", and `severity` is a per-record property of the registry
(`rules/RULE-FORMAT.md` §9.5) that every DAST suite asserts the script and the registry agree on - so
a script that raised it in place would put the report and the registry into disagreement, and would
also collapse two states with different remediations onto one fingerprint.  `DAST-MARKUP-TABNABBING-01`
(`low`) and `DAST-MARKUP-TABNABBING_SENSITIVE-01` (`medium`) are the same argument
`cookies.rules` already records for absent-versus-weak `SameSite`.
Second, tension 24: the record stream between this phase's `awk` tokenizer and its bash reader is
separated by 0x1f rather than by a tab, because a tab is an IFS-*whitespace* character and `read`
folds a run of them into one delimiter - a six-column record with two empty middle columns arrives as
four and shifts every later value left.  Measured, not reasoned about: it made the SRI check read an
`integrity` attribute the server never sent, and it read as a clean result.
`docs/STEP5-DAST-PLAN.md`'s DAST-11 landing note carries the full detail, including the parser's
stated limits in both directions and the shared-`passive/response_engine.sh` lift it declined to make
under a peer's file and filed instead.
Their remaining peers DAST-07 and DAST-09 are open and unordered among themselves; DAST-08 (below) and
DAST-10 have since landed too.
Three things about it belong here rather than only in the plan, because each is a tension decision.
First, tension 19 again: this phase issues real traffic and every request of it goes through
`http_request`, with a NON-fatal `http_gate_url` pre-check ahead of each inventory-derived URL for
exactly DAST-04's reason - one out-of-scope row written by another producer would otherwise abort the
operator's whole run with exit 3.
Second, tension 21's artifacts are consumed as OPTIONAL input and the phase degrades to the operator's
own `base-url`, then to a recorded `coverage_gap`, rather than to silence; applicability is tracked per
check so an inapplicable one (HSTS over plaintext, a CSP check against a JSON response) is DECLARED
uncovered instead of counted in `checks_run`, which is tension 12's coverage question answered honestly
rather than by execution.
Third, the "configurable" roll-up is a vendored data file plus an environment seam, NOT a
`config/scanner.conf` key: `rules/RULE-FORMAT.md` §9.6.1 is frozen and §14 item 2 prices a new key at
`lib/records.sh` plus `tests/lint-rules.sh` moving together, which a tier-2 check should not spend on
behalf of six parallel peers.
It independently hit the same pre-existing `modules/dast/run.sh` defect DAST-06 filed, and
likewise did not fix it in place: the inventory paths are exported BEFORE the phase loop while
`crawl.sh` writes the files inside it, so `SCOURSH_DAST_ENDPOINTS` is empty on every first run
and any consumer trusting it alone sees no surface - `modules/dast/active/inject_engine.sh` is one such consumer today.
**Tier 5's DAST-28 (`modules/dast/ratelimit.sh`, the §7.4 missing-throttling burst probe) has landed
too**, shipping two `DAST-RATE-*` script checks in the shared `modules/dast/checks.rules` and
`tests/suites/dast-ratelimit.sh` (66 assertions, recorded responses, no network).
Four tension decisions in it belong here rather than only in the plan.
Tension 16 first: this is the one check `docs/DESIGN.md` §7.4 flags as intentionally multi-request, and
it draws its burst down from the SAME per-run budget counter the limiter owns, through a new
`http_budget_remaining_set` in `lib/http.sh` beside that counter - a module-local reader would be a
second definition of where the budget lives, and `docs/STEP5-DAST-PLAN.md`'s own DAST-28 amendment
requires the shared one.
It spends at most half of what remains, because the budget refusal is fatal (exit 5) and a probe sized
to the whole remainder would end the run for every phase and target after it; and the number it reads
is a READ rather than a reservation, since nothing is charged until `_http_throttle` charges it inside
its own critical section.
Tension 19 again: every burst request goes through `http_request`, so the burst is rate-limited,
budgeted, breaker-watched and scope-gated by the chokepoint rather than by the module, and a "burst"
therefore means "as fast as this run's configured rate permits" - which is why the achieved rate is in
the evidence of every finding it emits.
Tension 14's honesty posture is what the four refusal gates implement: an unaffirmed run, an affirmed
run whose rate was never actually raised, a budget too small to fund a meaningful burst, and a target
with no idempotent endpoint each record a `coverage_reduction` and a `coverage_gap` and send nothing,
so an absent throttling finding never reads as a clean result.
Tension 5 explains the two check ids: the DAST fingerprint carries no component naming the defect, so
"no throttle at all" and "throttles but offers no usable back-off" under one id would collide on one
endpoint and `findings_merge` would silently keep one.
**DAST-29 (`modules/dast/authz.sh` plus `authz_engine.sh`) has also landed** - §7.4's object-level
authorization (IDOR) and excessive-data-exposure checks, the first consumer of DAST-03's labelled
multi-identity plumbing and the first tier-5 phase at the top level of `modules/dast/`, with the new
shared `modules/dast/checks.rules` carrying its four `DAST-AUTHZ-*` ids and
`tests/suites/dast-authz.sh` proving them from a scripted, no-network server keyed on
(path, identity).
Six things about it are tension decisions rather than implementation detail; the last two are
corrections made after a QA pass on the first landing, and each is pinned by a case in that suite's
section H which was observed red against the shipped code.
First, tension 5 again: a shared object is `DAST-AUTHZ-IDOR-01` or
`DAST-AUTHZ-CROSS_IDENTITY_READ-01` depending on whether a refusal was observed elsewhere under the
same path template, and they are two ids rather than one check with two messages because `check_id`
is a fingerprint component and the DAST location profile names nothing that distinguishes them, so a
single id would make two claims with different remediations one finding whose meaning flips between
runs - exactly DAST-06's absent-versus-weak-`SameSite` reasoning.
Second, tension 9: the "other identity's data" arm tests for an identifier out of `config/auth.conf`,
a mode-600 credential file, so it is a pure-bash substring test over a bounded read rather than a
`scan_match` - every engine this repository wraps takes its pattern on argv - and the identifier is
never echoed into the evidence, which names the identity LABEL instead.
Third, tension 19 again, in DAST-04's shape: inventory-derived URLs get a NON-fatal `http_gate_url`
pre-check and are then requested through `http_request`, which re-gates.
Fourth, tension 14's declared-versus-unplanned distinction decides every skip: fewer than two LIVE
sessions, no object reference in the inventory, and an unreadable field list are each a
`coverage_reduction` plus a `coverage_gap` and a return of 0, never an exit code - a check whose
silence would otherwise read as "this application enforces object-level authorization".
Fifth, tension 5 once more, in the direction that is easy to miss: `loc_method` must carry the method
that was actually requested and never a constant.  The DAST location profile includes the method and
this phase's own group key discriminates on it, so a hardcoded `GET` made two groups it deliberately
kept apart hash identically and `findings_merge` silently kept one - the very collision the four ids
exist to avoid, reintroduced one field lower down.  In the same family, `HEAD` is now refused at
candidate selection under its own counter: RFC 7231 §4.3.2 gives it no response body, so the
byte-comparison oracle cannot conclude, and admitting it produced two coverage records that were
false about their own input (a body-less response reported as "different bytes to each identity", and
a zero-byte body reported as exceeding the 512 KiB parse bound).
Sixth, tension 14's honesty requirement applied to `checks_run` itself, plus one place where §7.0's
own rule is locally wrong.  `checks_run` is written from the ids a pass actually EXECUTED rather than
from the passes that were entered, because `rules/RULE-FORMAT.md` §9.6.2 makes `username` optional
and mode-restricted - so `DAST-AUTHZ-OTHER_IDENTITY_DATA-01` cannot run for a `bearer` or `api-key`
identity, which is the ordinary shape, and recording it as run was exactly the "could not tell 'ran
and found nothing' from 'never loaded'" state `lib/records.sh` defines the field to prevent.  And
§7.0's "on 401 refresh once and retry, else mark the identity `failed`" is right for every other
phase and inverted for this one: this check asks one identity for another's object on purpose, so a
401 is the expected refusal and the enforcement witness.  `authz_probe_as` therefore does not call
`dast_auth_request`; it refreshes only when the identity has not yet been seen to read anything
successfully, at most once per identity per pass, and a still-401 retry is reported as a refusal
without marking the identity `failed` - because otherwise one refused URL silently disabled every
later check needing that identity.

**DAST-30 (`modules/dast/passive/transport.sh`) has landed** - the §7.4 transport-exposure family,
five `DAST-TRANSPORT-*` script checks appended to the same shared
`modules/dast/passive/checks.rules` alongside the blocks DAST-06, DAST-05, DAST-10 and DAST-11 each
appended to it, with `transport_engine.sh` as the pure half and
`tests/suites/dast-transport.sh` proving them from recorded response heads AND bodies with no
network.  It reports the two classes a TLS check cannot see: content that TRAVELS unencrypted
(sensitive content over `http://`, and a plaintext origin that does not redirect to TLS) and content
an encrypted page LOADS unencrypted (mixed content, split into blockable, optionally-blockable and
form-action ids).  Four things about it are tension decisions rather than implementation detail.

First, **its row in `modules/dast/engine.sh`'s phase table MOVED, from `transport.sh:active` to
`passive/transport.sh:passive`, and that is tension 15's intersection rule being honoured rather than
bent.**  DAST-02 transcribed every tier-5 row from `docs/DESIGN.md` §7.4's section heading, which is
right for that section's other four scripts and wrong for this one; the phase table's own note
already specified the remedy ("a later ticket whose checks legitimately carry a LOWER type tag than
the tier its row declares here must change that row in the same change and say why"), and this is its
first exercise.  Nothing here mutates target state - every request is a plain GET to the operator's
`base-url` or to an endpoint an earlier phase already fetched - so §7.1's admission criterion is met;
§7.4's own wording for this bullet calls it a complement to "the TLS **passive** check"; and at
`active` it would never run at all, since `--intensity` defaults to `passive` and anything above it
additionally requires `--i-own-target`.  A row left at `active` is not a conservative choice, it is a
check that is dead code on every ordinary run.  The records carry the matching `passive` type tag, so
both gates permit and neither widens the other.

Second, **tension 19 again, and with a boundary the other passive phases do not have**: every request
goes through `http_request` behind a NON-fatal `http_gate_url` pre-check, for DAST-04's reason.  But
this family also DISCOVERS URLs - the sub-resources an HTTPS document references - and it never
requests any of them.  They are classified from the markup alone.  That is deliberate and it is the
honest reading rather than a shortcut: a third-party CDN loaded over plaintext is the commonest real
mixed-content case and is out of scope by definition, so filtering discovered references by the scope
gate would produce a false negative on exactly the case that matters most.  The gate governs what is
REQUESTED; this phase requests only the documents the operator authorised.

Third, **tension 12's coverage question is answered per class rather than per run.**  A
mixed-content check needs a secure DOCUMENT to be applicable at all, and a plaintext check needs an
unencrypted response; a run that saw neither did not test them.  Both directions record
`transport_check_not_applicable` naming the uncovered ids and the counts that made them so, and an
inapplicable check never enters `checks_run` - "nothing was mixed" and "nothing was testable" are
different facts and the report must not render them the same.

Fourth, **two of this family's decisions were found by MUTATION rather than by review, and the
register records that because the pattern generalises.**  A plaintext `<a href>` is not mixed content
in any browser - nothing is loaded into the secure document - and the naive "match `http://` anywhere
in the body" reading floods the report with every external link on every page; the extractor emits
navigation references anyway, so their ABSENCE from the findings can be asserted.  And the obvious
assertion for reference resolution ("a protocol-relative reference produces no finding") pins
NOTHING, because it passes under both resolving the reference and simply skipping anything with no
scheme of its own - only an absolute `http://` reference can be mixed content on an https page at
all.  What discriminates is the ACCOUNTING (`_TR_REF_TOTAL`, references the check could judge), which
under the skip silently becomes "references that happened to be written absolutely".  This is
`docs/DESIGN.md` §12's testing rule biting on a case that looked already covered, and the assertion
was reworded rather than left claiming a discrimination it did not have.

`docs/STEP5-DAST-PLAN.md`'s DAST-30 landing note carries the full detail, including the scope
boundary against `passive/tls.sh` (the connection), `passive/headers.sh` (HSTS) and
`passive/cookies.sh` (the `Secure` attribute), and the `lib/http.sh` gap it filed rather than widened
into itself: `http_request` publishes no final post-redirect URL, so an `https://` endpoint that
redirects to an in-scope `http://` one delivers a plaintext document this phase still counts as a
secure context.

**DAST-08 (`modules/dast/passive/cors.sh` plus `cors_engine.sh`) has also landed** - the §7.1 CORS
origin-reflection family, three check ids (`DAST-CORS-ORIGIN_REFLECTED-01`,
`DAST-CORS-REFLECTED_WITH_CREDENTIALS-01`, `DAST-CORS-WILDCARD-01`) driven from recorded response
headers by `tests/suites/dast-cors.sh`.  It lands after tension 29's split of the directory's registry
(above), so its three ids were seeded directly into their own `modules/dast/passive/checks-cors.rules`
rather than into the now-retired shared `checks.rules` its own commit message describes, and
`modules/dast/passive/` itself already existed by the time it landed (DAST-06 created it first, per
above).  It is the first §7.1 check to send a request at all, and it settles what that means: §7.1's
contract is "no mutation of state", not "no traffic", so the probe is bounded by six properties
asserted against a request log rather than claimed in prose - GET/HEAD inventory endpoints only, one
request per distinct route, no request body, no response-body capture sink, no redirect followed, and
everything through `http_request` so tension 19's gate and tension 16's limiter, budget and breaker all
bind it.  Two further things about it are tension decisions rather than implementation detail.  First,
tension 4: its response-header read is case-INSENSITIVE on the field name (`cors_header_last` passes
`-i` through `scan_match`, never a bare grep), because RFC 7230 §3.2 makes header names
case-insensitive and HTTP/2 (RFC 7540 §8.1.2) requires them lowercase on the wire, so a target behind
any HTTP/2 edge answers `access-control-allow-origin:` and an RFC-6454-spelled matcher would report
every one of them clean - a silent false negative on the commonest production deployment shape, caught
only by `tests/suites/dast-cors.sh`'s dedicated lowercase fixtures.  Second, tension 4's `mktemp`
discipline: `cors_engine.sh`'s two scratch paths were first spelled with a `$BASHPID`-derived name and
corrected in the same ticket, since a predictable name under `${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}` is
one a local user can pre-create as a symlink for `scan_match` or a response-header capture sink to
write through (CWE-377 via CWE-59); `tests/suites/dast-cors.sh` section A2 plants that exact symlink
and asserts a canary file survives.
`docs/STEP5-DAST-PLAN.md`'s DAST-08 landing note carries the full detail.

Tiers 4 and 5: **DAST-14 (`modules/dast/active/sqli.sh`) and DAST-26 (`modules/dast/jwt.sh`) both
landed in `a656663`** without this section or its `AGENTS.md` mirror being updated in that commit range
- the same process failure this document's own build-status rule exists to prevent, corrected here
rather than left for a third rediscovery.
`docs/STEP5-DAST-PLAN.md`'s per-ticket landing notes are the authority for all three.

Two things about DAST-04 are worth carrying here rather than only in the plan, because both are
tension decisions rather than implementation detail.
First, the scope pre-check on a discovered link is **not** a second gate and never becomes one
(tension 19): `http_request` gates fatally, which is right for an operator-configured URL and wrong
for one lifted off a scanned page, since it would let any site abort the operator's run by linking
off-target; the pre-check decides only what is worth enqueueing, and everything that survives is
still requested through `http_request`, which re-gates on the way out and on every redirect hop.
Second, a specification contributes its PATHS and never its HOST - adopting an OpenAPI
`servers[].url`, a Postman URL or a HAR entry's host would turn `config/discovery.conf` into a way
past that gate.
The client-rendered (SPA) limitation ships as a stated `coverage_gap` reaching `run.json` and both
report formats, not as prose and not as a fix: scoursh executes no JavaScript, so a crawl of a real
Angular target found 13 endpoints and 0 parameters and said so, which is the honest result
`docs/DESIGN.md` §15 demands rather than a defect to tune away.
**DAST-09 (`modules/dast/passive/banner.sh` plus `banner_engine.sh`) has landed**, a §7.1 passive check.
`modules/dast/passive/` already existed by the time it landed (DAST-06 created it first), and its three
check ids are seeded into their own `modules/dast/passive/checks-banner.rules` rather than a shared
`checks.rules` - tension 29's split into one `checks-<name>.rules` per owner was already in effect for
its peers, so this ticket follows that convention rather than reintroducing the retired shared file.
`checks_registry_load` globs `*.rules` at any depth under `modules/dast/` regardless of which shape a
given owner picked.
Two things about it are tension decisions rather than implementation detail.
First, tension 25 applies unchanged to a DAST version check: the scanner does an **exact table lookup**
against the vendored `data/versions.db` and performs no version comparison and no range arithmetic at
all, so "out of date" means "this exact version is named in the list" and never a guess - the expansion
of an advisory range into exact versions stays on the networked box that has the tooling.
`docs/VERSIONS-DB.md` is the normative format for that file and, per tension 25's own "a list nobody can
refresh becomes wrong quietly", carries the refresh procedure as part of the format; the file's `banner`
namespace and the SCA-ecosystem namespace `tools/vendor-engines.sh advisories` writes coexist in one
table by construction (that writer replaces only its own ecosystem's rows, and `banner` sorts before
every ecosystem name under `LC_ALL=C`).
Second, an absent or `banner`-less list is a **declared coverage reduction of that one sub-check**, under
tension 14's declared rows and `docs/DESIGN.md` §15, never an error and never a clean result: the two
disclosure checks keep running, `versions_db_absent` and `versions_db_no_banner_rows` are distinct
reasons, a product the list has never heard of is counted into a `versions_db_product_unknown` roll-up,
and every out-of-date finding carries the list's own generation stamp - because a stale list produces
false negatives, which is the failure mode that hides.
Tier 4's DAST-14 (`active/sqli.sh`) and tier 5's DAST-26 (`jwt.sh`) also landed, out of tier order;
`docs/STEP5-DAST-PLAN.md`'s per-ticket tables are the authority for what is in.
`modules/cloud/` remains unbuilt and steps 6, 7 and 10 remain unstarted; step 5 is still the top
priority ahead of them.
`lib/awscli.sh` is a further out-of-sequence exception: a credential-less pass built it ahead of step
6, so the chokepoint exists while `modules/cloud/aws/live/*.sh` and everything else step 6 names are
still unbuilt - see "AWS module: what exists ahead of step 6" in `AGENTS.md`.
The remaining follow-ups (F5 and F20) are inherited by steps 4 through 10 and are still open.
(F3, F4, F8, and F16 - including its `look` half - are closed above, and F17 closed out of order as
part of that same credential-less pass.)

**Step 4's IaC half landed out of sequence, ahead of step 3's remaining sub-steps and ahead of step 4's
own SCA half, one ticket per file format.**
`5de4460` ("IaC: Terraform checks via the pattern-rule engine (§13 step 4)") shipped `modules/iac/run.sh`
(the `scan_dispatch iac` entry point), `modules/iac/parse.sh` (the Terraform HCL parser), and
`modules/iac/terraform.rules`, reusing the native pattern engine `modules/sast/engine.sh` built at step
3a rather than forking a second one.
`terraform.rules` seeds seven checks: `IAC-TF-OPEN_CIDR-01`, `IAC-TF-PUBLIC_ACL-01`,
`IAC-TF-UNENCRYPTED-01`, `IAC-TF-KEY_ROTATION_DISABLED-01`, `IAC-TF-PUBLIC_IP-01`,
`IAC-TF-HARDCODED_SECRET-01`, and `IAC-TF-RDS_PUBLIC-01`; `tests/suites/iac.sh` tests it.
A second landing, `add2b21` ("IaC: Helm chart checks via the pattern-rule engine (§13 step 4)"),
added `modules/iac/helm.rules`: three checks (`IAC-HELM-HOST_PORT-01`, `IAC-HELM-HOST_MOUNT-01`,
`IAC-HELM-HARDCODED_SECRET-01`) against Helm chart sources only (`values.yaml` and
`templates/*.yaml`) - `helm.rules`' own header states its scope discipline explicitly (never a
docker-compose file, never a bare non-Helm Kubernetes manifest) and its own "KNOWN GAP" note confirms no
`modules/iac/kubernetes.rules` (or any other Kubernetes-manifest pattern pack) exists on `dev` as of
that landing.
A third landing, `25abfa3` ("IaC: Dockerfile checks via the pattern-rule engine (§13 step 4)") added
`modules/iac/dockerfile.rules`: six checks (root/no `USER`, `:latest` base tag, secrets
in `ENV`/`ARG`, remote `ADD`, `curl | sh` build steps, unpinned base digest), scoped strictly to
`Dockerfile`, `Dockerfile.*`, and `*.dockerfile` - `docker-compose*.yml` and Helm `values.yaml` are
deliberately excluded from this pack's `files:` list, continuing the same one-pack-per-format split
`terraform.rules`' own header already established for `docs/DESIGN.md` §3's originally-combined
`containers.rules` sketch.
A fourth landing, `bb75c9b` ("IaC: Kubernetes manifest checks via the pattern-rule engine (§13 step 4)")
added `modules/iac/kubernetes.rules`: eight `IAC-K8S-*` checks (privileged containers,
host network/PID namespace sharing, missing resource limits/requests, `runAsNonRoot` unset, plaintext
secrets in env vars, the mutable `:latest` image tag, wildcard RBAC verbs/resources, and
`automountServiceAccountToken` left at its default), scoped to plain Kubernetes YAML/JSON manifests and
reusing `modules/iac/run.sh`/`parse.sh` unchanged - closing exactly the gap the Helm landing's own
"KNOWN GAP" note (above) flagged as still open at that point. Helm chart templates and CloudFormation
templates are explicitly excluded by design: the pack's own header covers the case-sensitivity
(Kubernetes' lowerCamelCase field names versus CloudFormation's PascalCase) and `context-deny` (`\{\{`
for Helm, `AWSTemplateFormatVersion|AWS::` for CloudFormation, on the three absence-style checks)
mechanisms that keep it out of scope for those two shapes even though the file glob overlaps;
`tests/suites/iac.sh` proves both fixture shapes yield zero `IAC-K8S-*` findings.
§6.6's container/orchestration catalog and §8.2's CloudFormation checks are two separate sub-scopes of
step 4's IaC half; which of their slices have landed, and the on-disk pattern-pack count that
`tests/lint-rules.sh`'s E060 fixture-coverage note reports, are both in the generated block below.
Do not read this paragraph as "step 4 is done."

**A fifth landing has since closed the docker-compose gap the paragraph above left open:
`57d1cd1` ("IaC: docker-compose checks via the pattern-rule engine (§13 step 4)") added
`modules/iac/docker-compose.rules`.**
`docs/DESIGN.md` §6.6 bundles docker-compose in with Dockerfile/Kubernetes/Helm under one prose
"containers.rules" bullet, but none of the four landings above had claimed the docker-compose slice
itself; this ticket closed exactly that one gap, reusing `modules/iac/run.sh`/`parse.sh` unchanged (they
already existed from the Terraform landing above) and adding only the new flat pack file plus its
fixtures.
`docker-compose.rules` seeds four checks: `IAC-COMPOSE-EXPOSED_PORT-01` (a host port bound without
restricting the interface), `IAC-COMPOSE-PRIVILEGED-01` (`privileged: true`),
`IAC-COMPOSE-SENSITIVE_MOUNT-01` (a host bind mount of `/var/run/docker.sock`, `/etc`, `/root`, `/home`,
`/proc`, `/sys`, or `/` itself), and `IAC-COMPOSE-PLAINTEXT_SECRET-01` (a literal credential value in an
`environment:` entry, rather than a `${VAR}`/`env_file:` reference).
Its `files:` globs match `docker-compose.yml`/`compose.yml` (and their `.yaml`/override-variant forms)
only - `tests/suites/iac.sh` has a dedicated cross-shape section proving a Kubernetes-manifest-shaped and
a Helm `values.yaml`-shaped fixture, each deliberately carrying content that would trip every
`IAC-COMPOSE-*` check if the engine ever inspected file content, still produce zero findings, and that a
mixed directory holding one file of each IaC shape never lets a check cross-attribute to the wrong file.
The on-disk pattern-pack count `tests/lint-rules.sh`'s E060 fixture-coverage note reports, and which
§6.6/§8.2 slices are still unclaimed, are in the generated block below rather than in this paragraph -
this one records only what the docker-compose landing itself decided.
Do not read it as "step 4 is done."

**A sixth landing added `modules/iac/cloudformation.rules`, closing out §8.2's CloudFormation half of
the IaC catalog** (§8.2's own catalog line - "cloud.rules terraform.rules cloudformation.rules" - names
this file directly).
It seeds eight checks: the seven `IAC-TF-*` siblings restated in CloudFormation's PascalCase property
shape (`IAC-CFN-OPEN_CIDR-01`, `IAC-CFN-S3_PUBLIC_ACCESS-01`, `IAC-CFN-UNENCRYPTED-01`,
`IAC-CFN-KEY_ROTATION_DISABLED-01`, `IAC-CFN-PUBLIC_IP-01`, `IAC-CFN-HARDCODED_SECRET-01`,
`IAC-CFN-RDS_PUBLIC-01`) plus `IAC-CFN-ECS_PRIVILEGED-01`, which has no Terraform sibling and is the
CloudFormation spelling of the Kubernetes pack's own `IAC-K8S-PRIVILEGED-01`.
**Its scoping inverts every other pack in `modules/iac/`, and that is what this paragraph exists to
record.**
Unlike Terraform (`*.tf`, a format nothing else in this repo emits) and unlike Helm (`values.yaml` /
`templates/*.yaml`, a path convention to lean on), a genuine CloudFormation template has no reserved
filename or path convention at all - `docs/DESIGN.md` §8.2 itself walks `*.yaml`/`*.yml`/`*.json`
generically - so `files:` globs cannot do the disambiguation the sibling packs rely on.
Every rule is therefore deliberately as broad on `files:` as the format allows and does the real
narrowing with a `context-require` that a genuine `Type: AWS::<Service>::<Resource>` declaration (or its
quoted JSON spelling) sits within the window: the one string a Kubernetes manifest, a Helm chart, or a
docker-compose file cannot carry while still being that thing.
That anchor is **strictly stronger than a filename glob**, which is why this pack ships no
`exclude-files` where `kubernetes.rules` needs eight compose globs (tension 4's own docker-compose
cross-fire) - and, because an untested claim is not a resolution, `tests/suites/iac.sh` asserts it
against the same `tests/fixtures/iac/docker-compose/` fixture that pack needed its globs for, plus the
Helm-template fixture, a bare Kubernetes Secret manifest and a generic non-CloudFormation JSON file that
both deliberately reuse the pack's own PascalCase vocabulary.
Adding compose globs here would be a guard no fixture can distinguish from its absence; if that
assertion ever goes red, adding them is the fix, not the prophylactic.
The landing also made an already-committed fixture load-bearing:
`tests/fixtures/iac/cloudformation/cloudformation_template.yaml` arrived with the Kubernetes pack as its
CloudFormation-shaped NEGATIVE guard and, until this pack existed, exercised no CloudFormation check at
all - `IAC-CFN-ECS_PRIVILEGED-01` now fires on the `Privileged: true` it already carried, asserted as a
`check_id@loc_path` pair so the assertion names that exact file, with the opposite direction asserted
too (no other check may fire on an otherwise-clean template).
Which §6.6/§8.2 slices have landed, and the on-disk pattern-pack count `tests/lint-rules.sh`'s E060
fixture-coverage note reports, are in the generated block below rather than in this paragraph.

**A third piece of step 4 has now landed, in three sub-tickets: `modules/sca/` (the SCA module's npm,
Python, and Ruby slices).**
`ed8c283` ("SCA: parse npm lockfiles and match against data/advisories.db") shipped `modules/sca/run.sh`
(the `scan_dispatch sca` entry point, with no check-registry gate - SCA is a table lookup, not a
pattern-rule engine) and `modules/sca/engine.sh`: lockfile discovery, `package-lock.json` (v1 and
v2/v3), `yarn.lock`, and `pnpm-lock.yaml` parsing, npm's own (identity) name normalisation, and the
`data/advisories.db` exact-match lookup (`sca_lookup_exact`/`sca_package_known`, both routed through
`lib/core.sh`'s `db_lookup_exact`, tension 25), emitting `SCA-NPM-VULNERABLE_DEP-01` and the
`SCA-COV-UNKNOWN_VERSION-01` roll-up.
A follow-on ticket ("SCA: parse Python lockfiles and match against data/advisories.db") added the
module's Python slice on top of the same `run.sh`/`engine.sh` split, exactly as `run.sh`'s own header
comment anticipated for a sibling ecosystem: `requirements.txt`, `poetry.lock`, and `Pipfile.lock`
parsing, PEP 503 name normalisation (`sca_pypi_normalize_name`), and `SCA-PY-VULNERABLE_DEP-01`
findings under ecosystem `pypi`, plus its own `SCA-COV-UNKNOWN_VERSION-01` roll-up (a separate finding
from npm's own when both ecosystems have unknown-version cases in the same run - a stated scope limit,
not a true cross-ecosystem merge; see `sca_scan_python_tree`'s own header comment in
`modules/sca/engine.sh`).
`a2d37aa` ("SCA: parse Ruby Gemfile.lock and match against data/advisories.db (§13 step 4)") then added
Ruby/RubyGems, in the same `modules/sca/engine.sh` file rather than a forked one: `sca_parse_gemfile_lock`
(Gemfile.lock's `GEM`/`GIT`/`PATH` `specs:` blocks, already flat - no recursion needed, unlike npm v1),
`sca_ruby_normalize_name` (lowercase, tension 25's RubyGems rule), and direct-vs-transitive from the
lockfile's own `DEPENDENCIES` stanza versus a specs-only entry, minting `SCA-RUBY-VULNERABLE_DEP-01`.
UNLIKE Python, Ruby joined npm's own `sca_scan_tree` call rather than getting a sibling function:
`sca_scan_tree` walks BOTH npm's and RubyGems' lockfiles in ONE call, sharing one `unknown_count` table,
rather than one call per ecosystem, because `SCA-COV-UNKNOWN_VERSION-01`'s fingerprint carries no
ecosystem/package/advisory_id component - two separate calls would emit two findings colliding on one
fingerprint, and `findings_merge`'s dedup would silently drop whichever ecosystem lost the sort instead
of merging their counts - proved concretely in `tests/suites/sca.sh` via a `mixed-ecosystems` fixture
(one npm lockfile, one Gemfile.lock, one root) asserting exactly one roll-up finding naming both
ecosystems.
`sca_scan_python_tree` (the Python slice, above) still runs as its own separate call for the reason it
always did - to avoid touching `sca_scan_tree`'s already-tested npm code path - so a run with
unknown-version cases in both an npm/Ruby lockfile AND a Python one still emits two separate roll-up
findings; a stated, filed gap, not a defect either the Python or Ruby ticket needed to fix.
`tests/suites/sca.sh` tests all three slices, including the real `scan.sh sca` end-to-end path.

**Java, PHP/Composer, and Go then completed step 4's SCA half.**
`a1b3c43` added Maven coordinates (`pom.xml`, `build.gradle`) as `sca_scan_java_tree` in
`modules/sca/engine.sh`, under `SCA-JAVA-VULNERABLE_DEP-01`.
`7e7b186` added Composer (`composer.lock`, cross-referenced against `composer.json` for
direct-vs-transitive) under `SCA-PHP-VULNERABLE_DEP-01`; it is the first ecosystem whose parser lives
outside `engine.sh`, in `modules/sca/php_engine.sh`, though it is still driven from inside
`sca_scan_tree` and so joins npm/Ruby's shared roll-up.
The Go ticket landed last and went one step further: `modules/sca/go_engine.sh` is a fully standalone
engine with its own entry point, `sca_go_scan_tree`, called from its own `_sca_go_run` in
`modules/sca/run.sh` - exactly the shape that file's own header invited for a further ecosystem ("do not
fork this file per ecosystem").
`go.mod`'s `require` block (single-line and block form) is the authoritative direct/transitive source: a
trailing `// indirect` comment marks a require line transitive, its absence marks it direct.
`go.sum` alone (no `go.mod` beside it) is parsed too, but every entry is honestly reported `unknown`
rather than guessed; `go.mod` wins when both are present in one directory.
Normalisation follows tension 25's frozen Go row exactly - the full module path with a `/vN`
major-version suffix RETAINED, and a trailing `+incompatible` version suffix STRIPPED before lookup -
each direction pinned by its own test against the naive misreading, and the raw pinned version is kept
visible in the finding's evidence rather than silently rewritten.
`replace`/`exclude` directives are NOT resolved: a stated limitation, surfaced at runtime as a
`reason=go_replace_exclude_directives_not_resolved` coverage_reduction rather than hidden.
It mints `SCA-GO-VULNERABLE_DEP-01` and, like Python and Java, its own `SCA-COV-UNKNOWN_VERSION-01`
roll-up rather than joining npm/Ruby/PHP's shared one - the same stated cross-ecosystem-merge gap
recorded above, not a new one.
Unlike `sca_scan_python_tree` and `sca_scan_java_tree`, `sca_go_scan_tree` performs its own
`data/advisories.db`-readable check, so `_sca_go_run` carries no "must run after `_sca_npm_run`"
ordering requirement; it is still called last in `_sca_run_module` for a stable emission order.
Whether every ecosystem `docs/DESIGN.md` §6.5 names now has a parser - and so whether this half of the
since-discharged step-5 DAST gate is complete - is in the generated block below, counted from the tree.

**Step 5 (DAST) has a written, dependency-ordered sub-ticket plan (`docs/STEP5-DAST-PLAN.md`), and its
whole tier 0 has now landed.**
The plan breaks the ~30-script step-5 scope into tickets DAST-01 through DAST-30, ordered per this
section's own build-order sequence (`lib/http.sh -> auth.sh -> crawl.sh -> passive -> safe-active ->
injection, one file at a time -> §7.4 auth/API/authz`), confirms `lib/http.sh`'s scope-gate chokepoint
(tension 19) already shipped and removes it from the "still to plan" list rather than re-listing it as
pending, and states the client-rendered-app (SPA) limitation as a `coverage_gap` the crawler ticket
(DAST-04) must surface in the report, not a gap this plan (or any step-5 ticket) closes with a headless
browser.
**This entry used to read "no DAST-0x ticket is picked up until step 3's outstanding rule packs and
step 4's SCA half are both complete on `dev`". BOTH halves of that gate are now discharged, so the gate
is gone rather than narrowed** - the generated block below reports SCA at 6 of 6 ecosystems and SAST at
10 of 10 artifacts, each with none outstanding, and it remains the live answer if either half is ever
in doubt.
The gate is recorded here rather than deleted because it was a real constraint that was satisfied, not
one quietly dropped: step 4's SCA half completed first, and step 3's last two packs, `nosql.rules` and
`ldap.rules`, landed second.
**That gate was in any case a sequencing preference inherited from `docs/DESIGN.md` §13's build order,
not a technical dependency**: no DAST ticket consumes a SAST rule pack, and DAST-01 - the tension-16
rate limiter with its per-run request budget and circuit breaker - touches `lib/http.sh` only.
**One ordering constraint inside step 5 is genuine and outlives that gate: DAST-01 must land before
anything issues real HTTP traffic.**
Until the limiter and the budget are hooked into `http_request`, `--jobs` multiplies the request rate
against a live endpoint with no throttle at all - tension 16's own per-process-state failure, the same
one that leaves the breaker unable to trip - which is why DAST-01 is tier 0 in the plan and tier 0
blocks tiers 1 to 5.
That is a constraint internal to step 5 on the order its own tickets land, not a blocker on starting
step 5, and **it is now satisfied**: DAST-01 landed first, and the rest of tier 0 - DAST-02, and then
DAST-31/32/33/34 together - landed on top of it.
No ticket below tier 0 has yet issued a request, so nothing sent traffic before the controls existed.

**Tier 0's safety half, DAST-31 through DAST-34, added two refinements this register owns rather than
the plan, because both are decisions about tension 16's own controls.**
First, the ceilings are applied to the RESOLVED value at the `lib/http.sh` chokepoint, and lifting them
requires an affirmation carried as a per-run record under the run directory - never an environment
variable, because an env var is settable by anything that can start the process and the ceiling's whole
job is to bind callers whose command line nobody parsed (`tests/e2e/dast-target-smoke.sh` is exactly
such a caller today).
Second, and not stated by the plan's own "Relaxable" table: the affirmation lifts the three UPPER bounds
(rate, budget, breaker threshold) and lifts NEITHER of `circuit-breaker-window`'s two bounds.  The 60s
floor stays because a shorter window counts fewer failures towards the same threshold, so relaxing it
would reach "the breaker never trips" by a different route than the disable switch this tension declines
to offer; the 86400s maximum stays because it is arithmetic rather than safety - it is what keeps
`now - window` inside 64-bit arithmetic, which no assertion about who owns a host can change.

**Step 5 is still this project's top priority**, ahead of live cloud scanning (step 6), persistent run
state (step 7), and SARIF plus the compliance report (step 10).
`docs/STEP5-DAST-PLAN.md`, not this entry, is the authority for which tickets remain.

**Step 8 (`--paranoid` / `tools/run-in-netns.sh`) is half landed: NETNS-01 has shipped; PARANOID-01
has not.**
`docs/STEP8-PARANOID-PLAN.md` split `docs/DESIGN.md` §13 step 8 per tension 20's RESOLUTION into
**PARANOID-01** (the `--paranoid` connection-observer and abort-on-out-of-scope enforcement) and
**NETNS-01** (`tools/run-in-netns.sh`, the network-namespace runner - optional and root-requiring,
stated directly in that ticket's own filed description).
**NETNS-01 has now landed.**
`tools/run-in-netns.sh` is a Linux-only, root/CAP_NET_ADMIN+CAP_SYS_ADMIN-requiring wrapper: it builds a
network namespace whose route table admits only two IPv4 address sets - tension 19's pinned resolution
cache (read via `lib/http.sh`'s own `http_scope_load`/`http_resolve_host`, never re-implemented) for
scoursh's in-scope targets, and the nameservers parsed from `/etc/resolv.conf` (this tension's own "set
3") - installs no default route inside the namespace, and execs the wrapped command inside it via
`ip netns exec`, so a connection attempt to anything outside those two sets has no route and fails at
the kernel level before a packet is sent, rather than being sampled or logged after the fact the way
`--paranoid` (PARANOID-01, still unbuilt) would. Namespace/veth/NAT/`ip_forward` teardown runs from the
tool's own EXIT trap on every exit path, success or failure, and every failure path (bad usage, wrong
host, missing privilege, a plumbing step itself failing) goes through `lib/core.sh`'s `die`, staying
inside the 0-5 exit contract; the one exit path deliberately NOT forced through `die` is the wrapped
command's own exit status, which is forwarded transparently rather than laundered. It is never invoked
by `scan.sh` and carries no dependency on PARANOID-01 - confirming this RESOLUTION's own "guarantee vs
detector" distinction holds in the shipped code, not just in this register's prose. IPv6 routing is
out of scope for this tool per its own ticket; an in-scope host that only resolves to IPv6 is logged
and skipped, never routed - a follow-up ticket for dual-stack support was filed separately rather than
absorbed into NETNS-01.
`tests/suites/netns.sh` tests it, and states plainly what it can and cannot prove on a given host:
argument parsing, the CapEff bitmask arithmetic, the collectors, and the build/teardown command
sequence are unit-tested against stubbed `ip`/`iptables`/`sysctl` on any host; the fail-closed
non-Linux and no-privilege paths run as real subprocess invocations (whichever applies on the host the
suite runs on); and the one claim that genuinely needs a privileged Linux kernel - an out-of-scope
connection attempt actually failing - is a real end-to-end case gated behind a genuine capability probe,
recorded as SKIPPED rather than a silent pass when that probe fails.
**PARANOID-01 remains unimplemented** and is unaffected by NETNS-01 landing; the two were never
interdependent, so PARANOID-01 may still be picked up on its own. This planning ticket's own acceptance
criteria named `lib/http.sh` (tension 19) as step 8's blocker, and confirmed it present on `dev` before
either sub-ticket started - it shipped early, out of its normal step-5 sequence, exactly as noted
below - and tension 20's RESOLUTION already states that `lib/http.sh`'s pinned resolution cache was
step 8's only real dependency ("so the ordering already works"), which NETNS-01 landing now confirms in
practice as well as in plan. Steps 6, 7, 9, and 10 remain un-landed and are not touched by this.

**Step 6 (Cloud/AWS) also now has a written, dependency-ordered sub-ticket plan
(`docs/STEP6-CLOUD-PLAN.md`), but no implementation ticket has started.**
The plan breaks §13 step 6's scope (`regions.sh` iteration -> the §8.1 live read-only catalog -> the
read-only-verb CI lint -> `posture/` checks) into tickets CLOUD-01 through CLOUD-34 plus POSTURE-01
through POSTURE-04, confirms `tests/lint-aws-readonly.sh` (tension 23's read-only lint) already shipped
at step 1 as a no-op stub over an empty set of call sites and removes its matching logic from the
"still to write" list - `lib/awscli.sh` has since landed too, so what is left of CLOUD-03 is seeding
`tests/aws-readonly-allow.txt`, adding a negative-fixture test, and re-verifying the lint's checks
against the first real `aws_ro` call sites once the live scripts start landing - and states that the
landed IaC work (`modules/iac/`) is §8.2/step 4 work, out of this plan's scope. **No CLOUD-0x or
POSTURE-0x ticket is picked up until step 3, step 4 (SCA + IaC), and step 5 (DAST) are all complete on
`dev`** - step 6 is gated on the whole sequential chain ahead of it, not step 4 alone, per that plan's
own status section and this ticket's description.
Steps 3 and 4 are now complete, so step 5 is the only link in that chain still open.

**PARANOID-01 has landed: `lib/paranoid.sh` now implements `--paranoid` for real.**
Full detail lives in tension 20's own "Implementation" paragraph above, since that is where this
register already keeps the mechanism's contract; this entry exists only so this section does not go
stale the way the process note below warns against.
In short: the four-set allowlist, the `ss`/`strace` backend probe, the exit-3 abort and exit-4
missing-backend paths, and the deterministic `tests/suites/paranoid.sh` fixture all now exist on
`dev`.
`tools/run-in-netns.sh` (NETNS-01) remains unimplemented, as scoped.

**Step 9 (optional engine adapters) now has a real scaffold - `docs/ADAPTERS.md` and
`tools/vendor-engines.sh` both exist - landed out of sequence, ahead of step 3's then-remaining
`nosql`/`ldap` packs and steps 5/6, because it cost nothing those blocked steps and ships no per-engine
logic.**
Tension 27's own "Implementation" paragraph carries the full detail, since that is where this register
keeps the mechanism's contract, the same pattern PARANOID-01's entry above uses; in short,
`docs/ADAPTERS.md` freezes the `modules/<module>/adapters/<engine>/adapter.sh` directory convention and
three-function contract, and `tools/vendor-engines.sh` is now a real script - the sole network-permitted
one - with a genuinely empty engine registry, exercised end-to-end by `tests/suites/vendor-engines.sh`
with `curl`/`wget` stripped from `PATH`. `lib/engines.sh`, `has_engine()`, and `--use-engines` remain
unbuilt on purpose (the first concrete adapter ticket builds them together with its own adapter); zero
adapter directories exist anywhere in the tree, and the full suite passes with none present.

**This ticket, the first concrete adapter ticket, has now landed and closes every one of those
deliberate gaps.**
`lib/engines.sh` is real: `has_engine MODULE ENGINE`, memoised per pair, answers a pure filesystem
question only - whether `modules/<module>/adapters/<engine>/adapter.sh` exists and its own
`<engine>_detect` returns 0 - and deliberately never reads `--use-engines` itself, per docs/ADAPTERS.md
§5's own "two independent conditions" pseudocode.  `--use-engines` is wired through `scan.sh` (global
flag, usage text, one `run_record use_engines <bool>` per run); `lib/checks.sh` gained no new filtering
logic, only a header paragraph stating why an adapter check id is invisible to its filter chain (it is
minted at runtime, never declared in a `*.rules` file).  `modules/sast/adapters/semgrep/adapter.sh`
implements the three-function contract against semgrep's own JSON output via a purpose-built,
depth/string-aware `awk` splitter plus bash-native field extractors (never a general JSON parser, the
same pragmatic choice `modules/sca/engine.sh`'s `_sca_json_walk` already made), re-derives match text
from the real file at the reported line when it still resolves, and rejects any reported path that does
not resolve inside the scan root as its own `coverage_reduction`, never trusting it as a finding
location.  `modules/sast/adapters/semgrep/vendor.sh` is the only other file permitted to touch the
network, and even it only calls `veng_fetch` (new, in `tools/vendor-engines.sh`), which verifies a
caller-supplied sha256 and refuses - never hardcodes or guesses one.  `VENG_REGISTRY` now carries one
entry, `[semgrep]=veng_vendor_semgrep`.  Absent or un-vendored is a clean `coverage_reduction
reason=engine_not_vendored engine=semgrep`; without `--use-engines` at all, behaviour is unchanged from
before this ticket.  `tests/suites/engines.sh`, `tests/suites/sast-semgrep.sh`, and an expanded
`tests/suites/vendor-engines.sh` (a stubbed-`curl` fetch/verify section) all exist and pass; zero real
engines are vendored anywhere in this repository, per `docs/ADAPTERS.md` §1 - the round-trip and
graceful-degradation suites exercise a FAKE stand-in binary, never a real semgrep.

**A second concrete adapter ticket has now landed, `modules/iac/adapters/trivy/` - the first for a
module other than sast, proving `docs/ADAPTERS.md` §4's directory-convention generalization for real.**
`lib/engines.sh`/`has_engine`/`--use-engines` needed no change at all: `has_engine iac trivy` and the
`modules/iac/run.sh` call site (`if [[ ${SCAN_FLAGS[use-engines]:-} == true ]] && has_engine iac trivy`)
are the exact same shape `modules/sast/run.sh` already established, which is the point of building that
plumbing module-agnostic the first time.  Picking `trivy config` over `docs/DESIGN.md` §6.6's other two
named candidates (`checkov`, `tfsec`) was this ticket's own reasoned call, not the operator's: only
`trivy config` natively scans every IaC shape the ticket's scope named (Terraform, CloudFormation,
Kubernetes, Helm, docker-compose) in one binary, where `tfsec` is Terraform-only and `checkov` is a
Python application rather than a single vendorable static binary.  `trivy_detect` needs only an
executable `bin/trivy` - no `rules/` - because trivy's misconfiguration checks are compiled into the
binary itself, `docs/ADAPTERS.md` §4's "self-contained binary" case; `trivy_run` passes
`--offline-scan --skip-check-update --skip-db-update --scanners misconfig`.  `trivy_normalize` walks a
JSON shape nested TWO levels deep (`Results[].Misconfigurations[]`, one array per scanned target file)
rather than semgrep's single flat array, via a generalized version of the same depth/string-aware `awk`
splitting technique (`_trivy_split_objects_from_marker`, parameterised by which marker/level it is
walking) rather than two independent copies.  Severity mapping deliberately widens onto scoursh's full
`critical` severity - unlike `_semgrep_severity_map`, which caps at `high` - because native
`modules/iac/*.rules` packs already author `severity: critical` directly (e.g.
`IAC-TF-PUBLIC_ACL-01`/`IAC-K8S-*`), so capping this adapter alone would be an invented inconsistency,
not a rule this codebase actually follows.  `VENG_REGISTRY` gained a second entry,
`[trivy]=veng_vendor_trivy`, needing three operator-supplied `SCOURSH_TRIVY_*` values (version, URL,
sha256 - one artifact, since there is no separate ruleset) rather than semgrep's five; its `vendor.sh`
states explicitly why it never extracts trivy's real `.tar.gz` release archive itself (the operator
supplies a URL to the already-extracted binary).  Merge/dedup against native findings (this ticket's own
scope item 3) needed no new code - the frozen pipeline's existing fingerprint-based merge/dedup (tension
11 stage 3, above) already covers it, since a `trivy:<AVD-ID>` check id never collides with a native
`IAC-TF-*`/`IAC-K8S-*`/... id - `tests/suites/iac-trivy.sh` proves this concretely with a fixture where a
native `IAC-TF-OPEN_CIDR-01` finding and a `trivy:AVD-AWS-0107` finding share the exact same file, line,
and re-derived match text, and still both appear as two distinct findings.  `tests/suites/iac-trivy.sh`
and an extended `tests/suites/vendor-engines.sh` (a `trivy_vendor` fetch/verify section) both exist and
pass; as with semgrep, zero real engines are vendored anywhere in this repository, and the round-trip and
graceful-degradation proofs run against a FAKE stand-in `trivy` binary.

**A third concrete adapter ticket has now landed on top of that plumbing: `modules/sast/adapters/gitleaks/`.**
It reuses `lib/engines.sh`'s `has_engine` and `--use-engines` unchanged - this ticket adds no new
plumbing of its own - and ships `gitleaks_detect`/`gitleaks_run`/`gitleaks_normalize`
(`modules/sast/adapters/gitleaks/adapter.sh`) plus `modules/sast/adapters/gitleaks/vendor.sh`, gated
INDEPENDENTLY of semgrep in `modules/sast/run.sh`'s own `--use-engines` block so neither adapter's
presence, absence, or failure affects the other's own `coverage_reduction` line.  `gitleaks_run` invokes
`detect --no-banner --no-git --exit-code 0 ...` (`docs/DESIGN.md` §6.4's own "gitleaks --no-banner",
`--no-git` because history scanning is `history.sh`'s own already-shipped job, `--exit-code 0` because
gitleaks' normal "leaks found" exit status is 1, not a crash); `gitleaks_normalize` parses gitleaks' own
BARE top-level JSON array (unlike semgrep's `{"results":[...]}` envelope) with the same
depth/string-aware `awk` splitter shape, started at the first `[` directly.  `tools/vendor-engines.sh`'s
`VENG_REGISTRY` now carries three entries (`semgrep`, `trivy`, `gitleaks`), and `docs/ADAPTERS.md` §9's
roster gains its third row.
This ticket's own additional scope item - deduplicating a gitleaks finding against a
`modules/sast/rules/secrets.rules` native finding at the same file and matched bytes, which the ordinary
per-run fingerprint dedup cannot do because `check_id` is itself hashed into the fingerprint - is
`_gitleaks_dup_of_native_secret`, which reads this run's own not-yet-merged shard via
`lib/findings.sh`'s public `finding_decode` (native pattern scan, then history, then engine adapters run
strictly in that order, single-worker, so the native secrets findings are already on disk by the time
this runs) and compares `(loc_path, loc_match_digest)`.  Getting that comparison to actually FIRE
required matching how `modules/sast/engine.sh` computes its own digest - from the exact regex-match
SUBSTRING (`scan_match_offsets`' own `text` field), never a whole re-read line - which is why
`_gitleaks_match_text` prefers gitleaks' own reported `Secret` field (then `Match`, then a re-derived
line, then `Description`) rather than copying the semgrep adapter's own whole-line-read preference:
semgrep has no distinct matched-substring field to prefer, so its adapter reads the line as its best
available surrogate, but gitleaks already reports the exact matched bytes directly, and preferring those
is what makes this adapter's digest land on the same value a native finding's own digest does at the
identical file+line.  A first draft that copied semgrep's whole-line-read pattern silently defeated the
dedup end to end; `tests/suites/sast-gitleaks.sh` section D (a real `scan.sh sast --use-engines`
subprocess against a FAKE vendored gitleaks reporting one true duplicate and one non-overlapping finding)
is the fixture that caught it and now pins the fix, alongside sections A-C mirroring
`tests/suites/sast-semgrep.sh`'s own three-function/graceful-degradation/round-trip shape, and an
expanded `tests/suites/vendor-engines.sh` (three sorted registry entries, `gitleaks_vendor`'s own
fetch/verify path).

What §13 step 1 deliberately did **not** build, so the boundary is not rediscovered: `scan.sh`, anything
under `modules/`, `lib/http.sh`, `lib/engines.sh`, `lib/awscli.sh`, SARIF, the compliance report, any
shipped rule pack, and `state/`.  Diff classification (tension 12) and baseline suppression (tension 11
steps 5 and 6) are step 7's; step 1 delivers the primitives they call - the merge, the fingerprint, the
`findings_mark_suppressed` annotation, and `classify_derived`, which is pure and is already tested
against tension 6's full case table.
That sentence describes step 1's own historical boundary and is unaffected by later steps: `scan.sh`
was step 1's placeholder and is now built by step 2 (above); `modules/sast/`, `modules/iac/` and
`modules/sca/` are now built by steps 3 and 4, the latter landed out of sequence (above), and the
generated block below is what says which of their packs and ecosystems are in; `lib/http.sh` landed
early, out of its normal step-5 sequence (tension 19), and step 5 as a whole now has a written
sub-ticket plan (`docs/STEP5-DAST-PLAN.md`, above) whose first ticket, DAST-01, is under way while
everything under `modules/dast/` is still unbuilt; `lib/engines.sh` also
landed early, out of its normal step-9 sequence, as part of this ticket (immediately above);
`lib/awscli.sh` landed early too, out of its normal step-6 sequence, as part of a credential-less pass
that advanced only what needed no AWS account (see "AWS module: what exists ahead of step 6" in
`AGENTS.md`), so the read-only chokepoint exists while `modules/cloud/aws/live/*.sh` and the rest of
step 6 do not; and SARIF, the compliance report, and `state/` remain unbuilt.

<!-- BEGIN GENERATED STATUS -->
<!--
  GENERATED by tools/gen-status.sh.  Everything between these two markers is
  machine-written from the repository tree and docs/DESIGN.md's own catalog.

  Do not hand-edit inside the markers: run `tools/gen-status.sh --write`.
  `tests/lint-status.sh` (run by `tests/run-tests.sh`) fails when a committed
  block differs from a fresh generation, so an edit here is a broken build.

  A MERGE CONFLICT INSIDE THIS BLOCK IS NEVER RESOLVED BY HAND.  Take either
  side of the conflict, then re-run `tools/gen-status.sh --write`.
-->

### Module status inventory (generated)

What is PLANNED is parsed from `docs/DESIGN.md`'s own catalog (§6.3 SAST, §6.5
SCA, §6.6 and §8.2 IaC).  What has LANDED is read off the repository tree.  What
REMAINS is the difference, computed rather than typed - which is why no sentence
in here has to be rewritten when a module lands, and why two branches landing
different modules cannot conflict over it.

**Landed** means both halves hold, and both are checked on every run:

1. the artifact exists at its path under `modules/`, and
2. the test tree exercises it - for a rule pack, at least one check id the pack
   itself declares appears in a `tests/**/*.sh` suite; for a script, its
   basename does; for an SCA ecosystem, every manifest `docs/DESIGN.md` §6.5
   names for it is parsed under `modules/sca/` and at least one has a real
   fixture file under `tests/fixtures/`.

A file that is present but that no suite names is **present, untested** - its own
state, never rounded up to landed.  Artifacts are identified by PATH and never by
a commit sha: a ticket cannot know its own landing sha, and invented ones have
shipped here before.

#### SAST - `docs/DESIGN.md` §6.3 catalog -> `modules/sast/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/sast/rules/crypto.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/go.rules` | landed | 5 | `tests/suites/sast.sh` |
| `modules/sast/rules/injection.rules` | landed | 8 | `tests/suites/sast.sh` |
| `modules/sast/rules/java.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/javascript.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/ldap.rules` | landed | 3 | `tests/suites/sast.sh` |
| `modules/sast/rules/nosql.rules` | landed | 4 | `tests/suites/sast.sh` |
| `modules/sast/rules/python.rules` | landed | 7 | `tests/suites/sast.sh` |
| `modules/sast/rules/secrets.rules` | landed | 7 | `tests/suites/records.sh` |
| `modules/sast/history.sh` | landed | - | `tests/suites/sast-history.sh` |

Landed 10 of 10.  Outstanding: none.

#### SCA ecosystems - `docs/DESIGN.md` §6.5 catalog -> `modules/sca/`

| Manifests | Status | Parsers | Exercised by |
| --- | --- | --- | --- |
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-ecosystems-php/package-lock.json` |
| `requirements.txt`, `poetry.lock`, `Pipfile.lock` | landed | 3 of 3 parsed | `tests/fixtures/sca/mixed-four-ecosystems/requirements.txt` |
| `go.mod`, `go.sum` | landed | 2 of 2 parsed | `tests/fixtures/sca/go-mod/go.mod` |
| `pom.xml`, `build.gradle` | landed | 2 of 2 parsed | `tests/fixtures/sca/maven/pom.xml` |
| `Gemfile.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/mixed-ecosystems/Gemfile.lock` |
| `composer.lock` | landed | 1 of 1 parsed | `tests/fixtures/sca/composer-no-manifest/composer.lock` |

Landed 6 of 6.  Outstanding: none.

#### IaC rule packs - `docs/DESIGN.md` §6.6 and §8.2 -> `modules/iac/`

| Artifact | Status | Checks | Exercised by |
| --- | --- | --- | --- |
| `modules/iac/cloudformation.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/docker-compose.rules` | landed | 4 | `tests/suites/iac.sh` |
| `modules/iac/dockerfile.rules` | landed | 6 | `tests/suites/iac.sh` |
| `modules/iac/helm.rules` | landed | 3 | `tests/suites/iac.sh` |
| `modules/iac/kubernetes.rules` | landed | 8 | `tests/suites/iac.sh` |
| `modules/iac/terraform.rules` | landed | 7 | `tests/suites/iac-trivy.sh` |

Landed 6 of 6.  Outstanding: none.

#### Totals

- Pattern packs on disk: **15** (`modules/sast/rules/` 9, `modules/iac/` 6).
- Module directories present: `modules/dast/`, `modules/iac/`, `modules/sast/`, `modules/sca/`.

<!-- END GENERATED STATUS -->

**Process note: this section must be updated in the same change that lands a §13 step, not in a later
cleanup ticket.**
Step 3e shipped without this section (or `AGENTS.md`'s mirror) being updated, so a later agent working
an unrelated doc-staleness ticket had to rediscover that `history.sh` existed by reading the branch
rather than the docs - precisely the failure this section exists to prevent. `AGENTS.md`'s "Build order
and where we are" carries the same rule; keep the two in sync.
The Terraform IaC ticket repeated the same lapse (see "Step 4's IaC half" above): it shipped
`modules/iac/run.sh`/`parse.sh`/`terraform.rules` without touching this section or its mirror, and a
later IaC landing closed the gap.
The npm SCA ticket (`ed8c283`) repeated the exact same failure - this section and `AGENTS.md`'s mirror
both still said "SCA half has not landed"/"`modules/sca/`... remain unbuilt" straight through its own
landing - and it went uncaught until the Ruby SCA ticket (`a2d37aa`) corrected both in this same change.
The Java (`a1b3c43`) and PHP/Composer (`7e7b186`) SCA tickets then did it a fourth and fifth time: both
landed - `modules/sca/php_engine.sh` and `SCA-PHP-VULNERABLE_DEP-01` among them - without touching
either doc's build-status section, so both documents went on calling Java and PHP "still open" until
`ab23b79` and this ticket went back and corrected them. Two separate tickets spent cleaning up after
one landing's missing paragraph is exactly the cost this note exists to avoid.
Five independent instances of one failure mode is a pattern, not a coincidence, and the separate
correction tickets that cleaned up after them are a sixth cost: the inventory half of this section is
therefore GENERATED.
`tools/gen-status.sh --write` rewrites the block above - and its byte-identical copies in `AGENTS.md`
and `README.md` - from the repository tree, and `tests/lint-status.sh` fails the suite when a committed
block differs from a fresh generation. So "does the build-order doc already say this landed?" is now
answered by running the generator rather than by reviewer memory, and a landing ticket can no longer
leave this section stale by forgetting.
What is left for a landing ticket to write by hand is the reasoning - scoping decisions, exclusions,
why a file sits where it does - which no generator can derive, and it is still part of that ticket's
own deliverable.
A merge conflict inside the generated block is never resolved by hand: take either side and re-run the
generator.
Filing a follow-up documentation ticket to fix this section later is not an acceptable substitute for
updating it in the step ticket itself - that pattern is what produced the java.rules staleness this
section itself once had (a doc-refresh ticket landed a commit after java.rules shipped and still
described it as not landed), and then produced the SCA-ecosystem staleness the paragraphs above are
corrected for. A step ticket is not done while this section describes that step as unbuilt.
