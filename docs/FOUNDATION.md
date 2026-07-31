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
`tests/lint-rules.sh` implements the error codes in `rules/RULE-FORMAT.md` §13 and runs in CI.
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
`rg --no-config --no-ignore --hidden --binary=false --engine default -n --no-heading --color never`,
with `--engine pcre2` added only for `pcre` records.
The `grep` fallback is `grep -E -n -r` with an explicit exclude list.
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
   subshell**.
   A `( ... )` or a `$( ... )` that exits runs the cleanup handler, which shreds the scratch directory
   while the run is still using it.
   With `set -E` the same inheritance applies to the `ERR` trap.
   Since §10 fans out with `xargs -P` into subprocesses that each exit, this fires constantly.

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
   scan_match() {                       # writes hits to $2; 0 = matched, 1 = no match
     local rc=0 out=$1; shift
     "${SCOURSH_GREP[@]}" "$@" >"$out" || rc=$?
     (( rc <= 1 )) || die 6 "pattern engine failed (rc=$rc): $*"
     return $rc
   }
   ```

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
5. **The `EXIT` cleanup trap is guarded so that only the process owning the scratch dir removes it.**

   > **This rule is WRONG as written and is open as finding F13.**
   > Do not implement the guard below; read the "Known follow-ups" section of this document first.
   > Bash resets trapped `EXIT` actions in subshells, so the hazard the guard defends against does not
   > occur, while an `xargs -P` worker is a fresh *process* where `$BASHPID == $$` is true, so the guard
   > passes and the first worker to finish shreds the shared scratch dir.
   > The direction is to guard on scratch-dir **ownership** (a recorded owner pid plus a created-here
   > marker) rather than on subshell-ness.

   ```
   cleanup() { [[ $BASHPID == $$ ]] || return 0; ... shred the scratch dir ... }
   trap cleanup EXIT
   ```

   The `ERR` trap reports `${BASH_SOURCE[0]}:${LINENO}` and `$BASH_COMMAND`, must contain no command
   that can itself fail, and re-raises the original status.

**Consequence for the build.**
This lands in §13 step 1, because every later module depends on it.
`tests/run-tests.sh` includes a negative test that a deliberately broken pattern makes the run abort
with a non-zero status rather than reporting zero findings, and a test that a subshell exit leaves the
scratch dir intact.
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
| Derived | correlation value only (see tension 6) |

Four of these need their normalisation frozen:

- **`match_digest`** = first 16 hex characters of `sha256(normalise(raw_matched_text))`, where
  `normalise` collapses every run of whitespace to a single space and strips leading and trailing
  whitespace.
  Reindenting or reformatting therefore does not churn identity; changing the code does, which is
  correct, because the matched text *is* the finding.
  The raw text is hashed, not the redacted text; see tension 9 for why, and for the rule that it never
  touches disk.
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
`FP_SCHEMA` is written into every `state/` file and every `config/baseline.json`; on a mismatch the diff
refuses to classify and marks every finding `unknown` rather than reporting a spurious mass
new-and-fixed (tension 12).
A test asserts fingerprint stability directly: it inserts blank lines and reindents a fixture, re-runs,
and requires the fingerprint set to be byte-identical.
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
It frequently does not: `derived` is a type tag in no `--intensity` tier (open finding F8), so
`scan.sh all --intensity active` drops every composite, and `--profile-scan quick` drops any composite
without a `quick` profile tag.
Without (a), `scan.sh all` followed by `scan.sh all --intensity active` would classify the flagship
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
  Such a check must be covered **in at least one cell**, and if its module was not selected at all it is
  not covered and the composite is `unknown`.
  This is the case where "the one that would have fired never ran" has to be distinguished from "none of
  them fired", and it is why (b) is stated over the record's `requires` and `any-of` lists rather than
  over the recorded contributor set alone.

`contributors` is still what supplies the cells in (b1), so the pairs there are looked up, never
inferred, and no mapping from a correlation value to a contributor's coverage cell has to be invented.

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
| 5 | **Composite record dropped by `--intensity active`; all contributors present and firing** | **`unknown`** | condition (a) omitted - the round-2 rule returns `fixed (chain broken)` |
| 6 | **`any-of: A, B`; run 1 only A fired; run 2 covers A, module owning B not selected** | **`unknown`** | condition (b2) omitted - contributor-pair-only returns `fixed` |
| 7 | **`SAST-HIST-*` contributor whose cell is covered but whose `oldest_reaching_commit_time` precedes this run's `oldest_commit_time`** | **`unknown`** | condition (b1)'s `fixed`-eligibility clause omitted - cell-only returns `fixed` |
| 8 | Prior composite finding with no `contributors` recorded | **`unknown`** | the "covered in at least one cell" fallback applied to this branch |

Cases 5, 6, 7, and 8 are new, and each is the only case in the set that discriminates its condition:
under the round-2 rule every one of them returns `fixed (chain broken)` while cases 1 to 4 still pass, so
the previous suite certified the defect green.
Case 5 additionally pins that `--profile-scan quick` reaches the same hole independently of open finding
F8.
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
   inside a `umask 077` and is shredded on exit, and `config/scanner.conf` gains
   `scratch_dir` so an operator can point it at a tmpfs.
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
   build's, and when its `scan_root_id` does not match this run's (tension 12).
   In every one of those cases the diff carries no information, so `status` is `unknown` for every
   finding rather than only for carried-forward ones.
6. **Suppress**: for each finding matching a baseline entry, set `suppressed: true` and
   `suppressed_by: <entry id>`.
   **Never delete.**
7. **Gate**: `--fail-on` considers only findings where `suppressed == false` and `confidence >=
   --min-confidence`.
   When `--fail-on-new` is given, it additionally requires `status == new` **if and only if
   `diff_usable` is true**; when `diff_usable` is false, `--fail-on-new` gates on **all** findings this
   run.
   The carve-out is not optional wording: with an unusable diff every finding's status is `unknown` and
   never `new`, so a bare `status == new` predicate would gate on nothing and a run that found fifty
   criticals after a tool upgrade would exit `0`.
   Unusable prior state and absent prior state are the same situation and get the same fail-closed
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
  "scan_root_kind": "git", "scan_root_id": "<root-commit-sha>",
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
- `scan_root_kind` and `scan_root_id` are present on every run and gate whether any cell is comparable at
  all.

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
scan_root        =  git rev-parse --show-toplevel     # run from resolved_path, if it is a directory
                    else resolved_path                # not a git repo, or git absent
scan_root_kind   =  "git" | "path"                    # which branch was taken
scan_root_id     =  kind "git"  -> the repository's root-commit sha:
                                   the lexicographically smallest of
                                   `git rev-list --max-parents=0 --all`
                    kind "path" -> resolved absolute scan_root
```

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
So cells are comparable **only between runs whose `scan_root_id` is equal**; when it differs, every prior
finding is `unknown` and no `fixed` is inferred.
That closes the two constructions this rule exists for:

- **Non-git target** (an unpacked tarball, ordinary usage since only `history.sh` needs git).
  `--path /srv/app` and `--path /srv/app/frontend` each become their own `scan_root`, so both would
  otherwise carry cell `.` and the narrower run would report every backend finding `fixed`.
  Their `scan_root_id` values are the two different absolute paths, so the cells are not comparable and
  the result is `unknown`.
- **Nested repository or submodule.**
  `--path /repo` and `--path /repo/vendor/libfoo` both resolve to a git toplevel, so both would otherwise
  carry cell `.`.
  Their root-commit shas differ, so again the cells are not comparable.

Within one `scan_root_id`, comparison is **exact string equality with no subsumption rule**.
`--path .` after `--path src` therefore leaves the earlier findings `unknown` rather than `fixed`, and
so does the reverse, even though one root contains the other.
That is deliberate: a subsumption rule would have to decide whether a wider root's coverage entitles it
to declare a narrower root's findings fixed, and getting that wrong is phantom remediation.
Failing to `unknown` in both directions is the conservative reading, and it is the one frozen here.

`scan_root_kind` and `scan_root_id` are recorded in `state/` alongside `fp_schema`, and a mismatch is
handled exactly like an `fp_schema` mismatch below: the diff is unusable, every finding is `unknown`, and
the gate falls back to fail-closed.

**One consequence, stated so it is not discovered later.**
Because `location.path` is scan-root-relative and is a fingerprint input (tension 5), a **git** target's
fingerprints are stable no matter which `--path` subtree a run scans, since `scan_root` is the toplevel
either way.
A **non-git** target's are not: there `scan_root` is the resolved `--path`, so `--path /srv/app` and
`--path /srv/app/frontend` record different relative paths for the same file and therefore different
fingerprints.
That is correct rather than a defect, and it is safe: those two runs also have different `scan_root_id`
values, so their diffs are not comparable at all and every finding is `unknown` rather than `new` or
`fixed`.
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
  checks that did not fire by being covered in at least one cell - and **(c)** the predicate no longer
  holds.
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

- **`fp_schema` or `scan_root_id` mismatch** between `state/latest.json` and this run makes the whole
  diff `unknown` rather than reporting a mass new-and-fixed.
  The report says which changed and that a baseline rebuild is required.
  Both set **`diff_usable = false`** (tension 11 step 5), and that flag - not the `unknown` status - is
  what the gate reads.
  **The condition is fail-closed at the gate**: because it marks *this run's* present findings `unknown`
  and not merely carried-forward priors, letting `unknown` starve the gate would turn a tool upgrade that
  bumps `fp/1` to `fp/2` into a run that finds fifty criticals and exits `0`.
  So `--fail-on-new` gates on **all** findings, exactly as with no prior state.
  This is stated identically in tension 11 step 7 (which owns the gate predicate) and tension 14 (which
  owns exit codes); a rule that lived only here would be contradicted by both.
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
| An unusable diff: `fp_schema` or `scan_root_id` mismatch (tension 12) | neither; see below | none, **but the gate goes fail-closed** |
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
  ever run or `state/` cleared), an `fp_schema` mismatch, and a `scan_root_id` mismatch.
  In every one of these `--fail-on-new` gates on **all** findings, and the report says so.
  Failing open would let the very first CI run pass silently with a full backlog, and teams calibrate on
  that first green build; the `fp_schema` case is worse still, because a tool upgrade would turn fifty
  criticals into a green build with no operator action at all.
  The intended workflow after a first red build is to baseline (tension 11), which is explicit and
  reviewable, rather than to inherit an invisible amnesty.
  Unusable prior state and absent prior state are the same situation and get the same answer.
- **Findings classified `unknown` while the diff is usable** (tension 12): excluded from the gate, since
  nothing was learned about them.
  The qualifier matters - under an unusable diff *every* finding is `unknown`, and the bullet above
  governs instead, so this exclusion must never be read as unconditional.
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
| `sast`, `sca`, `iac` | a readable `--path`, which is optional and **defaults to `.`** (tension 12), so exit `4` means the resolved path is absent or unreadable, not that the flag was omitted. **No `scope.conf`.** |
| `dast` | `config/scope.conf` with a matching `--target`; `config/auth.conf` additionally when `--authed` |
| `cloud --live` | resolvable AWS credentials; `config/scope.conf` is not required, since AWS endpoints are allowed by §2 independently |
| `posture` | `config/posture.conf` |
| `all` | whatever each selected module requires; a module whose inputs are absent is **skipped with a `run.json` reason**, not an error, which is what §5's "run every module for which inputs are configured" already says |

A missing `scope.conf` is exit `4` only for `dast`.
This preserves the §7 gate exactly (a `dast` run still cannot proceed without it, and there is still no
raw-URL bypass) while removing the incentive to write a dummy entry.

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
| **the same after a `scan_root_id` change with no `fp_schema` change** | **`1`** | treating only `fp_schema` as making a diff unusable |

The third row is the one no earlier test touched: tension 14's matrix had no `fp_schema` axis, and
tensions 5, 11 and 12's tests are about fingerprints, baseline ordering, and coverage respectively, so
the fail-open shipped green under every prescribed test in the register.

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
2. **`--profile-scan`** filters by profile tag: `quick` keeps checks tagged `quick`; `full` keeps
   everything; `compliance` keeps checks with a non-empty `cis` **or** `owasp` field.
   `compliance` is thus computable from the record, with no separate list to drift.
3. **`--intensity`** applies a type-tag ceiling: `passive` keeps `passive`, `config-read`, `posture`,
   and `static`; `safe` additionally keeps `safe-active`; `active` additionally keeps `active`.
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
§13 step 2 delivers the filter chain and the registry loader.
The §7.4 enumeration-via-response checks and the §8.3 live user-enumeration probe are the seed
`intrusive` checks, which makes §14's "side-effecting checks are off unless `--allow-intrusive`"
enforced by the selection chain rather than by each script remembering to check a variable.
A test asserts that `--profile-scan quick --intensity active` selects zero `active` checks.

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
  local d="$SCOURSH_SCRATCH/mx/$1.lock" waited=0
  until mkdir "$d" 2>/dev/null; do
    if lock_is_stale "$d"; then rm -rf "$d"; continue; fi
    sleep 0.05; waited=$((waited+1))
    (( waited < MUTEX_TIMEOUT_TICKS )) || die 6 "mutex timeout: $1"
  done
  printf '%s %s\n' "$BASHPID" "$(now_epoch)" > "$d/owner"
}
```

`lock_is_stale` treats a lock as reclaimable when its `owner` pid is no longer alive **and** it is older
than `lock_stale_seconds` (default 30), so a `SIGKILL`ed worker cannot wedge the run.

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
Each worker writes only to `$SCRATCH/findings/<worker-id>.jsonl`, which it owns exclusively.
No locking is needed, because there is no sharing.
The worker id is `$BASHPID` plus the work-unit index, so it is unique even if a pid is recycled.

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
The shard directory is retained under `reports/<run>/shards/` when `--keep-shards` is given, for
debugging a partial run.

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

Each worker appends `{"unit_key":…, "state":"started"|"done"|"failed", "ts":…}` to its own shard of
`reports/<run>/units.jsonl`, using the same per-worker shard mechanism as tension 17, so the journal
needs no locking either.
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

**Consequence for the build.**
`lib/http.sh` at §13 step 5 owns the tuple set, the resolution cache, the deny list, and the manual
redirect loop.
`config/scope.conf` moves to the block-record format (tension 26), which is what lets `notes` be free
text and `extra-host` be repeatable.
Tests cover each bypass in turn: a different port, a subdomain, a redirect to an out-of-scope host, a
hostname resolving to `169.254.169.254`, and an `http://` probe of an `https://` target.

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
3. *Route every call through a wrapper, allowlist by operation prefix, enforce at runtime and in CI.*
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
| `sha256_of` | `sha256sum`, else `shasum -a 256`, else `openssl dgst -sha256`; **reads stdin only** (tension 9), output normalised to bare lowercase hex with any trailing filename stripped |
| `now_iso` | `date -u +%Y-%m-%dT%H:%M:%SZ`, which is portable, rather than `-Iseconds` |
| `now_epoch_ns` | `date +%s%N` where supported, else `%s` scaled, with the resolution recorded so the rate limiter's arithmetic is correct either way |
| `msleep` | `sleep 0.05` when fractional sleep works, else `read -t 0.05 </dev/null` (a bash builtin, so no process), else a 1-second floor with a startup warning |
| `stat_mode` | `stat -c %a`, else `stat -f %Lp` |
| `realpath_of` | `readlink -f`, else `cd`-and-`pwd -P` in a subshell |
| `sed_inplace` | `sed -i.bak` plus removal, which is the one form both accept |
| `tmpdir_make` | `mktemp -d "${TMPDIR:-/tmp}/scoursh.XXXXXXXX"`, which is the portable form |

`require_cmd` runs once at startup and reports **every** missing command at once rather than failing on
the first, since discovering four missing dependencies one run at a time is a bad first experience for an
air-gapped install.
Required: `bash`, `grep`, `sed`, `awk`, `sort`, `tr`, `cut`, `find`, `xargs`, `mktemp`, `date`, `curl`,
one of the SHA-256 providers, and `git` for `history.sh` only.
Optional and probed: `rg`, `rg` with PCRE2 (tension 2), `openssl` (for `tls.sh`), `aws`, GNU `parallel`,
`ss` or `strace` (tension 20).
Everything probed is recorded in `run.json`, so a report always states what the host could and could not
do.

`xargs -P` is used without `-r`, which BSD lacks, by never invoking `xargs` on a possibly-empty input:
the caller checks the unit count first.
**Version-aware sorting is not needed at all**, because tension 25 removes range arithmetic from the
scanner entirely.

**Consequence for the build.**
This is the first thing built in §13 step 1, ahead of everything else, since every later line depends on
it.
CI runs the full suite on Linux with GNU coreutils **and** on macOS with BSD userland, and the suite
fails if a finding, a fingerprint, or a `findings.jsonl` byte differs between them, which is what turns
this from a list of good intentions into a checked property.

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
`config/*.example` files ship in the frozen format, and the linter runs over them in CI so the examples
cannot drift from the schema.
`auth.conf` keeps its `600` permission requirement from §7.0, checked via `stat_mode` (tension 24), and
its values are marked secret at the schema level so `redact` (tension 9) covers them everywhere.

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
   Cells are comparable only between runs with equal `scan_root_id`.
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
8. **CI runs the suite on both GNU and BSD userlands** (tension 24) and asserts byte-identical findings,
   which is the check that keeps most of the resolutions above honest.

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

The twelve below remain **open**, deliberately deferred, and are recorded with their finding numbers so
the next task inherits them rather than rediscovering them.
Each names the tension it lands in and the build step it must land before.
None is a matter of taste; each has a defect and a direction, and the direction is not yet frozen.

### Must land before `lib/core.sh` and the parallel path are written (§13 step 1)

- **F13 [high] - the EXIT-trap subshell guard defends a case bash never produces and passes the case it
  does** (tension 4, rule 5).
  Bash resets trapped EXIT actions in subshells, so the stated hazard does not occur, while an
  `xargs -P` worker is a fresh process where `$BASHPID == $$` is true and the guard passes.
  The first worker to finish would shred the shared scratch dir holding the rate limiter, budget,
  breaker state, finding shards, and units journal, and the prescribed test is vacuous.
  Direction: guard on scratch-dir ownership (a recorded owner pid plus a created-here marker), not on
  subshell-ness, and replace the test with one that runs N workers under `xargs -P`.
  **This wrong claim is also frozen into `AGENTS.md`** under "Sharp edges"; correct both together.
- **F14 [high] - the `msleep` fallback does not sleep** (tension 24 capability table, consumed by
  tension 16's `mutex_acquire`).
  `read -t 0.05 </dev/null` returns at EOF immediately, so the mutex retry loop becomes a spin that
  exhausts its timeout in under a millisecond, and a probe based on exit status cannot detect it because
  `read` returns non-zero for both EOF and timeout.
  Direction: read from a descriptor that never yields data rather than one already at EOF, and probe by
  measuring elapsed time.
  Tension 16's code sample also calls `sleep 0.05` literally instead of the frozen wrapper.
- **F12 [high] - resume reads shards that the scratch-dir cleanup destroys** (tension 18 against
  tension 17 and tension 4).
  Finding shards and the unit journal live in `$SCRATCH`, are retained only under `--keep-shards`, and
  the EXIT trap shreds `$SCRATCH` on the signal tension 18's own resume test uses.
  Direction: write both unconditionally into the run directory and redefine `--keep-shards` as "do not
  delete after a successful merge", leaving the scratch dir for genuinely transient data.
- **F15 [medium] - the mkdir mutex stale-reclaim path can delete a live lock, and `lock_is_stale` is
  asserted rather than specified** (tension 16).
  Two waiters can both judge a lock stale, and the second deletes the first's freshly acquired lock.
  Separately the routine needs a liveness primitive, an mtime accessor that tension 24's capability layer
  does not provide (`stat_mtime`), a `now_epoch` that is not among the frozen functions, and a policy
  for the window in which a lock dir exists with no owner file.
  Direction: make reclaim single-winner via an atomic rename rather than `rm -rf`, publish the owner
  before publishing the lock, and add the missing capability functions.
- **F16 [medium] - `shred` is GNU-only, sits inside the mandated EXIT cleanup, and is absent from the
  capability layer** (tension 24 against tension 4 rule 5 and tension 9).
  On a host without it the trap fails and, under `set -Eeuo pipefail`, the process exits 127, outside
  the frozen 0-5 contract, leaving the scratch dir behind on exactly the platform the CI matrix
  mandates.
  Overwrite-based erasure is also ineffective on modern filesystems, so the honest control is
  `scratch_dir` on tmpfs.
  The same omission applies to `look` (tension 25), which is absent from several minimal images and is
  neither probed nor recorded, and whose stated `grep -F` fallback is O(n) per lookup against a
  millions-of-rows table that the tension justifies on O(log n) grounds.

### Cheap corrections, safe to defer

- **F4 [medium] - §12.2's `context-deny` rewrite suppresses true positives**
  (`rules/RULE-FORMAT.md` §12.2, blessed as the general recipe by §8.3 and tension 2).
  With `context-window: 2`, a correct safe-loader call within two lines of a genuine vulnerable call
  suppresses the finding, and tension 12 then classifies the suppressed finding `fixed`.
  §12.1 already states the correct discipline (`context-window: 0` for a same-line guard) and §12.2
  abandons it, so the two frozen examples give contradictory precedents for the identical hazard.
  Direction: freeze that a same-line-intent deny must carry `context-window: 0`, fix §12.2, add a linter
  warning for a deny on a rule with a window above 0, and state in §10.2 that widening a deny window
  trades false positives for silent false negatives rather than being monotonically safe.
- **F3 [medium] - the `tags` vocabulary is not closed, so `E044` is unimplementable and a typo silently
  disables** (`rules/RULE-FORMAT.md` §9.1.3 and §13 against tension 15).
  `tags: quik` lints clean and silently removes a rule from the `quick` profile, which is the exact
  failure mode `E017` exists to prevent for keys.
  `compliance` also has two incompatible definitions - tag-based in §9.1.3, derived from a non-empty
  `cis` or `owasp` in tension 15 - and since `owasp` is required on every pattern rule the derived form
  selects the entire catalog.
  Direction: declare the closed vocabulary normatively, add an error code for a tag outside it, and pick
  one definition of `compliance`.
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
- **F18 [medium] - `die 6` appears in two normative code samples and in no exit-code table**
  (tensions 4 and 16 against tension 14 and `docs/DESIGN.md` §5).
  Both conditions - a pattern-engine failure and a mutex timeout - are what tension 14 already calls an
  incomplete run, so `5` is the natural fit, and `6` would reach CI unclassifiable.
  Direction: change both samples to `die 5` and have it write `incomplete_reason`.
  While in tension 4, also fix the `scan_match` comment, which says "writes hits to `$2`" while the body
  takes the output path as `$1`.
- **F8 [low] - the `derived` type tag falls outside every `--intensity` tier** (tension 15 step 3, and
  `rules/RULE-FORMAT.md` §9.1.3 against §9.2).
  Under an intersection filter where nothing can be re-enabled, any run carrying `--intensity` drops
  every composite.
  The consequence is that composites are silently absent from those runs, not that they are wrongly
  classified: a composite has no `covered_checks` entry to lose, and tension 6 condition (a) makes an
  unselected composite `unknown`.
  (The earlier rationale here said "a dropped check never enters `covered_checks`, so its prior findings
  are `unknown` forever", which was the *ordinary*-check mechanism and stopped applying to composites
  once they lost their cell; the outcome is the same but it now comes from condition (a), and this entry
  no longer contradicts tension 6.)
  Direction: state that `derived` checks are exempt from the intensity ceiling, since they consume
  findings rather than issue requests, and add `derived` to §9.1.3's enumeration so `E044` and the
  schema agree.
- **F17 [low] - `aws_ro` pins `--no-cli-pager`, which AWS CLI v1 rejects** (tension 23, item 5).
  The flag is v2-only, and tension 24 probes for `aws` by presence rather than by major version, so on a
  v1 host every AWS call fails at argument parsing and the entire cloud module produces zero findings
  while reporting a tool error.
  Direction: set `AWS_PAGER=` in the call's environment instead, which both major versions honour and
  which needs no version detection, and record the detected major version in `run.json` either way.

## Where the build currently stands

Nothing in `docs/DESIGN.md` §13 has been implemented.
This foundation freezes the record format (`rules/RULE-FORMAT.md`) and resolves the tensions above so
that §13 step 1 can begin without re-litigating any of them, subject to the open follow-ups listed
immediately above, five of which must be settled before `lib/core.sh` and the parallel path are
written.
