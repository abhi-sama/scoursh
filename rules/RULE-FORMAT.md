# scoursh record format - FROZEN

> **This format is FROZEN.**
> `lib/records.sh`, every `.rules` pack, every human-authored config file in `config/`, the rule linter,
> the SAST/IaC engines, `lib/findings.sh`, and the derived-finding evaluator all depend on it.
> Changing the syntax in this document is a **breaking change**: it invalidates every rule pack on disk,
> every operator config, and (through the fingerprint inputs in `docs/FOUNDATION.md` tension 5) every
> entry in `state/` and `config/baseline.json`.
> A change requires a `format_version` bump (§2), a migration for `state/`, and a coordinated update of
> every pack in the repo.

This document is normative and self-contained.
A parser and a linter can both be written from this document alone, with no reference to any other file.

Companion documents:

- `docs/DESIGN.md` - what scoursh is, and §6.3 the rule catalog these records encode.
- `docs/FOUNDATION.md` - the design-tension register; tension 1 is why this format exists, tension 2 is
  the regex dialect, tension 3 is the `context` directive, tension 26 is why config files share this
  syntax.

---

## 1. Why this format and not the pipe-delimited one

`docs/DESIGN.md` §6.2 originally showed a pipe-delimited record:

```
PY-EVAL-01 | critical | CWE-95 | A03 | \beval\s*\( | eval() on untrusted input
```

The fifth field is a regex.
Alternation is the single most common construct in the §6.3 catalog: AWS key prefixes, weak-hash names,
dangerous sink names, and framework fingerprints are all alternations.
Every one of them contains `|`, which is also the field separator, so the split silently produces the
wrong number of fields and either drops the rule or truncates the regex into something that still
compiles and matches the wrong thing.
There is no escape mechanism that survives, because the escape character would then need escaping inside
the regex too, and regexes are already dense with backslashes.

The fix is to stop delimiting fields with a character that regexes use.
This format delimits fields with **line boundaries** and separates the key from the value with the first
`": "` on the line.
Regexes are stored byte-exact with **no escaping at all**, because no byte inside a value is meaningful
to the record syntax.

## 2. Terms and versioning

- **Record** - one logical entity (one rule, one scope target, one derived finding).
- **Field** - one `key: value` pair inside a record.
- **Record file** - a UTF-8 text file containing zero or more records.
- **Schema** - the set of keys legal for a given record file, listed in §9.
  The *syntax* in §3 to §7 is frozen and identical for every schema; only the key sets differ.
- **format_version** - `1`.
  A record file MAY declare `format-version: 1` as a field of its first record; a parser MUST reject any
  value other than `1`.

**Reference convention.**
A bare `§N` is a section of **this** document.
A section of another document is always written with its path, as in `docs/DESIGN.md` §6.2.
The two numbering spaces do not collide anywhere: this document has no subsections under §6, so `§6.2`
and `§6.3` unambiguously belong to `docs/DESIGN.md`, and they are the two most frequently cited.

## 3. Lexical syntax

### 3.1 File-level requirements

1. Encoding MUST be UTF-8.
   A parser MUST reject a file containing a byte sequence that is not valid UTF-8.
2. Line terminator MUST be LF (`0x0A`).
   A parser MUST reject a file containing CR (`0x0D`).
   This is not pedantry: a CRLF file would place a literal `\r` at the end of every `pattern` value, and
   the resulting regex would silently fail to match anything at end of line.
3. A byte-order mark MUST be rejected.
4. NUL (`0x00`) MUST be rejected anywhere in the file.
5. The file SHOULD end with a final LF.
   A parser MUST accept a final line with no terminator and MUST treat it as a complete line.
6. The file extension is `.rules` for rule packs and `.conf` for operator config.
   The extension carries no semantics; the schema is determined by the path, per §9.

### 3.2 Line classification

This is **the** normative definition of line kind.
§6 and §7 restate it and MUST NOT be read as varying it.

Every line is classified by applying these tests **in this exact order** and stopping at the first that
holds; row 7 is the fallback, not a test.
The order is part of the definition: several tests overlap, and a different order accepts different
files.

| # | Kind | Test (on the line's bytes, excluding its terminator) | Meaning |
|---|---|---|---|
| 1 | **Blank** | the line is **zero bytes** long | Record separator (§4) |
| 2 | **Invalid** `E011` | the line is non-empty and **every** byte is `0x20` or `0x09` | Whitespace-only line |
| 3 | **Invalid** `E021` | the first byte is `0x09` | Leading TAB |
| 4 | **Comment** | the first byte is `#` (`0x23`) | Never part of a value; does not end the record (§3.3) |
| 5 | **Continuation** | the **first two bytes are `0x20 0x20`** | Appends to the previous field (§6) |
| 6 | **Field** | the line matches `^[a-z][a-z0-9-]*: .` | A `key: value` pair (§5) |
| 7 | **Invalid** | anything else | Parse error, `E010` or `E013` per §7 |

Four consequences follow from the order, and all four are intended.

- **A whitespace-only line is never a Blank and never a Continuation.**
  Test 2 precedes test 5, so a line of exactly two spaces is `E011`, not a Continuation with an empty
  payload.
  This is the point of the whole rule: a "blank" line carrying an invisible trailing space must never
  silently fail to separate two records, and a stray two-space line inside a record must never silently
  append an empty line to a prose value.
  Both are the invisible-byte bug this format exists to eliminate, and both are now loud.
- **A line with more than two leading spaces is a Continuation**, because test 5 asks only about the
  first two bytes.
  `····x` (four spaces, then `x`) is a Continuation whose payload is `··x` (§6 rule 1).
  Test 2 has already excluded the case where there is nothing but whitespace.
- **A line with exactly one leading space followed by content is `E010`**, since it fails tests 1 to 6.
  This is the off-by-one indentation typo, and it is an error rather than a silent misparse.
  A line consisting of a single space and nothing else is `E011` instead, by test 2; both abort the
  parse, so the difference is only which code a linter fixture expects.
- **A TAB is legal inside a value and illegal as leading indentation** (test 3).
  A line that is only TABs is `E011` (test 2 runs first); a line that is a TAB followed by content is
  `E021`.

`E011` and `E021` are reported with the byte offset of the offending whitespace.
Worked negative examples for each of these cases are in §12.6.

### 3.3 Comments

A comment is a whole line whose first byte is `#`.
There is no end-of-line comment syntax and no way to start a comment mid-line.
Consequently a `#` inside a value is a literal `#` and needs no escaping, which matters because several
§6.3 rules match comment markers (`# nosec`, `// eslint-disable`).

A comment line may appear:

- before the first record,
- between records,
- between two field lines of the same record.

A comment line MUST NOT appear between a field line and its continuation lines (§6); that is `E012`.

A comment line does **not** separate records: the record continues after it.
It does, however, **end the current field's continuation eligibility**, which is what makes `E012`
detectable in a single forward pass with no lookahead.
So a comment between two field lines is fine, and a comment followed by a continuation line is `E012`.

## 4. Records

A record is a maximal run of Field lines (with their Continuation lines, and any interleaved Comment
lines) bounded by Blank lines, the start of file, or the end of file.

- Two or more consecutive Blank lines are equivalent to one.
- Leading and trailing Blank lines in a file are ignored.
- A record MUST contain at least one Field line.
- **The first Field line of a record MUST be the record's identity key** (`id` for every schema in §9).
  This is required so that the parser and linter can name a record in every diagnostic, including
  diagnostics raised on later lines of that same record.
  A record whose first field is not `id` is `E020`.

## 5. Fields

### 5.1 Key

A key matches `^[a-z][a-z0-9-]*$`.
Lowercase ASCII letters, digits, and hyphen only; it must start with a letter.
Keys are case-sensitive; `Id` is not `id` and is Invalid because of the leading uppercase.

### 5.2 Separator

The separator is exactly one colon followed by exactly one space: `": "` (`0x3A 0x20`).
The **first** occurrence of `": "` on the line separates key from value.
Any later `": "` is part of the value.

Consequences, all intended:

- A value may contain `:` freely (`pattern: __proto__\s*:` is fine).
- A value may contain `: ` freely.
- A value may contain `|`, `#`, `"`, `'`, `\`, `$`, backtick, `{`, `}`, and every other byte except LF
  and NUL.

### 5.3 Value

The value is the byte sequence from immediately after the separator to immediately before the line
terminator.

- **No trimming.** Leading and trailing spaces are part of the value.
- **No unquoting.** A value that starts and ends with `"` has those quotes as data.
- **No escape processing.** `\n` in a value is backslash followed by `n`, which is what a regex author
  means when they type it.
  There is no way to express a literal LF inside a single-line value; use continuations (§6) where the
  schema allows them.
- **No variable expansion.** `$HOME` is four literal bytes.
  Record files are **data**; see §11.
- **Empty values are illegal.** The Field pattern in §3.2 requires at least one byte after the
  separator, so `id:` and `id: ` are both Invalid (`E013`).
  A schema that needs "unset" uses the literal token `none`, never an empty value.

Because there is no trimming, a value can legally end in a space, and a space is invisible.
For the `pattern` key and the `context-require` / `context-deny` keys, a trailing space is therefore a
**linter error** (`E030`), and the author is directed to write `[ ]` or `\s` instead.
The parser still accepts it; only the linter rejects it, so a hand-edited pack that trips `E030` fails
CI rather than silently misbehaving in production.

### 5.4 Repetition

Each key in §9 is marked *single* or *repeatable*.

- A *single* key appearing twice in one record is `E014`.
- A *repeatable* key accumulates in **file order**, and order is significant only where §9 says so.

## 6. Multi-line values (continuations)

A Continuation line is one classified as such by §3.2: its **first two bytes are `0x20 0x20`**, and it
was not already claimed by an earlier test in that ordered list (in particular it is not
whitespace-only, which is `E011`).
§3.2 is the definition; this section only says what a Continuation *does*.

The two leading spaces are stripped; everything after them, byte-exact, is appended to the value of the
most recent Field line, preceded by one LF.

```
remediation: Do not pass request-derived data to eval().
  Parse literals with ast.literal_eval(), or dispatch through an explicit
  allowlist of permitted operations.
```

yields the value:

```
Do not pass request-derived data to eval().
Parse literals with ast.literal_eval(), or dispatch through an explicit
allowlist of permitted operations.
```

Rules:

1. Any indentation beyond the first two spaces is preserved.
   `····x` (four spaces) continues the value with `··x`.
2. A Continuation line with no preceding Field line in the current record is `E015`.
3. A Blank line ends the record even if the author intended the value to continue.
   There is exactly one record separator and it always wins.
   A value therefore cannot contain a blank line; use a single LF between paragraphs, or two records.
   A **whitespace-only** line does not continue a value either: it is `E011` per §3.2 test 2, so a
   continuation block cannot contain an empty line by any spelling.
4. Continuations are permitted **only** on keys marked *multi-line* in §9.
   In particular `pattern`, `context-require`, and `context-deny` are **single-line only** (`E016`).
   Regexes never span lines.
   This makes the format free of any block-scalar sentinel, so there is no ambiguity between a value of
   `|` and a "here follows a block" marker - a problem the obvious YAML-shaped design would have had,
   given that `|` is exactly the character regexes are full of.

## 7. Reference parse algorithm

Non-normative, but a conforming parser produces the same result.
The branch order below is exactly §3.2's test order, and is not an implementation choice.

```
records = []
cur = null          # {order: [], fields: {}, line: N}
last_key = null

for (lineno, raw) in lines(file):          # after the §3.1 file checks
    # --- §3.2 test 1: Blank
    if raw == "":
        if cur: records.append(cur); cur = null
        last_key = null
        continue
    # --- §3.2 test 2: whitespace-only. MUST precede the Continuation test.
    if every byte of raw is 0x20 or 0x09:  error E011
    # --- §3.2 test 3: leading TAB (with content, since test 2 already ran)
    if raw[0] == "\t":                     error E021
    # --- §3.2 test 4: Comment. Record continues; current field does not.
    if raw[0] == "#":
        last_key = null
        continue
    # --- §3.2 test 5: Continuation (first two bytes are 0x20 0x20)
    if raw[0] == " " and raw[1] == " ":
        if cur == null:      error E015    # no record open
        if last_key == null: error E012    # a comment intervened
        if last_key not multi-line in schema: error E016
        cur.fields[last_key][-1] += "\n" + raw[2:]
        continue
    # --- §3.2 test 6: Field
    m = match ^([a-z][a-z0-9-]*): (.+)$ against raw
    if not m:                              # --- §3.2 test 7: Invalid
        if raw matches ^[a-z][a-z0-9-]*:[ ]*$:       error E013   # empty value
        error E010                                                # incl. one leading space
    key, value = m[1], m[2]
    if cur == null:
        if key != "id": error E020
        cur = new record at lineno
    if key is single and key in cur.fields: error E014
    cur.fields[key].append(value)
    last_key = key

if cur: records.append(cur)
```

The parser's contract:

- It reports **every** syntax error with file, line, column, and code, then exits non-zero.
  It never repairs, never skips a bad record silently, and never partially loads a pack.
  A rule engine that silently drops a malformed rule reports "no findings" for a check that never ran,
  which is the worst possible failure mode for a security scanner.
- It returns records in file order, and files in `LC_ALL=C` sorted path order, so a run is reproducible.

## 8. Regex values

See `docs/FOUNDATION.md` tension 2 for the full reasoning; the normative rules are here.

### 8.1 Dialect

A `pattern`, `context-require`, or `context-deny` value is a regular expression in one of exactly two
declared dialects:

| `dialect` value | Meaning | Engine |
|---|---|---|
| `ere` | POSIX Extended Regular Expressions, as accepted by both `grep -E` and `rg`'s default syntax when restricted to the portable subset in §8.2 | always available |
| `pcre` | PCRE2 | requires `rg -P` built with PCRE2, or GNU `grep -P` |

`dialect` is *single*, optional, and defaults to `ere`.
It is declared **per record**, not per file, so one pack can mix both.

### 8.2 The portable ERE subset

An `ere` pattern MUST restrict itself to constructs that behave identically in `grep -E` and in `rg`:

- Literals, `.`, `[...]`, `[^...]`, `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`, `|`, `(...)`, `^`, `$`.
- The escapes `\.`, `\\`, `\[`, `\]`, `\(`, `\)`, `\{`, `\}`, `\|`, `\*`, `\+`, `\?`, `\^`, `\$`, `\/`.
- The GNU/rg-common word and class shorthands `\b`, `\B`, `\w`, `\W`, `\s`, `\S`, `\d`, `\D`.
- POSIX bracket classes `[:alpha:]`, `[:digit:]`, `[:alnum:]`, `[:space:]`, `[:upper:]`, `[:lower:]`,
  `[:xdigit:]`, `[:punct:]`.

An `ere` pattern MUST NOT use: lookahead or lookbehind (`(?=`, `(?!`, `(?<=`, `(?<!`), non-capturing
groups (`(?:`), named groups, backreferences (`\1`), lazy quantifiers (`*?`, `+?`), inline flags
(`(?i)`), `\A`, `\z`, `\Z`, `\K`, atomic groups, or possessive quantifiers.
The linter rejects each of these by construct (`E040`), naming the construct and the column.

Matching is **case-sensitive** and **line-oriented**: the engine evaluates the pattern against one line
at a time, so `^` and `$` anchor to line boundaries and a pattern can never match across a newline.
Case-insensitivity is expressed in the pattern (`[Mm][Dd]5`), never as a flag, so the same bytes mean
the same thing in both engines.

### 8.3 `pcre` records degrade, they do not fail

A `pcre` record is skipped when no PCRE2-capable engine is present.
When that happens the engine MUST:

1. Not emit findings for that check.
2. Record the check in `run.json` under `skipped_checks` with reason `pcre-unavailable`.
3. Exclude the check from `covered_checks` in `state/`, so the run-to-run diff reports its prior
   findings as `unknown` rather than manufacturing a wave of `fixed`
   (`docs/FOUNDATION.md` tension 12).

Because a skipped check is a silent coverage hole, `pcre` is a last resort.
Most patterns that reach for a lookahead are better written as an `ere` `pattern` plus a
`context-deny` (§10); the worked example `PY-YAML-LOAD-01` in §12.2 shows exactly that rewrite of the
§6.2 lookahead.

### 8.4 Complexity

A pattern MUST NOT contain nested unbounded quantification, that is a `*` or `+` applied to a group
that itself contains an unbounded quantifier, such as `(a+)+` or `(\s*\w*)*`.
This is the catastrophic-backtracking shape, and a scanner that hangs on a hostile source file is a
denial of service against its own operator.
The linter reports it as `E041`.

Unbounded quantifiers applied to a single character class are fine (`\s*`, `[A-Za-z0-9]+`).

## 9. Schemas

The syntax above is universal.
The key set depends on the record file's path.

This table is **exhaustive**: every path the format covers has a row, and every row names a schema
defined in this document.
A parser cannot classify a line without its schema, because §7 consults *single* / *repeatable* for
`E014` and *multi-line* for `E016`, so no schema may be deferred to "wherever its consumer lives".

| Path | Schema |
|---|---|
| any file named `checks.rules`, at any depth | **script check** (§9.5) |
| `modules/sast/rules/*.rules`, `modules/iac/*.rules` | **pattern rule** (§9.1) |
| `rules/derived.rules` | **derived finding** (§9.2) |
| `rules/redaction.rules` | **redaction rule** (§9.3) |
| `config/scope.conf` | **scope target** (§9.4) |
| `config/scanner.conf` | **scanner config** (§9.6.1) |
| `config/auth.conf` | **auth identity** (§9.6.2) |
| `config/discovery.conf` | **discovery input** (§9.6.3) |
| `config/posture.conf` | **posture expectation** (§9.6.4) |
| `data/severity-rubric.conf` | **severity modifier** (§9.6.5) |

**The first matching row wins**, which is why the `checks.rules` row is first.
The basename `checks.rules` is **reserved repository-wide**: it always takes the §9.5 schema regardless
of directory.
Without that reservation the `modules/iac/*.rules` glob would capture `modules/iac/checks.rules` and
assign it the pattern-rule schema, so every script-check record in it would fail `E023` for a missing
`pattern`.
A file matching no row is `E070`.

An unknown key in any schema is `E017`.
Unknown keys are an error and not a warning, because a typo in `context-deny` would otherwise silently
disable a false-positive guard and flood the report.

**Single-record config files.**
§4 requires every record's first field to be `id`.
For a file that holds exactly one record of flat settings (`config/scanner.conf`), the `id` value is a
frozen literal equal to the file's basename without extension, so `config/scanner.conf` begins
`id: scanner`.
This costs one line, keeps §4 total with no special case in the parser, and gives the linter a name to
put in every diagnostic for that file.
`E071` fires when a single-record schema's `id` is not its frozen literal, or when such a file contains
more than one record.

### 9.1 Schema: pattern rule

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Check id, §9.1.1. MUST be the first field. |
| `title` | required | single | no | One-line human summary; becomes the finding's `title`. This is §6.2's `message` column. |
| `severity` | required | single | no | One of `critical` `high` `medium` `low` `info`. The **base** severity; the frozen rubric adjusts it deterministically (`docs/FOUNDATION.md` tension 8). |
| `confidence` | optional | single | no | One of `high` `medium` `low`. Default `medium`. |
| `cwe` | required | single | no | `CWE-<digits>` or `none`. |
| `owasp` | required | single | no | `A<two digits>:<four digits>` (for example `A03:2021`) or `none`. The report expands it to the full label. |
| `pattern` | required | single | **no** | The regex, §8. |
| `dialect` | optional | single | no | `ere` (default) or `pcre`. |
| `files` | optional | repeatable | no | Glob restricting which paths the rule is applied to, §9.1.2. Multiple entries are ORed. Default: every text file the module walks. |
| `exclude-files` | optional | repeatable | no | Glob removing paths. Applied after `files`. |
| `context-require` | optional | repeatable | **no** | §10. All entries must be satisfied (AND). |
| `context-deny` | optional | repeatable | **no** | §10. Any entry satisfied suppresses the match (OR). |
| `context-window` | optional | single | no | Non-negative decimal integer, §10. Default `2`. Illegal unless at least one `context-require` or `context-deny` is present (`E031`). |
| `remediation` | required | single | **yes** | Fix guidance; becomes the finding's `remediation`. |
| `references` | optional | repeatable | no | Free-text reference token; becomes an entry in the finding's `references`. |
| `cis` | optional | repeatable | no | CIS control id, for the compliance report. |
| `tags` | optional | repeatable | no | Check-set tags, §9.1.3. |
| `severity-floor` | optional | single | no | Severity name; the rubric may never lower the finding below it. |
| `severity-ceiling` | optional | single | no | Severity name; the rubric may never raise the finding above it. |
| `format-version` | optional | single | no | `1`. Only meaningful on the first record of a file. |

#### 9.1.1 Check id

```
id     = MODULE "-" FAMILY "-" NAME [ "-" SEQ ]
MODULE = "SAST" / "SCA" / "IAC" / "DAST" / "CLOUD" / "POSTURE" / "COMPOSITE"
FAMILY = 1*( ALPHA / DIGIT )                 ; uppercase
NAME   = 1*( ALPHA / DIGIT / "_" )           ; uppercase
SEQ    = 2DIGIT
```

Full regex: `^(SAST|SCA|IAC|DAST|CLOUD|POSTURE|COMPOSITE)-[A-Z0-9]+-[A-Z0-9_]+(-[0-9]{2})?$`.

`SEQ` is **required in every schema except the derived-finding schema (§9.2), where it MUST be
omitted**.
Pattern rules come in families where sibling rules need distinguishing, so they are numbered; a derived
roll-up is singular by construction, so it is not.
This is what makes `docs/DESIGN.md` Appendix A's `COMPOSITE-TOKEN-HIJACK` a valid id exactly as written
there, with no renaming.
The linter enforces both directions (E027).

Examples: `SAST-PY-EVAL-01`, `SAST-SEC-AWS_AKID-01`, `IAC-TF-OPEN_CIDR-01`,
`COMPOSITE-TOKEN-HIJACK`.

Requirements:

- The `MODULE` component MUST match the module that owns the record file, per the frozen path map in
  §9.5.1 (`E018`).
- A check id MUST be unique across **every record file that carries check ids** (`E019`), not merely
  within its own file: all `*.rules` packs, every `checks.rules`, `rules/derived.rules`, and
  `rules/redaction.rules`.
  Uniqueness is scoped to that **namespace**, not to every record file in the repository, because the
  other schemas' `id` values are not check ids and live in namespaces of their own (§9.1.1a).
- The id is **stable forever**.
  It is the SARIF `ruleId`, the Appendix A check id, an input to the finding fingerprint, and the key
  for `covered_checks` in `state/`.
  Renaming a check id makes every historical finding for that check `fixed` and every current one `new`.
  To retire a check, delete the record and add its id to `rules/RETIRED.txt`; the linter fails if a
  retired id is ever reused.
- There is **no per-occurrence sequence number** anywhere in the system.
  The `-01` suffix distinguishes sibling rules of one family, not occurrences of a match.
  Per-occurrence identity is the fingerprint (`docs/FOUNDATION.md` tensions 5 and 7).

#### 9.1.1a Id namespaces

Not every schema's `id` is a check id, and uniqueness is scoped per namespace.
A global "unique across every record file" rule would be wrong in both directions: it would forbid
`config/discovery.conf` from using the target ids it is *required* to match, and it would let an
expectation id silently collide with a scope target id.

| Namespace | Files | Id form | Uniqueness |
|---|---|---|---|
| **check id** | `*.rules`, every `checks.rules`, `derived.rules`, `redaction.rules` | §9.1.1 | Unique across the whole namespace (`E019`) |
| **target id** | `config/scope.conf` | `^[a-z][a-z0-9-]*$` | Unique within `scope.conf` |
| **discovery id** | `config/discovery.conf` | `^[a-z][a-z0-9-]*$` | Unique within the file, and MUST name an existing target id (`E080`) |
| **auth identity id** | `config/auth.conf` | `<target>.<label>` | Unique within the file; the `<target>` part MUST name an existing target id (`E080`) |
| **expectation id** | `config/posture.conf` | `^[a-z][a-z0-9-]*$` | Unique within the file |
| **rubric modifier id** | `data/severity-rubric.conf` | `^[a-z][a-z0-9-]*$` | Unique within the file |
| **config literal** | single-record config files | the frozen basename literal | One record per file (`E071`) |
| **adapter check id** | not a record file; produced at runtime by a vendored engine (§6.4) | `<ADAPTER>:<engine rule id>`, for example `semgrep:python.lang.security.eval` | Unique within the adapter's own output; never linted, since no record declares it |

Ids in different namespaces may coincide freely; that is what lets `discovery.conf` and `auth.conf`
reference targets by name, and it is why a posture expectation named `staging` does not collide with a
scope target named `staging`.

#### 9.1.2 `files` globs

A glob is matched against the **scan-root-relative path** (`docs/FOUNDATION.md` tension 12 freezes what
the scan root is) with `/` separators, using these operators and no others:

- `*` matches any run of characters except `/`.
- `**` matches any run of characters including `/`, and is only legal as a whole path segment.
- `?` matches one character except `/`.
- `[abc]` and `[a-z]` match one character from the set.
- A leading `/` anchors to the scan root; without it the glob may match at any depth.

Examples: `*.py`, `**/Dockerfile`, `/infra/**/*.tf`, `*.[jt]s`.
A glob containing `\` or `{}` is `E042`; brace expansion is not supported, use two `files` entries.

#### 9.1.3 `tags`

Tags drive check-set selection (`docs/FOUNDATION.md` tension 15).

- Exactly one **type** tag is required on every rule: `static`.
  (Pattern rules are always static; the other type tags - `passive`, `safe-active`, `active`,
  `config-read`, `posture` - belong to script checks registered the same way, in
  `modules/<m>/checks.rules`.)
- Zero or more **profile** tags: `quick`, `compliance`.
  A rule with no profile tag runs only in `full`.
- The `intrusive` tag marks a check that mutates target state; it is refused unless `--allow-intrusive`
  is given.
  A pattern rule may never carry `intrusive` (`E043`).

### 9.2 Schema: derived finding

Derived findings are roll-ups computed in `lib/findings.sh`, not scanner scripts.
The mechanism is specified in `docs/FOUNDATION.md` tension 6; the record shape is here.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Check id per §9.1.1 with `MODULE` = `COMPOSITE` and **no `SEQ` suffix**, for example `COMPOSITE-TOKEN-HIJACK`. MUST be first. |
| `kind` | required | single | no | Literal `derived`. |
| `title` | required | single | no | As §9.1. |
| `severity` | required | single | no | As §9.1. Clamped upward to the highest contributor severity. |
| `confidence` | optional | single | no | Default `high`; a satisfied composite is a corroborated one. |
| `cwe` | required | single | no | As §9.1. |
| `owasp` | required | single | no | As §9.1. |
| `requires` | optional | repeatable | no | A contributor check id. **All** `requires` entries must have produced at least one finding this run. |
| `any-of` | optional | repeatable | no | A contributor check id. **At least one** `any-of` entry must have produced a finding this run. |
| `correlate-on` | required | single | no | The join key, §9.2.1. |
| `remediation` | required | single | yes | As §9.1. |
| `references` | optional | repeatable | no | As §9.1. |
| `cis` | optional | repeatable | no | As §9.1. |
| `tags` | optional | repeatable | no | Type tag MUST be `derived`. Profile tags as §9.1.3. |

A record MUST have at least one `requires` or `any-of` (`E050`).
Every `requires` / `any-of` value MUST be an existing, non-derived check id (`E051`).
A derived finding may not contribute to another derived finding: this keeps evaluation a single pass
with no fixed point to converge, and the linter enforces it.

#### 9.2.1 `correlate-on`

One of:

| Value | Contributors are grouped by |
|---|---|
| `none` | Nothing; the composite fires at most once per run |
| `target` | The scope target id (`config/scope.conf` `id`) |
| `account` | AWS account id |
| `account-region` | AWS account id and region |
| `file` | Repository-relative file path |

Contributors that cannot supply the correlation key cannot participate in a correlated composite.
The composite fires once per distinct correlation value for which the `requires` / `any-of` predicate
holds, and the correlation value is part of the composite's fingerprint.

#### 9.2.2 Correlation-key capability

`E053` requires deciding, statically, whether a contributor's module can supply a given correlation key.
This table is that decision, and it is frozen.
It governs `correlate-on` **only**.
`coverage-scope` is a different vocabulary and is validated against §9.5.1's own table; see the note
there.

| Module | `target` | `account` | `account-region` | `file` |
|---|---|---|---|---|
| SAST (incl. history) | no | no | no | **yes** |
| SCA | no | no | no | **yes** |
| IAC | no | no | no | **yes** |
| DAST | **yes** | no | no | no |
| CLOUD | **yes**, by attribution | **yes** | **yes** | no |
| POSTURE | **yes**, by scope-key | **yes** | **yes** | no |

`E053` fires when a derived record's `correlate-on` is a key that **any** of its `requires` or `any-of`
contributors' modules cannot supply per this table.
`correlate-on: none` is always legal.

Every **yes** in this table is a statement about the module *in principle*, which is what makes the
table static and `E053` decidable from record text alone.
Two cells are supplied conditionally at runtime, and both resolve the same graceful way: a finding that
cannot produce the value simply has no value for that key and does not participate in that composite.

- **CLOUD / `target`** is supplied by attribution, below; zero host matches means no `target` value.
- **POSTURE / `target`** is supplied when the finding's expectation carries a `scope-key` that is a
  scope target id (`rules/RULE-FORMAT.md` §9.6.4).
  When the `scope-key` is an account id or `account/region` instead, the finding has no `target` value
  and does not participate in a `target` composite, exactly as for a cloud finding with no host match.

Neither case is an error, and neither is silent: a composite that never fires because its contributors
never share a correlation value is reported in `run.json` under `coverage_gap`, so the operator sees a
chain that cannot correlate rather than a chain that is clean.

**Cloud target attribution.**
A cloud-live finding has no scope-target name in its own identity, so `target` is supplied by an
attribution step in `lib/findings.sh`, frozen here because `COMPOSITE-TOKEN-HIJACK` depends on it:

1. A cloud check that reads a resource with a public endpoint records the resource's domain names on
   the finding as `endpoint_hosts`, taken from the read-only API response (for example an AppSync
   `uris` value, a CloudFront `DomainName`, an ELB `DNSName`, an API Gateway execute-api hostname).
2. `lib/findings.sh` builds a **target attribution map** once per run from `config/scope.conf`: for each
   target, the set of hosts from its `base-url` and every `extra-host`, lowercased and dot-stripped
   exactly as the scope gate normalises them (`docs/FOUNDATION.md` tension 19).
   When a target declares `allow-subdomains: true`, the map additionally matches any host that is a
   subdomain of one of its hosts.
   Omitting that would make attribution flip on a flag this section never mentions: a custom-domain
   endpoint reachable only through `allow-subdomains` would be in scope for DAST, absent from the
   attribution set, and the composite would silently never fire, while the same deployment authored with
   an explicit `extra-host` would work.
3. A cloud finding's `target` correlation value is the target id whose host set matches any of the
   finding's `endpoint_hosts`.
   - **Zero matches**: the finding has no `target` value and does not participate in a `target`
     composite.
   - **Exactly one match**: that target id.
   - **More than one match**: the finding has **no** `target` value, and the ambiguity is recorded in
     `run.json` under `coverage_gap`.
     Two targets legitimately share a host whenever an operator authors two path-scoped targets on one
     host, which `docs/FOUNDATION.md` tension 19 explicitly supports as the way to bound two crawl
     frontiers, so this must not be an error.
     Declining to attribute is the same conservative outcome as zero matches, reached for the same
     reason: guessing a correlation value is worse than not having one.

**Authoring note.**
A `target` composite requires its contributors to be authored under **one** target id.
If the front end and the managed-GraphQL endpoint are authored as two separate `config/scope.conf`
targets, the §7.1 contributor carries the first and the §7.4 and cloud contributors carry the second,
and the predicate is unsatisfiable however open the chain actually is.
Nothing lints this, because both authorings are legal and only the operator knows which deployment they
describe, so the composite reports through `coverage_gap` rather than through a finding.

**Attribution never enters the fingerprint.**
`target` is a correlation attribute only.
Putting it in a cloud finding's fingerprint (tension 5) would make every cloud finding churn to
`new` the moment an operator edited `config/scope.conf`, which is precisely the instability tension 5
exists to prevent.

A run that produces cloud findings but has no `config/scope.conf` attributes no targets at all, which is
correct: with no authorised targets there is no deployed front end to attribute a chain to.
Such a run also has no DAST contributors, so a `target` composite has an uncovered contributor and is
classified `unknown` rather than `fixed` (`docs/FOUNDATION.md` tension 6).

### 9.3 Schema: redaction rule

Used by `redact()` before any evidence, log line, or report byte is written
(`docs/FOUNDATION.md` tension 9).

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Check id per §9.1.1, `MODULE` = `SAST`, `FAMILY` = `REDACT`. MUST be first. |
| `title` | required | single | no | What this redacts. |
| `pattern` | required | single | no | Regex, §8. Each match is replaced. |
| `dialect` | optional | single | no | As §9.1. |
| `kind` | required | single | no | Short uppercase token placed in the replacement, for example `AWS_SECRET`, `JWT`, `PRIVATE_KEY`, `BEARER`. `^[A-Z][A-Z0-9_]*$`. |

The replacement text is `<redacted:KIND:DDDDDDDD>` where `DDDDDDDD` is the first 8 lowercase hex
characters of the SHA-256 of the raw matched bytes.
The digest lets a reader tell two distinct secrets apart and lets the same secret be recognised across
findings, without disclosing it.

### 9.4 Schema: scope target

`config/scope.conf` uses this format rather than the `name | base_url | notes` line in
`docs/DESIGN.md` §11, for the reason in `docs/FOUNDATION.md` tension 26: a free-text `notes` field
cannot safely share a delimiter with the record, and the scope gate is the single most important safety
control in the tool.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | The target name used by `--target`. `^[a-z][a-z0-9-]*$`. MUST be first. |
| `base-url` | required | single | no | Absolute URL, `https://host[:port][/path]`. Scheme MUST be `http` or `https`. |
| `extra-host` | optional | repeatable | no | `host[:port]` additionally in scope for this target. |
| `allow-subdomains` | optional | single | no | `true` or `false`. Default `false`. |
| `allow-private-addresses` | optional | single | no | `true` or `false`. Default `false`. Gates the link-local and loopback deny list. |
| `notes` | optional | single | yes | Free text. Now safely free text. |

### 9.5 Schema: script check

A `checks.rules` registers every check that is a **script** rather than a pattern: all of DAST passive
and active, all cloud live checks, all posture checks, and the SCA checks.
It lives under the module that owns it, which for posture is `modules/cloud/posture/` rather than a
top-level directory; the owning-module map in §9.5.1 is authoritative, and a `checks.rules` outside every
prefix in it is `E081`.
It is the check registry that `docs/FOUNDATION.md` tension 12 computes `covered_checks` from, that
tension 15's filter chain filters, and that tension 7 requires so scripts have stable ids exactly as
patterns do.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Check id, §9.1.1, with `MODULE` matching the owning module. MUST be first. |
| `title` | required | single | no | As §9.1. |
| `script` | required | single | no | Module-relative path to the implementing script, for example `active/sqli.sh`. Must exist (`E072`). |
| `entry` | optional | single | no | Shell function name the runner calls. `^[a-z_][a-z0-9_]*$`. Default `run_check`. |
| `severity` | required | single | no | As §9.1. Base severity; the rubric adjusts it. |
| `confidence` | optional | single | no | As §9.1. Default `medium`. |
| `cwe` | required | single | no | As §9.1. |
| `owasp` | required | single | no | As §9.1. |
| `tags` | required | repeatable | no | §9.1.3. Exactly one type tag, which for this schema MUST NOT be `static` or `derived` (`E044`). |
| `coverage-scope` | required | single | no | The scope dimension that partitions this check's findings, §9.5.1. |
| `requires-config` | optional | repeatable | no | A config file that must be present and non-empty for the check to run, for example `config/auth.conf`. Absent means the check is skipped with a `run.json` reason, not an error. |
| `requires-cmd` | optional | repeatable | no | An external command the check needs, for example `openssl`. Absent means skipped with a reason. |
| `requires-identities` | optional | single | no | Decimal integer, the number of labelled auth identities the check needs. Default `0`. `authz.sh` declares `2`. |
| `remediation` | required | single | yes | As §9.1. |
| `references` | optional | repeatable | no | As §9.1. |
| `cis` | optional | repeatable | no | As §9.1. |
| `severity-floor` | optional | single | no | As §9.1. |
| `severity-ceiling` | optional | single | no | As §9.1. |

A script check has no `pattern`, `dialect`, `files`, or `context-*` key; those are `E017` here.

#### 9.5.1 `coverage-scope`

It names the dimension along which a run can cover *part* of a check, and it is what
`docs/FOUNDATION.md` tension 12 records in `state/` so that a region-scoped or target-scoped run cannot
manufacture `fixed` findings for the regions or targets it never visited.

This is a different vocabulary from §9.2.2's correlation keys and is **not** validated against that
table: correlation asks "can two findings be joined", coverage asks "what did this run visit".
The two vocabularies do not even overlap - `path-root` and `scope-key` appear in no §9.2.2 column - so
validating one against the other would emit an error for every SAST, SCA, IAC, and POSTURE script check.
The value is fixed per module, so the linter checks it against this table alone (`E079`):

| Module | Required `coverage-scope` | Cell value |
|---|---|---|
| `SAST` | `path-root` | the `--path` root relative to the scan root |
| `SCA` | `path-root` | the `--path` root relative to the scan root |
| `IAC` | `path-root` | the `--path` root relative to the scan root |
| `DAST` | `target` | the `config/scope.conf` target id |
| `CLOUD` | `account-region` | `<account_id>/<region>`, or `<account_id>/global` |
| `POSTURE` | `scope-key` | the expectation's `scope-key` (§9.6.4) |

`none` is not a legal value in a §9.5 record: no script check is all-or-nothing.
Derived findings have no `coverage-scope` at all - §9.2 has no such key - because they are classified by
their own selection plus contributor coverage rather than by a cell (`docs/FOUNDATION.md` tension 6).
A derived finding's persisted `cell` is JSON `null`, never the string `none`, since `none` is a legal
`path-root` and a legal scope target id and a string sentinel could collide with either.

`SAST-HIST-*` checks take `path-root` like the rest of SAST, and **their cell carries nothing else**.
The resolved history boundary is *not* part of the cell.
Cells are compared by exact value, so a boundary in the cell would make every prior history finding
`unknown` forever under a rolling window, which is the outcome `docs/FOUNDATION.md` tension 13 rejects.
That tension owns `SAST-HIST-*` classification and applies its per-finding boundary comparison
**inside** a covered cell, as a second layer, not as a competing cell definition.

**The cell is recorded on the finding, not always derived from it.**
For `CLOUD`, `DAST`, and `POSTURE` the cell is a projection of the finding's location components
(`docs/FOUNDATION.md` tension 5), so the two cannot drift.
For `SAST`, `SCA`, and `IAC` the cell is the run's `--path` root, which is a run parameter and is
deliberately absent from the finding's identity: `src/sub/x.py` is consistent with a root of `.`,
`src`, or `src/sub`, and an SCA finding's location carries no path at all.
`docs/FOUNDATION.md` tension 12 freezes the exact normalisation of the `path-root` string and states
that cells are compared by exact string equality with no subsumption rule.

**Owning module, for `E018`.**
`E018` compares a record's `MODULE` component against the module that owns the record's **file**.
That ownership is not the first path segment: `docs/DESIGN.md` §3 nests posture under
`modules/cloud/posture/` while `POSTURE` is a module in its own right in the §9.1.1 enum, and two rule
files live outside `modules/` entirely.
The map is frozen here, **most specific first, first match wins**:

| Path prefix | Owning module |
|---|---|
| `modules/cloud/posture/` | `POSTURE` |
| `modules/cloud/` | `CLOUD` |
| `modules/sast/` | `SAST` |
| `modules/sca/` | `SCA` |
| `modules/iac/` | `IAC` |
| `modules/dast/` | `DAST` |
| `rules/derived.rules` | `COMPOSITE` |
| `rules/redaction.rules` | `SAST` (redaction ids are `SAST-REDACT-*`, §9.3) |

A `POSTURE-*` record in `modules/cloud/posture/checks.rules` therefore does not fire `E018`, and a
`CLOUD-*` record in that same directory does.

The map is **total** over the §9 path table: a record file matching none of these prefixes carries no
check ids (every operator-config schema uses a different namespace, §9.1.1a), so `E018` does not apply
to it.
A `checks.rules` placed outside every prefix above matches the §9 table's "any depth" row but has no
owning module, which is `E081` - a script check must live under the module that owns it, since that is
what makes its ids, its `coverage-scope`, and its `script` path meaningful.

### 9.6 Schemas: operator config

These files are hand-edited by operators, so their key sets are frozen here rather than left with their
consumers.
Every value is data and is never expanded or executed (§11).

#### 9.6.1 `config/scanner.conf` - scanner config

Exactly one record, `id: scanner`.
`id` is required, as in every schema; every **other** key is optional and takes the stated default, so
an absent file is equivalent to one containing only `id: scanner`.

| Key | Card | Multi-line | Value | Default |
|---|---|---|---|---|
| `id` | single | no | Literal `scanner`. MUST be first. | required |
| `requests-per-second` | single | no | Decimal, may be fractional | `4` |
| `jobs` | single | no | Positive integer | `4` |
| `http-timeout` | single | no | Seconds, positive integer | `20` |
| `max-redirects` | single | no | Non-negative integer | `5` |
| `request-budget` | single | no | Positive integer, per run | `20000` |
| `circuit-breaker-failures` | single | no | Positive integer | `10` |
| `circuit-breaker-window` | single | no | Seconds | `60` |
| `fail-on` | single | no | Severity name or `none` | `none` |
| `min-confidence` | single | no | `high` `medium` `low` | `low` |
| `redact-secrets` | single | no | `true` or `false` | `true` |
| `formats` | repeatable | no | `json` `sarif` `html` `md` | all four |
| `max-matches-per-file` | single | no | Positive integer | `200` |
| `evidence-max-bytes` | single | no | Positive integer | `512` |
| `scratch-dir` | single | no | Absolute path | `${TMPDIR:-/tmp}` |
| `state-retain-runs` | single | no | Positive integer | `30` |
| `history-window-days` | single | no | Positive integer | `365` |
| `history-max-commits` | single | no | Positive integer | `5000` |
| `lock-stale-seconds` | single | no | Positive integer | `30` |
| `mutex-timeout-seconds` | single | no | Positive integer | `120` |
| `paranoid-allow` | repeatable | no | `addr:port` | empty |
| `advisory-update-url` | single | no | `https://` URL | empty (update channel disabled) |
| `notes` | single | yes | Free text | empty |

`advisory-update-url` is `docs/FOUNDATION.md` tension 27's third allowed scan-time destination category:
the base URL `tools/update-advisories.sh` fetches from, and the only additional host `lib/http.sh`
admits beyond `config/scope.conf`'s targets. Empty (the default) means the update channel is
unconfigured, and `tools/update-advisories.sh` refuses to run rather than guessing a host.

`docs/DESIGN.md` §11 also lists "the named scan-profile check-sets (`quick`/`full`/`compliance`)" as
living here.
They do not: `docs/FOUNDATION.md` tension 15 computes profile membership from each check's own record,
so there is no profile definition to store and no way for a profile list to drift out of sync with the
checks it names.
(Exactly *which* field of the record decides `compliance` - the `compliance` tag of §9.1.3, or a
non-empty `cis` / `owasp` per tension 15 - is open as finding **F3** in that document's known
follow-ups, and is not settled here.)

#### 9.6.2 `config/auth.conf` - auth identity

One record per (target, identity).
File permissions MUST be `600` (`E073`).
Every value in this schema is marked **secret**, so `redact()` covers it in every log, report, and
evidence field (`docs/FOUNDATION.md` tension 9).

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | `<target-id>.<label>`, for example `staging.a`. `^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$`. The `<target-id>` part MUST name a `config/scope.conf` target (`E080`, §9.1.1a). MUST be first. |
| `mode` | required | single | no | `bearer` `api-key` `form` `oauth2-password` `oauth2-client` `srp` `external` |
| `secret-file` | optional | single | no | Absolute path to a `600` file holding the credential. Preferred over inline values. |
| `token` | optional | single | no | Inline token, for `bearer` / `api-key`. |
| `header-name` | optional | single | no | Header to carry the credential. Default `Authorization`. |
| `username` | optional | single | no | For `form`, `oauth2-password`, `srp`. |
| `password` | optional | single | no | As above. Prefer `secret-file`. |
| `login-path` | optional | single | no | Target-relative path for `form`. |
| `token-url` | optional | single | no | For the OAuth2 modes. |
| `client-id` | optional | single | no | For the OAuth2 modes. |
| `client-secret` | optional | single | no | As above. Prefer `secret-file`. |
| `scope` | optional | single | no | OAuth2 scope string. |
| `pool-id` | optional | single | no | For `srp`. |
| `notes` | optional | single | yes | Free text. |

Which optional keys are required is a function of `mode`, checked as `E074`.

#### 9.6.3 `config/discovery.conf` - discovery input

One record per target, `id` = the target id.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Target id; MUST name a `config/scope.conf` target (`E080`, §9.1.1a). MUST be first. |
| `openapi-path` | optional | single | no | Path to an OpenAPI or Swagger document. |
| `graphql-schema-path` | optional | single | no | Path to a GraphQL schema. |
| `postman-path` | optional | single | no | Path to a Postman collection. |
| `har-path` | optional | single | no | Path to a HAR capture. |
| `crawl-depth` | optional | single | no | Non-negative integer. Default `3`. |
| `include-path` | optional | repeatable | no | Glob (§9.1.2) of target-relative paths to crawl. |
| `exclude-path` | optional | repeatable | no | Glob of target-relative paths never to request. |
| `notes` | optional | single | yes | Free text. |

#### 9.6.4 `config/posture.conf` - posture expectation

One record per expected control **per scope**, so §8.7 reports **drift** rather than opinion.

An expectation is **not** a check.
The check is the script registered in `checks.rules` (§9.5) that reads the live or config state; the
expectation is the operator-supplied baseline it is compared against.
They are two different things in two different files, so they live in **two different id namespaces**
(§9.1.1a): the check in the check-id namespace, the expectation in its own.
Giving the expectation a `POSTURE-*` check id instead would put two records in the check-id namespace
under one id and fire `E019` on every posture control.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | Expectation id, `^[a-z][a-z0-9-]*$`. **Not a check id.** MUST be first. |
| `check` | required | single | no | The check id this expectation parameterises, §9.1.1 with `MODULE` = `POSTURE`. Must exist in a `checks.rules` (`E077`). |
| `scope-key` | required | single | no | What this expectation applies to: a target id, an account id, or `account/region`. |
| `expect` | required | single | no | `present` `absent` `equals` `at-least` `at-most` |
| `value` | optional | single | no | Required when `expect` is `equals`, `at-least`, or `at-most`. |
| `notes` | optional | single | yes | Free text. |

The (`check`, `scope-key`) pair MUST be unique across the file (`E078`); two baselines for one control
in one scope is a contradiction with no defined winner.
That pair is also what makes a posture finding's identity unique (`docs/FOUNDATION.md` tension 5) and
what makes `coverage-scope: scope-key` a real partition rather than a degenerate one: a control can now
carry several expectations across several scopes, which is the shape `docs/DESIGN.md` §11 describes when
it lists "WAF IP/geo expectations, org password-policy thresholds" as posture config.

#### 9.6.5 `data/severity-rubric.conf` - severity modifier

One record per modifier, implementing the frozen table in `docs/FOUNDATION.md` tension 8.

| Key | Req | Card | Multi-line | Value |
|---|---|---|---|---|
| `id` | required | single | no | `^[a-z][a-z0-9-]*$`, for example `exposure-internet`. MUST be first. |
| `fact` | required | single | no | The finding field examined: `exposure` `auth` `sensitive-data` `confidence` |
| `equals` | required | single | no | The value of that field this record matches. |
| `modifier` | required | single | no | Signed decimal integer, `-4` to `+4`. |

The rubric reads no field outside this table, which is what makes `severity_of()` pure and total.
`E075` fires when two records share the same (`fact`, `equals`) pair, since that would make the sum
order-dependent.

## 10. The `context` directive

`docs/DESIGN.md` §6.2 asks for "a `# context:` directive option to require/deny a neighboring pattern
... within N lines".
That sketch is under-specified in three ways an implementer cannot guess past: whether the directive is
require or deny, whether the window is symmetric, and whether the match line itself counts.
`docs/FOUNDATION.md` tension 3 resolves all three; this section is the normative statement.

It is expressed as ordinary fields, not as a magic comment.
A directive smuggled inside a comment would be invisible to the linter and would be stripped by any
comment-aware tooling, so `#` retains its single meaning from §3.3.

### 10.1 Semantics

Let the rule's `pattern` match on line `m` of a file of `L` lines, and let `W` be `context-window`
(default `2`).

The **context window** is the inclusive line range `[max(1, m - W), min(L, m + W)]`.
It is **symmetric** and it **includes line `m` itself**.

For a match to become a finding, both must hold:

1. **Require (AND).** For *every* `context-require` value `R`, at least one line in the window matches
   `R`.
2. **Deny (OR).** For *no* `context-deny` value `D` does any line in the window match `D`.

Deny is evaluated after require, and deny wins.
A rule with neither key emits every match.
`context-window: 0` restricts the window to line `m` alone, which is the right setting for a guard that
must appear on the same line, such as `verify=False` on the call itself.

`context-require` and `context-deny` use the record's `dialect` and the same line-oriented,
case-sensitive matching as `pattern` (§8.2).

### 10.2 Why require-and-deny rather than one polarity

Require alone cannot express "flag `yaml.load(` unless `SafeLoader` is nearby", and deny alone cannot
express "flag `eval(` only where request data is nearby".
The §6.3 catalog needs both shapes, so both exist, with fixed and opposite quantifiers (all-of for
require, any-of for deny) chosen so that adding another entry always makes a rule *stricter* about
firing.
That monotonicity is what lets an author tune a noisy rule without re-reasoning about the whole
predicate.

### 10.3 Implementation contract

Non-normative, but the semantics above must be preserved exactly.

The engine gets candidate matches for a file in one pass, then evaluates windows for all of them in a
second single pass over the file, rather than re-reading the file once per match.

The first pass must yield **every match, with its byte offset within the line**, not one hit per matching
line: `docs/FOUNDATION.md` tension 5 orders the `occurrence` ordinal by line and then by byte offset, and
settles that one line yielding two matches yields two findings.
A bare `rg -n` or `grep -n` reports each matching line once and no offsets, so it **cannot** produce the
frozen ordinal.
Use `rg --json` (which reports every match with `absolute_offset` and submatch offsets) or
`rg -n --byte-offset -o` / `grep -n -b -o`, whose `-o` emits one record per match rather than per line.
`max_matches_per_file` (default 200, from `config/scanner.conf`) counts **matches**, not matching lines.

On overflow the engine emits the findings it has plus one `info` finding recording the truncation, and
records the truncation in `run.json`.
Silent truncation would understate coverage, which §15 of `docs/DESIGN.md` forbids.

## 11. Record files are data, never code

A record file MUST NOT be `source`d, `eval`ed, or expanded by the shell.
It is read line by line by `lib/records.sh` and its values are used as data.

This is a security requirement, not a style preference.
`config/scope.conf` is the gate that decides which hosts scoursh is allowed to contact.
If it were shell, a crafted config would execute arbitrary commands before the gate was ever consulted,
and the tool's central safety property would be defeated by its own config loader.
The same applies to rule packs, which are exactly the kind of file a team copies from an untrusted
source.

The linter enforces the converse in the code: `lib/records.sh` is the only file permitted to read a
`.rules` or `config/*.conf` file, and no script may contain `source` or `.` applied to a path under
`config/` or `rules/`.

## 12. Worked examples

All five are drawn from the `docs/DESIGN.md` §6.3 catalog and are chosen because their regexes stress
the format.

### 12.1 Alternation, which is what broke the pipe format

`secrets.rules`, from "AWS keys (`AKIA...`)".
The pattern contains six `|` characters.
Under the pipe-delimited format this record would have split into thirteen fields instead of six.

```
id: SAST-SEC-AWS_AKID-01
title: Hardcoded AWS access key id
severity: critical
confidence: high
cwe: CWE-798
owasp: A07:2021
pattern: \b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b
dialect: ere
context-deny: EXAMPLE|example|AKIAIOSFODNN7EXAMPLE|placeholder|XXXXXXXX
context-window: 0
tags: static
tags: quick
tags: compliance
remediation: Remove the key from source and rotate it immediately; a committed key must be
  treated as compromised even if the commit was reverted, because it remains in git history.
  Supply credentials through the instance role, the AWS profile, or the operator's secret store.
references: CWE-798
references: CIS-AWS-1.4
cis: 1.4
```

Note that `context-deny` is itself an alternation, so the deny value carries five more `|` bytes.
Nothing is escaped.
`context-window: 0` keeps the deny check on the matching line only, so a nearby unrelated comment
containing the word `example` cannot suppress a real key.

### 12.2 The §6.2 lookahead, rewritten without PCRE

`python.rules`, from "`yaml.load`".
`docs/DESIGN.md` §6.2 shows `yaml\.load\((?!.*Loader)`, a PCRE negative lookahead.
Under §8.3 that would make the whole check silently unavailable on any host whose `rg` lacks PCRE2 and
whose `grep` is BSD.
The `context` directive expresses the same intent portably, and gets a two-line window for free, so it
also catches the common shape where the loader is passed on the next line.

```
id: SAST-PY-YAML_LOAD-01
title: yaml.load() without a safe loader
severity: high
confidence: medium
cwe: CWE-502
owasp: A08:2021
pattern: \byaml\.load\s*\(
dialect: ere
files: *.py
files: *.pyi
context-deny: (SafeLoader|CSafeLoader|BaseLoader|yaml\.safe_load)
context-window: 2
tags: static
tags: quick
severity-floor: medium
remediation: Use yaml.safe_load(), or pass Loader=yaml.SafeLoader explicitly.
  yaml.load() with the default loader constructs arbitrary Python objects and is a
  remote code execution sink whenever the document is attacker-influenced.
references: CWE-502
```

### 12.3 A value containing `:`, quotes, and `$`

`javascript.rules`, from "prototype pollution patterns (recursive merge / `__proto__` assignment)".
The pattern contains `:` inside the value (which §5.2 makes safe because only the *first* `": "` is the
separator), a `$` (no expansion, §5.3), both quote characters, and alternation.

```
id: SAST-JS-PROTO_POLLUTION-01
title: Assignment or lookup of __proto__ / constructor.prototype from a dynamic key
severity: high
confidence: medium
cwe: CWE-1321
owasp: A08:2021
pattern: (__proto__\s*[:=]|\[\s*["']__proto__["']\s*\]|constructor\s*\.\s*prototype\s*\[)
dialect: ere
files: *.js
files: *.[cm]js
files: *.[jt]sx
files: *.ts
exclude-files: **/*.test.[jt]s
exclude-files: **/node_modules/**
context-require: (req|request|body|query|params|JSON\.parse|\$_)
context-window: 5
tags: static
remediation: Reject __proto__, constructor, and prototype keys before merging untrusted objects,
  or use a null-prototype target (Object.create(null)) and a merge helper that copies own
  enumerable properties only.
references: CWE-1321
```

`context-require` here is the "only flag when request data is nearby" shape from §6.2, with a wider
five-line window because the request object is usually destructured a few lines above the merge call.

### 12.4 A pattern that starts with `#`, proving comments are line-leading only

`injection.rules`, the suppression-comment audit implied by the false-positive-guard discussion.
The value begins with `#`, which §3.3 makes unambiguous: only a `#` in **column 1** starts a comment,
and this `#` is at column 10.

```
id: SAST-GEN-SUPPRESSION-01
title: Security-linter suppression comment in source
severity: low
confidence: high
cwe: none
owasp: none
pattern: (#\s*(nosec|noqa:\s*S[0-9]+|type:\s*ignore\[security)|//\s*eslint-disable.*security|//\s*nolint:\s*gosec)
dialect: ere
tags: static
remediation: A suppression comment hides a finding from every other tool in the pipeline.
  Confirm the suppression is still justified, record the justification inline, and prefer
  scoursh's config/baseline.json, which carries a reason and an expiry.
references: CWE-1078
```

Note the value also contains `[`, `]`, `:`, `+`, and a `.` inside `type:\s*ignore\[security`, and that
`noqa:\s*S[0-9]+` contains a second `": "`-adjacent colon.
None of it needs escaping.

### 12.5 An IaC rule with quotes, a slash, and a multi-line remediation

`modules/iac/cloud.rules`, from §8.2's seed rules.

```
id: IAC-TF-OPEN_CIDR-01
title: Security group rule open to 0.0.0.0/0
severity: high
confidence: high
cwe: CWE-284
owasp: A05:2021
pattern: cidr_blocks\s*=\s*\[[^]]*"0\.0\.0\.0/0"
dialect: ere
files: *.tf
files: *.tf.json
context-deny: ^\s*#\s*scoursh-allow: open-cidr
context-window: 1
tags: static
tags: compliance
cis: 5.2
cis: 5.3
remediation: Restrict the CIDR to the smallest network that needs access.
  Where public reachability is genuinely required (a public load balancer listener),
  terminate it at an edge that applies WAF and rate limiting rather than at the
  instance security group, and record the exception with an inline
  "# scoursh-allow: open-cidr" comment on the preceding line.
references: CIS-AWS-5.2
```

The pattern carries `"`, `/`, `[`, `]`, and `.` escapes.
The `context-deny` gives operators an in-file, reviewable exception marker whose absence is the default,
and `context-window: 1` keeps that marker adjacent so it cannot be parked at the top of the file and
forgotten.

### 12.6 Negative examples: the whitespace cases

These are the cases §3.2's test order exists to decide, and they are the first fixtures the linter needs.
`·` denotes one `0x20` space and `→` one `0x09` TAB; neither character appears in the file.

**(a) A "blank" line carrying two spaces does not separate records, and does not continue a value.**

```
id: SAST-PY-EVAL-01
remediation: line one
··
files: *.py
```

Line 3 is whitespace-only, so §3.2 test 2 fires **before** the Continuation test: **`E011` at 3:1**.

Without the ordering this file would parse clean two different ways depending on the implementation.
Read as a Continuation, `remediation` becomes `"line one\n"` with a trailing empty line and the record
continues.
Read as a Blank, the record ends at line 2 and `files: *.py` starts a new record that fails `E020` for
not beginning with `id`.
Both are silent misparses of an invisible byte, and the parsed bytes feed `rule_digest`
(`docs/FOUNDATION.md` tension 12), so the two implementations would also disagree on diff
classification.

**(b) One leading space is an error, not a continuation.**

```
id: SAST-PY-EVAL-01
remediation: line one
·line two
```

Line 3 fails every test: not blank, not whitespace-only, no leading TAB, not `#`, its first two bytes
are not `0x20 0x20`, and it does not match the Field pattern.
**`E010` at 3:1.**
This is the off-by-one indentation typo, and it is loud.

**(c) Three or more leading spaces is a valid continuation with preserved indentation.**

```
id: SAST-PY-EVAL-01
remediation: Do not eval() request data.
··Prefer:
····ast.literal_eval()
```

Parses clean.
`remediation` is `Do not eval() request data.\nPrefer:\n··ast.literal_eval()` - the first two spaces are
stripped from each continuation, and the remaining two on line 4 are part of the value (§6 rule 1).

**(d) A TAB is content, never indentation.**

```
id: SAST-PY-EVAL-01
→remediation: x
```

**`E021` at 2:1.**
A line that is only TABs would instead be `E011`, because test 2 runs before test 3.
A TAB *inside* a value is fine and needs no escaping.

**(e) An empty value is an error, not an unset field.**

```
id: SAST-PY-EVAL-01
cwe:
```

**`E013` at 2:1.**
So is `cwe:·`.
A schema that needs "unset" uses the literal token `none` (§5.3).

## 13. Linter checks

`tests/lint-rules.sh` implements every check below and exits non-zero if any error fires.
Warnings are reported and do not fail unless `--strict`.

### Syntax (from §3 to §7)

| Code | Severity | Check |
|---|---|---|
| E001 | error | File is not valid UTF-8 |
| E002 | error | File contains CR (`0x0D`) |
| E003 | error | File begins with a byte-order mark |
| E004 | error | File contains NUL |
| E010 | error | Line matches no line kind in §3.2 (includes the one-leading-space typo, §12.6b) |
| E011 | error | Line is non-empty and entirely whitespace: not a record separator, not a continuation (§3.2 test 2, §12.6a) |
| E012 | error | Comment line between a field line and its continuations |
| E013 | error | Field line with an empty value |
| E014 | error | Duplicate *single* key in one record |
| E015 | error | Continuation line with no preceding field |
| E016 | error | Continuation on a key that is single-line only |
| E017 | error | Unknown key for the file's schema |
| E018 | error | `id` module component does not match the owning module |
| E019 | error | Duplicate `id` within one id namespace (§9.1.1a) |
| E020 | error | Record's first field is not `id` |
| E021 | error | Leading TAB used as indentation |
| W022 | warning | Trailing whitespace on a non-pattern value |

### Schema (from §9)

| Code | Severity | Check |
|---|---|---|
| E023 | error | Missing required key |
| E024 | error | Enum value outside its permitted set (`severity`, `confidence`, `dialect`, `kind`, `correlate-on`, boolean fields) |
| E025 | error | `cwe` does not match `^(CWE-[0-9]+\|none)$` |
| E026 | error | `owasp` does not match `^(A[0-9]{2}:[0-9]{4}\|none)$` |
| E027 | error | `id` does not match the form its namespace requires (§9.1.1a); for check ids that is the §9.1.1 regex, with `SEQ` forbidden in the derived schema and required in every other |
| E080 | error | A `config/discovery.conf` or `config/auth.conf` `id` names a target that `config/scope.conf` does not define (§9.1.1a) |
| E028 | error | `id` appears in `rules/RETIRED.txt` |
| E029 | error | `severity-floor` is above `severity-ceiling` |
| E043 | error | `intrusive` tag on a pattern rule |
| E044 | error | No type tag, or more than one type tag, or a type tag illegal for the schema (§9.5) |
| E045 | error | `format-version` present and not `1` |
| E070 | error | Record file matches no row of the §9 path table |
| E071 | error | Single-record config file has the wrong `id` literal, or more than one record (§9) |
| E072 | error | §9.5 `script` names a path that does not exist |
| E073 | error | `config/auth.conf` permissions are not `600` |
| E074 | error | §9.6.2 record is missing a key its `mode` requires |
| E075 | error | Two `data/severity-rubric.conf` records share the same (`fact`, `equals`) pair |
| E077 | error | §9.6.4 `check` names a `POSTURE-*` check id that no `checks.rules` defines |
| E078 | error | Two §9.6.4 records share the same (`check`, `scope-key`) pair |
| E079 | error | §9.5 `coverage-scope` is not its module's required value (§9.5.1) |
| E081 | error | A `checks.rules` sits outside every prefix of the §9.5.1 owning-module map, so its records have no owning module |

### Regex (from §8)

| Code | Severity | Check |
|---|---|---|
| E030 | error | `pattern`, `context-require`, or `context-deny` value ends in a space |
| E040 | error | `dialect: ere` value uses a construct outside the §8.2 subset |
| E041 | error | Nested unbounded quantification (catastrophic-backtracking shape) |
| E046 | error | Value does not compile under its declared dialect (verified by invoking the engine on `/dev/null`) |
| W047 | warning | `dialect: pcre` used where the §8.2 subset would suffice (no PCRE-only construct present) |
| E042 | error | `files` / `exclude-files` glob uses `\` or `{}` |

### Directive (from §10)

| Code | Severity | Check |
|---|---|---|
| E031 | error | `context-window` present with no `context-require` and no `context-deny` |
| E032 | error | `context-window` is not a non-negative decimal integer, or exceeds 50 |

### Derived findings (from §9.2)

| Code | Severity | Check |
|---|---|---|
| E050 | error | Derived record has neither `requires` nor `any-of` |
| E051 | error | `requires` / `any-of` names an id that does not exist |
| E052 | error | `requires` / `any-of` names a derived id (no chaining) |
| E053 | error | `correlate-on` naming a key a contributor's module cannot supply (§9.2.2) |

### Coverage (from `docs/DESIGN.md` §12)

| Code | Severity | Check |
|---|---|---|
| E060 | error | A rule has no true-positive fixture under `tests/fixtures/` |
| W061 | warning | A rule fires on the clean fixture (false-positive guard) |
| E062 | error | `rules/RETIRED.txt` contains an id that is still defined |

Every diagnostic is printed as `path:line:col: CODE record-id message` so it is greppable and so an
editor can jump to it.

## 14. What a change to this format costs

Enumerated so the cost is explicit rather than discovered later:

1. Every `.rules` pack and every `config/*.conf` file in the repository must be rewritten.
2. `lib/records.sh` and `tests/lint-rules.sh` change together, and every module that consumes records
   must be re-tested.
3. Check ids feed the finding fingerprint (`docs/FOUNDATION.md` tension 5).
   Any change that alters an id, a module prefix, or the fingerprint inputs invalidates `state/` and
   `config/baseline.json`: every finding becomes `new`, every accepted risk stops being suppressed, and
   the "fail only on new findings" CI mode (`docs/DESIGN.md` §9a) fails every build until the baseline
   is rebuilt.
4. SARIF consumers key on `ruleId` and `partialFingerprints`; both change, so previously-ingested
   results are orphaned in the consumer's history.

That is why this format is frozen, and why §2's `format_version` exists: a future change is a versioned
migration, not an edit.
