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

Every line in the file is exactly one of five kinds, decided by the line's first bytes, in this order:

| Kind | Recognised by | Meaning |
|---|---|---|
| **Blank** | the line is zero bytes long | Record separator (§4) |
| **Comment** | the first byte is `#` | Never part of a value; does not end the record (§3.3) |
| **Continuation** | the line begins with exactly two spaces (`0x20 0x20`) | Appends to the previous field (§6) |
| **Field** | the line matches `^[a-z][a-z0-9-]*: .` | A `key: value` pair (§5) |
| **Invalid** | anything else | Parse error |

A line consisting only of whitespace (spaces or tabs) is **Invalid**, not Blank.
This is deliberate.
A "blank" line with a trailing space would otherwise fail to separate two records and silently merge
them, which is exactly the class of invisible-byte bug this format exists to eliminate.
The linter reports it as `E011` with the byte offset of the offending whitespace.

A TAB (`0x09`) is legal **inside a value** and illegal as **leading indentation**.
A line beginning with a TAB is Invalid.

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

A Continuation line begins with exactly two spaces.
The two spaces are stripped; everything after them, byte-exact, is appended to the value of the most
recent Field line, preceded by one LF.

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
   `    x` (four spaces) continues the value with `  x`.
2. A Continuation line with no preceding Field line in the current record is `E015`.
3. A Blank line ends the record even if the author intended the value to continue.
   There is exactly one record separator and it always wins.
   A value therefore cannot contain a blank line; use a single LF between paragraphs, or two records.
4. Continuations are permitted **only** on keys marked *multi-line* in §9.
   In particular `pattern`, `context-require`, and `context-deny` are **single-line only** (`E016`).
   Regexes never span lines.
   This makes the format free of any block-scalar sentinel, so there is no ambiguity between a value of
   `|` and a "here follows a block" marker - a problem the obvious YAML-shaped design would have had,
   given that `|` is exactly the character regexes are full of.

## 7. Reference parse algorithm

Non-normative, but a conforming parser produces the same result.

```
records = []
cur = null          # {order: [], fields: {}, line: N}
last_key = null

for (lineno, raw) in lines(file):          # after the §3.1 file checks
    if raw == "":                          # Blank
        if cur: records.append(cur); cur = null
        last_key = null
        continue
    if raw[0] == "#":                      # Comment: record continues, field does not
        last_key = null
        continue
    if raw starts with "  ":               # Continuation
        if cur == null:      error E015    # no record open
        if last_key == null: error E012    # a comment intervened
        if last_key not multi-line in schema: error E016
        cur.fields[last_key][-1] += "\n" + raw[2:]
        continue
    m = match ^([a-z][a-z0-9-]*): (.+)$ against raw
    if not m:
        if raw is all whitespace:                    error E011
        if raw matches ^[a-z][a-z0-9-]*:[ ]*$:       error E013   # empty value
        error E010
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

| Path | Schema |
|---|---|
| `modules/sast/rules/*.rules`, `modules/iac/*.rules` | **pattern rule** (§9.1) |
| `rules/derived.rules` | **derived finding** (§9.2) |
| `rules/redaction.rules` | **redaction rule** (§9.3) |
| `config/scope.conf` | **scope target** (§9.4) |
| `config/scanner.conf`, `config/auth.conf`, `config/discovery.conf`, `config/posture.conf`, `data/severity-rubric.conf` | operator config, one schema per file, keys defined alongside their consumer |

An unknown key in any schema is `E017`.
Unknown keys are an error and not a warning, because a typo in `context-deny` would otherwise silently
disable a false-positive guard and flood the report.

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

- The `MODULE` component MUST match the module that owns the rule pack (`E018`).
- The id MUST be unique across **every** record file in the repository (`E019`), not merely within its
  own file.
- The id is **stable forever**.
  It is the SARIF `ruleId`, the Appendix A check id, an input to the finding fingerprint, and the key
  for `covered_checks` in `state/`.
  Renaming a check id makes every historical finding for that check `fixed` and every current one `new`.
  To retire a check, delete the record and add its id to `rules/RETIRED.txt`; the linter fails if a
  retired id is ever reused.
- There is **no per-occurrence sequence number** anywhere in the system.
  The `-01` suffix distinguishes sibling rules of one family, not occurrences of a match.
  Per-occurrence identity is the fingerprint (`docs/FOUNDATION.md` tensions 5 and 7).

#### 9.1.2 `files` globs

A glob is matched against the **repository-relative path** with `/` separators, using these operators
and no others:

- `*` matches any run of characters except `/`.
- `**` matches any run of characters including `/`, and is only legal as a whole path segment.
- `?` matches one character except `/`.
- `[abc]` and `[a-z]` match one character from the set.
- A leading `/` anchors to the repository root; without it the glob may match at any depth.

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
| `target` | The scope target name (`config/scope.conf` `name`) |
| `account` | AWS account id |
| `account-region` | AWS account id and region |
| `file` | Repository-relative file path |

Contributors that lack the correlation key cannot participate in a correlated composite.
The composite fires once per distinct correlation value for which the `requires` / `any-of` predicate
holds, and the correlation value is part of the composite's fingerprint.

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

The engine gets candidate line numbers for a file in one pass (`rg -n` or `grep -n`), then evaluates
windows for all matches in that file in a second single pass over the file, rather than re-reading the
file once per match.
Per-file match count is capped by `max_matches_per_file` from `config/scanner.conf` (default 200); on
overflow the engine emits the findings it has plus one `info` finding recording the truncation, and
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
| E010 | error | Line matches no line kind in §3.2 |
| E011 | error | Line contains only whitespace (not a valid record separator) |
| E012 | error | Comment line between a field line and its continuations |
| E013 | error | Field line with an empty value |
| E014 | error | Duplicate *single* key in one record |
| E015 | error | Continuation line with no preceding field |
| E016 | error | Continuation on a key that is single-line only |
| E017 | error | Unknown key for the file's schema |
| E018 | error | `id` module component does not match the owning module |
| E019 | error | Duplicate `id` across all record files |
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
| E027 | error | `id` does not match the §9.1.1 regex, or carries a `SEQ` suffix in the derived schema, or omits one in any other schema |
| E028 | error | `id` appears in `rules/RETIRED.txt` |
| E029 | error | `severity-floor` is above `severity-ceiling` |
| E043 | error | `intrusive` tag on a pattern rule |
| E044 | error | No type tag, or more than one type tag |
| E045 | error | `format-version` present and not `1` |

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
| E053 | error | `correlate-on` value that a contributor's module cannot supply |

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
