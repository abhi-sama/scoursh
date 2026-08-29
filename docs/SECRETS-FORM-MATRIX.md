# The secrets-rule assignment-form matrix

This document records what `modules/sast/rules/secrets.rules` caught **before**
this ticket and what it catches **after**, measured against a dedicated tree of
planted controls at `tests/fixtures/sast-secret-forms/`.

It exists because the miss it fixes was found by planting a positive control, not
by reading the rules.
A secrets scanner's false negative is the product silently failing at its one
job - worse than a crash, because the operator reads a clean report and believes
it - so "which forms does it actually catch" has to be a measured table rather
than an inference from a regex.

Every value in the fixture tree is a **fake test value** that opens nothing.
The forms below carry `<VALUE>` and `<SHORT>` in place of those strings so that
this document does not itself become a match when `secrets.rules` is pointed at
this repository - the pattern engine has no comment awareness anywhere
(`AGENTS.md`), so prose that spells a hazard *is* the hazard.

## The headline

| | before | after |
|---|---|---|
| positive controls caught | **7 of 47** | **47 of 47** |
| negative controls flagged | 0 of 32 | 0 of 32 |
| findings on this repository outside its own test material | 0 | 0 |

The reported bug - an uppercase, double-quoted, seven-byte assignment in a
`.env` file - is control **P15**, and it failed for **two independent reasons**
at once, which is why fixing either alone would still have missed it:

1. the identifier pattern was lowercase-only, so `DB_PASSWORD` never matched, and
2. the value floor was 8 bytes, so a seven-byte value could not have matched
   even had the case been right.

## Which forms are covered, and which are deliberately not

Chosen deliberately as a matrix rather than by patching the two forms the report
named:

- **identifier case** - lowercase, UPPERCASE, Capitalised, `camelCase`, and
  `SCREAMING_SNAKE` with a prefix (`DB_PASSWORD`). All covered.
- **quoting** - unquoted, `'single'`, `"double"`, and `` `backtick` ``. All covered.
- **spacing** - none, and spaces on either side of the separator. Covered.
- **separator** - `=` and `:`. Covered.
- **prefixes** - `export `, `readonly `, Dockerfile `ENV`/`ARG`, and a
  command-prefix assignment (`VAR=value cmd`). Covered.
- **inline trailing comments** - every control in the tree carries one, since the
  tag itself is a trailing comment. Covered by construction.
- **keyword family** - `password`, `passwd`, `pwd`, `passphrase`, `secret`,
  `client_secret`, `api_key`/`apiKey`, `token`, `access_key`, `credentials`.
  Covered.
- **file types** - `.env`, shell, YAML, JSON, CI workflow YAML, and Dockerfile.
  Covered. `secrets.rules` ships **no `files:` glob** by design, so it reads
  every file in the tree it is pointed at; the file types above are therefore a
  test of the *forms* those files conventionally use, not of per-extension
  wiring.

**Deliberately not covered, and why:**

- **Multi-line and heredoc values where the value is on a different line from its
  keyword.** This is an architectural limit, not a rule defect:
  `rules/RULE-FORMAT.md` §8.2 freezes matching as line-oriented ("a pattern can
  never match across a newline"), so no pattern rule can reach it. Lifting it
  means a new matching mode in a FROZEN format - a register change, not a regex
  change. The three shapes are pinned in `multiline.py` as `G01`-`G03` (tagged
  `G`, not `P`) precisely so the gap stays visible instead of being silently
  assumed covered. A heredoc whose *body line* carries the keyword and value
  together **is** caught - that is control P34.
- **An unquoted, all-lowercase value made only of letters joined by `.` `_` `-`
  or `/`.** That shape is an identifier, a dotted name or a relative path far
  more often than a credential, and treating it as a secret produced real noise
  against scoursh's own tree. The cost is stated in the pack header: an unquoted
  all-lowercase hyphenated password is not reported. Quoting lifts the guard,
  because quoting is itself an authoring signal.
- **A quoted value containing spaces** (a multi-word passphrase). Admitting a
  space inside the quotes lets the match run from one string's opening quote to
  a *later* string's quote on the same line, and no `context-deny` can tell that
  apart from a real one. The pack header carries the same note.
- **A credential-shaped value under no credential-naming identifier at all**
  (`x = "<VALUE>"`). Nothing distinguishes it from any other string constant, and
  a rule that flags it flags every string in the repository. That is entropy
  detection - a different mechanism, and the job of the vendored gitleaks
  adapter (`modules/sast/adapters/gitleaks/`), which this pack deliberately does
  not duplicate.

## Precision, which is a cost and not an afterthought

A rule set that flags every `KEY=value` line trains operators to ignore the tool,
which is the same outcome as missing the secret. Three mechanisms hold the line,
each with its own negative controls in the tree:

1. **A reference is not a literal.** `${VAR}`, `$VAR`, `$(cmd)`, `{{ ... }}`
   templates, `${{ secrets.* }}`, and a YAML `!secret` tag are all denied
   (N01, N02, N20, N21, N41, N42, N43, N44, N50, N60, N70, N71).
2. **A name about a credential is not a credential.** `*_FILE`, `*_PATH`,
   `*_MIN_LENGTH`, `*_REGEX`, `*_REQUIRED`, `*_HEADER`, `passwordPolicy`, and a
   bare `value:` that names nothing are denied (N04-N08, N12, N22, N40, N46,
   N51, N52, N61).
3. **An obvious placeholder is not a secret.** `changeme`, `placeholder`,
   `your_api_key_here` (N09, N10, N11).
4. **There has to be a value at all, and it has to look like one.** An empty
   assignment, a bare key with nothing after the separator, a boolean, a bare
   integer, a prompt that *reads* a password rather than setting one, and a
   test on an unset variable are all quiet (N03, N23, N24, N45, N47, N52).

Measured noise, with the new rules over the whole repository: **112 findings,
every one of them inside `tests/fixtures/`, `tests/suites/` or `tests/e2e/`**,
which is where test credentials are supposed to live. Nothing in `lib/`,
`scan.sh`, `tools/`, `config/` or `docs/`. `tests/fixtures/clean/` - the shared
tree every pack asserts silence over - returns **zero** findings, so this pack
starts no cross-fire.

## What the widening costs in scan time

Measured on this repository, one full `sast` walk with this pack alone:
**17s before, 42s after** - roughly 2.5x. The pack goes from 5 records to 7,
and the two new ones carry the widest patterns in it, so every file is read
against two more expensive regexes.

That cost is in the *primary patterns*, not in the precision guards, and this
was measured rather than assumed: consolidating the 15 shared `context-deny`
lines into 5 equivalent alternations - which cuts the per-candidate
`scan_match` subprocess count by two thirds - moved the total from 42s to 41s
and was reverted for that reason. Fifteen lines each denying one concern are
far easier to audit than five dense alternations, and the trade only makes
sense if it buys something. It does not.

Anyone optimising this later should start from the two new records' patterns,
and should re-measure rather than reasoning from the shape of the rule file.

## The full table

Regenerate it by running `tests/suites/sast-secrets-forms.sh`, which asserts
every row of it. `before` is `modules/sast/rules/secrets.rules` as of `a656663`;
`after` is this branch.

| control | form | file | before | after | check |
|---|---|---|---|---|---|
| N01 | `PASSWORD=${DB_PASSWORD}` | `dotenv.env` | quiet | quiet | - |
| N02 | `PASSWORD=$DB_PASSWORD` | `dotenv.env` | quiet | quiet | - |
| N03 | `DB_PASSWORD=` | `dotenv.env` | quiet | quiet | - |
| N04 | `PASSWORD_FILE=/run/secrets/db_password` | `dotenv.env` | quiet | quiet | - |
| N05 | `DB_PASSWORD_PATH=./secrets/db.txt` | `dotenv.env` | quiet | quiet | - |
| N06 | `PASSWORD_MIN_LENGTH=12` | `dotenv.env` | quiet | quiet | - |
| N07 | `PASSWORD_REGEX=^[A-Za-z0-9]{10,}$` | `dotenv.env` | quiet | quiet | - |
| N08 | `PASSWORD_REQUIRED=true` | `dotenv.env` | quiet | quiet | - |
| N09 | `DB_PASSWORD="changeme"` | `dotenv.env` | quiet | quiet | - |
| N10 | `API_KEY="your_api_key_here"` | `dotenv.env` | quiet | quiet | - |
| N11 | `DB_PASSWORD="placeholder"` | `dotenv.env` | quiet | quiet | - |
| N12 | `API_KEY_HEADER=X-Api-Key` | `dotenv.env` | quiet | quiet | - |
| N20 | `export DB_PASSWORD="$VAULT_DB_PASSWORD"` | `deploy.shell` | quiet | quiet | - |
| N21 | `export DB_PASSWORD="$(vault kv get -field=password secret/db)"` | `deploy.shell` | quiet | quiet | - |
| N22 | `PASSWORD_FILE="/run/secrets/db_password"` | `deploy.shell` | quiet | quiet | - |
| N23 | `read -rsp 'password: ' DB_PASSWORD` | `deploy.shell` | quiet | quiet | - |
| N24 | `if [[ -z ${DB_PASSWORD:-} ]]; then echo 'password: not set' >&2; fi` | `deploy.shell` | quiet | quiet | - |
| N40 | `value: "<VALUE>"` | `config.yml` | quiet | quiet | - |
| N41 | `password: "{{ .Values.dbPassword }}"` | `config.yml` | quiet | quiet | - |
| N42 | `masterPassword: '{{resolve:secretsmanager:app/db/password}}'` | `config.yml` | quiet | quiet | - |
| N43 | `password: !secret db_password` | `config.yml` | quiet | quiet | - |
| N44 | `password: ${DB_PASSWORD}` | `config.yml` | quiet | quiet | - |
| N45 | `automountServiceAccountToken: false` | `config.yml` | quiet | quiet | - |
| N46 | `passwordPolicy: strict` | `config.yml` | quiet | quiet | - |
| N47 | `password:` | `config.yml` | quiet | quiet | - |
| N50 | `"_case": "[[N50]]", "Password": "${DB_PASSWORD}",` | `appsettings.json` | quiet | quiet | - |
| N51 | `"_case": "[[N51]]", "PasswordFile": "/run/secrets/db_password",` | `appsettings.json` | quiet | quiet | - |
| N52 | `"_case": "[[N52]]", "PasswordMinLength": 12` | `appsettings.json` | quiet | quiet | - |
| N60 | `ENV DB_PASSWORD=${DB_PASSWORD}` | `Dockerfile` | quiet | quiet | - |
| N61 | `ENV PASSWORD_FILE=/run/secrets/db_password` | `Dockerfile` | quiet | quiet | - |
| N70 | `DB_PASSWORD: ${{ secrets.DB_PASSWORD }}` | `ci-workflow.yml` | quiet | quiet | - |
| N71 | `API_KEY: $API_KEY` | `ci-workflow.yml` | quiet | quiet | - |
| P01 | `password="<VALUE>"` | `dotenv.env` | found | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P02 | `PASSWORD="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P03 | `Password="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P04 | `DB_PASSWORD="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P05 | `dbPassword="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P06 | `password='<VALUE>'` | `dotenv.env` | found | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P07 | `password=`<VALUE>`` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P08 | `DB_PASSWORD=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P09 | `password=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P10 | `password = "<VALUE>"` | `dotenv.env` | found | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P11 | `DB_PASSWORD = <VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P12 | `password: "<VALUE>"` | `dotenv.env` | found | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P13 | `export DB_PASSWORD="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P14 | `export DB_PASSWORD=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P15 | `DB_PASSWORD="<SHORT>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P16 | `DB_PASSWORD=<SHORT>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P17 | `PASSWD="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P18 | `PASSPHRASE="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P19 | `SECRET_KEY="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_SECRET-01 |
| P20 | `CLIENT_SECRET=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P21 | `AUTH_TOKEN="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_SECRET-01 |
| P22 | `ACCESS_TOKEN=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P23 | `API_KEY="<VALUE>"` | `dotenv.env` | found | found | SAST-SEC-GENERIC_API_KEY-01 |
| P24 | `API_KEY=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P25 | `apiKey="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_API_KEY-01 |
| P26 | `ACCESS_KEY_SECRET=<VALUE>` | `dotenv.env` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P27 | `DB_CREDENTIALS="<VALUE>"` | `dotenv.env` | MISS | found | SAST-SEC-GENERIC_SECRET-01 |
| P30 | `export DB_PASSWORD="<VALUE>"` | `deploy.shell` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P31 | `export DB_PASSWORD=<VALUE>` | `deploy.shell` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P32 | `readonly API_KEY="<VALUE>"` | `deploy.shell` | found | found | SAST-SEC-GENERIC_API_KEY-01 |
| P33 | `DB_PASSWORD=<VALUE> psql -h localhost` | `deploy.shell` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P34 | `DB_PASSWORD=<VALUE>` | `deploy.shell` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P40 | `password: "<VALUE>"` | `config.yml` | found | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P41 | `passwd: <VALUE>` | `config.yml` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P42 | `PASSWORD: '<VALUE>'` | `config.yml` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P43 | `apiKey: "<VALUE>"` | `config.yml` | MISS | found | SAST-SEC-GENERIC_API_KEY-01 |
| P44 | `client_secret: <VALUE>` | `config.yml` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P45 | `- DB_PASSWORD=<VALUE>` | `config.yml` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P50 | `"_case": "[[P50]]", "Password": "<VALUE>",` | `appsettings.json` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P51 | `"_case": "[[P51]]", "ApiKey": "<VALUE>",` | `appsettings.json` | MISS | found | SAST-SEC-GENERIC_API_KEY-01 |
| P52 | `"_case": "[[P52]]", "connectionPassword": "<VALUE>",` | `appsettings.json` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P60 | `ENV DB_PASSWORD="<VALUE>"` | `Dockerfile` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P61 | `ENV DB_PASSWORD=<VALUE>` | `Dockerfile` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P62 | `ARG API_KEY=<VALUE>` | `Dockerfile` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P70 | `DB_PASSWORD: "<VALUE>"` | `ci-workflow.yml` | MISS | found | SAST-SEC-GENERIC_PASSWORD-01 |
| P71 | `API_KEY: <VALUE>` | `ci-workflow.yml` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
| P72 | `- run: DEPLOY_TOKEN=<VALUE> ./deploy` | `ci-workflow.yml` | MISS | found | SAST-SEC-ENV_ASSIGNMENT-01 |
