# B6 secrets leg — leaky-repo, hand-labelled

**This is the B6 secrets leg.** Its siblings are the two IaC halves,
`bench/results/b6-iac-terragoat-aws/` and `bench/results/b6-iac-kubernetes-goat/`.
None of it is published anywhere in `docs/` — that is ticket B9.

## SecretBench is NOT MEASURED, and here is the reason

The ticket names SecretBench (`setu1421/SecretBench`, MSR'23) as the corpus, and
the scout report's §4.2 lists it as the best neutral secrets corpus. **It is not
obtainable in this environment**, and this is a scope boundary rather than a
result:

- The repository of that name holds only metadata — a file-type census, a
  language census, and a spreadsheet of the regular expressions used to mine
  the data. It contains none of the 97,479 labelled secrets.
- The dataset itself lives in **Google BigQuery** (the labels) and **Google
  Cloud Storage** (the 818 mined repositories), so using it needs a Google
  Cloud account.
- Its own README states that researchers "need to contact us … a data
  protection agreement has to be signed … later, we will give access to the
  dataset using their email addresses." Access is granted per email address by
  its authors.

None of those three is something a benchmark run can satisfy on its own. This
is recorded as an explicit **not-measured** cell, in the language rule R4 uses
for a category a tool never claimed — a zero would say the corpus was tried and
failed. Obtaining it is a real follow-up: it needs an account, a signed
agreement and a wait, and it would materially strengthen this leg because it is
the only secrets corpus with third-party labels at scale.

## What was measured instead

| | |
|---|---|
| Corpus | `Plazmaz/leaky-repo` @ `2e951359cac53addbee56437da3ffb546e3dfe24` (MIT), whole tree |
| Ground truth | `bench/labels/leaky-repo.truth` — **hand-authored for this leg and committed**, rationale beside every case |
| Cases | **82**: 65 planted credentials, 17 negative controls |
| scoursh | `0.1.0-dev+0be15e965f28`, `scan.sh sast --format json`, defaults, **not `--use-engines`**, **not `--history`**, output **not** filtered to `SAST-SEC-*` |
| Gitleaks | `8.30.1`, `gitleaks dir --exit-code 0`, default rule set, **working tree** |
| TruffleHog | `3.97.4`, `trufflehog filesystem --no-verification`, default detectors, `.git/` excluded |
| Host | one macOS machine, one run each |

**Why leaky-repo.** It is MIT, third-party, unchanged since 2020, and
deliberately seeded with the credential-bearing files that most often reach a
public repository by accident. Its author states plainly that none of the values
are real — they are randomised or redacted reproductions of shapes seen in the
wild, which is what makes the raw outputs in this directory publishable at all.

**Its relationship to the tools, disclosed rather than left to be found.** It is
not any scanned tool's own fixture set, which is what methodology rule R1
requires. It does ship `.leaky-meta/benchmarking/*.md` reporting how Gitleaks,
TruffleHog, gitrob and detect-secrets scored against it, so a tool author could
have tuned against it at some point since 2019. That is a weaker relationship
than authorship, and it cuts against scoursh rather than for it.

**Two decisions that could each have flattered scoursh, and were not taken:**

- **scoursh's output is not filtered to the `SAST-SEC-*` family.** scoursh has no
  secrets-only mode and `scan.sh` has no per-check selection flag, so
  `scan.sh sast` is what an operator runs. Filtering could only ever REMOVE a
  record from inside a labelled range, and a labelled range here is either a
  planted credential or a negative control — so it could only lower scoursh's
  false-positive count, never raise it.
- **`.git/` is excluded for TruffleHog.** `trufflehog filesystem` walks
  `.git/objects/` and reported the same credentials twice, once from the working
  tree and once from the loose object: 12 of its 24 findings were duplicates.
  Gitleaks `dir` and scoursh read only the working tree. Excluding it puts all
  three on one surface and can only LOWER TruffleHog's count.

## The numbers

All findings, loose matching, line granularity, window 0:

| tool | TP | FN | FP | TN | recall | FPR | precision | **Youden J** |
|---|---|---|---|---|---|---|---|---|
| scoursh-secrets | 33 | 32 | 0 | 17 | 0.508 | 0.000 | 1.000 | **+0.508** |
| gitleaks | 21 | 44 | 0 | 17 | 0.323 | 0.000 | 1.000 | **+0.323** |
| trufflehog | 9 | 56 | 1 | 16 | 0.138 | 0.059 | 0.900 | **+0.079** |

**scoursh finds more of this corpus's planted credentials than either
specialist, with no false positives.** That is the honest reading of the table
and it should be stated with its cause attached, because the cause bounds how
far it generalises.

### Why, and what it does not mean

**This corpus is dominated by generic key-value credentials in configuration
files**, and that is precisely what `modules/sast/rules/secrets.rules` was
widened to catch — the 47-of-47 assignment-form widening `AGENTS.md` records,
measured against `tests/fixtures/sast-secret-forms/`. The 16 cases scoursh finds
and both specialists miss are all of that shape: a `"password":` key in four
different editor sftp configs, `AdminPassword=` in a Ventrilo ini,
`"sshPassphrase"` and `"sshUserPassword"` in a Robomongo connection,
`DB_PASSWORD` / `REDIS_PASSWORD` / `MAIL_PASSWORD` in a Laravel `.env`,
`$dbpasswd` in a PHP config, `GMAIL_PASSWORD` in a shell rc.

**The six cases a specialist finds and scoursh misses are the mirror image** —
all of them provider-shaped or encoded rather than keyword-shaped: the base64
`auth` blob in two Docker registry configs (twice each), an npm registry
`_authToken`, and a MongoDB connection URI with the credential in the userinfo.
Gitleaks and TruffleHog carry named detectors for those; scoursh has no rule
that recognises a credential with no keyword beside it.

So the result is a fact about **this corpus's composition** as much as about the
tools. A corpus weighted toward provider-issued tokens - which is what
SecretBench is, and what a scan of real GitHub repositories would produce -
would move the ranking, and this leg cannot say by how much. **Do not restate
this as "scoursh beats Gitleaks at secret detection."** The defensible sentence
is: *on a corpus of the credential-bearing config files that leak by accident,
scoursh's generic-assignment rules found half the planted secrets with no false
positives, where Gitleaks found a third and TruffleHog a seventh; on
provider-specific token shapes the ordering reverses.*

### What every tool missed

**26 of the 65 planted credentials were found by none of the three.** They are
the most useful part of this table, because they are a shared gap rather than a
comparison:

- **Positional and structured formats with no `key = value`**: `.netrc`
  (`machine … login … password pass123`), `.pgpass`
  (`host:port:db:user:password`), `.htpasswd` and `/etc/shadow` (`user:$hash:…`),
  a `.git-credentials` URL with the password in the userinfo, a Salesforce
  `conn.login('user', 'password', …)` call passing the credential positionally.
- **XML attribute and element values**: the two FileZilla stores and the
  JetBrains `WebServers.xml`.
- **A whole file that IS the secret**: `web/ruby/config/master.key` — 32 hex
  characters, no key name, no context.
- **Non-PEM private key formats**: the PuTTY `.ppk`'s `Private-Lines` section,
  which no `-----BEGIN`-anchored rule can see.
- **A credential dump**: ten bcrypt hashes inside a MySQL `INSERT`.
- **Framework constants**: Django's `SECRET_KEY`, Laravel's `APP_KEY`,
  WordPress's eight auth keys and salts, WordPress's `DB_PASSWORD`.

Several of these are a straightforward rule-authoring opportunity for scoursh
(`.netrc`, `.pgpass`, `.htpasswd`, `shadow`, FileZilla, `master.key` by
filename). The positional-argument case is not: a value on a line with no
keyword is reachable, but a value whose only signal is its POSITION in a call is
the shape `rules/RULE-FORMAT.md` §8.2's line-oriented matching handles worst.

### The negative controls

All 17 held for scoursh and Gitleaks. TruffleHog produced the leg's only false
positive: its `Box` detector fired on line 10 of `misc-keys/putty-example.ppk`,
which is inside the `Public-Lines` block — the PUBLIC half of a key pair.

The sharpest control is `high-entropy-misc.txt`: two maximum-entropy strings
that authenticate nothing, which leaky-repo's own `secrets.csv` scores 0 risk. A
tool scoring on Shannon entropy alone cannot pass that case and also catch
`web/ruby/config/master.key`, which is 32 hex characters alone in a file. **No
tool here flagged it**, and none of the three caught `master.key` either.

## Why only the all-findings column

Methodology rule R5 asks for a `--min-severity high` column beside the
all-findings one. **Neither Gitleaks nor TruffleHog emits a severity of any
kind** — a Gitleaks finding carries a rule id, an entropy score and the matched
bytes; a TruffleHog result carries a detector name and a verification state.
Both adapters map that to `medium` as a stated convention, so a high+critical
column would compare scoursh's real severities against a placeholder for two of
three tools and report both at zero recall. The same situation as Checkov CE in
the IaC leg, and the same treatment.

## Strict CWE matching is not defined here, and that is a statement

Every planted credential in this corpus is CWE-798. A strict-CWE column would
therefore separate no two cases and no two tools — it would be a tautology
rather than the independent check the scout report's §5.2 wants it to be. The
label file carries an empty `cwe` on every case and the scorer renders the
strict column as an explicit `no CWE in truth` cell rather than a row of zeros.

## The committed raw outputs are redacted, and that is the one place this leg
## departs from "raw output verbatim"

A secrets scanner's raw output contains, by construction, the credential it
matched — Gitleaks reports it in `Secret` and `Match`, TruffleHog in `Raw`,
`RawV2`, `Redacted` and `SecretParts`. `bench/run-tool.sh --redact-secret-values`
replaces each of those values with a `<redacted:N-bytes>` placeholder carrying
its byte length; **every other field is the tool's own output untouched**, so a
reader can still check every scoring decision this harness made against the
tool's own words. Each `MANIFEST` records that it happened, exactly as
`--portable-paths` does.

**It is not a precaution, it is a fix for a real refusal.** Committing the
unredacted output was tried first, and GitHub push protection declined the push,
naming a Slack API token at `gitleaks/raw/gitleaks.json:49`. That refusal was
correct: a security tool's own repository is the last place to normalise waving
a secret past a scanner, and the values here are fakes only because leaky-repo's
author says so — a future corpus's might not be. The right response was to stop
shipping the value, not to click the bypass link.

Two things about the redaction are worth knowing before changing it. It is
**fail-loud**: the first version's awk had an escaping bug, exited non-zero, and
left every credential in place while the MANIFEST still gained its "the matched
credential was replaced" line — so the awk's status is now checked and the run
fails rather than writing a claim it cannot honour. And it has an **object
pass** as well as a keyed one: TruffleHog's `SecretParts` keys vary by detector
(`key`, `token`, `connection_string`), so a fixed key list left two entire
private keys in the file until that pass existed. A `-----BEGIN` anywhere under
`raw/` now fails the run as a shape-independent backstop.

**The normalised records carry no secret value at all** and never did — both
adapters emit the rule id and the line and nothing else, deliberately, and
`tests/suites/bench-b6-labels.sh` asserts it.

## How to reproduce

```sh
bench/fetch-corpus.sh leaky-repo
for t in scoursh-secrets gitleaks trufflehog; do
  bench/run-tool.sh --tool "$t" \
    --root bench/corpora/leaky-repo --corpus leaky-repo \
    --out bench/results/b6-secrets-leaky-repo \
    --portable-paths --redact-secret-values
done
bench/score.sh --truth bench/labels/leaky-repo.truth \
  --results bench/results/b6-secrets-leaky-repo --match line --format md
```

## Runtime

167 files — still far below the size at which a runtime comparison means
anything: scoursh 78 s, TruffleHog 1 s, Gitleaks under 1 s. **Not a ratio** —
`bench/README.md`'s rule 4.
