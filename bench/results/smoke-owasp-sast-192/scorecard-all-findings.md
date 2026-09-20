# Detection scorecard

Corpus categories: `cmdi crypto hash ldapi pathtraver sqli weakrand xss`

Cases: 192 (96 real, 96 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| scoursh | `0.1.0-dev+803503f3d515` | `20cbf3d11123347e47ed89541e6942836def53f7` | sqli cmdi ldapi pathtraver crypto hash weakrand xss terraform-aws |
| semgrep | `1.176.0` | `20cbf3d11123347e47ed89541e6942836def53f7` | sqli cmdi ldapi pathtraver crypto hash weakrand xss |

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh | cmdi | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | crypto | 0 | 12 | 5 | 7 | 0.000 | 0.417 | 0.000 | -0.417 |
| scoursh | hash | 2 | 10 | 0 | 12 | 0.167 | 0.000 | 1.000 | +0.167 |
| scoursh | ldapi | 12 | 0 | 12 | 0 | 1.000 | 1.000 | 0.500 | +0.000 |
| scoursh | pathtraver | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | sqli | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | weakrand | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | xss | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| semgrep | cmdi | 10 | 2 | 6 | 6 | 0.833 | 0.500 | 0.625 | +0.333 |
| semgrep | crypto | 12 | 0 | 0 | 12 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | hash | 6 | 6 | 0 | 12 | 0.500 | 0.000 | 1.000 | +0.500 |
| semgrep | ldapi | 11 | 1 | 8 | 4 | 0.917 | 0.667 | 0.579 | +0.250 |
| semgrep | pathtraver | 10 | 2 | 7 | 5 | 0.833 | 0.583 | 0.588 | +0.250 |
| semgrep | sqli | 12 | 0 | 4 | 8 | 1.000 | 0.333 | 0.750 | +0.667 |
| semgrep | weakrand | 12 | 0 | 0 | 12 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | xss | 9 | 3 | 1 | 11 | 0.750 | 0.083 | 0.900 | +0.667 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh | 8 of 8 | 0 | 14 | 82 | 17 | 79 | 0.146 | 0.177 | 0.452 | -0.031 |
| semgrep | 8 of 8 | 0 | 82 | 14 | 26 | 70 | 0.854 | 0.271 | 0.759 | +0.583 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh | cmdi | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | crypto | 0 | 12 | 5 | 7 | 0.000 | 0.417 | 0.000 | -0.417 |
| scoursh | hash | 2 | 10 | 0 | 12 | 0.167 | 0.000 | 1.000 | +0.167 |
| scoursh | ldapi | 12 | 0 | 12 | 0 | 1.000 | 1.000 | 0.500 | +0.000 |
| scoursh | pathtraver | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | sqli | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | weakrand | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | xss | 0 | 12 | 0 | 12 | 0.000 | 0.000 | n/a | +0.000 |
| semgrep | cmdi | 10 | 2 | 6 | 6 | 0.833 | 0.500 | 0.625 | +0.333 |
| semgrep | crypto | 12 | 0 | 0 | 12 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | hash | 6 | 6 | 0 | 12 | 0.500 | 0.000 | 1.000 | +0.500 |
| semgrep | ldapi | 11 | 1 | 8 | 4 | 0.917 | 0.667 | 0.579 | +0.250 |
| semgrep | pathtraver | 10 | 2 | 7 | 5 | 0.833 | 0.583 | 0.588 | +0.250 |
| semgrep | sqli | 12 | 0 | 4 | 8 | 1.000 | 0.333 | 0.750 | +0.667 |
| semgrep | weakrand | 12 | 0 | 0 | 12 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | xss | 9 | 3 | 1 | 11 | 0.750 | 0.083 | 0.900 | +0.667 |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh | 8 of 8 | 0 | 14 | 82 | 17 | 79 | 0.146 | 0.177 | 0.452 | -0.031 |
| semgrep | 8 of 8 | 0 | 82 | 14 | 26 | 70 | 0.854 | 0.271 | 0.759 | +0.583 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| scoursh | 8 of 8 | none |
| semgrep | 8 of 8 | none |


## What this scorecard is not

- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
