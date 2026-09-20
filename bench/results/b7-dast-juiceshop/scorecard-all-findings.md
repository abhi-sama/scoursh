# Detection scorecard

Corpus categories: `cors info-disclosure missing-csp sqli`

Cases: 20 (14 real, 6 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Matching granularity: `file` - a case is flagged by any finding in its file.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| scoursh-dast | `0.1.0-dev+3b25a218a010` | `sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf` | cors missing-csp sqli info-disclosure |
| zap | `2.17.0` | `sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf` | cors missing-csp sqli info-disclosure |

## Finding volume (records, not cases)

| tool | records kept | dropped by severity | no line |
|---|---|---|---|
| scoursh-dast | 18 | 0 | 18 |
| zap | 588 | 0 | 588 |

These are RECORD counts. Every number in the tables below counts CASES, so a
tool reporting one defect five times moves this table and nothing else.

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh-dast | cors | 2 | 10 | 0 | 0 | 0.167 | n/a | 1.000 | n/a |
| scoursh-dast | info-disclosure | 0 | 0 | 1 | 3 | n/a | 0.250 | 0.000 | n/a |
| scoursh-dast | missing-csp | 1 | 0 | 0 | 0 | 1.000 | n/a | 1.000 | n/a |
| scoursh-dast | sqli | 0 | 1 | 0 | 2 | 0.000 | 0.000 | n/a | +0.000 |
| zap | cors | 4 | 8 | 0 | 0 | 0.333 | n/a | 1.000 | n/a |
| zap | info-disclosure | 0 | 0 | 2 | 2 | n/a | 0.500 | 0.000 | n/a |
| zap | missing-csp | 1 | 0 | 0 | 0 | 1.000 | n/a | 1.000 | n/a |
| zap | sqli | 0 | 1 | 0 | 2 | 0.000 | 0.000 | n/a | +0.000 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh-dast | 4 of 4 | 0 | 3 | 11 | 1 | 5 | 0.214 | 0.167 | 0.750 | +0.047 |
| zap | 4 of 4 | 0 | 5 | 9 | 2 | 4 | 0.357 | 0.333 | 0.714 | +0.024 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh-dast | cors | 2 | 10 | 0 | 0 | 0.167 | n/a | 1.000 | n/a |
| scoursh-dast | info-disclosure | 0 | 0 | 0 | 4 | n/a | 0.000 | n/a | n/a |
| scoursh-dast | missing-csp | 1 | 0 | 0 | 0 | 1.000 | n/a | 1.000 | n/a |
| scoursh-dast | sqli | 0 | 1 | 0 | 2 | 0.000 | 0.000 | n/a | +0.000 |
| zap | cors | 0 | 12 | 0 | 0 | 0.000 | n/a | n/a | n/a |
| zap | info-disclosure | 0 | 0 | 0 | 4 | n/a | 0.000 | n/a | n/a |
| zap | missing-csp | 0 | 1 | 0 | 0 | 0.000 | n/a | n/a | n/a |
| zap | sqli | 0 | 1 | 0 | 2 | 0.000 | 0.000 | n/a | +0.000 |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh-dast | 4 of 4 | 0 | 3 | 11 | 0 | 6 | 0.214 | 0.000 | 1.000 | +0.214 |
| zap | 4 of 4 | 0 | 0 | 14 | 0 | 6 | 0.000 | 0.000 | n/a | +0.000 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| scoursh-dast | 3 of 4 | info-disclosure  |
| zap | 1 of 4 | cors info-disclosure missing-csp  |


## What this scorecard is not

- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
