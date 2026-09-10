# Detection scorecard

Corpus categories: `cmdi crypto hash ldapi pathtraver securecookie sqli trustbound weakrand xpathi xss`

Cases: 2740 (1415 real, 1325 sanitized trap)

Severity filter: `any`. CWE equivalence classes: `bench/cwe-classes.conf`.

Youden J = TPR - FPR. **J = 0.000 is a coin flip.**

## Tools

| tool | version | corpus commit | claims |
|---|---|---|---|
| scoursh | `0.1.0-dev+8b637cae9ce6` | `20cbf3d11123347e47ed89541e6942836def53f7` | sqli cmdi ldapi pathtraver crypto hash weakrand xss terraform-aws |
| semgrep | `1.176.0` | `20cbf3d11123347e47ed89541e6942836def53f7` | sqli cmdi ldapi pathtraver crypto hash weakrand xss |
| semgrep-default | `1.176.0` | `20cbf3d11123347e47ed89541e6942836def53f7` | sqli cmdi ldapi pathtraver crypto hash weakrand xss |

## Per category - loose CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh | cmdi | 0 | 126 | 0 | 125 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | crypto | 0 | 130 | 27 | 89 | 0.000 | 0.233 | 0.000 | -0.233 |
| scoursh | hash | 28 | 101 | 0 | 107 | 0.217 | 0.000 | 1.000 | +0.217 |
| scoursh | ldapi | 27 | 0 | 32 | 0 | 1.000 | 1.000 | 0.458 | +0.000 |
| scoursh | pathtraver | 0 | 133 | 0 | 135 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | sqli | 0 | 272 | 0 | 232 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | weakrand | 0 | 218 | 0 | 275 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | xss | 0 | 246 | 0 | 209 | 0.000 | 0.000 | n/a | +0.000 |
| semgrep | cmdi | 112 | 14 | 96 | 29 | 0.889 | 0.768 | 0.538 | +0.121 |
| semgrep | crypto | 130 | 0 | 0 | 116 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | hash | 89 | 40 | 0 | 107 | 0.690 | 0.000 | 1.000 | +0.690 |
| semgrep | ldapi | 26 | 1 | 28 | 4 | 0.963 | 0.875 | 0.481 | +0.088 |
| semgrep | pathtraver | 120 | 13 | 106 | 29 | 0.902 | 0.785 | 0.531 | +0.117 |
| semgrep | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | sqli | 234 | 38 | 143 | 89 | 0.860 | 0.616 | 0.621 | +0.244 |
| semgrep | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | weakrand | 218 | 0 | 0 | 275 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | xss | 202 | 44 | 108 | 101 | 0.821 | 0.517 | 0.652 | +0.304 |
| semgrep-default | cmdi | 117 | 9 | 109 | 16 | 0.929 | 0.872 | 0.518 | +0.057 |
| semgrep-default | crypto | 130 | 0 | 0 | 116 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep-default | hash | 89 | 40 | 0 | 107 | 0.690 | 0.000 | 1.000 | +0.690 |
| semgrep-default | ldapi | 26 | 1 | 28 | 4 | 0.963 | 0.875 | 0.481 | +0.088 |
| semgrep-default | pathtraver | 120 | 13 | 106 | 29 | 0.902 | 0.785 | 0.531 | +0.117 |
| semgrep-default | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | sqli | 253 | 19 | 170 | 62 | 0.930 | 0.733 | 0.598 | +0.197 |
| semgrep-default | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | weakrand | 218 | 0 | 0 | 275 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep-default | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | xss | 202 | 44 | 108 | 101 | 0.821 | 0.517 | 0.652 | +0.304 |

### Corpus aggregate - loose (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh | 8 of 11 | 3 | 55 | 1226 | 59 | 1172 | 0.043 | 0.048 | 0.482 | -0.005 |
| semgrep | 8 of 11 | 3 | 1131 | 150 | 481 | 750 | 0.883 | 0.391 | 0.702 | +0.492 |
| semgrep-default | 8 of 11 | 3 | 1155 | 126 | 521 | 710 | 0.902 | 0.423 | 0.689 | +0.479 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Per category - strict CWE matching

| tool | category | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| scoursh | cmdi | 0 | 126 | 0 | 125 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | crypto | 0 | 130 | 27 | 89 | 0.000 | 0.233 | 0.000 | -0.233 |
| scoursh | hash | 28 | 101 | 0 | 107 | 0.217 | 0.000 | 1.000 | +0.217 |
| scoursh | ldapi | 27 | 0 | 32 | 0 | 1.000 | 1.000 | 0.458 | +0.000 |
| scoursh | pathtraver | 0 | 133 | 0 | 135 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | sqli | 0 | 272 | 0 | 232 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | weakrand | 0 | 218 | 0 | 275 | 0.000 | 0.000 | n/a | +0.000 |
| scoursh | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| scoursh | xss | 0 | 246 | 0 | 209 | 0.000 | 0.000 | n/a | +0.000 |
| semgrep | cmdi | 112 | 14 | 96 | 29 | 0.889 | 0.768 | 0.538 | +0.121 |
| semgrep | crypto | 130 | 0 | 0 | 116 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | hash | 89 | 40 | 0 | 107 | 0.690 | 0.000 | 1.000 | +0.690 |
| semgrep | ldapi | 26 | 1 | 28 | 4 | 0.963 | 0.875 | 0.481 | +0.088 |
| semgrep | pathtraver | 120 | 13 | 106 | 29 | 0.902 | 0.785 | 0.531 | +0.117 |
| semgrep | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | sqli | 234 | 38 | 143 | 89 | 0.860 | 0.616 | 0.621 | +0.244 |
| semgrep | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | weakrand | 218 | 0 | 0 | 275 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep | xss | 202 | 44 | 108 | 101 | 0.821 | 0.517 | 0.652 | +0.304 |
| semgrep-default | cmdi | 117 | 9 | 109 | 16 | 0.929 | 0.872 | 0.518 | +0.057 |
| semgrep-default | crypto | 130 | 0 | 0 | 116 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep-default | hash | 89 | 40 | 0 | 107 | 0.690 | 0.000 | 1.000 | +0.690 |
| semgrep-default | ldapi | 26 | 1 | 28 | 4 | 0.963 | 0.875 | 0.481 | +0.088 |
| semgrep-default | pathtraver | 120 | 13 | 106 | 29 | 0.902 | 0.785 | 0.531 | +0.117 |
| semgrep-default | securecookie | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | sqli | 253 | 19 | 170 | 62 | 0.930 | 0.733 | 0.598 | +0.197 |
| semgrep-default | trustbound | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | weakrand | 218 | 0 | 0 | 275 | 1.000 | 0.000 | 1.000 | +1.000 |
| semgrep-default | xpathi | - | - | - | - | *no coverage* | *no coverage* | *no coverage* | *no coverage* |
| semgrep-default | xss | 202 | 44 | 108 | 101 | 0.821 | 0.517 | 0.652 | +0.304 |

### Corpus aggregate - strict (claimed categories only)

| tool | categories scored | categories with no coverage | TP | FN | FP | TN | recall | FPR | precision | Youden J |
|---|---|---|---|---|---|---|---|---|---|---|
| scoursh | 8 of 11 | 3 | 55 | 1226 | 59 | 1172 | 0.043 | 0.048 | 0.482 | -0.005 |
| semgrep | 8 of 11 | 3 | 1131 | 150 | 481 | 750 | 0.883 | 0.391 | 0.702 | +0.492 |
| semgrep-default | 8 of 11 | 3 | 1155 | 126 | 521 | 710 | 0.902 | 0.423 | 0.689 | +0.479 |

This aggregate spans one corpus and the categories each tool CLAIMS.
It is not comparable with any other corpus, and it is not an overall score.

## Strict/loose agreement

| tool | categories where strict and loose agree | disagreeing categories |
|---|---|---|
| scoursh | 8 of 8 | none |
| semgrep | 8 of 8 | none |
| semgrep-default | 8 of 8 | none |


## What this scorecard is not

- It is **not** an overall score. Every number above is scoped to one corpus
  and one category, and the aggregate rows say exactly which categories went
  into them and how many were excluded as no-coverage.
- A `no coverage` cell is **not** a zero. It records that the tool never
  claimed the category, which is a scope boundary and not a detection failure.
- Nothing here is measured on any tool's own test fixtures. A tool scored on a
  corpus it was authored against is measuring "still passes its own cases".
