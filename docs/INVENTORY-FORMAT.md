# The run inventory format

This document is normative and self-contained, in the same way `rules/RULE-FORMAT.md` is for records
and `docs/ADAPTERS.md` is for engine adapters.
It defines the two files modules exchange target-surface information through:

```
reports/<run>/inventory/endpoints.json
reports/<run>/inventory/parameters.json
```

`docs/FOUNDATION.md` tension 21 is the decision this implements, and it is the reason the files exist
at all: **modules never invoke each other and never import each other's code**, so the only channel
between SAST's route extraction, `aws/live/apigw.sh`, and the DAST crawler is an artifact in the run
directory with a frozen schema.
`docs/DESIGN.md` §7.5 is the source requirement ("a deduped `endpoints.json` + `parameters.json`
consumed by §7.3/§7.4").

## 1. Who writes these files, and who reads them

| Role | Component | Status |
|---|---|---|
| Producer | `modules/dast/crawl.sh` (DAST-04) | landed |
| Producer | SAST route extraction (`docs/DESIGN.md` §8.4) | not built |
| Producer | `modules/cloud/aws/live/apigw.sh` (§8.4) | not built |
| Consumer | every `docs/STEP5-DAST-PLAN.md` ticket in tiers 2-5 | not built |

Every consumer treats both files as **optional input**.
An absent, empty, or unreadable inventory is a normal state and is never an error; what a consumer owes
instead is a `coverage_gap` in `run.json` naming what was missing, which `lib/report.sh` renders in the
report's limitations section.

**A producer merges; it does not overwrite.**
`crawl.sh` reads whatever is already at `inventory/endpoints.json`, folds it into its own accumulator,
and writes the union back.
It reads from a **copy** taken before it writes, so an interrupted run cannot leave an inventory that
lost the routes another module contributed.

## 2. `endpoints.json`

```json
{
  "schema": "scoursh.inventory.endpoints/1",
  "run_id": "20260815T120000Z-ab12cd",
  "generated_by": "modules/dast/crawl.sh",
  "endpoints": [
    {
      "id": "3f9a1c02be77",
      "target": "my-target",
      "method": "GET",
      "url": "https://host.example/api/pets",
      "host": "host.example",
      "path": "/api/pets",
      "source": "crawl",
      "depth": 1,
      "status": "200",
      "content_type": "application/json"
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | 12 lowercase hex characters: the first 12 of the SHA-256 of `"<METHOD> <url>"`. The join key `parameters.json` refers to. |
| `target` | string | The `config/scope.conf` target id this endpoint belongs to - DAST's coverage cell (`rules/RULE-FORMAT.md` §9.5.1). |
| `method` | string | Uppercase HTTP method. |
| `url` | string | Absolute URL, **query string and fragment removed**. See §4. |
| `host` | string | The URL's host, split out so a consumer does not re-parse. |
| `path` | string | The URL's path, likewise. May contain a template segment such as `{petId}` when the source was a specification. |
| `source` | string | One of `crawl`, `openapi`, `postman`, `har`, `graphql`, `imported`. |
| `depth` | number | Crawl depth at which it was found; `0` for anything not found by following a link. |
| `status` | string | The observed HTTP status, or `""` when nothing was requested. |
| `content_type` | string | The observed `Content-Type`, or `""`. |

`source` is **never rewritten**.
An endpoint that arrived as `imported` stays `imported` even if the crawler later reaches the same URL,
because "SAST asserted this route exists" and "a request to this route was answered" are different
claims and tension 21 requires imported inventory to keep its audit trail.

## 3. `parameters.json`

```json
{
  "schema": "scoursh.inventory.parameters/1",
  "run_id": "20260815T120000Z-ab12cd",
  "generated_by": "modules/dast/crawl.sh",
  "parameters": [
    {
      "id": "b71e4409ac18",
      "endpoint_id": "3f9a1c02be77",
      "target": "my-target",
      "method": "GET",
      "url": "https://host.example/api/pets",
      "name": "limit",
      "location": "query",
      "source": "openapi",
      "example": "20"
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | 12 hex characters of the SHA-256 of `"<endpoint_id>|<location>|<name>"`. |
| `endpoint_id` | string | The `endpoints.json` entry this parameter belongs to. |
| `name` | string | The parameter name, verbatim from the target or the specification. **Untrusted.** |
| `location` | string | One of `query`, `body`, `path`, `header`, `cookie`, `formData`, `graphql`. |
| `source` | string | As for an endpoint. |
| `example` | string | An observed value, or `""`. See §5 - it is not a value to trust or to replay. |

`docs/DESIGN.md` §7.3 requires every injection probe to iterate "query params, body/JSON fields,
headers, and path segments - not just top-level query strings", which is what `location` is for.

## 4. Why the query string is not part of an endpoint

`?id=1` and `?id=2` are **one** endpoint with one parameter, not two endpoints.
Keeping them apart would turn a paginated listing into fifty endpoints, and every §7.3 probe would then
re-test the identical handler fifty times against one rate limit and one request budget.
The names go to `parameters.json`, which is the artifact the probes iterate.

A consumer that needs a concrete URL to send composes it from the endpoint's `url` plus the parameters
that name it.

## 5. `example` is redaction-processed, and is still not trustworthy

An observed value is a credential until proven otherwise, so two independent controls apply before one
reaches disk (`docs/FOUNDATION.md` tension 9):

1. The **value** goes through `redact` (`lib/findings.sh`, the frozen `rules/redaction.rules` pass),
   which recognises credential *shapes* - an AWS key id, a JWT, a private-key block.
2. The **name** is matched against a credential-name list (`password`, `token`, `session`, `csrf`, …),
   and a parameter whose name says it carries a credential has its example **dropped entirely**.

Neither control is sufficient alone and the pairing is deliberate.
Control 1 cannot recognise `password=hunter2` - no redaction rule can or should classify an arbitrary
human-chosen password by shape.
Control 2 cannot recognise a session token in a parameter innocently named `t`.
The residual gap - an unrecognised secret under an unsuggestive name - is stated here rather than
assumed away.

Values are additionally truncated (64 bytes).
`example` exists so a probe can construct a *plausible* baseline request; it is not a value to replay as
authentication and it is not evidence.

## 6. Everything in these files is untrusted input

A parameter name, a form action, and a URL all come off a scanned target and are therefore
attacker-controlled text (`docs/FOUNDATION.md` tension 10).
Two consequences bind every producer and every consumer:

- A producer writes every string through `lib/core.sh`'s `json_string` and never interpolates one into
  JSON at a call site.
- A consumer that puts one of these values into a report goes through `finding_set_evidence` or the
  emitter's own escaping, exactly as it would for any other target-derived text. The HTML report
  contains no `<script>` at all.

## 7. Reading the files without a JSON library

scoursh has no `jq` and no scan-time Python (`docs/DESIGN.md` §1).
`modules/dast/crawl_engine.sh`'s `crawl_json_flatten` is the reader: a purpose-built, depth- and
string-aware flattener that prints one line per scalar leaf as `path<TAB>type<TAB>raw-value`, with path
segments joined by US (0x1f).

Two properties of JSON's own grammar make that stream safe to read line by line from bash, and both are
why the raw value is emitted **still escaped**: a JSON string literal can contain neither a raw newline
nor a raw tab (RFC 8259 §7 requires both escaped), so there is exactly one output line per leaf and the
TAB split is unambiguous; and an object key cannot contain a literal US byte, so the path split is too.
`crawl_json_unescape` is the separate, caller-invoked step that decodes one field once it is about to be
used.

Because consumers read through the flattener rather than by matching the exact bytes a producer emits,
**a conformant producer may format the file however it likes** - pretty-printed, one line, any key
order. That is what "frozen schema" has to mean when three different modules write the same file.

## 8. What is bounded, and what happens when a bound bites

| Bound | Value | On reaching it |
|---|---|---|
| endpoints held per run | 5000 | further endpoints discarded, `coverage_gap` recorded |
| parameters held per run | 20000 | as above |
| pages fetched per target | 200 | crawl stops, `coverage_gap` recorded |
| response body parsed | 512 KiB | remainder not parsed for links |
| specification file read | 8 MiB | remainder not parsed |
| `example` value | 64 bytes | truncated |
| crawl depth | `crawl-depth`, default 3 | deeper links counted and recorded |

Only `crawl-depth` is operator-configurable, because `rules/RULE-FORMAT.md` §9.6.3 already froze it as a
config key; inventing keys for the rest would be a format change.
**No bound truncates silently.** A bound that did would be indistinguishable from a surface that was
really that small, which is the overstated coverage `docs/DESIGN.md` §15 forbids.

## 9. Changing this format

`schema` carries the version (`scoursh.inventory.endpoints/1`).
A change that removes or repurposes a field is a new major version and every consumer must be updated in
the same change; adding an **optional** field is not.
A consumer that meets a `schema` it does not know records a `coverage_gap` and treats the file as
absent - it never guesses.

Unlike `rules/RULE-FORMAT.md`, this format is **not** frozen against a fingerprint: nothing in these
files feeds a finding fingerprint, so a version bump invalidates no `state/` and no
`config/baseline.json`.
