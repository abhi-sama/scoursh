# Step 8 (`--paranoid` / netns) sub-ticket plan

This is a planning document only.
It contains no shell code and changes no behavior.
It exists so that step 8 - `docs/DESIGN.md` §13's "`--paranoid` enforcement + `tools/run-in-netns.sh`" -
can be picked up as two clean, independently reviewable tickets instead of being re-derived from
`docs/DESIGN.md` §2/§12 and `docs/FOUNDATION.md` tension 20 from scratch by whoever picks it up first.

This ticket (the one that produced this document) is planning-only, mirroring how
`docs/STEP5-DAST-PLAN.md` was produced without implementing any of DAST-01 through DAST-30.
Neither sub-ticket below is implemented here.

## Why step 8 bundles two different things

`docs/FOUNDATION.md` tension 20 ("paranoid mode versus infrastructure traffic") resolved this
explicitly: `--paranoid` and `tools/run-in-netns.sh` are two different mechanisms with two different
guarantees, and the resolution is careful to keep that distinction visible rather than let one script
grow into the other:

- **`--paranoid`** is a **detector**. It samples child-process connections (`ss` filtered by the run's
  cgroup/process group, `strace -f -e trace=connect` where available and permitted, or `lsof` - the
  backend added after this plan was written, and the one macOS ships; see tension 20's "Backend
  roster") and aborts the run (`exit 3`, `SCOURSH_EXIT_SCOPE`) on the first destination outside a
  four-set allowlist. Sampling can miss a sufficiently short-lived connection, and tension 20 is
  explicit that the docs and report must say so plainly (§15) rather than imply a guarantee.
- **`tools/run-in-netns.sh`** is the **guarantee**. A Linux network namespace whose only route is to the
  declared scope makes an out-of-scope connection categorically impossible rather than merely
  observable. It needs root (or `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`) to create the namespace and its
  veth/route plumbing, and it is Linux-only with **no macOS equivalent** - neither property
  `--paranoid` shares, now that `--paranoid` has a macOS backend.  On macOS the detector is therefore
  the only egress control available: there is no guarantee tier behind it.

Because the two mechanisms have different implementers' concerns (a sampling observer with graceful
degradation vs. a privileged, optional, Linux-only wrapper script), they are independently schedulable
and are split into two tickets below rather than landed as one.

## Status: dependency satisfied, both tickets ready to schedule

This ticket's own acceptance criteria named `lib/http.sh` (the tension-19 scope-gate chokepoint) as the
blocker on opening step 8's sub-tickets. That dependency is **satisfied**: `lib/http.sh` shipped on
`dev` early, out of its normal step-5 sequence, once its own tension-19 contract was signed off (see
`docs/STEP5-DAST-PLAN.md`'s "`lib/http.sh` has already shipped" section and `CLAUDE.md`'s "Build order
and where we are"). Confirmed again for this ticket: `lib/http.sh` is present on `dev` as of commit
`5de4460` (the tip checked for this ticket), and its pinned-resolution-cache function
(`http_resolve_host` / the resolution cache tension 19 built) is exactly what tension 20's RESOLUTION
names as step 8's real dependency:

> "§13 step 8 implements `--paranoid` and the netns tool; the allowlist construction depends on
> `lib/http.sh`'s resolution cache from step 5, so the ordering already works."

Unlike `docs/STEP5-DAST-PLAN.md` (genuinely blocked on unlanded `nosql`/`ldap` rule packs and all of
step 4), step 8 is not blocked on any unlanded step. Both tickets below may be opened and scheduled
independently of each other and of the remaining un-landed steps (6, 7, 9, 10), subject only to the
per-ticket notes on graceful degradation below.

## Dependency-ordered sub-ticket list

| # | Ticket | Depends on | Notes |
|---|---|---|---|
| PARANOID-01 | `--paranoid` mode: connection-observer + abort-on-out-of-scope enforcement | `lib/http.sh`'s pinned resolution cache (tension 19, shipped), `scan.sh`'s existing `--paranoid`/`paranoid-allow` CLI and config plumbing (step 2, shipped - flag parsing only, no enforcement yet), `SCOURSH_EXIT_SCOPE=3`/`SCOURSH_EXIT_INPUT=4` (step 1, shipped) | Implements tension 20's RESOLUTION verbatim: builds the four-set allowlist (in-scope resolved target addresses+ports; AWS endpoint addresses for regions actually iterated; `/etc/resolv.conf` nameservers on port 53 plus loopback; `scanner.conf`'s `paranoid_allow`), attaches the process-group-level observer, aborts with exit 3 on the first out-of-scope destination, and exits 4 when no backend is usable (`ss`/`strace` as written here; `lsof` was added to the roster afterwards - see tension 20's "Backend roster"). The AWS-endpoint set (set 2) has a forward dependency on step 6's `regions.sh` (not yet built): this ticket must degrade that set to empty with a stated reason rather than error, exactly the pattern `docs/STEP5-DAST-PLAN.md`'s DAST-09 used for its own forward dependency on `data/versions.db`. Also ships the deterministic §12 no-egress test tension 20 describes: the fixture suite run against mock responses and `file://` inputs with `--resolve` entries pre-seeded on loopback, so DNS is removed from the test entirely and a pass means zero non-loopback connections. Must state the "detector, not guarantee" framing in the report and docs per §15, not imply `--paranoid` alone proves zero out-of-scope traffic. |
| NETNS-01 | `tools/run-in-netns.sh`: network-namespace runner | `lib/http.sh`'s pinned resolution cache (tension 19, shipped) to know which addresses to route into the namespace | **Optional and root-requiring** - this is stated directly in the ticket's own description (filed separately; see below), not only here, per this ticket's own acceptance criteria. Does not depend on PARANOID-01: it is the alternative, stronger mechanism tension 20 names ("the guarantee" vs. `--paranoid`'s "the detector"), not a wrapper around it. Linux-only; must fail clearly (not silently degrade) on a non-Linux host or without the required privilege, rather than pretending isolation was applied. |

The two tickets are peers - neither blocks the other - which is why they are split rather than landed as
one, per this ticket's acceptance criteria.

## Tickets filed

Both tickets named above have been filed to the backlog as concrete, standalone tickets (not merely
described in this document, mirroring the distinction this planning ticket's own acceptance criteria
draw between "the sub-ticket's own description" and "this planning doc"):

- **PARANOID-01** - Crewban-57, "Implement `--paranoid` mode: connection-observer + abort-on-out-of-scope
  enforcement"
- **NETNS-01** - Crewban-58, "Build `tools/run-in-netns.sh`: optional, root-requiring network-namespace
  runner" - its own description states the optional/root-requiring constraint directly, not only here.

Neither has been implemented as part of this ticket - see "Fails review if..." in this ticket's own
acceptance criteria, which this document and the two filed tickets satisfy by construction: this change
touches no `.sh` file.

## Doc-update process

Per `CLAUDE.md`'s "Build order and where we are" process rule ("shipping a §13 step updates this
section, and its mirror in `docs/FOUNDATION.md`'s 'Where the build currently stands,' in the same
change"), whoever lands PARANOID-01 or NETNS-01 (the first real step-8 code) updates both `CLAUDE.md`'s
"Current position" paragraph and `docs/FOUNDATION.md`'s "Where the build currently stands" section, in
the same change, exactly as every §13 sub-step landing so far has had to. `docs/DESIGN.md` itself stays
verbatim (per this project's documented rule that its wording is load-bearing and preserved as-is) - it
is never the place build-order status is recorded; `CLAUDE.md` and this section of `docs/FOUNDATION.md`
are.
