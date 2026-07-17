# Claude SMR — hostile plan review r1 — #5858

**Plan:** `docs/research/5858-input-filter-invalidation/plan.md` @ commit `8f61631a15ca`
**Base:** origin/master `5c68818f6`
**Posture:** hostile. I tried to break the plan, not bless it.

## Verdict: **PLAN-NEEDS-MINOR**

The approach is **sound and genuinely bounded** — the enforcement mechanism
(exhaustive #5293 comparator + family-wide HA-aware purge + per-worker
load-then-purge ordering + config-generation flow-cache gate) all exists and is
reviewed; the fix removes one `.filter()` gate. But v1 of the **doc** has four
real completeness/precision gaps that must be closed before I will sign
PLAN-READY. None are PLAN-KILL. I am explicitly NOT soft-passing this on r1
(per the SMR-soft-pass anti-pattern) — the flow-cache gap in particular is a
question every hostile reviewer will ask and the doc currently does not answer.

---

## Confirmed correct (I verified these against code, not the prose)

- **The bug is real.** `resolve_flow_session_decision` runs no policy/static-
  filter re-eval for transit (`poll_descriptor/mod.rs:998` comment: "never runs
  policy evaluation"); `evaluate_dscp_sensitive_input_filter_on_session_hit`
  early-returns `None` for a static filter (no DSCP / per-packet-L4 term,
  `filter.rs:356-366`). So a static `then discard` attached post-creation is
  never rechecked on the hit path. ✔
- **The gate is the whole bug.** `input_dscp_filter_family_changed`
  (`cache_sensitive.rs:439`) and `input_per_packet_l4_filter_family_changed`
  (`:506`) both `.filter(|(_,f)| f.has_*_match_terms)`, so a static-only filter
  is invisible to the purge trigger. ✔
- **Dropping the gate catches attach/detach/static-change.** The `is_none_or`
  structure already handles attach (`old.get()==None`) and detach
  (`new.get()==None`); `dscp_sensitive_filter_semantics_match` (`:420`) compares
  filter-level flags + `terms.len()` + every term via the exhaustive
  `filter_term_semantics_match` (`:287`, `..`-free destructure). Term reorder is
  caught by the positional `zip` field-compare. ✔
- **The purge is complete + HA-aware.** `session_glue/mod.rs:326` is family-wide,
  releases source-NAT (`:355`) + NAT64 (`:364`) allocations, deletes
  session-map/conntrack/shared entries, and replicates the delete to the peer
  (`replicate_session_delete`, `:478`). Closeout item 4 is satisfied by reuse. ✔

---

## BLOCKING findings (must fix in the doc to reach PLAN-READY)

### SMR-1 (BLOCKING) — the flow-cache layer is undocumented
There are **two** decision caches on the RX path, and the plan only names one.
`stage_flow_cache_hit` (`poll_descriptor/mod.rs:870`) checks a per-worker
**flow cache** (`afxdp/flow_cache.rs`) **before** the session table
(`resolve_flow_session_decision`, `:969`). Issue closeout item 2 explicitly says
invalidate "sessions **/ flow-cache entries**." The plan body never explains
what happens to the flow cache.

I verified it is **not** a second bypass layer: flow-cache entries carry a
`config_generation: u64` (`flow_cache.rs:122`) stamped from `snapshot.generation`
(`coordinator/snapshot_refresh.rs:281`); a stale generation forces a lookup miss
(`flow_cache_tests.rs:187` `stale_config_generation_causes_miss`). Every accepted
commit advances the snapshot generation, so the flow cache **self-invalidates on
any commit** and falls through to the session-hit path — which the purge then
also invalidates. So the plan is *complete* with just the session purge, **but
the doc must say this.** Add a "Flow-cache layer" subsection (in §5 or §7)
stating the config-generation self-invalidation and that no new flow-cache work
is required. Without it, the plan looks like it ignores half the closeout.

### SMR-2 (BLOCKING) — the "no window" atomicity claim is overstated
§7 says the ordering guarantees "no window where the new filter is live but the
old session forwards." Precisely: there is no **intra-worker** window (straight-
line `forwarding=new` `:454` → purge `:455` → process). But each worker rotates
**independently** on its own poll iteration, so cross-worker convergence takes up
to **one poll tick** — during which a not-yet-rotated worker still runs
old-filter + old-session (self-consistent). Rewrite the claim as "per-worker
atomic; all workers converge within one rotation tick," and add the load-bearing
premise: a 5-tuple flow is RSS-pinned to one worker whose SessionTable is
worker-local, so there is **no split-brain for a given flow** (worker B never
holds a session for a flow steered to worker A). If a flow *can* migrate workers
mid-rotation (RSS reprogram / CoS owner handoff), state that the worst case is a
sub-ms enforcement delay bounded by the tick — matching the shipped DSCP/per-
packet precedent. The current absolute "no window" phrasing is refutable and a
reviewer will pull on it.

## Non-blocking findings (fold in; they make the plan honest)

### SMR-3 (MINOR) — "availability-safe" must cover NAT'd flows
§7 argues purging a still-permitted TCP flow is safe because a mid-stream
data/ACK re-installs the session (`poll_descriptor/mod.rs:2092`). True for
non-NAT flows. But the family-wide purge also drops **NAT'd** sessions and
releases their allocations (`:355`/`:364`) — a reviewer will ask "doesn't
re-allocation remap the translated port and break the unrelated in-flight NAT
flow the over-purge caught?" I checked: the SNAT allocator **deterministically
re-derives the preserved translated tuple** (`nat/source.rs:16-43` — "derives
the preserved port," `deterministic_indices_v4`, "preserved source port" in the
reverse identity), so a purged-then-re-created still-permitted flow reclaims its
just-released port. Add this to the availability-safe argument so it is honest
for NAT'd flows, not just plain TCP. (Net: still LOW risk, but state it.)

### SMR-4 (MINOR) — decouple detector deletion from the correctness fix
§5.1 says the two gated detectors "may be deleted." Keep the correctness change
minimal and low-risk: **add** `input_filter_families_changed`, **replace** the
two call sites in `loop_body`, and only *then* delete the old functions after a
grep confirms zero other consumers (§11 Q5). Do not couple a delete into the
security fix — if a hidden consumer exists, deletion breaks it; the replace is
the load-bearing change. Also state explicitly that the
`iface_filter_v{4,6}_has_dscp_match` / `_has_per_packet_l4_match` **sets** are
retained (they feed the per-hit re-eval gate `interface_input_filter_has_*`,
which is a different mechanism from the purge detectors — the detectors read the
per-`Filter` `has_*_match_terms` flags, not these sets).

## Design forks — my ruling

- **Granularity: Path A (family-wide) for v1 — agree.** With SMR-3 resolved
  (deterministic NAT re-derivation) family-wide is availability-safe for plain
  and NAT'd permitted flows, needs no new session field, and matches the shipped
  precedent. Path B (per-interface) is a clean follow-up if cluster profiling
  shows the family-wide walk churns a busy multi-interface box; it is correctly
  scoped out. Do **not** attempt Path C.
- **Comparator: Path A (reuse) for v1 — agree.** The over-purge on
  `then count`/`then log`-only edits is bounded (rare commits; seamless
  re-install) and preserves the #5293 single-comparator compile-time invariant.
  A second verdict-only comparator reintroduces exactly the divergence hazard
  #5293 closed — not worth it. The issue's "exclude telemetry" is an efficiency
  ask, not correctness.

## What would move me to PLAN-READY
Fold SMR-1 and SMR-2 into plan v2 (flow-cache subsection + atomicity precision),
and SMR-3/SMR-4 as the honest availability + minimal-change notes. No code, no
new mechanism, no re-architecture. I expect r2 to converge PLAN-READY.
