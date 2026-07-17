# #5858 — Revoke established transit sessions when an interface INPUT filter is attached / detached / tightened

## 1. Status

`v5 — SCOPE REASSESSED after Codex r2 (2nd PLAN-NEEDS-MAJOR). NOT a bounded
PLAN-READY: the correct fix is a MAJOR multi-subsystem feature gated on a
product decision. See §13 (Research conclusion) FIRST.` Changelog at end.

> **Read §13 before §5.** Two rounds of hostile review (both PLAN-NEEDS-MAJOR,
> code-verified) established that the bounded fix is unsafe and the correct fix
> engages ~6 subsystems plus a genuine product decision (revocation-guarantee
> strength vs failover-fence complexity). §5.1–§5.5 below record the *corrected
> design direction*; the load-bearing errors Codex r2 found are annotated inline,
> but the full mechanism is /engineer-depth and is deferred pending the §13
> decision. This is the "design needs human judgment" outcome `/research` exists
> to surface.

Research branch: `research/5858-input-filter-invalidation` off origin/master
`5c68818f6`. `/research` deliverable — stops at PLAN-READY / PLAN-KILL. No
production code touched.

> **Why v3 exists.** v1/v2 proposed the minimal "drop one `.filter()` gate +
> reuse the existing family-wide purge" fix. Codex r1 (independently
> re-verified) showed that design is **not production-safe**: a family-wide
> purge **drops permitted SNAT flows**, which then re-install on a **fresh**
> translated port and break; the HA delete propagation the plan leaned on is
> sibling-worker-only and its cross-node channel is a bounded ring that drops
> excess; and a validation/forwarding ArcSwap skew opens a one-iteration
> flow-cache bypass. The corrected design (Path C) **re-evaluates each affected
> session and drops only those whose verdict became a deny**, so permitted flows
> — including SNAT — are never touched.

## 2. Issue framing

An established transit session is served by the session-hit fast path
(`resolve_flow_session_decision`, `poll_descriptor/mod.rs:969`), which replays
the first packet's forwarding decision and runs **no** cold-path input-filter
evaluation. The only per-packet input-filter re-check on a hit is
`evaluate_dscp_sensitive_input_filter_on_session_hit` (`poll_descriptor/filter.rs:334`),
which early-returns `None` unless the ingress interface's filter carries a
**DSCP** or **per-packet-L4** match term (`:356-366`) — the only match classes
whose result varies *within* a flow. So a **static** address/protocol/port
`then discard`/`then reject` term **attached, detached, or tightened after** a
session was created is never re-evaluated for that session, and the flow is
forwarded until timeout. Filed **High** — a committed deny does not take effect
on in-flight flows (a policy-revocation gap).

The config-rotation purge that fixes this for the per-packet classes is gated on
`has_dscp_match_terms` / `has_per_packet_l4_match_terms`
(`cache_sensitive.rs:445`, `:512`), so a static change never triggers it. But
per Codex r1 the fix is **not** simply "widen the trigger and reuse that purge"
— that purge is family-wide and drops permitted flows. The issue's own closeout
already anticipates the harder parts:
1. Fingerprint the effective input filter per logical interface + family.
2. Invalidate affected sessions / flow-cache entries before or atomically with
   snapshot publication.
3. Preserve the optimized per-packet re-evaluation for genuinely per-packet
   fields.
4. Propagate companion deletes to the HA peer; surface/retry partial
   invalidation.
5. Test address/protocol/port/except/reorder/attach-detach/VLAN/IPv4+IPv6/
   flow-cache/HA failover.

## 3. Honest scope/value framing

The win is **security/correctness**: a committed input-filter deny revokes
in-flight transit flows promptly (within the config-rotation window on every
worker) instead of leaving them forwarded until timeout — **without** breaking
the permitted flows that share the box. The corrected scope is materially larger
than v1 assumed: it is a **new precise-revalidation mechanism** (a per-session
ingress-interface stamp + a cold-path per-session re-evaluation + a flow-cache
coherence fix), not a one-line gate removal. That is precisely why this went
through `/research`.

Absolute cost: all new work is on the **config-rotation cold path** (an operator
commit — serialized, seconds-to-minutes apart). Zero per-packet hot-path cost
except the one added `SessionMetadata` field (an `i32`) read only on the cold
re-eval walk. The re-eval is O(sessions on changed interfaces × terms) per
commit, bounded and infrequent.

*If reviewers conclude the mechanism is too large for the value — or that a
precise revalidation cannot be made HA-coherent without a wire-format flag-day
they will not accept — PLAN-KILL or a scope-split is an acceptable outcome.* The
recommendation below argues it is bounded and shippable.

## 4. What's already shipped / partially batched (must compose with)

- **Exhaustive verdict comparator (#5293 / PR #6053, HEAD `b43b16f44`).**
  `filter_term_semantics_match` (`cache_sensitive.rs:287`) destructures
  `FilterTerm` with **no `..` rest** (only `id` + `counter` excluded);
  `dscp_sensitive_filter_semantics_match` (`:420`) wraps it. Single source of
  truth for "did a filter change." Path C reuses it via a **comparison mode**
  (§5.3) so a telemetry-only edit is distinguishable from a verdict change while
  keeping the compile-time completeness guarantee.
- **Family-wide purge (`purge_sessions_for_input_dscp_filter_revalidation`,
  `session_glue/mod.rs:326`).** Retained **as-is for the DSCP/per-packet path**
  (those verdicts depend on per-packet fields not stored on a session, so they
  cannot be precisely re-evaluated from the session alone). Path C adds a
  **separate** precise walk for static input-filter changes; it does **not**
  route static changes through this family purge.
- **Per-worker rotation site (`worker/loop_body/mod.rs:372-499`).** The new
  precise re-eval hooks the same forwarding-rotation block, after
  `forwarding = new_forwarding` (`:454`).
- **Flow cache (`afxdp/flow_cache.rs`)** — checked before the session table
  (`stage_flow_cache_hit`, `poll_descriptor/mod.rs:870`); entries carry a
  `config_generation` (`:122`) from `snapshot.generation`
  (`coordinator/snapshot_refresh.rs:281`), evicted on mismatch
  (`flow_cache.rs:873`). Its coherence bug (finding 3) is fixed in §5.4.
- **HA config-sync (`pkg/cluster/sync_conn.go:1089`,
  `pkg/daemon/daemon_ha_sync.go:563`).** Raw config **text** ships; the standby
  compiles its own `ForwardingState`. `replicate_session_delete`
  (`session_glue/mod.rs:751`) is **sibling-worker only** — cross-node deletes
  ride the Close-delta path (bounded ring). §5.5 defines the HA contract
  accordingly (this is where v1/v2 were wrong).
- **SNAT allocator (`nat/allocator.rs:540`).** Non-persistent PAT hands out a
  **monotonic fresh cursor** port first, draining the recycle FIFO only after
  the fresh range is spent; freed ports are pushed to the FIFO **back** (`:602`).
  So re-creating a dropped permitted flow yields a **different** port → the flow
  breaks. This is *the* reason Path C must never drop a permitted flow.

Docs to update at `/engineer`: `userspace-dp/src/filter/README.md` (lines 58-65,
the "conservative packet-family purge on rotation" contract — extend to describe
the precise static-filter revalidation), `docs/pr/1431-filter-cache-invariants/plan.md`,
and `docs/session-sync-architecture.md` (the HA revocation contract in §5.5).

## 5. Concrete design — Path C (precise per-tuple revalidation)

> **Codex r2 corrections to the v4 design below (verified against code).** The
> §5.1–§5.5 text is kept for continuity but these five errors must be fixed in
> any implementation (full design deferred per §13):
> 1. **Reverse-ingress is NOT knowable at forward install.** v4 §5.1 assumed
>    reverse-ingress = forward-egress; false under asymmetric routing (reply can
>    enter a *different* interface — `poll_descriptor/mod.rs:649`; real ingress is
>    only on the reply's `meta`, `filter.rs:342`). Stamp the reverse entry's
>    ingress **on the first reply packet**, or accept **forward-ingress-only**
>    coverage as a documented limitation. (My SMR2-C was wrong.)
> 2. **Teardown must be PAIR-aware.** Forward + reverse are independent entries;
>    `delete_terminal_filtered_session` deletes only its argument key
>    (`session_glue/mod.rs:446`) and does **no** NAT release. Revoking a flow must
>    delete **both** keys, evict **both** from **every** binding cache, cancel
>    queued work for both, release NAT/NAT64 **once via the forward entry**, and
>    emit the **forward** Close even when the deny was found on the reverse entry.
> 3. **NAT release is separate.** The family purge calls
>    `release_source_nat_allocation`/`release_nat64_allocation` **before** delete
>    (`session_glue/mod.rs:355`,`:364`); the precise walk must do the same (source
>    release no-ops on a reverse entry, `nat/source.rs:789`). v4's attribution of
>    NAT release to `delete_terminal_filtered_session` would **leak** allocations.
> 4. **Flow-cache invalidation needs the all-binding `invalidate_slot` loop**
>    (`loop_body/mod.rs:1332`) — the cache is per-binding keyed by
>    `(SessionKey, physical ingress_ifindex)` (`flow_cache.rs:759`/`:868`/`:979`),
>    not the 5-tuple; and a sibling worker's `DeleteSynced` removes a session
>    without cache access (`delete_synced.rs:9`) so owner-side eviction alone can
>    be bypassed — generation-refresh (a) stays load-bearing. (My SMR2-B was
>    wrong: targeted eviction by 5-tuple is insufficient.)
> 5. **`static_input_filter_verdict` must be side-effect-free** — reusing
>    `evaluate_interface_filter` records a counter even at `packet_bytes==0`
>    (`eval.rs:139`,`filter/mod.rs:696`); use a pure walk. Also update the manual
>    `SessionMetadata::PartialEq` (`entry.rs:134`) for the new field.
>
> The purely-static↔mixed **partition is gap-free** (Codex verified no static
> deny falls through both detectors) — but **not** overlap-free operationally: a
> mixed change on interface A family-purges permitted sessions on a purely-static
> interface B changed in the same commit, so the "permitted flows never touched"
> invariant does **not** hold globally (§13).

### 5.1 Stamp the ingress logical interface on the session

Add one field to `SessionMetadata` (`session/entry.rs`):

```rust
/// #5858: logical ingress interface (from resolve_ingress_logical_ifindex at
/// install). Enables scoping/evaluating a session against the correct
/// interface INPUT filter on a config-rotation revalidation. LOCAL-ONLY:
/// NOT added to the HA sync wire format (the kernel ifindex is node-specific;
/// see §5.5). Default/-1 for synced sessions installed from a peer.
ingress_logical_ifindex: i32,
```

Set at every transit session install from
`resolve_ingress_logical_ifindex(forwarding, meta.ingress_ifindex, meta.ingress_vlan_id)`
(`afxdp/forwarding/mod.rs:882`) — the same resolution the input-filter eval
already does. **Confirmed excludable from the sync wire** (the delta encoder picks
metadata field-by-field, `session_delta.rs:89-118`, not a raw copy — an added
field the encoder never references stays off the wire). Synced sessions carry
`-1` (unknown ingress on this node) and are handled by §5.5, not the primary
re-eval walk.

**Dual-direction stamping (SMR2-C).** An input filter applies per **ingress**
direction. The reverse companion (reply traffic) ingresses the forward flow's
**egress** interface — a *different* interface's input filter. Stamp **each**
session entry (forward + reverse) with **its own** ingress logical ifindex at
install (the reverse entry's ingress = the forward flow's egress, known at
creation), so a deny on **either** direction's ingress interface revokes the
flow. (If a reviewer judges the reverse leg out of scope for v1, it becomes an
explicit §10 limitation — forward-ingress only — not silence.)

### 5.2 Precise re-evaluation walk — scoped to PURELY-STATIC filters (SMR2-A)

**The precise path runs ONLY for filters with no per-packet variance.** A filter
mixing static and per-packet terms has an indeterminate 5-tuple verdict (a term
`from dscp 10 then accept` ahead of `from address X then discard` makes the deny
hinge on the packet's DSCP), so a static evaluation could either drop a permitted
flow or miss a deny. The clean partition — **no gap, no overlap**:

- **Purely-static filter** (`!has_dscp_match_terms && !has_per_packet_l4_match_terms`
  on **both** the old and new snapshot for that ifindex): this is *exactly* the
  set the existing gated family purge **excludes** (its
  `.filter(has_dscp_match_terms)`), i.e. exactly the #5858 gap. Its 5-tuple
  verdict is fully determined ⇒ **precise re-eval** here.
- **Filter with any dscp/per-packet term** (either snapshot): **already**
  family-purged on **any** change — static edits included — because
  `dscp_sensitive_filter_semantics_match` compares *all* terms
  (`cache_sensitive.rs:432-436`; the `.filter()` gate only selects *which*
  filters, then compares them in full). Left to the existing purge, unchanged.
  (Its pre-existing SNAT-break on those rarer edits stays an out-of-scope,
  documented limitation, §10.)

Route by "**either** old **or** new snapshot has a dscp/per-packet term for that
ifindex ⇒ family purge; else precise re-eval" — so a purely-static↔mixed
transition in one commit is caught by the family purge (the mixed side carries
the flag). `verdict_changed_ifindexes` (§5.3) therefore emits **only** purely-
static changed ifindexes; `static_input_filter_verdict` sees only filters where
`TermMatchExtra::default()` is exact — the `PerPacketDepends` case cannot arise.
This closes §11 Q2 by construction.

New function (session_glue), invoked from `loop_body` in the forwarding-rotation
block right after `forwarding = new_forwarding`:

```
fn revalidate_sessions_for_input_filter_change(
    sessions, fds, shared_*, peer_worker_commands,
    old_filter_state, new_filter_state, forwarding /*new*/, now_ns) -> usize
{
    // 1. Compute the set of logical ifindexes whose input filter changed in a
    //    VERDICT-relevant way (per family), using the comparison-mode
    //    comparator (§5.3). Empty set ⇒ return 0 (no walk).
    let changed_v4: FxHashSet<i32> = verdict_changed_ifindexes(old, new, V4);
    let changed_v6: FxHashSet<i32> = verdict_changed_ifindexes(old, new, V6);
    if changed_v4.is_empty() && changed_v6.is_empty() { return 0; }

    // 2. Walk the session table; for each session whose stamped
    //    ingress_logical_ifindex is in the changed set for its family,
    //    re-evaluate its 5-tuple against the NEW interface input filter
    //    using a STATIC (TermMatchExtra::default()) evaluation.
    let mut deny = Vec::new();
    sessions.iter_with_origin(|key, decision, meta, origin| {
        let ifx = meta.ingress_logical_ifindex;
        if ifx < 0 { return; }                     // synced/unknown -> §5.5
        let changed = if key.is_v6 { &changed_v6 } else { &changed_v4 };
        if !changed.contains(&ifx) { return; }
        // Static verdict for this 5-tuple under the NEW (purely-static) filter.
        match static_input_filter_verdict(new_filter_state, ifx, key) {
            Verdict::Deny   => deny.push((key, decision, meta, origin)),
            Verdict::Permit => {}                  // untouched — no NAT churn
            // No PerPacketDepends: the changed set is purely-static (§5.2).
        }
    });

    // 3. Drop ONLY the now-denied sessions (release NAT/NAT64, delete session-
    //    map/conntrack/shared, emit Close delta, replicate to siblings) — reuse
    //    delete_terminal_filtered_session — AND evict each dropped key's flow-
    //    cache entry (§5.4, race-free targeted eviction).
    for e in &deny { delete_terminal_filtered_session(...); evict_flow_cache(e.key); }
    deny.len()
}
```

`static_input_filter_verdict` evaluates the session's stored 5-tuple + protocol
against the interface's new (purely-static) input filter with
`TermMatchExtra::default()` (exactly the cached path's assumption,
`cache_sensitive.rs:163`). Because the filter is purely static, exactly two
outcomes arise:
- **Deny** — a terminal `discard`/`reject` matches on static fields alone → drop.
- **Permit** — terminal accept, or no matching deny → **keep untouched** (the
  whole point: no drop, no NAT release, no re-alloc, no break).

Only **newly-denied** sessions are dropped. Because a permitted SNAT flow is
never dropped, the fresh-cursor re-alloc break (finding 6) cannot occur.

### 5.3 Verdict-only comparison mode (closes finding 7 without a divergent comparator)

Add a `verdict_only: bool` to the exhaustive-destructure comparator (or a sibling
`fn filter_term_verdict_match` that reuses the *same* `..`-free destructure).
When `verdict_only`, exclude `count` / `has_count` / `log` (and the filter-level
`has_counter_terms` / `has_log_terms`) from the equality — they never change
admit/deny — while still binding every field so a **new `FilterTerm` field fails
to compile** until classified. This preserves the #5293 single-source-of-truth
invariant (Codex correctly called the "one comparator vs unsafe second
comparator" framing a false dichotomy). `verdict_changed_ifindexes` uses this
mode so a `then count`/`then log`-only edit triggers **no** re-eval walk.

### 5.4 Flow-cache coherence (closes finding 3 — the one-iteration bypass)

`validation` (carrying `config_generation`) and `forwarding` are separate
ArcSwaps read at `loop_body:364` and `:372`. A worker can purge sessions under
the new forwarding while still processing that iteration's packets under the
**old** validation, so an old-generation flow-cache entry hits
(`poll_descriptor/mod.rs:870`) and replays the old allow for one tick.

- **(b) PRIMARY — targeted eviction of each dropped key's flow-cache entry**
  inside the re-eval walk (§5.2 step 3). Path C drops a *specific, known* set of
  keys; evicting their flow-cache entries (by the same 5-tuple / flow hash) is
  **race-free** — it does not depend on the validation/forwarding ArcSwap store
  order at all. A permitted flow is not dropped and its (correct) allow entry
  rightly stays. This fully closes finding 3 for the #5858 path.
- **(a) SUPPLEMENTARY — re-read `validation` when the forwarding rotates** (force
  `validation = *shared_validation.load()` in the rotation block). This is a
  cleanup of the *latent* one-iteration bypass in the **existing** DSCP/per-packet
  family purge. Its race-freedom depends on the coordinator storing `validation`
  **before** `forwarding` (`snapshot_refresh.rs:354-355`) with acquire ordering
  on the worker read; if that order is not guaranteed, prefer driving the
  flow-cache generation from the `forwarding` snapshot itself (single source, no
  skew). Verify the store order at `/engineer`.

(b) is the load-bearing, race-free fix for this issue; (a) is an
independent latent-bug hardening. The flow cache already **declines** insertion
for DSCP/per-packet filters (`flow_cache.rs:411`), so both concern
static/other cacheable flows only.

### 5.5 HA contract (closes findings 4 & 5 honestly)

The correct HA story, replacing v1/v2's wrong "replicate_session_delete
propagates to the peer for free":

- **Primary side:** the precise walk drops only newly-denied sessions — a
  **small** set in realistic edits — so their Close deltas comfortably fit the
  per-worker 4096 delta ring (`session/mod.rs:60`,`:312`; overflow drop at
  `:1656`). These deltas drive the Go cross-node delete path
  (`daemon_ha_userspace_stream.go` `QueueDeleteV4/V6`) to the standby.
- **Broad-deny fallback (SMR2 / §11 Q3):** if a single deny revokes **more than
  the ring holds** (denied > 4096 on a worker), trigger a `SessionSync.BulkSync`
  (`pkg/cluster/sync_bulk.go:14`) whose absence-based reconciliation deletes the
  revoked sessions on the standby by omission — the authoritative path when the
  incremental ring would overflow. Gate it on the dropped-count so ordinary edits
  keep the cheap delta path.
- **Standby side:** the standby independently compiles the synced config text
  and rotates its own `ForwardingState`. For **its own** locally-created
  sessions it has the ingress stamp and runs the **same precise re-eval** → same
  denies dropped, independent of deltas. For **synced** sessions (stamp `-1`, no
  node-local ingress identity — the kernel ifindex differs per node) it cannot
  precisely re-eval; those are revoked by the primary's Close deltas. This is
  the belt-and-suspenders that makes revocation reliable for the common case.
- **Residual (finding 5):** a failover in the window between the primary's
  commit and the standby's config-apply + delta drain can briefly forward a
  revoked synced flow on the newly-active node until it applies the config /
  drains deltas. Bounded by config-sync latency; self-heals. The plan
  **documents** this rather than adding a failover fence (a larger HA feature —
  scoped out, §10). See §5.6 Path option for a stronger-but-heavier alternative.

### 5.6 Naming / retained mechanisms

- The DSCP/per-packet detectors + family purge + the
  `iface_filter_v{4,6}_has_dscp_match` / `_has_per_packet_l4_match` **sets** and
  the per-hit gate (`interface_input_filter_has_*`) are **retained unchanged** —
  they handle within-flow per-packet variance, orthogonal to this fix.
- The new precise path is additive; no existing signature changes except the
  `SessionMetadata` field addition (§5.1).

## 6. Public API preservation

- No wire/protobuf/gRPC change. HA sync ships config text; the new
  `ingress_logical_ifindex` is **local-only**, excluded from the sync encoder
  (§5.1) — **no HA flag-day**.
- No session-map / conntrack layout change.
- The session-hit fast path (`resolve_flow_session_decision`) and the per-hit
  re-eval gate are unchanged.
- The DSCP/per-packet `purge_sessions_for_input_dscp_filter_revalidation` and its
  callers are unchanged.

## 7. Hidden invariants the change must preserve

- **Never drop a permitted flow (the core availability invariant).** The re-eval
  drops only sessions whose static verdict is a terminal deny; permitted flows
  (incl. SNAT) are untouched, so the fresh-cursor NAT re-alloc break
  (`nat/allocator.rs:540`/`:602`) cannot occur. This is the invariant that Path
  C exists to hold and v1/v2 violated.
- **Ordering / cutover.** The re-eval + flow-cache validation re-read run after
  `forwarding = new_forwarding` (`:454`) and before packet processing, so a
  worker never processes a packet under new-filter + stale-session or
  stale-flow-cache. Cutover is **per-worker within one tick**, not globally
  atomic (workers observe the Arc independently at `:372`; queued TX drains post-
  rotation, `lifecycle.rs:69`). State this contract precisely; do not claim
  global atomicity.
- **NAT/NAT64 release only for dropped (denied) sessions** — reuse
  `delete_terminal_filtered_session` (releases source-NAT `:355` + NAT64 `:364`).
- **Static-vs-per-packet split.** `static_input_filter_verdict` must return
  `PerPacketDepends` (not `Permit`) whenever the deny would hinge on a
  DSCP/per-packet-L4 term, so security coverage for those is not silently
  dropped — it is delegated to the retained per-packet mechanism, not lost.
- **#5293 exhaustive-destructure invariant** preserved via the comparison mode
  (§5.3) — a new `FilterTerm` field still fails to compile until classified.
- **HA sync portability** — the new field is local-only; no wire change.
- **No hot-path allocation** — the walk + eval are cold-path (commit-time) only.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **MED** | New mechanism (field + walk + eval + flow-cache re-read). Mitigated: precise re-eval only *adds* denies-dropped; permitted flows untouched; DSCP/per-packet path unchanged. RED-on-revert + smoke gate. |
| Availability regression | **LOW** | Core invariant: permitted flows never dropped → no NAT re-alloc break. The v1/v2 family-wide break is eliminated by construction. |
| Lifetime / borrow-checker | **LOW** | Walk is a read + a deferred delete list (existing pattern in the family purge). |
| Performance regression | **LOW** | Cold path only; O(sessions × terms) on changed interfaces per commit. Zero per-packet cost. |
| HA correctness | **MED** | Primary precise + delta; standby own-session precise + delta for synced; documented residual failover window (finding 5). Verify with `make test-failover`. |
| Architectural mismatch | **LOW** | Composes with the #2362/#5293 model + existing purge/rotation machinery; no verifier/shim wall; no HA flag-day. |

## 9. Test plan

Rust (`make test-rust`, `TMPDIR=/tmp`):

- `revalidate_sessions_for_input_filter_change`:
  - **Drops a now-denied static flow** (address / protocol / port / `except` /
    term-reorder → deny) whose stamped ingress ifindex is in the changed set.
    RED-on-revert: reverting the walk leaves the session.
  - **Does NOT drop a still-permitted flow on the changed interface** (incl. a
    NAT'd flow — assert its NAT allocation is retained and untouched). This is
    the anti-regression for finding 6.
  - **Does NOT touch sessions on unchanged interfaces** (ingress ifindex not in
    the changed set).
  - **`PerPacketDepends` deny is left to the per-packet path** (a deny hinging on
    a DSCP/tcp-flags term does not falsely drop, and the DSCP/per-packet purge
    still fires).
  - **Verdict-only mode:** a `then count`/`then log`-only edit yields an **empty**
    changed set → no walk (control: no spurious drops).
  - **Attach / detach:** attach a deny (old absent) drops matching flows; detach
    permits them going forward.
  - v4 and v6 independence.
- Flow-cache coherence (finding 3): a cached static-allow flow stops after a deny
  commit **in the same rotation** (no one-iteration bypass) — assert via a test
  that reproduces the validation/forwarding skew.
- Full cargo suite green; 5× named tests for flake; `make test-go`.
- Parent RED-on-revert gate.

Smoke (loss userspace cluster, at `/engineer`):

- Establish a permitted transit flow (iperf3 172.16.80.200 / v6
  `2001:559:8585:80::200`); commit an input-filter deny on that flow's ingress
  reth.unit → assert it **stops within one rotation tick**; commit a deny on a
  DIFFERENT flow → assert the first (permitted) flow **keeps running** (the
  availability anti-regression). v4 **and** v6.
- SNAT variant: a permitted SNAT'd flow must survive an unrelated-interface
  input-filter commit with **no throughput dip / no reset** (proves no port
  remap).
- HA failover: establish + sync a flow, commit the deny on the primary,
  `make test-failover`; assert the standby does **not** forward the revoked flow
  post-failover (delta path) and permitted synced flows survive.
- VLAN logical-interface variant (reth0.50 vs reth0.80) — per-logical-ifindex
  stamping.

## 10. Out of scope (explicitly)

- **Output (egress) + lo0 host-inbound filters** — output enforcement is in TX
  selection (`cos_classify.rs:157`); lo0 re-evaluates every host-bound hit
  (`poll_descriptor/filter.rs:509`). Transit **input** filters only.
- **DSCP/per-packet-L4 input-filter SNAT breakage (pre-existing).** The retained
  family purge for those still drops permitted SNAT flows on a DSCP/per-packet
  edit — a latent, out-of-scope issue (rare edits). Note it; a follow-up could
  extend precise re-eval to them, but their verdict needs per-packet fields not
  on the session, so it is a distinct design.
- **A hard failover fence** (block failover eligibility until config-apply +
  purge complete) — a larger HA feature; §5.6 Path option. v1 documents the
  residual window instead.
- **Node-stable synced ingress-interface identity** (would let the standby
  precisely re-eval synced sessions) — needs a wire-format field; deferred (the
  delta path + standby own-session re-eval cover the common case).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is the local-only ingress stamp actually excludable from HA sync** without a
   wire change? **Confirmed:** the session delta encoder picks metadata
   field-by-field into the wire struct (`session_delta.rs:89-118` —
   `ingress_zone` / `owner_rg_id` / `policy_id` / …), not a raw copy, so an added
   `SessionMetadata` field the encoder never references stays off the wire → no
   flag-day. (Reviewers: sanity-check no *other* encoder raw-copies the struct.)
2. **Static-vs-per-packet verdict split soundness.** Can
   `static_input_filter_verdict` always cleanly classify Deny / Permit /
   PerPacketDepends? A term mixing static + per-packet match (`from address X
   tcp-flags syn then discard`) matches statically on address X but the deny
   hinges on the flag — must return `PerPacketDepends`, and the DSCP/per-packet
   purge must actually cover it. Is there a term shape that falls through both
   (neither precise-dropped nor per-packet-purged) and silently bypasses a deny?
3. **Standby synced-session revocation.** Is relying on the primary's Close
   deltas (for synced sessions the standby can't precisely re-eval) acceptable,
   given the ring can drop on a pathologically broad deny (>4096 denied)? Should a
   broad-deny case trigger a `SessionSync.BulkSync` reconciliation
   (`sync_bulk.go:14`) instead? Or is the standby's own config-apply re-eval of
   *its* sessions plus deltas enough?
4. **Failover window severity.** Is the documented residual window (commit →
   standby apply/drain) acceptable for a security revocation, or does #5858
   require the failover fence (§5.6) in v1? (Trade-off: correctness vs a larger
   HA change + failover-latency risk.)
5. **Cutover accuracy.** Is "per-worker within one tick, not globally atomic,
   queued-TX drains post-rotation" the correct and complete cutover contract, or
   is there a stronger guarantee needed (e.g., cancel queued TX for dropped
   flows)? Codex flagged `lifecycle.rs:69` drain vs `loop_body:961` cancellation
   ordering.
6. **Re-eval cost.** O(all sessions) table walk + O(terms) eval on changed
   interfaces, per commit. On a box with the full 131072-session table and a
   broad multi-interface commit, is the cold-path cost acceptable, or is a
   by-ingress-interface session index warranted (a bigger structural change)?
7. **Flow-cache fix (a) vs (b).** Is re-reading validation in the rotation
   iteration (a) sufficient and race-free, or is targeted per-key flow-cache
   eviction (b) also required? Any ordering where (a) still leaves a stale entry?

---

## §12 — Multiple Path Options (the design forks reviewers must rule on)

### Fork 1 — granularity (revised after Codex r1)

| Path | Mechanism | Drops permitted flows? | SNAT-safe? | New session field | HA | Verdict |
|---|---|---|---|---|---|---|
| **A. Family-wide** (v1/v2) | ungated detector → drop all family sessions | **yes** | **no** — fresh-cursor remap breaks them | none | delta ring overflows on large purge | ✗ **rejected (Codex r1)** |
| **B. Per-interface drop** | stamp ingress ifindex; drop all sessions on the changed interface | **yes (on that iface)** | **no** | i32 | smaller purge | ✗ still breaks permitted flows |
| **C. Precise per-tuple re-eval** | stamp ingress ifindex; re-eval each affected session; drop **only newly-denied** | **no** | **yes** — permitted never dropped | i32 (local-only) | small delta set + standby own re-eval | ✅ **v3 recommendation** |

**Recommendation: C.** It is the only option that revokes denied flows without
breaking permitted ones. It costs one local session field + a cold-path re-eval,
but needs **no HA wire change** and reuses the existing delete/rotation/delta
machinery. B is strictly dominated (same field, still breaks permitted flows). A
is unsafe.

### Fork 2 — comparator (revised)

| Path | Mechanism | Telemetry-only edit triggers re-eval? | #5293 invariant | Verdict |
|---|---|---|---|---|
| Reuse full comparator | includes count/log | yes (wasted walk; but C drops nothing on it) | preserved | acceptable but wasteful |
| **Verdict-only mode** (§5.3) | exclude count/log via a mode on the *same* `..`-free destructure | **no** | **preserved** | ✅ **v3 recommendation** |

Codex correctly called the earlier "one comparator or unsafe second comparator"
fork a false dichotomy: a comparison **mode** on the exhaustive destructure keeps
the compile-time completeness guarantee *and* excludes telemetry. Under Path C
even the full comparator is only *wasteful* (a re-eval that drops nothing), not
unsafe — but the mode avoids the waste cleanly.

### Fork 3 — HA standby revocation of synced sessions

| Option | Mechanism | Cost | Verdict |
|---|---|---|---|
| **Deltas + standby own-session re-eval** | primary Close deltas revoke synced sessions; standby precisely re-evals its own | none extra | ✅ **v3 default** (small precise set fits the ring) |
| BulkSync on broad deny | trigger absence-based reconciliation when denied>ring | moderate | fallback for pathological broad denies (§11 Q3) |
| Node-stable synced ingress id | sync a config-stable interface id so the standby precisely re-evals synced sessions | **wire-format flag-day** | deferred (§10) |

### Bounded-vs-larger verdict

Path C is **larger than v1 claimed but still bounded**: one local session field,
one cold-path re-eval, one flow-cache read-ordering fix, and a comparator mode —
all composing with existing machinery, **no verifier/shim/HA flag-day wall**. The
honest residuals (failover window, broad-deny delta overflow, DSCP/per-packet
SNAT pre-existing) are documented and scoped, not hidden. Expected to converge
PLAN-READY on Fork 1=C / Fork 2=verdict-only / Fork 3=deltas+own-reeval — unless
a reviewer judges the residual HA failover window unacceptable for a security
revocation, in which case the §5.6 fence becomes required scope (a larger change)
or the issue splits.

---

## v2 → v3 changelog (Codex r1 PLAN-NEEDS-MAJOR folded)

- **Pivot Fork 1 A→C.** Codex proved (re-verified) that family-wide purge drops
  permitted SNAT flows which re-install on a fresh cursor port and break
  (`nat/allocator.rs:540`/`:602`). New design re-evaluates and drops **only
  newly-denied** sessions; permitted flows untouched. Requires a local
  `ingress_logical_ifindex` on `SessionMetadata` (§5.1) + a precise walk (§5.2).
- **Finding 3 (flow cache):** added §5.4 — re-read `validation` in the rotation
  iteration so an old-generation flow-cache entry cannot bypass the new deny for
  one tick (also fixes the latent bug for the existing purge).
- **Finding 4/5 (HA):** rewrote §5.5 — `replicate_session_delete` is
  sibling-worker only; cross-node revocation is Close-deltas (small precise set
  fits the ring) + the standby's own re-eval; documented the residual failover
  window instead of claiming it away. Corrects v1/v2's wrong HA claim.
- **Finding 7 (telemetry):** §5.3 verdict-only comparison **mode** on the same
  exhaustive destructure — excludes count/log, keeps the #5293 compile-time
  invariant (false-dichotomy fixed).
- **Finding 2 (cutover):** §7 states the per-worker-within-a-tick contract
  precisely (no global-atomic claim); queued-TX ordering flagged (§11 Q5).
- Risk table upgraded to MED where the mechanism grew; test plan gains the
  permitted-flow / SNAT-survival anti-regressions.

Claude SMR r1 = PLAN-NEEDS-MINOR (SMR-3 later shown wrong by Codex's NAT
finding). Codex r1 = PLAN-NEEDS-MAJOR (governing). AGY r1 = infra-blocked. v3
addresses all Codex BLOCKINGs; a fresh Claude SMR r2 + Codex r2 review the
pivoted design.

---

## v3 → v4 changelog (Claude SMR r2 folded)

- **SMR2-A (BLOCKING, the important one):** scope the precise re-eval to
  **purely-static** filters (`!has_dscp_match_terms && !has_per_packet_l4_match_terms`
  on both snapshots). Mixed static+per-packet filters have an indeterminate
  5-tuple verdict and are **already** family-purged on any change, so the two
  paths partition with no gap/overlap. Removes the `PerPacketDepends` branch;
  closes §11 Q2 by construction.
- **SMR2-B (BLOCKING):** make **targeted flow-cache eviction of the dropped keys**
  the primary, race-free flow-cache fix (§5.4 (b)); demote the validation-reread
  (a) to a latent-bug cleanup whose race-freedom depends on the ArcSwap store
  order.
- **SMR2-C:** stamp **both** the forward and reverse session entries so a deny on
  either direction's ingress interface revokes the flow (§5.1).
- **Fork 3 / §11 Q3:** name the `SessionSync.BulkSync` absence-based
  reconciliation as the broad-deny (denied > ring) fallback (§5.5).
- §5.1 HA-exclusion claim upgraded from "verify" to "confirmed"
  (`session_delta.rs:89-118` field-by-field encoding).

Claude SMR r2 = PLAN-NEEDS-MINOR (pivot correct; A/B/C tighten it). Codex r1 =
PLAN-NEEDS-MAJOR (folded in v3). AGY = infra-blocked. v4 goes to Codex r2 for
convergence.

---

## §13 — Research conclusion: scope reassessment + required product decision

Two rounds of hostile plan-review (Codex r1 + r2, both **PLAN-NEEDS-MAJOR**,
every load-bearing finding independently re-verified against code; Claude SMR
r1/r2 converging) have established the following, which is the deliverable of
this `/research`:

**1. The bug is real and High.** The session-hit fast path never re-evaluates a
static input-filter deny attached after session creation; the flow forwards until
timeout. Confirmed.

**2. The bounded fix is DEAD.** "Widen the trigger and reuse the existing
family-wide purge" (v1/v2) is a **connection-breaking availability regression**:
the family purge drops permitted flows, and permitted **SNAT** flows re-install
on a fresh monotonic-cursor port (`nat/allocator.rs:540`/`:602`) and break. It
also has a one-iteration flow-cache bypass and cannot reliably propagate large
purges to the HA peer. Not shippable.

**3. The correct fix (precise per-tuple revalidation, Path C) is DIRECTIONALLY
right but is a MAJOR multi-subsystem feature, not a bounded change.** A complete,
correct implementation must engage all of:
- a per-session **ingress-interface stamp**, with reverse-ingress captured **on
  the first reply** (asymmetric routing makes it unknowable at forward install);
- **pair-aware teardown** (delete forward+reverse, NAT release once via forward,
  forward-Close even for a reverse-discovered deny — today the reverse entry
  emits **no** Close, `install.rs:467`);
- **all-binding + sibling-coherent flow-cache invalidation**
  (`invalidate_slot` loop, `loop_body:1332`) plus generation-refresh, because a
  sibling `DeleteSynced` bypasses owner-side eviction;
- a **side-effect-free** static verdict evaluator;
- an **authoritative HA resync**: fix reverse-Close emission, use the real
  ring-occupancy overflow predicate (not `denied>4096`), and architect the
  Rust→Go `SessionSync.BulkSync` fallback end-to-end (signal, cross-worker
  aggregation, ordering, BulkAck) — the second Go queue and delete journal are
  themselves bounded (`sync.go:597`/`:619`);
- and — for the stated **High** security-revocation contract — a **failover
  fence** (block failover eligibility until the peer has *applied* the config and
  *completed* revocation), because config receipt can be dropped
  (`sync_conn.go:1632`), apply can fail (`:1175`), there is no apply-ack, and a
  standby retaining the old permitting config can **cold-reinstall the revoked
  tuple** after failover. "Bounded by config-sync latency; self-heals" is false.

**4. THE PRODUCT DECISION (this is why it stops here, not at PLAN-READY).**
The central fork is not a technical detail an engineer can pick — it is a
product/security judgment:

> **For #5858's "High" security-revocation guarantee, do we ship (A) the full
> failover-fenced mechanism, or (B) a scoped MVP with an explicitly-accepted
> weaker guarantee?**

- **Option A — full guarantee.** Immediate revocation on the active node **and**
  a failover fence so a newly-active standby cannot forward a revoked flow. This
  is the strongest posture but adds a real HA mechanism (apply-ack + fence) with
  a **failover-latency risk** (fencing failover on config-apply could slow the
  ~60ms failover the cluster is tuned for) and the full BulkSync resync. Largest
  effort.
- **Option B — scoped MVP + documented residual.** Precise per-tuple revocation
  on the active node (forward-ingress-first, reverse-on-reply), pair-aware
  teardown, all-binding cache invalidation, reverse-Close fix, and **lean on the
  standby's own config-apply re-eval + deltas** for peer revocation — accepting a
  **documented, bounded failover window** (a flow revoked on the primary may be
  briefly forwarded by a just-promoted standby until it applies the config). This
  is a meaningful security improvement over today (revocation goes from
  *never/until-timeout* to *prompt on the active node*) at far lower cost and
  **no failover-latency risk**, but it is an explicitly *weaker* guarantee that a
  security owner must sign off on.

**Reviewer convergence.** Codex r1+r2 = PLAN-NEEDS-MAJOR (not PLAN-KILL — "Path C
is salvageable"). Claude SMR converges: the bounded framing is dead; the correct
mechanism is well-characterized but MAJOR, and PLAN-READY is gated on (i)
substantial additional design (the six items in §13.3, each with an existing
in-tree pattern to follow) **and** (ii) the §13.4 product decision. AGY:
infra-blocked in this headless runtime (documented). Neither reviewer will sign
a bounded PLAN-READY, and neither recommends PLAN-KILL — the fix is real and
achievable.

**Recommended disposition:** **PLAN-DEFERRED pending a product decision on §13.4.**
- If the user picks **Option B (scoped MVP)** — the likely pragmatic choice — this
  plan is ~80% of the way to an /engineer-ready spec: it needs one more revision
  fully designing pair-aware teardown, reverse-on-reply stamping, all-binding
  invalidation, the reverse-Close fix, and the documented-residual HA contract
  (all with cited in-tree patterns), then a final Codex+SMR round. Estimate:
  1–2 more research rounds, then a substantial (multi-file, HA-touching) PR.
- If the user picks **Option A (full fence)** — add the failover-fence + BulkSync
  design; larger, with a `make test-failover` latency-regression gate.
- Either way this is **not** a mechanical `/engineer 5858` from v5; it needs the
  decision first, then a v6 design round.

## v4 → v5 changelog (Codex r2 folded)

- Recorded Codex r2 (2nd PLAN-NEEDS-MAJOR) at `codex-plan-r2.md`; re-verified the
  load-bearing findings (reverse-Close early-return `install.rs:467`; per-binding
  `(key,ifindex)` cache + all-binding `invalidate_slot` `loop_body:1332`; NAT
  release separate from `delete_terminal_filtered_session`).
- Corrected the five verified design errors inline at the head of §5 (reverse-
  ingress-on-reply, pair-aware teardown, separate NAT release, all-binding cache
  invalidation, side-effect-free evaluator + PartialEq).
- Reframed scope honestly: this is a MAJOR multi-subsystem feature, not a bounded
  fix (§13); the "permitted flows never touched" invariant does not hold globally
  (mixed-filter family purge on co-committed interfaces).
- Elevated the failover-fence-vs-weaker-guarantee fork to the explicit **product
  decision** (§13.4) that gates PLAN-READY. **Research stops here** for that
  decision (the `/research` "design needs human judgment" outcome).

