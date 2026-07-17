# #5858 — Revoke established transit sessions when an interface INPUT filter is attached / detached / tightened

## 1. Status

`DRAFT v2 — Claude SMR r1 folded (SMR-1..4); pending Codex + AGY r1`
(Codex + AGY + Claude SMR). v1 → v2 changelog at the end of this doc.

Research branch: `research/5858-input-filter-invalidation` off origin/master
`5c68818f6`. This is a `/research` deliverable — it stops at PLAN-READY /
PLAN-KILL. No production code is touched here.

## 2. Issue framing

A stateful transit session, once established, is served by the userspace
session-hit fast path (`resolve_flow_session_decision`,
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:969`). That path replays the
forwarding decision computed for the flow's **first** packet and does **no**
cold-path input-filter evaluation. The only per-packet input-filter re-check on
a session hit is `evaluate_dscp_sensitive_input_filter_on_session_hit`
(`poll_descriptor/filter.rs:334`), which early-returns `None` unless the ingress
interface's input filter carries a **DSCP** match term or a **per-packet-L4**
match term (tcp-flags / is-fragment / icmp-type / icmp-code) — the only match
classes whose result can vary *within* a single 5-tuple flow.

Consequently a **static** address / protocol / port input-filter term
(`then discard` / `then reject`) that is **attached, detached, or tightened
after** a session was created is never re-evaluated for that session. The flow
continues to be forwarded until it times out, contrary to the immediate
firewall-enforcement expectation. Because this is a security-policy *revocation*
gap (a deny the operator just committed does not take effect on in-flight
flows), the issue is filed **High**.

The config-rotation purge that *would* fix this already exists for the
per-packet classes: on a `ForwardingState` rotation the worker
(`worker/loop_body/mod.rs:376-393`) computes
`input_dscp_filter_families_changed` and
`input_per_packet_l4_filter_families_changed` and, if either fired, calls
`purge_sessions_for_input_dscp_filter_revalidation`
(`session_glue/mod.rs:326`) to drop the affected sessions so their next packet
re-evaluates against the new snapshot. **Both change-detectors are gated on
`has_dscp_match_terms` / `has_per_packet_l4_match_terms`** (the `.filter(...)`
predicates at `cache_sensitive.rs:445` and `:512`), so a static-only filter
change produces no purge. **That gate is the entire bug.**

The issue's required closeout:
1. Fingerprint the effective input filter per logical interface + family.
2. On attach/detach or any verdict-relevant static match/action change,
   invalidate affected sessions / flow-cache entries before or atomically with
   snapshot publication.
3. Preserve the optimized per-packet re-evaluation for fields that genuinely
   vary within a flow.
4. Propagate companion deletes to the HA peer; surface/retry partial
   invalidation.
5. Test address / protocol / port / except / term-reorder / attach-detach /
   VLAN logical interfaces / IPv4+IPv6 / flow-cache / HA failover.

## 3. Honest scope/value framing

The "win" is **correctness / security**, not throughput: an operator commit
that adds or tightens an interface input-filter deny must revoke in-flight
transit flows immediately (≈ within one config-rotation tick on every worker),
instead of leaving them forwarded until session timeout (potentially hours for
a long-lived TCP flow with default inactivity timeouts).

Absolute cost at scale: the fix runs **only on the config-rotation cold path**
(a `ForwardingState` ArcSwap rotation, i.e. an operator commit — seconds-to-
minutes apart, serialized by the commit machinery). It adds **zero** per-packet
hot-path work. The added cold-path work is one extra structural diff of the
per-interface input-filter maps per family per rotation (bounded by interface
count × terms), plus, when a change is detected, a single family-wide session-
table walk that already exists for the DSCP/per-packet case.

*If reviewers conclude the correctness gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (It is not expected to be — this is a
named security gap with a shipped, reviewed purge mechanism one predicate away.)

## 4. What's already shipped / partially batched (the plan must compose with)

The entire enforcement mechanism already exists and is HA-aware. The fix is a
**trigger broadening**, not a new subsystem:

- **Exhaustive verdict comparator (#5293 / PR #6053, in HEAD as `b43b16f44`).**
  `filter_term_semantics_match` (`cache_sensitive.rs:287`) destructures
  `FilterTerm` with **no `..` rest pattern**, so every field is either compared
  or explicitly bound to `_` (only `id` and the `counter` Arc handle are
  excluded). `dscp_sensitive_filter_semantics_match` (`:420`) wraps it with the
  filter-level flags + `terms.len()` + per-term walk. This is the single
  source of truth for "did this filter change in a verdict-relevant way," and
  it already handles flex-match, `*_constrained`, `*_except`, `continue_term`,
  action, routing-instance, forwarding-class, dscp-rewrite.
- **Family-wide purge (`purge_sessions_for_input_dscp_filter_revalidation`,
  `session_glue/mod.rs:326`).** Given `purge_v4` / `purge_v6` booleans it walks
  the session table (`iter_with_origin`), and for each matching-family session:
  releases source-NAT (`release_source_nat_allocation`) and NAT64
  (`release_nat64_allocation`) allocations, deletes the session-map + conntrack
  + shared-session entries, **replicates the delete to the HA peer**
  (`replicate_session_delete`, `:478` via `delete_terminal_filtered_session`),
  and emits the close delta. It is already the correct, complete, HA-propagating
  invalidation primitive — closeout item 4 is satisfied by reusing it.
- **Per-worker load-then-purge ordering (`worker/loop_body/mod.rs:372-499`).**
  Each worker, on observing the ArcSwap rotation, runs straight-line: load new
  snapshot → dependent updates → `forwarding = new_forwarding` (`:454`) → purge
  (`:455`), all **before** the packet-processing section of that loop iteration.
  This gives per-worker atomicity for free (closeout item 2).
- **HA config-sync recompiles per node (`pkg/cluster/sync_conn.go:1089`,
  `pkg/daemon/daemon_ha_sync.go:563`).** Raw Junos config **text** is shipped;
  the standby compiles its **own** `ForwardingState` and independently rotates
  + purges. So invalidation reaches the standby two independent ways: the
  primary's `replicate_session_delete`, *and* the standby's own recompute-and-
  purge. No compiled state crosses the wire; no new HA message is needed.
- **Session-hit per-packet re-eval gate (DSCP / per-packet-L4).** Untouched by
  this fix — it correctly stays for match classes that vary within a flow
  (closeout item 3).

Authoritative docs to update in `/engineer`: `userspace-dp/src/filter/README.md`
(lines 58-65 describe the "conservative packet-family purge on rotation"
contract) and `docs/pr/1431-filter-cache-invariants/plan.md`.

## 5. Concrete design

### 5.1 Core change (all path options share this)

Add a **general, un-gated** per-family input-filter change detector that reuses
the existing verdict comparator, and fold it into the existing purge trigger.

New function in `userspace-dp/src/filter/engine/cache_sensitive.rs`, mirroring
`input_dscp_filter_family_changed` **without** the `has_*_match_terms`
`.filter(...)` predicate:

```rust
/// #5858: a verdict-relevant change to ANY interface input filter in this
/// family — attach (new key absent from old), detach (old key absent from
/// new), or a static match/action edit (both present, terms differ). Unlike
/// input_dscp_filter_family_changed / input_per_packet_l4_filter_family_changed
/// this is NOT gated on has_dscp_match_terms / has_per_packet_l4_match_terms,
/// so a static address/protocol/port `then discard` added after session
/// creation triggers the rotation purge and the stale session is revoked.
fn input_filter_family_changed(
    old_filters: &FxHashMap<i32, Arc<Filter>>,
    new_filters: &FxHashMap<i32, Arc<Filter>>,
) -> bool {
    old_filters.iter().any(|(ifindex, old)| {
        new_filters.get(ifindex)
            .is_none_or(|new| !dscp_sensitive_filter_semantics_match(old, new))
    }) || new_filters.iter().any(|(ifindex, new)| {
        old_filters.get(ifindex)
            .is_none_or(|old| !dscp_sensitive_filter_semantics_match(old, new))
    })
}

pub(crate) fn input_filter_families_changed(
    old: &FilterState, new: &FilterState,
) -> (bool, bool) {
    (
        input_filter_family_changed(&old.iface_filter_v4_fast, &new.iface_filter_v4_fast),
        input_filter_family_changed(&old.iface_filter_v6_fast, &new.iface_filter_v6_fast),
    )
}
```

The `is_none_or` structure already handles **attach** (`old.get()==None ⇒
changed`) and **detach** (`new.get()==None ⇒ changed`) — the existing gated
detector relies on exactly this; we only drop the family-membership filter.

**Subsumption / simplification.** `input_filter_families_changed` is a strict
superset of both `input_dscp_filter_families_changed` and
`input_per_packet_l4_filter_families_changed` (any DSCP/per-packet change is
also a general change). So in `worker/loop_body/mod.rs` the three separate
calls collapse to one:

```rust
// BEFORE (loop_body/mod.rs:376-393): two gated detectors OR'd.
// AFTER: one general detector.
let (purge_input_v4, purge_input_v6) =
    crate::filter::input_filter_families_changed(
        &forwarding.filter_state, &new_forwarding.filter_state);
```

feeding the **existing** `purge_sessions_for_input_dscp_filter_revalidation`
call at `:455` (renamed — see 5.3).

**Decouple deletion from the correctness fix (SMR-4).** The load-bearing change
is *adding* `input_filter_families_changed` and *replacing* the two call sites in
`loop_body`. The now-dead `input_dscp_filter_families_changed` /
`input_per_packet_l4_filter_families_changed` (`filter/engine/mod.rs:15`) are
deleted **only after** a grep confirms zero other consumers (§11 Q5) — a
separate, non-security cleanup step, so a hidden consumer cannot turn a deletion
into a regression of the security fix. Note these detectors read the **per-
`Filter`** flags `has_dscp_match_terms` / `has_per_packet_l4_match_terms`, which
is a distinct thing from the `FilterState` **sets** below.

**Nothing on the session-hit hot path changes.** The DSCP/per-packet gate in
`evaluate_dscp_sensitive_input_filter_on_session_hit` and the
`iface_filter_v{4,6}_has_dscp_match` / `_has_per_packet_l4_match` **sets** that
gate it (read by `interface_input_filter_has_dscp_match` /
`interface_input_filter_has_per_packet_l4_match`) are **retained unchanged** —
they serve within-flow per-packet variance, an orthogonal mechanism from the
cross-rotation purge this issue fixes. (They are *not* the same as the detectors
deleted above; nothing here removes them.)

### 5.2 Where the "fingerprint" lives (closeout item 1)

The issue asks for a per-interface+family fingerprint. There is **no hash today
and the plan does not add one**: the coordinator holds both the old and new
`FilterState` at rotation time, so a direct structural diff (the existing
`dscp_sensitive_filter_semantics_match` per ifindex) *is* the fingerprint
comparison — cheaper and less error-prone than maintaining a hash (a hash
introduces a collision-and-staleness surface with no benefit when both snapshots
are in hand). "Verdict-relevant" is precisely the field set the #5293
exhaustive-destructure already classifies: match criteria + terminal action +
forwarding-class / dscp-rewrite / routing-instance modifiers; `id` and the
runtime `counter` Arc are excluded. (Comparator Path A vs B in §5.4 refines
whether `then count`/`then log` should also be excluded.)

### 5.3 Naming

`purge_sessions_for_input_dscp_filter_revalidation`,
`purge_input_dscp_v4/v6`, and the `INPUT_DSCP_FILTER_PURGE` debug tag become
misnamed once the trigger is general. Rename to
`purge_sessions_for_input_filter_revalidation` /
`purge_input_filter_v4/v6` / `INPUT_FILTER_PURGE`. Pure rename; no behavior
change. (Deferrable, but recommended in the same PR for clarity.)

### 5.4 The two decision-cache layers — the flow cache needs no new work (SMR-1)

The RX path has **two** decision caches, and this fix touches only one:

1. **Flow cache** (per-worker, `afxdp/flow_cache.rs`), checked **first** via
   `stage_flow_cache_hit` (`poll_descriptor/mod.rs:870`).
2. **Session table** (`resolve_flow_session_decision`, `:969`), checked on a
   flow-cache miss.

Issue closeout item 2 says invalidate "sessions **/ flow-cache entries**." The
flow cache is **already** invalidated on every commit and requires **no new
work**: each entry carries a `config_generation: u64` (`flow_cache.rs:122`)
stamped from `snapshot.generation` (`coordinator/snapshot_refresh.rs:281`), and a
stale generation forces a lookup miss (`flow_cache_tests.rs:187`
`stale_config_generation_causes_miss`). Every accepted config apply advances the
snapshot generation, so **all** flow-cache entries go stale on **any** commit and
fall through to the session-hit path — which this fix's purge then invalidates.
So the flow cache is strictly downstream of the session table: purge the session,
the next packet misses both caches, re-evaluates cold against the new filter, and
re-populates both with the correct new decision. The plan therefore satisfies
closeout item 2 in full with the single session-purge trigger; the flow-cache
layer self-heals via the existing generation gate. (The DSCP/per-packet filters
additionally *decline* flow-cache insertion; static filters are cacheable, but
that only means their entries live until the next generation bump — the deny lands
on a commit, which *is* a generation bump, so there is no static-filter flow-cache
bypass either.)

## 6. Public API preservation

- No wire/protobuf/gRPC change. HA sync ships config text unchanged.
- No `ForwardingState` / `FilterState` field additions under Path A (§5.1).
- No session-map / conntrack layout change.
- `purge_sessions_for_input_dscp_filter_revalidation` signature preserved (only
  renamed); all args and the `usize` return unchanged.
- The session-hit fast path signature (`resolve_flow_session_decision`) and the
  per-packet re-eval gate are byte-for-byte unchanged.

## 7. Hidden invariants the change must preserve

- **Side-effect ordering / atomicity (precision — SMR-2).** The purge must
  remain **after** `forwarding = new_forwarding` and **before** packet processing
  within the worker loop iteration (current `:454`→`:455`). This is
  **per-worker atomic**: within one worker there is no window where the new
  filter is live but the old session still forwards, nor one where sessions are
  purged but the old filter still forwards. It is **not** instantaneously global:
  each worker rotates independently on its own poll iteration, so **all workers
  converge within one rotation tick** (sub-millisecond). A not-yet-rotated worker
  still runs old-filter + old-session — self-consistent, and identical to the
  shipped DSCP/per-packet purge's convergence model. The load-bearing premise
  that rules out split-brain for a *given* flow: a 5-tuple is RSS-pinned to one
  worker, and the SessionTable consulted by the hit path
  (`resolve_flow_session_decision(sessions, …)`) is **worker-local**, so worker B
  never holds a session for a flow steered to worker A. Preserved by keeping the
  call site. (If a flow can migrate workers mid-rotation via an RSS reprogram or
  CoS owner handoff, the worst case is that same sub-ms enforcement delay bounded
  by the tick — an open question for review, §11 Q3.)
- **NAT/NAT64 allocation release + deterministic re-derivation (SMR-3).** Every
  purged session returns its source-NAT (`:355`) and NAT64 (`:364`) allocations
  (reusing the existing purge body). For an *unrelated still-permitted* NAT'd flow
  caught by the family-wide over-purge, re-creation must not remap the translated
  port. Verified safe: the SNAT allocator **deterministically re-derives the
  preserved translated tuple** (`nat/source.rs:16-43` — "derives the preserved
  port," `deterministic_indices_v4`, "preserved source port" in the reverse
  identity), so the re-created flow reclaims its just-released port. The remap
  hazard is therefore LOW even under family-wide purge.
- **HA peer delete propagation.** Reusing `delete_terminal_filtered_session`
  keeps `replicate_session_delete` in the loop → the standby is told. The delete
  rides the same FIFO `peer_worker_commands` queue as any install, so it cannot
  be overtaken by an earlier in-flight install for the same key.
- **Established-flow availability.** Purging a still-permitted TCP session must
  not break the flow. Verified: the transit session-miss path only drops a bare
  RST/FIN-no-SYN (`strict_syn_check_drops_new_flow`,
  `poll_descriptor/mod.rs:679`); a mid-stream data/ACK re-installs the session
  (Junos no-syn-check default, `mod.rs:2092`). So re-evaluation of a permitted
  flow is seamless (plain **and** NAT'd, per the deterministic re-derivation
  above); only a now-denied flow is dropped (the intended effect).
- **No hot-path allocation.** The change adds no per-packet allocation (it is
  cold-path only).
- **Fail-closed compile.** The filter compiler already returns
  `Err(MissingFilterRef)` on a hook naming a missing filter
  (`filter/compiler.rs:191`); the fix does not weaken this.
- **#5293 exhaustive-destructure invariant.** Under comparator Path A the single
  `filter_term_semantics_match` remains the only term comparator — adding a
  `FilterTerm` field still fails to compile until classified.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Superset trigger of an already-shipped purge; DSCP/per-packet behavior unchanged; established permitted flows re-install seamlessly. Only new effect: static-filter edits now also purge (the fix). |
| Lifetime / borrow-checker | **LOW** | New fn is a pure read over two `&FilterState` maps returning `(bool,bool)`; identical shape to the existing detector. |
| Performance regression | **LOW** | Cold path only (operator commit). One extra per-family structural diff + a family-wide table walk that already exists. Zero per-packet cost. Family-wide over-purge on a busy multi-interface box is the only cost lever → see Path B (§5.4) if profiling demands it. |
| Architectural mismatch | **LOW** | Reuses the #2362/#5293 purge model exactly; no new mechanism, no HA flag-day, no shim/verifier surface. Bounded extension. |

## 9. Test plan

Rust (`make test-rust` / cargo, short `TMPDIR=/tmp` per memory):

- **New unit tests in `session_glue/tests.rs` + `cache_sensitive.rs`:**
  - `input_filter_families_changed` fires on: static address deny **attach**
    (old absent), **detach** (new absent), address-list tighten, protocol
    change, port change, `source-address except` toggle, term **reorder**, and
    action `accept`→`discard`. (RED-on-revert: restoring the `has_dscp_match_terms`
    `.filter()` gate must make each assertion fail.)
  - Does **not** fire on an unrelated commit (identical input filters ⇒
    `(false,false)` ⇒ no purge — the no-spurious-purge control).
  - v4 and v6 independence (a v4-only change returns `(true,false)`).
  - The existing `purge_..._removes_family` test extended to assert the purge is
    driven by the general detector output.
- **Full cargo suite green** (`make test-rust`), 5× the named new tests for
  flake, plus `make test-go` for the Go legs untouched.
- **Parent RED-on-revert gate** (project merge gate): reverting the
  `.filter(...)`-drop must break a bound assertion, not merely a build.

Smoke (loss userspace cluster, at `/engineer` time — deferred here):

- Establish a transit flow (iperf3 172.16.80.200 / v6 `2001:559:8585:80::200`),
  then `set interfaces <reth>.<unit> family inet filter input <deny>` and
  commit; assert the flow **stops within one rotation tick** (was: continues to
  timeout). Repeat detach (flow resumes on re-permit). v4 **and** v6.
- HA failover variant: establish + sync a flow to the standby, commit the deny
  on the primary, `make test-failover`; assert the standby does **not** forward
  the revoked flow post-failover. (Required by the CLAUDE.md HA-touch gate —
  this touches session-sync-adjacent purge.)
- VLAN logical-interface variant (reth0.50 vs reth0.80) to confirm per-logical-
  ifindex keying.
- Flow-cache assertion (SMR-1): establish a **cacheable** flow (plain TCP/UDP,
  no NAT64) so it populates the flow cache, then commit the deny; assert the flow
  stops (proves the `config_generation` gate flushes the flow cache and the
  session purge revokes the underlying session — neither cache layer bypasses
  the new deny).

## 10. Out of scope (explicitly)

- **Output (egress) filters and lo0 host-inbound filters.** lo0 already
  re-evaluates every host-local hit (#3706 mandatory teardown re-check +
  `republish_local_delivery_sessions_for_lo0_filter`, `loop_body/mod.rs:477`);
  output filters run in the TX path. This issue is the **transit input** filter
  (`iface_filter_v{4,6}_fast`) only.
- **Per-interface / per-tuple purge granularity** (Path B / C, §5.4) — deferred
  follow-up unless a reviewer requires it for v1.
- **Policy (zone-based) revocation on session hit** — a separate concern
  (`show security policies` re-eval); not this issue.
- **Surfacing per-session delete errno** beyond the existing purge behavior —
  matches current DSCP-purge semantics; a metrics follow-up if wanted.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Granularity (the central design fork).** Is **family-wide** purge (Path A)
   acceptable, or must v1 be **per-interface** (Path B, requires a new
   `ingress_logical_ifindex` on `SessionMetadata` + install-site stamping,
   because neither `SessionKey` nor `SessionMetadata` records the ingress
   logical interface today — only `ingress_zone`, which is coarser)? Family-wide
   matches the shipped DSCP/per-packet precedent and is availability-safe for
   established flows; per-interface halves the blast radius on multi-interface
   boxes at the cost of a hot-path session field. Recommend A; B as follow-up.
   **Is that the right call, or is family-wide churn a real DoS/availability
   problem worth the field now?**
2. **Comparator reuse vs verdict-only (Path A vs B, §5.4).** Reusing
   `dscp_sensitive_filter_semantics_match` means a `then count`/`then log`-only
   edit also triggers a family-wide purge (over-purge on telemetry-only
   changes). The issue explicitly asks to **exclude** counters/log-only. Do we
   accept the over-purge to preserve the #5293 single-comparator invariant, or
   build a second verdict-only comparator and re-accept the divergence risk
   #5293 fought? Recommend accept over-purge (established flows re-install
   seamlessly; commits are rare).
3. **Atomicity across workers.** Is the per-worker load-then-purge ordering
   truly gap-free, or is there a cross-worker window (worker A purged + new
   filter live while worker B still runs old filter + old session for a flow
   RSS-steered to B)? Claim: each worker is self-consistent (old filter ⇒ old
   session, new filter ⇒ purged) and a 5-tuple flow is RSS-pinned to one worker,
   so there is no split-brain for a given flow. **Refute if a flow can migrate
   workers mid-rotation** (e.g. RSS reprogram, CoS owner handoff).
4. **HA sufficiency.** Is `replicate_session_delete` + standby independent
   recompile enough, or is there a failover window between primary-purge and
   standby-config-apply where the standby forwards the revoked flow? Does the
   config-generation high-water mark (#3931) plus the fast session-delete
   channel close it, or must the purge block on peer-ack?
5. **Subsumption safety.** Collapsing the two gated detectors into one general
   detector — does any *other* caller depend on the DSCP-specific /
   per-packet-specific `input_*_families_changed` returning a *narrower*
   signal (e.g. a different downstream action keyed only to DSCP changes)? Grep
   says the purge trigger is the sole consumer; **confirm no hidden second
   consumer** before deleting them.
6. **Reorder / continue-term correctness.** A term **reorder** with identical
   term set changes verdict precedence. `terms.len()` is equal, so detection
   relies on positional `zip` inequality in `dscp_sensitive_filter_semantics_match`
   (`:432-436`). Confirm a reorder actually yields a per-position `name`/field
   mismatch (it does when term names differ; **does a reorder of two terms with
   identical fields but different match sets get caught?** — yes via the field
   compare, but call it out).

---

## §5.4 — Multiple Path Options (the design forks reviewers must rule on)

### Fork 1 — purge granularity

| Path | Mechanism | Blast radius | Complexity | New hot-path state | Recommend |
|---|---|---|---|---|---|
| **A. Family-wide** *(existing precedent)* | ungated detector → `purge_v4/v6` → drop all sessions of the changed family | all v4 (or v6) sessions on the node | ~30 LoC, one new fn | none | ✅ **v1** |
| **B. Per-interface** | stamp `ingress_logical_ifindex` on `SessionMetadata` at install; purge only sessions ingressing a changed ifindex | only the changed interface's sessions | new session field + install-site stamping + purge predicate; touches hot path; possibly HA metadata | one `i32` per session | follow-up |
| **C. Per-tuple precise** | re-evaluate every session against old vs new filter; drop only verdict-changed | minimal | O(sessions × terms) per rotation; **also** needs the ingress ifindex from B to re-run the filter; most code | as B | ✗ |

**Recommendation: A for v1.** It reuses a shipped, HA-aware, NAT-safe purge;
adds no hot-path state; and is availability-safe because purging a still-
permitted TCP flow re-installs on the next data packet. Family-wide over-purge
costs a re-eval of unrelated-interface sessions on a *commit that changed an
input filter* — an infrequent, operator-initiated, already-heavyweight event.
Ship B only if cluster profiling shows the family-wide walk materially churns a
busy multi-interface deployment; it is a clean incremental follow-up (add the
field, narrow the predicate — the detector and trigger are unchanged).

### Fork 2 — comparator scope

| Path | Comparator | Purges on `then count`/`then log`-only edit? | Divergence risk | Recommend |
|---|---|---|---|---|
| **A. Reuse `dscp_sensitive_filter_semantics_match`** | full #5293 exhaustive | yes (over-purge) | none — one comparator | ✅ **v1** |
| **B. New verdict-only comparator** | excludes `count`/`has_count`/`log` (and re-decides policer/`three_color_policer`) | no | reintroduces a 2nd comparator that must track `FilterTerm` — the exact hazard #5293 closed | ✗ |

**Recommendation: A.** The issue's "exclude telemetry" is an efficiency ask, not
a correctness one; the cost of a spurious purge is a seamless session re-install
on the next packet. Preserving the single-source-of-truth comparator (and its
compile-time completeness guarantee) outweighs saving a rare purge. Revisit only
if a real workload commits `then count`/`then log` edits frequently enough to
matter (unlikely).

### Bounded-vs-larger verdict

This is a **BOUNDED extension**, not a new mechanism. The comparator, the purge,
the atomicity ordering, the flow-cache generation gate, and the HA propagation
all exist and are reviewed. The fix removes one `.filter(...)` gate (adds one
general detector) and reuses everything downstream. No verifier / shim / HA
flag-day wall. Expected to converge PLAN-READY on Path A / Path A.

---

## v1 → v2 changelog (Claude SMR r1 folded)

- **SMR-1 (was BLOCKING):** added §5.4 documenting the two decision-cache layers
  and why the **flow cache** needs no new work (self-invalidates via
  `config_generation` = `snapshot.generation` on every commit). Closeout item 2
  ("sessions / flow-cache entries") now fully addressed.
- **SMR-2 (was BLOCKING):** §7 atomicity claim tightened from "no window" to
  "per-worker atomic; all workers converge within one rotation tick," with the
  RSS-pinned worker-local-SessionTable premise that rules out per-flow
  split-brain. Migration edge moved to §11 Q3.
- **SMR-3:** §7 now states the SNAT allocator deterministically re-derives the
  preserved translated tuple (`nat/source.rs:16-43`), so family-wide over-purge
  is availability-safe for NAT'd flows too, not just plain TCP.
- **SMR-4:** §5.1 decouples deleting the old detectors from the correctness fix
  (replace call sites first; delete only after grep) and clarifies that the
  retained `iface_filter_v*_has_*` **sets** are distinct from the deleted
  detector functions.
- Test plan (§9): add an explicit flow-cache assertion (a cached-then-denied
  flow stops after commit) and keep the HA-failover + VLAN-logical-interface
  legs.

Claude SMR r1 verdict on v1 was **PLAN-NEEDS-MINOR** (approach sound + bounded;
these four doc gaps blocked/qualified PLAN-READY). v2 folds all four.
