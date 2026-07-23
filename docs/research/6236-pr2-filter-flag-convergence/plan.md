# #6236 PR-2 — property-set → `Filter`-flag convergence + single-lookup fold

## 1. Status

`DRAFT v1 — REVISED after Codex PR-1 plan-review (3 blockers resolved); pending
adversarial plan review`

Research base: `origin/master` @ `394f53fa3` (includes #6236 **PR-1**, merged as
PR #6350 / commits `3d1734334` + `a69380764`). Worktree
`.claude/worktrees/6236p2-research`, branch
`research/6236-pr2-filter-flag-convergence`.

PR-1 already deleted the 8 grep-dead fields (4 name maps, 2 dead input
`affects_tx_selection` sets, 2 lo0 name Strings): `FilterState` is now **23
fields** (`filter/mod.rs:743-795`). The original umbrella plan
(`research/6236-filterstate-typed-hooks:docs/.../plan.md`, §3b/§3c/§5 Design A)
is superseded for PR-2 by this document. No production source was touched; the
only file written is this plan.

The three PR-2 blockers Codex raised on the PR-1 review (issue #6236 comment,
"Plan-review round 1") are resolved here in §5.

---

## 2. Issue framing (in my words)

PR-1 removed dead bookkeeping. PR-2 removes the **live redundancy**: eight
per-ifindex `FxHashSet<i32>` "property sets" that each re-encode an immutable
flag already carried by the `Arc<Filter>` sitting in the per-interface fast map.
The compiler maintains the sets and the fast map in lockstep by hand; the hot
path then re-joins them with a redundant second hash probe, and (on the output
TX path) a third inline recompute of a predicate the set already encoded.

The eight live sets (post-PR-1):

| Set field | Duplicates `Filter` field | Read by (hot precheck) |
|---|---|---|
| `iface_filter_v{4,6}_affects_route_lookup` | `affects_route_lookup` | `interface_filter_affects_route_lookup` (eval.rs:1089) |
| `iface_filter_v{4,6}_has_dscp_match` | `has_dscp_match_terms` | `interface_input_filter_has_dscp_match` (rotation.rs:212) |
| `iface_filter_v{4,6}_has_per_packet_l4_match` | `has_per_packet_l4_match_terms` | `interface_input_filter_has_per_packet_l4_match` (rotation.rs:285) |
| `iface_filter_out_v{4,6}_needs_tx_eval` | *composite* — see §5.2 | `interface_output_filter_needs_tx_eval` (tx_selection.rs:375) |

The **output** direction already ships the target design: its DSCP / per-packet-L4
prechecks (`interface_output_filter_has_dscp_match`,
`interface_output_filter_has_per_packet_l4_match`, rotation.rs:224/301) read the
flag off `iface_filter_out_v*_fast.get(&if)` — no set. The cold config-rotation
purge paths (`input_dscp_filter_families_changed`,
`input_per_packet_l4_filter_families_changed`, rotation.rs:202/269) already
iterate `iface_filter_v*_fast` filtering on the `Filter` flag — they never
consulted the sets. **Only the four hot input/output prechecks above read the
sets.** PR-2 converges those four onto the output pattern and deletes the eight
sets, so a single `.get()` returns the filter and every derived flag.

> PLAN-KILL remains an acceptable verdict if reviewers judge the per-packet win
> too small for the hot-path churn (§11 Q1/Q5).

---

## 3. What PR-1 already shipped (do not re-do)

- Deleted: `iface_filter_v4`/`v6`/`out_v4`/`out_v6` name maps; the two dead input
  `iface_filter_v{4,6}_affects_tx_selection` sets; the `lo0_filter_v{4,6}` name
  Strings (now compiler locals, compiler.rs:293-328); the test-only helper
  `interface_filter_affects_tx_selection` and its four assertions.
- `FilterState` 31 → 23 fields; `size_of` 736 → 496 (measured, per the PR-1
  commit body).
- Docs updated: `filter/README.md:710-722` records the PR-1 removal and pins the
  #3296 fail-closed contract to the RETAINED fast maps **and the
  `iface_filter_out_*_needs_tx_eval` sets** — that last clause is what PR-2 must
  re-anchor (§5.2 / §7).

---

## 4. Concrete design (Design A, per the umbrella plan)

`iface_filter_v*_fast` **is** the typed hook record: it holds `Arc<Filter>`, and
`Filter` (compiler.rs:132-149) already carries every derived flag
(`affects_tx_selection`, `affects_route_lookup`, `has_counter_terms`,
`has_log_terms`, `has_terminal_action_terms`, `has_dscp_match_terms`,
`has_per_packet_l4_match_terms`, `has_three_color_policer_terms`). No new flag is
computed. Design B (`filter/hooks.rs` wrapper type) is **forbidden** — it
degenerates to A once you drop the redundant flags bitset (umbrella plan §11 Q6).

Add one accessor on `Filter` (the sole definition of the output-TX composite,
replacing three copies — compiler.rs:199-204/265-269 and the two inline
recomputes at cos_classify.rs:225-231/667-673):

```rust
impl Filter {
    /// The output filter must still be walked on the TX path when it can
    /// change/observe the packet: CoS/DSCP tx-selection, a counter, a log, a
    /// terminal (non-Accept) action, or a three-color policer. Mirrors exactly
    /// the five-flag OR the compiler used to populate iface_filter_out_*_needs_tx_eval.
    #[inline]
    pub(crate) fn needs_tx_eval(&self) -> bool {
        self.affects_tx_selection
            || self.has_counter_terms
            || self.has_log_terms
            || self.has_terminal_action_terms
            || self.has_three_color_policer_terms
    }
}
```

Struct after PR-2 (**15 fields**; see §5.1 for why aggregates move + why
`has_output_tx_selection` folds away):

```rust
pub(crate) struct FilterState {
    filters: FxHashMap<String, Arc<Filter>>,                         // registry
    three_color_policer_by_name: FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    three_color_policers: Vec<Arc<ThreeColorPolicerRuntime>>,
    iface_filter_v4_fast: FxHashMap<i32, Arc<Filter>>,               // hook record (input v4)
    iface_filter_v6_fast: FxHashMap<i32, Arc<Filter>>,               // hook record (input v6)
    iface_filter_out_v4_fast: FxHashMap<i32, Arc<Filter>>,           // hook record (output v4)
    iface_filter_out_v6_fast: FxHashMap<i32, Arc<Filter>>,           // hook record (output v6)
    lo0_filter_v4_fast: Option<Arc<Filter>>,
    lo0_filter_v6_fast: Option<Arc<Filter>>,
    has_input_tx_selection_v4: bool,                                 // aggregate
    has_input_tx_selection_v6: bool,
    has_input_three_color_policer_v4: bool,
    has_input_three_color_policer_v6: bool,
    has_output_needs_tx_eval_v4: bool,                               // NEW aggregate (§5.2)
    has_output_needs_tx_eval_v6: bool,
}
```

**DELETE (8 sets):** `iface_filter_v{4,6}_affects_route_lookup`,
`iface_filter_v{4,6}_has_dscp_match`,
`iface_filter_v{4,6}_has_per_packet_l4_match`,
`iface_filter_out_v{4,6}_needs_tx_eval`.
**REPLACE:** `has_output_tx_selection_v{4,6}` → `has_output_needs_tx_eval_v{4,6}`
(§5.1). **RETAIN:** 4 fast maps + 2 lo0 fast + 3 registries + 4 input aggregates.
23 → 15 fields (net −8: −8 sets −2 `has_output_tx_selection` +2
`has_output_needs_tx_eval`).

---

## 5. The three blockers — resolutions

### 5.1 Blocker #1 — duplicate-ifindex cache-equivalence (DECISION: last-wins canonical, derive every value from the FINAL fast map)

**The hazard, exactly.** The compiler loop (compiler.rs:154-291) walks
`snapshot.interfaces`. For each interface with a non-empty hook it (a) `insert`s
into the property sets *monotonically* (union — a set entry is never removed) and
(b) `insert`s into `iface_filter_v*_fast` (a map — **last write wins**, silently
overwriting a prior entry for the same ifindex). It also ORs the aggregate
booleans monotonically. There is **no** duplicate-ifindex rejection. So if two
interface entries share an ifindex+family+direction where the first names a
DSCP-sensitive (or route-affecting) filter and the second a non-sensitive one:

- set: `contains(if) == true` (union kept the first)
- fast map: `get(if)` → the **second** filter (`has_dscp_match_terms == false`)
- aggregate: `true` (OR kept the first)

So `set.contains(if) == fast.get(if).is_some_and(flag)` is **false** for that
ifindex — the naive convergence would change behavior there.

**Key observation that makes the decision easy.** Every filter EVALUATION on the
packet path already reads `iface_filter_v*_fast.get(&if)` — i.e. the **last-wins**
filter — never the set. The set is consulted ONLY by the four prechecks that
*gate whether that eval runs*. Concretely:

- PBR precheck→eval (pbr.rs:60 → eval.rs:924): today `set.contains` (from the
  first filter) can say "route-affecting", then the evaluator runs the
  **second** filter and finds no routing-instance term → returns `None` →
  `RouteOverride::None`. After the fold, `affects_route_lookup` reads the second
  filter's flag → `false` → `None` immediately. **Same outcome, one fewer probe.**
- Input non-routing eval (poll_descriptor/filter.rs:219): the set only chooses the
  `NonRoutingCountPolicy`; the eval itself always reads the fast map (the second
  filter). After the fold the count-policy decision reads the same filter the
  eval uses.
- Flow-cache DSCP/L4 seed-decline gate (flow_cache.rs:475/495) and session-hit
  re-eval gate (poll_descriptor/filter.rs:356): today the set (first filter) can
  DECLINE caching / force re-eval even though only the second filter is installed;
  after the fold the gate reads the installed (second) filter. This is the ONE
  site whose boolean genuinely changes for a duplicate — and it changes to agree
  with the filter that is actually evaluated. Declining-cache-but-evaluating-the-
  other-filter was the inconsistent state; reading both from the fast map is
  strictly *more* coherent, never a stale-verdict hazard (the cached verdict is
  the installed filter's verdict).

**DECISION: (b) last-wins canonical.** Keep the fast map's existing last-wins
overwrite as the single source of truth, DELETE the sets, and read every derived
per-ifindex value off `iface_filter_v*_fast`. The fold does not *introduce* a
last-wins semantic — it makes the four prechecks agree with the eval that has
**always** used last-wins. There are no sets left to diverge.

**Mandatory construction rule (applies regardless of the decision):** the
retained/added aggregate booleans must be **recomputed from the FINAL fast maps
after the interface loop**, NOT accumulated monotonically inside it. Replace the
in-loop `state.has_* = true` writes with a post-loop pass:

```rust
// after the `for iface in interfaces { … }` loop, from the FINAL maps:
state.has_input_tx_selection_v4 =
    state.iface_filter_v4_fast.values().any(|f| f.affects_tx_selection);
state.has_input_three_color_policer_v4 =
    state.iface_filter_v4_fast.values().any(|f| f.has_three_color_policer_terms);
state.has_output_needs_tx_eval_v4 =
    state.iface_filter_out_v4_fast.values().any(|f| f.needs_tx_eval());
// …_v6 mirrors over the _v6 maps.
```

This closes the aggregate half of the hazard: a duplicate that overwrites the
fast map with a non-sensitive filter can no longer leave a stale aggregate
`true`, because the aggregate is derived from the final map, not the union of
everything ever inserted. (Cost: one `values().any()` per aggregate at
*compile* time — cold, once per snapshot, not per packet.)

**Why not (a) reject-fail-closed?** Rejecting duplicate positive ifindices is a
*new* fail-closed policy and a behavior change (today duplicates are silently
accepted). It is not required for correctness once every value derives from the
final map, and it risks refusing a snapshot the current code accepts. Whether a
duplicate ifindex is even reachable from a committed config is unverified (each
logical unit gets a distinct kernel ifindex; a duplicate would be drift/
corruption — §11 Q2). Fail-closed-on-duplicate is a defensible *separate* issue
if the team wants it, but bundling it into a convergence refactor widens the
blast radius for no correctness gain. **Recommend (b); note (a) as a possible
future hardening.**

**Why not (c) accept-and-test-the-change?** (b) *is* (c) with a cleaner framing:
we explicitly accept that the duplicate-ifindex flow-cache gate now reads the
installed filter, and we TEST it (§9, the duplicate-ifindex case). The framing
matters because "last-wins canonical, all values from the final map" is a
provable invariant; "accept an ad-hoc behavior change" is not.

### 5.2 Blocker #2 — `tx_selection_enabled_*` global gate consumes the output `needs_tx_eval` sets

`forwarding_build/mod.rs:420-435` computes the family-wide `tx_selection_enabled_v4/v6`
gate (which short-circuits the ENTIRE `cos_classify` TX path when false —
cos_classify.rs:588-595). Its last clause reads the set directly:

```rust
state.tx_selection_enabled_v4 = has_cos_interfaces
    || state.filter_state.has_input_tx_selection_v4
    || state.filter_state.has_output_tx_selection_v4          // ⊂ needs_tx_eval
    || state.filter_state.has_input_three_color_policer_v4
    || !state.filter_state.iface_filter_out_v4_needs_tx_eval.is_empty();  // ← deleted set
```

`has_output_tx_selection_*` (OR of `affects_tx_selection`) is a STRICT SUBSET of
`needs_tx_eval` (which also covers counter/log/terminal/policer). Deleting the
set without a replacement would fail-OPEN: an output filter with only
counter/log/terminal/policer terms would clear the whole gate → its counters,
logs, and `then discard`/`reject` would silently stop being enforced.

**Resolution.** Introduce the family-wide aggregate `has_output_needs_tx_eval_v{4,6}`
(computed from the final output fast maps, §5.1) and rewrite the gate:

```rust
state.tx_selection_enabled_v4 = has_cos_interfaces
    || state.filter_state.has_input_tx_selection_v4
    || state.filter_state.has_input_three_color_policer_v4
    || state.filter_state.has_output_needs_tx_eval_v4;   // ⊇ old has_output_tx_selection clause
```

Because `needs_tx_eval ⊇ affects_tx_selection`, the new aggregate SUBSUMES the old
`has_output_tx_selection_v*` clause AND the set-emptiness clause in one boolean —
which is why §4 deletes `has_output_tx_selection_v*` (its only reads are this OR
and a production-DEAD accessor `filter_state_has_output_tx_selection`, whose sole
caller is one test at tests.rs:2336 — verify no other consumer before deleting,
§9). Alternative if reviewers want to keep `has_output_tx_selection_*`: retain it
and ADD `has_output_needs_tx_eval_*` (23 → 17 fields, redundant but minimal-diff).
**Recommend the fold (15 fields)** — removing the redundant aggregate is exactly
the modularity win #6236 targets.

### 5.3 Blocker #3 — PBR is two probes; the evaluator needs a `&Filter` API

`ingress_route_table_override` (pbr.rs:43-66) probes the capability twice on the
present path: `interface_filter_affects_route_lookup(...)` (set `.contains`, :60)
→ then `evaluate_interface_filter_routing_instance_event_counted(...)` which
*re-probes* `iface_filter_v*_fast.get(&if)` internally (eval.rs:924-928). The
umbrella plan's "unchanged evaluator signatures" contradicts the single-lookup
acceptance criterion.

**Resolution.** Add a `&Filter`-taking core to the routing-instance evaluator and
make the current `&FilterState, ifindex, is_v6` entry point a thin wrapper that
does the one `.get()`:

```rust
// new core — no map probe, caller supplies the borrow:
pub(crate) fn evaluate_filter_ref_routing_instance_event_counted<'a>(
    filter: &'a Filter, src_ip: IpAddr, dst_ip: IpAddr, protocol: u8,
    src_port: u16, dst_port: u16, dscp: u8,
    extra: TermMatchExtra<'_>, packet_bytes: u64,
) -> Option<FilterRoutingInstanceResult<'a>> { /* body from eval.rs:932-956 */ }

// existing signature retained as a wrapper (other callers unaffected):
pub(crate) fn evaluate_interface_filter_routing_instance_event_counted<'a>(
    state: &'a FilterState, ifindex: i32, is_v6: bool, /* … */
) -> Option<FilterRoutingInstanceResult<'a>> {
    let filter = if is_v6 { state.iface_filter_v6_fast.get(&ifindex) }
                 else      { state.iface_filter_v4_fast.get(&ifindex) };
    evaluate_filter_ref_routing_instance_event_counted(filter?.as_ref(), /* … */)
}
```

PBR then fetches ONCE and threads the borrow:

```rust
let filter = if is_v6 { forwarding.filter_state.iface_filter_v6_fast.get(&ingress_ifindex) }
             else      { forwarding.filter_state.iface_filter_v4_fast.get(&ingress_ifindex) };
let Some(filter) = filter.map(Arc::as_ref) else { return RouteOverride::None; };
if !filter.affects_route_lookup { return RouteOverride::None; }        // was the set probe
let extra = term_match_extra_from_frame(frame, meta);
let routing_result = match evaluate_filter_ref_routing_instance_event_counted(filter, …) {
    Some(r) => r, None => return RouteOverride::None,
};
```

Same `Arc::as_ref` borrow feeds both the `affects_route_lookup` check and the
eval — one probe, no clone (the `Arc` in the map outlives the call). Mirror the
same wrapper/core split for the input non-routing evaluator
(`evaluate_interface_filter_non_routing_counted`, poll_descriptor/filter.rs:229)
so its `#2620` count-policy decision (which today set-probes at :219) reads
`affects_route_lookup` off the same fetched filter it evaluates.

---

## 6. Public API preservation

All `FilterState` fields are `pub(crate)`; no external/gRPC/wire surface (§7 inv.1).
Preserved crate-internal accessor signatures (bodies change, callers untouched):
`interface_filter_affects_route_lookup`, `interface_input_filter_has_dscp_match`,
`interface_input_filter_has_per_packet_l4_match`,
`interface_output_filter_needs_tx_eval`, `filter_state_has_input_tx_selection`,
`filter_state_has_input_three_color_policer`,
`interface_output_filter_has_dscp_match` /
`interface_output_filter_has_per_packet_l4_match` (already fast-map, unchanged).

**Added:** `Filter::needs_tx_eval()`; `evaluate_filter_ref_routing_instance_event_counted`
(and the non-routing `&Filter` core). **Removed:** `filter_state_has_output_tx_selection`
(production-dead) + the `has_output_tx_selection_v*` fields (§5.2). The four hot
prechecks keep their signatures; only their bodies swap set→fast-map — so the
single-lookup fold in §5.3/§8 is a *call-site* change at PBR + poll-descriptor +
cos_classify, not an accessor break.

---

## 7. Hidden invariants to preserve

1. **No wire / HA-sync crossing.** `FilterState` is in-process
   (`ForwardingState.filter_state`, forwarding.rs:264); `#[derive(Clone, Debug,
   Default)]`, no `Serialize`/`repr(C)`/`bytemuck`, rebuilt from snapshot each
   apply. The refactor cannot desync peers. Keep `Default` derivable (all
   retained/added fields are `Default`) and `Clone` (snapshot swap clones it).
2. **#3296 fail-closed `MissingFilterRef`.** The `filters.get()` presence guard
   at each direction (compiler.rs:183-194/215-225/252-260/281-289 + lo0
   303-328) is the ONLY thing preventing a dangling output hook from failing
   OPEN — it must stay byte-identical. Deleting the `needs_tx_eval` set `.insert`
   must not touch the `else { return Err(MissingFilterRef) }` arm. **Re-anchor
   the doc**: `filter/README.md:710-712` currently pins the fail-closed contract
   to the fast maps **and the `needs_tx_eval` sets**; after PR-2 it keys off the
   fast maps + the `has_output_needs_tx_eval_*` aggregate. Update it.
3. **`Arc<Filter>` identity.** Fast maps keep `Arc<Filter>` verbatim; the
   `&Filter` cores take `Arc::as_ref` — no clone, no identity change.
4. **#1430 cache-sensitivity bit-identical.** `set.contains(&if)` was populated
   iff `filter.has_dscp_match_terms` (resp. `has_per_packet_l4_match_terms`), so
   `fast.get(&if).is_some_and(|f| f.has_dscp_match_terms)` is bit-identical for a
   unique ifindex, and last-wins-consistent for a duplicate (§5.1). A silent
   divergence corrupts the flow cache (a DSCP-varying flow gets a stale verdict).
   Runbook docs mirror the same field names in three places —
   `filter/mod.rs:76-90`, `protocol/security.rs:137-147`, `filter/README.md:497`
   — update all three.
5. **`needs_tx_eval` composite identity (#2620-adjacent).** `Filter::needs_tx_eval()`
   must OR *exactly* the five flags the compiler ORed (compiler.rs:199-204). The
   two inline recomputes at cos_classify.rs:225-231 and :667-673 MUST be replaced
   by the accessor (not left as a drifting second definition).
6. **Counter-ownership ordering (#2620).** poll_descriptor/filter.rs:219-242
   picks `NonRoutingCountPolicy` from `affects_route_lookup` *before* the eval, to
   avoid double/under-count. The fold must decide the policy from the fetched
   `&Filter`'s `affects_route_lookup`, then evaluate with that policy — the borrow
   must outlive both uses. No reordering of count-policy-vs-eval.
7. **NAT64 family selection (#3642 / #5158).** cos_classify selects the INPUT
   filter family from the pre-NAT ingress key (`ingress_is_v6`) and the OUTPUT
   filter family from the post-NAT egress key (`is_v6`) — two distinct `is_v6`
   selectors (cos_classify.rs:266-285 / 725-744). The fold must NOT collapse
   them: fetch the output filter with `is_v6`, the input aggregates with
   `ingress_is_v6`.
8. **Aggregate-false fast branch.** cos_classify.rs:286-292 / 745-757 early-return
   `default()` when `!has_output_tx_eval && !has_input_tx_selection &&
   !has_input_three_color_policer`. After the fold, `has_output_tx_eval` is
   `output_filter.as_ref().is_some_and(|f| f.needs_tx_eval())` computed from the
   SAME `.get()` that the arm below reuses — the early-return semantics are
   preserved, one probe instead of a set-probe + a map-get.

---

## 8. Call-site fold map (single-lookup)

| Site | Today | After fold | Probe Δ |
|---|---|---|---|
| PBR (pbr.rs:60 + eval.rs:924) | set `.contains` + map `.get` | one `.get`, read `affects_route_lookup`, pass `&Filter` | **2→1** |
| Input non-routing (poll_descriptor/filter.rs:219 + eval `.get`) | set `.contains` (count policy) + map `.get` (eval) | one `.get`, `affects_route_lookup` → count policy, pass `&Filter` | **2→1** |
| Output TX cached flow-keyed (cos_classify.rs:274-309) | set `.contains` + map `.get` | one `.get`, `needs_tx_eval()` gate + reuse | **2→1** |
| Output TX cached flowless (cos_classify.rs:206-247) | set `.contains` + map `.get` + inline 5-flag recompute | one `.get`, `needs_tx_eval()` | **2+recompute→1** |
| Output TX runtime flow-keyed (cos_classify.rs:733-…) | set `.contains` + map `.get` | one `.get`, `needs_tx_eval()` gate + reuse | **2→1** |
| Output TX runtime flowless (cos_classify.rs:648-716) | set `.contains` + map `.get` + inline recompute | one `.get`, `needs_tx_eval()` | **2+recompute→1** |
| Session-hit DSCP/L4 gate (poll_descriptor/filter.rs:356-364) | two set `.contains` | one `.get`, read BOTH flags | **2→1** |
| Flow-cache seed decline (flow_cache.rs:475-508) | 2 input set-probes + 2 output map-gets (distinct ifindices) | 2 input map-gets + 2 output map-gets | **neutral** (ingress≠egress; no merge) |
| `tx_selection_enabled_*` build gate (forwarding_build/mod.rs:420) | set `.is_empty()` | `has_output_needs_tx_eval_*` aggregate | cold (compile-time) |

**Honest caveat (unchanged from umbrella §3c):** the flow-cache seed-decline gate
is boolean-only and probes ingress-input + egress-output on *different*
interfaces, so it stays 4 probes (set→map for the two input ones). No uniform
2→1; state this to reviewers. Acceptance ("no more hash probes for the
capability-hook lookups") is met for every eval-following site and neutral for
the boolean-only gate.

---

## 9. Test plan

- `cargo build -p userspace-dp` + `cargo clippy` clean on the branch; `make
  test-rust` full (filter, CoS, forwarding, cache-rotation, snapshot-integrity),
  `make test-go` (retirement path-keyed canary needs the full Go suite even
  though no Go touches `FilterState`).
- **Equivalence test — added BEFORE deleting any set (sub-PR B gate).** For a
  normally-compiled `FilterState` (unique ifindices), assert for every set:
  `set.contains(&if) == fast.get(&if).is_some_and(flag)` across all four
  families/directions AND the `needs_tx_eval` composite. This proves the accessor
  body-swap is behavior-preserving on the common path. Keep it in the tree as a
  regression pin even after the sets are deleted (rewrite the LHS to the retained
  fast-map read once the sets are gone, so it guards the accessor semantics).
- **Duplicate-ifindex test (blocker #1).** Compile a `FilterState` from two
  interface entries sharing an ifindex+family+direction — first filter
  DSCP-sensitive/route-affecting, second not — and assert: (a) `iface_filter_*_fast`
  holds the SECOND (last-wins); (b) after the fold the precheck reads the second
  filter's flag (`false`); (c) the recomputed aggregate is derived from the final
  map (not stale-true); (d) `parse_filter_state` still `Ok` (we did NOT adopt
  reject-fail-closed). This pins the §5.1 decision.
- **Parent-RED (three, one per blocker).** (1) Make `Filter::needs_tx_eval()` drop
  `has_counter_terms`; assert a counter-only output filter's TX-eval /
  `tx_selection_enabled` test goes red (blocker #2). (2) Make the DSCP precheck
  read the wrong flag; assert `flow_cache` DSCP-coherency test red (#1430). (3)
  Make the PBR fold skip the `affects_route_lookup` check; assert a PBR
  routing-instance test red. Each must be an ASSERTION failure, not a build break
  (vet-safe neutralization — invert a comparison / drop one OR operand, not
  `&& false`).
- **`has_output_tx_selection` deletion safety.** Grep-prove
  `filter_state_has_output_tx_selection` + `has_output_tx_selection_v*` have no
  consumer beyond the OR + the one test (tests.rs:2336) before deleting; update
  that test to the new aggregate.
- **5× flake** on the most-affected targeted test under `TMPDIR=/tmp` (sun_path
  108 trap).
- **Loss-cluster iperf smoke (filter is hot-path; output-TX fold touches CoS).**
  `make cluster-deploy` then `make test-failover` + `security-matrix`: v4 **and**
  v6, push **and** reverse, CoS-on **and** CoS-off, and **per-class CoS**
  (`cos-iperf-config.set`, ports 5200-5211). Re-apply CoS after deploy
  (`apply-cos-config.sh` — deploy wipes CoS). Reassert node0 primary before
  failover (memory: post-deploy node0 stays SECONDARY). Serialize through one
  agent under the shared-cluster lock. Smoke gates sub-PR C (the hot-path fold);
  sub-PR A/B can ride the same cluster cycle or a batched smoke.
- **Bench (acceptance).** Micro-bench absent-hook / present-simple / capability
  hook lookups; assert no added probe on the eval-following sites and ≤1%
  regression on the boolean-only gate; print `size_of::<FilterState>()`
  before/after; inspect optimized asm for no new alloc/indirect-call/atomic on
  the packet path.

---

## 10. Sub-PR split (recommendation: 3 sequenced PRs, A→B→C)

Codex's suggested ordering, mapped to attributable-smoke discipline:

- **PR-2A — foundations (LOW-MED).** Add `Filter::needs_tx_eval()`; add
  `has_output_needs_tx_eval_v{4,6}`; recompute ALL aggregates from the FINAL fast
  maps post-loop (§5.1); rewire `tx_selection_enabled_*` (§5.2); replace the two
  cos_classify inline recomputes with the accessor. Delete
  `has_output_tx_selection_v*` + its dead accessor. **No set deleted yet, no
  call-site fold yet** — sets and prechecks still work unchanged. Adds the
  duplicate-ifindex test. Parent-RED #2.
- **PR-2B — accessor migration + set deletion (MED, cache-sensitivity).** Swap the
  four hot precheck bodies (`interface_filter_affects_route_lookup`,
  `interface_input_filter_has_dscp_match`,
  `interface_input_filter_has_per_packet_l4_match`,
  `interface_output_filter_needs_tx_eval`) from set→`fast.get().is_some_and(flag)`;
  land the equivalence test FIRST, then delete the 8 sets. Parent-RED #1(DSCP).
  23→15 fields realized here.
- **PR-2C — single-lookup fold (MED-HIGH, hot path).** Add the `&Filter`
  evaluator cores (routing + non-routing); fold PBR (blocker #3), the
  poll-descriptor route-lookup/count-policy site (#2620 borrow), and the four
  cos_classify arms (cached/runtime × flow-keyed/flowless), preserving the
  aggregate-false branch + NAT64 family split. Parent-RED #3(PBR). Owns the
  loss-cluster CoS smoke.

**Decision: N=3, not 1.** They carry sharply different risk (A cold/compile-time;
B cache-coherency; C hot-path borrow + counter-ordering + NAT64), and separate
PRs keep parent-RED and smoke attributable (project memory: two-gate discipline).
A+B could fold into one PR if reviewers prefer 2 (they share the "sets" surface
and B is trivial once A recomputes aggregates from the final map), but **C must
stay separate** — it is the hot-path change that earns its own smoke + bench.
Signatures never change across the boundary, so consumers never see an
intermediate broken state; no per-direction compatibility shim is needed.

**Out of scope:** the registries (`filters`, policer maps); the `Filter` struct
(only the additive `needs_tx_eval()` method); Go control plane / gRPC / wire; the
output DSCP/L4 accessors (already fast-map); Design B `hooks.rs`.

---

## 11. Open questions for adversarial review (each PLAN-KILL-invitable)

1. **Is the per-packet win worth PR-2C's hot-path churn?** The eval-following
   sites drop one probe; the boolean-only flow-cache gate is neutral. Given one
   `FilterState` cloned per snapshot (not per-CPU), the sizeof win (15 fields) is
   clone-cost + clarity, not a packet cache-line win. If the bench shows <0.5% and
   the fold forces awkward borrows (§Q5), is PR-2C worth it, or should #6236 stop
   at PR-2A+B (delete the sets, read off `Filter`, accept probe-count stays 1
   where a boolean suffices and 2 only where an eval follows — i.e. no worse than
   today)? **PLAN-KILL PR-2C** is defensible; A+B alone still deletes 8 fields.

2. **Is a duplicate ifindex reachable from a committed config, or only drift?**
   §5.1 (b) is robust either way (all values derive from the final map), but if
   duplicates are structurally impossible (each logical unit → distinct kernel
   ifindex; the Go snapshot builder de-dups) then the whole hazard is theoretical
   and the duplicate-ifindex test documents an unreachable state. Conversely, if
   duplicates ARE reachable, does the team want (a) reject-fail-closed as a
   *separate* hardening issue? I did not trace the Go `snapshot.interfaces`
   builder for a uniqueness guarantee — a reviewer should.

3. **Does deleting `has_output_tx_selection_v*` (§5.2) miss a consumer?** Grep
   shows only the `tx_selection_enabled` OR + a production-dead accessor + one
   test. Is there a reflection/status/Debug path, or a planned consumer, that
   makes retaining it (the 17-field minimal-diff variant) safer?

4. **Does reading a flag off `Arc<Filter>` add a pointer-chase the set avoided on
   the boolean-only gates?** `set.contains(&if)` touches only the set's control
   bytes; `fast.get(&if)` then `f.has_dscp_match_terms` chases the `Arc` to heap.
   For eval-following sites this is free (the eval chases it anyway). For the
   flow-cache seed gate and session-hit gate (boolean-only), is the extra `Arc`
   deref measurable at line rate? The bench MUST include the boolean-only path.

5. **PR-2C borrow ergonomics under #2620 + #3642.** Threading one `&Filter`
   through the count-policy decision, the NAT64 family selection, and the
   evaluator without a second `.get()` or a clone — is it clean in the actual
   control flow of `poll_descriptor/filter.rs` and `cos_classify.rs`, or does the
   borrow force a restructure that eats the win? (The `Arc` in the map outlives
   the call, so `let f = map.get(&if)?.as_ref();` should suffice — verify no
   `&mut FilterState`/`state` reborrow conflict on the counted-eval path.)

6. **Equivalence-test lifetime.** After the sets are deleted (PR-2B), the
   `set.contains == fast.flag` equivalence test loses its LHS. Rewriting it to
   assert the accessor's fast-map semantics keeps a regression pin but no longer
   proves "the fold preserved the OLD behavior" (nothing does, once the sets are
   gone). Is a git-history note + the parent-RED sufficient, or should PR-2B keep
   the sets one extra commit purely to run the equivalence assertion in CI before
   removing them in the same PR's final commit?
