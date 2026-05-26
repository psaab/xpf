# #1163 plan v1 — next_table resolution: recursion + String → iterative + interned table ID

## Status

DRAFT v1 — pending adversarial plan review.

## Issue framing (#1163, in our words)

The issue claims `lookup_forwarding_resolution_v4/v6` in
`userspace-dp/src/afxdp/forwarding/mod.rs` is an "IPC killer" because it
resolves inter-VRF route leaks via:

1. **Recursion**: `lookup_forwarding_resolution_v4(..., depth + 1, ...)`
   at mod.rs:1273 (v4) and mod.rs:1421 (v6), bounded by
   `MAX_NEXT_TABLE_DEPTH = 8` (mod.rs:5).
2. **String comparison + String key**: the routing table is identified
   by `&str` (`table: &str` at mod.rs:1178), looked up in
   `routes_v4: FastMap<String, Vec<RouteEntryV4>>`
   (types/forwarding.rs:21), and the loop guard `next_table_name ==
   table` is a String compare (mod.rs:1260). `RouteEntryV4.next_table`
   is `String` (types/forwarding.rs:92).

The proposed fix (from the issue body):

1. Pre-compute route leaks in the Go control plane and push only
   flattened next-hops to Rust.
2. Use `u16` integer table IDs instead of String names.
3. Replace recursion with a bounded `while` loop.

## Honest scope/value framing

What this is NOT:
- It is **not** "per-packet" on the established-flow fast path. Flow-cache
  hits (`poll_descriptor/flow_cache_hit.rs:93` —
  `flow_state.flow_cache.lookup_counted(...)`) short-circuit *before*
  any call to `lookup_forwarding_resolution_*`. The only hot call site
  is `poll_descriptor/mod.rs:1006` —
  `lookup_forwarding_resolution_in_table_with_dynamic` — and that runs
  on session-miss only (first packet of a new flow that did not match
  an interface-local or interface-NAT shortcut).
- It is **not** a stack-overflow risk. Recursion is hard-capped at
  `MAX_NEXT_TABLE_DEPTH = 8` (mod.rs:1182, 1330). Each frame holds
  `state: &…, dynamic_neighbors, ip, table: &str, depth, allow_tunnels`
  plus locals — well under one kilobyte. Eight frames is ~5-8 KB worst
  case on a 1 MB+ worker thread stack.
- It is **not** an L1-d thrasher in the issue's sense. Each recursive
  step does:
  - One FxHashMap String key hash + lookup on `routes_v4.get(table)`
    (~30-80 cycles cold, ~10-25 cycles L1-hot).
  - A linear scan of the table's `Vec<RouteEntryV4>` to find the
    longest-prefix match (the vec is pre-sorted by descending prefix
    length at build time, but the scan still goes from index 0).
  - The recursion guard is *one* `&String == &str` compare against the
    current table; no other String compares per step.

What this actually IS (the real, smaller win):
- **String allocation on every entry**: `lookup_forwarding_resolution_inner`
  at mod.rs:881-883 does
  `table.map(|table| canonical_route_table(table, false))
   .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string())`.
  Every session-miss resolution allocates at least one String, plus
  another if the canonicalisation goes through the `format!("{prefix}.inet6.0")`
  arm (mod.rs:32, 39). That's a heap allocation + free per session-miss
  resolution. The recursion does NOT allocate again — it passes
  `&next_table_name` — but the entry path does.
- **String-keyed hash lookup**: each FxHashMap get on a String key
  hashes the full string (typically 6-22 bytes — `"inet.0"`,
  `"Comcast.inet.0"`, `"red.inet6.0"`). With u16 IDs the same lookup
  is a single load from a flat `Vec<…>` indexed by ID — ~3-5 cycles
  vs ~25-60 cycles cold.
- **Recursion → iteration**: not a perf win in isolation (LLVM tail-
  calls the self-recursion already since the recursive call is in
  tail position on both v4 and v6 paths, mod.rs:1273/1421). The win
  is structural: the iterative form lets us fold the v4/v6 paths
  into a single resolver with a clearer "current table" cursor, and
  removes a class of "argument drift" bugs where future modifications
  could pass the wrong table downward.

**Absolute-scale estimate (worst case):**
- 50k-100k session-installs per second peak (NEW-flow rate; sustained
  established traffic uses flow-cache).
- Per session-miss, current path: ~1 String allocation + ~25-60 cycles
  on the FastMap String hash + ~5-15 cycles per recursion step
  (assume 1-2 hops in production; depth-8 case is exceptionally rare).
  Total: ~80-150 cycles + 1 alloc/free pair.
- After fix: ~3-5 cycles for `Vec<…>[id as usize]` + 0 allocations.
- Estimated saving: **~70-145 cycles per session install + one
  alloc/free pair**. At 100k session-misses/sec on a 3 GHz core: ~7-15
  microseconds/sec of CPU, i.e. ~0.0007-0.0015% of one core.
- The allocator-pressure win matters more than the cycle count: on
  hot session-install paths we are also fighting jemalloc lock
  contention from sync paths (HA, GC). Removing one alloc/free pair
  per session install is a structurally clean win, just not a
  perf-headline one.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** This is exactly the
class of "issue body inflates the impact" finding that previous
triple-review rounds (#967, #969, #1243, #1244) killed at plan time.

## What's already shipped that this composes with

- **Flow cache** (`flow_cache.rs`): post-resolution caching of
  `ForwardCandidate` / `FabricRedirect` dispositions, gated on RG epoch
  (#1065). This is why `lookup_forwarding_resolution` is *not* per-packet
  — flow_cache absorbs the second-and-subsequent packets of every flow.
- **#921 zone_id_to_u16**: precedent for replacing String identifiers
  with u16 IDs at config-build time. `forwarding.zone_name_to_id`
  (types/forwarding.rs:34) is the existing pattern. This work would
  add `forwarding.route_table_name_to_id` in the same idiom.
- **#1373 / #1476 retirement of legacy BPF dataplane**: confirms
  userspace-dp owns the next_table semantics. No BPF map state to keep
  in sync.

## What's NOT done by this PR (deferred follow-ups)

- **Go-side pre-flattening**: option (1) from the issue body —
  resolving route leaks in Go and pushing only flattened next-hops to
  Rust — is **out of scope**. It would require:
  1. The Go compiler to recursively walk `RoutingInstanceConfig` +
     `StaticRoute.NextTable` chains.
  2. A new wire-protocol message shape (flattened FIB without
     `next_table` strings).
  3. Reasoning about how `rib-group` + DHCP-learned routes interact
     with pre-flattening (today, DHCP routes go into FRR and are
     re-snapshotted; if Go pre-flattens, late-arriving DHCP routes in
     a leaked-to table would need a re-flatten round-trip).
  4. Compatibility with the legacy `pkg/routing/routing.go`
     `ApplyNextTableRules` path that today programs Linux policy
     routing rules from the same data.
  Out of scope; this plan is Rust-side only.
- **Removing String entirely**: we keep `RouteEntryV4.next_table` and
  the wire-protocol field as String to preserve the Junos config
  semantics (route leak target identified by routing-instance NAME).
  At Rust ForwardingState build time we *resolve* the name to an
  `Option<RouteTableId>` and store that resolved ID; the recursive
  loop then operates on IDs only.

## Concrete design

### New types

```rust
// userspace-dp/src/afxdp/types/forwarding.rs

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub(in crate::afxdp) struct RouteTableId(pub u16);

impl RouteTableId {
    pub(in crate::afxdp) const INVALID: RouteTableId = RouteTableId(0);
    pub(in crate::afxdp) const DEFAULT_V4: RouteTableId = RouteTableId(1);
    pub(in crate::afxdp) const DEFAULT_V6: RouteTableId = RouteTableId(2);

    #[inline]
    pub(in crate::afxdp) fn is_valid(self) -> bool {
        self.0 != Self::INVALID.0
    }
    #[inline]
    pub(in crate::afxdp) fn index(self) -> usize {
        self.0 as usize
    }
}
```

### ForwardingState changes

```rust
pub(in crate::afxdp) struct ForwardingState {
    // ... existing fields ...

    // OLD: pub(in crate::afxdp) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    // NEW:
    pub(in crate::afxdp) routes_v4_by_id: Vec<Vec<RouteEntryV4>>, // indexed by RouteTableId.0
    pub(in crate::afxdp) routes_v6_by_id: Vec<Vec<RouteEntryV6>>,

    // Name → ID resolution, populated at build time.
    pub(in crate::afxdp) route_table_name_to_id: FastMap<String, RouteTableId>,
    // ID → Name, for telemetry/debug status output (kept for parity with #921 zone_id_to_name).
    pub(in crate::afxdp) route_table_id_to_name: Vec<String>,
}
```

### RouteEntry changes

```rust
pub(in crate::afxdp) struct RouteEntryV4 {
    // ... existing fields ...
    // OLD: pub(in crate::afxdp) next_table: String,
    // NEW:
    pub(in crate::afxdp) next_table: RouteTableId, // INVALID if no next-table
}
```

(Same shape for `RouteEntryV6`.)

### Iterative resolution function

```rust
pub(super) fn lookup_forwarding_resolution_v4_iter(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    start_table: RouteTableId,
    allow_tunnels: bool,
) -> ForwardingResolution {
    // Track visited tables to detect loops without separate counter.
    // (Cycle detection is currently `next_table_name == table`, which
    // only catches self-loops. The bounded `depth >= MAX_NEXT_TABLE_DEPTH`
    // counter catches longer cycles.)
    //
    // Preserve EXACTLY the current semantics:
    //   - hard cap at MAX_NEXT_TABLE_DEPTH (8) returns NextTableUnsupported
    //   - self-loop (current_table == next_table) returns NextTableUnsupported
    //   - depth==0 case has `allow_tunnels` passed through; deeper steps
    //     also pass `allow_tunnels` unchanged.

    let mut current_table = start_table;
    let mut depth = 0usize;

    loop {
        if !current_table.is_valid() {
            return no_route_resolution(Some(IpAddr::V4(ip)));
        }
        if depth >= MAX_NEXT_TABLE_DEPTH {
            return next_table_unsupported_v4(ip);
        }

        let routes = state
            .routes_v4_by_id
            .get(current_table.index())
            .filter(|routes| !routes.is_empty());
        let static_match = routes
            .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
        let connected_match = state
            .connected_v4
            .iter()
            .find(|entry| entry.prefix.contains(ip));

        match choose_v4_route(static_match, connected_match) {
            Some(ResolvedRouteV4::Connected { ifindex, tunnel_endpoint_id }) => {
                return resolve_connected_v4(
                    state, dynamic_neighbors, ip,
                    ifindex, tunnel_endpoint_id, depth, allow_tunnels,
                );
            }
            Some(ResolvedRouteV4::Static { ifindex, tunnel_endpoint_id, next_hop, discard, next_table }) => {
                if discard {
                    return discard_resolution_v4(ip, ifindex, tunnel_endpoint_id, next_hop);
                }
                if next_table.is_valid() {
                    if next_table == current_table {
                        return next_table_unsupported_v4(ip);
                    }
                    current_table = next_table;
                    depth += 1;
                    continue; // <-- iterative tail call
                }
                return resolve_static_v4(
                    state, dynamic_neighbors, ip,
                    ifindex, tunnel_endpoint_id, next_hop, depth, allow_tunnels,
                );
            }
            None => return no_route_resolution(None),
        }
    }
}
```

`choose_v4_route` and the inner `Connected`/`Static` resolvers are
factored into helpers to keep the loop body small. `lookup_forwarding_resolution_inner`
becomes:

```rust
let start_table = table
    .and_then(|table| state.route_table_name_to_id.get(table).copied())
    .unwrap_or(RouteTableId::DEFAULT_V4);
lookup_forwarding_resolution_v4_iter(state, dynamic_neighbors, ip, start_table, true)
```

The `canonical_route_table` String allocation is eliminated for hot
path; canonicalisation moves into the `route_table_name_to_id` lookup
(the table only needs to canonicalise the name once at build time when
keys are inserted, plus once per session-miss when the caller passes a
non-default `&str` — but the canonicalised result lives in the FastMap
key, so the *lookup* hashes the operand directly with no fresh
allocation).

Actually, to preserve "caller passes `untrust.inet.0`, but state was
built with `untrust.inet.0` canonicalised" semantics, we keep the
canonicalisation step but only on the slow-path callers that pass
named `&str` (`coordinator/inject`, `icmp_embed`, `shared_ops`). The
hot-path call from `poll_descriptor/mod.rs:1006` already has a
`Option<&str>` and we resolve it to `RouteTableId` once via the
`route_table_name_to_id` FastMap. That FastMap key uses the canonical
form (we canonicalise at insertion time in `build_forwarding_state`).

### Build-time changes

In `forwarding_build.rs` (line 308-344 today):

```rust
// Build a stable id assignment for every table NAME we encounter.
let mut name_to_id: FastMap<String, RouteTableId> = FastMap::default();
let mut id_to_name: Vec<String> = vec![String::new(), DEFAULT_V4_TABLE.into(), DEFAULT_V6_TABLE.into()];
// Slot 0 reserved = INVALID; slot 1 = inet.0; slot 2 = inet6.0.
name_to_id.insert(DEFAULT_V4_TABLE.into(), RouteTableId::DEFAULT_V4);
name_to_id.insert(DEFAULT_V6_TABLE.into(), RouteTableId::DEFAULT_V6);

let mut intern = |name: &str, is_ipv6: bool| -> RouteTableId {
    let canon = canonical_route_table(name, is_ipv6);
    if let Some(id) = name_to_id.get(&canon) {
        return *id;
    }
    let id = RouteTableId(id_to_name.len() as u16);
    id_to_name.push(canon.clone());
    name_to_id.insert(canon, id);
    id
};

// First pass: assign IDs for every table mentioned in routes
// (including next_table references) and route_instances. This
// guarantees that next_table on a route always resolves to an ID
// even if the referenced instance has no routes of its own yet.
for route in &snapshot.routes {
    // ...
    let _ = intern(&route.table, /*is_ipv6=*/ false);
    if !route.next_table.is_empty() {
        let _ = intern(&route.next_table, /*is_ipv6=*/ false);
        // Same for the v6 sibling — Junos puts `next-table` under
        // both `inet` and `inet6` independently; the routing
        // compiler resolves the .inet vs .inet6 variant per family.
    }
}

// Second pass: populate routes_v4_by_id / routes_v6_by_id.
state.routes_v4_by_id.resize_with(id_to_name.len(), Vec::new);
state.routes_v6_by_id.resize_with(id_to_name.len(), Vec::new);
for route in &snapshot.routes {
    // ... existing logic, but:
    let table_id = intern(&route.table, is_ipv6);
    let next_table_id = if route.next_table.is_empty() {
        RouteTableId::INVALID
    } else {
        intern(&route.next_table, is_ipv6)
    };
    state.routes_v4_by_id[table_id.index()].push(RouteEntryV4 {
        // ... next_table: next_table_id, ...
    });
}

state.route_table_name_to_id = name_to_id;
state.route_table_id_to_name = id_to_name;
```

The `BorrowMut`/closure-capture shape here is awkward (`intern`
mutably borrows three fields). In the actual implementation we'll
factor it into a method on a small `TableInterner` struct that
takes `&mut self` and stores the three fields. The above is for
plan readability.

## Public API preservation

- `lookup_forwarding_resolution(state, dst)` — unchanged signature.
- `lookup_forwarding_resolution_with_dynamic(state, dn, dst)` — unchanged.
- `lookup_forwarding_resolution_in_table_with_dynamic(state, dn, dst, table: Option<&str>)`
  — unchanged signature; internal body resolves the `&str` to
  `RouteTableId` once, then delegates to the iterative resolver.
- `lookup_forwarding_resolution_v4/v6(state, dn, ip, table: &str, depth, allow_tunnels)`
  — **deprecated but kept** as a thin adapter that resolves `table`
  to an ID and calls the iterative form. This preserves all `tests.rs`
  call sites verbatim. Mark with `#[doc(hidden)]` + comment to deter
  new use.
- `ForwardingDisposition::NextTableUnsupported` — unchanged.
- `RouteEntryV4 { next_table: String }` → `RouteEntryV4 { next_table: RouteTableId }`
  is a **breaking field change** but the field is
  `pub(in crate::afxdp)` (types/forwarding.rs:11) — module-internal only,
  no external consumers.

## Hidden invariants the change must preserve

1. **Side-effect ordering**: there are no side effects in the
   resolution path. Pure read of ForwardingState.
2. **Allocation rules**: per the project's hot-path allocation policy,
   the resolution path must not allocate. Today it allocates one
   String per call (canonical_route_table). After fix: zero
   allocations on the hot path (assuming caller already has a
   `RouteTableId`; the slow-path `&str` callers still allocate during
   the FastMap lookup, but that's not the hot path).
3. **HA sync portability**: `ForwardingState` is built per-snapshot
   from `ConfigSnapshot` which is the same wire shape on both nodes.
   The `route_table_name_to_id` mapping is built deterministically
   from the same snapshot ordering, so both nodes assign the same
   IDs to the same table names. **However**: IDs are stable only
   within a single snapshot. If a new table appears in snapshot N+1
   that didn't exist in N, IDs assigned in N+1 may differ. Since
   IDs are not persisted across snapshots (rebuilt fresh each commit),
   this is fine. `ForwardingResolution` carries no `RouteTableId`
   in its output, so no cross-snapshot ID leakage.
4. **Stale-handle hazards**: the resolver passes `RouteTableId` by
   value through the loop, indexing into `routes_v4_by_id` each
   iteration. No reference held across loop iterations to avoid
   the borrow-checker issue with the current `&next_table_name`.
5. **Lifetime / borrow-checker shape**: the iterative form is
   simpler than recursion here because there's no per-step borrow
   chain — `current_table: RouteTableId` is Copy, and each iteration
   re-borrows `state.routes_v4_by_id[i]` fresh.
6. **Cycle detection semantics**: current code rejects only the
   single self-loop `next_table_name == table` and otherwise relies
   on `depth >= MAX_NEXT_TABLE_DEPTH`. Plan preserves both: the
   self-loop check (now `next_table == current_table` via `==` on
   `RouteTableId`) AND the depth cap. A→B→A two-step cycle is
   still caught by depth=8 ceiling. Reviewers should confirm this
   is acceptable; if not, we add a small `[RouteTableId; 8]` visited
   array in the loop (stack-allocated, no heap).
7. **Default-table fallback**: when the caller passes `None` for
   `table`, current code uses `DEFAULT_V4_TABLE.to_string()` /
   `DEFAULT_V6_TABLE.to_string()`. Plan: `RouteTableId::DEFAULT_V4`
   / `RouteTableId::DEFAULT_V6` (constant IDs 1 and 2 reserved at
   slot 0=INVALID, slot 1=inet.0, slot 2=inet6.0).
8. **canonical_route_table semantics**: must still apply to
   slow-path callers that pass `&str` (e.g., a stat command from
   `coordinator/inject` that takes a user-typed table name).
   We canonicalise at FastMap insertion time AND at the slow-path
   `&str → RouteTableId` lookup time, so a caller that passes
   `"untrust.inet.0"` and one that passes `"untrust.inet6.0"` hit
   the right v4-or-v6 partition. The hot-path `poll_descriptor`
   call already knows the family from the IP, so it resolves in
   the correct family namespace.

## Risk assessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression risk | **MED** | Semantics preserved per invariants 1, 6, 7, 8. Risk surface: cross-family canonical lookup (caller passes a v6 packet with a v4-flavoured table name). Mitigated by per-family `route_table_name_to_id` mapping or by `intern` taking `is_ipv6`. Test plan exercises both. |
| Lifetime / borrow-checker risk | **LOW** | Iterative form with Copy IDs removes the recursive `&str` borrow chain. The interner closure during build needs refactor into a method, but that's straightforward. |
| Performance regression risk | **LOW** | Hot path is strictly fewer cycles + zero allocations. Cold path (slow-path callers) is bounded by an extra `FastMap<String, _>::get` lookup, which is the same op the old code did anyway. |
| Architectural mismatch (#961/#946-Ph2 pattern) | **LOW** | Direct precedent: #921 did exactly this for zone names. The shape of the change matches the codebase. No #961-style "PacketContext architecture doesn't fit" risk. |
| Wire-protocol risk | **NONE** | No protocol change. `RouteSnapshot.next_table: String` on the wire is unchanged. Resolution to `RouteTableId` happens inside `build_forwarding_state`. |

## Out of scope (explicit)

- **Pre-flattening route leaks in Go control plane**. Issue's
  proposal (1) deferred. Would require new wire-protocol message
  shape + interaction with DHCP-learned routes + rib-group. Reopen
  as a separate issue if Rust-side win is insufficient.
- **Removing String from `RouteSnapshot.next_table`**. Wire-level
  field still carries the routing-instance NAME for human-readable
  config + telemetry parity.
- **Touching `pkg/routing/routing.go` `ApplyNextTableRules`**. Linux
  policy-routing rule programming uses the same source data
  (`StaticRoute.NextTable`) but is independent of dataplane
  resolution. Untouched.
- **Pre-resolved chain materialisation**. We could pre-walk every
  `(table, prefix)` to its final next-hop at build time, eliminating
  even the iterative loop on the hot path. We choose not to because:
  (a) the loop runs at most 8 iterations; (b) materialising every
  `(table, prefix) → final hop` pair multiplies storage by the
  number of leaked tables; (c) it changes the semantics of
  "destination prefix changes mid-chain" — Junos resolves `next-table`
  at lookup time, not at config time. Preserving lookup-time
  resolution keeps Junos parity.

## Test plan

1. **Compile**: `cargo build --release` clean — no clippy regressions.
2. **Existing cargo tests** (forwarding/tests.rs has 30+ next_table-
   touching tests including the loop detection test at line 2128):
   - `forwarding_resolution_supports_next_table_recursion` (line 1982)
   - `forwarding_resolution_rejects_next_table_loop` (line 2128)
   - all `next_table` cases in `forwarding/tests.rs`,
     `frame/tests.rs`, and `tests.rs` continue to pass.
3. **5/5 flake check** on `forwarding_resolution_supports_next_table_recursion`
   and `forwarding_resolution_rejects_next_table_loop`.
4. **Go suite**: `go test ./pkg/config/... ./pkg/routing/...` —
   no changes to Go but assert nothing regresses.
5. **End-to-end route-leak smoke**:
   - Deploy on loss userspace cluster.
   - `set routing-instances foo instance-type virtual-router`
   - `set routing-options static route 10.99.0.0/16 next-table foo.inet.0`
   - Force a session into the leaked table; confirm packets exit on
     foo's interface, not on `inet.0` defaults.
6. **Full smoke matrix** per skill standing rules:
   - Pass A (CoS disabled): v4+v6 × push+reverse × single + `-P 12 -R`
     multi-stream. Line rate on multi-stream; 0 retrans on every cell.
   - Pass B (CoS enabled): per-class CoS smoke 5201-5206, all 24
     cells pass.

## Open questions for adversarial review

1. **Is the perf gain too small?** ~70-145 cycles + 1 alloc/free per
   session install at ~100k installs/sec ≈ ~0.001% of one core. Is
   this worth ~150-250 LOC of churn + new type + breaking the
   internal `RouteEntryV4.next_table` field shape? **A PLAN-KILL is
   acceptable here** — this is the exact #967/#969-style "issue body
   inflates the impact" pattern.
2. **Cycle detection**: today's code only rejects the immediate self-
   loop (`A → A`) and relies on `depth=8` for longer cycles
   (`A → B → A → B → ...`). Should we add a stack-allocated
   `[RouteTableId; 8]` visited array to detect cycles eagerly and
   return `NextTableUnsupported` at the first repeat? Or is preserving
   today's "burn through depth=8 then return Unsupported" behaviour
   the correct Junos parity?
3. **v4 vs v6 namespace collision**: `routes_v4` and `routes_v6` are
   separate FastMaps today, so a table NAME could theoretically be
   used in both families without conflict. The proposed shared
   `route_table_name_to_id` mapping would conflate them. Mitigation:
   per-family map (`route_table_name_to_id_v4` /
   `route_table_name_to_id_v6`) OR a single ID space where IDs are
   assigned per-family-keyed name. Reviewer pick?
4. **Snapshot churn cost**: today each ConfigSnapshot rebuild walks
   `snapshot.routes` once. The proposal needs **two passes** (first
   to assign IDs, second to populate routes by ID). Is that
   acceptable for snapshot rebuild latency? (Snapshot rebuilds are
   sub-millisecond today; doubling that is sub-millisecond still.)
5. **#1373 / userspace-dp scope**: the issue body proposes Go-side
   pre-flattening (option 1) as the headline fix. We are explicitly
   *not* doing that and deferring it. Is "Rust-side ID + iteration
   only" enough to call #1163 closed, or should this be Step 1 of a
   multi-step refactor with the Go-side flatten as Step 2? If Step 2
   is required, what's the right stop-line for Step 1?
6. **Compatibility with future dynamic FIB updates**: if the FIB
   ever moves to per-route incremental updates (vs full-snapshot
   rebuilds), the `route_table_name_to_id` mapping needs an
   "unstable IDs across snapshots" annotation. Today snapshots are
   atomic full rebuilds, so this is fine — but if anyone adds an
   incremental FIB-update path, IDs must be stabilised. Reviewer:
   is this worth a doc-comment now to prevent future foot-guns?
