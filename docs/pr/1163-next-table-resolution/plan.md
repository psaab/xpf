# #1163 plan v2 — next_table iterative + interned table ID, family-aware

## Status

DRAFT v2 — addressing round-1 findings.

## Round-1 verdicts

- **Gemini (pro-3, task-mpn2y7qs-ptdcm8): PLAN-KILL.**
  Key finding: NAT64 + PBR breaks the plan's "zero-allocation hot path"
  claim — `ingress_route_table_override` returns `.inet6.0`-suffixed
  names but NAT64 may translate `effective_resolution_target` to v4,
  so the current `canonical_route_table(table, false)` rewrites the
  suffix at lookup time. The plan's shortcut would look up the v6
  table ID and search v4 routes in the v6 partition (empty hit).
  Perf gain (~0.001% of a core on session-miss slow path) cited as
  "too small to justify new structural complexity to fix it."

- **Codex (task-mpn2x6g6-2zr1d0): PLAN-NEEDS-MAJOR.**
  Three concrete findings:
  (1) Go strips `next-table X.inet[6].0` to **bare routing-instance
      name** via `parseNextTableInstance`
      (`pkg/config/compiler_routing.go:266`); `RouteSnapshot.NextTable`
      carries `"Comcast"`, but `ForwardingState.routes_v4` is keyed by
      `"Comcast.inet.0"`. Today's `next_table_name == table`
      self-loop check (`forwarding/mod.rs:1260`) effectively never
      fires in production because the bare RI name is never equal to
      a suffixed table key. The recursive lookup
      `state.routes_v4.get("Comcast")` misses entirely → `None` →
      `no_route_resolution` for genuine `next-table` flows. **This is
      a latent functional bug, not just a perf issue.**
  (2) Same NAT64 + PBR finding as Gemini.
  (3) **Perf math was wrong by 100x**: 70-145 cycles × 100k/sec on
      3GHz is **0.23-0.48% of one core**, not 0.001%. Also,
      `choose_v4_route`/`choose_v6_route` already **clone**
      `route.next_table` at `forwarding/mod.rs:1625` and `:1655`, so
      the existing path allocates **per recursion hop**, not just per
      session-miss entry.

## Revised perf framing (honest)

- Real cost per leaked-route session miss:
  - `canonical_route_table` allocation at entry: 1 alloc/free (per
    session miss).
  - **Per recursion hop**: `choose_v[46]_route` clones `next_table`
    (`forwarding/mod.rs:1625`/`:1655`) → another alloc/free.
  - `FastMap<String, _>::get` hash + string compare for routes_v[46]:
    ~25-60 cycles cold per hop.
  - Linear scan of routes vec: depends on prefix count.
- Cycle math: 70-145 cycles + 1-N allocations per session install at
  ~100k installs/sec = **~7-15M cycles/sec ≈ 0.23-0.48% of one core**.
  Allocator pressure (vs jemalloc lock contention with HA / GC) is
  the more interesting axis.
- Caveat: this only matters for sessions that actually traverse a
  `next-table` route. On a config without `next-table`, the
  recursion never fires; the entry allocation
  (`canonical_route_table`) still happens but the rest is moot.

**This is still on the edge of "worth doing." PLAN-KILL remains a
valid verdict in round 2 if reviewers conclude the latent bug
(finding 1) should be a separate scoped bug fix and the perf framing
is too thin for the structural change.**

## What changed from v1

### A. Bare-RI next_table normalization (NEW — addresses Codex finding 1)

Today: `RouteSnapshot.NextTable` is the bare RI name from
`pkg/config/compiler_routing.go:266` `parseNextTableInstance`. Rust's
recursive lookup at `forwarding/mod.rs:1273` does
`lookup_forwarding_resolution_v4(..., &next_table_name, ...)` and then
`state.routes_v4.get(table)` at `:1197` — which misses because the
map is keyed by full table names (`"Comcast.inet.0"`).

Plan v2: at `build_forwarding_state` time, **normalize**
`route.next_table` (bare RI name) to the family-specific table name
that matches the existing key shape, **per family**:
- For `RouteEntryV4`: `next_table_v4_id = intern_v4("Comcast.inet.0")`.
- For `RouteEntryV6`: `next_table_v6_id = intern_v6("Comcast.inet6.0")`.

This makes `next-table` resolution **functional for the first time
under the production wire format**, independent of the perf
refactor. The refactor inherits this fix.

Open question: this is technically a bug-fix for a latent issue.
Should it ship as a separate one-line patch (just change the
recursive call site to `format!("{next_table_name}.inet.0")` or
similar) instead of being bundled into the perf refactor? Decision
deferred to reviewer pick.

### B. Per-family RouteTableId interning (replaces single shared map)

```rust
pub(in crate::afxdp) struct ForwardingState {
    // ... existing fields ...
    pub(in crate::afxdp) routes_v4_by_id: Vec<Vec<RouteEntryV4>>,
    pub(in crate::afxdp) routes_v6_by_id: Vec<Vec<RouteEntryV6>>,

    // Per-family interning. Slot 0 = INVALID; slot 1 = inet.0 / inet6.0.
    pub(in crate::afxdp) route_table_name_to_id_v4: FastMap<String, RouteTableId>,
    pub(in crate::afxdp) route_table_name_to_id_v6: FastMap<String, RouteTableId>,
    pub(in crate::afxdp) route_table_id_to_name_v4: Vec<String>,
    pub(in crate::afxdp) route_table_id_to_name_v6: Vec<String>,
}
```

`RouteTableId` carries no family tag — the caller selects the right
namespace by family. This addresses Gemini's namespace-collision
concern conservatively (separate maps; cheap; no semantic risk).

### C. Preserve canonical_route_table on hot path (addresses NAT64+PBR)

```rust
pub(super) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            // ... LocalDelivery shortcut unchanged ...
            //
            // The PBR + NAT64 case: caller may pass a `.inet6.0`-suffixed
            // table name when dst is v4 (NAT64 translated mid-pipeline).
            // We canonicalize to the v4-family table name first.
            let start_id = match table {
                Some(name) => {
                    let canon = canonical_route_table(name, /*is_ipv6=*/ false);
                    state
                        .route_table_name_to_id_v4
                        .get(canon.as_str())
                        .copied()
                        .unwrap_or(RouteTableId::INVALID)
                }
                None => RouteTableId::DEFAULT_V4, // ID 1 = "inet.0"
            };
            lookup_forwarding_resolution_v4_iter(state, dynamic_neighbors, ip, start_id, true)
        }
        IpAddr::V6(ip) => {
            // Mirror: canonical to v6 family.
            // ...
        }
    }
}
```

Trade-off: we keep one `canonical_route_table` allocation on the PBR
slow path. That's **net same** as today for PBR flows; we lose nothing.
For non-PBR flows (caller passes `None`), we use `DEFAULT_V[46]` ID
directly — zero allocations.

Then the iterative resolver:

```rust
pub(super) fn lookup_forwarding_resolution_v4_iter(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    start_table: RouteTableId,
    allow_tunnels: bool,
) -> ForwardingResolution {
    if !start_table.is_valid() {
        return no_route_resolution(Some(IpAddr::V4(ip)));
    }
    let mut current_table = start_table;
    let mut depth = 0usize;
    let mut visited = [RouteTableId::INVALID; MAX_NEXT_TABLE_DEPTH];

    loop {
        if depth >= MAX_NEXT_TABLE_DEPTH {
            return next_table_unsupported_v4(ip);
        }
        // Eager cycle detection (NEW — replaces today's self-loop-only check
        // and addresses Codex 'add A→B→A regression' note).
        if visited[..depth].iter().any(|&id| id == current_table) {
            return next_table_unsupported_v4(ip);
        }
        visited[depth] = current_table;

        let routes_for_table = state
            .routes_v4_by_id
            .get(current_table.index())
            .filter(|r| !r.is_empty());
        let static_match = routes_for_table
            .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
        let connected_match = state
            .connected_v4
            .iter()
            .find(|entry| entry.prefix.contains(ip));

        match choose_v4_route(static_match, connected_match) {
            Some(ResolvedRouteV4::Connected { ifindex, tunnel_endpoint_id }) => {
                return resolve_connected_v4(/* ... */);
            }
            Some(ResolvedRouteV4::Static {
                ifindex, tunnel_endpoint_id, next_hop, discard, next_table_id,
                // next_table_id is RouteTableId (was String); choose_v4_route
                // returns Copy values now (no clone).
            }) => {
                if discard { return discard_resolution_v4(/* ... */); }
                if next_table_id.is_valid() {
                    current_table = next_table_id;
                    depth += 1;
                    continue;
                }
                return resolve_static_v4(/* ... */);
            }
            None => return no_route_resolution(None),
        }
    }
}
```

`choose_v4_route`/`choose_v6_route` change shape: today they return
`ResolvedRouteV4::Static { next_table: String, ... }` (cloning).
After: `next_table_id: RouteTableId` (Copy, zero alloc per hop).
This is the **largest allocation win** in the refactor and was
understated in v1.

### D. Honest perf framing (replaces v1 framing)

- Eliminated allocations per session miss on `next-table` flows:
  - 1 entry alloc (`canonical_route_table` on non-PBR path) when
    caller passes `None` table.
  - N hop allocs (`choose_v[46]_route::next_table.clone()`) — 1 per
    depth-step, up to 8.
- Net win for a 2-hop session miss: ~3 allocations + ~50-120 cycles
  hashing.
- At 100k session installs/sec, **only** counting flows that hit
  `next-table` (say ≤10k/sec in a realistic VRF leak config):
  ~30k allocations/sec eliminated + ~1.5M cycles/sec saved
  ≈ **0.05% of one core**.
- Allocator-pressure axis is more interesting than CPU: removes a
  malloc/free cluster on the session-install slow path that competes
  with HA-sync, GC-callback, and bulk-snapshot writes for jemalloc
  arena locks.

**Honest verdict assessment**: this is a small-but-real perf win
**plus** a correctness fix (bare-RI normalization). The combined
package is worth ~250-350 LOC of churn. If reviewers conclude the
correctness fix should ship as a separate one-line patch and the
remaining perf gain is too small to justify the structural change,
**PLAN-KILL is still acceptable in round 2**.

## Test plan (updated)

1. `cargo build --release` clean.
2. **NEW**: `forwarding_resolution_rejects_next_table_cycle_a_b_a`
   — explicit A→B→A two-step cycle test, exercising the eager
   visited-set check.
3. **NEW**: `forwarding_resolution_handles_bare_ri_next_table`
   — fixture with `next_table: "blue"` (bare RI, mirroring Go
   wire format) and `routes_v4` keyed by `"blue.inet.0"`. Plan v2
   makes this pass; current code returns NoRoute. **This test
   should fail on current master**, proving the latent bug.
4. **NEW**: `forwarding_resolution_handles_nat64_pbr_canonical`
   — fixture with PBR override `"foo.inet6.0"` but lookup IP is
   v4 (NAT64-translated). Both current code and plan v2 should
   pass; this guards against the regression Gemini identified.
5. Existing tests unchanged: `forwarding_resolution_supports_next_table_recursion`,
   `forwarding_resolution_rejects_next_table_loop` (self-loop).
6. 5/5 flake check on the new + recursion test.
7. Go suite full.
8. Smoke matrix on loss userspace cluster: Pass A (CoS off) + Pass B
   (CoS on), per skill standing rules.

## Risk reassessment

| Class | Level | Rationale |
|-------|-------|-----------|
| Behavioral regression risk | **LOW** (down from MED) | Per-family interning eliminates namespace collision risk; canonical_route_table preserved on PBR slow path. Bare-RI normalization moves us *toward* correct behavior, not away. |
| Lifetime / borrow-checker risk | **LOW** | RouteTableId is Copy throughout. |
| Performance regression risk | **LOW** | Hot path strictly fewer cycles + zero/fewer allocations. |
| Correctness risk on bare-RI fix | **MED** | We are changing observable behavior for any config with `next-table` directives. Today: silently `no_route`. After: actually routes through the target table. Operators may have grown to expect the silent-drop behavior. **Mitigation**: this is correctness-fixing-a-bug, not behavior-changing-on-purpose; document loudly in release notes. |
| Architectural mismatch | **LOW** | #921 zone_id precedent matches; per-family namespaces are a conservative tweak. |

## Open questions for round 2

1. **Should the bare-RI normalization ship as a separate one-line bug
   fix** (just `format!("{next_table_name}.inet.0")` at the recursion
   call site, keyed by family from the IP type), leaving the
   ID-interning refactor as a subsequent perf-only change? This
   would isolate the correctness change from the structural one.
2. **Is the round-2 perf framing (~0.05% of one core for next-table
   flows) sufficient justification for ~250-350 LOC**, or does this
   still cross the PLAN-KILL line given that #1166, #1187, #1188,
   #1189 perf wins were of comparable scale and shipped?
3. **Eager visited-set cycle detection**: round 1 left this as
   optional; round 2 includes it as a clean win (cheap, removes
   "burn-through-depth-8" Junos-parity ambiguity). Confirm
   acceptable?
4. **Bare-RI behavior change**: is reverting the current "silently
   no_route" behavior of misconfigured `next-table` a release-note-
   worthy operator-facing change? Or is anyone relying on it?
5. **Out-of-scope reaffirmation**: Go-side pre-flattening still
   deferred. Issue body lists it as option (1) of three; we treat
   the three as alternatives, not a checklist. Confirm.
