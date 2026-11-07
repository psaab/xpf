# Userspace Dataplane JIT Compiler Design

Date: 2026-03-17
Updated: 2026-05-26

**Tracking issue:** [#1605](https://github.com/psaab/xpf/issues/1605)

## Doc-coherency contract (load-bearing)

This doc and issue #1605 are co-canonical for the userspace JIT
architecture. **Any PR that changes JIT architecture MUST update
both** in the same change set:

- The status table immediately below
- The relevant Phase section
- A comment on #1605 summarizing the change and linking the PR

Architecture for this purpose means: IR shape, compilation phase
boundary, flow cache shape, config-invalidation protocol, dispatch
boundary between cached and uncached paths, choice of code
generator, or any phase-boundary decision (defer / kill / fold).

Non-architectural changes (perf tuning within an existing phase,
test additions, build hygiene) do not need a doc update — say so
explicitly in the PR review notes.

## Current Status

| Phase | Description | Status | Measured Gain |
|-------|-------------|--------|---------------|
| 1 | Flow cache + rewrite descriptors | **DONE** — cache hit skips session/policy/NAT/FIB; `apply_rewrite_descriptor()` straight-line rewrite with precomputed csum deltas; dual-stack; cross-binding copy is inherent to AF_XDP | 23+ Gbps sustained |
| 2 | Policy decision trees | **DONE** — zone-pair HashMap index + precompiled protocol-indexed application matcher with exact-port HashSets | O(1) zone + O(K) rules × O(1) app match |
| 3 | Address-book trie compilation | Not started | — |
| 4 | Cranelift JIT | Not started | — |
| 5 | Screen function specialization | **DONE** — zones without screen profiles return Pass immediately (O(1) HashMap miss); no further specialization needed | O(1) |
| 6 | CoS scheduler oversubscription semantics (#1614) | **WIRED / NOT YET MEETING GATE** — the operator-selectable `oversubscription-policy guarantee-rate <X>` wire surface + commit warning shipped (#1618) and the smoke fixture activates the knob (#1629), but the scheduler does **not** yet honour small-class guarantees: under `guarantee-rate 0.7` it still equalizes ~20%/class instead of meeting the small-class ≥ 95% acceptance gate (#1630 measurement, see `docs/fairness-regimes.md` "CoS oversubscription policy"). Root cause proven — the v8 epoch-cap clamp discards lagged rate credit (`rotate_epoch_v8.rs`). The `proportional` default and `priority-low-min-share`/`codel-target` knobs parse as designed. See `docs/pr/1614-multi-rss-cos/plan.md` v5. | regression open, see #1630/#1614 |

### Phase 1 implementation details (as of `2f818e8`, 2026-03-22)

**Done:**
- [x] `FlowCache` (4096 direct-mapped) + `RewriteDescriptor` struct
- [x] TCP ACK-only + UDP flow cache lookup in hot path
- [x] IPv6 flow cache (address-family agnostic key)
- [x] Self-target inline in-place rewrite (hairpin, 0 hits in practice)
- [x] Precomputed `ip_csum_delta` / `l4_csum_delta` at cache insertion
- [x] Config/FIB generation invalidation
- [x] Amortized session timestamp touch (every 64 hits)
- [x] Zero-copy fill ring bootstrap (pre-bind prime)
- [x] Netlink neighbor monitor (event-driven RTM_NEWNEIGH)
- [x] Buffer-and-retry for MissingNeighbor (cold connect — see #1636
      below; the original "~2ms" claim was wrong, real baseline ~3.371s)
- [x] Session creation on MissingNeighbor (SYN-ACK reverse path)
- [x] ICMP SOCK_RAW probe for ARP/NDP (dual-stack)
- [x] #1636 cold-connect mitigation: kernel `retrans_time_ms` lowered to
      250ms (option B), proactive neighbor warming at config-apply with
      per-RG HA gating (option C), and a ForwardingState-computed 800ms
      `PENDING_NEIGH_TIMEOUT` when fast-retrans is confirmed (option D).
      Measured cold connect to an on-link (un-warmed) host: ~1.016s
      median (was 3.371s, 3.3× better — the B+D worst-case path). For
      routed operator-configured next-hops the warm pass keeps the
      gateway neighbor resolved so the first flow is ≤200ms. Directly-
      connected host neighbors are not warmed (plan open-question #1,
      out of scope for the initial ship).

- [x] `apply_rewrite_descriptor()` — straight-line frame rewrite using
      precomputed descriptor fields (MACs, IPs, ports, csum deltas).
      IPv4: precomputed NAT delta + constant 0xFEFF TTL-1 delta.
      IPv6: precomputed L4 delta (extended `compute_l4_csum_delta` for
      128-bit addresses). Falls back to generic on port mismatch/NAT64.
- [x] Apply precomputed csum deltas in the rewrite hot path — both
      `ip_csum_delta` (IPv4 header) and `l4_csum_delta` (TCP/UDP L4)
- [x] `compute_l4_csum_delta` extended for IPv6 address changes

**Not done (Phase 1 remaining):**
- [ ] Cross-binding in-place rewrite — attempted and reverted due to
      frame lifetime issues. Self-target only works for hairpin.

**Current throughput:**
- Cold TCP connect: ~1.016s median to an on-link host after ARP/NDP
  flush with #1636 mitigation (was a mis-documented "~2ms" against a
  real ~3.371s baseline — 3.3× improvement). ≤200ms for warmed routed
  next-hops; ~1.02s for an un-warmed / on-link neighbor (the smoke
  target `$IPERF_TARGET4` is on-link, so it exercises the worst case).
- Cold iperf3 IPv4: 20.1 Gbps (8 streams, 5s)
- Cold iperf3 IPv6: 20.0 Gbps (8 streams, 5s)
- Warm iperf3: 23+ Gbps (8 streams, 10s)
- Baseline before userspace dataplane: ~13 Gbps (eBPF kernel path)

## Motivation

The userspace AF_XDP dataplane currently interprets every packet through a
generic pipeline: parse metadata, screen, session lookup, policy evaluation,
NAT decision, FIB lookup, frame rewrite. For established flows (>99% of
transit packets), the session-hit path still executes ~15 branches and 3-4
hash map lookups that always produce the same answer.

The eBPF dataplane avoids this with a per-CPU flow cache (`xdp_zone.c`) that
stores the complete forwarding decision (egress ifindex, MACs, NAT flags,
policy ID) and replays it in O(1) for subsequent packets in the same flow.
The userspace dataplane has no equivalent.

A JIT compiler can close this gap by generating specialized machine code for
the common-case packet paths, eliminating branches, hash lookups, and
indirection that the interpreter must execute on every packet.

## What the eBPF pipeline precomputes that userspace doesn't

| Feature | eBPF (compile-time) | Userspace (per-packet) |
|---------|---------------------|----------------------|
| Zone lookup | `iface_zone_map` HASH: O(1) | Same: O(1) HashMap |
| Address matching | LPM trie + membership HASH: O(log N) + O(1) | Linear scan of CIDR list |
| Policy rules | Flat ARRAY indexed by `set_id * MAX + idx` | Linear scan of Vec |
| Application match | HASH by `(proto, port)`: O(1) | Linear scan of application terms |
| Flow cache | Per-CPU 256-slot array: O(1) established hit | None; full session lookup every packet |
| Session lookup | Dual-entry HASH: O(1) forward+reverse | Multi-scope fallthrough with Mutex locks |
| NAT pool alloc | Atomic per-CPU counter | Mutex-protected PortAllocator |
| Frame rewrite | Inline in xdp_nat with incremental csum | Generic function with branch per NAT type |

## Where a JIT wins

### 1. Per-flow compiled fast-path (highest impact)

When a session is created, the JIT compiles a small function that encodes
the complete forwarding decision for that flow:

```
// Generated for flow: 10.0.1.102:55068 -> $IPERF_TARGET4:443 TCP
// Zone: trust -> wan, SNAT to 172.16.80.8, egress ge-0-0-2.80
fn flow_0x7a3b(frame: &mut [u8]) -> TxTarget {
    // Ethernet: fixed MACs + VLAN 80 (12 bytes, no branch)
    write_eth_header(frame, DST_MAC, SRC_MAC, 80, 0x0800);
    // TTL decrement at known offset (no AF_INET/AF_INET6 branch)
    frame[22] -= 1;
    // IP checksum adjust (precomputed delta for TTL-1)
    adjust_csum_16(frame, 24, TTL_DELTA);
    // SNAT: rewrite src IP at offset 26 (precomputed)
    write_u32(frame, 26, 0xac108008); // 172.16.80.8
    // L4 pseudo-header csum adjust (precomputed delta)
    adjust_csum_32(frame, 40, SNAT_CSUM_DELTA);
    TxTarget { ifindex: 12, queue: 3 }
}
```

No branches. No hash lookups. No NAT type dispatch. No zone lookup.
Just straight-line memory writes with precomputed constants.

**Estimated gain**: 3-5x for established-flow throughput. The eBPF flow
cache achieves similar gains; this is the userspace equivalent.

### 2. Policy decision trees (high impact on large rulesets)

Current: linear scan of N rules per zone-pair, checking each rule's
address/port/protocol match sequentially.

JIT: at config compile time, build a binary decision tree for each
(src_zone, dst_zone) pair:

```
// Generated for trust -> wan policy (3 rules)
fn policy_trust_wan(proto: u8, dst_port: u16, src_ip: u32, dst_ip: u32) -> PolicyDecision {
    // Rule 1: permit tcp 80,443 to 0.0.0.0/0
    if proto == 6 && (dst_port == 80 || dst_port == 443) {
        return PolicyDecision::Permit { nat: SNAT_INTERFACE, rule_id: 1 };
    }
    // Rule 2: permit udp 53 to 0.0.0.0/0
    if proto == 17 && dst_port == 53 {
        return PolicyDecision::Permit { nat: SNAT_INTERFACE, rule_id: 2 };
    }
    // Rule 3: deny any
    return PolicyDecision::Deny { rule_id: 3 };
}
```

For policies with address-book references, expand CIDR matches into a
trie or sorted-array binary search at compile time instead of runtime
linear scan:

```
// Generated for address-book "servers" containing 10.0.1.0/24, 10.0.2.0/24
fn match_servers(ip: u32) -> bool {
    let prefix = ip >> 8;
    prefix == 0x0a0001 || prefix == 0x0a0002
}
```

**Estimated gain**: O(1) or O(log N) vs O(N) per miss. Matters most for
firewalls with 50+ rules per zone-pair.

### 3. NAT rule compilation (medium impact)

Current: `match_source_nat_for_flow()` iterates SNAT rule sets, checking
each rule's source/destination address match.

JIT: compile NAT rules into a dispatch table indexed by zone-pair:

```
// Generated SNAT dispatch for trust -> wan
fn snat_trust_wan(src_ip: u32, egress_ifindex: i32) -> Option<NatDecision> {
    // Rule 1: interface mode on egress
    if src_ip & 0xffffff00 == 0x0a000100 { // 10.0.1.0/24
        return Some(NatDecision::interface(egress_ifindex));
    }
    None
}
```

### 4. Screen inlining (low-medium impact)

Current: `check_packet()` evaluates all 11 screen checks for every packet
before session lookup, even when the zone has no screen profile.

JIT: at config compile time, generate a per-zone screen function that only
contains the enabled checks:

```
// Generated for zone "wan" with syn-flood + land-attack enabled
fn screen_wan(meta: &Meta) -> ScreenVerdict {
    // Land attack (always cheap)
    if meta.src_ip == meta.dst_ip { return Drop; }
    // SYN flood (only if TCP SYN)
    if meta.protocol == 6 && meta.tcp_flags & 0x02 != 0 {
        if syn_rate.check_and_increment() > 1000 { return Drop; }
    }
    Pass
}
// Generated for zone "trust" with NO screen profile
fn screen_trust(_meta: &Meta) -> ScreenVerdict { Pass }
```

### 5. Frame rewrite templates (medium impact)

Current: `build_forwarded_frame_into_from_frame()` has branches for:
- IPv4 vs IPv6
- VLAN vs no VLAN
- SNAT vs DNAT vs NAT64 vs no NAT
- TCP vs UDP vs ICMP (checksum handling)
- MSS clamping on/off

JIT: generate specialized rewrite functions per (addr_family, vlan,
nat_type, protocol) tuple. For the common case of IPv4+VLAN+SNAT+TCP,
this eliminates ~8 branches from the frame build path.

## Architecture

```
                    Config Change
                         |
                         v
              ┌─────────────────────┐
              │  Snapshot Compiler   │  (existing: Go manager)
              │  policies, zones,   │
              │  NAT rules, routes  │
              └──────────┬──────────┘
                         |
                         v
              ┌─────────────────────┐
              │  JIT Compiler       │  (NEW: Rust, runs on config apply)
              │                     │
              │  Inputs:            │
              │  - PolicySnapshots  │
              │  - SourceNATSnaps   │
              │  - ZoneSnapshots    │
              │  - ScreenSnapshots  │
              │  - RouteSnapshots   │
              │                     │
              │  Outputs:           │
              │  - Zone-pair policy │
              │    decision fns     │
              │  - NAT dispatch fns │
              │  - Screen fns       │
              │  - Frame rewrite    │
              │    templates        │
              │  - Flow cache       │
              │    code gen         │
              └──────────┬──────────┘
                         |
                         v
              ┌─────────────────────┐
              │  Compiled Pipeline  │  (mmap'd executable pages)
              │                     │
              │  Per-worker:        │
              │  - flow_cache[4096] │
              │    maps 5-tuple ->  │
              │    compiled fn ptr  │
              │                     │
              │  Per-zone-pair:     │
              │  - policy_fn()      │
              │  - snat_fn()        │
              │  - screen_fn()      │
              │                     │
              │  Per-flow (on hit): │
              │  - rewrite_fn()     │
              │    straight-line    │
              │    MAC+IP+port+csum │
              └─────────────────────┘
```

### Flow cache design

Each worker maintains a per-CPU flow cache (similar to eBPF's
`xdp_zone.c` flow cache):

```rust
struct FlowCacheEntry {
    key: SessionKey,          // 5-tuple for validation
    generation: u64,          // config generation (invalidate on change)
    rewrite_fn: fn(&mut [u8]) -> TxTarget,  // JIT-compiled rewrite
    nat_decision: NatDecision,
    egress: ForwardingResolution,
}

struct FlowCache {
    entries: [Option<FlowCacheEntry>; 4096],  // direct-mapped, hash-indexed
}
```

**Hit path** (established TCP, ~95% of packets):
1. Hash 5-tuple → cache index
2. Compare stored key (cache validation)
3. Call `rewrite_fn(frame)` → straight-line rewrite
4. Return TxTarget

**Miss path** (new flow or cache miss):
1. Full pipeline: session lookup → policy → NAT → FIB
2. JIT-compile rewrite function for this flow
3. Insert into flow cache
4. Forward packet

### JIT compilation strategy

**Option A: Cranelift** (recommended)

Use Cranelift as the JIT backend. It's a Rust-native code generator
with good ARM64/x86-64 support and fast compile times (~100us per
function). Already used by Wasmtime and rustc_codegen_cranelift.

```toml
[dependencies]
cranelift = "0.110"
cranelift-jit = "0.110"
cranelift-module = "0.110"
```

Pros:
- Native Rust, no FFI
- Fast compilation (~100us per flow function)
- Good register allocation
- Supports both x86-64 and aarch64

Cons:
- ~5MB binary size increase
- Learning curve for IR construction

**Option B: dynasm-rs** (simpler, x86-64 only)

Use dynasm-rs for direct x86-64 assembly emission. Simpler for the
narrow rewrite-function use case.

```toml
[dependencies]
dynasm = "2.0"
dynasmrt = "2.0"
```

Pros:
- Very fast compile (~10us per function)
- Zero abstraction overhead
- Tiny dependency

Cons:
- x86-64 only (no ARM64)
- Manual register management
- Harder to maintain

**Option C: Interpreted fast-path with template specialization**

No actual JIT — instead, precompute a "rewrite descriptor" at session
creation that encodes the exact byte offsets and values to write:

```rust
struct RewriteDescriptor {
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
    ttl_offset: u16,
    src_ip_offset: u16,
    src_ip_value: [u8; 4],      // or 16 for IPv6
    dst_ip_offset: u16,
    dst_ip_value: [u8; 4],
    l3_csum_offset: u16,
    l3_csum_delta: u16,         // precomputed
    l4_csum_offset: u16,
    l4_csum_delta: u32,         // precomputed from IP+port changes
    src_port_offset: u16,
    src_port_value: u16,
    dst_port_offset: u16,
    dst_port_value: u16,
}
```

Apply with a tight loop of `write_at(frame, offset, value)` calls.
No branches, no lookups, but still interpreted (not native code).

Pros:
- No JIT complexity or dependencies
- Works on all architectures
- Easy to reason about correctness
- Can be implemented incrementally

Cons:
- ~30-50% slower than native JIT (branch predictor still sees the
  dispatch loop)
- Still has function-call overhead per field

**Recommendation: Start with Option C**, measure, then graduate to
Option A (Cranelift) if the interpreted fast-path isn't enough.

**Decision (2026-03-18):** Option C chosen and implemented. The
`RewriteDescriptor` struct and `FlowCache` are in place with full
dual-stack (IPv4+IPv6) and UDP support. Cache-hit skips session
lookup, policy, NAT, and FIB — contributing ~35% of the 13→23 Gbps
improvement. The descriptor fields (MACs, IPs, ports, csum deltas)
are populated but not yet used for straight-line rewriting; the
hit path still calls the generic frame builder. Applying the
descriptor directly is the last remaining Phase 1 optimization.

## Implementation phases

### Phase 1: Flow cache + rewrite descriptors (Option C) — COMPLETE

**Status**: All Phase 1 optimizations are implemented. The cache-hit
path calls `apply_rewrite_descriptor()` for straight-line frame rewrite
using precomputed descriptor fields (MACs, IPs, ports, csum deltas),
with automatic fallback to the generic path for edge cases (port
mismatch, NAT64, NPTv6). The only remaining Phase 1 gap is cross-
binding in-place rewrite (UMEM frame lifetime issue).

**What's done** (as of `2f818e8`, 2026-03-22):
- [x] `RewriteDescriptor` struct defined (`afxdp.rs:187`) with MACs, VLAN,
      NAT IPs/ports, precomputed csum deltas, egress info, validation
- [x] `FlowCache` (4096-entry direct-mapped, `afxdp.rs:231`)
- [x] Flow cache lookup in `poll_binding()` hot path — TCP ACK-only +
      UDP packets checked before session lookup
- [x] IPv6 flow cache (address-family agnostic key hashing)
- [x] Cache population on ForwardCandidate after full pipeline
- [x] Config/FIB generation invalidation on lookup
- [x] Amortized session timestamp touch (every 64 hits)
- [x] Per-worker hit/miss/eviction counters
- [x] Precomputed `ip_csum_delta` / `l4_csum_delta` at cache insertion
      (`compute_ip_csum_delta()` / `compute_l4_csum_delta()`)
- [x] Self-target inline in-place rewrite (hairpin, 0 hits in practice)
- [x] Zero-copy fill ring bootstrap (pre-bind prime, `8a05d52`)
- [x] Netlink neighbor monitor (event-driven RTM_NEWNEIGH, `293b818`)
- [x] Buffer-and-retry for MissingNeighbor (cold connect — the original
      "~2ms" claim was a mis-measurement; real baseline ~3.371s, see
      #1636 mitigation below)
- [x] Session creation on MissingNeighbor for SYN-ACK reverse path (`9584447`)
- [x] ICMP SOCK_RAW probe for ARP/NDP dual-stack (`fd53f19`, `2f818e8`)
- [x] Retry pending neighbors on empty RX poll (`293b818`)
- [x] Heartbeat gating removal — unconditional after grace period (`161053a`)

**Done since Phase 1 core (2026-03-22 → 2026-03-23):**
- [x] `apply_rewrite_descriptor()` straight-line rewrite with precomputed
      csum deltas (commit `6df734d`). 6 unit tests.
- [x] Precomputed csum deltas applied in hot path (ip_csum_delta + 0xFEFF
      TTL constant, l4_csum_delta for TCP/UDP)
- [x] Embedded ICMP NAT reversal — XDP shim routes ICMP errors to XSK,
      helper does `try_embedded_icmp_nat_match`, dnat_table populated
      for BPF fallback (`949facf`)
- [x] LocalDelivery slow-path reinject — host-bound packets (NDP, ICMP
      echo, BGP) reinjected to TUN for kernel processing (`949facf`)
- [x] RA ResendBurst after RETH MAC link cycle (`49c4cb8`)
- [x] HA ctrl enable delay 15s for cluster, rebind gate reset (`49c4cb8`)
- [x] Fabric-ingress TTL skip — no double decrement on cross-chassis
      packets (`efd79d7`)
- [x] Dynamic fabric state sync — SyncFabricState pushes peer MACs to
      helper via shared_fabrics ArcSwap for cross-RG redirect (`48b7f2a`)
- [x] BPF dnat_table population for embedded ICMP (`949facf`)

**Not possible:**
- Cross-binding in-place rewrite — architecturally impossible. XSK TX
  requires the frame to reside in the target binding's UMEM. Frames
  from a different binding's UMEM cannot be submitted to another
  binding's TX ring. The frame copy between bindings is fundamental
  to AF_XDP's per-queue UMEM ownership model. Only self-target
  (hairpin) in-place rewrite works, and that's already implemented.

**Measured throughput** (as of 2026-03-23):
- Cold TCP connect: ~1.016s median (10 runs, loss userspace cluster,
  on-link target after ARP/NDP flush) with the #1636 mitigation — the
  prior "~2ms" was a mis-measurement; the real baseline was ~3.371s.
  #1636 lowers every interface's kernel retrans_time_ms to ~250ms (B),
  warms routed next-hops at config-apply with per-RG HA gating (C), and
  drops a stuck SYN at 800ms when fast-retrans is confirmed (D). Routed
  warmed next-hops connect ≤200ms; on-link / un-warmed neighbors hit the
  ~1.02s worst case.
- Cold iperf3 IPv4: 20.1 Gbps (8 streams, 5s)
- Cold iperf3 IPv6: 20.0 Gbps (8 streams, 5s)
- Warm iperf3: 23+ Gbps (8 streams, 10s)
- Fabric redirect iperf3: 16.9 Gbps (cross-chassis, 4 streams)
- Warm ICMP: 0% loss, consistent TTL=63 (50 probes)
- mtr IPv4/IPv6: intermediate hops visible (embedded ICMP NAT reversal)
- Baseline before userspace dataplane: ~13 Gbps (eBPF kernel path)
- Flow cache hit path (skipping session/policy/NAT/FIB) contributed
  ~35% of the improvement; remaining gains from zero-copy XSK path

**Files**:
- `userspace-dp/src/afxdp.rs` — flow cache, `compute_ip_csum_delta()`,
  `compute_l4_csum_delta()` (now handles IPv6), cache-hit wiring
- `userspace-dp/src/afxdp/frame.rs` — `apply_rewrite_descriptor()` with
  6 unit tests (no-NAT, SNAT+VLAN, DNAT-VLAN, IPv6, port mismatch, NAT64 fallback)
- `userspace-dp/src/afxdp/session_glue.rs` — descriptor construction

**Test criteria**:
- Established-flow throughput improves (measured by perf-compare)
- `flow_cache_hits / total_packets > 0.9` for sustained TCP
- No regression in HA failover tests
- 6 unit tests validate checksum correctness for all NAT/VLAN combos

### Phase 2: Policy decision trees — DONE

**Scope**: Compile policies into zone-pair decision functions at
config apply time.

1. In `buildPolicySnapshots()`, generate a decision tree representation
2. Pass decision tree to Rust helper as part of ConfigSnapshot
3. In Rust, compile decision tree into a match cascade
4. On session miss, call zone-pair decision function instead of
   linear policy scan

**Expected gain**: O(1)-O(log N) policy evaluation vs O(N) linear scan.
Significant for rulesets with 20+ rules per zone-pair.

### Phase 3: Address-book trie compilation — WIRE FORMAT LANDED (#1606), TRIE COMPACTION DEFERRED TO #1608

**Wire format (done in #1606)**: ConfigSnapshot now carries a top-
level `address_books: Vec<AddressBookSnapshot>` table. Multiple
named books with identical canonical CIDR content share one row
and one u32 ID (content-hashed). Each `PolicyRuleSnapshot` cites
books by ID via `source_book_ids` / `destination_book_ids` and
free-form CIDRs via `source_literals` / `destination_literals`.
The legacy `source_addresses` field stays on the wire for one-
release rolling-upgrade compatibility with old Rust binaries.

The Rust side stores books in a flat dense `Vec<BookEntry>` on
`PolicyState`; rules carry `SmallVec<[u32; 8]>` indices. No
`Arc<BookEntry>` per rule; the table lifetime is tied to the
ArcSwap-published `ForwardingState` snapshot.

This delivers the **structural memory deduplication** prerequisite
for the 1M-policy scale: prefix-table memory is now
`O(book_count × per_book_size)` not
`O(rule_count × avg_books_per_rule)`. A 10K-book × 100K-rule
config with 3 books per rule averages 30× fewer prefix-set
materializations than today.

**Trie compaction (deferred to #1608)**: the per-book `PrefixSetV4`/
`PrefixSetV6` is still the uncompressed binary trie introduced in
#923. At 10K books × 1K CIDRs each, that's ~25 GB of trie node
memory — usable but not optimal. #1608 will replace the binary
trie with a DIR-24-8 or Patricia compressed structure to bring
the per-book footprint down 10-100×.

### Phase 4: Cranelift JIT for flow rewrite functions — NOT STARTED

**Scope**: Replace rewrite descriptors with native code generation.

1. Add Cranelift dependency
2. At session creation, emit Cranelift IR for the rewrite function
3. Compile to native code (~100us)
4. Store function pointer in flow cache entry
5. On cache hit, call native function directly

**Expected gain**: Additional 30-50% over descriptors for the rewrite
path (eliminates dispatch loop overhead).

### Phase 5: Screen function specialization — DONE (inherent)

**Scope**: Generate per-zone screen functions at config apply time.

Only compile the enabled screen checks. Zones with no screen profile
get a no-op function. Zones with only land-attack get a single
comparison.

## Incremental checksum precomputation

The biggest single optimization in the rewrite path is precomputing
checksum deltas at session creation time:

**Current** (per-packet):
```rust
// Recompute full L3 checksum after TTL + src_ip change
let old_csum = read_u16(frame, csum_offset);
let new_csum = fold16(
    !old_csum as u32
    + !old_ttl as u32 + new_ttl as u32
    + !old_src_hi as u32 + new_src_hi as u32
    + !old_src_lo as u32 + new_src_lo as u32
);
```

**Precomputed** (at session creation):
```rust
// At session create time:
let ip_csum_delta = compute_incremental_delta(old_src_ip, new_src_ip);
// Per-packet: just add delta + TTL adjustment
let new_csum = fold16(!old_csum as u32 + ip_csum_delta + 0x0100);
```

The IP checksum delta for SNAT is constant for the lifetime of the
session. Only the TTL decrement adds a per-packet component (and
that's always `+0x0100` for TTL-1).

For L4 (TCP/UDP), the pseudo-header checksum delta from IP changes
is also constant per session. Only payload changes (which we don't
modify) affect the L4 checksum.

## Memory and safety considerations

- Flow cache: 4096 entries * ~128 bytes = 512KB per worker (L2 cache friendly)
- Rewrite descriptors: ~64 bytes each, embedded in flow cache entry
- JIT code (Phase 4): ~256 bytes per function, mmap'd with PROT_EXEC
- Total per-worker overhead: ~1MB (acceptable)

**Safety**: All rewrite functions operate on bounded frame buffers
with length checks at the entry point. The descriptor approach
(Phase 1) is inherently safe — it's just offset+value pairs applied
to a validated frame. Cranelift JIT (Phase 4) generates verified
code through its IR builder, which prevents out-of-bounds access
by construction.

**Config invalidation**: Flow cache entries carry a `generation`
counter. On config change, bump the generation; stale entries are
lazily evicted on next access. No stop-the-world flush needed.

## Measurement plan

All phases measured using:
- `scripts/userspace-perf-compare.sh` for A/B throughput
- `iperf3 -P 4 -t 30` (min 3 runs)
- `perf record` / `perf report` for hot-symbol validation
- Flow cache hit rate counter
- `scripts/userspace-ha-failover-validation.sh` for HA regression
