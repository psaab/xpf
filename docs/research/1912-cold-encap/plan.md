# Plan of action — #1912: cold ENCAP outer next-hop blackholes tunnel-bound replies

- **Status**: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
- **Issue**: #1912 — encap-bound transit replies blackhole for the full
  cold window when the tunnel's OUTER next-hop neighbor is flushed; the
  documented "#1769 resolver + kernel ARP probe recover the outer hop"
  mechanism never engages (no who-has on the wire, resolver counters flat).
- **Branch**: `research/1912-cold-encap-outer-nh`
- **Base**: `origin/master` @ `09cd972bc` (post-#1914 #1952 merge)
- **Scope class**: dataplane bug — cold-path neighbor resolution for the
  GRE/tunnel encap egress. NOT a hot-path fast-path change. Touches the
  userspace AF_XDP helper only (`userspace-dp/`).

---

## 1. Problem statement

GRE-to-self choreography on the loss cluster (issue repro): inner pings
10.255.200.2 → 10.0.61.103 over `gr-0/0/1` (tunnel 10.0.61.1 ↔ 10.0.61.102).
Each round flushes `ip neigh` on `ge-0-0-1` (removing both the inner hop
10.0.61.103 AND the tunnel outer hop 10.0.61.102).

- **Forward inner leg recovers every round** (18/18): the inner hop
  re-resolves via the MissingNeighbor-arm kernel ARP probe — who-has
  10.0.61.103 visible on the inner tap.
- **Reply leg (wg-peer → 10.255.200.2, routed into `gr-0/0/1` encap, outer
  next-hop 10.0.61.102) blackholes** for the full 2 s window: 6/6 lost when
  the outer hop is fully flushed; **no who-has 10.0.61.102 from fw0 at all**;
  `neg_neigh_fast_fail_total` 0, `pending_timeout_drops_total` 0, resolver
  get/probe counters all 0. ICMP/UDP get no retransmission help, so the
  blackhole lasts until unrelated traffic re-populates the kernel entry.

## 2. Root cause (verified against `09cd972bc`)

The reply is **transit** (RX on `ge-0-0-1`, routed into the tunnel), so it
resolves through `resolve_tunnel_forwarding_resolution`
(`userspace-dp/src/afxdp/forwarding/mod.rs:1515`). That function:

1. looks up the tunnel endpoint by id;
2. resolves the **outer** destination (10.0.61.102) via
   `lookup_forwarding_resolution_v4/_v6` → `outer`;
3. returns a `ForwardingResolution` (mod.rs:1547-1557):
   ```
   disposition:   outer.disposition          // cold outer hop ⇒ MissingNeighbor
   egress_ifindex: endpoint.logical_ifindex   // the TUNNEL logical ifindex (gr-0/0/1)
   tx_ifindex:    outer.tx_ifindex            // physical outer TX (ge-0-0-1, or VLAN parent)
   next_hop:      outer.next_hop              // the OUTER hop 10.0.61.102
   tunnel_endpoint_id: <id != 0>
   // outer.egress_ifindex is DISCARDED.
   ```

The outer neighbor (10.0.61.102) is keyed in `state.neighbors` /
`dynamic_neighbors` by the **L3 egress ifindex** of the outer path — i.e.
`outer.egress_ifindex` (the iface passed to `lookup_neighbor_entry`,
mod.rs:1251-1259; for VLAN this is the subif, `tx_ifindex` is the parent —
`populate_egress_resolution`, session_glue/mod.rs:52-59). That ifindex is
**thrown away** by `resolve_tunnel_forwarding_resolution`.

In the MissingNeighbor arm (`poll_descriptor/mod.rs:2204+`), the cold-path
recovery side-effects are all keyed by `decision.resolution.egress_ifindex`
— which for a tunnel-marked decision is the **tunnel logical ifindex**, not
the outer L3 iface:

- **Kernel ARP probe** (mod.rs:2508-2530):
  `name = ifindex_to_name.get(&egress_ifindex)` then
  `trigger_kernel_arp_probe(name, next_hop)`. `trigger_kernel_arp_probe`
  (`neighbor.rs:36`) `SO_BINDTODEVICE`-binds an ICMP socket to `name` and
  sends to `next_hop`. With `egress_ifindex` = the tunnel logical ifindex,
  either `ifindex_to_name` returns the GRE name `gr-0/0/1` (binding an ICMP
  probe for 10.0.61.102 to a GRE L3 interface emits **nothing** on
  `ge-0-0-1` — a point-to-point GRE iface has no ARP), or it returns `None`
  (no probe fired at all). Either way: **no who-has 10.0.61.102 on the
  wire** — exactly the captured symptom.
- **Resolver enqueue + neg-cache key** (mod.rs:2375-2496): `neg_key =
  (egress_ifindex, next_hop)` = `(tunnel_logical, 10.0.61.102)`. (a) On a
  FRESHLY-flushed hop there is no negative-cache entry, so `neg_neigh_gate`
  returns `fast_fail=false` and the **resolver is never enqueued** (the
  enqueue lives only inside the `fast_fail` branch) → resolver counters
  stay flat, matching the issue. (b) Even when it would enqueue, the key
  uses the tunnel logical ifindex, so the resolved-wins lookup
  (`neighbors.contains_key(&(tunnel_logical, hop))`, mod.rs:2388-2396) can
  never match the real `(ge-0-0-1, 10.0.61.102)` entry, and the resolver
  would probe on the wrong iface.

So the R-E gate's documented promise — "the kernel ARP/ICMP probe above
already fired … the #1769 resolver keeps driving the outer next-hop, and
the flow recovers via retransmission once resolved" (mod.rs:2752-2758) —
**is false for tunnel-marked decisions**: the probe fired on the wrong
(tunnel logical) interface and the resolver was keyed on / never reached
the right one. The frame is then correctly refused pending_neigh buffering
(R-E, anti-plaintext-leak) and recycled → blackhole until unrelated traffic
re-resolves 10.0.61.102.

**This is independent of #1911/#1902** (confirmed by the issue's condition
algebra) and of #1873 R-C's *drop* of tunnel-marked slow-path reinjection
(that drop is correct — the bug is that nothing drives the outer-hop ARP).

## 3. Why "refuse to buffer + recover by probe" is the right shape (and what's actually broken)

The architecture deliberately does **not** buffer tunnel-marked frames in
`pending_neigh` (R-E) because the retry path TXes a buffered frame by
in-place MAC/VLAN rewrite with **no encapsulation** — replaying a buffered
inner packet would leak it PLAINTEXT on the physical wire once the outer
neighbor resolves. That decision is sound and **must be preserved**.

The intended recovery for a cold outer hop is therefore: fire a kernel ARP
probe **on the correct physical egress** so the kernel learns the outer
MAC within ~1 RTT; the netlink monitor picks up the resolved entry; the
NEXT encap packet forwards normally. The first packet is lost (not
buffered, by design), but ICMP/UDP recover on the next packet instead of
blackholing for the whole cold window.

The bug is purely that the probe + resolver are keyed by the **tunnel
logical ifindex** instead of the **outer L3 egress ifindex**. Fix the
ifindex and the documented recovery actually engages.

## 4. Design

### Option A (recommended) — carry the outer-neighbor ifindex on the resolution

Add a field to `ForwardingResolution`:

```rust
/// The ifindex on which `next_hop` must be neighbor-resolved (ARP/NDP
/// probe + neighbor-map key). For a normal resolution this equals
/// `egress_ifindex`. For a tunnel-marked resolution it is the OUTER
/// transport's L3 egress ifindex (where the outer next-hop neighbor
/// lives), which differs from `egress_ifindex` (the tunnel logical
/// ifindex, used for zone/policy/CoS) and from `tx_ifindex` (the VLAN
/// parent for a VLAN outer transport).
neigh_ifindex: i32,
```

- In `resolve_tunnel_forwarding_resolution` set `neigh_ifindex =
  outer.egress_ifindex` (the value currently discarded). Everywhere else
  `neigh_ifindex = egress_ifindex` (the same iface already passed to
  `lookup_neighbor_entry`).
- In the MissingNeighbor arm, replace the three `egress_ifindex` uses that
  drive **outer-hop** resolution with `neigh_ifindex`:
  - kernel ARP probe: `ifindex_to_name.get(&neigh_ifindex)` (mod.rs:2520-2528);
  - `neg_key` / resolver enqueue / resolved-wins (mod.rs:2376-2496);
  - the `already_probing` dedup (mod.rs:2515-2518).
  `pending_neigh` insertion stays keyed by `egress_ifindex` **and is never
  reached for tunnel-marked anyway** (R-E), and for non-tunnel
  `neigh_ifindex == egress_ifindex`, so non-tunnel behavior is byte-identical.
- **Construction cost**: `ForwardingResolution` is built at ~15 literal
  sites. To avoid touching all of them error-prone, the recommended
  mechanic is a single post-construction normalizer
  `fn finalize_neigh_ifindex(&mut self)` that sets `neigh_ifindex =
  egress_ifindex` when `neigh_ifindex == 0`, OR (cleaner) add the field
  with a `Default`-friendly sentinel of 0 and have the MissingNeighbor arm
  treat `neigh_ifindex == 0 → fall back to egress_ifindex`. Reviewers to
  pick: explicit field on every literal vs sentinel+fallback. The
  tunnel-resolution site sets it explicitly to `outer.egress_ifindex`
  regardless.

### Option C (lower-churn alternative) — arm-local re-derivation

Leave `ForwardingResolution` unchanged. In the MissingNeighbor arm, when
`decision.resolution.tunnel_endpoint_id != 0`, look up
`state.tunnel_endpoints[id]`, resolve the outer destination's egress
ifindex (a single `lookup_forwarding_resolution_*` call with
`allow_tunnels=false`), and use THAT ifindex for the probe + resolver +
neg-cache key. Avoids a struct change but re-runs outer resolution in the
arm (work the original resolution already did and discarded) and
duplicates the outer-resolution logic. **Tradeoff**: smaller diff, but a
second resolution call on the cold path and a logic-duplication drift risk
vs Option A's single authoritative source.

### Optional enhancement (decide in review) — enqueue the resolver for tunnel-marked unconditionally

Today the resolver is enqueued only inside the neg-cache `fast_fail`
branch. On a freshly-flushed outer hop (no neg entry) only the kernel ARP
probe fires. With the ifindex fixed, the probe alone resolves a fully-cold
hop within ~1 RTT. But a STALE/DELAY outer entry (kernel has a usable but
unconfirmed lladdr) benefits from a resolver-driven RTM_GETNEIGH revalidation.
Proposal: for a tunnel-marked MissingNeighbor with a resolved `neigh_ifindex`,
ALSO enqueue the #1769 resolver (rate-limited, keyed by `(neigh_ifindex,
next_hop)`), not only on the neg fast-fail. **Defer-or-include is a review
call**; the core ifindex fix is sufficient for the reported full-flush
blackhole, the resolver enqueue hardens the STALE case.

## 5. Public API / invariants preserved

- `StableTunnelEndpointID` / wire protocol: untouched.
- #1873 R-C (drop tunnel-marked slow-path reinjection) + R-E (never buffer
  tunnel-marked in pending_neigh): **preserved** — no plaintext-leak window
  is opened. The fix only changes which interface the (already-fired) probe
  binds to.
- Non-tunnel MissingNeighbor path: byte-identical (`neigh_ifindex ==
  egress_ifindex`).
- HA / session-sync: the stored session resolution gains a field; verify it
  is not serialized across the cluster wire (it is recomputable from the
  tunnel endpoint id on the peer). If `ForwardingResolution` is part of any
  HA-synced struct, the new field must be recomputed on the peer, not
  trusted from the wire (mirror the existing tunnel_endpoint_id re-own
  guard, session_glue/mod.rs:90+).

## 6. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression (non-tunnel) | LOW | `neigh_ifindex == egress_ifindex` off the tunnel path; probe/key unchanged. |
| Plaintext leak re-open | LOW | R-C/R-E unchanged; no buffering/reinjection added. |
| Borrow/lifetime | LOW | additive field + read in the arm. |
| Perf | LOW | cold path only; one extra i32 on the resolution. |
| Arch mismatch | LOW | fix matches the documented intent (probe drives outer hop). |
| HA-sync field trust | MED | must confirm `neigh_ifindex` is recomputed on the peer, not wire-trusted (see §5). |
| VLAN outer transport | MED | the whole point of using `outer.egress_ifindex` not `tx_ifindex`; add a VLAN-outer-transport test. |

## 7. Test plan

- **Unit (forwarding)**: `resolve_tunnel_forwarding_resolution` sets
  `neigh_ifindex == outer.egress_ifindex` (≠ `egress_ifindex` = tunnel
  logical) for a GRE endpoint; for a VLAN outer transport `neigh_ifindex`
  is the subif, `tx_ifindex` the parent.
- **Unit (arm keying)**: a tunnel-marked MissingNeighbor resolution drives
  the probe + resolver enqueue + neg-cache key on `neigh_ifindex` (assert
  via the existing probe/resolver seams / counters).
- **Regression (non-tunnel)**: existing MissingNeighbor tests unchanged
  (neigh_ifindex == egress_ifindex).
- **cargo**: full `cargo test --release` + 5× flake on the new tests.
- **Go**: `go test ./...` (no Go change expected; confirm protocol parity
  if any resolution field crosses the boundary — it should not).
- **Live (loss cluster, the canonical repro)**: run `tmp/v1902b.sh`
  choreography (gr-0/0/1 + lan→lan permit, gre1902 peer on
  cluster-userspace-host with `modprobe ip_gre`, route 10.0.61.103/32 via
  the tunnel from lanhost, wg-peer return route 10.255.200.0/30 via
  10.0.61.1), `ip neigh flush dev ge-0-0-1`, ping 10.0.61.103 from lanhost
  while tcpdumping lanhost eth0 for reply GRE frames AND who-has
  10.0.61.102. **Pass = who-has 10.0.61.102 NOW appears from fw0 on
  ge-0-0-1 after flush, reply leg recovers within ~1 ping** (was 6/6 loss).
- **Failover**: `make test-failover` — the change touches tunnel egress
  resolution; expected green (mechanism unchanged, only the probe iface).
- Standard smoke matrix (v4+v6, push+reverse, CoS off+on) — no fast-path
  change expected.

## 8. Out of scope (explicit)

- Buffering/replaying tunnel-marked frames (R-E stays; plaintext-leak risk).
- Changing R-C slow-path tunnel drop.
- The inner-hop path (already recovers correctly).
- A general neighbor-resolution redesign (#1771 territory).

## 9. Open questions for adversarial review

1. **Option A vs C**: dedicated `neigh_ifindex` field (touches ~15 literals
   or needs a sentinel+fallback) vs arm-local re-derivation (smaller diff,
   re-runs outer resolution + duplicates logic). Which is the right
   long-term SSOT?
2. **Sentinel vs explicit**: if Option A, is `neigh_ifindex == 0 → fall
   back to egress_ifindex` acceptable, or must every literal set it
   explicitly (compile-time completeness)?
3. **Resolver-for-tunnel enhancement**: include the unconditional resolver
   enqueue for tunnel-marked MissingNeighbor (hardens STALE), or defer?
4. **HA-sync**: is `ForwardingResolution.neigh_ifindex` ever trusted from
   the cluster wire? If a session's resolution is synced, confirm the peer
   recomputes it (like the tunnel_endpoint_id re-own guard) rather than
   adopting a stale/owner-divergent ifindex.
5. **VLAN outer transport**: does `outer.egress_ifindex` correctly key the
   neighbor when the tunnel's outer transport rides a VLAN subif? (Belief:
   yes — neighbor is keyed by the L3 subif; `tx_ifindex` would be wrong.)
   Any case where `lookup_neighbor_entry` keys on `tx_ifindex` instead?
6. **Is the first-packet loss acceptable** for ICMP/UDP, or should the
   design also reduce the cold-window to zero (would require buffering,
   which R-E forbids — so likely accept one-RTT recovery)?

## 10. Multiple path options summary

- **Path A** (recommended): add `neigh_ifindex`, fix the three arm keyings.
  Authoritative SSOT, VLAN-correct, byte-identical off the tunnel path.
- **Path C**: arm-local re-derivation. Smaller diff, logic duplication +
  extra cold-path resolution call.
- Both are compatible with the optional resolver-enqueue enhancement.

---

## 11. Validation gate before `/engineer`

A converged plan must settle: Option A vs C (Q1/Q2), the resolver
enhancement (Q3), and the HA-sync field-trust question (Q4). The live
loss-cluster repro (§7) is the only ground truth that the who-has now
appears and the reply leg recovers.
