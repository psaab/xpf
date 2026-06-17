# Claude SMR plan review r1 — #1912 cold ENCAP outer next-hop blackhole

**Verdict: PLAN-NEEDS-MINOR** (root cause verified solid; converge the open
design choices before `/engineer`).

Reviewed hostile as dataplane SMR. I traced the actual code paths on
`09cd972bc` rather than trusting the plan prose. The root cause is correct
and the fix direction is right; the remaining work is converging the
options the plan deliberately leaves open.

## Root cause — VERIFIED (not just plausible)

- `resolve_tunnel_forwarding_resolution` (forwarding/mod.rs:1547-1557) does
  set `egress_ifindex = endpoint.logical_ifindex` (tunnel logical) and
  `next_hop = outer.next_hop` (outer hop), and **discards
  `outer.egress_ifindex`**. Confirmed by reading the literal.
- Neighbors are keyed by the **L3 egress ifindex**: the base resolution
  (mod.rs:1251-1259) calls `lookup_neighbor_entry(state, dyn, ifindex, ip)`
  with `egress_ifindex = ifindex`; `populate_egress_resolution`
  (session_glue/mod.rs:52-59) moves `tx_ifindex` to `bind_ifindex` (the
  VLAN parent) but leaves `egress_ifindex` as the subif. So
  `outer.egress_ifindex` IS the correct neighbor key, and `tx_ifindex`
  (parent) would be WRONG for a VLAN outer transport — the plan's VLAN
  reasoning holds, and it rules out the tempting "just use tx_ifindex"
  shortcut.
- The MissingNeighbor arm keys the kernel ARP probe
  (poll_descriptor/mod.rs:2520-2528, `ifindex_to_name.get(&egress_ifindex)`
  → `trigger_kernel_arp_probe`), the resolver enqueue + neg-cache + resolved-
  wins (mod.rs:2376-2496), and the `already_probing` dedup (2515-2518) all
  by `egress_ifindex`. For a tunnel-marked decision that is the tunnel
  logical ifindex → probe binds to the GRE iface (no ARP) and the resolver
  is keyed off the real outer iface. `trigger_kernel_arp_probe`
  (neighbor.rs:36-71) `SO_BINDTODEVICE`-binds to the name and sends ICMP —
  binding to a GRE netdev emits nothing on `ge-0-0-1`. Confirmed.
- Fresh-flush detail confirmed: the resolver enqueue lives ONLY inside the
  `fast_fail` branch (mod.rs:2429-2486), which requires a negative-cache
  entry. A freshly-flushed hop has none → `fast_fail=false` → resolver
  never enqueued → "resolver counters flat", exactly as captured.

## Death-site clarification — STRENGTHEN the plan

The plan says the packet "dies" and "never recovers." Be precise (the issue
explicitly asks to localize the death site): the cold-outer-hop reply
reaches the **MissingNeighbor arm** (disposition = outer.disposition =
MissingNeighbor, mod.rs:1256), fires the wrong-iface probe, is correctly
**refused pending_neigh** (R-E, anti-plaintext-leak), then the trailing
`maybe_reinject_slow_path_from_frame` routes it into the **R-C
`tunnel_encap_unresolved` drop** (slow_path.rs:231-243). So:

- **Where it dies**: the R-C `tunnel_encap_unresolved` drop (correctly — no
  plaintext reinjection).
- **Why it never recovers**: the probe in the arm fired on the wrong
  interface, so the kernel never learns the outer MAC.

**Action (MINOR-1)**: the plan + the live repro should record
`tunnel_encap_unresolved_drops` (per-binding, slow_path.rs:232) — it should
be NONZERO during the blackhole windows, proving the death site. The issue
listed neg_neigh/pending/resolver counters but NOT this one; confirming it
non-zero closes the localization the issue asked for.

## Design convergence required (the plan leaves these open by design)

- **MINOR-2 — commit to Option A with explicit field on all literals, not
  the sentinel.** Option A (dedicated `neigh_ifindex`) is the right SSOT;
  Option C (arm-local re-derivation) duplicates outer-resolution logic and
  adds a cold-path resolution call — reject C. On the sentinel question:
  prefer the EXPLICIT field on every `ForwardingResolution` literal over
  `neigh_ifindex == 0 → fall back to egress_ifindex`. A sentinel lets a
  future literal silently forget the field and mis-key a non-tunnel
  neighbor; an explicit field is compile-time complete (every literal must
  set it, so the compiler enforces the invariant). The ~15-literal cost is
  mechanical and the right tradeoff (matches this codebase's "compile-time
  invariants" discipline). A tiny constructor/helper that takes
  `egress_ifindex` and sets both can reduce the noise without losing
  completeness.
- **MINOR-3 — settle the HA-sync field-trust question (Q4) with a code
  check, not a deferral.** Confirm whether `ForwardingResolution` (with the
  new field) is serialized in any cluster-synced struct
  (`SyncedSessionEntry` / session sync). If a session's stored resolution
  crosses the wire, the peer MUST recompute `neigh_ifindex` from the tunnel
  endpoint id (mirroring the existing tunnel_endpoint_id re-own guard at
  session_glue/mod.rs:90+), never trust a wire value — a stale/owner-
  divergent ifindex would mis-probe. This must be answered in the converged
  plan, not left as an `/engineer`-time surprise.
- **MINOR-4 — resolver-for-tunnel enhancement (Q3): INCLUDE it.** The
  core ifindex fix recovers a fully-flushed hop via the kernel probe, but a
  STALE/DELAY outer entry (the issue's one partially-successful round had
  10.0.61.102 STALE) benefits from the #1769 resolver's RTM_GETNEIGH
  revalidation. Since the fix already computes the correct `neigh_ifindex`,
  enqueuing the rate-limited resolver for a tunnel-marked MissingNeighbor
  (keyed by `(neigh_ifindex, next_hop)`) is cheap and closes the STALE gap.
  Recommend including it, not deferring.

## Things I checked that are NOT problems

- Non-tunnel path is byte-identical (`neigh_ifindex == egress_ifindex`).
- The fix opens no plaintext-leak window: R-C drop + R-E no-buffer unchanged;
  only the probe's bound interface changes.
- First-packet loss for ICMP/UDP is inherent to "don't buffer tunnel-marked"
  and acceptable — one-RTT recovery beats a full-window blackhole. Do NOT
  try to drive the cold window to zero (would require buffering, which R-E
  forbids).

## Bottom line

Root cause is airtight and code-verified. Convert MINOR-1..4 into the
converged plan (commit to Option A + explicit field; record the
tunnel_encap_unresolved_drops localization; resolve HA-sync trust; include
the resolver enqueue) and this is PLAN-READY for `/engineer`. The live
loss-cluster repro (who-has 10.0.61.102 now appears on ge-0-0-1; reply
recovers within one ping) is the only ground truth.
