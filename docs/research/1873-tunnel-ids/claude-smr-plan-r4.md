# #1873 plan v4 — Claude SMR hostile review (round 4)

Reviewer: Claude (domain SMR). Final pass on the blanket R-C gate.

## Q1 — blanket gate: ratified (attack failed)

Attempted to construct tunnel-marked TRANSIT traffic whose delivery
depends on kernel slow-path reinjection:

- WG pre-handshake: refuted — `frame/wg.rs:104` arms
  `request_handshake` before returning None; the TUN shuttle's
  `encap_and_send` hits the same `EncapError::NoSession` and drops
  (`wg_control.rs:548,592`). Delivery is impossible on both paths
  until the handshake completes; arming is worker-local.
- WG established-session build failures: MTU guard (already an
  explicit drop with counter), malformed (drop correct),
  TX-slot backpressure (drop is normal backpressure behavior).
- GRE outer MissingNeighbor: delivery deferred behind neighbor
  resolution on both designs; under blanket the prober (#1769)
  resolves and subsequent packets flow — only the in-window packets
  drop. Probing is preserved by R-E's explicit probe-then-drop.
- IPsec/XFRM traffic: XFRM interfaces are NOT tunnel endpoints in
  the snapshot (no `Tunnel` config ⇒ `tunnel_endpoint_id == 0`), so
  st0-bound traffic reinjects exactly as today — the gate cannot
  touch it.
- Host-originated traffic enters wgN/grN via the kernel host stack,
  not xpf-usp0 — untouched.

No depending-delivery trace found. The gate closes the admin-down
and VRF divergence leaks unconditionally.

## Q2 — new holes from blanket semantics: one editorial note

`record_slow_path_accept` consumers merely observe fewer accepts —
no invariant requires tunnel-marked accepts. One behavioral note for
§8/§9: dropped tunnel-marked packets generate NO ICMP unreachable
(today the kernel might emit one after reinjection). Silent
drop-with-counter is standard stateful-firewall behavior and the
`tunnel_encap_unresolved` counter is the operator surface; folding a
one-line note into §8 (done in this commit).

## Q3 — implementability: yes

R-A/R-B are bounded Go changes with exact functions named; R-C is a
one-condition gate at a single named chokepoint; R-E is two named
sites + a defensive arm; R-D's walk has named inputs (prev/next
`tunnel_endpoints` by logical name) and a named delivery mechanism
(Close deltas). Test matrix enumerates each pin. No open design
decisions remain that would need pre-approval at /engineer time.

## Verdict

PLAN-READY.
