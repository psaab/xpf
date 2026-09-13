# #9506 — Route-based IPsec decrypted-ingress capture/re-entry bridge (PLAN ONLY)

## 0. Status

**PLAN** — no production code. This document is the triple-review planning
artifact for `psaab/xpf#9506`. Successor to closed #8276 (priced only, PR
#8604 landed no production code) and to umbrella #7167 (closed NOT_PLANNED,
not fixed). The residual has no other open owner.

- Branch: `research/9506-xfrm-capture`, base `origin/master 7ef226474`.
- Scope of this plan: design the bounded kernel-to-userspace plaintext
  capture/re-entry mechanism ("B2") for XFRM-decrypted ingress, with a
  chosen handoff shape, budget math, invariants, risks, tests, and kill
  criteria. Explicitly no implementation, no PR.
- Plan review gate: hostile PLAN review by `zai/glm-5.3` and
  `openai-codex/gpt-6-astra`, verdicts PLAN-READY / NEEDS-MINOR /
  NEEDS-MAJOR / PLAN-KILL, raw outputs in `reviews/`. Max 3 rounds, then
  a split is reported honestly.

## 1. Framing

Route-based IPsec (`bind-interface stN`, the only IPsec model xpf supports
since policy-based `then permit tunnel` is hard-rejected per #3114)
decrypts in the kernel XFRM stack. Plaintext surfaces on the `xfrmi`
netdev, which is **excluded from AF_XDP ingress adjudication in both
planes independently** (Go `pkg/dataplane/userspace/ingress_exclusions.go`
`SecureTunnel` class via `userspaceSkipsIngressInterface` gating
`buildUserspaceIngressIfindexes` in `maps_sync.go`; Rust
`userspace-dp/src/server/helpers/planning.rs`
`include_userspace_binding_interface`). The armed kernel-forward path is
**deliberately open**: `pkg/daemon/daemon_transit_gate.go`
`applyTransitBarrier(armed=true)` *removes* the barrier, and the barrier
exists only while unarmed when `ip_forward` is already 0
(`pkg/nftables/transit_barrier.go:36-39`, "CLOSES NOTHING THAT WAS OPEN").
Admission is warning-only
(`pkg/config/compiler_ipsec_plaintext_warn.go:120-191`).

Net effect: an authenticated IPsec peer's inner packets reach
kernel-routed internal destinations with no zone policy, no session, no
NAT, no screen, no counter, and no deny event — the classic
site-to-site-tunnel-as-policy-bypass. The product discloses it
(`docs/userspace-dataplane-gaps.md` tunnel-plaintext section;
commit-time advisory), so this is a disclosed, unremediated, high-severity
gap with no active owner — not a hidden zero-day, and not a surprise.

## 2. Honest scope and value, with absolute numbers

What this plan buys, if built: every decrypted-ingress inner flow
evaluated against the tunnel's zone policy *before* session/flow-cache
lookup, with permit/deny evidence (session, counters, deny events), for
IPv4 and IPv6, including host-bound inner packets and multi-tunnel
isolation. What it does not buy: the kernel half is **unpriced** — no
number below covers getting a frame out of XFRM and a verdict back in.

Per-packet budget (carried from #8276/#7167 adjudication, not re-derived
here): **2,797 ns/packet**, from #5275's appliance measurement
(4.29 Gbit/s IPv4 = 357,500 pps). Measured in-process-half rows from the
committed instrument (`userspace-dp/benches/b2_capture_bridge.rs`, PR
#8545, 1500 B frames):

| Row | Cost | % of budget |
|---|---|---|
| 1500 B copy into reused buffer (irreducible floor) | 25.4 ns | 0.9% |
| Same-thread queue handoff | ~111 ns | ~4.0% |
| Cross-thread **round trip** | 12,648 ns | **452%** |
| Cross-thread **one-way** (halved, per bench comment) | ~6,324 ns | **226%** |

Per-packet cross-thread handoff is priced OUT: one-way it costs ~2.3x
the whole budget before the capture syscall, before adjudication, before
re-inject. Caveats travel with the numbers: ns figures from a dev box vs
an appliance-derived pps budget (order-of-magnitude, not verdict — one
`cargo bench --bench b2_capture_bridge` run on the loss userspace cluster
converts it), and the pooled-slot row must not be read as "allocation is
free" (extra per-slot mutex).

Honest value statement: this plan converts a disclosed bypass into an
enforced, measured path **only if** the kernel-half pricing (loss-cluster
gate, §8) confirms the surviving shape end-to-end. Until that gate
passes, the value is a converged, kill-criteria-bound design — not
protection.

## 3. Shipped work this plan builds on (not re-proposed)

- #8276 / PR #8604: B2 pricing instrument committed; in-process half
  measured; kernel half explicitly not priced.
- #7167 adjudication (`docs/research/7167-tunnel-ingress/adjudication.md`):
  four each-sufficient grounds refuting naive AF_XDP attach to the xfrmi
  (Ethernet-only `parse_l2` runs *before* the ingress-set lookup;
  global-minimum RX-queue collapse to one worker per NIC; one-shot
  `COPY_ONLY_BIND_FLAGS` bind with no fallback → black-holed tunnel;
  no egress path → `missing_egress_binding` recycle), plus the plan-r2 §0
  rule that a capture target must supply a *resolving* logical ifindex
  (`resolve_ifindex` → `None` collapses to `(0,0)` and silently
  reinjects).
- #8274 (WireGuard dataplane decap): proves the owned-frame entry pattern
  (`logical_ingress::build_logical_ingress_packet` rebinding to a
  tunnel `logical_ifindex`) and the #6682 unzoned-ingress guard (zone 0
  → deny even under permit-all).
- #7949: `bind-interface`-only tunnels visible in snapshot (egress half);
  the ingress advisory is narrowed to decrypted traffic and stays until
  enforcement is real.
- #7191 / #5275: unarmed-only transit barrier; `ip_forward` conditional on
  armed state but never lowered while armed — the bypass is LOAD-BEARING
  and the bridge must be built and proven BEFORE it is closed.
- #7480: `noroute_policy_denial` in the `NoRoute` arm before the
  slow-path chokepoint (outbound Shape-B tunnels fail closed on deny-all
  defaults) — ordering the inbound design must respect, not disturb.

## 4. Concrete design: capture, handoff, adjudication, re-entry

### 4.1 Chosen shape: batched cross-thread handoff, B ≥ 4 (design target 8–32, hard bound 64)

Same-thread adjudication in the capture thread (~111 ns handoff, 4.0%)
is the cheapest row, but it requires extracting the RX-loop body with
`binding` threaded through 17 fields, a second adjudication entry that
must not drift from the loop, and it spends the full adjudication cost
inside the capture thread where it starves capture under flood. The
**batched handoff** keeps one adjudication entry point (the worker) and
amortizes the ~6,324 ns one-way wake over B frames:

per-packet handoff ≈ 6,324/B + copy (25.4) + queue (~111, same-thread row).

| B | 6,324/B | +136 floor | % of 2,797 budget |
|---|---|---|---|
| 3 | 2,108 | ~2,244 | ~80% (survives, no headroom) |
| 4 | 1,581 | ~1,717 | ~61% |
| 8 | 791 | ~927 | ~33% |
| 16 | 395 | ~531 | ~19% |
| 32 | 198 | ~334 | ~12% |

B=3 is the adjudication's stated minimum; this plan sets the **acceptance
floor at B ≥ 4** (headroom for the adjudication itself, which is not in
these rows) and the design target at **B = 8–32** with a hard bound of
64 (latency cap: a batch waits at most one NAPI quantum / 100 µs timer
before flush, so low-rate flows never stall behind a half-full batch).
Saturation behavior is fail-closed: bounded queue, non-blocking producer,
refuse-at-bound (`push_bounded` shape), drop-and-count — never silent
fallback to the kernel bypass (§6.1).

Heap policy per frame: pooled slabs (no hot-path allocation, per
`docs/engineering-style.md`), sized against the existing bounds
(`MAX_PENDING_WORKER_COMMANDS` 4096 × 264 B ≈ 1.03 MiB/worker today; an
inline-MTU variant would be ~6.16 MiB/worker — arithmetic that rules out
inline payloads). Batch carries (slot, len, tunnel identity, generation)
— never raw pointers across threads.

### 4.2 Kernel half (the unpriced part this plan prices first, §8)

Candidate transport, in preference order, to be decided by the
loss-cluster gate — not by this document:

1. **AF_PACKET capture on the `xfrmi` + authoritative re-inject.** Read
   decrypted plaintext frames as they surface post-XFRM; adjudicated
   permits re-enter through a dedicated re-entry path (separate TUN,
   §4.4), denies die in userspace with counters. Copies: one
   kernel→user, one into the slab (the priced 25.4 ns floor).
2. **nfqueue round-trip with verdict.** Authoritative by construction
   (verdict = forward/drop at the hook), but the queue round trip is the
   dominant unknown and nfqueue is known-slow; kept as the fallback if
   AF_PACKET re-inject cannot be made authoritative (i.e. a permitted
   frame's re-entry can be confused with unadjudicated traffic).

Either way the capture binds to the tunnel's **logical ifindex** (the
`stN` the VPN's `bind-interface` names), resolved at bring-up and
re-resolved on rotation; an unresolvable target is observably REFUSED
(plan-r2 §0 negative case), never silently absent.

### 4.3 Adjudication entry: owned-frame path on the worker

Extend the #8274/#8062 owned-frame pattern: the batch lands on the
worker's existing bounded command queue as a packet-bearing command;
each frame enters **before** flow-cache/session lookup and before
policy, evaluated on the tunnel's logical ifindex, configured zone,
routing instance/table, and RG identity — never the outer physical
interface's zone. An existing outer ESP/IKE session must not imply an
inner-flow permit. The three known Option-E costs are owned explicitly:

- the loop-body extraction threads `binding` through 17 fields — done
  once, behind a batch-drain call, not per packet;
- `PendingForwardRequest.desc` is non-`Option` and TX unconditionally
  recycles `request.desc.addr` — the owned entry must construct a
  recyclable descriptor (pool slot return), not a fake addr;
- all 25 byte counters use `desc.len` (outer length) — the owned entry
  carries the **inner** length and every counter touched by this path is
  audited so inner bytes are counted as inner bytes (fail-on-revert test
  pins permit-counter equality between a tunnel flow and the same flow
  on a physical interface).

### 4.4 Re-entry without recirculation

Permitted inner frames re-enter the forwarding pipeline through a path
that cannot be reclassified as fresh inbound plaintext: a dedicated
re-entry TUN per worker (or fwmark + ingress-set membership that only
the re-entry path holds), consumed by the same worker that adjudicated
them. Outbound-encryption traffic handed to XFRM is never presented to
the capture socket (direction keyed on the xfrmi + if_id, not on
addresses). No-recirculation is a fail-on-revert test, not a comment.

### 4.5 Close the bypass only after the bridge is proven

Per the load-bearing constraint: ship capture + adjudication +
re-entry with the kernel forward path still open, prove deny/permit
parity on real traffic (§8), *then* close the xfrmi kernel-forward
bypass in the same change that removes the commit-time advisory
(`compiler_ipsec_plaintext_warn.go` + shared renderer
`compiler_tunnel_plaintext_advisory.go`; otherwise the advisory becomes
a second untruth). Bring-up capability failure (capture socket refused,
queue unavailable) fails the IPsec dataplane **closed** and
operator-visible — never silent fallback to Linux forwarding. Also in
the same change: update the two in-source references that still point
at closed #8276 (`compiler_ipsec_plaintext_warn.go:103-104`,
`pkg/dataplane/README.md:1133`) to #9506.

### 4.6 Explicitly NOT proposed (refuted in-issue, do-not-re-propose)

- No live-while-armed nftables `hook forward` chain: breaks the three
  armed paths `transit_barrier.go:29-33` enumerates (xfrm plaintext
  egress, SNAT'd frames for kernel routing via `accept_local`, #7409
  slow-path reinject) — each would need exemption before the chain
  exists, not after.
- No naive AF_XDP/generic-XDP attach to the xfrmi: refuted on all four
  adjudication grounds (§3), each sufficient alone.
- No userspace ESP decryption (XFRM stays crypto/SA authority), no SA
  traffic-selector-as-policy.

## 5. API preservation

- Config schema and CLI: unchanged. No new statement, no new show
  output, no flag. The zone already assigned to the tunnel becomes
  enforced; `commit` output loses the plaintext advisory for tunnels
  covered by the bridge (advisory removal is deletion of a spent
  warning, not a contract change).
- Go/Rust internal extension is additive: new bounded batch-queue
  type, new packet-bearing command variant, new owned-frame entry
  function, new capture-reader thread. No change to `WorkerCommand`
  wire shape for existing variants, no change to queue bounds
  (4096 / 16384), no change to the slow-path write-only contract for
  existing users (the capture reader is new machinery alongside it,
  not a second reader on its channel).
- Telemetry: additive counters only (captured, batch-flushed-by-size,
  batch-flushed-by-timer, queue-full drops, generation-fenced drops,
  recirculation refusals, inner-byte counters). Existing counter
  semantics for non-tunnel paths untouched.

## 6. Hidden invariants

1. **Bounded, fail-closed handoff.** No unbounded queue, no blocking
   producer, no silent kernel fallback on saturation. Saturation drops
   and counts (counter + deny event path, not `/dev/null`).
2. **Tunnel-identity adjudication.** Logical ifindex + configured zone
   + routing instance/table + RG identity; never the outer phys zone.
3. **Pipeline order.** Inner ingress before flow-cache/session and
   before policy; outer ESP/IKE session implies nothing inner.
4. **No recirculation** (§4.4), pinned by test.
5. **Generation fencing** across snapshot rotation, xfrmi recreate,
   `if_id` change, zone/VRF move, and HA demotion: every batch row
   carries the generation it was captured under; a worker whose
   generation has moved drops-and-counts stale rows. HA demotion
   additionally quiesces the capture reader before the RG role flips,
   so no pre-demotion plaintext is adjudicated under post-demotion
   identity.
6. **Bring-up fails closed**, operator-visible (§4.5).
7. **HA behavior:** capture state is per-node, never synced; standby
   runs no capture reader; failover re-resolves the logical ifindex
   and generation on the new active before the reader starts. No
   cross-tunnel identity leakage between two `xfrmi`/`if_id` instances
   with distinct zones/VRFs (overlapping inner prefixes adjudicated
   per-VRF).
8. **MTU/fragments:** capture MTU ≥ tunnel effective MTU; inner
   fragments adjudicated on first-fragment policy with non-first
   fragments tied to the same verdict (no fragment-evasion permit,
   no fragment-only DoS amplification — bounded reassembly budget);
   inner ICMP errors adjudicated as their own flow, never as an
   implied permit for the embedded flow.
9. **Counter semantics:** inner bytes counted as inner bytes (§4.3);
   outer ESP bytes never attributed to the inner session.
10. **Ordering with outbound (#7480):** the `NoRoute`-arm
    `noroute_policy_denial` behavior for Shape-B outbound is
    untouched; inbound capture never masks an outbound deny.
11. **`resolve_ifindex` totality:** every name the design introduces
    resolves or refuses loudly; `(0,0)` collapse is a test-pinned
    impossibility, not a hope.

## 7. Risk table

| # | Class | Risk | Mitigation |
|---|---|---|---|
| R1 | Correctness / security | Capture misses a plaintext path (second xfrmi, `if_id` change, recreate race) → silent bypass returns | Generation-fenced re-resolve on every snapshot rotation; recreate/zone-move/HA-demotion fail-on-revert tests; unresolvable-target REFUSED loudly |
| R2 | Correctness / security | Recirculation: re-injected permit re-enters as fresh plaintext → policy applied twice or bypassed on second pass | Dedicated re-entry path (§4.4) + no-recirculation test; direction keyed on xfrmi+if_id |
| R3 | Correctness / security | Counter/session drift: `desc.len` outer-vs-inner confusion, outer ESP session implying inner permit | Inner-length plumbing + counter-parity test; pipeline-order invariant (§6.3) pinned by deny-with-valid-SA test |
| R4 | Performance | Kernel half (AF_PACKET / nfqueue) blows the 2,797 ns budget even batched | Loss-cluster pricing gate FIRST (§8); kill criteria if B=32 still >80% budget end-to-end |
| R5 | Performance | Batching latency hurts low-rate / single-packet flows (IKE-adjacent, keepalives) | 100 µs / one-NAPI-quantum flush timer; timer-flush counter proves it fires |
| R6 | Performance | Slab-pool contention (per-slot mutex caveat from #8276) on many workers | Pool sharded per worker; contention row in the pricing gate |
| R7 | Availability | Queue-full under flood drops legitimate tunnel traffic (fail-closed = outage) | Bounded-drop-and-count is the *specified* behavior; sized queues + saturation test proving drop rate tracks overload, not deadlock; operator-visible counters |
| R8 | Availability | Closing the bypass breaks the three load-bearing armed paths | Close-last ordering (§4.5); armed-path regression tests (xfrm egress, SNAT accept_local, #7409 reinject) must pass with the bypass closed |
| R9 | Availability | Bring-up failure (no AF_PACKET / nfqueue caps) bricks IPsec dataplane closed with no recourse | Fail-closed + operator-visible error naming the missing capability; documented runbook entry |
| R10 | Operability / HA | Stale-generation adjudication across RG failover; standby/active capture overlap | Per-node capture, standby reader stopped, generation re-resolve on active (§6.5, §6.7); demotion-race test |
| R11 | Operability / HA | MTU/fragment evasion or black-hole after enforcement (DF, non-first-fragment, ICMP errors) | §6.8 fragment/ICMP rules + MTU fail-on-revert tests (v4 + v6, NAT-T and native ESP) |
| R12 | Operability | Advisory removal mistimed → CLI lies in either direction | Same-change rule (§4.5); test asserting advisory absent iff bridge enforced |

## 8. Test plan (fail-on-revert; loss userspace cluster, never faked)

Pricing gate (before any implementation PR beyond scaffolding):

- G1. `cargo bench --bench b2_capture_bridge` on the loss cluster:
  converts the dev-box rows to cluster silicon; confirms B ≥ 4 floor
  with headroom (target: batched per-packet ≤ 61% of budget at B=4).
- G2. Kernel-half pricing on real SAs: AF_PACKET capture + re-inject
  round cost and nfqueue round-trip cost per packet, at B = 4/8/16/32,
  IPv4 + IPv6, NAT-T and native ESP. Kill the plan if B=32 still
  exceeds ~80% of the budget end-to-end.

Enforcement tests (each must fail on today's tree, pass with the
change; smoke numbers from real runs only):

- T1. Authenticated ESP, denied inner flow (v4 + v6): drop, no inner
  egress, no session, deny event + counters.
- T2. Permitted inner flow (v4 + v6): expected session, forwarded,
  inner-byte counter parity with the same flow on a physical NIC.
- T3. Exact logical-xfrmi from-zone → routed to-zone attribution with
  overlapping per-VRF destination prefixes.
- T4. Valid SA + selector but denied application/port policy: drop.
- T5. Host-destination inner packet: host-inbound deny and permit.
- T6. NAT-T and native ESP; fragment / non-first-fragment; inner ICMP
  error handling per §6.8.
- T7. Two xfrmi/if_id instances, distinct zones/VRFs: no identity
  leakage either direction.
- T8. Saturation: bounded capture full → fail-closed drops with
  counters, no kernel fallback, recovery without restart.
- T9. Bring-up without capture capability: IPsec dataplane closed +
  operator-visible error.
- T10. xfrmi recreate / zone move / HA demotion races; unresolvable
  capture target observably REFUSED.
- T11. No-recirculation: reinjected permits not re-adjudicated.
- T12. Armed-path regressions with bypass closed: xfrm egress,
  SNAT accept_local, #7409 reinject.
- T13. Advisory: present before enforcement, absent after, per tunnel.

## 9. Out of scope

- Userspace ESP decryption (XFRM remains the crypto/SA authority).
- Policy-based IPsec (`then permit tunnel`, hard-rejected since #3114).
- Any live-while-armed nftables forward chain; any AF_XDP attach to the
  xfrmi (both refuted, §4.6).
- WireGuard kernel-path residual (#8274's stated residual) and the
  #8279 TUN-admission defect — separate owners, separate plans.
- SA traffic-selector-as-policy; `allowed-ips`-as-policy for IPsec.
- Flowtable machinery (repo creates no flowtable; #7191 pins it).
- Cross-node capture state sync; standby adjudication.
- Re-tuning the 2,797 ns budget itself (a new appliance measurement is
  a different task; the gate converts the rows, not the budget).

## 10. Open questions (each invites PLAN-KILL if answered badly)

1. **Which kernel transport actually meets the budget?** AF_PACKET +
   re-inject vs nfqueue is unpriced by definition (§8 G2). If neither
   fits at B=32, is there a third transport, or is B2 dead and this
   plan killed?
2. **What does adjudication itself cost per inner packet?** All rows
   price the handoff, none price policy+session+NAT+screen on an
   owned frame. If adjudication alone approaches the budget, does any
   B save us?
3. **Who owns the batch-flush timer under NAPI pressure?** A timer
   that slips under flood turns B=8 into B=64 latency for the flows
   that survive — is the latency cap enforceable in the capture
   thread without reintroducing a per-packet wake?
4. **How is re-entry authorized, exactly?** Dedicated TUN per worker
   vs fwmark vs kernel key: which one provably cannot be reached by
   unadjudicated traffic, and what breaks (VRF? netns? MTU?) with
   each?
5. **What is the generation primitive?** Snapshot generation,
   ifindex+generation tuple, or RG-epoch? What orders a demotion
   against in-flight batches without a per-packet fence that eats
   the budget the batching saved?
6. **Do the 25 `desc.len` counters have a complete enumeration?**
   The plan asserts an audit (§4.3); if the audit finds counters
   that cannot distinguish inner from outer without a wider
   refactor, does the plan's scope explode past a bounded bridge?
7. **Fragment policy: deny-non-first-fragment or bounded reassembly?**
   Either choice has a DoS or compatibility tail — which does the
   project accept, and is it written down anywhere yet?
8. **What closes the Shape-B outbound question (#8276 pricing Q3)?**
   #7480 changed the picture; under `permit-all` defaults the old
   unadjudicated outbound remains. Does this plan inherit that
   half, or does it stay explicitly out?

## 11. Acceptance (to move from PLAN to implementation)

- This plan converged on the branch with both hostile reviewers at
  PLAN-READY (or a reported split), raw verdicts saved in `reviews/`.
- Loss-cluster pricing gate G1+G2 passes: chosen transport at B ≥ 4
  leaves headroom inside 2,797 ns/pkt end-to-end (target ≤ 61% at
  B=4); kill/split reported otherwise.
- Implementation PR (separate work, not this plan) carries T1–T13
  green on real traffic, no faked smoke numbers, plus the same-change
  advisory removal and the #8276 in-source reference updates.
