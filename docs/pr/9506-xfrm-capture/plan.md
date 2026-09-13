# #9506 — Route-based IPsec decrypted-ingress capture/re-entry bridge (PLAN ONLY, r2)

## 0. Status

**PLAN r2** — no production code. Revision 2 of the triple-review planning
artifact for `psaab/xpf#9506`, rewritten after round-1 hostile review
(Codex: NEEDS-MAJOR; GLM: NEEDS-MAJOR; neither a PLAN-KILL — raw verdicts
in `reviews/codex-r1.txt`, `reviews/glm-5.3-r1.txt`). Successor to closed
#8276 (priced only, PR #8604 landed no production code) and umbrella
#7167 (closed NOT_PLANNED, not fixed). The residual has no other owner.

- Branch: `research/9506-xfrm-capture`, base `origin/master 7ef226474`.
- What changed in r2 (every item traces to a round-1 finding; codes Cx =
  Codex, Fx = GLM): authority-first transport order with a named closure
  mechanism (C3/C4/F5/F6/F20); shadow-mode interim with exactly-once
  invariant (F7/F14); re-derived budget with per-core accounting and
  corrected rows (C1/C2/F1/F2/F3); same-thread alternative held to the
  same standard (F4); B1 refutation refreshed for #7497 (C6); eleven new
  invariants (C7/F8–F13); nine new tests plus enforcement/preservation
  split and per-transport coverage (C8/F14–F19); questions rewritten
  (F20/F21/C9).
- Plan review gate: hostile PLAN review by `zai/glm-5.3` and
  `openai-codex/gpt-6-astra`, verdicts PLAN-READY / NEEDS-MINOR /
  NEEDS-MAJOR / PLAN-KILL, raw outputs in `reviews/`. This is round 2 of
  max 3; a split is reported honestly.

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

Round-1 correction to r1's framing, stated plainly: r1's "capture,
prove parity, then close the bypass" was **circular**. A passive tap
cannot deny anything while the original still forwards, and a permit
that is both kernel-forwarded and re-injected delivers twice. The
*denial mechanism* is the entire point of the bridge, and r1 left it
unnamed. This revision names it first (§4.2) and demotes everything
else below it.

## 2. Honest scope and value, with absolute numbers

What this plan buys, if built and gated: every decrypted-ingress inner
flow evaluated against the tunnel's zone policy *before*
session/flow-cache lookup, with permit/deny evidence (session, counters,
deny events), for IPv4 and IPv6, including host-bound inner packets and
multi-tunnel isolation — enforced by packet disposition (NFQUEUE
verdict), not by observation. What it does not buy yet: the kernel-half
cost and the owned-frame adjudication cost are **unmeasured** — no
number below covers them.

Budget, re-derived after round 1 (F1/C2 — the r1 presentation was
wrong in three ways, all corrected here):

- The 2,797 ns figure is the reciprocal of #5275's achieved whole-box
  throughput (4.29 Gbit/s IPv4 = 357,500 pps). It is the total
  per-packet time of the *entire armed pipeline* at max throughput, NOT
  slack available to a new mechanism. This plan therefore does NOT
  budget "61% of 2,797 ns with headroom". It defines the bridge's
  allowance as **incremental cost**: the bridge must not reduce
  sustained tunnel throughput below the e2e floor (T22) and must fit
  inside per-thread headroom measured on the loss cluster (G1). The
  2,797 ns reciprocal is retained only as a scale reference, cited to
  `adjudication.md:649`, never as spendable budget.
- Capture-thread ns and worker-thread ns are different cores. The
  binding constraint is the **worse** thread, not the sum. Rows are
  reported per-thread below (F1).
- Corrected bench facts (verified against
  `userspace-dp/benches/b2_capture_bridge.rs` in r2 preparation):
  the ~111 ns same-thread rows **already include** the 1500 B copy
  (`extend_from_slice` / `copy_from_slice` inside the timed region),
  so r1's "+136 floor" double-counted the copy — stated here as a
  conservative error, now removed. The cross-thread consumer reads
  only `f.len()`, so no payload-cache traffic is priced. The
  cross-thread row uses `sync_channel`; production uses the mutex
  `VecDeque` worker queue — a different primitive. There is **no
  batched row**: `6324/B` was a model, not a measurement. And
  4096 × 1504 B = 6,160,384 B = **6.16 MB (5.88 MiB)** — r1's "MiB"
  inherited the bench comment's wrong unit (F3).

| Row (all 1500 B, dev box) | Thread charged | Cost | Note |
|---|---|---|---|
| Copy into reused buffer (floor) | capture | 25.4 ns | irreducible, paid by every shape |
| Same-thread queue handoff (incl. copy) | capture/worker | ~111 ns | cheapest measured row |
| Cross-thread round trip | both + wake | 12,648 ns | 452% of the 2,797 scale ref |
| Cross-thread one-way (halved estimate) | both + wake | ~6,324 ns | 226%; a halving convention, not an isolation |
| Cross-core payload read of B frames | worker | **unmeasured** | ~100–300 ns/pkt plausible at B=32 (48 KB); must be a new bench row (G1) |
| Batched send, B frames per wake | capture | **unmeasured** | the decisive row; G1 must add it |
| Owned-frame adjudication (policy+session+NAT+screen) | worker | **unmeasured** | r1's Q2; folded into G1, no longer an open question (F21) |

The B=3 row is struck: at ~80% of the scale reference for the handoff
alone with the kernel half unpriced, it is dead, not surviving (F3).
Sustained-flood acceptance floor is **B ≥ 8** (target 8–32, hard bound
64, flush at one NAPI quantum / 100 µs). Timer-flushed partial batches
(singles at low rate) are part of the measured occupancy distribution,
not an exception to the floor — a floor that cannot hold at low rate
alongside bounded latency is not a floor (C2).

Honest value statement, unchanged in substance: this plan converts a
disclosed bypass into an enforced, measured path **only if** the
pricing gate (§8) confirms the authoritative shape end-to-end. Until
then its value is a converged, kill-criteria-bound design — not
protection.

## 3. Shipped work this plan builds on (not re-proposed)

- #8276 / PR #8604: B2 pricing instrument committed; in-process half
  partially measured; kernel half explicitly not priced.
- #7167 adjudication (`docs/research/7167-tunnel-ingress/adjudication.md`):
  the case against naive AF_XDP attach to the xfrmi, **refreshed for
  #7497** (C6 — r1 restated a stale ground). Current-tree grounds:
  (a) framing: the shim's `parse_l2` is Ethernet-only and runs *before*
  the ingress-set lookup, so a raw-L3 frame is misparsed without the
  set ever consulted (`8.0.x.x` inner sources alias `0x0800`);
  (b) an xfrmi has exactly one RX queue and **no dataplane egress
  path back** — admitting it mints a binding the dataplane cannot
  transmit into and spends a slot against `MAX_BINDING_SLOTS`
  (`ingress_exclusions.go:327-334`); (c) bind fragility: one-shot
  `COPY_ONLY_BIND_FLAGS` attempt with no fallback → black-holed tunnel;
  (d) no egress path → `missing_egress_binding` recycle, converting
  unadjudicated-but-forwarded into dropped plaintext. Deliberately NOT
  claimed: that a copy-mode XSK *cannot* come up on an xfrmi
  (`ingress_exclusions.go:356-363` — needs a live NIC, untested). The
  pre-#7497 global-minimum queue collapse is retired with the guard
  that pinned it; live guards are
  `secure_tunnel_adds_nothing_to_the_binding_plan` and
  `binding_candidate_excludes_secure_tunnel`. Consequences this plan
  inherits: adjudication identity must stay distinct from binding-plan
  admission, and "adjudicate but do not bind" is unavailable — an
  ifindex in the shim ingress map with no READY binding takes
  `drop_degraded_transit` (`BINDING_MISSING`), which is why the
  re-entry path (§4.4) must NEVER enter the ingress set (F12/C5).
- #8274 (WireGuard dataplane decap): proves the owned-frame entry
  pattern (`logical_ingress::build_logical_ingress_packet` rebinding to
  a tunnel `logical_ifindex`) and the #6682 unzoned-ingress guard.
- #7949: `bind-interface`-only tunnels visible in snapshot (egress
  half); ingress advisory narrowed and stays until enforcement is real.
- #7191 / #5275: unarmed-only transit barrier; `ip_forward` never
  lowered while armed — the bypass is LOAD-BEARING.
- #7480: `noroute_policy_denial` in the `NoRoute` arm (Shape-B outbound
  fail-closed on deny-all) — respected, not disturbed; the residual
  permit-all-defaults outbound behavior stays explicitly out (§9, F21).
- #7497: per-interface queue counts (`min(rx_queues, 16)` each) — the
  reason the queue-collapse ground above is stated per-binding, not
  globally.

## 4. Concrete design: authority first, then handoff, adjudication, re-entry

### 4.1 Design order (round-1 lesson)

The mechanism is ordered by what makes a denial real: (1) the
authoritative interception boundary (§4.2); (2) the handoff shape
(§4.3); (3) the adjudication entry (§4.4 in r2 numbering — kept as
§4.3 below for stable section references: §4.2 transport+closure,
§4.3 batch handoff, §4.4 adjudication entry, §4.5 re-entry, §4.6
close-last ordering, §4.7 refuted list). No section below may assume
what an earlier one has not supplied.

### 4.2 Primary transport: scoped NFQUEUE divert on the xfrmi (authoritative); AF_PACKET demoted to shadow-mode tap

**Chosen: a scoped nftables divert delivering xfrmi ingress to an
NFQUEUE drained by a capture thread, with per-packet verdicts returned
from userspace adjudication.** Authority first (F6/F20): NFQUEUE holds
the original packet — a deny verdict *is* the drop, a permit verdict
*is* the release. There is no second copy of the packet to suppress,
no re-entry confusion on the capture side, and no window in which a
"denied" packet forwards anyway. The r1 fallback trigger is reversed:
AF_PACKET is NOT an enforcement fallback. It is a shadow-mode-only tap
(§4.6) that can never graduate to enforcement, because a tap cannot
deny (C3).

The divert rules, stated exactly so §4.7's prohibition stays checkable:

- `forward` hook: match `iifname == <stN>` → `queue` (per-tunnel
  queue, or one queue with tunnel keying — implementation choice,
  same verdict semantics). This matches exactly the bypass traffic:
  decrypted ingress delivered on the xfrmi entering forward.
- `input` hook: match `iifname == <stN>` with host destination →
  `queue`. Forward-only interception would leave host-bound inner
  packets (T5) unadjudicated (C3).
- Untouched by construction: outbound toward the tunnel (`oif ==
  <stN>`, `iif` = LAN — the match is on `iif`, not `oif`); the SNAT'd
  frames passed up for kernel routing (different ingress, the reason
  `accept_local` is set); the #7409 slow-path reinject (reinject path,
  never `iif == stN`).

Reconciliation with §4.7 (F5): the refuted object is an *unconditional
policy-DROP forward chain* live while armed
(`transit_barrier.go:25-33` — the armed paths rely on forward being
"OPEN and UNFILTERED"). A scoped `iifname == stN → queue` divert is
not a policy chain: it carries no verdict of its own, drops nothing by
rule, and matches none of the other two armed paths. The first named
armed path (xfrm plaintext) is the divert's *input*: it is not broken,
it is replaced — open forwarding becomes verdict forwarding for
exactly that traffic. If implementation review finds the divert
matching anything beyond `iif == stN` ingress, that is the refuted
design returning indirectly (C4) and kills the change.

Verdict path and batching: NFQUEUE requires a per-packet verdict, so
batching lives between capture thread and worker, not at the kernel
boundary. The capture thread drains up to B packets from the queue,
hands the batch to the worker (§4.3), receives B verdicts, and issues
them. The amortized wake is per batch; the verdict-issue loop is per
packet on the capture thread (charged to the capture core in G1).

Rotation/disposition (F11): generation rotation drains or detaches the
queue; a detached queue's pending packets are dropped by the kernel
(socket close ⇒ fail-closed), stated and tested (T-rank rotation
test). An in-flight verdict applied post-rotation is safe because the
verdict was computed under the generation the packet was captured
under — stamping is at capture (§6.5), and rotation never re-keys a
packet already queued.

### 4.3 Handoff: batched, B ≥ 8 sustained (target 8–32, bound 64)

Same verdict as r1, re-derived under the corrected budget: the batch
keeps one adjudication entry point (the worker) and amortizes the wake
over B frames per §4.2's verdict loop. The `6324/B` table is struck
from this plan as pricing — it is a hypothesis pending the G1 batched
rows (C1/F2). What survives as *reasoning*: the wake is the dominant
measured term, batching is the only known amortization, and the floor
(B ≥ 8 sustained, partial batches at low rate measured as part of the
occupancy distribution) plus the 100 µs / one-quantum flush cap bound
both throughput and latency. Saturation is fail-closed: bounded queue,
non-blocking producer, refuse-at-bound, drop-and-count — never silent
kernel fallback. Heap policy: pooled slabs, no hot-path allocation;
batch rows carry (slot, len, tunnel identity, capture-stamped
generation) — never raw pointers; byte/slot bounds sized for 64-frame
commands, not command counts alone (C7).

The rejected alternative, held to the same standard (F4):
same-thread adjudication in the capture thread (~111 ns handoff, the
cheapest measured row) is rejected on a *model*, not a measurement —
full adjudication cost inside the capture thread risks capture
starvation under flood — and that model is gated the same way: G1's
fairness row must confirm the worker-side batch-drain does not starve
AF_XDP RX either (F8). If the gate shows worker-side starvation with
no bound that fixes it, the alternative reopens and this choice falls.

### 4.4 Adjudication entry: owned-frame path on the worker (unchanged mechanism, sharpened costs)

The #8274/#8062 owned-frame pattern: each frame of the batch enters
**before** flow-cache/session lookup and before policy, evaluated on
the tunnel's logical ifindex, configured zone, routing instance/table,
and RG identity — never the outer physical zone. Outer ESP/IKE session
implies nothing inner. Framing representation is specified, not
assumed: the xfrmi is `ARPHRD_NONE` (C7) — capture yields raw-L3
frames and the owned entry consumes an explicit L3-offset
representation, never the Ethernet-assuming shim parse. The three
Option-E costs, owned explicitly:

- loop-body extraction threads `binding` through 17 fields — once,
  behind a batch-drain call, with a batches-per-poll-cycle fairness
  bound so tunnel flood cannot starve the worker's AF_XDP RX (F8);
- `PendingForwardRequest.desc` non-`Option` + unconditional TX recycle
  of `request.desc.addr` — the owned entry constructs a recyclable
  pool-slot descriptor, never a fake addr;
- all 25 byte counters use `desc.len` (outer length) — the owned entry
  carries the **inner L3 byte count**, and the byte boundary is
  defined: inner L3 bytes, attempted vs successfully forwarded kept
  distinct, duplicates impossible by exactly-once (§4.5), fragments
  accounted per §6.8 (C7). Counter parity (permit AND deny sides,
  F19) against the same flow on a physical NIC is a fail-on-revert
  test.

Generation stamping is at **capture**, never dequeue: a kernel-buffered
packet read after rotation carries the old generation and is
drop-and-counted, never relabeled (C7).

### 4.5 Re-entry and exactly-once (shadow mode first, verdicts only at closure)

Permitted inner frames re-enter forwarding through a path that cannot
be reclassified as fresh inbound plaintext: a dedicated per-worker
re-entry TUN (fwmark alternatives rejected as underspecified, C5 —
anything less than a path the kernel cannot confuse is not a design).
Direction keyed on xfrmi + if_id; outbound-encryption traffic handed
to XFRM is never presented to the queue. Exactly-once invariant (C8):
a permitted flow egresses exactly once in every phase — in shadow
phase the kernel forwards the original and NO copy is re-injected, so
"exactly once" holds via suppression; after closure the NFQUEUE
permit-verdict release is the single egress and the re-entry TUN
carries only the post-adjudication forward. No-recirculation and
exactly-once are fail-on-revert tests, not comments.

The re-entry TUN is a new kernel netdev and therefore a new member
risk for every netdev-enumerating set (F12): it is excluded from the
snapshot/binding plan, the RSS/AF_XDP allowlist, and the refused-netdev
index by construction (same exclusion machinery, new class), with an
invariant + test. It MUST never enter the shim ingress map (half-admit
⇒ `drop_degraded_transit`, §3).

### 4.6 Close-last ordering with shadow mode (replaces r1 §4.5)

Three phases, each operator-visible, each with its test:

1. **Shadow**: divert live, verdicts computed and counted but the
   enforcement release suppressed — adjudicate-and-count. Interim
   semantics are defined, not tolerated: no packet egresses twice,
   divergence between verdict and kernel behavior is counted per
   verdict class, phase is queryable (F7/F14).
2. **Enforcing**: verdicts released; deny/permit parity proved on real
   traffic (§8); the commit-time advisory
   (`compiler_ipsec_plaintext_warn.go` + shared renderer
   `compiler_tunnel_plaintext_advisory.go`) removed in the SAME change
   (otherwise a second untruth). Same change also updates the two
   in-source references still pointing at closed #8276
   (`compiler_ipsec_plaintext_warn.go:103-104`,
   `pkg/dataplane/README.md:1133`) to #9506.
3. **Closed**: the pre-existing open-forward bypass for `iif == stN`
   no longer exists *because* the divert holds every such packet —
   there is no separate "close the bypass" step and no second
   mechanism to smuggle the refuted chain through (C4).

Bring-up or runtime capability failure (queue refused, reader death,
worker loss, socket closure — T9 extended to runtime, C8) fails the
IPsec dataplane **closed** and operator-visible: with the divert
holding packets and no verdicts forthcoming, the queue fills and the
kernel drops (fail-closed by disposition, T14) — never silent fallback
to Linux forwarding.

### 4.7 Explicitly NOT proposed (refuted in-issue, do-not-re-propose)

- No unconditional policy-DROP `hook forward` chain live while armed;
  the only armed forward-hook presence is the scoped `iifname == stN →
  queue` divert, which carries no verdict and matches no other armed
  path (§4.2). Anything broader is the refuted design returning (C4).
- No naive AF_XDP/generic-XDP attach to the xfrmi, on the refreshed
  four grounds (§3 a–d), each sufficient alone.
- No AF_PACKET-tap enforcement, ever — shadow/diagnostic only (C3/F6).
- No userspace ESP decryption (XFRM stays crypto/SA authority), no SA
  traffic-selector-as-policy.

## 5. API preservation

- Config schema and CLI: unchanged. No new statement, no new show
  output, no flag. The zone already assigned to the tunnel becomes
  enforced; `commit` output loses the plaintext advisory for enforced
  tunnels (deletion of a spent warning, not a contract change). Phase
  (shadow/enforcing) is exposed through existing telemetry/show
  surfaces, not a new CLI contract.
- Go/Rust internal extension is additive: new bounded batch-queue
  type, new packet-bearing command variant, new owned-frame entry
  function, new queue-draining capture thread, new per-tunnel divert
  lifecycle tied to snapshot generation. No change to `WorkerCommand`
  wire shape for existing variants, no change to queue bounds
  (4096 / 16384 — now joined by explicit byte/slot bounds for
  64-frame commands, C7), no second reader on the write-only slow-path
  channel.
- Telemetry: additive counters only (queued, batch-flushed-by-size,
  batch-flushed-by-timer, queue-full drops, generation-fenced drops,
  verdicts by class, shadow-divergence, recirculation refusals,
  inner-byte attempted/forwarded, timer-latency histogram). Existing
  counter semantics for non-tunnel paths untouched; telemetry itself
  is rate-bounded so per-drop events under flood cannot become the
  outage (C7).

## 6. Hidden invariants

1. **Bounded, fail-closed handoff.** No unbounded queue, no blocking
   producer, no silent kernel fallback on saturation. Saturation drops
   and counts. Mutex acquisition on the enqueue path is
   try-or-drop-and-count — a blocking producer is an unbounded queue
   with better manners (C7). Control-command progress is fenced from
   batch occupancy: a full packet batch never stalls a non-packet
   command (C7).
2. **Tunnel-identity adjudication.** Logical ifindex + configured zone
   + routing instance/table + RG identity; never the outer phys zone.
3. **Pipeline order.** Inner ingress before flow-cache/session and
   before policy; outer ESP/IKE session implies nothing inner.
4. **No recirculation; exactly-once egress** in every phase (§4.5),
   pinned by test.
5. **Generation fencing, atomic and capture-stamped.** Each queued
   packet carries an atomic (identity, configuration, ownership)
   association stamped at capture: tunnel key + snapshot generation +
   RG epoch. Covers rotation, xfrmi recreate, `if_id` change (incl.
   ifindex reuse — a reused ifindex under a new generation never
   inherits the old), zone/VRF move, HA demotion. Kernel-buffered
   packets read after rotation keep their capture stamp and are
   dropped-and-counted. NFQUEUE rotation drains/detaches with
   close-on-detach ⇒ pending dropped (fail-closed, F11). Demotion
   quiesces the reader AND fences in-flight verdicts, pending TX, and
   re-entry-queued frames: authorization must remain valid through
   final disposition, so a post-verdict pre-transmit demotion is
   drop-and-count, never transmit-under-new-role (C7/C8).
6. **Bring-up AND runtime failure fail closed**, operator-visible
   (§4.6, T14).
7. **HA behavior, RG-scoped.** Capture state is per-node, never synced;
   roles are per-RG, not per-node: different RGs with different owners
   capture only where active. Standby runs no reader. Abrupt failure:
   the failed node's queue-held packets die with it (fail-closed);
   the new owner re-resolves logical ifindex + generation before its
   reader starts, and adjudicates nothing until then — "new owner not
   capture-ready" is a closed tunnel, not an open one (C7). No
   cross-tunnel leakage between two xfrmi/if_id instances with
   distinct zones/VRFs (overlapping inner prefixes per-VRF).
8. **MTU/fragments/GRO.** Capture path handles GRO super-frames from
   `gro_cells` (F9): anything above the slab bound is refused-and-
   counted, never truncated. Slab sizing covers jumbo xfrmi MTUs, and
   re-entry TUN MTU writes that would fail are specified (fail-closed
   + counted). Fragment contract, decided (r1 Q7 resolved in-plan):
   **bounded reassembly** with explicit isolation keys (tunnel +
   VRF + src/dst/proto/id), overlap handling (first-wins + count,
   never merge-and-forward), expiry, and a hard resource cap; over
   cap ⇒ drop-and-count. Non-first fragments never earn a permit
   alone; inner ICMP errors adjudicated as their own flow, never as
   an implied permit for the embedded flow. Cross-batch fragment
   state lifetime spans the flush timer and generation rotation —
   rotation drops pending fragment state (F13). If the gate shows the
   reassembly budget incompatible with the handoff budget, this
   invariant — not the tests — is what kills the plan.
9. **Counter semantics.** Inner L3 bytes; attempted vs forwarded
   distinct; duplicates excluded by exactly-once; fragments per §6.8;
   outer ESP bytes never attributed to the inner session; permit AND
   deny parity (C7/F19).
10. **Ordering with outbound (#7480)** untouched; permit-all-defaults
    outbound residual stays out (§9).
11. **`resolve_ifindex` totality:** every name the design introduces
    resolves or refuses loudly; `(0,0)` collapse test-pinned
    impossible.
12. **Ownership-keyed capture resolution** (F10): the divert binds the
    tunnel by the SecureTunnel ownership union
    (`SecureTunnelNetdevForRef` ∪ `liveXfrmNetdevs`) — never the `stN`
    name shape. An unowned `st5` (physical NIC, no VPN) is never
    diverted and keeps its AF_XDP path (test T20).
13. **Re-entry TUN exclusion** from snapshot, binding plan, RSS
    allowlist, refused-netdev index; never in the shim ingress map
    (F12).
14. **Worker fairness bound** (F8/C7): batches-per-poll-cycle cap on
    the batch-drain; starvation of AF_XDP RX by tunnel flood is a
    gated measurement, not an assumption.

## 7. Risk table

| # | Class | Risk | Mitigation |
|---|---|---|---|
| R1 | Correctness / security | Divert misses a plaintext path (second xfrmi, `if_id` change, recreate race) → silent bypass returns | Ownership-keyed divert re-resolved every rotation; recreate/zone-move/HA-demotion fail-on-revert tests; unresolvable target REFUSED loudly |
| R2 | Correctness / security | Recirculation / double delivery: verdict-released permit plus kernel-forwarded original | No open-forward original exists once diverted (authority by hold); shadow phase suppresses re-inject; exactly-once + no-recirculation tests |
| R3 | Correctness / security | Counter/session drift: outer-vs-inner confusion, outer session implying inner permit | Inner-L3 plumbing + permit/deny parity tests; pipeline-order invariant pinned by deny-with-valid-SA test; session revocation test (T16) |
| R4 | Performance | Kernel half (NFQUEUE divert + verdict loop) blows the budget even batched | Pricing gate FIRST (§8); kill if B=32 still exceeds the e2e floor |
| R5 | Performance | Batching latency hurts low-rate flows | 100 µs / one-quantum flush cap; occupancy distribution measured incl. timer-flushed singles; latency test T22 |
| R6 | Performance | Slab-pool contention (per-slot mutex caveat) on many workers | Per-worker sharded pools; contention row in G1; cross-core payload-read row (F2) |
| R7 | Availability | Queue-full under flood drops legitimate tunnel traffic | Specified behavior (bounded-drop-and-count); sized queues + saturation test proving drop tracks overload, not deadlock; rate-bounded telemetry; control-command progress fenced |
| R8 | Availability | Divert breaks the two surviving armed paths (SNAT accept_local, #7409 reinject) | `iif == stN` scoping proof + armed-path regression tests with divert live (T12); anything broader kills the change (C4) |
| R9 | Availability | Bring-up/runtime failure bricks IPsec dataplane closed with no recourse | Fail-closed + operator-visible error naming the missing/dead capability; runbook entry; T14 |
| R10 | Operability / HA | Stale-generation verdicts across RG failover; standby/active overlap; abrupt-failure orphans | Per-node per-RG capture; standby reader stopped; re-resolve before start; in-flight fencing (§6.5); demotion-race + abrupt-failover tests |
| R11 | Operability | MTU/fragment/GRO evasion or black-hole (DF, non-first-fragment, super-frames, ICMP errors) | §6.8 contract + GRO/j junior-MTU tests (T21); reassembly budget as kill-linked invariant |
| R12 | Operability | Advisory removal mistimed → CLI lies either direction; shadow divergence invisible | Same-change rule; advisory presence/absence test per phase; shadow-divergence counters + phase visibility |

## 8. Test plan (fail-on-revert; loss userspace cluster, never faked)

Pricing gate (before any implementation PR beyond scaffolding):

- G1. On the loss cluster: re-run `b2_capture_bridge` PLUS three new
  committed rows — batched send (B = 8/16/32, occupancy incl.
  timer-flushed singles), cross-core payload read (B × 1500 B), and
  owned-frame adjudication cost through a real worker fast path
  (absorbs r1 Q2, F21) — with per-core attribution (capture core vs
  worker core; binding = worse thread) and a fairness row
  (batch-drain vs AF_XDP RX under tunnel flood, F8).
- G2. Kernel-half pricing on real SAs: NFQUEUE divert + verdict-loop
  cost per packet at B = 8/16/32, IPv4 + IPv6, NAT-T and native ESP,
  input-hook and forward-hook diverts. Kill the plan if B=32 still
  exceeds the e2e floor (T22's threshold).

Enforcement tests (each names the reverted mechanism it detects;
preservation tests marked [P] already pass today and guard the
load-bearing paths — C8):

- T1. Denied inner flow, valid SA (v4+v6): NFQUEUE drop verdict, no
  egress, no session, deny event + inner-byte attempted counters.
- T2. Permitted flow (v4+v6): session, single egress, inner-byte
  parity both directions with the same flow on a physical NIC.
- T3. Logical-xfrmi from-zone → to-zone attribution, overlapping
  per-VRF prefixes.
- T4. Valid SA + selector, denied app/port: drop.
- T5. Host-destination inner: input-hook divert, host-inbound deny
  and permit.
- T6. NAT-T + native ESP; fragments incl. split-across-batches;
  non-first-fragment alone never permits; inner ICMP error as own
  flow.
- T7. Two xfrmi/if_id, distinct zones/VRFs: no leakage either way.
- T8. Saturation: queue-full → fail-closed drops + counters, no
  kernel fallback, recovery without restart.
- T9. Bring-up without queue capability: closed + visible error.
- T10. Recreate / zone move / HA demotion (orderly + abrupt)
  races; unresolvable target REFUSED; post-verdict pre-transmit
  demotion drops.
- T11. No-recirculation + exactly-once per phase.
- T12 [P]. Armed-path regressions with divert live: SNAT
  accept_local path, #7409 reinject, outbound-to-tunnel (`oif ==
  stN`) unaffected.
- T13. Advisory present in shadow, absent when enforcing, per
  tunnel; in-source #8276 references updated.
- T14. Runtime death (reader/worker/socket) while armed+enforcing:
  queue fills, kernel drops, closed + counted — routed AND
  host-bound originals never forward unadjudicated (C8).
- T15. Exactly-once permits under flood + timer-flush scheduling.
- T16. Session/flow-cache/fragment revocation after policy/zone/VRF
  change (cached-state invalidation, C7).
- T17. Post-verdict pre-transmit demotion fencing (covered in T10;
  listed separately so it cannot be merged away).
- T18 [P]. SecureTunnel exclusions preserved across parent/unit
  aliases in both planes; unowned `st5` never diverted, keeps AF_XDP
  path (F10/F15).
- T19. Flush-timer latency measured under contention (histogram,
  not just a fire counter, F17-latency).
- T20. GRO super-frame / jumbo / over-TUN-MTU: refused-and-counted,
  never truncated (F9/F16).
- T21. Deny-side byte parity (F19).
- T22. E2e floors: tunnel throughput with bridge live ≥ stated % of
  pre-bridge on the loss cluster; p99 added latency bound (F17).

Per-transport coverage (F18): the T-suite runs against the NFQUEUE
shape; the AF_PACKET tap runs a stated shadow-only subset (divergence
counting, T20-style sizing) and is never graded as enforcement.

## 9. Out of scope

- Userspace ESP decryption (XFRM remains the crypto/SA authority).
- Policy-based IPsec (`then permit tunnel`, hard-rejected since #3114).
- Any unconditional policy-DROP forward chain live while armed; any
  AF_XDP attach to the xfrmi; any AF_PACKET-tap enforcement (§4.7).
- WireGuard kernel-path residual (#8274's stated residual) and the
  #8279 TUN-admission defect — separate owners, separate plans.
- SA traffic-selector-as-policy; `allowed-ips`-as-policy for IPsec.
- Shape-B outbound under permit-all defaults (#7480 residual) —
  stays out; value claims and advisory removal exclude it (F21/C9).
- Flowtable machinery (repo creates no flowtable; #7191 pins it).
- Cross-node capture state sync; standby adjudication.
- Re-tuning the throughput scale itself (a new appliance measurement
  is a different task; the gate measures incrementally against it).

## 10. Open questions (each invites PLAN-KILL if answered badly)

1. **What does the divert + verdict loop cost end-to-end?**
   Replaces r1 Q1 with the authority-correct form: NFQUEUE hold +
   batched adjudication + verdict issue at B = 8/16/32 on real SAs.
   If B=32 still breaks the T22 floor, is there a third
   authoritative transport, or is B2 dead?
2. **Who owns the flush timer under NAPI pressure?** A timer that
   slips under flood turns B=8 into B=64 latency for surviving flows
   — enforceable in the capture thread without reintroducing a
   per-packet wake, or is the latency cap fiction?
3. **What is the generation primitive?** Snapshot generation,
   ifindex+generation tuple, or RG-epoch — which orders demotion
   against in-flight batches without a per-packet fence eating what
   batching saved, and which fences kernel-in-flight verdicts (F11)?
4. **Do the 25 `desc.len` counters have a complete enumeration?**
   If the audit finds counters that cannot distinguish inner from
   outer without a wider refactor, scope explodes past a bounded
   bridge — kill or re-scope?
5. **Does the bounded-reassembly budget fit inside the handoff
   budget?** §6.8 chose bounded reassembly over drop-non-first; if
   G1/G2 show the memory/locking budget incompatible, which side
   gives — and is drop-non-first (with its compatibility tail)
   acceptable to the project, stated where?
6. **NFQUEUE queue sizing vs burst absorption:** what depth holds a
   flood burst without turning fail-closed into fail-always, and
   does depth itself cost latency the T22 bound forbids?
7. **Can the divert match stay minimal forever?** `iifname == stN →
   queue` plus the input-hook twin is the whole armed footprint;
   who guards it against "just one more match" in a future change —
   a test pinning the exact rule set, and does that test exist in
   this plan's T-suite (it must: T12's scope check)?

## 11. Acceptance (to move from PLAN to implementation)

- This plan converged on the branch with both hostile reviewers at
  PLAN-READY (or a reported split), raw verdicts saved in `reviews/`.
- Pricing gate G1+G2 passes on the loss cluster with per-core
  attribution: batched verdict loop at B ≥ 8 within the incremental
  allowance and the T22 e2e floor held; kill/split reported
  otherwise. No inferred `X/B` table is cited as pricing anywhere
  beyond this document's stated hypothesis.
- Implementation PR (separate work, not this plan) carries T1–T22
  green on real traffic (enforcement vs [P] preservation split
  honored), no faked smoke numbers, plus the same-change advisory
  removal and the #8276 in-source reference updates.
