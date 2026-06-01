# Research Plan — #1742: Same-queue XSK fanout for sub-multinomial per-flow fairness

- **Issue**: #1742 (label `perf`)
- **Branch**: `research/1742-same-queue-xsk-fanout`
- **Base**: origin/master @ e4556085a
- **Revision**: r1 (DRAFT)
- **Mode**: `/research` — stops at PLAN-READY or PLAN-KILL. No PR, no production code.

## 1. Problem statement

Per-flow throughput fairness under high fan-in (`iperf3 -P48` to a single
target, or any low-tuple-entropy workload) is bounded below by the RSS
**multinomial floor**: N flows hash across the mlx5 VF's 6 combined RX
queues; AF_XDP zero-copy pins each RX queue 1:1 to one worker; an
RSS-overloaded worker (12–15 of 48 flows) cannot be relieved because
every cross-*queue* rebalancing mechanism is killed (#937 XDP_REDIRECT,
#840 RETA tuning, #1203/#1211/#1693 placement). The kernel enforces
`xs->queue_id == xdp->rxq->queue_index` in `net/xdp/xsk.c::xsk_rcv_check`,
so a zero-copy frame can only be delivered to a socket bound to the
*packet's own* RX queue.

#1742 proposes the **one lever that lineage never tested**: keep
`queue_id` constant (so `xsk_rcv_check` passes) but bind **multiple XSKs
to the SAME (netdev, queue_id)** via `XDP_SHARED_UMEM`, and have the
custom XDP program steer each packet (stable per-5-tuple hash) to a
different XSKMAP slot. That lets **>1 worker drain one hot RX queue**,
breaking the 1:1 queue↔worker assumption that produces the multinomial
floor.

## 2. Feasibility findings (code + kernel walk)

### 2.1 AF_XDP same-queue multi-socket IS supported (SPSC objection resolved)

The issue worried that AF_XDP RX rings are SPSC so "you can't have two
threads consume one RX ring." Correct — but that is **not** what
same-queue fanout requires. Under `XDP_SHARED_UMEM`, binding a second
socket to the same `(dev, queue_id)` gives that socket its **own**
RX/TX/FILL/COMPLETION rings while sharing only the UMEM frame area
(kernel `xsk_bind`/`xp_assign_dev_shared`; libxdp
`xsk_socket__create_shared`). So two workers each own a **distinct** RX
ring on the same queue → two SPSC consumers, no shared-ring contention.
The XDP `bpf_redirect_map(xskmap, slot, 0)` picks which socket's RX ring
each frame lands in. Both slots have `queue_id == rxq->queue_index`, so
`xsk_rcv_check` passes for both → **genuinely not the killed cross-queue
path**.

Evidence in-tree:
- `userspace-xdp/src/lib.rs:312` already declares `USERSPACE_XSK_MAP:
  XskMap(4096)` and `:670` already calls
  `USERSPACE_XSK_MAP.redirect(binding.slot, 0)` to an arbitrary slot.
- `userspace-dp/src/afxdp/bind.rs:8-9` already defines
  `SHARED_OWNER_BIND_FLAGS = [ZEROCOPY]` and `SHARED_SECONDARY_BIND_FLAGS
  = [XDP_BIND_SHARED_UMEM]`; `:380` calls `create_shared`. The
  shared-UMEM owner/secondary machinery **exists today**.

### 2.2 But the existing shared-UMEM is CROSS-NIC, not same-queue

`shared_umem.rs` only ever groups secondaries **across different NIC
devices on the same worker** (`apply_cross_nic_groups`,
`cross_nic_eligible() = driver==mlx5_core && distinct device_path`) or a
`same-device-debug` mode that still groups *distinct (queue,ifindex)
bindings owned by one worker*. `assign_group_roles` sorts by
`(queue_id, ifindex, slot)` and gives one Owner + N Secondary, but every
member is a **different** (ifindex,queue) tuple and they are all driven
by the **same** worker thread. There is **no** code path today that
places two *different workers'* sockets on one `(ifindex, queue_id)`.
The XDP steerer (`select_userspace_queue`, lib.rs:1364) explicitly
returns `rx_queue_index % queue_count` and carries a comment (1377–1384)
forbidding cross-queue hashing. So #1742 is **net-new ownership
topology**, not a config flip of existing shared-UMEM.

### 2.3 TCP ordering: feasible IF the hash is stable and reverse-consistent

Per-flow fanout must be **stable** (a flow always → same XSK) for TCP
ordering, and the XDP `parse_l4` already extracts the 4-tuple
(lib.rs:1388). A symmetric hash over the 5-tuple within the XDP program
keeps a flow on one slot for its lifetime. Caveat: the **return**
direction (reverse 5-tuple) hashes to a *different* slot unless the hash
is made direction-symmetric — but forward/reverse already land on
different RX *queues* today (RSS is not symmetric on this VF unless
keyed), so this is not a new regression, only a non-improvement for the
reverse path of a given flow.

## 3. Blast radius (this is where it likely PLAN-KILLs)

The 1:1 queue↔worker assumption is **load-bearing in at least five
subsystems**. Same-queue fanout makes the mapping `(ifindex, queue_id) →
{worker_a, worker_b}` (1:N), which violates structural assumptions:

| Subsystem | Current assumption | Breakage under fanout |
|---|---|---|
| **CoS shared-lease v8** | `cos_owner_worker_by_queue: (egress_ifindex,queue_id) → ONE worker` (coordinator/mod.rs:1305, :1358 `eligible_workers[next % len]`). `unique_interface_owner_worker_id` (mod.rs:1247) asserts one owner per interface. | A queue now has 2 RX-owning workers. CoS lease arbitration, cross-binding redirect (`cross_binding.rs` routes TX to `owner_worker_id`), and the v8 epoch rate-meter all key on a *single* owner. Two ingress workers feeding one egress CoS queue is exactly the cross-binding funnel that caused the **#1183 10× reverse regression**. |
| **Session table** | Worker-local `SessionTable` per worker; a flow's forward+reverse entries live on the worker that owns its RX queue (`session/entry.rs`, `worker/lifecycle.rs:22`). | Fanout splits flows of one queue across 2 workers' session tables. First-packet→session-create races if hash assignment changes (it must not), and conntrack lookups stay worker-local only if the hash is *perfectly* stable across config reload, GC, and HA failover. |
| **HA session sync** | `owner_rg_id` + shared synced maps `Arc<Mutex<FastMap>>` (session_manager.rs:13-15); peer reconstructs ownership by RG, not by sub-queue slot. | A synced session arriving on the peer must map back to the *same* sub-slot the hash would pick, or post-failover the flow lands on the wrong worker and either duplicates session state or strands the fast path (the `try_fabric_redirect` class of bug). Hash function must be byte-identical and config-stable across both nodes. |
| **FILL/COMPLETION ring ownership** | Each binding owns its FILL/CQ; mlx5 ZC posts RX WQEs from the fill ring during NAPI (`bind.rs:248`). | Two same-queue sockets each have their own FILL ring but **share one UMEM frame pool**. Frame-leak/double-free risk if both workers recycle into the same UMEM region; needs a partitioned frame allocator per secondary (net-new; the cross-NIC path never had two consumers racing one pool on one queue). |
| **Status/metrics/fairness telemetry** | `xpf_userspace_cos_active_flow_count{ifindex,queue_id,worker_id}` and the whole #1217/#1220 fairness harness assume `{a_i}` is per-worker == per-queue. | `Cstruct` computation, the `aggregate_per_worker()` helper, and `cos_owner_worker_by_queue` all need a sub-queue dimension. The harness merge-bar would have to be re-derived. |

## 4. Does fanout actually beat the multinomial floor? (the math)

The multinomial floor (docs/fairness-regimes.md, state.md) is
`CoV_floor(N,K)` for K=6 workers. Same-queue fanout **changes K**: if
every hot queue fans out to 2 workers, the effective worker count for
flow placement goes from 6 to up to 12. By the documented `1/sqrt`-ish
scaling and the `(N,K)` floor table, **K=12 lowers the floor**
(N=48,K=12 ≈ 0.30 vs N=48,K=6 ≈ 0.31 occupancy-CoV; the per-flow
throughput floor drops more because each worker now serves ~half as many
flows). BUT — and this is decisive — **K is bounded by physical CPUs**.
The cluster has 6 RX queues → 6 workers on ~6 cores. Fanning out to 12
software slots does **not** create 12 cores; two same-queue workers
**contend for the same NAPI-delivered packet stream and the same memory
bandwidth**. This is exactly the #1243 trap restated:

> "changing K alone trades aggregate throughput for fairness without net
> benefit; only K *plus* added physical capacity moves the floor."

Same-queue fanout adds **software** parallelism on a queue whose
**hardware** delivery (single NAPI context, single RX IRQ, single
mlx5 RX ring fill) is still serialized. The second worker can only
process frames the first didn't, but they both pull from one hardware
queue's bandwidth.

### 4.1 Simulation (run, per state.md "show the math first")

`/tmp/fanout_sim.py` (seed=42, population CoV, matching
`fairness.rs::compute_observed_cov`). Baseline reproduces the documented
floor exactly (N=12,K=6 → 0.5105 vs state.md closed-form 0.5106).

Three models of the fairness floor under fanout:

| Model | N=12 | N=24 | N=48 |
|---|---|---|---|
| Baseline floor (K=6) | 0.510 | 0.503 | 0.346 |
| **(a)** Naive "fanout = K=12, each slot a fresh core" | 0.424 (−0.086) | 0.547 (+0.044) | **0.546 (+0.199, WORSE)** |
| **(b)** Lazy split hottest queue, each slot a fresh core | 0.395 (−0.115) | 0.395 (−0.108) | 0.288 (−0.059) |
| **(c)** Capacity-aware: 2 slots SHARE one hw-queue bw, NO new core | 0.519 (+0.008) | 0.505 (+0.002) | **0.347 (+0.001, ZERO)** |

**Model (c) is the physical reality** and it is decisive. Adding a
software XSK slot to an existing RX queue creates **no** new core, IRQ,
or NAPI context — the two slots split that queue's *existing* hardware
bandwidth. Under that constraint the per-flow CoV floor is **unchanged**
(delta ≈ 0 at every N). The apparent wins in models (a)/(b) come
**entirely** from the false premise that each new software slot brings a
fresh capacity-1.0 core. This is the **#1243 cancellation, restated**:
changing K without adding physical capacity moves nothing.

Model (a) further shows that at the *motivating* `-P48` workload, even
the fresh-core fantasy makes the floor **worse** (+0.199), because 48
flows over 6 queues are already well-averaged and splitting each queue
into 2 slots of ~4 flows raises per-flow rate variance.

**Conclusion: same-queue fanout fails state.md's "Bar for future
fairness pitches" — it changes K but adds no physical capacity, so by
the project's own formal prior it cannot move the floor.**

## 5. Scope justification (settle FIRST per issue)

Is single-source-many-flows a real production workload?
- **NAT'd subscribers / CGNAT**: many subscribers behind one public IP →
  diverse *source* 5-tuples → spreads across queues fine. NOT this case.
- **Proxy / CDN origin / backup accelerator**: one client IP, many
  parallel connections to one origin. Source ports are ephemeral and
  random → still a uniform multinomial draw over 6 queues. The floor
  bites only at **low N** (N≈6–12), and the floor *shrinks* as N grows
  (state.md table: N=24 occupancy-CoV 0.44, N=48 lower). A real
  high-fan-in proxy has **high N**, where the floor is already mild.
- **The synthetic `iperf3 -P48`**: the only workload where the floor is
  both reproducible and "bad," and #1220's empirical sweep already
  returns **PASS** on every tested class (P=12/6/24/12-push) because
  observed_CoV sits *below* Cstruct. There is **no empirically failing
  production workload on record** (state.md "Open work": "As of the
  2026-05-07 sweep, NO empirically failing workload exists").

This is the same wall that killed #1211 (Path 2 AFD): the harness PASSes
the real workloads, so a redesign "solving" the synthetic probe is
solving a non-existent problem.

## 6. Multiple path options

- **Path A — Full same-queue fanout (the #1742 lever).** Net-new 1:N
  ownership, new partitioned frame allocator, CoS/session/HA rework, new
  fairness telemetry dimension. Highest blast radius. Win is real on the
  synthetic probe; aggregate cost is the #1243 cancellation on shared
  hardware-queue bandwidth.
- **Path B — Lazy fanout (only hot queues).** Fan out a queue only when
  it carries `> threshold` active flows AND aggregate is saturated.
  Mitigates the #1183 common-path regression, but the *trigger* is a
  reactive re-steer of an established flow (the SYN was already
  RSS-placed) — which is the forbidden re-steer pattern (#1649,
  docs/fairness-regimes.md "negative dependence"). Moving an established
  flow to a different slot breaks TCP ordering. So lazy fanout can only
  apply to **newly-created** flows on a hot queue, which doesn't relieve
  the existing overload.
- **Path C — PLAN-KILL / document.** Conclude that same-queue fanout is
  AF_XDP-*feasible* but (a) doesn't beat the floor without added
  physical capacity (#1243 cancellation), (b) has no failing production
  workload to justify the cross-cutting rework, (c) re-introduces the
  #1183 cross-binding funnel. Update state.md's killed-mechanisms table
  to close the "same-queue (not cross-queue)" gap explicitly so the
  lineage is complete.

## 7. Recommendation (DRAFT — pending reviewer rounds)

**Path C (PLAN-KILL with documentation).** The lever is genuinely
different and AF_XDP-feasible (resolving the issue's SPSC and
cross-queue worries), but it fails the project's own
"Bar for future fairness pitches": it changes K *without* adding
physical capacity (#1243 cancellation), and there is no empirically
failing production workload (#1211 closure rationale). The one honest
deliverable is to **close the lineage gap**: state.md and
fairness-regimes.md currently document only *cross-queue* kills; adding
the same-queue-fanout analysis makes the kill archive complete and
prevents a sixth re-attempt.

This recommendation is explicitly subject to the **Section 4 simulation
being run** — if a closed-form/Monte-Carlo model shows same-queue fanout
beats the floor by a margin that survives the shared-hardware-bandwidth
penalty on a *named real workload*, the recommendation flips to a
scoped Path B feasibility prototype.

## 8. Validation plan (if it were to ship — for completeness)

Per docs/fairness-regimes.md + state.md "How to apply":
1. Baseline `(observed_CoV, Cstruct, gap)` on loss userspace cluster,
   master, for the targeted workload via `fairness-harness.sh` +
   `fairness-eval` (per-stream CoV ground truth — NOT the
   `cos_active_flow_count` gauge, which is buggy per #1741 in flight).
2. Section 4 simulation FIRST (closed-form new floor under fanout).
3. Smoke matrix v4+v6 × push/reverse × CoS-off/on; #1183 regression
   guard (common non-overloaded path aggregate ≤5% regression).

## 9. Risks / unknowns

- **#1741 counter bug**: any measurement must use iperf per-stream CoV,
  not `cos_active_flow_count`.
- **Shared-UMEM frame allocator**: two same-queue consumers racing one
  UMEM pool is unproven in-tree (cross-NIC never did this).
- **HA hash stability**: byte-identical fanout hash across both nodes
  and across config reload is a correctness gate, not a perf nice.

## 10. Open questions for reviewers

1. Is the Section 4 #1243-cancellation argument decisive, or does
   software fanout on a shared hardware queue still net a fairness win
   because the *scheduler/session domains* split even if bandwidth
   doesn't? (Quantify.)
2. Is there ANY named production workload (not iperf) where the floor
   empirically fails the #1217 contract today? If yes, Path B reopens.
3. Does the existing cross-NIC shared-UMEM frame allocator already
   tolerate two consumers, or is a partitioned allocator truly net-new?

## 11. Decision

DRAFT — awaiting Codex + AGY + Claude-SMR round 1.
