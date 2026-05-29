# Research plan — #1649 Per-flow evenness via better INITIAL placement (no mid-flight re-steer)

- **Revision**: r2 (post round-1: Codex PLAN-NEEDS-WORK, AGY PLAN-READY, Claude SMR PLAN-NEEDS-WORK)
- **Status**: PLAN-KILL (rationale re-grounded on the multinomial argument; verdict unchanged from r1, mechanism analysis corrected)
- **Skill**: `/research` (research-only; stop at PLAN-READY or PLAN-KILL; no code; docs only)
- **Issue**: #1649 (label `perf`)
- **Worktree**: `.claude/worktrees/1649-research-initial-placement`, branch `research/1649-initial-placement`

---

## 1. Problem statement

`iperf3 -c 172.16.80.200 -p 5210 -P 6` on the loss userspace cluster shows a
stable bimodal per-flow distribution: ~17% CoV at 6 flows, 2 flows pinned slow
(~2.26 G) sharing one worker, 4 flows solo (~3.0-3.35 G), ≥1 worker idle. This
is the multinomial RSS-skew floor: N flows hashed into M RX queues do not
distribute one-per-queue. Aggregate is fine (~17.2 G, the push ceiling); only
per-flow distribution within a single best-effort class is uneven.

#1649 asks whether **initial placement** — a hardware steering rule programmed
once at flow-setup and NEVER re-steered — can beat that floor on the deployed
NIC, and explicitly forbids any mid-flight cross-worker re-steer (the killed
chain: #1215 #837 #937 #840 #1238 #1243).

## 2. NIC capability findings (Step 1 — non-disruptive ethtool, verbatim)

**The deployed loss-cluster dataplane NIC is mlx5_core, NOT i40e.** CLAUDE.md's
"i40e PF passthrough" claim is stale for this cluster (doc-drift; the i40e
description applies to the older standalone test VM). Verbatim from
`loss:xpf-userspace-fw0`:

```
$ ethtool -i ge-0-0-2          # transit iface carrying VLAN 50/80 (iperf path)
driver: mlx5_core
version: 7.0.0-rc7+
firmware-version: 26.48.1000 (MT_0000000531)
bus-info: 0000:09:00.0

$ ethtool -i ge-0-0-1          # loss-zone iface
driver: mlx5_core            # same

$ ethtool -i ge-0-0-0 / fxp0 / em0
driver: virtio_net           # trust/mgmt — NOT dataplane-saturating
```

fw1 peer uses the same NIC model on renamed interfaces (`ge-7-0-1`,
`ge-7-0-2`, both mlx5_core, 6 combined channels, ntuple togglable).

### 2.1 Channels / RX queues

```
$ ethtool -l ge-0-0-2
Combined: 6   (pre-set max 6, current 6)
```

6 RX queues = 6 workers — exactly the 6-flow CoV symptom denominator.

### 2.2 RSS indirection + hash

```
$ ethtool -x ge-0-0-2
RX flow hash indirection table for ge-0-0-2 with 6 RX ring(s):
  round-robin 0..5 across 256 buckets
RSS hash key: toeplitz: on / xor: off / symmetric-xor: off / symmetric-or-xor: on

$ ethtool -n ge-0-0-2 rx-flow-hash tcp4
IP SA, IP DA, L4 src port, L4 dst port   (full 5-tuple hashing)
```

The daemon already reshapes this table on mlx5 ifaces via
`pkg/daemon/rss_indirection.go` (`applyRSSIndirection`, allowlist + driver
guard + kill switch + reconcile-on-worker-change + CLI knob
`set system dataplane rss-indirection`). #840 reverted *indirection-table
tuning* for fairness (CoV 37.7% with vs 18.5% baseline) — documented in
`docs/fairness-regimes.md`.

### 2.3 ntuple (Flow steering) — the #937-named prerequisite EXISTS

```
$ ethtool -k ge-0-0-2 | grep ntuple
ntuple-filters: off              # default off, but…

$ ethtool -K ge-0-0-2 ntuple on  # togglable
ntuple-filters: on

$ ethtool -N ge-0-0-2 flow-type tcp4 src-ip 1.2.3.4 dst-ip 5.6.7.8 \
      src-port 1111 dst-port 2222 action 3
Added rule with ID 1023          # exact 5-tuple -> RX queue 3 WORKS
```

mlx5 supports exact-5-tuple → chosen-RX-queue steering via ethtool ntuple
(`ETHTOOL_SRXCLSRLINS`). The #937 / #840 kill verdicts named this exact
primitive as "the missing prerequisite." It is present on the deployed NIC.

### 2.4 Rule-table capacity (probed to exhaustion, then flushed)

```
# insert until failure:
FAIL at insert 1004: rmgr: Cannot find appropriate slot to insert rule
TOTAL_OK=1003 (+21 pre-existing) ; ethtool -n reports "Total 1024 rules"
```

**Capacity = 1024 rules** on this mlx5 / firmware combo via the ethtool path.
(The #1203 plan assumed "mlx5 typical 32k+" — that is WRONG for this firmware;
measured ceiling is 1024.) Rule IDs allocate descending from 1023.

### 2.5 Per-rule programming cost (measured)

```
200 sequential `ethtool -N` inserts: 1023 ms total → ~5.1 ms/insert wall-clock
ethtool --version fork+exec baseline (incus exec): ~4.0 ms/call
=> marginal HW-programming cost ≈ 1.1 ms/rule (firmware-mediated ioctl)
200 deletes: 789 ms total
```

~1.1 ms is the *kernel/firmware* ETHTOOL_SRXCLSRLINS cost even discounting
process fork. A direct netlink path (no `ethtool` fork) removes the ~4 ms
exec overhead but NOT the ~1.1 ms firmware programming.

## 3. Architecture: how a queue maps to a worker

`userspace-xdp/src/lib.rs:371-635`: native XDP reads `ctx->rx_queue_index`
(set by HW RSS or ntuple) → `select_userspace_queue()` → `binding.slot` →
`USERSPACE_XSK_MAP.redirect(binding.slot, 0)`. Each AF_XDP socket is bound to
`ifname:queue_id` (`xsk_ffi.rs`, `bind.rs:82` `info.set_queue(binding.queue_id)`).
**The binding is queue-bound and deterministic: RX queue N ⇒ the worker whose
XSK is bound to queue N** (the slot layout is stable per interface; HA/interface
changes re-derive it). So an ntuple rule pinning a
5-tuple to RX queue N delivers every packet of that flow to worker N. The lever
is real and direct. `userspace-xdp/src/lib.rs:1322`: "AF_XDP delivery is
queue-bound … redirect to a socket bound to a *different* queue silently
strands packets" — the durable physics behind the killed re-steer chain.

## 4. Prior art that nearly fully pre-tests this angle — #1203 / #789

**#1203 already implemented closed-loop mlx5 ntuple flow-steering on this exact
cluster** (`refactor/789-fairness-via-ntuple`,
`pkg/dataplane/userspace/flow_steering.go`): sticky placement, stale-rule
eviction, 1Hz reconcile, K=4 rules/tick, CLI knob, 6 Prometheus surfaces, 23
unit tests, 6 plan-review rounds. Empirical:

| Workload | Master CoV | #1203 closed-loop CoV | Phase-0 hand-installed |
|----------|-----------|----------------------|------------------------|
| iperf-c P=12 -R | 62.5% | **49-55%** (gate ≤20% NOT met) | **3.8%** (deterministic mod-8) |

#1203 was CLOSED. Both reviewers' convergent structural verdict (verbatim from
the issue close comment):

> "HW flow steering can't drive per-flow CoV under 20% for the iperf P=N
> workload because **per-flow CoV is bounded by within-queue scheduling, not
> placement.** … the within-queue path is currently single-FIFO-per-worker."

The controller successfully **flattened flow-count across queues** yet CoV
stayed ~50% — because at P=12 every queue holds ≥2 flows and the within-queue
scheduler (single FIFO for `shared_exact`/best-effort) sets their relative
rates. Placement was not the bottleneck; within-queue scheduling was.

### 4.1 The genuinely-fresh sub-case #1649 isolates: N ≤ M

#1649's symptom is **N=6 flows, M=6 workers** — distinct from #1203's P=12
(N>M). When N≤M, an ideal placement puts ≤1 flow per worker, so within-queue
scheduling is irrelevant (no contention). The Phase-0 hand-experiment hitting
**3.8% with deterministic per-port-mod assignment** is direct evidence that HW
steering CAN flatten the N≤M case. This is the one regime #1203's P=12 test
never cleanly isolated.

## 5. The fatal defect of REACTIVE initial placement (the central kill risk)

"Initial placement at first SYN" cannot be done without re-steering an
established flow, because of a strict ordering:

1. SYN arrives. **Hardware RSS (not the controller) picks the RX queue** —
   there is no ntuple rule for an unseen 5-tuple yet. The SYN lands on the
   RSS-chosen worker `W_rss`, which creates the conntrack/flow-cache entry.
2. The worker publishes its active-flow inventory at **1 Hz** (#1203's
   `ACTIVE_FLOWS_PUBLISH_INTERVAL_NS`). The Go controller learns of the new
   5-tuple **~0.5-1 s later**, by which time the flow is established on `W_rss`.
3. The controller computes "least-loaded worker" = `W_lru`. If `W_lru == W_rss`
   the rule is a **no-op** (RSS already put it there). If `W_lru ≠ W_rss`, the
   rule **moves the flow's packets to a different worker** — i.e. a **mid-flight
   re-steer**, which (a) is exactly the forbidden killed pattern, and (b) lands
   packets on a worker whose per-worker FlowCache (`afxdp/flow_cache.rs`) has no
   entry, forcing a slow-path re-resolution and risking the queue-strand
   physics at `lib.rs:1322`.

There is no syscall in the ethtool/devlink/TC surface that lets you choose the
queue for a 5-tuple **before that 5-tuple's first packet arrives** — the SYN's
 port is not knowable in advance. Therefore **reactive flow-setup-time placement
is structurally identical to a re-steer** for any flow RSS happened to mis-place
(which is precisely the flows you want to fix). True proactive initial placement
would require predicting future 5-tuples, which is impossible for the wildcard
connection-accept case.

**This is the same wall that closed the killed chain, re-expressed: AF_XDP +
HW-RSS means the FIRST packet's placement is owned by RSS, and any correction is
by definition a re-steer.**

## 6. Mechanism — the one non-reactive mechanism that exists: masked source-port-residue

There IS a non-reactive, non-re-steer ntuple mechanism (round-1 Codex
counter-example, confirmed on the hardware): **masked source-port-residue
rules**. Install once at boot, before any SYN:

```
$ ethtool -K ge-0-0-2 ntuple on
$ ethtool -N ge-0-0-2 flow-type tcp4 src-port 0 m 0xfff8 dst-port 5210 m 0x0000 action 0
  Added rule with ID 1023
$ ... src-port {0..5} m 0xfff8 -> queue {0..5}   # 6 rules, all accepted
  Filter: Src port: 0 mask: 0xfff8  ->  matches (src_port & 0x0007) == 0
```

mlx5 accepts masked src-port rules (verified). These six rules partition the
**future** src-port space by `src_port & 0x07` (low 3 bits) → RX queue. Because
a flow's src-port is fixed for its lifetime, the flow's queue never changes:
this is **genuinely not a re-steer** and **not reactive** — it does not need to
know the ephemeral port in advance, it classifies by residue. RSS-context
(`ethtool -X context` + a wildcard rule steering dst-port 5210 into the context)
is a second variant of the same idea (a static per-class hash). r1 §6 wrongly
claimed "no viable per-flow non-re-steer mechanism exists" — corrected here.

The kill is therefore NOT "no mechanism exists." The kill is that this mechanism
**relocates the multinomial draw without flattening it** for realistic traffic
(§7.0).

## 7. Honest viability (falsify the design)

### 7.0 The load-bearing kill: residue steering relocates the multinomial, does not flatten it

The §6 residue mechanism is a *different hash* (1 field: low-3-bits of src-port)
substituted for the NIC's *4-field Toeplitz*. For any workload whose clients use
**ephemeral src-ports** (iperf3 default; every production client), the residues
are an effectively-random draw — the **same multinomial collision** as RSS, just
keyed differently. Monte-Carlo (200k trials, N=6 flows):

```
P(6 flows all distinct residues, B=8 classes)   = 0.077   (only 7.7%)
Mean bucket-count CoV (src_port mod 8, 6 flows)  = 1.05
Mean bucket-count CoV (RSS uniform into 6)       = 0.87    <- residue is WORSE
```

Residue steering is *worse* than default RSS here: 8 residue classes for 6
queues wastes 2 classes (residues 6,7 fall through to default RSS), and a
single weak field hashes worse than 4-field Toeplitz. **It does not beat the
floor — it can move below it.** AGY's independent round-1 computation
(P=6!/6^6 ≈ 1.54% perfect spread for the exact-hash variant) reaches the same
multinomial conclusion: no *static* hash flattens N≤M for arbitrary src-ports.

The residue mechanism beats the floor ONLY when the **generator deliberately
assigns distinct residues** (e.g. `iperf3 --cport` stepping by 1 across 6
streams). That is exactly the Phase-0 "deterministic per-port-mod → 3.8% CoV"
result: a **controlled-test-harness artifact**, not a property of real traffic.
Production clients never coordinate src-port residues with the firewall's queue
count. So for the realistic flow mix the mechanism cannot beat the floor.

### 7.1 Secondary nails (not load-bearing, but corroborating)

- **#1203 prior art:** the reactive closed-loop form already measured 49-55% at
  P=12, closed with "per-flow CoV is bounded by within-queue scheduling, not
  placement" — confirming placement-only can't fix N>M.
- **Capacity:** 1024 rules (measured) = mlx5 driver `MLX5E_ETHTOOL_FLOW_SPEC_NUM`
  (AGY-verified), not the 32k #1203 assumed. Residue steering needs only 6-8
  rules, so capacity is NOT the binding constraint for residue (it is for an
  exact-5-tuple controller, which §5 already kills).
- **Per-rule cost (DEMOTED per round-1):** ~1 ms-class firmware-synchronous
  command per ethtool insert. Fatal for an exact-5-tuple-per-flow controller at
  real conn rates; **irrelevant for the residue mechanism** (6 static rules at
  boot). Not load-bearing for the kill — the multinomial math is.
- **HA failover:** the 6 residue rules must re-arm on the new primary's NIC
  (empty at takeover). Cheap (6 rules) but pointless given §7.0.
- **mlx5 vs i40e:** moot — the loss-cluster dataplane is mlx5 on both nodes
  (verified ge-0-0-1/2 on fw0, ge-7-0-1/2 on fw1); CLAUDE.md's "i40e PF
  passthrough" is stale doc-drift for this cluster.

## 8. Recommendation — PLAN-KILL

The #937-named hardware prerequisite (exact-5-tuple→queue steering) **exists**
on the deployed mlx5 NIC, and so does a genuinely **non-reactive, non-re-steer**
mechanism — masked src-port-residue rules (§6). These are the new facts this
research contributes. The kill stands anyway, on the multinomial math:

1. **The non-reactive residue mechanism does not beat the floor for realistic
   traffic** (§7.0) — for client-assigned ephemeral src-ports it is the same
   (or worse) multinomial draw as RSS (CoV 1.05 vs RSS 0.87 at N=6). It beats
   the floor only when the *generator* coordinates src-port residues with the
   queue count, which is a controlled-harness artifact (the Phase-0 3.8%), not a
   production-traffic property.
2. **Reactive exact-5-tuple placement is structurally a re-steer** (§5) — the
   SYN is RSS-placed before any exact rule can exist, so every correction moves
   an established flow (the forbidden killed pattern). aRFS, dynamic RSS-context
   reweighting, and tc-flower wildcard all reduce to this or to the static hash
   of point 1 (round-1 reviewers confirmed; no falsifying primitive found).
3. **#1203 already built + measured the reactive closed-loop form on this
   cluster** (49-55% CoV at P=12), closed with "per-flow CoV is bounded by
   within-queue scheduling, not placement" for N>M.

No initial-placement-only mechanism beats the floor for the realistic flow mix.
**PLAN-KILL.**

## 9. PLAN-KILL deliverable — document the floor curve

On kill, add to `docs/fairness-regimes.md`:

- A **CoV-vs-flow-count floor curve** for the N-into-M=6 multinomial: expected
  per-flow CoV as a function of N (the 6-flow ~17% observation is one point on
  it; include the closed-form multinomial CoV for N=2..24 at M=6) so the
  bimodal unevenness is documented as expected, not a bug.
- A new **"Why HW ntuple steering does not help"** subsection citing: (a) this
  research's capability findings (mlx5 supports exact AND masked steering,
  cap 1024 = `MLX5E_ETHTOOL_FLOW_SPEC_NUM`, ~1 ms-class firmware/rule);
  (b) the **multinomial result** — masked src-port-residue is a static hash on
  the same (or worse) floor for ephemeral ports (CoV 1.05 vs RSS 0.87 at N=6),
  beating the floor only with generator-coordinated src-ports (harness
  artifact); (c) the §5 reactive-exact-5-tuple-is-a-re-steer argument;
  (d) the #1203 empirical 49-55% result and its within-queue-scheduling verdict.
  Pre-empt the "couldn't we just steer by port?" question explicitly.
- Cross-link #1649, #1203/#789, #840, #937 so the next person who sees the
  bimodal iperf output finds the closed rationale immediately.

## 10. Multiple-path options considered (all rejected)

| Path | Verdict |
|------|---------|
| Reactive per-5-tuple ntuple at first SYN | KILL — §5, it is a re-steer |
| Proactive per-5-tuple ntuple | Impossible — future ports unknowable |
| **Masked src-port-residue ntuple (non-reactive, non-re-steer)** | **Real mechanism (verified on NIC), but a static 1-field hash: same/worse multinomial as RSS for ephemeral ports (CoV 1.05 vs 0.87 at N=6); beats floor only with generator-coordinated src-ports = harness artifact (§7.0). KILL.** |
| RSS-context + dst-port wildcard into context | Same as residue — static hash inside the context, same multinomial floor; dynamic reweight re-hashes active flows = re-steer |
| dst-port / subnet pre-partition (non-re-steer) | No win for same-dst-port symptom |
| Symmetric Toeplitz RSS key | Helps RX/TX same-queue symmetry, NOT N-into-M collision; current key already `symmetric-or-xor`. Refuted as a fix for the symptom. |
| RSS indirection-table reshape (#840) | Already reverted, net-negative on fairness |
| Document the floor (PLAN-KILL) | RECOMMENDED |

## 11. Round-1 reviewer resolution

1. **Codex (PLAN-NEEDS-WORK):** correctly found that r1 §6's "no non-re-steer
   mechanism exists" was false — masked src-port-residue is a valid non-reactive
   classifier. RESOLVED: §6 rewritten to acknowledge + verify the mechanism;
   §7.0 added showing it does not beat the floor for ephemeral ports
   (multinomial CoV 1.05 vs 0.87). The kill spine moved from "no mechanism" to
   "the mechanism is on the same/worse floor."
2. **AGY (PLAN-READY):** independently verified the KILL — §5 airtight (no
   wildcard-pre-commit primitive: aRFS/RSS-context/tc-flower all reactive or
   static-hash), N≤M unreachable by static hash (1.54% perfect spread), all
   empirical claims verified (1024 = `MLX5E_ETHTOOL_FLOW_SPEC_NUM`, ~1 ms
   firmware, queue-bound `xsk_rcv_check`). No salvage.
3. **Claude SMR (PLAN-NEEDS-WORK → resolved):** agreed the KILL is correct but
   flagged §6 false + the 1.1 ms cost as non-load-bearing; both addressed in r2.

**Convergence:** all three agree the verdict is PLAN-KILL. The only round-1
divergence was rationale (mechanism existence), now corrected. No mechanism
beats the floor for the realistic (ephemeral-port) flow mix without a re-steer.
