# Research plan — #1649 Per-flow evenness via better INITIAL placement (no mid-flight re-steer)

- **Revision**: r1 (DRAFT — pre first reviewer round)
- **Status**: DRAFT → awaiting Codex + AGY + Claude SMR round 1
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
**RX queue N ⇒ worker N, deterministically.** So an ntuple rule pinning a
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

## 6. Mechanism (if any path survived §5)

The ONLY non-re-steer use of ntuple is **structural pre-partitioning that does
NOT depend on per-flow identity** — e.g. pinning a *destination-port* or
*subnet* class to a queue subset. That is coarse (not per-5-tuple), helps only
when the workload's flows differ in the pinned field, and does NOT address the
N-into-M multinomial collision for flows that share dst-port (the iperf P=6
case has identical dst-port 5210 → all 6 flows hash on src-port only → the very
collision we cannot pre-partition without knowing src-port, which is ephemeral).
No viable per-flow non-re-steer mechanism exists.

## 7. Honest viability (falsify the design)

- **Beats the floor?** Only via re-steer (forbidden) per §5; the one
  non-re-steer lever (port/subnet pre-partition) does not apply to the
  same-dst-port iperf workload that defines the symptom.
- **Even if re-steer were allowed (it is not):** #1203 already measured
  49-55% at P=12 — placement flattening does not beat the floor when N>M,
  because within-queue scheduling dominates. The N≤M 3.8% Phase-0 number is
  real but only reachable by *deterministic pre-assignment* (knowing the port
  map in advance) — not by a reactive controller, which is back to §5's
  re-steer.
- **Capacity:** 1024 rules (measured), not 32k. Past 1024 long-lived flows →
  RSS floor. Acceptable for ≤K elephants, irrelevant given §5/§6.
- **Per-rule cost:** ~1.1 ms firmware + ~4 ms exec. At any real connection rate
  (10K conn/s) this is fatal even before §5; even at the elephant-only rate it
  adds setup latency and a 1 Hz control loop's worth of complexity for no win.
- **HA failover:** ntuple rules are NIC-local; the new primary's NIC starts
  empty. Re-arming per-RG on failover is extra cost + a correctness surface
  (rules referencing evicted sessions), all for a mechanism that does not beat
  the floor.
- **mlx5-VF vs i40e-PF asymmetry:** moot — both the FW dataplane and the #1615
  flooder are mlx5 here; production parity is mlx5; i40e is not in this path.

## 8. Recommendation — PLAN-KILL

The #937-named hardware prerequisite (exact-5-tuple→queue steering) **exists**
on the deployed mlx5 NIC, which is the new fact this research contributes. But:

1. **Reactive flow-setup placement is structurally a re-steer** (§5) — the SYN
   is RSS-placed before any rule can exist, so every correction moves an
   established flow. That is the forbidden killed pattern, not a fresh angle.
2. **#1203 already built + measured the closed-loop form on this cluster**
   (49-55% CoV at P=12) and was closed with the convergent structural verdict
   that **per-flow CoV is bounded by within-queue scheduling, not placement**
   for N>M. #1649's only fresh sub-case (N≤M) is reachable in a hand-experiment
   (3.8%) but ONLY via deterministic pre-assignment, which a reactive controller
   cannot do without re-steering.
3. **Capacity (1024, not 32k) and cost (~1.1 ms/rule)** further bound it to a
   narrow long-lived-elephant case that does not match the same-dst-port iperf
   symptom.

There is no initial-placement-only mechanism that beats the floor for the
realistic flow mix without re-steering. **PLAN-KILL.**

## 9. PLAN-KILL deliverable — document the floor curve

On kill, add to `docs/fairness-regimes.md`:

- A **CoV-vs-flow-count floor curve** for the N-into-M=6 multinomial: expected
  per-flow CoV as a function of N (the 6-flow ~17% observation is one point on
  it; include the closed-form multinomial CoV for N=2..24 at M=6) so the
  bimodal unevenness is documented as expected, not a bug.
- A new **"Why HW ntuple steering does not help"** subsection citing: (a) this
  research's capability findings (mlx5 supports it, cap 1024, ~1.1 ms/rule);
  (b) the §5 reactive-is-a-re-steer argument; (c) the #1203 empirical
  49-55% result and its within-queue-scheduling verdict.
- Cross-link #1649, #1203/#789, #840, #937 so the next person who sees the
  bimodal iperf output finds the closed rationale immediately.

## 10. Multiple-path options considered (all rejected)

| Path | Verdict |
|------|---------|
| Reactive per-5-tuple ntuple at first SYN | KILL — §5, it is a re-steer |
| Proactive per-5-tuple ntuple | Impossible — future ports unknowable |
| dst-port / subnet pre-partition (non-re-steer) | No win for same-dst-port symptom (§6) |
| Symmetric Toeplitz RSS key | Helps RX/TX same-queue symmetry, NOT N-into-M collision; current key already `symmetric-or-xor`. Refuted as a fix for the symptom. |
| RSS indirection-table reshape (#840) | Already reverted, net-negative on fairness |
| Document the floor (PLAN-KILL) | RECOMMENDED |

## 11. Open questions for reviewers

1. Is the §5 "reactive = re-steer" argument airtight, or is there an
   ethtool/devlink/TC primitive that pre-commits a queue for a *wildcard*
   src-port accept that I missed?
2. Does the N≤M sub-case deserve a *non-reactive* treatment (e.g. operator
   hand-pinned rules for known long-lived flows) shipped as an explicit
   opt-in tool rather than an automatic controller — or is even that a
   re-tread of #1203's CLI knob that was withdrawn?
3. Is 1024-rule capacity firmware-bumpable (newer mlx5 FW) in a way that
   changes the calculus? (Believed no — the defect is §5, not capacity.)
