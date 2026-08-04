# AGY hostile plan review — #6751 (round 30)

# Adversarial Plan Review: Issue #6751 (v15.17, Round 30)

**Verdict:** `PLAN-NEEDS-REVISION`

Reviewed `docs/research/6751-nopat-admission/plan.md` at v15.17 (commit `d421d5d2e`). While v15.17 successfully folds many of Codex's r29 findings, an adversarial re-attack reveals **1 BLOCKER**, **3 MAJORs**, and **4 MINORs** across the newly added mechanisms (incarnation-conditional close funnel, carry-forward window, cross-worker sharding, and static NAT occupancy).

---

## Summary of Findings

| # | Severity | Category | Summary |
|---|---|---|---|
| 1 | **BLOCKER** | Close Funnel | 4th outbound close producer missed in [`tunnel_purge.rs:47`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs#L47). |
| 2 | **MAJOR** | Mirror Failure | Failed mirror delete resurrects zombie session on peer via bulk sync and #2442 re-export. |
| 3 | **MAJOR** | Incarnation Check | Worker-shard locality of `SessionTable` deletes live replacement sessions under flow migration. |
| 4 | **MAJOR** | Carry-Forward | Carry-forward log invalidation on mid-bulk abort causes false session deletions at `BulkEnd`. |
| 5 | **MINOR** | Index Cardinality | Incremental index cap (4096) overflow degrades to 5s traffic misdelivery via synthesized companions. |
| 6 | **MINOR** | Carry-Forward | Unbounded cardinality on the received-set carry-forward accumulator between bulks. |
| 7 | **MINOR** | Metrics | Missing metric taxonomy for static NAT occupancy conflict drops in §5.8. |
| 8 | **MINOR** | Static NAT | Mapped-port static NAT is missing explicit occupancy registration, risking PAT collisions. |

---

## Detailed Analysis

### 1. BLOCKER — Missed 4th Outbound Close Producer in `tunnel_purge.rs`

- **File & Line:** [`userspace-dp/src/afxdp/ha/tunnel_purge.rs:47-103`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs#L47-L103), [`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:379`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs#L379), [`plan.md:L8`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L8), [`plan.md:L1148-1158`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1148-L1158)
- **Impact:** Complete failure of the producer-ordering invariant for tunnel-remapped sessions.
- **Description:** [`plan.md:L8`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L8) and [`plan.md:L1148-1158`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1148-L1158) claim that a 3-producer funnel (expiry in [`session_delta.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs), terminal teardown in [`session_glue/mod.rs:546`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs#L546), and policy invalidation in [`daemon_policy_invalidate.go:357`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_policy_invalidate.go#L357)) covers *every* outbound close producer.
  
  However, [`purge_remapped_tunnel_sessions`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs#L47) in `tunnel_purge.rs` is a **4th outbound close producer**. When a tunnel endpoint rebinds or changes config, `purge_remapped_tunnel_sessions` constructs `SessionDeltaKind::Close` deltas and emits them directly to the `event_stream` via `push_purge_close_deltas` (which feeds Go's `QueueDeleteV4`/`V6`). `tunnel_purge.rs` deletes `shared_sessions` entries on `SessionManager` without going through the incarnation-checked BPF mirror deletion or worker table check required by rule (R1)/(R2). Thus, `mirror presence` does NOT imply no close was published.

---

### 2. MAJOR — Persistent Delete Failure Resurrects Zombie Sessions via Bulk Sync and #2442 Re-Export

- **File & Line:** [`plan.md:L1137-1145`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1137-L1145), [`plan.md:L1191-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1191-L1196), [`plan.md:L1269-1285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1269-L1285)
- **Impact:** Catastrophic session resurrection on the standby node when BPF map deletes fail.
- **Description:** When a mirror delete fails after retries, [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1137) still publishes the Close (tombstone generation `G_close`) and latches out-of-sync to drive a #2442 full re-export. When Go consumes the Close, `takeDeleteGenV4(K)` removes `K` from `genSentV4`. 
  
  When the #2442 re-export (or a routine bulk sync) runs, the bulk callback re-reads the BPF mirror. Because the mirror delete failed, the BPF mirror still contains `K = V_old`. Because `K` is now missing from `genSentV4`, rule (V2) ([`plan.md:L1191`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1191)) mints a **fresh generation `G_bulk > G_close`** for `V_old` and publishes `V_old` in the bulk sync. The standby receives `G_bulk > G_close`, accepts `V_old`, and **resurrects the closed session**. Rather than recovering from a unwritable mirror, the out-of-sync latch and #2442 re-export actively re-synchronize zombie sessions.

---

### 3. MAJOR — Worker-Shard Locality of `SessionTable` Strips Live Replacements Under Flow Migration

- **File & Line:** [`userspace-dp/src/afxdp/worker/loop_body/mod.rs:958`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L958), [`userspace-dp/src/afxdp/session_delta.rs:406`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs#L406), [`plan.md:L1130-1136`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1130-L1136)
- **Impact:** Live replacement sessions stripped from BPF forwarding maps across RSS steering/worker rebalance.
- **Description:** Rule (R1) checks the authoritative `SessionTable` to ensure a same-key replacement does not exist before deleting from the BPF mirror. `SessionTable` instances are worker-thread local, while BPF maps (`session_map_fd`, `conntrack_v4_fd`) are shared across all worker threads.
  
  If RSS rebalancing, interface migration, or multi-worker steering causes a replacement session `K'` to be installed on Worker 1 while Worker 0 has an expiring Close delta for `K`: Worker 0 checks only Worker 0's local `SessionTable`, finds no entry, and issues `bpf_map_delete_elem` against the shared BPF mirror. This deletes Worker 1's **live replacement session `K'`** from the BPF forwarding table.

---

### 4. MAJOR — Carry-Forward Accumulator Invalidation on Mid-Bulk Abort Causes False Session Deletions

- **File & Line:** [`plan.md:L1170-1182`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1170-L1174), [`plan.md:L828-837`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L828-L837), [`pkg/cluster/sync.go:1080`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go#L1080)
- **Impact:** Valid live sessions deleted by `reconcileStaleSessions` when a bulk aborts mid-stream.
- **Description:** [`plan.md:L1171`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1171) states that at `BulkStart` the receiver seeds the new received set with keys installed by deltas since the last completed `BulkEnd`.
  
  Consider this sequence:
  1. `BulkEnd 1` completes. Delta `D1` is installed and logged in the carry-forward set `{D1}`.
  2. `BulkStart 2` arrives. The carry-forward accumulator is consumed into `bulkRecv2` and reset for Bulk 2.
  3. Bulk 2 encounters an abort (e.g. deadline timeout, quarantine overflow, or disconnect) before `BulkEnd 2`.
  4. Per [`plan.md:L828`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L828), Bulk 2's provisional installs stand until the next completed bulk. `D1` remains live in `sessions`.
  5. `BulkStart 3` arrives. If the carry-forward accumulator only tracked deltas installed *during* Bulk 2, `D1` is absent from Bulk 3's carry-forward set.
  6. Bulk 3 completes (`BulkEnd 3`). `reconcileStaleSessions` sees `D1` in `sessions`, but `D1` is not in Bulk 3's snapshot and not in Bulk 3's carry-forward set.
  7. `reconcileStaleSessions` **erroneously deletes live session `D1`**.

  *Correction required:* The carry-forward accumulator must be retained across aborted bulk attempts and cleared only upon a successfully completed `BulkEnd`.

---

### 5. MINOR — Incremental Index Cap (4096) Overflow Degrades to 5s Traffic Misdelivery

- **File & Line:** [`plan.md:L1545-1550`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1545-L1550), [`plan.md:L1563-1577`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1563-L1577), [`userspace-dp/src/afxdp/shared_ops.rs:750`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L750)
- **Impact:** Misdelivery of return traffic for excess fabric SNAT flows during high delta bursts.
- **Description:** Under a high-rate burst of incremental fabric SNAT deltas (>4096 flows between bulks), the incremental base-identity index cap (4096) rejects further entries. Excess alias frames fail confirmation and fall back to the 5s timeout-admission path, installing explicit alias rows into `SessionSync.sessions`. This synthesizes broken reverse companions (un-NATing return traffic to the firewall's egress IP instead of the client) for 5 seconds until the next bulk sync or timeout.

---

### 6. MINOR — Unbounded Cardinality of the Received-Set Carry-Forward Accumulator

- **File & Line:** [`plan.md:L1170-1182`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1170-L1182)
- **Impact:** Unbounded memory growth in Go under long periods or high delta churn between bulks.
- **Description:** Unlike the quarantine map (capped at 4096) and incremental index (capped at 4096), the received-set carry-forward accumulator has no numeric upper bound specified in §5.6. Under sustained high delta churn between bulks, the tracking set grows without bound.

---

### 7. MINOR — Missing Metric Taxonomy for Static NAT Occupancy Conflict Drops

- **File & Line:** [`plan.md:L1739-1743`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1739-L1743), [`plan.md:L1777-1828`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1777-L1828)
- **Impact:** Uncounted or mis-attributed static NAT drops.
- **Description:** When a static NAT flow fails closed because its occupancy `(E_static, original_port, effective_dst)` is held in the registry, §5.8 defines no counter for static NAT drops (`xpf_userspace_interface_snat_identity_exhaustion_total` explicitly counts interface-SNAT probe exhaustion, port-less collisions, and drain-quarantine rejections). Static NAT conflict drops are either uncounted or misattributed to interface-SNAT metrics.

---

### 8. MINOR — Mapped-Port Static NAT Missing Explicit Occupancy Registration

- **File & Line:** [`plan.md:L1734-1743`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1734-L1743), [`userspace-dp/src/nat/static_nat.rs:746`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/static_nat.rs#L746)
- **Impact:** Potential PAT collisions between interface SNAT flows and mapped-port static NAT.
- **Description:** §5.7 requires whole-address static NAT to register its translated occupancy `(E_static, original_port, effective_dst)` in the interface registry. However, mapped-port static NAT (which rewrites to a specific `mapped_port`) is not explicitly required to register `(E_static, mapped_port, effective_dst)`. Without this, an interface SNAT flow attempting to preserve or PAT to `mapped_port` on `E_static` will fail to detect the occupancy conflict and take `mapped_port`, creating a wire collision with the static mapped-port flow.

---

## Summary Recommendation

The plan requires a revision to v15.18 addressing:
1. Incorporating `tunnel_purge.rs` into the close producer funnel or ensuring its deletes perform incarnation-safe mirror removal.
2. Preventing rule (V2) fresh-generation minting on un-deleted BPF mirror rows when a delete syscall fails.
3. Making the incarnation check cross-worker aware or checking global table presence before BPF mirror deletes.
4. Retaining the carry-forward log across aborted bulks until a completed `BulkEnd` is received.
