# AGY hostile plan review — #6751 (round 31)

# Adversarial Plan Review: Issue #6751 (v15.18, Round 31 Convergence Adjudication)

**Verdict:** `PLAN-READY-WITH-NITS`

Reviewed `docs/research/6751-nopat-admission/plan.md` at **v15.18** (commit [`d3f1152b2`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3-L27)). Plan v15.18 successfully folds all findings from Round 30 (AGY r30 findings 1–8 and Codex r30 findings 1–7). 

All 4 BLOCKER/MAJOR findings from AGY r30 and 6 BLOCKERs from Codex r30 are closed, and full re-attack against the foundational pillars confirms zero regressions in core invariants.

---

## 1. Verification of AGY Round 30 Findings

### 1.1 BLOCKER — Missed 4th Outbound Close Producer (`tunnel_purge.rs:47-103`)
- **Status:** **CLOSED**
- **Verification:**
  - **(a) Delete-before-publish execution ordering:** In [`userspace-dp/src/afxdp/ha/tunnel_purge.rs:77-103`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/tunnel_purge.rs#L77-L103), `purge_remapped_tunnel_sessions` invokes `delete_synced_session(key)` (which deletes the BPF mirror entry under rule (R1)) in lines 77–79 **BEFORE** pushing Close deltas to the event stream via `push_purge_close_deltas` at line 102. The producer's own execution flow strictly satisfies compare-and-delete before publish.
  - **(b) Untracked gen-0 residual:** For untracked keys (keys with no sender record in `genSentV4`), no tracked replacement session exists. Furthermore, under the `#2170` generation guard, `gen-0` is the lowest-ranked unordered class: any live replacement `K'` carrying a stamped generation `G_new >= 1` outranks `gen-0` and cannot be overwritten by a `gen-0` delete.

### 1.2 MAJOR 2 — Persistent Delete Failure & Zombie Resurrection
- **Status:** **CLOSED**
- **Verification:**
  - **(a) Omission of surviving mirror rows:** Rule (R1) ([`plan.md:L1194-1202`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1194-L1202)) retains sender delete tombstones `(K -> G_close)` in `genSentV4`/`genSentV6` upon Close publication. When routine bulk sync reads a surviving mirror row `K=V_old` following a failed delete syscall, rule (V3)/(V4) sees the active delete tombstone and **OMITS** `K` from the bulk frame. The peer does not receive `V_old` with a minted `G_bulk > G_close`, preventing zombie session resurrection.
  - **(b) Tombstone cardinality:** Sender-side tombstones reside in `genSentV4`/`genSentV6`, which are bounded by the 200,000-key capacity limit (`sync_conn_gen.go:23/45`). Capacity overflow triggers `forceResync`, re-anchoring state authoritatively.
  - **(c) Tombstone clearing vs. staged-replacement overlap:** When a replacement session `T_new` (`session_id = ID_new`) installs at key `K`, it stamps `G_new > G_close` and replaces the tombstone in `genSentV4`. If `T_old`'s delayed compare-and-delete executes against `K`, the compare-and-delete fails because stored `session_id == ID_new != ID_old`. On both sender and receiver generation maps, `G_new > G_close` ensures `T_new` outranks `T_old` regardless of message arrival ordering.

### 1.3 MAJOR 3 — Worker-Shard Locality under Flow Migration
- **Status:** **CLOSED**
- **Verification:**
  - **(a) `session_id` stamping:** [`bpf_map/mod.rs:260-265`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs#L260-L265) and [`publish_conntrack.rs:113`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs#L113) stamp the stable `#5213` `session_id` into `BpfSessionValueV4` / `BpfSessionValueV6` for all forward, reverse, and redirect conntrack entries at publish.
  - **(b) Legacy zero-id rows:** A pre-`#5213` row with stored `session_id = 0` will fail compare-and-delete against a closing session with `session_id > 0`. The close is still published to Go with tombstone `G_close`, and the sender tombstone suppresses re-minting during bulk syncs. The legacy mirror row survives locally until reaped by idle GC or helper restart.
  - **(c) Non-`session_id` maps:** `session_map_fd` (kernel-XDP fast path) carries a single byte (`u8`) without `session_id` and is deleted key-wise. Because `session_map_fd` is an internal XDP routing table that is never read by Go's `SessionSync` or transmitted across HA, its lack of `session_id` cannot cause peer zombie resurrection or HA desynchronization.

### 1.4 MAJOR 4 — Carry-Forward Abort Invalidation
- **Status:** **CLOSED**
- **Verification:**
  - **`BulkEnd1 → D1 → BulkStart2 → abort → BulkStart3 → BulkEnd3` Trace:** At `BulkStart2`, `bulkRecv2` is seeded with carry-forward accumulator `CF = {D1}`, but `CF` is retained across aborts ([`plan.md:L1256-1266`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1256-L1266)). When Bulk 2 aborts, `CF` remains `{D1}`. `BulkStart3` seeds `bulkRecv3` with `{D1}`. At `BulkEnd3`, `reconcileStaleSessions` matches `D1` against `bulkRecv3` and preserves `D1`. `CF` clears only upon successful `BulkEnd3`.
  - **Disconnect-clear interaction:** When all fabrics disconnect (`pkg/cluster/sync_conn.go:554`), peer communication halts and a mandatory cold-prime bulk is armed upon reconnect. Clearing `CF` on all-fabrics disconnect / cold-prime arming prevents pre-disconnect stale entries from polluting the new cold-prime snapshot.

---

## 2. Verification of MINOR Findings (AGY r30 findings 5–8)

- **MINOR 5 (Index Overflow Deferral):** Incremental index overflow (capped at 4096) defers excess alias entries to the next completed `BulkEnd` resolution ([`plan.md:L1638-1648`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1638-L1648)). The wait is bounded by the periodic bulk sync interval (default ~5s). During deferral, the base session forwards normally without disruption; only the fabric-redirect shortcut is temporarily bypassed.
- **MINOR 6 (Carry-Forward Capping):** `CF` cardinality is capped at 200,000 entries (matching generation maps). Overflow arms `forceResync` and clears `CF`, re-anchoring authoritatively.
- **MINOR 7 (Static Conflict Metric):** Static NAT conflict drops carry a dedicated counter `xpf_userspace_static_nat_occupancy_conflict_drops_total` ([`plan.md:L1911-1913`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1911-L1913)), bringing the metric count to 5 helper + 3 Go = 8 total.
- **MINOR 8 (Mapped-Port Static Registration):** Mapped-port static NAT registers `(E_static, mapped_port, effective_dst)` in the interface registry ([`plan.md:L1853-1856`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1853-L1856)).

---

## 3. Adjudication of Codex Round 30 Folds

1. **Import-Driven Standby Allocator Creation:** `reserve_synced` creates allocators import-driven when passive standbys process peer interface-SNAT rows ([`plan.md:L374-383`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L374-L383)), preventing post-failover identity preservation collisions.
2. **`InterfaceOwnerKey` vs. `SourceNatFlowKey` Domain Separation:** Owner keys for interface SNAT retain original destination `(dst_ip, dst_port)`, while pool `SourceNatFlowKey` retains effective destination ([`plan.md:L410-415`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L410-L415)).
3. **Provisional Admitted Aliases & Exact-Publication Purge:** Timeout-admitted aliases are re-evaluated and purged at `BulkEnd` (rule P1) using exact-publication compare-and-delete (`session_id` matched, rule P2, [`plan.md:L1658-1673`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1658-L1673)).
4. **`RTFlowSessionID` Preservation Across Re-Bulk:** Sync-side session records carry `RTFlowSessionID` to preserve IDs across HA re-exports ([`plan.md:L1621-1625`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1621-L1625)).
5. **Static Provenance & §9 Test Directions:** Config removal releases static holders, static addresses participate in drain discipline, and §9 test directions match §5.7 norms (static-first -> interface PATs; interface-first -> static fails closed, [`plan.md:L2291-2297`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2291-L2297)).

---

## 4. Full-Plan Re-Attack

A full adversarial audit of v15.18 confirms that none of the core foundational pillars have regressed:
- **Producer-Ordering Invariant (G0/G1 Trace):** Maintained across all four producers (`session_delta.rs`, `session_glue/mod.rs:546`, `daemon_policy_invalidate.go:357`, `tunnel_purge.rs:47-103`).
- **Epoch Barrier & Drain:** Intact ([`plan.md:L1137-1146`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1137-L1146)).
- **Quarantine Order-Agnostic Confirmation:** Intact ([`plan.md:L1620-1650`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1620-L1650)).
- **Episode Latch & Cooldown:** Intact ([`plan.md:L1400-1430`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1400-L1430)).
- **Readiness Double-Gate:** Intact.
- **Uniform Mint Quarantine:** Intact ([`plan.md:L1830-1848`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1830-L1848)).

---

## Numbered Nits

1. **NIT 1 (Legacy zero-id row assertion in §9):**
   - **File & Line:** [`plan.md:L2257`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2257), [`bpf_map/mod.rs:260-265`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs#L260-L265)
   - **Description:** A pre-`#5213` BPF mirror row has `session_id = 0`. During compare-and-delete on close, `0` will never match a closing `session_id > 0`. The legacy row survives locally until idle GC or helper restart, while sender tombstoning prevents peer resurrection. Section 9 should explicitly pin this zero-id non-match behavior in the integration test suite to protect against future refactor regressions.

2. **NIT 2 (Standby 256-allocator cap import surface):**
   - **File & Line:** [`plan.md:L374-383`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L374-L383), [`plan.md:L1924-1929`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1924-L1929)
   - **Description:** If an active node owns >256 distinct egress addresses for interface SNAT, a passive standby receiving bulk sync will hit the 256-allocator cap on `allocator_for` during import-driven creation. The standby will reject excess imports via `xpf_userspace_interface_snat_registry_cap_exhaustion_total` and latch out-of-sync/drive resync. This is an expected operational ceiling that matches the local admission cap posture.

---

## Summary

Plan **v15.18** fully resolves all Round 30 findings and achieves convergence across AGY, Codex, and Claude SMR reviews. No BLOCKER or MAJOR findings survive. The plan is **`PLAN-READY-WITH-NITS`**.
