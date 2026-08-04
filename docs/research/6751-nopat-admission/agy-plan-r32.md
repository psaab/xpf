# AGY hostile plan review — #6751 (round 32)

# Adversarial PLAN Review: Issue #6751 (Research Round 32)

**Repo (worktree):** `/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission`  
**Plan doc:** [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) — **v15.19** (`0dd57f613`)  
**Verdict:** **`PLAN-READY-WITH-NITS`**

---

## Executive Summary

Document v15.19 comprehensively folds Codex Round 31's ten findings (7 BLOCKERs, 2 MAJORs, 1 MINOR). The crux mechanism introduced in v15.19—**incarnation-gated close suppression** atomic under a striped per-key producer mutex—successfully eliminates the TOCTOU delete-after-publish race and the fatal inverse tombstone hazard without introducing un-bounded failure windows or memory leaks.

No **BLOCKER** or **MAJOR** defects survive this adversarial attack. All core invariants (generation trace, epoch barrier, quarantine, episode latch, readiness double-gate, debt machinery, and uniform mint quarantine) remain intact.

---

## Detailed Attack & Verification Analysis

### 1. Incarnation-Gated Close Suppression (The Crux)

* **(a) Dropped `Open` Delta for Replacement `S_new` (Queue-Full Race):**
  * *Scenario:* `S_old` exists on peer. `S_new` is admitted locally, but its `Open` delta is dropped due to a full queue (`sendCh`). `S_old`'s close runs locally and observes `S_new`'s newer incarnation ID (`#5213` id), suppressing `S_old`'s close entirely (no delete, no publish, no generation draw).
  * *Peer State Walk:* Peer retains `S_old`. However, dropping an `Open` delta arms `syncBackfillNeeded`, which immediately resets and wakes the backfill sweep timer ([`plan.md:749-754`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L749-L754), [`plan.md:1170-1350`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1170-L1350)). The sweep reads `S_new` from the mirror/session table and re-sends `S_new`. When `S_new` arrives (via sweep or authoritative bulk), its strictly greater generation (`G_new > G_old`) overwrites `S_old` on the peer.
  * *Verdict:* **Bounded.** The window is strictly bounded by the woken sweep cycle.

* **(b) Reverse-Companion Residual:**
  * *Scenario:* When `S_old`'s forward close is suppressed, no delete frame is transmitted for `S_old`'s forward key. `S_old`'s reverse companion on the peer (which carries a separate reverse key) is not explicitly deleted by a close frame.
  * *Verdict:* **Adopted as Documented.** The peer's reverse companion for `S_old` ages out at standard session timeout or is cleared during bulk reconciliation. This is identical to standard shipped pool-mode reverse-companion behavior.

* **(c) Stripe Coverage Completeness:**
  * *Coverage Requirement:* The striped per-key producer mutex must cover all same-key mirror operations ([`plan.md:1189-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1189-L1196)):
    1. Direct BPF conntrack publish ([`publish_conntrack.rs:141`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs#L141))
    2. Session-map publish/delete ([`bpf_map/mod.rs:600-720`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs#L600-L720))
    3. Redirect and forward/reverse wire entry updates
    4. `last_seen` and `policy_id` refresh writers ([`bpf_map/mod.rs:364/438`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs#L364-L438))
  * *Verdict:* The text explicitly mandates coverage across all mirror writers. Implementation must ensure `update_session_last_seen` and `update_session_policy_id` take the per-key stripe lock to prevent stale value overwrites.

* **(d) Stripe Cost Model under Session Churn Storm:**
  * *Scenario:* 100k creates/deletes per second across worker threads.
  * *Evaluation:* Stripe locks are acquired only at session create/delete (not per packet). Each lock acquisition wraps an $O(1)$ memory/BPF map check (a few nanoseconds). Hash-striping over 1024 or 4096 mutex buckets renders inter-key lock contention negligible.

---

### 2. Omission Index + Table-Truth Overflow

* **(a) Omission Index Cardinality under Delete-Failure Storm:**
  * *Scenario:* A corrupted or full BPF map causes every `bpf_map_delete_elem` to fail.
  * *Walk:* Failed deletes are recorded into the 4096-entry omission index. Upon reaching capacity (4097th failure), the omission index **overflows**.
  * *Behavior:* At overflow, recovery stops trusting the dirty mirror and forces an authoritative **TABLE-TRUTH export** (`ExportOwnerRGSessions`) ([`plan.md:1222-1227`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1222-L1227)). The Rust `SessionTable` contains only live sessions; closed sessions are absent.
  * *Verdict:* **Sound.** No unbounded memory growth occurs; the 4096 index is fixed-cap, and overflow transitions to table-truth export mode.

* **(b) Table-Truth Export vs. Received-Set Reconcile Semantics:**
  * *Evaluation:* The table-truth bulk exports standard `SyncedSessionEntry` frames bounded by `BulkStart` and `BulkEnd`. The peer records received keys into `bulkRecvV4/V6` identically to a mirror bulk.
  * *Reconcile Result:* Keys absent from the authoritative `SessionTable` (including the zombie keys from failed deletes) are absent from the received set. Reconcile on the peer deletes all un-received keys, cleaning up peer zombies cleanly.

---

### 3. Fenced Inbound Re-Prime + Reconciliation Hold

* **(a) Hold Lifetime vs. Aborted Re-Prime:**
  * *Scenario:* Carry-forward overflow forces a fenced reconnect, triggering an inbound cold-prime and establishing a reconciliation hold on carried keys ([`plan.md:1308-1320`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1308-L1320)).
  * *Evaluation:* If the inbound re-prime aborts mid-bulk, `BulkEnd` is not received. The reconciliation hold remains active until a subsequent re-prime attempt completes with `BulkEnd` (or the cluster comms connection tears down). This prevents premature reconcile-deletion of live carried sessions during transient bulk aborts.

* **(b) Second Overflow During Active Hold:**
  * *Evaluation:* If a second overflow occurs before `BulkEnd` completes, the newly carried keys are merged into the hold set, extending hold protection until the replacement re-prime's `BulkEnd` completes.

* **(c) Blast Radius of Forced Reconnect:**
  * *Evaluation:* The forced reconnect resets the `pkg/cluster` TCP session sync connection. Dataplane packet forwarding (AF_XDP/BPF) continues uninterrupted without packet loss.

---

### 4. Honest Signature Inventory & InterfaceOwnerKey Split

* **Signature Inventory Alignment (§4 vs §5.2 vs §5.3 vs §6):**
  * [`plan.md:200-208`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L200-L208) and [`plan.md:415`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L415) maintain a strict type separation:
    * `InterfaceOwnerKey`: Original destination identity (`src_ip, src_port, orig_dst_ip, orig_dst_port`). Used for owner flow identity, idempotence, and staged replacements.
    * `SourceNatFlowKey`: Pool domain key with effective destination (`eff_dst_ip, eff_dst_port`).
  * The release/rollback closure captures both the owner key and the occupancy tuple explicitly at the decision point ([`plan.md:213-217`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L213-L217)), resolving Codex Round 31 Finding 4 where `nat_match_flow` alone was insufficient.
  * Internal function argument budgets in §6 ([`plan.md:2080-2090`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2080-L2090)) accurately inventory the `+3` parameters (registry, worker ID, effective destination) across decision and release paths.

---

### 5. Static Emitted-Port, Inbound Acquisition, Purge, Old-Sender Cell, and Edge Tests

1. **Static Emitted-Port:** Mapped-port static mappings reserve the emitted external source port (`rewrite_src_port`, e.g., `8080->80` reserves `E:8080`), fixing Codex r31 Finding 5 ([`plan.md:1926-1935`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1926-L1935)).
2. **Inbound Acquisition:** Static occupancy is acquired at all decision points including inbound static DNAT ([`poll_descriptor/mod.rs:1018`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1018), [`plan.md:1936-1941`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1936-L1941)).
3. **Drain-on-Removal:** Static holders enter `DRAINING` upon config removal ([`plan.md:1949-1956`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1949-L1956)); existing static flows retain identity until close, while new interface mints quarantine.
4. **Serialized-Loop Purge:** P2 exact-publication purge runs on the receiver's single-threaded event loop ([`sync_conn_gen.go:381`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L381)) with store-mutex acquired before BPF deletion ([`plan.md:1722-1736`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1722-L1736)).
5. **Honest Old-Sender Cell:** The mixed-version matrix cell acknowledges that old-sender aliases in the lost-base case expire with session lifetime ([`plan.md:1805-1816`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1805-L1816)).
6. **Scoped Producer Claim:** Outbound delete producers in userspace mode total four, with kernel conntrack GC disabled ([`daemon_run.go:230`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_run.go#L230), [`plan.md:1248-1254`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1248-L1254)).
7. **Standby Edge Tests:** Pinned tests cover the 257th synchronized import and imports during domain drain ([`plan.md:2358-2364`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2358-L2364)).

---

### 6. Full-Plan Re-Attack

* **Generation Trace (G0/G1):** Critical section under `genSentMu` covers generation draw, epoch capture, and map record uniformly for all producers ([`plan.md:776-788`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L776-L788)).
* **Barrier:** Cold-prime bulk sync executes epoch barrier drain before emitting frames.
* **Quarantine & Reconcile:** Decode-time base identity index and per-bulk/superseding resolution operate without loss.
* **Episode Latch & Debt:** Monotonic `debtGen` persists in `Daemon`, discharges only on matching `BulkEnd-ACK`, and survives `SessionSync` rebuilds ([`plan.md:800-835`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L800-L835)).
* **Uniform Mint Quarantine:** Skips quarantined addresses across all allocation modes ([`plan.md:1900-1925`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1900-L1925)).

---

## Numbered Findings (Nits)

1. **NIT 1 (Implementation Guidance — Stripe Mutex Bucket Count):**
   * *Location:* [`plan.md:1189`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1189)
   * *Detail:* The plan specifies a "striped per-key producer mutex" without naming a fixed stripe array size. For optimal lock distribution under heavy session churn (100k+ ops/sec), `N_STRIPES` should be configured to at least 1024 (e.g., `1024` or `4096` `Mutex<()>` entries indexed by key hash).

2. **NIT 2 (Test Plan — Reverse Companion Expiry Verification):**
   * *Location:* [`plan.md:1198`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1198)
   * *Detail:* When a stale close is suppressed, the peer's reverse companion for `S_old` lingers until session timeout. The test suite in §9 should explicitly include a test verifying that `S_new`'s reverse traffic resolves correctly even while `S_old`'s stale reverse companion is in the process of timing out on the peer.
