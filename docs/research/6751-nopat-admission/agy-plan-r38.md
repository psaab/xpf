# AGY hostile plan review — #6751 (round 38)

# AGY Hostile Plan Review — #6751 Plan v15.26 (Round 38 Convergence Adjudication)

**Verdict**: **PLAN-READY-WITH-NITS**

---

### Executive Summary & Convergence Adjudication

Plan document [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) at **v15.26** (commit `917f84481`) has been evaluated following the round-37 fold-check and audit. 

- **Process Failure Audit & Verification**: All three previously silently-failed folds (v15.24 daemon-issued incarnation text, v15.25 Rule 6 normative body text, and v15.25 §9 failure-semantics pins) have been repaired and grep-verified.
- **Substrate & Core Status**: Both design forks remain settled (**PATH A** sole-writer helper in [§4.0.1](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L196-L451); **Option (a)** preserve-first + exact PAT fallback in [§4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L542-L654)). Three independent review channels (AGY, Codex, Claude SMR) have repeatedly confirmed zero kill-shots against the option-(a) core across rounds 34–38.
- **Convergence**: Zero BLOCKER or MAJOR defects survive v15.26. All internal cross-section contradictions have been resolved.

---

### 1. Codex r37 BLOCKER Fold Attack & Verification (Generation-Bound Admission)

**Fold Verification** ([`plan.md#L609-L623`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L609-L623), [`plan.md#L2812-L2823`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2812-L2823)):
Codex r37 BLOCKER 1 identified that closing the listener did not close accepted pre-install TCP children (stalled between `Accept→beginSetup` or `finishSetup→installConn`), allowing unkeyed initiators to install locally and survive quiet-interval expiry. v15.26 generation-binds the whole admission path: children are stamped at `Accept`/dial completion, pre-fence children are killed before the drain clock starts, and stale-stamp children are rejected at every subsequent stage.

**Hostile Attack Analysis**:
- **(a) Child accepted DURING the kill sweep**:
  - *Scenario*: A child socket completes `Accept()` after the kill sweep starts but before listener closure takes full effect.
  - *Adjudication*: Ordering of fence engagement is deterministic: (1) close listener socket, (2) increment fence generation $G \to G+1$, (3) kill pre-fence children (tracked and accepted-untracked carrying generation $G$), (4) start drain clock. Any child accepted prior to step (2) is stamped with generation $G$. If the kill sweep in step (3) misses it because it was in-flight, the child carries stamp $G$. At `beginSetup`, `finishSetup`, or `installConn`, the child's stamp $G$ is compared against the current fence generation $G+1$. Because $G < G+1$, the child is REJECTED as stale. Any connection attempting to accept after step (1) receives `net.ErrClosed`. The stage-independent generation guard prevents stale connection survival regardless of race timing. Sound.
- **(b) Old peer's LOCAL install of its accepted C0 under transport refusal**:
  - *Scenario*: The old peer accepted connection C0 locally prior to Node A's fence and installed C0 in its local slots (`sync_auth.go:329`).
  - *Adjudication*: When Node A fences, it closes C0's socket during teardown, sending TCP FIN/RST. Node A then refuses all incoming TCP connection retries at the transport layer (SYN-level refused) for $T_{\text{quiet}} = 2.5 \times \text{keepalive\_timeout}$ (7.5s). Node B's socket for C0 sees FIN/RST. Node B's retry attempts during $T_{\text{quiet}}$ fail instantly (`ECONNREFUSED`). Node B's disconnect detection bound ($1 \times \text{keepalive\_timeout}$, e.g. 3s) expires without a successful reconnect, forcing Node B to unregister C0 and set `wasDisconnected = true`. When Node A re-opens its listener after $T_{\text{quiet}}$, Node B's next retry succeeds, observes `wasDisconnected == true`, re-arms `needColdPrime`, and streams a complete bulk. Sound.
- **(c) Fence generation namespace vs. helper incarnation namespace**:
  - *Scenario*: Does the cluster-sync fence generation collide with the helper incarnation generation?
  - *Adjudication*: The cluster-sync fence generation is a Go-side `uint64` on `syncConn` / cluster manager (`pkg/cluster/sync_conn.go`). The helper incarnation generation $G_{\text{inc}}$ is a daemon-issued `uint64` tracking Rust DP helper process instances (`pkg/daemon/`). The #2170 generation is a Go-side session-quarantine generation (`pkg/session/`). They exist in distinct Go packages, distinct structs, and distinct namespaces. Zero collision potential. Sound.

---

### 2. Codex r37 MAJOR Fold Attack & Verification (Owed-Prime & Clearance Rules)

**Fold Verification** ([`plan.md#L471-L494`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L471-L494)):
Codex r37 MAJOR 2 demonstrated that the 5-second incremental window was not definitive because a lost-base alias copies the base value exactly, leaving no sibling base present at timeout. v15.26 eliminates 5-second window clearing: `alias-suspect` clears ONLY via the COMPLETE-PRIME definitive pass or row close, and an unresolved suspect owes a complete inbound prime via `prime-REQUEST` bounded by the fence cycle.

**Hostile Attack Analysis**:
- **(a) Owed-prime accounting (many suspects, one prime)**:
  - *Scenario*: Node A admits 5 timeout-admitted suspects ($S_1 \dots S_5$) in `alias-suspect` state.
  - *Adjudication*: Node A sets the `prime-REQUEST` bit on outbound frames. Node B responds by streaming ONE complete inbound prime (full bulk snapshot). Upon `BulkEnd`, Node A executes the complete-prime definitive pass over its entire table store. All 5 suspects ($S_1 \dots S_5$) are evaluated against the complete incoming snapshot in that single pass: rows with matching sibling bases transition to `alias-lineage`; rows without matching sibling bases clear `alias-suspect` and export normally. One prime resolves all outstanding owed suspects atomically. Sound.
- **(b) Genuine row release bound end-to-end**:
  - *Scenario*: A genuine self-NAT/NPTv6 row $R$ is admitted under timeout-admission as `alias-suspect`.
  - *Adjudication Timeline*:
    1. $t=5\text{s}$: Row $R$ admitted, marked `alias-suspect` (export suppressed).
    2. $t \in (5\text{s}, 8\text{s})$: Receiver sets `prime-REQUEST` bit on outbound frame.
    3. $t \in (8\text{s}, 8.5\text{s})$: Sender receives bit and streams complete inbound bulk prime.
    4. $t=8.5\text{s}$: Complete-prime pass runs. No sibling base found for $R$. `alias-suspect` mark CLEARED; $R$ exports normally.
    5. If sender fails to prime within fence cycle $T_{\text{fence}}$, receiver re-fences, starting quiet interval $T_{\text{quiet}}$ followed by an immediate cold prime.
    - *Worst-case bound*: $t_{\text{timeout}} + T_{\text{fence}} + T_{\text{quiet}} + t_{\text{bulk}} \approx 20.5\text{s}$ or session lifetime (the documented residual). Sound.
- **(c) Suspect whose base arrives DURING owed-prime wait**:
  - *Scenario*: A base row $B$ arrives via individual frame while suspect $S$ is waiting for the owed prime.
  - *Adjudication*: Decode-time base-identity index matches $B$ with $S$. Verdict for $S$ transitions immediately: `alias-suspect` $\to$ `alias-lineage` (permanent alias mark). Export remains suppressed. When the complete prime eventually arrives, the pass sees $S$ already marked `alias-lineage` and preserves export suppression. State transition is monotonic and safe. Sound.

---

### 3. Codex r37 MINORs/NITs Verification (Grep-Verified Line Cites)

Each item was verified directly against the `plan.md` v15.26 blob using `grep`:

1. **Stage Carrier Inventory**:
   - `plan.md:2352-2358`: `SessionMetadata` for local rows, additive `SyncedSessionEntry` extension for synced rows (per #1961), worker replication, promotion Open path, and every exporter checked.
   - `plan.md:2801-2804`: `"the suspect mark rides SessionMetadata for local rows and the additive SyncedSessionEntry extension for synced rows, is preserved by worker replication and by the promotion Open path, and is checked by every exporter"`.
2. **Four Section 9 Test Suites**:
   - **PATH-A sole-writer transaction suite**: `plan.md:2749-2783`.
   - **Failure-semantics pins**: `plan.md:2784-2797`.
   - **Alias-stage propagation suite**: `plan.md:2798-2811`.
   - **Pre-install children fence suite**: `plan.md:2812-2823`.
3. **Rule 6 Body (Normative Daemon-Issued Incarnation)**:
   - `plan.md:424-435`: `"The incarnation is NORMATIVELY a DAEMON-ISSUED monotonic generation (or collision-resistant nonce), established at the barriered handoff and bound to the currently validated helper instance on BOTH lanes..."`.
4. **Stale-Replica Pin**:
   - `plan.md:2792-2794`: `"the stale-replica last_seen regression (a replica's older candidate never overwrites the owner's newer value — monotonic max(current, candidate))"`.

---

### 4. Full-Plan Convergence Sweep

A complete internal consistency sweep across all sections of v15.26 confirms zero surviving BLOCKER or MAJOR defects. Both forks are settled, option-(a) core integrity is confirmed across all three review channels, and the fold audit is clean.

---

### Numbered Findings (Nits Only)

1. **[NIT] Helper-Side Export Skip Metric Taxonomy Refinement in §5.8**
   - **File:Line**: [`plan.md#L501-L505`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L501-L505) & [`plan.md#L2532-L2546`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2532-L2546) (§4.0.1 / §5.8)
   - **Description**: While §4.0.1 Rule 7 ([`plan.md#L501-L505`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L501-L505)) mandates that helper-side export skips of both `alias-suspect` and `alias-lineage` entries get a distinct helper-side counter covering both marks, §5.8's summary list enumerates the 5 helper-side and 3 Go-side counters without explicitly adding a separate line item name for the helper-side export skip counter in the 5+3 table. The implementation PR should ensure this helper-side counter label is registered alongside the 5 existing helper-side metrics.

2. **[NIT] Incarnation Advancement Log Marker Requirement in Implementation Spec**
   - **File:Line**: [`plan.md#L434-L435`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L434-L435) (§4.0.1 Rule 6)
   - **Description**: Rule 6 mandates emitting one info-level log marker upon every incarnation advancement. During PR implementation, verify that this log marker includes both old and new incarnation generation IDs (`G_old -> G_new`) to ensure clear traceability during helper restarts in production logs.

---

### Summary & Next Steps

Plan v15.26 is **PLAN-READY-WITH-NITS**. All architectural, transport, generation, and state-machine boundaries are fully closed and grep-verified. Plan research for issue #6751 has converged; the task is ready for PR implementation.
