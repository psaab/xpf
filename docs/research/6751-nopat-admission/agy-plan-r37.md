# AGY hostile plan review — #6751 (round 37)

# AGY Hostile Plan Review — #6751 Plan v15.25 (Round 37 Convergence Adjudication)

**Verdict**: **PLAN-READY-WITH-NITS**

---

### Executive Summary & Convergence Decision

Plan doc [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (NOW AT v15.25, commit `1139d4153`) has been evaluated against Codex r36's 6 findings (1 BLOCKER, 1 MAJOR, 2 MINORs, 2 NITs), AGY r36's 2 nits, and Claude SMR r37's fold-check ([`claude-smr-plan-r37.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/claude-smr-plan-r37.md)).

- **Substrate & Core Status**: Both design forks are fully settled (**PATH A** sole-writer helper in [§4.0.1](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L193-L451); **Option (a)** preserve-first + exact PAT fallback in [§4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L542-L654)). Three independent review channels (AGY, Codex, Claude SMR) have repeatedly confirmed zero kill-shots against the option-(a) core across rounds 34–37.
- **Fold Verification**: Codex r36's BLOCKER (transport refusal), MAJOR (two-stage alias lineage), MINORs (§5.6 replacement, §9 test pins), and NITs (daemon-issued incarnation, refresh iterator origin projection) are cleanly and textually integrated into v15.25.
- **Convergence**: Zero BLOCKER or MAJOR defects survive in v15.25. All internal cross-section contradictions have been resolved. The remaining items are minor implementation-level nits.

---

### 1. Codex r36 BLOCKER Fold Attack & Verification (Transport Refusal & Quiet Interval)

**Fold Verification** ([`plan.md#L8-L9`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L8-L9), [`plan.md#L547-L580`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L547-L580)):
Codex r36 BLOCKER 1 observed that an `installConn`-time post-auth refusal allowed both endpoints to complete setup and install locally before returning `REFUSED`, leaving open a late-retry race. v15.25 shifts refusal to the **TRANSPORT level** (listener closed / TCP SYN refused). No handshake, setup, or `installConn` completes on either endpoint.

**Hostile Attack Analysis**:
- **(a) Fence Engagement's Own Install State (Teardown vs. Drain)**:
  - *Scenario*: Connection $C$ is installed at the fencing side immediately before fence engagement.
  - *Adjudication*: Upon fence engagement, the fencing node actively closes its sync listener and tears down existing sync sockets (`CloseAllConnections()` / socket teardown). This emits TCP FIN/RST. The peer's disconnect detection bound is $1 \times \text{keepalive\_timeout}$ (e.g. 3s). The quiet interval $T_{\text{quiet}} = 2.5 \times \text{keepalive\_timeout}$ (e.g. 7.5s) begins at fence engagement. By $t = 7.5\text{s}$, the peer has long detected the disconnect, unregistered $C$, and confirmed both connection slots `nil`. Transport refusal ensures no new setup can complete during $T_{\text{quiet}}$. Drain + teardown cover the state completely.
- **(b) Re-Fence Cycle vs. Readiness Timeout (Terminal Timeline)**:
  - *Scenario*: Persistent network corruption or dead peer causing repeated re-fence cycles.
  - *Adjudication Timeline*:
    1. $t=0$: Node A misses bulk deadline / detects checksum failure and engages fence ($T_{\text{quiet}} = 7.5\text{s}$). Listener closed.
    2. $t \in (0, 7.5\text{s})$: Node B's 1s retries fail instantly (`ECONNREFUSED`). No setup completes.
    3. $t=7.5\text{s}$: Node A re-opens listener. Node B's next retry succeeds. Node B confirms `wasDisconnected == true`, arms `needColdPrime`, and streams bulk.
    4. $t=t_{\text{fail}}$: Bulk fails or misses deadline. Node A RE-FENCES ($T_{\text{quiet}}$ restarts).
    5. $t=30\text{s}$: The 30s readiness timeout ([`manager.go:372`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/manager.go#L372)) fires as the global upper bound, releasing sync hold degraded.
  - *Result*: No liveness leak or infinite loop exists; the readiness timeout guarantees bounded degradation.
- **(c) Old Peer Write-Completion Clearing under Re-Fence**:
  - *Scenario*: Old peer sender writes `BulkEnd` on epoch $E_1$ and sets sticky `outboundBulkAcked = true` before receiver A re-fences.
  - *Adjudication*: On receiver A, the reconciliation hold protects carried state, and A never reconciles without a complete, valid bulk. When A closes its listener to re-fence, B's connection is torn down. Connection teardown on B clears B's registry slots; when B reconnects post-interval on $E_2$, `installConn` observes `wasDisconnected == true` ([`sync_conn.go:248`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L248)), which re-arms `needColdPrime` and clears `outboundBulkAcked`. B is forced to re-prime. A cannot be left in an unprimed or half-reconciled state.

---

### 2. Codex r36 MAJOR Fold Attack & Verification (Two-Stage Alias Lineage & Resolution Pass)

**Fold Verification** ([`plan.md#L9-L13`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L9-L13), [`plan.md#L444-L465`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L444-L465)):
Codex r36 MAJOR 2 showed that marking only confirmed aliases allowed timeout-admitted suspects to promote to `SharedPromote` and export as canonical. v15.25 implements two-stage lineage:
1. `alias-suspect`: Provisional, set at quarantine insertion AND timeout-admission for signature-matching rows, sticky, export-suppressing while `UNRESOLVED`.
2. `alias-lineage`: Permanent, set on alias confirmation, suppressing export for row lifetime.

**Hostile Attack Analysis**:
- **(a) 5s Incremental Window vs. Export Check Critical Section**:
  - *Attack*: Does a genuine verdict arriving via the 5s incremental window update the mark in the same critical section as export iteration?
  - *Adjudication*: Under §4.0.1 (sole-writer model inside the Rust helper), all session store mutations—quarantine insertion, 5s window resolution, `BulkEnd` resolution pass, alias confirmation, promotion, and table-truth export iteration—take place under the session store lock / sole-writer transaction model. The resolution pass updates `alias-suspect` $\rightarrow$ cleared (for genuine) or `alias-suspect` $\rightarrow$ `alias-lineage` (for confirmed alias) atomically. No export scan can observe a genuine row with a stale `alias-suspect` mark after resolution completes.
- **(b) Suspect Mark Memory Lifecycle**:
  - *Attack*: Does a suspect row that ages out (idle timeout / TCP FIN purge) leak the suspect mark?
  - *Adjudication*: Line 465–468 specifies that the mark is stored either directly on the session record (`xpf_conntrack.h` ABI provenance bit / Rust `SessionEntry`) or in an exact lifecycle-managed side index ("same lifetime as the row, updated by the same transactions"). When a session row ages out or is deleted, its mark is freed in the exact same transaction. Memory leak is impossible.
- **(c) Conservative Suppression & Export Skip Counter**:
  - *Attack*: Does conservative suppression of `alias-suspect` interact cleanly with export skip metrics (§5.8)?
  - *Adjudication*: Lines 463–464 mandate that "every export path skips a marked row with the skip counted". Both `alias-suspect` and `alias-lineage` rows are filtered out by export scans (`export.rs` / `sync_bulk.go`).

---

### 3. Codex r36 MINORs & NITs Verification

1. **§5.6 Supersession Replacement (Codex r36 MINOR 3)**:
   - Contradictory "not fed back" paragraph at [`plan.md#L1037-L1044`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1037-L1044) has been replaced with the explicit supersession explaining that Rules 2–3 mandate worker outcome reporting before barrier ACK.
2. **§9 Test Plan Pins (Codex r36 MINOR 4 & NIT 6)**:
   - Section 9 ([`plan.md#L2680-L3050`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2680-L3050)) includes explicit test pins for: worker refusal before barrier ACK, purge failure $\rightarrow$ `Failed`, timeout/unknown $\rightarrow$ `Pending` with teardown, restarted incarnation `(E2,1)` after `(E1,100)`, and the stale-replica `last_seen` regression.
3. **Normative Daemon-Issued Incarnation (Codex r36 NIT 5)**:
   - Rule 6 ([`plan.md#L416-L422`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L416-L422)) explicitly establishes that helper incarnation is daemon-issued, bound at barriered handoff, and high-water marks reset only upon validating $G_{\text{inc}} + 1 > G_{\text{inc}}$.
4. **Refresh Iterator Origin Projection (Codex r36 NIT 6)**:
   - Section 4.0.1 Rule 5 ([`plan.md#L375-L384`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L375-L384)) updates the refresh iterator signature to project `Origin`, enabling `origin == Owner` gating for counter/policy updates and monotonic `last_seen` updates.

---

### 4. Full-Plan Convergence Sweep & Cross-Sectional Consistency

A full-plan internal contradiction sweep across all sections of v15.25 ([`plan.md#L1-L3125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1-L3125)) confirms:
- **Sole-Writer vs. Option (a)**: Sole-writer helper substrate (§4.0.1) and option-(a) identity reservation (§4) interface seamlessly.
- **Ledger & Quarantine**: Two-ledger transaction model (§4.0.1 Rule 3) and two-stage alias lineage (§4.0.1 Rule 7 / §5.6) are aligned without state leaks.
- **Wire Preservation**: Section 6 additive optional fields (`syncMsgCapability`, ordering tuple `(worker_id, seq, incarnation/epoch)`, prime-REQUEST bit, provenance bit) remain strictly backward-compatible.
- **Observability & Tests**: Section 5.8 8-counter taxonomy (5 helper-side + 3 Go-side) matches Section 9 test assertions.

---

### 5. Numbered Findings (Nits Only)

1. **[NIT] Helper-Side Export Skip Metric Taxonomy Refinement in §5.8**
   - **File:Line**: [`plan.md#L463-L464`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L463-L464) & [`plan.md#L2476-L2480`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2476-L2480) (§4.0.1 / §5.8)
   - **Description**: While `alias-suspect` and `alias-lineage` export skips are explicitly required to be skipped and counted on every export path (`plan.md#L463-L464`), the §5.8 metrics inventory explicitly names the Go-side counter `xpf_userspace_session_sync_forward_wire_alias_ignored_total` for quarantine drops. The implementation PR should ensure the helper-side export skip counter (or metric label) explicitly accounts for export skips of both `alias-suspect` and `alias-lineage` entries.

2. **[NIT] Incarnation Generation Advancement Log Marker**
   - **File:Line**: [`plan.md#L416-L422`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L416-L422) (§4.0.1 Rule 6)
   - **Description**: Rule 6 specifies that helper incarnation is daemon-issued and high-water marks reset only upon validating a new incarnation generation $G_{\text{inc}} + 1 > G_{\text{inc}}$. During implementation, an explicit info log should be emitted upon incarnation advancement to aid in debugging helper restarts in production logs.

---

### Conclusion

v15.25 is **PLAN-READY-WITH-NITS**. All architectural, mathematical, state-machine, and transport boundaries are fully verified across all three independent reviewer channels. Plan research for issue #6751 has achieved convergence; implementation may proceed.
