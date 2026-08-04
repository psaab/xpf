# AGY hostile plan review — #6751 (round 39)

# AGY Hostile Plan Review — #6751 Plan v15.27 (Round 39 Convergence Adjudication)

**Verdict**: **PLAN-READY-WITH-NITS**

---

### Executive Summary & Convergence Adjudication

Plan document [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) at **v15.27** (commit `788b256aa`) has been evaluated following the round-38 fold verification and hostile attack.

- **Folds Verified**: Codex r38's two BLOCKERs, two MAJORs, MINOR, and NIT, along with AGY r38's two NITs, have been folded into v15.27.
- **Substrate Integrity**: Both design forks remain settled (**PATH A** sole-writer helper in [§4.0.1](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L415-L541); **Option (a)** preserve-first + exact PAT fallback in [§4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L710-L822)).
- **Convergence**: Zero BLOCKER or MAJOR defects survive v15.27. All line numbers referenced below have been verified via `grep` directly against the codebase and plan blob.

---

### 1. Codex r38 BLOCKER 1 Fold Attack & Verification (Accept-Proof Fenced Window)

**Fold Verification** ([`plan.md:636-644`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L636-L644), [`plan.md:2905-2916`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2905-L2916)):
v15.27 generation-binds the admission path via a two-part rule:
1. While the fence is engaged, `Accept` atomically refuses incoming connections (no stamp issued).
2. The fence advances the admission generation **AGAIN AT RELEASE** (after listener quiescence and a final sweep), rendering any mid-window stamp stale upon release.

**Hostile Attack Analysis**:
- **(a) Engaged-flag/stamp critical section**:
  - *Code Inspection* ([`pkg/cluster/sync_conn.go:388-413`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L388-L413)): In the Go `acceptLoop`, `ln.Accept()` returns a raw socket outside locks. To enforce atomic refusal, the wrapper check following `ln.Accept()` reads `fenceEngaged` under lock/atomic. If `fenceEngaged == true`, `conn.Close()` is called immediately without issuing a stamp. If `fenceEngaged == false`, `conn` is stamped with generation $G_1$.
  - Even if a connection returns from `ln.Accept()` just before `fenceEngaged` becomes `true` and receives stamp $G_1$, step (2) of the fold advances the generation $G_1 \to G_2 = G_1 + 1$ on fence release after listener quiescence and a final sweep. When the candidate attempts `beginSetup`, `finishSetup`, or `installConn`, its stamp $G_1 < G_2$ fails the stale check and is rejected. Sound.
- **(b) Installed connection tearing vs. draining**:
  - *Scenario*: Connection $C$ completed `installConn` on the fencing side's listener right before fence engagement.
  - *Adjudication*: Fence engagement initiates cluster sync teardown ([`sync_conn.go:349`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L349)), which closes listeners, setup children, and registered active slots (`conn0`/`conn1`). $C$ is closed at engagement, sending TCP FIN/RST. The quiet interval $T_{\text{quiet}} = 2.5 \times \text{keepalive\_timeout}$ (e.g. 7.5s) allows $C$'s dead state to drain on the remote peer within its disconnect bound. Sound.

---

### 2. Codex r38 BLOCKER 2 Fold Attack & Verification (Two-Mode Both-Empty Proof)

**Fold Verification** ([`plan.md:667-683`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L667-L683), [`plan.md:2898-2900`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2898-L2900)):
The both-empty proof operates in two modes:
1. **Interval-Derived Mode**: For peers with known disconnect bounds (heartbeat ACK active), $T_{\text{quiet}}$ guarantees slot clearance.
2. **Observed Prime Mode**: For legacy no-ACK peers, the completion condition is the `BulkStart` frame of an incoming cold prime (firing when the peer's own slots were empty). A missed per-bulk receive deadline triggers a re-fence, with the readiness timeout as the terminal release.

**Hostile Attack Analysis**:
- **(a) Old peer's write-completion clearing under mode (ii)**:
  - *Scenario*: An old peer connects, sends `BulkStart`, writes a partial bulk, and writes `BulkEnd` (clearing its `needColdPrime` latch on write-completion per [`sync_bulk.go:169`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go#L169) / [`sync_conn.go:194`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L194)), leaving the receiver un-reconciled.
  - *Adjudication*: The receiver enforces `no-reconcile-without-complete-bulk` and maintains the `reconciliation hold`. If the bulk stream fails to complete, the receiver's per-bulk receive deadline fires and triggers a **RE-FENCE**. Re-fencing closes transport sockets, tearing down $C_0$ again and forcing another quiet cycle. The receiver-side invariant prevents premature hold release or un-reconciled export. Sound.
- **(b) Legacy peer lacking BOTH detectors**:
  - *Scenario*: A peer lacks both heartbeat-ACK tracking ([`sync_conn_read.go:27`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L27)) and read deadlines ([`sync_protocol.go:59`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go#L59)).
  - *Adjudication*: The plan explicitly documents this residual ([`plan.md:681`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L681)): the terminal bound for such an uncooperative legacy peer is the readiness timeout's degraded release ([`plan.md:1996`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1996), [`plan.md:2039`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2039)). This provides a bounded release without making false protocol claims. Sound.

---

### 3. Codex r38 MAJOR 3 & MAJOR 4 Folds Attack & Verification

**MAJOR 3 (Disposition vs. Lineage Wording)** ([`plan.md:2214-2218`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2214-L2218), [`plan.md:2890-2892`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2890-L2892)):
- The 5-second timer resolves **ONLY quarantine disposition** (releasing the row into the normal import path) and **NEVER clears lineage** (`alias-suspect`).
- `alias-suspect` is cleared exclusively by the `COMPLETE-PRIME` pass or row closure (§4.0.1 Rule 7). §9 includes a direct regression pin ensuring timeout admission never clears `alias-suspect`. Sound.

**MAJOR 4 (End-to-End Stage Carrier)** ([`plan.md:2412-2432`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2412-L2432)):
- The stage carrier is the additive `SyncedSessionEntry` extension carrying two additive fields (`pub_token` and `alias stage`). It rides the import request (JSON + binary codec per `#1961`), lands in table metadata via `entry.metadata` ([`upsert_synced.rs:64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L64)), is preserved across replication and promotion, and gates promotion `Open` ([`session/mod.rs:1516`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs#L1516) emits only for clear/unmarked rows). All exporters are gated.
- *Old-helper degradation*: Absence of the stage field in requests from older helpers is treated as legacy (unmarked), matching the ratified mixed-version posture. Sound.

---

### 4. §9 Liveness Suite & §5.8 Observability Taxonomy Verification

- **Prime-Request/Re-Fence Liveness Suite** ([`plan.md:2893-2904`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2893-L2904)): Pins coalesced suspects, capable-peer completion, ignored-request fence cycle, and post-prime debt re-arm. Verified.
- **Rule 6 Incarnation Log Marker** ([`plan.md:438-441`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L438-L441)): Mandates an info-level log marker emitting `G_old -> G_new` upon helper incarnation advancement. Verified.
- **§5.8 Counter Inventory** ([`plan.md:2598-2624`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2598-L2624)): Fully inventories six helper-side counters (including `xpf_userspace_ha_export_alias_lineage_skips_total` at line 2616) and three Go-side cluster counters ($6 + 3 = 9$ total). Verified.

---

### 5. Full-Plan Convergence Sweep

A grep-verified sweep across all sections confirms that no BLOCKER or MAJOR defects remain in v15.27. Option (a) core and Path A sole-writer architecture are fully intact.

---

### Numbered Findings (Nits Only)

1. **[NIT] Section 6 Text Refinement for `SyncedSessionEntry` Additive Fields**
   - **File:Line**: [`plan.md:2414-2415`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2414-L2415) (§5.6) & [`plan.md:2690`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2690) (§6)
   - **Description**: §5.6 specifies that `SyncedSessionEntry` carries **two** additive fields (`pub_token` and `alias stage`) and notes that §6 is updated accordingly. However, §6 line 2690 still reads: "`SyncedSessionEntry` gains ONE additive HELPER-INTERNAL field (`pub_token: u64`...". During implementation PR preparation, update §6 line 2690 to explicitly list both additive fields (`pub_token` and `alias stage`) for full section-to-section alignment.

---

### Summary & Next Steps

Plan v15.27 is **PLAN-READY-WITH-NITS**. All architectural boundaries, transport fences, and generation mechanics are sound, closed, and grep-verified. Issue #6751 research has reached convergence and is ready for implementation.
