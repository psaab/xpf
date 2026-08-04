# AGY hostile plan review — #6751 (round 47, final convergence verification)

# Adversarial PLAN Review — #6751 Plan v15.34.1 (Research Round 47: Final Convergence Verification)

**Terminal Verdict**: **PLAN-READY-WITH-NITS**

This is the final convergence verification over `docs/research/6751-nopat-admission/plan.md` at **v15.34.1** (commit `75980514c` + AGY r46 nit fold). Both forks are settled (behavior option **(a)**, substrate **PATH A**), no BLOCKER or MAJOR findings survive, and all prior reviewer folds have been verified in the worktree blob.

---

### 1. AGY Round-46 Nit Fold Verification
- **Deferred-overflow line capability-qualification**: Verified at [`plan.md:2603-2606`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2603-L2606). The text explicitly specifies:
  > `ITS overflow DEFERS the excess alias-signature entries to the NEXT BULK's CAPABILITY-QUALIFIED BulkEnd resolution (provisional admission with the alias-suspect mark on a non-capable BulkEnd, per the explicit terminal — AGY r46 nit 1)`

---

### 2. Codex Round-45 Folds Verification (All in v15.34)
- **a. Epoch-pass snapshot-authority scoping**: Verified at [`plan.md:2471-2478`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2471-L2478). Non-capable epoch passes are explicitly scoped as `DISPOSITION-ONLY` and never perform `SNAPSHOT-AUTHORITY` confirmation, purge, or mark clearing.
- **b. Explicit deferred-entry terminal + revised guarantee + §9 correction**:
  - Terminal & revised guarantee verified at [`plan.md:2170-2184`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2170-L2184) ("never left UNRESOLVED past the row's own lifetime or the peer's capability upgrade").
  - §9 permanent broken companion correction verified at [`plan.md:3475-3480`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3475-L3480).
- **c. Generation-bound live-transition arming & zero-transport restart guard**: Verified at [`plan.md:765-785`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L765-L785) (citing `daemon_apply_tail.go:243` for the zero-transport restart guard and pinning the day-2 regression).
- **d. Epoch-selection note (not `syncPeerConnEpoch`)**: Verified at [`plan.md:1809-1813`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1809-L1813) (clarifying `syncPeerConnEpoch` advances only on connect).
- **e. Branch (ii)'s `current epoch != arming epoch` precondition**: Verified at [`plan.md:1818-1821`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1818-L1821) (covers cold start connecting mid-bound, arming 0 $\to$ current 1).
- **f. "OMITS the id field — receiver decodes zero" terminology**: Verified at [`plan.md:2724-2726`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2724-L2726).
- **g. Reconciliation-hold deduplication**: Verified at [`plan.md:675-725`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L675-L725) (duplicate reconciliation-hold text deduplicated cleanly).

---

### 3. Final Convergence Sweep & Code Evidence
1. **Fork Settlement**: Both behavior option **(a)** and substrate **PATH A** are settled and locked. Option-(a) core has 4 independent no-kill-shot confirmations.
2. **Evidence/Authority Split Verification**:
   - [`pkg/cluster/sync_protocol.go:491-496`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go#L491-L496): Absent `RTFlowSessionID` in legacy payload decodes to 0.
   - [`pkg/cluster/sync_rtflow_session_id_5212_test.go:64-74`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_rtflow_session_id_5212_test.go#L64-L74): Tests that truncated legacy frames decode `RTFlowSessionID` as zero.
3. **Substrate Seams**:
   - `userspace-dp/src/nat/allocator.rs:165` holds the reverse-identity lookup key.
   - `userspace-dp/src/nat/source.rs:1226` is the unreserved interface NAT seam.

---

### Numbered Findings

1. **NIT** — `plan.md:794-795`: Cold-start bound primitive relies on existing `syncReadyTimeout` ([`pkg/daemon/daemon.go:1148`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon.go#L1148)); exact timer handle naming is a PR implementation detail.
2. **NIT** — `plan.md:1407`, `3033`: Wire enum numerical values for the alias lineage `STAGE` field (`alias-suspect` / `alias-lineage`) remain PR wire-format decisions.
3. **NIT** — `plan.md:254`, `2166`: Concrete fence generation counter primitive struct naming is an implementation detail pinned by unit tests.

### Summary
The research plan is fully converged, structurally sound, free of contradiction-class defects, and ready for implementation.
