Here is the adversarial review of the implementation plan. All code citations, raw Prometheus metrics, and iperf3 JSON results have been verified against the active worktree.

---

### Analysis of Attack Vectors

#### 1. Shaper Ceiling Headroom (Section 3 Kill-Exit)
*   **Verification**: The unshaped mix ceiling ([sim_5204.json](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/raw/unshaped-r2-034255/sim_5204.json) etc.) yields **23.22 Gbps**, while the shaped baseline ([sim_5204.json](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/raw/base-r3-033430/sim_5204.json) etc.) delivers **19.61 Gbps**.
*   **Finding**: Removing CoS does eliminate CPU/scheduler overhead, but we can prove the shaped capacity limit $C_{phys}(shaped)$ is at least **19.61 Gbps**. In the `agg9` cell ([sim_5204.json](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/raw/agg9-r2-022931/sim_5204.json) etc.), the total demand is **19.1 Gbps** but XPF only delivers **15.12 Gbps** (a 3.98 Gbps deficit). Since the demand of 19.1 Gbps is below XPF's verified capacity under shaping (19.61 Gbps), XPF was not CPU-saturated in the +9g cell. The gap is logical, not physical. The kill-exit is closed.

#### 2. Rate-Setter Verification (Section 4.2)
*   **Strict No-Surplus**: Confirmed in [mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L1386-L1388) (`ShareExhausted` breaks primary grants) and [mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L1495) (`let surplus_open = bypass && !equal_flow_enforced`).
*   **Flow-count proportional shares**: Confirmed in [rotate_epoch_v8.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs#L350-L356).
*   **Share evaporation**: Confirmed in [rotate_epoch_v8.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs#L125-L130). Every worker grant is atomically reset to a new tag with `0` consumed bytes, abandoning unclaimed shares.
*   **Cell P Invariance**: When `buffer-size 4m` raises the watermark from 12 KB to 150 KB, the worker's grant is still bounded by `my_share` (25 KB for 6g in 12-flow mix). Unused shares of other workers evaporate, keeping the rate invariant.

#### 3. Cell P Admission-Layer Masking (Section 2.4 / 8)
*   **Verification**: Client-side iperf3 JSON files show retransmits at **0** (baseline `base-r3`) and **1** (Cell P `p6g-r1`). No packet drops occurred at the admission layer.
*   **Finding**: The sojourn EWMA latency for 6g actually decreased from **23.0 ms** to **9.6 ms** in `p6g-r1` due to re-batching. This refutes the possibility that buffer bloat or admission tail-drops masked a watermark gain. The rate invariance is a genuine lease-grant property.

#### 4. Historical Strictness Rationale (#1231 v5.5)
*   **Finding**: Allowing workers to reclaim remaining class room within the epoch (Option A-i) creates a race condition. If a fast worker claims the class room, a slower worker trying to claim its share later will be blocked by a `ClassCap` undergrant, reproducing the #1231 multi-flow starvation regression. Option A-ii (carrying over the worker's own unclaimed share) is structurally safe because it maintains worker share isolation.

---

### Verdict

**PLAN-NEEDS-CHANGES**

#### Finding 1: Option A-i (second-pass peer reclaim) reintroduces the verified #1231 peer-starvation regression.
*   **File**: [mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L1486-L1496)
*   **Detail**: Reclaiming class room within the epoch allows faster workers to starve slower, multi-flow workers' shares under shaper-bound traffic. The plan must reject A-i and select **A-ii (per-worker share carry-over)** as the primary path.

#### Finding 2: Pre-fix diagnostic instrumentation of the mismatch (a) vs sampling loss (b) split is mandatory.
*   **File**: [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L207-L215)
*   **Detail**: Option A-ii only solves sampling loss (b). If static worker-demand mismatch (a) is the dominant cause of the 30% gap, Option A-ii will fail to meet the acceptance gates, requiring Path B (demand-weighted shares) instead. We must instrument this split before coding.

#### Finding 3: Decouple the `burst/8` queue-lease ceiling fix for hygiene.
*   **File**: [mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L888-L894)
*   **Detail**: The `burst/8` clamp silently limits the top-up watermark to 12 KB for default-buffer queues (96 KB). This restricts the token bank even under a single worker (no sharing mismatch). The ceiling should be raised for exact queues as hygiene.

#### Finding 4: Verification of Stale-Token Completion-Lag (Q1).
*   **File**: [queue_service/mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1192-L1195) and [tx_completion.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/tx_completion.rs#L799)
*   **Detail**: The stale-token completion-lag reading is correct. Tokens are debited at completion, but Phase 2 (24g) has no honored-bit lockout, allowing it to be repeatedly selected in the same worker pass while reading stale, not-yet-debited token values.
