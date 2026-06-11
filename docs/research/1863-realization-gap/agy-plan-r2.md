An adversarial review of implementation plan v3 for **xpf issue #1863** has been performed against the active worktree located at `/home/ps/git/bpfrx/.claude/worktrees/1863-research` (branch `research/1863-realization-gap` at commit `06e05742f`).

All metrics tables, data structures, and code citations have been cross-checked directly against the checked-in source files and the raw experimental directories.

---

### 1. Fold Verification: Antigravity R1 Findings

We verified that each of our findings from Round 1 (archived in [agy-plan-r1.md](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/agy-plan-r1.md)) has been faithfully addressed in v3:

*   **Finding 1 (A-ii Primary over A-i):** Option A-i (second-pass peer reclaim) has been explicitly rejected in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L276-L282) due to the risk of reintroducing the `#1231` peer-starvation race condition under `ClassCap` limit bounds in [mod.rs:1396-1398](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L1396-L1398). Option A-ii (per-worker share carry-over) is now the primary path. The carry-over logic explicitly notes the required isolation boundaries, respect for `equal_flow_cap_v8`, and bounding of carry-over credit against both the future class cap and the outstanding credit `max_total_leased` ([plan.md:283-294](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L283-L294)).
*   **Finding 2 (Mandatory Step-0 Instrumentation):** The (a)/(b) attribution instrument (worker mismatch vs. sampling loss) is now a **mandatory** pre-fix step (Path-A Step 0) in [plan.md:296-312](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L296-L312). A registered decision rule has been codified: if sampling loss (b) is dominant, Option A-ii proceeds; if share/demand mismatch (a) is dominant, Path B (demand-weighted shares) is promoted.
*   **Finding 3 (Decouple `burst/8` Hygiene):** The `burst/8` queue-lease ceiling clamp at [mod.rs:888-894](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs#L888-L894) has been successfully decoupled. It is framed as an independent hygiene PR focused on latency and jitter optimization rather than throughput ([plan.md:322-332](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L322-L332)).
*   **Finding 4 (Ratify Stale-Token Reading Q1):** The explanation for Q1 is ratified. Phase 2 (24g) does not have an honored-bit lockout, meaning that back-to-back selector visits within the same worker pass read stale, not-yet-debited token values from [queue_service/mod.rs:1191-1195](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L1191-L1195) before they are debited at completion in [tx_completion.rs:799](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/tx_completion.rs#L799).

---

### 2. Spot-Check: Codex R1 Folds

All Codex Round 1 findings (archived in [codex-plan-r1.md](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/codex-plan-r1.md)) were audited to confirm they did not introduce new logical or structural errors:

*   **Codex F1 (C_phys Upper Bound Caveat):** Section 3 leg 3 in [plan.md:174-180](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L174-L180) now correctly models the 23.2 G unshaped mix capacity as an upper bound rather than an directly reachable shaped headroom target. It accurately points to the `+9g` cell (delivered 15.12 G against 19.1 G demand, which is well below the system's verified shaped baseline of 19.61 G) to carry the work-conservation proof. This is arithmetically sound.
*   **Codex F2 (Worker-pooled Grants == Sends Overclaim):** The grants-to-sends tracking in [plan.md:96-115](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L96-L115) has been downgraded from a proven per-class identity to a worker-pooled implication. This aligns with the fact that `xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total` tracks worker totals, not class totals, highlighting the need for the Step-0 per-class requested-vs-granted counters.
*   **Codex F3 (Admission Buffer Confound):** The plan now correctly acknowledges that `buffer_limit` at [admission.rs:222](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/userspace-dp/src/afxdp/cos/admission.rs#L222) scales with `buffer_bytes`. In [plan.md:307-311](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L307-L311) and [plan.md:401-407](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L401-L407), the admission-drop counters are added to the mandatory Step-0 collection.
*   **Codex F5 (Ceiling Citation Correction):** The incorrect 22.72 G push citation from the `#1691` reverse-direction sanity test was removed. The aggregate acceptance gate in [plan.md:364-370](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/plan.md#L364-L370) has been downgraded to secondary and set to a realistic `≥ 20.5 G`, with per-class mid gates remaining primary.
*   **Codex F6 (Raw Cell Manifest):** A machine-auditable [MANIFEST.md](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/raw/MANIFEST.md) has been created to record incident labels, timestamps, roles, and status (e.g., decisive vs. tainted/mislabeled) for every experimental run in `raw/`.

---

### 3. Data Consistency check

The metrics analysis scripts [honor-analysis.py](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/honor-analysis.py) and [grants-analysis.py](file:///home/ps/git/bpfrx/.claude/worktrees/1863-research/docs/research/1863-realization-gap/grants-analysis.py) were executed against the checked-in metrics files. All calculations match the values listed in the plan:
*   `p6g-r1-033531` verifies 6g buffer watermarks: `57,706 B/honor` vs. `31,505` baseline, `280,570` admissions vs. `537,005` baseline, and `16.19 GB` sent vs. `16.92 GB` baseline.
*   `udp3g-r1-035126` and `udp3g-r2-035202` verify inelastic constant-pressure drops: `2.067 G` (68.9% of shape, 37.35% loss) and `2.041 G` (68.0% of shape, 38.14% loss) under full 24g TCP aggressor load.

There are no unresolved contradictions or code discrepancies in the updated plan.

---

### Verdict

**PLAN-READY**
