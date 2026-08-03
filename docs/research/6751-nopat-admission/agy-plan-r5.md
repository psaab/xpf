# AGY hostile plan review — #6751 plan v5 (round 5)

PLAN-READY-WITH-NITS

---

### Executive Summary & Convergence Adjudication

All 2 MAJORs and 1 MINOR from AGY Round 4, as well as all 6 BLOCKERs, 2 MAJORs, 1 MINOR, and 1 NIT from Codex Round 4, have been fully addressed and folded into **v5** of the plan document (`docs/research/6751-nopat-admission/plan.md`). No BLOCKER or MAJOR issues remain open. The architecture and detailed implementation protocol are complete, sound, and ready for code implementation.

---

### Verification of Folds & Attack Walkthroughs (Items 1–7)

#### 1. AGY MAJOR 1 (Worker-Teardown Leak) — Verified Resolved (§5.6)
- **Code Audit**: In `[userspace-dp/src/afxdp/coordinator/worker_manager.rs:141]`, `stop_and_clear` signals and joins all worker threads. `release_all_worker_markers()` is executed immediately after worker threads join, clearing all `{Worker(*)}` holder markers across `InterfaceNatAllocators`.
- **Path Matrix Verification**:
  - `stop_inner(false)` on reconcile (`[teardown.rs:80]`) and bind-incomplete rollback (`[bringup.rs:213]`): Worker threads join and `{Worker(*)}` markers are released. Canonical `shared_sessions` entries are snapshot-preserved at `[teardown.rs:56]` and replayed via `replay_synced_sessions` at `[coordinator/mod.rs:810]`. `{Shared}` markers survive on the coordinator during teardown, and replay re-acquires `{Worker(*)}` markers via the worker `install_synced_with_reserve` wrapper.
  - `stop_inner(true)` on link-cycle stop (`[coordinator/mod.rs:459]`) and process exit (`[coordinator/mod.rs:473]`): Workers are joined (releasing all `{Worker(*)}` markers), and `clear_synced_state` iterate-and-releases all `{Shared}` markers before clearing `shared_sessions`. Both marker classes are cleanly purged without leaks.

#### 2. AGY MAJOR 2 (Mid-Drain Pool Edit) — Verified Resolved (§5.3)
- **Analysis**: In v4, removing or editing an overlapping pool rule mid-drain left its allocator $A_P$ in `InterfaceNatAllocators.draining[E]`, but `release_source_nat_allocation` searched only active rules, causing expiring pool flows to miss $A_P$ and trapping address $E$ in permanent quarantine.
- **Verification**: In v5 §5.3, `InterfaceNatAllocators.draining` participates in **both** release and reserve scans (searched after active rules, before the interface registry). Flow-keyed discrimination ensures expiring pool releases locate $A_P$ in `draining`, decrementing $A_P$'s live count to 0, completing the drain, and lifting quarantine cleanly.

#### 3. AGY MINOR 3 (`{Shared}` Asymmetry) — Verified Acceptable (§5.6)
- **Analysis**: When coordinator pre-reserve attaches `{Shared}` but worker `install_synced_with_reserve` refuses the reserve (dropping `UpsertSynced`), `{Shared}` remains attached until peer delete-sync or session expiry.
- **Verdict**: Acceptable. The identity is held fail-closed, preventing cross-session misdelivery or squatting. The canonical row's lifetime governs `{Shared}`'s existence, and peer deletion/expiry cleans up `{Shared}` via `remove_shared_session`.

#### 4. Codex r4 B1 (Tri-State Reserve & Mint Split) — Verified Correct (§5.3)
- **Standby Dual-Import Attack**: Two interface-mode flows ($F_1$ and $F_2$) with different internal tuples but colliding identity $T$ arrive back-to-back on the standby. $F_1$ reserves $T$ (`Owned`) and attaches `{Shared}`. When $F_2$ arrives, the interface registry checks $T$, sees $T$ owned by $F_1$, and returns `IdentityConflict`. Tri-state reserve immediately **aborts and drops** $F_2$ import (`xpf_userspace_interface_snat_sync_identity_conflict_drops_total`). $F_2$ is never installed on the standby, preventing cross-session misdelivery.
- **Mint vs Reserve Split Coherence**: Local admission mints seek to allocate a valid identity for a new local flow (using preserve-first with exact PAT fallback upon collision). Reserves, however, verify and claim a *specific* pre-allocated wire identity $T$ for a synced flow; if $T$ is occupied by another flow, the reserve cannot pick a different port and MUST return `IdentityConflict` and abort. The split is 100% coherent.

#### 5. Codex r4 B5 (Publication Acquires `{Shared}`) — Full Lifecycle Walkthrough (§5.6)
1. **Decision (Local Mint)**: Mint inserts `{Worker(W)}` in `live_by_flow[F]`. Holders = `{Worker(W)}`.
2. **Install**: Flow $F$ installed into local `SessionTable` on Worker $W$.
3. **Publish (`[poll_descriptor/mod.rs:2591]`)**: `publish_shared_session` receives `registry` and inserts `{Shared}` into `live_by_flow[F]`. Holders = `{Worker(W), Shared}`.
4. **Worker Reap (`[loop_body/mod.rs:1625]`)**: Worker $W$ local entry expires; reap releases `{Worker(W)}`. Holders = `{Shared}`. Identity $T$ is NOT freed because `{Shared}` persists.
5. **Close-Delta Relay (`[session_delta.rs:436]`)**: Canonical row removed; `remove_shared_session` releases `{Shared}`. Holder set becomes empty (`{}`), freeing identity $T$.
- **Verdict**: There is **zero window** where identity $T$ is free while reachable.

#### 6. Codex r4 B6 (Staged Replacement Protocol) — Walkthrough (§5.6)
- **Coordinator**: Pre-reads canonical tuple $T_{\text{old}}$, pre-reserves $T_{\text{new}}$ (+`{Shared}` on $T_{\text{new}}$), drops `{Shared}` on $T_{\text{old}}$, publishes $T_{\text{new}}$. $T_{\text{new}}$ is held by `{Shared}` before publication; $T_{\text{old}}$ remains held by `{Worker(W)}`.
- **Worker Wrapper**: Pre-reads existing entry's tuple $T_{\text{old}}$, reserves $T_{\text{new}}$ (+`{Worker(W)}` on $T_{\text{new}}$), installs $T_{\text{new}}$ in local table (in-table replace at `[session/install.rs:322]` makes $T_{\text{old}}$ unreachable), and releases $T_{\text{old}}$ (`-{Worker(W)}` on $T_{\text{old}}$). $T_{\text{old}}$ holder set empties and $T_{\text{old}}$ is freed.
- **Verdict**: $T_{\text{old}}$ and $T_{\text{new}}$ are continuously held throughout the overlap; third flows cannot claim either tuple during transition.

#### 7. End-to-End Drain Model Walkthrough (§5.7)
1. **Overlap Discovery**: DHCP adds address $E$ overlapping pool $P$. Builder (`daemon_dhcp.go:73`, `buildLinkSnapshot`) detects overlap and marks pool $P$ unusable (`PoolUnusable`).
2. **Quarantine Installation**: Coordinator retains $P$'s allocator $A_P$ in `InterfaceNatAllocators.draining[E]`. Quarantine marker for $E$ is installed BEFORE the new `RuntimeView` store (`[snapshot_refresh.rs:458/472]`).
3. **Quarantined Admission**: New interface mints on $E$ hit `is_draining(E)` and fail closed (`InterfaceOverlapDraining`).
4. **Reap & Drain**: Live sessions on $A_P$ expire; releases find $A_P$ via `draining` vec scan and decrement $A_P$'s live count (tracked accurately via authoritative `addr_index` at `[allocator.rs:1770]`).
5. **Atomic Lift**: When $A_P$'s live count hits 0, $A_P$ is removed from `draining[E]` and quarantine lifts in one atomic write-lock critical section. Interface mints on $E$ resume.
- **Verdict**: Zero packet misdelivery at any point in the lifecycle.

---

### Numbered Findings

#### 1. [NIT] Prometheus Metric Sub-labeling for Registry Memory Caps
- **Evidence**: `[userspace-dp/src/afxdp/coordinator/status.rs:241]`, `[pkg/api/metrics.go:791]`, `plan.md:497`.
- **Impact**: Section 5.8 aggregates both the per-address 64,512 flow-registry cap and the 256-retained-allocator cap into `xpf_userspace_interface_snat_registry_cap_exhaustion_total`.
- **Recommendation**: Consider adding a `reason` label (`reason="flow_cap"` vs `reason="allocator_cap"`) to distinguish table-full exhaustion from WAN-IP churn allocator retained cap exhaustion in Prometheus dashboards.

#### 2. [NIT] Helper Signature Refinement for Staged Replacement Pre-read
- **Evidence**: `[userspace-dp/src/session/install.rs:322]`, `[userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:65]`, `plan.md:386`.
- **Impact**: Worker-side staged replacement requires pre-reading the existing session's tuple $T_{\text{old}}$ before in-table replacement. Currently `upsert_synced_with_origin` returns `bool` (whether inserted/updated).
- **Recommendation**: Update `upsert_synced_with_origin` (or internal table helpers) to return `Option<NatDecision>` containing the previous decision/tuple directly, eliminating an extra pre-lookup step in the worker wrapper.
