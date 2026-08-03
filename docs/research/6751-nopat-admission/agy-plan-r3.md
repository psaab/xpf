# AGY hostile plan review — #6751 plan v3 (round 3)

PLAN-NEEDS-REVISION

---

### Summary of Round 3 Adversarial Audit

Plan v3 successfully folds almost all major findings from Round 2 (including the transactional coordinator pre-reserve, single wrapper for sync-family installs, exact chunked full-cycle probe, and two-layer overlap foreclosure). However, an exhaustive audit of shared-map mutation paths reveals **two residual `{Shared}` holder leak paths** where shared map entries are cleared or overwritten without invoking `remove_shared_session` or decrementing the `{Shared}` holder count.

---

### Numbered Findings

#### 1. [MAJOR] Leaked `{Shared}` Holders on `publish_shared_session` Entry Displacement
- **Evidence**: `[userspace-dp/src/afxdp/shared_ops.rs:921](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L921)` (`let displaced = sessions.insert(reverse_wire.clone(), entry.clone());`), `[shared_ops.rs:932](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L932)`.
- **Impact**: In `publish_shared_session`, when a new session insert displaces an existing entry in `shared_nat_sessions` (producing a non-None `displaced`), `displaced` is overwritten and dropped from the map. `remove_shared_session` is **never called** for `displaced`. Under v3's holder model, `displaced`'s `{Shared}` holder count is never decremented (`-Shared`). Even after all worker sessions for `displaced` stale-reap (`-Worker(W)`), `{Shared}` remains in `holders`, permanently leaking the identity token in `InterfaceNatAllocators` and preventing identity reuse until process restart.
- **Remediation**: `publish_shared_session` must check `if let Some(ref old_entry) = displaced`, and if `old_entry` carries an interface-mode SNAT decision, decrement `-Shared` (or call a shared-holder drop helper) for `old_entry`.

#### 2. [MAJOR] Leaked `{Shared}` Holders on Wholesale Shared Map Clears During HA Transitions
- **Evidence**: `[userspace-dp/src/afxdp/coordinator/mod.rs:756-767](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs#L756-L767)` (`stop_and_clear` / `clear_synced_state`).
- **Impact**: When `clear_synced_state` is true during HA transitions, redundancy group state changes, or coordinator resets, `nat_sessions.clear()` is called directly on `shared_nat_sessions`. This drops all shared entries wholesale without invoking `remove_shared_session` or decrementing `{Shared}` for any entry. Every active shared interface-SNAT session at the time of an HA state clear will have its `{Shared}` holder permanently leaked in `InterfaceNatAllocators`.
- **Remediation**: Before executing `nat_sessions.clear()` during `clear_synced_state`, iterate `nat_sessions` (or `sessions.synced`) and release/decrement `-Shared` for every interface-mode entry, or clear/re-initialize `InterfaceNatAllocators` if all synced states are being wiped.

#### 3. [NIT] Unbounded Allocator Accumulation under High Egress IP Churn Before Snapshot Apply
- **Evidence**: `docs/research/6751-nopat-admission/plan.md:275` (`reclaim_absent`), `plan.md:270` (`allocator_if_present`).
- **Impact**: `reclaim_absent` only runs at snapshot-apply time and only reclaims allocators whose `live_by_flow` is empty. If egress IPs are rotated rapidly (>256 IPs) while old flows remain active during rotation, the 256 cumulative allocator cap will be hit, causing new address mints to fail closed (`AllocatorExhausted`).
- **Remediation**: Document this as expected policy or ensure `reclaim_absent` is triggered whenever a flow release leaves an absent allocator empty.

---

### Detailed Verification of Round 3 Questions

#### 1. Materialize Bypass & Install Path Search (BLOCKER 1 Fold Verification)
- **Callers of `upsert_synced_with_origin`**: Grep across `userspace-dp/src` confirms exactly 3 production call sites:
  1. `[afxdp/session_glue/commands/upsert_synced.rs:65](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L65)` (`WorkerCommand::UpsertSynced` handling)
  2. `[afxdp/session_glue/mod.rs:808](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs#L808)` (`WorkerCommand::UpsertLocal` handling)
  3. `[afxdp/session_glue/mod.rs:1130](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs#L1130)` (`materialize_shared_session_hit`)
  - All 3 sites are routed through `install_synced_with_reserve` wrapper in v3 §5.6.
- **Callers of `install_with_protocol_with_origin`**: Called only in `[afxdp/poll_descriptor/mod.rs:2450, 2779, 4788](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2450)` for local packet-driven admissions. Local packet admissions acquire `{Worker(W)}` at decision time in `allocate_interface_identity` (and release/rollback on install failure).
- **Verdict**: Verified complete. No 4th unwrapped install path exists.

#### 2. Replace Leak (BLOCKER 2 Fold Verification)
- `reserve_flow` (`[nat/allocator.rs:1666-1676](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs#L1666-L1676)`) checks if `live_by_flow.get(&flow)` exists; if the translated tuple changed, it drops the old reservation first.
- v3 section 5.3 mirrors this behavior in `reserve_synced_source_nat_allocation`: a re-reserve whose synced tuple changed decrements/removes the holder on `existing.translated` first before inserting the new `translated` tuple.
- **Verdict**: Verified. Solves AGY r2 Blocker 2.

#### 3. Standalone Node Helper Restart (MAJOR 3 Verification)
- On a **STANDALONE (non-HA)** node, session state exists only in `userspace-dp` process memory. When `userspace-dp` restarts, all session tables are wiped. There is no Go-to-helper session re-push for established dataplane sessions in standalone mode.
- Clients must re-establish connections, which go through packet-driven local admission (`match_source_nat_result_for_tuple`) and reserve fresh identities in `InterfaceNatAllocators`.
- On **HA** nodes, coordinator pre-reserve during HA re-sync handles rehydration.
- **Verdict**: Agreed with v3's analysis. No standalone rehydration path bypasses reserve.

#### 4. Probe Contention & Admission-Rate Impact (MAJOR 4 Verification)
- **Math & Lock Impact per Egress Address**:
  - Full probe range: 64,512 candidates.
  - Chunk size: 64 candidates per acquisition.
  - Total chunks per full cycle: $64512 / 64 = 1008$ mutex acquisitions.
  - Time per chunk (64 hashmap lookups + lock/unlock): $\approx 640\,\text{ns}$.
  - Continuous lock hold time is capped at $\approx 0.64\,\mu\text{s}$ (down from $\approx 600\,\mu\text{s}$ unchunked).
  - Yielding between chunks allows other worker threads admitting non-colliding flows (0 probes, $<50\,\text{ns}$ lock time) to proceed without lock starvation.
  - Cumulative lock time across all 1008 chunks for a probing thread is $\approx 0.665\,\text{ms}$, spread across 1008 micro-acquisitions.
- **Verdict**: Sufficient. Lock contention per acquisition is reduced by $\sim 1000\times$.

#### 5. False Exhaustion & Concurrent Probe Semantics (MINOR 5 Verification)
- **Exhaustion Exactness**: A deterministic 64,512-candidate walk starting from the atomic cursor and wrapping around guarantees all candidate ports in $[1024, 65535]$ are checked. Exhaustion is 100% exact for any static state (0 false negatives).
- **Concurrent Mints/Frees**:
  - Each worker probing candidate ports maintains its own local loop counter ($1024 + ((\text{start} + i) \pmod{64512})$), traversing an independent sequence of all 64,512 candidates.
  - Concurrent mints/frees by other workers do **not** cause the probing worker to skip or double-probe any candidate in its own cycle.
  - Concurrent frees of a previously passed candidate may cause the walk to conclude with `AllocatorExhausted` while that port is now free; this is a standard linearizability boundary in concurrent systems and does not violate correctness.
- **Verdict**: Exhaustion claim is exact. Correctness holds under concurrency.

#### 6. Observability Plumbing (MINOR 6 Verification)
- Adding `interface_snat_pat_collisions_total` and `interface_snat_identity_exhaustion_total` via `#[serde(rename = "...", default)]` in `[protocol/control.rs:343] (file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs#L343)` and `omitempty` in `[protocol_status.go:287](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_status.go#L287)` follows the exact `#1760` precedent.
- Additive and backward compatible per `#1961`.
- **Verdict**: Sufficient for operational Prometheus monitoring.

#### 7. Codex Round 2 Blockers & Shared Map Residual Hole Audit
- **Transactional Pre-Reserve & Two-Layer Overlap Foreclosure**: Successfully folded in v3.
- **Shared Map Residual Hole Audit**:
  - `remove_shared_session` callers: `afxdp/session_delta.rs:436/446`, `afxdp/session_glue/promote.rs:181`, `afxdp/session_glue/mod.rs:587/938/945`, `afxdp/ha/session_import.rs:314/329`, `afxdp/forwarding/local_delivery.rs:91`.
  - **Unwrapped Shared Map Mutations**:
    1. `publish_shared_session` (`[shared_ops.rs:921/932](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L921)`): `sessions.insert` overwrites and drops displaced entries without calling `remove_shared_session` $\rightarrow$ **Major 1 finding**.
    2. `stop_and_clear` / HA `clear_synced_state` (`[coordinator/mod.rs:756-767](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs#L756-L767)`): `nat_sessions.clear()` clears the map directly without calling `remove_shared_session` $\rightarrow$ **Major 2 finding**.

#### 8. Missing Elements in v3
- Explicit holder release handling for `publish_shared_session` displacement (`shared_ops.rs:921/932`).
- Explicit holder release/clear handling for `clear_synced_state` wholesale shared-map clears (`coordinator/mod.rs:756-767`).
