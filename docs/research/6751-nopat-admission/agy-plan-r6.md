# AGY hostile plan review — #6751 plan v6 (round 6)

PLAN-READY-WITH-NITS

---

### Executive Summary & Convergence Adjudication

V6 of the plan (`docs/research/6751-nopat-admission/plan.md`) successfully folds all 3 BLOCKERs and 1 MAJOR from Codex Round 5, as well as the 2 NITs from AGY Round 5. 

The architecture is complete, robust, and mathematically sound across all lifecycle state transitions. No BLOCKER or MAJOR issues remain open. The protocol guarantees continuous ownership holding, zero window for double-minting or early-freeing, strict cross-domain drain isolation, and fail-closed security posture.

---

### Analysis of the Six Verification Items

#### 1. Tuple-Versioned Records (§5.3)
- **Shape & Lifecycle**: Ownership records within the interface registry's allocator instances are keyed by `(SourceNatFlowKey, TranslatedTuple)` (`plan.md:297`). Pool allocators retain today's flow-keyed `SourceNatFlowKey` shape (`allocator.rs:481`).
- **End-to-End Staged Replacement Walkthrough**:
  1. *Coordinator*: Pre-reads canonical entry to obtain $T_{\text{old}}$ $\rightarrow$ pre-reserves $T_{\text{new}}$ (inserts `(flow, T_new)` with `{Shared}`) $\rightarrow$ replaces canonical row $\rightarrow$ executes alias sweep of $T_{\text{old}}$'s aliases $\rightarrow$ removes `{Shared}` from `(flow, T_old)`. $T_{\text{old}}$ remains held in registry by its `{Worker(W)}` markers; $T_{\text{new}}$ is held by `{Shared}`.
  2. *Worker*: Pre-reads existing entry's tuple $T_{\text{old}}$ via `translated_tuple_of(key)` $\rightarrow$ reserves $T_{\text{new}}$ (adds `{Worker(W)}` to `(flow, T_new)`) $\rightarrow$ performs in-table replacement in `SessionTable` (rendering $T_{\text{old}}$ unreachable) $\rightarrow$ releases $T_{\text{old}}$ (`−{Worker(W)}` on `(flow, T_old)`).
  3. *Stale-Drop*: When `(flow, T_old)`'s holder set empties, the record is removed.
- **Continuity**: $T_{\text{old}}$ is held continuously by worker holders until rendered unreachable; $T_{\text{new}}$ is held continuously by `{Shared}` and `{Worker(W)}` before becoming reachable.
- **Double-Count Hazard Analysis**:
  - *Caps (`max_tracked_flows`)*: `max_tracked_flows` counts active records. During the microsecond transient, a flow undergoing staged replacement holds 2 records. This transient +1 is bounded, safe, and correctly enforces total record capacity.
  - *Per-Index Drain Counter*: Each record carries its own authoritative `addr_index`. During staged replacement, if $T_{\text{old}}$ is on address index $i_1$ and $T_{\text{new}}$ is on address index $i_2$, $i_1$ maintains its live count (+1) until $T_{\text{old}}$ is released, while $i_2$ increments (+1). If both are on the same address $i$, the drain count temporarily increases by 1 and decrements upon $T_{\text{old}}$ release. There is zero risk of underflow, false drain completion, or double-freeing.

#### 2. Transactional Shared Replacement with Alias Sweep (§5.6)
- **Displacement Sweep Audit**: When `publish_shared_session` replaces an existing canonical row (`shared_ops.rs:907`), it extracts the displaced entry `displaced_canonical` ($T_{\text{old}}$).
- **Parity with `remove_shared_session`**: The displacement sweep in `publish_shared_session` mirrors `remove_shared_session` (`shared_ops.rs:960-1013`) exactly:
  - Checks `!displaced_canonical.metadata.is_reverse`.
  - Removes `reverse_wire` key derived from $T_{\text{old}}$.
  - Checks `reverse_canonical != reverse_wire` before removing `reverse_canonical`.
  - Checks `forward_wire != key` before removing `forward_wire` from `shared_forward_wire_sessions`.
- **Verdict**: Unreachable stale aliases derived from $T_{\text{old}}$ are wiped transactionally upon canonical publication of $T_{\text{new}}$, closing Codex r5 Blocker 2.

#### 3. Uniform Mint Quarantine (§5.7)
- **Quarantine Placement**: The quarantine check slots into `allocate_translation` (`allocator.rs:1012`), `reserve_address_only_roundrobin` (`allocator.rs:1848`), and `reserve_address_only_persistent` before claiming an address index/IP. If `is_quarantined(translated_ip)` is true, the address loop executes `continue` (skips the address).
- **Single-Probe Contract Preservation**: For address-persistent (sticky) pools, `address_attempts` is hardcoded to `1` (`allocator.rs:1011`, `allocator.rs:1831`, `source.rs:1528`). If the chosen address is quarantined, skipping it immediately terminates the loop and returns `AllocatorExhausted`. Sticky pools never rotate to a secondary sibling address, fully preserving the single-probe persistence contract. Non-sticky round-robin pools rotate past quarantined addresses to free siblings.

#### 4. MaterializeConflict (§5.6)
- **Failure Path Scoping**: In `session_glue/mod.rs:1128/1146/1227`, a reserve conflict during `materialize_shared_session_hit` returns a distinct `MaterializeConflict` outcome rather than `None`.
- **Caller Behavior**: `resolve_flow_session_decision` propagates `MaterializeConflict` directly to `poll_descriptor/mod.rs:432/903`, which enters an explicit packet recycle/drop branch instead of treating it as a session miss. The packet is never routed to the cold policy/NAT admission path.
- **Verdict**: Plan-level specification is complete and sufficient.

#### 5. Verification of Round 5 Nits
- **Prometheus Reason Label**: `plan.md:570` documents the `reason="flow_cap"` vs `reason="allocator_cap"` metric label as an optional implementation refinement.
- **`translated_tuple_of` Read Accessor**: `plan.md:430` and `plan.md:598` explicitly specify adding `SessionTable::translated_tuple_of(&self, key: &SessionKey) -> Option<TranslatedTuple>` to bypass the private `entry_by_key` helper at `session/mod.rs:1093`.

---

### Numbered Findings

#### 1. [NIT] Optional Prometheus Metric Sub-labeling for Registry Cap Exhaustion
- **Evidence**: `[userspace-dp/src/afxdp/coordinator/status.rs:241]`, `[pkg/api/metrics.go:791]`, `[plan.md:570]`.
- **Description**: `xpf_userspace_interface_snat_registry_cap_exhaustion_total` aggregates both per-address flow caps (64,512) and retained allocator caps (256).
- **Recommendation**: As noted in Section 5.8, adding `reason="flow_cap"` vs `reason="allocator_cap"` labels during code implementation will assist operational debugging when inspecting Grafana dashboards.

#### 2. [NIT] Dedicated Read Accessor for Staged Replacement Pre-read
- **Evidence**: `[userspace-dp/src/session/mod.rs:1093]`, `[userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:65]`, `[plan.md:430]`.
- **Description**: `SessionTable::entry_by_key` is private (`pub(crate)` visibility not present).
- **Recommendation**: Implement `translated_tuple_of(&self, key: &SessionKey) -> Option<TranslatedTuple>` directly on `SessionTable` in `session/mod.rs` as specified in Section 6 to cleanly support the worker-side staged replacement pre-read step.
