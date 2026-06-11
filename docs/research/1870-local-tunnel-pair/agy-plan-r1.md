Here is the hostile adversarial plan review for **xpf issue #1870** based on a codebase inspection of the `/home/ps/git/bpfrx/.claude/worktrees/1870-research` worktree.

---

### A. Below-Cap Equivalence Verification
A line-by-line comparison of [install_with_protocol_with_origin](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L748-806) and [upsert_synced_with_origin](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L834-883) confirms that for `SyncImport` origin entries, their execution paths below-cap are behavior-identical:
1. **Delta Pushing**: In `install_with_protocol_with_origin`, the `push_delta` block ([session/mod.rs:795-804](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L795-804)) is gated by `!origin.is_peer_synced()`. Because `SyncImport` returns `true` for `is_peer_synced()` ([session/entry.rs:81](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/entry.rs#L81)), it suppresses the delta push. `upsert_synced_with_origin` has no delta push logic whatsoever.
2. **Local Clobbering**: With `allow_replace_local = true`, the only exit guard in `upsert_synced_with_origin` ([session/mod.rs:850-854](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L850-854)) is bypassed.
3. **Internal Mechanics**: Key-to-handle updates, secondary NAT indexes, epoch advances, and expiration scheduling ([session/mod.rs:878-881](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L878-881)) are functionally identical. 

### B. HA Interleaving & Local Clobber Correctness
The use of `allow_replace_local = true` for `UpsertLocal` is architecturally correct:
- **Local Authority**: Unlike synced remote replicas (`UpsertSynced`), `UpsertLocal` represents coordinator-driven local stack packets read from the TUN interface. If a local session (`ForwardFlow`/`ReverseFlow`) already exists for that key, it means routing has shifted this flow to the local tunnel. Failing to clobber it would leave the old non-tunnel forwarding state active, steering packets incorrectly.
- **Standby Overrides**: If a standby node receives a peer-synced entry but its local stack generates a packet under the same key, the local stack is authoritative for local processing. Thus, clobbering the standby's peer-synced copy is correct.

### C. `SessionTable::len() <= max_sessions` Invariant Check
- **Sizing & Allocation**: [SessionTable::new](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L205-233) initializes an empty slab (`entries: Slab::new()`) which grows dynamically rather than pre-allocating based on `max_sessions`. 
- **Telemetry & Gauges**: On the Go side ([buffersfmt.go:189](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/pkg/dataplane/userspace/buffersfmt.go#L189)) and Rust side, `max_sessions` is used strictly as a raw metric label or status reporting field. No code performs mathematical division or percentage calculations using `max_sessions` that could trigger division-by-zero or panic.
- **Precedent**: The `UpsertSynced` path already installs sessions uncapped, meaning the `len() <= max_sessions` invariant is already violated in practice today.

### D. Verification of `create_drops` Export
- At-cap drops on the `install_with_protocol_with_origin` path increment `self.create_drops` ([session/mod.rs:759](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L759)).
- This is exported via `wr_counters.session_create_drops = sessions.create_drops()` ([worker/loop_body/mod.rs:200](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L200)), aggregated at the server lifecycle level, and formatted as a Prometheus metric. The plan's assertion in Section 2.4 is **verified**.

### E. Adversarial Evaluation: Close-as-Fixed vs. Path A
We reject **close-as-fixed**. Path A is the only logically coherent architecture:
1. **Divergence Degradation**: Leaving the at-cap drop in place forces all subsequent packets of the affected local-tunnel flow to miss in the worker table and fall back to the shared map lookup ([session_glue/mod.rs:954](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L954)), incurring mutex overhead on every packet.
2. **Illogical Cap Enforcement**: The packet hot-path already materializes shared-map hits *uncapped* via [materialize_shared_session_hit](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L850). Because a matching packet will immediately install the session uncapped anyway, enforcing the cap on the coordinator's `UpsertLocal` command is futile and serves only to degrade performance for the first packet.
3. **Telemetry Cleansing**: Transitioning to Path A stops `session_create_drops` from reporting false-positive drops for sync-family replication events.

### F. Test Plan Sufficiency & #1855 Contract
The test plan (Section 5) is sufficient, but unit tests must use `assert!` to check the return value of `upsert_synced_with_origin` rather than `debug_assert!`. Under the `#1855` contract, `debug_assert!` compiles out in release profiles, meaning the infallibility invariant would go unverified during `cargo test --release`. The production code should still use `debug_assert!`.

---

### Findings List

1. **Medium (Design Assumption)**: The plan's argument regarding the "HA bulk-export gap" is partially incorrect. Local-tunnel sessions carry the `SyncImport` origin ([tunnel.rs:202](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/tunnel.rs#L202)), which is explicitly skipped in [export_forward_sessions_for_owner_rgs](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L427-457) regardless of worker table capacity. Therefore, their exclusion from bulk sync is a permanent design characteristic, not a cap-induced gap. The plan's justification in Section 2.3 and 11.1 should be corrected.
2. **Low (Test Implementation)**: Section 5 test assertions should use `assert!(installed)` in the test harness instead of relying on `debug_assert!` so that infallibility is actively verified in both release and debug profiles.

---

### Verdict
**PLAN-READY**
