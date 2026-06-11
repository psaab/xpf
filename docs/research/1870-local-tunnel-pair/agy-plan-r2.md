I will list the contents of the local-tunnel-pair research directory to locate the plan and review files.
I will read the v2 implementation plan from the workspace.
I will view the round-1 findings file `agy-plan-r1.md`.
I will search for `materialize_shared_session_hit` in the codebase to find its definition and location.
I will view the `session_glue/mod.rs` code around the definition of `materialize_shared_session_hit` and the hit resolution/lookup code.
I will search for `should_keep_synced_hit_transient` in the codebase to find its definition.
I will view `session_glue/promote.rs` to read the definition of `should_keep_synced_hit_transient`.
I will view the beginning of `promote.rs` to see how `is_translated_forward_session_key` is implemented.
I will search for the definition of `maybe_enqueue_local_tunnel_session` in `tunnel.rs` to see the structure of local-tunnel session decisions and metadata.
I will view `userspace-dp/src/afxdp/tunnel.rs` to see how local-tunnel sessions are created and populated.
I will view lines 140 to 250 of `userspace-dp/src/afxdp/tunnel.rs` to see how `LocalTunnelTxPlan` and its session entries are created.
I will search for `synthesized_synced_reverse_entry` to see how the reverse session is constructed.
I will view the definition of `synthesized_synced_reverse_entry` in `shared_ops.rs`.
I will search for `is_peer_synced` to see which origins return true.
I will view `userspace-dp/src/session/entry.rs` to see `is_peer_synced` and other `SessionOrigin` helpers.
I will search for `owner_rg_is_locally_active` to see how it determines if an RG is active.
I will view the definition of `owner_rg_is_locally_active` in `session_glue/mod.rs`.
I will search for `struct NatDecision` to verify the default values of `rewrite_src` and `rewrite_dst`.
I will view the `NatDecision` struct definition in `userspace-dp/src/nat/mod.rs` to see its fields.
I will search for the definition of `upsert_synced_with_origin` to verify if it enforces `max_sessions`.
I will view the `upsert_synced_with_origin` function in `userspace-dp/src/session/mod.rs` to verify if it has any cap checks.
I will perform a search for `SharedMaterialize` to find all places in the Rust codebase where its behavior is checked or handled.
I will search for `SyncImport` in the codebase to see if it has special paths that `SharedMaterialize` does not.
I will search for usage of `origin` in `userspace-dp/src/session/mod.rs` to understand behavior differences.
I will view lines 890 to 1030 of `userspace-dp/src/session/mod.rs` to see the logic for promotion and updating of synced entries.
I will view lines 1030 to 1100 of `userspace-dp/src/session/mod.rs` to see the definitions of `refresh_local`, `promote_synced_with_origin`, and `upsert_synced_with_origin`.
I will search for `promote_synced_with_origin` to locate its definition in `session/mod.rs`.
I will view lines 1145 to 1180 of `userspace-dp/src/session/mod.rs` to see how `promote_synced_with_origin` works.
I will search for `is_peer_synced` in `session_glue/mod.rs` to see what depends on peer-synced origins there.
I will view lines 420 to 460 of `userspace-dp/src/afxdp/session_glue/mod.rs` to see `export_forward_sessions_for_owner_rgs`.
I will search for `session_timeout_ns` in the codebase to see if timeouts depend on `SessionOrigin`.
I will view `session_timeout_ns` in `userspace-dp/src/session/mod.rs` to see its parameters.
I will search for the expiration purging logic in `session/mod.rs` to see if there is any origin-based differentiation.
I will search for `expire` or `wheel` in `session/mod.rs` to find how expirations are handled.
I will view lines 510 to 550 of `userspace-dp/src/session/mod.rs` to see how expired sessions are handled.
I will search for usage of `expire_stale_entries` or `expire_stale` across the codebase to see how expired sessions are processed.
I will view `loop_body/mod.rs` around line 573 to see how expired sessions are processed.
I will search for the definition of `delete_session_map_entry_for_removed_session_with_origin`.
I will view lines 1040 to 1080 of `userspace-dp/src/afxdp/bpf_map/mod.rs`.
I will search for `uses_kernel_local_session_map_entry` to see if there is origin-specific logic.
I will view the beginning of `userspace-dp/src/afxdp/bpf_map/mod.rs` to see `uses_kernel_local_session_map_entry`.
I will view lines 810 to 835 of `userspace-dp/src/session/mod.rs` to see what happens around line 824.
I will view lines 1240 to 1270 of `userspace-dp/src/session/mod.rs` to see what is happening around line 1252.
I will view `userspace-dp/src/server/helpers.rs` around line 388 to see if origin is used in serialization or metrics.
I will search for `SyncImport` or `SharedMaterialize` in Go files to see if the Go side distinguishes between them.
I will search for the word `origin` in Go files to see how the session origin is handled on the Go side.
I will search for `origin` in `pkg/api` to see if API objects represent the session origin.
I will search for `origin` in `pkg/grpcapi/server_sessions.go` to see if the grpcapi handles it.
I will search for `allow_replace` in the test files to see what is already covered.
I will search for `upsert_synced_with_origin` in `userspace-dp/src/session/tests.rs` to see what is currently tested.
I will search for `upsert_synced` in `session/tests.rs` to see what tests exist.
I will view `userspace-dp/src/session/tests.rs` around lines 830 to 920 to see the existing coverage for `upsert_synced`.
I will search for `session_create_drops` in `pkg/api/metrics_descriptors.go` to see what is currently defined.
I will search the workspace for `metrics_descriptors.go` to find its exact path and contents.
I will search for `metrics_descriptors.go` in the current worktree.
I will view the `pkg/api` directory in our worktree to check if `metrics_descriptors.go` is present.
I will search for `create_drops` in `metrics_descriptors.go` to locate the help text.
I will view `metrics_descriptors.go` around lines 545 to 630 to inspect the metric descriptors and help text for `session_create_drops`.
I will search for `workerSessionCreateDrops` in the Go files to see how it is defined, registered, and used.
I will search for `workerSessionCreateDrops` inside the worktree's `pkg` directory.
I will view lines 820 to 840 of `pkg/api/metrics_userspace.go` to see the telemetry data mapping for `workerSessionCreateDrops`.
### (1) Claim Verification: `materialize_shared_session_hit` Self-Healing and `should_keep_synced_hit_transient` Blocking

We verified the self-healing and blocking behavior against the codebase:
- **Uncapped Materialization**: In [`userspace-dp/src/afxdp/session_glue/mod.rs:949`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L949), a traversing packet that hits the shared scope calls [`materialize_shared_session_hit`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L850-L876). This calls [`upsert_synced_with_origin`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L834-L880), which contains no capacity checks (unlike `install_with_protocol_with_origin` at [lines 758-761](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L758-L761)). Because the proactive prewarm pair was dropped at cap, no entry exists under this key in the worker table. Thus, the clobber guard at [`userspace-dp/src/session/mod.rs:850-854`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L850-L854) is bypassed even with `allow_replace_local = false`.
- **Transient Check**: [`should_keep_synced_hit_transient`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/promote.rs#L48-L59) is evaluated at [`userspace-dp/src/afxdp/session_glue/mod.rs:932-934`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L932-L934). It returns `true` if and only if:
  ```rust
  origin.is_peer_synced()
      && !owner_rg_is_locally_active(ha_state, metadata.owner_rg_id, now_secs)
      && is_translated_forward_session_key(key, decision, metadata)
  ```
  However, [`is_translated_forward_session_key`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/promote.rs#L32-L41) checks if the session key is translation-active:
  ```rust
  decision.nat.rewrite_src == Some(key.src_ip) || decision.nat.rewrite_dst == Some(key.dst_ip)
  ```
  Because local-tunnel sessions carry `decision.nat = NatDecision::default()` (which contains `None` for all rewrite IPs, as shown in [`userspace-dp/src/nat/mod.rs:48-52`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/nat/mod.rs#L48-L52)), `is_translated_forward_session_key` is guaranteed to return `false` for both the forward and reverse local-tunnel entries.
- **Verdict**: `should_keep_synced_hit_transient` **never** blocks local-tunnel `SyncImport` entries. The self-healing materialization path works infallibly on the first traversing packet.

---

### (2) Behavioral Differences: `SyncImport` vs. `SharedMaterialize`

We traced the behavior of `SyncImport` and `SharedMaterialize` (defined in [`userspace-dp/src/session/entry.rs:54-55`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/entry.rs#L54-L55)):
- **Identical Behaviors**:
  - **Promotion**: Both return `true` for `is_promotable_synced()` ([entry.rs:85-87](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/entry.rs#L85-L87)). Both allow promotion to `SharedPromote` and emit an open delta because `was_peer_synced = old_origin.is_peer_synced()` evaluates to `true` for both ([session/mod.rs:1013](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L1013)).
  - **Demote/Refresh**: Normal local refreshes via `refresh_local` are rejected for both because both are peer-synced ([session/mod.rs:947-964](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L947-L964)). Under HA activation updates, both preserve their origins. `demote_owner_rg` skips both because both are already peer-synced ([session/mod.rs:1251](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L1251)).
  - **Export**: Both are skipped by `export_forward_sessions_for_owner_rgs` because `origin.is_peer_synced()` is `true` for both ([session_glue/mod.rs:440](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/session_glue/mod.rs#L440)).
  - **GC**: Neither triggers a Close delta when purged during GC because `!removed.origin.is_peer_synced()` evaluates to `false` for both ([session/mod.rs:524](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L524)).
  - **BPF Map Deletion**: `uses_kernel_local_session_map_entry` evaluates both identically ([bpf_map/mod.rs:8](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/afxdp/bpf_map/mod.rs#L8)).
- **Actual Differences**:
  1. **Semantic Labeling**: `SyncImport` represents a session proactively sync-imported (either via HA peer sync or coordinator prewarm). `SharedMaterialize` represents a session reactively materialized from a shared map hit on a packet flow.
  2. **Strings**: `"sync_import"` vs `"shared_materialize"`, visible in expiration logging (`SESS_EXPIRE` at [`userspace-dp/src/session/mod.rs:518`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/mod.rs#L518)).
  3. **Transition Rules**: When fanning out/replicating via peer worker commands, a local `SharedMaterialize` entry transitions to `SyncImport` replica origin ([entry.rs:89-91](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/userspace-dp/src/session/entry.rs#L89-L91)).

---

### (3) Sufficiency of Section 5 Test Plan and `#1855` Contract

The 6 proposed tests in Section 5 are sufficient to guard against regression:
- Tests 1–3 verify at-cap, fan-out, and cap-1 boundary (partial pair) installs.
- Test 4 pins correct replacement semantics of existing local entries below cap.
- Test 5 pins the exclusion of local-tunnel entries from bulk export.
- Test 6 verifies session-level infallibility under cap bounds.
- **`#1855` compliance**: Because `upsert_synced_with_origin` uses `debug_assert!` internally (which is compiled out in release profiles), test assertions are implemented via client-side `assert!` on outcomes, ensuring correctness under `cargo test --release`.

---

### (4) Go-Side Scope Verification

- **Counter Mapping**: In [`pkg/api/metrics_userspace.go:830-831`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/pkg/api/metrics_userspace.go#L830-L831), the `workerSessionCreateDrops` metric reads from `w.SessionCreateDrops`. 
- **Wire/Series Integrity**: Since Path A changes the Rust-side call flow (so the worker stops incrementing `create_drops` for `UpsertLocal`), the metric value will naturally stop counting these drops. No changes are required to Go struct fields, serialization code, or proto files.
- **Required Changes**: Only the description help-text at [`pkg/api/metrics_descriptors.go:559`](file:///home/ps/git/bpfrx/.claude/worktrees/1870-research/pkg/api/metrics_descriptors.go#L559) needs to be updated to remove the reference to `"UpsertLocal replicas"`.

---

### Findings List

1. **Low (Test coverage)**: While Test 4 (`upsert_local_below_cap_replaces_existing_local_entry`) asserts replacement semantics below cap, it should also assert replacement *at cap* (i.e. table at capacity, local entry exists, new local-tunnel entry replaces it). Because `upsert_synced_with_origin` is uncapped, this is theoretically correct but should be explicitly pinned in the test suite to guard against future cap regressions.
2. **Low (Documentation)**: The README updates described in Section 7 must be thoroughly synchronized with the new metric behavior to prevent developer confusion regarding the change in `create_drops` contributors.

---

### Verdict
**PLAN-READY**
