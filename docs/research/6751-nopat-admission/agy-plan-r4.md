# AGY hostile plan review — #6751 plan v4 (round 4)

PLAN-NEEDS-REVISION

---

### Executive Summary & Round 4 Verification

Plan v4 successfully resolves Round 3 AGY Major 1 (publish displacement) by decoupling `{Shared}` from reverse-index maps and pinning it exclusively to the canonical `shared_sessions` map. It also incorporates exact chunked PAT probing with mutation-epoch retries, transactional coordinator pre-reservation, and reserve-before-install worker wrappers.

However, **two critical lifecycle leaks remain**:
1. **`stop_workers` drops worker local tables without releasing `{Worker(W)}` holders**, leaving identity tokens leaked in `InterfaceNatAllocators` across rebind cycles even after `{Shared}` is released.
2. **The drain model's release scan ignores draining allocators when a pool configuration is edited**, permanently trapping interface addresses in fail-closed quarantine.

---

### Verification of Round 4 Audit Items

#### 1. AGY Round 3 MAJOR 1 (Publish Displacement) — Verified Resolved
- **Verification**: In `[userspace-dp/src/afxdp/shared_ops.rs:905-909](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L905-L909)`, `shared_sessions` (canonical map) is keyed strictly by forward `SessionKey`. Two colliding internal hosts (H1 and H2) produce distinct forward keys `(H1 -> S)` and `(H2 -> S)`. Insertion into `shared_nat_sessions` (reverse index at lines 921/932) displaces reverse index entries, but reverse index displacement is now a non-event for holder tracking.
- **Canonical Same-Key Displacement**: Any `shared_sessions.insert` returning `Some(existing)` is a same-key update (refresh/re-publish of the same logical flow); `{Shared}` set-insertion is idempotent.
- **Removal Inventory**: All 7 callers of `remove_shared_session` (`session_delta.rs:436/446`, `promote.rs:181`, `session_glue/mod.rs:587/938/945`, `session_import.rs:314/329`, `local_delivery.rs:91`) invoke `sessions.remove(key)` on `shared_sessions`, cleanly triggering `-Shared` removal for the canonical row.

#### 2. AGY Round 3 MAJOR 2 (Wholesale Clear) — Insufficient (Finding 1)
- **Verification**: `stop_workers` (`[server/handlers/stop_workers.rs:7](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/stop_workers.rs#L7)`) invokes `workers.stop_and_clear` (`[coordinator/worker_manager.rs:141] (file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/worker_manager.rs#L141)`), which joins worker threads. Worker threads exit and drop their local `SessionTable` stack frames **without running release routines** for `{Worker(W)}`.
- **Hole**: v4 §5.6 specifies walking `shared_sessions` to release `-Shared` before `clear_synced_state` at `[coordinator/mod.rs:756-766](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs#L756-L766)`. However, because every active session holds both `{Worker(W)}` and `{Shared}`, removing `{Shared}` alone leaves `{Worker(W)}` registered in `InterfaceNatAllocators.holders`. When workers rebind and restart, old identity allocations remain locked by abandoned `{Worker(W)}` markers.

#### 3. AGY Round 3 NIT 3 (Churn Cap) — Verified Sufficient
- **Verification**: Defining the cap as 256 currently-retained `Arc<PortAllocator>` instances in `InterfaceNatAllocators` (map cardinality, not lifetime cumulative creations) with opportunistic reclaim when a release leaves an absent allocator empty correctly bounds memory usage under WAN IP rotation.

#### 4. Codex Round 3 Blocker 1 Fold (Drain Model) — Flawed under Pool Edits (Finding 2)
- **Scenario Analysis**:
  - **(a) DHCP Address Removal/Re-addition**: Coherent. $A_P$ remains in `draining[E]` until `live_count == 0`. Re-adding E continues failing interface mints closed until drain completes.
  - **(b) Pool Edited / Removed while Draining (BUG)**: Pool $P_1$ overlapping interface address E is edited/removed during a config recompile while flows are active. $A_{P1}$ is moved to `draining[E]`. When active pool sessions release, `release_source_nat_allocation_with_mode` (`[nat/source.rs:781-835](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L781-L835)`) iterates only active `rules`. Since $A_{P1}$ is no longer in `rules`, `release_flow` is never called on $A_{P1}$. $A_{P1}$'s live count never reaches 0, trapping interface address E in permanent `InterfaceOverlapDraining` fail-closed quarantine.
  - **(c) Two Overlapping Pools**: Coherent. `draining[E]` holds a vector of allocators $[A_{P1}, A_{P2}]$ and quarantine lifts when both empty.

#### 5. Codex Round 3 Blocker 3 Fold (Reserve-Before-Install Wrapper) — Verified Resolved
- **Race Walk**: Stale queued `UpsertSynced` commands arriving after a coordinator delete + local mint encounter `reserve_synced_source_nat_allocation` first. Because the local flow holds the identity, flow-keyed discrimination fails the reserve, dropping the `UpsertSynced` command before installation.
- **Upstream Gap Behavior**: Dropping an `UpsertSynced` command leaves the session uninstalled on that specific worker. If failover occurs to that worker, inbound packets hit a local lookup miss (NO_SESSION) and follow standard TCP RST / connection re-establishment without security or confidentiality compromise.

#### 6. Codex Round 3 Major 5 Fold (Exact Probe) — Verified Resolved
- **Verification**: Local start ordinal capture, 64-candidate micro-acquisitions, and yielding prevent lock starvation. Capturing `mutation_epoch` before the walk and retrying once if `mutation_epoch` advances guarantees exact proof of exhaustion for stable states while bounding retry work under churn to 2 full cycles (2016 acquisitions).

#### 7. Core Invariant Falsification — Falsified on Lifecycle Transitions
- **Invariant**: *"every reachable session owns exactly one translated identity, held continuously from before it is reachable until after it is not."*
- **Falsification Paths**:
  1. **`stop_workers` Rebind Cycle**: Stale `{Worker(W)}` holders persist in `InterfaceNatAllocators` long after sessions cease to exist or be reachable in any table.
  2. **Pool Edit during Drain**: Active pool flows expiring after a pool config edit fail to decrement their draining allocator, keeping identity reservations active indefinitely after sessions have closed.

---

### Numbered Findings

#### 1. [MAJOR] Leaked `{Worker(W)}` Holders Across `stop_workers` / Rebind Cycles
- **Evidence**: `[userspace-dp/src/afxdp/coordinator/mod.rs:756-767](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs#L756-L767)` (`stop_inner` / `clear_synced_state`), `[userspace-dp/src/afxdp/coordinator/worker_manager.rs:141-167](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/worker_manager.rs#L141-L167)` (`stop_and_clear`).
- **Impact**: `workers.stop_and_clear` joins worker threads whose local `SessionTable`s drop without invoking release routines for `{Worker(W)}` holders. v4 §5.6 iterates `shared_sessions` to release `{Shared}` holders before clearing, but omits releasing `{Worker(W)}` holders. Because every active session carries at least one `{Worker(W)}` holder, `{Worker(W)}` markers remain in `InterfaceNatAllocators.holders`, permanently leaking identity allocations across link stop→rebind cycles.
- **Remediation**: `clear_synced_state` (or worker teardown) must clear/reset `InterfaceNatAllocators` or release all registered `{Worker(W)}` holders when all worker tables and shared maps are wiped.

#### 2. [MAJOR] Draining Allocator Release Scan Omission Traps Interface Addresses in Permanent Quarantine
- **Evidence**: `[userspace-dp/src/nat/source.rs:781-835](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L781-L835)` (`release_source_nat_allocation_with_mode`), `[userspace-dp/src/afxdp/coordinator/session_manager.rs:12](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/session_manager.rs#L12)`.
- **Impact**: When a source pool overlapping an interface address is marked unusable, its allocator $A_P$ is retained in `InterfaceNatAllocators.draining[E]`. If the pool rule is modified or removed during a config recompile while sessions remain live, $A_P$ is no longer present in `forwarding.source_nat_rules`. `release_source_nat_allocation_with_mode` iterates only active `rules`, missing $A_P$. Consequently, releases for expiring pool flows never decrement $A_P$'s live count, $A_P$ never reaches 0, and `draining[E]` never clears, permanently locking interface address E in `InterfaceOverlapDraining` fail-closed quarantine.
- **Remediation**: Include `InterfaceNatAllocators.draining` allocators in the `release_source_nat_allocation_with_mode` search path so expiring pool flows correctly decrement draining allocators.

#### 3. [MINOR] Unhandled `{Shared}` Cleanup on Worker-Side Reserve Refusal
- **Evidence**: `[userspace-dp/src/afxdp/ha/session_import.rs:133](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L133)`, `[userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:65](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L65)`.
- **Impact**: If coordinator pre-reserve succeeds and attaches `{Shared}`, but worker-side `install_synced_with_reserve` fails to reserve `{Worker(W)}` and drops `UpsertSynced`, `{Shared}` remains attached to `shared_sessions` until external HA delete or session expiration. While safe (fails closed and prevents misdelivery), it leaves an asymmetry where a worker-rejected entry continues holding `{Shared}` on the coordinator.
- **Remediation**: Document this as accepted coordinator state or add worker feedback to clear `{Shared}` if all workers reject installation.

---

### What v4 is still missing (file:line inventory)

1. **`userspace-dp/src/afxdp/coordinator/mod.rs:756-767` & `userspace-dp/src/afxdp/coordinator/worker_manager.rs:141-167`**: Worker table teardown does not release `{Worker(W)}` holders, and `clear_synced_state` only releases `{Shared}`. Missing explicit registry reset/clear on wholesale teardown.
2. **`userspace-dp/src/nat/source.rs:781-835`**: `release_source_nat_allocation_with_mode` iterates only active rule allocators. Missing inclusion of `InterfaceNatAllocators.draining` allocators in the release scan.
