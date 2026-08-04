# AGY plan review — round 14 — #6749 armed-state plan v8.9 (6e2da70b98e1)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r14-prompt.txt assembled at 126,095 bytes). Raw output: /tmp/agy-6749-r14.out.

**Verdict: DEMAND-REVISION** (4 BLOCKER + 2 MAJOR + 1 MINOR).

---

### Evidence Requests

To fully audit the runtime edge cases of the v8.9 model beyond the provided snippets, access to the following full source files would have been required:
1. `pkg/configstore/store_persist.go:472-579` and factory-reset script routines — to inspect how helper persistence files are handled during configstore re-initialization.
2. `pkg/dataplane/userspace/manager_compile.go` and `process_status.go` — to trace all exit paths of `Compile()` and ensure `m.compileInFlight` state transitions are exception-safe.
3. `pkg/daemon/daemon_ha.go:774-783` — to inspect the exact method signatures and structs used by the HA controller to query manager state for takeover readiness.
4. `userspace-dp/src/server/handlers/mod.rs` — to verify the exact Serde deserialization and validation logic for `note_config_epoch` and `provenance`.

---

### Findings

#### 1. BLOCKER: Tying `config_epoch` to `archiveSeq` breaks Factory Reset via epoch-rollback refusal
- **Evidence:** `pkg/configstore/store.go:233-245` (`archiveSeq atomic.Uint64`, "It is a per-PROCESS counter that restarts at 0, so SetArchiveConfig seeds it from the highest seq on disk at startup"), `docs/research/6749-armed-state/plan.md` §5-C & §6 item 3 (epoch-rollback refusal: "helper REFUSES an `apply_snapshot` whose `config_epoch` is STRICTLY LESS than its stored epoch").
- **Rationale:** When a factory reset is executed, existing archive files on disk are pruned/deleted, causing `SetArchiveConfig` to reseed `archiveSeq` from 0. The first commit post-reset receives `archiveSeq = 1`. However, if the daemon/helper state on disk (or the running helper process) retains a stored `config_epoch` from prior operations (e.g. `42`), Go will send `apply_snapshot` with `config_epoch = 1`. The helper evaluates `1 < 42` and triggers its **epoch-rollback refusal**, rejecting the initial post-reset configuration fail-closed without mutating or persisting state. The entire dataplane remains permanently disabled following a factory reset until helper storage is manually purged.

#### 2. BLOCKER: `StartDeferredCompile()` leaves non-deferred compiles vulnerable to poll-driven defer corruption
- **Evidence:** `pkg/dataplane/userspace/manager_compile.go:326-332` (`if m.deferWorkers { snap.DeferWorkers = true }`), `docs/research/6749-armed-state/plan.md` §5-C (`StartDeferredCompile()` called at precheck point for deferred compiles; (v) latch echo skips only when `m.compileInFlight` is true).
- **Rationale:** `StartDeferredCompile()` sets `m.compileInFlight = true` at the daemon precheck point *only* when `rethMACPending` is true (deferred compiles). During a non-deferred compile (`rethMACPending == false`), `m.compileInFlight` remains `false`. `manager_compile.go` builds the snapshot payload outside `m.mu`. If a 1 Hz status poll executes while a non-deferred compile is building outside `m.mu` and observes `stored_defer_workers = true` from a prior unconsumed helper latch, it checks the (v) gate: `m.compileInFlight` is `false`, so it echoes `m.deferWorkers = true` into `Manager` state under `m.mu`. When the non-deferred compile acquires `m.mu` at `manager_compile.go:330`, it reads `m.deferWorkers == true` and stamps `snap.DeferWorkers = true`, corrupting a non-deferred compile into a deferred snapshot.

#### 3. BLOCKER: Operator-disarmed slots during MAC debt recovery create an infinite retry loop
- **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C ("The recovery debt CLEARS only on OBSERVED success — the post-rebind status showing the member's slots `bound+ready`").
- **Rationale:** If an interface member is in `macAndLinkRecovery` debt and an operator explicitly disarms it via `set_binding_state` (`activation_state = operator`, `armed = false`), the helper status for that member will continuously report `armed = false`. Because the MAC debt clear condition strictly requires observed status showing slots `bound+ready` (`armed == true`), the debt clear condition will never be satisfied. The recovery debt task will re-claim the member every 60s indefinitely, emitting edge Warns and executing netlink link cycles on an interface the operator explicitly disabled.

#### 4. BLOCKER: Helper ack-set eviction permanently strands Go's env resend suppression
- **Evidence:** `docs/research/6749-armed-state/plan.md` §4(i)(b) & §6 item 9 (helper retains bounded set $\le 4$ of rejected projections as `(identity, sample)` pairs; Go caches `(rejectedIdentity, rejectedGen)`).
- **Rationale:** The helper retains a maximum of 4 rejected projections in its environment watch set. If more than 4 projection candidates are rejected (e.g. across 5 sub-interfaces during unreadable sysfs states), older rejected projection entries (e.g. $P_1$) are evicted from the helper's retained watch set via replace-oldest. When sysfs recovers for $P_1$, the helper does not watch $P_1$, so `guard_env_generation` does not bump for $P_1$. Go's cache continues to suppress resending $P_1$ while waiting for a `guard_env_generation` bump that can never occur. $P_1$ is permanently suppressed and never retried.

#### 5. MAJOR: `note_config_epoch` lacks epoch-monotonicity validation and race protection
- **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (iii) & §6 item 6 (`ControlRequest.note_config_epoch`: helper sets stored `config_epoch` to it).
- **Rationale:** `note_config_epoch` transmits the staged commit sequence on content-dedup skips. If a racing full apply for a newer commit $C$ (`seq = 12`) completes before a delayed `note_config_epoch` for commit $B$ (`seq = 11`) arrives at the helper, an un-fenced `note_config_epoch(11)` will overwrite the helper's stored `config_epoch` backwards from 12 to 11. Conversely, if `note_config_epoch` enforces `note_config_epoch >= stored_epoch`, `note_config_epoch(11)` will be refused, causing Go's `FAILED/UNKNOWN transfer` handling to engage fail-closed divergence suppression unnecessarily.

#### 6. MAJOR: Missing daemon-to-manager API for fabric sync debt state in takeover readiness
- **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (i) ("daemon reads debt state through existing HA controller path"), `docs/research/6749-armed-state/plan.md` §6 (Go manager API additions list `StartDeferredCompile`, `ClaimMACDebtWork`, `ReportMACDebtAttempt`, but omit any fabric sync debt query interface).
- **Rationale:** `daemon_ha.go:774-783` checks takeover readiness by requiring `fabricPopulated` AND "no outstanding debt for the current projection". However, the plan fails to expose a method on `LinkController` or `Manager` for the daemon to query fabric sync debt state, leaving `daemon_ha.go` unable to perform this check.

#### 7. MINOR: `MACDebtWorkItem.Deadline` consumer semantics are unspecified
- **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C & §6 (`MACDebtWorkItem` struct includes `Deadline time.Time`).
- **Rationale:** The plan introduces `Deadline` on `MACDebtWorkItem` during `ClaimMACDebtWork()`, but never defines how the daemon execution queue consumes or enforces `Deadline` (e.g. whether expired items are dropped, retried, or bypassed).

---

DEMAND-REVISION
