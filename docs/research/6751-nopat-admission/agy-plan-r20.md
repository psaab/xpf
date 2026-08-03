# AGY hostile plan review — #6751 (round 20)

**VERDICT: PLAN-READY-WITH-NITS**

---

### Analysis & Adjudication

#### 1. Normative Contract Verification (§5.6)
* **Status**: **VERIFIED PRESENT AND NORMATIVE**
* In [plan.md](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L686-L746), §5.6 explicitly specifies the six-clause normative transition contract:
  1. **Fence state**: Atomic `abort_generation` counter + `fenced` flag in the connection registry updated on the serialized event loop.
  2. **Admission verdicts**: `installConn` returns `ADMITTED`/`REFUSED`. Refused connections immediately close with zero pending-frame dispatch, zero receive loop launch, zero clock sync, zero lifecycle callbacks, and zero cold-prime work. `handleNewConnection` at [sync_conn.go:130](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L130) is made conditional on `ADMITTED`.
  3. **Install-before-dispatch**: Pending first frame dispatch is reordered from before `installConn` ([sync_conn.go:119](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L119)) to *after* `installConn` ([sync_conn.go:130](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L130)) and carries the Clause (4) generation guard.
  4. **Commit-time generation validation**: Every stateful frame application re-checks the frame's slot-stamped generation against the registry's current `abort_generation` at the commit point. Discards any frame carrying an older generation or arriving while `fenced == true`.
  5. **Reset-once ownership**: Bulk, quarantine, and capability state resets run exactly once inside the serialized loop owned by the fence transition. Nested aborts re-arm at higher generations or no-op if generation hasn't advanced.
  6. **Peer convergence**: Reconnect attempts during a fence are refused; peers land after cleanup on the empty→connected cold-prime edge ([sync_conn.go:139/551](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L139), [sync_bulk.go:65](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go#L65)).

#### 2. Structural Completeness & Commit-Time Coverage
* **Status**: **VERIFIED COMPLETE**
* Analyzed against frame dispatch in [sync_conn_read.go:91](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L91), session installs at `:109`, bulk state mutations at `:183`, disconnect handling in [sync_conn.go:483/496/551](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L483), and cold-prime bulk drives in [sync_bulk.go:65](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go#L65).
* All state-mutating frame types (`syncMsgSessionV4/V6`, `syncMsgDeleteV4/V6`, `syncMsgBulkStart`, `syncMsgBulkEnd`, `syncMsgBulkAck`, `syncMsgConfig`, `syncMsgIPsecSA`, `syncMsgCapability`, and pending first frame) run on the serialized receive loop or ordered queues and pass through Clause (4)'s commit-time guard. No mutation path bypasses generation validation.

#### 3. Clause (4) Commit-Time Slot-Stamped Generation Soundness
* **Status**: **VERIFIED SOUND**
* Each connection slot is stamped at admission in `installConn` with `slot.gen = current_abort_gen`.
* Any abort increments `abort_generation` and arms the fence. Frames buffered on a connection slot created before the abort carry `slot.gen < new_abort_gen`.
* At the commit point on the serialized receiver loop, the guard checks `slot.gen == current_abort_gen && !fenced`. A stale slot's frame carries `slot.gen < current_abort_gen` and is unconditionally discarded at commit, even if the receive handler passed a pre-dispatch check or stalled across a reset. Stale slot generations cannot validate.

#### 4. Clause (2) Verdict Plumbing
* **Status**: **VERIFIED COMPLETE**
* In production code, `handleNewConnection` at [sync_conn.go:130](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L130) is the sole caller of `installConn`.
* Test callers in `pkg/cluster/sync_conn_race_4962_test.go` will be updated to check/assert the returned verdict. No production caller ignores `ADMITTED`/`REFUSED` verdicts.

---

### Findings

1. **NIT 1 — §5.8 Go-Side Counter Inventory Bullet List Completeness**
   * **Location**: [plan.md#L995-L1035](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L995-L1035)
   * **Description**: Section 5.8 states that there are "THREE GO-side Prometheus counters" ([plan.md:1003](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1003)). Section 5.6 ([plan.md:640](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L640)) and Section 9 ([plan.md:1284](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1284)) define all three (`xpf_userspace_session_sync_forward_wire_alias_ignored_total`, `xpf_userspace_session_sync_alias_quarantine_admitted_total`, and `xpf_userspace_session_sync_alias_quarantine_overflow_total`). However, §5.8's bullet list at lines 1025-1035 explicitly formats bullet items for the first two counters, mentioning overflow in §5.6 without an explicit third bullet item in §5.8.
   * **Recommendation**: Add a explicit bullet in §5.8 for `xpf_userspace_session_sync_alias_quarantine_overflow_total` matching the existing bullets for completeness.
