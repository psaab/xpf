# AGY hostile plan review — #6751 (round 15)

VERDICT: PLAN-NEEDS-REVISION

### 1. BLOCKER: Quarantine placement before `bulkRecv` bookkeeping causes live session drops during bulk reconcile and a nil-map panic on timeout admission
- **File:Line Evidence**: [`docs/research/6751-nopat-admission/plan.md:591,628`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L591-L628), [`pkg/cluster/sync_conn_read.go:110-117`](file:///home/ps/git/kimi-xpf/pkg/cluster/sync_conn_read.go#L110-L117), [`pkg/cluster/sync.go:1086-1126`](file:///home/ps/git/kimi-xpf/pkg/cluster/sync.go#L1086-L1126)
- **Analysis**:
  - `plan.md:591` specifies that signature quarantine evaluation runs at the `pkg/cluster` decode boundary *before* `bulkRecv` bookkeeping (`sync_conn_read.go:110`). Consequently, a quarantined frame's key is not recorded in `s.bulkRecvV4[key]`.
  - When `BulkEnd` arrives, `reconcileStaleSessions()` invokes `ReconcileClusterBulk` (`sync.go:1121`) with `ReceivedV4` missing that key. Any existing live session (such as a non-fabric identity-NPTv6 or self-NAT session) present in `s.sessions` prior to bulk sync will be deleted as stale by `ReconcileClusterBulk` at bulk completion ($t \approx 50\text{ ms}$).
  - Furthermore, `plan.md:628` states that timeout admission ($t = 5\text{ s}$) performs `bulk bookkeeping`. But by $t = 5\text{ s}$, `s.bulkRecvV4` has already been nil'd out at `sync.go:1090`, so writing `s.bulkRecvV4[key] = struct{}{}` will trigger an immediate runtime panic (`panic: assignment to entry in nil map`). If guarded against nil, bulk bookkeeping is skipped, but the session was already wrongfully deleted 4.9 seconds earlier during bulk reconciliation.
- **Required Fix**: `bulkRecv` bookkeeping must be recorded at decode time for all received frames regardless of quarantine status, and timeout admission must not attempt to modify `bulkRecv` post-bulk.

---

### 2. BLOCKER: Lossy-reorder open scenario (`alias` before `base`) fails to confirm alias because base installation does not check quarantine
- **File:Line Evidence**: [`docs/research/6751-nopat-admission/plan.md:614-624`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L614-L624), [`pkg/cluster/sync_conn_gen.go:435-462`](file:///home/ps/git/kimi-xpf/pkg/cluster/sync_conn_gen.go#L435-L462)
- **Analysis**:
  - `plan.md:614-624` states that alias confirmation checks the current store for a sibling canonical base at quarantine *insertion* (when the alias `A` arrives).
  - In the lossy-reorder case where alias `A` arrives before base `B`, `A` is quarantined because `B` is not yet in `s.sessions`.
  - When base `B` arrives shortly after and is installed via `installClusterSyncedV4/V6` (`sync_conn_gen.go:435`), the plan does not state that base installation must inspect the quarantine map for pending aliases. Without a reverse lookup on base installation, `A` remains unconfirmed in quarantine until its 5s timer expires.
  - Upon timeout, `A` is admitted as a canonical session, installing both `B` and `A` in `s.sessions` and re-creating the dual-session collision and broken synthesized companion hazard.
- **Required Fix**: Alias confirmation must be explicit in both directions: (1) quarantine insertion of an alias checks `s.sessions` for an existing base, AND (2) base installation in `installClusterSynced*` checks quarantine for pending aliases matching the base's derived forward-wire form.

---

### 3. MINOR: Incomplete counter inventory in §6 after adding sixth Go-side Prometheus counter in §5.8
- **File:Line Evidence**: [`docs/research/6751-nopat-admission/plan.md:832-840,860,868`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L832-L868)
- **Analysis**:
  - In v15, §5.8 was updated to add a sixth counter (`xpf_userspace_session_sync_alias_quarantine_admitted_total`).
  - However, §6 (lines 860 and 868) still refers to "the fifth §5.8 counter (alias-ignored)" as the sole Go-side Prometheus counter, omitting the newly added sixth counter.
- **Required Fix**: Update §6 text to reflect both Go-side Prometheus counters (fifth and sixth).

---

### Verification of Round-15 Verification Items

1. **SNAT Class Walk & Fabric Gate Removal**: Walking all SNAT classes (PAT, 1:1 Static NAT, Interface SNAT, DNAT, NAT64, Self-NAT, Identity-NPTv6) against `forward ∧ sync-derived ∧ SNAT flag ∧ NOT NAT64 ∧ key.src_ip == rewrite_src ∧ (key.src_port == rewrite_src_port OR rewrite_src_port == 0)` confirms that only Self-NAT and Identity-NPTv6 match among non-alias sessions. However, as noted in BLOCKER 1, quarantining Identity-NPTv6/Self-NAT sessions without updating `bulkRecv` at decode time leads to session drops during bulk reconcile and a nil-map panic on timeout admission.
2. **Ordering State Machine**: The close-ordering sequence (base delete then alias delete) works as designed under suppression. However, as noted in BLOCKER 2, the open-ordering sequence under lossy network reordering (`A` before `B`) wrongly admits `A` on timeout unless base installation performs a reverse lookup into quarantine.
3. **Capability Channel**: The pre-data `syncMsgCapability` frame with hold-until-known alias queueing is implementable at `daemon_ha_userspace_stream.go:373/400`. Fallback to `UNSUPPORTED` on timeout or frame loss safely degrades to legacy behavior without dropping sync.
4. **Timeout Admission**: Specified to re-enter the complete normal import path (`installGenGuard`, timestamp rebasing, config epoch check, coordinator reserve, helper dispatch) with its own counter `xpf_userspace_session_sync_alias_quarantine_admitted_total`. The interaction with `bulkRecv` post-BulkEnd must be corrected per BLOCKER 1.
