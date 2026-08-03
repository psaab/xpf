# AGY hostile plan review — #6751 plan v8 (round 8)

PLAN-READY-WITH-NITS

---

### Convergence Adjudication Summary

Plan v8 ([`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md)) successfully resolves all BLOCKERs, MAJORs, and MINORs raised by Codex, SMR, and AGY in Round 7. No BLOCKERs remain open.

Below is the detailed item-by-item verification against the 7 adjudication criteria:

1. **Codex r7 B1 (Ownership-Equivalence Predicate & Session Identity)**:
   - **Verification**: In §5.6 ([`plan.md:520-538`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L520-L538)), the wire-alias predicate is now a four-part ownership predicate: (1) wire-form match, (2) identical `NatDecision`, (3) sync-derived origin, and (4) **same session identity**.
   - **Counterexample Re-run**: Colliding flow B's alias has `session_id = 202` while A's base record has `session_id = 101`. Clause (4) evaluates $202 \neq 101$ and fails the predicate. B's alias is not attached to A's record; instead, it enters as a standalone import, hits `IdentityConflict` against A's reservation of $T$, and drops.
   - **0/Legacy Fallback**: When `session_id == 0`, the fallback checks whether the base canonical row present at the canonical key contains an *identical session value*. Because [`userspaceForwardWireAliasV4`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L399-L405) carries the base's full value ($V(A_B) = V(S_B)$ containing internal host $H_B$), $V(S_B) \neq V(S_A)$ (which contains $H_A$). Thus, id-less colliding flows also fail the fallback check and cannot mis-attach.

2. **Codex r7 B2 (Multiplicity & Holder Counting)**:
   - **Verification**: §5.6 ([`plan.md:375-381`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L375-L381)) replaces `FxHashSet` with `HolderSet { per_worker: FxHashMap<u32, u16>, shared_rows: u16 }`.
   - **Arrival/Deletion Walk**:
     - *Base-first*: Base adds 1 to `shared_rows` and 1 to `per_worker[W]`; alias attaches and adds +1 to each (total = 2 for both).
     - *Alias-first*: Alias creates record (count 1); base arriving later adopts/merges the alias record via the both-direction rule ([`plan.md:548-558`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L548-L558)) and increments counts to 2.
     - *Delete-alias-first / Delete-base-first*: Either deletion decrements counts by 1 (remaining count = 1). The record identity is freed **only** when `shared_rows == 0` AND `per_worker` is empty.
     - *Duplicate delta replay*: Duplicate upserts hit the existing canonical/worker row and do not mint new holder rows.

3. **Codex r7 B3 (NAT64 Alias Class Scope)**:
   - **Verification**: Scoped OUT in §5.6 ([`plan.md:575-590`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L575-L590)) and §10 ([`plan.md:942-947`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L942-L947)). NAT64 decisions bypass the interface registry entirely (§5.3), so NAT64 alias reserves retain their shipped graceful-skip posture. Cross-family v4-in-v6 alias reconstruction is properly named as an independent follow-up candidate. This is an appropriate and safe scope boundary.

4. **Codex r7 M4 (Sweep Compare-and-Remove)**:
   - **Verification**: §5.6 ([`plan.md:564-574`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L564-L574)) specifies compare-and-remove ownership validation (verifying key + `NatDecision`) before deleting any swept derived slot, and §9 ([`plan.md:862-866`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L862-L866)) includes a third-party displacement unit test.

5. **Codex r7 m5/n6 (Persistent Lease Quarantine Gate & Wording)**:
   - **Verification**: §5.7 ([`plan.md:672-678`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L672-L678)) places the quarantine gate at the port-translating persistent lease decision ([`allocator.rs:1114`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs#L1114)). §9 ([`plan.md:860-862`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L860-L862)) updates the wording to state that different-tuple records are removed only by explicit holder release when their holder set empties.

6. **AGY r7 Nits & SMR r7 E1 Folds**:
   - Both-direction adopt/merge (§5.6 [`plan.md:548-558`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L548-L558)), out-of-order alias arrival test (§9 [`plan.md:870-873`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L870-L873)), and predicate `sync_derived` doc comment note (§5.6 [`plan.md:591-596`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L591-L596)) are fully incorporated.

---

### Ranked Findings

#### NIT 1 — Unit Test Scope for `session_id == 0` Predicate Fallback
- **Evidence**: [`plan.md:867-873`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L867-L873) (Section 9 Unit Test Plan); [`plan.md:528-532`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L528-L532) (§5.6 Predicate).
- **Detail**: When implementing unit tests for the four-part ownership predicate, ensure the suite explicitly tests both `session_id > 0` matching/mismatching AND `session_id == 0` legacy fallback matching (identical vs non-identical `SessionValue` internal 5-tuple) to verify both branches of clause (4).

#### NIT 2 — `shared_sessions` Lookup Note in Predicate Implementation
- **Evidence**: [`plan.md:528-532`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L528-L532); [`shared_ops.rs:73-100`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L73-L100).
- **Detail**: In the Rust implementation of the predicate helper, add a brief comment indicating that clause (4)'s legacy fallback performs a lookup against `shared_sessions` for the base canonical key to compare `SessionValue` equality.

---

### Conclusion
Plan v8 is fully converged, robust, and **PLAN-READY-WITH-NITS**. Implementation may proceed.
