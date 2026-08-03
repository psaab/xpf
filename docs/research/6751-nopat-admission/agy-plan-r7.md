# AGY hostile plan review — #6751 plan v7 (round 7)

PLAN-READY-WITH-NITS

### Adjudication & Findings

1. **Adjudication of Fabric Forward-Wire Alias End-to-End Lifecycle (Codex r6 BLOCKER Fold)**
   - **Export & Import**: Fabric redirect sessions are exported as two keys ([`daemon_ha_userspace_stream.go:370-376`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go#L370-L376)): the canonical key $K_{\text{base}}$ and forward-wire alias key $K_{\text{alias}}$. Both are processed via [`publish_shared_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L133) and worker fanout ([`session_import.rs:233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L233)).
   - **Reserve & Ownership**: Under v7 §5.6 ([`plan.md:479-513`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L479-L513)), $K_{\text{base}}$ mints/reserves record $R_{\text{base}}$ for `(flow_base, translated)`. When $K_{\text{alias}}$ arrives, the elevated wire-alias predicate ([`shared_ops.rs:73-130`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L73-L130)) evaluates to true (identical `NatDecision`, sync-derived origin, and $K_{\text{alias}} == \text{forward\_wire\_key}(K_{\text{base}})$). $K_{\text{alias}}$ attaches its holder markers (`{Shared}`, `{Worker(W)}`) directly to $R_{\text{base}}$.
   - **Tuple-Changing Re-Sync**: Coordinator pre-reserves $T_{\text{new}}$ on $R_{\text{new}}$, replaces canonical row $K_{\text{base}}$, and performs the transactional alias sweep. The alias sweep removes old index rows and predicate-checked explicit canonical alias row $K_{\text{alias}}$, decrementing holders on $R_{\text{old}}$. $R_{\text{old}}$ is freed only after all markers drop.
   - **Deletion**: Deleting $K_{\text{base}}$ decrements only $K_{\text{base}}$'s markers on $R_{\text{base}}$, leaving $K_{\text{alias}}$'s markers active. $R_{\text{base}}$ (and its allocated identity) is freed only when both $K_{\text{base}}$ and $K_{\text{alias}}$ are deleted. No early free or double mint exists.

2. **Predicate Under-Count & Standby Ownership Interaction**
   - The shipped exclusion at [`shared_ops.rs:73-100`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L73-L100) was originally documented as an accepted metric under-count on standbys. Elevating it to an admission predicate means a standby will attach a presented key matching an existing entry's wire-form to that base record if their `NatDecision`s match and at least one is sync-derived.
   - On the active/owner node, local mints have `sync_derived = false`, preventing local cross-session collisions from matching the predicate. Genuine collisions on the active node receive distinct PAT decisions (`NatDecision` mismatch), which causes subsequent sync imports on the standby to fail the predicate's `decision.nat` equality check. Thus, the standby's behavior is safe and does not create cross-session mis-attachments in practice.

3. **Idempotence & Secondary Index (Codex r6 MAJOR Fold)**
   - Section 5.3 ([`plan.md:298-322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L298-L322)) specifies the `flow -> SmallVec<records>` secondary index backing the local admission mint path.
   - Local mint re-entry queries the secondary index for `flow` and returns the locally-minted record for idempotent re-entry. `reserve` calls present `(flow, translated)` explicitly to hit the specific record, and `reserve` never auto-drops different-tuple records. This resolves Codex's r6 MAJOR completely.

4. **Review of Minor/Nit Folds**
   - **Fixed-Address Fail-Closed Modes**: §5.7 ([`plan.md:586-593`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L586-L593)) explicitly specifies that address-persistent/sticky pools, deterministic CGNAT, persistent NAT, and deterministic NAT64 fail closed when their selected address is quarantined.
   - **MaterializeConflict Wording**: §5.6 ([`plan.md:410-419`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L410-L419)) and §7 ([`plan.md:702-704`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L702-L704)) accurately reflect that `MaterializeConflict` routes to an explicit recycle/drop branch and never becomes a cold-admission miss.
   - **Reverse-Companion Bound & Qualification**: §5.6 ([`plan.md:520-525`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L520-L525)) and §7 ([`plan.md:723-726`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L723-L726)) qualify the reverse-companion lag as queue/relay-or-expiry bounded and restrict identity lifetime assertions to holder-bearing forward replicas.
   - **Alias-Sweep & Sticky Pool Nits**: §5.6 ([`plan.md:442-444`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L442-L444)) filters same-tuple refreshes, and §5.7 ([`plan.md:586-589`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L586-L589)) enforces non-rotation for sticky pools.

---

### Detailed Findings

1. **NIT — HA Stream Import Out-Of-Order Fabric Alias Test Assertion**
   - **Evidence**: [`plan.md:784-793`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L784-L793) (Section 9 Unit Test Plan); [`session_import.rs:133`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L133).
   - **Detail**: The test plan specifies verifying that alias import attaches markers to the base record without false `IdentityConflict`. When implementing the unit tests in `ha/session_import.rs`, ensure the test explicitly verifies out-of-order stream delivery ($K_{\text{alias}}$ arriving before $K_{\text{base}}$) to confirm that holder attachment and record creation remain symmetric regardless of message arrival order.

2. **NIT — Code Annotation for Standby Wire-Alias Predicate Scope**
   - **Evidence**: [`plan.md:492-505`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L492-L505); [`shared_ops.rs:73-130`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L73-L130).
   - **Detail**: In the implementation of the shared wire-alias predicate helper, add a brief doc comment highlighting that `sync_derived` origin check ensures active local mints never mistake a local cross-session collision for a fabric forward-wire alias.

---

### Summary
All BLOCKERs and MAJORs from prior rounds are fully resolved in v7. Plan v7 is sound, comprehensive, and ready for implementation.
