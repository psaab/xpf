# AGY hostile plan review — #6751 (round 10)

PLAN-READY-WITH-NITS

---

### Round 10 Convergence Adjudication Findings

#### 1. VERIFICATION — Codex r9 BLOCKER: Zero-ID Alias-First Wire-Form-Yield Rule Walk
- **Status**: **RESOLVED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:533-566`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L533-L566); [`userspace-dp/src/afxdp/ha/session_import.rs:133-233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L133-L233); [`userspace-dp/src/afxdp/shared_ops.rs:678-738`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L678-L738).
- **Rule Verification & Scenario Walks**:
  - **Rule Definition**: v10 §5.6 specifies that between two zero-id imports attempting to claim the same translated identity $E$:
    - **(i)** If one presented key is the forward-wire form of the other under identical `NatDecision`, the canonical-form import **wins** via both-direction adopt/merge regardless of arrival order.
    - **(ii)** If neither key is the other's wire form, it is a genuine collision: first-wins, second receives `IdentityConflict` and **drops**.

  - **Scenario (a) — Legit Alias-First Arrival Walk**:
    1. Zero-id alias $S1_{\text{alias}}$ ($E \to S$, NatDecision $N$) arrives first. No existing session holds identity $E$, so $S1_{\text{alias}}$ reserves identity $E$ and publishes a canonical row at key $E \to S$ into `shared_sessions`.
    2. Zero-id base $S1_{\text{base}}$ ($H \to S$, NatDecision $N$) arrives second. It attempts to reserve identity $E$ and hits an identity conflict with $S1_{\text{alias}}$.
    3. Both entries have zero IDs, triggering rule (i). Key $E \to S$ IS the forward-wire form of $H \to S$ under NatDecision $N$. Thus, rule (i) evaluates **true**: canonical-form $S1_{\text{base}}$ wins and adopts $S1_{\text{alias}}$ via the both-direction merge.
    4. **Fate of $S1_{\text{alias}}$'s published canonical row**: During the adopt/merge, $S1_{\text{alias}}$'s spare coordinator record drops and its explicit canonical row at key $E \to S$ in `shared_sessions` is swept/removed as part of transactional shared replacement ([`plan.md:597-600`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L597-L600)). $S1_{\text{base}}$ publishes its canonical row at $H \to S$ into `shared_sessions` and populates `shared_forward_wire_sessions` with $E \to S \to S1_{\text{base}}$.
    5. **Lookup outcome**: Standby fabric-return lookups for $E \to S$ hit `shared_forward_wire_sessions` which resolves to $S1_{\text{base}}$ ($H \to S$). Reverse synthesis reads $S1_{\text{base}}$'s source IP ($H$), correctly routing packets back to the real client $H$.

  - **Scenario (b) — Codex r8 Colliding Zero-ID Alias ($B_{\text{alias}}$) vs Base ($A_{\text{base}}$) Walk**:
    1. Flow A base $A_{\text{base}}$ ($H_A \to S$, NatDecision $N$) arrives first, reserves identity $E$, and publishes canonical row $H_A \to S$.
    2. Flow B zero-id alias $B_{\text{alias}}$ ($E \to S$, NatDecision $N$) arrives second, attempting to claim identity $E$.
       - Key $E \to S$ IS the forward-wire form of $A_{\text{base}}$ ($H_A \to S$) under NatDecision $N$.
       - Rule (i) triggers: $B_{\text{alias}}$ merges into $A_{\text{base}}$'s record via the both-direction rule.
       - **Benign vs Harmful check**: $B_{\text{alias}}$ carries key $E \to S$ and decision $N$, which is **byte-identical** to $A_{\text{base}}$'s own forward-wire alias. Merging $B_{\text{alias}}$ into $A_{\text{base}}$ is completely **benign**: it simply attaches an additional holder unit to $A_{\text{base}}$'s record.
    3. Flow B zero-id base $B_{\text{base}}$ ($H_B \to S$, NatDecision $N$) arrives third, attempting to claim identity $E$ held by $A_{\text{base}}$.
       - Wire-form check: $H_B \to S$ is NOT the wire-form of $H_A \to S$, and $H_A \to S$ is NOT the wire-form of $H_B \to S$ (both have wire-form $E \to S$, but neither base key is the wire-form of the other base key).
       - Rule (i) evaluates **false**; rule (ii) applies.
       - $B_{\text{base}}$ receives `IdentityConflict` and **drops** (fail-closed).
    4. **Conclusion**: Arrival order independence and fail-closed security guarantees are fully satisfied.

---

#### 2. VERIFICATION — Codex r9 MAJOR: Publication Token (`pub_token`) & Stampable Choke Point
- **Status**: **RESOLVED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:606-626`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L606-L626); [`docs/research/6751-nopat-admission/plan.md:793-796`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L793-L796); [`userspace-dp/src/afxdp/shared_ops.rs:900-958`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L900-L958).
- **Analysis**:
  1. **Identity Validation Chain**: v10 introduces an additive helper-internal field `SyncedSessionEntry.pub_token: u64` (stamped at publication from a coordinator-local monotonic counter). Every atomic compare-and-remove sweep validates ownership under each map's lock against the identity chain:
     $$\text{equal non-zero } \texttt{RTFlowSessionID} \longrightarrow \text{equal non-zero } \texttt{pub\_token} \longrightarrow (\text{token-0 legacy only}) \text{ full } \texttt{SyncedSessionEntry} \text{ equality ex-counters}$$
  2. **Publish Choke Point Audit**:
     - `session_import` ([`session_import.rs:133`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L133), [`206`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L206)) $\to$ calls `publish_shared_session`
     - Local publish ([`poll_descriptor/mod.rs:2591`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2591)) $\to$ calls `publish_shared_session`
     - Tunnel prewarm ([`tunnel.rs:748`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/tunnel.rs#L748), [`756`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/tunnel.rs#L756)) $\to$ calls `publish_shared_session`
     - Activation prewarm ([`shared_ops.rs:391`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L391)) $\to$ calls `publish_shared_session`
  3. **Choke Point Stampability**: All publication paths in the userspace dataplane pass through `publish_shared_session` ([`shared_ops.rs:900`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L900)). Stamping `entry.pub_token = next_pub_token()` inside `publish_shared_session` guarantees that both canonical and derived index rows created during that publication carry identical non-zero tokens.
  4. **Token-0 Row Exhaustion Check**: No active helper publication path bypasses `publish_shared_session`. Only pre-existing legacy entries loaded from older image snapshots deserialize with `pub_token == 0`, which are explicitly handled by step 3 of the compare-and-remove identity chain.

---

#### 3. NIT 1 — Unit Test Parity Across IPv4 and IPv6 Alias Fail-Closed Imports
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:934-941`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L934-L941); [`pkg/daemon/daemon_ha_userspace_convert.go:399-511`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L399-L511).
- **Detail**: When implementing unit tests in §9 for clause (4) zero-id alias fail-closed imports and the wire-form-yield rule, ensure test cases cover both `userspaceForwardWireAliasV4` and `userspaceForwardWireAliasV6` paths to maintain full behavioral parity across IPv4 and IPv6 fabric-redirect alias conversions.

---

### Final Adjudication Summary

| Severity | Count | Details |
| :--- | :---: | :--- |
| **BLOCKER** | 0 | None. Codex r9 zero-id alias-first BLOCKER fully resolved and verified. |
| **MAJOR** | 0 | None. Codex r9 `pub_token` MAJOR fully resolved and verified. |
| **MINOR** | 0 | None. |
| **NIT** | 1 | Unit test parity for IPv4 and IPv6 alias conversion paths. |

The v10 plan is completely sound, mathematically converged, and ready for immediate implementation.
