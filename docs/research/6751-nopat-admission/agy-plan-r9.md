# AGY hostile plan review — #6751 plan v9 (round 9)

PLAN-READY-WITH-NITS

---

### Convergence Adjudication & Verification Findings

Plan v9 ([`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md), commit `1c66a7c05`) successfully folds all findings from Round 8. No BLOCKER or MAJOR issues remain open. 

---

### Numbered Findings

#### 1. VERIFICATION — Codex r8 BLOCKER (Zero/Legacy ID Fallback & Standby Packet Walk)
- **Status**: **RESOLVED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:532-547`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L532-L547); [`userspace-dp/src/afxdp/shared_ops.rs:585-635`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L585-L635); [`userspace-dp/src/afxdp/shared_ops.rs:943-957`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L943-L957).
- **Analysis & Standby Lookup Walk**:
  1. **Fail-Closed Alias Import**: v9 removes the zero-id value-equality fallback. When an alias entry with `session_id == 0` arrives on the standby, clause (4) fails closed: the alias cannot attach to the base record, imports as a standalone entry, hits `IdentityConflict` against the base, and drops. Consequently, no explicit canonical alias row is inserted into `shared_sessions`.
  2. **Standby Forward-Wire Lookup Walk**: For a fabric-return packet matching the forward-wire key $K_W$ of an id-0-synced session:
     - `lookup_session_across_scopes` ([`shared_ops.rs:594`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L594)) first queries local `sessions`. If a local placeholder entry exists (`fabric_ingress: true`, `is_reverse: false`, `rewrite_src.is_some()`), `is_fabric_wire_placeholder` ([`shared_ops.rs:583-592`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L583-L592)) evaluates `true` (lines 603-608 & 619-626) and delegates to `lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)`.
     - If no local placeholder exists, `lookup_shared_session(shared_sessions, key)` returns `None` (since the explicit alias row was dropped), and line 633 falls through to `lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)`.
     - **Outcome**: When the base session $S_{base}$ was originally published, [`publish_shared_session`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L943-L957) automatically populated `shared_forward_wire_sessions` with $K_W \to S_{base}$ (lines 945-948). Thus, both lookup branches hit `shared_forward_wire_sessions` and safely resolve to `ResolvedSessionLookup::shared(S_{base})`. The missing explicit alias row in `shared_sessions` does **not** misroute or drop traffic; it resolves safely to $S_{base}$.

#### 2. VERIFICATION — Codex r8 MAJOR (Compare-and-Remove Identity Validation Chain)
- **Status**: **RESOLVED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:583-600`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L583-L600); [`pkg/daemon/daemon_ha_userspace_convert.go:118-170`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L118-L170); [`userspace-dp/src/session/entry.rs:11-99`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L11-L99).
- **Analysis**:
  1. **Node-Local ID Uniqueness**: On any single node, [`nextUserspaceSyncedSessionID()`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L165) mints a strictly monotonic 48-bit counter in Go atomic storage (`userspaceSyncedSessionIDs`). Distinct session conversions on the same node receive distinct `SessionID` values. Two distinct concurrent sessions on the same node will not share a node-local `SessionID`.
  2. **Colliding Id-0 Value Field Differences**: For legacy pairs where both `RTFlowSessionID` and node-local `SessionID` are `0`, compare-and-remove falls back to `full-SessionValue-ex-generation-and-counters`. Between two colliding id-0 sessions sharing key and NAT decision, the following fields in `SessionValue` / `SessionMetadata` / `ForwardingResolution` can differ and prevent false matches:
     - `ingress_zone` and `egress_zone` IDs ([`entry.rs:25-26`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L25-L26))
     - `policy_id` ([`entry.rs:58`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L58))
     - `policy_counter_idx` ([`entry.rs:78`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L78))
     - `inactivity_timeout_ns` ([`entry.rs:59`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L59))
     - `ForwardingResolution` / FIB nexthop details (`egress_ifindex`, nexthop IP/MAC) ([`entry.rs:12`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L12))
     - `owner_rg_id` ([`entry.rs:27`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L27))
     - `fabric_ingress` flag ([`entry.rs:28`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L28))
     - `log_session_init` / `log_session_close` policy flags ([`entry.rs:39-40`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L39-L40))
     - `nat64_reverse` info ([`entry.rs:32`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs#L32))

#### 3. VERIFICATION — Codex r8 MINOR (§9 Enumeration of Fixed-Path Quarantine Tests)
- **Status**: **RESOLVED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:906-912`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L906-L912).
- **Analysis**: §9 explicitly enumerates test cases for all five fixed-address quarantine paths:
  1. Address-persistent / sticky single-probe
  2. Port-translating persistent-NAT pinned-lease decision (`allocator.rs:1114`)
  3. Address-only persistent (`allocator.rs:1955`)
  4. Deterministic CGNAT (`allocator.rs:1482`)
  5. Deterministic NAT64 (`allocator.rs:1561`)

#### 4. VERIFICATION — v8.1 (SMR r8) Clause 4 Naming
- **Status**: **CONFIRMED / PASS**
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:527-532`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L527-L532).
- **Analysis**: Clause 4 of the wire-alias ownership predicate explicitly requires equal non-zero `RTFlowSessionID` and explicitly notes that it must **not** use node-local `SessionID` (on which peer HA nodes deliberately disagree).

---

#### NIT 1 — Unit Test Coverage for Both IPv4 and IPv6 Alias Fail-Closed Imports
- **Evidence**: [`docs/research/6751-nopat-admission/plan.md:898-901`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L898-L901); [`pkg/daemon/daemon_ha_userspace_convert.go:399-511`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L399-L511).
- **Detail**: When writing unit tests for clause (4) zero-id fail-closed alias imports in §9, ensure test coverage includes both `userspaceForwardWireAliasV4` and `userspaceForwardWireAliasV6` paths to verify parity across IPv4 and IPv6 fabric-redirect alias conversions.

---

### Conclusion

The v9 plan is complete, rigorous, and fully converged. Implementation may proceed immediately.
