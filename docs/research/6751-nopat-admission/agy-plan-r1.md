# AGY hostile plan review — #6751 plan v1 (round 1)

PLAN-NEEDS-REVISION

### 1. Verification of Bug Analysis (Axis 1)

The plan's root-cause analysis is **correct**, and there is **no existing field or index** that disambiguates colliding return tuples:

- **Admission path** ([`userspace-dp/src/nat/source.rs:1226-1251`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L1226-L1251)): `match_source_nat_result_for_tuple` returns `NatDecision { rewrite_src: Some(egress), rewrite_dst: None, ..Default::default() }`. It performs no port allocation, no occupancy check, and leaves `rewrite_src_port` as `None` (preserving the client source port).
- **Candidate matching** ([`userspace-dp/src/session/key.rs:19-26`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs#L19-L26)): `reply_matches_forward_session` checks `reverse_wire_key(forward_key, nat) == *reply_key`. Because `nat.rewrite_src_port` is `None`, two internal hosts $H_1$ (`10.0.0.1:5555`) and $H_2$ (`10.0.0.2:5555`) sending to $S:80$ produce identical reverse wire keys (`S:80 -> E:5555`). Both forward sessions evaluate `true` against the reply key.
- **Multimap lookup** ([`userspace-dp/src/session/lookup.rs:222-249`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs#L222-L249)): `find_forward_nat_match` walks `nat_reverse_index` bucket $K$ (which contains handles for both $H_1$ and $H_2$). It returns the first entry that passes `reply_matches_forward_session`. Since $H_1$ is first in iteration order, reply traffic for both flows deterministically resolves to $H_1$, leaking $H_2$'s data to $H_1$ and causing RST teardowns.
- **Shared map displacement** ([`userspace-dp/src/afxdp/shared_ops.rs:897-942`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L897-L942)): `publish_shared_session` puts reverse wire keys into `shared_nat_sessions` (a single-value `FastMap`). The second installed session overwrites the first, causing RSS worker topology-dependent hijacking.
- **Pinned behavior** ([`userspace-dp/src/session/tests.rs:4560-4610`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs#L4560-L4610)): The test explicitly asserts that a reply on shared reverse key $K$ resolves to the first-installed session $S_1$.
- **Disambiguation impossibility**: Neither `SessionKey`, `NatDecision`, `SessionMetadata`, nor any lookup index stores inner host info or VRF tags on reverse packets. On the wire, the reply packet `(S:80 -> E:5555)` contains zero identifying header fields. Disambiguation without PAT or rejection is mathematically impossible.

---

### 2. Detailed Findings

#### 1. [BLOCKER] Concurrency Race and Port Churn in Option (a)'s `allocate_interface` Idempotent Re-entry
- **Evidence**: [`userspace-dp/src/nat/allocator.rs:1000-1060`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs#L1000-L1060) vs Plan §5.2 ([`plan.md:238-264`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L238-L264)).
- **Impact**: In Option (a), `allocate_interface` executes lock-free `occupancy.reserve(src_port)` before acquiring `live: Mutex<PortAllocatorLiveState>`. If two initial packets for the *same* flow arrive concurrently on different worker threads ($T_1$ and $T_2$):
  1. $T_1$ executes `occupancy.reserve(5555)` and succeeds.
  2. $T_2$ executes `occupancy.reserve(5555)` and fails (bit 5555 is set).
  3. $T_2$ falls back to `claim()`, claiming a non-preserved port (e.g., `1024`).
  4. $T_2$ acquires `live.lock()`. Because $T_1$ has not yet inserted the flow into `live_by_flow`, $T_2$ inserts `flow -> 1024` and returns port `1024`.
  5. $T_1$ acquires `live.lock()`, finds `flow` already present (inserted by $T_2$), frees port `5555`, and returns `1024`.
- **Consequence**: Concurrent first-packets of a single non-colliding flow cause spurious source port translation (PAT) and bitmap churn, violating the "preserve-first" wire contract.

#### 2. [BLOCKER] Allocator Leak on Egress Interface Reconfiguration Across Commits
- **Evidence**: [`userspace-dp/src/nat/source.rs:781-820`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L781-L820), [`userspace-dp/src/afxdp/forwarding_build/mod.rs:312-344`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding_build/mod.rs#L312-L344), Plan §5.1 ([`plan.md:203-231`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L203-L231)).
- **Impact**: The plan proposes `InterfaceNatAllocators::carry_over`, which filters and retains allocators only for egress IP addresses present in the *new* configuration snapshot. If a configuration commit changes or removes an interface IP:
  1. Generation $N+1$'s `InterfaceNatAllocators` drops the `Arc<PortAllocator>` for the removed egress IP.
  2. Active sessions established under Generation $N$ remain alive. When they eventually close or age out, `release_source_nat_allocation_with_mode` is invoked using the worker's current `ForwardingState` (Generation $N+1$).
  3. Lookups in Generation $N+1$'s `InterfaceNatAllocators` for the removed `rewrite_src` return `None` (or lazy-instantiate a dummy allocator).
  4. The allocated port inside Generation $N$'s `PortAllocator` is **never freed**, resulting in leaked memory and un-reclaimed port state.

#### 3. [MAJOR] Unhandled HA Sync Discrepancy & Mixed-Version Rolling Upgrade Failure
- **Evidence**: [`pkg/dataplane/userspace/protocol_ha.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go), [`userspace-dp/src/afxdp/session_glue/mod.rs:1294`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs#L1294), Plan §5.4 ([`plan.md:278-285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L278-L285)).
- **Impact**: 
  - **Go Daemon Omission**: The plan touches only `userspace-dp` Rust code, missing HA session message handling and validation on the Go side ([`pkg/dataplane/userspace/protocol_ha.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go)).
  - **Rolling Upgrades**: If Node A (upgraded, active) admits a colliding interface flow and assigns `rewrite_src_port = Some(60001)` (PAT), it syncs this decision to Node B (un-upgraded standby). Node B expects interface-mode flows to have `rewrite_src_port == None`. Node B will mis-parse or fail to install the reverse session.
  - **Failover Inconsistency**: If Node B (un-upgraded active) admits two colliding flows without PAT, Node A (upgraded standby) receives two sync messages with identical wire keys. Node A's `reserve_synced` for the second flow will fail. Following a failover to Node A, the second flow will be un-tracked or broken.

#### 4. [MAJOR] Option (a) Recommendation is Indefensible for a High Security Issue
- **Evidence**: [`userspace-dp/src/nat/allocator.rs:1727-1785`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs#L1727-L1785) (#5269 address-only token discipline), Plan §4 ([`plan.md:100-198`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L100-L198)).
- **Impact**: 
  - Option (a) introduces a hybrid NAT engine that mutates port-preserving interface SNAT into dynamic PAT. It requires node-global registries, complex cross-worker holder refcounting (#6522 coupling), flow-cache L4 rewrite modifications, and multi-subsystem churn.
  - Option (b) (reserve-and-reject fail-closed) applies the **already shipped** address-only occupancy token pattern from issue #5269. It completely eliminates cross-session data leaks and session hijacks with minimal diff, zero risk of PAT state corruption, and no alteration of wire behavior.
  - Recommending Option (a)'s high-risk architectural churn over Option (b)'s predictable fail-closed security fix is indefensible for a High security finding. Option (b) should be the primary recommendation.

#### 5. [MINOR] Insufficient Evidence for Junos Parity Claim
- **Evidence**: [`pkg/config/compiler_nat_source.go:253-273`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_nat_source.go#L253-L273), Plan §2/§3 ([`plan.md:63-67, 95-96`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L63-L67)).
- **Impact**: The plan cites `compiler_nat_source.go:253-271` as proof that Junos interface mode translates ports by default. However, lines 253–271 merely parse the advisory knob `security nat source interface port-overloading off`, which in `xpf` is un-enforced and recorded for advisory purposes only. The comment refers to pool-mode port overloading, not interface-mode PAT. While Junos documentation states interface mode uses PAT by default, citing `compiler_nat_source.go:253-271` is inaccurate code evidence.

#### 6. [MINOR] Missing Audits for Flow Cache Seeding, Flow Export, and CLI Show Commands
- **Evidence**: [`userspace-dp/src/afxdp/flow_cache.rs:297-309`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/flow_cache.rs#L297-L309), Plan §4/§6 ([`plan.md:154-156, 318-327`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L154-L156)).
- **Impact**: Under Option (a), interface-mode decisions can carry `rewrite_src_port = Some(port)`. The plan fails to audit:
  1. **Flow Cache Seeding**: `flow_cache.rs` must be verified to ensure L4 port rewrite actions are correctly constructed for interface-mode decisions when `rewrite_src_port` is present.
  2. **Flow Export & CLI**: IPFIX/syslog flow export and `show security nat source` CLI outputs must display translated ports for interface PAT flows.

#### 7. [NIT] Stale Pinned Test Comments Require Explicit Update Strategy
- **Evidence**: [`userspace-dp/src/session/tests.rs:4560-4610`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/tests.rs#L4560-L4610), Plan §8/§9 ([`plan.md:380-383`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L380-L383)).
- **Impact**: The plan notes that comments in `session/tests.rs:4560-4610` will go stale. The plan should explicitly detail updating these test comments to clarify that direct table insertion bypasses admission checks, preserving unit test clarity.

---

### Summary
The plan requires revision to adopt **Option (b)** (reserve-and-reject fail-closed) as the primary recommendation. If Option (a) is pursued, the plan must address the `allocate_interface` concurrency race, cross-commit allocator leaks, HA daemon compatibility, and flow-cache/export coverage.
