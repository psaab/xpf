# Codex hostile plan review — #6751 plan v6 (round 6)

# PLAN-NEEDS-REVISION

1. **BLOCKER — The sweep and holder model miss the separately synchronized fabric forward-wire alias.**

   Fabric redirect exports two keys for one logical session: the canonical key and a separately queued forward-wire alias ([daemon_ha_userspace_stream.go:370](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370>), [daemon_ha_userspace_stream.go:373](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:373>)). The alias retains the base value ([daemon_ha_userspace_convert.go:399](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399>)); its pinned test explicitly calls these “two conntrack keys for ONE logical session” ([userspace_sync_session_id_6198_test.go:350](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/userspace_sync_session_id_6198_test.go:350>)).

   On import, each key independently reaches `publish_shared_session` and worker fanout ([session_import.rs:133](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133>), [session_import.rs:233](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233>)). Reservation derives `SourceNatFlowKey` from the presented `SessionKey` ([source.rs:880](</home/ps/git/kimi-xpf/.claude/worktrees/6751-nopat-admission/userspace-dp/src/nat/source.rs:880>)), so canonical and wire keys appear to be different flows even though they claim the same translated identity. Under v6’s coordinator contract, the second import therefore becomes `IdentityConflict` and is dropped ([plan.md:375](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:375>)).

   Treating it as idempotent without further design is also unsafe: `FxHashSet<Worker(u32) | Shared>` ([plan.md:352](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:352>)) cannot count two reachable forward entries in the same worker/shared scope. Deleting either key could remove the sole marker while its companion remains reachable.

   Finally, v6’s sweep covers the internally derived `shared_nat_sessions` and `shared_forward_wire_sessions` aliases ([shared_ops.rs:918](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:918>), [shared_ops.rs:943](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:943>)), but not the explicit alias stored as another canonical row in `shared_sessions` at [shared_ops.rs:907](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907>). That is the alias-creation site the plan missed.

   The plan must define this alias as holder-neutral and tied to its base, or introduce per-entry/refcounted ownership. Tuple replacement must also conditionally remove the old explicit canonical alias without deleting an unrelated real session occupying that key.

2. **MAJOR — Tuple-versioned records can represent two tuples, but the current idempotence contract is incomplete.**

   The two-shape split itself is coherent: limiting `(flow, translated)` records to interface allocator instances avoids dragging pool allocator issue #6522 into scope. Release matching, cap accounting, and per-index accounting are all specified ([plan.md:292](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:292>)).

   However, interface admission calls the allocator with only `flow` and egress address ([plan.md:248](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:248>)). A previously PAT’d flow’s translated tuple is not known to the caller. Today this is resolved by direct `live_by_flow.get(&flow)` lookup ([allocator.rs:1035](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1035>)); keying solely by `(flow, translated)` removes that lookup.

   Specify an efficient secondary flow index/current-record selection rule—especially while `T_old` and `T_new` coexist. Also clarify that staged pre-reserve must not perform the old marker decrement described at [plan.md:305](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:305>) before the explicit post-replacement release in §5.6.

3. **MINOR — Uniform quarantine closes the r5 counterexample, but skip-next only applies to rotatable pools.**

   Re-running `[E,A] → drain A0 → [E,B] re-enabled`: the new allocator must check quarantine before claiming from `occupancy[E]`; it skips E and tries B in the existing address loop ([allocator.rs:1008](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1008>)). Thus r5 BLOCKER 3 is closed, and skip-next is the correct posture for ordinary round-robin pools.

   Fixed-address modes cannot rotate:

   - `address-persistent` deliberately attempts one address ([allocator.rs:1011](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1011>)).
   - Deterministic CGNAT derives a fixed address from the subscriber ([allocator.rs:1482](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1482>)).
   - Persistent NAT can reuse a pinned address ([allocator.rs:1955](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1955>)).

   The plan should explicitly say those modes—and deterministic NAT64—fail closed when their selected/pinned address is quarantined.

4. **MINOR — The materialization fold is sufficient, but §7 contradicts it.**

   `MaterializeConflict → explicit recycle/drop` is the correct plan-level contract. Current materialization unconditionally returns the shared decision ([session_glue/mod.rs:1128](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1128>)), while `None` enters cold admission ([poll_descriptor/mod.rs:432](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:432>), [poll_descriptor/mod.rs:903](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:903>)), exactly as v6 now recognizes.

   Correct the stale invariant text “materialize returns miss-on-failure” at [plan.md:633](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:633>) to say `MaterializeConflict` recycles/drops and never becomes a miss.

5. **NIT — Reverse-companion scoping is acceptable, but “ms-scale” is not guaranteed by the code.**

   I accept N16’s scoping. The interface design does not widen the shipped pool window; it retains `{Shared}` until canonical removal, whereas pool allocations can already free at forward reap. But `replicate_session_delete` only enqueues worker commands ([session_glue/mod.rs:881](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:881>)); it provides no strict millisecond deadline. Describe the exception as queue/relay-or-expiry bounded rather than “ms-scale.” Also qualify “ANY entry replica” at [plan.md:478](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:478>) as “any holder-bearing forward replica,” since reverse companions are explicitly excluded.

AGY’s two r5 nits are correctly folded: the reason label is explicitly optional ([plan.md:566](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:566>)), and the narrow `translated_tuple_of` accessor is specified ([plan.md:597](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:597>)).

Option (a) remains endorsed; this verdict does not reopen the settled design fork.

Codex session ID: 019fc800-2646-70d1-a7d2-a28e76dd9a1d
Resume in Codex: codex resume 019fc800-2646-70d1-a7d2-a28e76dd9a1d
