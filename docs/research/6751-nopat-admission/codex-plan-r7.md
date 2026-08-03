# Codex hostile plan review — #6751 plan v7 (round 7)

# PLAN-NEEDS-REVISION

1. **BLOCKER — The shipped telemetry predicate is not safe as an ownership-equivalence predicate.**

   The code explicitly accepts false negatives for genuine collisions involving a sync-derived wire-form entry ([shared_ops.rs:87](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:87>), [shared_ops.rs:120](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:120>)). v7 nevertheless uses that predicate to bypass `IdentityConflict` and destructively sweep canonical rows ([plan.md:493](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:493>), [plan.md:498](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:498>), [plan.md:506](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:506>)).

   Normal walk: base `H:p→S:q` reconstructs flow `H→S`; alias `E:p→S:q` reconstructs a different flow `E→S` ([source.rs:880](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:880>)). Both claim translated identity `(E,p)`, and the predicate can conditionally associate the alias with an already-present base.

   Counterexample under v7’s old-active/new-standby window: A’s base reserves T; A’s alias attaches. B’s colliding base drops, but B’s independently imported alias has the same NAT decision, sync-derived origin, and equals A’s forward-wire form. It therefore attaches to A and publishes B’s value into the explicit canonical alias row ([shared_ops.rs:907](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907>)), contradicting v7’s promised second-import drop ([plan.md:350](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:350>)). The telemetry under-count becomes a correctness/security failure.

2. **BLOCKER — The holder representation still cannot encode base-plus-alias multiplicity.**

   v7 retains `FxHashSet<HolderId>` where `HolderId = Worker(u32) | Shared` ([plan.md:368](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:368>)). Base and explicit alias independently reach coordinator publication and every worker ([session_import.rs:133](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133>), [session_import.rs:233](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233>)), but adding the same `{Shared}` or `{Worker(W)}` twice still records one element.

   Removing either row can therefore remove the sole marker while its companion remains reachable. v7 asserts otherwise ([plan.md:498](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:498>)) without defining per-entry counts, alias-group membership, or an atomic last-member release rule.

   Arrival/deletion order cannot be assumed: base and alias use separate calls ([daemon_ha_userspace_stream.go:370](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370>), [daemon_ha_userspace_stream.go:398](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:398>)), and each enqueue is independently nonblocking/lossy ([sync_conn_write.go:36](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36>)). The ownership model must count holder-bearing rows per scope or persist explicit alias-group membership.

3. **BLOCKER — NAT64 is another explicit forward-alias export class, but v7’s ownership treatment is interface-only.**

   NAT64 fabric redirects can enter the same alias exporter:

   - The event codec independently marks `FabricRedirect` and NAT64, and emits both generic NAT rewrites and `nat64_snat_v4` ([session_sync.rs:80](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:80>), [session_sync.rs:128](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:128>), [session_sync.rs:171](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:171>)).
   - Every IPv6 fabric redirect attempts `userspaceForwardWireAliasV6` ([daemon_ha_userspace_stream.go:379](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:379>), [daemon_ha_userspace_convert.go:496](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:496>)).
   - v7 bypasses the source/interface scan for NAT64 and confines tuple-versioned holders to interface allocators ([plan.md:281](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:281>), [plan.md:326](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:326>)).
   - NAT64 reserve reconstructs `SourceNatFlowKey` from the presented key, so base and alias look like different flows ([nat64.rs:1322](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs:1322>)).

   Cross-family encoding makes this worse: IPv4 rewrites are padded into an IPv6 slot ([wire.rs:182](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/wire.rs:182>)), while NAT64 reconstruction derives `dst_v4` from the presented key’s low 32 bits ([session_sync.rs:47](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/helpers/session_sync.rs:47>)). The alias can reconstruct a different `NatDecision`, evade the equality predicate, and conflict with/drop its own base reservation. v7 must either cover NAT64 aliases transactionally or prevent this invalid alias export.

4. **MAJOR — Derived-alias sweeping can delete a third party that displaced the old row.**

   v7 filters the old sweep against the new entry’s aliases ([plan.md:433](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:433>)), but says it mirrors current removal conditionals. Those removals delete derived reverse/forward-wire slots by key without confirming the stored entry still belongs to the removed session ([shared_ops.rs:978](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:978>), [shared_ops.rs:987](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:987>), [shared_ops.rs:997](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:997>)).

   If another legitimate non-bijective session has since displaced T_old’s derived slot, the sweep removes that current occupant. Every swept map needs compare-and-remove ownership validation plus a third-party-displacement test.

5. **MINOR — Fixed-mode quarantine is specified correctly, but its hook/test inventory is incomplete.**

   Deterministic CGNAT selects a fixed address at [allocator.rs:1482](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1482>); deterministic NAT64 has its separate fixed path at [allocator.rs:1561](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1561>); address-only persistent reuse is at [allocator.rs:1955](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1955>). But port-translating persistent NAT can return a pinned lease before the address loop ([allocator.rs:1114](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1114>)).

   Section 9 tests only generic pool/interface quarantine ([plan.md:779](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:779>)). Add explicit tests for sticky, both persistent paths, deterministic CGNAT, and deterministic NAT64.

6. **NIT — One stale test phrase contradicts the no-auto-drop contract.**

   The normative secondary-index/no-auto-drop design is sufficient ([plan.md:305](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:305>), [plan.md:311](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:311>)), but §9 still says “stale-drop removes the record” ([plan.md:774](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:774>)). Replace that with explicit holder release/removal when the holder set empties.

The `MaterializeConflict` invariant, queue/relay-or-expiry qualification, holder-bearing-forward wording, same-tuple refresh filter, and sticky exhaustion folds are otherwise correct. Reverse companions are holder-neutral and tunnel-local rows use `NatDecision::default()`; neither needs fabric-alias ownership treatment. Option (a) remains endorsed—the design fork is not reopened.

Codex session ID: 019fc822-a935-71e3-addc-8573934988ef
Resume in Codex: codex resume 019fc822-a935-71e3-addc-8573934988ef
