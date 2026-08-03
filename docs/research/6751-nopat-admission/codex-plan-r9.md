# Codex hostile plan review — #6751 plan v9 (round 9)

# PLAN-NEEDS-REVISION

1. **BLOCKER — Zero-ID fail-closed handling is not arrival-order safe.**

   V9 says a zero-ID alias imports as a first-class entry, conflicts with its base, and drops, leaving the base unaffected ([plan.md:533](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:533)). That is true only for base-first arrival.

   The plan itself establishes that alias-first arrival is possible across reconnect/interleaving ([plan.md:565](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:565)). In that order:

   1. Zero-ID alias `E→S` has no base candidate against which clause 4 can succeed.
   2. Per v9, it imports as a first-class flow and successfully reserves the translated identity because nothing owns it yet.
   3. Imports are published and fanned out immediately ([session_import.rs:133](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133), [session_import.rs:233](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233)).
   4. The real base `H→S` then arrives as a different `SourceNatFlowKey`, finds the alias holding its translated identity, receives `IdentityConflict`, and drops.

   Thus the surviving row is the alias and the base is absent—the opposite of v9’s promised outcome. Worse, reverse synthesis treats the alias’s source `E` as the original client: resolution targets `forward_match.key.src_ip` ([shared_ops.rs:678](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:678)), and reverse NAT is constructed from that same alias key ([shared_ops.rs:738](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:738)). The standby therefore cannot reconstruct delivery to `H`; the legacy fabric session is broken rather than merely lacking a redundant alias row.

   The base-first case itself is safe: the base publishes the forward-wire key into the XDP steering map ([bpf_map/mod.rs:76](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:76)), the worker indexes it under `forward_wire_index` ([session/mod.rs:1971](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1971)), and shared publication creates the same derived index ([shared_ops.rs:943](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:943)). Lookup tries exact local, local forward-wire, shared canonical, then shared forward-wire ([shared_ops.rs:602](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:602)). Server replies are additionally covered by the synthesized reverse companion ([session_import.rs:122](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:122)). Consequently, no normal lookup step breaks merely because the explicit canonical alias row is absent.

   V9 needs an explicit zero-ID alias-first protocol—group identity, transactional grouping, or safe deferral/quarantine—and a zero-ID alias-first regression test. “Import first-class and let conflict decide” is insufficient.

2. **MAJOR — The compare-and-remove identity chain is not representable by the rows being swept, and its final fallback remains unsafe.**

   Atomic validation under each removing map’s lock is correct and closes the cross-lock check/remove race ([plan.md:591](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:591)). Equal non-zero RTFlow IDs are also sufficient.

   However, the proposed fallback chain then requires the node-local `SessionID`, followed by full `SessionValue` equality excluding generation and counters ([plan.md:595](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:595)). The swept Rust maps store `SyncedSessionEntry`, not Go `SessionValue` ([session_manager.rs:12](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/session_manager.rs:12)). `SyncedSessionEntry` has only one ID field, explicitly the cross-node RTFlow ID ([worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:375)); the helper populates it from `SessionSyncRequest.session_id`/`RTFlowSessionID` ([session_sync.rs:274](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/helpers/session_sync.rs:274)). The distinct Go node-local `SessionID` is not transmitted—the request builder sends only `RTFlowSessionID` ([manager_ha.go:1645](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1645)).

   Local shared publications make the hole concrete: they deliberately store `session_id: 0` ([poll_descriptor/mod.rs:2569](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2569)). A newer local same-key/same-NAT publication can therefore equal the displaced entry on every remaining static field. Excluding generation makes the final comparison accept it, allowing the sweep to remove the newer occupant despite the atomic map lock.

   V9 must specify an identity actually stored with every derived row—such as a coordinator-local publication token copied into canonical and derived entries—or explicitly carry/store the required stable ID and update §6’s shape-preservation claim.

Verified folds:

- **Fixed-address quarantine tests:** complete. Section 9 now separately names all five requested cases ([plan.md:907](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:907)), matching the pinned-lease bypass ([allocator.rs:1114](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1114)), address-only persistent selection ([allocator.rs:1955](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1955)), deterministic CGNAT ([allocator.rs:1482](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1482)), and deterministic NAT64 ([allocator.rs:1561](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1561)).
- **v8.1 identity naming:** confirmed. Clause 4 now names `RTFlowSessionID`, distinct from node-local `SessionID` ([protocol_ha.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go:183), [types.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/types.go:27)).

A new BLOCKER remains open; convergence has not been reached.

Codex session ID: 019fc851-bc9c-7df0-94bc-40a9954e4a95
Resume in Codex: codex resume 019fc851-bc9c-7df0-94bc-40a9954e4a95
