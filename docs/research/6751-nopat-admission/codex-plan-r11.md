# Codex hostile plan review — #6751 plan v11 (round 11)

# PLAN-NEEDS-REVISION

The alias-removal idea is sound: the explicit canonical alias has no unique Rust forwarding consumer, and its synthesized reverse companion is a live hazard. However, v11 does not define how the exact alias flag crosses the node-to-node session-sync boundary or how alias deletes are identified. Consequently, the clean new/new path is not implementable as written, and the old-Go/new-helper cell can regress.

## Findings

1. **BLOCKER — `is_forward_wire_alias` has no end-to-end carrier, and alias deletes remain unmarked.**

   The plan says the flag is set at the exporter’s alias queue sites and appears on the Go→helper `SessionSyncRequest` ([plan.md:527](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:527)). Those points are separated by the cluster wire:

   - The exporter queues only `(wireKey, wireVal)` ([daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370), [daemon_ha_userspace_stream.go:375](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:375)).
   - `QueueSessionV4/V6` accept only key and `SessionValue`, then encode those onto the cluster wire ([sync_conn_write.go:56](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:56), [sync_protocol.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:95)).
   - The peer later constructs the helper `SessionSyncRequest` solely from the decoded key/value ([manager_ha.go:1584](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1584), [manager_ha.go:1668](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1668)).
   - Neither `SessionValue` nor the cluster payload currently carries alias provenance ([types.go:16](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/types.go:16), [sync_protocol.go:98](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:98)).

   Deletes are a second uncovered path. The exporter separately emits wire-alias deletes for both families ([daemon_ha_userspace_stream.go:400](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:400), [daemon_ha_userspace_stream.go:413](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:413)), but `QueueDeleteV4/V6` carry only key plus generation ([sync_conn_write.go:77](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:77)). The peer builds helper deletes with `val == nil` ([manager_ha.go:1524](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1524)), and the helper unconditionally deletes the presented key ([sync_session.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/sync_session.rs:29)).

   Therefore v11 must specify alias provenance across:

   - Cluster upsert and delete wire formats.
   - `SessionValue{V6}` or an equivalent receiver-visible carrier.
   - Go BPF mirror/bulk replay behavior.
   - Go→helper upsert and delete requests.
   - Helper handling of flagged deletes.

   Otherwise a dropped alias upsert can still be followed by an unflagged delete under the translated wire key, potentially deleting a real canonical occupant or its companion.

2. **BLOCKER — old Go + new helper is not “today’s exact behavior.”**

   V11 itself records why: an unflagged alias reconstructs as a different flow, and alias-first ordering reserves the identity before the real base, causing the base to conflict and drop ([plan.md:510](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:510)). Yet it later claims unflagged aliases retain today’s exact behavior ([plan.md:563](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:563)).

   The observability section contradicts that claim by saying an unflagged legacy alias can become an identity-conflict drop ([plan.md:709](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:709)).

   Canonical then alias is the normal producer order, but the two enqueue operations are independently lossy ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)). A base enqueue can fail while the following alias succeeds after queue drainage; reconnect/bulk interactions also cannot be treated as a permanent ordering invariant.

   Mixed-version adjudication:

   | Cell | Result |
   |---|---|
   | New Go + old helper | Intended status quo only if the missing flag carrier is added; old helper ignoring the final JSON field is otherwise sound. |
   | Old Go + new helper | **Regression:** unflagged alias participates in new ownership reservation; alias-first can make the real base lose. |
   | New + new | Clean in principle, but not achievable with v11’s presently specified wire path and unmarked deletes. |

3. **MAJOR — the transactional derived-index sweep references an undefined `pub_token` identity chain.**

   V11 says the sweep is “compare-and-remove validated with the `pub_token` identity chain above” ([plan.md:577](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:577)), but no chain is defined above. The only remaining description says merely that `pub_token` is stamped at publish ([plan.md:738](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:738)).

   This matters because current removal is key-only and unconditional for reverse-wire, reverse-canonical, and forward-wire slots ([shared_ops.rs:978](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:978), [shared_ops.rs:998](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:998)). Without the exact comparison hierarchy removed from v10, an implementor cannot know how to avoid sweeping a newer third-party occupant. Restore the precise nonzero session-ID / nonzero publication-token / legacy-token fallback rules.

4. **NIT — v11 retains several stale fold artifacts; the V4+V6 parity nit is fixed.**

   - `HolderSet` still justifies counting through a base plus explicit alias pair even though the new path removes that pair ([plan.md:369](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:369)).
   - The implementation inventory still includes the removed wire-alias predicate and base-record marker attachment ([plan.md:763](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:763)).
   - It says “four” status-counter mirrors/tests despite listing five counters ([plan.md:769](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:769), [plan.md:939](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:939)).
   - The requested V4 and V6 alias-converter parity test is now explicitly present ([plan.md:883](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:883)). R10’s parity nit is closed.

## Confirmed technical claims

The explicit canonical alias row has no unique Rust forwarding consumer:

- Exact shared lookup under the wire key is followed immediately by the derived forward-wire lookup ([shared_ops.rs:630](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:630)).
- Publishing the base creates that derived entry with the base value ([shared_ops.rs:943](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:943)).
- `is_fabric_wire_placeholder` only controls whether local placeholder hits yield to that shared derived lookup ([shared_ops.rs:603](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:603)).
- Materialization and promotion receive the base’s canonical key from the derived entry ([shared_ops.rs:549](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:549), [session_glue/mod.rs:1268](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1268)).
- Activation prewarm needs only the base canonical row. Publishing that base into `USERSPACE_SESSIONS` already emits its forward-wire, reverse-wire, and reverse-canonical keys ([bpf_map/mod.rs:76](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:76)).
- Export, demotion, purge, reconcile snapshot/replay, owner-RG indexing, cap accounting, and clear/delete scans merely process the alias as duplicate lifecycle state; none performs a unique translated-wire lookup that lacks the derived fallback.

The broken companion is also confirmed live:

- `synthesized_synced_reverse_entry` rejects only `is_reverse`; it has no alias detection ([shared_ops.rs:750](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:750)).
- `NatDecision::reverse` sets `rewrite_dst` to the supplied original source whenever forward SNAT exists ([nat/mod.rs:106](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/mod.rs:106)). For alias key `A=(E→S)`, that produces `rewrite_dst=E`, not `H`.
- Base and alias both derive reverse key `K=(S→E)` ([key.rs:94](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:94)).
- Normal export queues base before alias, so the alias import and its reverse publish later ([daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)); `publish_shared_session` is last-write-wins in the canonical map ([shared_ops.rs:907](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907)).
- Return packets consult exact local/shared session key `K`, so the poisoned companion is forwarding-relevant, not dead state ([shared_ops.rs:602](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:602), [shared_ops.rs:630](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:630)).

No separate blocker was found in the tri-state reserve, tuple-versioned record, staged holder replacement, drain/quarantine, or five-counter design beyond the missing `pub_token` comparison specification above.

Codex session ID: 019fc88d-926d-7510-b7b5-b5069e7bbacd
Resume in Codex: codex resume 019fc88d-926d-7510-b7b5-b5069e7bbacd
