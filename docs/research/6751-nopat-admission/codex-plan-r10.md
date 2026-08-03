# Codex hostile plan review — #6751 (round 10)

# PLAN-NEEDS-REVISION

1. **BLOCKER — Zero-ID wire-form-yield remains unsafe and reintroduces cross-flow mis-attachment.**

   V10 requires the canonical-form import to win and holder units to merge regardless of arrival order ([plan.md:533](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:533)). That allocation-record rule does not address already-reachable session rows.

   Alias-first walk:

   1. The alias reserves the identity and acquires `{Shared}`.
   2. Import immediately synthesizes its reverse companion from the alias entry, publishes both rows, then fans them to every worker ([session_import.rs:122](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:122), [session_import.rs:133](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133), [session_import.rs:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:205), [session_import.rs:233](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233)).
   3. Reverse synthesis targets `forward_match.key.src_ip`; for the alias that is external address `E`, not client `H` ([shared_ops.rs:668](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:668), [shared_ops.rs:738](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:738)).
   4. Therefore a window still exists—from alias publication until the base arrives—in which the base is absent but needed for correct delivery. Reconnect loss can make that window last until expiry.
   5. When the base eventually arrives, transferring the alias record’s existing `{Shared}` and per-worker counts into the base record prevents early allocation release, but it does not retract or rewrite the alias’s canonical shared row, synthesized reverse companion, or already-installed worker rows. Exact local lookup precedes forward-wire lookup, so a retained alias row can continue winning ([shared_ops.rs:602](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:602), [shared_ops.rs:614](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:614)). V10 also does not specify how later deletion of that alias row finds the adopted base record after the spare alias ownership record is dropped.

   The r8 mis-attachment remains harmful:

   - Let A’s base be `H_A→S`; let B’s zero-ID alias be `E→S`. B’s alias is A’s forward-wire form under the identical decision, so clause (i) attaches it to A.
   - The alias export carries **B’s** value unchanged, not A’s ([daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)). Rust also embeds the presented key inside `SyncedSessionEntry`, so B’s alias entry contains `key.src_ip == E` ([worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:375)).
   - Publishing it inserts that alias entry into the canonical and reverse-NAT maps; the reverse slot can displace A’s entry ([shared_ops.rs:907](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907), [shared_ops.rs:918](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:918)).
   - B’s later base drops under clause (ii), but B’s accepted alias remains backed by A’s allocation. Replies can therefore resolve through an entry whose embedded source is `E`, recreating the broken-delivery outcome. Moreover, identical `NatDecision` does not imply identical metadata or resolution; zones, policy, owner RG and forwarding resolution are independent fields ([entry.rs:23](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:23), [forwarding.rs:1030](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/types/forwarding.rs:1030)).

   Thus the merge is distinguishable and harmful. V10 still needs safe zero-ID grouping/deferral/quarantine, or explicit transactional replacement of every published alias artifact. Holder merging alone is insufficient. Section 7 also retains the contradictory v9 invariant that zero-ID aliases drop on conflict ([plan.md:876](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:876)).

2. **NIT — V4/V6 zero-ID alias-test parity is not explicitly carried into §9.**

   The test plan names the generic predicate and alias-first case but never requires both address families ([plan.md:934](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:934)). V4 and V6 use separate alias converters ([daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399), [daemon_ha_userspace_convert.go:509](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:509)). The existing dual-family test only checks shared session IDs, not the new zero-ID import/conflict behavior ([userspace_sync_session_id_6198_test.go:350](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/userspace_sync_session_id_6198_test.go:350)).

The r9 `pub_token` MAJOR is otherwise resolved. Every production shared-map insertion occurs inside `publish_shared_session`, which writes the canonical and all derived rows ([shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897)). Its callers cover session import, all three poll-descriptor publications, tunnel prewarm, reverse activation prewarm, promotion, and learned reverse publication. Activation’s forward leg only clones already-stamped shared rows; it creates no new shared-map row. No production bypass insertion was found. Token-zero prepublication/worker clones are not rows swept from the shared maps.

The settled option (a) is not reopened; the remaining blocker is confined to the zero-ID HA alias protocol.

Codex session ID: 019fc86a-a176-7f60-ae06-a38c38bf45d2
Resume in Codex: codex resume 019fc86a-a176-7f60-ae06-a38c38bf45d2
