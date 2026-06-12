**R2 Resolution Audit**

- C1: RESOLVED. v5 uses attempt `baseline_session`/`local_index` identity, not timestamps, at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:501), backed by collision refusal in `install_session_locked` at [engine.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs:656).
- C2: RESOLVED. §5.1 reverses cached-clock enforcement and specifies per-use `CLOCK_MONOTONIC` via `WgEngine::now_ns()` plus test mock at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:308); S3 coarse-clock concern remains in §7.5 at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:649).
- C3: RESOLVED. `u64::MAX` sentinel, `next_deadline = 0` first-pass forcing, and recompute-from-scratch are explicit at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:415).
- C4: RESOLVED. `consume_response` Ok now sends exactly one stamped/countable keepalive at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:459), matching Linux’s immediate-confirmation path in [receive.c](/home/ps/git/linux/drivers/net/wireguard/receive.c:180).
- C5: RESOLVED. v5 requires one bulk signal-then-join helper across stale-prune, stop-all, and deferred snapshot prune at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:561).

**AGY Fold Sanity**

- A1: The consumption itself is right and does not disturb T8 traversal semantics because `last_send_any_ns`/`last_recv_any_ns` remain intact. It does, however, exposes the separate T7 “latest send vs armed send” problem below.
- A4: Correct for the AGY failure mode: continuous inbound-only traffic will no longer suppress passive keepalives forever. Not strictly kernel-equivalent for first-fire timing; see finding 2.
- A2: Correct. `confirmed && unexpired` matches the existing unconfirmed egress gate in [session.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/session.rs:82) and [engine.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs:728).

**New Findings**

1. BLOCKER - T7 is still modeled as “latest data send,” so continuous outbound traffic can suppress dead-peer reinit forever.
   Evidence: v5 stores `last_send_data_ns` on every successful non-empty encap at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:177) and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:335). Linux arms the new-handshake timer only if it is not already pending, then clears it only on authenticated receive: [timers.c](/home/ps/git/linux/drivers/net/wireguard/timers.c:147) and [timers.c](/home/ps/git/linux/drivers/net/wireguard/timers.c:176). With v5, outbound packets every second and zero inbound keep refreshing the stamp, so T7 never reaches 15s; responder-role sessions then wait until T3 instead of repairing the blackhole at T7.
   Fix direction: replace `last_send_data_ns` with an armed T7 send timestamp, or add a separate `t7_armed_send_ns`; set it only when unarmed, clear/consume it on any authenticated receive or attempt start, and add a continuous outbound-only regression test.

2. MINOR - A4 overclaims kernel-equivalence for passive keepalive timing.
   Evidence: v5 says T6 fires on `last_recv_data_ns > last_send_any_ns && now - last_send_any_ns >= 10s` at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:165). Linux schedules `timer_send_keepalive` for receive-time + 10s when no timer is pending, and uses `timer_need_another_keepalive` for additional inbound data while pending: [timers.c](/home/ps/git/linux/drivers/net/wireguard/timers.c:157). v5 can send an immediate passive keepalive on the first inbound data packet after a long idle because `last_send_any_ns` is old.
   Fix direction: either document this as an intentional over-eager deviation, or add passive keepalive pending/due state if “kernel-equivalent” remains the bar.

PLAN-NEEDS-REVISION - v5 resolves C1-C5 and most AGY folds, but the T7 stamp model still suppresses no-reply reinit under continuous outbound traffic, which is the dead-peer repair this plan is supposed to ship. The T6 predicate also overclaims kernel equivalence; both fixes are bounded, but the section-of-record cannot be handed to implementors as-is.