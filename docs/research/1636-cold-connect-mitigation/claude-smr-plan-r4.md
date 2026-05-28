# Claude SMR plan review — round 4 (#1636)

**Domain hat**: same as prior rounds.
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v4 @ `d5a4a5eb87b5`.

## Verdict: PLAN-READY

v4 has folded:
- All of my r1 and r2 findings
- All of Codex r1 and r2 findings
- All of AGY r1, r2, and r3 findings
- Codex r3 was tooling-blocked; the r3 retry with inlined sections is in flight at task-mppsygv9-n0gwuq

The plan is now design-tight enough that I can attest PLAN-READY in good conscience. Specifically:

### What's resolved

1. **Kernel rate-limit + option A**: A removed; §5 + §5.1 document the kernel semantics with quoted source citations from Codex r1 #1.
2. **Option D timing**: D=800ms per AGY r3 #4 strict-dominance argument. The 700ms variant was a measurement-wins-50ms argument that AGY correctly refuted as kernel-state-machine-async.
3. **Generation collapse**: warm_generation AtomicU64 + per-item tag; warmer worker drops stale on dequeue.
4. **HA invariant precision**: §9 invariant 2 expanded — warm pass runs only when `ha.is_active() == true` AND dataplane MAC/VIP/egress committed. `on_rg_promote_active()` clears `last_probed_at`. `on_link_up(ifindex)` clears matching keys.
5. **GC bypass under load**: AGY r3 #2 fix — GC runs at top of every warmer_loop iteration keyed off `last_gc_ns`, idle OR dequeue path. Cost: one atomic read + compare per iteration, negligible.
6. **Producer error handling**: `TrySendError::Full` (counted as `warm_drops`, log gated on `debug-log`) vs `TrySendError::Disconnected` (counted as `warm_disconnected`, log NOT gated — operators must see). Both counters MANDATORILY exposed as Prometheus.
7. **Tunnel endpoints**: out of scope per AGY r1 #3.
8. **Connected subnets**: out of scope per AGY r2 #5 (broadcast storm risk).
9. **§10 acceptance gate**: derived per-option × per-scenario; honest about p99 limits.
10. **PR sequence**: B sysctl first (no Rust, fully reversible), measure, then C, then optionally D.

### Remaining open questions (open for /engineer to resolve, not blocking PLAN-READY)

- **Connected subnets / `forwarding.connected_v4/v6`** (my r2 #14.1): the plan keeps this out-of-scope. For a first ship targeting "operator-configured next-hops", this is fine. Follow-up issue likely.
- **`last_probed_at` cleanup on DOWN events**: currently only on UP. Flapping interfaces could in theory build up stale entries — but the 5min GC pruner cleans them. AGY r3 #3 mitigation is sufficient.
- **Operator CLI knob**: deferred to follow-up.
- **NUD_FAILED reactive re-kick**: noted in §14 question; out of scope for initial ship.

### Why PLAN-READY

This is round 4. The plan has been hostile-reviewed by 3 distinct reviewers over 4 rounds. The directional recommendation hasn't changed since r2 (B sysctl → measure → C warmer-worker → maybe D timeout=800ms). The technical content has tightened substantially each round. We're at the point where additional rounds would produce diminishing returns.

If Codex r4 (or AGY r4) finds a NEW fatal flaw in v4, I'll revise this verdict. Otherwise PLAN-READY is the correct call.

### Acceptance for /engineer phase

If Codex r4 + AGY r4 also attest PLAN-READY (or PLAN-NEEDS-MINOR with foldable nits), the plan converges. Implementation phase:

1. **PR-1**: sysctl drop-in. No Rust. Measure on loss userspace cluster.
2. **PR-2**: Rust warmer-worker implementation per §7 sketch. Test plan per §12. Smoke matrix per §12.
3. **PR-3 (optional)**: D=800ms one-line constant change after PR-2 measurement informs.

Each PR goes through `/engineer` quad-review (Claude SMR + Codex + AGY + Copilot).
