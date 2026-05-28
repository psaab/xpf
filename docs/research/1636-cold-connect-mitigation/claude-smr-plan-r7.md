# Claude SMR plan review — round 7 (#1636) — CONVERGENCE

**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v7 @ `3f9aecc700c9`.

## Verdict: PLAN-READY

This is round 7. Convergence is achieved:

- **Codex r6**: PLAN-READY (token-level fixes only)
- **AGY r7**: PLAN-READY (3 low-severity doc nits for /engineer)
- **Claude SMR r7**: PLAN-READY (this verdict)

All architectural questions are settled. The remaining doc nits (AGY r7 #1-3 — `self.ha.rg_runtime` access path, drop §8 last_warm_sweep_ns duplicate mention, fabric `parent_ifindex` field name) are implementation details the /engineer phase will catch in code review.

## Final acceptance for /research

The plan-of-action is converged. Implementation can proceed via `/engineer 1636`:

1. **PR-1**: B (sysctl drop-in `/etc/sysctl.d/99-xpf-neighbor.conf` setting `net.ipv4.neigh.default.retrans_time_ms = 250` + v6 equivalent). No Rust. Empirically measure cold connect on the loss userspace cluster.

2. **PR-2**: C (proactive neighbor warm). Per the §7 design:
   - `NeighborManager` gains: `last_probed_at`, `warm_queue`, `warm_stop`, `warm_generation`, `warm_drops`, `warm_disconnected`, `warned_disconnect`, `last_warm_sweep_ns`.
   - `Coordinator` gains: `queue_warm_pass(&self, force: bool)` + `on_rg_promote_active(&self)` + `on_link_up(&self, ifindex: i32)`.
   - Long-lived warmer worker thread (`warmer_loop`) fed via crossbeam_channel::bounded(4096). Per-RG check via `self.ha.rg_runtime.load()`. Per-key 5s rate-limit, per-snapshot 1s rate-limit (force bypassable). GC every iteration keyed off `last_gc_ns`.
   - Targets: `forwarding.routes_v4.values().flat_map(...).filter_map(|r| r.next_hop)` + `routes_v6` + `forwarding.fabrics.iter().map(|f| (f.parent_ifindex, f.peer_addr))`.
   - Tests per §12 (mocked netlink fixture, per-key/per-sweep rate-limit unit tests, warmer-worker MPSC tests, RG-promote/link-up cache clears).
   - Smoke matrix per §12 (v4+v6 × push+reverse × CoS-on+CoS-off).

3. **PR-3 (optional)**: D (lower `PENDING_NEIGH_TIMEOUT_NS` to 800ms via ForwardingState computed value). After empirical measurement.

## Reviewer convergence statement

3-of-3 PLAN-READY (Claude SMR + Codex + AGY). Copilot joins as 4th reviewer at `/engineer 1636` time on the implementation PR. Per `feedback_codex_infra_must_retry` — Codex r3 was REVIEW-BLOCKED but successfully retried at r4-r6. All 3 reviewers verified the kernel-side ARP timing claim independently against `net/core/neighbour.c`.

Plan doc at branch `research/1636-cold-connect-mitigation` commit `3f9aecc700c9`.
