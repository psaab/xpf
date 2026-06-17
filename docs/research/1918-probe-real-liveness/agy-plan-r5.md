VERDICT: PLAN-READY

### Findings

1. **Deadlock Hazard in `linkGen` Lock Scope (Lines 269-270 vs 301-303):**
   The plan proposes:
   > "Before the netlink op, the runner re-reads t.linkGen[tunnelName] under t.mu" (Lines 269-270)
   If [Apply](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L94) holds `t.mu` and attempts to drain the runner:
   > "cancel + drain the existing keepalive runner FIRST (move the cancel/<-done ahead of the LinkByName/LinkDel/LinkAdd recreate block" (Lines 301-303)
   A classic deadlock occurs if the runner tick is in progress and blocks on `t.mu.Lock()` while `Apply` blocks on `<-runner.done`.
   *Resolution:* The runner must **not** acquire `t.mu`. The generation check should instead read `linkGen` atomically (e.g. using `atomic.Uint64`) or be omitted entirely, as drain-before-recreate guarantees safety by construction.

2. **Draining Safety and Lock-Across-Netlink Check (a):**
   Given the runner tick does *not* acquire `t.mu`, draining does **not** deadlock. The runner only holds the fine-grained `state.mu` briefly at the start of its tick and releases it before executing netlink calls or socket I/O. `Apply` calling `cancel` and blocking on `<-runner.done` will safely wait for any in-flight tick to complete and exit. No new lock-across-netlink is introduced since netlink calls are performed outside all locks.

3. **Retain Path Correctness (b):**
   Moving the drain earlier does **not** affect the correctness of the retain/no-recreate path. When a tunnel configuration does not require recreation, `Apply` does not cancel or drain the runner:
   > "when a per-tunnel apply is going to recreate or replace the link, cancel + drain the existing keepalive runner FIRST" (Lines 301-303)
   The existing runner continues ticking uninterrupted.

4. **F7 Window Elimination:**
   Drain-before-recreate successfully eliminates the F7 race window:
   > "no stale runner goroutine exists during the recreate. After the drain, the old runner is guaranteed not to issue any further LinkSet*" (Lines 303-305)
   Because the old runner is fully stopped before the new link is recreated, it cannot race or target a reused ifindex.

See [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1918-research-probe-real-liveness/docs/research/1918-probe-real-liveness/plan.md) for context.
