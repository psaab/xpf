# Codex plan review r3 — task-mqac1mk2-l40m4t (session 019eb9c0-416e-7e80-8ae7-bd4ff7113e5c)

Verdict: PLAN-NEEDS-REVISION. r2 findings all addressed in text.

1. H — retry loop lacks daemon lifecycle/cancellation invariant: daemon
   constructs frr.New() (daemon_run.go:241), shutdown only cancels the
   daemon ctx (daemon_run.go:1179); nothing stops the retry goroutine or
   its in-flight child. Require manager-owned context + Stop()/wait +
   pgroup kill on cancel + cleanup-one-shot-never-retries.
2. M — supersession/gauge race: atomic rename prevents torn reads, not
   the retry-loads-A / ApplyFull-renames-B / retry-succeeds-on-A /
   gauge-falsely-clears edge. Require reloadMu over the full
   write+reload critical section or a confGen check; unit coverage for
   the stale-success edge.
3. L — "30s worst case" stale once WaitDelay added (vtysh.go:88
   precedent is 5s): real bound 30s + 1-2 WaitDelay windows.
