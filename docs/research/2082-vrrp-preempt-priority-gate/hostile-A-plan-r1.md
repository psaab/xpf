# Hostile reviewer A — plan review r1, #2082

OVERALL: PLAN-NEEDS-WORK

Reachability CONFIRMED REACHABLE (every link traced to source @ 4565a9ee1;
PLAN-KILL correctly rejected). Timing safe (legitimate promotion is
ForceRGMaster force=true, bypasses gate). Two concrete defects required before
READY:

1. Test as written (helper-direct "preferred") would let a non-wired
   implementation pass — the regression-guard test MUST drive the actual
   `run()` `preemptNowCh` case and assert the BACKUP node stays BACKUP, not just
   call `shouldPreemptObservedMaster()` in isolation (precedent: vrrp_test.go
   re-implements handler logic inline → same trap).
2. Self-deadlock is a binding design rule, not a "verify": `getPriority()`
   (track.go:32-34) and `getPreempt()` (instance.go:252-254) both RLock vi.mu;
   Go RWMutex non-reentrant. Helper MUST snapshot all inputs under one RLock and
   inline the track-clamp, never call getPriority()/getPreempt() while holding
   vi.mu.
3. Require confirming the smoke RG sets `preempt`; if not, add a preempt-enabled
   repro or explicitly downgrade the integration claim to no-regression-only so
   test-failover green is not mis-cited as proof.
4. Pin equal-priority-with-nil-localIP behavior explicitly (defaults to "we
   preempt") so test #6 is unambiguous. [r2: moot — IP tie-break dropped.]

(Full transcript relayed to orchestrator; key source citations:
compiler_system.go:1052-1053, vrrp.go:97/154/173, group_state.go:207-219,
manager.go:159-162, daemon_ha_sync.go:88, daemon_run.go:552-556,
instance.go:369/354-355/386-387, daemon_ha.go:235-244/636-644.)
