# Hostile reviewer B — plan review r1, #2082

OVERALL: PLAN-NEEDS-WORK

Reachability + harm CONFIRMED. Path A is the right choice. Required changes:

1. Fix the concurrency model — r1 wrongly framed "receiver goroutine writes
   lastMaster*, run loop reads" (cross-goroutine TOCTOU). FACT:
   handleBackupRx/handleMasterRx run in the run-loop goroutine
   (instance.go:354-355,386-387); receiver only `rxCh <- pkt`. Record + gate
   are co-goroutine, serialized — no TOCTOU. The only lock rule is RWMutex
   non-reentrancy: snapshot lastMaster* under vi.mu, release, then call
   getPriority()/getPreempt() (track.go:33, instance.go:253).
2. Integration test reality is a BLOCKER, not a caveat: smoke cluster is
   preempt=false (ha-cluster-userspace.conf:70-91); scripts assert no-preempt
   (test-chained-crash.sh:362, test-double-failover.sh:239). With preempt=false
   the bug path never runs → test-failover validates nothing. Require a
   preempt-enabled run-loop/unit repro; do NOT add preempt to the shared smoke
   cluster (breaks no-preempt assertions).
3. Expand staleness fallback (§6): credit lastMasterSeen>masterDownInterval as
   the rescue for stale-high lastMasterPriority after a SILENT (non-priority-0)
   master death; bound deny window to masterDownInterval; note priority-0
   resign takeover is unaffected (ungated masterDownTimer.C path,
   instance.go:728,357-358).
4. Note pre-existing force/non-force preemptNowCh coalescing (cap-1 channel,
   ForceRGMaster sets forcePreemptOnce before trigger, getState()!=StateMaster
   guard): Path A changes only the force==false branch, coalescing unchanged.

HARM CONFIRMED (Path C rejected): spurious Secondary becomeMaster emits MASTER
VRRPEvent → watchVRRPEvents (daemon_ha.go:395-422) → on all RG instances
flipping, allMasterLocked() (rg_state.go:256, non-strict mode) →
rg_active=true on Secondary + removeBlackholeRoutes + applyRethServicesForRG +
GARP. Real transient split-brain, not noise. Self-heal via next Primary advert
~one advert interval (handleMasterRx pktPri 200>100 → becomeBackup); the
CheckVRRPPosture resign path is 2s/10s delayed so the advert is the fast healer.
