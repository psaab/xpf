# Hostile reviewer A — plan confirm r3 (A3), #2082

OVERALL: PLAN-READY

Confirmed the r3 stepBackup() seam genuinely closes the r2 nil-conn blocker:
- go vi.receiver() spawned at exactly ONE site (instance.go:306, run() preamble);
  the seam touches none of it → no nil conn.SetReadDeadline (instance.go:445).
- StateBackup select body (instance.go:351-374) depends only on
  vi.stopCh/vi.rxCh/vi.preemptNowCh + the two timer locals → clean,
  behavior-preserving extraction; the only subtlety (stopCh return) is handled
  by the §7 returned-bool signature.
- becomeMaster() fail-soft chain holds on a fake-iface/nil-socket test instance
  (addVIPs Warn+return, sendPacket/sendPacketIPv6 nil-guards, emitEvent
  non-blocking, suppressGARP skips the goroutine). newInstance(&net.Interface{
  Name:"eth0"}, nil sockets) is the established 24+-site test pattern;
  TestHandleMasterRx_HigherPriority_StepsDown already drives a handler this way.
- Pre-loading cap-1 preemptNowCh (triggerPreemptNow) before stepBackup() is
  deterministic IF tests use long-duration timers (time.NewTimer(time.Hour),
  the existing idiom). Implementer note: do NOT use already-expired timers in
  tests #1/#2/#5/#6. [folded into §7.]
- r3 folds correct: AdvertiseInterval in the §5 snapshot; RLock-not-Lock; line
  cites fixed (372, 727, 445).
- No new flaw from the extraction; lock-non-reentrancy is the one binding rule,
  pinned in §5. Reachability CONFIRMED (not PLAN-KILL).

Agent: general-purpose hostile-reviewer-A3 (agentId a876122896625a0ce).
