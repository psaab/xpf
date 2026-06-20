# Hostile reviewer B — plan re-review r2 (B2), #2082

OVERALL: PLAN-READY

All four r1 points closed and verified against source:
- Concurrency model corrected throughout (record+gate co-goroutine, single-
  goroutine serialization invariant correct; RWMutex non-reentrancy preserved
  as the real hazard; masterDownInterval() also self-RLocks → needs *Locked).
- Integration honesty correct (smoke preempt=false confirmed; scripts assert
  no-preempt; test-failover no-regression-only; run-loop unit test authoritative).
- Staleness invariant (c) covers cold-start AND silent-master-death bounded to
  masterDownInterval; priority-0 resign ungated (masterDownTimer.C path) (b);
  gate-only-shortcut (a) — masterDownTimer.Stop() inside taken branch (372).
- Coalescing note correct (§8).

New hostile pass:
- Harm REAL and realized even in multi-VLAN RGs (per-sub-interface instances all
  share GroupID, all get triggerPreemptNow → allMasterLocked() → rg_active=true
  on Secondary). NOT mitigated by multi-instance.
- Self-heal leaves NO durable rg_active damage (BACKUP event resets it; 2s
  reconcile loop backstops even if the event drops).
- vrrp is the RIGHT fix layer (rg_state faithfully reflects the wrong VRRP
  input; fixing rg_state would mask the bad VIP/advert/GARP).
- strict `>` correct for all cases incl. standalone (equal-no-preempt is RFC).

Agent: general-purpose hostile-reviewer-B2 (agentId a2744f21be78fde12).
