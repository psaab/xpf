# AGY adversarial review — plan review r2, #2082

OVERALL: PLAN-NEEDS-WORK (one real blocker, two refinements)

(a) Lock discipline: deadlock-free as specified (snapshot/`*Locked` helpers).
    Refinements: use RLock not Lock in the gate helper (read-only); optionally
    fold the preemptNowCh forcePreemptOnce read + gate into one held-lock
    `shouldPreemptObservedMasterLocked()`. [r3: folded into §5.]
(b) RFC 5798 §6.4.2: fully addressed — strict `>`, equal→false, peer-IP field
    removed. Compliant.
(c) Integration honesty: correct (smoke is preempt=false → test-failover is a
    no-regression check only; run-loop unit test authoritative). BUT test
    FEASIBILITY GAP (BLOCKER, same as reviewer A2): starting `go vi.run()` in a
    unit test spawns `go vi.receiver()` → `vi.conn.SetReadDeadline` on nil conn
    → nil-pointer panic crashes the test. Resolution: stub a dummy
    conn/afPacketFD, OR (r3 choice) extract a `stepBackup()` seam so the test
    never spawns the receiver.
(d) Invariants all correct (gate-only-shortcut, priority-0 resign ungated,
    staleness rescues silent-death).

Remaining gaps for READY: document how the run-loop/wiring test avoids the
nil-conn panic; use RLock in the gate; optionally optimize the relock.

NOTE: AGY cited instance.go/vrrp_test.go line numbers as if code already
existed — that is AGY misreading the plan as implemented (this is research-only;
no code written). Its findings about the PLAN are valid regardless and corroborate
reviewer A2's nil-conn blocker independently.

Job: adversarial-review-mqmr4pfq-ij4ibi (succeeded).
