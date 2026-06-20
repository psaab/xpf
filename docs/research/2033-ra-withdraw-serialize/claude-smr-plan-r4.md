# Claude SMR — hostile plan review r4 (#2033)

Verdict: **PLAN-READY.** r4 folds all of round-3: Codex r3's 3 MAJOR + 1 MOD +
1 MINOR, AGY r3's 2 MAJOR + 1 MINOR, and my r3 N1. I independently re-traced
the now-load-bearing pieces (owner-closes-after-goodbye, graceful-upgrades-hard
under m.mu-released withdrawal, defer+second-pass for Apply/claim, bounded
writes) and they are mutually consistent and correct. The design has converged
to a coherent single-owner model where every shutdown concern (skip, close
race, lock-hold, write-hang, claim deadlock) is handled by ONE mechanism:
**only the owner goroutine emits RAs and closes the conn, after an arbitrated
mode, with bounded writes.** I have no remaining MAJOR/MINOR; the open
questions are genuine /engineer choices, not gaps.

## Re-verification of round-3 folds

- **Codex r3 MAJOR #1 (close race breaks upgrade):** RESOLVED → I17 + §5
  `finishShutdown` is now the SOLE closer, after the goodbye. No caller closes
  directly. A racing hard `Clear` can set mode=hard, but graceful upgrades it,
  and the single owner-close happens after the (upgraded) goodbye. There is no
  longer any close-before-goodbye path. ✔ I traced: `stop()` and
  `withdrawAndStop()` only `signalStop`+`<-stopped`; the close moved into
  `finishShutdown`. Correct.
- **Codex r3 MODERATE #4 (write hang):** RESOLVED → I18 `SetWriteDeadline` on
  every owner write + the seam includes `SetWriteDeadline`. This also removes
  the original justification for hard close-before-join, so owner-closes is
  safe for both modes. ✔
- **Codex r3 MAJOR #2 (I13 mis-cited):** RESOLVED → I13 rewritten. I
  re-verified `daemon_apply.go:1016` `isCluster` guard: in cluster mode no
  `ra.Apply`/`ra.Clear` is called from the apply path; all HA RA ops are on
  VRRP/reconcile goroutines without `applySem`. So `m.mu` is the only
  serialization. ✔ This correctly elevates I16 to load-bearing.
- **AGY r3 MAJOR #2 + SMR r3 N1 + AGY MINOR #3 (m.mu held across withdraw /
  deadlock / upgrade-redundancy coupling):** RESOLVED → I16. Snapshot+delete
  under `m.mu`, withdraw outside. The coupling is now explicit: releasing
  `m.mu` is what makes the graceful-vs-hard race reachable, which is why the
  upgrade is necessary, not redundant. ✔ The Apply-claim deadlock is resolved
  by defer+second-pass (I4).
- **Codex r3 MAJOR #3 (kill option b):** RESOLVED → I4 now mandates defer +
  second pass only; the skip-and-rely-on-reconcile option is killed because it
  drops a MASTER Apply. ✔
- **Codex r3 MINOR #5 (test predicate):** RESOLVED → §5 invariant + §9 T1 now
  assert against the FIRST goodbye seq, with an explicit note that "last write
  is a goodbye" is unsound. ✔

## Independent consistency check of the converged design

I checked the pieces don't contradict each other:
1. Owner is the single writer (all RAs) AND single closer (conn). ✔ no
   caller touches the conn → no close-vs-write or write-vs-write race.
2. Bounded writes (I18) → owner always returns promptly → `<-stopped` in
   `stop()`/`withdrawAndStop()` never hangs → no need for caller close-before-
   join. ✔
3. graceful-upgrades-hard (I13) + owner-close-after-goodbye (I17) → a graceful
   call always yields the goodbye regardless of a racing hard call. ✔ (T7.)
4. `Withdraw` releases `m.mu` before the blocking withdraw (I16) → no
   Status/Apply stall, AND the race in (3) becomes reachable, AND no deadlock
   with the WithdrawOnce claim (I4 defer+second-pass). ✔
5. The headline test (T1) asserts the achievable+sound predicate (no
   lifetime>0 after the FIRST goodbye) under a forced interleave. ✔

No internal contradiction. The one subtle residual: if the OWNER has already
called `finishShutdown` (read mode=hard, sent no goodbye, closed conn) BEFORE a
graceful caller's upgrade store lands, the goodbye is lost. But with I16
(senders deleted from the map under m.mu before the hard path runs), a
graceful `Withdraw` and a hard `Clear` operate on the SAME `*sender` only if
both captured it before deletion — and the first `signalStop` to fire wins the
`stopOnce`; the upgrade `Store` is unconditional so it lands before the owner
reads mode UNLESS the owner already woke and read. That window exists but is
genuinely tiny (owner wakeup latency after a close it didn't cause yet) and the
new primary's RA is the recovery. This is the honest residual; it is documented
(Q3) and acceptable for a best-effort goodbye. It is NOT the original bug (a
normal RA AFTER the goodbye) — it is at worst a MISSED goodbye on a
double-teardown, which the periodic RA lifetime expiry + new primary cover.

## Conclusion

**PLAN-READY.** Four rounds, three independent reviewers, daemon-call-paths
verified, the design converged to a single-owner model with all shutdown
hazards funneled through one mechanism. Path A confirmed over Path B
decisively (Path B cannot cleanly express owner-closes / bounded-writes /
single-writer). Remaining open questions are /engineer choices (Q-list), not
correctness gaps. Recommend proceeding to /engineer 2033 with Path A.
