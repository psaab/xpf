# AGY plan review — round 24 — #6749 armed-state plan v8.19 (8d1911b5f)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r24-prompt.txt` (126,135 bytes —
rebuilt from the r23 transport by swapping the r22 table for the
r23 table, replaying the v8.19 normative edits on the inline doc,
eliding the closed §6 wire items 10-13, and rewriting the
boilerplate for the v8.19 deltas). Raw output:
`/tmp/agy-6749-r24.out`. Background bash `bych5k71e` (direct `agy
--print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 2 MAJOR + 1 MINOR + 1
NIT).

---

1. **[BLOCKER] Catch-up completion notice drains un-semaphored and
   out-of-order relative to newer commits** (plan §5-C (ii), Delta
   3): B accepted via catch-up posts its notice; C promotes and
   applies under `applySem`; the stale notice then drains and runs
   B's tails — the A→B invalidation deletes sessions C re-permits
   (live authorized traffic), and B's applied stamp overwrites
   C's. (AGY's proposed gate: `applySem` or
   `notice.revision == ActivePair().revision` re-verify.) SMR r24
   SMR24-1 independently derived the same hole and showed the
   abort-only fix LEAKS (C's B→C delta never covers
   A-permitted/B-revoked/C-revoked sessions): the folded fix is
   the plan's own uniform-base rule — the drain acquires
   `applySem`, re-reads the CURRENT pair, composes prior →
   CURRENT, currency-gates the stamp/push, and marks the
   superseded cursor entry SUPERSEDED (terminal).
2. **[MAJOR] Data race on `cursor.completionState` between the
   Compile-leg wrapper and the listener thread** (plan §5-C (ii),
   §6, Delta 3): the exactly-once authority lacks a pinned mutex
   for the check-and-advance. SMR r24 SMR24-2 confirmed (pin: one
   manager method under `m.mu` for every cursor
   read-modify-write; the transports are per-acceptance unique so
   the residual race is phase-level).
3. **[MAJOR] Dropping `m.lastSnapshot` on OVERLAP finalization
   risks nil dereference in auxiliary producers** (plan Delta 4;
   process_status.go:11 vs manager_overlay.go:188). SMR r24
   SMR24-3 downgraded to MINOR on the nil-guard census (overlay
   manager_overlay.go:129/:134, neighbor, HA, status,
   applied_nat_view all nil-guard under `m.mu` — VERIFIED): the
   fold pins the post-clear value as NIL (no retained second
   reference; revert-to-published impossible), adds the census as
   a build-time canary, and states the transient overlay/
   scheduler publish gap.
4. **[MINOR] Bounded-channel overflow drops catch-up notices**
   (plan Delta 3): a full buffer loses the completion tails
   permanently. (Resolution folded: the notice is an optimization
   over a periodic pending-cursor sweep on the daemon scheduler;
   the enqueue failure Warns.) SMR r24 SMR24-4 confirmed.
5. **[NIT] §9 lacks the interleaved notice-drain assertion**
   (plan §9): assert a stale notice for B arriving after C's
   application neither overwrites C's stamp nor invalidates C's
   sessions. Folds with SMR24-1/SMR24-6's §9 (a) assertions.

Evidence wishes (informational): daemon_policy_invalidate.go,
daemon_ha_sync.go (`reconcileConfigSyncToPeer`),
manager_overlay.go:188 — the third was partially covered by the
inline census verification this round.

DEMAND-REVISION
