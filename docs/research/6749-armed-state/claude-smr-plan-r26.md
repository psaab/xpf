# Claude SMR plan review — round 26 — #6749 armed-state plan v8.21 (b7b9ff1ae + e728b2e7d)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.21 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the SUPERSEDED reword's residue, the sweep's 1s-pass pins,
the §9 (a) skip-everything pin, the lock-order census, the
chain-state note, the f1 record correction, and Q1 (26th
enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 1 MAJOR + 3 MINOR + 0
NIT. The MAJOR is self-found in my own v8.21 sweep pin (the 1s
status pass must never block on `applySem` — my "one routine, two
triggers" wording lets the status thread freeze behind a long
control apply). AGY r26 (1 MAJOR + 2 MINOR + 1 NIT) independently
found the same two substantive pins; Codex remains infra-blocked
(fifth documented attempt).

---

## SMR26-1 (MAJOR) — the sweep's drain execution must never block the status thread (= AGY r26 f1)

My v8.21 pin says the sweep "rides the 1s status-application pass"
and "the sweep's per-entry execution is the SAME
`applySem`-acquiring drain path as the notice's (ONE routine, two
triggers)". Read literally, the 1s status pass executes a blocking
`applySem.Acquire` — and `applySem` can be held for minutes by a
long control apply (the sequential capped control requests). A
blocking acquire on the status thread freezes helper-status
ingestion, fabric map tracking, and heartbeat monitoring for the
whole hold — a liveness hazard the v8.21 pin INTRODUCED (the v8.20
"standing debt cadence" form had the drain on the scheduler
thread, where blocking is safe). Pin (the correction, not a
redesign): the 1s pass only SCANS and MARKS pending cursors
(under `m.mu` — fast, non-blocking) and DISPATCHES the per-entry
drain execution to the daemon's apply scheduler (the same
scheduler thread the notice drain rides); the "ONE routine, two
triggers" lives on the scheduler thread (notice-triggered or
sweep-dispatched), where the blocking acquire is safe; the status
thread never takes `applySem`. §9 (a) asserts the status pass
completes without `applySem` contention (a held `applySem` does
not stall the pass — the entries dispatch and the next tick
re-scans).

## SMR26-2 (MINOR) — the drain-time composition target is the drain-time EXPOSED pair, not `ActivePair()` (= AGY r26 f2 + f4)

My v8.20/v8.21 fold says the drain "re-reads the CURRENT pair at
drain time" and composes prior → CURRENT. Trace the gated
successor: B exposed via catch-up (notice queued); C promoted
GATED (`R_c > durableRevision` — store-active but unexposed; the
dataplane still enforces B). If CURRENT reads `ActivePair()` = C,
the invalidation A→C deletes sessions by C's policy while C is
not enforced — killing B-authorized traffic (the exposure gate's
invariant: an unexposed config never alters session posture). The
correct target is the drain-time EXPOSED pair
(`m.lastExposedPair` under `m.mu`): C exposed ⇒ A→C (the SMR24-1
case); C gated ⇒ A→B — exactly the sessions the ENFORCED config
revokes, and C's own exposure tails compose B→C later. One rule
covers both shapes. And the stamp/push gate keys on STORE
currency (unchanged — skip when the notice's pair is no longer
store-active; the two "currents" are named explicitly). §9 (a)
gains the gated-successor assertion (C promoted-gated: the drain
composes prior → B, never prior → C).

## SMR26-3 (MINOR) — the r25 table's f1 row mis-recorded the closure (= AGY r26 f3, CLOSED-ALREADY)

The v8.21 table row blamed a "prompt-build script" typo; the
correction commit `e728b2e7d` (post-v8.21, pre-r26-prompt —
actually the r26 prompt was built from pre-correction plan.md,
which is how AGY saw the stale row) re-records it as NOT-VERIFIED
(spurious — both artifacts read `C-revoked`; an AGY misread of
the wrapped clause pair). Already folded; the r26 table carries
the SHA.

## SMR26-4 (MINOR) — the cursor registry's terminal-entry GC is unpinned (self-found)

The sweep scans "the pending-cursor set" every 1s pass; cursors
reach terminal states (completed, SUPERSEDED) but no GC rule is
stated — a churn storm accumulates terminal entries for the
daemon's lifetime and the 1s scan degrades to O(lifetime
acceptances). Pin: a cursor entry is GC'd on the sweep pass that
first observes it terminal (completed or SUPERSEDED), so the
registry's live set is bounded by concurrently-incomplete
exposures (a handful), and the scan is O(handful). The exactly-once
semantics are unaffected (a terminal entry's work is done; the
crash rule re-derives from the sidecar + store, never from a GC'd
entry).

## Attack trace (what else I tried, and why it fails to break v8.21)

1. **The reword's residue.** Every SUPERSEDED context re-read
   (the normative text, the r24 row, §9 (a), the §6 note): all
   now scope the skip to the pair-specific tails; the §6 note's
   "marks a superseded entry SUPERSEDED" sits next to the
   currency gate and reads correctly in context. Clean.
2. **The sweep × notice double-dispatch.** An entry dispatched by
   the sweep while its notice also lands: the cursor's
   `completionState` check-and-advance (m.mu) lets the first
   executor win; the second sees complete/SUPERSEDED and skips.
   Coherent.
3. **The gated-successor stamp.** C promoted-gated while B's
   notice drains: B is no longer store-active ⇒ stamp/push
   skipped (store-currency gate); C's own exposure tails stamp C
   later. No stamp regression. Coherent (and now explicit in
   SMR26-2).
4. **Q1, twenty-sixth enumeration.** The v8.21 mechanics
   (reword, sweep pins, §9 pin, census, chain note) mutate NO
   binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
5. **The r25 disposition table.** Every row re-derived: SMR25-1,
   SMR25-2, SMR25-3, SMR25-4 rows verified present and correct;
   the AGY f1 row was stale at the r26-prompt build and is
   corrected at `e728b2e7d` (SMR26-3).

## Required for convergence

v8.22: SMR26-1's scan-and-dispatch pin (+ §9 (a) assertion);
SMR26-2's drain-time-exposed composition + the two-currencies
naming + the gated-successor §9 (a) assertion; SMR26-4's GC pin;
SMR26-3 recorded (already folded at `e728b2e7d`). AGY r26's
f1-f4 map onto SMR26-1/2/3/2 respectively.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 1 MAJOR + 3 MINOR + 0
NIT — pins on the v8.21 sweep/composition wording; nothing
architectural).
