# AGY plan review — round 26 — #6749 armed-state plan v8.21 (b7b9ff1ae)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r26-prompt.txt` (120,054 bytes —
r25 transport + the r25 table swapped in, the v8.21 normative edits
replayed, the boilerplate rewritten for the v8.21 deltas; NOTE the
r25 table in this prompt was the pre-correction row, see f3). Raw
output: `/tmp/agy-6749-r26.out`. Background bash `bh4feiu5m`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 2 MINOR + 1 NIT).

---

1. **[MAJOR] The 1s status-pass sweep synchronously acquires
   `applySem`, risking a status-loop freeze during long control
   applies** (plan §5-C (ii), §1 r25 row 2): the v8.21 sweep pin
   has the 1s pass executing the SAME `applySem`-acquiring drain
   path; a blocking acquire on the status thread stalls
   helper-status ingestion, fabric tracking, and heartbeat for
   the whole hold. (AGY's remedy: TryAcquire or async dispatch.)
   SMR r26 SMR26-1 confirmed and pinned: the 1s pass only SCANS
   and MARKS (under `m.mu`, non-blocking) and DISPATCHES the
   per-entry drain execution to the daemon's apply scheduler
   (the scheduler thread the notice drain rides) — "ONE routine,
   two triggers" lives on the scheduler thread, never the status
   thread.
2. **[MINOR] prior → CURRENT can invalidate sessions for a gated
   (unexposed) successor** (plan §5-C (ii), §9 (a)): C promoted
   but gated means the dataplane still enforces B; composing
   A→C deletes B-authorized sessions. (Remedy: cap CURRENT at
   the exposed pair.) SMR r26 SMR26-2 confirmed and sharpened:
   the composition target is the drain-time EXPOSED pair
   (`m.lastExposedPair`) — A→C when C is exposed, A→B when C is
   gated; the stamp/push gate keys on STORE currency (two
   "currents" named explicitly); §9 (a) gains the
   gated-successor assertion (= AGY f4).
3. **[MINOR] The r25 table's f1 row mis-attributes the closure to
   a prompt-build script typo** (plan §1 r25 row 3): no script
   typo existed — both artifacts read `C-revoked`. Already
   corrected at `e728b2e7d` (the r26 prompt was built from
   pre-correction plan.md, which is how the stale row shipped);
   SMR r26 SMR26-3 records CLOSED-ALREADY.
4. **[NIT] §9 (a) lacks the gated-successor exposure assertion**
   — folds with SMR26-2.

Evidence wishes (informational): the status-loop body/dispatcher
(to pin the sweep's invocation locus) and the invalidation
composition helper.

DEMAND-REVISION
