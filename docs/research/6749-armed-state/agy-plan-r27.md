# AGY plan review — round 27 — #6749 armed-state plan v8.22 (a5ddf88ed)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r27-prompt.txt` (121,994 bytes —
r26 transport + the r26 table swapped in, the v8.22 normative edits
replayed, the boilerplate rewritten for the v8.22 deltas). Raw
output: `/tmp/agy-6749-r27.out`. Background bash `bzv6j93yf`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (2 MAJOR + 1 MINOR + 1 NIT).

---

1. **[MAJOR] Missing-entry race on a dequeued drain after terminal
   cursor GC** (plan §5-C (ii)): Execution 1 advances the cursor
   to terminal; the 1s pass GCs it; Execution 2 then dequeues and
   looks up the cursor — the key is GONE, and the plan never
   specifies the lookup's missing-entry contract (nil dereference
   / unhandled error vs safe no-op). (= SMR r27 SMR27-2; folded
   v8.23: a MISSING entry is treated as already-terminal — a safe
   no-op; the crash rule never depends on a GC'd entry.)
2. **[MAJOR] Unbounded scheduler queue or unrecoverable stalls on
   queue-drop** (plan §5-C (ii), §9 (a)): the v8.22 "dispatch"
   leaves the queue's capacity/drop policy/mark semantics
   unspecified — a bounded queue that drops strands a
   marked-dispatched entry forever (never pending, never
   terminal); an unbounded queue is an OOM vector. (= SMR r27
   SMR27-1; folded v8.23 by REMOVING the channel: the scheduler's
   per-tick pass iterates the PENDING cursor set — the pending
   set IS the correctness path; no dispatched-flag, no queue, no
   drop policy, no stuck state.)
3. **[MINOR] The r26 SMR26-1 disposition row over-simplifies
   dispatch atomicity** (plan §1 r26 row 1): the row treated
   dispatch as equivalent to execution. Amended v8.23 (the
   iterate-pending-set model + the missing-entry contract).
4. **[NIT] §9 (a) gaps for the GC'd-dequeue no-op and queue
   backpressure** — folded v8.23 (both assertions added).

Evidence wishes (informational): the daemon apply scheduler
implementation (buffer sizes, dispatch loop, drop handling) and
the manager cursor registry definitions.

DEMAND-REVISION
