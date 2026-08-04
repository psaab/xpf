# Claude SMR plan review — round 28 — #6749 armed-state plan v8.23 (6c6d00b09)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.23 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the iterate-pending-set scheduler model, the missing-entry
contract, the cursor GC × drain-execution interplay, the §9 (a)
additions, and Q1 (28th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 2 MINOR + 0
NIT. Both MINORs are self-found in my own v8.20-v8.23 cursor
wording (the check-and-advance is ambiguous between claim-or-skip
and check-then-execute-then-advance — only the first is
exactly-once; and a failing tail's retry cadence is unpinned).
The rest of the v8.23 surface held under my attacks (trace
below). Codex remains infra-blocked (seventh documented
attempt).

---

## SMR28-1 (MINOR) — the check-and-advance needs the claim-or-skip tri-state

My v8.20 text makes every cursor read-modify-write go through
"ONE manager method under `m.mu`", and v8.23 says the check-and
-advance is "the only exactly-once authority" — but the PHASE
model has only two states in the text (pending, terminal), and
two concurrent drains (the notice-triggered and the
scheduler-iterated) expose the ambiguity: if the method is
check-then-execute-then-advance, drain A checks phase k
(pending), executes the (slow) tail, and advances — while drain
B checks the SAME phase (still pending — A has not advanced)
and executes the SAME tail concurrently (double invalidation,
double push — not exactly-once). The exactly-once model
requires the CLAIM: per phase, pending → claimed → complete,
with claim-or-skip atomic under `m.mu` (a duplicate claimant
skips the phase — the first drain's execution covers it; a
claimed-but-crashed drain is the in-memory-loss case the crash
rule re-derives; a claimed-but-slow drain makes the duplicate
skip and the claimed phase completes on the first drain). Pin:
the phase state machine is tri-state, the claim is the atomic,
and the §9 (a) double-run assertion exercises the
claim-collision (two concurrent drains, one phase, exactly one
execution).

## SMR28-2 (MINOR) — the failing-tail retry cadence is unpinned

In the iterate-pending-set model, a drain that FAILS mid-tails
(a peer push error, a stamp persistence error) leaves the entry
pending — retried on the next scheduler tick, which my v8.23
text sets at the 1s pass: a permanently-failing tail (e.g. the
peer's control socket persistently refusing) loops the FULL
drain (applySem + invalidation compose + push attempt) every
1s forever — log spam and applySem pressure for a deterministic
failure, against the plan's own standing posture (the
5/10/20/60s exponent-preserving backoff + the fingerprint
Warn). Pin: the entry stays pending (correct), the retry rides
a per-entry `nextAttempt` on the standing backoff ladder (the
scheduler's per-tick pass skips entries whose `nextAttempt` is
in the future), and the failure Warns on the standing
edge-detect — stated next to the sweep text; §9 (a) asserts
the backoff (two consecutive failures do not produce two
back-to-back full drains).

## Attack trace (what else I tried, and why it fails to break v8.23)

1. **The GC-during-execution window.** The drain captures the
   entry under `m.mu`, executes the tails outside it, and
   advances at the end; during the window the entry reads
   INCOMPLETE, so the 1s pass cannot GC it (it GCs only
   terminal entries); the final advance makes it terminal and
   the NEXT pass GCs it; a concurrent drain for the same entry
   then hits the missing-entry contract (safe no-op). Coherent
   (given SMR28-1's claim).
2. **The notice-vs-iterate overlap.** A notice for an entry the
   scheduler already drained: the notice's drain sees the
   terminal state and skips; the scheduler's iterate skips
   terminal entries by construction. Coherent.
3. **The registry's other readers' missing-key handling.** The
   sweep iterates (no per-key lookup); the crash rule reads the
   sidecar + store, never the registry; the notice post does
   not read the registry. No unspecified reader remains.
4. **Q1, twenty-eighth enumeration.** The v8.23 mechanics
   (iterate-pending-set, missing-entry contract, §9
   assertions) mutate NO binding slots on any refuse/degrade
   path. No new `Registered && !Armed && state==none` producer.
   Q1 holds.
5. **The r27 disposition table.** Every row re-derived against
   the file: SMR27-1 (the iterate-pending-set model + the r26
   row amendment) and SMR27-2 (the missing-entry contract + the
   §9 (a) assertions) both present and correctly cited.

## Required for convergence

v8.24: SMR28-1's claim-or-skip tri-state (+ the §9 (a)
claim-collision assertion); SMR28-2's per-entry backoff +
Warn pin (+ the §9 (a) assertion). AGY r28 pending at this
writing — its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 2 MINOR +
0 NIT — semantics-pin level; the v8.23 model held).
