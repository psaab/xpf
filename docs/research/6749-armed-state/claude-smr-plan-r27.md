# Claude SMR plan review — round 27 — #6749 armed-state plan v8.22 (a5ddf88ed)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.22 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the sweep's scan-and-dispatch semantics, the drain-time
EXPOSED composition, the cursor GC, the two-currencies naming, the
§9 (a) additions, and Q1 (27th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 1
NIT. The MINOR is self-found in my own scan-and-dispatch wording
(the "dispatch" mechanism is unpinned — as a channel it inherits a
drop policy and a queue bound; as a mark it needs neither — the
plan must say which). The rest of the v8.22 surface held under my
attacks (trace below). Codex remains infra-blocked (sixth
documented attempt).

---

## SMR27-1 (MINOR) — the sweep's "dispatch" mechanism is unpinned (channel vs mark)

My v8.22 text says the 1s pass "DISPATCHES the per-entry drain
execution to the daemon's apply scheduler" without naming the
mechanism. Two readings with different failure shapes: (i) a
bounded channel — inherits a depth, a drop policy, and a
double-queue case (the notice and the sweep-dispatch can both
queue the same entry's drain; the second execution must see the
cursor complete and skip); (ii) a MARK — the sweep sets the
entry's drain-pending flag and the scheduler iterates the marked
set (the debts' own shape): no queue, no drop policy, duplicates
collapse by construction, and the crash semantics are identical
(the mark is advisory and in-memory, like the notice). Pin (ii):
the sweep-dispatch is a MARK on the pending-cursor entry (the
scheduler's per-tick pass drains the marked set through the one
drain routine); the notice remains the fast-path optimization;
the cursor's `m.mu` check-and-advance is the only exactly-once
authority either way. §9 (a) asserts the mark-and-iterate shape
(a full notice channel plus N pending entries converges with no
queue).

## SMR27-2 (NIT) — the drain's missing-entry posture

A drain dispatched for an entry that a concurrent sweep already
observed terminal and GC'd: the drain looks up the cursor and
finds it GONE. Pin the posture: skip (a GC'd entry is
terminal-by-observation — its work completed or was covered by
the newer pair's chain; the crash rule never depends on a GC'd
entry). One sentence in §5-C (ii).

## Attack trace (what else I tried, and why it fails to break v8.22)

1. **The mark-then-crash edge.** The sweep marks an entry; a
   daemon crash before the scheduler drains it: the cursor and
   the mark are in-memory (lost together); the crash rule
   re-derives exposed < active ⇒ re-run the tails exposed→active
   — the same composition the drain would have run. Coherent.
2. **The double-composition overlap.** The stale notice's drain
   composes A→C (drain-time exposed) while C's own wrapper
   composed B→C: the two deletions overlap on B\C sessions —
   idempotent deletes (a session delete is safe to re-issue).
   Coherent.
3. **The gated-successor × stamp interplay.** C promoted-gated
   while B's notice drains: the stamp/push skip keys on STORE
   currency (B is no longer store-active ⇒ skipped); C's own
   exposure tails stamp C on exposure. No stamp regression, no
   double-stamp. Coherent.
4. **The GC × crash-rule independence.** Recovery derives from
   the `appliedRevision` sidecar + the store trees, never from a
   cursor entry (GC'd or not) — the GC cannot destroy recovery
   information. Coherent.
5. **Q1, twenty-seventh enumeration.** The v8.22 mechanics
   (scan-and-dispatch, drain-time-exposed composition, cursor
   GC, the two-currencies naming) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
6. **The r26 disposition table.** Every row re-derived against
   the file: SMR26-1 (sweep scan-and-dispatch + §9 (a)
   assertion), SMR26-2 (composition + the gated-successor §9 (a)
   assertion + the two-currencies naming), SMR26-3 (the
   e728b2e7d record), SMR26-4 (the GC pin) — all present and
   correctly cited.

## Required for convergence

v8.23: SMR27-1's mark-and-iterate pin (+ the §9 (a) assertion);
SMR27-2's missing-entry sentence. AGY r27 pending at this
writing — its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR + 1
NIT — mechanism-naming level; the v8.22 mechanics held).
