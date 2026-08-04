# Claude SMR plan review — round 35 — #6749 armed-state plan v8.30 (1b3cf5138)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.30 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the captured-digest stamp form, the stamp-LANDS assertion,
the exposed-currency gate's residue, and Q1 (35th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 1
NIT. The MINOR is self-found in my own v8.30 fold (the captured
digest's SOURCE is unpinned for the catch-up acceptance leg —
"the pair's OWN digest" must come from the store's RETAINED TREE
for the pair's revision, never from `ActiveDigest()` at drain or
acceptance time, or the form re-opens the #6296 class it cites).
Codex remains infra-blocked (fourteenth documented attempt).

---

## SMR35-1 (MINOR) — the captured digest's SOURCE must be pinned (the retained tree, never `ActiveDigest()` at capture time)

My v8.30 fold says the stamp is `MarkAppliedDigest(pair.
capturedDigest)` "captured at acceptance/apply time under the
apply serialization". For the Compile leg that is precise (the
wrapper captures `ActiveDigest()` while holding `applySem` —
`s.active` IS the pair being applied, the standing #6296
pattern). For the CATCH-UP leg it is not: the catch-up's
acceptance runs in the manager's status loop (NO `applySem`,
and — in exactly the stale-notice windows this machinery
exists for — a NEWER promotion (C2) can already be
store-active at capture time): a capture via `ActiveDigest()`
at drain or acceptance time would read `digest(s.active ==
C2)` — the wrong tree, the very #6296 class the captured form
cites. Pin: the pair's `capturedDigest` is computed from the
STORE'S RETAINED TREE for the pair's revision (the
rollback/archive trees — durable by construction (the v8.18
fold's own guarantee), via a store accessor
(`DigestOfRevision(rev)` taking `s.mu`) — NEVER from
`s.active` at capture time; the cursor's install
(`beginFirstExposure`, the same `m.mu` section) captures it
there for BOTH legs (the Compile leg's wrapper digest and the
catch-up leg's cursor digest are then the SAME value for the
same pair — the single-source property the stamp's
idempotency argument silently assumed). The lock order for
the new edge: the cursor install holds `m.mu` and the
accessor takes `s.mu` (m.mu → s.mu — safe by the SMR25-3
census's own argument: the store never calls into the
manager, so no s.mu → m.mu path exists).

## SMR35-2 (NIT) — the marker's window semantics are stated once, completely

The three windows for `ActiveApplied()`: post-stamp(C1) ⇒
true; post-promotion(C2) pre-apply ⇒ false (C2 not applied —
correct); post-stamp(C2) ⇒ true; rollback-to-C1 ⇒ true (C1's
digest already landed). One sentence in §5-C (ii) so the
operator-visible semantics are not left to inference.

## Attack trace (what else I tried, and why it fails to break v8.30)

1. **The push ordering at the peer (again, with the digest
   form).** C1's push then C2's push, `applySem`-serialized,
   monotonic wire generations; the peer applies in wire order;
   the stamp's digest form does not affect the push path.
   Coherent.
2. **The SUPERSEDED marking × the digest form.** A stale
   notice's stamp is skipped at the gate; its captured digest
   dies with the entry (GC'd at terminal) — no stale digest
   can surface later. Coherent.
3. **The double-leg digest identity.** Compile-leg wrapper
   digest vs catch-up cursor digest for the same pair: both
   from the retained tree (SMR35-1) — identical by
   construction; `MarkAppliedDigest` of the same value twice
   is a no-op-equivalent overwrite. Coherent.
4. **Q1, thirty-fifth enumeration.** The v8.30 mechanics
   (captured-digest stamp, the stamp-LANDS assertion) mutate
   NO binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
5. **The r34 disposition table.** Every row re-derived against
   the file: SMR34-1 (the retraction + the captured-digest
   form + the admission-gate protection) and SMR34-2 (the §9
   (a) digest assertion) — both present and correctly cited.

## Required for convergence

v8.31: SMR35-1's digest-source pin (+ the lock-order note);
SMR35-2's window-semantics sentence. AGY r35 pending at this
writing — its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
1 NIT — capture-point pin level; the v8.30 form held).
