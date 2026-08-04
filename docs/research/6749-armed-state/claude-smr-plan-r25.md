# Claude SMR plan review — round 25 — #6749 armed-state plan v8.20 (783c9581d)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.20 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the notice pair-currency gate, the cursor check-and-advance
atomic, the NIL post-clear pin + canary, the overflow sweep, the
shared marker locus, the §9 (a) assertions, the lock-order rule, the
held-push budget note, and Q1 (25th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 2 MINOR + 2
NIT. Both MINORs are self-found in my own v8.20 fold text (the
SUPERSEDED parenthetical mis-describes the fix it ships — an
implementer reading it reintroduces the leak the fold exists to
kill; and the sweep's semaphore/cadence are unpinned). The rest of
the v8.20 surface held under my attacks (trace below). Codex
remains infra-blocked (usage limit, reset Aug 10 — fourth
documented attempt this session).

---

## SMR25-1 (MINOR) — the SUPERSEDED parenthetical mis-describes the fix, in the normative text AND the table row

My v8.20 fold ships (i) the invalidation composing prior →
CURRENT unconditionally, (ii) the stamp/push currency-gated,
(iii) the SUPERSEDED terminal marking — with the parenthetical
"(terminal — the composition is covered by the newer pair's
chain, never left pending)". That clause is FALSE on its face
(it is exactly the abort-only leak SMR24-1 traced: C's B→C chain
never covers A-permitted/B-revoked/C-revoked sessions) and it
contradicts (i) two lines earlier (the invalidation that
ACTUALLY covers the A-era deletions is the drain's own prior →
CURRENT composition, which runs ALWAYS — that is the point of
the fold). The same mis-description rides the §1 SMR24-1
disposition row ("marks a superseded notice's cursor entry
SUPERSEDED (terminal — the newer pair's chain covers the
composition)"). An implementer reading (iii) as "skip
everything for a stale notice" reintroduces the leak verbatim.
Reword both spots: SUPERSEDED marks ONLY the pair-specific
tails (stamp/push) as skipped-by-design; the invalidation (i)
composes prior → CURRENT and runs for stale notices exactly as
for current ones; the §9 (a) assertion must pin that reading
(assert the A→C composition RUNS for the stale notice — a
skip-everything implementation fails).

## SMR25-2 (MINOR) — the sweep's semaphore and cadence are unpinned

My fold gives the daemon's apply scheduler "a periodic
pending-cursor sweep at the standing debt cadence" without
saying (a) whether the sweep's tail execution takes `applySem`
(it must — the tails are the same phased set the notice drain
runs, and the currency gate's whole force is `applySem`
serialization; a sweep that composes prior → CURRENT WITHOUT
the semaphore races a promotion mid-composition), or (b) what
the cadence is ("the standing debt cadence" is a 5/10/20/60s
backoff ladder, not a cadence). Pin: the sweep rides the 1s
status-application pass (after each helper-status application
the daemon scans the pending-cursor set — no new timer, and a
dropped notice delays the tails ≤ 1s + drain scheduling), and
the sweep's per-entry execution is the SAME applySem-acquiring
drain path as the notice's (one routine, two triggers).

## SMR25-3 (NIT) — the applySem → m.mu lock-order census is unstated

The notice drain (applySem) calls the cursor's manager method
(m.mu): order applySem → m.mu. The census: Compile runs under
applySem and takes m.mu (same order); the GO-LOCAL debt
recording is enqueue-after-unlock (no m.mu → applySem path);
the manager never acquires applySem (it is a daemon
semaphore). One direction everywhere — state it next to
SMR24-8's writeMu → s.mu rule.

## SMR25-4 (NIT) — the OVERLAP-clear → re-drive chain-state note

After T1's node is OVERLAP-finalized (terminal) and T2 fails,
the re-drive's StartCompile begins a FRESH chain
(`compileInFlight` cleared by T2's Finish, whose reduction
already folded the recorded outcomes oldest-first) — no stale
chain state carries, and the cleared staged reference means the
rebuild mints from the store. Coherent — stated for the
implementer.

## Attack trace (what else I tried, and why it fails to break v8.20)

1. **The drain's currency re-read atomicity.** Promotions hold
   `applySem`; the drain's re-read of `ActivePair()` under the
   same semaphore is atomic vs any promotion — the
   check-and-compose cannot tear. Coherent.
2. **A second staleness generation.** B's notice stale over C,
   draining after D lands: prior → CURRENT is A→D — the uniform
   base composes the full delta regardless of depth. Coherent.
3. **The stamp skip vs C's incomplete wrapper.** C's wrapper
   tails run inside C's `applySem` hold; the stale notice's
   drain cannot interleave — it runs strictly after C's tails
   complete. Coherent.
4. **The SUPERSEDED × crash-rule interplay.** A crash before a
   stale notice drains: the recovery derives exposed < active ⇒
   re-run tails exposed→active — the same composition the drain
   would have run. The SUPERSEDED marking is an optimization,
   never a loss. Coherent.
5. **The shared marker locus vs a local commit.** A LOCAL
   topology/identity commit is refused at commit-check
   (preflight), never reaching `applyConfigLocked` — the guard
   in the drain/sync paths is the only live evaluation, and the
   shared routine records once. Coherent.
6. **Q1, twenty-fifth enumeration.** The v8.20 mechanics
   (currency gate, cursor atomic, NIL pin, sweep, shared locus,
   §9 assertions, lock order) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
7. **The r24 disposition table.** Every row re-derived against
   the file: all folds present and cited correctly EXCEPT the
   SMR24-1 row's SUPERSEDED parenthetical (SMR25-1).

## Required for convergence

v8.21: SMR25-1's reword (normative + table row + the §9 (a)
pin); SMR25-2's sweep applySem/cadence pin; SMR25-3/SMR25-4
folded. AGY r25 pending at this writing — its verdict may add
to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 2 MINOR +
2 NIT — wording-and-pin level; the v8.20 mechanics held).
