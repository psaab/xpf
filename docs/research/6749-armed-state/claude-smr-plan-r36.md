# Claude SMR plan review — round 36 — #6749 armed-state plan v8.31 (31fea1cef)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.31 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand — and
this round I walked the configstore retention model
(store.go:215-216 + the rollback slots) before writing). Attack
surface: the digest source pin, the marker window semantics, the
§9 (a) mandated sequence, the (d) leftover sweep, and Q1 (36th
enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 1
NIT. The MINOR is self-found in my own v8.31 digest-source fold
(the retained-tree accessor inherits the store's BOUNDED retention
— a staged acceptance whose revision has rotated out of the
rollback slots has no tree to read — and it introduces a lock edge
and a drain-time read that a strictly simpler form avoids: capture
the digest AT BUILD, riding the staged object). Codex remains
infra-blocked (fifteenth documented attempt).

---

## SMR36-1 (MINOR) — the digest source should be build-time capture riding the staged object, not a drain-time retained-tree accessor

My v8.31 fold pins `DigestOfRevision(rev)` (the rollback/archive
trees) captured at the cursor's install. Two problems with my
own pin: (i) the retention is BOUNDED (rollback slots rotate;
`archiveDir` with `archiveMax`, "empty = disabled"
(store.go:215-216)) — a staged acceptance completing after the
revision rotated out has no tree, and my fold gave no
missing-revision posture; and (ii) the accessor adds the
`m.mu` → `s.mu` edge and a render+hash inside `m.mu`. The
strictly simpler form that needs NEITHER: the digest is
captured AT BUILD time — inside Compile, while `s.active` is
still the pair being built (every apply-path Compile holds
`applySem` via `applyConfigLocked`, so `ActiveDigest()` there
is exactly the standing #6296 pattern) — and RIDES the staged
object into the cursor (the pending-XSK staged object carries
it; `beginFirstExposure` copies it from the staged object;
the Compile-leg wrapper uses the same captured value). No
drain-time store read, no retention dependency, no new lock
edge, and the two legs' digests are identical BY CONSTRUCTION
(one capture, one renderer — the store's own
`configTextDigest(s.active.Format())`, never a manager-side
re-render whose byte-identity with the store's render would
need proving (SMR36-2)). The OVERLAP-clear discards the
staged object and its digest with it; the re-drive's rebuild
re-captures; the revision-0 CLI diagnostic compile is exempt
from the stamp path entirely (it never installs a completion
cursor). Supersedes the v8.31 accessor form (which is kept as
the fallback for a cursor whose staged object predates the
capture (recovery/replay) — there the retained-tree lookup
runs, and a missing revision skips the stamp with a Warn
(the push + invalidation still run; the marker heals on the
next full apply)).

## SMR36-2 (NIT) — the single-renderer property

All digest values in the machinery come from the store's ONE
renderer (`configTextDigest(s.active.Format())` at build time
or `DigestOfRevision`'s render of the same tree) — no
manager-side `Config.Format()` re-render is ever compared
against a store render (a byte-level render divergence would
flap `ActiveApplied()`; the build-time capture makes the
question moot). Stated.

## Attack trace (what else I tried, and why it fails to break v8.31)

1. **The same-pair staged reshape.** T1 staged (digest captured
   at build, R1), T2 re-staged the same pair (re-captured at
   T2's build — `s.active` is still R1 — identical digest).
   Coherent.
2. **The OVERLAP-clear × the digest.** T1's staged object and
   its captured digest are discarded together; T2's build
   captures R2's. No stale digest survives the clear.
   Coherent.
3. **The gated-successor with build-time capture.** C1's
   staged object carries digest(C1) from C1's Compile;
   C2 promotes (gated); C1's catch-up accepts and the cursor
   carries digest(C1); the stamp (admitted by the
   exposed-currency gate) stamps digest(C1) — never touching
   `s.active`. `ActiveApplied()` ⇒ false for C2 (correct).
   Coherent.
4. **The recovery/replay edge.** A cursor re-derived at
   startup (the crash rule) has no staged object — the
   retained-tree fallback runs; a rotated-out revision skips
   the stamp with a Warn and the next full apply heals the
   marker. Bounded and visible. Coherent (SMR36-1's parenthesis).
5. **Q1, thirty-sixth enumeration.** The v8.31 mechanics
   (digest source pin, window semantics, mandated sequence,
   the (d) sweep) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
6. **The r35 disposition table.** Every row re-derived against
   the file: SMR35-1 (the source pin), SMR35-2 (the windows),
   AGY f2 (the mandated sequence), the (d) sweep — all
   present and correctly cited.

## Required for convergence

v8.32: SMR36-1's build-time capture form (superseding the
accessor form, kept as the recovery fallback) + SMR36-2's
single-renderer sentence. AGY r36 pending at this writing —
its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
1 NIT — a simpler-form refinement of my own pin; the v8.31
mechanics held).
