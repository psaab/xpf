# Claude SMR plan review — round 39 — #6749 armed-state plan v8.34 (6c01344b3)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
and this round AGY landed before I finished my sweep; my
independent findings are below, and AGY's two MAJORs are
independently evaluated, not adopted on faith). Attack surface:
the acceptance-transported digest, the full terminal set, the
Warn scope, the heal phrasing, the §9 (a) additions, and Q1
(39th enumeration).

**Verdict: DEMAND-REVISION** — 1 MAJOR + 2 MINOR + 1 NIT.
Codex remains infra-blocked (eighteenth documented attempt).

---

## SMR39-1 (MAJOR) — the non-first re-apply's stamp authority is unstated (= AGY r39 f2, independently derived before reading AGY's output)

Trace: pair P takes `complete-skipped` (the recovery
fallback). P is later re-applied — an identical recommit
(`s.active` still P — no new revision) or the GO-LOCAL
re-drive. `beginFirstExposure(P)` returns `firstExposure=false`
(P already exposed) — and my v8.19-v8.34 text never says
whether the stamp runs for a non-first apply. If the stamp
lives only in the first-exposure cursor's tails, the marker
stays un-applied FOREVER (every subsequent apply of P is a
non-first exposure). The standing machinery answers it: the
daemon wrapper stamps after EVERY successful
`applyConfigLocked` (the #4957/#6296 pattern — the stamp is
not cursor-exclusive), so the rule must be stated: the stamp
runs on EVERY successful apply/publish of the exposed pair
(the Compile-leg wrapper from the result's `capturedDigest`;
the catch-up leg from the accepting snapshot's own digest
field — first-exposure via the cursor's stamp phase,
non-first idempotently from the same field) — all idempotent
(one value, one renderer; the cursor remains the catch-up's
TAIL authority for the invalidation/push, and the wrapper's
stamp is never suppressed by the cursor). The
complete-skipped state heals on the next successful apply of
the exposed pair, from ANY transport.

## SMR39-2 (MINOR) — the §6 `ApplyResult` inventory never gained `capturedDigest` (self-found claimed-but-wrong)

My own r38 disposition row cites "(§5-C (ii), §6, §9 (a))"
for the transport fix — but the §6 `ApplyResult` inventory
(plan.md:8059ff) still lists only the commit revision and the
exposure-transition triple. The `capturedDigest` field must
be added to §6 (the field's provenance: minted at build time
inside Compile, transported on the result, consumed by the
wrapper's stamp and the cursor install).

## SMR39-3 (MINOR) — the duplicate-install policy for `beginFirstExposure` (= AGY r39 f4)

Two acceptance calls for the same pair: the install is
IDEMPOTENT per pair — a second `beginFirstExposure` for the
same pair+ledgerID no-ops (the cursor exists; its fields
(including the digest) are install-time-immutable), and a
call with an empty digest NEVER overwrites a valid captured
value. A new first exposure (a NEW revision) installs a new
cursor (the prior is terminal or is superseded by the newer
exposure per the standing rule). Stated.

## On AGY r39's f1 (the catch-up carrier gap) — PARTIALLY VERIFIED

AGY claims the catch-up leg lacks a carrier for direct
applies. My walk of `process_status.go:2206-2275`: EVERY
deferred snapshot is produced by Compile's `pendingXSKStartup`
branch (the excerpt's own comment: "It is the sole producer
of an unpublished lastSnapshot") — which stages the object
the v8.34 transport names — so the deferred legs (the
linkcycle defer AND the XSK-startup defer) DO have the
staged-object carrier, and the synchronous-publish Compile
leg has the `ApplyResult`. The gap is the TEXT's enumeration:
"the pending-XSK staged object" can be read as only the
linkcycle case, leaving the XSK-startup-defer leg's carrier
unnamed — and an implementer reading it narrowly builds the
gap AGY traced. The fold kills the ambiguity class rather
than renaming the leg: the digest is a FIELD of the built
snapshot (minted at build time inside Compile), and EVERY
acceptance leg (the Compile-leg result, the staged object
(which wraps the snapshot), the catch-up
(`m.lastSnapshot.capturedDigest`)) reads that ONE field —
the transport stops depending on which defer shape produced
the object.

## Attack trace (what else I tried, and why it fails to break v8.34)

1. **The direct-then-deferred same-pair identity.** T1's
   direct apply fails post-capture (a shim error — no cursor,
   no staged object); the re-drive stages the same pair
   pending-XSK — T2's build-time capture (`s.active` still
   the pair — the render determinism) — identical digest.
   Coherent.
2. **The GO-LOCAL drain's capture.** The drain holds
   `applySem`; `s.active` is the active pair; the build-time
   `ActiveDigest()` read is the #6296 pattern. Coherent.
3. **The duplicate-cursor overwrite.** Given SMR39-3's
   idempotent install, the Compile-leg install and a later
   catch-up call for the same pair: the first install wins;
   the second no-ops (the catch-up's tails are already
   covered by the first cursor). Coherent.
4. **Q1, thirty-ninth enumeration.** The v8.34 mechanics
   (acceptance-transported digest, full terminal set, Warn
   scope, heal phrasing, §9 (a) additions) mutate NO binding
   slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
5. **The r38 disposition table.** Every row re-derived against
   the file: AGY f1 (the argument transport), AGY f2 (the
   terminal set), AGY f3 (the Warn scope), AGY f4 (the heal
   phrasing) — all present EXCEPT the §6 element of the f1
   row (SMR39-2).

## Required for convergence

v8.35: the snapshot-field unification (SMR39-1's stamp rule
+ the AGY-f1 ambiguity class); SMR39-2's §6 field; SMR39-3's
duplicate-install policy; AGY r39's f3 (§9 (a) assertions)
folded with them.

**Verdict: DEMAND-REVISION** (1 MAJOR + 2 MINOR + 1 NIT —
one authority-rule statement, one citation fix, one
idempotency pin, and the transport-unification fold; the
rest of v8.34 held).
