# Claude SMR plan review — round 40 — #6749 armed-state plan v8.35 (64bad83d7)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
the trace below is the evidence). Attack surface: the snapshot
field's wire posture, the stamp-on-every-apply rule, the §6
field, the idempotent install, the §9 (a) additions, and Q1
(40th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR +
2 NIT. The MINOR is self-found in my own v8.35 fold (the
`ConfigSnapshot.capturedDigest` field's WIRE POSTURE is
unpinned — `ConfigSnapshot` is the helper-bound wire object,
and a manager-local bookkeeping digest must never be
half-specified onto it). Codex remains infra-blocked
(nineteenth documented attempt).

---

## SMR40-1 (MINOR) — the snapshot field's wire posture must be manager-local (or the leak story stated)

My v8.35 fold makes the digest a field of the BUILT SNAPSHOT
(`ConfigSnapshot.capturedDigest`) — but `ConfigSnapshot` is
the helper-bound wire object (the full snapshot is marshaled
to the helper on every publish). Two postures are possible:
(a) wire it (additive, serde-default — old helpers ignore it
(the standing additive precedent) — the helper gains a hash
of the full config text, which is information-theoretically
harmless (the helper already HAS the full text) but buys
nothing (the helper never consumes it today)); or (b)
manager-local (the manager's in-memory snapshot struct
carries the field; the wire marshal EXCLUDES it (or the
builder's zero set (builder.go:156-178) grows to cover it —
the semantic-hash/dedup path already has the field-exclusion
mechanism)). Pin (b): the field is manager-local — NOT
marshaled to the helper (the manager's snapshot struct
carries it; the wire encode omits it; the semantic hash's
zero set grows to cover it (so the content-hash dedup never
sees a difference between two snapshots whose only delta is
the field)); the auxiliary clones (route overlay, scheduler
republish, #5134) inherit the field verbatim on their clones
(same pair, same value — their republish's stamp is
idempotent-correct). The reasoning: the field is the STORE's
bookkeeping (the pair's text digest), which the helper never
needs — the helper's authority is the snapshot content, not
the store's hash of it.

## SMR40-2 (NIT) — the auxiliary-clone note

The auxiliary producers clone the cached snapshot and
republish (the route overlay, the scheduler republish, and
the #5134 forcible-`DeferWorkers=false` worker-arm clone):
the clone carries the field verbatim (same pair), the
republish's stamp uses it (the pair's own digest — correct),
and the OVERLAP-clear discards the staged object and its
snapshot's field together (the re-drive's rebuild mints a
new snapshot with the identical field value if the pair is
unchanged — the render determinism). Stated.

## SMR40-3 (NIT) — the boot-path capture note

The stamp-on-every-apply rule covers the boot apply and the
rollback executor's apply (both are ordinary serialized
applies whose wrapper stamps their own pair's digest — the
boot's pair is the boot-promoted active (`s.active` at that
Compile — the #6296 form), and the feed/DHCP-queued
identical-recommit retry re-reads the pair under `applySem`
and re-stamps the SAME digest (idempotent)). Stated next to
the rule.

## Attack trace (what else I tried, and why it fails to break v8.35)

1. **The direct-then-deferred identity (again, with the
   field).** T1's direct apply fails post-capture; the
   re-drive stages the same pair pending-XSK — T2's snapshot
   carries the field (same pair, identical digest) — and the
   catch-up reads it from `m.lastSnapshot.capturedDigest`.
   Coherent.
2. **The idempotent install × the two-leg same-pair.**
   Compile-leg installs the cursor with the field; a later
   catch-up acceptance for the same pair no-ops (the install
   is idempotent; the digest is install-time-immutable) —
   the catch-up's tails are covered by the first cursor.
   Coherent.
3. **The complete-skipped heal × the every-apply rule.** A
   pair in the complete-skipped state re-applies (recommit,
   re-drive, feed-queued retry): the wrapper stamps the same
   digest from the result's field (idempotent) — the marker
   heals on the FIRST subsequent successful apply, regardless
   of `firstExposure`. Coherent.
4. **Q1, fortieth enumeration.** The v8.35 mechanics (the
   snapshot field, the every-apply stamp rule, the §6 field,
   the idempotent install) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
5. **The r39 disposition table.** Every row re-derived against
   the file: AGY f1 (the field unification), SMR39-1/AGY f2
   (the every-apply rule), SMR39-2 (the §6 field), SMR39-3/AGY
   f4 (the idempotent install), AGY f3 (§9 (a)) — all present
   and correctly cited (the §6 field now exists).

## Required for convergence

v8.36: SMR40-1's wire-posture pin (+ the zero-set note);
SMR40-2/SMR40-3 folded. AGY r40 pending at this writing —
its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
2 NIT — wire-posture pin level; the v8.35 mechanics held).
