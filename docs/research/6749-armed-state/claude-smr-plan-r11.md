# Claude SMR plan review — round 11 — #6749 armed-state plan v8.6 (dc0e618f8)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v8.6 deltas — bucket-i-only validation,
`m.configEpoch`, the `expected_snapshot_generation` refusal,
three-authority latch clearing, the PAIR-GATED fabric adoption, the
edge-triggered verified pre-disable, the LinkController handoff.

**Verdict: PLAN-READY-WITH-NITS** — the v8.6 mechanics hold under my
attacks (trace below), but I found one real refinement of my own in
the pair-gated adoption (SMR11-1, MINOR — a bounded stall on
fib-bump failure that the generation-only refinement eliminates),
plus two documentation nits. Fold all three without a re-review. If
Codex/AGY r11 surface a real hole, this verdict is void and we
iterate.

---

## SMR11-1 (MINOR) — the pair-gated adoption wedges on a fib-bump failure

v8.6's adoption gate is the `(generation, fib)` PAIR. A `bump_fib`
round-trip moves Go's `m.lastSnapshot.FIBGeneration` BEFORE the
helper's control message lands (manager_generation.go:70 assigns it,
then the bump message is sent); if that message fails (the #1844
contract says it is retried by the actuator's pendingFIBBump), Go's
fib is ahead of the helper's until the retry lands — and the pair
gate then BLOCKS fabric adoption for the whole wedge. During the
wedge the helper's accepted fabrics legitimately advance (the
`update_fabrics` RPC path is independent of fib), Go's
`m.lastSnapshot.fabrics` stays stale, and route/scheduler publishers
clone the stale set — a bounded but real fabric-cache regression
with the wrong mechanism blamed (fib, which is a cache-invalidation
counter, not snapshot lineage).

The refinement: the adoption gate should key on CONFIG LINEAGE, not
the fib-inclusive pair. The exact rule that covers Codex r10 f3's
two quadrants without the wedge: adopt `status.Fabrics` UNLESS
(a) a staged-but-UNCOMMITTED snapshot exists (Go-ahead — the
staged-B-carries-A's-numbers case the pair could not distinguish
either), or (b) `status.LastSnapshotGeneration >
m.publishedSnapshot.Generation` (helper-ahead — the lost-ACK case).
Both conditions are manager-derivable (a `stagedPending` boolean and
two counters Go already owns), and (b) self-resolves via the #4036
exact-equal republish. The fib leg never gates (it is
cache-invalidation identity, not snapshot identity — #5169 uses the
pair for flow-cache invalidation, which is a different contract).

## Attack trace (what else I tried, and why it fails to break v8.6)

1. **Q2 — bucket-i flap during its own MAC cycle.** The member's MAC
   was programmed (bucket i), the link cycled, and it came back down
   before the settle reread. The reread reclassifies it bucket ii
   (never gating) and the completion binds/arms its slots — the XSK
   binds on the netdev's queues regardless of carrier (the queues
   exist while the netdev is admin-up), so the slot is physically
   bound, simply passing no traffic while the carrier is down — the
   same posture as any down interface, with NO dataplane-wide gate.
   The alternative (hold bucket-i slots pending until the link
   returns) is exactly AGY r9 f1's one-dead-member-holds-the-
   dataplane class, correctly rejected. And the link's return rides
   the EXISTING link-event machinery (link-UP → process_linkcycle.go
   rebind on mlx5 queue reinit), not the epoch. One sentence (nit
   N2).
2. **Q3 — the expected-generation refusal vs same-epoch overlays.**
   `m.publishedSnapshot.Generation` advances on every Go-observed
   successful publish, and the helper's stored generation advances
   on every accepted apply — they move together on success. The only
   divergence is timeout-but-landed (helper ahead without Go
   confirming) — and THAT is exactly the stale-completion case the
   refusal exists for; the successor's own epoch+debt fires with
   `expected == stored` once ITS completion is driven (and if its
   ACK was also lost: the mandatory non-deferred re-apply that
   landed already converged helper-side, and if it failed to land,
   the #5134 debt republishes the same snapshot to success). No
   successful publish path moves the helper without moving
   `m.publishedSnapshot.Generation` — so no false refusal exists.
3. **Q4 — (subsumed by SMR11-1 above; the fib-leg wedge is the only
   failure I could construct, and the refined rule eliminates it
   while keeping both hazard quadrants covered.)**
4. **Q5 — the configured-disabled member's binding slots.** A
   `disable: true` member that is also a zoned binding candidate:
   networkd keeps the link down, the XSK binds on its queues (they
   exist while admin-up), the binding is physically inert (no
   traffic), and the all-or-nothing `enabled` gate counts it as an
   ordinary binding. That is the correct posture for THIS PR: the
   binding plan is about config presence (zoned), not runtime link
   state; any `disable`-driven planner exclusion is #6702's
   candidate-filter territory (`include_userspace_binding_interface`),
   explicitly out of scope here. One sentence (nit N3).
5. **Q1 — the tenth completeness enumeration.** Every
   `armed=false` producer under the v8.6 surface: planner marks
   (S1/S2/S3/S4'/S5/fabric mark-all), the armed-leg convergence,
   operator verbs (C2), global fan-outs (C3), lifecycle init (no
   bindings), rebind (never sets), update_fabrics (mark-all =
   planner class), failure restoration (S4'), the #2794 disarmed
   leg (no production). All owned; the mixed-version producer is
   the one documented exception, gated on the REQUIRED helper
   restart with D as its tripwire. No unowned producer.

## Nits (fold without a re-review)

- **N1 = SMR11-1 above** (the adoption-gate refinement — fold as
  the (a)/(b) rule replacing the fib-inclusive pair).
- **N2:** §5-C's bucket bullet should state that a bucket-i member
  whose link flaps down during its own cycle is bound and armed
  normally (queues exist while admin-up; traffic flows when the
  carrier returns via the EXISTING link-event rebind machinery —
  the epoch is not involved in link recovery).
- **N3:** §5-C or §11 should state the configured-disabled binding
  posture explicitly: `disable: true` members bind and arm as
  ordinary (physically inert) bindings; a planner exclusion for
  them is #6702's candidate-filter territory, not this PR's.

## Required for convergence

SMR11-1's fold (the adoption-gate refinement) and the two doc
sentences. If Codex + AGY r11 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold all three and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
