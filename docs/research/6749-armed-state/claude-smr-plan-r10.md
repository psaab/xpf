# Claude SMR plan review — round 10 — #6749 armed-state plan v8.5 (fe899556f)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v8.5 production-hardening deltas — the
VERIFIED pre-disable, the helper-authoritative fabric cache adoption,
the exponent-preserving reset clock, the tagged retry's
stored-generation guard, the HA role-based authority, the nil-config
teardown rule.

**Verdict: PLAN-READY-WITH-NITS** — every attack I mounted was
absorbed (trace below). Three documentation nits to fold without a
re-review. If Codex/AGY r10 surface a real hole, this verdict is
void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v8.5)

1. **Q2 — the verified pre-disable's failure shape.** A readback
   that intermittently fails (degraded control plane, healthy
   dataplane) blocks fabric PROJECTION MUTATIONS while the
   dataplane keeps running the old projection. The alternative —
   send and accept the unknown outcome — would let the helper
   accept a mutation Go cannot verify its fail-closed gate for.
   Control-path mutations are exactly the class that should require
   a verified gate; the dataplane's availability is preserved where
   it matters (old plan keeps forwarding). The one
   safety-sensitive case — a fabric peer dying — rides the
   telemetry path (unresolved-peer is already a first-class
   counter, `fabric_link_unresolved_peer_total`), not the
   projection path, so blocking never strands it. The posture is
   correct; one sentence stating it (nit N3).
2. **Q3 — adoption vs an in-flight apply.** `m.lastSnapshot` (last
   PUBLISHED) and the helper's accepted set are the same object in
   every steady state, because the publish IS the acceptance point
   on both sides: an in-flight compile has advanced nothing
   manager-side until its publish lands, and the helper's status
   is generated under the same ServerState lock that swaps the
   snapshot — a racing poll sees either the pre-apply or the
   post-apply state, both coherent. Unconditional adoption is
   therefore a no-op when aligned and the cure when diverged. No
   illegitimate window found.
3. **Q4 — the stored-generation guard vs route overlays.** The
   #5169 monotonicity comment (snapshot.rs:33-82) is the exact
   evidence: a route-only overlay advances `fib_generation` with
   the config generation REUSED — `LastSnapshotGeneration` does
   not move on `bump_fib`/overlay paths (manager_overlay.go:188).
   The guard's comparison (stored config generation > debt epoch)
   is therefore exact for the config dimension and cannot be
   fooled by fib-only bumps. One sentence stating the fib-
   invariance explicitly (nit N1).
4. **Q5 — flap-during-commit.** A bucket-iii member flapping down
   mid-flow: the MAC step is a no-op (correct MAC), so no link
   cycle is needed and the live-change completion proceeds — the
   XSK binds to the netdev's queues regardless of carrier state,
   and the readiness barrier (`bound == planned`) is about binding,
   not carrier. A member that is physically down simply passes no
   traffic (reality, not a plan defect), and the EXISTING
   link-event machinery owns the mid-operation flap: the XSK dies
   with the link, and the next link-UP event drives the rebind
   (process_linkcycle.go's normal path). The bucket-ii recovery
   entry is only for "should be up but isn't after OUR programming
   attempt" (a failed setUp or a restart with correct-MAC-down) —
   external flaps are not its job. One sentence separating the two
   (nit N2).
5. **Q1 — the v8.5 completeness enumeration.** Every
   `armed=false` producer re-enumerated under the final surface:
   planner marks (S1/S2/S3/S4'/S5/fabric mark-all), convergence
   (armed leg only), operator verbs (C2), global fan-outs (C3),
   lifecycle init (no bindings), rebind (never sets), update_fabrics
   (mark-all = planner class), failure restoration (S4'), the
   #2794 disarmed leg (no production). All owned; the
   mixed-version producer is the one documented exception and it
   is gated on the REQUIRED helper restart with D as its tripwire.
   No unowned producer.

## Nits (fold without a re-review)

- **N1:** §5-C's tagged-retry guard should state the fib-invariance
  explicitly: route-overlay/bump_fib advances `fib_generation`
  with the config generation reused (#5169, snapshot.rs:33-82), so
  `LastSnapshotGeneration` never moves on overlay paths and the
  guard's comparison is exact — no (generation, fib) pair needed.
- **N2:** §5-C's three-bucket bullet should separate two link-down
  classes: an EXTERNAL flap mid-operation (the XSK dies with the
  link; the existing link-event machinery rebinds on link-UP) from
  a SHOULD-BE-UP failure (a failed setUp or restart with
  correct-MAC-down — the bucket-ii recovery entry's job). The
  bucket-ii recovery never races the link-event machinery because
  it only fires inside an open epoch/debt context.
- **N3:** §5-C's pre-disable bullet should state the posture in one
  line: control-path mutations require a readback-verified
  fail-closed gate; the dataplane keeps the OLD projection
  meanwhile (availability preserved where it matters), and a
  failed gate blocks only the mutation, never the dataplane.

## Required for convergence

Nothing structural. If Codex + AGY r10 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
