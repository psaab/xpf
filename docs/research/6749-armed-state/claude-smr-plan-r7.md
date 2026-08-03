# Claude SMR plan review — round 7 — #6749 armed-state plan v8 (ee2f548d8)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v8 deltas — result-based C2, the
deletion boundary, the identity-checked volatile refresh, the
projection-scoped `update_fabrics`, the defer epoch, the actionable
retry, the phase-revalidating MAC debt.

**Verdict: PLAN-READY-WITH-NITS** — every attack I mounted was
absorbed (trace below). Three nits to fold without a re-review: the
empty-replan guard needs its discriminator stated exactly, the MAC
debt needs a cancel-on-member-removal note, and the Q2 convergence
scope answer belongs in the doc. If Codex/AGY r7 surface a real
hole, this verdict is void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v8)

1. **Q3 — the volatile identity check vs multi-queue workers.** The
   live table is keyed by slot (`workers.live.get(&binding.slot)`,
   refresh_bindings.rs:25) and each live record carries its own
   `socket_ifindex`/`socket_queue_id` (:61-62) — one XSK per
   (netdev, queue) per the #1921 contract, so a slot maps to exactly
   one physical pair. A worker owning multiple slots (all interfaces
   at its queue_id) holds one record PER slot, each created at that
   slot's own XSK registration (bringup.rs:273 plans by slot). The
   identity check is therefore per-slot exact: a record at slot S
   describing (ifA, q0) can never be confused with the same worker's
   record at slot S' describing (ifB, q0) — the check compares the
   RECORD's fields to the BINDING's fields, and a stale record
   (pre-reshuffle XSK on the old physical) fails the comparison and
   zeroes. Per-slot-correct; no cross-slot bleed.
2. **Q4 — the empty-replan guard's discriminator.** The snapshot
   alone distinguishes intent from transient failure: config
   candidates are computed by the
   `include_userspace_binding_interface` filter over the snapshot —
   if that set is NON-empty but the replan produces an EMPTY vector,
   every candidate's `rx_queue_count` read_dir failed (the only
   path to 0 — planning.rs:605-621; a readable dir returns
   `count.max(1)`), i.e. the emptiness is transient by construction
   and the guard keeps the prior vector. If the filter yields zero
   candidates (operator deleted all zoned interfaces), the empty
   plan is intentional and installs. The discriminator is
   `len(config_candidates) > 0 && len(planned) == 0` — no
   provenance field needed. The plan should state it in exactly
   this form (nit N1).
3. **Q2 — tagged-convergence over-reach.** A tagged rebind
   converges ALL pendings, not just defer-created ones. This is not
   over-reach: `pending` means "waiting for a successful
   defer-authorized armed reconcile of the CURRENT plan", and the
   tagged rebind's reconcile re-binds the whole current plan —
   every pending slot's workers are bound by it regardless of which
   rule (S3 defer, S4' failure, S5 new, fabric projection) created
   the mark. Convergence is plan-scoped, not cause-scoped; a
   prior S4' pending converging on a defer completion is exactly
   the intended self-heal. The doc should say it in one sentence
   (nit N3).
4. **Live-change clear timing.** The flag clears immediately before
   the synchronous mandatory re-apply. The status loop and the
   re-apply's compile both serialize on `m.mu`
   (process_status.go:162 vs the compile lock), so no poll tick can
   interleave inside the re-apply; a tick landing after it sees
   pendings already converged (no-op) or the #5134 debt set
   (suppression). Benign.
5. **MAC debt across commits.** The debt's target MAC derives from
   (clusterID, rgID, nodeID) — config-independent, so a newer
   commit cannot stale it; the debt persists across config
   generations until both phases validate. One missing rule: a
   member interface REMOVED from config must cancel its debt entry
   (nit N2 — otherwise the debt retries a MAC for an interface the
   operator deliberately unmapped).
6. **Tagged-retry vs #5134 debt overlap.** Flow-disjoint: the
   tagged retry exists only for the link-cycle flow (failed tagged
   rebind); the #5134 debt exists only for the live-change flow
   (failed mandatory re-apply). A new commit abandons the old
   tagged retry by epoch expiry. No double-retry.
7. **Wrong-physical publication, v7 → v8.** Codex r6 f4's chain
   (same-name/new-ifindex published armed with no reconcile → Go
   programs the new ifindex to the old XSK with enabled=true) is
   broken at two points now: the replan marks the identity
   `pending` (physically unbound → `enabled=false` → ctrl=0 → no
   publication), and the rate-capped reconcile rebinds it on the
   new ifindex before convergence re-arms. The residual v7 shape
   cannot reach the map write.
8. **Result-based C2.** The two "wire-identical" requests Codex r6
   f2 raised — `(registered=true, armed=false)` as "register" vs
   "disarm" — collapse correctly: both leave the slot
   non-forwarding, which IS the operator's intent in both readings
   (the API takes explicit booleans; there is no "register into the
   global default" request shape). Result-keying is the honest
   semantics, and the deletion boundary is the honest lifetime
   (claims die with the physical binding).

## Nits (fold without a re-review)

- **N1:** §5-C's empty-replan guard should state its discriminator
  exactly: `len(include_userspace_binding_interface(snapshot)) > 0
  && len(planned) == 0` ⟹ transient (keep prior vector); zero
  config candidates ⟹ intentional empty plan (install). One
  sentence; the unit test (§9 item 19(vi)) asserts both arms.
- **N2:** the MAC-retry debt must cancel entries for member
  interfaces that leave the config (a commit unmapping the RETH
  member) — otherwise the debt retries a MAC the operator
  deliberately abandoned. One rule + one daemon test line.
- **N3:** §5-C's convergence paragraph should state explicitly
  that convergence is PLAN-scoped, not cause-scoped: any successful
  defer-authorized armed reconcile converges every pending slot,
  because "pending" means "waiting for the current plan to be
  bound" and the rebind binds it (answers Q2).

## Required for convergence

Nothing structural. If Codex + AGY r7 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
