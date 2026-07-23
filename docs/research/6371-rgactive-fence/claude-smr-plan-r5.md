# Claude SMR hostile plan-review — #6371 r5

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r5 (commit ba3cfb4b5),
base origin/master @ 3ecdc80568a3.

## r4 BLOCKERs closed — verified firsthand
- **Boot pin-quarantine precedes all map-derived publication (r4-B3/B4):** verified
  the ordering — `manager_compile` does `refreshHAStateFromMapsLocked` →
  `syncHAStateLocked` (HA replay, `:372-378`) THEN `ensureStatusLoopLocked` (`:399`).
  So the replay is the FIRST map-derived publication and the status/watchdog loop
  starts after it. Zeroing the pin at shim-map-load (before the manager's first
  apply replay) precedes replay, poll, and watchdog — §5.1 is achievable at that
  seam. Recommend the plan name the seam precisely (shim-map-load, not "earliest
  boot point").
- **Seed/sticky-`applyPending` (r4-B1):** moot — r5 drops seed-applied for
  quarantine. Correct.
- **Peer-fence one-shot (r4-B5):** §5.2's daemon-level intent + reconcile
  retry-consumer to convergence (pin==0 AND helper Active=false) genuinely closes
  it; the convergence definition is self-consistent (helper can't stay inactive
  while the pin=1, since the poll re-arms — so convergence truly proves the clear
  stuck). Good.
- **Alarm convergence / tombstones / read API (r4-H6/H7):** addressed
  (generation-tracked convergence, first-failure timestamp, shutdown excluded,
  zero-all-16 tombstones, new fail-closed snapshot API).

## Finding (strengthening, fold into §5.1/§8)

**F-r5-1 (the fail-closed-on-boot availability cost is largely moot — say so).**
§5.1/BLOCKER-2 frame the up-to-30 s legitimate-owner gap as the accepted safety
cost. Firsthand, that worst case is narrower than stated and the trade is nearly
free: VRRP is daemon-managed, so a daemon restart **already** drops adverts and
the peer takes over within masterDownInterval (~97 ms) — the returning node is
**legitimately Secondary**, so quarantining its stale pin **prevents dual-active
rather than causing a new outage**. It re-owns only by normal failback (election),
which with a live, already-known peer is ~election-time (~1 s), NOT 30 s; the 30 s
never-seen-peer floor applies only to a **cold cluster boot** (both nodes down),
where fail-closed is unambiguously correct anyway. So fail-closed-on-boot is the
right default and the availability objection is largely resolved — the
peer-authoritative refinement is a nicety, not a gating requirement. Fold this
into §5.1 (it materially strengthens the invariant choice) and §8.

## Residual items are /engineer-scope, not plan blockers
The remaining specifics — the exact quarantine call site, the daemon-level
`clearIntent` struct + reconcile hook, the alarm `T`, and the `HAController`
snapshot API shape — are legitimate implementation decisions a converged research
plan may leave to /engineer. The plan has established (a) the real defect
(stale-active `rg_active` reactivation, unbounded, via restart / peer-fence
one-shot / persistent map-write), (b) the invariant choice (fail-closed-on-boot,
disclosed), (c) a mechanism that closes every reachable unbounded mode, and (d) an
honest, tracked deferral of only the architectural cleanup. That is a complete
research deliverable.

## Verdict
r5 closes every r4 BLOCKER with a cleaner architecture (boot pin-quarantine +
convergent retryable clear), makes the security-vs-availability invariant explicit
and defensible (and, per F-r5-1, nearly cost-free), and defers only the
map-as-authority cleanup with a follow-up to be filed. Five rounds of hostile
review have converged the facts; the one remaining note is a strengthening
clarification, not a defect. PLAN-KILL of Option D / Path A′ / the decouple stands.

VERDICT: PLAN-READY
