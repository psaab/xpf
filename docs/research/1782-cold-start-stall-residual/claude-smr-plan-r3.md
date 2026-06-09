# Claude SMR hostile plan-review — #1782 r3 (`99e7dbfd0`)

**Verdict: PLAN-READY**

v3 folds both Codex r2 MAJOR findings, which were real and verified against code
(I confirmed the first-miss site inserts INCOMPLETE for the kernel to probe
`poll_descriptor/mod.rs:2168-2174`, that the resolver is reached only via the
neg-fast-fail path, that `neighbor_pending_dwell` #1772 is the Stage-1 signal,
and that `PENDING_NEIGH_TIMEOUT_NS = 2 s` default with the 800 ms fast path
gated on sysctl validation).

Re-checked hostilely:

- **Two-stage cold path** is now explicit in §4; H3's signal corrected to
  `neighbor_pending_dwell` (not `get_rtt`) in §5/§6; the capture adds the
  pre-connect t0′ `dynamic_neighbors` sample that separates H2 (pre-existing
  absence) from H3 (slow resolution). This closes Codex's "H2 vs H3 not yet
  separable" gap.
- **Option B reframed** to act at the Stage-1 first-miss site (not only the
  Stage-2 resolver), with the explicit caveat that same-poll-burst siblings can
  still drop before an async confirm — so B shrinks but may not fully eliminate
  H5, and PR-2 must decide inline-synchronous vs async. This is the correct,
  honest framing; it no longer overclaims that B "automatically" defuses H5.
- **Timeout wording** fixed to 2 s default / 800 ms fast path with the harness
  recording the actual sysctl state.
- **PR-1 dup counter** now specified as the `contains_key` case only (not the
  co-located capacity drop), per-worker — separable from RSS fan-out (Q5).
- **Q7 elevated to fix-gating** with AGY's self-healing analysis folded in (§8):
  XSK bypasses kernel `dst_confirm`, but the kernel's own DELAY→PROBE cycle +
  netlink REACHABLE update self-heal a transient stale MAC; bounded wrong-MAC
  window is an acceptable trade. Correctly parked for PR-2 ratification rather
  than pre-decided.

No new findings. The capture now disambiguates all four live mechanisms (H2/H3/
H5/H1) with a code-grounded signal per column, the 2-PR sequence is sound, the
fix lean (B-first-miss + D, with C as the structural-absence fallback) is honest
about its limits, and PLAN-KILL remains a listed outcome. The plan is a correct,
actionable, capture-first research deliverable. Ready.
