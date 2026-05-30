# Codex plan-review r1 — #1608 v3 (research)

Local `codex exec` (read-only, `codex-cli 0.133.0`), worktree
`research/1608-phase4c`. Full raw transcript: too large to inline
(~1.3 MB of tool-call traces); verdict block reproduced below verbatim.

**Verdict: PLAN-NEEDS-MAJOR** — the "do not ship B/C now" conclusion is
correct, but the plan must be revised before KILL-confirmation because
its #1615/870 Kpps premise is **materially false** in this worktree.

## Findings (verbatim)

1. **Stale measurement rationale (the one MAJOR).** `docs/userspace-jit-
   design.md:637` "## Measurement plan"; `:639-644` lists only generic
   methods, no A1/A2/B1/B2 rows. **Counter-evidence:** `docs/pr/1615-
   flooder-multithread-virtio/measurements.md:23` "4 | ~2.94 M aggregate
   | … BLOCKING GATE PASS"; `:55` "Multi-thread design empirically breaks
   the ~870 K pps single-thread ceiling". **Path D is not blocked by
   #1615 anymore; it is simply not run/populated.**
2. Section 2 cold-path topology correct. `poll_descriptor/mod.rs:2392`
   MissingNeighbor arm; `:2418` neg_neigh_gate; `:2441` scratch_recycle;
   `:2442` continue (skips `:2522` policy eval).
3. #1660 overlap correct for dead/unresolved dst; residual = live/
   resolvable cold floods. `neighbor_dispatch.rs:110` timeout →
   `:121 neg_neigh_record`; live path policy eval at
   `poll_descriptor/mod.rs:1364-1366 ForwardCandidate` → `:1393`.
4. Policy path still rule-count-linear: `policy.rs:885` zone_pair_index
   get; `:886 for &idx in indices`; `:901` global_indices; `:926
   try_match_rule`.
5. #1606 dedup accurate but does NOT remove the outer scan. `policy.rs:
   416-417` deduped book table; `:944-949` match expr. Reduces per-rule
   address duplication, not `for &idx in indices`.
6. #1623 shipped scaffolding not the DAG. `policy.rs:180` "NOT consumed
   by the hot path in this PR"; `:182-185` parallel arrays;
   `evaluate_policy_result_with_len :873-919` never uses them.
7. Section 8 arithmetic correct as inherited sizing (4096 × 96 B = 384
   KiB > 256 KiB) but prose-only — no `VerdictCacheEntry` struct exists
   in-tree to prove the 96 B layout. (Expected: no code in a research
   plan.)
8. Paths B/C do not close the fatal axes enough to ship now. B needs
   measured hit rate, default-deny caching, full key invariants,
   generation invalidation (`flow_cache.rs:625-627`), real size proof.
   C is the only structurally useful live-dst defense but needs rate
   semantics, default-off controls, real flood measurement, and the
   explicit `continue` (session install still occurs at
   `poll_descriptor/mod.rs:2652-2657` unless the limiter `continue`s).

**Net:** no PLAN-READY for B or C; KILL conclusion is right once finding
#1 is corrected.

## Resolution (v3 r2 plan)

Finding #1 folded: Section 3 + Path D + Recommendation now state #1615
is RESOLVED and the measurement is achievable-but-unrun, which
*strengthens* the KILL (no tooling excuse remains). Findings #2-#8 are
confirmations or affirmations of constraints already in the plan;
finding #7 is expected for a no-code research doc. Re-confirmation
requested from Codex r2.
