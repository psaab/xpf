# Claude SMR hostile plan review — #1870 plan v2, round 2

**Reviewer:** Claude (domain SMR)
**Plan:** `docs/research/1870-local-tunnel-pair/plan.md` v2 @ `68e0285b8`
**Stance:** adversarial re-verification of the v2 folds and the two new
load-bearing claims the severity reframe introduced.

## Verification of round-1 folds

- **F1/Codex-1/AGY-1 (bulk-export refutation):** v2 §2.3 now states the
  exclusion is permanent by-origin design with the correct citation
  (`session_glue/mod.rs:439-441`); the HA leg is deleted from the impact
  list and §10 pins it as a non-goal with test 5. Fold correct.
- **F2 (materialization):** v2 §2.3 carries the mechanism with the
  `should_keep_synced_hit_transient` exception named. Fold correct.
- **Codex-2 (descriptor text):** v2 §6/§7/§8 add
  `pkg/api/metrics_descriptors.go:553-560` help-text and
  `session/README.md:88-99` updates and add `go test ./...` to the gates.
  Re-verified both sites name "UpsertLocal replicas" verbatim. Fold correct.
- **Codex-3/Codex-4/AGY-2/F6:** tests 5, 2, the `assert!`-in-tests note, and
  hot-path reachability assertions are all present in §5. Folds correct.

## New hostile checks on v2's load-bearing claims

### C1: SyncImport vs SharedMaterialize residency — no behavioral difference (verified)

Post-fix the entry sits in the worker table as `SyncImport`; under today's
at-cap reactive healing it would sit as `SharedMaterialize`. Grepped for any
direct consumer of either variant outside `session/entry.rs` and tests:
**none exist**. All behavior routes through the predicate methods, and the
two variants are identical under every one of them: `is_peer_synced()` true
for both (`entry.rs:78-83`), `is_promotable_synced()` true for both
(`entry.rs:85-87`), `worker_replica_origin()` maps both to `SyncImport`,
`materialized_shared_hit_origin()` maps both to `SharedMaterialize`. Path A's
end-state is therefore indistinguishable from the reactive-healing end-state
except for the origin label string in diagnostics. No finding.

### C2: the materialization claim's residual uncertainty is not load-bearing for Path A

§2.3's "self-heals on first traversing packet" claim has a named exception
(`should_keep_synced_hit_transient`) and an unverified-by-me corner: whether
every local-tunnel reply variant traverses `resolve_flow_session_decision`
(vs some dedicated decap/delivery shortcut). I did not complete an
end-to-end packet-path walk. However: if the healing claim were weaker than
stated, the divergence window grows back toward the ≥1 s/5 s re-enqueue
bound — which makes the *defect* worse and Path A *more* justified, not
less. The claim only weights the Path-E (close-as-fixed) comparison, which
all reviewers already rejected. Codex r2 was explicitly tasked with breaking
this claim; accept its verdict as the tiebreaker.

### C3: test 5's mechanism is deterministic

`export_forward_sessions_for_owner_rgs` emits via
`emit_open_delta_with_origin` into the table's delta ring; the pin drains
deltas and asserts neither pair key appears. Single-threaded, no timing. OK.

## Verdict

**PLAN-READY** — contingent on Codex r2 and AGY r2 not breaking the §2.3
materialization-coverage claim (C2) or finding a SyncImport/SharedMaterialize
divergence I missed (C1 says none exists). The plan's mechanism, equivalence
proof, scope, tests, and doc surface are correct and complete for /engineer.
