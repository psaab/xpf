# Adversarial plan review — #9522 Phase 0 LPM parity corpus

## Verdict: **NEEDS-MINOR**

The pinned semantics themselves verify clean against head — every behavioral expectation in cells 1–11 matches what `fib.rs`/`forwarding_build` actually implement. But the plan's §5 concrete design contains one implementability defect (the sketched helper cannot compile under the plan's own zero-production-edit constraint) and one cell asserting an unconditional property the code does not implement. Both are fixable inside the test-only envelope; neither requires redesign.

---

## 1. Pinned semantics vs head source — all verified

| Plan claim | Source ground | Result |
|---|---|---|
| Longest-first, pref-ASC, stable sort; `find` first-match | `forwarding_build/fib.rs:161-184` (comparator), `fib.rs:428-431` + v6 twin (`routes.iter().find(contains)`) | ✅ exact |
| Connected wins iff `conn ≥ route`; three prefix-len relations | `fib.rs:863-881` (`choose_v4_route`), `fib.rs:883-899` (v6 twin) | ✅ exact — cells 7/11v6 correct |
| Discard: no ancestor fallback | `fib.rs:469-482` — discard checked first on the *matched* (most-specific) entry, returns `DiscardRoute` egress 0, no rescan | ✅ |
| Next-table recursion; depth/cycle → `NextTableUnsupported` | `fib.rs:483-525` (`MAX_NEXT_TABLE_DEPTH`, visited-chain) | ✅ (but see F4) |
| ECMP bitmask, order-stable over slice, cap 64 | `fib.rs:1055+` (`select_route_next_hop`, pick-th-set-bit ascending; `MAX_SUPPORTED_ECMP_FANOUT = 64`) | ✅ |
| MissingNeighbor winner-oracle (egress attributed without seeded neighbors) | `fib.rs:571-587` static path: all-dead fallback still selects a member (`fib.rs:1128-1131`), then `egress_ifindex: ifindex` with `MissingNeighbor`; interface-only members live by `ifindex > 0` (`fib.rs:543-548`) | ✅ oracle is sound — including for explicit-gateway ECMP via the fallback arm |
| Table-scoped connected | `fib.rs:444-450` (`entry.table == table` in the find predicate) | ✅ |
| NoRoute on empty table, egress 0 | `fib.rs:833-839` (`no_route_resolution`) | ✅ |
| #6568 fail-closed | `forwarding_build/fib.rs:128-138` (`RouteDestinationUnparseable`) | ✅ (but see F3) |
| `single()` ctors, `PrefixV4::from_net`, `ShardedNeighborMap::new()`, `#[path]` wiring | `types/forwarding.rs:952-986`, `src/prefix.rs:5-11`, `sharded_neighbor.rs:245`, `forwarding/mod.rs:330-342` | ✅ all exist; fields `pub(in crate::afxdp)` so multi-member ECMP routes are constructible in-test |

Entry-point fidelity (Q4 of your checklist): `lookup_forwarding_resolution_in_table_with_dynamic` (`fib.rs:182-190`) is a real production entry; no cell requires reimplemented matching.

## 2. Findings

**F1 — §5 helper cannot compile as specified (blocker-as-written, mechanical fix).** The plan claims "`sort_routes` reachable via `super::super::forwarding_build::*` (same pattern as `tests.rs`)". False: `sort_routes` is `pub(super)` in `forwarding_build::fib` (`forwarding_build/fib.rs:161`), i.e. visible only inside `forwarding_build` and descendants, and the re-export list (`forwarding_build/mod.rs:44-47`) covers only `infer_connected_route_target_*`, `parse_route_next_hop*`, `resolve_ifindex`, `resolve_route_next_hops_*` — no `sort_routes`. The cited precedent actually drives sorting *through* `build_forwarding_state` (`tests_leak_overlap_9955.rs:165`; wrapper at `forwarding_build/mod.rs:196`, `pub(super)` = afxdp-wide). Fix within the zero-edit e…

**F2 — cell 4 asserts a property the code does not implement (corpus-incorrectness risk).** "Same SET built in two insertion orders ⇒ identical resolutions" is false for sets containing duplicate `(prefix, preference)` keys: the stable sort preserves insertion order among equals, and **cell 3 pins exactly that order-dependence** — the two cells contradict each other as written. Scope cell 4 to distinct-`(prefix, pref)` sets (also what chunk-transfer dedup would guarantee). An implementer following the plan literally would write a red-on-arrival cell or, worse, "fix" it by weakening cell 3.

**F3 — cell 12 duplicates existing coverage.** #6568 fail-closed is already pinned at `forwarding_build/tests.rs:3315-3362`, including the anti-over-reject companion. The plan's Q11.4 asks keep-or-drop for next-table but not for this cell. Drop it, or keep one line-referencing doc cell max.

**F4 — cell 6 near-pure duplication.** Next-table recursion, self-loop, v6 canonicalization, and cross-table cycle are covered at `tests.rs:2717`, `3071`, `3090`, `3123`. The only LPM-relevant angle *not* covered: a next-table route *losing* longest-match to a longer direct route in the same table. Reduce cell 6 to that, or drop.

**F5 — cell 2 (v4) duplicates `tests.rs:4679` (#2390).** Keeping the v4 twin inside a unified one-file parity contract is defensible, but the plan should state it as deliberate re-homing, not novel coverage. The genuinely novel cells are 1 (cross-prefix longest-beats-preference — no "longest" test exists anywhere in `tests.rs`), 3 (equal-pref insertion stability), the v6 twins (no v6 preference tie-break test exists), and 4-with-F2's-scoping.

**F6 — cell 9 wording vs entry point + Q2 ruling.** `lookup_forwarding_resolution_in_table_with_dynamic` threads `ecmp_flow_hash = None` (`fib.rs:200`) — there is no flow-hash parameter; "same winner for the same flow hash" is only realizable as same-destination determinism plus a destination sweep (per-destination `ecmp_hash_v4`). On Q2: pin **sweep-containment (every winner ∈ authored slice) + per-destination repeatability + full member coverage across the sweep** — do NOT pin exact dst→member maps; that over-pins the bitmask implementation, which legitimately changed in #7204 without changing selection. Note also that with an empty neighbor map and explicit-gateway members you exercise the all-dead fallback arm; use interface-only members (`n…

**F7 — cosmetics.** "Two-line wiring" is three lines per the `mod.rs:330-342` precedent; the `(&str, i32, i32)` helper tuple can't express discard/next-table variants (RouteSnapshot carries both — another argument for the snapshot path); under snapshot-build, probe destinations must avoid fixture on-link addresses or cells resolve `LocalDelivery` (`fib.rs:299-337`) — #9955 already manages this constraint.

## 3. Open questions ruled

- **Q3 (oracle sufficiency):** sufficient. No cell needs `ForwardCandidate`; no tunnels authored; `local_v4/v6` empty under direct construction (with F7's snapshot caveat). No disposition/selection interaction is left uncovered by the corpus's scope.
- **Q5 (cell 4 load-bearing):** keep, with F2's scoping — cheapest order-independence documentation, directly feeds any future transfer/dedup lane; not load-bearing today, and priced accordingly (one cell).
- **Q6 (kill the corpus):** no. Both parent reviews hold Phase 0 independently viable; cell 1 + v6 twins + the unified parity contract are genuinely uncovered; ~15 deterministic unit tests, zero production risk. Not churn.
- **Q7:** home-package `go test ./pkg/dataplane/userspace/` is the sufficient cheap gate; full `go test ./...` is disproportionate for a Rust-test-only change.

## 4. Required revisions before PLAN-READY

1. Rewrite §5's construction strategy per F1 (snapshot-build for sort-dependent cells; direct-state only where order-irrelevant) and correct the false §4 reachability claim.
2. Add F2's distinct-key qualifier to cell 4.
3. Resolve F3/F4/F5 (drop or deliberately reframe duplicated cells 6, 12, and the v4 twin of 2).
4. Fix cell 9's wording and adopt F6's containment-level pinning.

**Verdict: NEEDS-MINOR** — every pinned semantic survives hostile source verification; the defects are in the plan's construction mechanics and two over-broad/duplicative cells, all repairable within the test-only envelope.
