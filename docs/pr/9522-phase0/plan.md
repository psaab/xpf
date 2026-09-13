# #9522-Phase0 — LPM parity corpus: pin today's route-lookup semantics in tests (no production change)

## 1. Status

DRAFT v2 — pending implementation (plan-review gate: ONE round per model; Astra NEEDS-MAJOR
vs GLM NEEDS-MINOR → STOPPED per the worse-than-MINOR rule, then parent authorized option (a):
implement with fixes). Raw round-1 reviews: `docs/pr/9522-phase0/reviews/`. This revision
addresses EVERY convergent item; no second plan-review round per parent instruction (fixes are
agreed-mechanical). PR-stage hostile code review still applies.

Round-1 record: Astra NEEDS-MAJOR (3 blocking: `sort_routes`/`populate_routes` privacy;
reassembly-invariance false with ties; ECMP entry-point hash mismatch) + scope decisions;
GLM NEEDS-MINOR (F1–F7 convergent + rulings). The reviews CONVERGE on mechanics; delta is
severity only. V2 dispositions, each mapped:

- Construction: snapshot-build ONLY via `build_forwarding_state` (`forwarding_build/mod.rs`,
  `pub(super)` = afxdp-wide, already used by `tests.rs`); the false §4 reachability claim is
  corrected — `sort_routes`/`populate_routes` are `pub(super)` in private `forwarding_build::fib`,
  unreexported, and are NEVER called directly nor copied. Fixture interfaces + gateway
  next-hops reuse the #4446 table-scoped inference path (complementary gates cited, not duplicated).
- Cell 4: distinct-`(prefix, pref)` qualifier + NEW reversed-tie case proving the winner CHANGES
  (honest direction of the stability property).
- ECMP: `lookup_forwarding_resolution_inner_ecmp` with EXPLICIT hashes {0,1} + exact members +
  reordered-slice swap + sweep-containment + per-destination repeatability via the plain wrapper
  (no exact dst→member maps — GLM F6). Robustness note: with all members sharing liveness state,
  live/all-dead arms select identically (`h % len` over the same order), so the assertions hold
  under both liveness outcomes.
- Dropped/reframed: cell 12 (#6568 — cite `forwarding_build/tests.rs:3315-3362`, one doc line);
  cell 6 reduced to the novel angle (next-table route LOSING longest-match to a longer direct
  route); v4-twin-of-2 stated as deliberate re-homing inside the unified contract.
- Fixture constraints (Astra): positive distinct ifindices, tunnel IDs zero, empty static AND
  dynamic neighbor maps, no local-address membership in probe ranges; unresolved-interface
  gateway (ifindex 0) ⇒ `NoRoute` documented, not asserted otherwise; outside-prefix miss in a
  populated table; IPv6 canonical builder-to-lookup case.
- Wording: "selected lookup-semantic coverage" (not equivalence proof); "repeat-run check"
  (not determinism proof); scoped-diff no-production rule (not `git status` prose);
  home-package Go gate only.

## 2. Issue framing

Unchanged from v1: a pinned corpus must precede any LPM cutover or table-growth fix, or
"equivalence" is asserted. #9522's bypass + killed Designs A/B are the motivation; this file
remediates nothing by itself (labeled accordingly).

## 3. Honest scope / value framing

Test-only: one new test file + three-line `mod.rs` wiring (doc comment + `#[cfg(test)]` +
`#[path]` + `mod`, per the `mod.rs:330-342` precedent — "two-line" corrected). Zero behavior
change. Value: LPM-gating evidence foundation + regression net over the route-selection
decision. Novel coverage (nothing like it in tree): cross-prefix longest-beats-preference,
equal-pref insertion stability (+ honest reversed-tie), v6 preference tie-breaks, unified
parity contract. *Q6 answered permanent: keep iff these cells stay green and review-clean.*

## 4. What's already shipped / partially batched

V1 §4 stands, CORRECTED: `sort_routes`/`populate_routes` NOT directly reachable (privacy,
verified); construction rides `build_forwarding_state(&ConfigSnapshot)` exclusively.
Complementary (cited, not duplicated): #6568 ingest cells (`forwarding_build/tests.rs:3315,
3367` + anti-over-reject), gateway inference (`forwarding_build/tests.rs:3525+`), #2390
preference cell (`tests.rs:4679`), next-table recursion/self-loop/v6-canonical/cycle cells
(`tests.rs:2717, 3071, 3090, 3123`). Reused: `RouteSnapshot` wire shape
(`protocol/snapshot.rs:251`: table/family/destination/next_hops`Vec<String>`/discard/
next_table/preference), `lookup_forwarding_resolution_in_table_with_dynamic`
(`fib.rs:182-190`, hash None → destination hash), `lookup_forwarding_resolution_inner_ecmp`
(`fib.rs:205-213`, explicit `Option<u64>` hash used VERBATIM as spread
(`:528`, `:759`)), `select_route_next_hop` bitmask order-stable + all-dead fallback
`candidates[hash % len]` (`fib.rs:1055-1135`, cap 64), `choose_v4/v6_route` (`fib.rs:863-899`),
`ShardedNeighborMap::new()`, `#[path]` wiring.

## 5. Concrete design

File `userspace-dp/src/afxdp/forwarding/tests_lpm_parity_9522.rs`, wired in `mod.rs`.
File-local helpers ONLY (snapshot builders — no production additions):

```rust
// Base snapshot: lan (ifindex 11, 10.99.0.1/24) + wan (ifindex 12, 192.0.2.10/24).
// Connected 10.99.0.0/24 + 192.0.2.0/24; gateways .2/.1 resolve per #4446.
// Probe ranges avoid locals/connected except composition cells: 10.0.0.0/8,
// 172.16.0.0/12, 198.51.100.0/24, 203.0.113.0/24 (+ v6: 2001:db8:1::/48 etc.).
fn base_snapshot() -> ConfigSnapshot
fn with_routes(base: ConfigSnapshot, routes: Vec<RouteSnapshot>) -> ForwardingState
// = build_forwarding_state(&snap) — production sort path, never copied.
fn resolve(state, dst: &str) -> ForwardingResolution  // empty maps, table inet.0
fn resolve_ecmp(state, dst: &str, hash: u64) -> ForwardingResolution  // inner_ecmp, Some(hash)
```

Cells (each `(disposition, egress)` + named revert; `*_9522` names):

1. `longest_match_beats_better_preference_9522` (NOVEL — no longest test in tree): /8 pref 5
   vs /24 pref 200 ⇒ /24 egress. Revert comparator to preference-first ⇒ RED.
2. `same_prefix_lowest_preference_wins_9522` — deliberate RE-HOMING of #2390 (`tests.rs:4679`)
   into the unified contract (stated, not novel): prefs 10/5/7 ⇒ pref-5 egress.
3. `equal_preference_keeps_insertion_order_9522` (NOVEL): same prefix+pref, egresses A,B ⇒ A.
3b. `reversed_tie_changes_winner_9522` (honest direction): B,A ⇒ B. Revert stability ⇒ RED.
4. `distinct_key_reassembly_order_independent_9522` (SCOPED per F2): distinct-(prefix,pref) set
   built in two snapshot orders ⇒ identical sweep resolutions. With ties ⇒ NOT asserted (3b).
5. `discard_never_falls_back_to_ancestor_9522`: discard /24 under /8 ⇒ `(DiscardRoute, 0)`.
6. `next_table_loses_longest_match_9522` (REDUCED — the one novel angle): next-table /16 vs
   direct /24 ⇒ direct wins; + terminal-failure cell (unresolvable depth ⇒
   `NextTableUnsupported`, no ancestor fallback; missing target table ⇒ `NoRoute` — no
   early-cycle-detection claim).
7. `connected_{shorter_loses,equal_wins,longer_wins}_9522` — the three relations vs a static
   route (probe inside connected ranges; expectation per `choose_v4_route`).
8. `connected_is_table_scoped_9522`: tenant-b lookup never matches tenant-a connected.
9. ECMP (explicit-hash entry, exact members): two gateways (egresses 11, 12), hash 0 ⇒ member 0,
   hash 1 ⇒ member 1; `reordered_slice_swaps_winners_9522`; `sweep_containment_9522` (every
   winner ∈ slice over dst sweep via plain wrapper); `destination_repeatability_9522` (same dst
   twice ⇒ same winner; NO exact dst→member maps — F6). Liveness-robust by construction
   (shared liveness state ⇒ identical selection either arm).
10. `noroute_empty_table_9522` + `noroute_outside_prefix_populated_table_9522`: `(NoRoute, 0)` both.
11. v6 twins: longest-beats-preference, same-pref-wins, connected 3 relations, NoRoute (the v6
    preference tie-break has NO tree coverage — NOVEL). Plus builder-to-lookup IPv6
    canonical-table case (Astra: distinct coverage).
- Cell 12 DROPPED (dup of 3315-3362); one doc line cites it. Unresolved-interface gateway
  (ifindex 0) ⇒ `NoRoute` documented in fixture notes (Astra constraint).

NOT asserted: comparator internals, sessions/flow-cache, policy, perf numbers, cycle
early-detection, exact dst→member maps.

## 6. Public API preservation

Zero production edits (enforced by scoped diff in review). Test-only use of existing
crate-visible entry points. Three-line `mod.rs` wiring inside `#[cfg(test)]`.

## 7. Hidden invariants the change must preserve

V1's five stand, amended: (4) entry-point fidelity — real lookup fns only, INCLUDING the
explicit-hash ECMP entry (documented exception); (5) every cell names its revert; new (6)
snapshot-build construction exclusively (no direct-state FIB assembly — also answers Q1:
integration realism for family/canonicalization/inference comes free); (7) fixture hygiene —
positive distinct ifindices, zero tunnels, empty maps, probes avoid locals (F7 caveat honored).

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | LOW (none possible) | Test-only, scoped-diff enforced. |
| Lifetime / borrow-checker | LOW | Owned test values. |
| Performance regression | LOW | ~18 deterministic unit tests. |
| Architectural mismatch | LOW | File-per-concern precedent; Q6 keep (novel cells + unified contract). |

Residual risk = corpus incorrectness: mitigated by derivation-from-head + both-reviewer
verification (GLM's table: every semantic ✅ exact; Astra: cells 1–3/connected/discard/NoRoute
correct) + implementation run green + fail-on-revert discipline.

## 9. Test plan

- `cargo test --release tests_lpm_parity_9522` green (the corpus, ~18 cells).
- Repeat-run check (module 5×; "proof" language dropped).
- Full `forwarding` module + full `cargo test --release` green.
- `go test ./pkg/dataplane/userspace/` (home-package gate; full `./...` disproportionate — Q7).
- Scoped-diff review: exactly two paths (new file + `mod.rs`); any production hunk kills the PR.
- No cluster smoke (no behavior change — stated).

## 10. Out of scope (explicitly)

LPM implementation/cutover; transfer verb; any production edit; perf measurement; #9172;
Design A/B revival; ECMP hash-policy semantics beyond member-stability; cycle
early-detection claims; exact dst→member maps.

## 11. Open questions for adversarial review — RESOLVED (no second round per parent)

1. Snapshot vs direct-state → SNAPSHOT exclusively (both reviewers; integration realism free).
2. Exact-member ECMP → YES at explicit hashes (Astra: legitimate contract) with
   sweep-containment + repeatability alongside (GLM F6); NO exact dst→member maps.
3. Oracle sufficiency → sufficient with fixture constraints (both).
4. Next-table → reduced novel angle (both).
5. Cell 4 → kept scoped (both).
6. Kill corpus → NO (both).
7. Go gate → home-package (both).
