# #9522-Phase0 — LPM parity corpus: pin today's route-lookup semantics in tests (no production change)

## 1. Status

DRAFT v1 (salvage lane) — pending adversarial plan review (ONE round per model). Same branch
`fix/9522-learned-route-cap`, base `origin/master 7ef226474`. Parent ruling killed Design A
(`docs/pr/9522/KILLED-DesignA.md`) and Design B Phase 1+3
(`docs/pr/9522-designB/KILLED-Phase1-3.md`); Phase 0 (LPM) is the piece BOTH reviewers hold
independently viable (Astra: "proceed with Phase 0 only"; GLM verified the semantic-identity
set in source). This plan implements the corpus half of Phase 0 ONLY: new test file(s)
asserting today's lookup behavior through the production entry points. NO production file is
touched — no trie, no map-type change, no behavior delta. A future LPM cutover must pass every
cell herein; that cutover is a separate plan.

## 2. Issue framing

#9522's bypass exists because the helper FIB cannot hold a full table; any future fix that
grows the table (chunked transport) or restructures lookup (LPM trie) must prove it decides
exactly what today's linear scan decides. That proof needs a pinned corpus FIRST — otherwise
the cutover's "equivalence" is asserted, not tested. This plan writes that corpus:
longest-match, preference, insertion stability, discard/next-table, connected composition
(three prefix-length relations), ECMP slice/order/hash-member behavior, both families,
table scoping, and the NoRoute boundary — each cell derived from code read at head
(`forwarding/fib.rs`, `forwarding_build/fib.rs:37-184`, `types/forwarding.rs:894-919`,
`choose_v4_route` + v6 twin) and each fail-on-revert against the semantic it pins.

## 3. Honest scope / value framing

Test-only change: one new test file + two-line module wiring. Zero throughput/cycle/memory
impact; zero behavior change. Value is entirely future-facing: (a) the LPM cutover's
acceptance corpus exists before the cutover; (b) a regression net over the most
security-adjacent decision in the dataplane (which route — and therefore which zone/NAT/screen
path — a destination takes). *If reviewers conclude even a test-only corpus is unjustified
churn without a committed LPM consumer, PLAN-KILL is acceptable — say so explicitly.*

## 4. What's already shipped / partially batched

- Lookup: per-table sorted-`Vec` first-match (`fib.rs:428-431` + v6 twin); `sort_routes`
  longest-first/preference-ASC/stable (`forwarding_build/fib.rs:161-184`); `choose_v4/v6_route`
  connected-wins-iff-`conn ≥ route` (`fib.rs:863-881`); ECMP `select_route_next_hop` bitmask
  order-stable over the whole slice (`fib.rs:1055+`, fanout cap 64); table-scoped connected
  (#2388); `lookup_forwarding_resolution_in_table_with_dynamic(state, neighbors, dst, table)`
  as the drivable public entry point.
- Test affordances: `RouteEntryV4/V6::single` cfg(test) ctors (`types/forwarding.rs:954+`);
  `PrefixV4/V6::from_net`; `sort_routes` reachable via `super::super::forwarding_build::*`
  (same pattern as `tests.rs`); `ShardedNeighborMap::new()` empty dynamic map;
  `#[path]` module wiring precedent (`mod.rs:337-342`).
- Neighbor semantics the corpus must respect: unresolved next-hop ⇒ `MissingNeighbor`
  (egress still attributed — the winner is readable without seeding neighbors); discard ⇒
  `DiscardRoute`; no match ⇒ `NoRoute` (egress 0).

## 5. Concrete design

New file `userspace-dp/src/afxdp/forwarding/tests_lpm_parity_9522.rs`, wired in `mod.rs`
next to the #7480/#9054 cells (two lines: doc comment + `#[cfg(test)] #[path] mod`). Helpers
are file-local ONLY (no production `cfg(test)` additions — existing `single()` ctors suffice):

```rust
// file-local helpers (test-only):
fn v4_table(routes: Vec<(/*prefix*/ &str, /*egress*/ i32, /*pref*/ i32)>) -> ForwardingState
// parses prefixes via Ipv4Net, builds RouteEntryV4::single (discard=false,
// next_table=""), inserts into routes_v4["inet.0"], runs sort_routes.
fn v6_table(...)  // mirror for inet6.0
fn resolve_v4(state, dst: &str) -> ForwardingResolution  // empty neighbor map, table Some("inet.0")
```

Cells (each asserts `(disposition, egress_ifindex)` — the LPM-visible contract; each names the
revert that reds it):

1. `longest_match_beats_better_preference_9522` — /8 pref 5 vs /24 pref 200 ⇒ /24's egress.
2. `same_prefix_lowest_preference_wins_9522` — three same-prefix routes prefs 10/5/7 ⇒ pref-5 egress.
3. `equal_preference_keeps_insertion_order_9522` — same prefix+pref, egresses A,B ⇒ A (stable sort).
4. `insertion_order_irrelevant_across_reassembly_9522` — same SET built in two insertion orders
   ⇒ identical resolutions over a sweep of destinations (the chunk-reassembly property).
5. `discard_never_falls_back_to_ancestor_9522` — discard /24 under /8 ⇒ `DiscardRoute` (not /8's egress).
6. `next_table_chain_resolves_9522` + `next_table_unsupported_9522` — named-table recursion and
   the depth/cycle terminal (mirror existing #6664-adjacent behavior, assert don't re-specify).
7. `connected_shorter_than_route_loses_9522` / `connected_equal_wins_9522` /
   `connected_longer_wins_9522` — the three `conn.prefix_len()` relations vs a static route.
8. `connected_is_table_scoped_9522` — connected entry in tenant-a never matches tenant-b lookup.
9. `ecmp_same_slice_order_and_hash_member_stable_9522` — multi-next-hop route: same winner for
   the same flow hash across calls; all members within the slice across hash sweep (no
   out-of-slice selection); member ORDER preserved as authored.
10. `noroute_on_empty_table_9522` — empty table ⇒ `NoRoute`, egress 0 (uncacheable lookup boundary).
11. v6 twins of 1, 2, 7 (three relations), 10 — the v6 lookup path is a separate function.
12. `unparseable_destination_fails_closed_9522` — build-path level (via `populate_routes`
    error arm, #6568): garbage destination ⇒ `Err`, never a silent skip (documents the ingest
    contract the trie must preserve: tries never see bad routes).

Explicitly NOT asserted (would over-pin internals): exact `sort_routes` comparator shape
(assert outcomes, not ordering internals); session/flow-cache behavior; policy verdicts;
performance numbers.

## 6. Public API preservation

Nothing preserved-changed: zero production edits. Test file uses only existing public-in-crate
entry points (`lookup_forwarding_resolution_in_table_with_dynamic`, `sort_routes`,
`single()` ctors, `populate_routes` error type). Module wiring adds two lines to `mod.rs`
inside `#[cfg(test)]`.

## 7. Hidden invariants the change must preserve

1. **No production delta**: `git status` after implementation shows exactly two paths
   (new test file + `mod.rs` wiring). Any production hunk fails review outright.
2. **Determinism**: no timing, no netlink, no threads, no global state; fixed hashes/addresses;
   empty neighbor maps (no resolver involvement).
3. **Full-suite safety**: unique `*_9522` test names; no shared `static`s; file-local helpers
   (no fixture coupling that a neighbor refactor can break silently).
4. **Entry-point fidelity**: every cell drives a REAL lookup function (never a reimplementation
   of matching logic in the test — a corpus that reimplements `find` proves nothing).
5. **Fail-on-revert honesty**: each cell's doc comment names the precise revert that reds it
   (e.g. "flip comparator to preference-DESC ⇒ RED"); cells that cannot name one are deleted.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | LOW (none possible) | Test-only; production untouched by construction (§7.1 enforced in review). |
| Lifetime / borrow-checker | LOW | Test-local owned values; no new production types. |
| Performance regression | LOW | ~15 unit tests, no benches; suite-time noise only. |
| Architectural mismatch | LOW | Follows the `tests_noroute_*` file-per-concern precedent; but Q6 invites the kill if even this is churn-without-consumer. |

The REAL risk is corpus incorrectness (asserting a semantic the code does not implement —
then a future LPM "passes" against a lie). Mitigation: every expectation derived from code
read at head (§4 citations) + cross-checked against existing passing tests + hostile review
of the plan itself.

## 9. Test plan

- `cargo test --release tests_lpm_parity_9522` green (the corpus).
- Named-module 5× flake check (determinism proof).
- Full `forwarding` test module + full `cargo test --release` (no regressions possible, prove it).
- `go test ./pkg/dataplane/userspace/` (Go untouched — sanity that the tree is green around the
  issue's home package; doubles as the lane's go-suite gate).
- Loss-cluster smoke: NOT REQUIRED (no dataplane behavior change — nothing to smoke; stated,
  not skipped silently).

## 10. Out of scope (explicitly)

LPM trie implementation or cutover; transfer verb; any production edit; perf measurement;
#9172; Design A/B revival; ECMP hash-policy semantics beyond member-stability observation.

## 11. Open questions for adversarial review

1. **Snapshot-build vs direct-state construction?** The corpus builds `ForwardingState`
   directly (precise entry control). Should a subset ALSO go through `ConfigSnapshot` →
   `populate_routes` → `sort_routes` (integration realism: family-match, canonicalization,
   next-hop resolution)? Or does dual construction double maintenance for zero added signal?
2. **ECMP member-stability: pin EXACT member per fixed hash, or determinism-only?** Exact-member
   pins the bitmask-selection implementation (brittle across legitimate refactors?); sweep-only
   (all winners ∈ slice + repeatable) pins the contract. Which is the right level — kill the
   exact-member cell if it over-pins?
3. **MissingNeighbor as the winner-oracle:** most cells assert winner via `egress_ifindex`
   under `MissingNeighbor` (no neighbor seeding). Does any cell NEED `ForwardCandidate`
   (seeded neighbor map) to be meaningful — i.e. does disposition interact with selection
   anywhere (tunnel outer? local-delivery?) that the corpus must cover?
4. **Next-table cells: assert or drop?** They mirror existing #6664-adjacent coverage. Keep as
   LPM-relevant (recursion must survive the trie) or drop as duplication?
5. **Insertion-reassembly cell (4): is it load-bearing?** It exists for chunked transfer
   (killed). Without a transfer consumer, is it speculative — delete, or keep as
   order-independence documentation?
6. **Kill the whole corpus?** No LPM consumer is committed; #9522's fix direction is undecided
   (documented residual vs Alternative C per parent). Is a 15-cell corpus now churn without a
   consumer — PLAN-KILL the salvage too?
7. **Go-suite gate proportionality:** Go is untouched; is `go test` on the home package
   sufficient, or does the lane require the full `go test ./...`? Name the cheaper sufficient
   gate if the full suite is disproportionate.
