# Claude SMR hostile plan review — #1870 plan v4, round 3

**Reviewer:** Claude (domain SMR)
**Plan:** `docs/research/1870-local-tunnel-pair/plan.md` v4 @ `dd83445db`

## Independent verification of the Codex r3 folds

- **r3-1 (stale full-pair wording):** all four sites narrowed (§1 severity
  paragraph, §2.3 counter-signal bullet, §4 arm comment, Path E item (b)).
  Grepped the plan for remaining "same entries"/"self-reverses on the next
  data packet" full-pair phrasing: none left.
- **r3-2 ("no RX consumer" precision + test-1 spec bug):** re-verified all
  three line claims against the code myself:
  - `index_forward_nat_key` inserts into `forward_wire_index` only when
    `forward_wire != *key` (`session/mod.rs:1478-1481`); the shared
    forward-wire publish has the same `wire_key != entry.key` condition
    (`shared_ops.rs:826-827`). Local-tunnel decisions carry
    `NatDecision::default()`, so `wire_key == key` and neither index ever
    holds these entries — v1-v3's test-1 `find_forward_wire_match`
    assertion would have failed spuriously and been "fixed" wrongly during
    /engineer. Real catch; v4 test 1 now asserts via exact forward-key
    lookup.
  - `lookup_session_across_scopes` checks the local table first
    (`shared_ops.rs:528`), so the generic exact-key consumer exists but is
    only reachable if the inner forward 5-tuple arrives unencapsulated at a
    worker — not normal local-origin traffic (`tunnel.rs:72-101`). The v4
    wording states exactly this. Correct.

## Residual position

The plan's mechanism (Path A: `upsert_synced_with_origin(…, true)` in the
`UpsertLocal` arm), equivalence proof, severity framing
(reverse-half-self-healing / forward-half-inert / counter pollution /
at-cap-replace semantic change), 7-pin test plan (1, 2, 3, 4, 4b, 5, 6), and
doc surface (Rust README + arm comment + Go descriptor help text) have now
survived three hostile rounds with every substantive objection folded. The
remaining open item from my r2 review (C2 materialization coverage) was
settled by Codex r2-1 (split per-half, folded in v3) and AGY r2
(transient-arm impossibility proof). No open findings remain.

## Verdict

**PLAN-READY**
