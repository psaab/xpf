# #1855 plan — hostile Claude SMR review (round 1)

Reviewer: Claude (domain SMR: session-table data structures, Rust test
semantics, HA dataplane). Stance: hostile; tried to kill Path H.

## Attack 1 — reachability: enumerate EVERY `key_to_handle` writer
Claim under attack: "stale/vacant mapping is impossible-by-construction."

Full enumeration (grep `key_to_handle\.` in `src/session/mod.rs`):
- Inserts: `:723` and `:810` (both install paths — paired with a slab
  `entries.insert` two lines above, so the handle is fresh by
  construction), `:1271`/`:1281` (remove_entry's restore-on-failed-remove —
  reinstates the exact prior mapping), `:1325` (`restore_entry`,
  `#[cfg_attr(not(test), allow(dead_code))]` — test-only reference half
  since #1752).
- Removes: `:1255` only (inside `remove_entry`).
- Slab removes: `:1304` only (inside `remove_entry`, AFTER index cleanup +
  `no_index_points_at` debug scan).
- Reads: lookup paths only (`:319`, `:361`, `:532`, `:847`, `:1022`).

All removal call sites (`remove_entry(` at `:435`, `:706`, `:792`,
`:1123`, `:1159`) funnel through the one cleanup function. The expiry
wheel (`wheel.rs`) holds keys, not handles, and deletes via the same
paths. **No bypass found. Attack fails.**

## Attack 2 — concurrency: lookup→use window
`SessionTable` is owned by value per worker
(`src/afxdp/worker/loop_body/setup.rs:40`); every mutator takes
`&mut self`, and within `update_session` the handle read (`:847`) and the
slab access (`:853`) happen under one exclusive borrow — no interleaving
is possible even in principle. The `Arc<Mutex<FastMap<...>>>` maps in
`session_glue/promote.rs` / `tunnel.rs` are the synced-session side
tables, a different structure. **Attack fails.** (The session README's
"per-worker handles read and update under shared locks" phrasing refers
to those side tables; worth not copying that phrasing into new docs.)

## Attack 3 — test-split mechanics
- `should_panic(expected=…)` is a substring match against the panic
  payload. Verified messages:
  - `:854` "update_session: key_to_handle had stale handle {h} for {k:?}"
  - `:862` "update_session: stale key_to_handle for {k:?}"
  - `:1026` "refresh_for_ha_transition: stale handle {h} for {k:?}"
  - `:1034` "refresh_for_ha_transition: stale key_to_handle for {k:?}"
  The plan's four expected substrings each match exactly one arm. OK.
- No `[profile.*]` section exists in `userspace-dp/Cargo.toml`, so:
  debug `cargo test` has `debug_assertions` ON, `cargo test --release`
  OFF, and default `panic = "unwind"` (required for `should_panic`). OK.
- The vacant release test calls BOTH `update_session` and
  `refresh_for_ha_transition`; a single debug `should_panic` variant
  would stop at the first panic — the plan correctly splits per-arm. OK.
- One panic per test, so substring ambiguity ("stale handle" appears in
  two arms' messages) is moot; still, the plan uses function-qualified
  prefixes. OK.

## Attack 4 — is Path B (counter) secretly right?
A counter increments only if a logic bug exists; it cannot fire under
correct code (Attack 1). Dead telemetry + wire/protocol/Prometheus
plumbing cost, and it would make `update_session`'s arms diverge from
`remove_entry`'s identical reviewed arms (`:1263`/`:1280`, #964 "release-
mode safety net"). The #1760 precedent (ship a counter, watch it) applied
because that collision WAS reachable (interface-mode SNAT). Here it is
not. **Attack fails; Path B stays rejected.**

## Attack 5 — factual audit of the plan
- Commit order claim: 5d81c3ed9 (13:51) precedes d1e2ba33d (13:56), both
  2026-06-03 — verified via `git show`. The tests were red in debug from
  birth. OK.
- Line refs spot-checked: `:141` field, `:854`/`:862`/`:1026`/`:1034`
  asserts, `:1254` remove_entry, `:1298` no_index_points_at assert. OK.
- Initial plan draft said the session module "has no standalone README" —
  WRONG (`src/session/README.md` exists). Fixed in §8 before review
  dispatch; Phase 2 must add the contract note there.

## Residual concerns (minor, not blocking)
1. `cfg(not(debug_assertions))` tests are invisible to anyone running
   only debug `cargo test`; the both-profiles gate is procedural, not
   enforced by tooling. Accepted in §7; suggest the Phase-2 PR
   description restate the both-profiles requirement.
2. The debug variants must NOT reuse the release tests' post-state
   assertions after the panicking call (unreachable code after panic);
   bodies should end at the panicking call.

## Verdict
PLAN-READY (with §8 README addition retained and residual concern 2
honored at implementation time).
