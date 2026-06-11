# #1855 — inplace_{stale,vacant} debug_assert contradiction: contract decision

Status: DRAFT for 3-way review (Codex + AGY + Claude SMR).
Scope: small contract decision + test-only fix. Proportionate plan.

> PLAN-KILL is invited. The legitimate kill shape here is small: "tests are
> wrong, cfg-gate / #[should_panic] them" is itself the proposed outcome, so a
> kill must show either (a) staleness IS production-reachable (→ Path B,
> counter), or (b) a simpler/safer test rig exists via legitimate API
> sequences.

## 1. Problem

`cargo test` (debug profile) is red on master:

```
session::tests::inplace_stale_handle_returns_false_no_panic   FAILED
  panicked at src/session/mod.rs:862: update_session: stale key_to_handle for ...
session::tests::inplace_vacant_handle_returns_false_no_panic  FAILED
  panicked at src/session/mod.rs:854: update_session: key_to_handle had stale handle 9999 ...
```

Reproduced on this branch (origin/master @ 79dd55e53): `cargo test inplace_`
→ 12 passed, 2 failed, both at the `debug_assert!(false, ...)` arms.

The tests (added d1e2ba33d, #1752 Path E differential tests) deliberately
corrupt `key_to_handle` via private-field access and assert `update_session`
returns `false` **without panicking**. The defensive arms in `update_session`
(added 5d81c3ed9, same day, 5 minutes EARLIER) are `debug_assert!(false, ...)`
— so the tests were red in debug from birth; the d1e2ba33d message's "All 11
pass" can only have been a release-profile run. Release gates stayed green
because `debug_assert!` compiles out (no `[profile.release]` override of
`debug-assertions` in `userspace-dp/Cargo.toml`).

## 2. Evidence: is a stale/vacant `key_to_handle` production-reachable?

No. It is impossible-by-construction absent a logic bug:

- **Single-writer:** `SessionTable` is per-worker; every mutator takes
  `&mut self`. There is no cross-thread mutation path and no lookup→update
  window in which another writer can evict/reuse the slot
  (`src/afxdp/worker_runtime.rs` ownership; all `update_session` callers are
  `&mut` wrappers in `src/session/mod.rs:967/996/1078` plus
  `refresh_for_ha_transition` callers in `session_glue/commands/*.rs`).
- **Private field:** `key_to_handle` (`src/session/mod.rs:141`) is
  module-private. The tests can rig the corruption only because
  `session/tests.rs` is in-module. No external API writes it directly.
- **Eager-cleanup invariant (#964):** every removal goes through
  `remove_entry` (`mod.rs:1254`), which removes the `key_to_handle` mapping
  FIRST, cleans every handle-valued secondary index, and (debug-only)
  asserts `no_index_points_at(handle)` before the slab slot is freed
  (`mod.rs:1298`). Installs insert a freshly allocated slab handle. So a
  mapping pointing at a vacant or reused slot cannot arise from any
  legitimate call sequence — i.e. the rigged state is a logic-bug state,
  not a reachable runtime race (HA sync, eviction interleaving, etc. all
  funnel through the same single-threaded `&mut` methods).

## 3. Sibling precedent — the contract already exists in the code

`remove_entry` has the **identical** two arms (vacant slot at `mod.rs:1263`,
key mismatch at `mod.rs:1280`), each `debug_assert!(false, ...)` + tolerate
in release, with the contract spelled out in comments:

> "Should never fire under correct cleanup; **release-mode safety net**
> (Copilot review — was `.expect()` which panicked)."

That pattern survived the #964 multi-round review precisely in this shape:
**debug = crash loudly (invariant violation), release = tolerate + refuse
(return None/false) rather than corrupt another session's indices.** The
#1752 arms in `update_session` / `refresh_for_ha_transition` copied it
("parity with remove_entry", `mod.rs:850`). No counter exists for any of
these arms, in `remove_entry` either.

## 4. Paths

### Path A — pure crash contract (tests → unconditional `#[should_panic]`)
Rejected: `cargo test --release` would then be red (the assert compiles out,
no panic occurs). Would also misdocument production behavior, which IS
"return false".

### Path B — pure tolerate contract (demote `debug_assert` to counter/log)
Rejected:
- The counter is dead telemetry: §2 shows the state is unreachable absent a
  logic bug, so it never increments in production; wire-additive counter
  plumbing (protocol.rs + protocol.go + status + Prometheus) is pure cost
  with no operator-visible value.
- Loses debug-time bug detection: the asserts are the *only* thing that
  turns a future index-corruption logic bug into a loud test failure
  instead of a silently dropped refresh.
- Inconsistent with `remove_entry` unless its two arms are demoted too —
  widening a test-only fix into a behavior-contract change across the #964
  invariant machinery.

### Path H (CHOSEN) — ratify the existing hybrid contract; fix the tests
The code contract is already correct and consistent: **debug asserts
loudly, release tolerates + returns false.** Only the tests contradict it,
because they assert the release-mode posture while running in debug. Fix is
test-only + documentation:

1. **Split each red test into a cfg-gated pair** in
   `userspace-dp/src/session/tests.rs`:
   - `#[cfg(not(debug_assertions))]` — keep the existing names + bodies
     verbatim (`inplace_stale_handle_returns_false_no_panic`,
     `inplace_vacant_handle_returns_false_no_panic`): they correctly verify
     the release safety net (returns false, does not mutate the unrelated
     reused-slot session, `refresh_for_ha_transition` shares the guard).
   - `#[cfg(debug_assertions)]` + `#[should_panic(expected = "...")]` —
     debug variants documenting the invariant crash, one per assert arm
     (a `should_panic` test stops at the first panic, so the vacant test's
     two calls must split):
     - `inplace_stale_handle_asserts_in_debug` → `update_session`,
       expected `"update_session: stale key_to_handle"` (mod.rs:862)
     - `inplace_vacant_handle_asserts_in_debug` → `update_session`,
       expected `"key_to_handle had stale handle"` (mod.rs:854)
     - `ha_transition_vacant_handle_asserts_in_debug` →
       `refresh_for_ha_transition`, expected
       `"refresh_for_ha_transition: stale handle"` (mod.rs:1026)
     - `ha_transition_stale_handle_asserts_in_debug` →
       `refresh_for_ha_transition`, expected
       `"refresh_for_ha_transition: stale key_to_handle"` (mod.rs:1034)
     (the last adds debug coverage for an arm the release tests never
     reached; symmetric four-arm coverage, ~10 lines each reusing the
     existing rig helpers)
2. **Doc-comments** on `update_session` + `refresh_for_ha_transition`
   guard arms (and the test pairs) stating the contract in one place:
   stale/vacant `key_to_handle` is impossible-by-construction
   (single-writer `&mut`, #964 eager cleanup); debug builds assert loudly;
   release builds tolerate and return false without touching the
   reused-slot session.
3. No production code changes. No counters. No wire changes.

## 5. Why not "rig the state via legitimate API sequences"?
There is none — that is the point of the §2 invariant. Any sequence of
public calls leaves `key_to_handle` consistent (verified by
`no_index_points_at` on every removal in debug). A test that *could* reach
the state legitimately would itself be the discovery of a real bug → Path B
revisit (same trigger as the #1760 "watch the counter" rule: if a future
incident shows the arm firing in release, the contract decision reopens).

## 6. Gates (Phase 2)
- `cargo test` (DEBUG — the profile red today): full run, awk-aggregated
  over all "test result" lines, unmasked `; echo T=$?`.
- `cargo test --release`: same aggregation, unmasked.
- The two release-named tests + four debug variants run 5x in their
  respective profiles (cfg-gating means each profile runs its own set).
- `go test ./...` once, unmasked (no Go delta expected).
- Known unrelated flake from the issue
  (`afxdp::worker_queue::tests::concurrent_recovery_processes_each_command_exactly_once`,
  passes in isolation, load flake) is out of scope; if it fires in a full
  run, rerun in isolation and document.

## 7. Risks
- **Profile-gated test rot:** `cfg(not(debug_assertions))` tests only run
  under `--release`; if CI/local habit is debug-only, the release safety-net
  assertions go unexercised. Mitigated: the project's standing gate (per
  #1855 itself and the /engineer skill) runs BOTH profiles.
- **`should_panic(expected=…)` message coupling:** expected substrings are
  prefixes of the assert messages; if the messages are reworded the tests
  fail loudly (acceptable, self-locating).
- **Randomized differential test** (`inplace_randomized_sequence_matches_reference`)
  is untouched and remains the behavioral equivalence oracle.

## 8. Docs
- `userspace-dp/src/session/mod.rs` doc-comments (the invariant decision —
  module contract lives next to the arms).
- `userspace-dp/src/session/README.md` — add a short "Corruption contract"
  note (stale `key_to_handle` impossible-by-construction; debug asserts,
  release tolerates + returns false/None). The README is the module
  contract doc per project rules.
- `_Log.md` entry.
- `docs/pr/1752-session-inplace-refresh/plan.md` is historical and stays
  as-written.

Ownership note verified for §2: the table is owned by value per worker
(`src/afxdp/worker/loop_body/setup.rs:40`, `pub(super) sessions:
SessionTable`); the `Arc<Mutex<FastMap<...>>>` shared maps elsewhere in
`session_glue`/`tunnel.rs` are the *synced-session* side tables, not this
`SessionTable`.

## 9. Out of scope
- `worker_queue` load flake (issue notes it separately).
- Any change to `remove_entry`'s arms (already correct, already reviewed).
- Counters / wire protocol.

## 10. Deliverable
Single small PR off origin/master: test split + doc comments + `_Log.md`,
`Closes #1855`.

## 11. Decision asked of reviewers
Ratify Path H (hybrid: debug crash / release tolerate, cfg-gated tests), or
kill with evidence per the invitation at top.
