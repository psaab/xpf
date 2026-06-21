# Claude SMR — Hostile review of the #2158 file-split plan (round 1)

Reviewer stance: assume the plan is wrong until proven otherwise. The
nominal risk in "pure code-motion" is an *accidental* behavior change that
the diff hides because it looks like a move. I hunted for: lost receivers,
silent visibility changes mislabeled as "no change", init-order shifts,
codegen/inlining regressions on the hot path, and any file the plan calls
"clean" that actually isn't.

Verdict: **plan is PLAN-READY** after the corrections below were folded in.
Three findings were material and changed the plan; the rest are confirmations.

---

## F1 (MAJOR — folded) — "shared_cos_lease split needs NO visibility change" is FALSE

The first-pass boundary analysis asserted the shared_cos_lease split needs
"zero new private→pub conversions" and "no visibility widening." That is
**wrong** and would have shipped a PR whose diff is not what the body claims.

Evidence (read directly):
- `V8State` (line 405) and `SharedCoSEpochState` (line 335) have **all
  inherent-private fields** (no `pub`/`pub(super)` modifier).
- `lease.rs`'s `acquire_v8` (~550 LOC) reads those fields directly
  (`v8.epoch.epoch_seq`, `v8.worker_grants[]`, `v8.equal_flow.*`, …).
- The *already-extracted* `rotate_epoch_v8.rs` header comment states it
  outright: "Visibility widens from inherent-private to `pub(super)` so the
  rotation tick path in `mod.rs` continues to find it." The
  `publish_equal_flow_epoch_v8.rs` comment says the same.

So splitting `epoch.rs` away from `lease.rs` **forces `pub(super)` widening**
on every private field crossed. This IS still acceptable code-motion under the
project's definition (it matches the documented #1588 precedent), but the plan
MUST say so honestly. **Folded into §4.2 and §5.4**: relabeled as "minimal
`pub(super)` widening, compiler-enumerated, no new `pub`/`pub(crate)`, no
cross-crate surface change," and added to the §8 behavior-preservation
checklist (item 3 carves out the `pub(super)`-only allowance). The PR body must
list each widened field and justify it.

## F2 (MAJOR — folded) — codegen assumption was backwards (LTO is OFF)

The boundary analysis claimed `userspace-dp/Cargo.toml` defaults to `lto =
true`, concluding cross-module inlining "just works." **Verified false:**
there is no `[profile.release]` at all, so release uses Cargo defaults —
`lto = false`, `codegen-units = 16`. With 16 codegen units and no LTO, moving
a hot function to a new file *can* change its codegen unit and thus its
inlining decision. For HOT-PATH files (shared_cos_lease, and the deferred
queue_service/forwarding) this is the real risk, not a non-issue. **Folded
into §6**: carry `#[inline]` with moved hot helpers (the #1588 precedent did
exactly this), and the loss-cluster smoke is mandatory for #2158-E/-F. Note
`acquire_v8` is too large to inline so its move is codegen-neutral; only the
small helpers are inlining-sensitive.

## F3 (MAJOR — folded) — the issue's offender list is incomplete; the worst file is a god-function, not code-motion

Re-running the project's own `scripts/refactoring-audit.sh` at HEAD showed the
committed heatmap is stale and the true REFACTOR set is **seven** files, not
three. The two biggest — `poll_descriptor/mod.rs` (3462) and `compiler.go`
(3050) — aren't in the issue. Critically, `poll_descriptor/mod.rs` is **not a
code-motion candidate at all**: ~3074 of its lines are the single function
`poll_binding_process_descriptor` (the standing god-function example named in
engineering-style.md, tracked as **#961**). Splitting it changes the function
body → behavior risk → outside #2158's "byte-identical" bar. **Folded into
§5.1 and §9**: classified as defer-to-#961, with rationale; only its 232-line
inline-test relocation is a clean #2158 move and even that doesn't clear the
audit gate, so the whole file is deferred. Plan now covers all seven and
prioritizes the genuinely-splittable ones.

## F4 (MEDIUM — folded) — Go init-order is a real code-motion trap

Go runs package-level `var` initializers and `init()` in **source-file-name
order** within a package. A split that moves a side-effecting `var x = f()` or
an `init()` into a file whose name sorts differently can silently change init
order — a behavior change that no test may catch. `manager.go` has an `init()`
(line 108) + `Boot()` registration. **Folded into §8 item 5** as a required
check, with the explicit instruction to keep `init()` in `manager.go` and to
verify no cross-file package-`var` init dependency in store.go / compiler.go /
cli_show_security.go before fixing file names. This is the one Go-specific way
"pure file move" can bite.

## F5 (MEDIUM — confirmed safe) — Go method-receiver / Rust impl-block integrity

Checked the named Go files: the functions to move are overwhelmingly methods
with explicit receivers (`func (s *Store) …`, `func (m *Manager) …`) or pure
free funcs. Moving a method to another file in the same package keeps the
receiver verbatim — Go has no per-file method-set scoping. Rust: moved methods
stay in `impl <Type>` blocks in the sibling (multiple impl blocks per type are
legal). Risk is low PROVIDED the diff is verified move-only (§8 item 7). No
change needed; added the explicit "no receiver drift" check to §8 item 4.

## F6 (MINOR — confirmed) — queue_service / forwarding are WATCH not REFACTOR

The issue lists these under "watch-list" but a casual reader might split them
as part of #2158. The audit tool puts them at 1880 / 1761 (below the 2000 hard
line). The engineering-style rule is explicit: split WATCH-tier files *with
the next substantive change*, not as standalone code-motion. **Folded into
§5.8**: their boundaries are recorded for the next toucher, but they are
explicitly NOT standalone #2158 PRs. Prevents scope creep + needless hot-path
churn.

## F7 (MINOR — folded) — the audit drift gate is a hard CI requirement, easy to forget

`make audit-check` diffs the regenerated heatmap against the committed
`docs/refactoring-audit-current.txt` and fails on drift. Every split changes
file sizes → the committed heatmap MUST be regenerated in the same PR or CI
goes red. This is exactly the kind of step that gets dropped. **Folded into
§2, §7 (per-PR requirement column), and §8 item 9.**

## F8 (NIT) — `wg/engine.rs` test-hooks must not be swept into the relocation

The cheap engine.rs win is sound, but a careless relocation could grab the
`#[cfg(test)]` struct field `mock_now_ns` (line ~345) and the `table_for_test`
accessor (line ~629) — those are test hooks compiled into the *prod* file, not
part of the `mod engine_internal_tests` block, and must STAY in engine.rs.
**Already called out in §5.5.** Confirmed correct.

---

## Files I tried to break and couldn't (clean-split confirmations)

- **store.go** — clean 6-way; all methods on `*Store`, no package-level
  side-effecting `var` spotted, `store_test.go` covers the surface. The only
  caveat is F4 (verify no init dependency) — low.
- **compiler.go** — clean; the validate-strict / validate-warn / applications
  clusters are cohesive and mostly free functions; the compile core stays.
- **backlog.rs / vtime.rs** — genuinely self-contained (only `AtomicU64`/
  `Box<[…]>` members, no cross-group field reach). These ARE zero-visibility-
  change moves (unlike epoch/lease — F1).

## Residual risk accepted

- shared_cos_lease is HOT PATH; even with `#[inline]` hints, the only true
  proof of no-codegen-regression is the loss-cluster smoke (gated, §6). Plan
  requires it. This is the residual the engineer must actually run, not assert.
- `lease.rs` stays ~1233 LOC post-split (acquire_v8 is itself huge). Under
  threshold, so acceptable for #2158; flagged as a future god-function cut.

**Conclusion: PLAN-READY.** All MAJOR findings folded; the plan now (a) covers
the true seven-file set, (b) is honest about the `pub(super)` widening and the
LTO-off codegen risk, (c) defers the god-function file to #961, and (d) makes
the audit-drift gate and Go init-order check explicit.
