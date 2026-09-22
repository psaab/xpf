# #10492 — Anchor the debug Rust cargo leg's test selectors

## Status

PLAN-REVIEW PENDING — Wave 1 plan round. NO production code in this round;
this file is the only change on branch `fix/10492-cargo-filters`.

- Issue: #10492 (OPEN, validated-by:research, source:deep-review finding
  `q06-rust-types-F5`). Issue live at `origin/master b71c52d60` — verified
  2026-09-21 (see Shipped context). Prior-fix check negative:
  `git log origin/master --grep=10492|cargo.*filter|anchored|substring` empty,
  `git log --all --grep=10492` empty, last-50 merged-PR scan clean, and
  `git show origin/master:Makefile` still carries the unanchored filter.
- Worktree: `/home/ps/git/pi-xpf/.claude/worktrees/10492-cargo`,
  base `b71c52d60` (matches `origin/master`, no rebase needed).
- Next gate: parent-run adversarial plan review; implementation lands only
  after PLAN-READY.

## 1. Issue framing

`make test-rust` (`Makefile:362-367`) runs three legs:

| Leg | Lines | Command | Profile |
|---|---|---|---|
| check | :363 | `cargo check --benches` | dev (compile-only, evaluates `const assert!`) |
| release | :364-365 | `cargo test --release --bins --tests -- --test-threads=1` | release: overflow checks OFF, `debug_assert!` compiled out |
| debug | :366-367 | `cargo test --bins --tests -- --test-threads=1 frame nat session checksum` | dev: overflow checks ON, `debug_assert!` live |

The debug leg is the ONLY **test-executing** leg with overflow checks and
live `debug_assert!` behavior — the check leg compiles dev-profile code but
does not execute tests — and it selects tests by four trailing libtest
filters. `cargo test` treats those as **unanchored substring filters (union
semantics)**: any test whose full path contains `frame`, `nat`, `session`, or
`checksum` anywhere is swept in. Membership is therefore accidental, not
intentional:

- `coordinator`.find(`nat`) == 6 — every coordinator test matches the `nat`
  filter. Examples swept in incidentally: `untracked_coordinator_release_*_9902`
  (`userspace-dp/src/nat/tests_pool.rs:12673,12704`),
  `binding_coordinate_*_7497`
  (`userspace-dp/src/afxdp/coordinator/reconcile/stage.rs:254,288`).
- Conversely, renaming a module (e.g. `frame` -> `packet`) silently DROPS
  its tests from the checked leg with no signal; coining a new `*nat*`
  identifier silently ADDS tests. Both directions are silent.

Acceptance (from issue): the debug leg uses anchored/exact selectors with a
comment stating each leg's purpose; coordinator tests are in or out by exact
match, not substring accident; a rename that would silently leave the leg
fails loudly (or selection is by target, immune to renames).

## 2. Scope / value

Scope (implementation round, NOT this round):

- Rewrite the `Makefile:366-367` debug-leg selector to anchored/exact form.
- Add a per-leg purpose comment (release leg vs debug leg vs check leg).
- Make coordinator membership deliberate (in-list or explicit exclusion).
- Add a rename-loud mechanism (expected-membership guard — see Design).

Value: the overflow/`debug_assert!` oracle added by #9499 (member 1) only
means something if its test set is deterministic. Today a rename can hollow
the leg out while CI stays green. Exact selection plus live-list validation
converts silent coverage drift into a reviewed change or a loud failure.

Explicitly in scope: `Makefile:347-367`, the reviewed exact-path allowlist,
and its validator (comment + recipe + membership artifact). Nothing else.

## 3. Shipped context

Base: `origin/master b71c52d60` (`pmech: land deny-only D11 bridge (#9506)
(#10483)`). Evidence pin from the issue (`1a6952b61`) still accurate —
`Makefile:362-367` line numbers unchanged between the pin and `b71c52d60`.

Why the leg exists (`Makefile:347-361` + `docs/log/9499.md`):

- #9499 member 1 added the debug leg because the release leg cannot catch
  wraps: release has overflow-checks OFF, so a wrap fails only if a test
  asserts the exact wrapped value.
- Proof of value: mutating `parsed.seq.wrapping_add(seg_len)` to
  `parsed.seq + seg_len` in `afxdp/frame/tcp.rs` keeps the release leg green
  and fails the debug leg on `reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499`
  ("attempt to add with overflow").
- Measured (`docs/log/9499.md`, worktree `fix/9499-rust-overflow-miri-gates`
  @ `fbc51cc02`): debug filtered leg = 213 s cold build, 65 s run,
  **2489 passed**; whole suite with
  `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true` = 5877 passed, 0 failed.
  (First `RUSTFLAGS="-C overflow-checks=on"` attempt failed to link with
  `duplicate symbol: crc32` — `RUSTFLAGS` replaces
  `userspace-dp/.cargo/config.toml` rustflags and drops
  `--allow-multiple-definition`. Use the profile variable, not `RUSTFLAGS`.)

Blast-radius census (worktree, 2026-09-21; grep-based lexical counts,
denominators unverified per issue Limits — no `cargo test -- --list` run in
plan round):

| Signal | Count | Command |
|---|---|---|
| lines matching `#[test]` (`src`+`tests`) | 6751 | `grep -rn '#\[test\]' --include='*.rs'` |
| lines matching `debug_assert` | 175 | `grep -rn 'debug_assert' --include='*.rs'` |
| integration files (`tests/*.rs`) | 12 | `ls userspace-dp/tests/*.rs` |
| files containing `frame` / `nat` / `session` / `checksum` | 348 / 501 / 388 / 111 | `grep -rln <tok> --include='*.rs'` |
| fn-name matches for `frame` / `nat` / `session` / `checksum` | 404 / 1139 / 769 / 125 | `grep -rn 'fn .*<tok>.*(' --include='*.rs'` |
| `coordinator` files / fn-name matches | 161 / 27 | same patterns |
| accidental-host files (`donat\|alternat\|coordinat`) | 186 | `grep -rln` |

Other `cargo test` legs in `Makefile` (out of scope, for orientation):
`test/incus/cold-path-flooder` (:1175) and `newflow-gen` (:1179) — unrelated
load-gen crates, not the userspace-dp suite.

Structural facts constraining the design:

- `userspace-dp` is a **binary-only crate** (no `[lib]` target;
  `Cargo.toml:1-2` package `xpf-userspace-dp`, no `[[bin]]`/`[lib]` stanzas).
  Unit tests live in the bin, hence `--bins`; `--tests` adds the 12
  integration files. Selection "by target" here means `--bin <name>` /
  `--test <file>` granularity, or module-path filters within the bin.
- Benches are deliberately excluded: 6 benches carry `harness = false`
  (`tx_kick_latency`, `prefix_set_lookup`, `session_table`,
  `snat_allocator`, `runtime_view_refresh`, `b2_capture_bridge`), and
  criterion's harness rejects libtest's `--test-threads` flag, so adding
  `--benches` would break the run (`Makefile:313-322`). Any redesign must
  keep benches out of the `--test-threads=1` legs.
- `--exact` precedent: exactly one comment in the tree
  (`userspace-dp/src/nat64_tests.rs:1665`), zero `Makefile` usage. No
  established anchored-selector idiom to copy.
- Path-qualified filter precedent: the Miri gate uses `afxdp::frame::`
  (`Makefile:395` comment) — still technically a substring, but a
  module-path prefix, which is far less collision-prone than bare words.
- `--test-threads=1` rationale (`Makefile:323-328`): some dataplane socket
  tests wedge in `__skb_wait_for_more_packets` under concurrency; the
  serialize-the-harness flag avoids the intermittent hang.

## 4. Design

### Option A (recommended) — `--exact` full test paths + checked-in allowlist

Enumerate every intended debug-leg test by its full libtest path, one path
per line in `userspace-dp/debug-leg.tests`. The implementation round first
captures `cargo test --bins --tests -- --list`, normalizes the names, and
compares the live set with this reviewed allowlist. Only after that
comparison passes does the debug command run with `--exact` and all
allowlisted paths as filters. The allowlist is the source-controlled
membership contract; the comparison is mandatory, not advisory.

- Pro: exactness is total; a renamed/removed test is a loud set diff; the
  diff IS the review surface for membership changes; coordinator inclusion
  or exclusion is explicit in the file.
- Con: a roughly 2,489-entry list is churn-prone (every intended
  frame/NAT/session/checksum test must be reviewed when added/renamed);
  the recipe needs a small validator and a safe way to pass the list to
  one test invocation.

The validator must fail for every expected path missing from `--list` and
for every unexpected path that falls under the documented debug-leg
families. It may permit unrelated tests outside the allowlist (they are
not part of this leg), but it MUST NOT silently accept a rename or
accidental family match. Exact allowlist semantics are therefore stronger
than a non-empty prefix/count guard.

### Option B — path-qualified module filters (rejected as the fix)

Replacing `frame nat session checksum` with prefixes such as
`afxdp::frame::` would reduce collisions, but these are **still libtest
substring filters**, not anchors. A renamed path can still disappear
silently, and an identifier containing the prefix can still match
incidentally. This option does not satisfy #10492's anchored/exact
acceptance and is not an acceptable implementation.

Path prefixes MAY be used during the census to generate candidate paths for
the reviewed allowlist, but they MUST NOT be the shipped selector.

### Option C — `--skip`-only hardening (rejected)

Keeping the four substring filters and adding `--skip coordinator` would
fix one known accident while leaving the unanchored mechanism in place.
The next `*nat*` coinage reopens the hole. Coordinator inclusion/exclusion
belongs in the exact allowlist, not in a skip-only patch.

### Option D — profile-level overflow checks on the release leg (alternative, needs parent call)

Set `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true` for the release leg (the
`docs/log/9499.md` measurement proves the suite passes: 5877/0). This would
make the debug leg redundant for overflow (though NOT for `debug_assert!`,
which stays compiled out under release).

- Rejected for this issue: it changes release-artifact semantics for every
  consumer of the leg, does not cover `debug_assert!`, and the issue's
  acceptance explicitly asks for anchored selectors, not leg removal. Noted
  so the review can consciously decline it.

### Recommended shape (Option A + allowlist validation + comments)

```
# Leg 2 of 3: debug-profile overflow + debug_assert oracle (#9499 member 1).
# Selectors are exact full test paths from userspace-dp/debug-leg.tests;
# membership is compared with cargo test -- --list before execution.
# Coordinator tests are deliberately IN or OUT by reviewed allowlist entry,
# never swept in by a substring.
```

Implementation steps:

1. Generate and review `userspace-dp/debug-leg.tests` from the agreed
   `--list` census. Keep one canonical full path per line, sorted and
   duplicate-free. Decide coordinator membership explicitly.
2. Run a validator against a fresh `--list` result before the debug leg.
   It fails with missing/unexpected path names, so a test rename cannot
   leave the oracle silently green.
3. Pass the allowlist paths to one debug cargo invocation with
   `--exact --test-threads=1`; do not use module prefixes as the shipped
   filter. Preserve `--bins --tests` and exclude benches.
4. Keep the validator and selector invocation under the pinned
   `dp-toolchain.sh`/stamp wrapper. Avoid one cargo process per test.

The implementation-round census must run with isolated
`CARGO_TARGET_DIR=/dev/shm/cargo-10492 TMPDIR=/dev/shm`: capture
`cargo test --bins --tests -- --list`, diff current bare-word membership
against the proposed exact set, and classify every delta before editing the
recipe.


## 5. API

No Rust API changes. The "API" is the `make test-rust` contract:

Before:

```make
test-rust: check-userspace-dt-needed
	... cargo check ... --benches
	... cargo test ... --release --bins --tests -- --test-threads=1
	... cargo test ... --bins --tests -- --test-threads=1 frame nat session checksum
```

After (schematic — exact allowlist contents and validator interface pending
the `--list` census):

```make
test-rust: check-userspace-dt-needed
	... cargo check ... --benches                          # leg 0: compile bench invariants (unchanged)
	... cargo test ... --release --bins --tests -- --test-threads=1            # leg 1: full suite, overflow OFF (unchanged)
	... validate fresh --list against userspace-dp/debug-leg.tests
	... cargo test ... --bins --tests -- --test-threads=1 --exact <allowlist paths>
```


- `make test-rust` target name, prerequisites, and exit semantics unchanged
  (plain recipe lines; non-zero cargo exit still fails the target —
  `Makefile:330-332`).
- No new make targets. A `DEBUG_RUST_TESTS` variable or validator script
  interface is OPTIONAL — keep the allowlist/validation contract obvious
  rather than hiding it in a prefix-filter loop.
- Pinned-toolchain wrapper (`dp-toolchain.sh` + `linked-libs-stamp.sh`) and
  `XPF_LINKED_LIBS_STAMP` pass-through unchanged.

## 6. Invariants

1. Debug-leg membership is the reviewed exact-path allowlist, not a
   bare-word or module-prefix substring rule.
2. Coordinator is deliberate: every coordinator test intended for the
   oracle is an explicit allowlist entry, and every excluded one is absent
   by review decision.
3. Rename-loud: a missing expected path or unexpected path in a documented
   debug-leg family fails the live-list validator with names and a diff.
4. Release leg untouched: same command, same full-suite coverage, same
   overflow-OFF semantics; the 5877-baseline behavior does not shift.
5. Serialization preserved: `--test-threads=1` stays on both test legs
   (socket-test hang avoidance).
6. Bench exclusion preserved: no `--benches` on any `--test-threads=1` leg
   (criterion harness incompatibility).
7. Second-build cost acknowledged: the debug leg remains a filtered second
   build (~3.5 min cold per `Makefile:360-361`); the fix must not silently
   expand it to whole-suite (widen-by-edit rule in `Makefile:352-354` stays).
8. Toolchain pinning untouched: `dp-toolchain.sh` /
   `rust-toolchain.toml` / `linked-libs-stamp.sh` flow unchanged.

## 7. Risk

4-class mapping used: Correctness / Compatibility / Performance /
Operability.

- **Correctness — Medium, mitigated.** Risk: the allowlist accidentally
  NARROWS the leg (dropping a currently-covered subtree) or admits an
  accidental host. Mitigation: `--list` before/after diff is a required
  implementation-round artifact; every dropped/added path is classified
  intentional, and the exact list is reviewed. The #9499 mutant check
  (mutant fails debug leg, passes release leg) re-proves the oracle.
- **Compatibility — Low.** Risk: libtest's exact-filter/list output shape
  or the validator's parser differs on the pinned toolchain. Mitigation:
  validate the parser against the pinned toolchain's actual `--list`
  output; keep the command POSIX-make + pinned cargo; add no provider or
  cluster dependency.
- **Performance — Low.** Risk: the live-list validation adds build/run
  overhead. Mitigation: `--list` reuses the just-built debug artifacts
  (warm, seconds), and exact filters still execute one cargo test process;
  total wall time stays within the documented ~3.5 min cold / ~65 s run
  envelope. No per-test process loop.
- **Operability — Low-Medium, mitigated.** Risk: an allowlist must be
  deliberately updated for intended test additions/renames, which can
  otherwise block CI. Mitigation: failure prints missing/unexpected names;
  the file is sorted, duplicate-free, reviewable, and its update is part
  of the same change as any intended membership change. No brittle count
  band is required.

## 8. Test plan

All in the implementation round (parent sequences smoke at merge; no
cluster/incus commands in Wave 1):

1. `--list` diff: `cargo test --bins --tests -- --list` (isolated
   `CARGO_TARGET_DIR=/dev/shm/cargo-10492`) before vs after; compare with
   `userspace-dp/debug-leg.tests`. Every missing/added path is classified:
   kept / intentionally dropped / intentionally added. Zero unclassified
   deltas.
2. Oracle re-proof: re-apply the #9499 planted mutant
   (`wrapping_add` -> `+` in `afxdp/frame/tcp.rs`); the exact allowlist
   must still include `reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499`;
   the debug leg must FAIL with "attempt to add with overflow", while the
   release leg stays green. Revert mutant.
3. Rename-loud probe: in a scratch worktree, rename one allowlisted test
   path (or remove it from the compiled list) without updating the
   allowlist; the validator must fail naming the missing path. No silent
   green.
4. Coordinator disposition check: compare every coordinator path against
   the reviewed allowlist decision — all intended entries in, all intended
   exclusions out, with no substring-derived partial set.
5. `make -n test-rust` dry-run: recipe expansion shows the validator,
   exact selector, and comments; no other target's expansion changes
   (`git diff` touches only `Makefile:347-367` plus allowlist/validator).
6. Full `make test-rust` green on a loaded host with timing recorded
   (compare against the 2489-test / ~65 s baseline; report new totals).

## 9. Out of scope

- `debug_assert!` census (175 sites noted, not audited) and any
  `debug_assert!` additions/removals.
- Release-profile overflow-flag overhaul (Option D declined above).
- Miri gate (`Makefile:388+`, `MIRI.registry`) — separate #9499 member 2.
- Bench gating (`cargo bench` exit-status semantics, #5190) — benches stay
  compile-only via the check leg.
- Test-count denominator verification beyond the `--list` diff (issue Limits
  stand: denominators unverified until the implementation round runs `--list`).
- The `test/incus/*` cargo legs and any Go (`test-go`, `test-race-dp`) legs.
- New CI jobs: the guard lives inside `test-rust`, no new workflow.

## 10. Open questions

1. Coordinator IN or OUT? The 27 coordinator-named test-function matches
   (161 coordinator-containing files) are currently swept in via `nat`.
   Which exact paths belong in the debug allowlist, and which should stay
   out?
2. Allowlist generation: should `userspace-dp/debug-leg.tests` be updated
   by a checked-in helper script, a documented one-shot command, or an
   explicit review-only process? How do we prevent hand-edited drift?
3. What is the TRUE intended set? The comment says "frame, NAT, session and
   checksum tests" — which full paths exactly? Is `checksum` one module or
   several? The `--list` census enumerates candidates, but intent needs a
   human blessing per path family.
4. Validator output contract: should it require exact equality for all
   selected paths, or permit unrelated tests outside the four documented
   families while requiring exact equality inside them? What normalization
   handles separate bin/integration target output?
5. One invocation vs argument size: can the pinned shell/toolchain pass all
   allowlist paths in one `--exact` invocation under the host's `ARG_MAX`?
   If not, what reviewed runner preserves one build and exact membership
   without one cargo process per test?
6. Allowlist policy for additions: does every newly added frame/NAT/session/
   checksum test enter the debug leg by default (requiring a same-change
   list update), or remain out until explicitly added?
7. Who owns `test-rust` and `debug-leg.tests` long-term versus sibling
   lanes? Wave 1 runs 8 lanes concurrently; `Makefile:362-367` is shared
   surface.
8. Should the leg-purpose comments be terse (one line per leg) or keep the
   current #9499 narrative depth? The issue asks for "a comment stating each
   leg's purpose" — minimal compliance versus preserving the mutant-proof
   story for the next reader.
9. Timing envelope: is ~3.5 min cold / ~65 s run still the budget, or may
   the exact allowlist broaden the leg (for example, coordinator-in adds
   tests)? At what test-count growth does the "filtered second build"
   rationale need revisiting?
