# #10492 — Anchor the debug Rust cargo leg's test selectors

## Status

READY v4 — plan review closed; implementation shipped on branch
`fix/10492-cargo-filters` (9 files: Makefile leg, three registries, live
validator + static self-test, selftest registration, log, and this plan).

- Round-1 findings closed in this revision: validator contract and family
  tripwire, coordinator criterion, ignored-test rule, multi-target
  normalization, Miri precedent, current `--list` membership, validator
  self-tests, and timing/argument-size bounds.
- v3/v4 delta review folded the exact registry cutover, live validator,
  coordinator dispositions, ignored transitions, target normalization,
  fixture mutations, and argv/timing bounds; the parent marked v4 PLAN-READY
  before implementation.
- Issue: #10492 (OPEN, validated-by:research, source:deep-review finding
  `q06-rust-types-F5`). Issue state verified 2026-09-21.
- Prior-fix checks: historical pin `b71c52d60` had the unanchored
  recipe; `git log origin/master --grep=10492` and matching filter/anchor
  searches found no fix. PR authority searches were also explicit:
  GitHub Search API `repo:psaab/xpf is:pr "10492"` returned
  `total_count: 0`; `repo:psaab/xpf is:pr "frame nat session checksum"`
  returned 4 results, of which merged #9833 is the #9499 introducer and
  still contains the bare filters. No later matching fix was found.
- Worktree: `/home/ps/git/pi-xpf/.claude/worktrees/10492-cargo`,
  base `4d45b4115` (rebased onto `origin/master` 2026-09-21).
- Next gate: code review of the shipped implementation; PR #10542 is open
  with `Closes #10492`.

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
semantics)**: any full test path containing `frame`, `nat`, `session`, or
`checksum` is selected. Membership is therefore accidental, not intentional.

Current runtime membership was measured from the pinned toolchain, not
inferred from source grep:

```text
CARGO_TARGET_DIR=/dev/shm/cargo-10492 TMPDIR=/dev/shm
cargo +1.98.1 test --manifest-path userspace-dp/Cargo.toml \
  --bins --tests -- --list
```

The unfiltered command listed **6,724 target-qualified tests in 14
sections** (2 bin targets + 12 integration targets; 6,702 distinct raw
names because 22 names repeat across targets). The same target set was
then run once per current filter:

```text
for filter in frame nat session checksum; do
  cargo +1.98.1 test --manifest-path userspace-dp/Cargo.toml \
    --bins --tests -- --list "$filter"
done
```

The four actual filtered outputs contained these unique full-path counts:

| Filter token | Matching full paths |
|---|---:|
| `frame` | 586 |
| `nat` | 1,529 |
| `session` | 965 |
| `checksum` | 77 |

The per-filter sum is 3,157; pair overlaps are frame/nat 95,
frame/session 32, frame/checksum 37, nat/session 119, nat/checksum 32,
session/checksum 0. After union/deduplication, the legacy filter listing
(`F ∩ L`) contains **2,857** unique raw paths; subtracting the two ignored
family paths leaves **2,855 runnable exact candidates** (`F ∩ R`), all with
unique target-qualified entries.

Target distribution of the 2,857 listed paths: `xpf-userspace-dp` bin
2,852 (2,850 runnable); `frag_assoc_reverse_unreachable_9957` 1;
`session_id_node_namespace_6311_guard` 1; `snat_contract_doc_guard` 1;
`vrf_session_identity_doc_guard` 2; the other nine targets 0. The current
runnable candidate set has no duplicate raw path, so one exact-filter
invocation is currently possible; the validator pins a fail-closed
collision rule below.

`coordinator` contains `nat` at character index 6. The actual list has
**287** selected paths under a `::coordinator::` module segment (all
selected through `nat`), and **298** selected paths containing the literal
`coordinator` anywhere. This is a path-membership fact, not the earlier
grep proxy count. Examples of unrelated-name sweep-ins include
`a_coordinator_write_claims_the_row_9560`,
`a_coordinator_and_a_worker_both_hold_the_same_row_9560`, and
`a_coordinator_delete_skips_a_worker_held_row_and_deletes_an_unowned_one_9560`
(`userspace-dp/src/afxdp/bpf_map/steering_owners.rs:672,693,731`).
Conversely, `nat::tests_pool::*coordinator*` paths are genuine NAT-module
tests and must not be excluded by a test-name rule.

Acceptance (from the issue): the debug leg uses anchored/exact selectors
with a comment stating each leg's purpose; coordinator tests are in or out
by exact match, not substring accident; a rename that would silently leave
the leg fails loudly (or selection is by target, immune to renames).

## 2. Scope / value

Scope (implementation round, NOT this round):

- Rewrite the `Makefile:366-367` debug-leg selector to exact form and add
  one purpose comment for each check/release/debug leg.
- Add the target-qualified `debug-leg.tests`, `.ignored`, and `.excluded`
  registries plus the live validator implementing the fixed equations.
- Add the static validator self-test through the existing `make selftest`
  registration path.
- Make coordinator membership deliberate under the pinned criterion
  (in-list, ignored, or explicit exclusion with reason).

Value: the overflow/`debug_assert!` oracle added by #9499 (member 1) only
means something if its test set is deterministic. Today a rename can hollow
the leg out while CI stays green. Exact selection plus live-list validation
converts silent coverage drift into a reviewed change or a loud failure.

Explicitly in scope: `Makefile:347-367`, the three registries, the live
validator, and its static self-test. Nothing else.

## 3. Shipped context

Base: `origin/master 4d45b4115` (current merge-base after the
latest implementation rebase). The historical evidence pin from the issue
(`1a6952b61`) remains accurate for the original unanchored recipe.

Why the leg exists (`Makefile:347-361` + `docs/log/9499.md`):

- #9499 member 1 added the debug leg because the release leg cannot catch
  wraps: release has overflow-checks OFF, so a wrap fails only if a test
  asserts the exact wrapped value.
- Proof of value: mutating `parsed.seq.wrapping_add(seg_len)` to
  `parsed.seq + seg_len` in `afxdp/frame/tcp.rs` keeps the release leg green
  and fails the debug leg on `reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499`
  ("attempt to add with overflow").
- Historical measurement (`docs/log/9499.md`, worktree
  `fix/9499-rust-overflow-miri-gates` @ `fbc51cc02`): debug filtered leg =
  213 s cold build, 65 s run, **2489 passed**; whole suite with
  `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true` = 5877 passed, 0 failed.
  These are historical baselines, not current membership or pass-count
  invariants: the current `--list` union is 2,857.
- The earlier `RUSTFLAGS="-C overflow-checks=on"` attempt failed to link with
  `duplicate symbol: crc32` — `RUSTFLAGS` replaces root `.cargo/config.toml`
  rustflags and drops `--allow-multiple-definition`. Use the profile
  variable, not `RUSTFLAGS`.

Current membership evidence (2026-09-21; target-qualified `--list` output):

- 6,724 runnable-or-ignored test entries across 14 target sections;
  2,857 match the current four-token union (2,855 runnable, 2 ignored).
- `cargo ... -- --list --ignored` reports 6 ignored entries total; the
  current debug family contains exactly 2 ignored paths:
  `afxdp::session_glue::tests::reconcile_cost_9327` and
  `nat::tests_pool::recycle_amortization_9327`.
  The default debug command does not run them. The v2 contract records
  these in an explicit ignored registry rather than silently treating them
  as runnable.
- Source context, not membership: 175 lines matching `debug_assert` and
  12 integration-test files. Full execution pass/fail denominators are
  intentionally not claimed in a plan-only round.

Other `cargo test` legs in `Makefile` (out of scope, for orientation):
`test/incus/cold-path-flooder` (:1175) and `newflow-gen` (:1179) — unrelated
load-gen crates, not the userspace-dp suite.

There is no GitHub Actions workflow to update: `.github/` contains
instructions only, and `make test` reaches this lane via `test-rust` at
`Makefile:99`.

Structural facts constraining the design:

- `userspace-dp` has no `[lib]` target and has two implicit bin targets
  (`src/main.rs` and `src/bin/fairness-eval.rs`); `--tests` adds 12
  integration targets. The current 14-section list must therefore be
  normalized by target, not by one global first-result parser.
- The validator's normalized key is `(target-name, full-test-path)`, matching the registry's two columns; `cargo metadata --no-deps` shows all 14 bin/test target names unique across kinds, so the kind adds no identity.
- For each target discovered from Cargo metadata, capture both
  `cargo test --bin/--test <target> -- --list` and the corresponding
  `--list --ignored`; parse every `: test` line and sum every target. A
  zero-row normal list emits an explicit warning and contributes an empty set;
  the global empty-census guard still fails if every target is empty. An empty
  ignored list is valid.
  Current selected raw paths are unique across targets; a future selected
  duplicate is a fail-closed validator error until target-grouped selectors
  are used.
- Benches are deliberately excluded: 6 benches carry `harness = false`
  (`tx_kick_latency`, `prefix_set_lookup`, `session_table`,
  `snat_allocator`, `runtime_view_refresh`, `b2_capture_bridge`), and
  criterion's harness rejects libtest's `--test-threads` flag, so adding
  `--benches` would break the run (`Makefile:313-322`). Any redesign must
  keep benches out of the `--test-threads=1` legs.
- `--exact` precedent: exactly one comment in the tree
  (`userspace-dp/src/nat64_tests.rs:1665`), zero `Makefile` usage.
- The Miri precedent is real and is not a strawman: `MIRI.registry:35` uses
  a module-prefix substring and floor 12; `scripts/miri-leg.sh:7-24,79-80`
  fails on missing result/zero passed/below floor, and
  `scripts/miri-leg.sh:91-114` sums result lines across binaries. Prefix +
  floor catches silent shrink/rename, but a substitution can drop one
  intended test and add one incidental test while preserving the floor.
  Exact paths additionally catch that growth/substitution and provide the
  reviewed membership diff, so exact selection remains the chosen contract.
- `--test-threads=1` rationale (`Makefile:323-328`): some dataplane socket
  tests wedge in `__skb_wait_for_more_packets` under concurrency; the
  serialize-the-harness flag avoids the intermittent hang.

## 4. Design

### Option A (recommended) — exact target-qualified allowlist + live tripwire

Use three reviewable, source-controlled registries:

- `userspace-dp/debug-leg.tests`: one exact runnable entry per line,
  `target-name<TAB>full-libtest-path`, sorted and duplicate-free.
- `userspace-dp/debug-leg.ignored`: exact family paths that are intentionally
  ignored by libtest, with a reason. The current two entries are
  `xpf-userspace-dp<TAB>afxdp::session_glue::tests::reconcile_cost_9327`
  and `xpf-userspace-dp<TAB>nat::tests_pool::recycle_amortization_9327`.
- `userspace-dp/debug-leg.excluded`: exact runnable family paths deliberately
  outside the oracle, with a reason (for example a coordinator lifecycle
  test that fails the coordinator criterion below).

The source of truth is the exact registries, not a family generator. A live
validator runs before the debug leg:

1. Discover the two bins and 12 integration targets from `cargo metadata`.
   Run each target's `--list` and `--list --ignored` under the pinned cargo
   wrapper; normalize only the trailing `: test`, retaining target identity.
2. Let `L` be all target-qualified listed paths, `I` the ignored subset,
   `R = L - I`, `A` the `debug-leg.tests` set, `X` the ignored registry,
   and `E` the excluded registry.
3. Define the **legacy-family tripwire** `F` exactly as:
   `(target,path) ∈ F` iff the case-sensitive raw full path contains one of
   the literal substrings `frame`, `nat`, `session`, or `checksum`. No
   regex, case-folding, or token-boundary interpretation is used. This
   deliberately mirrors the old selector and therefore conservatively
   includes `coordinator`; false positives block for review rather than run.
4. Enforce the pinned contract:
   `A ⊆ R`, `E ⊆ R`, `X = F ∩ I`, `A ∪ E = F ∩ R`, and `A ∩ E = ∅`.
   Every missing expected path, newly matching family path, unexpected
   ignored transition, duplicate registry entry, or target collision fails
   closed with a named diff. Tests outside `F` may remain outside the debug
   leg.

The substring predicate is acceptable **only as a fail-closed validator
tripwire**: it never selects a test. It detects both shrink (missing exact
entry) and growth/substitution (unexpected family entry), while an exact
selector cannot accidentally execute a new path. This is the explicit
reconciliation with Option B and the reason the selector itself remains
exact.

Coordinator criterion (decision criterion pinned; final per-path assignment
may land in implementation): for a path whose **module segments** include
`coordinator`, put it in `A` iff source/test inspection shows
wrapping-sensitive integer arithmetic or a `debug_assert!`-guarded invariant
whose failure is relevant to the #9499 overflow/debug oracle. Put it in `E`
with a reason iff it is orchestration, lifecycle, or control-plane behavior
without that arithmetic/invariant; put it in `X` only when libtest marks it
ignored. This criterion is module-aware and never classifies a test by the
word `coordinator` in its function name. NAT-module paths named
`*coordinator*` remain governed by the NAT family and are not excluded by
name.

Ignored-test rule is pinned: the shipped debug command does **not** pass
`--ignored` or `--include-ignored`; ignored family paths belong in `X` with
a reason, and any transition between `I` and `R` fails until the registry is
updated in the same change. This preserves today's non-ignored execution
semantics without silently dropping a family test.

Multi-target selector rule is pinned: current `F ∩ R` has 2,855 unique raw
paths and 236,137 bytes of filter arguments (`F ∩ L` is 2,857 = 2,855 runnable + 2 ignored); host `ARG_MAX` is 2,097,152.
The implementation asserts the expanded argv remains below 1 MiB and passes
the deduplicated exact paths to one `--bins --tests` invocation. If a future
target collision violates uniqueness or the 1 MiB bound, the validator fails
before execution and the same change must switch to target-grouped
`--bin`/`--test` invocations (never one cargo process per test).

- Pro: exactness catches rename and substitution/growth drift; target
  identity and ignored transitions are explicit; registry diffs are a
  review surface; one current invocation stays below the measured bound.
- Con: approximately 2,855 entries are churn-prone; the live validator
  needs 14 targets × (`--list` + `--list --ignored`) = 28 list
  invocations and a small parser; coordinator exclusions require per-path review.

### Option B — prefix filters plus floors (honest alternative, not selected)

The repository already ships this shape in the Miri gate: a module-prefix
substring plus a floor catches a renamed module that produces zero/below-floor
results. It is a credible low-churn alternative for detecting shrink.
It does **not** catch substitution/growth (one intended path removed while an
incidental path keeps the floor), and it does not produce an exact reviewable
membership set. #10492 asks for anchored/exact selectors, so Option B is
retained as the validator-tripwire precedent but not shipped as the selector.

### Option C — `--skip`-only hardening (rejected)

Keeping the four substring filters and adding `--skip coordinator` fixes one
known accident while leaving both shrink and substitution drift in place.
Coordinator inclusion/exclusion belongs in `A`, `E`, or `X`, not a skip-only
patch.

### Option D — profile-level overflow checks on the release leg (rejected)

Setting `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true` on the release leg
would not cover `debug_assert!`, changes the release leg's semantics, and
does not satisfy the issue's exact-selector acceptance. The historical
5877/0 measurement is evidence only, not a reason to remove this oracle.

### Validator boundary and self-tests

The live validator belongs inside `test-rust` because only the pinned,
compiled libtest binaries can provide the actual target-qualified `--list`
and ignored sets. A hermetic static self-test is also required:
`scripts/debug-leg-census-selftest.sh` (registered with the existing
`make selftest` path) validates target-qualified sorted/unique/non-empty
registries, exact tabular shape, and explicit reason text for every `X`/`E`
entry (ignored measurements use a stable reason marker such as
`MEASUREMENT:`). Fixture-driven partition behavior must kill: empty
allowlist, empty live list, parser/classifier positive control,
missing-expected, unexpected-family, ignored-to-runnable transition,
duplicate-target-path, and unsorted-registry mutations. This is additive
to, not a replacement for, the live check; no CI workflow is introduced.

### Recommended shape (Option A + fail-closed tripwire + comments)

```
# Leg 2 of 3: debug-profile overflow + debug_assert oracle (#9499 member 1).
# Selectors are exact target-qualified paths from debug-leg.tests; the live
# validator compares every target's --list and --list --ignored output.
# Coordinator paths follow the arithmetic/debug_assert criterion above;
# ignored and deliberately excluded paths are recorded, never swept in.
```

Implementation steps:

1. Generate the three registries from the current 14-target census, then
   human-review every coordinator path and every `E` reason. Keep entries
   target-qualified, sorted, and duplicate-free.
   For deterministic regeneration, use byte-order sorting for each file:
   `LC_ALL=C sort -u userspace-dp/debug-leg.tests -o userspace-dp/debug-leg.tests`,
   and the same command for `debug-leg.ignored` and `debug-leg.excluded`.
2. Run the live validator under the pinned wrapper before the exact debug
   invocation. It enforces `A ⊆ R`, `E ⊆ R`, `X = F ∩ I`,
   `A ∪ E = F ∩ R`, and `A ∩ E = ∅`, then prints named set diffs.
3. Pass the deduplicated `A` paths with `--exact --test-threads=1` to one
   debug cargo invocation while preserving `--bins --tests`; exclude benches.
4. Run the static census self-test through the existing selftest path.
   Keep the #9499 narrative and add one explicit purpose line per leg.
5. Preserve the pinned `dp-toolchain.sh`, linked-libs stamp, and
   `XPF_LINKED_LIBS_STAMP` flow. Do not use one cargo process per test.


## 5. API

No Rust API changes. The "API" is the `make test-rust` contract:

Before:

```make
test-rust: check-userspace-dt-needed
	... cargo check ... --benches
	... cargo test ... --release --bins --tests -- --test-threads=1
	... cargo test ... --bins --tests -- --test-threads=1 frame nat session checksum
```

After (schematic — exact registry contents are implementation artifacts;
the validator contract is fixed here):

```make
test-rust: check-userspace-dt-needed
	... cargo check ... --benches                          # leg 0: compile bench invariants (unchanged)
	... cargo test ... --release --bins --tests -- --test-threads=1            # leg 1: full suite, overflow OFF (unchanged)
	... debug-leg live validator: target-qualified --list + --list --ignored
	... cargo test ... --bins --tests -- --test-threads=1 --exact <dedup A paths>
```

- `make test-rust` target name, prerequisites, and exit semantics remain
  unchanged (plain recipe lines; non-zero cargo exit fails the target —
  `Makefile:330-332`).
- The live validator is inside the existing target because it needs pinned
  compiled test binaries. The static registry self-test is registered with
  the existing `make selftest` path; no new CI workflow is introduced.
- `userspace-dp/debug-leg.tests`, `.ignored`, and `.excluded` are the
  target-qualified source-of-truth registries. The selector receives only
  exact paths from `A` and never the family tripwire.
- Pinned-toolchain wrapper (`dp-toolchain.sh` + `linked-libs-stamp.sh`) and
  `XPF_LINKED_LIBS_STAMP` pass-through remain unchanged.

## 6. Invariants

1. Debug execution selects exactly `A` (`debug-leg.tests`) with libtest
   `--exact`; the family substring predicate is validator-only.
2. The coordinator criterion is module-aware: coordinator paths enter `A`
   only for wrapping-sensitive arithmetic/debug-assert invariants relevant
   to #9499, enter `E` with a reason for orchestration/lifecycle/control
   behavior, or enter `X` only when ignored.
3. Validator membership is fail-closed: `A ⊆ R`, `E ⊆ R`,
   `X = F ∩ I`, `A ∪ E = F ∩ R`, and `A ∩ E = ∅`; missing expected,
   unexpected family, ignored-state, duplicate, and target-collision diffs
   fail with names.
4. Ignored tests are never executed implicitly: no `--ignored` or
   `--include-ignored`; every ignored family path is explicit in `X`.
5. Multi-target normalization sums all 14 target sections, retains target
   identity, and rejects a selected duplicate raw path or expanded argv
   at/above 1 MiB (current F∩R candidate argv is 236,137 B, a conservative
   upper bound on selected-A argv; the 1 MiB assertion measures F∩R;
   host ARG_MAX is 2,097,152 B).
6. Release leg remains the same command and full-suite scope; its historical
   5877 result is not asserted as a current baseline.
7. Serialization preserved: `--test-threads=1` stays on both test legs
   (socket-test hang avoidance).
8. Bench exclusion preserved: no `--benches` on any `--test-threads=1` leg
   (criterion harness incompatibility).
9. The debug leg remains a filtered second build; implementation reports
   current timing and flags >2x the historical 213 s cold / 65 s run for
   review rather than silently widening the set.
10. Toolchain pinning remains untouched: `dp-toolchain.sh`,
    `rust-toolchain.toml`, linked-libs stamp, and environment flow.

## 7. Risk

4-class mapping used: Correctness / Compatibility / Performance /
Operability.

- **Correctness — Medium, mitigated.** Risk: the three registries drift,
  the family classifier is accidentally weakened, or coordinator paths are
  assigned by name rather than module-aware criterion. Mitigation: the
  fail-closed equations (`A ⊆ R`, `E ⊆ R`, `X = F ∩ I`,
  `A ∪ E = F ∩ R`, `A ∩ E = ∅`), exact target-qualified diffs,
  self-test mutations, and the #9499 planted mutant (debug fails, release
  stays green) all have named failure signals.
- **Compatibility — Low-Medium, mitigated.** Risk: libtest list formatting,
  ignored-state behavior, or target discovery changes on the pinned
  toolchain. Mitigation: parse only `: test` lines from every target,
  capture `--list` and `--list --ignored`, retain target identity, sum all
  sections, and fail closed on unknown format or duplicate selected paths.
- **Performance — Low-Medium, bounded.** Risk: 14 targets ×
  (`--list` + `--list --ignored`) = 28 warm list invocations, plus the
  exact allowlist increase gate overhead. Mitigation: probes reuse compiled
  artifacts; current F∩R candidate argv is 236,137 B (conservative upper
  bound on selected-A argv) versus a 1 MiB assertion on F∩R; one exact
  invocation remains the current path; no per-test process loop.
  Implementation reports timing and flags >2x the historical 213 s cold /
  65 s run for review.
- **Operability — Medium, mitigated.** Risk: a new family test or ignored
  transition blocks until a registry diff is reviewed. That is deliberate
  fail-closed behavior, not a silent drop. Sorted target-qualified files,
  explicit exclusion/ignored reasons, static self-tests, and the existing
  selftest path keep maintenance visible; no new workflow is required.

## 8. Test plan

All in the implementation round (parent sequences smoke at merge; no
cluster/incus commands in Wave 1):

1. **Live membership contract:** with isolated
   `CARGO_TARGET_DIR=/dev/shm/cargo-10492`, discover all 14 targets and
   capture both `--list` and `--list --ignored` per target. Assert the
   current baseline (6,724 total entries, F ∩ L = 2,857, F ∩ R = 2,855,
   6 ignored, 2 ignored-family entries), then run the registry equations
   with zero unclassified diffs.
2. **Static validator self-test:** run the registered
   `scripts/debug-leg-census-selftest.sh` fixtures. Kill cases must include
   empty allowlist, empty live list, broken parser/classifier positive
   control, missing expected, unexpected family, ignored-to-runnable
   transition, duplicate registry entry, duplicate target path, and
   unsorted registry.
3. **Rename and substitution probes:** remove/rename an allowlisted path
   without changing the registry (missing-expected FAIL), then replace one
   family path with an unrelated family path while preserving total count
   (missing + unexpected FAIL). This covers both shrink and growth escapes.
4. **Ignored-state probe:** place an ignored family fixture in `A`, and a
   runnable family fixture in `X`; both validators must fail. Move each to
   its proper registry and verify the default debug command does not run
   ignored entries.
5. **Coordinator disposition:** inspect every `::coordinator::` path under
   the pinned arithmetic/debug-assert criterion; verify `A`, `E`, and `X`
   assignments and reasons. Confirm NAT-module paths whose test names
   contain `coordinator` are not excluded by name.
6. **Target normalization/argv:** fixture two targets with the same raw
   path and exceed the 1 MiB expansion; validator must fail before cargo
   runs. Verify current F∩R candidate argv has no collision and is
   236,137 B (conservative upper bound on selected-A argv); the 1 MiB
   assertion measures F∩R.
7. **Oracle re-proof:** re-apply the #9499 planted mutant
   (`wrapping_add` -> `+` in `afxdp/frame/tcp.rs`); the exact registry must
   include `reject_rst_v4_for_syn_at_seq_max_wraps_ack_to_zero_9499`; the
   debug leg must FAIL with "attempt to add with overflow", while release
   stays green. Revert mutant.
8. **Make contract:** `make -n test-rust` shows the per-leg purpose
   comments, live validator, exact selector, and unchanged pinned wrapper;
   `git diff` touches only `Makefile:347-367` plus registries/validator.
9. **Full gate:** run `make test-rust` on a loaded host, report current
   pass/ignored totals and cold/run timing, and flag >2x historical timing
   for parent review. Parent sequences cluster smoke at merge.

## 9. Out of scope

- `debug_assert!` census (175 source lines noted, not audited) and any
  `debug_assert!` additions/removals.
- Release-profile overflow-flag overhaul (Option D declined above).
- Miri runtime gate (`Makefile:388+`, `MIRI.registry`) — separate #9499
  member 2; only its scorer/normalization precedent is used here.
- Bench execution (`cargo bench` exit-status semantics, #5190); benches
  remain compile-only via the check leg.
- Other `test/incus/*` cargo legs and any Go (`test-go`, `test-race-dp`)
  legs.
- A new CI workflow; the live validator stays in `test-rust` and the static
  self-test uses the existing selftest registration path.
- Full current execution pass/fail re-baselining in this plan round; the
  actual `--list` membership census is in scope and recorded above.

## 10. Open questions

All load-bearing selector, validator, ignored-state, target-normalization,
collision, and timing-bound contracts are pinned above. Remaining questions
are implementation/ownership choices, not permission to weaken those
invariants:

1. Which exact coordinator paths satisfy the pinned arithmetic/debug-assert
   criterion, and which need an `E` reason? The implementation review must
   bless the per-path assignment.
2. Should registry generation be a checked-in helper script or a documented
   one-shot command? The registries remain authoritative either way, and
   the static self-test must prevent hand-edited drift.
3. Which module/path-family headers best explain why each selected family
   belongs to the #9499 oracle, especially the broad `checksum` family?
4. If a future selected raw path collision appears, should the fallback
   use one grouped invocation per target kind or a generated grouped shell
   loop? Either must preserve one build and exact target identity.
5. Which long-term steward owns `test-rust` plus the three registries versus
   sibling lanes? The recipe lines are a shared eight-lane collision surface.
6. Should the leg-purpose comments retain the full #9499 mutant narrative
   in Makefile and docs, or be shortened after the registries land?
7. Where should the static census self-test fixture files live so they are
   discoverable beside the existing Miri/ignored-cell selftests?
8. After implementation, does the measured 2,855-path run stay within the
   >2x review bound, and does coordinator IN/OUT assignment change that
   report enough to revisit the filtered-second-build rationale?
